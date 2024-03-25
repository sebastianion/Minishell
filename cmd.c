// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1


/**
 * do redirections for stdin, stdout, stderr
 */
void redirect(simple_command_t *s)
{
	// check the "in", "out" and "err" fields of the simple_command_t structure;
	// if any of those is not null, open a file with the correct flag and dup2
	// the file descriptor accordingly;
	// dup2 closes the 2nd file descriptor entered as parameter and replaces it
	// with the 1st one;
	if (s->in) {
		int fd = open(s->in->string, O_RDONLY, 0644);

		DIE(fd < 0, "open");

		dup2(fd, STDIN_FILENO);
	}

	// for stdout and stderr, we need to check if the append flag is set
	// or not;
	// if not, use "O_TRUNC" to write the file from scratch;
	if (s->err) {
		int append_or_not = s->io_flags == IO_ERR_APPEND ? O_APPEND : O_TRUNC;
		int fd = open(s->err->string, O_WRONLY | O_CREAT | append_or_not, 0644);

		DIE(fd < 0, "open");

		dup2(fd, STDERR_FILENO);
	}

	// for stdout we also have to keep in mind that stderr is always
	// the first one to appear as output, as it is unbuffered;
	// to do this, first check if the "err" field is null or not;
	// in case it is not, the opened file for stdout needs to be in append mode;
	if (s->out) {
		int append_or_not = s->io_flags == IO_OUT_APPEND || s->err ? O_APPEND : O_TRUNC;
		int fd = open(get_word(s->out), O_WRONLY | O_CREAT | append_or_not, 0644);

		DIE(fd < 0, "open");

		dup2(fd, STDOUT_FILENO);
	}
}

/**
 * internal change-directory command
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */

	// if no parameter has been entered, go home
	if (!dir)
		return chdir(getenv("HOME"));

	int res = chdir(dir->string);

	if (res < 0)
		fprintf(stderr, "cd: no such file or directory: %s\n", dir->string);

	return res;
}

/**
 * internal exit/quit command
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 * parse a simple command (internal, environment variable assignment,
 * external command)
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	// if builtin command, execute the command

	if (strcmp(s->verb->string, "cd") == 0) {
		int res;

		// backup file descriptors for stdout and stderr
		int stderr_backup = dup(STDERR_FILENO);
		int stdout_backup = dup(STDOUT_FILENO);

		// do necessary redirections
		redirect(s);

		// change directory
		res = shell_cd(s->params);

		// restore fds if previously changed
		dup2(stderr_backup, STDERR_FILENO);
		close(stderr_backup);
		dup2(stdout_backup, STDOUT_FILENO);
		close(stdout_backup);

		return res;
	}

	// check shell exit conditions
	if (strcmp(s->verb->string, "exit") == 0 ||
		strcmp(s->verb->string, "quit") == 0) {
		return shell_exit();
	}

	// if variable assignment, execute the assignment and return the exit status;
	// get_word() function has been used because it does the expanding of variables;
	// for the get_word() function, the parameter "s->verb->next_part->next_part"
	// has been used because we know that if "s->verb->next_part" is not null,
	// it should represent "="; that is why we use the function for the part that
	// comes right after "=";
	if (s->verb->next_part != NULL)
		return setenv(s->verb->string, get_word(s->verb->next_part->next_part), 1);

	/* if external command:
	 *   1. fork new process
	 *     2c. perform redirections in child
	 *     3c. load executable in child
	 *   2. wait for child
	 *   3. return exit status
	 */

	int status;
	pid_t pid = fork();

	switch (pid) {
	case -1:
		exit(EXIT_FAILURE);

	// child process
	case 0:
		// do necessary redirections
		redirect(s);

		int size;

		// execute command with its arguments, given by the function get_argv()
		execvp(s->verb->string, get_argv(s, &size));

		// if this code is reachable, it means that the execution of the given
		// command failed, so log the error and exit;
		fprintf(stderr, "Execution failed for '%s'\n", s->verb->string);
		exit(EXIT_FAILURE);

	// parrent process waits for the child process to finish its execution
	default:
		waitpid(pid, &status, 0);
	}

	// if the program's execution finished, return its exit status
	if (WIFEXITED(status) == true)
		return WEXITSTATUS(status);

	return 1;
}

/**
 * process two commands in parallel
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	// the '&' operator will be the first one to be parsed,
	// so the parent process can execute a given command as well;
	int status;
	pid_t pid = fork();

	switch (pid) {
	case -1:
		exit(EXIT_FAILURE);

	// child process
	case 0:
		// execute a command by parsing it and exiting with its return value
		exit(parse_command(cmd1, level, father));

	// parent process
	default:
		parse_command(cmd2, level, father);
		waitpid(pid, &status, 0);
	}

	// if the program's execution finished, return its exit status
	if (WIFEXITED(status) == true)
		return WEXITSTATUS(status);

	return false;
}

/**
 * run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	// the idea is to use two fork() functions, in which the children
	// will be the ones to run the commands; the first resulting
	// parent process will use another fork() to spawn a grandchild process;
	// the children processes will also ave to make use of the pipe's reading
	// and writing ends accordingly;

	int pid, pid_nested, status;
	int fd[2];

	// initialize pipe
	pipe(fd);

	pid = fork();

	switch (pid) {
	case -1:
		exit(EXIT_FAILURE);

	// child process
	case 0:
		// close the pipe's reading end
		close(fd[0]);
		// replace the stdout with the pipe's writing eng
		dup2(fd[1], STDOUT_FILENO);

		// parse and execute the command
		exit(parse_command(cmd1, level, father));

	// parent process
	default:
		pid_nested = fork();

		switch (pid_nested) {
		case -1:
			exit(EXIT_FAILURE);

		// second child process (grandchild)
		case 0:
			// close the pipe's writing end
			close(fd[1]);
			// replace the stdin with the pipe's reading eng
			dup2(fd[0], STDIN_FILENO);

			// parse and execute the command
			exit(parse_command(cmd2, level, father));

		// second parent process
		default:
			// close the pipe
			close(fd[0]);
			close(fd[1]);

			// wait for processes to finish their execution
			waitpid(pid, &status, 0);
			waitpid(pid_nested, &status, 0);
		}
	}

	// if the program's execution finished, return its exit status
	if (WIFEXITED(status) == true)
		return WEXITSTATUS(status);

	return false;
}

/**
 * parse and execute a command
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (c->op == OP_NONE)
		// execute a simple command
		return parse_simple(c->scmd, level, c);

	switch (c->op) {
	case OP_SEQUENTIAL:
		// execute the commands one after the other

		parse_command(c->cmd1, level, c);
		return parse_command(c->cmd2, level, c);

	case OP_PARALLEL:
		// execute the commands simultaneously
		return run_in_parallel(c->cmd1, c->cmd2, level, c);

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
		 * returns non zero.
		 */

		if (parse_command(c->cmd1, level, c))
			return parse_command(c->cmd2, level, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
		 * returns zero.
		 */

		if (!parse_command(c->cmd1, level, c))
			return parse_command(c->cmd2, level, c);

		break;

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second.
		 */

		return run_on_pipe(c->cmd1, c->cmd2, level, c);

	default:
		return SHELL_EXIT;
	}

	return 0;
}
