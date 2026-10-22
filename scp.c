/* $OpenBSD: scp.c,v 1.278 2026/10/01 07:10:56 djm Exp $ */
/*
 * scp - secure remote copy.  This is basically patched BSD rcp which
 * uses ssh to do the data transfer (instead of using rcmd).
 *
 * NOTE: This version should NOT be suid root.  (This uses ssh to
 * do the transfer and ssh has the necessary privileges.)
 *
 * 1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Aaron Campbell.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Parts from:
 *
 * Copyright (c) 1983, 1990, 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif
#include <glob.h>
#include <libgen.h>
#include <locale.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <util.h>
#නම් defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#include <vis.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "atomicio.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "progressmeter.h"
#include "utf8.h"
#include "sftp.h"

#include "sftp-common.h"
#include "sftp-client.h"

extern var_na *__progname;

#define COPY_BUFLEN	16384

පූර්ණ_සංඛ්‍යා do_cmd(var_na *, var_na *, var_na *, පූර්ණ_සංඛ්‍යා, පූර්ණ_සංඛ්‍යා, var_na *, පූර්ණ_සංඛ්‍යා *, පූර්ණ_සංඛ්‍යා *, pid_t *);
පූර්ණ_සංඛ්‍යා do_cmd2(var_na *, var_na *, පූර්ණ_සංඛ්‍යා, var_na *, පූර්ණ_සංඛ්‍යා, පූර්ණ_සංඛ්‍යා);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
sa_nracanaa bwlimit bwlimit;

/* Name of current file being transferred. */
var_na *curfile;

/* This is set to non-zero to enable verbose mode. */
පූර්ණ_සංඛ්‍යා verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
පූර්ණ_සංඛ්‍යා showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
පූර්ණ_සංඛ්‍යා throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
පූර්ණ_සංඛ්‍යා sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
var_na *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
ca_ncala sig_atomic_t interrupted = 0;

පූර්ණ_සංඛ්‍යා sftp_glob(sa_nracanaa sftp_conn *, const var_na *, පූර්ණ_සංඛ්‍යා,
    පූර්ණ_සංඛ්‍යා (*)(const var_na *, පූර්ණ_සංඛ්‍යා), glob_t *); /* proto for sftp-glob.c */

static void
killchild(පූර්ණ_සංඛ්‍යා signo)
{
	නම් (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid, NULL, 0);
	}
	නම් (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid2, NULL, 0);
	}

	නම් (signo)
		_exit(1);
	exit(1);
}

static void
suspone(පූර්ණ_සංඛ්‍යා pid, පූර්ණ_සංඛ්‍යා signo)
{
	පූර්ණ_සංඛ්‍යා status;

	නම් (pid > 1) {
		kill(pid, signo);
		අතරතුර (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

static void
suspchild(පූර්ණ_සංඛ්‍යා signo)
{
	පූර්ණ_සංඛ්‍යා save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static පූර්ණ_සංඛ්‍යා
do_local_cmd(arglist *a)
{
	var_na *cp;
	පූර්ණ_සංඛ්‍යා status;
	pid_t pid;

	නම් (a->num == 0)
		fatal("do_local_cmd: no arguments");

	නම් (verbose_mode) {
		cp = argv_assemble(a->num, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		free(cp);
	}
	නම් ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	නම් (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	අතරතුර (waitpid(pid, &status, 0) == -1)
		නම් (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	නම් (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ආපසු (-1);

	ආපසු (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

පූර්ණ_සංඛ්‍යා
do_cmd(var_na *program, var_na *host, var_na *remuser, පූර්ණ_සංඛ්‍යා port, පූර්ණ_සංඛ්‍යා subsystem,
    var_na *cmd, පූර්ණ_සංඛ්‍යා *fdin, පූර්ණ_සංඛ්‍යා *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	පූර්ණ_සංඛ්‍යා pin[2], pout[2];
#නැතහොත්
	පූර්ණ_සංඛ්‍යා sv[2];
#endif

	නම් (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	නම් (port == -1)
		port = sshport;

#ifdef USE_PIPES
	නම් (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#නැතහොත්
	/* Create a socket pair for communicating with ssh. */
	නම් (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	switch (*pid) {
	pak_sa -1:
		fatal("fork: %s", strerror(errno));
	pak_sa 0:
		/* Child. */
#ifdef USE_PIPES
		නම් (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#නැතහොත්
		නම් (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		නම් (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		නම් (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		නම් (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	default:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#නැතහොත්
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		ආපසු 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
පූර්ණ_සංඛ්‍යා
do_cmd2(var_na *host, var_na *remuser, පූර්ණ_සංඛ්‍යා port, var_na *cmd,
    පූර්ණ_සංඛ්‍යා fdin, පූර්ණ_සංඛ්‍යා fdout)
{
	පූර්ණ_සංඛ්‍යා status;
	pid_t pid;

	නම් (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	නම් (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	නම් (pid == 0) {
		නම් (dup2(fdin, 0) == -1)
			perror("dup2");
		නම් (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		නම් (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		නම් (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		addargs(&args, "-oBatchMode=yes");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(ssh_program, args.list);
		perror(ssh_program);
		exit(1);
	} නැතහොත් නම් (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	අතරතුර (waitpid(pid, &status, 0) == -1)
		නම් (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	ආපසු 0;
}

typedef sa_nracanaa {
	size_t cnt;
	var_na *buf;
} BUF;

BUF *allocbuf(BUF *, පූර්ණ_සංඛ්‍යා, පූර්ණ_සංඛ්‍යා);
void lostconn(පූර්ණ_සංඛ්‍යා);
පූර්ණ_සංඛ්‍යා okname(var_na *);
void run_err(const var_na *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
පූර්ණ_සංඛ්‍යා note_err(const var_na *,...)
    __attribute__((__format__ (printf, 1, 2)));
void verifydir(var_na *);

sa_nracanaa passwd *pwd;
uid_t userid;
පූර්ණ_සංඛ්‍යා errs, remin, remout, remin2, remout2;
පූර්ණ_සංඛ්‍යා Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
var_na cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

ga_nanaa scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

පූර්ණ_සංඛ්‍යා response(void);
void rsource(var_na *, sa_nracanaa stat *);
void sink(පූර්ණ_සංඛ්‍යා, var_na *[], const var_na *);
void source(පූර්ණ_සංඛ්‍යා, var_na *[]);
void tolocal(පූර්ණ_සංඛ්‍යා, var_na *[], ga_nanaa scp_mode_e, var_na *sftp_direct);
void toremote(පූර්ණ_සංඛ්‍යා, var_na *[], ga_nanaa scp_mode_e, var_na *sftp_direct);
void usage(void);

void source_sftp(පූර්ණ_සංඛ්‍යා, var_na *, var_na *, sa_nracanaa sftp_conn *);
void sink_sftp(පූර්ණ_සංඛ්‍යා, var_na *, const var_na *, sa_nracanaa sftp_conn *);
void throughlocal_sftp(sa_nracanaa sftp_conn *, sa_nracanaa sftp_conn *,
    var_na *, var_na *);

පූර්ණ_සංඛ්‍යා
main(පූර්ණ_සංඛ්‍යා argc, var_na **argv)
{
	පූර්ණ_සංඛ්‍යා ch, fflag, tflag, status, r, n;
	var_na **newargv, *argv0;
	const var_na *errstr;
	extern var_na *optarg;
	extern පූර්ණ_සංඛ්‍යා optind;
	ga_nanaa scp_mode_e mode = MODE_SFTP;
	var_na *sftp_direct = NULL;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), parimaa_na(*newargv));
	සඳහා (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', parimaa_na(args));
	memset(&remote_remote_args, '\0', parimaa_na(remote_remote_args));
	args.list = remote_remote_args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	අතරතුර ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		switch (ch) {
		/* User-visible flags. */
		pak_sa '1':
			fatal("SSH protocol v.1 is no longer supported");
			bha_nga;
		pak_sa '2':
			/* Ignored */
			bha_nga;
		pak_sa 'A':
		pak_sa '4':
		pak_sa '6':
		pak_sa 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			bha_nga;
		pak_sa 'D':
			sftp_direct = optarg;
			bha_nga;
		pak_sa '3':
			throughlocal = 1;
			bha_nga;
		pak_sa 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			bha_nga;
		pak_sa 'o':
		pak_sa 'c':
		pak_sa 'i':
		pak_sa 'F':
		pak_sa 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			bha_nga;
		pak_sa 'O':
			mode = MODE_SCP;
			bha_nga;
		pak_sa 's':
			/* Ignored */
			bha_nga;
		pak_sa 'P':
			sshport = a2port(optarg);
			නම් (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			bha_nga;
		pak_sa 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			bha_nga;
		pak_sa 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			නම් (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			bha_nga;
		pak_sa 'p':
			pflag = 1;
			bha_nga;
		pak_sa 'r':
			iamrecursive = 1;
			bha_nga;
		pak_sa 'S':
			ssh_program = xstrdup(optarg);
			bha_nga;
		pak_sa 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			නම් (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			නැතහොත් නම් (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			bha_nga;
		pak_sa 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			bha_nga;
		pak_sa 'X':
			/* Please keep in sync with sftp.c -X */
			නම් (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				නම් (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				නම් (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} නැතහොත් නම් (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				නම් (errstr != NULL) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} නැතහොත් {
				fatal("Invalid -X option");
			}
			bha_nga;

		/* Server options. */
		pak_sa 'd':
			targetshouldbedirectory = 1;
			bha_nga;
		pak_sa 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			bha_nga;
		pak_sa 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_BINARY);
#endif
			bha_nga;
		pak_sa 'T':
			Tflag = 1;
			bha_nga;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	නම් (iamremote)
		mode = MODE_SCP;

	නම් ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);

	නම් (!isatty(STDOUT_FILENO))
		showprogress = 0;

	නම් (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} නැතහොත් {
		නම් (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	නම් (fflag) {
		/* Follow "protocol", send data. */
		(void) response();
		source(argc, argv);
		exit(errs != 0);
	}
	නම් (tflag) {
		/* Receive data. */
		sink(argc, argv, NULL);
		exit(errs != 0);
	}
	නම් (argc < 2)
		usage();
	නම් (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(void) snprintf(cmd, parimaa_na cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(void) ssh_signal(SIGPIPE, lostconn);

	නම් (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	නැතහොත් {
		නම් (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	නම් (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		නම් (remin != -1)
		    (void) close(remin);
		නම් (remout != -1)
		    (void) close(remout);
		නම් (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		නැතහොත් {
			නම් (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
static පූර්ණ_සංඛ්‍යා
scpio(void *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	නම් (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
do_times(පූර්ණ_සංඛ්‍යා fd, පූර්ණ_සංඛ්‍යා verb, const sa_nracanaa stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	var_na buf[(20 + 7 + 2) * 2 + 2];

	(void)snprintf(buf, parimaa_na(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	නම් (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(void) atomicio(vwrite, fd, buf, strlen(buf));
	ආපසු (response());
}

static පූර්ණ_සංඛ්‍යා
parse_scp_uri(const var_na *uri, var_na **userp, var_na **hostp, පූර්ණ_සංඛ්‍යා *portp,
    var_na **pathp)
{
	පූර්ණ_සංඛ්‍යා r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	නම් (r == 0 && *pathp == NULL)
		*pathp = xstrdup(".");
	ආපසු r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
static පූර්ණ_සංඛ්‍යා
append(var_na *cp, var_na ***ap, size_t *np)
{
	var_na **tmp;

	නම් ((tmp = reallocarray(*ap, *np + 1, parimaa_na(*tmp))) == NULL)
		ආපසු -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	ආපසු 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
static පූර්ණ_සංඛ්‍යා
find_brace(const var_na *pattern, පූර්ණ_සංඛ්‍යා *startp, පූර්ණ_සංඛ්‍යා *endp)
{
	පූර්ණ_සංඛ්‍යා i;
	පූර්ණ_සංඛ්‍යා in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	සඳහා (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		switch (pattern[i]) {
		pak_sa '\\':
			/* skip next character */
			නම් (pattern[i + 1] != '\0')
				i++;
			bha_nga;
		pak_sa '[':
			in_bracket = 1;
			bha_nga;
		pak_sa ']':
			in_bracket = 0;
			bha_nga;
		pak_sa '{':
			නම් (in_bracket)
				bha_nga;
			නම් (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				bha_nga;
			}
			නම් (*startp == -1)
				*startp = i;
			brace_level++;
			bha_nga;
		pak_sa '}':
			නම් (in_bracket)
				bha_nga;
			නම් (*startp < 0) {
				/* Unbalanced brace */
				ආපසු -1;
			}
			නම් (--brace_level <= 0)
				*endp = i;
			bha_nga;
		}
	}
	/* unbalanced brackets/braces */
	නම් (*endp < 0 && (*startp >= 0 || in_bracket))
		ආපසු -1;
	ආපසු 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
static පූර්ණ_සංඛ්‍යා
emit_expansion(const var_na *pattern, පූර්ණ_සංඛ්‍යා brace_start, පූර්ණ_සංඛ්‍යා brace_end,
    පූර්ණ_සංඛ්‍යා sel_start, පූර්ණ_සංඛ්‍යා sel_end, var_na ***patternsp, size_t *npatternsp)
{
	var_na *cp;
	size_t pattern_len;
	පූර්ණ_සංඛ්‍යා o = 0, tail_len;

	නම් ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		ආපසු -1;

	tail_len = strlen(pattern + brace_end + 1);
	නම් ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == NULL)
		ආපසු -1;

	/* Pattern before initial brace */
	නම් (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	නම් (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	නම් (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	නම් (append(cp, patternsp, npatternsp) != 0) {
		free(cp);
		ආපසු -1;
	}
	ආපසු 0;
}

/*
 * Expand the first encountered brace in pattern, appending the expanded
 * patterns it yielded to the *patternsp array.
 *
 * Returns 0 on success or -1 on allocation failure.
 *
 * Signals whether expansion was performed via *expanded and whether
 * pattern was invalid via *invalid.
 */
static පූර්ණ_සංඛ්‍යා
brace_expand_one(const var_na *pattern, var_na ***patternsp, size_t *npatternsp,
    පූර්ණ_සංඛ්‍යා *expanded, පූර්ණ_සංඛ්‍යා *invalid)
{
	පූර්ණ_සංඛ්‍යා i;
	පූර්ණ_සංඛ්‍යා in_bracket, brace_start, brace_end, brace_level;
	පූර්ණ_සංඛ්‍යා sel_start, sel_end;

	*invalid = *expanded = 0;

	නම් (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		ආපසු 0;
	} නැතහොත් නම් (brace_start == -1)
		ආපසු 0;

	in_bracket = brace_level = 0;
	සඳහා (i = sel_start = brace_start + 1; i < brace_end; i++) {
		switch (pattern[i]) {
		pak_sa '{':
			නම් (in_bracket)
				bha_nga;
			brace_level++;
			bha_nga;
		pak_sa '}':
			නම් (in_bracket)
				bha_nga;
			brace_level--;
			bha_nga;
		pak_sa '[':
			in_bracket = 1;
			bha_nga;
		pak_sa ']':
			in_bracket = 0;
			bha_nga;
		pak_sa '\\':
			නම් (i < brace_end - 1)
				i++; /* skip */
			bha_nga;
		}
		නම් (pattern[i] == ',' || i == brace_end - 1) {
			නම් (in_bracket || brace_level > 0)
				continue;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			නම් (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				ආපසු -1;
			/* move on to the next selection */
			sel_start = i + 1;
			continue;
		}
	}
	නම් (in_bracket || brace_level > 0) {
		*invalid = 1;
		ආපසු 0;
	}
	/* success */
	*expanded = 1;
	ආපසු 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
static පූර්ණ_සංඛ්‍යා
brace_expand(const var_na *pattern, var_na ***patternsp, size_t *npatternsp)
{
	var_na *cp, *cp2, **active = NULL, **done = NULL;
	size_t i, nactive = 0, ndone = 0;
	පූර්ණ_සංඛ්‍යා ret = -1, invalid = 0, expanded = 0;

	*patternsp = NULL;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	නම් ((cp = strdup(pattern)) == NULL)
		ආපසු -1;
	නම් (append(cp, &active, &nactive) != 0) {
		free(cp);
		ආපසු -1;
	}
	අතරතුර (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		නම් (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			free(cp);
			goto fail;
		}
		නම් (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		නම් (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			free(cp);
			continue;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		නම් ((cp2 = strrchr(cp, '/')) != NULL)
			*cp2++ = '\0';
		නැතහොත්
			cp2 = cp;
		නම් (append(xstrdup(cp2), &done, &ndone) != 0) {
			free(cp);
			goto fail;
		}
		free(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = NULL;
	ndone = 0;
	ret = 0;
 fail:
	සඳහා (i = 0; i < nactive; i++)
		free(active[i]);
	free(active);
	සඳහා (i = 0; i < ndone; i++)
		free(done[i]);
	free(done);
	ආපසු ret;
}

static sa_nracanaa sftp_conn *
do_sftp_connect(var_na *host, var_na *user, පූර්ණ_සංඛ්‍යා port, var_na *sftp_direct,
   පූර්ණ_සංඛ්‍යා *reminp, පූර්ණ_සංඛ්‍යා *remoutp, පූර්ණ_සංඛ්‍යා *pidp)
{
	නම් (sftp_direct == NULL) {
		නම් (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			ආපසු NULL;

	} නැතහොත් {
		freeargs(&args);
		addargs(&args, "sftp-server");
		නම් (do_cmd(sftp_direct, host, NULL, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			ආපසු NULL;
	}
	ආපසු sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

void
toremote(පූර්ණ_සංඛ්‍යා argc, var_na **argv, ga_nanaa scp_mode_e mode, var_na *sftp_direct)
{
	var_na *suser = NULL, *host = NULL, *src = NULL;
	var_na *bp, *tuser, *thost, *targ;
	පූර්ණ_සංඛ්‍යා sport = -1, tport = -1;
	sa_nracanaa sftp_conn *conn = NULL, *conn2 = NULL;
	arglist alist;
	පූර්ණ_සංඛ්‍යා i, r, status;
	sa_nracanaa stat sb;
	u_int j;

	memset(&alist, '\0', parimaa_na(alist));
	alist.list = NULL;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	නම් (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		goto out;
	}
	නම් (r != 0) {
		නම් (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			goto out;
		}
	}

	/* Parse source files */
	සඳහා (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		නම් (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		නම් (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		නම් (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		නම් (host && throughlocal) {	/* extended remote to remote */
			නම් (mode == MODE_SFTP) {
				නම් (remin == -1 || conn == NULL) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					නම් (conn == NULL) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (long)do_cmd_pid);
				}
				/*
				 * XXX remember suser/host/sport and only
				 * reconnect if they change between arguments.
				 * would save reconnections for cases like
				 * scp -3 hosta:/foo hosta:/bar hostb:
				 */
				/* Connect to origin now */
				sftp_free(conn2);
				conn2 = do_sftp_connect(host, suser,
				    sport, sftp_direct,
				    &remin2, &remout2, &do_cmd_pid2);
				නම් (conn2 == NULL) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(void) close(remin2);
				(void) close(remout2);
				remin2 = remout2 = -1;
				නම් (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				නැතහොත් නම් (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				continue;
			} නැතහොත් {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				නම් (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				free(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				නම් (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				free(bp);
				(void) close(remin);
				(void) close(remout);
				remin = remout = -1;
			}
		} නැතහොත් නම් (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			නම් (tuser != NULL && !okname(tuser)) {
				++errs;
				continue;
			}
			නම් (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			සඳහා (j = 0; j < remote_remote_args.num; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			නම් (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			නම් (suser) {
				addargs(&alist, "-l");
				addargs(&alist, "%s", suser);
			}
			addargs(&alist, "--");
			addargs(&alist, "%s", host);
			addargs(&alist, "%s", cmd);
			addargs(&alist, "%s", src);
			addargs(&alist, "%s%s%s:%s",
			    tuser ? tuser : "", tuser ? "@" : "",
			    thost, targ);
			නම් (do_local_cmd(&alist) != 0)
				errs = 1;
		} නැතහොත් {	/* local to remote */
			නම් (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				නම් (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				නම් (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					නම් (conn == NULL) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				continue;
			}
			/* SCP */
			නම් (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				නම් (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				නම් (response() < 0)
					exit(1);
				free(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	free(tuser);
	free(thost);
	free(targ);
	free(suser);
	free(host);
	free(src);
	sftp_free(conn);
	sftp_free(conn2);
}

void
tolocal(පූර්ණ_සංඛ්‍යා argc, var_na **argv, ga_nanaa scp_mode_e mode, var_na *sftp_direct)
{
	var_na *bp, *host = NULL, *src = NULL, *suser = NULL;
	arglist alist;
	sa_nracanaa sftp_conn *conn = NULL;
	පූර්ණ_සංඛ්‍යා i, r, sport = -1;

	memset(&alist, '\0', parimaa_na(alist));
	alist.list = NULL;

	සඳහා (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		නම් (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		නම් (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		නම් (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		නම් (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			නම් (iamrecursive)
				addargs(&alist, "-r");
			නම් (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			නම් (do_local_cmd(&alist))
				++errs;
			continue;
		}
		/* Remote to local. */
		නම් (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			නම් (conn == NULL) {
				error("sftp connection failed");
				++errs;
				continue;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(void) close(remin);
			(void) close(remout);
			remin = remout = -1;
			continue;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		නම් (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			free(bp);
			++errs;
			continue;
		}
		free(bp);
		sink(1, argv + argc - 1, src);
		(void) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	free(suser);
	free(host);
	free(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
static var_na *
prepare_remote_path(sa_nracanaa sftp_conn *conn, const var_na *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	නම් (*path == '\0' || strcmp(path, "~") == 0)
		ආපසු xstrdup(".");
	නම් (*path != '~')
		ආපසු xstrdup(path);
	නම් (strncmp(path, "~/", 2) == 0) {
		නම් ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			ආපසු xstrdup(".");
		ආපසු xstrdup(path + 2 + nslash);
	}
	නම් (sftp_can_expand_path(conn))
		ආපසු sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	ආපසු NULL;
}

void
source_sftp(පූර්ණ_සංඛ්‍යා argc, var_na *src, var_na *targ, sa_nracanaa sftp_conn *conn)
{
	var_na *target = NULL, *filename = NULL, *abs_dst = NULL;
	පූර්ණ_සංඛ්‍යා src_is_dir, target_is_dir;
	Attrib a;
	sa_nracanaa stat st;

	memset(&a, '\0', parimaa_na(a));
	නම් (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	නම් ((filename = basename(src)) == NULL)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	නම් (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	නම් ((target = prepare_remote_path(conn, targ)) == NULL)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	නම් (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		නම් (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	නම් (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	නැතහොත් {
		abs_dst = target;
		target = NULL;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	නම් (src_is_dir && iamrecursive) {
		නම් (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} නැතහොත් නම් (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	free(abs_dst);
	free(target);
}

void
source(පූර්ණ_සංඛ්‍යා argc, var_na **argv)
{
	sa_nracanaa stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	පූර්ණ_සංඛ්‍යා fd = -1, haderr, indx;
	var_na *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	පූර්ණ_සංඛ්‍යා len;

	සඳහා (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		අතරතුර (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		නම් ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			goto syserr;
		නම් (strchr(name, '\n') != NULL) {
			strnvis(encname, name, parimaa_na(encname), VIS_NL);
			name = encname;
		}
		නම් (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			goto next;
		}
		නම් (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			goto next;
		}
		unset_nonblock(fd);
		switch (stb.st_mode & S_IFMT) {
		pak_sa S_IFREG:
			bha_nga;
		pak_sa S_IFDIR:
			නම් (iamrecursive) {
				rsource(name, &stb);
				goto next;
			}
			/* FALLTHROUGH */
		default:
			run_err("%s: not a regular file", name);
			goto next;
		}
		නම් ((last = strrchr(name, '/')) == NULL)
			last = name;
		නැතහොත්
			++last;
		curfile = last;
		නම් (pflag) {
			නම් (do_times(remout, verbose_mode, &stb) < 0)
				goto next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, parimaa_na buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		නම් (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(void) atomicio(vwrite, remout, buf, strlen(buf));
		නම් (response() < 0)
			goto next;
		නම් ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == NULL) {
next:			නම් (fd != -1) {
				(void) close(fd);
				fd = -1;
			}
			continue;
		}
		නම් (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		සඳහා (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			නම් (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			නම් (!haderr) {
				නම් ((nr = atomicio(read, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			නම් (haderr) {
				(void)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				continue;
			}
			නම් (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		නම් (fd != -1) {
			නම් (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		නම් (!haderr)
			(void) atomicio(vwrite, remout, "", 1);
		නැතහොත්
			run_err("%s: %s", name, strerror(haderr));
		(void) response();
		නම් (showprogress)
			stop_progress_meter();
	}
}

void
rsource(var_na *name, sa_nracanaa stat *statp)
{
	DIR *dirp;
	sa_nracanaa dirent *dp;
	var_na *last, *vect[1], path[PATH_MAX];

	නම් (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		ආපසු;
	}
	last = strrchr(name, '/');
	නම් (last == NULL)
		last = name;
	නැතහොත්
		last++;
	නම් (pflag) {
		නම් (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			ආපසු;
		}
	}
	(void) snprintf(path, parimaa_na path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	නම් (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(void) atomicio(vwrite, remout, path, strlen(path));
	නම් (response() < 0) {
		closedir(dirp);
		ආපසු;
	}
	අතරතුර ((dp = readdir(dirp)) != NULL) {
		නම් (dp->d_ino == 0)
			continue;
		නම් (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		නම් (strlen(name) + 1 + strlen(dp->d_name) >= parimaa_na(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			continue;
		}
		(void) snprintf(path, parimaa_na path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(void) closedir(dirp);
	(void) atomicio(vwrite, remout, "E\n", 2);
	(void) response();
}

void
sink_sftp(පූර්ණ_සංඛ්‍යා argc, var_na *dst, const var_na *src, sa_nracanaa sftp_conn *conn)
{
	var_na *abs_src = NULL;
	var_na *abs_dst = NULL;
	glob_t g;
	var_na *filename, *tmp = NULL;
	පූර්ණ_සංඛ්‍යා i, r, err = 0, dst_is_dir;
	sa_nracanaa stat st;

	memset(&g, 0, parimaa_na(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	නම් ((abs_src = prepare_remote_path(conn, src)) == NULL) {
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	නම් ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		නම් (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		නැතහොත්
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	නම් (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		නම් (sftp_stat(conn, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	නම් ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	නම් (g.gl_matchc > 1 && !dst_is_dir) {
		නම් (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			goto out;
		}
		debug2_f("creating destination \"%s\"", dst);
		නම් (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			goto out;
		}
		dst_is_dir = 1;
	}

	සඳහා (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		නම් ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for destination of '..' */
		නම් (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		නම් (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		නැතහොත්
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		නම් (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			නම් (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} නැතහොත් {
			නම් (sftp_download(conn, g.gl_pathv[i], abs_dst, NULL,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		free(abs_dst);
		abs_dst = NULL;
		free(tmp);
		tmp = NULL;
	}

out:
	free(abs_src);
	free(tmp);
	globfree(&g);
	නම් (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((parimaa_na(type) == 4 && (val) > INT32_MAX) || \
	 (parimaa_na(type) == 8 && (val) > INT64_MAX) || \
	 (parimaa_na(type) != 4 && parimaa_na(type) != 8))

void
sink(පූර්ණ_සංඛ්‍යා argc, var_na **argv, const var_na *src)
{
	static BUF buffer;
	sa_nracanaa stat stb;
	BUF *bp;
	off_t i;
	size_t j, count;
	පූර්ණ_සංඛ්‍යා amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	පූර්ණ_සංඛ්‍යා setimes, targisdir, wrerr;
	var_na ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	var_na **patterns = NULL;
	size_t n, npatterns = 0;
	sa_nracanaa timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	නම් (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	නම් (!pflag) {
		(void) umask(mask);
		mask |= 07000;
	}
	නම් (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	නම් (targetshouldbedirectory)
		verifydir(targ);

	(void) atomicio(vwrite, remout, "", 1);
	නම් (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	නම් (src != NULL && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		නම් (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	සඳහා (first = 1;; first = 0) {
		cp = buf;
		නම් (atomicio(read, remin, cp, 1) != 1)
			goto done;
		නම් (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			නම් (atomicio(read, remin, &ch, parimaa_na(ch)) != parimaa_na(ch))
				SCREWUP("lost connection");
			නම් (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} අතරතුර (cp < &buf[parimaa_na(buf) - 1] && ch != '\n');
		*cp = 0;
		නම් (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		නම් (buf[0] == '\01' || buf[0] == '\02') {
			නම් (iamremote == 0) {
				(void) snmprintf(visbuf, parimaa_na(visbuf),
				    NULL, "%s", buf + 1);
				(void) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			නම් (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		නම් (buf[0] == 'E') {
			(void) atomicio(vwrite, remout, "", 1);
			goto done;
		}
		නම් (ch == '\n')
			*--cp = 0;

		cp = buf;
		නම් (*cp == 'T') {
			setimes++;
			cp++;
			නම් (!isdigit((unsigned var_na)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			නම් (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			නම් (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			නම් (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			නම් (!isdigit((unsigned var_na)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			නම් (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			නම් (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			නම් (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(void) atomicio(vwrite, remout, "", 1);
			continue;
		}
		නම් (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			නම් (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		සඳහා (++cp; cp < buf + 5; cp++) {
			නම් (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		නම් (!pflag)
			mode &= ~mask;
		නම් (*cp++ != ' ')
			SCREWUP("mode not delimited");

		නම් (!isdigit((unsigned var_na)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		නම් (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		නම් (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		නම් (*cp == '\0' || strchr(cp, '/') != NULL ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		නම් (npatterns > 0) {
			සඳහා (n = 0; n < npatterns; n++) {
				නම් (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					bha_nga;
			}
			නම් (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				සඳහා (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		නම් (targisdir) {
			static var_na *namebuf;
			static size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			නම් (need > cursize) {
				free(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} නැතහොත්
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		නම් (buf[0] == 'D') {
			පූර්ණ_සංඛ්‍යා mod_flag = pflag;
			නම් (!iamrecursive)
				SCREWUP("received directory without -r");
			නම් (exists) {
				නම් (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					goto bad;
				}
				නම් (pflag)
					(void) chmod(np, mode);
			} නැතහොත් {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				නම් (mkdir(np, mode | S_IRWXU) == -1)
					goto bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			නම් (setimes) {
				setimes = 0;
				(void) utimes(vect[0], tv);
			}
			නම් (mod_flag)
				(void) chmod(vect[0], mode);
			free(vect[0]);
			continue;
		}
		omode = mode;
		mode |= S_IWUSR;
		නම් ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
		(void) atomicio(vwrite, remout, "", 1);
		නම් ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == NULL) {
			(void) close(ofd);
			continue;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		නම් (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		සඳහා (count = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			නම් (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = atomicio6(read, remin, cp, amt,
				    scpio, &statbytes);
				නම් (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} අතරතුර (amt > 0);

			නම් (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				නම් (!wrerr) {
					නම් (atomicio(vwrite, ofd, bp->buf,
					    count) != count) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				count = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		නම් (count != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, count) != count) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		නම් (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		නම් (pflag) {
			නම් (exists || omode != mode)
#ifdef HAVE_FCHMOD
				නම් (fchmod(ofd, omode)) {
#නැතහොත් /* HAVE_FCHMOD */
				නම් (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} නැතහොත් {
			නම් (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				නම් (fchmod(ofd, omode & ~mask)) {
#නැතහොත් /* HAVE_FCHMOD */
				නම් (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		නම් (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(void) response();
		නම් (showprogress)
			stop_progress_meter();
		නම් (setimes && !wrerr) {
			setimes = 0;
			නම් (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		නම් (note_err(NULL) == 0)
			(void) atomicio(vwrite, remout, "", 1);
	}
done:
	සඳහා (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	ආපසු;
screwup:
	සඳහා (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

void
throughlocal_sftp(sa_nracanaa sftp_conn *from, sa_nracanaa sftp_conn *to,
    var_na *src, var_na *targ)
{
	var_na *target = NULL, *filename = NULL, *abs_dst = NULL;
	var_na *abs_src = NULL, *tmp = NULL;
	glob_t g;
	පූර්ණ_සංඛ්‍යා i, r, targetisdir, err = 0;

	නම් ((filename = basename(src)) == NULL)
		fatal("basename %s: %s", src, strerror(errno));

	නම් ((abs_src = prepare_remote_path(from, src)) == NULL ||
	    (target = prepare_remote_path(to, targ)) == NULL)
		cleanup_exit(255);
	memset(&g, 0, parimaa_na(g));

	targetisdir = sftp_remote_is_dir(to, target);
	නම් (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	නම් ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		නම් (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		නැතහොත්
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	නම් (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		නම් (sftp_stat(from, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	සඳහා (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		නම් ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for source of '..' */
		නම් (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		නම් (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		නැතහොත්
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		නම් (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			නම් (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    NULL, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} නැතහොත් {
			නම් (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    NULL, pflag) == -1)
				err = -1;
		}
		free(abs_dst);
		abs_dst = NULL;
		free(tmp);
		tmp = NULL;
	}

out:
	free(abs_src);
	free(abs_dst);
	free(target);
	free(tmp);
	globfree(&g);
	නම් (err == -1)
		errs = 1;
}

පූර්ණ_සංඛ්‍යා
response(void)
{
	var_na ch, *cp, resp, rbuf[2048], visbuf[2048];

	නම් (atomicio(read, remin, &resp, parimaa_na(resp)) != parimaa_na(resp))
		lostconn(0);

	cp = rbuf;
	switch (resp) {
	pak_sa 0:		/* ok */
		ආපසු (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	pak_sa 1:		/* error, followed by error msg */
	pak_sa 2:		/* fatal error, "" */
		do {
			නම් (atomicio(read, remin, &ch, parimaa_na(ch)) != parimaa_na(ch))
				lostconn(0);
			*cp++ = ch;
		} අතරතුර (cp < &rbuf[parimaa_na(rbuf) - 1] && ch != '\n');

		නම් (!iamremote) {
			cp[-1] = '\0';
			(void) snmprintf(visbuf, parimaa_na(visbuf),
			    NULL, "%s\n", rbuf);
			(void) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		නම් (resp == 1)
			ආපසු (-1);
		exit(1);
	}
	/* NOTREACHED */
}

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

void
run_err(const var_na *fmt,...)
{
	static FILE *fp;
	va_list ap;

	++errs;
	නම් (fp != NULL || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(void) fprintf(fp, "%c", 0x01);
		(void) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(void) vfprintf(fp, fmt, ap);
		va_end(ap);
		(void) fprintf(fp, "\n");
		(void) fflush(fp);
	}

	නම් (!iamremote) {
		va_start(ap, fmt);
		vfmprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

/*
 * Notes a sink error for sending at the end of a file transfer. Returns 0 if
 * no error has been noted or -1 otherwise. Use note_err(NULL) to flush
 * any active error at the end of the transfer.
 */
පූර්ණ_සංඛ්‍යා
note_err(const var_na *fmt, ...)
{
	static var_na *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	නම් (fmt == NULL) {
		නම් (emsg == NULL)
			ආපසු 0;
		run_err("%s", emsg);
		free(emsg);
		emsg = NULL;
		ආපසු -1;
	}

	errs++;
	/* Prefer first-noted error */
	නම් (emsg != NULL)
		ආපසු -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, NULL, fmt, ap);
	va_end(ap);
	ආපසු -1;
}

void
verifydir(var_na *cp)
{
	sa_nracanaa stat stb;

	නම් (!stat(cp, &stb)) {
		නම් (S_ISDIR(stb.st_mode))
			ආපසු;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

පූර්ණ_සංඛ්‍යා
okname(var_na *cp0)
{
	පූර්ණ_සංඛ්‍යා c;
	var_na *cp;

	cp = cp0;
	do {
		c = (පූර්ණ_සංඛ්‍යා)*cp;
		නම් (c & 0200)
			goto bad;
		නම් (!isalpha(c) && !isdigit((unsigned var_na)c)) {
			switch (c) {
			pak_sa '\'':
			pak_sa '"':
			pak_sa '`':
			pak_sa ' ':
			pak_sa '#':
				goto bad;
			default:
				bha_nga;
			}
		}
	} අතරතුර (*++cp);
	ආපසු (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	ආපසු (0);
}

BUF *
allocbuf(BUF *bp, පූර්ණ_සංඛ්‍යා fd, පූර්ණ_සංඛ්‍යා blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	sa_nracanaa stat stb;

	නම් (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		ආපසු (NULL);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	නම් (size == 0)
		size = blksize;
#නැතහොත් /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	නම් (bp->cnt >= size)
		ආපසු (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	ආපසු (bp);
}

void
lostconn(පූර්ණ_සංඛ්‍යා signo)
{
	නම් (!iamremote)
		(void)write(STDERR_FILENO, "lost connection\n", 16);
	නම් (signo)
		_exit(1);
	නැතහොත්
		exit(1);
}

void
cleanup_exit(පූර්ණ_සංඛ්‍යා i)
{
	නම් (remin > 0)
		close(remin);
	නම් (remout > 0)
		close(remout);
	නම් (remin2 > 0)
		close(remin2);
	නම් (remout2 > 0)
		close(remout2);
	නම් (do_cmd_pid > 0)
		(void)waitpid(do_cmd_pid, NULL, 0);
	නම් (do_cmd_pid2 > 0)
		(void)waitpid(do_cmd_pid2, NULL, 0);
	exit(i);
}
