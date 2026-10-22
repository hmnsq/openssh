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
#ᰀᰧ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
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

puur_naa_nka do_cmd(var_na *, var_na *, var_na *, puur_naa_nka, puur_naa_nka, var_na *, puur_naa_nka *, puur_naa_nka *, pid_t *);
puur_naa_nka do_cmd2(var_na *, var_na *, puur_naa_nka, var_na *, puur_naa_nka, puur_naa_nka);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
sa_nracanaa bwlimit bwlimit;

/* Name of current file being transferred. */
var_na *curfile;

/* This is set to non-zero to enable verbose mode. */
puur_naa_nka verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
puur_naa_nka showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
puur_naa_nka throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
puur_naa_nka sshport = -1;

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

puur_naa_nka sftp_glob(sa_nracanaa sftp_conn *, const var_na *, puur_naa_nka,
    puur_naa_nka (*)(const var_na *, puur_naa_nka), glob_t *); /* proto for sftp-glob.c */

static void
killchild(puur_naa_nka signo)
{
	ᰀᰧ (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid, NULL, 0);
	}
	ᰀᰧ (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid2, NULL, 0);
	}

	ᰀᰧ (signo)
		_exit(1);
	exit(1);
}

static void
suspone(puur_naa_nka pid, puur_naa_nka signo)
{
	puur_naa_nka status;

	ᰀᰧ (pid > 1) {
		kill(pid, signo);
		ᰀᰬ (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

static void
suspchild(puur_naa_nka signo)
{
	puur_naa_nka save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static puur_naa_nka
do_local_cmd(arglist *a)
{
	var_na *cp;
	puur_naa_nka status;
	pid_t pid;

	ᰀᰧ (a->num == 0)
		fatal("do_local_cmd: no arguments");

	ᰀᰧ (verbose_mode) {
		cp = argv_assemble(a->num, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		free(cp);
	}
	ᰀᰧ ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	ᰀᰧ (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	ᰀᰬ (waitpid(pid, &status, 0) == -1)
		ᰀᰧ (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	ᰀᰧ (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ᰀᰧᰌ (-1);

	ᰀᰧᰌ (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

puur_naa_nka
do_cmd(var_na *program, var_na *host, var_na *remuser, puur_naa_nka port, puur_naa_nka subsystem,
    var_na *cmd, puur_naa_nka *fdin, puur_naa_nka *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	puur_naa_nka pin[2], pout[2];
#ᰀᰧᰀ
	puur_naa_nka sv[2];
#endif

	ᰀᰧ (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ᰀᰧ (port == -1)
		port = sshport;

#ifdef USE_PIPES
	ᰀᰧ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#ᰀᰧᰀ
	/* Create a socket pair for communicating with ssh. */
	ᰀᰧ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
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
		ᰀᰧ (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#ᰀᰧᰀ
		ᰀᰧ (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		ᰀᰧ (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		ᰀᰧ (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		ᰀᰧ (subsystem)
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
#ᰀᰧᰀ
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		ᰀᰧᰌ 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
puur_naa_nka
do_cmd2(var_na *host, var_na *remuser, puur_naa_nka port, var_na *cmd,
    puur_naa_nka fdin, puur_naa_nka fdout)
{
	puur_naa_nka status;
	pid_t pid;

	ᰀᰧ (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ᰀᰧ (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	ᰀᰧ (pid == 0) {
		ᰀᰧ (dup2(fdin, 0) == -1)
			perror("dup2");
		ᰀᰧ (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		ᰀᰧ (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		ᰀᰧ (remuser != NULL) {
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
	} ᰀᰧᰀ ᰀᰧ (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	ᰀᰬ (waitpid(pid, &status, 0) == -1)
		ᰀᰧ (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	ᰀᰧᰌ 0;
}

typedef sa_nracanaa {
	size_t cnt;
	var_na *buf;
} BUF;

BUF *allocbuf(BUF *, puur_naa_nka, puur_naa_nka);
void lostconn(puur_naa_nka);
puur_naa_nka okname(var_na *);
void run_err(const var_na *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
puur_naa_nka note_err(const var_na *,...)
    __attribute__((__format__ (printf, 1, 2)));
void verifydir(var_na *);

sa_nracanaa passwd *pwd;
uid_t userid;
puur_naa_nka errs, remin, remout, remin2, remout2;
puur_naa_nka Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
var_na cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

ga_nanaa scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

puur_naa_nka response(void);
void rsource(var_na *, sa_nracanaa stat *);
void sink(puur_naa_nka, var_na *[], const var_na *);
void source(puur_naa_nka, var_na *[]);
void tolocal(puur_naa_nka, var_na *[], ga_nanaa scp_mode_e, var_na *sftp_direct);
void toremote(puur_naa_nka, var_na *[], ga_nanaa scp_mode_e, var_na *sftp_direct);
void usage(void);

void source_sftp(puur_naa_nka, var_na *, var_na *, sa_nracanaa sftp_conn *);
void sink_sftp(puur_naa_nka, var_na *, const var_na *, sa_nracanaa sftp_conn *);
void throughlocal_sftp(sa_nracanaa sftp_conn *, sa_nracanaa sftp_conn *,
    var_na *, var_na *);

puur_naa_nka
main(puur_naa_nka argc, var_na **argv)
{
	puur_naa_nka ch, fflag, tflag, status, r, n;
	var_na **newargv, *argv0;
	const var_na *errstr;
	extern var_na *optarg;
	extern puur_naa_nka optind;
	ga_nanaa scp_mode_e mode = MODE_SFTP;
	var_na *sftp_direct = NULL;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), parimaa_na(*newargv));
	for (n = 0; n < argc; n++)
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
	ᰀᰬ ((ch = getopt(argc, argv,
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
			ᰀᰧ (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			bha_nga;
		pak_sa 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			bha_nga;
		pak_sa 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ᰀᰧ (errstr != NULL)
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
			ᰀᰧ (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ᰀᰧᰀ ᰀᰧ (log_level < SYSLOG_LEVEL_DEBUG3)
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
			ᰀᰧ (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				ᰀᰧ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ᰀᰧ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} ᰀᰧᰀ ᰀᰧ (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ᰀᰧ (errstr != NULL) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} ᰀᰧᰀ {
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

	ᰀᰧ (iamremote)
		mode = MODE_SCP;

	ᰀᰧ ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);

	ᰀᰧ (!isatty(STDOUT_FILENO))
		showprogress = 0;

	ᰀᰧ (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} ᰀᰧᰀ {
		ᰀᰧ (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	ᰀᰧ (fflag) {
		/* Follow "protocol", send data. */
		(void) response();
		source(argc, argv);
		exit(errs != 0);
	}
	ᰀᰧ (tflag) {
		/* Receive data. */
		sink(argc, argv, NULL);
		exit(errs != 0);
	}
	ᰀᰧ (argc < 2)
		usage();
	ᰀᰧ (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(void) snprintf(cmd, parimaa_na cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(void) ssh_signal(SIGPIPE, lostconn);

	ᰀᰧ (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	ᰀᰧᰀ {
		ᰀᰧ (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	ᰀᰧ (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		ᰀᰧ (remin != -1)
		    (void) close(remin);
		ᰀᰧ (remout != -1)
		    (void) close(remout);
		ᰀᰧ (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		ᰀᰧᰀ {
			ᰀᰧ (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
static puur_naa_nka
scpio(void *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	ᰀᰧ (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	ᰀᰧᰌ 0;
}

static puur_naa_nka
do_times(puur_naa_nka fd, puur_naa_nka verb, const sa_nracanaa stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	var_na buf[(20 + 7 + 2) * 2 + 2];

	(void)snprintf(buf, parimaa_na(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	ᰀᰧ (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(void) atomicio(vwrite, fd, buf, strlen(buf));
	ᰀᰧᰌ (response());
}

static puur_naa_nka
parse_scp_uri(const var_na *uri, var_na **userp, var_na **hostp, puur_naa_nka *portp,
    var_na **pathp)
{
	puur_naa_nka r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	ᰀᰧ (r == 0 && *pathp == NULL)
		*pathp = xstrdup(".");
	ᰀᰧᰌ r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
static puur_naa_nka
append(var_na *cp, var_na ***ap, size_t *np)
{
	var_na **tmp;

	ᰀᰧ ((tmp = reallocarray(*ap, *np + 1, parimaa_na(*tmp))) == NULL)
		ᰀᰧᰌ -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	ᰀᰧᰌ 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
static puur_naa_nka
find_brace(const var_na *pattern, puur_naa_nka *startp, puur_naa_nka *endp)
{
	puur_naa_nka i;
	puur_naa_nka in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	for (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		switch (pattern[i]) {
		pak_sa '\\':
			/* skip next character */
			ᰀᰧ (pattern[i + 1] != '\0')
				i++;
			bha_nga;
		pak_sa '[':
			in_bracket = 1;
			bha_nga;
		pak_sa ']':
			in_bracket = 0;
			bha_nga;
		pak_sa '{':
			ᰀᰧ (in_bracket)
				bha_nga;
			ᰀᰧ (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				bha_nga;
			}
			ᰀᰧ (*startp == -1)
				*startp = i;
			brace_level++;
			bha_nga;
		pak_sa '}':
			ᰀᰧ (in_bracket)
				bha_nga;
			ᰀᰧ (*startp < 0) {
				/* Unbalanced brace */
				ᰀᰧᰌ -1;
			}
			ᰀᰧ (--brace_level <= 0)
				*endp = i;
			bha_nga;
		}
	}
	/* unbalanced brackets/braces */
	ᰀᰧ (*endp < 0 && (*startp >= 0 || in_bracket))
		ᰀᰧᰌ -1;
	ᰀᰧᰌ 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
static puur_naa_nka
emit_expansion(const var_na *pattern, puur_naa_nka brace_start, puur_naa_nka brace_end,
    puur_naa_nka sel_start, puur_naa_nka sel_end, var_na ***patternsp, size_t *npatternsp)
{
	var_na *cp;
	size_t pattern_len;
	puur_naa_nka o = 0, tail_len;

	ᰀᰧ ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		ᰀᰧᰌ -1;

	tail_len = strlen(pattern + brace_end + 1);
	ᰀᰧ ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == NULL)
		ᰀᰧᰌ -1;

	/* Pattern before initial brace */
	ᰀᰧ (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	ᰀᰧ (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	ᰀᰧ (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	ᰀᰧ (append(cp, patternsp, npatternsp) != 0) {
		free(cp);
		ᰀᰧᰌ -1;
	}
	ᰀᰧᰌ 0;
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
static puur_naa_nka
brace_expand_one(const var_na *pattern, var_na ***patternsp, size_t *npatternsp,
    puur_naa_nka *expanded, puur_naa_nka *invalid)
{
	puur_naa_nka i;
	puur_naa_nka in_bracket, brace_start, brace_end, brace_level;
	puur_naa_nka sel_start, sel_end;

	*invalid = *expanded = 0;

	ᰀᰧ (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		ᰀᰧᰌ 0;
	} ᰀᰧᰀ ᰀᰧ (brace_start == -1)
		ᰀᰧᰌ 0;

	in_bracket = brace_level = 0;
	for (i = sel_start = brace_start + 1; i < brace_end; i++) {
		switch (pattern[i]) {
		pak_sa '{':
			ᰀᰧ (in_bracket)
				bha_nga;
			brace_level++;
			bha_nga;
		pak_sa '}':
			ᰀᰧ (in_bracket)
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
			ᰀᰧ (i < brace_end - 1)
				i++; /* skip */
			bha_nga;
		}
		ᰀᰧ (pattern[i] == ',' || i == brace_end - 1) {
			ᰀᰧ (in_bracket || brace_level > 0)
				continue;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			ᰀᰧ (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				ᰀᰧᰌ -1;
			/* move on to the next selection */
			sel_start = i + 1;
			continue;
		}
	}
	ᰀᰧ (in_bracket || brace_level > 0) {
		*invalid = 1;
		ᰀᰧᰌ 0;
	}
	/* success */
	*expanded = 1;
	ᰀᰧᰌ 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
static puur_naa_nka
brace_expand(const var_na *pattern, var_na ***patternsp, size_t *npatternsp)
{
	var_na *cp, *cp2, **active = NULL, **done = NULL;
	size_t i, nactive = 0, ndone = 0;
	puur_naa_nka ret = -1, invalid = 0, expanded = 0;

	*patternsp = NULL;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	ᰀᰧ ((cp = strdup(pattern)) == NULL)
		ᰀᰧᰌ -1;
	ᰀᰧ (append(cp, &active, &nactive) != 0) {
		free(cp);
		ᰀᰧᰌ -1;
	}
	ᰀᰬ (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		ᰀᰧ (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			free(cp);
			goto fail;
		}
		ᰀᰧ (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		ᰀᰧ (expanded) {
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
		ᰀᰧ ((cp2 = strrchr(cp, '/')) != NULL)
			*cp2++ = '\0';
		ᰀᰧᰀ
			cp2 = cp;
		ᰀᰧ (append(xstrdup(cp2), &done, &ndone) != 0) {
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
	for (i = 0; i < nactive; i++)
		free(active[i]);
	free(active);
	for (i = 0; i < ndone; i++)
		free(done[i]);
	free(done);
	ᰀᰧᰌ ret;
}

static sa_nracanaa sftp_conn *
do_sftp_connect(var_na *host, var_na *user, puur_naa_nka port, var_na *sftp_direct,
   puur_naa_nka *reminp, puur_naa_nka *remoutp, puur_naa_nka *pidp)
{
	ᰀᰧ (sftp_direct == NULL) {
		ᰀᰧ (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			ᰀᰧᰌ NULL;

	} ᰀᰧᰀ {
		freeargs(&args);
		addargs(&args, "sftp-server");
		ᰀᰧ (do_cmd(sftp_direct, host, NULL, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			ᰀᰧᰌ NULL;
	}
	ᰀᰧᰌ sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

void
toremote(puur_naa_nka argc, var_na **argv, ga_nanaa scp_mode_e mode, var_na *sftp_direct)
{
	var_na *suser = NULL, *host = NULL, *src = NULL;
	var_na *bp, *tuser, *thost, *targ;
	puur_naa_nka sport = -1, tport = -1;
	sa_nracanaa sftp_conn *conn = NULL, *conn2 = NULL;
	arglist alist;
	puur_naa_nka i, r, status;
	sa_nracanaa stat sb;
	u_int j;

	memset(&alist, '\0', parimaa_na(alist));
	alist.list = NULL;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	ᰀᰧ (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		goto out;
	}
	ᰀᰧ (r != 0) {
		ᰀᰧ (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			goto out;
		}
	}

	/* Parse source files */
	for (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ᰀᰧ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		ᰀᰧ (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		ᰀᰧ (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		ᰀᰧ (host && throughlocal) {	/* extended remote to remote */
			ᰀᰧ (mode == MODE_SFTP) {
				ᰀᰧ (remin == -1 || conn == NULL) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					ᰀᰧ (conn == NULL) {
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
				ᰀᰧ (conn2 == NULL) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(void) close(remin2);
				(void) close(remout2);
				remin2 = remout2 = -1;
				ᰀᰧ (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				ᰀᰧᰀ ᰀᰧ (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				continue;
			} ᰀᰧᰀ {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				ᰀᰧ (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				free(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ᰀᰧ (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				free(bp);
				(void) close(remin);
				(void) close(remout);
				remin = remout = -1;
			}
		} ᰀᰧᰀ ᰀᰧ (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			ᰀᰧ (tuser != NULL && !okname(tuser)) {
				++errs;
				continue;
			}
			ᰀᰧ (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			for (j = 0; j < remote_remote_args.num; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			ᰀᰧ (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			ᰀᰧ (suser) {
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
			ᰀᰧ (do_local_cmd(&alist) != 0)
				errs = 1;
		} ᰀᰧᰀ {	/* local to remote */
			ᰀᰧ (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				ᰀᰧ (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				ᰀᰧ (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					ᰀᰧ (conn == NULL) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				continue;
			}
			/* SCP */
			ᰀᰧ (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ᰀᰧ (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				ᰀᰧ (response() < 0)
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
tolocal(puur_naa_nka argc, var_na **argv, ga_nanaa scp_mode_e mode, var_na *sftp_direct)
{
	var_na *bp, *host = NULL, *src = NULL, *suser = NULL;
	arglist alist;
	sa_nracanaa sftp_conn *conn = NULL;
	puur_naa_nka i, r, sport = -1;

	memset(&alist, '\0', parimaa_na(alist));
	alist.list = NULL;

	for (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ᰀᰧ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		ᰀᰧ (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		ᰀᰧ (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		ᰀᰧ (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			ᰀᰧ (iamrecursive)
				addargs(&alist, "-r");
			ᰀᰧ (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			ᰀᰧ (do_local_cmd(&alist))
				++errs;
			continue;
		}
		/* Remote to local. */
		ᰀᰧ (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			ᰀᰧ (conn == NULL) {
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
		ᰀᰧ (do_cmd(ssh_program, host, suser, sport, 0, bp,
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
	ᰀᰧ (*path == '\0' || strcmp(path, "~") == 0)
		ᰀᰧᰌ xstrdup(".");
	ᰀᰧ (*path != '~')
		ᰀᰧᰌ xstrdup(path);
	ᰀᰧ (strncmp(path, "~/", 2) == 0) {
		ᰀᰧ ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			ᰀᰧᰌ xstrdup(".");
		ᰀᰧᰌ xstrdup(path + 2 + nslash);
	}
	ᰀᰧ (sftp_can_expand_path(conn))
		ᰀᰧᰌ sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	ᰀᰧᰌ NULL;
}

void
source_sftp(puur_naa_nka argc, var_na *src, var_na *targ, sa_nracanaa sftp_conn *conn)
{
	var_na *target = NULL, *filename = NULL, *abs_dst = NULL;
	puur_naa_nka src_is_dir, target_is_dir;
	Attrib a;
	sa_nracanaa stat st;

	memset(&a, '\0', parimaa_na(a));
	ᰀᰧ (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	ᰀᰧ ((filename = basename(src)) == NULL)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	ᰀᰧ (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	ᰀᰧ ((target = prepare_remote_path(conn, targ)) == NULL)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	ᰀᰧ (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		ᰀᰧ (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	ᰀᰧ (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	ᰀᰧᰀ {
		abs_dst = target;
		target = NULL;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	ᰀᰧ (src_is_dir && iamrecursive) {
		ᰀᰧ (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} ᰀᰧᰀ ᰀᰧ (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	free(abs_dst);
	free(target);
}

void
source(puur_naa_nka argc, var_na **argv)
{
	sa_nracanaa stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	puur_naa_nka fd = -1, haderr, indx;
	var_na *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	puur_naa_nka len;

	for (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		ᰀᰬ (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		ᰀᰧ ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			goto syserr;
		ᰀᰧ (strchr(name, '\n') != NULL) {
			strnvis(encname, name, parimaa_na(encname), VIS_NL);
			name = encname;
		}
		ᰀᰧ (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			goto next;
		}
		ᰀᰧ (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			goto next;
		}
		unset_nonblock(fd);
		switch (stb.st_mode & S_IFMT) {
		pak_sa S_IFREG:
			bha_nga;
		pak_sa S_IFDIR:
			ᰀᰧ (iamrecursive) {
				rsource(name, &stb);
				goto next;
			}
			/* FALLTHROUGH */
		default:
			run_err("%s: not a regular file", name);
			goto next;
		}
		ᰀᰧ ((last = strrchr(name, '/')) == NULL)
			last = name;
		ᰀᰧᰀ
			++last;
		curfile = last;
		ᰀᰧ (pflag) {
			ᰀᰧ (do_times(remout, verbose_mode, &stb) < 0)
				goto next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, parimaa_na buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		ᰀᰧ (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(void) atomicio(vwrite, remout, buf, strlen(buf));
		ᰀᰧ (response() < 0)
			goto next;
		ᰀᰧ ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == NULL) {
next:			ᰀᰧ (fd != -1) {
				(void) close(fd);
				fd = -1;
			}
			continue;
		}
		ᰀᰧ (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		for (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			ᰀᰧ (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			ᰀᰧ (!haderr) {
				ᰀᰧ ((nr = atomicio(read, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			ᰀᰧ (haderr) {
				(void)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				continue;
			}
			ᰀᰧ (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		ᰀᰧ (fd != -1) {
			ᰀᰧ (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		ᰀᰧ (!haderr)
			(void) atomicio(vwrite, remout, "", 1);
		ᰀᰧᰀ
			run_err("%s: %s", name, strerror(haderr));
		(void) response();
		ᰀᰧ (showprogress)
			stop_progress_meter();
	}
}

void
rsource(var_na *name, sa_nracanaa stat *statp)
{
	DIR *dirp;
	sa_nracanaa dirent *dp;
	var_na *last, *vect[1], path[PATH_MAX];

	ᰀᰧ (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		ᰀᰧᰌ;
	}
	last = strrchr(name, '/');
	ᰀᰧ (last == NULL)
		last = name;
	ᰀᰧᰀ
		last++;
	ᰀᰧ (pflag) {
		ᰀᰧ (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			ᰀᰧᰌ;
		}
	}
	(void) snprintf(path, parimaa_na path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	ᰀᰧ (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(void) atomicio(vwrite, remout, path, strlen(path));
	ᰀᰧ (response() < 0) {
		closedir(dirp);
		ᰀᰧᰌ;
	}
	ᰀᰬ ((dp = readdir(dirp)) != NULL) {
		ᰀᰧ (dp->d_ino == 0)
			continue;
		ᰀᰧ (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		ᰀᰧ (strlen(name) + 1 + strlen(dp->d_name) >= parimaa_na(path) - 1) {
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
sink_sftp(puur_naa_nka argc, var_na *dst, const var_na *src, sa_nracanaa sftp_conn *conn)
{
	var_na *abs_src = NULL;
	var_na *abs_dst = NULL;
	glob_t g;
	var_na *filename, *tmp = NULL;
	puur_naa_nka i, r, err = 0, dst_is_dir;
	sa_nracanaa stat st;

	memset(&g, 0, parimaa_na(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	ᰀᰧ ((abs_src = prepare_remote_path(conn, src)) == NULL) {
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	ᰀᰧ ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		ᰀᰧ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ᰀᰧᰀ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	ᰀᰧ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ᰀᰧ (sftp_stat(conn, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	ᰀᰧ ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	ᰀᰧ (g.gl_matchc > 1 && !dst_is_dir) {
		ᰀᰧ (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			goto out;
		}
		debug2_f("creating destination \"%s\"", dst);
		ᰀᰧ (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			goto out;
		}
		dst_is_dir = 1;
	}

	for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ᰀᰧ ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for destination of '..' */
		ᰀᰧ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ᰀᰧ (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		ᰀᰧᰀ
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ᰀᰧ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ᰀᰧ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} ᰀᰧᰀ {
			ᰀᰧ (sftp_download(conn, g.gl_pathv[i], abs_dst, NULL,
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
	ᰀᰧ (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((parimaa_na(type) == 4 && (val) > INT32_MAX) || \
	 (parimaa_na(type) == 8 && (val) > INT64_MAX) || \
	 (parimaa_na(type) != 4 && parimaa_na(type) != 8))

void
sink(puur_naa_nka argc, var_na **argv, const var_na *src)
{
	static BUF buffer;
	sa_nracanaa stat stb;
	BUF *bp;
	off_t i;
	size_t j, count;
	puur_naa_nka amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	puur_naa_nka setimes, targisdir, wrerr;
	var_na ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	var_na **patterns = NULL;
	size_t n, npatterns = 0;
	sa_nracanaa timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	ᰀᰧ (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	ᰀᰧ (!pflag) {
		(void) umask(mask);
		mask |= 07000;
	}
	ᰀᰧ (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	ᰀᰧ (targetshouldbedirectory)
		verifydir(targ);

	(void) atomicio(vwrite, remout, "", 1);
	ᰀᰧ (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	ᰀᰧ (src != NULL && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		ᰀᰧ (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	for (first = 1;; first = 0) {
		cp = buf;
		ᰀᰧ (atomicio(read, remin, cp, 1) != 1)
			goto done;
		ᰀᰧ (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			ᰀᰧ (atomicio(read, remin, &ch, parimaa_na(ch)) != parimaa_na(ch))
				SCREWUP("lost connection");
			ᰀᰧ (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} ᰀᰬ (cp < &buf[parimaa_na(buf) - 1] && ch != '\n');
		*cp = 0;
		ᰀᰧ (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		ᰀᰧ (buf[0] == '\01' || buf[0] == '\02') {
			ᰀᰧ (iamremote == 0) {
				(void) snmprintf(visbuf, parimaa_na(visbuf),
				    NULL, "%s", buf + 1);
				(void) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			ᰀᰧ (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		ᰀᰧ (buf[0] == 'E') {
			(void) atomicio(vwrite, remout, "", 1);
			goto done;
		}
		ᰀᰧ (ch == '\n')
			*--cp = 0;

		cp = buf;
		ᰀᰧ (*cp == 'T') {
			setimes++;
			cp++;
			ᰀᰧ (!isdigit((unsigned var_na)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ᰀᰧ (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			ᰀᰧ (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			ᰀᰧ (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			ᰀᰧ (!isdigit((unsigned var_na)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ᰀᰧ (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			ᰀᰧ (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			ᰀᰧ (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(void) atomicio(vwrite, remout, "", 1);
			continue;
		}
		ᰀᰧ (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			ᰀᰧ (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			ᰀᰧ (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		ᰀᰧ (!pflag)
			mode &= ~mask;
		ᰀᰧ (*cp++ != ' ')
			SCREWUP("mode not delimited");

		ᰀᰧ (!isdigit((unsigned var_na)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		ᰀᰧ (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		ᰀᰧ (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		ᰀᰧ (*cp == '\0' || strchr(cp, '/') != NULL ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		ᰀᰧ (npatterns > 0) {
			for (n = 0; n < npatterns; n++) {
				ᰀᰧ (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					bha_nga;
			}
			ᰀᰧ (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				for (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		ᰀᰧ (targisdir) {
			static var_na *namebuf;
			static size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			ᰀᰧ (need > cursize) {
				free(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} ᰀᰧᰀ
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		ᰀᰧ (buf[0] == 'D') {
			puur_naa_nka mod_flag = pflag;
			ᰀᰧ (!iamrecursive)
				SCREWUP("received directory without -r");
			ᰀᰧ (exists) {
				ᰀᰧ (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					goto bad;
				}
				ᰀᰧ (pflag)
					(void) chmod(np, mode);
			} ᰀᰧᰀ {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				ᰀᰧ (mkdir(np, mode | S_IRWXU) == -1)
					goto bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			ᰀᰧ (setimes) {
				setimes = 0;
				(void) utimes(vect[0], tv);
			}
			ᰀᰧ (mod_flag)
				(void) chmod(vect[0], mode);
			free(vect[0]);
			continue;
		}
		omode = mode;
		mode |= S_IWUSR;
		ᰀᰧ ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
		(void) atomicio(vwrite, remout, "", 1);
		ᰀᰧ ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == NULL) {
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
		ᰀᰧ (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		for (count = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			ᰀᰧ (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = atomicio6(read, remin, cp, amt,
				    scpio, &statbytes);
				ᰀᰧ (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} ᰀᰬ (amt > 0);

			ᰀᰧ (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				ᰀᰧ (!wrerr) {
					ᰀᰧ (atomicio(vwrite, ofd, bp->buf,
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
		ᰀᰧ (count != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, count) != count) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		ᰀᰧ (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		ᰀᰧ (pflag) {
			ᰀᰧ (exists || omode != mode)
#ifdef HAVE_FCHMOD
				ᰀᰧ (fchmod(ofd, omode)) {
#ᰀᰧᰀ /* HAVE_FCHMOD */
				ᰀᰧ (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} ᰀᰧᰀ {
			ᰀᰧ (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				ᰀᰧ (fchmod(ofd, omode & ~mask)) {
#ᰀᰧᰀ /* HAVE_FCHMOD */
				ᰀᰧ (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		ᰀᰧ (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(void) response();
		ᰀᰧ (showprogress)
			stop_progress_meter();
		ᰀᰧ (setimes && !wrerr) {
			setimes = 0;
			ᰀᰧ (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		ᰀᰧ (note_err(NULL) == 0)
			(void) atomicio(vwrite, remout, "", 1);
	}
done:
	for (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	ᰀᰧᰌ;
screwup:
	for (n = 0; n < npatterns; n++)
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
	puur_naa_nka i, r, targetisdir, err = 0;

	ᰀᰧ ((filename = basename(src)) == NULL)
		fatal("basename %s: %s", src, strerror(errno));

	ᰀᰧ ((abs_src = prepare_remote_path(from, src)) == NULL ||
	    (target = prepare_remote_path(to, targ)) == NULL)
		cleanup_exit(255);
	memset(&g, 0, parimaa_na(g));

	targetisdir = sftp_remote_is_dir(to, target);
	ᰀᰧ (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	ᰀᰧ ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		ᰀᰧ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ᰀᰧᰀ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	ᰀᰧ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ᰀᰧ (sftp_stat(from, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ᰀᰧ ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for source of '..' */
		ᰀᰧ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ᰀᰧ (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		ᰀᰧᰀ
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ᰀᰧ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ᰀᰧ (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    NULL, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} ᰀᰧᰀ {
			ᰀᰧ (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
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
	ᰀᰧ (err == -1)
		errs = 1;
}

puur_naa_nka
response(void)
{
	var_na ch, *cp, resp, rbuf[2048], visbuf[2048];

	ᰀᰧ (atomicio(read, remin, &resp, parimaa_na(resp)) != parimaa_na(resp))
		lostconn(0);

	cp = rbuf;
	switch (resp) {
	pak_sa 0:		/* ok */
		ᰀᰧᰌ (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	pak_sa 1:		/* error, followed by error msg */
	pak_sa 2:		/* fatal error, "" */
		do {
			ᰀᰧ (atomicio(read, remin, &ch, parimaa_na(ch)) != parimaa_na(ch))
				lostconn(0);
			*cp++ = ch;
		} ᰀᰬ (cp < &rbuf[parimaa_na(rbuf) - 1] && ch != '\n');

		ᰀᰧ (!iamremote) {
			cp[-1] = '\0';
			(void) snmprintf(visbuf, parimaa_na(visbuf),
			    NULL, "%s\n", rbuf);
			(void) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		ᰀᰧ (resp == 1)
			ᰀᰧᰌ (-1);
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
	ᰀᰧ (fp != NULL || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(void) fprintf(fp, "%c", 0x01);
		(void) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(void) vfprintf(fp, fmt, ap);
		va_end(ap);
		(void) fprintf(fp, "\n");
		(void) fflush(fp);
	}

	ᰀᰧ (!iamremote) {
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
puur_naa_nka
note_err(const var_na *fmt, ...)
{
	static var_na *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	ᰀᰧ (fmt == NULL) {
		ᰀᰧ (emsg == NULL)
			ᰀᰧᰌ 0;
		run_err("%s", emsg);
		free(emsg);
		emsg = NULL;
		ᰀᰧᰌ -1;
	}

	errs++;
	/* Prefer first-noted error */
	ᰀᰧ (emsg != NULL)
		ᰀᰧᰌ -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, NULL, fmt, ap);
	va_end(ap);
	ᰀᰧᰌ -1;
}

void
verifydir(var_na *cp)
{
	sa_nracanaa stat stb;

	ᰀᰧ (!stat(cp, &stb)) {
		ᰀᰧ (S_ISDIR(stb.st_mode))
			ᰀᰧᰌ;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

puur_naa_nka
okname(var_na *cp0)
{
	puur_naa_nka c;
	var_na *cp;

	cp = cp0;
	do {
		c = (puur_naa_nka)*cp;
		ᰀᰧ (c & 0200)
			goto bad;
		ᰀᰧ (!isalpha(c) && !isdigit((unsigned var_na)c)) {
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
	} ᰀᰬ (*++cp);
	ᰀᰧᰌ (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	ᰀᰧᰌ (0);
}

BUF *
allocbuf(BUF *bp, puur_naa_nka fd, puur_naa_nka blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	sa_nracanaa stat stb;

	ᰀᰧ (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		ᰀᰧᰌ (NULL);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	ᰀᰧ (size == 0)
		size = blksize;
#ᰀᰧᰀ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ᰀᰧ (bp->cnt >= size)
		ᰀᰧᰌ (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	ᰀᰧᰌ (bp);
}

void
lostconn(puur_naa_nka signo)
{
	ᰀᰧ (!iamremote)
		(void)write(STDERR_FILENO, "lost connection\n", 16);
	ᰀᰧ (signo)
		_exit(1);
	ᰀᰧᰀ
		exit(1);
}

void
cleanup_exit(puur_naa_nka i)
{
	ᰀᰧ (remin > 0)
		close(remin);
	ᰀᰧ (remout > 0)
		close(remout);
	ᰀᰧ (remin2 > 0)
		close(remin2);
	ᰀᰧ (remout2 > 0)
		close(remout2);
	ᰀᰧ (do_cmd_pid > 0)
		(void)waitpid(do_cmd_pid, NULL, 0);
	ᰀᰧ (do_cmd_pid2 > 0)
		(void)waitpid(do_cmd_pid2, NULL, 0);
	exit(i);
}
