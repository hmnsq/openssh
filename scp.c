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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <dirent.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ifdef HAVE_FNMATCH_H
#ଅନ୍ତର୍ଭାଵ <fnmatch.h>
#endif
#ଅନ୍ତର୍ଭାଵ <glob.h>
#ଅନ୍ତର୍ଭାଵ <libgen.h>
#ଅନ୍ତର୍ଭାଵ <locale.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <util.h>
#ଯଦି defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ଅନ୍ତର୍ଭାଵ <vis.h>
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "progressmeter.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"
#ଅନ୍ତର୍ଭାଵ "sftp.h"

#ଅନ୍ତର୍ଭାଵ "sftp-common.h"
#ଅନ୍ତର୍ଭାଵ "sftp-client.h"

ବାହ୍ୟ ଅକ୍ଷର *__progname;

#define COPY_BUFLEN	16384

ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_cmd(ଅକ୍ଷର *, ଅକ୍ଷର *, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *, pid_t *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_cmd2(ଅକ୍ଷର *, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
ସଂରଚନା bwlimit bwlimit;

/* Name of current file being transferred. */
ଅକ୍ଷର *curfile;

/* This is set to non-zero to enable verbose mode. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
ଅକ୍ଷର *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
ଅସ୍ଥିର sig_atomic_t interrupted = 0;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_glob(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*)(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା), glob_t *); /* proto for sftp-glob.c */

ସ୍ଥିର ଶୂନ୍ୟ
killchild(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	ଯଦି (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(ଶୂନ୍ୟ)waitpid(do_cmd_pid, ଖାଲି, 0);
	}
	ଯଦି (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(ଶୂନ୍ୟ)waitpid(do_cmd_pid2, ଖାଲି, 0);
	}

	ଯଦି (signo)
		_exit(1);
	exit(1);
}

ସ୍ଥିର ଶୂନ୍ୟ
suspone(ପୂର୍ଣ୍ଣସଂଖ୍ୟା pid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;

	ଯଦି (pid > 1) {
		kill(pid, signo);
		ଯେତେବେଳେ (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
suspchild(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_local_cmd(arglist *a)
{
	ଅକ୍ଷର *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;
	pid_t pid;

	ଯଦି (a->ଅଙ୍କ == 0)
		fatal("do_local_cmd: no arguments");

	ଯଦି (verbose_mode) {
		cp = argv_assemble(a->ଅଙ୍କ, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		ମୁକ୍ତ(cp);
	}
	ଯଦି ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	ଯଦି (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1)
		ଯଦି (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	ଯଦି (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ଫେରନ୍ତୁ (-1);

	ଫେରନ୍ତୁ (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_cmd(ଅକ୍ଷର *program, ଅକ୍ଷର *host, ଅକ୍ଷର *remuser, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, ପୂର୍ଣ୍ଣସଂଖ୍ୟା subsystem,
    ଅକ୍ଷର *cmd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdin, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pin[2], pout[2];
#ଅନ୍ୟଥା
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sv[2];
#endif

	ଯଦି (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ଯଦି (port == -1)
		port = sshport;

#ifdef USE_PIPES
	ଯଦି (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#ଅନ୍ୟଥା
	/* Create a socket pair for communicating with ssh. */
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	ବାଛ (*pid) {
	ସ୍ଥିତି -1:
		fatal("fork: %s", strerror(errno));
	ସ୍ଥିତି 0:
		/* Child. */
#ifdef USE_PIPES
		ଯଦି (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#ଅନ୍ୟଥା
		ଯଦି (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		ଯଦି (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		ଯଦି (remuser != ଖାଲି) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		ଯଦି (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#ଅନ୍ୟଥା
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		ଫେରନ୍ତୁ 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_cmd2(ଅକ୍ଷର *host, ଅକ୍ଷର *remuser, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, ଅକ୍ଷର *cmd,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fdin, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fdout)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;
	pid_t pid;

	ଯଦି (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ଯଦି (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	ଯଦି (pid == 0) {
		ଯଦି (dup2(fdin, 0) == -1)
			perror("dup2");
		ଯଦି (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		ଯଦି (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		ଯଦି (remuser != ଖାଲି) {
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
	} ଅନ୍ୟଥା ଯଦି (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1)
		ଯଦି (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	ଫେରନ୍ତୁ 0;
}

ପ୍ରକାରବ୍ୟାଖ୍ୟା ସଂରଚନା {
	size_t cnt;
	ଅକ୍ଷର *buf;
} BUF;

BUF *allocbuf(BUF *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ lostconn(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା okname(ଅକ୍ଷର *);
ଶୂନ୍ୟ run_err(ଅଚଳ ଅକ୍ଷର *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା note_err(ଅଚଳ ଅକ୍ଷର *,...)
    __attribute__((__format__ (printf, 1, 2)));
ଶୂନ୍ୟ verifydir(ଅକ୍ଷର *);

ସଂରଚନା passwd *pwd;
uid_t userid;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା errs, remin, remout, remin2, remout2;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
ଅକ୍ଷର cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

ଗଣନା scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା response(ଶୂନ୍ୟ);
ଶୂନ୍ୟ rsource(ଅକ୍ଷର *, ସଂରଚନା stat *);
ଶୂନ୍ୟ sink(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *[], ଅଚଳ ଅକ୍ଷର *);
ଶୂନ୍ୟ source(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *[]);
ଶୂନ୍ୟ tolocal(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *[], ଗଣନା scp_mode_e, ଅକ୍ଷର *sftp_direct);
ଶୂନ୍ୟ toremote(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *[], ଗଣନା scp_mode_e, ଅକ୍ଷର *sftp_direct);
ଶୂନ୍ୟ usage(ଶୂନ୍ୟ);

ଶୂନ୍ୟ source_sftp(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, ଅକ୍ଷର *, ସଂରଚନା sftp_conn *);
ଶୂନ୍ୟ sink_sftp(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sftp_conn *);
ଶୂନ୍ୟ throughlocal_sftp(ସଂରଚନା sftp_conn *, ସଂରଚନା sftp_conn *,
    ଅକ୍ଷର *, ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch, fflag, tflag, status, r, n;
	ଅକ୍ଷର **newargv, *argv0;
	ଅଚଳ ଅକ୍ଷର *errstr;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ଗଣନା scp_mode_e mode = MODE_SFTP;
	ଅକ୍ଷର *sftp_direct = ଖାଲି;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), ଆକାର(*newargv));
	ପାଇଁ (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', ଆକାର(args));
	memset(&remote_remote_args, '\0', ଆକାର(remote_remote_args));
	args.list = remote_remote_args.list = ଖାଲି;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	ଯେତେବେଳେ ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		ବାଛ (ch) {
		/* User-visible flags. */
		ସ୍ଥିତି '1':
			fatal("SSH protocol v.1 is no longer supported");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '2':
			/* Ignored */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'A':
		ସ୍ଥିତି '4':
		ସ୍ଥିତି '6':
		ସ୍ଥିତି 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			sftp_direct = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '3':
			throughlocal = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'o':
		ସ୍ଥିତି 'c':
		ସ୍ଥିତି 'i':
		ସ୍ଥିତି 'F':
		ସ୍ଥିତି 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'O':
			mode = MODE_SCP;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 's':
			/* Ignored */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			sshport = a2port(optarg);
			ଯଦି (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ଯଦି (errstr != ଖାଲି)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			pflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'r':
			iamrecursive = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'S':
			ssh_program = xstrdup(optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			ଯଦି (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ଅନ୍ୟଥା ଯଦି (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'X':
			/* Please keep in sync with sftp.c -X */
			ଯଦି (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				ଯଦି (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ଯଦି (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} ଅନ୍ୟଥା ଯଦି (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ଯଦି (errstr != ଖାଲି) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} ଅନ୍ୟଥା {
				fatal("Invalid -X option");
			}
			ଭାଙ୍ଗ;

		/* Server options. */
		ସ୍ଥିତି 'd':
			targetshouldbedirectory = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_ଦ୍ୱିମିକ);
#endif
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'T':
			Tflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	ଯଦି (iamremote)
		mode = MODE_SCP;

	ଯଦି ((pwd = getpwuid(userid = getuid())) == ଖାଲି)
		fatal("unknown user %u", (u_int) userid);

	ଯଦି (!isatty(STDOUT_FILENO))
		showprogress = 0;

	ଯଦି (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} ଅନ୍ୟଥା {
		ଯଦି (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ଖାଲି) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	ଯଦି (fflag) {
		/* Follow "protocol", send data. */
		(ଶୂନ୍ୟ) response();
		source(argc, argv);
		exit(errs != 0);
	}
	ଯଦି (tflag) {
		/* Receive data. */
		sink(argc, argv, ଖାଲି);
		exit(errs != 0);
	}
	ଯଦି (argc < 2)
		usage();
	ଯଦି (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(ଶୂନ୍ୟ) snprintf(cmd, ଆକାର cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(ଶୂନ୍ୟ) ssh_signal(SIGPIPE, lostconn);

	ଯଦି (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	ଅନ୍ୟଥା {
		ଯଦି (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	ଯଦି (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		ଯଦି (remin != -1)
		    (ଶୂନ୍ୟ) close(remin);
		ଯଦି (remout != -1)
		    (ଶୂନ୍ୟ) close(remout);
		ଯଦି (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		ଅନ୍ୟଥା {
			ଯଦି (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
scpio(ଶୂନ୍ୟ *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	ଯଦି (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_times(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା verb, ଅଚଳ ସଂରଚନା stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	ଅକ୍ଷର buf[(20 + 7 + 2) * 2 + 2];

	(ଶୂନ୍ୟ)snprintf(buf, ଆକାର(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	ଯଦି (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(ଶୂନ୍ୟ) atomicio(vwrite, fd, buf, strlen(buf));
	ଫେରନ୍ତୁ (response());
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_scp_uri(ଅଚଳ ଅକ୍ଷର *uri, ଅକ୍ଷର **userp, ଅକ୍ଷର **hostp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *portp,
    ଅକ୍ଷର **pathp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	ଯଦି (r == 0 && *pathp == ଖାଲି)
		*pathp = xstrdup(".");
	ଫେରନ୍ତୁ r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
append(ଅକ୍ଷର *cp, ଅକ୍ଷର ***ap, size_t *np)
{
	ଅକ୍ଷର **tmp;

	ଯଦି ((tmp = reallocarray(*ap, *np + 1, ଆକାର(*tmp))) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	ଫେରନ୍ତୁ 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
find_brace(ଅଚଳ ଅକ୍ଷର *pattern, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *startp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *endp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	ପାଇଁ (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		ବାଛ (pattern[i]) {
		ସ୍ଥିତି '\\':
			/* skip next character */
			ଯଦି (pattern[i + 1] != '\0')
				i++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '[':
			in_bracket = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ']':
			in_bracket = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '{':
			ଯଦି (in_bracket)
				ଭାଙ୍ଗ;
			ଯଦି (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				ଭାଙ୍ଗ;
			}
			ଯଦି (*startp == -1)
				*startp = i;
			brace_level++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '}':
			ଯଦି (in_bracket)
				ଭାଙ୍ଗ;
			ଯଦି (*startp < 0) {
				/* Unbalanced brace */
				ଫେରନ୍ତୁ -1;
			}
			ଯଦି (--brace_level <= 0)
				*endp = i;
			ଭାଙ୍ଗ;
		}
	}
	/* unbalanced brackets/braces */
	ଯଦି (*endp < 0 && (*startp >= 0 || in_bracket))
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
emit_expansion(ଅଚଳ ଅକ୍ଷର *pattern, ପୂର୍ଣ୍ଣସଂଖ୍ୟା brace_start, ପୂର୍ଣ୍ଣସଂଖ୍ୟା brace_end,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା sel_start, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sel_end, ଅକ୍ଷର ***patternsp, size_t *npatternsp)
{
	ଅକ୍ଷର *cp;
	size_t pattern_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା o = 0, tail_len;

	ଯଦି ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		ଫେରନ୍ତୁ -1;

	tail_len = strlen(pattern + brace_end + 1);
	ଯଦି ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	/* Pattern before initial brace */
	ଯଦି (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	ଯଦି (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	ଯଦି (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	ଯଦି (append(cp, patternsp, npatternsp) != 0) {
		ମୁକ୍ତ(cp);
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ 0;
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
brace_expand_one(ଅଚଳ ଅକ୍ଷର *pattern, ଅକ୍ଷର ***patternsp, size_t *npatternsp,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *expanded, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *invalid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_bracket, brace_start, brace_end, brace_level;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sel_start, sel_end;

	*invalid = *expanded = 0;

	ଯଦି (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		ଫେରନ୍ତୁ 0;
	} ଅନ୍ୟଥା ଯଦି (brace_start == -1)
		ଫେରନ୍ତୁ 0;

	in_bracket = brace_level = 0;
	ପାଇଁ (i = sel_start = brace_start + 1; i < brace_end; i++) {
		ବାଛ (pattern[i]) {
		ସ୍ଥିତି '{':
			ଯଦି (in_bracket)
				ଭାଙ୍ଗ;
			brace_level++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '}':
			ଯଦି (in_bracket)
				ଭାଙ୍ଗ;
			brace_level--;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '[':
			in_bracket = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ']':
			in_bracket = 0;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '\\':
			ଯଦି (i < brace_end - 1)
				i++; /* skip */
			ଭାଙ୍ଗ;
		}
		ଯଦି (pattern[i] == ',' || i == brace_end - 1) {
			ଯଦି (in_bracket || brace_level > 0)
				ଜାରି;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			ଯଦି (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				ଫେରନ୍ତୁ -1;
			/* move on to the next selection */
			sel_start = i + 1;
			ଜାରି;
		}
	}
	ଯଦି (in_bracket || brace_level > 0) {
		*invalid = 1;
		ଫେରନ୍ତୁ 0;
	}
	/* success */
	*expanded = 1;
	ଫେରନ୍ତୁ 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
brace_expand(ଅଚଳ ଅକ୍ଷର *pattern, ଅକ୍ଷର ***patternsp, size_t *npatternsp)
{
	ଅକ୍ଷର *cp, *cp2, **active = ଖାଲି, **done = ଖାଲି;
	size_t i, nactive = 0, ndone = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1, invalid = 0, expanded = 0;

	*patternsp = ଖାଲି;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	ଯଦି ((cp = strdup(pattern)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	ଯଦି (append(cp, &active, &nactive) != 0) {
		ମୁକ୍ତ(cp);
		ଫେରନ୍ତୁ -1;
	}
	ଯେତେବେଳେ (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		ଯଦି (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			ମୁକ୍ତ(cp);
			ଯାଅ fail;
		}
		ଯଦି (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		ଯଦି (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			ମୁକ୍ତ(cp);
			ଜାରି;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		ଯଦି ((cp2 = strrchr(cp, '/')) != ଖାଲି)
			*cp2++ = '\0';
		ଅନ୍ୟଥା
			cp2 = cp;
		ଯଦି (append(xstrdup(cp2), &done, &ndone) != 0) {
			ମୁକ୍ତ(cp);
			ଯାଅ fail;
		}
		ମୁକ୍ତ(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = ଖାଲି;
	ndone = 0;
	ret = 0;
 fail:
	ପାଇଁ (i = 0; i < nactive; i++)
		ମୁକ୍ତ(active[i]);
	ମୁକ୍ତ(active);
	ପାଇଁ (i = 0; i < ndone; i++)
		ମୁକ୍ତ(done[i]);
	ମୁକ୍ତ(done);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ସଂରଚନା sftp_conn *
do_sftp_connect(ଅକ୍ଷର *host, ଅକ୍ଷର *user, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, ଅକ୍ଷର *sftp_direct,
   ପୂର୍ଣ୍ଣସଂଖ୍ୟା *reminp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *remoutp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *pidp)
{
	ଯଦି (sftp_direct == ଖାଲି) {
		ଯଦି (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			ଫେରନ୍ତୁ ଖାଲି;

	} ଅନ୍ୟଥା {
		freeargs(&args);
		addargs(&args, "sftp-server");
		ଯଦି (do_cmd(sftp_direct, host, ଖାଲି, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

ଶୂନ୍ୟ
toremote(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv, ଗଣନା scp_mode_e mode, ଅକ୍ଷର *sftp_direct)
{
	ଅକ୍ଷର *suser = ଖାଲି, *host = ଖାଲି, *src = ଖାଲି;
	ଅକ୍ଷର *bp, *tuser, *thost, *targ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sport = -1, tport = -1;
	ସଂରଚନା sftp_conn *conn = ଖାଲି, *conn2 = ଖାଲି;
	arglist alist;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, status;
	ସଂରଚନା stat sb;
	u_int j;

	memset(&alist, '\0', ଆକାର(alist));
	alist.list = ଖାଲି;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	ଯଦି (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		ଯାଅ out;
	}
	ଯଦି (r != 0) {
		ଯଦି (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			ଯାଅ out;
		}
	}

	/* Parse source files */
	ପାଇଁ (i = 0; i < argc - 1; i++) {
		ମୁକ୍ତ(suser);
		ମୁକ୍ତ(host);
		ମୁକ୍ତ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ଯଦି (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ଜାରି;
		}
		ଯଦି (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		ଯଦି (suser != ଖାଲି && !okname(suser)) {
			++errs;
			ଜାରି;
		}
		ଯଦି (host && throughlocal) {	/* extended remote to remote */
			ଯଦି (mode == MODE_SFTP) {
				ଯଦି (remin == -1 || conn == ଖାଲି) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					ଯଦି (conn == ଖାଲି) {
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
				ଯଦି (conn2 == ଖାଲି) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(ଶୂନ୍ୟ) close(remin2);
				(ଶୂନ୍ୟ) close(remout2);
				remin2 = remout2 = -1;
				ଯଦି (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				ଅନ୍ୟଥା ଯଦି (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				ଜାରି;
			} ଅନ୍ୟଥା {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				ଯଦି (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				ମୁକ୍ତ(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ଯଦି (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				ମୁକ୍ତ(bp);
				(ଶୂନ୍ୟ) close(remin);
				(ଶୂନ୍ୟ) close(remout);
				remin = remout = -1;
			}
		} ଅନ୍ୟଥା ଯଦି (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			ଯଦି (tuser != ଖାଲି && !okname(tuser)) {
				++errs;
				ଜାରି;
			}
			ଯଦି (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			ପାଇଁ (j = 0; j < remote_remote_args.ଅଙ୍କ; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			ଯଦି (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			ଯଦି (suser) {
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
			ଯଦି (do_local_cmd(&alist) != 0)
				errs = 1;
		} ଅନ୍ୟଥା {	/* local to remote */
			ଯଦି (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				ଯଦି (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				ଯଦି (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					ଯଦି (conn == ଖାଲି) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				ଜାରି;
			}
			/* SCP */
			ଯଦି (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ଯଦି (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				ଯଦି (response() < 0)
					exit(1);
				ମୁକ୍ତ(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	ମୁକ୍ତ(tuser);
	ମୁକ୍ତ(thost);
	ମୁକ୍ତ(targ);
	ମୁକ୍ତ(suser);
	ମୁକ୍ତ(host);
	ମୁକ୍ତ(src);
	sftp_free(conn);
	sftp_free(conn2);
}

ଶୂନ୍ୟ
tolocal(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv, ଗଣନା scp_mode_e mode, ଅକ୍ଷର *sftp_direct)
{
	ଅକ୍ଷର *bp, *host = ଖାଲି, *src = ଖାଲି, *suser = ଖାଲି;
	arglist alist;
	ସଂରଚନା sftp_conn *conn = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, sport = -1;

	memset(&alist, '\0', ଆକାର(alist));
	alist.list = ଖାଲି;

	ପାଇଁ (i = 0; i < argc - 1; i++) {
		ମୁକ୍ତ(suser);
		ମୁକ୍ତ(host);
		ମୁକ୍ତ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ଯଦି (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ଜାରି;
		}
		ଯଦି (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		ଯଦି (suser != ଖାଲି && !okname(suser)) {
			++errs;
			ଜାରି;
		}
		ଯଦି (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			ଯଦି (iamrecursive)
				addargs(&alist, "-r");
			ଯଦି (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			ଯଦି (do_local_cmd(&alist))
				++errs;
			ଜାରି;
		}
		/* Remote to local. */
		ଯଦି (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			ଯଦି (conn == ଖାଲି) {
				error("sftp connection failed");
				++errs;
				ଜାରି;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(ଶୂନ୍ୟ) close(remin);
			(ଶୂନ୍ୟ) close(remout);
			remin = remout = -1;
			ଜାରି;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		ଯଦି (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			ମୁକ୍ତ(bp);
			++errs;
			ଜାରି;
		}
		ମୁକ୍ତ(bp);
		sink(1, argv + argc - 1, src);
		(ଶୂନ୍ୟ) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	ମୁକ୍ତ(suser);
	ମୁକ୍ତ(host);
	ମୁକ୍ତ(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
ସ୍ଥିର ଅକ୍ଷର *
prepare_remote_path(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	ଯଦି (*path == '\0' || strcmp(path, "~") == 0)
		ଫେରନ୍ତୁ xstrdup(".");
	ଯଦି (*path != '~')
		ଫେରନ୍ତୁ xstrdup(path);
	ଯଦି (strncmp(path, "~/", 2) == 0) {
		ଯଦି ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			ଫେରନ୍ତୁ xstrdup(".");
		ଫେରନ୍ତୁ xstrdup(path + 2 + nslash);
	}
	ଯଦି (sftp_can_expand_path(conn))
		ଫେରନ୍ତୁ sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	ଫେରନ୍ତୁ ଖାଲି;
}

ଶୂନ୍ୟ
source_sftp(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର *src, ଅକ୍ଷର *targ, ସଂରଚନା sftp_conn *conn)
{
	ଅକ୍ଷର *target = ଖାଲି, *filename = ଖାଲି, *abs_dst = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା src_is_dir, target_is_dir;
	Attrib a;
	ସଂରଚନା stat st;

	memset(&a, '\0', ଆକାର(a));
	ଯଦି (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	ଯଦି ((filename = basename(src)) == ଖାଲି)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	ଯଦି (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	ଯଦି ((target = prepare_remote_path(conn, targ)) == ଖାଲି)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	ଯଦି (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		ଯଦି (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	ଯଦି (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	ଅନ୍ୟଥା {
		abs_dst = target;
		target = ଖାଲି;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	ଯଦି (src_is_dir && iamrecursive) {
		ଯଦି (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} ଅନ୍ୟଥା ଯଦି (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	ମୁକ୍ତ(abs_dst);
	ମୁକ୍ତ(target);
}

ଶୂନ୍ୟ
source(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ସଂରଚନା stat stb;
	ସ୍ଥିର BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd = -1, haderr, indx;
	ଅକ୍ଷର *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len;

	ପାଇଁ (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		ଯେତେବେଳେ (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		ଯଦି ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			ଯାଅ syserr;
		ଯଦି (strchr(name, '\n') != ଖାଲି) {
			strnvis(encname, name, ଆକାର(encname), VIS_NL);
			name = encname;
		}
		ଯଦି (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			ଯାଅ next;
		}
		ଯଦି (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			ଯାଅ next;
		}
		unset_nonblock(fd);
		ବାଛ (stb.st_mode & S_IFMT) {
		ସ୍ଥିତି S_IFREG:
			ଭାଙ୍ଗ;
		ସ୍ଥିତି S_IFDIR:
			ଯଦି (iamrecursive) {
				rsource(name, &stb);
				ଯାଅ next;
			}
			/* FALLTHROUGH */
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			run_err("%s: not a regular file", name);
			ଯାଅ next;
		}
		ଯଦି ((last = strrchr(name, '/')) == ଖାଲି)
			last = name;
		ଅନ୍ୟଥା
			++last;
		curfile = last;
		ଯଦି (pflag) {
			ଯଦି (do_times(remout, verbose_mode, &stb) < 0)
				ଯାଅ next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, ଆକାର buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		ଯଦି (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(ଶୂନ୍ୟ) atomicio(vwrite, remout, buf, strlen(buf));
		ଯଦି (response() < 0)
			ଯାଅ next;
		ଯଦି ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == ଖାଲି) {
next:			ଯଦି (fd != -1) {
				(ଶୂନ୍ୟ) close(fd);
				fd = -1;
			}
			ଜାରି;
		}
		ଯଦି (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		ପାଇଁ (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			ଯଦି (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			ଯଦି (!haderr) {
				ଯଦି ((nr = atomicio(ପଠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			ଯଦି (haderr) {
				(ଶୂନ୍ୟ)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				ଜାରି;
			}
			ଯଦି (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		ଯଦି (fd != -1) {
			ଯଦି (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		ଯଦି (!haderr)
			(ଶୂନ୍ୟ) atomicio(vwrite, remout, "", 1);
		ଅନ୍ୟଥା
			run_err("%s: %s", name, strerror(haderr));
		(ଶୂନ୍ୟ) response();
		ଯଦି (showprogress)
			stop_progress_meter();
	}
}

ଶୂନ୍ୟ
rsource(ଅକ୍ଷର *name, ସଂରଚନା stat *statp)
{
	DIR *dirp;
	ସଂରଚନା dirent *dp;
	ଅକ୍ଷର *last, *vect[1], path[PATH_MAX];

	ଯଦି (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		ଫେରନ୍ତୁ;
	}
	last = strrchr(name, '/');
	ଯଦି (last == ଖାଲି)
		last = name;
	ଅନ୍ୟଥା
		last++;
	ଯଦି (pflag) {
		ଯଦି (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			ଫେରନ୍ତୁ;
		}
	}
	(ଶୂନ୍ୟ) snprintf(path, ଆକାର path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	ଯଦି (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(ଶୂନ୍ୟ) atomicio(vwrite, remout, path, strlen(path));
	ଯଦି (response() < 0) {
		closedir(dirp);
		ଫେରନ୍ତୁ;
	}
	ଯେତେବେଳେ ((dp = readdir(dirp)) != ଖାଲି) {
		ଯଦି (dp->d_ino == 0)
			ଜାରି;
		ଯଦି (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			ଜାରି;
		ଯଦି (strlen(name) + 1 + strlen(dp->d_name) >= ଆକାର(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			ଜାରି;
		}
		(ଶୂନ୍ୟ) snprintf(path, ଆକାର path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(ଶୂନ୍ୟ) closedir(dirp);
	(ଶୂନ୍ୟ) atomicio(vwrite, remout, "E\n", 2);
	(ଶୂନ୍ୟ) response();
}

ଶୂନ୍ୟ
sink_sftp(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର *dst, ଅଚଳ ଅକ୍ଷର *src, ସଂରଚନା sftp_conn *conn)
{
	ଅକ୍ଷର *abs_src = ଖାଲି;
	ଅକ୍ଷର *abs_dst = ଖାଲି;
	glob_t g;
	ଅକ୍ଷର *filename, *tmp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, err = 0, dst_is_dir;
	ସଂରଚନା stat st;

	memset(&g, 0, ଆକାର(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	ଯଦି ((abs_src = prepare_remote_path(conn, src)) == ଖାଲି) {
		err = -1;
		ଯାଅ out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	ଯଦି ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ଖାଲି, &g)) != 0) {
		ଯଦି (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ଅନ୍ୟଥା
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ଯାଅ out;
	}

	/* Did we actually get any matches back from the glob? */
	ଯଦି (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ଖାଲି) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ଯଦି (sftp_stat(conn, g.gl_pathv[0], 1, ଖାଲି) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ଯାଅ out;
		}
	}

	ଯଦି ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	ଯଦି (g.gl_matchc > 1 && !dst_is_dir) {
		ଯଦି (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			ଯାଅ out;
		}
		debug2_f("creating destination \"%s\"", dst);
		ଯଦି (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			ଯାଅ out;
		}
		dst_is_dir = 1;
	}

	ପାଇଁ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ଯଦି ((filename = basename(tmp)) == ଖାଲି) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ଯାଅ out;
		}

		/* Special handling for destination of '..' */
		ଯଦି (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ଯଦି (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		ଅନ୍ୟଥା
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ଯଦି (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ଯଦି (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ଖାଲି, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} ଅନ୍ୟଥା {
			ଯଦି (sftp_download(conn, g.gl_pathv[i], abs_dst, ଖାଲି,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		ମୁକ୍ତ(abs_dst);
		abs_dst = ଖାଲି;
		ମୁକ୍ତ(tmp);
		tmp = ଖାଲି;
	}

out:
	ମୁକ୍ତ(abs_src);
	ମୁକ୍ତ(tmp);
	globfree(&g);
	ଯଦି (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((ଆକାର(type) == 4 && (val) > INT32_MAX) || \
	 (ଆକାର(type) == 8 && (val) > INT64_MAX) || \
	 (ଆକାର(type) != 4 && ଆକାର(type) != 8))

ଶୂନ୍ୟ
sink(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv, ଅଚଳ ଅକ୍ଷର *src)
{
	ସ୍ଥିର BUF buffer;
	ସଂରଚନା stat stb;
	BUF *bp;
	off_t i;
	size_t j, ଗଣନା_2;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା setimes, targisdir, wrerr;
	ଅକ୍ଷର ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	ଅକ୍ଷର **patterns = ଖାଲି;
	size_t n, npatterns = 0;
	ସଂରଚନା timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; ଯାଅ screwup; }

	ଯଦି (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	ଯଦି (!pflag) {
		(ଶୂନ୍ୟ) umask(mask);
		mask |= 07000;
	}
	ଯଦି (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	ଯଦି (targetshouldbedirectory)
		verifydir(targ);

	(ଶୂନ୍ୟ) atomicio(vwrite, remout, "", 1);
	ଯଦି (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	ଯଦି (src != ଖାଲି && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		ଯଦି (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	ପାଇଁ (first = 1;; first = 0) {
		cp = buf;
		ଯଦି (atomicio(ପଠ, remin, cp, 1) != 1)
			ଯାଅ done;
		ଯଦି (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		କର {
			ଯଦି (atomicio(ପଠ, remin, &ch, ଆକାର(ch)) != ଆକାର(ch))
				SCREWUP("lost connection");
			ଯଦି (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} ଯେତେବେଳେ (cp < &buf[ଆକାର(buf) - 1] && ch != '\n');
		*cp = 0;
		ଯଦି (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		ଯଦି (buf[0] == '\01' || buf[0] == '\02') {
			ଯଦି (iamremote == 0) {
				(ଶୂନ୍ୟ) snmprintf(visbuf, ଆକାର(visbuf),
				    ଖାଲି, "%s", buf + 1);
				(ଶୂନ୍ୟ) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			ଯଦି (buf[0] == '\02')
				exit(1);
			++errs;
			ଜାରି;
		}
		ଯଦି (buf[0] == 'E') {
			(ଶୂନ୍ୟ) atomicio(vwrite, remout, "", 1);
			ଯାଅ done;
		}
		ଯଦି (ch == '\n')
			*--cp = 0;

		cp = buf;
		ଯଦି (*cp == 'T') {
			setimes++;
			cp++;
			ଯଦି (!isdigit((unsigned ଅକ୍ଷର)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ଯଦି (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			ଯଦି (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			ଯଦି (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			ଯଦି (!isdigit((unsigned ଅକ୍ଷର)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ଯଦି (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			ଯଦି (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			ଯଦି (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(ଶୂନ୍ୟ) atomicio(vwrite, remout, "", 1);
			ଜାରି;
		}
		ଯଦି (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			ଯଦି (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		ପାଇଁ (++cp; cp < buf + 5; cp++) {
			ଯଦି (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		ଯଦି (!pflag)
			mode &= ~mask;
		ଯଦି (*cp++ != ' ')
			SCREWUP("mode not delimited");

		ଯଦି (!isdigit((unsigned ଅକ୍ଷର)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		ଯଦି (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		ଯଦି (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		ଯଦି (*cp == '\0' || strchr(cp, '/') != ଖାଲି ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		ଯଦି (npatterns > 0) {
			ପାଇଁ (n = 0; n < npatterns; n++) {
				ଯଦି (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					ଭାଙ୍ଗ;
			}
			ଯଦି (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				ପାଇଁ (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		ଯଦି (targisdir) {
			ସ୍ଥିର ଅକ୍ଷର *namebuf;
			ସ୍ଥିର size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			ଯଦି (need > cursize) {
				ମୁକ୍ତ(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(ଶୂନ୍ୟ) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} ଅନ୍ୟଥା
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		ଯଦି (buf[0] == 'D') {
			ପୂର୍ଣ୍ଣସଂଖ୍ୟା mod_flag = pflag;
			ଯଦି (!iamrecursive)
				SCREWUP("received directory without -r");
			ଯଦି (exists) {
				ଯଦି (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					ଯାଅ bad;
				}
				ଯଦି (pflag)
					(ଶୂନ୍ୟ) chmod(np, mode);
			} ଅନ୍ୟଥା {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				ଯଦି (mkdir(np, mode | S_IRWXU) == -1)
					ଯାଅ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			ଯଦି (setimes) {
				setimes = 0;
				(ଶୂନ୍ୟ) utimes(vect[0], tv);
			}
			ଯଦି (mod_flag)
				(ଶୂନ୍ୟ) chmod(vect[0], mode);
			ମୁକ୍ତ(vect[0]);
			ଜାରି;
		}
		omode = mode;
		mode |= S_IWUSR;
		ଯଦି ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			ଜାରି;
		}
		(ଶୂନ୍ୟ) atomicio(vwrite, remout, "", 1);
		ଯଦି ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == ଖାଲି) {
			(ଶୂନ୍ୟ) close(ofd);
			ଜାରି;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		ଯଦି (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		ପାଇଁ (ଗଣନା_2 = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			ଯଦି (i + amt > size)
				amt = size - i;
			ଗଣନା_2 += amt;
			କର {
				j = atomicio6(ପଠ, remin, cp, amt,
				    scpio, &statbytes);
				ଯଦି (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} ଯେତେବେଳେ (amt > 0);

			ଯଦି (ଗଣନା_2 == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				ଯଦି (!wrerr) {
					ଯଦି (atomicio(vwrite, ofd, bp->buf,
					    ଗଣନା_2) != ଗଣନା_2) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				ଗଣନା_2 = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		ଯଦି (ଗଣନା_2 != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, ଗଣନା_2) != ଗଣନା_2) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		ଯଦି (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		ଯଦି (pflag) {
			ଯଦି (exists || omode != mode)
#ifdef HAVE_FCHMOD
				ଯଦି (fchmod(ofd, omode)) {
#ଅନ୍ୟଥା /* HAVE_FCHMOD */
				ଯଦି (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} ଅନ୍ୟଥା {
			ଯଦି (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				ଯଦି (fchmod(ofd, omode & ~mask)) {
#ଅନ୍ୟଥା /* HAVE_FCHMOD */
				ଯଦି (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		ଯଦି (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(ଶୂନ୍ୟ) response();
		ଯଦି (showprogress)
			stop_progress_meter();
		ଯଦି (setimes && !wrerr) {
			setimes = 0;
			ଯଦି (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		ଯଦି (note_err(ଖାଲି) == 0)
			(ଶୂନ୍ୟ) atomicio(vwrite, remout, "", 1);
	}
done:
	ପାଇଁ (n = 0; n < npatterns; n++)
		ମୁକ୍ତ(patterns[n]);
	ମୁକ୍ତ(patterns);
	ଫେରନ୍ତୁ;
screwup:
	ପାଇଁ (n = 0; n < npatterns; n++)
		ମୁକ୍ତ(patterns[n]);
	ମୁକ୍ତ(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

ଶୂନ୍ୟ
throughlocal_sftp(ସଂରଚନା sftp_conn *from, ସଂରଚନା sftp_conn *to,
    ଅକ୍ଷର *src, ଅକ୍ଷର *targ)
{
	ଅକ୍ଷର *target = ଖାଲି, *filename = ଖାଲି, *abs_dst = ଖାଲି;
	ଅକ୍ଷର *abs_src = ଖାଲି, *tmp = ଖାଲି;
	glob_t g;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, targetisdir, err = 0;

	ଯଦି ((filename = basename(src)) == ଖାଲି)
		fatal("basename %s: %s", src, strerror(errno));

	ଯଦି ((abs_src = prepare_remote_path(from, src)) == ଖାଲି ||
	    (target = prepare_remote_path(to, targ)) == ଖାଲି)
		cleanup_exit(255);
	memset(&g, 0, ଆକାର(g));

	targetisdir = sftp_remote_is_dir(to, target);
	ଯଦି (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		ଯାଅ out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	ଯଦି ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ଖାଲି, &g)) != 0) {
		ଯଦି (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ଅନ୍ୟଥା
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ଯାଅ out;
	}

	/* Did we actually get any matches back from the glob? */
	ଯଦି (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ଖାଲି) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ଯଦି (sftp_stat(from, g.gl_pathv[0], 1, ଖାଲି) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ଯାଅ out;
		}
	}

	ପାଇଁ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ଯଦି ((filename = basename(tmp)) == ଖାଲି) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ଯାଅ out;
		}

		/* Special handling for source of '..' */
		ଯଦି (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ଯଦି (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		ଅନ୍ୟଥା
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ଯଦି (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ଯଦି (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    ଖାଲି, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} ଅନ୍ୟଥା {
			ଯଦି (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    ଖାଲି, pflag) == -1)
				err = -1;
		}
		ମୁକ୍ତ(abs_dst);
		abs_dst = ଖାଲି;
		ମୁକ୍ତ(tmp);
		tmp = ଖାଲି;
	}

out:
	ମୁକ୍ତ(abs_src);
	ମୁକ୍ତ(abs_dst);
	ମୁକ୍ତ(target);
	ମୁକ୍ତ(tmp);
	globfree(&g);
	ଯଦି (err == -1)
		errs = 1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
response(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର ch, *cp, resp, rbuf[2048], visbuf[2048];

	ଯଦି (atomicio(ପଠ, remin, &resp, ଆକାର(resp)) != ଆକାର(resp))
		lostconn(0);

	cp = rbuf;
	ବାଛ (resp) {
	ସ୍ଥିତି 0:		/* ok */
		ଫେରନ୍ତୁ (0);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		*cp++ = resp;
		/* FALLTHROUGH */
	ସ୍ଥିତି 1:		/* error, followed by error msg */
	ସ୍ଥିତି 2:		/* fatal error, "" */
		କର {
			ଯଦି (atomicio(ପଠ, remin, &ch, ଆକାର(ch)) != ଆକାର(ch))
				lostconn(0);
			*cp++ = ch;
		} ଯେତେବେଳେ (cp < &rbuf[ଆକାର(rbuf) - 1] && ch != '\n');

		ଯଦି (!iamremote) {
			cp[-1] = '\0';
			(ଶୂନ୍ୟ) snmprintf(visbuf, ଆକାର(visbuf),
			    ଖାଲି, "%s\n", rbuf);
			(ଶୂନ୍ୟ) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		ଯଦି (resp == 1)
			ଫେରନ୍ତୁ (-1);
		exit(1);
	}
	/* NOTREACHED */
}

ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
{
	(ଶୂନ୍ୟ) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

ଶୂନ୍ୟ
run_err(ଅଚଳ ଅକ୍ଷର *fmt,...)
{
	ସ୍ଥିର FILE *fp;
	va_list ap;

	++errs;
	ଯଦି (fp != ଖାଲି || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(ଶୂନ୍ୟ) fprintf(fp, "%c", 0x01);
		(ଶୂନ୍ୟ) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(ଶୂନ୍ୟ) vfprintf(fp, fmt, ap);
		va_end(ap);
		(ଶୂନ୍ୟ) fprintf(fp, "\n");
		(ଶୂନ୍ୟ) fflush(fp);
	}

	ଯଦି (!iamremote) {
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
note_err(ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	ସ୍ଥିର ଅକ୍ଷର *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	ଯଦି (fmt == ଖାଲି) {
		ଯଦି (emsg == ଖାଲି)
			ଫେରନ୍ତୁ 0;
		run_err("%s", emsg);
		ମୁକ୍ତ(emsg);
		emsg = ଖାଲି;
		ଫେରନ୍ତୁ -1;
	}

	errs++;
	/* Prefer first-noted error */
	ଯଦି (emsg != ଖାଲି)
		ଫେରନ୍ତୁ -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, ଖାଲି, fmt, ap);
	va_end(ap);
	ଫେରନ୍ତୁ -1;
}

ଶୂନ୍ୟ
verifydir(ଅକ୍ଷର *cp)
{
	ସଂରଚନା stat stb;

	ଯଦି (!stat(cp, &stb)) {
		ଯଦି (S_ISDIR(stb.st_mode))
			ଫେରନ୍ତୁ;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
okname(ଅକ୍ଷର *cp0)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c;
	ଅକ୍ଷର *cp;

	cp = cp0;
	କର {
		c = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)*cp;
		ଯଦି (c & 0200)
			ଯାଅ bad;
		ଯଦି (!isalpha(c) && !isdigit((unsigned ଅକ୍ଷର)c)) {
			ବାଛ (c) {
			ସ୍ଥିତି '\'':
			ସ୍ଥିତି '"':
			ସ୍ଥିତି '`':
			ସ୍ଥିତି ' ':
			ସ୍ଥିତି '#':
				ଯାଅ bad;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				ଭାଙ୍ଗ;
			}
		}
	} ଯେତେବେଳେ (*++cp);
	ଫେରନ୍ତୁ (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	ଫେରନ୍ତୁ (0);
}

BUF *
allocbuf(BUF *bp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	ସଂରଚନା stat stb;

	ଯଦି (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		ଫେରନ୍ତୁ (ଖାଲି);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	ଯଦି (size == 0)
		size = blksize;
#ଅନ୍ୟଥା /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ଯଦି (bp->cnt >= size)
		ଫେରନ୍ତୁ (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	ଫେରନ୍ତୁ (bp);
}

ଶୂନ୍ୟ
lostconn(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	ଯଦି (!iamremote)
		(ଶୂନ୍ୟ)ଲିଖ(STDERR_FILENO, "lost connection\n", 16);
	ଯଦି (signo)
		_exit(1);
	ଅନ୍ୟଥା
		exit(1);
}

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା i)
{
	ଯଦି (remin > 0)
		close(remin);
	ଯଦି (remout > 0)
		close(remout);
	ଯଦି (remin2 > 0)
		close(remin2);
	ଯଦି (remout2 > 0)
		close(remout2);
	ଯଦି (do_cmd_pid > 0)
		(ଶୂନ୍ୟ)waitpid(do_cmd_pid, ଖାଲି, 0);
	ଯଦି (do_cmd_pid2 > 0)
		(ଶୂନ୍ୟ)waitpid(do_cmd_pid2, ଖାଲି, 0);
	exit(i);
}
