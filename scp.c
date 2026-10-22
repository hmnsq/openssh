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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ifdef HAVE_FNMATCH_H
#ಅನ್ತರ್ಭಾವ <fnmatch.h>
#endif
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <libgen.h>
#ಅನ್ತರ್ಭಾವ <locale.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <util.h>
#ಯದಿ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ಅನ್ತರ್ಭಾವ <vis.h>
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "progressmeter.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"
#ಅನ್ತರ್ಭಾವ "sftp.h"

#ಅನ್ತರ್ಭಾವ "sftp-common.h"
#ಅನ್ತರ್ಭಾವ "sftp-client.h"

ಬಾಹ್ಯ ವರ್ಣ *__progname;

#define COPY_BUFLEN	16384

ಪೂರ್ಣಾಙ್ಕ do_cmd(ವರ್ಣ *, ವರ್ಣ *, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ *, ಪೂರ್ಣಾಙ್ಕ *, pid_t *);
ಪೂರ್ಣಾಙ್ಕ do_cmd2(ವರ್ಣ *, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
ಸಂರಚನಾ bwlimit bwlimit;

/* Name of current file being transferred. */
ವರ್ಣ *curfile;

/* This is set to non-zero to enable verbose mode. */
ಪೂರ್ಣಾಙ್ಕ verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
ಪೂರ್ಣಾಙ್ಕ showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
ಪೂರ್ಣಾಙ್ಕ throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
ಪೂರ್ಣಾಙ್ಕ sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
ವರ್ಣ *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
ಚಞ್ಚಲ sig_atomic_t interrupted = 0;

ಪೂರ್ಣಾಙ್ಕ sftp_glob(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ,
    ಪೂರ್ಣಾಙ್ಕ (*)(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ), glob_t *); /* proto for sftp-glob.c */

ಸ್ಥಿರ ಶೂನ್ಯ
killchild(ಪೂರ್ಣಾಙ್ಕ signo)
{
	ಯದಿ (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(ಶೂನ್ಯ)waitpid(do_cmd_pid, ರಿಕ್ತ, 0);
	}
	ಯದಿ (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(ಶೂನ್ಯ)waitpid(do_cmd_pid2, ರಿಕ್ತ, 0);
	}

	ಯದಿ (signo)
		_exit(1);
	exit(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
suspone(ಪೂರ್ಣಾಙ್ಕ pid, ಪೂರ್ಣಾಙ್ಕ signo)
{
	ಪೂರ್ಣಾಙ್ಕ status;

	ಯದಿ (pid > 1) {
		kill(pid, signo);
		ಯಾವತ್ (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
suspchild(ಪೂರ್ಣಾಙ್ಕ signo)
{
	ಪೂರ್ಣಾಙ್ಕ save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_local_cmd(arglist *a)
{
	ವರ್ಣ *cp;
	ಪೂರ್ಣಾಙ್ಕ status;
	pid_t pid;

	ಯದಿ (a->ಅಂಕೆ == 0)
		fatal("do_local_cmd: no arguments");

	ಯದಿ (verbose_mode) {
		cp = argv_assemble(a->ಅಂಕೆ, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		ಮುಕ್ತ(cp);
	}
	ಯದಿ ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	ಯದಿ (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	ಯಾವತ್ (waitpid(pid, &status, 0) == -1)
		ಯದಿ (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	ಯದಿ (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ಪ್ರತ್ಯಾಗಮ (-1);

	ಪ್ರತ್ಯಾಗಮ (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

ಪೂರ್ಣಾಙ್ಕ
do_cmd(ವರ್ಣ *program, ವರ್ಣ *host, ವರ್ಣ *remuser, ಪೂರ್ಣಾಙ್ಕ port, ಪೂರ್ಣಾಙ್ಕ subsystem,
    ವರ್ಣ *cmd, ಪೂರ್ಣಾಙ್ಕ *fdin, ಪೂರ್ಣಾಙ್ಕ *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	ಪೂರ್ಣಾಙ್ಕ pin[2], pout[2];
#ಅನ್ಯಥಾ
	ಪೂರ್ಣಾಙ್ಕ sv[2];
#endif

	ಯದಿ (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ಯದಿ (port == -1)
		port = sshport;

#ifdef USE_PIPES
	ಯದಿ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#ಅನ್ಯಥಾ
	/* Create a socket pair for communicating with ssh. */
	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	ವಿಕಲ್ಪ (*pid) {
	ಪಕ್ಷ -1:
		fatal("fork: %s", strerror(errno));
	ಪಕ್ಷ 0:
		/* Child. */
#ifdef USE_PIPES
		ಯದಿ (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#ಅನ್ಯಥಾ
		ಯದಿ (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		ಯದಿ (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		ಯದಿ (remuser != ರಿಕ್ತ) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		ಯದಿ (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	ಸ್ವಭಾವ:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#ಅನ್ಯಥಾ
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
ಪೂರ್ಣಾಙ್ಕ
do_cmd2(ವರ್ಣ *host, ವರ್ಣ *remuser, ಪೂರ್ಣಾಙ್ಕ port, ವರ್ಣ *cmd,
    ಪೂರ್ಣಾಙ್ಕ fdin, ಪೂರ್ಣಾಙ್ಕ fdout)
{
	ಪೂರ್ಣಾಙ್ಕ status;
	pid_t pid;

	ಯದಿ (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ಯದಿ (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	ಯದಿ (pid == 0) {
		ಯದಿ (dup2(fdin, 0) == -1)
			perror("dup2");
		ಯದಿ (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		ಯದಿ (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		ಯದಿ (remuser != ರಿಕ್ತ) {
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
	} ಅನ್ಯಥಾ ಯದಿ (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	ಯಾವತ್ (waitpid(pid, &status, 0) == -1)
		ಯದಿ (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ {
	size_t cnt;
	ವರ್ಣ *buf;
} BUF;

BUF *allocbuf(BUF *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ lostconn(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ okname(ವರ್ಣ *);
ಶೂನ್ಯ run_err(ಧ್ರುವ ವರ್ಣ *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
ಪೂರ್ಣಾಙ್ಕ note_err(ಧ್ರುವ ವರ್ಣ *,...)
    __attribute__((__format__ (printf, 1, 2)));
ಶೂನ್ಯ verifydir(ವರ್ಣ *);

ಸಂರಚನಾ passwd *pwd;
uid_t userid;
ಪೂರ್ಣಾಙ್ಕ errs, remin, remout, remin2, remout2;
ಪೂರ್ಣಾಙ್ಕ Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
ವರ್ಣ cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

ಗಣನಾ scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

ಪೂರ್ಣಾಙ್ಕ response(ಶೂನ್ಯ);
ಶೂನ್ಯ rsource(ವರ್ಣ *, ಸಂರಚನಾ stat *);
ಶೂನ್ಯ sink(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *[], ಧ್ರುವ ವರ್ಣ *);
ಶೂನ್ಯ source(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *[]);
ಶೂನ್ಯ tolocal(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *[], ಗಣನಾ scp_mode_e, ವರ್ಣ *sftp_direct);
ಶೂನ್ಯ toremote(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *[], ಗಣನಾ scp_mode_e, ವರ್ಣ *sftp_direct);
ಶೂನ್ಯ usage(ಶೂನ್ಯ);

ಶೂನ್ಯ source_sftp(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *, ವರ್ಣ *, ಸಂರಚನಾ sftp_conn *);
ಶೂನ್ಯ sink_sftp(ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sftp_conn *);
ಶೂನ್ಯ throughlocal_sftp(ಸಂರಚನಾ sftp_conn *, ಸಂರಚನಾ sftp_conn *,
    ವರ್ಣ *, ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ ch, fflag, tflag, status, r, n;
	ವರ್ಣ **newargv, *argv0;
	ಧ್ರುವ ವರ್ಣ *errstr;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಗಣನಾ scp_mode_e mode = MODE_SFTP;
	ವರ್ಣ *sftp_direct = ರಿಕ್ತ;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), ಪರಿಮಾಣ(*newargv));
	ಪ್ರತಿ (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', ಪರಿಮಾಣ(args));
	memset(&remote_remote_args, '\0', ಪರಿಮಾಣ(remote_remote_args));
	args.list = remote_remote_args.list = ರಿಕ್ತ;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	ಯಾವತ್ ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		/* User-visible flags. */
		ಪಕ್ಷ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ಭಙ್ಗ;
		ಪಕ್ಷ '2':
			/* Ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'A':
		ಪಕ್ಷ '4':
		ಪಕ್ಷ '6':
		ಪಕ್ಷ 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			sftp_direct = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ '3':
			throughlocal = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'o':
		ಪಕ್ಷ 'c':
		ಪಕ್ಷ 'i':
		ಪಕ್ಷ 'F':
		ಪಕ್ಷ 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'O':
			mode = MODE_SCP;
			ಭಙ್ಗ;
		ಪಕ್ಷ 's':
			/* Ignored */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			sshport = a2port(optarg);
			ಯದಿ (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ಯದಿ (errstr != ರಿಕ್ತ)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			pflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
			iamrecursive = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'S':
			ssh_program = xstrdup(optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			ಯದಿ (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಅನ್ಯಥಾ ಯದಿ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'X':
			/* Please keep in sync with sftp.c -X */
			ಯದಿ (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				ಯದಿ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ಯದಿ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} ಅನ್ಯಥಾ ಯದಿ (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ಯದಿ (errstr != ರಿಕ್ತ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} ಅನ್ಯಥಾ {
				fatal("Invalid -X option");
			}
			ಭಙ್ಗ;

		/* Server options. */
		ಪಕ್ಷ 'd':
			targetshouldbedirectory = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_ದ್ವಿಮಾನ);
#endif
			ಭಙ್ಗ;
		ಪಕ್ಷ 'T':
			Tflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	ಯದಿ (iamremote)
		mode = MODE_SCP;

	ಯದಿ ((pwd = getpwuid(userid = getuid())) == ರಿಕ್ತ)
		fatal("unknown user %u", (u_int) userid);

	ಯದಿ (!isatty(STDOUT_FILENO))
		showprogress = 0;

	ಯದಿ (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} ಅನ್ಯಥಾ {
		ಯದಿ (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ರಿಕ್ತ) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	ಯದಿ (fflag) {
		/* Follow "protocol", send data. */
		(ಶೂನ್ಯ) response();
		source(argc, argv);
		exit(errs != 0);
	}
	ಯದಿ (tflag) {
		/* Receive data. */
		sink(argc, argv, ರಿಕ್ತ);
		exit(errs != 0);
	}
	ಯದಿ (argc < 2)
		usage();
	ಯದಿ (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(ಶೂನ್ಯ) snprintf(cmd, ಪರಿಮಾಣ cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(ಶೂನ್ಯ) ssh_signal(SIGPIPE, lostconn);

	ಯದಿ (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	ಅನ್ಯಥಾ {
		ಯದಿ (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	ಯದಿ (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		ಯದಿ (remin != -1)
		    (ಶೂನ್ಯ) close(remin);
		ಯದಿ (remout != -1)
		    (ಶೂನ್ಯ) close(remout);
		ಯದಿ (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		ಅನ್ಯಥಾ {
			ಯದಿ (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
scpio(ಶೂನ್ಯ *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	ಯದಿ (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_times(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ verb, ಧ್ರುವ ಸಂರಚನಾ stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	ವರ್ಣ buf[(20 + 7 + 2) * 2 + 2];

	(ಶೂನ್ಯ)snprintf(buf, ಪರಿಮಾಣ(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	ಯದಿ (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(ಶೂನ್ಯ) atomicio(vwrite, fd, buf, strlen(buf));
	ಪ್ರತ್ಯಾಗಮ (response());
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_scp_uri(ಧ್ರುವ ವರ್ಣ *uri, ವರ್ಣ **userp, ವರ್ಣ **hostp, ಪೂರ್ಣಾಙ್ಕ *portp,
    ವರ್ಣ **pathp)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	ಯದಿ (r == 0 && *pathp == ರಿಕ್ತ)
		*pathp = xstrdup(".");
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
append(ವರ್ಣ *cp, ವರ್ಣ ***ap, size_t *np)
{
	ವರ್ಣ **tmp;

	ಯದಿ ((tmp = reallocarray(*ap, *np + 1, ಪರಿಮಾಣ(*tmp))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
find_brace(ಧ್ರುವ ವರ್ಣ *pattern, ಪೂರ್ಣಾಙ್ಕ *startp, ಪೂರ್ಣಾಙ್ಕ *endp)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪೂರ್ಣಾಙ್ಕ in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	ಪ್ರತಿ (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		ವಿಕಲ್ಪ (pattern[i]) {
		ಪಕ್ಷ '\\':
			/* skip next character */
			ಯದಿ (pattern[i + 1] != '\0')
				i++;
			ಭಙ್ಗ;
		ಪಕ್ಷ '[':
			in_bracket = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ ']':
			in_bracket = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ '{':
			ಯದಿ (in_bracket)
				ಭಙ್ಗ;
			ಯದಿ (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				ಭಙ್ಗ;
			}
			ಯದಿ (*startp == -1)
				*startp = i;
			brace_level++;
			ಭಙ್ಗ;
		ಪಕ್ಷ '}':
			ಯದಿ (in_bracket)
				ಭಙ್ಗ;
			ಯದಿ (*startp < 0) {
				/* Unbalanced brace */
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			ಯದಿ (--brace_level <= 0)
				*endp = i;
			ಭಙ್ಗ;
		}
	}
	/* unbalanced brackets/braces */
	ಯದಿ (*endp < 0 && (*startp >= 0 || in_bracket))
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
emit_expansion(ಧ್ರುವ ವರ್ಣ *pattern, ಪೂರ್ಣಾಙ್ಕ brace_start, ಪೂರ್ಣಾಙ್ಕ brace_end,
    ಪೂರ್ಣಾಙ್ಕ sel_start, ಪೂರ್ಣಾಙ್ಕ sel_end, ವರ್ಣ ***patternsp, size_t *npatternsp)
{
	ವರ್ಣ *cp;
	size_t pattern_len;
	ಪೂರ್ಣಾಙ್ಕ o = 0, tail_len;

	ಯದಿ ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		ಪ್ರತ್ಯಾಗಮ -1;

	tail_len = strlen(pattern + brace_end + 1);
	ಯದಿ ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Pattern before initial brace */
	ಯದಿ (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	ಯದಿ (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	ಯದಿ (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	ಯದಿ (append(cp, patternsp, npatternsp) != 0) {
		ಮುಕ್ತ(cp);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
brace_expand_one(ಧ್ರುವ ವರ್ಣ *pattern, ವರ್ಣ ***patternsp, size_t *npatternsp,
    ಪೂರ್ಣಾಙ್ಕ *expanded, ಪೂರ್ಣಾಙ್ಕ *invalid)
{
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪೂರ್ಣಾಙ್ಕ in_bracket, brace_start, brace_end, brace_level;
	ಪೂರ್ಣಾಙ್ಕ sel_start, sel_end;

	*invalid = *expanded = 0;

	ಯದಿ (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		ಪ್ರತ್ಯಾಗಮ 0;
	} ಅನ್ಯಥಾ ಯದಿ (brace_start == -1)
		ಪ್ರತ್ಯಾಗಮ 0;

	in_bracket = brace_level = 0;
	ಪ್ರತಿ (i = sel_start = brace_start + 1; i < brace_end; i++) {
		ವಿಕಲ್ಪ (pattern[i]) {
		ಪಕ್ಷ '{':
			ಯದಿ (in_bracket)
				ಭಙ್ಗ;
			brace_level++;
			ಭಙ್ಗ;
		ಪಕ್ಷ '}':
			ಯದಿ (in_bracket)
				ಭಙ್ಗ;
			brace_level--;
			ಭಙ್ಗ;
		ಪಕ್ಷ '[':
			in_bracket = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ ']':
			in_bracket = 0;
			ಭಙ್ಗ;
		ಪಕ್ಷ '\\':
			ಯದಿ (i < brace_end - 1)
				i++; /* skip */
			ಭಙ್ಗ;
		}
		ಯದಿ (pattern[i] == ',' || i == brace_end - 1) {
			ಯದಿ (in_bracket || brace_level > 0)
				ಅನುವರ್ತ;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			ಯದಿ (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				ಪ್ರತ್ಯಾಗಮ -1;
			/* move on to the next selection */
			sel_start = i + 1;
			ಅನುವರ್ತ;
		}
	}
	ಯದಿ (in_bracket || brace_level > 0) {
		*invalid = 1;
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	/* success */
	*expanded = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
brace_expand(ಧ್ರುವ ವರ್ಣ *pattern, ವರ್ಣ ***patternsp, size_t *npatternsp)
{
	ವರ್ಣ *cp, *cp2, **active = ರಿಕ್ತ, **done = ರಿಕ್ತ;
	size_t i, nactive = 0, ndone = 0;
	ಪೂರ್ಣಾಙ್ಕ ret = -1, invalid = 0, expanded = 0;

	*patternsp = ರಿಕ್ತ;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	ಯದಿ ((cp = strdup(pattern)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (append(cp, &active, &nactive) != 0) {
		ಮುಕ್ತ(cp);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯಾವತ್ (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		ಯದಿ (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			ಮುಕ್ತ(cp);
			ಗಚ್ಛ fail;
		}
		ಯದಿ (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		ಯದಿ (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			ಮುಕ್ತ(cp);
			ಅನುವರ್ತ;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		ಯದಿ ((cp2 = strrchr(cp, '/')) != ರಿಕ್ತ)
			*cp2++ = '\0';
		ಅನ್ಯಥಾ
			cp2 = cp;
		ಯದಿ (append(xstrdup(cp2), &done, &ndone) != 0) {
			ಮುಕ್ತ(cp);
			ಗಚ್ಛ fail;
		}
		ಮುಕ್ತ(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = ರಿಕ್ತ;
	ndone = 0;
	ret = 0;
 fail:
	ಪ್ರತಿ (i = 0; i < nactive; i++)
		ಮುಕ್ತ(active[i]);
	ಮುಕ್ತ(active);
	ಪ್ರತಿ (i = 0; i < ndone; i++)
		ಮುಕ್ತ(done[i]);
	ಮುಕ್ತ(done);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಸಂರಚನಾ sftp_conn *
do_sftp_connect(ವರ್ಣ *host, ವರ್ಣ *user, ಪೂರ್ಣಾಙ್ಕ port, ವರ್ಣ *sftp_direct,
   ಪೂರ್ಣಾಙ್ಕ *reminp, ಪೂರ್ಣಾಙ್ಕ *remoutp, ಪೂರ್ಣಾಙ್ಕ *pidp)
{
	ಯದಿ (sftp_direct == ರಿಕ್ತ) {
		ಯದಿ (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	} ಅನ್ಯಥಾ {
		freeargs(&args);
		addargs(&args, "sftp-server");
		ಯದಿ (do_cmd(sftp_direct, host, ರಿಕ್ತ, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

ಶೂನ್ಯ
toremote(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv, ಗಣನಾ scp_mode_e mode, ವರ್ಣ *sftp_direct)
{
	ವರ್ಣ *suser = ರಿಕ್ತ, *host = ರಿಕ್ತ, *src = ರಿಕ್ತ;
	ವರ್ಣ *bp, *tuser, *thost, *targ;
	ಪೂರ್ಣಾಙ್ಕ sport = -1, tport = -1;
	ಸಂರಚನಾ sftp_conn *conn = ರಿಕ್ತ, *conn2 = ರಿಕ್ತ;
	arglist alist;
	ಪೂರ್ಣಾಙ್ಕ i, r, status;
	ಸಂರಚನಾ stat sb;
	u_int j;

	memset(&alist, '\0', ಪರಿಮಾಣ(alist));
	alist.list = ರಿಕ್ತ;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	ಯದಿ (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		ಗಚ್ಛ out;
	}
	ಯದಿ (r != 0) {
		ಯದಿ (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			ಗಚ್ಛ out;
		}
	}

	/* Parse source files */
	ಪ್ರತಿ (i = 0; i < argc - 1; i++) {
		ಮುಕ್ತ(suser);
		ಮುಕ್ತ(host);
		ಮುಕ್ತ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ಯದಿ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ಅನುವರ್ತ;
		}
		ಯದಿ (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		ಯದಿ (suser != ರಿಕ್ತ && !okname(suser)) {
			++errs;
			ಅನುವರ್ತ;
		}
		ಯದಿ (host && throughlocal) {	/* extended remote to remote */
			ಯದಿ (mode == MODE_SFTP) {
				ಯದಿ (remin == -1 || conn == ರಿಕ್ತ) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					ಯದಿ (conn == ರಿಕ್ತ) {
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
				ಯದಿ (conn2 == ರಿಕ್ತ) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(ಶೂನ್ಯ) close(remin2);
				(ಶೂನ್ಯ) close(remout2);
				remin2 = remout2 = -1;
				ಯದಿ (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				ಅನ್ಯಥಾ ಯದಿ (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				ಅನುವರ್ತ;
			} ಅನ್ಯಥಾ {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				ಯದಿ (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				ಮುಕ್ತ(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ಯದಿ (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				ಮುಕ್ತ(bp);
				(ಶೂನ್ಯ) close(remin);
				(ಶೂನ್ಯ) close(remout);
				remin = remout = -1;
			}
		} ಅನ್ಯಥಾ ಯದಿ (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			ಯದಿ (tuser != ರಿಕ್ತ && !okname(tuser)) {
				++errs;
				ಅನುವರ್ತ;
			}
			ಯದಿ (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			ಪ್ರತಿ (j = 0; j < remote_remote_args.ಅಂಕೆ; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			ಯದಿ (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			ಯದಿ (suser) {
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
			ಯದಿ (do_local_cmd(&alist) != 0)
				errs = 1;
		} ಅನ್ಯಥಾ {	/* local to remote */
			ಯದಿ (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				ಯದಿ (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				ಯದಿ (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					ಯದಿ (conn == ರಿಕ್ತ) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				ಅನುವರ್ತ;
			}
			/* SCP */
			ಯದಿ (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ಯದಿ (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				ಯದಿ (response() < 0)
					exit(1);
				ಮುಕ್ತ(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	ಮುಕ್ತ(tuser);
	ಮುಕ್ತ(thost);
	ಮುಕ್ತ(targ);
	ಮುಕ್ತ(suser);
	ಮುಕ್ತ(host);
	ಮುಕ್ತ(src);
	sftp_free(conn);
	sftp_free(conn2);
}

ಶೂನ್ಯ
tolocal(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv, ಗಣನಾ scp_mode_e mode, ವರ್ಣ *sftp_direct)
{
	ವರ್ಣ *bp, *host = ರಿಕ್ತ, *src = ರಿಕ್ತ, *suser = ರಿಕ್ತ;
	arglist alist;
	ಸಂರಚನಾ sftp_conn *conn = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i, r, sport = -1;

	memset(&alist, '\0', ಪರಿಮಾಣ(alist));
	alist.list = ರಿಕ್ತ;

	ಪ್ರತಿ (i = 0; i < argc - 1; i++) {
		ಮುಕ್ತ(suser);
		ಮುಕ್ತ(host);
		ಮುಕ್ತ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ಯದಿ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ಅನುವರ್ತ;
		}
		ಯದಿ (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		ಯದಿ (suser != ರಿಕ್ತ && !okname(suser)) {
			++errs;
			ಅನುವರ್ತ;
		}
		ಯದಿ (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			ಯದಿ (iamrecursive)
				addargs(&alist, "-r");
			ಯದಿ (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			ಯದಿ (do_local_cmd(&alist))
				++errs;
			ಅನುವರ್ತ;
		}
		/* Remote to local. */
		ಯದಿ (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			ಯದಿ (conn == ರಿಕ್ತ) {
				error("sftp connection failed");
				++errs;
				ಅನುವರ್ತ;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(ಶೂನ್ಯ) close(remin);
			(ಶೂನ್ಯ) close(remout);
			remin = remout = -1;
			ಅನುವರ್ತ;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		ಯದಿ (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			ಮುಕ್ತ(bp);
			++errs;
			ಅನುವರ್ತ;
		}
		ಮುಕ್ತ(bp);
		sink(1, argv + argc - 1, src);
		(ಶೂನ್ಯ) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	ಮುಕ್ತ(suser);
	ಮುಕ್ತ(host);
	ಮುಕ್ತ(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
ಸ್ಥಿರ ವರ್ಣ *
prepare_remote_path(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	ಯದಿ (*path == '\0' || strcmp(path, "~") == 0)
		ಪ್ರತ್ಯಾಗಮ xstrdup(".");
	ಯದಿ (*path != '~')
		ಪ್ರತ್ಯಾಗಮ xstrdup(path);
	ಯದಿ (strncmp(path, "~/", 2) == 0) {
		ಯದಿ ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			ಪ್ರತ್ಯಾಗಮ xstrdup(".");
		ಪ್ರತ್ಯಾಗಮ xstrdup(path + 2 + nslash);
	}
	ಯದಿ (sftp_can_expand_path(conn))
		ಪ್ರತ್ಯಾಗಮ sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಶೂನ್ಯ
source_sftp(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ *src, ವರ್ಣ *targ, ಸಂರಚನಾ sftp_conn *conn)
{
	ವರ್ಣ *target = ರಿಕ್ತ, *filename = ರಿಕ್ತ, *abs_dst = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ src_is_dir, target_is_dir;
	Attrib a;
	ಸಂರಚನಾ stat st;

	memset(&a, '\0', ಪರಿಮಾಣ(a));
	ಯದಿ (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	ಯದಿ ((filename = basename(src)) == ರಿಕ್ತ)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	ಯದಿ (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	ಯದಿ ((target = prepare_remote_path(conn, targ)) == ರಿಕ್ತ)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	ಯದಿ (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		ಯದಿ (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	ಯದಿ (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	ಅನ್ಯಥಾ {
		abs_dst = target;
		target = ರಿಕ್ತ;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	ಯದಿ (src_is_dir && iamrecursive) {
		ಯದಿ (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} ಅನ್ಯಥಾ ಯದಿ (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	ಮುಕ್ತ(abs_dst);
	ಮುಕ್ತ(target);
}

ಶೂನ್ಯ
source(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಸಂರಚನಾ stat stb;
	ಸ್ಥಿರ BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	ಪೂರ್ಣಾಙ್ಕ fd = -1, haderr, indx;
	ವರ್ಣ *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	ಪೂರ್ಣಾಙ್ಕ len;

	ಪ್ರತಿ (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		ಯಾವತ್ (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		ಯದಿ ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			ಗಚ್ಛ syserr;
		ಯದಿ (strchr(name, '\n') != ರಿಕ್ತ) {
			strnvis(encname, name, ಪರಿಮಾಣ(encname), VIS_NL);
			name = encname;
		}
		ಯದಿ (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			ಗಚ್ಛ next;
		}
		ಯದಿ (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			ಗಚ್ಛ next;
		}
		unset_nonblock(fd);
		ವಿಕಲ್ಪ (stb.st_mode & S_IFMT) {
		ಪಕ್ಷ S_IFREG:
			ಭಙ್ಗ;
		ಪಕ್ಷ S_IFDIR:
			ಯದಿ (iamrecursive) {
				rsource(name, &stb);
				ಗಚ್ಛ next;
			}
			/* FALLTHROUGH */
		ಸ್ವಭಾವ:
			run_err("%s: not a regular file", name);
			ಗಚ್ಛ next;
		}
		ಯದಿ ((last = strrchr(name, '/')) == ರಿಕ್ತ)
			last = name;
		ಅನ್ಯಥಾ
			++last;
		curfile = last;
		ಯದಿ (pflag) {
			ಯದಿ (do_times(remout, verbose_mode, &stb) < 0)
				ಗಚ್ಛ next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, ಪರಿಮಾಣ buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		ಯದಿ (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(ಶೂನ್ಯ) atomicio(vwrite, remout, buf, strlen(buf));
		ಯದಿ (response() < 0)
			ಗಚ್ಛ next;
		ಯದಿ ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == ರಿಕ್ತ) {
next:			ಯದಿ (fd != -1) {
				(ಶೂನ್ಯ) close(fd);
				fd = -1;
			}
			ಅನುವರ್ತ;
		}
		ಯದಿ (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		ಪ್ರತಿ (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			ಯದಿ (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			ಯದಿ (!haderr) {
				ಯದಿ ((nr = atomicio(ಪಠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			ಯದಿ (haderr) {
				(ಶೂನ್ಯ)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				ಅನುವರ್ತ;
			}
			ಯದಿ (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		ಯದಿ (fd != -1) {
			ಯದಿ (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		ಯದಿ (!haderr)
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
		ಅನ್ಯಥಾ
			run_err("%s: %s", name, strerror(haderr));
		(ಶೂನ್ಯ) response();
		ಯದಿ (showprogress)
			stop_progress_meter();
	}
}

ಶೂನ್ಯ
rsource(ವರ್ಣ *name, ಸಂರಚನಾ stat *statp)
{
	DIR *dirp;
	ಸಂರಚನಾ dirent *dp;
	ವರ್ಣ *last, *vect[1], path[PATH_MAX];

	ಯದಿ (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ;
	}
	last = strrchr(name, '/');
	ಯದಿ (last == ರಿಕ್ತ)
		last = name;
	ಅನ್ಯಥಾ
		last++;
	ಯದಿ (pflag) {
		ಯದಿ (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			ಪ್ರತ್ಯಾಗಮ;
		}
	}
	(ಶೂನ್ಯ) snprintf(path, ಪರಿಮಾಣ path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	ಯದಿ (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(ಶೂನ್ಯ) atomicio(vwrite, remout, path, strlen(path));
	ಯದಿ (response() < 0) {
		closedir(dirp);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯಾವತ್ ((dp = readdir(dirp)) != ರಿಕ್ತ) {
		ಯದಿ (dp->d_ino == 0)
			ಅನುವರ್ತ;
		ಯದಿ (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			ಅನುವರ್ತ;
		ಯದಿ (strlen(name) + 1 + strlen(dp->d_name) >= ಪರಿಮಾಣ(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			ಅನುವರ್ತ;
		}
		(ಶೂನ್ಯ) snprintf(path, ಪರಿಮಾಣ path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(ಶೂನ್ಯ) closedir(dirp);
	(ಶೂನ್ಯ) atomicio(vwrite, remout, "E\n", 2);
	(ಶೂನ್ಯ) response();
}

ಶೂನ್ಯ
sink_sftp(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, ಸಂರಚನಾ sftp_conn *conn)
{
	ವರ್ಣ *abs_src = ರಿಕ್ತ;
	ವರ್ಣ *abs_dst = ರಿಕ್ತ;
	glob_t g;
	ವರ್ಣ *filename, *tmp = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ i, r, err = 0, dst_is_dir;
	ಸಂರಚನಾ stat st;

	memset(&g, 0, ಪರಿಮಾಣ(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	ಯದಿ ((abs_src = prepare_remote_path(conn, src)) == ರಿಕ್ತ) {
		err = -1;
		ಗಚ್ಛ out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	ಯದಿ ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ರಿಕ್ತ, &g)) != 0) {
		ಯದಿ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ಅನ್ಯಥಾ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ಗಚ್ಛ out;
	}

	/* Did we actually get any matches back from the glob? */
	ಯದಿ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ರಿಕ್ತ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ಯದಿ (sftp_stat(conn, g.gl_pathv[0], 1, ರಿಕ್ತ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ಗಚ್ಛ out;
		}
	}

	ಯದಿ ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	ಯದಿ (g.gl_matchc > 1 && !dst_is_dir) {
		ಯದಿ (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			ಗಚ್ಛ out;
		}
		debug2_f("creating destination \"%s\"", dst);
		ಯದಿ (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			ಗಚ್ಛ out;
		}
		dst_is_dir = 1;
	}

	ಪ್ರತಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ಯದಿ ((filename = basename(tmp)) == ರಿಕ್ತ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ಗಚ್ಛ out;
		}

		/* Special handling for destination of '..' */
		ಯದಿ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ಯದಿ (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		ಅನ್ಯಥಾ
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ಯದಿ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ಯದಿ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ರಿಕ್ತ, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} ಅನ್ಯಥಾ {
			ಯದಿ (sftp_download(conn, g.gl_pathv[i], abs_dst, ರಿಕ್ತ,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		ಮುಕ್ತ(abs_dst);
		abs_dst = ರಿಕ್ತ;
		ಮುಕ್ತ(tmp);
		tmp = ರಿಕ್ತ;
	}

out:
	ಮುಕ್ತ(abs_src);
	ಮುಕ್ತ(tmp);
	globfree(&g);
	ಯದಿ (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((ಪರಿಮಾಣ(type) == 4 && (val) > INT32_MAX) || \
	 (ಪರಿಮಾಣ(type) == 8 && (val) > INT64_MAX) || \
	 (ಪರಿಮಾಣ(type) != 4 && ಪರಿಮಾಣ(type) != 8))

ಶೂನ್ಯ
sink(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv, ಧ್ರುವ ವರ್ಣ *src)
{
	ಸ್ಥಿರ BUF buffer;
	ಸಂರಚನಾ stat stb;
	BUF *bp;
	off_t i;
	size_t j, ಎಣಿಕೆ;
	ಪೂರ್ಣಾಙ್ಕ amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	ಪೂರ್ಣಾಙ್ಕ setimes, targisdir, wrerr;
	ವರ್ಣ ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	ವರ್ಣ **patterns = ರಿಕ್ತ;
	size_t n, npatterns = 0;
	ಸಂರಚನಾ timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; ಗಚ್ಛ screwup; }

	ಯದಿ (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	ಯದಿ (!pflag) {
		(ಶೂನ್ಯ) umask(mask);
		mask |= 07000;
	}
	ಯದಿ (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	ಯದಿ (targetshouldbedirectory)
		verifydir(targ);

	(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
	ಯದಿ (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	ಯದಿ (src != ರಿಕ್ತ && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		ಯದಿ (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	ಪ್ರತಿ (first = 1;; first = 0) {
		cp = buf;
		ಯದಿ (atomicio(ಪಠ, remin, cp, 1) != 1)
			ಗಚ್ಛ done;
		ಯದಿ (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		ಕುರು {
			ಯದಿ (atomicio(ಪಠ, remin, &ch, ಪರಿಮಾಣ(ch)) != ಪರಿಮಾಣ(ch))
				SCREWUP("lost connection");
			ಯದಿ (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} ಯಾವತ್ (cp < &buf[ಪರಿಮಾಣ(buf) - 1] && ch != '\n');
		*cp = 0;
		ಯದಿ (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		ಯದಿ (buf[0] == '\01' || buf[0] == '\02') {
			ಯದಿ (iamremote == 0) {
				(ಶೂನ್ಯ) snmprintf(visbuf, ಪರಿಮಾಣ(visbuf),
				    ರಿಕ್ತ, "%s", buf + 1);
				(ಶೂನ್ಯ) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			ಯದಿ (buf[0] == '\02')
				exit(1);
			++errs;
			ಅನುವರ್ತ;
		}
		ಯದಿ (buf[0] == 'E') {
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
			ಗಚ್ಛ done;
		}
		ಯದಿ (ch == '\n')
			*--cp = 0;

		cp = buf;
		ಯದಿ (*cp == 'T') {
			setimes++;
			cp++;
			ಯದಿ (!isdigit((unsigned ವರ್ಣ)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ಯದಿ (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			ಯದಿ (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			ಯದಿ (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			ಯದಿ (!isdigit((unsigned ವರ್ಣ)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ಯದಿ (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			ಯದಿ (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			ಯದಿ (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
			ಅನುವರ್ತ;
		}
		ಯದಿ (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			ಯದಿ (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		ಪ್ರತಿ (++cp; cp < buf + 5; cp++) {
			ಯದಿ (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		ಯದಿ (!pflag)
			mode &= ~mask;
		ಯದಿ (*cp++ != ' ')
			SCREWUP("mode not delimited");

		ಯದಿ (!isdigit((unsigned ವರ್ಣ)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		ಯದಿ (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		ಯದಿ (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		ಯದಿ (*cp == '\0' || strchr(cp, '/') != ರಿಕ್ತ ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		ಯದಿ (npatterns > 0) {
			ಪ್ರತಿ (n = 0; n < npatterns; n++) {
				ಯದಿ (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					ಭಙ್ಗ;
			}
			ಯದಿ (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				ಪ್ರತಿ (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		ಯದಿ (targisdir) {
			ಸ್ಥಿರ ವರ್ಣ *namebuf;
			ಸ್ಥಿರ size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			ಯದಿ (need > cursize) {
				ಮುಕ್ತ(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(ಶೂನ್ಯ) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} ಅನ್ಯಥಾ
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		ಯದಿ (buf[0] == 'D') {
			ಪೂರ್ಣಾಙ್ಕ mod_flag = pflag;
			ಯದಿ (!iamrecursive)
				SCREWUP("received directory without -r");
			ಯದಿ (exists) {
				ಯದಿ (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					ಗಚ್ಛ bad;
				}
				ಯದಿ (pflag)
					(ಶೂನ್ಯ) chmod(np, mode);
			} ಅನ್ಯಥಾ {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				ಯದಿ (mkdir(np, mode | S_IRWXU) == -1)
					ಗಚ್ಛ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			ಯದಿ (setimes) {
				setimes = 0;
				(ಶೂನ್ಯ) utimes(vect[0], tv);
			}
			ಯದಿ (mod_flag)
				(ಶೂನ್ಯ) chmod(vect[0], mode);
			ಮುಕ್ತ(vect[0]);
			ಅನುವರ್ತ;
		}
		omode = mode;
		mode |= S_IWUSR;
		ಯದಿ ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			ಅನುವರ್ತ;
		}
		(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
		ಯದಿ ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == ರಿಕ್ತ) {
			(ಶೂನ್ಯ) close(ofd);
			ಅನುವರ್ತ;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		ಯದಿ (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		ಪ್ರತಿ (ಎಣಿಕೆ = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			ಯದಿ (i + amt > size)
				amt = size - i;
			ಎಣಿಕೆ += amt;
			ಕುರು {
				j = atomicio6(ಪಠ, remin, cp, amt,
				    scpio, &statbytes);
				ಯದಿ (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} ಯಾವತ್ (amt > 0);

			ಯದಿ (ಎಣಿಕೆ == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				ಯದಿ (!wrerr) {
					ಯದಿ (atomicio(vwrite, ofd, bp->buf,
					    ಎಣಿಕೆ) != ಎಣಿಕೆ) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				ಎಣಿಕೆ = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		ಯದಿ (ಎಣಿಕೆ != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, ಎಣಿಕೆ) != ಎಣಿಕೆ) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		ಯದಿ (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		ಯದಿ (pflag) {
			ಯದಿ (exists || omode != mode)
#ifdef HAVE_FCHMOD
				ಯದಿ (fchmod(ofd, omode)) {
#ಅನ್ಯಥಾ /* HAVE_FCHMOD */
				ಯದಿ (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} ಅನ್ಯಥಾ {
			ಯದಿ (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				ಯದಿ (fchmod(ofd, omode & ~mask)) {
#ಅನ್ಯಥಾ /* HAVE_FCHMOD */
				ಯದಿ (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		ಯದಿ (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(ಶೂನ್ಯ) response();
		ಯದಿ (showprogress)
			stop_progress_meter();
		ಯದಿ (setimes && !wrerr) {
			setimes = 0;
			ಯದಿ (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		ಯದಿ (note_err(ರಿಕ್ತ) == 0)
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
	}
done:
	ಪ್ರತಿ (n = 0; n < npatterns; n++)
		ಮುಕ್ತ(patterns[n]);
	ಮುಕ್ತ(patterns);
	ಪ್ರತ್ಯಾಗಮ;
screwup:
	ಪ್ರತಿ (n = 0; n < npatterns; n++)
		ಮುಕ್ತ(patterns[n]);
	ಮುಕ್ತ(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

ಶೂನ್ಯ
throughlocal_sftp(ಸಂರಚನಾ sftp_conn *from, ಸಂರಚನಾ sftp_conn *to,
    ವರ್ಣ *src, ವರ್ಣ *targ)
{
	ವರ್ಣ *target = ರಿಕ್ತ, *filename = ರಿಕ್ತ, *abs_dst = ರಿಕ್ತ;
	ವರ್ಣ *abs_src = ರಿಕ್ತ, *tmp = ರಿಕ್ತ;
	glob_t g;
	ಪೂರ್ಣಾಙ್ಕ i, r, targetisdir, err = 0;

	ಯದಿ ((filename = basename(src)) == ರಿಕ್ತ)
		fatal("basename %s: %s", src, strerror(errno));

	ಯದಿ ((abs_src = prepare_remote_path(from, src)) == ರಿಕ್ತ ||
	    (target = prepare_remote_path(to, targ)) == ರಿಕ್ತ)
		cleanup_exit(255);
	memset(&g, 0, ಪರಿಮಾಣ(g));

	targetisdir = sftp_remote_is_dir(to, target);
	ಯದಿ (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		ಗಚ್ಛ out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	ಯದಿ ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ರಿಕ್ತ, &g)) != 0) {
		ಯದಿ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ಅನ್ಯಥಾ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ಗಚ್ಛ out;
	}

	/* Did we actually get any matches back from the glob? */
	ಯದಿ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ರಿಕ್ತ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ಯದಿ (sftp_stat(from, g.gl_pathv[0], 1, ರಿಕ್ತ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ಗಚ್ಛ out;
		}
	}

	ಪ್ರತಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ಯದಿ ((filename = basename(tmp)) == ರಿಕ್ತ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ಗಚ್ಛ out;
		}

		/* Special handling for source of '..' */
		ಯದಿ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ಯದಿ (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		ಅನ್ಯಥಾ
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ಯದಿ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ಯದಿ (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    ರಿಕ್ತ, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} ಅನ್ಯಥಾ {
			ಯದಿ (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    ರಿಕ್ತ, pflag) == -1)
				err = -1;
		}
		ಮುಕ್ತ(abs_dst);
		abs_dst = ರಿಕ್ತ;
		ಮುಕ್ತ(tmp);
		tmp = ರಿಕ್ತ;
	}

out:
	ಮುಕ್ತ(abs_src);
	ಮುಕ್ತ(abs_dst);
	ಮುಕ್ತ(target);
	ಮುಕ್ತ(tmp);
	globfree(&g);
	ಯದಿ (err == -1)
		errs = 1;
}

ಪೂರ್ಣಾಙ್ಕ
response(ಶೂನ್ಯ)
{
	ವರ್ಣ ch, *cp, resp, rbuf[2048], visbuf[2048];

	ಯದಿ (atomicio(ಪಠ, remin, &resp, ಪರಿಮಾಣ(resp)) != ಪರಿಮಾಣ(resp))
		lostconn(0);

	cp = rbuf;
	ವಿಕಲ್ಪ (resp) {
	ಪಕ್ಷ 0:		/* ok */
		ಪ್ರತ್ಯಾಗಮ (0);
	ಸ್ವಭಾವ:
		*cp++ = resp;
		/* FALLTHROUGH */
	ಪಕ್ಷ 1:		/* error, followed by error msg */
	ಪಕ್ಷ 2:		/* fatal error, "" */
		ಕುರು {
			ಯದಿ (atomicio(ಪಠ, remin, &ch, ಪರಿಮಾಣ(ch)) != ಪರಿಮಾಣ(ch))
				lostconn(0);
			*cp++ = ch;
		} ಯಾವತ್ (cp < &rbuf[ಪರಿಮಾಣ(rbuf) - 1] && ch != '\n');

		ಯದಿ (!iamremote) {
			cp[-1] = '\0';
			(ಶೂನ್ಯ) snmprintf(visbuf, ಪರಿಮಾಣ(visbuf),
			    ರಿಕ್ತ, "%s\n", rbuf);
			(ಶೂನ್ಯ) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		ಯದಿ (resp == 1)
			ಪ್ರತ್ಯಾಗಮ (-1);
		exit(1);
	}
	/* NOTREACHED */
}

ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	(ಶೂನ್ಯ) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

ಶೂನ್ಯ
run_err(ಧ್ರುವ ವರ್ಣ *fmt,...)
{
	ಸ್ಥಿರ FILE *fp;
	va_list ap;

	++errs;
	ಯದಿ (fp != ರಿಕ್ತ || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(ಶೂನ್ಯ) fprintf(fp, "%c", 0x01);
		(ಶೂನ್ಯ) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(ಶೂನ್ಯ) vfprintf(fp, fmt, ap);
		va_end(ap);
		(ಶೂನ್ಯ) fprintf(fp, "\n");
		(ಶೂನ್ಯ) fflush(fp);
	}

	ಯದಿ (!iamremote) {
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
ಪೂರ್ಣಾಙ್ಕ
note_err(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	ಸ್ಥಿರ ವರ್ಣ *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	ಯದಿ (fmt == ರಿಕ್ತ) {
		ಯದಿ (emsg == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ 0;
		run_err("%s", emsg);
		ಮುಕ್ತ(emsg);
		emsg = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	errs++;
	/* Prefer first-noted error */
	ಯದಿ (emsg != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, ರಿಕ್ತ, fmt, ap);
	va_end(ap);
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಶೂನ್ಯ
verifydir(ವರ್ಣ *cp)
{
	ಸಂರಚನಾ stat stb;

	ಯದಿ (!stat(cp, &stb)) {
		ಯದಿ (S_ISDIR(stb.st_mode))
			ಪ್ರತ್ಯಾಗಮ;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

ಪೂರ್ಣಾಙ್ಕ
okname(ವರ್ಣ *cp0)
{
	ಪೂರ್ಣಾಙ್ಕ c;
	ವರ್ಣ *cp;

	cp = cp0;
	ಕುರು {
		c = (ಪೂರ್ಣಾಙ್ಕ)*cp;
		ಯದಿ (c & 0200)
			ಗಚ್ಛ bad;
		ಯದಿ (!isalpha(c) && !isdigit((unsigned ವರ್ಣ)c)) {
			ವಿಕಲ್ಪ (c) {
			ಪಕ್ಷ '\'':
			ಪಕ್ಷ '"':
			ಪಕ್ಷ '`':
			ಪಕ್ಷ ' ':
			ಪಕ್ಷ '#':
				ಗಚ್ಛ bad;
			ಸ್ವಭಾವ:
				ಭಙ್ಗ;
			}
		}
	} ಯಾವತ್ (*++cp);
	ಪ್ರತ್ಯಾಗಮ (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	ಪ್ರತ್ಯಾಗಮ (0);
}

BUF *
allocbuf(BUF *bp, ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	ಸಂರಚನಾ stat stb;

	ಯದಿ (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	ಯದಿ (size == 0)
		size = blksize;
#ಅನ್ಯಥಾ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ಯದಿ (bp->cnt >= size)
		ಪ್ರತ್ಯಾಗಮ (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	ಪ್ರತ್ಯಾಗಮ (bp);
}

ಶೂನ್ಯ
lostconn(ಪೂರ್ಣಾಙ್ಕ signo)
{
	ಯದಿ (!iamremote)
		(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, "lost connection\n", 16);
	ಯದಿ (signo)
		_exit(1);
	ಅನ್ಯಥಾ
		exit(1);
}

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ i)
{
	ಯದಿ (remin > 0)
		close(remin);
	ಯದಿ (remout > 0)
		close(remout);
	ಯದಿ (remin2 > 0)
		close(remin2);
	ಯದಿ (remout2 > 0)
		close(remout2);
	ಯದಿ (do_cmd_pid > 0)
		(ಶೂನ್ಯ)waitpid(do_cmd_pid, ರಿಕ್ತ, 0);
	ಯದಿ (do_cmd_pid2 > 0)
		(ಶೂನ್ಯ)waitpid(do_cmd_pid2, ರಿಕ್ತ, 0);
	exit(i);
}
