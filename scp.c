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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FNMATCH_H
#ಅನ್ತರ್ಭಾವ <fnmatch.h>
#ಆದರೆ_ಅಂತ್ಯ
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
#ಆದರೆ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ಅನ್ತರ್ಭಾವ <vis.h>
#ಆದರೆ_ಅಂತ್ಯ

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

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

#ವ್ಯಾಖ್ಯಾನಿಸು COPY_BUFLEN	16384

ಪೂರ್ಣಾಂಕ do_cmd(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ *, pid_t *);
ಪೂರ್ಣಾಂಕ do_cmd2(ಅಕ್ಷರ *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);

/* Struct for addargs */
arglist ವಾದಗಳು;
arglist remote_remote_ವಾದಗಳು;

/* Bandwidth limit */
ದೀರ್ಘ ದೀರ್ಘ ಎಲ್ಲೆ_kbps = 0;
ರಚನೆ bwlimit bwlimit;

/* Name of current file being transferred. */
ಅಕ್ಷರ *curfile;

/* This is set to non-zero to enable verbose mode. */
ಪೂರ್ಣಾಂಕ verbose_ಬಹುಲಕ = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
ಪೂರ್ಣಾಂಕ showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
ಪೂರ್ಣಾಂಕ throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
ಪೂರ್ಣಾಂಕ sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
ಅಕ್ಷರ *ssh_ಕಾರ್ಯಕ್ರಮ = ಮಾರ್ಗ_SSH_ಕಾರ್ಯಕ್ರಮ;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
ಗಾತ್ರ_t sftp_copy_buflen;
ಗಾತ್ರ_t sftp_nrequests;

/* Needed for sftp */
ಅಸ್ಥಿರ sig_atomic_t interrupted = 0;

ಪೂರ್ಣಾಂಕ sftp_glob(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ,
    ಪೂರ್ಣಾಂಕ (*)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ), glob_t *); /* proto for sftp-glob.c */

ಸ್ಥಿರ ಶೂನ್ಯ
killchild(ಪೂರ್ಣಾಂಕ signo)
{
	ಆದರೆ (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(ಶೂನ್ಯ)waitpid(do_cmd_pid, ಖಾಲಿ, 0);
	}
	ಆದರೆ (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(ಶೂನ್ಯ)waitpid(do_cmd_pid2, ಖಾಲಿ, 0);
	}

	ಆದರೆ (signo)
		_exit(1);
	ನಿರ್ಗಮಿಸು(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
suspone(ಪೂರ್ಣಾಂಕ pid, ಪೂರ್ಣಾಂಕ signo)
{
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;

	ಆದರೆ (pid > 1) {
		kill(pid, signo);
		ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
suspchild(ಪೂರ್ಣಾಂಕ signo)
{
	ಪೂರ್ಣಾಂಕ save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_local_cmd(arglist *a)
{
	ಅಕ್ಷರ *cp;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;
	pid_t pid;

	ಆದರೆ (a->ಅಂಕೆ == 0)
		fatal("do_local_cmd: no arguments");

	ಆದರೆ (verbose_ಬಹುಲಕ) {
		cp = argv_assemble(a->ಅಂಕೆ, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		ಬಿಡುಗಡೆ(cp);
	}
	ಆದರೆ ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	ಆದರೆ (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		ನಿರ್ಗಮಿಸು(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1)
		ಆದರೆ (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2) || WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0)
		ಹಿಂತಿರುಗಿ (-1);

	ಹಿಂತಿರುಗಿ (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

ಪೂರ್ಣಾಂಕ
do_cmd(ಅಕ್ಷರ *ಕಾರ್ಯಕ್ರಮ, ಅಕ್ಷರ *host, ಅಕ್ಷರ *remuser, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, ಪೂರ್ಣಾಂಕ subsystem,
    ಅಕ್ಷರ *cmd, ಪೂರ್ಣಾಂಕ *fdin, ಪೂರ್ಣಾಂಕ *fdout, pid_t *pid)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
	ಪೂರ್ಣಾಂಕ pin[2], pout[2];
#ಇಲ್ಲದಿದ್ದರೆ
	ಪೂರ್ಣಾಂಕ sv[2];
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (verbose_ಬಹುಲಕ)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    ಕಾರ್ಯಕ್ರಮ, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ಆದರೆ (ಪೋರ್ಟ್ == -1)
		ಪೋರ್ಟ್ = sshport;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
	ಆದರೆ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#ಇಲ್ಲದಿದ್ದರೆ
	/* Create a socket pair for communicating with ssh. */
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#ಆದರೆ_ಅಂತ್ಯ

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	ಆಯ್ಕೆ (*pid) {
	ಸ್ಥಿತಿ -1:
		fatal("fork: %s", strerror(errno));
	ಸ್ಥಿತಿ 0:
		/* Child. */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
		ಆದರೆ (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#ಇಲ್ಲದಿದ್ದರೆ
		ಆದರೆ (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#ಆದರೆ_ಅಂತ್ಯ
		replacearg(&ವಾದಗಳು, 0, "%s", ಕಾರ್ಯಕ್ರಮ);
		ಆದರೆ (ಪೋರ್ಟ್ != -1) {
			addargs(&ವಾದಗಳು, "-p");
			addargs(&ವಾದಗಳು, "%d", ಪೋರ್ಟ್);
		}
		ಆದರೆ (remuser != ಖಾಲಿ) {
			addargs(&ವಾದಗಳು, "-l");
			addargs(&ವಾದಗಳು, "%s", remuser);
		}
		ಆದರೆ (subsystem)
			addargs(&ವಾದಗಳು, "-s");
		addargs(&ವಾದಗಳು, "--");
		addargs(&ವಾದಗಳು, "%s", host);
		addargs(&ವಾದಗಳು, "%s", cmd);

		execvp(ಕಾರ್ಯಕ್ರಮ, ವಾದಗಳು.list);
		perror(ಕಾರ್ಯಕ್ರಮ);
		_exit(1);
	ಪೂರ್ವನಿಯೋಜಿತ:
		/* Parent.  Close the other side, and return the local side. */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#ಇಲ್ಲದಿದ್ದರೆ
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#ಆದರೆ_ಅಂತ್ಯ
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		ಹಿಂತಿರುಗಿ 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
ಪೂರ್ಣಾಂಕ
do_cmd2(ಅಕ್ಷರ *host, ಅಕ್ಷರ *remuser, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, ಅಕ್ಷರ *cmd,
    ಪೂರ್ಣಾಂಕ fdin, ಪೂರ್ಣಾಂಕ fdout)
{
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;
	pid_t pid;

	ಆದರೆ (verbose_ಬಹುಲಕ)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_ಕಾರ್ಯಕ್ರಮ, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ಆದರೆ (ಪೋರ್ಟ್ == -1)
		ಪೋರ್ಟ್ = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	ಆದರೆ (pid == 0) {
		ಆದರೆ (dup2(fdin, 0) == -1)
			perror("dup2");
		ಆದರೆ (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&ವಾದಗಳು, 0, "%s", ssh_ಕಾರ್ಯಕ್ರಮ);
		ಆದರೆ (ಪೋರ್ಟ್ != -1) {
			addargs(&ವಾದಗಳು, "-p");
			addargs(&ವಾದಗಳು, "%d", ಪೋರ್ಟ್);
		}
		ಆದರೆ (remuser != ಖಾಲಿ) {
			addargs(&ವಾದಗಳು, "-l");
			addargs(&ವಾದಗಳು, "%s", remuser);
		}
		addargs(&ವಾದಗಳು, "-oBatchMode=yes");
		addargs(&ವಾದಗಳು, "--");
		addargs(&ವಾದಗಳು, "%s", host);
		addargs(&ವಾದಗಳು, "%s", cmd);

		execvp(ssh_ಕಾರ್ಯಕ್ರಮ, ವಾದಗಳು.list);
		perror(ssh_ಕಾರ್ಯಕ್ರಮ);
		ನಿರ್ಗಮಿಸು(1);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1)
		ಆದರೆ (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	ಹಿಂತಿರುಗಿ 0;
}

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
	ಗಾತ್ರ_t cnt;
	ಅಕ್ಷರ *buf;
} BUF;

BUF *allocbuf(BUF *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಶೂನ್ಯ lostconn(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ okname(ಅಕ್ಷರ *);
ಶೂನ್ಯ ಸತತ_err(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,...)
    __attribute__((__format__ (ಬರೆ, 1, 2)))
    __attribute__((__nonnull__ (1)));
ಪೂರ್ಣಾಂಕ note_err(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,...)
    __attribute__((__format__ (ಬರೆ, 1, 2)));
ಶೂನ್ಯ verifydir(ಅಕ್ಷರ *);

ರಚನೆ passwd *pwd;
uid_t userid;
ಪೂರ್ಣಾಂಕ errs, remin, remout, remin2, remout2;
ಪೂರ್ಣಾಂಕ Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#ವ್ಯಾಖ್ಯಾನಿಸು	CMDNEEDS	64
ಅಕ್ಷರ cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

ಎಣಿಕೆ scp_ಬಹುಲಕ_e {
	ಬಹುಲಕ_SCP,
	ಬಹುಲಕ_SFTP
};

ಪೂರ್ಣಾಂಕ response(ಶೂನ್ಯ);
ಶೂನ್ಯ rsource(ಅಕ್ಷರ *, ರಚನೆ stat *);
ಶೂನ್ಯ sink(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *[], ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಶೂನ್ಯ ಮೂಲ(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *[]);
ಶೂನ್ಯ tolocal(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *[], ಎಣಿಕೆ scp_ಬಹುಲಕ_e, ಅಕ್ಷರ *sftp_ನೇರ);
ಶೂನ್ಯ toremote(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *[], ಎಣಿಕೆ scp_ಬಹುಲಕ_e, ಅಕ್ಷರ *sftp_ನೇರ);
ಶೂನ್ಯ usage(ಶೂನ್ಯ);

ಶೂನ್ಯ ಮೂಲ_sftp(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಅಕ್ಷರ *, ರಚನೆ sftp_conn *);
ಶೂನ್ಯ sink_sftp(ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sftp_conn *);
ಶೂನ್ಯ throughlocal_sftp(ರಚನೆ sftp_conn *, ರಚನೆ sftp_conn *,
    ಅಕ್ಷರ *, ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ ch, fflag, tflag, ಸ್ಥಿತಿ_2, r, n;
	ಅಕ್ಷರ **newargv, *argv0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಎಣಿಕೆ scp_ಬಹುಲಕ_e ಬಹುಲಕ = ಬಹುಲಕ_SFTP;
	ಅಕ್ಷರ *sftp_ನೇರ = ಖಾಲಿ;
	ದೀರ್ಘ ದೀರ್ಘ llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(ಗರಿಷ್ಠ(argc + 1, 1), ಗಾತ್ರ(*newargv));
	ಗಾಗಿ (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&ವಾದಗಳು, '\0', ಗಾತ್ರ(ವಾದಗಳು));
	memset(&remote_remote_ವಾದಗಳು, '\0', ಗಾತ್ರ(remote_remote_ವಾದಗಳು));
	ವಾದಗಳು.list = remote_remote_ವಾದಗಳು.list = ಖಾಲಿ;
	addargs(&ವಾದಗಳು, "%s", ssh_ಕಾರ್ಯಕ್ರಮ);
	addargs(&ವಾದಗಳು, "-x");
	addargs(&ವಾದಗಳು, "-oPermitLocalCommand=no");
	addargs(&ವಾದಗಳು, "-oClearAllForwardings=yes");
	addargs(&ವಾದಗಳು, "-oRemoteCommand=none");
	addargs(&ವಾದಗಳು, "-oRequestTTY=no");
	addargs(&ವಾದಗಳು, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	ಆಗ ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		ಆಯ್ಕೆ (ch) {
		/* User-visible flags. */
		ಸ್ಥಿತಿ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '2':
			/* Ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'A':
		ಸ್ಥಿತಿ '4':
		ಸ್ಥಿತಿ '6':
		ಸ್ಥಿತಿ 'C':
			addargs(&ವಾದಗಳು, "-%c", ch);
			addargs(&remote_remote_ವಾದಗಳು, "-%c", ch);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			sftp_ನೇರ = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '3':
			throughlocal = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'o':
		ಸ್ಥಿತಿ 'c':
		ಸ್ಥಿತಿ 'i':
		ಸ್ಥಿತಿ 'F':
		ಸ್ಥಿತಿ 'J':
			addargs(&remote_remote_ವಾದಗಳು, "-%c", ch);
			addargs(&remote_remote_ವಾದಗಳು, "%s", optarg);
			addargs(&ವಾದಗಳು, "-%c", ch);
			addargs(&ವಾದಗಳು, "%s", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'O':
			ಬಹುಲಕ = ಬಹುಲಕ_SCP;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 's':
			/* Ignored */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			sshport = a2port(optarg);
			ಆದರೆ (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'B':
			addargs(&remote_remote_ವಾದಗಳು, "-oBatchmode=yes");
			addargs(&ವಾದಗಳು, "-oBatchmode=yes");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
			ಎಲ್ಲೆ_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ಆದರೆ (errstr != ಖಾಲಿ)
				usage();
			ಎಲ್ಲೆ_kbps *= 1024; /* kbps */
			bandwidth_ಎಲ್ಲೆ_init(&bwlimit, ಎಲ್ಲೆ_kbps, COPY_BUFLEN);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			pflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
			iamrecursive = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'S':
			ssh_ಕಾರ್ಯಕ್ರಮ = xstrdup(optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'v':
			addargs(&ವಾದಗಳು, "-v");
			addargs(&remote_remote_ವಾದಗಳು, "-v");
			ಆದರೆ (verbose_ಬಹುಲಕ == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_ಬಹುಲಕ = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			addargs(&ವಾದಗಳು, "-q");
			addargs(&remote_remote_ವಾದಗಳು, "-q");
			showprogress = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'X':
			/* Please keep in sync with sftp.c -X */
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(optarg, "buffer=", 7) == 0) {
				r = ಪರಿಶೀಲನೆ_scaled(optarg + 7, &llv);
				ಆದರೆ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ಆದರೆ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (ಗಾತ್ರ_t)llv;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ಆದರೆ (errstr != ಖಾಲಿ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (ಗಾತ್ರ_t)llv;
			} ಇಲ್ಲದಿದ್ದರೆ {
				fatal("Invalid -X option");
			}
			ನಿಲ್ಲಿಸು;

		/* Server options. */
		ಸ್ಥಿತಿ 'd':
			targetshouldbedirectory = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
			setmode(0, O_ದ್ವಿಮಾನ);
#ಆದರೆ_ಅಂತ್ಯ
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'T':
			Tflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&ವಾದಗಳು, "-oForwardAgent=no");

	ಆದರೆ (iamremote)
		ಬಹುಲಕ = ಬಹುಲಕ_SCP;

	ಆದರೆ ((pwd = getpwuid(userid = getuid())) == ಖಾಲಿ)
		fatal("unknown user %u", (u_int) userid);

	ಆದರೆ (!isatty(STDOUT_FILENO))
		showprogress = 0;

	ಆದರೆ (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ಖಾಲಿ) == -1) {
			perror("pledge");
			ನಿರ್ಗಮಿಸು(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	ಆದರೆ (fflag) {
		/* Follow "protocol", send data. */
		(ಶೂನ್ಯ) response();
		ಮೂಲ(argc, argv);
		ನಿರ್ಗಮಿಸು(errs != 0);
	}
	ಆದರೆ (tflag) {
		/* Receive data. */
		sink(argc, argv, ಖಾಲಿ);
		ನಿರ್ಗಮಿಸು(errs != 0);
	}
	ಆದರೆ (argc < 2)
		usage();
	ಆದರೆ (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(ಶೂನ್ಯ) snprintf(cmd, ಗಾತ್ರ cmd, "scp%s%s%s%s",
	    verbose_ಬಹುಲಕ ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(ಶೂನ್ಯ) ssh_signal(SIGPIPE, lostconn);

	ಆದರೆ (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, ಬಹುಲಕ, sftp_ನೇರ);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, ಬಹುಲಕ, sftp_ನೇರ);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	ಆದರೆ (do_cmd_pid != -1 && (ಬಹುಲಕ == ಬಹುಲಕ_SFTP || errs == 0)) {
		ಆದರೆ (remin != -1)
		    (ಶೂನ್ಯ) close(remin);
		ಆದರೆ (remout != -1)
		    (ಶೂನ್ಯ) close(remout);
		ಆದರೆ (waitpid(do_cmd_pid, &ಸ್ಥಿತಿ_2, 0) == -1)
			errs = 1;
		ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2) || WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0)
				errs = 1;
		}
	}
	ನಿರ್ಗಮಿಸು(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
scpio(ಶೂನ್ಯ *_cnt, ಗಾತ್ರ_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_ಪ್ರಗತಿ_meter(0);
	ಆದರೆ (ಎಲ್ಲೆ_kbps > 0)
		bandwidth_ಎಲ್ಲೆ(&bwlimit, s);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_times(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ verb, ಸ್ಥಿರಾಂಕ ರಚನೆ stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	ಅಕ್ಷರ buf[(20 + 7 + 2) * 2 + 2];

	(ಶೂನ್ಯ)snprintf(buf, ಗಾತ್ರ(buf), "T%llu 0 %llu 0\n",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ) (sb->st_atime < 0 ? 0 : sb->st_atime));
	ಆದರೆ (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (ದೀರ್ಘ ದೀರ್ಘ)sb->st_mtime, (ದೀರ್ಘ ದೀರ್ಘ)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(ಶೂನ್ಯ) atomicio(vwrite, fd, buf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf));
	ಹಿಂತಿರುಗಿ (response());
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_scp_uri(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *uri, ಅಕ್ಷರ **userp, ಅಕ್ಷರ **hostp, ಪೂರ್ಣಾಂಕ *portp,
    ಅಕ್ಷರ **pathp)
{
	ಪೂರ್ಣಾಂಕ r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	ಆದರೆ (r == 0 && *pathp == ಖಾಲಿ)
		*pathp = xstrdup(".");
	ಹಿಂತಿರುಗಿ r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
append(ಅಕ್ಷರ *cp, ಅಕ್ಷರ ***ap, ಗಾತ್ರ_t *np)
{
	ಅಕ್ಷರ **tmp;

	ಆದರೆ ((tmp = reallocarray(*ap, *np + 1, ಗಾತ್ರ(*tmp))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕಂಡುಹಿಡಿ_brace(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಪೂರ್ಣಾಂಕ *startp, ಪೂರ್ಣಾಂಕ *endp)
{
	ಪೂರ್ಣಾಂಕ i;
	ಪೂರ್ಣಾಂಕ ಒಳ_bracket, brace_level;

	*startp = *endp = -1;
	ಒಳ_bracket = brace_level = 0;
	ಗಾಗಿ (i = 0; i < ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ && *endp < 0 && ನಮೂನೆ[i] != '\0'; i++) {
		ಆಯ್ಕೆ (ನಮೂನೆ[i]) {
		ಸ್ಥಿತಿ '\\':
			/* skip next character */
			ಆದರೆ (ನಮೂನೆ[i + 1] != '\0')
				i++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '[':
			ಒಳ_bracket = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ']':
			ಒಳ_bracket = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '{':
			ಆದರೆ (ಒಳ_bracket)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (ನಮೂನೆ[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (*startp == -1)
				*startp = i;
			brace_level++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '}':
			ಆದರೆ (ಒಳ_bracket)
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (*startp < 0) {
				/* Unbalanced brace */
				ಹಿಂತಿರುಗಿ -1;
			}
			ಆದರೆ (--brace_level <= 0)
				*endp = i;
			ನಿಲ್ಲಿಸು;
		}
	}
	/* unbalanced brackets/braces */
	ಆದರೆ (*endp < 0 && (*startp >= 0 || ಒಳ_bracket))
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
emit_expansion(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಪೂರ್ಣಾಂಕ brace_ಆರಂಭ, ಪೂರ್ಣಾಂಕ brace_ಕೊನೆ,
    ಪೂರ್ಣಾಂಕ sel_ಆರಂಭ, ಪೂರ್ಣಾಂಕ sel_ಕೊನೆ, ಅಕ್ಷರ ***patternsp, ಗಾತ್ರ_t *npatternsp)
{
	ಅಕ್ಷರ *cp;
	ಗಾತ್ರ_t ನಮೂನೆ_len;
	ಪೂರ್ಣಾಂಕ o = 0, ಬಾಲ_len;

	ಆದರೆ ((ನಮೂನೆ_len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ನಮೂನೆ)) == 0 || ನಮೂನೆ_len >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		ಹಿಂತಿರುಗಿ -1;

	ಬಾಲ_len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ನಮೂನೆ + brace_ಕೊನೆ + 1);
	ಆದರೆ ((cp = ಸ್ಮರಣೆ_ಕೊಡು(brace_ಆರಂಭ + (sel_ಕೊನೆ - sel_ಆರಂಭ) +
	    ಬಾಲ_len + 1)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	/* Pattern before initial brace */
	ಆದರೆ (brace_ಆರಂಭ > 0) {
		ಸ್ಮರಣೆ_ನಕಲು(cp, ನಮೂನೆ, brace_ಆರಂಭ);
		o = brace_ಆರಂಭ;
	}
	/* Current braced selection */
	ಆದರೆ (sel_ಕೊನೆ - sel_ಆರಂಭ > 0) {
		ಸ್ಮರಣೆ_ನಕಲು(cp + o, ನಮೂನೆ + sel_ಆರಂಭ,
		    sel_ಕೊನೆ - sel_ಆರಂಭ);
		o += sel_ಕೊನೆ - sel_ಆರಂಭ;
	}
	/* Remainder of pattern after closing brace */
	ಆದರೆ (ಬಾಲ_len > 0) {
		ಸ್ಮರಣೆ_ನಕಲು(cp + o, ನಮೂನೆ + brace_ಕೊನೆ + 1, ಬಾಲ_len);
		o += ಬಾಲ_len;
	}
	cp[o] = '\0';
	ಆದರೆ (append(cp, patternsp, npatternsp) != 0) {
		ಬಿಡುಗಡೆ(cp);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ 0;
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
brace_expand_one(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಅಕ್ಷರ ***patternsp, ಗಾತ್ರ_t *npatternsp,
    ಪೂರ್ಣಾಂಕ *expanded, ಪೂರ್ಣಾಂಕ *invalid)
{
	ಪೂರ್ಣಾಂಕ i;
	ಪೂರ್ಣಾಂಕ ಒಳ_bracket, brace_ಆರಂಭ, brace_ಕೊನೆ, brace_level;
	ಪೂರ್ಣಾಂಕ sel_ಆರಂಭ, sel_ಕೊನೆ;

	*invalid = *expanded = 0;

	ಆದರೆ (ಕಂಡುಹಿಡಿ_brace(ನಮೂನೆ, &brace_ಆರಂಭ, &brace_ಕೊನೆ) != 0) {
		*invalid = 1;
		ಹಿಂತಿರುಗಿ 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (brace_ಆರಂಭ == -1)
		ಹಿಂತಿರುಗಿ 0;

	ಒಳ_bracket = brace_level = 0;
	ಗಾಗಿ (i = sel_ಆರಂಭ = brace_ಆರಂಭ + 1; i < brace_ಕೊನೆ; i++) {
		ಆಯ್ಕೆ (ನಮೂನೆ[i]) {
		ಸ್ಥಿತಿ '{':
			ಆದರೆ (ಒಳ_bracket)
				ನಿಲ್ಲಿಸು;
			brace_level++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '}':
			ಆದರೆ (ಒಳ_bracket)
				ನಿಲ್ಲಿಸು;
			brace_level--;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '[':
			ಒಳ_bracket = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ']':
			ಒಳ_bracket = 0;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '\\':
			ಆದರೆ (i < brace_ಕೊನೆ - 1)
				i++; /* skip */
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (ನಮೂನೆ[i] == ',' || i == brace_ಕೊನೆ - 1) {
			ಆದರೆ (ಒಳ_bracket || brace_level > 0)
				ಮುಂದುವರಿ;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_ಕೊನೆ = (i == brace_ಕೊನೆ - 1) ? brace_ಕೊನೆ : i;
			ಆದರೆ (emit_expansion(ನಮೂನೆ, brace_ಆರಂಭ, brace_ಕೊನೆ,
			    sel_ಆರಂಭ, sel_ಕೊನೆ, patternsp, npatternsp) != 0)
				ಹಿಂತಿರುಗಿ -1;
			/* move on to the next selection */
			sel_ಆರಂಭ = i + 1;
			ಮುಂದುವರಿ;
		}
	}
	ಆದರೆ (ಒಳ_bracket || brace_level > 0) {
		*invalid = 1;
		ಹಿಂತಿರುಗಿ 0;
	}
	/* success */
	*expanded = 1;
	ಹಿಂತಿರುಗಿ 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
brace_expand(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಅಕ್ಷರ ***patternsp, ಗಾತ್ರ_t *npatternsp)
{
	ಅಕ್ಷರ *cp, *cp2, **ಸಕ್ರಿಯ = ಖಾಲಿ, **ಮುಗಿದ = ಖಾಲಿ;
	ಗಾತ್ರ_t i, nactive = 0, ndone = 0;
	ಪೂರ್ಣಾಂಕ ret = -1, invalid = 0, expanded = 0;

	*patternsp = ಖಾಲಿ;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	ಆದರೆ ((cp = strdup(ನಮೂನೆ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (append(cp, &ಸಕ್ರಿಯ, &nactive) != 0) {
		ಬಿಡುಗಡೆ(cp);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆಗ (nactive > 0) {
		cp = ಸಕ್ರಿಯ[nactive - 1];
		nactive--;
		ಆದರೆ (brace_expand_one(cp, &ಸಕ್ರಿಯ, &nactive,
		    &expanded, &invalid) == -1) {
			ಬಿಡುಗಡೆ(cp);
			ಹೋಗು fail;
		}
		ಆದರೆ (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		ಆದರೆ (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			ಬಿಡುಗಡೆ(cp);
			ಮುಂದುವರಿ;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		ಆದರೆ ((cp2 = strrchr(cp, '/')) != ಖಾಲಿ)
			*cp2++ = '\0';
		ಇಲ್ಲದಿದ್ದರೆ
			cp2 = cp;
		ಆದರೆ (append(xstrdup(cp2), &ಮುಗಿದ, &ndone) != 0) {
			ಬಿಡುಗಡೆ(cp);
			ಹೋಗು fail;
		}
		ಬಿಡುಗಡೆ(cp);
	}
	/* success */
	*patternsp = ಮುಗಿದ;
	*npatternsp = ndone;
	ಮುಗಿದ = ಖಾಲಿ;
	ndone = 0;
	ret = 0;
 fail:
	ಗಾಗಿ (i = 0; i < nactive; i++)
		ಬಿಡುಗಡೆ(ಸಕ್ರಿಯ[i]);
	ಬಿಡುಗಡೆ(ಸಕ್ರಿಯ);
	ಗಾಗಿ (i = 0; i < ndone; i++)
		ಬಿಡುಗಡೆ(ಮುಗಿದ[i]);
	ಬಿಡುಗಡೆ(ಮುಗಿದ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ರಚನೆ sftp_conn *
do_sftp_connect(ಅಕ್ಷರ *host, ಅಕ್ಷರ *user, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, ಅಕ್ಷರ *sftp_ನೇರ,
   ಪೂರ್ಣಾಂಕ *reminp, ಪೂರ್ಣಾಂಕ *remoutp, ಪೂರ್ಣಾಂಕ *pidp)
{
	ಆದರೆ (sftp_ನೇರ == ಖಾಲಿ) {
		ಆದರೆ (do_cmd(ssh_ಕಾರ್ಯಕ್ರಮ, host, user, ಪೋರ್ಟ್, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	} ಇಲ್ಲದಿದ್ದರೆ {
		freeargs(&ವಾದಗಳು);
		addargs(&ವಾದಗಳು, "sftp-server");
		ಆದರೆ (do_cmd(sftp_ನೇರ, host, ಖಾಲಿ, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, ಎಲ್ಲೆ_kbps);
}

ಶೂನ್ಯ
toremote(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv, ಎಣಿಕೆ scp_ಬಹುಲಕ_e ಬಹುಲಕ, ಅಕ್ಷರ *sftp_ನೇರ)
{
	ಅಕ್ಷರ *suser = ಖಾಲಿ, *host = ಖಾಲಿ, *src = ಖಾಲಿ;
	ಅಕ್ಷರ *bp, *tuser, *thost, *targ;
	ಪೂರ್ಣಾಂಕ sport = -1, tport = -1;
	ರಚನೆ sftp_conn *conn = ಖಾಲಿ, *conn2 = ಖಾಲಿ;
	arglist alist;
	ಪೂರ್ಣಾಂಕ i, r, ಸ್ಥಿತಿ_2;
	ರಚನೆ stat sb;
	u_int j;

	memset(&alist, '\0', ಗಾತ್ರ(alist));
	alist.list = ಖಾಲಿ;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	ಆದರೆ (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (r != 0) {
		ಆದರೆ (parse_user_host_ಮಾರ್ಗ(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Parse source files */
	ಗಾಗಿ (i = 0; i < argc - 1; i++) {
		ಬಿಡುಗಡೆ(suser);
		ಬಿಡುಗಡೆ(host);
		ಬಿಡುಗಡೆ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ಆದರೆ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (r != 0) {
			parse_user_host_ಮಾರ್ಗ(argv[i], &suser, &host, &src);
		}
		ಆದರೆ (suser != ಖಾಲಿ && !okname(suser)) {
			++errs;
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (host && throughlocal) {	/* extended remote to remote */
			ಆದರೆ (ಬಹುಲಕ == ಬಹುಲಕ_SFTP) {
				ಆದರೆ (remin == -1 || conn == ಖಾಲಿ) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_ನೇರ,
					    &remin, &remout, &do_cmd_pid);
					ಆದರೆ (conn == ಖಾಲಿ) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (ದೀರ್ಘ)do_cmd_pid);
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
				    sport, sftp_ನೇರ,
				    &remin2, &remout2, &do_cmd_pid2);
				ಆದರೆ (conn2 == ಖಾಲಿ) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (ದೀರ್ಘ)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(ಶೂನ್ಯ) close(remin2);
				(ಶೂನ್ಯ) close(remout2);
				remin2 = remout2 = -1;
				ಆದರೆ (waitpid(do_cmd_pid2, &ಸ್ಥಿತಿ_2, 0) == -1)
					++errs;
				ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2) ||
				    WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0)
					++errs;
				do_cmd_pid2 = -1;
				ಮುಂದುವರಿ;
			} ಇಲ್ಲದಿದ್ದರೆ {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				ಆದರೆ (do_cmd(ssh_ಕಾರ್ಯಕ್ರಮ, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					ನಿರ್ಗಮಿಸು(1);
				ಬಿಡುಗಡೆ(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ಆದರೆ (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					ನಿರ್ಗಮಿಸು(1);
				ಬಿಡುಗಡೆ(bp);
				(ಶೂನ್ಯ) close(remin);
				(ಶೂನ್ಯ) close(remout);
				remin = remout = -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			ಆದರೆ (tuser != ಖಾಲಿ && !okname(tuser)) {
				++errs;
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (tport != -1 && tport != SSH_DEFAULT_ಪೋರ್ಟ್) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_ಕಾರ್ಯಕ್ರಮ);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			ಗಾಗಿ (j = 0; j < remote_remote_ವಾದಗಳು.ಅಂಕೆ; j++) {
				addargs(&alist, "%s",
				    remote_remote_ವಾದಗಳು.list[j]);
			}

			ಆದರೆ (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			ಆದರೆ (suser) {
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
			ಆದರೆ (do_local_cmd(&alist) != 0)
				errs = 1;
		} ಇಲ್ಲದಿದ್ದರೆ {	/* local to remote */
			ಆದರೆ (ಬಹುಲಕ == ಬಹುಲಕ_SFTP) {
				/* no need to glob: already done by shell */
				ಆದರೆ (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				ಆದರೆ (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_ನೇರ,
					    &remin, &remout, &do_cmd_pid);
					ಆದರೆ (conn == ಖಾಲಿ) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				ಮೂಲ_sftp(1, argv[i], targ, conn);
				ಮುಂದುವರಿ;
			}
			/* SCP */
			ಆದರೆ (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ಆದರೆ (do_cmd(ssh_ಕಾರ್ಯಕ್ರಮ, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					ನಿರ್ಗಮಿಸು(1);
				ಆದರೆ (response() < 0)
					ನಿರ್ಗಮಿಸು(1);
				ಬಿಡುಗಡೆ(bp);
			}
			ಮೂಲ(1, argv + i);
		}
	}
ಹೊರಹೋಗು:
	freeargs(&alist);
	ಬಿಡುಗಡೆ(tuser);
	ಬಿಡುಗಡೆ(thost);
	ಬಿಡುಗಡೆ(targ);
	ಬಿಡುಗಡೆ(suser);
	ಬಿಡುಗಡೆ(host);
	ಬಿಡುಗಡೆ(src);
	sftp_free(conn);
	sftp_free(conn2);
}

ಶೂನ್ಯ
tolocal(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv, ಎಣಿಕೆ scp_ಬಹುಲಕ_e ಬಹುಲಕ, ಅಕ್ಷರ *sftp_ನೇರ)
{
	ಅಕ್ಷರ *bp, *host = ಖಾಲಿ, *src = ಖಾಲಿ, *suser = ಖಾಲಿ;
	arglist alist;
	ರಚನೆ sftp_conn *conn = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i, r, sport = -1;

	memset(&alist, '\0', ಗಾತ್ರ(alist));
	alist.list = ಖಾಲಿ;

	ಗಾಗಿ (i = 0; i < argc - 1; i++) {
		ಬಿಡುಗಡೆ(suser);
		ಬಿಡುಗಡೆ(host);
		ಬಿಡುಗಡೆ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ಆದರೆ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (r != 0)
			parse_user_host_ಮಾರ್ಗ(argv[i], &suser, &host, &src);
		ಆದರೆ (suser != ಖಾಲಿ && !okname(suser)) {
			++errs;
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", ಮಾರ್ಗ_CP);
			ಆದರೆ (iamrecursive)
				addargs(&alist, "-r");
			ಆದರೆ (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			ಆದರೆ (do_local_cmd(&alist))
				++errs;
			ಮುಂದುವರಿ;
		}
		/* Remote to local. */
		ಆದರೆ (ಬಹುಲಕ == ಬಹುಲಕ_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_ನೇರ, &remin, &remout, &do_cmd_pid);
			ಆದರೆ (conn == ಖಾಲಿ) {
				error("sftp connection failed");
				++errs;
				ಮುಂದುವರಿ;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(ಶೂನ್ಯ) close(remin);
			(ಶೂನ್ಯ) close(remout);
			remin = remout = -1;
			ಮುಂದುವರಿ;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		ಆದರೆ (do_cmd(ssh_ಕಾರ್ಯಕ್ರಮ, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			ಬಿಡುಗಡೆ(bp);
			++errs;
			ಮುಂದುವರಿ;
		}
		ಬಿಡುಗಡೆ(bp);
		sink(1, argv + argc - 1, src);
		(ಶೂನ್ಯ) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	ಬಿಡುಗಡೆ(suser);
	ಬಿಡುಗಡೆ(host);
	ಬಿಡುಗಡೆ(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
ಸ್ಥಿರ ಅಕ್ಷರ *
prepare_remote_ಮಾರ್ಗ(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಗಾತ್ರ_t nslash;

	/* Handle ~ prefixed paths */
	ಆದರೆ (*ಮಾರ್ಗ == '\0' || strcmp(ಮಾರ್ಗ, "~") == 0)
		ಹಿಂತಿರುಗಿ xstrdup(".");
	ಆದರೆ (*ಮಾರ್ಗ != '~')
		ಹಿಂತಿರುಗಿ xstrdup(ಮಾರ್ಗ);
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ಮಾರ್ಗ, "~/", 2) == 0) {
		ಆದರೆ ((nslash = strspn(ಮಾರ್ಗ + 2, "/")) == ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ + 2))
			ಹಿಂತಿರುಗಿ xstrdup(".");
		ಹಿಂತಿರುಗಿ xstrdup(ಮಾರ್ಗ + 2 + nslash);
	}
	ಆದರೆ (sftp_can_expand_ಮಾರ್ಗ(conn))
		ಹಿಂತಿರುಗಿ sftp_expand_ಮಾರ್ಗ(conn, ಮಾರ್ಗ);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಶೂನ್ಯ
ಮೂಲ_sftp(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ *src, ಅಕ್ಷರ *targ, ರಚನೆ sftp_conn *conn)
{
	ಅಕ್ಷರ *ಗುರಿ = ಖಾಲಿ, *filename = ಖಾಲಿ, *abs_dst = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ src_is_dir, ಗುರಿ_is_dir;
	Attrib a;
	ರಚನೆ stat st;

	memset(&a, '\0', ಗಾತ್ರ(a));
	ಆದರೆ (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	ಆದರೆ ((filename = basename(src)) == ಖಾಲಿ)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	ಆದರೆ (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	ಆದರೆ ((ಗುರಿ = prepare_remote_ಮಾರ್ಗ(conn, targ)) == ಖಾಲಿ)
		cleanup_exit(255);
	ಗುರಿ_is_dir = sftp_remote_is_dir(conn, ಗುರಿ);
	ಆದರೆ (targetshouldbedirectory && !ಗುರಿ_is_dir) {
		debug("target directory \"%s\" does not exist", ಗುರಿ);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		ಆದರೆ (sftp_mkdir(conn, ಗುರಿ, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		ಗುರಿ_is_dir = 1;
	}
	ಆದರೆ (ಗುರಿ_is_dir)
		abs_dst = sftp_ಮಾರ್ಗ_append(ಗುರಿ, filename);
	ಇಲ್ಲದಿದ್ದರೆ {
		abs_dst = ಗುರಿ;
		ಗುರಿ = ಖಾಲಿ;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	ಆದರೆ (src_is_dir && iamrecursive) {
		ಆದರೆ (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_ಪ್ರಗತಿ_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	ಬಿಡುಗಡೆ(abs_dst);
	ಬಿಡುಗಡೆ(ಗುರಿ);
}

ಶೂನ್ಯ
ಮೂಲ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ರಚನೆ stat stb;
	ಸ್ಥಿರ BUF ಬಫರ್;
	BUF *bp;
	off_t i, statbytes;
	ಗಾತ್ರ_t amt, nr;
	ಪೂರ್ಣಾಂಕ fd = -1, haderr, indx;
	ಅಕ್ಷರ *ಕೊನೆಯ, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	ಪೂರ್ಣಾಂಕ len;

	ಗಾಗಿ (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name);
		ಆಗ (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		ಆದರೆ ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			ಹೋಗು syserr;
		ಆದರೆ (strchr(name, '\n') != ಖಾಲಿ) {
			strnvis(encname, name, ಗಾತ್ರ(encname), VIS_NL);
			name = encname;
		}
		ಆದರೆ (fstat(fd, &stb) == -1) {
syserr:			ಸತತ_err("%s: %s", name, strerror(errno));
			ಹೋಗು ಮುಂದಿನ;
		}
		ಆದರೆ (stb.st_size < 0) {
			ಸತತ_err("%s: %s", name, "Negative file size");
			ಹೋಗು ಮುಂದಿನ;
		}
		unset_nonblock(fd);
		ಆಯ್ಕೆ (stb.st_mode & S_IFMT) {
		ಸ್ಥಿತಿ S_IFREG:
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ S_IFDIR:
			ಆದರೆ (iamrecursive) {
				rsource(name, &stb);
				ಹೋಗು ಮುಂದಿನ;
			}
			/* FALLTHROUGH */
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಸತತ_err("%s: not a regular file", name);
			ಹೋಗು ಮುಂದಿನ;
		}
		ಆದರೆ ((ಕೊನೆಯ = strrchr(name, '/')) == ಖಾಲಿ)
			ಕೊನೆಯ = name;
		ಇಲ್ಲದಿದ್ದರೆ
			++ಕೊನೆಯ;
		curfile = ಕೊನೆಯ;
		ಆದರೆ (pflag) {
			ಆದರೆ (do_times(remout, verbose_ಬಹುಲಕ, &stb) < 0)
				ಹೋಗು ಮುಂದಿನ;
		}
#ವ್ಯಾಖ್ಯಾನಿಸು	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, ಗಾತ್ರ buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (ದೀರ್ಘ ದೀರ್ಘ)stb.st_size, ಕೊನೆಯ);
		ಆದರೆ (verbose_ಬಹುಲಕ)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(ಶೂನ್ಯ) atomicio(vwrite, remout, buf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf));
		ಆದರೆ (response() < 0)
			ಹೋಗು ಮುಂದಿನ;
		ಆದರೆ ((bp = allocbuf(&ಬಫರ್, fd, COPY_BUFLEN)) == ಖಾಲಿ) {
ಮುಂದಿನ:			ಆದರೆ (fd != -1) {
				(ಶೂನ್ಯ) close(fd);
				fd = -1;
			}
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (showprogress)
			ಆರಂಭ_ಪ್ರಗತಿ_meter(curfile, stb.st_size, &statbytes);
		ಗಣ_nonblock(remout);
		ಗಾಗಿ (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			ಆದರೆ (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			ಆದರೆ (!haderr) {
				ಆದರೆ ((nr = atomicio(ಪಠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			ಆದರೆ (haderr) {
				(ಶೂನ್ಯ)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		ಆದರೆ (fd != -1) {
			ಆದರೆ (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		ಆದರೆ (!haderr)
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
		ಇಲ್ಲದಿದ್ದರೆ
			ಸತತ_err("%s: %s", name, strerror(haderr));
		(ಶೂನ್ಯ) response();
		ಆದರೆ (showprogress)
			stop_ಪ್ರಗತಿ_meter();
	}
}

ಶೂನ್ಯ
rsource(ಅಕ್ಷರ *name, ರಚನೆ stat *statp)
{
	DIR *dirp;
	ರಚನೆ dirent *dp;
	ಅಕ್ಷರ *ಕೊನೆಯ, *vect[1], ಮಾರ್ಗ[PATH_MAX];

	ಆದರೆ (!(dirp = opendir(name))) {
		ಸತತ_err("%s: %s", name, strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}
	ಕೊನೆಯ = strrchr(name, '/');
	ಆದರೆ (ಕೊನೆಯ == ಖಾಲಿ)
		ಕೊನೆಯ = name;
	ಇಲ್ಲದಿದ್ದರೆ
		ಕೊನೆಯ++;
	ಆದರೆ (pflag) {
		ಆದರೆ (do_times(remout, verbose_ಬಹುಲಕ, statp) < 0) {
			closedir(dirp);
			ಹಿಂತಿರುಗಿ;
		}
	}
	(ಶೂನ್ಯ) snprintf(ಮಾರ್ಗ, ಗಾತ್ರ ಮಾರ್ಗ, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, ಕೊನೆಯ);
	ಆದರೆ (verbose_ಬಹುಲಕ)
		fmprintf(stderr, "Entering directory: %s", ಮಾರ್ಗ);
	(ಶೂನ್ಯ) atomicio(vwrite, remout, ಮಾರ್ಗ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ));
	ಆದರೆ (response() < 0) {
		closedir(dirp);
		ಹಿಂತಿರುಗಿ;
	}
	ಆಗ ((dp = readdir(dirp)) != ಖಾಲಿ) {
		ಆದರೆ (dp->d_ino == 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			ಮುಂದುವರಿ;
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name) + 1 + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(dp->d_name) >= ಗಾತ್ರ(ಮಾರ್ಗ) - 1) {
			ಸತತ_err("%s/%s: name too long", name, dp->d_name);
			ಮುಂದುವರಿ;
		}
		(ಶೂನ್ಯ) snprintf(ಮಾರ್ಗ, ಗಾತ್ರ ಮಾರ್ಗ, "%s/%s", name, dp->d_name);
		vect[0] = ಮಾರ್ಗ;
		ಮೂಲ(1, vect);
	}
	(ಶೂನ್ಯ) closedir(dirp);
	(ಶೂನ್ಯ) atomicio(vwrite, remout, "E\n", 2);
	(ಶೂನ್ಯ) response();
}

ಶೂನ್ಯ
sink_sftp(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ರಚನೆ sftp_conn *conn)
{
	ಅಕ್ಷರ *abs_src = ಖಾಲಿ;
	ಅಕ್ಷರ *abs_dst = ಖಾಲಿ;
	glob_t g;
	ಅಕ್ಷರ *filename, *tmp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ i, r, err = 0, dst_is_dir;
	ರಚನೆ stat st;

	memset(&g, 0, ಗಾತ್ರ(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	ಆದರೆ ((abs_src = prepare_remote_ಮಾರ್ಗ(conn, src)) == ಖಾಲಿ) {
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	ಆದರೆ ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ಖಾಲಿ, &g)) != 0) {
		ಆದರೆ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ಇಲ್ಲದಿದ್ದರೆ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Did we actually get any matches back from the glob? */
	ಆದರೆ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ಖಾಲಿ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ಆದರೆ (sftp_stat(conn, g.gl_pathv[0], 1, ಖಾಲಿ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	ಆದರೆ ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	ಆದರೆ (g.gl_matchc > 1 && !dst_is_dir) {
		ಆದರೆ (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug2_f("creating destination \"%s\"", dst);
		ಆದರೆ (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		dst_is_dir = 1;
	}

	ಗಾಗಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ಆದರೆ ((filename = basename(tmp)) == ಖಾಲಿ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}

		/* Special handling for destination of '..' */
		ಆದರೆ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ಆದರೆ (dst_is_dir)
			abs_dst = sftp_ಮಾರ್ಗ_append(dst, filename);
		ಇಲ್ಲದಿದ್ದರೆ
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ಆದರೆ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ಆದರೆ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ಖಾಲಿ, pflag, SFTP_ಪ್ರಗತಿ_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (sftp_download(conn, g.gl_pathv[i], abs_dst, ಖಾಲಿ,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		ಬಿಡುಗಡೆ(abs_dst);
		abs_dst = ಖಾಲಿ;
		ಬಿಡುಗಡೆ(tmp);
		tmp = ಖಾಲಿ;
	}

ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(abs_src);
	ಬಿಡುಗಡೆ(tmp);
	globfree(&g);
	ಆದರೆ (err == -1)
		errs = 1;
}


#ವ್ಯಾಖ್ಯಾನಿಸು TYPE_ಅತಿಪ್ರವಾಹ(type, val) \
	((ಗಾತ್ರ(type) == 4 && (val) > INT32_MAX) || \
	 (ಗಾತ್ರ(type) == 8 && (val) > INT64_MAX) || \
	 (ಗಾತ್ರ(type) != 4 && ಗಾತ್ರ(type) != 8))

ಶೂನ್ಯ
sink(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src)
{
	ಸ್ಥಿರ BUF ಬಫರ್;
	ರಚನೆ stat stb;
	BUF *bp;
	off_t i;
	ಗಾತ್ರ_t j, ಎಣಿಕೆ_2;
	ಪೂರ್ಣಾಂಕ amt, exists, ಮೊದಲ, ofd;
	ಬಹುಲಕ_t ಬಹುಲಕ, omode, ಮುಖವಾಡ;
	off_t ಗಾತ್ರ_2, statbytes;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ ull;
	ಪೂರ್ಣಾಂಕ setimes, targisdir, wrerr;
	ಅಕ್ಷರ ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	ಅಕ್ಷರ **patterns = ಖಾಲಿ;
	ಗಾತ್ರ_t n, npatterns = 0;
	ರಚನೆ timeval tv[2];

#ವ್ಯಾಖ್ಯಾನಿಸು	atime	tv[0]
#ವ್ಯಾಖ್ಯಾನಿಸು	mtime	tv[1]
#ವ್ಯಾಖ್ಯಾನಿಸು	SCREWUP(str)	{ why = str; ಹೋಗು screwup; }

	ಆದರೆ (TYPE_ಅತಿಪ್ರವಾಹ(time_t, 0) || TYPE_ಅತಿಪ್ರವಾಹ(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	ಮುಖವಾಡ = umask(0);
	ಆದರೆ (!pflag) {
		(ಶೂನ್ಯ) umask(ಮುಖವಾಡ);
		ಮುಖವಾಡ |= 07000;
	}
	ಆದರೆ (argc != 1) {
		ಸತತ_err("ambiguous target");
		ನಿರ್ಗಮಿಸು(1);
	}
	targ = *argv;
	ಆದರೆ (targetshouldbedirectory)
		verifydir(targ);

	(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
	ಆದರೆ (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	ಆದರೆ (src != ಖಾಲಿ && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		ಆದರೆ (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	ಗಾಗಿ (ಮೊದಲ = 1;; ಮೊದಲ = 0) {
		cp = buf;
		ಆದರೆ (atomicio(ಪಠ, remin, cp, 1) != 1)
			ಹೋಗು ಮುಗಿದ;
		ಆದರೆ (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		ಮಾಡು {
			ಆದರೆ (atomicio(ಪಠ, remin, &ch, ಗಾತ್ರ(ch)) != ಗಾತ್ರ(ch))
				SCREWUP("lost connection");
			ಆದರೆ (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} ಆಗ (cp < &buf[ಗಾತ್ರ(buf) - 1] && ch != '\n');
		*cp = 0;
		ಆದರೆ (verbose_ಬಹುಲಕ)
			fmprintf(stderr, "Sink: %s", buf);

		ಆದರೆ (buf[0] == '\01' || buf[0] == '\02') {
			ಆದರೆ (iamremote == 0) {
				(ಶೂನ್ಯ) snmprintf(visbuf, ಗಾತ್ರ(visbuf),
				    ಖಾಲಿ, "%s", buf + 1);
				(ಶೂನ್ಯ) atomicio(vwrite, STDERR_FILENO,
				    visbuf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(visbuf));
			}
			ಆದರೆ (buf[0] == '\02')
				ನಿರ್ಗಮಿಸು(1);
			++errs;
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (buf[0] == 'E') {
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
			ಹೋಗು ಮುಗಿದ;
		}
		ಆದರೆ (ch == '\n')
			*--cp = 0;

		cp = buf;
		ಆದರೆ (*cp == 'T') {
			setimes++;
			cp++;
			ಆದರೆ (!ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ಆದರೆ (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			ಆದರೆ (TYPE_ಅತಿಪ್ರವಾಹ(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			ಆದರೆ (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			ಆದರೆ (!ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ಆದರೆ (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			ಆದರೆ (TYPE_ಅತಿಪ್ರವಾಹ(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			ಆದರೆ (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			ಆದರೆ (ಮೊದಲ) {
				ಸತತ_err("%s", cp);
				ನಿರ್ಗಮಿಸು(1);
			}
			SCREWUP("expected control record");
		}
		ಬಹುಲಕ = 0;
		ಗಾಗಿ (++cp; cp < buf + 5; cp++) {
			ಆದರೆ (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			ಬಹುಲಕ = (ಬಹುಲಕ << 3) | (*cp - '0');
		}
		ಆದರೆ (!pflag)
			ಬಹುಲಕ &= ~ಮುಖವಾಡ;
		ಆದರೆ (*cp++ != ' ')
			SCREWUP("mode not delimited");

		ಆದರೆ (!ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		ಆದರೆ (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		ಆದರೆ (TYPE_ಅತಿಪ್ರವಾಹ(off_t, ull))
			SCREWUP("size out of range");
		ಗಾತ್ರ_2 = (off_t)ull;

		ಆದರೆ (*cp == '\0' || strchr(cp, '/') != ಖಾಲಿ ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			ಸತತ_err("error: unexpected filename: %s", cp);
			ನಿರ್ಗಮಿಸು(1);
		}
		ಆದರೆ (npatterns > 0) {
			ಗಾಗಿ (n = 0; n < npatterns; n++) {
				ಆದರೆ (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				ಗಾಗಿ (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		ಆದರೆ (targisdir) {
			ಸ್ಥಿರ ಅಕ್ಷರ *namebuf;
			ಸ್ಥಿರ ಗಾತ್ರ_t cursize;
			ಗಾತ್ರ_t need;

			need = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(targ) + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp) + 250;
			ಆದರೆ (need > cursize) {
				ಬಿಡುಗಡೆ(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(ಶೂನ್ಯ) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} ಇಲ್ಲದಿದ್ದರೆ
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		ಆದರೆ (buf[0] == 'D') {
			ಪೂರ್ಣಾಂಕ mod_flag = pflag;
			ಆದರೆ (!iamrecursive)
				SCREWUP("received directory without -r");
			ಆದರೆ (exists) {
				ಆದರೆ (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					ಹೋಗು bad;
				}
				ಆದರೆ (pflag)
					(ಶೂನ್ಯ) chmod(np, ಬಹುಲಕ);
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				ಆದರೆ (mkdir(np, ಬಹುಲಕ | S_IRWXU) == -1)
					ಹೋಗು bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			ಆದರೆ (setimes) {
				setimes = 0;
				(ಶೂನ್ಯ) utimes(vect[0], tv);
			}
			ಆದರೆ (mod_flag)
				(ಶೂನ್ಯ) chmod(vect[0], ಬಹುಲಕ);
			ಬಿಡುಗಡೆ(vect[0]);
			ಮುಂದುವರಿ;
		}
		omode = ಬಹುಲಕ;
		ಬಹುಲಕ |= S_IWUSR;
		ಆದರೆ ((ofd = open(np, O_WRONLY|O_CREAT, ಬಹುಲಕ)) == -1) {
bad:			ಸತತ_err("%s: %s", np, strerror(errno));
			ಮುಂದುವರಿ;
		}
		(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
		ಆದರೆ ((bp = allocbuf(&ಬಫರ್, ofd, COPY_BUFLEN)) == ಖಾಲಿ) {
			(ಶೂನ್ಯ) close(ofd);
			ಮುಂದುವರಿ;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		ಆದರೆ (showprogress)
			ಆರಂಭ_ಪ್ರಗತಿ_meter(curfile, ಗಾತ್ರ_2, &statbytes);
		ಗಣ_nonblock(remin);
		ಗಾಗಿ (ಎಣಿಕೆ_2 = i = 0; i < ಗಾತ್ರ_2; i += bp->cnt) {
			amt = bp->cnt;
			ಆದರೆ (i + amt > ಗಾತ್ರ_2)
				amt = ಗಾತ್ರ_2 - i;
			ಎಣಿಕೆ_2 += amt;
			ಮಾಡು {
				j = atomicio6(ಪಠ, remin, cp, amt,
				    scpio, &statbytes);
				ಆದರೆ (j == 0) {
					ಸತತ_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					ನಿರ್ಗಮಿಸು(1);
				}
				amt -= j;
				cp += j;
			} ಆಗ (amt > 0);

			ಆದರೆ (ಎಣಿಕೆ_2 == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				ಆದರೆ (!wrerr) {
					ಆದರೆ (atomicio(vwrite, ofd, bp->buf,
					    ಎಣಿಕೆ_2) != ಎಣಿಕೆ_2) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				ಎಣಿಕೆ_2 = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		ಆದರೆ (ಎಣಿಕೆ_2 != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, ಎಣಿಕೆ_2) != ಎಣಿಕೆ_2) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		ಆದರೆ (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, ಗಾತ್ರ_2) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		ಆದರೆ (pflag) {
			ಆದರೆ (exists || omode != ಬಹುಲಕ)
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCHMOD
				ಆದರೆ (fchmod(ofd, omode)) {
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_FCHMOD */
				ಆದರೆ (chmod(np, omode)) {
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (!exists && omode != ಬಹುಲಕ)
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FCHMOD
				ಆದರೆ (fchmod(ofd, omode & ~ಮುಖವಾಡ)) {
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_FCHMOD */
				ಆದರೆ (chmod(np, omode & ~ಮುಖವಾಡ)) {
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		ಆದರೆ (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(ಶೂನ್ಯ) response();
		ಆದರೆ (showprogress)
			stop_ಪ್ರಗತಿ_meter();
		ಆದರೆ (setimes && !wrerr) {
			setimes = 0;
			ಆದರೆ (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		ಆದರೆ (note_err(ಖಾಲಿ) == 0)
			(ಶೂನ್ಯ) atomicio(vwrite, remout, "", 1);
	}
ಮುಗಿದ:
	ಗಾಗಿ (n = 0; n < npatterns; n++)
		ಬಿಡುಗಡೆ(patterns[n]);
	ಬಿಡುಗಡೆ(patterns);
	ಹಿಂತಿರುಗಿ;
screwup:
	ಗಾಗಿ (n = 0; n < npatterns; n++)
		ಬಿಡುಗಡೆ(patterns[n]);
	ಬಿಡುಗಡೆ(patterns);
	ಸತತ_err("protocol error: %s", why);
	ನಿರ್ಗಮಿಸು(1);
}

ಶೂನ್ಯ
throughlocal_sftp(ರಚನೆ sftp_conn *from, ರಚನೆ sftp_conn *ಗಮ್ಯ,
    ಅಕ್ಷರ *src, ಅಕ್ಷರ *targ)
{
	ಅಕ್ಷರ *ಗುರಿ = ಖಾಲಿ, *filename = ಖಾಲಿ, *abs_dst = ಖಾಲಿ;
	ಅಕ್ಷರ *abs_src = ಖಾಲಿ, *tmp = ಖಾಲಿ;
	glob_t g;
	ಪೂರ್ಣಾಂಕ i, r, targetisdir, err = 0;

	ಆದರೆ ((filename = basename(src)) == ಖಾಲಿ)
		fatal("basename %s: %s", src, strerror(errno));

	ಆದರೆ ((abs_src = prepare_remote_ಮಾರ್ಗ(from, src)) == ಖಾಲಿ ||
	    (ಗುರಿ = prepare_remote_ಮಾರ್ಗ(ಗಮ್ಯ, targ)) == ಖಾಲಿ)
		cleanup_exit(255);
	memset(&g, 0, ಗಾತ್ರ(g));

	targetisdir = sftp_remote_is_dir(ಗಮ್ಯ, ಗುರಿ);
	ಆದರೆ (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	debug3_f("copying remote %s to remote %s", abs_src, ಗುರಿ);
	ಆದರೆ ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ಖಾಲಿ, &g)) != 0) {
		ಆದರೆ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ಇಲ್ಲದಿದ್ದರೆ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Did we actually get any matches back from the glob? */
	ಆದರೆ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ಖಾಲಿ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ಆದರೆ (sftp_stat(from, g.gl_pathv[0], 1, ಖಾಲಿ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	ಗಾಗಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ಆದರೆ ((filename = basename(tmp)) == ಖಾಲಿ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}

		/* Special handling for source of '..' */
		ಆದರೆ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ಆದರೆ (targetisdir)
			abs_dst = sftp_ಮಾರ್ಗ_append(ಗುರಿ, filename);
		ಇಲ್ಲದಿದ್ದರೆ
			abs_dst = xstrdup(ಗುರಿ);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ಆದರೆ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ಆದರೆ (sftp_crossload_dir(from, ಗಮ್ಯ, g.gl_pathv[i], abs_dst,
			    ಖಾಲಿ, pflag, SFTP_ಪ್ರಗತಿ_ONLY, 1) == -1)
				err = -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (sftp_crossload(from, ಗಮ್ಯ, g.gl_pathv[i], abs_dst,
			    ಖಾಲಿ, pflag) == -1)
				err = -1;
		}
		ಬಿಡುಗಡೆ(abs_dst);
		abs_dst = ಖಾಲಿ;
		ಬಿಡುಗಡೆ(tmp);
		tmp = ಖಾಲಿ;
	}

ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(abs_src);
	ಬಿಡುಗಡೆ(abs_dst);
	ಬಿಡುಗಡೆ(ಗುರಿ);
	ಬಿಡುಗಡೆ(tmp);
	globfree(&g);
	ಆದರೆ (err == -1)
		errs = 1;
}

ಪೂರ್ಣಾಂಕ
response(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ ch, *cp, resp, rbuf[2048], visbuf[2048];

	ಆದರೆ (atomicio(ಪಠ, remin, &resp, ಗಾತ್ರ(resp)) != ಗಾತ್ರ(resp))
		lostconn(0);

	cp = rbuf;
	ಆಯ್ಕೆ (resp) {
	ಸ್ಥಿತಿ 0:		/* ok */
		ಹಿಂತಿರುಗಿ (0);
	ಪೂರ್ವನಿಯೋಜಿತ:
		*cp++ = resp;
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ 1:		/* error, followed by error msg */
	ಸ್ಥಿತಿ 2:		/* fatal error, "" */
		ಮಾಡು {
			ಆದರೆ (atomicio(ಪಠ, remin, &ch, ಗಾತ್ರ(ch)) != ಗಾತ್ರ(ch))
				lostconn(0);
			*cp++ = ch;
		} ಆಗ (cp < &rbuf[ಗಾತ್ರ(rbuf) - 1] && ch != '\n');

		ಆದರೆ (!iamremote) {
			cp[-1] = '\0';
			(ಶೂನ್ಯ) snmprintf(visbuf, ಗಾತ್ರ(visbuf),
			    ಖಾಲಿ, "%s\n", rbuf);
			(ಶೂನ್ಯ) atomicio(vwrite, STDERR_FILENO,
			    visbuf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(visbuf));
		}
		++errs;
		ಆದರೆ (resp == 1)
			ಹಿಂತಿರುಗಿ (-1);
		ನಿರ್ಗಮಿಸು(1);
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
	ನಿರ್ಗಮಿಸು(1);
}

ಶೂನ್ಯ
ಸತತ_err(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,...)
{
	ಸ್ಥಿರ FILE *fp;
	va_list ap;

	++errs;
	ಆದರೆ (fp != ಖಾಲಿ || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(ಶೂನ್ಯ) fprintf(fp, "%c", 0x01);
		(ಶೂನ್ಯ) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(ಶೂನ್ಯ) vfprintf(fp, fmt, ap);
		va_end(ap);
		(ಶೂನ್ಯ) fprintf(fp, "\n");
		(ಶೂನ್ಯ) fflush(fp);
	}

	ಆದರೆ (!iamremote) {
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
ಪೂರ್ಣಾಂಕ
note_err(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	ಸ್ಥಿರ ಅಕ್ಷರ *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	ಆದರೆ (fmt == ಖಾಲಿ) {
		ಆದರೆ (emsg == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ 0;
		ಸತತ_err("%s", emsg);
		ಬಿಡುಗಡೆ(emsg);
		emsg = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ -1;
	}

	errs++;
	/* Prefer first-noted error */
	ಆದರೆ (emsg != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, ಖಾಲಿ, fmt, ap);
	va_end(ap);
	ಹಿಂತಿರುಗಿ -1;
}

ಶೂನ್ಯ
verifydir(ಅಕ್ಷರ *cp)
{
	ರಚನೆ stat stb;

	ಆದರೆ (!stat(cp, &stb)) {
		ಆದರೆ (S_ISDIR(stb.st_mode))
			ಹಿಂತಿರುಗಿ;
		errno = ENOTDIR;
	}
	ಸತತ_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

ಪೂರ್ಣಾಂಕ
okname(ಅಕ್ಷರ *cp0)
{
	ಪೂರ್ಣಾಂಕ c;
	ಅಕ್ಷರ *cp;

	cp = cp0;
	ಮಾಡು {
		c = (ಪೂರ್ಣಾಂಕ)*cp;
		ಆದರೆ (c & 0200)
			ಹೋಗು bad;
		ಆದರೆ (!ಅಕ್ಷರವೇ(c) && !ಅಂಕಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)c)) {
			ಆಯ್ಕೆ (c) {
			ಸ್ಥಿತಿ '\'':
			ಸ್ಥಿತಿ '"':
			ಸ್ಥಿತಿ '`':
			ಸ್ಥಿತಿ ' ':
			ಸ್ಥಿತಿ '#':
				ಹೋಗು bad;
			ಪೂರ್ವನಿಯೋಜಿತ:
				ನಿಲ್ಲಿಸು;
			}
		}
	} ಆಗ (*++cp);
	ಹಿಂತಿರುಗಿ (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	ಹಿಂತಿರುಗಿ (0);
}

BUF *
allocbuf(BUF *bp, ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ blksize)
{
	ಗಾತ್ರ_t ಗಾತ್ರ_2;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_STAT_ST_BLKSIZE
	ರಚನೆ stat stb;

	ಆದರೆ (fstat(fd, &stb) == -1) {
		ಸತತ_err("fstat: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	ಗಾತ್ರ_2 = ROUNDUP(stb.st_blksize, blksize);
	ಆದರೆ (ಗಾತ್ರ_2 == 0)
		ಗಾತ್ರ_2 = blksize;
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ಗಾತ್ರ_2 = blksize;
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ಆದರೆ (bp->cnt >= ಗಾತ್ರ_2)
		ಹಿಂತಿರುಗಿ (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, ಗಾತ್ರ_2, 1);
	bp->cnt = ಗಾತ್ರ_2;
	ಹಿಂತಿರುಗಿ (bp);
}

ಶೂನ್ಯ
lostconn(ಪೂರ್ಣಾಂಕ signo)
{
	ಆದರೆ (!iamremote)
		(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, "lost connection\n", 16);
	ಆದರೆ (signo)
		_exit(1);
	ಇಲ್ಲದಿದ್ದರೆ
		ನಿರ್ಗಮಿಸು(1);
}

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ i)
{
	ಆದರೆ (remin > 0)
		close(remin);
	ಆದರೆ (remout > 0)
		close(remout);
	ಆದರೆ (remin2 > 0)
		close(remin2);
	ಆದರೆ (remout2 > 0)
		close(remout2);
	ಆದರೆ (do_cmd_pid > 0)
		(ಶೂನ್ಯ)waitpid(do_cmd_pid, ಖಾಲಿ, 0);
	ಆದರೆ (do_cmd_pid2 > 0)
		(ಶೂನ್ಯ)waitpid(do_cmd_pid2, ಖಾಲಿ, 0);
	ನಿರ್ಗಮಿಸು(i);
}
