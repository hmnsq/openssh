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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <dirent.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FNMATCH_H
#ਅਨ੍ਤਰ੍ਭਾਵ <fnmatch.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <glob.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <libgen.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <locale.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>
#ਜੇ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ਅਨ੍ਤਰ੍ਭਾਵ <vis.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "progressmeter.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-client.h"

ਬਾਹਰੀ ਅੱਖਰ *__progname;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ COPY_BUFLEN	16384

ਪੂਰਨ do_cmd(ਅੱਖਰ *, ਅੱਖਰ *, ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ, ਅੱਖਰ *, ਪੂਰਨ *, ਪੂਰਨ *, pid_t *);
ਪੂਰਨ do_cmd2(ਅੱਖਰ *, ਅੱਖਰ *, ਪੂਰਨ, ਅੱਖਰ *, ਪੂਰਨ, ਪੂਰਨ);

/* Struct for addargs */
arglist ਦਲੀਲਾਂ;
arglist remote_remote_ਦਲੀਲਾਂ;

/* Bandwidth limit */
ਲੰਮਾ ਲੰਮਾ ਹੱਦਬੰਦੀ_kbps = 0;
ਬਣਤਰ bwlimit bwlimit;

/* Name of current file being transferred. */
ਅੱਖਰ *curfile;

/* This is set to non-zero to enable verbose mode. */
ਪੂਰਨ verbose_ਬਹੁਲਕ = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
ਪੂਰਨ showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
ਪੂਰਨ throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
ਪੂਰਨ sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
ਅੱਖਰ *ssh_ਪ੍ਰੋਗਰਾਮ = ਰਸਤਾ_SSH_ਪ੍ਰੋਗਰਾਮ;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
ਮਾਪ_t sftp_copy_buflen;
ਮਾਪ_t sftp_nrequests;

/* Needed for sftp */
ਅਸਥਿਰ sig_atomic_t interrupted = 0;

ਪੂਰਨ sftp_glob(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ,
    ਪੂਰਨ (*)(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ), glob_t *); /* proto for sftp-glob.c */

ਸਥਿਰ ਖਾਲੀ
killchild(ਪੂਰਨ signo)
{
	ਜੇ (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(ਖਾਲੀ)waitpid(do_cmd_pid, ਨਿਰਾ, 0);
	}
	ਜੇ (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(ਖਾਲੀ)waitpid(do_cmd_pid2, ਨਿਰਾ, 0);
	}

	ਜੇ (signo)
		_exit(1);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਸਥਿਰ ਖਾਲੀ
suspone(ਪੂਰਨ pid, ਪੂਰਨ signo)
{
	ਪੂਰਨ ਸਥਿਤੀ;

	ਜੇ (pid > 1) {
		kill(pid, signo);
		ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

ਸਥਿਰ ਖਾਲੀ
suspchild(ਪੂਰਨ signo)
{
	ਪੂਰਨ save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ਸਥਿਰ ਪੂਰਨ
do_local_cmd(arglist *a)
{
	ਅੱਖਰ *cp;
	ਪੂਰਨ ਸਥਿਤੀ;
	pid_t pid;

	ਜੇ (a->ਅੰਕ == 0)
		fatal("do_local_cmd: no arguments");

	ਜੇ (verbose_ਬਹੁਲਕ) {
		cp = argv_assemble(a->ਅੰਕ, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		ਮੁਕਤ(cp);
	}
	ਜੇ ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	ਜੇ (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1)
		ਜੇ (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	ਜੇ (!WIFEXITED(ਸਥਿਤੀ) || WEXITSTATUS(ਸਥਿਤੀ) != 0)
		ਵਾਪਸ (-1);

	ਵਾਪਸ (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

ਪੂਰਨ
do_cmd(ਅੱਖਰ *ਪ੍ਰੋਗਰਾਮ, ਅੱਖਰ *host, ਅੱਖਰ *remuser, ਪੂਰਨ ਪੋਰਟ, ਪੂਰਨ subsystem,
    ਅੱਖਰ *cmd, ਪੂਰਨ *fdin, ਪੂਰਨ *fdout, pid_t *pid)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
	ਪੂਰਨ pin[2], pout[2];
#ਨਹੀਂਤਾਂ
	ਪੂਰਨ sv[2];
#ਜੇ_ਅੰਤ

	ਜੇ (verbose_ਬਹੁਲਕ)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    ਪ੍ਰੋਗਰਾਮ, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ਜੇ (ਪੋਰਟ == -1)
		ਪੋਰਟ = sshport;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
	ਜੇ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#ਨਹੀਂਤਾਂ
	/* Create a socket pair for communicating with ssh. */
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#ਜੇ_ਅੰਤ

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	ਚੋਣ (*pid) {
	ਹਾਲਤ -1:
		fatal("fork: %s", strerror(errno));
	ਹਾਲਤ 0:
		/* Child. */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
		ਜੇ (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#ਨਹੀਂਤਾਂ
		ਜੇ (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#ਜੇ_ਅੰਤ
		replacearg(&ਦਲੀਲਾਂ, 0, "%s", ਪ੍ਰੋਗਰਾਮ);
		ਜੇ (ਪੋਰਟ != -1) {
			addargs(&ਦਲੀਲਾਂ, "-p");
			addargs(&ਦਲੀਲਾਂ, "%d", ਪੋਰਟ);
		}
		ਜੇ (remuser != ਨਿਰਾ) {
			addargs(&ਦਲੀਲਾਂ, "-l");
			addargs(&ਦਲੀਲਾਂ, "%s", remuser);
		}
		ਜੇ (subsystem)
			addargs(&ਦਲੀਲਾਂ, "-s");
		addargs(&ਦਲੀਲਾਂ, "--");
		addargs(&ਦਲੀਲਾਂ, "%s", host);
		addargs(&ਦਲੀਲਾਂ, "%s", cmd);

		execvp(ਪ੍ਰੋਗਰਾਮ, ਦਲੀਲਾਂ.list);
		perror(ਪ੍ਰੋਗਰਾਮ);
		_exit(1);
	ਮੂਲ:
		/* Parent.  Close the other side, and return the local side. */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#ਨਹੀਂਤਾਂ
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#ਜੇ_ਅੰਤ
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		ਵਾਪਸ 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
ਪੂਰਨ
do_cmd2(ਅੱਖਰ *host, ਅੱਖਰ *remuser, ਪੂਰਨ ਪੋਰਟ, ਅੱਖਰ *cmd,
    ਪੂਰਨ fdin, ਪੂਰਨ fdout)
{
	ਪੂਰਨ ਸਥਿਤੀ;
	pid_t pid;

	ਜੇ (verbose_ਬਹੁਲਕ)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_ਪ੍ਰੋਗਰਾਮ, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ਜੇ (ਪੋਰਟ == -1)
		ਪੋਰਟ = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	ਜੇ (pid == 0) {
		ਜੇ (dup2(fdin, 0) == -1)
			perror("dup2");
		ਜੇ (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&ਦਲੀਲਾਂ, 0, "%s", ssh_ਪ੍ਰੋਗਰਾਮ);
		ਜੇ (ਪੋਰਟ != -1) {
			addargs(&ਦਲੀਲਾਂ, "-p");
			addargs(&ਦਲੀਲਾਂ, "%d", ਪੋਰਟ);
		}
		ਜੇ (remuser != ਨਿਰਾ) {
			addargs(&ਦਲੀਲਾਂ, "-l");
			addargs(&ਦਲੀਲਾਂ, "%s", remuser);
		}
		addargs(&ਦਲੀਲਾਂ, "-oBatchMode=yes");
		addargs(&ਦਲੀਲਾਂ, "--");
		addargs(&ਦਲੀਲਾਂ, "%s", host);
		addargs(&ਦਲੀਲਾਂ, "%s", cmd);

		execvp(ssh_ਪ੍ਰੋਗਰਾਮ, ਦਲੀਲਾਂ.list);
		perror(ssh_ਪ੍ਰੋਗਰਾਮ);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	} ਨਹੀਂਤਾਂ ਜੇ (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1)
		ਜੇ (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	ਵਾਪਸ 0;
}

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
	ਮਾਪ_t cnt;
	ਅੱਖਰ *buf;
} BUF;

BUF *allocbuf(BUF *, ਪੂਰਨ, ਪੂਰਨ);
ਖਾਲੀ lostconn(ਪੂਰਨ);
ਪੂਰਨ okname(ਅੱਖਰ *);
ਖਾਲੀ ਲੜੀਵਾਰ_err(ਅਚਲ ਅੱਖਰ *,...)
    __attribute__((__format__ (ਲਿਖੋ, 1, 2)))
    __attribute__((__nonnull__ (1)));
ਪੂਰਨ note_err(ਅਚਲ ਅੱਖਰ *,...)
    __attribute__((__format__ (ਲਿਖੋ, 1, 2)));
ਖਾਲੀ verifydir(ਅੱਖਰ *);

ਬਣਤਰ passwd *pwd;
uid_t userid;
ਪੂਰਨ errs, remin, remout, remin2, remout2;
ਪੂਰਨ Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CMDNEEDS	64
ਅੱਖਰ cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

ਗਿਣਤੀ scp_ਬਹੁਲਕ_e {
	ਬਹੁਲਕ_SCP,
	ਬਹੁਲਕ_SFTP
};

ਪੂਰਨ response(ਖਾਲੀ);
ਖਾਲੀ rsource(ਅੱਖਰ *, ਬਣਤਰ stat *);
ਖਾਲੀ sink(ਪੂਰਨ, ਅੱਖਰ *[], ਅਚਲ ਅੱਖਰ *);
ਖਾਲੀ ਸਰੋਤ(ਪੂਰਨ, ਅੱਖਰ *[]);
ਖਾਲੀ tolocal(ਪੂਰਨ, ਅੱਖਰ *[], ਗਿਣਤੀ scp_ਬਹੁਲਕ_e, ਅੱਖਰ *sftp_ਸਿੱਧਾ);
ਖਾਲੀ toremote(ਪੂਰਨ, ਅੱਖਰ *[], ਗਿਣਤੀ scp_ਬਹੁਲਕ_e, ਅੱਖਰ *sftp_ਸਿੱਧਾ);
ਖਾਲੀ usage(ਖਾਲੀ);

ਖਾਲੀ ਸਰੋਤ_sftp(ਪੂਰਨ, ਅੱਖਰ *, ਅੱਖਰ *, ਬਣਤਰ sftp_conn *);
ਖਾਲੀ sink_sftp(ਪੂਰਨ, ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sftp_conn *);
ਖਾਲੀ throughlocal_sftp(ਬਣਤਰ sftp_conn *, ਬਣਤਰ sftp_conn *,
    ਅੱਖਰ *, ਅੱਖਰ *);

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ ch, fflag, tflag, ਸਥਿਤੀ, r, n;
	ਅੱਖਰ **newargv, *argv0;
	ਅਚਲ ਅੱਖਰ *errstr;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਗਿਣਤੀ scp_ਬਹੁਲਕ_e ਬਹੁਲਕ = ਬਹੁਲਕ_SFTP;
	ਅੱਖਰ *sftp_ਸਿੱਧਾ = ਨਿਰਾ;
	ਲੰਮਾ ਲੰਮਾ llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(ਵੱਧ_ਤੋਂ_ਵੱਧ(argc + 1, 1), ਆਕਾਰ(*newargv));
	ਲਈ (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&ਦਲੀਲਾਂ, '\0', ਆਕਾਰ(ਦਲੀਲਾਂ));
	memset(&remote_remote_ਦਲੀਲਾਂ, '\0', ਆਕਾਰ(remote_remote_ਦਲੀਲਾਂ));
	ਦਲੀਲਾਂ.list = remote_remote_ਦਲੀਲਾਂ.list = ਨਿਰਾ;
	addargs(&ਦਲੀਲਾਂ, "%s", ssh_ਪ੍ਰੋਗਰਾਮ);
	addargs(&ਦਲੀਲਾਂ, "-x");
	addargs(&ਦਲੀਲਾਂ, "-oPermitLocalCommand=no");
	addargs(&ਦਲੀਲਾਂ, "-oClearAllForwardings=yes");
	addargs(&ਦਲੀਲਾਂ, "-oRemoteCommand=none");
	addargs(&ਦਲੀਲਾਂ, "-oRequestTTY=no");
	addargs(&ਦਲੀਲਾਂ, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	ਜਦੋਂ ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		ਚੋਣ (ch) {
		/* User-visible flags. */
		ਹਾਲਤ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ਰੋਕੋ;
		ਹਾਲਤ '2':
			/* Ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'A':
		ਹਾਲਤ '4':
		ਹਾਲਤ '6':
		ਹਾਲਤ 'C':
			addargs(&ਦਲੀਲਾਂ, "-%c", ch);
			addargs(&remote_remote_ਦਲੀਲਾਂ, "-%c", ch);
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			sftp_ਸਿੱਧਾ = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ '3':
			throughlocal = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			ਰੋਕੋ;
		ਹਾਲਤ 'o':
		ਹਾਲਤ 'c':
		ਹਾਲਤ 'i':
		ਹਾਲਤ 'F':
		ਹਾਲਤ 'J':
			addargs(&remote_remote_ਦਲੀਲਾਂ, "-%c", ch);
			addargs(&remote_remote_ਦਲੀਲਾਂ, "%s", optarg);
			addargs(&ਦਲੀਲਾਂ, "-%c", ch);
			addargs(&ਦਲੀਲਾਂ, "%s", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'O':
			ਬਹੁਲਕ = ਬਹੁਲਕ_SCP;
			ਰੋਕੋ;
		ਹਾਲਤ 's':
			/* Ignored */
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			sshport = a2port(optarg);
			ਜੇ (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'B':
			addargs(&remote_remote_ਦਲੀਲਾਂ, "-oBatchmode=yes");
			addargs(&ਦਲੀਲਾਂ, "-oBatchmode=yes");
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
			ਹੱਦਬੰਦੀ_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ਜੇ (errstr != ਨਿਰਾ)
				usage();
			ਹੱਦਬੰਦੀ_kbps *= 1024; /* kbps */
			bandwidth_ਹੱਦਬੰਦੀ_init(&bwlimit, ਹੱਦਬੰਦੀ_kbps, COPY_BUFLEN);
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			pflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
			iamrecursive = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'S':
			ssh_ਪ੍ਰੋਗਰਾਮ = xstrdup(optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'v':
			addargs(&ਦਲੀਲਾਂ, "-v");
			addargs(&remote_remote_ਦਲੀਲਾਂ, "-v");
			ਜੇ (verbose_ਬਹੁਲਕ == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ਨਹੀਂਤਾਂ ਜੇ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_ਬਹੁਲਕ = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			addargs(&ਦਲੀਲਾਂ, "-q");
			addargs(&remote_remote_ਦਲੀਲਾਂ, "-q");
			showprogress = 0;
			ਰੋਕੋ;
		ਹਾਲਤ 'X':
			/* Please keep in sync with sftp.c -X */
			ਜੇ (ਲੜੀ_ਤੁਲਨਾ(optarg, "buffer=", 7) == 0) {
				r = ਜਾਂਚ_scaled(optarg + 7, &llv);
				ਜੇ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ਜੇ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (ਮਾਪ_t)llv;
			} ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ਜੇ (errstr != ਨਿਰਾ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (ਮਾਪ_t)llv;
			} ਨਹੀਂਤਾਂ {
				fatal("Invalid -X option");
			}
			ਰੋਕੋ;

		/* Server options. */
		ਹਾਲਤ 'd':
			targetshouldbedirectory = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
			setmode(0, O_ਦੁਆਧਾਰੀ);
#ਜੇ_ਅੰਤ
			ਰੋਕੋ;
		ਹਾਲਤ 'T':
			Tflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&ਦਲੀਲਾਂ, "-oForwardAgent=no");

	ਜੇ (iamremote)
		ਬਹੁਲਕ = ਬਹੁਲਕ_SCP;

	ਜੇ ((pwd = getpwuid(userid = getuid())) == ਨਿਰਾ)
		fatal("unknown user %u", (u_int) userid);

	ਜੇ (!isatty(STDOUT_FILENO))
		showprogress = 0;

	ਜੇ (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} ਨਹੀਂਤਾਂ {
		ਜੇ (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ਨਿਰਾ) == -1) {
			perror("pledge");
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	ਜੇ (fflag) {
		/* Follow "protocol", send data. */
		(ਖਾਲੀ) response();
		ਸਰੋਤ(argc, argv);
		ਬਾਹਰ_ਨਿਕਲੋ(errs != 0);
	}
	ਜੇ (tflag) {
		/* Receive data. */
		sink(argc, argv, ਨਿਰਾ);
		ਬਾਹਰ_ਨਿਕਲੋ(errs != 0);
	}
	ਜੇ (argc < 2)
		usage();
	ਜੇ (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(ਖਾਲੀ) snprintf(cmd, ਆਕਾਰ cmd, "scp%s%s%s%s",
	    verbose_ਬਹੁਲਕ ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(ਖਾਲੀ) ssh_signal(SIGPIPE, lostconn);

	ਜੇ (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, ਬਹੁਲਕ, sftp_ਸਿੱਧਾ);
	ਨਹੀਂਤਾਂ {
		ਜੇ (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, ਬਹੁਲਕ, sftp_ਸਿੱਧਾ);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	ਜੇ (do_cmd_pid != -1 && (ਬਹੁਲਕ == ਬਹੁਲਕ_SFTP || errs == 0)) {
		ਜੇ (remin != -1)
		    (ਖਾਲੀ) close(remin);
		ਜੇ (remout != -1)
		    (ਖਾਲੀ) close(remout);
		ਜੇ (waitpid(do_cmd_pid, &ਸਥਿਤੀ, 0) == -1)
			errs = 1;
		ਨਹੀਂਤਾਂ {
			ਜੇ (!WIFEXITED(ਸਥਿਤੀ) || WEXITSTATUS(ਸਥਿਤੀ) != 0)
				errs = 1;
		}
	}
	ਬਾਹਰ_ਨਿਕਲੋ(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ਸਥਿਰ ਪੂਰਨ
scpio(ਖਾਲੀ *_cnt, ਮਾਪ_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_ਤਰੱਕੀ_meter(0);
	ਜੇ (ਹੱਦਬੰਦੀ_kbps > 0)
		bandwidth_ਹੱਦਬੰਦੀ(&bwlimit, s);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
do_times(ਪੂਰਨ fd, ਪੂਰਨ verb, ਅਚਲ ਬਣਤਰ stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	ਅੱਖਰ buf[(20 + 7 + 2) * 2 + 2];

	(ਖਾਲੀ)snprintf(buf, ਆਕਾਰ(buf), "T%llu 0 %llu 0\n",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ) (sb->st_atime < 0 ? 0 : sb->st_atime));
	ਜੇ (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (ਲੰਮਾ ਲੰਮਾ)sb->st_mtime, (ਲੰਮਾ ਲੰਮਾ)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(ਖਾਲੀ) atomicio(vwrite, fd, buf, ਲੜੀ_ਲੰਬਾਈ(buf));
	ਵਾਪਸ (response());
}

ਸਥਿਰ ਪੂਰਨ
parse_scp_uri(ਅਚਲ ਅੱਖਰ *uri, ਅੱਖਰ **userp, ਅੱਖਰ **hostp, ਪੂਰਨ *portp,
    ਅੱਖਰ **pathp)
{
	ਪੂਰਨ r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	ਜੇ (r == 0 && *pathp == ਨਿਰਾ)
		*pathp = xstrdup(".");
	ਵਾਪਸ r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
ਸਥਿਰ ਪੂਰਨ
append(ਅੱਖਰ *cp, ਅੱਖਰ ***ap, ਮਾਪ_t *np)
{
	ਅੱਖਰ **tmp;

	ਜੇ ((tmp = reallocarray(*ap, *np + 1, ਆਕਾਰ(*tmp))) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	ਵਾਪਸ 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
ਸਥਿਰ ਪੂਰਨ
ਲੱਭੋ_brace(ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਪੂਰਨ *startp, ਪੂਰਨ *endp)
{
	ਪੂਰਨ i;
	ਪੂਰਨ ਵਿੱਚ_bracket, brace_level;

	*startp = *endp = -1;
	ਵਿੱਚ_bracket = brace_level = 0;
	ਲਈ (i = 0; i < ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ && *endp < 0 && ਨਮੂਨਾ[i] != '\0'; i++) {
		ਚੋਣ (ਨਮੂਨਾ[i]) {
		ਹਾਲਤ '\\':
			/* skip next character */
			ਜੇ (ਨਮੂਨਾ[i + 1] != '\0')
				i++;
			ਰੋਕੋ;
		ਹਾਲਤ '[':
			ਵਿੱਚ_bracket = 1;
			ਰੋਕੋ;
		ਹਾਲਤ ']':
			ਵਿੱਚ_bracket = 0;
			ਰੋਕੋ;
		ਹਾਲਤ '{':
			ਜੇ (ਵਿੱਚ_bracket)
				ਰੋਕੋ;
			ਜੇ (ਨਮੂਨਾ[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				ਰੋਕੋ;
			}
			ਜੇ (*startp == -1)
				*startp = i;
			brace_level++;
			ਰੋਕੋ;
		ਹਾਲਤ '}':
			ਜੇ (ਵਿੱਚ_bracket)
				ਰੋਕੋ;
			ਜੇ (*startp < 0) {
				/* Unbalanced brace */
				ਵਾਪਸ -1;
			}
			ਜੇ (--brace_level <= 0)
				*endp = i;
			ਰੋਕੋ;
		}
	}
	/* unbalanced brackets/braces */
	ਜੇ (*endp < 0 && (*startp >= 0 || ਵਿੱਚ_bracket))
		ਵਾਪਸ -1;
	ਵਾਪਸ 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ਸਥਿਰ ਪੂਰਨ
emit_expansion(ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਪੂਰਨ brace_ਸ਼ੁਰੂ, ਪੂਰਨ brace_ਸਿਰਾ,
    ਪੂਰਨ sel_ਸ਼ੁਰੂ, ਪੂਰਨ sel_ਸਿਰਾ, ਅੱਖਰ ***patternsp, ਮਾਪ_t *npatternsp)
{
	ਅੱਖਰ *cp;
	ਮਾਪ_t ਨਮੂਨਾ_len;
	ਪੂਰਨ o = 0, ਪੂਛ_len;

	ਜੇ ((ਨਮੂਨਾ_len = ਲੜੀ_ਲੰਬਾਈ(ਨਮੂਨਾ)) == 0 || ਨਮੂਨਾ_len >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		ਵਾਪਸ -1;

	ਪੂਛ_len = ਲੜੀ_ਲੰਬਾਈ(ਨਮੂਨਾ + brace_ਸਿਰਾ + 1);
	ਜੇ ((cp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(brace_ਸ਼ੁਰੂ + (sel_ਸਿਰਾ - sel_ਸ਼ੁਰੂ) +
	    ਪੂਛ_len + 1)) == ਨਿਰਾ)
		ਵਾਪਸ -1;

	/* Pattern before initial brace */
	ਜੇ (brace_ਸ਼ੁਰੂ > 0) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp, ਨਮੂਨਾ, brace_ਸ਼ੁਰੂ);
		o = brace_ਸ਼ੁਰੂ;
	}
	/* Current braced selection */
	ਜੇ (sel_ਸਿਰਾ - sel_ਸ਼ੁਰੂ > 0) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp + o, ਨਮੂਨਾ + sel_ਸ਼ੁਰੂ,
		    sel_ਸਿਰਾ - sel_ਸ਼ੁਰੂ);
		o += sel_ਸਿਰਾ - sel_ਸ਼ੁਰੂ;
	}
	/* Remainder of pattern after closing brace */
	ਜੇ (ਪੂਛ_len > 0) {
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(cp + o, ਨਮੂਨਾ + brace_ਸਿਰਾ + 1, ਪੂਛ_len);
		o += ਪੂਛ_len;
	}
	cp[o] = '\0';
	ਜੇ (append(cp, patternsp, npatternsp) != 0) {
		ਮੁਕਤ(cp);
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ 0;
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
ਸਥਿਰ ਪੂਰਨ
brace_expand_one(ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਅੱਖਰ ***patternsp, ਮਾਪ_t *npatternsp,
    ਪੂਰਨ *expanded, ਪੂਰਨ *invalid)
{
	ਪੂਰਨ i;
	ਪੂਰਨ ਵਿੱਚ_bracket, brace_ਸ਼ੁਰੂ, brace_ਸਿਰਾ, brace_level;
	ਪੂਰਨ sel_ਸ਼ੁਰੂ, sel_ਸਿਰਾ;

	*invalid = *expanded = 0;

	ਜੇ (ਲੱਭੋ_brace(ਨਮੂਨਾ, &brace_ਸ਼ੁਰੂ, &brace_ਸਿਰਾ) != 0) {
		*invalid = 1;
		ਵਾਪਸ 0;
	} ਨਹੀਂਤਾਂ ਜੇ (brace_ਸ਼ੁਰੂ == -1)
		ਵਾਪਸ 0;

	ਵਿੱਚ_bracket = brace_level = 0;
	ਲਈ (i = sel_ਸ਼ੁਰੂ = brace_ਸ਼ੁਰੂ + 1; i < brace_ਸਿਰਾ; i++) {
		ਚੋਣ (ਨਮੂਨਾ[i]) {
		ਹਾਲਤ '{':
			ਜੇ (ਵਿੱਚ_bracket)
				ਰੋਕੋ;
			brace_level++;
			ਰੋਕੋ;
		ਹਾਲਤ '}':
			ਜੇ (ਵਿੱਚ_bracket)
				ਰੋਕੋ;
			brace_level--;
			ਰੋਕੋ;
		ਹਾਲਤ '[':
			ਵਿੱਚ_bracket = 1;
			ਰੋਕੋ;
		ਹਾਲਤ ']':
			ਵਿੱਚ_bracket = 0;
			ਰੋਕੋ;
		ਹਾਲਤ '\\':
			ਜੇ (i < brace_ਸਿਰਾ - 1)
				i++; /* skip */
			ਰੋਕੋ;
		}
		ਜੇ (ਨਮੂਨਾ[i] == ',' || i == brace_ਸਿਰਾ - 1) {
			ਜੇ (ਵਿੱਚ_bracket || brace_level > 0)
				ਜਾਰੀ;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_ਸਿਰਾ = (i == brace_ਸਿਰਾ - 1) ? brace_ਸਿਰਾ : i;
			ਜੇ (emit_expansion(ਨਮੂਨਾ, brace_ਸ਼ੁਰੂ, brace_ਸਿਰਾ,
			    sel_ਸ਼ੁਰੂ, sel_ਸਿਰਾ, patternsp, npatternsp) != 0)
				ਵਾਪਸ -1;
			/* move on to the next selection */
			sel_ਸ਼ੁਰੂ = i + 1;
			ਜਾਰੀ;
		}
	}
	ਜੇ (ਵਿੱਚ_bracket || brace_level > 0) {
		*invalid = 1;
		ਵਾਪਸ 0;
	}
	/* success */
	*expanded = 1;
	ਵਾਪਸ 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ਸਥਿਰ ਪੂਰਨ
brace_expand(ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਅੱਖਰ ***patternsp, ਮਾਪ_t *npatternsp)
{
	ਅੱਖਰ *cp, *cp2, **ਸਰਗਰਮ = ਨਿਰਾ, **ਪੂਰਾ = ਨਿਰਾ;
	ਮਾਪ_t i, nactive = 0, ndone = 0;
	ਪੂਰਨ ret = -1, invalid = 0, expanded = 0;

	*patternsp = ਨਿਰਾ;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	ਜੇ ((cp = strdup(ਨਮੂਨਾ)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਜੇ (append(cp, &ਸਰਗਰਮ, &nactive) != 0) {
		ਮੁਕਤ(cp);
		ਵਾਪਸ -1;
	}
	ਜਦੋਂ (nactive > 0) {
		cp = ਸਰਗਰਮ[nactive - 1];
		nactive--;
		ਜੇ (brace_expand_one(cp, &ਸਰਗਰਮ, &nactive,
		    &expanded, &invalid) == -1) {
			ਮੁਕਤ(cp);
			ਜਾਓ fail;
		}
		ਜੇ (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		ਜੇ (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			ਮੁਕਤ(cp);
			ਜਾਰੀ;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		ਜੇ ((cp2 = strrchr(cp, '/')) != ਨਿਰਾ)
			*cp2++ = '\0';
		ਨਹੀਂਤਾਂ
			cp2 = cp;
		ਜੇ (append(xstrdup(cp2), &ਪੂਰਾ, &ndone) != 0) {
			ਮੁਕਤ(cp);
			ਜਾਓ fail;
		}
		ਮੁਕਤ(cp);
	}
	/* success */
	*patternsp = ਪੂਰਾ;
	*npatternsp = ndone;
	ਪੂਰਾ = ਨਿਰਾ;
	ndone = 0;
	ret = 0;
 fail:
	ਲਈ (i = 0; i < nactive; i++)
		ਮੁਕਤ(ਸਰਗਰਮ[i]);
	ਮੁਕਤ(ਸਰਗਰਮ);
	ਲਈ (i = 0; i < ndone; i++)
		ਮੁਕਤ(ਪੂਰਾ[i]);
	ਮੁਕਤ(ਪੂਰਾ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਬਣਤਰ sftp_conn *
do_sftp_connect(ਅੱਖਰ *host, ਅੱਖਰ *user, ਪੂਰਨ ਪੋਰਟ, ਅੱਖਰ *sftp_ਸਿੱਧਾ,
   ਪੂਰਨ *reminp, ਪੂਰਨ *remoutp, ਪੂਰਨ *pidp)
{
	ਜੇ (sftp_ਸਿੱਧਾ == ਨਿਰਾ) {
		ਜੇ (do_cmd(ssh_ਪ੍ਰੋਗਰਾਮ, host, user, ਪੋਰਟ, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			ਵਾਪਸ ਨਿਰਾ;

	} ਨਹੀਂਤਾਂ {
		freeargs(&ਦਲੀਲਾਂ);
		addargs(&ਦਲੀਲਾਂ, "sftp-server");
		ਜੇ (do_cmd(sftp_ਸਿੱਧਾ, host, ਨਿਰਾ, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, ਹੱਦਬੰਦੀ_kbps);
}

ਖਾਲੀ
toremote(ਪੂਰਨ argc, ਅੱਖਰ **argv, ਗਿਣਤੀ scp_ਬਹੁਲਕ_e ਬਹੁਲਕ, ਅੱਖਰ *sftp_ਸਿੱਧਾ)
{
	ਅੱਖਰ *suser = ਨਿਰਾ, *host = ਨਿਰਾ, *src = ਨਿਰਾ;
	ਅੱਖਰ *bp, *tuser, *thost, *targ;
	ਪੂਰਨ sport = -1, tport = -1;
	ਬਣਤਰ sftp_conn *conn = ਨਿਰਾ, *conn2 = ਨਿਰਾ;
	arglist alist;
	ਪੂਰਨ i, r, ਸਥਿਤੀ;
	ਬਣਤਰ stat sb;
	u_int j;

	memset(&alist, '\0', ਆਕਾਰ(alist));
	alist.list = ਨਿਰਾ;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	ਜੇ (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (r != 0) {
		ਜੇ (parse_user_host_ਰਸਤਾ(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Parse source files */
	ਲਈ (i = 0; i < argc - 1; i++) {
		ਮੁਕਤ(suser);
		ਮੁਕਤ(host);
		ਮੁਕਤ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ਜੇ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ਜਾਰੀ;
		}
		ਜੇ (r != 0) {
			parse_user_host_ਰਸਤਾ(argv[i], &suser, &host, &src);
		}
		ਜੇ (suser != ਨਿਰਾ && !okname(suser)) {
			++errs;
			ਜਾਰੀ;
		}
		ਜੇ (host && throughlocal) {	/* extended remote to remote */
			ਜੇ (ਬਹੁਲਕ == ਬਹੁਲਕ_SFTP) {
				ਜੇ (remin == -1 || conn == ਨਿਰਾ) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_ਸਿੱਧਾ,
					    &remin, &remout, &do_cmd_pid);
					ਜੇ (conn == ਨਿਰਾ) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (ਲੰਮਾ)do_cmd_pid);
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
				    sport, sftp_ਸਿੱਧਾ,
				    &remin2, &remout2, &do_cmd_pid2);
				ਜੇ (conn2 == ਨਿਰਾ) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (ਲੰਮਾ)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(ਖਾਲੀ) close(remin2);
				(ਖਾਲੀ) close(remout2);
				remin2 = remout2 = -1;
				ਜੇ (waitpid(do_cmd_pid2, &ਸਥਿਤੀ, 0) == -1)
					++errs;
				ਨਹੀਂਤਾਂ ਜੇ (!WIFEXITED(ਸਥਿਤੀ) ||
				    WEXITSTATUS(ਸਥਿਤੀ) != 0)
					++errs;
				do_cmd_pid2 = -1;
				ਜਾਰੀ;
			} ਨਹੀਂਤਾਂ {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				ਜੇ (do_cmd(ssh_ਪ੍ਰੋਗਰਾਮ, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					ਬਾਹਰ_ਨਿਕਲੋ(1);
				ਮੁਕਤ(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ਜੇ (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					ਬਾਹਰ_ਨਿਕਲੋ(1);
				ਮੁਕਤ(bp);
				(ਖਾਲੀ) close(remin);
				(ਖਾਲੀ) close(remout);
				remin = remout = -1;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			ਜੇ (tuser != ਨਿਰਾ && !okname(tuser)) {
				++errs;
				ਜਾਰੀ;
			}
			ਜੇ (tport != -1 && tport != SSH_DEFAULT_ਪੋਰਟ) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_ਪ੍ਰੋਗਰਾਮ);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			ਲਈ (j = 0; j < remote_remote_ਦਲੀਲਾਂ.ਅੰਕ; j++) {
				addargs(&alist, "%s",
				    remote_remote_ਦਲੀਲਾਂ.list[j]);
			}

			ਜੇ (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			ਜੇ (suser) {
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
			ਜੇ (do_local_cmd(&alist) != 0)
				errs = 1;
		} ਨਹੀਂਤਾਂ {	/* local to remote */
			ਜੇ (ਬਹੁਲਕ == ਬਹੁਲਕ_SFTP) {
				/* no need to glob: already done by shell */
				ਜੇ (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				ਜੇ (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_ਸਿੱਧਾ,
					    &remin, &remout, &do_cmd_pid);
					ਜੇ (conn == ਨਿਰਾ) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				ਸਰੋਤ_sftp(1, argv[i], targ, conn);
				ਜਾਰੀ;
			}
			/* SCP */
			ਜੇ (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ਜੇ (do_cmd(ssh_ਪ੍ਰੋਗਰਾਮ, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					ਬਾਹਰ_ਨਿਕਲੋ(1);
				ਜੇ (response() < 0)
					ਬਾਹਰ_ਨਿਕਲੋ(1);
				ਮੁਕਤ(bp);
			}
			ਸਰੋਤ(1, argv + i);
		}
	}
ਬਾਹਰਲਾ:
	freeargs(&alist);
	ਮੁਕਤ(tuser);
	ਮੁਕਤ(thost);
	ਮੁਕਤ(targ);
	ਮੁਕਤ(suser);
	ਮੁਕਤ(host);
	ਮੁਕਤ(src);
	sftp_free(conn);
	sftp_free(conn2);
}

ਖਾਲੀ
tolocal(ਪੂਰਨ argc, ਅੱਖਰ **argv, ਗਿਣਤੀ scp_ਬਹੁਲਕ_e ਬਹੁਲਕ, ਅੱਖਰ *sftp_ਸਿੱਧਾ)
{
	ਅੱਖਰ *bp, *host = ਨਿਰਾ, *src = ਨਿਰਾ, *suser = ਨਿਰਾ;
	arglist alist;
	ਬਣਤਰ sftp_conn *conn = ਨਿਰਾ;
	ਪੂਰਨ i, r, sport = -1;

	memset(&alist, '\0', ਆਕਾਰ(alist));
	alist.list = ਨਿਰਾ;

	ਲਈ (i = 0; i < argc - 1; i++) {
		ਮੁਕਤ(suser);
		ਮੁਕਤ(host);
		ਮੁਕਤ(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ਜੇ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ਜਾਰੀ;
		}
		ਜੇ (r != 0)
			parse_user_host_ਰਸਤਾ(argv[i], &suser, &host, &src);
		ਜੇ (suser != ਨਿਰਾ && !okname(suser)) {
			++errs;
			ਜਾਰੀ;
		}
		ਜੇ (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", ਰਸਤਾ_CP);
			ਜੇ (iamrecursive)
				addargs(&alist, "-r");
			ਜੇ (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			ਜੇ (do_local_cmd(&alist))
				++errs;
			ਜਾਰੀ;
		}
		/* Remote to local. */
		ਜੇ (ਬਹੁਲਕ == ਬਹੁਲਕ_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_ਸਿੱਧਾ, &remin, &remout, &do_cmd_pid);
			ਜੇ (conn == ਨਿਰਾ) {
				error("sftp connection failed");
				++errs;
				ਜਾਰੀ;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(ਖਾਲੀ) close(remin);
			(ਖਾਲੀ) close(remout);
			remin = remout = -1;
			ਜਾਰੀ;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		ਜੇ (do_cmd(ssh_ਪ੍ਰੋਗਰਾਮ, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			ਮੁਕਤ(bp);
			++errs;
			ਜਾਰੀ;
		}
		ਮੁਕਤ(bp);
		sink(1, argv + argc - 1, src);
		(ਖਾਲੀ) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	ਮੁਕਤ(suser);
	ਮੁਕਤ(host);
	ਮੁਕਤ(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
ਸਥਿਰ ਅੱਖਰ *
prepare_remote_ਰਸਤਾ(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਮਾਪ_t nslash;

	/* Handle ~ prefixed paths */
	ਜੇ (*ਰਸਤਾ == '\0' || strcmp(ਰਸਤਾ, "~") == 0)
		ਵਾਪਸ xstrdup(".");
	ਜੇ (*ਰਸਤਾ != '~')
		ਵਾਪਸ xstrdup(ਰਸਤਾ);
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ਰਸਤਾ, "~/", 2) == 0) {
		ਜੇ ((nslash = strspn(ਰਸਤਾ + 2, "/")) == ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ + 2))
			ਵਾਪਸ xstrdup(".");
		ਵਾਪਸ xstrdup(ਰਸਤਾ + 2 + nslash);
	}
	ਜੇ (sftp_can_expand_ਰਸਤਾ(conn))
		ਵਾਪਸ sftp_expand_ਰਸਤਾ(conn, ਰਸਤਾ);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	ਵਾਪਸ ਨਿਰਾ;
}

ਖਾਲੀ
ਸਰੋਤ_sftp(ਪੂਰਨ argc, ਅੱਖਰ *src, ਅੱਖਰ *targ, ਬਣਤਰ sftp_conn *conn)
{
	ਅੱਖਰ *ਨਿਸ਼ਾਨਾ = ਨਿਰਾ, *filename = ਨਿਰਾ, *abs_dst = ਨਿਰਾ;
	ਪੂਰਨ src_is_dir, ਨਿਸ਼ਾਨਾ_is_dir;
	Attrib a;
	ਬਣਤਰ stat st;

	memset(&a, '\0', ਆਕਾਰ(a));
	ਜੇ (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	ਜੇ ((filename = basename(src)) == ਨਿਰਾ)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	ਜੇ (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	ਜੇ ((ਨਿਸ਼ਾਨਾ = prepare_remote_ਰਸਤਾ(conn, targ)) == ਨਿਰਾ)
		cleanup_exit(255);
	ਨਿਸ਼ਾਨਾ_is_dir = sftp_remote_is_dir(conn, ਨਿਸ਼ਾਨਾ);
	ਜੇ (targetshouldbedirectory && !ਨਿਸ਼ਾਨਾ_is_dir) {
		debug("target directory \"%s\" does not exist", ਨਿਸ਼ਾਨਾ);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		ਜੇ (sftp_mkdir(conn, ਨਿਸ਼ਾਨਾ, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		ਨਿਸ਼ਾਨਾ_is_dir = 1;
	}
	ਜੇ (ਨਿਸ਼ਾਨਾ_is_dir)
		abs_dst = sftp_ਰਸਤਾ_append(ਨਿਸ਼ਾਨਾ, filename);
	ਨਹੀਂਤਾਂ {
		abs_dst = ਨਿਸ਼ਾਨਾ;
		ਨਿਸ਼ਾਨਾ = ਨਿਰਾ;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	ਜੇ (src_is_dir && iamrecursive) {
		ਜੇ (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_ਤਰੱਕੀ_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	ਮੁਕਤ(abs_dst);
	ਮੁਕਤ(ਨਿਸ਼ਾਨਾ);
}

ਖਾਲੀ
ਸਰੋਤ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਬਣਤਰ stat stb;
	ਸਥਿਰ BUF ਬਫਰ;
	BUF *bp;
	off_t i, statbytes;
	ਮਾਪ_t amt, nr;
	ਪੂਰਨ fd = -1, haderr, indx;
	ਅੱਖਰ *ਆਖਰੀ, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	ਪੂਰਨ len;

	ਲਈ (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = ਲੜੀ_ਲੰਬਾਈ(name);
		ਜਦੋਂ (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		ਜੇ ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			ਜਾਓ syserr;
		ਜੇ (strchr(name, '\n') != ਨਿਰਾ) {
			strnvis(encname, name, ਆਕਾਰ(encname), VIS_NL);
			name = encname;
		}
		ਜੇ (fstat(fd, &stb) == -1) {
syserr:			ਲੜੀਵਾਰ_err("%s: %s", name, strerror(errno));
			ਜਾਓ ਅਗਲਾ;
		}
		ਜੇ (stb.st_size < 0) {
			ਲੜੀਵਾਰ_err("%s: %s", name, "Negative file size");
			ਜਾਓ ਅਗਲਾ;
		}
		unset_nonblock(fd);
		ਚੋਣ (stb.st_mode & S_IFMT) {
		ਹਾਲਤ S_IFREG:
			ਰੋਕੋ;
		ਹਾਲਤ S_IFDIR:
			ਜੇ (iamrecursive) {
				rsource(name, &stb);
				ਜਾਓ ਅਗਲਾ;
			}
			/* FALLTHROUGH */
		ਮੂਲ:
			ਲੜੀਵਾਰ_err("%s: not a regular file", name);
			ਜਾਓ ਅਗਲਾ;
		}
		ਜੇ ((ਆਖਰੀ = strrchr(name, '/')) == ਨਿਰਾ)
			ਆਖਰੀ = name;
		ਨਹੀਂਤਾਂ
			++ਆਖਰੀ;
		curfile = ਆਖਰੀ;
		ਜੇ (pflag) {
			ਜੇ (do_times(remout, verbose_ਬਹੁਲਕ, &stb) < 0)
				ਜਾਓ ਅਗਲਾ;
		}
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, ਆਕਾਰ buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (ਲੰਮਾ ਲੰਮਾ)stb.st_size, ਆਖਰੀ);
		ਜੇ (verbose_ਬਹੁਲਕ)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(ਖਾਲੀ) atomicio(vwrite, remout, buf, ਲੜੀ_ਲੰਬਾਈ(buf));
		ਜੇ (response() < 0)
			ਜਾਓ ਅਗਲਾ;
		ਜੇ ((bp = allocbuf(&ਬਫਰ, fd, COPY_BUFLEN)) == ਨਿਰਾ) {
ਅਗਲਾ:			ਜੇ (fd != -1) {
				(ਖਾਲੀ) close(fd);
				fd = -1;
			}
			ਜਾਰੀ;
		}
		ਜੇ (showprogress)
			ਸ਼ੁਰੂ_ਤਰੱਕੀ_meter(curfile, stb.st_size, &statbytes);
		ਸੈੱਟ_nonblock(remout);
		ਲਈ (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			ਜੇ (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			ਜੇ (!haderr) {
				ਜੇ ((nr = atomicio(ਪਠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			ਜੇ (haderr) {
				(ਖਾਲੀ)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				ਜਾਰੀ;
			}
			ਜੇ (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		ਜੇ (fd != -1) {
			ਜੇ (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		ਜੇ (!haderr)
			(ਖਾਲੀ) atomicio(vwrite, remout, "", 1);
		ਨਹੀਂਤਾਂ
			ਲੜੀਵਾਰ_err("%s: %s", name, strerror(haderr));
		(ਖਾਲੀ) response();
		ਜੇ (showprogress)
			stop_ਤਰੱਕੀ_meter();
	}
}

ਖਾਲੀ
rsource(ਅੱਖਰ *name, ਬਣਤਰ stat *statp)
{
	DIR *dirp;
	ਬਣਤਰ dirent *dp;
	ਅੱਖਰ *ਆਖਰੀ, *vect[1], ਰਸਤਾ[PATH_MAX];

	ਜੇ (!(dirp = opendir(name))) {
		ਲੜੀਵਾਰ_err("%s: %s", name, strerror(errno));
		ਵਾਪਸ;
	}
	ਆਖਰੀ = strrchr(name, '/');
	ਜੇ (ਆਖਰੀ == ਨਿਰਾ)
		ਆਖਰੀ = name;
	ਨਹੀਂਤਾਂ
		ਆਖਰੀ++;
	ਜੇ (pflag) {
		ਜੇ (do_times(remout, verbose_ਬਹੁਲਕ, statp) < 0) {
			closedir(dirp);
			ਵਾਪਸ;
		}
	}
	(ਖਾਲੀ) snprintf(ਰਸਤਾ, ਆਕਾਰ ਰਸਤਾ, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, ਆਖਰੀ);
	ਜੇ (verbose_ਬਹੁਲਕ)
		fmprintf(stderr, "Entering directory: %s", ਰਸਤਾ);
	(ਖਾਲੀ) atomicio(vwrite, remout, ਰਸਤਾ, ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ));
	ਜੇ (response() < 0) {
		closedir(dirp);
		ਵਾਪਸ;
	}
	ਜਦੋਂ ((dp = readdir(dirp)) != ਨਿਰਾ) {
		ਜੇ (dp->d_ino == 0)
			ਜਾਰੀ;
		ਜੇ (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			ਜਾਰੀ;
		ਜੇ (ਲੜੀ_ਲੰਬਾਈ(name) + 1 + ਲੜੀ_ਲੰਬਾਈ(dp->d_name) >= ਆਕਾਰ(ਰਸਤਾ) - 1) {
			ਲੜੀਵਾਰ_err("%s/%s: name too long", name, dp->d_name);
			ਜਾਰੀ;
		}
		(ਖਾਲੀ) snprintf(ਰਸਤਾ, ਆਕਾਰ ਰਸਤਾ, "%s/%s", name, dp->d_name);
		vect[0] = ਰਸਤਾ;
		ਸਰੋਤ(1, vect);
	}
	(ਖਾਲੀ) closedir(dirp);
	(ਖਾਲੀ) atomicio(vwrite, remout, "E\n", 2);
	(ਖਾਲੀ) response();
}

ਖਾਲੀ
sink_sftp(ਪੂਰਨ argc, ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਬਣਤਰ sftp_conn *conn)
{
	ਅੱਖਰ *abs_src = ਨਿਰਾ;
	ਅੱਖਰ *abs_dst = ਨਿਰਾ;
	glob_t g;
	ਅੱਖਰ *filename, *tmp = ਨਿਰਾ;
	ਪੂਰਨ i, r, err = 0, dst_is_dir;
	ਬਣਤਰ stat st;

	memset(&g, 0, ਆਕਾਰ(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	ਜੇ ((abs_src = prepare_remote_ਰਸਤਾ(conn, src)) == ਨਿਰਾ) {
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	ਜੇ ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ਨਿਰਾ, &g)) != 0) {
		ਜੇ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ਨਹੀਂਤਾਂ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Did we actually get any matches back from the glob? */
	ਜੇ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ਨਿਰਾ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ਜੇ (sftp_stat(conn, g.gl_pathv[0], 1, ਨਿਰਾ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	ਜੇ ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	ਜੇ (g.gl_matchc > 1 && !dst_is_dir) {
		ਜੇ (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug2_f("creating destination \"%s\"", dst);
		ਜੇ (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		dst_is_dir = 1;
	}

	ਲਈ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ਜੇ ((filename = basename(tmp)) == ਨਿਰਾ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		/* Special handling for destination of '..' */
		ਜੇ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ਜੇ (dst_is_dir)
			abs_dst = sftp_ਰਸਤਾ_append(dst, filename);
		ਨਹੀਂਤਾਂ
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ਜੇ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ਜੇ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ਨਿਰਾ, pflag, SFTP_ਤਰੱਕੀ_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (sftp_download(conn, g.gl_pathv[i], abs_dst, ਨਿਰਾ,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		ਮੁਕਤ(abs_dst);
		abs_dst = ਨਿਰਾ;
		ਮੁਕਤ(tmp);
		tmp = ਨਿਰਾ;
	}

ਬਾਹਰਲਾ:
	ਮੁਕਤ(abs_src);
	ਮੁਕਤ(tmp);
	globfree(&g);
	ਜੇ (err == -1)
		errs = 1;
}


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TYPE_ਉਛਾਲ(type, val) \
	((ਆਕਾਰ(type) == 4 && (val) > INT32_MAX) || \
	 (ਆਕਾਰ(type) == 8 && (val) > INT64_MAX) || \
	 (ਆਕਾਰ(type) != 4 && ਆਕਾਰ(type) != 8))

ਖਾਲੀ
sink(ਪੂਰਨ argc, ਅੱਖਰ **argv, ਅਚਲ ਅੱਖਰ *src)
{
	ਸਥਿਰ BUF ਬਫਰ;
	ਬਣਤਰ stat stb;
	BUF *bp;
	off_t i;
	ਮਾਪ_t j, ਗਿਣਤੀ_2;
	ਪੂਰਨ amt, exists, ਪਹਿਲਾ, ofd;
	ਬਹੁਲਕ_t ਬਹੁਲਕ, omode, ਨਕਾਬ;
	off_t ਮਾਪ, statbytes;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ ull;
	ਪੂਰਨ setimes, targisdir, wrerr;
	ਅੱਖਰ ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	ਅੱਖਰ **patterns = ਨਿਰਾ;
	ਮਾਪ_t n, npatterns = 0;
	ਬਣਤਰ timeval tv[2];

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	atime	tv[0]
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	mtime	tv[1]
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SCREWUP(str)	{ why = str; ਜਾਓ screwup; }

	ਜੇ (TYPE_ਉਛਾਲ(time_t, 0) || TYPE_ਉਛਾਲ(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	ਨਕਾਬ = umask(0);
	ਜੇ (!pflag) {
		(ਖਾਲੀ) umask(ਨਕਾਬ);
		ਨਕਾਬ |= 07000;
	}
	ਜੇ (argc != 1) {
		ਲੜੀਵਾਰ_err("ambiguous target");
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	targ = *argv;
	ਜੇ (targetshouldbedirectory)
		verifydir(targ);

	(ਖਾਲੀ) atomicio(vwrite, remout, "", 1);
	ਜੇ (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	ਜੇ (src != ਨਿਰਾ && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		ਜੇ (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	ਲਈ (ਪਹਿਲਾ = 1;; ਪਹਿਲਾ = 0) {
		cp = buf;
		ਜੇ (atomicio(ਪਠ, remin, cp, 1) != 1)
			ਜਾਓ ਪੂਰਾ;
		ਜੇ (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		ਕਰੋ {
			ਜੇ (atomicio(ਪਠ, remin, &ch, ਆਕਾਰ(ch)) != ਆਕਾਰ(ch))
				SCREWUP("lost connection");
			ਜੇ (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} ਜਦੋਂ (cp < &buf[ਆਕਾਰ(buf) - 1] && ch != '\n');
		*cp = 0;
		ਜੇ (verbose_ਬਹੁਲਕ)
			fmprintf(stderr, "Sink: %s", buf);

		ਜੇ (buf[0] == '\01' || buf[0] == '\02') {
			ਜੇ (iamremote == 0) {
				(ਖਾਲੀ) snmprintf(visbuf, ਆਕਾਰ(visbuf),
				    ਨਿਰਾ, "%s", buf + 1);
				(ਖਾਲੀ) atomicio(vwrite, STDERR_FILENO,
				    visbuf, ਲੜੀ_ਲੰਬਾਈ(visbuf));
			}
			ਜੇ (buf[0] == '\02')
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			++errs;
			ਜਾਰੀ;
		}
		ਜੇ (buf[0] == 'E') {
			(ਖਾਲੀ) atomicio(vwrite, remout, "", 1);
			ਜਾਓ ਪੂਰਾ;
		}
		ਜੇ (ch == '\n')
			*--cp = 0;

		cp = buf;
		ਜੇ (*cp == 'T') {
			setimes++;
			cp++;
			ਜੇ (!ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ਜੇ (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			ਜੇ (TYPE_ਉਛਾਲ(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			ਜੇ (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			ਜੇ (!ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ਜੇ (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			ਜੇ (TYPE_ਉਛਾਲ(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			ਜੇ (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(ਖਾਲੀ) atomicio(vwrite, remout, "", 1);
			ਜਾਰੀ;
		}
		ਜੇ (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			ਜੇ (ਪਹਿਲਾ) {
				ਲੜੀਵਾਰ_err("%s", cp);
				ਬਾਹਰ_ਨਿਕਲੋ(1);
			}
			SCREWUP("expected control record");
		}
		ਬਹੁਲਕ = 0;
		ਲਈ (++cp; cp < buf + 5; cp++) {
			ਜੇ (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			ਬਹੁਲਕ = (ਬਹੁਲਕ << 3) | (*cp - '0');
		}
		ਜੇ (!pflag)
			ਬਹੁਲਕ &= ~ਨਕਾਬ;
		ਜੇ (*cp++ != ' ')
			SCREWUP("mode not delimited");

		ਜੇ (!ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		ਜੇ (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		ਜੇ (TYPE_ਉਛਾਲ(off_t, ull))
			SCREWUP("size out of range");
		ਮਾਪ = (off_t)ull;

		ਜੇ (*cp == '\0' || strchr(cp, '/') != ਨਿਰਾ ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			ਲੜੀਵਾਰ_err("error: unexpected filename: %s", cp);
			ਬਾਹਰ_ਨਿਕਲੋ(1);
		}
		ਜੇ (npatterns > 0) {
			ਲਈ (n = 0; n < npatterns; n++) {
				ਜੇ (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					ਰੋਕੋ;
			}
			ਜੇ (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				ਲਈ (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		ਜੇ (targisdir) {
			ਸਥਿਰ ਅੱਖਰ *namebuf;
			ਸਥਿਰ ਮਾਪ_t cursize;
			ਮਾਪ_t need;

			need = ਲੜੀ_ਲੰਬਾਈ(targ) + ਲੜੀ_ਲੰਬਾਈ(cp) + 250;
			ਜੇ (need > cursize) {
				ਮੁਕਤ(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(ਖਾਲੀ) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} ਨਹੀਂਤਾਂ
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		ਜੇ (buf[0] == 'D') {
			ਪੂਰਨ mod_flag = pflag;
			ਜੇ (!iamrecursive)
				SCREWUP("received directory without -r");
			ਜੇ (exists) {
				ਜੇ (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					ਜਾਓ bad;
				}
				ਜੇ (pflag)
					(ਖਾਲੀ) chmod(np, ਬਹੁਲਕ);
			} ਨਹੀਂਤਾਂ {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				ਜੇ (mkdir(np, ਬਹੁਲਕ | S_IRWXU) == -1)
					ਜਾਓ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			ਜੇ (setimes) {
				setimes = 0;
				(ਖਾਲੀ) utimes(vect[0], tv);
			}
			ਜੇ (mod_flag)
				(ਖਾਲੀ) chmod(vect[0], ਬਹੁਲਕ);
			ਮੁਕਤ(vect[0]);
			ਜਾਰੀ;
		}
		omode = ਬਹੁਲਕ;
		ਬਹੁਲਕ |= S_IWUSR;
		ਜੇ ((ofd = open(np, O_WRONLY|O_CREAT, ਬਹੁਲਕ)) == -1) {
bad:			ਲੜੀਵਾਰ_err("%s: %s", np, strerror(errno));
			ਜਾਰੀ;
		}
		(ਖਾਲੀ) atomicio(vwrite, remout, "", 1);
		ਜੇ ((bp = allocbuf(&ਬਫਰ, ofd, COPY_BUFLEN)) == ਨਿਰਾ) {
			(ਖਾਲੀ) close(ofd);
			ਜਾਰੀ;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		ਜੇ (showprogress)
			ਸ਼ੁਰੂ_ਤਰੱਕੀ_meter(curfile, ਮਾਪ, &statbytes);
		ਸੈੱਟ_nonblock(remin);
		ਲਈ (ਗਿਣਤੀ_2 = i = 0; i < ਮਾਪ; i += bp->cnt) {
			amt = bp->cnt;
			ਜੇ (i + amt > ਮਾਪ)
				amt = ਮਾਪ - i;
			ਗਿਣਤੀ_2 += amt;
			ਕਰੋ {
				j = atomicio6(ਪਠ, remin, cp, amt,
				    scpio, &statbytes);
				ਜੇ (j == 0) {
					ਲੜੀਵਾਰ_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					ਬਾਹਰ_ਨਿਕਲੋ(1);
				}
				amt -= j;
				cp += j;
			} ਜਦੋਂ (amt > 0);

			ਜੇ (ਗਿਣਤੀ_2 == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				ਜੇ (!wrerr) {
					ਜੇ (atomicio(vwrite, ofd, bp->buf,
					    ਗਿਣਤੀ_2) != ਗਿਣਤੀ_2) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				ਗਿਣਤੀ_2 = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		ਜੇ (ਗਿਣਤੀ_2 != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, ਗਿਣਤੀ_2) != ਗਿਣਤੀ_2) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		ਜੇ (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, ਮਾਪ) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		ਜੇ (pflag) {
			ਜੇ (exists || omode != ਬਹੁਲਕ)
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCHMOD
				ਜੇ (fchmod(ofd, omode)) {
#ਨਹੀਂਤਾਂ /* HAVE_FCHMOD */
				ਜੇ (chmod(np, omode)) {
#ਜੇ_ਅੰਤ /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} ਨਹੀਂਤਾਂ {
			ਜੇ (!exists && omode != ਬਹੁਲਕ)
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FCHMOD
				ਜੇ (fchmod(ofd, omode & ~ਨਕਾਬ)) {
#ਨਹੀਂਤਾਂ /* HAVE_FCHMOD */
				ਜੇ (chmod(np, omode & ~ਨਕਾਬ)) {
#ਜੇ_ਅੰਤ /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		ਜੇ (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(ਖਾਲੀ) response();
		ਜੇ (showprogress)
			stop_ਤਰੱਕੀ_meter();
		ਜੇ (setimes && !wrerr) {
			setimes = 0;
			ਜੇ (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		ਜੇ (note_err(ਨਿਰਾ) == 0)
			(ਖਾਲੀ) atomicio(vwrite, remout, "", 1);
	}
ਪੂਰਾ:
	ਲਈ (n = 0; n < npatterns; n++)
		ਮੁਕਤ(patterns[n]);
	ਮੁਕਤ(patterns);
	ਵਾਪਸ;
screwup:
	ਲਈ (n = 0; n < npatterns; n++)
		ਮੁਕਤ(patterns[n]);
	ਮੁਕਤ(patterns);
	ਲੜੀਵਾਰ_err("protocol error: %s", why);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਖਾਲੀ
throughlocal_sftp(ਬਣਤਰ sftp_conn *from, ਬਣਤਰ sftp_conn *ਮੰਜ਼ਿਲ,
    ਅੱਖਰ *src, ਅੱਖਰ *targ)
{
	ਅੱਖਰ *ਨਿਸ਼ਾਨਾ = ਨਿਰਾ, *filename = ਨਿਰਾ, *abs_dst = ਨਿਰਾ;
	ਅੱਖਰ *abs_src = ਨਿਰਾ, *tmp = ਨਿਰਾ;
	glob_t g;
	ਪੂਰਨ i, r, targetisdir, err = 0;

	ਜੇ ((filename = basename(src)) == ਨਿਰਾ)
		fatal("basename %s: %s", src, strerror(errno));

	ਜੇ ((abs_src = prepare_remote_ਰਸਤਾ(from, src)) == ਨਿਰਾ ||
	    (ਨਿਸ਼ਾਨਾ = prepare_remote_ਰਸਤਾ(ਮੰਜ਼ਿਲ, targ)) == ਨਿਰਾ)
		cleanup_exit(255);
	memset(&g, 0, ਆਕਾਰ(g));

	targetisdir = sftp_remote_is_dir(ਮੰਜ਼ਿਲ, ਨਿਸ਼ਾਨਾ);
	ਜੇ (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	debug3_f("copying remote %s to remote %s", abs_src, ਨਿਸ਼ਾਨਾ);
	ਜੇ ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ਨਿਰਾ, &g)) != 0) {
		ਜੇ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ਨਹੀਂਤਾਂ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Did we actually get any matches back from the glob? */
	ਜੇ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ਨਿਰਾ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ਜੇ (sftp_stat(from, g.gl_pathv[0], 1, ਨਿਰਾ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	ਲਈ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ਜੇ ((filename = basename(tmp)) == ਨਿਰਾ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		/* Special handling for source of '..' */
		ਜੇ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ਜੇ (targetisdir)
			abs_dst = sftp_ਰਸਤਾ_append(ਨਿਸ਼ਾਨਾ, filename);
		ਨਹੀਂਤਾਂ
			abs_dst = xstrdup(ਨਿਸ਼ਾਨਾ);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ਜੇ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ਜੇ (sftp_crossload_dir(from, ਮੰਜ਼ਿਲ, g.gl_pathv[i], abs_dst,
			    ਨਿਰਾ, pflag, SFTP_ਤਰੱਕੀ_ONLY, 1) == -1)
				err = -1;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (sftp_crossload(from, ਮੰਜ਼ਿਲ, g.gl_pathv[i], abs_dst,
			    ਨਿਰਾ, pflag) == -1)
				err = -1;
		}
		ਮੁਕਤ(abs_dst);
		abs_dst = ਨਿਰਾ;
		ਮੁਕਤ(tmp);
		tmp = ਨਿਰਾ;
	}

ਬਾਹਰਲਾ:
	ਮੁਕਤ(abs_src);
	ਮੁਕਤ(abs_dst);
	ਮੁਕਤ(ਨਿਸ਼ਾਨਾ);
	ਮੁਕਤ(tmp);
	globfree(&g);
	ਜੇ (err == -1)
		errs = 1;
}

ਪੂਰਨ
response(ਖਾਲੀ)
{
	ਅੱਖਰ ch, *cp, resp, rbuf[2048], visbuf[2048];

	ਜੇ (atomicio(ਪਠ, remin, &resp, ਆਕਾਰ(resp)) != ਆਕਾਰ(resp))
		lostconn(0);

	cp = rbuf;
	ਚੋਣ (resp) {
	ਹਾਲਤ 0:		/* ok */
		ਵਾਪਸ (0);
	ਮੂਲ:
		*cp++ = resp;
		/* FALLTHROUGH */
	ਹਾਲਤ 1:		/* error, followed by error msg */
	ਹਾਲਤ 2:		/* fatal error, "" */
		ਕਰੋ {
			ਜੇ (atomicio(ਪਠ, remin, &ch, ਆਕਾਰ(ch)) != ਆਕਾਰ(ch))
				lostconn(0);
			*cp++ = ch;
		} ਜਦੋਂ (cp < &rbuf[ਆਕਾਰ(rbuf) - 1] && ch != '\n');

		ਜੇ (!iamremote) {
			cp[-1] = '\0';
			(ਖਾਲੀ) snmprintf(visbuf, ਆਕਾਰ(visbuf),
			    ਨਿਰਾ, "%s\n", rbuf);
			(ਖਾਲੀ) atomicio(vwrite, STDERR_FILENO,
			    visbuf, ਲੜੀ_ਲੰਬਾਈ(visbuf));
		}
		++errs;
		ਜੇ (resp == 1)
			ਵਾਪਸ (-1);
		ਬਾਹਰ_ਨਿਕਲੋ(1);
	}
	/* NOTREACHED */
}

ਖਾਲੀ
usage(ਖਾਲੀ)
{
	(ਖਾਲੀ) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਖਾਲੀ
ਲੜੀਵਾਰ_err(ਅਚਲ ਅੱਖਰ *fmt,...)
{
	ਸਥਿਰ FILE *fp;
	va_list ap;

	++errs;
	ਜੇ (fp != ਨਿਰਾ || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(ਖਾਲੀ) fprintf(fp, "%c", 0x01);
		(ਖਾਲੀ) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(ਖਾਲੀ) vfprintf(fp, fmt, ap);
		va_end(ap);
		(ਖਾਲੀ) fprintf(fp, "\n");
		(ਖਾਲੀ) fflush(fp);
	}

	ਜੇ (!iamremote) {
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
ਪੂਰਨ
note_err(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	ਸਥਿਰ ਅੱਖਰ *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	ਜੇ (fmt == ਨਿਰਾ) {
		ਜੇ (emsg == ਨਿਰਾ)
			ਵਾਪਸ 0;
		ਲੜੀਵਾਰ_err("%s", emsg);
		ਮੁਕਤ(emsg);
		emsg = ਨਿਰਾ;
		ਵਾਪਸ -1;
	}

	errs++;
	/* Prefer first-noted error */
	ਜੇ (emsg != ਨਿਰਾ)
		ਵਾਪਸ -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, ਨਿਰਾ, fmt, ap);
	va_end(ap);
	ਵਾਪਸ -1;
}

ਖਾਲੀ
verifydir(ਅੱਖਰ *cp)
{
	ਬਣਤਰ stat stb;

	ਜੇ (!stat(cp, &stb)) {
		ਜੇ (S_ISDIR(stb.st_mode))
			ਵਾਪਸ;
		errno = ENOTDIR;
	}
	ਲੜੀਵਾਰ_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

ਪੂਰਨ
okname(ਅੱਖਰ *cp0)
{
	ਪੂਰਨ c;
	ਅੱਖਰ *cp;

	cp = cp0;
	ਕਰੋ {
		c = (ਪੂਰਨ)*cp;
		ਜੇ (c & 0200)
			ਜਾਓ bad;
		ਜੇ (!ਅੱਖਰ_ਹੈ(c) && !ਅੰਕ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)c)) {
			ਚੋਣ (c) {
			ਹਾਲਤ '\'':
			ਹਾਲਤ '"':
			ਹਾਲਤ '`':
			ਹਾਲਤ ' ':
			ਹਾਲਤ '#':
				ਜਾਓ bad;
			ਮੂਲ:
				ਰੋਕੋ;
			}
		}
	} ਜਦੋਂ (*++cp);
	ਵਾਪਸ (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	ਵਾਪਸ (0);
}

BUF *
allocbuf(BUF *bp, ਪੂਰਨ fd, ਪੂਰਨ blksize)
{
	ਮਾਪ_t ਮਾਪ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_STAT_ST_BLKSIZE
	ਬਣਤਰ stat stb;

	ਜੇ (fstat(fd, &stb) == -1) {
		ਲੜੀਵਾਰ_err("fstat: %s", strerror(errno));
		ਵਾਪਸ (ਨਿਰਾ);
	}
	ਮਾਪ = ROUNDUP(stb.st_blksize, blksize);
	ਜੇ (ਮਾਪ == 0)
		ਮਾਪ = blksize;
#ਨਹੀਂਤਾਂ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ਮਾਪ = blksize;
#ਜੇ_ਅੰਤ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ਜੇ (bp->cnt >= ਮਾਪ)
		ਵਾਪਸ (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, ਮਾਪ, 1);
	bp->cnt = ਮਾਪ;
	ਵਾਪਸ (bp);
}

ਖਾਲੀ
lostconn(ਪੂਰਨ signo)
{
	ਜੇ (!iamremote)
		(ਖਾਲੀ)ਲਿਖ(STDERR_FILENO, "lost connection\n", 16);
	ਜੇ (signo)
		_exit(1);
	ਨਹੀਂਤਾਂ
		ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ i)
{
	ਜੇ (remin > 0)
		close(remin);
	ਜੇ (remout > 0)
		close(remout);
	ਜੇ (remin2 > 0)
		close(remin2);
	ਜੇ (remout2 > 0)
		close(remout2);
	ਜੇ (do_cmd_pid > 0)
		(ਖਾਲੀ)waitpid(do_cmd_pid, ਨਿਰਾ, 0);
	ਜੇ (do_cmd_pid2 > 0)
		(ਖਾਲੀ)waitpid(do_cmd_pid2, ਨਿਰਾ, 0);
	ਬਾਹਰ_ਨਿਕਲੋ(i);
}
