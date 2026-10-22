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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/uio.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <dirent.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#ifdef HAVE_FNMATCH_H
#അന്തര്ഭാവ <fnmatch.h>
#endif
#അന്തര്ഭാവ <glob.h>
#അന്തര്ഭാവ <libgen.h>
#അന്തര്ഭാവ <locale.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <util.h>
#എങ്കിൽ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#അന്തര്ഭാവ <vis.h>
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "atomicio.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "progressmeter.h"
#അന്തര്ഭാവ "utf8.h"
#അന്തര്ഭാവ "sftp.h"

#അന്തര്ഭാവ "sftp-common.h"
#അന്തര്ഭാവ "sftp-client.h"

ബാഹ്യ അക്ഷരം *__progname;

#define COPY_BUFLEN	16384

പൂർണ്ണസംഖ്യ do_cmd(അക്ഷരം *, അക്ഷരം *, അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, അക്ഷരം *, പൂർണ്ണസംഖ്യ *, പൂർണ്ണസംഖ്യ *, pid_t *);
പൂർണ്ണസംഖ്യ do_cmd2(അക്ഷരം *, അക്ഷരം *, പൂർണ്ണസംഖ്യ, അക്ഷരം *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
ഘടന bwlimit bwlimit;

/* Name of current file being transferred. */
അക്ഷരം *curfile;

/* This is set to non-zero to enable verbose mode. */
പൂർണ്ണസംഖ്യ verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
പൂർണ്ണസംഖ്യ showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
പൂർണ്ണസംഖ്യ throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
പൂർണ്ണസംഖ്യ sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
അക്ഷരം *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
അസ്ഥിര sig_atomic_t interrupted = 0;

പൂർണ്ണസംഖ്യ sftp_glob(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ,
    പൂർണ്ണസംഖ്യ (*)(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ), glob_t *); /* proto for sftp-glob.c */

സ്ഥിതം ശൂന്യം
killchild(പൂർണ്ണസംഖ്യ signo)
{
	എങ്കിൽ (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(ശൂന്യം)waitpid(do_cmd_pid, ശൂന്യ, 0);
	}
	എങ്കിൽ (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(ശൂന്യം)waitpid(do_cmd_pid2, ശൂന്യ, 0);
	}

	എങ്കിൽ (signo)
		_exit(1);
	exit(1);
}

സ്ഥിതം ശൂന്യം
suspone(പൂർണ്ണസംഖ്യ pid, പൂർണ്ണസംഖ്യ signo)
{
	പൂർണ്ണസംഖ്യ status;

	എങ്കിൽ (pid > 1) {
		kill(pid, signo);
		ആകുമ്പോൾ (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

സ്ഥിതം ശൂന്യം
suspchild(പൂർണ്ണസംഖ്യ signo)
{
	പൂർണ്ണസംഖ്യ save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_local_cmd(arglist *a)
{
	അക്ഷരം *cp;
	പൂർണ്ണസംഖ്യ status;
	pid_t pid;

	എങ്കിൽ (a->അക്കം == 0)
		fatal("do_local_cmd: no arguments");

	എങ്കിൽ (verbose_mode) {
		cp = argv_assemble(a->അക്കം, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		സ്വതന്ത്രം(cp);
	}
	എങ്കിൽ ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	എങ്കിൽ (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1)
		എങ്കിൽ (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	എങ്കിൽ (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		തിരികെ (-1);

	തിരികെ (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

പൂർണ്ണസംഖ്യ
do_cmd(അക്ഷരം *program, അക്ഷരം *host, അക്ഷരം *remuser, പൂർണ്ണസംഖ്യ port, പൂർണ്ണസംഖ്യ subsystem,
    അക്ഷരം *cmd, പൂർണ്ണസംഖ്യ *fdin, പൂർണ്ണസംഖ്യ *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	പൂർണ്ണസംഖ്യ pin[2], pout[2];
#അല്ലെങ്കിൽ
	പൂർണ്ണസംഖ്യ sv[2];
#endif

	എങ്കിൽ (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	എങ്കിൽ (port == -1)
		port = sshport;

#ifdef USE_PIPES
	എങ്കിൽ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#അല്ലെങ്കിൽ
	/* Create a socket pair for communicating with ssh. */
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	തിരഞ്ഞെടുപ്പ് (*pid) {
	അവസ്ഥ -1:
		fatal("fork: %s", strerror(errno));
	അവസ്ഥ 0:
		/* Child. */
#ifdef USE_PIPES
		എങ്കിൽ (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#അല്ലെങ്കിൽ
		എങ്കിൽ (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		എങ്കിൽ (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		എങ്കിൽ (remuser != ശൂന്യ) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		എങ്കിൽ (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	സ്ഥിരസ്ഥിതി:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#അല്ലെങ്കിൽ
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		തിരികെ 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
പൂർണ്ണസംഖ്യ
do_cmd2(അക്ഷരം *host, അക്ഷരം *remuser, പൂർണ്ണസംഖ്യ port, അക്ഷരം *cmd,
    പൂർണ്ണസംഖ്യ fdin, പൂർണ്ണസംഖ്യ fdout)
{
	പൂർണ്ണസംഖ്യ status;
	pid_t pid;

	എങ്കിൽ (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	എങ്കിൽ (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	എങ്കിൽ (pid == 0) {
		എങ്കിൽ (dup2(fdin, 0) == -1)
			perror("dup2");
		എങ്കിൽ (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		എങ്കിൽ (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		എങ്കിൽ (remuser != ശൂന്യ) {
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
	} അല്ലെങ്കിൽ എങ്കിൽ (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1)
		എങ്കിൽ (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	തിരികെ 0;
}

തരനിർവചനം ഘടന {
	size_t cnt;
	അക്ഷരം *buf;
} BUF;

BUF *allocbuf(BUF *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
ശൂന്യം lostconn(പൂർണ്ണസംഖ്യ);
പൂർണ്ണസംഖ്യ okname(അക്ഷരം *);
ശൂന്യം run_err(സ്ഥിരം അക്ഷരം *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
പൂർണ്ണസംഖ്യ note_err(സ്ഥിരം അക്ഷരം *,...)
    __attribute__((__format__ (printf, 1, 2)));
ശൂന്യം verifydir(അക്ഷരം *);

ഘടന passwd *pwd;
uid_t userid;
പൂർണ്ണസംഖ്യ errs, remin, remout, remin2, remout2;
പൂർണ്ണസംഖ്യ Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
അക്ഷരം cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

എണ്ണൽ scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

പൂർണ്ണസംഖ്യ response(ശൂന്യം);
ശൂന്യം rsource(അക്ഷരം *, ഘടന stat *);
ശൂന്യം sink(പൂർണ്ണസംഖ്യ, അക്ഷരം *[], സ്ഥിരം അക്ഷരം *);
ശൂന്യം source(പൂർണ്ണസംഖ്യ, അക്ഷരം *[]);
ശൂന്യം tolocal(പൂർണ്ണസംഖ്യ, അക്ഷരം *[], എണ്ണൽ scp_mode_e, അക്ഷരം *sftp_direct);
ശൂന്യം toremote(പൂർണ്ണസംഖ്യ, അക്ഷരം *[], എണ്ണൽ scp_mode_e, അക്ഷരം *sftp_direct);
ശൂന്യം usage(ശൂന്യം);

ശൂന്യം source_sftp(പൂർണ്ണസംഖ്യ, അക്ഷരം *, അക്ഷരം *, ഘടന sftp_conn *);
ശൂന്യം sink_sftp(പൂർണ്ണസംഖ്യ, അക്ഷരം *, സ്ഥിരം അക്ഷരം *, ഘടന sftp_conn *);
ശൂന്യം throughlocal_sftp(ഘടന sftp_conn *, ഘടന sftp_conn *,
    അക്ഷരം *, അക്ഷരം *);

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ ch, fflag, tflag, status, r, n;
	അക്ഷരം **newargv, *argv0;
	സ്ഥിരം അക്ഷരം *errstr;
	ബാഹ്യ അക്ഷരം *optarg;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	എണ്ണൽ scp_mode_e mode = MODE_SFTP;
	അക്ഷരം *sftp_direct = ശൂന്യ;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), വലുപ്പം(*newargv));
	വേണ്ടി (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', വലുപ്പം(args));
	memset(&remote_remote_args, '\0', വലുപ്പം(remote_remote_args));
	args.list = remote_remote_args.list = ശൂന്യ;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	ആകുമ്പോൾ ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		/* User-visible flags. */
		അവസ്ഥ '1':
			fatal("SSH protocol v.1 is no longer supported");
			നിർത്തുക;
		അവസ്ഥ '2':
			/* Ignored */
			നിർത്തുക;
		അവസ്ഥ 'A':
		അവസ്ഥ '4':
		അവസ്ഥ '6':
		അവസ്ഥ 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			നിർത്തുക;
		അവസ്ഥ 'D':
			sftp_direct = optarg;
			നിർത്തുക;
		അവസ്ഥ '3':
			throughlocal = 1;
			നിർത്തുക;
		അവസ്ഥ 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			നിർത്തുക;
		അവസ്ഥ 'o':
		അവസ്ഥ 'c':
		അവസ്ഥ 'i':
		അവസ്ഥ 'F':
		അവസ്ഥ 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			നിർത്തുക;
		അവസ്ഥ 'O':
			mode = MODE_SCP;
			നിർത്തുക;
		അവസ്ഥ 's':
			/* Ignored */
			നിർത്തുക;
		അവസ്ഥ 'P':
			sshport = a2port(optarg);
			എങ്കിൽ (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			നിർത്തുക;
		അവസ്ഥ 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			നിർത്തുക;
		അവസ്ഥ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			എങ്കിൽ (errstr != ശൂന്യ)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			നിർത്തുക;
		അവസ്ഥ 'p':
			pflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'r':
			iamrecursive = 1;
			നിർത്തുക;
		അവസ്ഥ 'S':
			ssh_program = xstrdup(optarg);
			നിർത്തുക;
		അവസ്ഥ 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			എങ്കിൽ (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			അല്ലെങ്കിൽ എങ്കിൽ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			നിർത്തുക;
		അവസ്ഥ 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			നിർത്തുക;
		അവസ്ഥ 'X':
			/* Please keep in sync with sftp.c -X */
			എങ്കിൽ (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				എങ്കിൽ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				എങ്കിൽ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} അല്ലെങ്കിൽ എങ്കിൽ (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				എങ്കിൽ (errstr != ശൂന്യ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} അല്ലെങ്കിൽ {
				fatal("Invalid -X option");
			}
			നിർത്തുക;

		/* Server options. */
		അവസ്ഥ 'd':
			targetshouldbedirectory = 1;
			നിർത്തുക;
		അവസ്ഥ 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			നിർത്തുക;
		അവസ്ഥ 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_ദ്വിമാന);
#endif
			നിർത്തുക;
		അവസ്ഥ 'T':
			Tflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	എങ്കിൽ (iamremote)
		mode = MODE_SCP;

	എങ്കിൽ ((pwd = getpwuid(userid = getuid())) == ശൂന്യ)
		fatal("unknown user %u", (u_int) userid);

	എങ്കിൽ (!isatty(STDOUT_FILENO))
		showprogress = 0;

	എങ്കിൽ (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ശൂന്യ) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	എങ്കിൽ (fflag) {
		/* Follow "protocol", send data. */
		(ശൂന്യം) response();
		source(argc, argv);
		exit(errs != 0);
	}
	എങ്കിൽ (tflag) {
		/* Receive data. */
		sink(argc, argv, ശൂന്യ);
		exit(errs != 0);
	}
	എങ്കിൽ (argc < 2)
		usage();
	എങ്കിൽ (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(ശൂന്യം) snprintf(cmd, വലുപ്പം cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(ശൂന്യം) ssh_signal(SIGPIPE, lostconn);

	എങ്കിൽ (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	അല്ലെങ്കിൽ {
		എങ്കിൽ (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	എങ്കിൽ (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		എങ്കിൽ (remin != -1)
		    (ശൂന്യം) close(remin);
		എങ്കിൽ (remout != -1)
		    (ശൂന്യം) close(remout);
		എങ്കിൽ (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		അല്ലെങ്കിൽ {
			എങ്കിൽ (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
സ്ഥിതം പൂർണ്ണസംഖ്യ
scpio(ശൂന്യം *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	എങ്കിൽ (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_times(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ verb, സ്ഥിരം ഘടന stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	അക്ഷരം buf[(20 + 7 + 2) * 2 + 2];

	(ശൂന്യം)snprintf(buf, വലുപ്പം(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	എങ്കിൽ (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(ശൂന്യം) atomicio(vwrite, fd, buf, strlen(buf));
	തിരികെ (response());
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_scp_uri(സ്ഥിരം അക്ഷരം *uri, അക്ഷരം **userp, അക്ഷരം **hostp, പൂർണ്ണസംഖ്യ *portp,
    അക്ഷരം **pathp)
{
	പൂർണ്ണസംഖ്യ r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	എങ്കിൽ (r == 0 && *pathp == ശൂന്യ)
		*pathp = xstrdup(".");
	തിരികെ r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
സ്ഥിതം പൂർണ്ണസംഖ്യ
append(അക്ഷരം *cp, അക്ഷരം ***ap, size_t *np)
{
	അക്ഷരം **tmp;

	എങ്കിൽ ((tmp = reallocarray(*ap, *np + 1, വലുപ്പം(*tmp))) == ശൂന്യ)
		തിരികെ -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	തിരികെ 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
find_brace(സ്ഥിരം അക്ഷരം *pattern, പൂർണ്ണസംഖ്യ *startp, പൂർണ്ണസംഖ്യ *endp)
{
	പൂർണ്ണസംഖ്യ i;
	പൂർണ്ണസംഖ്യ in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	വേണ്ടി (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		തിരഞ്ഞെടുപ്പ് (pattern[i]) {
		അവസ്ഥ '\\':
			/* skip next character */
			എങ്കിൽ (pattern[i + 1] != '\0')
				i++;
			നിർത്തുക;
		അവസ്ഥ '[':
			in_bracket = 1;
			നിർത്തുക;
		അവസ്ഥ ']':
			in_bracket = 0;
			നിർത്തുക;
		അവസ്ഥ '{':
			എങ്കിൽ (in_bracket)
				നിർത്തുക;
			എങ്കിൽ (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				നിർത്തുക;
			}
			എങ്കിൽ (*startp == -1)
				*startp = i;
			brace_level++;
			നിർത്തുക;
		അവസ്ഥ '}':
			എങ്കിൽ (in_bracket)
				നിർത്തുക;
			എങ്കിൽ (*startp < 0) {
				/* Unbalanced brace */
				തിരികെ -1;
			}
			എങ്കിൽ (--brace_level <= 0)
				*endp = i;
			നിർത്തുക;
		}
	}
	/* unbalanced brackets/braces */
	എങ്കിൽ (*endp < 0 && (*startp >= 0 || in_bracket))
		തിരികെ -1;
	തിരികെ 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
emit_expansion(സ്ഥിരം അക്ഷരം *pattern, പൂർണ്ണസംഖ്യ brace_start, പൂർണ്ണസംഖ്യ brace_end,
    പൂർണ്ണസംഖ്യ sel_start, പൂർണ്ണസംഖ്യ sel_end, അക്ഷരം ***patternsp, size_t *npatternsp)
{
	അക്ഷരം *cp;
	size_t pattern_len;
	പൂർണ്ണസംഖ്യ o = 0, tail_len;

	എങ്കിൽ ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		തിരികെ -1;

	tail_len = strlen(pattern + brace_end + 1);
	എങ്കിൽ ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == ശൂന്യ)
		തിരികെ -1;

	/* Pattern before initial brace */
	എങ്കിൽ (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	എങ്കിൽ (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	എങ്കിൽ (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	എങ്കിൽ (append(cp, patternsp, npatternsp) != 0) {
		സ്വതന്ത്രം(cp);
		തിരികെ -1;
	}
	തിരികെ 0;
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
brace_expand_one(സ്ഥിരം അക്ഷരം *pattern, അക്ഷരം ***patternsp, size_t *npatternsp,
    പൂർണ്ണസംഖ്യ *expanded, പൂർണ്ണസംഖ്യ *invalid)
{
	പൂർണ്ണസംഖ്യ i;
	പൂർണ്ണസംഖ്യ in_bracket, brace_start, brace_end, brace_level;
	പൂർണ്ണസംഖ്യ sel_start, sel_end;

	*invalid = *expanded = 0;

	എങ്കിൽ (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		തിരികെ 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (brace_start == -1)
		തിരികെ 0;

	in_bracket = brace_level = 0;
	വേണ്ടി (i = sel_start = brace_start + 1; i < brace_end; i++) {
		തിരഞ്ഞെടുപ്പ് (pattern[i]) {
		അവസ്ഥ '{':
			എങ്കിൽ (in_bracket)
				നിർത്തുക;
			brace_level++;
			നിർത്തുക;
		അവസ്ഥ '}':
			എങ്കിൽ (in_bracket)
				നിർത്തുക;
			brace_level--;
			നിർത്തുക;
		അവസ്ഥ '[':
			in_bracket = 1;
			നിർത്തുക;
		അവസ്ഥ ']':
			in_bracket = 0;
			നിർത്തുക;
		അവസ്ഥ '\\':
			എങ്കിൽ (i < brace_end - 1)
				i++; /* skip */
			നിർത്തുക;
		}
		എങ്കിൽ (pattern[i] == ',' || i == brace_end - 1) {
			എങ്കിൽ (in_bracket || brace_level > 0)
				തുടരുക;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			എങ്കിൽ (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				തിരികെ -1;
			/* move on to the next selection */
			sel_start = i + 1;
			തുടരുക;
		}
	}
	എങ്കിൽ (in_bracket || brace_level > 0) {
		*invalid = 1;
		തിരികെ 0;
	}
	/* success */
	*expanded = 1;
	തിരികെ 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
സ്ഥിതം പൂർണ്ണസംഖ്യ
brace_expand(സ്ഥിരം അക്ഷരം *pattern, അക്ഷരം ***patternsp, size_t *npatternsp)
{
	അക്ഷരം *cp, *cp2, **active = ശൂന്യ, **done = ശൂന്യ;
	size_t i, nactive = 0, ndone = 0;
	പൂർണ്ണസംഖ്യ ret = -1, invalid = 0, expanded = 0;

	*patternsp = ശൂന്യ;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	എങ്കിൽ ((cp = strdup(pattern)) == ശൂന്യ)
		തിരികെ -1;
	എങ്കിൽ (append(cp, &active, &nactive) != 0) {
		സ്വതന്ത്രം(cp);
		തിരികെ -1;
	}
	ആകുമ്പോൾ (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		എങ്കിൽ (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			സ്വതന്ത്രം(cp);
			പോകുക fail;
		}
		എങ്കിൽ (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		എങ്കിൽ (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			സ്വതന്ത്രം(cp);
			തുടരുക;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		എങ്കിൽ ((cp2 = strrchr(cp, '/')) != ശൂന്യ)
			*cp2++ = '\0';
		അല്ലെങ്കിൽ
			cp2 = cp;
		എങ്കിൽ (append(xstrdup(cp2), &done, &ndone) != 0) {
			സ്വതന്ത്രം(cp);
			പോകുക fail;
		}
		സ്വതന്ത്രം(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = ശൂന്യ;
	ndone = 0;
	ret = 0;
 fail:
	വേണ്ടി (i = 0; i < nactive; i++)
		സ്വതന്ത്രം(active[i]);
	സ്വതന്ത്രം(active);
	വേണ്ടി (i = 0; i < ndone; i++)
		സ്വതന്ത്രം(done[i]);
	സ്വതന്ത്രം(done);
	തിരികെ ret;
}

സ്ഥിതം ഘടന sftp_conn *
do_sftp_connect(അക്ഷരം *host, അക്ഷരം *user, പൂർണ്ണസംഖ്യ port, അക്ഷരം *sftp_direct,
   പൂർണ്ണസംഖ്യ *reminp, പൂർണ്ണസംഖ്യ *remoutp, പൂർണ്ണസംഖ്യ *pidp)
{
	എങ്കിൽ (sftp_direct == ശൂന്യ) {
		എങ്കിൽ (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			തിരികെ ശൂന്യ;

	} അല്ലെങ്കിൽ {
		freeargs(&args);
		addargs(&args, "sftp-server");
		എങ്കിൽ (do_cmd(sftp_direct, host, ശൂന്യ, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			തിരികെ ശൂന്യ;
	}
	തിരികെ sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

ശൂന്യം
toremote(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv, എണ്ണൽ scp_mode_e mode, അക്ഷരം *sftp_direct)
{
	അക്ഷരം *suser = ശൂന്യ, *host = ശൂന്യ, *src = ശൂന്യ;
	അക്ഷരം *bp, *tuser, *thost, *targ;
	പൂർണ്ണസംഖ്യ sport = -1, tport = -1;
	ഘടന sftp_conn *conn = ശൂന്യ, *conn2 = ശൂന്യ;
	arglist alist;
	പൂർണ്ണസംഖ്യ i, r, status;
	ഘടന stat sb;
	u_int j;

	memset(&alist, '\0', വലുപ്പം(alist));
	alist.list = ശൂന്യ;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	എങ്കിൽ (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		പോകുക out;
	}
	എങ്കിൽ (r != 0) {
		എങ്കിൽ (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			പോകുക out;
		}
	}

	/* Parse source files */
	വേണ്ടി (i = 0; i < argc - 1; i++) {
		സ്വതന്ത്രം(suser);
		സ്വതന്ത്രം(host);
		സ്വതന്ത്രം(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		എങ്കിൽ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			തുടരുക;
		}
		എങ്കിൽ (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		എങ്കിൽ (suser != ശൂന്യ && !okname(suser)) {
			++errs;
			തുടരുക;
		}
		എങ്കിൽ (host && throughlocal) {	/* extended remote to remote */
			എങ്കിൽ (mode == MODE_SFTP) {
				എങ്കിൽ (remin == -1 || conn == ശൂന്യ) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					എങ്കിൽ (conn == ശൂന്യ) {
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
				എങ്കിൽ (conn2 == ശൂന്യ) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(ശൂന്യം) close(remin2);
				(ശൂന്യം) close(remout2);
				remin2 = remout2 = -1;
				എങ്കിൽ (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				അല്ലെങ്കിൽ എങ്കിൽ (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				തുടരുക;
			} അല്ലെങ്കിൽ {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				എങ്കിൽ (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				സ്വതന്ത്രം(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				എങ്കിൽ (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				സ്വതന്ത്രം(bp);
				(ശൂന്യം) close(remin);
				(ശൂന്യം) close(remout);
				remin = remout = -1;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			എങ്കിൽ (tuser != ശൂന്യ && !okname(tuser)) {
				++errs;
				തുടരുക;
			}
			എങ്കിൽ (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			വേണ്ടി (j = 0; j < remote_remote_args.അക്കം; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			എങ്കിൽ (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			എങ്കിൽ (suser) {
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
			എങ്കിൽ (do_local_cmd(&alist) != 0)
				errs = 1;
		} അല്ലെങ്കിൽ {	/* local to remote */
			എങ്കിൽ (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				എങ്കിൽ (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				എങ്കിൽ (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					എങ്കിൽ (conn == ശൂന്യ) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				തുടരുക;
			}
			/* SCP */
			എങ്കിൽ (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				എങ്കിൽ (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				എങ്കിൽ (response() < 0)
					exit(1);
				സ്വതന്ത്രം(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	സ്വതന്ത്രം(tuser);
	സ്വതന്ത്രം(thost);
	സ്വതന്ത്രം(targ);
	സ്വതന്ത്രം(suser);
	സ്വതന്ത്രം(host);
	സ്വതന്ത്രം(src);
	sftp_free(conn);
	sftp_free(conn2);
}

ശൂന്യം
tolocal(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv, എണ്ണൽ scp_mode_e mode, അക്ഷരം *sftp_direct)
{
	അക്ഷരം *bp, *host = ശൂന്യ, *src = ശൂന്യ, *suser = ശൂന്യ;
	arglist alist;
	ഘടന sftp_conn *conn = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i, r, sport = -1;

	memset(&alist, '\0', വലുപ്പം(alist));
	alist.list = ശൂന്യ;

	വേണ്ടി (i = 0; i < argc - 1; i++) {
		സ്വതന്ത്രം(suser);
		സ്വതന്ത്രം(host);
		സ്വതന്ത്രം(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		എങ്കിൽ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			തുടരുക;
		}
		എങ്കിൽ (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		എങ്കിൽ (suser != ശൂന്യ && !okname(suser)) {
			++errs;
			തുടരുക;
		}
		എങ്കിൽ (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			എങ്കിൽ (iamrecursive)
				addargs(&alist, "-r");
			എങ്കിൽ (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			എങ്കിൽ (do_local_cmd(&alist))
				++errs;
			തുടരുക;
		}
		/* Remote to local. */
		എങ്കിൽ (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			എങ്കിൽ (conn == ശൂന്യ) {
				error("sftp connection failed");
				++errs;
				തുടരുക;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(ശൂന്യം) close(remin);
			(ശൂന്യം) close(remout);
			remin = remout = -1;
			തുടരുക;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		എങ്കിൽ (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			സ്വതന്ത്രം(bp);
			++errs;
			തുടരുക;
		}
		സ്വതന്ത്രം(bp);
		sink(1, argv + argc - 1, src);
		(ശൂന്യം) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	സ്വതന്ത്രം(suser);
	സ്വതന്ത്രം(host);
	സ്വതന്ത്രം(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
സ്ഥിതം അക്ഷരം *
prepare_remote_path(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	എങ്കിൽ (*path == '\0' || strcmp(path, "~") == 0)
		തിരികെ xstrdup(".");
	എങ്കിൽ (*path != '~')
		തിരികെ xstrdup(path);
	എങ്കിൽ (strncmp(path, "~/", 2) == 0) {
		എങ്കിൽ ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			തിരികെ xstrdup(".");
		തിരികെ xstrdup(path + 2 + nslash);
	}
	എങ്കിൽ (sftp_can_expand_path(conn))
		തിരികെ sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	തിരികെ ശൂന്യ;
}

ശൂന്യം
source_sftp(പൂർണ്ണസംഖ്യ argc, അക്ഷരം *src, അക്ഷരം *targ, ഘടന sftp_conn *conn)
{
	അക്ഷരം *target = ശൂന്യ, *filename = ശൂന്യ, *abs_dst = ശൂന്യ;
	പൂർണ്ണസംഖ്യ src_is_dir, target_is_dir;
	Attrib a;
	ഘടന stat st;

	memset(&a, '\0', വലുപ്പം(a));
	എങ്കിൽ (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	എങ്കിൽ ((filename = basename(src)) == ശൂന്യ)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	എങ്കിൽ (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	എങ്കിൽ ((target = prepare_remote_path(conn, targ)) == ശൂന്യ)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	എങ്കിൽ (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		എങ്കിൽ (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	എങ്കിൽ (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	അല്ലെങ്കിൽ {
		abs_dst = target;
		target = ശൂന്യ;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	എങ്കിൽ (src_is_dir && iamrecursive) {
		എങ്കിൽ (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	സ്വതന്ത്രം(abs_dst);
	സ്വതന്ത്രം(target);
}

ശൂന്യം
source(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	ഘടന stat stb;
	സ്ഥിതം BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	പൂർണ്ണസംഖ്യ fd = -1, haderr, indx;
	അക്ഷരം *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	പൂർണ്ണസംഖ്യ len;

	വേണ്ടി (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		ആകുമ്പോൾ (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		എങ്കിൽ ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			പോകുക syserr;
		എങ്കിൽ (strchr(name, '\n') != ശൂന്യ) {
			strnvis(encname, name, വലുപ്പം(encname), VIS_NL);
			name = encname;
		}
		എങ്കിൽ (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			പോകുക next;
		}
		എങ്കിൽ (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			പോകുക next;
		}
		unset_nonblock(fd);
		തിരഞ്ഞെടുപ്പ് (stb.st_mode & S_IFMT) {
		അവസ്ഥ S_IFREG:
			നിർത്തുക;
		അവസ്ഥ S_IFDIR:
			എങ്കിൽ (iamrecursive) {
				rsource(name, &stb);
				പോകുക next;
			}
			/* FALLTHROUGH */
		സ്ഥിരസ്ഥിതി:
			run_err("%s: not a regular file", name);
			പോകുക next;
		}
		എങ്കിൽ ((last = strrchr(name, '/')) == ശൂന്യ)
			last = name;
		അല്ലെങ്കിൽ
			++last;
		curfile = last;
		എങ്കിൽ (pflag) {
			എങ്കിൽ (do_times(remout, verbose_mode, &stb) < 0)
				പോകുക next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, വലുപ്പം buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		എങ്കിൽ (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(ശൂന്യം) atomicio(vwrite, remout, buf, strlen(buf));
		എങ്കിൽ (response() < 0)
			പോകുക next;
		എങ്കിൽ ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == ശൂന്യ) {
next:			എങ്കിൽ (fd != -1) {
				(ശൂന്യം) close(fd);
				fd = -1;
			}
			തുടരുക;
		}
		എങ്കിൽ (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		വേണ്ടി (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			എങ്കിൽ (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			എങ്കിൽ (!haderr) {
				എങ്കിൽ ((nr = atomicio(പഠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			എങ്കിൽ (haderr) {
				(ശൂന്യം)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				തുടരുക;
			}
			എങ്കിൽ (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		എങ്കിൽ (fd != -1) {
			എങ്കിൽ (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		എങ്കിൽ (!haderr)
			(ശൂന്യം) atomicio(vwrite, remout, "", 1);
		അല്ലെങ്കിൽ
			run_err("%s: %s", name, strerror(haderr));
		(ശൂന്യം) response();
		എങ്കിൽ (showprogress)
			stop_progress_meter();
	}
}

ശൂന്യം
rsource(അക്ഷരം *name, ഘടന stat *statp)
{
	DIR *dirp;
	ഘടന dirent *dp;
	അക്ഷരം *last, *vect[1], path[PATH_MAX];

	എങ്കിൽ (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		തിരികെ;
	}
	last = strrchr(name, '/');
	എങ്കിൽ (last == ശൂന്യ)
		last = name;
	അല്ലെങ്കിൽ
		last++;
	എങ്കിൽ (pflag) {
		എങ്കിൽ (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			തിരികെ;
		}
	}
	(ശൂന്യം) snprintf(path, വലുപ്പം path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	എങ്കിൽ (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(ശൂന്യം) atomicio(vwrite, remout, path, strlen(path));
	എങ്കിൽ (response() < 0) {
		closedir(dirp);
		തിരികെ;
	}
	ആകുമ്പോൾ ((dp = readdir(dirp)) != ശൂന്യ) {
		എങ്കിൽ (dp->d_ino == 0)
			തുടരുക;
		എങ്കിൽ (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			തുടരുക;
		എങ്കിൽ (strlen(name) + 1 + strlen(dp->d_name) >= വലുപ്പം(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			തുടരുക;
		}
		(ശൂന്യം) snprintf(path, വലുപ്പം path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(ശൂന്യം) closedir(dirp);
	(ശൂന്യം) atomicio(vwrite, remout, "E\n", 2);
	(ശൂന്യം) response();
}

ശൂന്യം
sink_sftp(പൂർണ്ണസംഖ്യ argc, അക്ഷരം *dst, സ്ഥിരം അക്ഷരം *src, ഘടന sftp_conn *conn)
{
	അക്ഷരം *abs_src = ശൂന്യ;
	അക്ഷരം *abs_dst = ശൂന്യ;
	glob_t g;
	അക്ഷരം *filename, *tmp = ശൂന്യ;
	പൂർണ്ണസംഖ്യ i, r, err = 0, dst_is_dir;
	ഘടന stat st;

	memset(&g, 0, വലുപ്പം(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	എങ്കിൽ ((abs_src = prepare_remote_path(conn, src)) == ശൂന്യ) {
		err = -1;
		പോകുക out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	എങ്കിൽ ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ശൂന്യ, &g)) != 0) {
		എങ്കിൽ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		അല്ലെങ്കിൽ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		പോകുക out;
	}

	/* Did we actually get any matches back from the glob? */
	എങ്കിൽ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ശൂന്യ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		എങ്കിൽ (sftp_stat(conn, g.gl_pathv[0], 1, ശൂന്യ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			പോകുക out;
		}
	}

	എങ്കിൽ ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	എങ്കിൽ (g.gl_matchc > 1 && !dst_is_dir) {
		എങ്കിൽ (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			പോകുക out;
		}
		debug2_f("creating destination \"%s\"", dst);
		എങ്കിൽ (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			പോകുക out;
		}
		dst_is_dir = 1;
	}

	വേണ്ടി (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		എങ്കിൽ ((filename = basename(tmp)) == ശൂന്യ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			പോകുക out;
		}

		/* Special handling for destination of '..' */
		എങ്കിൽ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		എങ്കിൽ (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		അല്ലെങ്കിൽ
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		എങ്കിൽ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			എങ്കിൽ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ശൂന്യ, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (sftp_download(conn, g.gl_pathv[i], abs_dst, ശൂന്യ,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		സ്വതന്ത്രം(abs_dst);
		abs_dst = ശൂന്യ;
		സ്വതന്ത്രം(tmp);
		tmp = ശൂന്യ;
	}

out:
	സ്വതന്ത്രം(abs_src);
	സ്വതന്ത്രം(tmp);
	globfree(&g);
	എങ്കിൽ (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((വലുപ്പം(type) == 4 && (val) > INT32_MAX) || \
	 (വലുപ്പം(type) == 8 && (val) > INT64_MAX) || \
	 (വലുപ്പം(type) != 4 && വലുപ്പം(type) != 8))

ശൂന്യം
sink(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv, സ്ഥിരം അക്ഷരം *src)
{
	സ്ഥിതം BUF buffer;
	ഘടന stat stb;
	BUF *bp;
	off_t i;
	size_t j, എണ്ണം;
	പൂർണ്ണസംഖ്യ amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	പൂർണ്ണസംഖ്യ setimes, targisdir, wrerr;
	അക്ഷരം ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	അക്ഷരം **patterns = ശൂന്യ;
	size_t n, npatterns = 0;
	ഘടന timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; പോകുക screwup; }

	എങ്കിൽ (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	എങ്കിൽ (!pflag) {
		(ശൂന്യം) umask(mask);
		mask |= 07000;
	}
	എങ്കിൽ (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	എങ്കിൽ (targetshouldbedirectory)
		verifydir(targ);

	(ശൂന്യം) atomicio(vwrite, remout, "", 1);
	എങ്കിൽ (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	എങ്കിൽ (src != ശൂന്യ && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		എങ്കിൽ (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	വേണ്ടി (first = 1;; first = 0) {
		cp = buf;
		എങ്കിൽ (atomicio(പഠ, remin, cp, 1) != 1)
			പോകുക done;
		എങ്കിൽ (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		ചെയ്യുക {
			എങ്കിൽ (atomicio(പഠ, remin, &ch, വലുപ്പം(ch)) != വലുപ്പം(ch))
				SCREWUP("lost connection");
			എങ്കിൽ (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} ആകുമ്പോൾ (cp < &buf[വലുപ്പം(buf) - 1] && ch != '\n');
		*cp = 0;
		എങ്കിൽ (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		എങ്കിൽ (buf[0] == '\01' || buf[0] == '\02') {
			എങ്കിൽ (iamremote == 0) {
				(ശൂന്യം) snmprintf(visbuf, വലുപ്പം(visbuf),
				    ശൂന്യ, "%s", buf + 1);
				(ശൂന്യം) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			എങ്കിൽ (buf[0] == '\02')
				exit(1);
			++errs;
			തുടരുക;
		}
		എങ്കിൽ (buf[0] == 'E') {
			(ശൂന്യം) atomicio(vwrite, remout, "", 1);
			പോകുക done;
		}
		എങ്കിൽ (ch == '\n')
			*--cp = 0;

		cp = buf;
		എങ്കിൽ (*cp == 'T') {
			setimes++;
			cp++;
			എങ്കിൽ (!isdigit((unsigned അക്ഷരം)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			എങ്കിൽ (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			എങ്കിൽ (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			എങ്കിൽ (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			എങ്കിൽ (!isdigit((unsigned അക്ഷരം)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			എങ്കിൽ (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			എങ്കിൽ (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			എങ്കിൽ (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(ശൂന്യം) atomicio(vwrite, remout, "", 1);
			തുടരുക;
		}
		എങ്കിൽ (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			എങ്കിൽ (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		വേണ്ടി (++cp; cp < buf + 5; cp++) {
			എങ്കിൽ (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		എങ്കിൽ (!pflag)
			mode &= ~mask;
		എങ്കിൽ (*cp++ != ' ')
			SCREWUP("mode not delimited");

		എങ്കിൽ (!isdigit((unsigned അക്ഷരം)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		എങ്കിൽ (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		എങ്കിൽ (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		എങ്കിൽ (*cp == '\0' || strchr(cp, '/') != ശൂന്യ ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		എങ്കിൽ (npatterns > 0) {
			വേണ്ടി (n = 0; n < npatterns; n++) {
				എങ്കിൽ (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					നിർത്തുക;
			}
			എങ്കിൽ (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				വേണ്ടി (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		എങ്കിൽ (targisdir) {
			സ്ഥിതം അക്ഷരം *namebuf;
			സ്ഥിതം size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			എങ്കിൽ (need > cursize) {
				സ്വതന്ത്രം(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(ശൂന്യം) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} അല്ലെങ്കിൽ
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		എങ്കിൽ (buf[0] == 'D') {
			പൂർണ്ണസംഖ്യ mod_flag = pflag;
			എങ്കിൽ (!iamrecursive)
				SCREWUP("received directory without -r");
			എങ്കിൽ (exists) {
				എങ്കിൽ (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					പോകുക bad;
				}
				എങ്കിൽ (pflag)
					(ശൂന്യം) chmod(np, mode);
			} അല്ലെങ്കിൽ {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				എങ്കിൽ (mkdir(np, mode | S_IRWXU) == -1)
					പോകുക bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			എങ്കിൽ (setimes) {
				setimes = 0;
				(ശൂന്യം) utimes(vect[0], tv);
			}
			എങ്കിൽ (mod_flag)
				(ശൂന്യം) chmod(vect[0], mode);
			സ്വതന്ത്രം(vect[0]);
			തുടരുക;
		}
		omode = mode;
		mode |= S_IWUSR;
		എങ്കിൽ ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			തുടരുക;
		}
		(ശൂന്യം) atomicio(vwrite, remout, "", 1);
		എങ്കിൽ ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == ശൂന്യ) {
			(ശൂന്യം) close(ofd);
			തുടരുക;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		എങ്കിൽ (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		വേണ്ടി (എണ്ണം = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			എങ്കിൽ (i + amt > size)
				amt = size - i;
			എണ്ണം += amt;
			ചെയ്യുക {
				j = atomicio6(പഠ, remin, cp, amt,
				    scpio, &statbytes);
				എങ്കിൽ (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} ആകുമ്പോൾ (amt > 0);

			എങ്കിൽ (എണ്ണം == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				എങ്കിൽ (!wrerr) {
					എങ്കിൽ (atomicio(vwrite, ofd, bp->buf,
					    എണ്ണം) != എണ്ണം) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				എണ്ണം = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		എങ്കിൽ (എണ്ണം != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, എണ്ണം) != എണ്ണം) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		എങ്കിൽ (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		എങ്കിൽ (pflag) {
			എങ്കിൽ (exists || omode != mode)
#ifdef HAVE_FCHMOD
				എങ്കിൽ (fchmod(ofd, omode)) {
#അല്ലെങ്കിൽ /* HAVE_FCHMOD */
				എങ്കിൽ (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				എങ്കിൽ (fchmod(ofd, omode & ~mask)) {
#അല്ലെങ്കിൽ /* HAVE_FCHMOD */
				എങ്കിൽ (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		എങ്കിൽ (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(ശൂന്യം) response();
		എങ്കിൽ (showprogress)
			stop_progress_meter();
		എങ്കിൽ (setimes && !wrerr) {
			setimes = 0;
			എങ്കിൽ (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		എങ്കിൽ (note_err(ശൂന്യ) == 0)
			(ശൂന്യം) atomicio(vwrite, remout, "", 1);
	}
done:
	വേണ്ടി (n = 0; n < npatterns; n++)
		സ്വതന്ത്രം(patterns[n]);
	സ്വതന്ത്രം(patterns);
	തിരികെ;
screwup:
	വേണ്ടി (n = 0; n < npatterns; n++)
		സ്വതന്ത്രം(patterns[n]);
	സ്വതന്ത്രം(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

ശൂന്യം
throughlocal_sftp(ഘടന sftp_conn *from, ഘടന sftp_conn *to,
    അക്ഷരം *src, അക്ഷരം *targ)
{
	അക്ഷരം *target = ശൂന്യ, *filename = ശൂന്യ, *abs_dst = ശൂന്യ;
	അക്ഷരം *abs_src = ശൂന്യ, *tmp = ശൂന്യ;
	glob_t g;
	പൂർണ്ണസംഖ്യ i, r, targetisdir, err = 0;

	എങ്കിൽ ((filename = basename(src)) == ശൂന്യ)
		fatal("basename %s: %s", src, strerror(errno));

	എങ്കിൽ ((abs_src = prepare_remote_path(from, src)) == ശൂന്യ ||
	    (target = prepare_remote_path(to, targ)) == ശൂന്യ)
		cleanup_exit(255);
	memset(&g, 0, വലുപ്പം(g));

	targetisdir = sftp_remote_is_dir(to, target);
	എങ്കിൽ (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		പോകുക out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	എങ്കിൽ ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ശൂന്യ, &g)) != 0) {
		എങ്കിൽ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		അല്ലെങ്കിൽ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		പോകുക out;
	}

	/* Did we actually get any matches back from the glob? */
	എങ്കിൽ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ശൂന്യ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		എങ്കിൽ (sftp_stat(from, g.gl_pathv[0], 1, ശൂന്യ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			പോകുക out;
		}
	}

	വേണ്ടി (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		എങ്കിൽ ((filename = basename(tmp)) == ശൂന്യ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			പോകുക out;
		}

		/* Special handling for source of '..' */
		എങ്കിൽ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		എങ്കിൽ (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		അല്ലെങ്കിൽ
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		എങ്കിൽ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			എങ്കിൽ (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    ശൂന്യ, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    ശൂന്യ, pflag) == -1)
				err = -1;
		}
		സ്വതന്ത്രം(abs_dst);
		abs_dst = ശൂന്യ;
		സ്വതന്ത്രം(tmp);
		tmp = ശൂന്യ;
	}

out:
	സ്വതന്ത്രം(abs_src);
	സ്വതന്ത്രം(abs_dst);
	സ്വതന്ത്രം(target);
	സ്വതന്ത്രം(tmp);
	globfree(&g);
	എങ്കിൽ (err == -1)
		errs = 1;
}

പൂർണ്ണസംഖ്യ
response(ശൂന്യം)
{
	അക്ഷരം ch, *cp, resp, rbuf[2048], visbuf[2048];

	എങ്കിൽ (atomicio(പഠ, remin, &resp, വലുപ്പം(resp)) != വലുപ്പം(resp))
		lostconn(0);

	cp = rbuf;
	തിരഞ്ഞെടുപ്പ് (resp) {
	അവസ്ഥ 0:		/* ok */
		തിരികെ (0);
	സ്ഥിരസ്ഥിതി:
		*cp++ = resp;
		/* FALLTHROUGH */
	അവസ്ഥ 1:		/* error, followed by error msg */
	അവസ്ഥ 2:		/* fatal error, "" */
		ചെയ്യുക {
			എങ്കിൽ (atomicio(പഠ, remin, &ch, വലുപ്പം(ch)) != വലുപ്പം(ch))
				lostconn(0);
			*cp++ = ch;
		} ആകുമ്പോൾ (cp < &rbuf[വലുപ്പം(rbuf) - 1] && ch != '\n');

		എങ്കിൽ (!iamremote) {
			cp[-1] = '\0';
			(ശൂന്യം) snmprintf(visbuf, വലുപ്പം(visbuf),
			    ശൂന്യ, "%s\n", rbuf);
			(ശൂന്യം) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		എങ്കിൽ (resp == 1)
			തിരികെ (-1);
		exit(1);
	}
	/* NOTREACHED */
}

ശൂന്യം
usage(ശൂന്യം)
{
	(ശൂന്യം) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

ശൂന്യം
run_err(സ്ഥിരം അക്ഷരം *fmt,...)
{
	സ്ഥിതം FILE *fp;
	va_list ap;

	++errs;
	എങ്കിൽ (fp != ശൂന്യ || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(ശൂന്യം) fprintf(fp, "%c", 0x01);
		(ശൂന്യം) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(ശൂന്യം) vfprintf(fp, fmt, ap);
		va_end(ap);
		(ശൂന്യം) fprintf(fp, "\n");
		(ശൂന്യം) fflush(fp);
	}

	എങ്കിൽ (!iamremote) {
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
പൂർണ്ണസംഖ്യ
note_err(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	സ്ഥിതം അക്ഷരം *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	എങ്കിൽ (fmt == ശൂന്യ) {
		എങ്കിൽ (emsg == ശൂന്യ)
			തിരികെ 0;
		run_err("%s", emsg);
		സ്വതന്ത്രം(emsg);
		emsg = ശൂന്യ;
		തിരികെ -1;
	}

	errs++;
	/* Prefer first-noted error */
	എങ്കിൽ (emsg != ശൂന്യ)
		തിരികെ -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, ശൂന്യ, fmt, ap);
	va_end(ap);
	തിരികെ -1;
}

ശൂന്യം
verifydir(അക്ഷരം *cp)
{
	ഘടന stat stb;

	എങ്കിൽ (!stat(cp, &stb)) {
		എങ്കിൽ (S_ISDIR(stb.st_mode))
			തിരികെ;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

പൂർണ്ണസംഖ്യ
okname(അക്ഷരം *cp0)
{
	പൂർണ്ണസംഖ്യ c;
	അക്ഷരം *cp;

	cp = cp0;
	ചെയ്യുക {
		c = (പൂർണ്ണസംഖ്യ)*cp;
		എങ്കിൽ (c & 0200)
			പോകുക bad;
		എങ്കിൽ (!isalpha(c) && !isdigit((unsigned അക്ഷരം)c)) {
			തിരഞ്ഞെടുപ്പ് (c) {
			അവസ്ഥ '\'':
			അവസ്ഥ '"':
			അവസ്ഥ '`':
			അവസ്ഥ ' ':
			അവസ്ഥ '#':
				പോകുക bad;
			സ്ഥിരസ്ഥിതി:
				നിർത്തുക;
			}
		}
	} ആകുമ്പോൾ (*++cp);
	തിരികെ (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	തിരികെ (0);
}

BUF *
allocbuf(BUF *bp, പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	ഘടന stat stb;

	എങ്കിൽ (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		തിരികെ (ശൂന്യ);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	എങ്കിൽ (size == 0)
		size = blksize;
#അല്ലെങ്കിൽ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	എങ്കിൽ (bp->cnt >= size)
		തിരികെ (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	തിരികെ (bp);
}

ശൂന്യം
lostconn(പൂർണ്ണസംഖ്യ signo)
{
	എങ്കിൽ (!iamremote)
		(ശൂന്യം)ലിഖ(STDERR_FILENO, "lost connection\n", 16);
	എങ്കിൽ (signo)
		_exit(1);
	അല്ലെങ്കിൽ
		exit(1);
}

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ i)
{
	എങ്കിൽ (remin > 0)
		close(remin);
	എങ്കിൽ (remout > 0)
		close(remout);
	എങ്കിൽ (remin2 > 0)
		close(remin2);
	എങ്കിൽ (remout2 > 0)
		close(remout2);
	എങ്കിൽ (do_cmd_pid > 0)
		(ശൂന്യം)waitpid(do_cmd_pid, ശൂന്യ, 0);
	എങ്കിൽ (do_cmd_pid2 > 0)
		(ശൂന്യം)waitpid(do_cmd_pid2, ശൂന്യ, 0);
	exit(i);
}
