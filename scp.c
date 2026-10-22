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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/time.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/uio.h>

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <dirent.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#ifdef HAVE_FNMATCH_H
#অন্তর্ভাব <fnmatch.h>
#endif
#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <libgen.h>
#অন্তর্ভাব <locale.h>
#অন্তর্ভাব <poll.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <util.h>
#যদি defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#অন্তর্ভাব <vis.h>
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "atomicio.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "progressmeter.h"
#অন্তর্ভাব "utf8.h"
#অন্তর্ভাব "sftp.h"

#অন্তর্ভাব "sftp-common.h"
#অন্তর্ভাব "sftp-client.h"

বাহ্য বর্ণ *__progname;

#define COPY_BUFLEN	16384

পূর্ণাঙ্ক do_cmd(বর্ণ *, বর্ণ *, বর্ণ *, পূর্ণাঙ্ক, পূর্ণাঙ্ক, বর্ণ *, পূর্ণাঙ্ক *, পূর্ণাঙ্ক *, pid_t *);
পূর্ণাঙ্ক do_cmd2(বর্ণ *, বর্ণ *, পূর্ণাঙ্ক, বর্ণ *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
সংরচনা bwlimit bwlimit;

/* Name of current file being transferred. */
বর্ণ *curfile;

/* This is set to non-zero to enable verbose mode. */
পূর্ণাঙ্ক verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
পূর্ণাঙ্ক showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
পূর্ণাঙ্ক throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
পূর্ণাঙ্ক sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
বর্ণ *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
চঞ্চল sig_atomic_t interrupted = 0;

পূর্ণাঙ্ক sftp_glob(সংরচনা sftp_conn *, ধ্রুব বর্ণ *, পূর্ণাঙ্ক,
    পূর্ণাঙ্ক (*)(ধ্রুব বর্ণ *, পূর্ণাঙ্ক), glob_t *); /* proto for sftp-glob.c */

স্থির শূন্য
killchild(পূর্ণাঙ্ক signo)
{
	যদি (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(শূন্য)waitpid(do_cmd_pid, রিক্ত, 0);
	}
	যদি (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(শূন্য)waitpid(do_cmd_pid2, রিক্ত, 0);
	}

	যদি (signo)
		_exit(1);
	exit(1);
}

স্থির শূন্য
suspone(পূর্ণাঙ্ক pid, পূর্ণাঙ্ক signo)
{
	পূর্ণাঙ্ক status;

	যদি (pid > 1) {
		kill(pid, signo);
		যাবত্ (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

স্থির শূন্য
suspchild(পূর্ণাঙ্ক signo)
{
	পূর্ণাঙ্ক save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

স্থির পূর্ণাঙ্ক
do_local_cmd(arglist *a)
{
	বর্ণ *cp;
	পূর্ণাঙ্ক status;
	pid_t pid;

	যদি (a->অঙ্ক == 0)
		fatal("do_local_cmd: no arguments");

	যদি (verbose_mode) {
		cp = argv_assemble(a->অঙ্ক, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		মুক্ত(cp);
	}
	যদি ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	যদি (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	যাবত্ (waitpid(pid, &status, 0) == -1)
		যদি (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	যদি (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		প্রত্যাগম (-1);

	প্রত্যাগম (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

পূর্ণাঙ্ক
do_cmd(বর্ণ *program, বর্ণ *host, বর্ণ *remuser, পূর্ণাঙ্ক port, পূর্ণাঙ্ক subsystem,
    বর্ণ *cmd, পূর্ণাঙ্ক *fdin, পূর্ণাঙ্ক *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	পূর্ণাঙ্ক pin[2], pout[2];
#অন্যথা
	পূর্ণাঙ্ক sv[2];
#endif

	যদি (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	যদি (port == -1)
		port = sshport;

#ifdef USE_PIPES
	যদি (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#অন্যথা
	/* Create a socket pair for communicating with ssh. */
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	বিকল্প (*pid) {
	পক্ষ -1:
		fatal("fork: %s", strerror(errno));
	পক্ষ 0:
		/* Child. */
#ifdef USE_PIPES
		যদি (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#অন্যথা
		যদি (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		যদি (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		যদি (remuser != রিক্ত) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		যদি (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	স্বভাব:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#অন্যথা
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		প্রত্যাগম 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
পূর্ণাঙ্ক
do_cmd2(বর্ণ *host, বর্ণ *remuser, পূর্ণাঙ্ক port, বর্ণ *cmd,
    পূর্ণাঙ্ক fdin, পূর্ণাঙ্ক fdout)
{
	পূর্ণাঙ্ক status;
	pid_t pid;

	যদি (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	যদি (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	যদি (pid == 0) {
		যদি (dup2(fdin, 0) == -1)
			perror("dup2");
		যদি (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		যদি (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		যদি (remuser != রিক্ত) {
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
	} অন্যথা যদি (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	যাবত্ (waitpid(pid, &status, 0) == -1)
		যদি (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	প্রত্যাগম 0;
}

প্রকারনির্দেশ সংরচনা {
	size_t cnt;
	বর্ণ *buf;
} BUF;

BUF *allocbuf(BUF *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
শূন্য lostconn(পূর্ণাঙ্ক);
পূর্ণাঙ্ক okname(বর্ণ *);
শূন্য run_err(ধ্রুব বর্ণ *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
পূর্ণাঙ্ক note_err(ধ্রুব বর্ণ *,...)
    __attribute__((__format__ (printf, 1, 2)));
শূন্য verifydir(বর্ণ *);

সংরচনা passwd *pwd;
uid_t userid;
পূর্ণাঙ্ক errs, remin, remout, remin2, remout2;
পূর্ণাঙ্ক Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
বর্ণ cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

গণনা scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

পূর্ণাঙ্ক response(শূন্য);
শূন্য rsource(বর্ণ *, সংরচনা stat *);
শূন্য sink(পূর্ণাঙ্ক, বর্ণ *[], ধ্রুব বর্ণ *);
শূন্য source(পূর্ণাঙ্ক, বর্ণ *[]);
শূন্য tolocal(পূর্ণাঙ্ক, বর্ণ *[], গণনা scp_mode_e, বর্ণ *sftp_direct);
শূন্য toremote(পূর্ণাঙ্ক, বর্ণ *[], গণনা scp_mode_e, বর্ণ *sftp_direct);
শূন্য usage(শূন্য);

শূন্য source_sftp(পূর্ণাঙ্ক, বর্ণ *, বর্ণ *, সংরচনা sftp_conn *);
শূন্য sink_sftp(পূর্ণাঙ্ক, বর্ণ *, ধ্রুব বর্ণ *, সংরচনা sftp_conn *);
শূন্য throughlocal_sftp(সংরচনা sftp_conn *, সংরচনা sftp_conn *,
    বর্ণ *, বর্ণ *);

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	পূর্ণাঙ্ক ch, fflag, tflag, status, r, n;
	বর্ণ **newargv, *argv0;
	ধ্রুব বর্ণ *errstr;
	বাহ্য বর্ণ *optarg;
	বাহ্য পূর্ণাঙ্ক optind;
	গণনা scp_mode_e mode = MODE_SFTP;
	বর্ণ *sftp_direct = রিক্ত;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), পরিমাণ(*newargv));
	প্রতি (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', পরিমাণ(args));
	memset(&remote_remote_args, '\0', পরিমাণ(remote_remote_args));
	args.list = remote_remote_args.list = রিক্ত;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	যাবত্ ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		বিকল্প (ch) {
		/* User-visible flags. */
		পক্ষ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ভঙ্গ;
		পক্ষ '2':
			/* Ignored */
			ভঙ্গ;
		পক্ষ 'A':
		পক্ষ '4':
		পক্ষ '6':
		পক্ষ 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			ভঙ্গ;
		পক্ষ 'D':
			sftp_direct = optarg;
			ভঙ্গ;
		পক্ষ '3':
			throughlocal = 1;
			ভঙ্গ;
		পক্ষ 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			ভঙ্গ;
		পক্ষ 'o':
		পক্ষ 'c':
		পক্ষ 'i':
		পক্ষ 'F':
		পক্ষ 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			ভঙ্গ;
		পক্ষ 'O':
			mode = MODE_SCP;
			ভঙ্গ;
		পক্ষ 's':
			/* Ignored */
			ভঙ্গ;
		পক্ষ 'P':
			sshport = a2port(optarg);
			যদি (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			ভঙ্গ;
		পক্ষ 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			ভঙ্গ;
		পক্ষ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			যদি (errstr != রিক্ত)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			ভঙ্গ;
		পক্ষ 'p':
			pflag = 1;
			ভঙ্গ;
		পক্ষ 'r':
			iamrecursive = 1;
			ভঙ্গ;
		পক্ষ 'S':
			ssh_program = xstrdup(optarg);
			ভঙ্গ;
		পক্ষ 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			যদি (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			ভঙ্গ;
		পক্ষ 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			ভঙ্গ;
		পক্ষ 'X':
			/* Please keep in sync with sftp.c -X */
			যদি (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				যদি (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				যদি (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} অন্যথা যদি (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				যদি (errstr != রিক্ত) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} অন্যথা {
				fatal("Invalid -X option");
			}
			ভঙ্গ;

		/* Server options. */
		পক্ষ 'd':
			targetshouldbedirectory = 1;
			ভঙ্গ;
		পক্ষ 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			ভঙ্গ;
		পক্ষ 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_দ্বিমিক);
#endif
			ভঙ্গ;
		পক্ষ 'T':
			Tflag = 1;
			ভঙ্গ;
		স্বভাব:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	যদি (iamremote)
		mode = MODE_SCP;

	যদি ((pwd = getpwuid(userid = getuid())) == রিক্ত)
		fatal("unknown user %u", (u_int) userid);

	যদি (!isatty(STDOUT_FILENO))
		showprogress = 0;

	যদি (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} অন্যথা {
		যদি (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    রিক্ত) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	যদি (fflag) {
		/* Follow "protocol", send data. */
		(শূন্য) response();
		source(argc, argv);
		exit(errs != 0);
	}
	যদি (tflag) {
		/* Receive data. */
		sink(argc, argv, রিক্ত);
		exit(errs != 0);
	}
	যদি (argc < 2)
		usage();
	যদি (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(শূন্য) snprintf(cmd, পরিমাণ cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(শূন্য) ssh_signal(SIGPIPE, lostconn);

	যদি (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	অন্যথা {
		যদি (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	যদি (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		যদি (remin != -1)
		    (শূন্য) close(remin);
		যদি (remout != -1)
		    (শূন্য) close(remout);
		যদি (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		অন্যথা {
			যদি (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
স্থির পূর্ণাঙ্ক
scpio(শূন্য *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	যদি (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
do_times(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক verb, ধ্রুব সংরচনা stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	বর্ণ buf[(20 + 7 + 2) * 2 + 2];

	(শূন্য)snprintf(buf, পরিমাণ(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	যদি (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(শূন্য) atomicio(vwrite, fd, buf, strlen(buf));
	প্রত্যাগম (response());
}

স্থির পূর্ণাঙ্ক
parse_scp_uri(ধ্রুব বর্ণ *uri, বর্ণ **userp, বর্ণ **hostp, পূর্ণাঙ্ক *portp,
    বর্ণ **pathp)
{
	পূর্ণাঙ্ক r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	যদি (r == 0 && *pathp == রিক্ত)
		*pathp = xstrdup(".");
	প্রত্যাগম r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
স্থির পূর্ণাঙ্ক
append(বর্ণ *cp, বর্ণ ***ap, size_t *np)
{
	বর্ণ **tmp;

	যদি ((tmp = reallocarray(*ap, *np + 1, পরিমাণ(*tmp))) == রিক্ত)
		প্রত্যাগম -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	প্রত্যাগম 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
স্থির পূর্ণাঙ্ক
find_brace(ধ্রুব বর্ণ *pattern, পূর্ণাঙ্ক *startp, পূর্ণাঙ্ক *endp)
{
	পূর্ণাঙ্ক i;
	পূর্ণাঙ্ক in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	প্রতি (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		বিকল্প (pattern[i]) {
		পক্ষ '\\':
			/* skip next character */
			যদি (pattern[i + 1] != '\0')
				i++;
			ভঙ্গ;
		পক্ষ '[':
			in_bracket = 1;
			ভঙ্গ;
		পক্ষ ']':
			in_bracket = 0;
			ভঙ্গ;
		পক্ষ '{':
			যদি (in_bracket)
				ভঙ্গ;
			যদি (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				ভঙ্গ;
			}
			যদি (*startp == -1)
				*startp = i;
			brace_level++;
			ভঙ্গ;
		পক্ষ '}':
			যদি (in_bracket)
				ভঙ্গ;
			যদি (*startp < 0) {
				/* Unbalanced brace */
				প্রত্যাগম -1;
			}
			যদি (--brace_level <= 0)
				*endp = i;
			ভঙ্গ;
		}
	}
	/* unbalanced brackets/braces */
	যদি (*endp < 0 && (*startp >= 0 || in_bracket))
		প্রত্যাগম -1;
	প্রত্যাগম 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
স্থির পূর্ণাঙ্ক
emit_expansion(ধ্রুব বর্ণ *pattern, পূর্ণাঙ্ক brace_start, পূর্ণাঙ্ক brace_end,
    পূর্ণাঙ্ক sel_start, পূর্ণাঙ্ক sel_end, বর্ণ ***patternsp, size_t *npatternsp)
{
	বর্ণ *cp;
	size_t pattern_len;
	পূর্ণাঙ্ক o = 0, tail_len;

	যদি ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		প্রত্যাগম -1;

	tail_len = strlen(pattern + brace_end + 1);
	যদি ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == রিক্ত)
		প্রত্যাগম -1;

	/* Pattern before initial brace */
	যদি (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	যদি (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	যদি (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	যদি (append(cp, patternsp, npatternsp) != 0) {
		মুক্ত(cp);
		প্রত্যাগম -1;
	}
	প্রত্যাগম 0;
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
স্থির পূর্ণাঙ্ক
brace_expand_one(ধ্রুব বর্ণ *pattern, বর্ণ ***patternsp, size_t *npatternsp,
    পূর্ণাঙ্ক *expanded, পূর্ণাঙ্ক *invalid)
{
	পূর্ণাঙ্ক i;
	পূর্ণাঙ্ক in_bracket, brace_start, brace_end, brace_level;
	পূর্ণাঙ্ক sel_start, sel_end;

	*invalid = *expanded = 0;

	যদি (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		প্রত্যাগম 0;
	} অন্যথা যদি (brace_start == -1)
		প্রত্যাগম 0;

	in_bracket = brace_level = 0;
	প্রতি (i = sel_start = brace_start + 1; i < brace_end; i++) {
		বিকল্প (pattern[i]) {
		পক্ষ '{':
			যদি (in_bracket)
				ভঙ্গ;
			brace_level++;
			ভঙ্গ;
		পক্ষ '}':
			যদি (in_bracket)
				ভঙ্গ;
			brace_level--;
			ভঙ্গ;
		পক্ষ '[':
			in_bracket = 1;
			ভঙ্গ;
		পক্ষ ']':
			in_bracket = 0;
			ভঙ্গ;
		পক্ষ '\\':
			যদি (i < brace_end - 1)
				i++; /* skip */
			ভঙ্গ;
		}
		যদি (pattern[i] == ',' || i == brace_end - 1) {
			যদি (in_bracket || brace_level > 0)
				অনুবর্ত;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			যদি (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				প্রত্যাগম -1;
			/* move on to the next selection */
			sel_start = i + 1;
			অনুবর্ত;
		}
	}
	যদি (in_bracket || brace_level > 0) {
		*invalid = 1;
		প্রত্যাগম 0;
	}
	/* success */
	*expanded = 1;
	প্রত্যাগম 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
স্থির পূর্ণাঙ্ক
brace_expand(ধ্রুব বর্ণ *pattern, বর্ণ ***patternsp, size_t *npatternsp)
{
	বর্ণ *cp, *cp2, **active = রিক্ত, **done = রিক্ত;
	size_t i, nactive = 0, ndone = 0;
	পূর্ণাঙ্ক ret = -1, invalid = 0, expanded = 0;

	*patternsp = রিক্ত;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	যদি ((cp = strdup(pattern)) == রিক্ত)
		প্রত্যাগম -1;
	যদি (append(cp, &active, &nactive) != 0) {
		মুক্ত(cp);
		প্রত্যাগম -1;
	}
	যাবত্ (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		যদি (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			মুক্ত(cp);
			গচ্ছ fail;
		}
		যদি (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		যদি (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			মুক্ত(cp);
			অনুবর্ত;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		যদি ((cp2 = strrchr(cp, '/')) != রিক্ত)
			*cp2++ = '\0';
		অন্যথা
			cp2 = cp;
		যদি (append(xstrdup(cp2), &done, &ndone) != 0) {
			মুক্ত(cp);
			গচ্ছ fail;
		}
		মুক্ত(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = রিক্ত;
	ndone = 0;
	ret = 0;
 fail:
	প্রতি (i = 0; i < nactive; i++)
		মুক্ত(active[i]);
	মুক্ত(active);
	প্রতি (i = 0; i < ndone; i++)
		মুক্ত(done[i]);
	মুক্ত(done);
	প্রত্যাগম ret;
}

স্থির সংরচনা sftp_conn *
do_sftp_connect(বর্ণ *host, বর্ণ *user, পূর্ণাঙ্ক port, বর্ণ *sftp_direct,
   পূর্ণাঙ্ক *reminp, পূর্ণাঙ্ক *remoutp, পূর্ণাঙ্ক *pidp)
{
	যদি (sftp_direct == রিক্ত) {
		যদি (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			প্রত্যাগম রিক্ত;

	} অন্যথা {
		freeargs(&args);
		addargs(&args, "sftp-server");
		যদি (do_cmd(sftp_direct, host, রিক্ত, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			প্রত্যাগম রিক্ত;
	}
	প্রত্যাগম sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

শূন্য
toremote(পূর্ণাঙ্ক argc, বর্ণ **argv, গণনা scp_mode_e mode, বর্ণ *sftp_direct)
{
	বর্ণ *suser = রিক্ত, *host = রিক্ত, *src = রিক্ত;
	বর্ণ *bp, *tuser, *thost, *targ;
	পূর্ণাঙ্ক sport = -1, tport = -1;
	সংরচনা sftp_conn *conn = রিক্ত, *conn2 = রিক্ত;
	arglist alist;
	পূর্ণাঙ্ক i, r, status;
	সংরচনা stat sb;
	u_int j;

	memset(&alist, '\0', পরিমাণ(alist));
	alist.list = রিক্ত;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	যদি (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		গচ্ছ out;
	}
	যদি (r != 0) {
		যদি (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			গচ্ছ out;
		}
	}

	/* Parse source files */
	প্রতি (i = 0; i < argc - 1; i++) {
		মুক্ত(suser);
		মুক্ত(host);
		মুক্ত(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		যদি (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			অনুবর্ত;
		}
		যদি (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		যদি (suser != রিক্ত && !okname(suser)) {
			++errs;
			অনুবর্ত;
		}
		যদি (host && throughlocal) {	/* extended remote to remote */
			যদি (mode == MODE_SFTP) {
				যদি (remin == -1 || conn == রিক্ত) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					যদি (conn == রিক্ত) {
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
				যদি (conn2 == রিক্ত) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(শূন্য) close(remin2);
				(শূন্য) close(remout2);
				remin2 = remout2 = -1;
				যদি (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				অন্যথা যদি (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				অনুবর্ত;
			} অন্যথা {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				যদি (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				মুক্ত(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				যদি (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				মুক্ত(bp);
				(শূন্য) close(remin);
				(শূন্য) close(remout);
				remin = remout = -1;
			}
		} অন্যথা যদি (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			যদি (tuser != রিক্ত && !okname(tuser)) {
				++errs;
				অনুবর্ত;
			}
			যদি (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			প্রতি (j = 0; j < remote_remote_args.অঙ্ক; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			যদি (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			যদি (suser) {
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
			যদি (do_local_cmd(&alist) != 0)
				errs = 1;
		} অন্যথা {	/* local to remote */
			যদি (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				যদি (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				যদি (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					যদি (conn == রিক্ত) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				অনুবর্ত;
			}
			/* SCP */
			যদি (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				যদি (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				যদি (response() < 0)
					exit(1);
				মুক্ত(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	মুক্ত(tuser);
	মুক্ত(thost);
	মুক্ত(targ);
	মুক্ত(suser);
	মুক্ত(host);
	মুক্ত(src);
	sftp_free(conn);
	sftp_free(conn2);
}

শূন্য
tolocal(পূর্ণাঙ্ক argc, বর্ণ **argv, গণনা scp_mode_e mode, বর্ণ *sftp_direct)
{
	বর্ণ *bp, *host = রিক্ত, *src = রিক্ত, *suser = রিক্ত;
	arglist alist;
	সংরচনা sftp_conn *conn = রিক্ত;
	পূর্ণাঙ্ক i, r, sport = -1;

	memset(&alist, '\0', পরিমাণ(alist));
	alist.list = রিক্ত;

	প্রতি (i = 0; i < argc - 1; i++) {
		মুক্ত(suser);
		মুক্ত(host);
		মুক্ত(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		যদি (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			অনুবর্ত;
		}
		যদি (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		যদি (suser != রিক্ত && !okname(suser)) {
			++errs;
			অনুবর্ত;
		}
		যদি (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			যদি (iamrecursive)
				addargs(&alist, "-r");
			যদি (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			যদি (do_local_cmd(&alist))
				++errs;
			অনুবর্ত;
		}
		/* Remote to local. */
		যদি (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			যদি (conn == রিক্ত) {
				error("sftp connection failed");
				++errs;
				অনুবর্ত;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(শূন্য) close(remin);
			(শূন্য) close(remout);
			remin = remout = -1;
			অনুবর্ত;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		যদি (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			মুক্ত(bp);
			++errs;
			অনুবর্ত;
		}
		মুক্ত(bp);
		sink(1, argv + argc - 1, src);
		(শূন্য) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	মুক্ত(suser);
	মুক্ত(host);
	মুক্ত(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
স্থির বর্ণ *
prepare_remote_path(সংরচনা sftp_conn *conn, ধ্রুব বর্ণ *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	যদি (*path == '\0' || strcmp(path, "~") == 0)
		প্রত্যাগম xstrdup(".");
	যদি (*path != '~')
		প্রত্যাগম xstrdup(path);
	যদি (strncmp(path, "~/", 2) == 0) {
		যদি ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			প্রত্যাগম xstrdup(".");
		প্রত্যাগম xstrdup(path + 2 + nslash);
	}
	যদি (sftp_can_expand_path(conn))
		প্রত্যাগম sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	প্রত্যাগম রিক্ত;
}

শূন্য
source_sftp(পূর্ণাঙ্ক argc, বর্ণ *src, বর্ণ *targ, সংরচনা sftp_conn *conn)
{
	বর্ণ *target = রিক্ত, *filename = রিক্ত, *abs_dst = রিক্ত;
	পূর্ণাঙ্ক src_is_dir, target_is_dir;
	Attrib a;
	সংরচনা stat st;

	memset(&a, '\0', পরিমাণ(a));
	যদি (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	যদি ((filename = basename(src)) == রিক্ত)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	যদি (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	যদি ((target = prepare_remote_path(conn, targ)) == রিক্ত)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	যদি (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		যদি (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	যদি (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	অন্যথা {
		abs_dst = target;
		target = রিক্ত;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	যদি (src_is_dir && iamrecursive) {
		যদি (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} অন্যথা যদি (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	মুক্ত(abs_dst);
	মুক্ত(target);
}

শূন্য
source(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	সংরচনা stat stb;
	স্থির BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	পূর্ণাঙ্ক fd = -1, haderr, indx;
	বর্ণ *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	পূর্ণাঙ্ক len;

	প্রতি (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		যাবত্ (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		যদি ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			গচ্ছ syserr;
		যদি (strchr(name, '\n') != রিক্ত) {
			strnvis(encname, name, পরিমাণ(encname), VIS_NL);
			name = encname;
		}
		যদি (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			গচ্ছ next;
		}
		যদি (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			গচ্ছ next;
		}
		unset_nonblock(fd);
		বিকল্প (stb.st_mode & S_IFMT) {
		পক্ষ S_IFREG:
			ভঙ্গ;
		পক্ষ S_IFDIR:
			যদি (iamrecursive) {
				rsource(name, &stb);
				গচ্ছ next;
			}
			/* FALLTHROUGH */
		স্বভাব:
			run_err("%s: not a regular file", name);
			গচ্ছ next;
		}
		যদি ((last = strrchr(name, '/')) == রিক্ত)
			last = name;
		অন্যথা
			++last;
		curfile = last;
		যদি (pflag) {
			যদি (do_times(remout, verbose_mode, &stb) < 0)
				গচ্ছ next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, পরিমাণ buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		যদি (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(শূন্য) atomicio(vwrite, remout, buf, strlen(buf));
		যদি (response() < 0)
			গচ্ছ next;
		যদি ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == রিক্ত) {
next:			যদি (fd != -1) {
				(শূন্য) close(fd);
				fd = -1;
			}
			অনুবর্ত;
		}
		যদি (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		প্রতি (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			যদি (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			যদি (!haderr) {
				যদি ((nr = atomicio(পঠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			যদি (haderr) {
				(শূন্য)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				অনুবর্ত;
			}
			যদি (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		যদি (fd != -1) {
			যদি (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		যদি (!haderr)
			(শূন্য) atomicio(vwrite, remout, "", 1);
		অন্যথা
			run_err("%s: %s", name, strerror(haderr));
		(শূন্য) response();
		যদি (showprogress)
			stop_progress_meter();
	}
}

শূন্য
rsource(বর্ণ *name, সংরচনা stat *statp)
{
	DIR *dirp;
	সংরচনা dirent *dp;
	বর্ণ *last, *vect[1], path[PATH_MAX];

	যদি (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		প্রত্যাগম;
	}
	last = strrchr(name, '/');
	যদি (last == রিক্ত)
		last = name;
	অন্যথা
		last++;
	যদি (pflag) {
		যদি (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			প্রত্যাগম;
		}
	}
	(শূন্য) snprintf(path, পরিমাণ path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	যদি (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(শূন্য) atomicio(vwrite, remout, path, strlen(path));
	যদি (response() < 0) {
		closedir(dirp);
		প্রত্যাগম;
	}
	যাবত্ ((dp = readdir(dirp)) != রিক্ত) {
		যদি (dp->d_ino == 0)
			অনুবর্ত;
		যদি (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			অনুবর্ত;
		যদি (strlen(name) + 1 + strlen(dp->d_name) >= পরিমাণ(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			অনুবর্ত;
		}
		(শূন্য) snprintf(path, পরিমাণ path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(শূন্য) closedir(dirp);
	(শূন্য) atomicio(vwrite, remout, "E\n", 2);
	(শূন্য) response();
}

শূন্য
sink_sftp(পূর্ণাঙ্ক argc, বর্ণ *dst, ধ্রুব বর্ণ *src, সংরচনা sftp_conn *conn)
{
	বর্ণ *abs_src = রিক্ত;
	বর্ণ *abs_dst = রিক্ত;
	glob_t g;
	বর্ণ *filename, *tmp = রিক্ত;
	পূর্ণাঙ্ক i, r, err = 0, dst_is_dir;
	সংরচনা stat st;

	memset(&g, 0, পরিমাণ(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	যদি ((abs_src = prepare_remote_path(conn, src)) == রিক্ত) {
		err = -1;
		গচ্ছ out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	যদি ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    রিক্ত, &g)) != 0) {
		যদি (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		অন্যথা
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		গচ্ছ out;
	}

	/* Did we actually get any matches back from the glob? */
	যদি (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != রিক্ত) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		যদি (sftp_stat(conn, g.gl_pathv[0], 1, রিক্ত) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			গচ্ছ out;
		}
	}

	যদি ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	যদি (g.gl_matchc > 1 && !dst_is_dir) {
		যদি (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			গচ্ছ out;
		}
		debug2_f("creating destination \"%s\"", dst);
		যদি (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			গচ্ছ out;
		}
		dst_is_dir = 1;
	}

	প্রতি (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == রিক্ত) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			গচ্ছ out;
		}

		/* Special handling for destination of '..' */
		যদি (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		যদি (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		অন্যথা
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		যদি (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			যদি (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    রিক্ত, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} অন্যথা {
			যদি (sftp_download(conn, g.gl_pathv[i], abs_dst, রিক্ত,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		মুক্ত(abs_dst);
		abs_dst = রিক্ত;
		মুক্ত(tmp);
		tmp = রিক্ত;
	}

out:
	মুক্ত(abs_src);
	মুক্ত(tmp);
	globfree(&g);
	যদি (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((পরিমাণ(type) == 4 && (val) > INT32_MAX) || \
	 (পরিমাণ(type) == 8 && (val) > INT64_MAX) || \
	 (পরিমাণ(type) != 4 && পরিমাণ(type) != 8))

শূন্য
sink(পূর্ণাঙ্ক argc, বর্ণ **argv, ধ্রুব বর্ণ *src)
{
	স্থির BUF buffer;
	সংরচনা stat stb;
	BUF *bp;
	off_t i;
	size_t j, গুনতি;
	পূর্ণাঙ্ক amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	পূর্ণাঙ্ক setimes, targisdir, wrerr;
	বর্ণ ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	বর্ণ **patterns = রিক্ত;
	size_t n, npatterns = 0;
	সংরচনা timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; গচ্ছ screwup; }

	যদি (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	যদি (!pflag) {
		(শূন্য) umask(mask);
		mask |= 07000;
	}
	যদি (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	যদি (targetshouldbedirectory)
		verifydir(targ);

	(শূন্য) atomicio(vwrite, remout, "", 1);
	যদি (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	যদি (src != রিক্ত && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		যদি (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	প্রতি (first = 1;; first = 0) {
		cp = buf;
		যদি (atomicio(পঠ, remin, cp, 1) != 1)
			গচ্ছ done;
		যদি (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		কুরু {
			যদি (atomicio(পঠ, remin, &ch, পরিমাণ(ch)) != পরিমাণ(ch))
				SCREWUP("lost connection");
			যদি (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} যাবত্ (cp < &buf[পরিমাণ(buf) - 1] && ch != '\n');
		*cp = 0;
		যদি (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		যদি (buf[0] == '\01' || buf[0] == '\02') {
			যদি (iamremote == 0) {
				(শূন্য) snmprintf(visbuf, পরিমাণ(visbuf),
				    রিক্ত, "%s", buf + 1);
				(শূন্য) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			যদি (buf[0] == '\02')
				exit(1);
			++errs;
			অনুবর্ত;
		}
		যদি (buf[0] == 'E') {
			(শূন্য) atomicio(vwrite, remout, "", 1);
			গচ্ছ done;
		}
		যদি (ch == '\n')
			*--cp = 0;

		cp = buf;
		যদি (*cp == 'T') {
			setimes++;
			cp++;
			যদি (!isdigit((unsigned বর্ণ)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			যদি (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			যদি (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			যদি (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			যদি (!isdigit((unsigned বর্ণ)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			যদি (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			যদি (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			যদি (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(শূন্য) atomicio(vwrite, remout, "", 1);
			অনুবর্ত;
		}
		যদি (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			যদি (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		প্রতি (++cp; cp < buf + 5; cp++) {
			যদি (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		যদি (!pflag)
			mode &= ~mask;
		যদি (*cp++ != ' ')
			SCREWUP("mode not delimited");

		যদি (!isdigit((unsigned বর্ণ)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		যদি (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		যদি (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		যদি (*cp == '\0' || strchr(cp, '/') != রিক্ত ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		যদি (npatterns > 0) {
			প্রতি (n = 0; n < npatterns; n++) {
				যদি (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					ভঙ্গ;
			}
			যদি (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				প্রতি (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		যদি (targisdir) {
			স্থির বর্ণ *namebuf;
			স্থির size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			যদি (need > cursize) {
				মুক্ত(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(শূন্য) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} অন্যথা
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		যদি (buf[0] == 'D') {
			পূর্ণাঙ্ক mod_flag = pflag;
			যদি (!iamrecursive)
				SCREWUP("received directory without -r");
			যদি (exists) {
				যদি (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					গচ্ছ bad;
				}
				যদি (pflag)
					(শূন্য) chmod(np, mode);
			} অন্যথা {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				যদি (mkdir(np, mode | S_IRWXU) == -1)
					গচ্ছ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			যদি (setimes) {
				setimes = 0;
				(শূন্য) utimes(vect[0], tv);
			}
			যদি (mod_flag)
				(শূন্য) chmod(vect[0], mode);
			মুক্ত(vect[0]);
			অনুবর্ত;
		}
		omode = mode;
		mode |= S_IWUSR;
		যদি ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			অনুবর্ত;
		}
		(শূন্য) atomicio(vwrite, remout, "", 1);
		যদি ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == রিক্ত) {
			(শূন্য) close(ofd);
			অনুবর্ত;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		যদি (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		প্রতি (গুনতি = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			যদি (i + amt > size)
				amt = size - i;
			গুনতি += amt;
			কুরু {
				j = atomicio6(পঠ, remin, cp, amt,
				    scpio, &statbytes);
				যদি (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} যাবত্ (amt > 0);

			যদি (গুনতি == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				যদি (!wrerr) {
					যদি (atomicio(vwrite, ofd, bp->buf,
					    গুনতি) != গুনতি) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				গুনতি = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		যদি (গুনতি != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, গুনতি) != গুনতি) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		যদি (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		যদি (pflag) {
			যদি (exists || omode != mode)
#ifdef HAVE_FCHMOD
				যদি (fchmod(ofd, omode)) {
#অন্যথা /* HAVE_FCHMOD */
				যদি (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} অন্যথা {
			যদি (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				যদি (fchmod(ofd, omode & ~mask)) {
#অন্যথা /* HAVE_FCHMOD */
				যদি (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		যদি (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(শূন্য) response();
		যদি (showprogress)
			stop_progress_meter();
		যদি (setimes && !wrerr) {
			setimes = 0;
			যদি (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		যদি (note_err(রিক্ত) == 0)
			(শূন্য) atomicio(vwrite, remout, "", 1);
	}
done:
	প্রতি (n = 0; n < npatterns; n++)
		মুক্ত(patterns[n]);
	মুক্ত(patterns);
	প্রত্যাগম;
screwup:
	প্রতি (n = 0; n < npatterns; n++)
		মুক্ত(patterns[n]);
	মুক্ত(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

শূন্য
throughlocal_sftp(সংরচনা sftp_conn *from, সংরচনা sftp_conn *to,
    বর্ণ *src, বর্ণ *targ)
{
	বর্ণ *target = রিক্ত, *filename = রিক্ত, *abs_dst = রিক্ত;
	বর্ণ *abs_src = রিক্ত, *tmp = রিক্ত;
	glob_t g;
	পূর্ণাঙ্ক i, r, targetisdir, err = 0;

	যদি ((filename = basename(src)) == রিক্ত)
		fatal("basename %s: %s", src, strerror(errno));

	যদি ((abs_src = prepare_remote_path(from, src)) == রিক্ত ||
	    (target = prepare_remote_path(to, targ)) == রিক্ত)
		cleanup_exit(255);
	memset(&g, 0, পরিমাণ(g));

	targetisdir = sftp_remote_is_dir(to, target);
	যদি (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		গচ্ছ out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	যদি ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    রিক্ত, &g)) != 0) {
		যদি (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		অন্যথা
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		গচ্ছ out;
	}

	/* Did we actually get any matches back from the glob? */
	যদি (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != রিক্ত) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		যদি (sftp_stat(from, g.gl_pathv[0], 1, রিক্ত) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			গচ্ছ out;
		}
	}

	প্রতি (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == রিক্ত) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			গচ্ছ out;
		}

		/* Special handling for source of '..' */
		যদি (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		যদি (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		অন্যথা
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		যদি (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			যদি (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    রিক্ত, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} অন্যথা {
			যদি (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    রিক্ত, pflag) == -1)
				err = -1;
		}
		মুক্ত(abs_dst);
		abs_dst = রিক্ত;
		মুক্ত(tmp);
		tmp = রিক্ত;
	}

out:
	মুক্ত(abs_src);
	মুক্ত(abs_dst);
	মুক্ত(target);
	মুক্ত(tmp);
	globfree(&g);
	যদি (err == -1)
		errs = 1;
}

পূর্ণাঙ্ক
response(শূন্য)
{
	বর্ণ ch, *cp, resp, rbuf[2048], visbuf[2048];

	যদি (atomicio(পঠ, remin, &resp, পরিমাণ(resp)) != পরিমাণ(resp))
		lostconn(0);

	cp = rbuf;
	বিকল্প (resp) {
	পক্ষ 0:		/* ok */
		প্রত্যাগম (0);
	স্বভাব:
		*cp++ = resp;
		/* FALLTHROUGH */
	পক্ষ 1:		/* error, followed by error msg */
	পক্ষ 2:		/* fatal error, "" */
		কুরু {
			যদি (atomicio(পঠ, remin, &ch, পরিমাণ(ch)) != পরিমাণ(ch))
				lostconn(0);
			*cp++ = ch;
		} যাবত্ (cp < &rbuf[পরিমাণ(rbuf) - 1] && ch != '\n');

		যদি (!iamremote) {
			cp[-1] = '\0';
			(শূন্য) snmprintf(visbuf, পরিমাণ(visbuf),
			    রিক্ত, "%s\n", rbuf);
			(শূন্য) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		যদি (resp == 1)
			প্রত্যাগম (-1);
		exit(1);
	}
	/* NOTREACHED */
}

শূন্য
usage(শূন্য)
{
	(শূন্য) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

শূন্য
run_err(ধ্রুব বর্ণ *fmt,...)
{
	স্থির FILE *fp;
	va_list ap;

	++errs;
	যদি (fp != রিক্ত || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(শূন্য) fprintf(fp, "%c", 0x01);
		(শূন্য) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(শূন্য) vfprintf(fp, fmt, ap);
		va_end(ap);
		(শূন্য) fprintf(fp, "\n");
		(শূন্য) fflush(fp);
	}

	যদি (!iamremote) {
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
পূর্ণাঙ্ক
note_err(ধ্রুব বর্ণ *fmt, ...)
{
	স্থির বর্ণ *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	যদি (fmt == রিক্ত) {
		যদি (emsg == রিক্ত)
			প্রত্যাগম 0;
		run_err("%s", emsg);
		মুক্ত(emsg);
		emsg = রিক্ত;
		প্রত্যাগম -1;
	}

	errs++;
	/* Prefer first-noted error */
	যদি (emsg != রিক্ত)
		প্রত্যাগম -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, রিক্ত, fmt, ap);
	va_end(ap);
	প্রত্যাগম -1;
}

শূন্য
verifydir(বর্ণ *cp)
{
	সংরচনা stat stb;

	যদি (!stat(cp, &stb)) {
		যদি (S_ISDIR(stb.st_mode))
			প্রত্যাগম;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

পূর্ণাঙ্ক
okname(বর্ণ *cp0)
{
	পূর্ণাঙ্ক c;
	বর্ণ *cp;

	cp = cp0;
	কুরু {
		c = (পূর্ণাঙ্ক)*cp;
		যদি (c & 0200)
			গচ্ছ bad;
		যদি (!isalpha(c) && !isdigit((unsigned বর্ণ)c)) {
			বিকল্প (c) {
			পক্ষ '\'':
			পক্ষ '"':
			পক্ষ '`':
			পক্ষ ' ':
			পক্ষ '#':
				গচ্ছ bad;
			স্বভাব:
				ভঙ্গ;
			}
		}
	} যাবত্ (*++cp);
	প্রত্যাগম (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	প্রত্যাগম (0);
}

BUF *
allocbuf(BUF *bp, পূর্ণাঙ্ক fd, পূর্ণাঙ্ক blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	সংরচনা stat stb;

	যদি (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		প্রত্যাগম (রিক্ত);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	যদি (size == 0)
		size = blksize;
#অন্যথা /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	যদি (bp->cnt >= size)
		প্রত্যাগম (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	প্রত্যাগম (bp);
}

শূন্য
lostconn(পূর্ণাঙ্ক signo)
{
	যদি (!iamremote)
		(শূন্য)লিখ(STDERR_FILENO, "lost connection\n", 16);
	যদি (signo)
		_exit(1);
	অন্যথা
		exit(1);
}

শূন্য
cleanup_exit(পূর্ণাঙ্ক i)
{
	যদি (remin > 0)
		close(remin);
	যদি (remout > 0)
		close(remout);
	যদি (remin2 > 0)
		close(remin2);
	যদি (remout2 > 0)
		close(remout2);
	যদি (do_cmd_pid > 0)
		(শূন্য)waitpid(do_cmd_pid, রিক্ত, 0);
	যদি (do_cmd_pid2 > 0)
		(শূন্য)waitpid(do_cmd_pid2, রিক্ত, 0);
	exit(i);
}
