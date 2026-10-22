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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <sys/time.h>
#ضمن <sys/wait.h>
#ضمن <sys/uio.h>

#ضمن <ctype.h>
#ضمن <dirent.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#اگر_تعریف_شده HAVE_FNMATCH_H
#ضمن <fnmatch.h>
#پایان_اگر
#ضمن <glob.h>
#ضمن <libgen.h>
#ضمن <locale.h>
#ضمن <poll.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <time.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <util.h>
#إذا defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ضمن <vis.h>
#پایان_اگر

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "atomicio.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "progressmeter.h"
#ضمن "utf8.h"
#ضمن "sftp.h"

#ضمن "sftp-common.h"
#ضمن "sftp-client.h"

خارجي حرف *__progname;

#تعریف_کن COPY_BUFLEN	16384

صحيح do_cmd(حرف *, حرف *, حرف *, صحيح, صحيح, حرف *, صحيح *, صحيح *, pid_t *);
صحيح do_cmd2(حرف *, حرف *, صحيح, حرف *, صحيح, صحيح);

/* Struct for addargs */
arglist آرگومانها;
arglist remote_remote_آرگومانها;

/* Bandwidth limit */
دراز دراز حد_kbps = 0;
بنية bwlimit bwlimit;

/* Name of current file being transferred. */
حرف *curfile;

/* This is set to non-zero to enable verbose mode. */
صحيح verbose_نما = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
صحيح showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
صحيح throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
صحيح sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
حرف *ssh_برنامه = مسیر_SSH_برنامه;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
اندازه_t sftp_copy_buflen;
اندازه_t sftp_nrequests;

/* Needed for sftp */
متطاير sig_atomic_t interrupted = 0;

صحيح sftp_glob(بنية sftp_conn *, ثابت حرف *, صحيح,
    صحيح (*)(ثابت حرف *, صحيح), glob_t *); /* proto for sftp-glob.c */

ساكن فراغ
killchild(صحيح signo)
{
	إذا (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(فراغ)waitpid(do_cmd_pid, عدم, 0);
	}
	إذا (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(فراغ)waitpid(do_cmd_pid2, عدم, 0);
	}

	إذا (signo)
		_exit(1);
	خروج(1);
}

ساكن فراغ
suspone(صحيح pid, صحيح signo)
{
	صحيح وضعیت;

	إذا (pid > 1) {
		kill(pid, signo);
		طالما (waitpid(pid, &وضعیت, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

ساكن فراغ
suspchild(صحيح signo)
{
	صحيح save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ساكن صحيح
do_local_cmd(arglist *a)
{
	حرف *cp;
	صحيح وضعیت;
	pid_t pid;

	إذا (a->رقم == 0)
		fatal("do_local_cmd: no arguments");

	إذا (verbose_نما) {
		cp = argv_assemble(a->رقم, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		حرر(cp);
	}
	إذا ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	إذا (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		خروج(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	طالما (waitpid(pid, &وضعیت, 0) == -1)
		إذا (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	إذا (!WIFEXITED(وضعیت) || WEXITSTATUS(وضعیت) != 0)
		أرجع (-1);

	أرجع (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

صحيح
do_cmd(حرف *برنامه, حرف *host, حرف *remuser, صحيح پورت, صحيح subsystem,
    حرف *cmd, صحيح *fdin, صحيح *fdout, pid_t *pid)
{
#اگر_تعریف_شده USE_PIPES
	صحيح pin[2], pout[2];
#وإلا
	صحيح sv[2];
#پایان_اگر

	إذا (verbose_نما)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    برنامه, host,
		    remuser ? remuser : "(unspecified)", cmd);

	إذا (پورت == -1)
		پورت = sshport;

#اگر_تعریف_شده USE_PIPES
	إذا (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#وإلا
	/* Create a socket pair for communicating with ssh. */
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#پایان_اگر

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	بدل (*pid) {
	حالة -1:
		fatal("fork: %s", strerror(errno));
	حالة 0:
		/* Child. */
#اگر_تعریف_شده USE_PIPES
		إذا (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#وإلا
		إذا (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#پایان_اگر
		replacearg(&آرگومانها, 0, "%s", برنامه);
		إذا (پورت != -1) {
			addargs(&آرگومانها, "-p");
			addargs(&آرگومانها, "%d", پورت);
		}
		إذا (remuser != عدم) {
			addargs(&آرگومانها, "-l");
			addargs(&آرگومانها, "%s", remuser);
		}
		إذا (subsystem)
			addargs(&آرگومانها, "-s");
		addargs(&آرگومانها, "--");
		addargs(&آرگومانها, "%s", host);
		addargs(&آرگومانها, "%s", cmd);

		execvp(برنامه, آرگومانها.list);
		perror(برنامه);
		_exit(1);
	افتراضي:
		/* Parent.  Close the other side, and return the local side. */
#اگر_تعریف_شده USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#وإلا
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#پایان_اگر
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		أرجع 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
صحيح
do_cmd2(حرف *host, حرف *remuser, صحيح پورت, حرف *cmd,
    صحيح fdin, صحيح fdout)
{
	صحيح وضعیت;
	pid_t pid;

	إذا (verbose_نما)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_برنامه, host,
		    remuser ? remuser : "(unspecified)", cmd);

	إذا (پورت == -1)
		پورت = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	إذا (pid == 0) {
		إذا (dup2(fdin, 0) == -1)
			perror("dup2");
		إذا (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&آرگومانها, 0, "%s", ssh_برنامه);
		إذا (پورت != -1) {
			addargs(&آرگومانها, "-p");
			addargs(&آرگومانها, "%d", پورت);
		}
		إذا (remuser != عدم) {
			addargs(&آرگومانها, "-l");
			addargs(&آرگومانها, "%s", remuser);
		}
		addargs(&آرگومانها, "-oBatchMode=yes");
		addargs(&آرگومانها, "--");
		addargs(&آرگومانها, "%s", host);
		addargs(&آرگومانها, "%s", cmd);

		execvp(ssh_برنامه, آرگومانها.list);
		perror(ssh_برنامه);
		خروج(1);
	} وإلا إذا (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	طالما (waitpid(pid, &وضعیت, 0) == -1)
		إذا (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	أرجع 0;
}

تعريفنوع بنية {
	اندازه_t cnt;
	حرف *buf;
} BUF;

BUF *allocbuf(BUF *, صحيح, صحيح);
فراغ lostconn(صحيح);
صحيح okname(حرف *);
فراغ پیاپی_err(ثابت حرف *,...)
    __attribute__((__format__ (چاپ_کن, 1, 2)))
    __attribute__((__nonnull__ (1)));
صحيح note_err(ثابت حرف *,...)
    __attribute__((__format__ (چاپ_کن, 1, 2)));
فراغ verifydir(حرف *);

بنية passwd *pwd;
uid_t userid;
صحيح errs, remin, remout, remin2, remout2;
صحيح Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#تعریف_کن	CMDNEEDS	64
حرف cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

تعداد scp_نما_e {
	نما_SCP,
	نما_SFTP
};

صحيح response(فراغ);
فراغ rsource(حرف *, بنية stat *);
فراغ sink(صحيح, حرف *[], ثابت حرف *);
فراغ منبع(صحيح, حرف *[]);
فراغ tolocal(صحيح, حرف *[], تعداد scp_نما_e, حرف *sftp_مستقیم);
فراغ toremote(صحيح, حرف *[], تعداد scp_نما_e, حرف *sftp_مستقیم);
فراغ usage(فراغ);

فراغ منبع_sftp(صحيح, حرف *, حرف *, بنية sftp_conn *);
فراغ sink_sftp(صحيح, حرف *, ثابت حرف *, بنية sftp_conn *);
فراغ throughlocal_sftp(بنية sftp_conn *, بنية sftp_conn *,
    حرف *, حرف *);

صحيح
اصلی(صحيح argc, حرف **argv)
{
	صحيح ch, fflag, tflag, وضعیت, r, n;
	حرف **newargv, *argv0;
	ثابت حرف *errstr;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	تعداد scp_نما_e نما = نما_SFTP;
	حرف *sftp_مستقیم = عدم;
	دراز دراز llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(بیشینه(argc + 1, 1), حجم(*newargv));
	لكل (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&آرگومانها, '\0', حجم(آرگومانها));
	memset(&remote_remote_آرگومانها, '\0', حجم(remote_remote_آرگومانها));
	آرگومانها.list = remote_remote_آرگومانها.list = عدم;
	addargs(&آرگومانها, "%s", ssh_برنامه);
	addargs(&آرگومانها, "-x");
	addargs(&آرگومانها, "-oPermitLocalCommand=no");
	addargs(&آرگومانها, "-oClearAllForwardings=yes");
	addargs(&آرگومانها, "-oRemoteCommand=none");
	addargs(&آرگومانها, "-oRequestTTY=no");
	addargs(&آرگومانها, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	طالما ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		بدل (ch) {
		/* User-visible flags. */
		حالة '1':
			fatal("SSH protocol v.1 is no longer supported");
			اكسر;
		حالة '2':
			/* Ignored */
			اكسر;
		حالة 'A':
		حالة '4':
		حالة '6':
		حالة 'C':
			addargs(&آرگومانها, "-%c", ch);
			addargs(&remote_remote_آرگومانها, "-%c", ch);
			اكسر;
		حالة 'D':
			sftp_مستقیم = optarg;
			اكسر;
		حالة '3':
			throughlocal = 1;
			اكسر;
		حالة 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			اكسر;
		حالة 'o':
		حالة 'c':
		حالة 'i':
		حالة 'F':
		حالة 'J':
			addargs(&remote_remote_آرگومانها, "-%c", ch);
			addargs(&remote_remote_آرگومانها, "%s", optarg);
			addargs(&آرگومانها, "-%c", ch);
			addargs(&آرگومانها, "%s", optarg);
			اكسر;
		حالة 'O':
			نما = نما_SCP;
			اكسر;
		حالة 's':
			/* Ignored */
			اكسر;
		حالة 'P':
			sshport = a2port(optarg);
			إذا (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			اكسر;
		حالة 'B':
			addargs(&remote_remote_آرگومانها, "-oBatchmode=yes");
			addargs(&آرگومانها, "-oBatchmode=yes");
			اكسر;
		حالة 'l':
			حد_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			إذا (errstr != عدم)
				usage();
			حد_kbps *= 1024; /* kbps */
			bandwidth_حد_init(&bwlimit, حد_kbps, COPY_BUFLEN);
			اكسر;
		حالة 'p':
			pflag = 1;
			اكسر;
		حالة 'r':
			iamrecursive = 1;
			اكسر;
		حالة 'S':
			ssh_برنامه = xstrdup(optarg);
			اكسر;
		حالة 'v':
			addargs(&آرگومانها, "-v");
			addargs(&remote_remote_آرگومانها, "-v");
			إذا (verbose_نما == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وإلا إذا (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_نما = 1;
			اكسر;
		حالة 'q':
			addargs(&آرگومانها, "-q");
			addargs(&remote_remote_آرگومانها, "-q");
			showprogress = 0;
			اكسر;
		حالة 'X':
			/* Please keep in sync with sftp.c -X */
			إذا (مقایسه_رشته(optarg, "buffer=", 7) == 0) {
				r = پیمایش_scaled(optarg + 7, &llv);
				إذا (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				إذا (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (اندازه_t)llv;
			} وإلا إذا (مقایسه_رشته(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				إذا (errstr != عدم) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (اندازه_t)llv;
			} وإلا {
				fatal("Invalid -X option");
			}
			اكسر;

		/* Server options. */
		حالة 'd':
			targetshouldbedirectory = 1;
			اكسر;
		حالة 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			اكسر;
		حالة 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#اگر_تعریف_شده HAVE_CYGWIN
			setmode(0, O_دودویی);
#پایان_اگر
			اكسر;
		حالة 'T':
			Tflag = 1;
			اكسر;
		افتراضي:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&آرگومانها, "-oForwardAgent=no");

	إذا (iamremote)
		نما = نما_SCP;

	إذا ((pwd = getpwuid(userid = getuid())) == عدم)
		fatal("unknown user %u", (u_int) userid);

	إذا (!isatty(STDOUT_FILENO))
		showprogress = 0;

	إذا (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} وإلا {
		إذا (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    عدم) == -1) {
			perror("pledge");
			خروج(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	إذا (fflag) {
		/* Follow "protocol", send data. */
		(فراغ) response();
		منبع(argc, argv);
		خروج(errs != 0);
	}
	إذا (tflag) {
		/* Receive data. */
		sink(argc, argv, عدم);
		خروج(errs != 0);
	}
	إذا (argc < 2)
		usage();
	إذا (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(فراغ) snprintf(cmd, حجم cmd, "scp%s%s%s%s",
	    verbose_نما ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(فراغ) ssh_signal(SIGPIPE, lostconn);

	إذا (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, نما, sftp_مستقیم);
	وإلا {
		إذا (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, نما, sftp_مستقیم);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	إذا (do_cmd_pid != -1 && (نما == نما_SFTP || errs == 0)) {
		إذا (remin != -1)
		    (فراغ) close(remin);
		إذا (remout != -1)
		    (فراغ) close(remout);
		إذا (waitpid(do_cmd_pid, &وضعیت, 0) == -1)
			errs = 1;
		وإلا {
			إذا (!WIFEXITED(وضعیت) || WEXITSTATUS(وضعیت) != 0)
				errs = 1;
		}
	}
	خروج(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ساكن صحيح
scpio(فراغ *_cnt, اندازه_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_پیشرفت_meter(0);
	إذا (حد_kbps > 0)
		bandwidth_حد(&bwlimit, s);
	أرجع 0;
}

ساكن صحيح
do_times(صحيح fd, صحيح verb, ثابت بنية stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	حرف buf[(20 + 7 + 2) * 2 + 2];

	(فراغ)snprintf(buf, حجم(buf), "T%llu 0 %llu 0\n",
	    (بیعلامت دراز دراز) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (بیعلامت دراز دراز) (sb->st_atime < 0 ? 0 : sb->st_atime));
	إذا (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (دراز دراز)sb->st_mtime, (دراز دراز)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(فراغ) atomicio(vwrite, fd, buf, طول_رشته(buf));
	أرجع (response());
}

ساكن صحيح
parse_scp_uri(ثابت حرف *uri, حرف **userp, حرف **hostp, صحيح *portp,
    حرف **pathp)
{
	صحيح r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	إذا (r == 0 && *pathp == عدم)
		*pathp = xstrdup(".");
	أرجع r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
ساكن صحيح
append(حرف *cp, حرف ***ap, اندازه_t *np)
{
	حرف **tmp;

	إذا ((tmp = reallocarray(*ap, *np + 1, حجم(*tmp))) == عدم)
		أرجع -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	أرجع 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
ساكن صحيح
پیدا_کن_brace(ثابت حرف *الگو, صحيح *startp, صحيح *endp)
{
	صحيح i;
	صحيح درون_bracket, brace_level;

	*startp = *endp = -1;
	درون_bracket = brace_level = 0;
	لكل (i = 0; i < بیشترین_صحیح && *endp < 0 && الگو[i] != '\0'; i++) {
		بدل (الگو[i]) {
		حالة '\\':
			/* skip next character */
			إذا (الگو[i + 1] != '\0')
				i++;
			اكسر;
		حالة '[':
			درون_bracket = 1;
			اكسر;
		حالة ']':
			درون_bracket = 0;
			اكسر;
		حالة '{':
			إذا (درون_bracket)
				اكسر;
			إذا (الگو[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				اكسر;
			}
			إذا (*startp == -1)
				*startp = i;
			brace_level++;
			اكسر;
		حالة '}':
			إذا (درون_bracket)
				اكسر;
			إذا (*startp < 0) {
				/* Unbalanced brace */
				أرجع -1;
			}
			إذا (--brace_level <= 0)
				*endp = i;
			اكسر;
		}
	}
	/* unbalanced brackets/braces */
	إذا (*endp < 0 && (*startp >= 0 || درون_bracket))
		أرجع -1;
	أرجع 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ساكن صحيح
emit_expansion(ثابت حرف *الگو, صحيح brace_شروع, صحيح brace_انتها,
    صحيح sel_شروع, صحيح sel_انتها, حرف ***patternsp, اندازه_t *npatternsp)
{
	حرف *cp;
	اندازه_t الگو_len;
	صحيح o = 0, دم_len;

	إذا ((الگو_len = طول_رشته(الگو)) == 0 || الگو_len >= بیشترین_صحیح)
		أرجع -1;

	دم_len = طول_رشته(الگو + brace_انتها + 1);
	إذا ((cp = حافظه_بده(brace_شروع + (sel_انتها - sel_شروع) +
	    دم_len + 1)) == عدم)
		أرجع -1;

	/* Pattern before initial brace */
	إذا (brace_شروع > 0) {
		کپی_حافظه(cp, الگو, brace_شروع);
		o = brace_شروع;
	}
	/* Current braced selection */
	إذا (sel_انتها - sel_شروع > 0) {
		کپی_حافظه(cp + o, الگو + sel_شروع,
		    sel_انتها - sel_شروع);
		o += sel_انتها - sel_شروع;
	}
	/* Remainder of pattern after closing brace */
	إذا (دم_len > 0) {
		کپی_حافظه(cp + o, الگو + brace_انتها + 1, دم_len);
		o += دم_len;
	}
	cp[o] = '\0';
	إذا (append(cp, patternsp, npatternsp) != 0) {
		حرر(cp);
		أرجع -1;
	}
	أرجع 0;
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
ساكن صحيح
brace_expand_one(ثابت حرف *الگو, حرف ***patternsp, اندازه_t *npatternsp,
    صحيح *expanded, صحيح *invalid)
{
	صحيح i;
	صحيح درون_bracket, brace_شروع, brace_انتها, brace_level;
	صحيح sel_شروع, sel_انتها;

	*invalid = *expanded = 0;

	إذا (پیدا_کن_brace(الگو, &brace_شروع, &brace_انتها) != 0) {
		*invalid = 1;
		أرجع 0;
	} وإلا إذا (brace_شروع == -1)
		أرجع 0;

	درون_bracket = brace_level = 0;
	لكل (i = sel_شروع = brace_شروع + 1; i < brace_انتها; i++) {
		بدل (الگو[i]) {
		حالة '{':
			إذا (درون_bracket)
				اكسر;
			brace_level++;
			اكسر;
		حالة '}':
			إذا (درون_bracket)
				اكسر;
			brace_level--;
			اكسر;
		حالة '[':
			درون_bracket = 1;
			اكسر;
		حالة ']':
			درون_bracket = 0;
			اكسر;
		حالة '\\':
			إذا (i < brace_انتها - 1)
				i++; /* skip */
			اكسر;
		}
		إذا (الگو[i] == ',' || i == brace_انتها - 1) {
			إذا (درون_bracket || brace_level > 0)
				استمر;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_انتها = (i == brace_انتها - 1) ? brace_انتها : i;
			إذا (emit_expansion(الگو, brace_شروع, brace_انتها,
			    sel_شروع, sel_انتها, patternsp, npatternsp) != 0)
				أرجع -1;
			/* move on to the next selection */
			sel_شروع = i + 1;
			استمر;
		}
	}
	إذا (درون_bracket || brace_level > 0) {
		*invalid = 1;
		أرجع 0;
	}
	/* success */
	*expanded = 1;
	أرجع 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ساكن صحيح
brace_expand(ثابت حرف *الگو, حرف ***patternsp, اندازه_t *npatternsp)
{
	حرف *cp, *cp2, **فعال = عدم, **انجامشده = عدم;
	اندازه_t i, nactive = 0, ndone = 0;
	صحيح ret = -1, invalid = 0, expanded = 0;

	*patternsp = عدم;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	إذا ((cp = strdup(الگو)) == عدم)
		أرجع -1;
	إذا (append(cp, &فعال, &nactive) != 0) {
		حرر(cp);
		أرجع -1;
	}
	طالما (nactive > 0) {
		cp = فعال[nactive - 1];
		nactive--;
		إذا (brace_expand_one(cp, &فعال, &nactive,
		    &expanded, &invalid) == -1) {
			حرر(cp);
			اذهب fail;
		}
		إذا (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		إذا (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			حرر(cp);
			استمر;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		إذا ((cp2 = strrchr(cp, '/')) != عدم)
			*cp2++ = '\0';
		وإلا
			cp2 = cp;
		إذا (append(xstrdup(cp2), &انجامشده, &ndone) != 0) {
			حرر(cp);
			اذهب fail;
		}
		حرر(cp);
	}
	/* success */
	*patternsp = انجامشده;
	*npatternsp = ndone;
	انجامشده = عدم;
	ndone = 0;
	ret = 0;
 fail:
	لكل (i = 0; i < nactive; i++)
		حرر(فعال[i]);
	حرر(فعال);
	لكل (i = 0; i < ndone; i++)
		حرر(انجامشده[i]);
	حرر(انجامشده);
	أرجع ret;
}

ساكن بنية sftp_conn *
do_sftp_connect(حرف *host, حرف *user, صحيح پورت, حرف *sftp_مستقیم,
   صحيح *reminp, صحيح *remoutp, صحيح *pidp)
{
	إذا (sftp_مستقیم == عدم) {
		إذا (do_cmd(ssh_برنامه, host, user, پورت, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			أرجع عدم;

	} وإلا {
		freeargs(&آرگومانها);
		addargs(&آرگومانها, "sftp-server");
		إذا (do_cmd(sftp_مستقیم, host, عدم, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			أرجع عدم;
	}
	أرجع sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, حد_kbps);
}

فراغ
toremote(صحيح argc, حرف **argv, تعداد scp_نما_e نما, حرف *sftp_مستقیم)
{
	حرف *suser = عدم, *host = عدم, *src = عدم;
	حرف *bp, *tuser, *thost, *targ;
	صحيح sport = -1, tport = -1;
	بنية sftp_conn *conn = عدم, *conn2 = عدم;
	arglist alist;
	صحيح i, r, وضعیت;
	بنية stat sb;
	u_int j;

	memset(&alist, '\0', حجم(alist));
	alist.list = عدم;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	إذا (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		اذهب بیرون;
	}
	إذا (r != 0) {
		إذا (parse_user_host_مسیر(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			اذهب بیرون;
		}
	}

	/* Parse source files */
	لكل (i = 0; i < argc - 1; i++) {
		حرر(suser);
		حرر(host);
		حرر(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		إذا (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			استمر;
		}
		إذا (r != 0) {
			parse_user_host_مسیر(argv[i], &suser, &host, &src);
		}
		إذا (suser != عدم && !okname(suser)) {
			++errs;
			استمر;
		}
		إذا (host && throughlocal) {	/* extended remote to remote */
			إذا (نما == نما_SFTP) {
				إذا (remin == -1 || conn == عدم) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_مستقیم,
					    &remin, &remout, &do_cmd_pid);
					إذا (conn == عدم) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (دراز)do_cmd_pid);
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
				    sport, sftp_مستقیم,
				    &remin2, &remout2, &do_cmd_pid2);
				إذا (conn2 == عدم) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (دراز)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(فراغ) close(remin2);
				(فراغ) close(remout2);
				remin2 = remout2 = -1;
				إذا (waitpid(do_cmd_pid2, &وضعیت, 0) == -1)
					++errs;
				وإلا إذا (!WIFEXITED(وضعیت) ||
				    WEXITSTATUS(وضعیت) != 0)
					++errs;
				do_cmd_pid2 = -1;
				استمر;
			} وإلا {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				إذا (do_cmd(ssh_برنامه, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					خروج(1);
				حرر(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				إذا (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					خروج(1);
				حرر(bp);
				(فراغ) close(remin);
				(فراغ) close(remout);
				remin = remout = -1;
			}
		} وإلا إذا (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			إذا (tuser != عدم && !okname(tuser)) {
				++errs;
				استمر;
			}
			إذا (tport != -1 && tport != SSH_DEFAULT_پورت) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_برنامه);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			لكل (j = 0; j < remote_remote_آرگومانها.رقم; j++) {
				addargs(&alist, "%s",
				    remote_remote_آرگومانها.list[j]);
			}

			إذا (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			إذا (suser) {
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
			إذا (do_local_cmd(&alist) != 0)
				errs = 1;
		} وإلا {	/* local to remote */
			إذا (نما == نما_SFTP) {
				/* no need to glob: already done by shell */
				إذا (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				إذا (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_مستقیم,
					    &remin, &remout, &do_cmd_pid);
					إذا (conn == عدم) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				منبع_sftp(1, argv[i], targ, conn);
				استمر;
			}
			/* SCP */
			إذا (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				إذا (do_cmd(ssh_برنامه, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					خروج(1);
				إذا (response() < 0)
					خروج(1);
				حرر(bp);
			}
			منبع(1, argv + i);
		}
	}
بیرون:
	freeargs(&alist);
	حرر(tuser);
	حرر(thost);
	حرر(targ);
	حرر(suser);
	حرر(host);
	حرر(src);
	sftp_free(conn);
	sftp_free(conn2);
}

فراغ
tolocal(صحيح argc, حرف **argv, تعداد scp_نما_e نما, حرف *sftp_مستقیم)
{
	حرف *bp, *host = عدم, *src = عدم, *suser = عدم;
	arglist alist;
	بنية sftp_conn *conn = عدم;
	صحيح i, r, sport = -1;

	memset(&alist, '\0', حجم(alist));
	alist.list = عدم;

	لكل (i = 0; i < argc - 1; i++) {
		حرر(suser);
		حرر(host);
		حرر(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		إذا (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			استمر;
		}
		إذا (r != 0)
			parse_user_host_مسیر(argv[i], &suser, &host, &src);
		إذا (suser != عدم && !okname(suser)) {
			++errs;
			استمر;
		}
		إذا (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", مسیر_CP);
			إذا (iamrecursive)
				addargs(&alist, "-r");
			إذا (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			إذا (do_local_cmd(&alist))
				++errs;
			استمر;
		}
		/* Remote to local. */
		إذا (نما == نما_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_مستقیم, &remin, &remout, &do_cmd_pid);
			إذا (conn == عدم) {
				error("sftp connection failed");
				++errs;
				استمر;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(فراغ) close(remin);
			(فراغ) close(remout);
			remin = remout = -1;
			استمر;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		إذا (do_cmd(ssh_برنامه, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			حرر(bp);
			++errs;
			استمر;
		}
		حرر(bp);
		sink(1, argv + argc - 1, src);
		(فراغ) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	حرر(suser);
	حرر(host);
	حرر(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
ساكن حرف *
prepare_remote_مسیر(بنية sftp_conn *conn, ثابت حرف *مسیر)
{
	اندازه_t nslash;

	/* Handle ~ prefixed paths */
	إذا (*مسیر == '\0' || strcmp(مسیر, "~") == 0)
		أرجع xstrdup(".");
	إذا (*مسیر != '~')
		أرجع xstrdup(مسیر);
	إذا (مقایسه_رشته(مسیر, "~/", 2) == 0) {
		إذا ((nslash = strspn(مسیر + 2, "/")) == طول_رشته(مسیر + 2))
			أرجع xstrdup(".");
		أرجع xstrdup(مسیر + 2 + nslash);
	}
	إذا (sftp_can_expand_مسیر(conn))
		أرجع sftp_expand_مسیر(conn, مسیر);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	أرجع عدم;
}

فراغ
منبع_sftp(صحيح argc, حرف *src, حرف *targ, بنية sftp_conn *conn)
{
	حرف *هدف = عدم, *filename = عدم, *abs_dst = عدم;
	صحيح src_is_dir, هدف_is_dir;
	Attrib a;
	بنية stat st;

	memset(&a, '\0', حجم(a));
	إذا (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	إذا ((filename = basename(src)) == عدم)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	إذا (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	إذا ((هدف = prepare_remote_مسیر(conn, targ)) == عدم)
		cleanup_exit(255);
	هدف_is_dir = sftp_remote_is_dir(conn, هدف);
	إذا (targetshouldbedirectory && !هدف_is_dir) {
		debug("target directory \"%s\" does not exist", هدف);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		إذا (sftp_mkdir(conn, هدف, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		هدف_is_dir = 1;
	}
	إذا (هدف_is_dir)
		abs_dst = sftp_مسیر_append(هدف, filename);
	وإلا {
		abs_dst = هدف;
		هدف = عدم;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	إذا (src_is_dir && iamrecursive) {
		إذا (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_پیشرفت_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} وإلا إذا (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	حرر(abs_dst);
	حرر(هدف);
}

فراغ
منبع(صحيح argc, حرف **argv)
{
	بنية stat stb;
	ساكن BUF میانگیر;
	BUF *bp;
	off_t i, statbytes;
	اندازه_t amt, nr;
	صحيح fd = -1, haderr, indx;
	حرف *آخرین, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	صحيح len;

	لكل (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = طول_رشته(name);
		طالما (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		إذا ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			اذهب syserr;
		إذا (strchr(name, '\n') != عدم) {
			strnvis(encname, name, حجم(encname), VIS_NL);
			name = encname;
		}
		إذا (fstat(fd, &stb) == -1) {
syserr:			پیاپی_err("%s: %s", name, strerror(errno));
			اذهب بعدی;
		}
		إذا (stb.st_size < 0) {
			پیاپی_err("%s: %s", name, "Negative file size");
			اذهب بعدی;
		}
		unset_nonblock(fd);
		بدل (stb.st_mode & S_IFMT) {
		حالة S_IFREG:
			اكسر;
		حالة S_IFDIR:
			إذا (iamrecursive) {
				rsource(name, &stb);
				اذهب بعدی;
			}
			/* FALLTHROUGH */
		افتراضي:
			پیاپی_err("%s: not a regular file", name);
			اذهب بعدی;
		}
		إذا ((آخرین = strrchr(name, '/')) == عدم)
			آخرین = name;
		وإلا
			++آخرین;
		curfile = آخرین;
		إذا (pflag) {
			إذا (do_times(remout, verbose_نما, &stb) < 0)
				اذهب بعدی;
		}
#تعریف_کن	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, حجم buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (دراز دراز)stb.st_size, آخرین);
		إذا (verbose_نما)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(فراغ) atomicio(vwrite, remout, buf, طول_رشته(buf));
		إذا (response() < 0)
			اذهب بعدی;
		إذا ((bp = allocbuf(&میانگیر, fd, COPY_BUFLEN)) == عدم) {
بعدی:			إذا (fd != -1) {
				(فراغ) close(fd);
				fd = -1;
			}
			استمر;
		}
		إذا (showprogress)
			شروع_پیشرفت_meter(curfile, stb.st_size, &statbytes);
		مجموعه_nonblock(remout);
		لكل (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			إذا (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			إذا (!haderr) {
				إذا ((nr = atomicio(اقرأ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			إذا (haderr) {
				(فراغ)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				استمر;
			}
			إذا (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		إذا (fd != -1) {
			إذا (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		إذا (!haderr)
			(فراغ) atomicio(vwrite, remout, "", 1);
		وإلا
			پیاپی_err("%s: %s", name, strerror(haderr));
		(فراغ) response();
		إذا (showprogress)
			stop_پیشرفت_meter();
	}
}

فراغ
rsource(حرف *name, بنية stat *statp)
{
	DIR *dirp;
	بنية dirent *dp;
	حرف *آخرین, *vect[1], مسیر[PATH_MAX];

	إذا (!(dirp = opendir(name))) {
		پیاپی_err("%s: %s", name, strerror(errno));
		أرجع;
	}
	آخرین = strrchr(name, '/');
	إذا (آخرین == عدم)
		آخرین = name;
	وإلا
		آخرین++;
	إذا (pflag) {
		إذا (do_times(remout, verbose_نما, statp) < 0) {
			closedir(dirp);
			أرجع;
		}
	}
	(فراغ) snprintf(مسیر, حجم مسیر, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, آخرین);
	إذا (verbose_نما)
		fmprintf(stderr, "Entering directory: %s", مسیر);
	(فراغ) atomicio(vwrite, remout, مسیر, طول_رشته(مسیر));
	إذا (response() < 0) {
		closedir(dirp);
		أرجع;
	}
	طالما ((dp = readdir(dirp)) != عدم) {
		إذا (dp->d_ino == 0)
			استمر;
		إذا (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			استمر;
		إذا (طول_رشته(name) + 1 + طول_رشته(dp->d_name) >= حجم(مسیر) - 1) {
			پیاپی_err("%s/%s: name too long", name, dp->d_name);
			استمر;
		}
		(فراغ) snprintf(مسیر, حجم مسیر, "%s/%s", name, dp->d_name);
		vect[0] = مسیر;
		منبع(1, vect);
	}
	(فراغ) closedir(dirp);
	(فراغ) atomicio(vwrite, remout, "E\n", 2);
	(فراغ) response();
}

فراغ
sink_sftp(صحيح argc, حرف *dst, ثابت حرف *src, بنية sftp_conn *conn)
{
	حرف *abs_src = عدم;
	حرف *abs_dst = عدم;
	glob_t g;
	حرف *filename, *tmp = عدم;
	صحيح i, r, err = 0, dst_is_dir;
	بنية stat st;

	memset(&g, 0, حجم(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	إذا ((abs_src = prepare_remote_مسیر(conn, src)) == عدم) {
		err = -1;
		اذهب بیرون;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	إذا ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    عدم, &g)) != 0) {
		إذا (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		وإلا
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		اذهب بیرون;
	}

	/* Did we actually get any matches back from the glob? */
	إذا (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != عدم) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		إذا (sftp_stat(conn, g.gl_pathv[0], 1, عدم) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			اذهب بیرون;
		}
	}

	إذا ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	إذا (g.gl_matchc > 1 && !dst_is_dir) {
		إذا (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			اذهب بیرون;
		}
		debug2_f("creating destination \"%s\"", dst);
		إذا (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			اذهب بیرون;
		}
		dst_is_dir = 1;
	}

	لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		إذا ((filename = basename(tmp)) == عدم) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			اذهب بیرون;
		}

		/* Special handling for destination of '..' */
		إذا (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		إذا (dst_is_dir)
			abs_dst = sftp_مسیر_append(dst, filename);
		وإلا
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		إذا (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			إذا (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    عدم, pflag, SFTP_پیشرفت_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} وإلا {
			إذا (sftp_download(conn, g.gl_pathv[i], abs_dst, عدم,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		حرر(abs_dst);
		abs_dst = عدم;
		حرر(tmp);
		tmp = عدم;
	}

بیرون:
	حرر(abs_src);
	حرر(tmp);
	globfree(&g);
	إذا (err == -1)
		errs = 1;
}


#تعریف_کن TYPE_سرریز(type, val) \
	((حجم(type) == 4 && (val) > INT32_MAX) || \
	 (حجم(type) == 8 && (val) > INT64_MAX) || \
	 (حجم(type) != 4 && حجم(type) != 8))

فراغ
sink(صحيح argc, حرف **argv, ثابت حرف *src)
{
	ساكن BUF میانگیر;
	بنية stat stb;
	BUF *bp;
	off_t i;
	اندازه_t j, شمار;
	صحيح amt, exists, اولی, ofd;
	نما_t نما, omode, ماسک;
	off_t اندازه, statbytes;
	بیعلامت دراز دراز ull;
	صحيح setimes, targisdir, wrerr;
	حرف ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	حرف **patterns = عدم;
	اندازه_t n, npatterns = 0;
	بنية timeval tv[2];

#تعریف_کن	atime	tv[0]
#تعریف_کن	mtime	tv[1]
#تعریف_کن	SCREWUP(str)	{ why = str; اذهب screwup; }

	إذا (TYPE_سرریز(time_t, 0) || TYPE_سرریز(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	ماسک = umask(0);
	إذا (!pflag) {
		(فراغ) umask(ماسک);
		ماسک |= 07000;
	}
	إذا (argc != 1) {
		پیاپی_err("ambiguous target");
		خروج(1);
	}
	targ = *argv;
	إذا (targetshouldbedirectory)
		verifydir(targ);

	(فراغ) atomicio(vwrite, remout, "", 1);
	إذا (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	إذا (src != عدم && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		إذا (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	لكل (اولی = 1;; اولی = 0) {
		cp = buf;
		إذا (atomicio(اقرأ, remin, cp, 1) != 1)
			اذهب انجامشده;
		إذا (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		افعل {
			إذا (atomicio(اقرأ, remin, &ch, حجم(ch)) != حجم(ch))
				SCREWUP("lost connection");
			إذا (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} طالما (cp < &buf[حجم(buf) - 1] && ch != '\n');
		*cp = 0;
		إذا (verbose_نما)
			fmprintf(stderr, "Sink: %s", buf);

		إذا (buf[0] == '\01' || buf[0] == '\02') {
			إذا (iamremote == 0) {
				(فراغ) snmprintf(visbuf, حجم(visbuf),
				    عدم, "%s", buf + 1);
				(فراغ) atomicio(vwrite, STDERR_FILENO,
				    visbuf, طول_رشته(visbuf));
			}
			إذا (buf[0] == '\02')
				خروج(1);
			++errs;
			استمر;
		}
		إذا (buf[0] == 'E') {
			(فراغ) atomicio(vwrite, remout, "", 1);
			اذهب انجامشده;
		}
		إذا (ch == '\n')
			*--cp = 0;

		cp = buf;
		إذا (*cp == 'T') {
			setimes++;
			cp++;
			إذا (!آیا_رقم((بیعلامت حرف)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			إذا (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			إذا (TYPE_سرریز(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			إذا (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			إذا (!آیا_رقم((بیعلامت حرف)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			إذا (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			إذا (TYPE_سرریز(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			إذا (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(فراغ) atomicio(vwrite, remout, "", 1);
			استمر;
		}
		إذا (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			إذا (اولی) {
				پیاپی_err("%s", cp);
				خروج(1);
			}
			SCREWUP("expected control record");
		}
		نما = 0;
		لكل (++cp; cp < buf + 5; cp++) {
			إذا (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			نما = (نما << 3) | (*cp - '0');
		}
		إذا (!pflag)
			نما &= ~ماسک;
		إذا (*cp++ != ' ')
			SCREWUP("mode not delimited");

		إذا (!آیا_رقم((بیعلامت حرف)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		إذا (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		إذا (TYPE_سرریز(off_t, ull))
			SCREWUP("size out of range");
		اندازه = (off_t)ull;

		إذا (*cp == '\0' || strchr(cp, '/') != عدم ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			پیاپی_err("error: unexpected filename: %s", cp);
			خروج(1);
		}
		إذا (npatterns > 0) {
			لكل (n = 0; n < npatterns; n++) {
				إذا (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					اكسر;
			}
			إذا (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				لكل (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		إذا (targisdir) {
			ساكن حرف *namebuf;
			ساكن اندازه_t cursize;
			اندازه_t need;

			need = طول_رشته(targ) + طول_رشته(cp) + 250;
			إذا (need > cursize) {
				حرر(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(فراغ) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} وإلا
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		إذا (buf[0] == 'D') {
			صحيح mod_flag = pflag;
			إذا (!iamrecursive)
				SCREWUP("received directory without -r");
			إذا (exists) {
				إذا (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					اذهب bad;
				}
				إذا (pflag)
					(فراغ) chmod(np, نما);
			} وإلا {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				إذا (mkdir(np, نما | S_IRWXU) == -1)
					اذهب bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			إذا (setimes) {
				setimes = 0;
				(فراغ) utimes(vect[0], tv);
			}
			إذا (mod_flag)
				(فراغ) chmod(vect[0], نما);
			حرر(vect[0]);
			استمر;
		}
		omode = نما;
		نما |= S_IWUSR;
		إذا ((ofd = open(np, O_WRONLY|O_CREAT, نما)) == -1) {
bad:			پیاپی_err("%s: %s", np, strerror(errno));
			استمر;
		}
		(فراغ) atomicio(vwrite, remout, "", 1);
		إذا ((bp = allocbuf(&میانگیر, ofd, COPY_BUFLEN)) == عدم) {
			(فراغ) close(ofd);
			استمر;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		إذا (showprogress)
			شروع_پیشرفت_meter(curfile, اندازه, &statbytes);
		مجموعه_nonblock(remin);
		لكل (شمار = i = 0; i < اندازه; i += bp->cnt) {
			amt = bp->cnt;
			إذا (i + amt > اندازه)
				amt = اندازه - i;
			شمار += amt;
			افعل {
				j = atomicio6(اقرأ, remin, cp, amt,
				    scpio, &statbytes);
				إذا (j == 0) {
					پیاپی_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					خروج(1);
				}
				amt -= j;
				cp += j;
			} طالما (amt > 0);

			إذا (شمار == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				إذا (!wrerr) {
					إذا (atomicio(vwrite, ofd, bp->buf,
					    شمار) != شمار) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				شمار = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		إذا (شمار != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, شمار) != شمار) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		إذا (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, اندازه) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		إذا (pflag) {
			إذا (exists || omode != نما)
#اگر_تعریف_شده HAVE_FCHMOD
				إذا (fchmod(ofd, omode)) {
#وإلا /* HAVE_FCHMOD */
				إذا (chmod(np, omode)) {
#پایان_اگر /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} وإلا {
			إذا (!exists && omode != نما)
#اگر_تعریف_شده HAVE_FCHMOD
				إذا (fchmod(ofd, omode & ~ماسک)) {
#وإلا /* HAVE_FCHMOD */
				إذا (chmod(np, omode & ~ماسک)) {
#پایان_اگر /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		إذا (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(فراغ) response();
		إذا (showprogress)
			stop_پیشرفت_meter();
		إذا (setimes && !wrerr) {
			setimes = 0;
			إذا (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		إذا (note_err(عدم) == 0)
			(فراغ) atomicio(vwrite, remout, "", 1);
	}
انجامشده:
	لكل (n = 0; n < npatterns; n++)
		حرر(patterns[n]);
	حرر(patterns);
	أرجع;
screwup:
	لكل (n = 0; n < npatterns; n++)
		حرر(patterns[n]);
	حرر(patterns);
	پیاپی_err("protocol error: %s", why);
	خروج(1);
}

فراغ
throughlocal_sftp(بنية sftp_conn *from, بنية sftp_conn *مقصد,
    حرف *src, حرف *targ)
{
	حرف *هدف = عدم, *filename = عدم, *abs_dst = عدم;
	حرف *abs_src = عدم, *tmp = عدم;
	glob_t g;
	صحيح i, r, targetisdir, err = 0;

	إذا ((filename = basename(src)) == عدم)
		fatal("basename %s: %s", src, strerror(errno));

	إذا ((abs_src = prepare_remote_مسیر(from, src)) == عدم ||
	    (هدف = prepare_remote_مسیر(مقصد, targ)) == عدم)
		cleanup_exit(255);
	memset(&g, 0, حجم(g));

	targetisdir = sftp_remote_is_dir(مقصد, هدف);
	إذا (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		اذهب بیرون;
	}

	debug3_f("copying remote %s to remote %s", abs_src, هدف);
	إذا ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    عدم, &g)) != 0) {
		إذا (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		وإلا
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		اذهب بیرون;
	}

	/* Did we actually get any matches back from the glob? */
	إذا (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != عدم) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		إذا (sftp_stat(from, g.gl_pathv[0], 1, عدم) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			اذهب بیرون;
		}
	}

	لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		إذا ((filename = basename(tmp)) == عدم) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			اذهب بیرون;
		}

		/* Special handling for source of '..' */
		إذا (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		إذا (targetisdir)
			abs_dst = sftp_مسیر_append(هدف, filename);
		وإلا
			abs_dst = xstrdup(هدف);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		إذا (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			إذا (sftp_crossload_dir(from, مقصد, g.gl_pathv[i], abs_dst,
			    عدم, pflag, SFTP_پیشرفت_ONLY, 1) == -1)
				err = -1;
		} وإلا {
			إذا (sftp_crossload(from, مقصد, g.gl_pathv[i], abs_dst,
			    عدم, pflag) == -1)
				err = -1;
		}
		حرر(abs_dst);
		abs_dst = عدم;
		حرر(tmp);
		tmp = عدم;
	}

بیرون:
	حرر(abs_src);
	حرر(abs_dst);
	حرر(هدف);
	حرر(tmp);
	globfree(&g);
	إذا (err == -1)
		errs = 1;
}

صحيح
response(فراغ)
{
	حرف ch, *cp, resp, rbuf[2048], visbuf[2048];

	إذا (atomicio(اقرأ, remin, &resp, حجم(resp)) != حجم(resp))
		lostconn(0);

	cp = rbuf;
	بدل (resp) {
	حالة 0:		/* ok */
		أرجع (0);
	افتراضي:
		*cp++ = resp;
		/* FALLTHROUGH */
	حالة 1:		/* error, followed by error msg */
	حالة 2:		/* fatal error, "" */
		افعل {
			إذا (atomicio(اقرأ, remin, &ch, حجم(ch)) != حجم(ch))
				lostconn(0);
			*cp++ = ch;
		} طالما (cp < &rbuf[حجم(rbuf) - 1] && ch != '\n');

		إذا (!iamremote) {
			cp[-1] = '\0';
			(فراغ) snmprintf(visbuf, حجم(visbuf),
			    عدم, "%s\n", rbuf);
			(فراغ) atomicio(vwrite, STDERR_FILENO,
			    visbuf, طول_رشته(visbuf));
		}
		++errs;
		إذا (resp == 1)
			أرجع (-1);
		خروج(1);
	}
	/* NOTREACHED */
}

فراغ
usage(فراغ)
{
	(فراغ) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	خروج(1);
}

فراغ
پیاپی_err(ثابت حرف *fmt,...)
{
	ساكن FILE *fp;
	va_list ap;

	++errs;
	إذا (fp != عدم || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(فراغ) fprintf(fp, "%c", 0x01);
		(فراغ) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(فراغ) vfprintf(fp, fmt, ap);
		va_end(ap);
		(فراغ) fprintf(fp, "\n");
		(فراغ) fflush(fp);
	}

	إذا (!iamremote) {
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
صحيح
note_err(ثابت حرف *fmt, ...)
{
	ساكن حرف *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	إذا (fmt == عدم) {
		إذا (emsg == عدم)
			أرجع 0;
		پیاپی_err("%s", emsg);
		حرر(emsg);
		emsg = عدم;
		أرجع -1;
	}

	errs++;
	/* Prefer first-noted error */
	إذا (emsg != عدم)
		أرجع -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, بیشترین_صحیح, عدم, fmt, ap);
	va_end(ap);
	أرجع -1;
}

فراغ
verifydir(حرف *cp)
{
	بنية stat stb;

	إذا (!stat(cp, &stb)) {
		إذا (S_ISDIR(stb.st_mode))
			أرجع;
		errno = ENOTDIR;
	}
	پیاپی_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

صحيح
okname(حرف *cp0)
{
	صحيح c;
	حرف *cp;

	cp = cp0;
	افعل {
		c = (صحيح)*cp;
		إذا (c & 0200)
			اذهب bad;
		إذا (!آیا_حرف(c) && !آیا_رقم((بیعلامت حرف)c)) {
			بدل (c) {
			حالة '\'':
			حالة '"':
			حالة '`':
			حالة ' ':
			حالة '#':
				اذهب bad;
			افتراضي:
				اكسر;
			}
		}
	} طالما (*++cp);
	أرجع (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	أرجع (0);
}

BUF *
allocbuf(BUF *bp, صحيح fd, صحيح blksize)
{
	اندازه_t اندازه;
#اگر_تعریف_شده HAVE_STRUCT_STAT_ST_BLKSIZE
	بنية stat stb;

	إذا (fstat(fd, &stb) == -1) {
		پیاپی_err("fstat: %s", strerror(errno));
		أرجع (عدم);
	}
	اندازه = ROUNDUP(stb.st_blksize, blksize);
	إذا (اندازه == 0)
		اندازه = blksize;
#وإلا /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	اندازه = blksize;
#پایان_اگر /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	إذا (bp->cnt >= اندازه)
		أرجع (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, اندازه, 1);
	bp->cnt = اندازه;
	أرجع (bp);
}

فراغ
lostconn(صحيح signo)
{
	إذا (!iamremote)
		(فراغ)اكتب(STDERR_FILENO, "lost connection\n", 16);
	إذا (signo)
		_exit(1);
	وإلا
		خروج(1);
}

فراغ
cleanup_exit(صحيح i)
{
	إذا (remin > 0)
		close(remin);
	إذا (remout > 0)
		close(remout);
	إذا (remin2 > 0)
		close(remin2);
	إذا (remout2 > 0)
		close(remout2);
	إذا (do_cmd_pid > 0)
		(فراغ)waitpid(do_cmd_pid, عدم, 0);
	إذا (do_cmd_pid2 > 0)
		(فراغ)waitpid(do_cmd_pid2, عدم, 0);
	خروج(i);
}
