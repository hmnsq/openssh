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
#که_تعریف_شوی HAVE_FNMATCH_H
#ضمن <fnmatch.h>
#د_که_پای
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
#د_که_پای

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

#تعریف_کړه COPY_BUFLEN	16384

صحيح do_cmd(حرف *, حرف *, حرف *, صحيح, صحيح, حرف *, صحيح *, صحيح *, pid_t *);
صحيح do_cmd2(حرف *, حرف *, صحيح, حرف *, صحيح, صحيح);

/* Struct for addargs */
arglist دلیلونه;
arglist remote_remote_دلیلونه;

/* Bandwidth limit */
اوږد اوږد حد_kbps = 0;
بنية bwlimit bwlimit;

/* Name of current file being transferred. */
حرف *curfile;

/* This is set to non-zero to enable verbose mode. */
صحيح verbose_ډېرپېښ = 0;
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
حرف *ssh_پروګرام = لار_SSH_پروګرام;

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
	وتل(1);
}

ساكن فراغ
suspone(صحيح pid, صحيح signo)
{
	صحيح حالت;

	إذا (pid > 1) {
		kill(pid, signo);
		طالما (waitpid(pid, &حالت, WUNTRACED) == -1 &&
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
	صحيح حالت;
	pid_t pid;

	إذا (a->عدد == 0)
		fatal("do_local_cmd: no arguments");

	إذا (verbose_ډېرپېښ) {
		cp = argv_assemble(a->عدد, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		حرر(cp);
	}
	إذا ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	إذا (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		وتل(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	طالما (waitpid(pid, &حالت, 0) == -1)
		إذا (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	إذا (!WIFEXITED(حالت) || WEXITSTATUS(حالت) != 0)
		أرجع (-1);

	أرجع (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

صحيح
do_cmd(حرف *پروګرام, حرف *host, حرف *remuser, صحيح پورټ, صحيح subsystem,
    حرف *cmd, صحيح *fdin, صحيح *fdout, pid_t *pid)
{
#که_تعریف_شوی USE_PIPES
	صحيح pin[2], pout[2];
#وإلا
	صحيح sv[2];
#د_که_پای

	إذا (verbose_ډېرپېښ)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    پروګرام, host,
		    remuser ? remuser : "(unspecified)", cmd);

	إذا (پورټ == -1)
		پورټ = sshport;

#که_تعریف_شوی USE_PIPES
	إذا (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#وإلا
	/* Create a socket pair for communicating with ssh. */
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#د_که_پای

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
#که_تعریف_شوی USE_PIPES
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
#د_که_پای
		replacearg(&دلیلونه, 0, "%s", پروګرام);
		إذا (پورټ != -1) {
			addargs(&دلیلونه, "-p");
			addargs(&دلیلونه, "%d", پورټ);
		}
		إذا (remuser != عدم) {
			addargs(&دلیلونه, "-l");
			addargs(&دلیلونه, "%s", remuser);
		}
		إذا (subsystem)
			addargs(&دلیلونه, "-s");
		addargs(&دلیلونه, "--");
		addargs(&دلیلونه, "%s", host);
		addargs(&دلیلونه, "%s", cmd);

		execvp(پروګرام, دلیلونه.list);
		perror(پروګرام);
		_exit(1);
	افتراضي:
		/* Parent.  Close the other side, and return the local side. */
#که_تعریف_شوی USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#وإلا
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#د_که_پای
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
do_cmd2(حرف *host, حرف *remuser, صحيح پورټ, حرف *cmd,
    صحيح fdin, صحيح fdout)
{
	صحيح حالت;
	pid_t pid;

	إذا (verbose_ډېرپېښ)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_پروګرام, host,
		    remuser ? remuser : "(unspecified)", cmd);

	إذا (پورټ == -1)
		پورټ = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	إذا (pid == 0) {
		إذا (dup2(fdin, 0) == -1)
			perror("dup2");
		إذا (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&دلیلونه, 0, "%s", ssh_پروګرام);
		إذا (پورټ != -1) {
			addargs(&دلیلونه, "-p");
			addargs(&دلیلونه, "%d", پورټ);
		}
		إذا (remuser != عدم) {
			addargs(&دلیلونه, "-l");
			addargs(&دلیلونه, "%s", remuser);
		}
		addargs(&دلیلونه, "-oBatchMode=yes");
		addargs(&دلیلونه, "--");
		addargs(&دلیلونه, "%s", host);
		addargs(&دلیلونه, "%s", cmd);

		execvp(ssh_پروګرام, دلیلونه.list);
		perror(ssh_پروګرام);
		وتل(1);
	} وإلا إذا (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	طالما (waitpid(pid, &حالت, 0) == -1)
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
فراغ پرلپسې_err(ثابت حرف *,...)
    __attribute__((__format__ (چاپ_کړه, 1, 2)))
    __attribute__((__nonnull__ (1)));
صحيح note_err(ثابت حرف *,...)
    __attribute__((__format__ (چاپ_کړه, 1, 2)));
فراغ verifydir(حرف *);

بنية passwd *pwd;
uid_t userid;
صحيح errs, remin, remout, remin2, remout2;
صحيح Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#تعریف_کړه	CMDNEEDS	64
حرف cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

تعداد scp_ډېرپېښ_e {
	ډېرپېښ_SCP,
	ډېرپېښ_SFTP
};

صحيح response(فراغ);
فراغ rsource(حرف *, بنية stat *);
فراغ sink(صحيح, حرف *[], ثابت حرف *);
فراغ سرچینه(صحيح, حرف *[]);
فراغ tolocal(صحيح, حرف *[], تعداد scp_ډېرپېښ_e, حرف *sftp_مستقیم);
فراغ toremote(صحيح, حرف *[], تعداد scp_ډېرپېښ_e, حرف *sftp_مستقیم);
فراغ usage(فراغ);

فراغ سرچینه_sftp(صحيح, حرف *, حرف *, بنية sftp_conn *);
فراغ sink_sftp(صحيح, حرف *, ثابت حرف *, بنية sftp_conn *);
فراغ throughlocal_sftp(بنية sftp_conn *, بنية sftp_conn *,
    حرف *, حرف *);

صحيح
اصلي(صحيح argc, حرف **argv)
{
	صحيح ch, fflag, tflag, حالت, r, n;
	حرف **newargv, *argv0;
	ثابت حرف *errstr;
	خارجي حرف *optarg;
	خارجي صحيح optind;
	تعداد scp_ډېرپېښ_e ډېرپېښ = ډېرپېښ_SFTP;
	حرف *sftp_مستقیم = عدم;
	اوږد اوږد llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(اعظمي(argc + 1, 1), حجم(*newargv));
	لكل (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&دلیلونه, '\0', حجم(دلیلونه));
	memset(&remote_remote_دلیلونه, '\0', حجم(remote_remote_دلیلونه));
	دلیلونه.list = remote_remote_دلیلونه.list = عدم;
	addargs(&دلیلونه, "%s", ssh_پروګرام);
	addargs(&دلیلونه, "-x");
	addargs(&دلیلونه, "-oPermitLocalCommand=no");
	addargs(&دلیلونه, "-oClearAllForwardings=yes");
	addargs(&دلیلونه, "-oRemoteCommand=none");
	addargs(&دلیلونه, "-oRequestTTY=no");
	addargs(&دلیلونه, "-oControlMaster=no");

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
			addargs(&دلیلونه, "-%c", ch);
			addargs(&remote_remote_دلیلونه, "-%c", ch);
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
			addargs(&remote_remote_دلیلونه, "-%c", ch);
			addargs(&remote_remote_دلیلونه, "%s", optarg);
			addargs(&دلیلونه, "-%c", ch);
			addargs(&دلیلونه, "%s", optarg);
			اكسر;
		حالة 'O':
			ډېرپېښ = ډېرپېښ_SCP;
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
			addargs(&remote_remote_دلیلونه, "-oBatchmode=yes");
			addargs(&دلیلونه, "-oBatchmode=yes");
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
			ssh_پروګرام = xstrdup(optarg);
			اكسر;
		حالة 'v':
			addargs(&دلیلونه, "-v");
			addargs(&remote_remote_دلیلونه, "-v");
			إذا (verbose_ډېرپېښ == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وإلا إذا (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_ډېرپېښ = 1;
			اكسر;
		حالة 'q':
			addargs(&دلیلونه, "-q");
			addargs(&remote_remote_دلیلونه, "-q");
			showprogress = 0;
			اكسر;
		حالة 'X':
			/* Please keep in sync with sftp.c -X */
			إذا (مزي_پرتله(optarg, "buffer=", 7) == 0) {
				r = لټون_scaled(optarg + 7, &llv);
				إذا (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				إذا (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (اندازه_t)llv;
			} وإلا إذا (مزي_پرتله(optarg, "nrequests=", 10) == 0) {
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
#که_تعریف_شوی HAVE_CYGWIN
			setmode(0, O_دوګونی);
#د_که_پای
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
	addargs(&دلیلونه, "-oForwardAgent=no");

	إذا (iamremote)
		ډېرپېښ = ډېرپېښ_SCP;

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
			وتل(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	إذا (fflag) {
		/* Follow "protocol", send data. */
		(فراغ) response();
		سرچینه(argc, argv);
		وتل(errs != 0);
	}
	إذا (tflag) {
		/* Receive data. */
		sink(argc, argv, عدم);
		وتل(errs != 0);
	}
	إذا (argc < 2)
		usage();
	إذا (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(فراغ) snprintf(cmd, حجم cmd, "scp%s%s%s%s",
	    verbose_ډېرپېښ ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(فراغ) ssh_signal(SIGPIPE, lostconn);

	إذا (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, ډېرپېښ, sftp_مستقیم);
	وإلا {
		إذا (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, ډېرپېښ, sftp_مستقیم);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	إذا (do_cmd_pid != -1 && (ډېرپېښ == ډېرپېښ_SFTP || errs == 0)) {
		إذا (remin != -1)
		    (فراغ) close(remin);
		إذا (remout != -1)
		    (فراغ) close(remout);
		إذا (waitpid(do_cmd_pid, &حالت, 0) == -1)
			errs = 1;
		وإلا {
			إذا (!WIFEXITED(حالت) || WEXITSTATUS(حالت) != 0)
				errs = 1;
		}
	}
	وتل(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ساكن صحيح
scpio(فراغ *_cnt, اندازه_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_پرمختګ_meter(0);
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
	    (بینښه اوږد اوږد) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (بینښه اوږد اوږد) (sb->st_atime < 0 ? 0 : sb->st_atime));
	إذا (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (اوږد اوږد)sb->st_mtime, (اوږد اوږد)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(فراغ) atomicio(vwrite, fd, buf, مزي_اوږدوالی(buf));
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
پیدا_کړه_brace(ثابت حرف *نمونه, صحيح *startp, صحيح *endp)
{
	صحيح i;
	صحيح دننه_bracket, brace_level;

	*startp = *endp = -1;
	دننه_bracket = brace_level = 0;
	لكل (i = 0; i < لوی_عدد && *endp < 0 && نمونه[i] != '\0'; i++) {
		بدل (نمونه[i]) {
		حالة '\\':
			/* skip next character */
			إذا (نمونه[i + 1] != '\0')
				i++;
			اكسر;
		حالة '[':
			دننه_bracket = 1;
			اكسر;
		حالة ']':
			دننه_bracket = 0;
			اكسر;
		حالة '{':
			إذا (دننه_bracket)
				اكسر;
			إذا (نمونه[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				اكسر;
			}
			إذا (*startp == -1)
				*startp = i;
			brace_level++;
			اكسر;
		حالة '}':
			إذا (دننه_bracket)
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
	إذا (*endp < 0 && (*startp >= 0 || دننه_bracket))
		أرجع -1;
	أرجع 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ساكن صحيح
emit_expansion(ثابت حرف *نمونه, صحيح brace_پیل, صحيح brace_پای_ټکی,
    صحيح sel_پیل, صحيح sel_پای_ټکی, حرف ***patternsp, اندازه_t *npatternsp)
{
	حرف *cp;
	اندازه_t نمونه_len;
	صحيح o = 0, لکۍ_len;

	إذا ((نمونه_len = مزي_اوږدوالی(نمونه)) == 0 || نمونه_len >= لوی_عدد)
		أرجع -1;

	لکۍ_len = مزي_اوږدوالی(نمونه + brace_پای_ټکی + 1);
	إذا ((cp = حافظه_ورکړه(brace_پیل + (sel_پای_ټکی - sel_پیل) +
	    لکۍ_len + 1)) == عدم)
		أرجع -1;

	/* Pattern before initial brace */
	إذا (brace_پیل > 0) {
		حافظه_نقل(cp, نمونه, brace_پیل);
		o = brace_پیل;
	}
	/* Current braced selection */
	إذا (sel_پای_ټکی - sel_پیل > 0) {
		حافظه_نقل(cp + o, نمونه + sel_پیل,
		    sel_پای_ټکی - sel_پیل);
		o += sel_پای_ټکی - sel_پیل;
	}
	/* Remainder of pattern after closing brace */
	إذا (لکۍ_len > 0) {
		حافظه_نقل(cp + o, نمونه + brace_پای_ټکی + 1, لکۍ_len);
		o += لکۍ_len;
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
brace_expand_one(ثابت حرف *نمونه, حرف ***patternsp, اندازه_t *npatternsp,
    صحيح *expanded, صحيح *invalid)
{
	صحيح i;
	صحيح دننه_bracket, brace_پیل, brace_پای_ټکی, brace_level;
	صحيح sel_پیل, sel_پای_ټکی;

	*invalid = *expanded = 0;

	إذا (پیدا_کړه_brace(نمونه, &brace_پیل, &brace_پای_ټکی) != 0) {
		*invalid = 1;
		أرجع 0;
	} وإلا إذا (brace_پیل == -1)
		أرجع 0;

	دننه_bracket = brace_level = 0;
	لكل (i = sel_پیل = brace_پیل + 1; i < brace_پای_ټکی; i++) {
		بدل (نمونه[i]) {
		حالة '{':
			إذا (دننه_bracket)
				اكسر;
			brace_level++;
			اكسر;
		حالة '}':
			إذا (دننه_bracket)
				اكسر;
			brace_level--;
			اكسر;
		حالة '[':
			دننه_bracket = 1;
			اكسر;
		حالة ']':
			دننه_bracket = 0;
			اكسر;
		حالة '\\':
			إذا (i < brace_پای_ټکی - 1)
				i++; /* skip */
			اكسر;
		}
		إذا (نمونه[i] == ',' || i == brace_پای_ټکی - 1) {
			إذا (دننه_bracket || brace_level > 0)
				استمر;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_پای_ټکی = (i == brace_پای_ټکی - 1) ? brace_پای_ټکی : i;
			إذا (emit_expansion(نمونه, brace_پیل, brace_پای_ټکی,
			    sel_پیل, sel_پای_ټکی, patternsp, npatternsp) != 0)
				أرجع -1;
			/* move on to the next selection */
			sel_پیل = i + 1;
			استمر;
		}
	}
	إذا (دننه_bracket || brace_level > 0) {
		*invalid = 1;
		أرجع 0;
	}
	/* success */
	*expanded = 1;
	أرجع 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ساكن صحيح
brace_expand(ثابت حرف *نمونه, حرف ***patternsp, اندازه_t *npatternsp)
{
	حرف *cp, *cp2, **فعال = عدم, **بشپړ = عدم;
	اندازه_t i, nactive = 0, ndone = 0;
	صحيح ret = -1, invalid = 0, expanded = 0;

	*patternsp = عدم;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	إذا ((cp = strdup(نمونه)) == عدم)
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
		إذا (append(xstrdup(cp2), &بشپړ, &ndone) != 0) {
			حرر(cp);
			اذهب fail;
		}
		حرر(cp);
	}
	/* success */
	*patternsp = بشپړ;
	*npatternsp = ndone;
	بشپړ = عدم;
	ndone = 0;
	ret = 0;
 fail:
	لكل (i = 0; i < nactive; i++)
		حرر(فعال[i]);
	حرر(فعال);
	لكل (i = 0; i < ndone; i++)
		حرر(بشپړ[i]);
	حرر(بشپړ);
	أرجع ret;
}

ساكن بنية sftp_conn *
do_sftp_connect(حرف *host, حرف *user, صحيح پورټ, حرف *sftp_مستقیم,
   صحيح *reminp, صحيح *remoutp, صحيح *pidp)
{
	إذا (sftp_مستقیم == عدم) {
		إذا (do_cmd(ssh_پروګرام, host, user, پورټ, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			أرجع عدم;

	} وإلا {
		freeargs(&دلیلونه);
		addargs(&دلیلونه, "sftp-server");
		إذا (do_cmd(sftp_مستقیم, host, عدم, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			أرجع عدم;
	}
	أرجع sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, حد_kbps);
}

فراغ
toremote(صحيح argc, حرف **argv, تعداد scp_ډېرپېښ_e ډېرپېښ, حرف *sftp_مستقیم)
{
	حرف *suser = عدم, *host = عدم, *src = عدم;
	حرف *bp, *tuser, *thost, *targ;
	صحيح sport = -1, tport = -1;
	بنية sftp_conn *conn = عدم, *conn2 = عدم;
	arglist alist;
	صحيح i, r, حالت;
	بنية stat sb;
	u_int j;

	memset(&alist, '\0', حجم(alist));
	alist.list = عدم;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	إذا (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		اذهب بهر;
	}
	إذا (r != 0) {
		إذا (parse_user_host_لار(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			اذهب بهر;
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
			parse_user_host_لار(argv[i], &suser, &host, &src);
		}
		إذا (suser != عدم && !okname(suser)) {
			++errs;
			استمر;
		}
		إذا (host && throughlocal) {	/* extended remote to remote */
			إذا (ډېرپېښ == ډېرپېښ_SFTP) {
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
					    remin, remout, (اوږد)do_cmd_pid);
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
				    remin2, remout2, (اوږد)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(فراغ) close(remin2);
				(فراغ) close(remout2);
				remin2 = remout2 = -1;
				إذا (waitpid(do_cmd_pid2, &حالت, 0) == -1)
					++errs;
				وإلا إذا (!WIFEXITED(حالت) ||
				    WEXITSTATUS(حالت) != 0)
					++errs;
				do_cmd_pid2 = -1;
				استمر;
			} وإلا {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				إذا (do_cmd(ssh_پروګرام, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					وتل(1);
				حرر(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				إذا (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					وتل(1);
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
			إذا (tport != -1 && tport != SSH_DEFAULT_پورټ) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_پروګرام);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			لكل (j = 0; j < remote_remote_دلیلونه.عدد; j++) {
				addargs(&alist, "%s",
				    remote_remote_دلیلونه.list[j]);
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
			إذا (ډېرپېښ == ډېرپېښ_SFTP) {
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
				سرچینه_sftp(1, argv[i], targ, conn);
				استمر;
			}
			/* SCP */
			إذا (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				إذا (do_cmd(ssh_پروګرام, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					وتل(1);
				إذا (response() < 0)
					وتل(1);
				حرر(bp);
			}
			سرچینه(1, argv + i);
		}
	}
بهر:
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
tolocal(صحيح argc, حرف **argv, تعداد scp_ډېرپېښ_e ډېرپېښ, حرف *sftp_مستقیم)
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
			parse_user_host_لار(argv[i], &suser, &host, &src);
		إذا (suser != عدم && !okname(suser)) {
			++errs;
			استمر;
		}
		إذا (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", لار_CP);
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
		إذا (ډېرپېښ == ډېرپېښ_SFTP) {
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
		إذا (do_cmd(ssh_پروګرام, host, suser, sport, 0, bp,
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
prepare_remote_لار(بنية sftp_conn *conn, ثابت حرف *لار)
{
	اندازه_t nslash;

	/* Handle ~ prefixed paths */
	إذا (*لار == '\0' || strcmp(لار, "~") == 0)
		أرجع xstrdup(".");
	إذا (*لار != '~')
		أرجع xstrdup(لار);
	إذا (مزي_پرتله(لار, "~/", 2) == 0) {
		إذا ((nslash = strspn(لار + 2, "/")) == مزي_اوږدوالی(لار + 2))
			أرجع xstrdup(".");
		أرجع xstrdup(لار + 2 + nslash);
	}
	إذا (sftp_can_expand_لار(conn))
		أرجع sftp_expand_لار(conn, لار);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	أرجع عدم;
}

فراغ
سرچینه_sftp(صحيح argc, حرف *src, حرف *targ, بنية sftp_conn *conn)
{
	حرف *موخه = عدم, *filename = عدم, *abs_dst = عدم;
	صحيح src_is_dir, موخه_is_dir;
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
	إذا ((موخه = prepare_remote_لار(conn, targ)) == عدم)
		cleanup_exit(255);
	موخه_is_dir = sftp_remote_is_dir(conn, موخه);
	إذا (targetshouldbedirectory && !موخه_is_dir) {
		debug("target directory \"%s\" does not exist", موخه);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		إذا (sftp_mkdir(conn, موخه, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		موخه_is_dir = 1;
	}
	إذا (موخه_is_dir)
		abs_dst = sftp_لار_append(موخه, filename);
	وإلا {
		abs_dst = موخه;
		موخه = عدم;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	إذا (src_is_dir && iamrecursive) {
		إذا (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_پرمختګ_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} وإلا إذا (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	حرر(abs_dst);
	حرر(موخه);
}

فراغ
سرچینه(صحيح argc, حرف **argv)
{
	بنية stat stb;
	ساكن BUF بفر;
	BUF *bp;
	off_t i, statbytes;
	اندازه_t amt, nr;
	صحيح fd = -1, haderr, indx;
	حرف *وروستی, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	صحيح len;

	لكل (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = مزي_اوږدوالی(name);
		طالما (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		إذا ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			اذهب syserr;
		إذا (strchr(name, '\n') != عدم) {
			strnvis(encname, name, حجم(encname), VIS_NL);
			name = encname;
		}
		إذا (fstat(fd, &stb) == -1) {
syserr:			پرلپسې_err("%s: %s", name, strerror(errno));
			اذهب بل;
		}
		إذا (stb.st_size < 0) {
			پرلپسې_err("%s: %s", name, "Negative file size");
			اذهب بل;
		}
		unset_nonblock(fd);
		بدل (stb.st_mode & S_IFMT) {
		حالة S_IFREG:
			اكسر;
		حالة S_IFDIR:
			إذا (iamrecursive) {
				rsource(name, &stb);
				اذهب بل;
			}
			/* FALLTHROUGH */
		افتراضي:
			پرلپسې_err("%s: not a regular file", name);
			اذهب بل;
		}
		إذا ((وروستی = strrchr(name, '/')) == عدم)
			وروستی = name;
		وإلا
			++وروستی;
		curfile = وروستی;
		إذا (pflag) {
			إذا (do_times(remout, verbose_ډېرپېښ, &stb) < 0)
				اذهب بل;
		}
#تعریف_کړه	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, حجم buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (اوږد اوږد)stb.st_size, وروستی);
		إذا (verbose_ډېرپېښ)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(فراغ) atomicio(vwrite, remout, buf, مزي_اوږدوالی(buf));
		إذا (response() < 0)
			اذهب بل;
		إذا ((bp = allocbuf(&بفر, fd, COPY_BUFLEN)) == عدم) {
بل:			إذا (fd != -1) {
				(فراغ) close(fd);
				fd = -1;
			}
			استمر;
		}
		إذا (showprogress)
			پیل_پرمختګ_meter(curfile, stb.st_size, &statbytes);
		سېټ_nonblock(remout);
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
			پرلپسې_err("%s: %s", name, strerror(haderr));
		(فراغ) response();
		إذا (showprogress)
			stop_پرمختګ_meter();
	}
}

فراغ
rsource(حرف *name, بنية stat *statp)
{
	DIR *dirp;
	بنية dirent *dp;
	حرف *وروستی, *vect[1], لار[PATH_MAX];

	إذا (!(dirp = opendir(name))) {
		پرلپسې_err("%s: %s", name, strerror(errno));
		أرجع;
	}
	وروستی = strrchr(name, '/');
	إذا (وروستی == عدم)
		وروستی = name;
	وإلا
		وروستی++;
	إذا (pflag) {
		إذا (do_times(remout, verbose_ډېرپېښ, statp) < 0) {
			closedir(dirp);
			أرجع;
		}
	}
	(فراغ) snprintf(لار, حجم لار, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, وروستی);
	إذا (verbose_ډېرپېښ)
		fmprintf(stderr, "Entering directory: %s", لار);
	(فراغ) atomicio(vwrite, remout, لار, مزي_اوږدوالی(لار));
	إذا (response() < 0) {
		closedir(dirp);
		أرجع;
	}
	طالما ((dp = readdir(dirp)) != عدم) {
		إذا (dp->d_ino == 0)
			استمر;
		إذا (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			استمر;
		إذا (مزي_اوږدوالی(name) + 1 + مزي_اوږدوالی(dp->d_name) >= حجم(لار) - 1) {
			پرلپسې_err("%s/%s: name too long", name, dp->d_name);
			استمر;
		}
		(فراغ) snprintf(لار, حجم لار, "%s/%s", name, dp->d_name);
		vect[0] = لار;
		سرچینه(1, vect);
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
	إذا ((abs_src = prepare_remote_لار(conn, src)) == عدم) {
		err = -1;
		اذهب بهر;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	إذا ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    عدم, &g)) != 0) {
		إذا (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		وإلا
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		اذهب بهر;
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
			اذهب بهر;
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
			اذهب بهر;
		}
		debug2_f("creating destination \"%s\"", dst);
		إذا (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			اذهب بهر;
		}
		dst_is_dir = 1;
	}

	لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		إذا ((filename = basename(tmp)) == عدم) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			اذهب بهر;
		}

		/* Special handling for destination of '..' */
		إذا (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		إذا (dst_is_dir)
			abs_dst = sftp_لار_append(dst, filename);
		وإلا
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		إذا (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			إذا (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    عدم, pflag, SFTP_پرمختګ_ONLY, 0, 0, 1, 1) == -1)
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

بهر:
	حرر(abs_src);
	حرر(tmp);
	globfree(&g);
	إذا (err == -1)
		errs = 1;
}


#تعریف_کړه TYPE_ډکېدنه(type, val) \
	((حجم(type) == 4 && (val) > INT32_MAX) || \
	 (حجم(type) == 8 && (val) > INT64_MAX) || \
	 (حجم(type) != 4 && حجم(type) != 8))

فراغ
sink(صحيح argc, حرف **argv, ثابت حرف *src)
{
	ساكن BUF بفر;
	بنية stat stb;
	BUF *bp;
	off_t i;
	اندازه_t j, شمېر;
	صحيح amt, exists, لومړی, ofd;
	ډېرپېښ_t ډېرپېښ, omode, ماسک;
	off_t اندازه, statbytes;
	بینښه اوږد اوږد ull;
	صحيح setimes, targisdir, wrerr;
	حرف ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	حرف **patterns = عدم;
	اندازه_t n, npatterns = 0;
	بنية timeval tv[2];

#تعریف_کړه	atime	tv[0]
#تعریف_کړه	mtime	tv[1]
#تعریف_کړه	SCREWUP(str)	{ why = str; اذهب screwup; }

	إذا (TYPE_ډکېدنه(time_t, 0) || TYPE_ډکېدنه(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	ماسک = umask(0);
	إذا (!pflag) {
		(فراغ) umask(ماسک);
		ماسک |= 07000;
	}
	إذا (argc != 1) {
		پرلپسې_err("ambiguous target");
		وتل(1);
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
	لكل (لومړی = 1;; لومړی = 0) {
		cp = buf;
		إذا (atomicio(اقرأ, remin, cp, 1) != 1)
			اذهب بشپړ;
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
		إذا (verbose_ډېرپېښ)
			fmprintf(stderr, "Sink: %s", buf);

		إذا (buf[0] == '\01' || buf[0] == '\02') {
			إذا (iamremote == 0) {
				(فراغ) snmprintf(visbuf, حجم(visbuf),
				    عدم, "%s", buf + 1);
				(فراغ) atomicio(vwrite, STDERR_FILENO,
				    visbuf, مزي_اوږدوالی(visbuf));
			}
			إذا (buf[0] == '\02')
				وتل(1);
			++errs;
			استمر;
		}
		إذا (buf[0] == 'E') {
			(فراغ) atomicio(vwrite, remout, "", 1);
			اذهب بشپړ;
		}
		إذا (ch == '\n')
			*--cp = 0;

		cp = buf;
		إذا (*cp == 'T') {
			setimes++;
			cp++;
			إذا (!که_عدد((بینښه حرف)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			إذا (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			إذا (TYPE_ډکېدنه(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			إذا (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			إذا (!که_عدد((بینښه حرف)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			إذا (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			إذا (TYPE_ډکېدنه(time_t, ull))
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
			إذا (لومړی) {
				پرلپسې_err("%s", cp);
				وتل(1);
			}
			SCREWUP("expected control record");
		}
		ډېرپېښ = 0;
		لكل (++cp; cp < buf + 5; cp++) {
			إذا (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			ډېرپېښ = (ډېرپېښ << 3) | (*cp - '0');
		}
		إذا (!pflag)
			ډېرپېښ &= ~ماسک;
		إذا (*cp++ != ' ')
			SCREWUP("mode not delimited");

		إذا (!که_عدد((بینښه حرف)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		إذا (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		إذا (TYPE_ډکېدنه(off_t, ull))
			SCREWUP("size out of range");
		اندازه = (off_t)ull;

		إذا (*cp == '\0' || strchr(cp, '/') != عدم ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			پرلپسې_err("error: unexpected filename: %s", cp);
			وتل(1);
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

			need = مزي_اوږدوالی(targ) + مزي_اوږدوالی(cp) + 250;
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
					(فراغ) chmod(np, ډېرپېښ);
			} وإلا {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				إذا (mkdir(np, ډېرپېښ | S_IRWXU) == -1)
					اذهب bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			إذا (setimes) {
				setimes = 0;
				(فراغ) utimes(vect[0], tv);
			}
			إذا (mod_flag)
				(فراغ) chmod(vect[0], ډېرپېښ);
			حرر(vect[0]);
			استمر;
		}
		omode = ډېرپېښ;
		ډېرپېښ |= S_IWUSR;
		إذا ((ofd = open(np, O_WRONLY|O_CREAT, ډېرپېښ)) == -1) {
bad:			پرلپسې_err("%s: %s", np, strerror(errno));
			استمر;
		}
		(فراغ) atomicio(vwrite, remout, "", 1);
		إذا ((bp = allocbuf(&بفر, ofd, COPY_BUFLEN)) == عدم) {
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
			پیل_پرمختګ_meter(curfile, اندازه, &statbytes);
		سېټ_nonblock(remin);
		لكل (شمېر = i = 0; i < اندازه; i += bp->cnt) {
			amt = bp->cnt;
			إذا (i + amt > اندازه)
				amt = اندازه - i;
			شمېر += amt;
			افعل {
				j = atomicio6(اقرأ, remin, cp, amt,
				    scpio, &statbytes);
				إذا (j == 0) {
					پرلپسې_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					وتل(1);
				}
				amt -= j;
				cp += j;
			} طالما (amt > 0);

			إذا (شمېر == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				إذا (!wrerr) {
					إذا (atomicio(vwrite, ofd, bp->buf,
					    شمېر) != شمېر) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				شمېر = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		إذا (شمېر != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, شمېر) != شمېر) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		إذا (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, اندازه) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		إذا (pflag) {
			إذا (exists || omode != ډېرپېښ)
#که_تعریف_شوی HAVE_FCHMOD
				إذا (fchmod(ofd, omode)) {
#وإلا /* HAVE_FCHMOD */
				إذا (chmod(np, omode)) {
#د_که_پای /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} وإلا {
			إذا (!exists && omode != ډېرپېښ)
#که_تعریف_شوی HAVE_FCHMOD
				إذا (fchmod(ofd, omode & ~ماسک)) {
#وإلا /* HAVE_FCHMOD */
				إذا (chmod(np, omode & ~ماسک)) {
#د_که_پای /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		إذا (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(فراغ) response();
		إذا (showprogress)
			stop_پرمختګ_meter();
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
بشپړ:
	لكل (n = 0; n < npatterns; n++)
		حرر(patterns[n]);
	حرر(patterns);
	أرجع;
screwup:
	لكل (n = 0; n < npatterns; n++)
		حرر(patterns[n]);
	حرر(patterns);
	پرلپسې_err("protocol error: %s", why);
	وتل(1);
}

فراغ
throughlocal_sftp(بنية sftp_conn *from, بنية sftp_conn *منزل,
    حرف *src, حرف *targ)
{
	حرف *موخه = عدم, *filename = عدم, *abs_dst = عدم;
	حرف *abs_src = عدم, *tmp = عدم;
	glob_t g;
	صحيح i, r, targetisdir, err = 0;

	إذا ((filename = basename(src)) == عدم)
		fatal("basename %s: %s", src, strerror(errno));

	إذا ((abs_src = prepare_remote_لار(from, src)) == عدم ||
	    (موخه = prepare_remote_لار(منزل, targ)) == عدم)
		cleanup_exit(255);
	memset(&g, 0, حجم(g));

	targetisdir = sftp_remote_is_dir(منزل, موخه);
	إذا (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		اذهب بهر;
	}

	debug3_f("copying remote %s to remote %s", abs_src, موخه);
	إذا ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    عدم, &g)) != 0) {
		إذا (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		وإلا
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		اذهب بهر;
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
			اذهب بهر;
		}
	}

	لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		إذا ((filename = basename(tmp)) == عدم) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			اذهب بهر;
		}

		/* Special handling for source of '..' */
		إذا (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		إذا (targetisdir)
			abs_dst = sftp_لار_append(موخه, filename);
		وإلا
			abs_dst = xstrdup(موخه);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		إذا (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			إذا (sftp_crossload_dir(from, منزل, g.gl_pathv[i], abs_dst,
			    عدم, pflag, SFTP_پرمختګ_ONLY, 1) == -1)
				err = -1;
		} وإلا {
			إذا (sftp_crossload(from, منزل, g.gl_pathv[i], abs_dst,
			    عدم, pflag) == -1)
				err = -1;
		}
		حرر(abs_dst);
		abs_dst = عدم;
		حرر(tmp);
		tmp = عدم;
	}

بهر:
	حرر(abs_src);
	حرر(abs_dst);
	حرر(موخه);
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
			    visbuf, مزي_اوږدوالی(visbuf));
		}
		++errs;
		إذا (resp == 1)
			أرجع (-1);
		وتل(1);
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
	وتل(1);
}

فراغ
پرلپسې_err(ثابت حرف *fmt,...)
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
		پرلپسې_err("%s", emsg);
		حرر(emsg);
		emsg = عدم;
		أرجع -1;
	}

	errs++;
	/* Prefer first-noted error */
	إذا (emsg != عدم)
		أرجع -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, لوی_عدد, عدم, fmt, ap);
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
	پرلپسې_err("%s: %s", cp, strerror(errno));
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
		إذا (!که_توری(c) && !که_عدد((بینښه حرف)c)) {
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
#که_تعریف_شوی HAVE_STRUCT_STAT_ST_BLKSIZE
	بنية stat stb;

	إذا (fstat(fd, &stb) == -1) {
		پرلپسې_err("fstat: %s", strerror(errno));
		أرجع (عدم);
	}
	اندازه = ROUNDUP(stb.st_blksize, blksize);
	إذا (اندازه == 0)
		اندازه = blksize;
#وإلا /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	اندازه = blksize;
#د_که_پای /* HAVE_STRUCT_STAT_ST_BLKSIZE */
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
		وتل(1);
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
	وتل(i);
}
