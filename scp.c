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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <sys/time.h>
#شامل <sys/wait.h>
#شامل <sys/uio.h>

#شامل <ctype.h>
#شامل <dirent.h>
#شامل <errno.h>
#شامل <fcntl.h>
#اگر_تعریف_شدہ HAVE_FNMATCH_H
#شامل <fnmatch.h>
#اگر_ختم
#شامل <glob.h>
#شامل <libgen.h>
#شامل <locale.h>
#شامل <poll.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <time.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <util.h>
#اگر defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#شامل <vis.h>
#اگر_ختم

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "atomicio.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "progressmeter.h"
#شامل "utf8.h"
#شامل "sftp.h"

#شامل "sftp-common.h"
#شامل "sftp-client.h"

خارجی حرف *__progname;

#تعریف_کرو COPY_BUFLEN	16384

صحیح do_cmd(حرف *, حرف *, حرف *, صحیح, صحیح, حرف *, صحیح *, صحیح *, pid_t *);
صحیح do_cmd2(حرف *, حرف *, صحیح, حرف *, صحیح, صحیح);

/* Struct for addargs */
arglist دلائل;
arglist remote_remote_دلائل;

/* Bandwidth limit */
طویل طویل حد_بندی_kbps = 0;
ساخت bwlimit bwlimit;

/* Name of current file being transferred. */
حرف *curfile;

/* This is set to non-zero to enable verbose mode. */
صحیح verbose_منوال = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
صحیح showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
صحیح throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
صحیح sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
حرف *ssh_پروگرام = راستہ_SSH_پروگرام;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
سائز_t sftp_copy_buflen;
سائز_t sftp_nrequests;

/* Needed for sftp */
متلون sig_atomic_t interrupted = 0;

صحیح sftp_glob(ساخت sftp_conn *, ثابت حرف *, صحیح,
    صحیح (*)(ثابت حرف *, صحیح), glob_t *); /* proto for sftp-glob.c */

ساکن خالی
killchild(صحیح signo)
{
	اگر (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(خالی)waitpid(do_cmd_pid, تہی, 0);
	}
	اگر (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(خالی)waitpid(do_cmd_pid2, تہی, 0);
	}

	اگر (signo)
		_exit(1);
	باہر_نکلو(1);
}

ساکن خالی
suspone(صحیح pid, صحیح signo)
{
	صحیح حالت_2;

	اگر (pid > 1) {
		kill(pid, signo);
		جب (waitpid(pid, &حالت_2, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

ساکن خالی
suspchild(صحیح signo)
{
	صحیح save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ساکن صحیح
do_local_cmd(arglist *a)
{
	حرف *cp;
	صحیح حالت_2;
	pid_t pid;

	اگر (a->عدد == 0)
		fatal("do_local_cmd: no arguments");

	اگر (verbose_منوال) {
		cp = argv_assemble(a->عدد, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		آزاد(cp);
	}
	اگر ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	اگر (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		باہر_نکلو(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	جب (waitpid(pid, &حالت_2, 0) == -1)
		اگر (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	اگر (!WIFEXITED(حالت_2) || WEXITSTATUS(حالت_2) != 0)
		واپس (-1);

	واپس (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

صحیح
do_cmd(حرف *پروگرام, حرف *host, حرف *remuser, صحیح پورٹ, صحیح subsystem,
    حرف *cmd, صحیح *fdin, صحیح *fdout, pid_t *pid)
{
#اگر_تعریف_شدہ USE_PIPES
	صحیح pin[2], pout[2];
#ورنہ
	صحیح sv[2];
#اگر_ختم

	اگر (verbose_منوال)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    پروگرام, host,
		    remuser ? remuser : "(unspecified)", cmd);

	اگر (پورٹ == -1)
		پورٹ = sshport;

#اگر_تعریف_شدہ USE_PIPES
	اگر (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#ورنہ
	/* Create a socket pair for communicating with ssh. */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#اگر_ختم

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	انتخاب (*pid) {
	حالت -1:
		fatal("fork: %s", strerror(errno));
	حالت 0:
		/* Child. */
#اگر_تعریف_شدہ USE_PIPES
		اگر (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#ورنہ
		اگر (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#اگر_ختم
		replacearg(&دلائل, 0, "%s", پروگرام);
		اگر (پورٹ != -1) {
			addargs(&دلائل, "-p");
			addargs(&دلائل, "%d", پورٹ);
		}
		اگر (remuser != تہی) {
			addargs(&دلائل, "-l");
			addargs(&دلائل, "%s", remuser);
		}
		اگر (subsystem)
			addargs(&دلائل, "-s");
		addargs(&دلائل, "--");
		addargs(&دلائل, "%s", host);
		addargs(&دلائل, "%s", cmd);

		execvp(پروگرام, دلائل.list);
		perror(پروگرام);
		_exit(1);
	طےشدہ:
		/* Parent.  Close the other side, and return the local side. */
#اگر_تعریف_شدہ USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#ورنہ
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#اگر_ختم
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		واپس 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
صحیح
do_cmd2(حرف *host, حرف *remuser, صحیح پورٹ, حرف *cmd,
    صحیح fdin, صحیح fdout)
{
	صحیح حالت_2;
	pid_t pid;

	اگر (verbose_منوال)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_پروگرام, host,
		    remuser ? remuser : "(unspecified)", cmd);

	اگر (پورٹ == -1)
		پورٹ = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	اگر (pid == 0) {
		اگر (dup2(fdin, 0) == -1)
			perror("dup2");
		اگر (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&دلائل, 0, "%s", ssh_پروگرام);
		اگر (پورٹ != -1) {
			addargs(&دلائل, "-p");
			addargs(&دلائل, "%d", پورٹ);
		}
		اگر (remuser != تہی) {
			addargs(&دلائل, "-l");
			addargs(&دلائل, "%s", remuser);
		}
		addargs(&دلائل, "-oBatchMode=yes");
		addargs(&دلائل, "--");
		addargs(&دلائل, "%s", host);
		addargs(&دلائل, "%s", cmd);

		execvp(ssh_پروگرام, دلائل.list);
		perror(ssh_پروگرام);
		باہر_نکلو(1);
	} ورنہ اگر (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	جب (waitpid(pid, &حالت_2, 0) == -1)
		اگر (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	واپس 0;
}

قسمتعریف ساخت {
	سائز_t cnt;
	حرف *buf;
} BUF;

BUF *allocbuf(BUF *, صحیح, صحیح);
خالی lostconn(صحیح);
صحیح okname(حرف *);
خالی تسلسل_err(ثابت حرف *,...)
    __attribute__((__format__ (لکھو, 1, 2)))
    __attribute__((__nonnull__ (1)));
صحیح note_err(ثابت حرف *,...)
    __attribute__((__format__ (لکھو, 1, 2)));
خالی verifydir(حرف *);

ساخت passwd *pwd;
uid_t userid;
صحیح errs, remin, remout, remin2, remout2;
صحیح Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#تعریف_کرو	CMDNEEDS	64
حرف cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

شمار scp_منوال_e {
	منوال_SCP,
	منوال_SFTP
};

صحیح response(خالی);
خالی rsource(حرف *, ساخت stat *);
خالی sink(صحیح, حرف *[], ثابت حرف *);
خالی ماخذ(صحیح, حرف *[]);
خالی tolocal(صحیح, حرف *[], شمار scp_منوال_e, حرف *sftp_براہ_راست);
خالی toremote(صحیح, حرف *[], شمار scp_منوال_e, حرف *sftp_براہ_راست);
خالی usage(خالی);

خالی ماخذ_sftp(صحیح, حرف *, حرف *, ساخت sftp_conn *);
خالی sink_sftp(صحیح, حرف *, ثابت حرف *, ساخت sftp_conn *);
خالی throughlocal_sftp(ساخت sftp_conn *, ساخت sftp_conn *,
    حرف *, حرف *);

صحیح
مین(صحیح argc, حرف **argv)
{
	صحیح ch, fflag, tflag, حالت_2, r, n;
	حرف **newargv, *argv0;
	ثابت حرف *errstr;
	خارجی حرف *optarg;
	خارجی صحیح optind;
	شمار scp_منوال_e منوال = منوال_SFTP;
	حرف *sftp_براہ_راست = تہی;
	طویل طویل llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(زیادہ_سے_زیادہ(argc + 1, 1), حجم(*newargv));
	برائے (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&دلائل, '\0', حجم(دلائل));
	memset(&remote_remote_دلائل, '\0', حجم(remote_remote_دلائل));
	دلائل.list = remote_remote_دلائل.list = تہی;
	addargs(&دلائل, "%s", ssh_پروگرام);
	addargs(&دلائل, "-x");
	addargs(&دلائل, "-oPermitLocalCommand=no");
	addargs(&دلائل, "-oClearAllForwardings=yes");
	addargs(&دلائل, "-oRemoteCommand=none");
	addargs(&دلائل, "-oRequestTTY=no");
	addargs(&دلائل, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	جب ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		انتخاب (ch) {
		/* User-visible flags. */
		حالت '1':
			fatal("SSH protocol v.1 is no longer supported");
			توڑو;
		حالت '2':
			/* Ignored */
			توڑو;
		حالت 'A':
		حالت '4':
		حالت '6':
		حالت 'C':
			addargs(&دلائل, "-%c", ch);
			addargs(&remote_remote_دلائل, "-%c", ch);
			توڑو;
		حالت 'D':
			sftp_براہ_راست = optarg;
			توڑو;
		حالت '3':
			throughlocal = 1;
			توڑو;
		حالت 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			توڑو;
		حالت 'o':
		حالت 'c':
		حالت 'i':
		حالت 'F':
		حالت 'J':
			addargs(&remote_remote_دلائل, "-%c", ch);
			addargs(&remote_remote_دلائل, "%s", optarg);
			addargs(&دلائل, "-%c", ch);
			addargs(&دلائل, "%s", optarg);
			توڑو;
		حالت 'O':
			منوال = منوال_SCP;
			توڑو;
		حالت 's':
			/* Ignored */
			توڑو;
		حالت 'P':
			sshport = a2port(optarg);
			اگر (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			توڑو;
		حالت 'B':
			addargs(&remote_remote_دلائل, "-oBatchmode=yes");
			addargs(&دلائل, "-oBatchmode=yes");
			توڑو;
		حالت 'l':
			حد_بندی_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			اگر (errstr != تہی)
				usage();
			حد_بندی_kbps *= 1024; /* kbps */
			bandwidth_حد_بندی_init(&bwlimit, حد_بندی_kbps, COPY_BUFLEN);
			توڑو;
		حالت 'p':
			pflag = 1;
			توڑو;
		حالت 'r':
			iamrecursive = 1;
			توڑو;
		حالت 'S':
			ssh_پروگرام = xstrdup(optarg);
			توڑو;
		حالت 'v':
			addargs(&دلائل, "-v");
			addargs(&remote_remote_دلائل, "-v");
			اگر (verbose_منوال == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			ورنہ اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_منوال = 1;
			توڑو;
		حالت 'q':
			addargs(&دلائل, "-q");
			addargs(&remote_remote_دلائل, "-q");
			showprogress = 0;
			توڑو;
		حالت 'X':
			/* Please keep in sync with sftp.c -X */
			اگر (لڑی_موازنہ(optarg, "buffer=", 7) == 0) {
				r = جائزہ_scaled(optarg + 7, &llv);
				اگر (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				اگر (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (سائز_t)llv;
			} ورنہ اگر (لڑی_موازنہ(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				اگر (errstr != تہی) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (سائز_t)llv;
			} ورنہ {
				fatal("Invalid -X option");
			}
			توڑو;

		/* Server options. */
		حالت 'd':
			targetshouldbedirectory = 1;
			توڑو;
		حالت 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			توڑو;
		حالت 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#اگر_تعریف_شدہ HAVE_CYGWIN
			setmode(0, O_ثنائی);
#اگر_ختم
			توڑو;
		حالت 'T':
			Tflag = 1;
			توڑو;
		طےشدہ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&دلائل, "-oForwardAgent=no");

	اگر (iamremote)
		منوال = منوال_SCP;

	اگر ((pwd = getpwuid(userid = getuid())) == تہی)
		fatal("unknown user %u", (u_int) userid);

	اگر (!isatty(STDOUT_FILENO))
		showprogress = 0;

	اگر (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} ورنہ {
		اگر (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    تہی) == -1) {
			perror("pledge");
			باہر_نکلو(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	اگر (fflag) {
		/* Follow "protocol", send data. */
		(خالی) response();
		ماخذ(argc, argv);
		باہر_نکلو(errs != 0);
	}
	اگر (tflag) {
		/* Receive data. */
		sink(argc, argv, تہی);
		باہر_نکلو(errs != 0);
	}
	اگر (argc < 2)
		usage();
	اگر (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(خالی) snprintf(cmd, حجم cmd, "scp%s%s%s%s",
	    verbose_منوال ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(خالی) ssh_signal(SIGPIPE, lostconn);

	اگر (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, منوال, sftp_براہ_راست);
	ورنہ {
		اگر (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, منوال, sftp_براہ_راست);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	اگر (do_cmd_pid != -1 && (منوال == منوال_SFTP || errs == 0)) {
		اگر (remin != -1)
		    (خالی) close(remin);
		اگر (remout != -1)
		    (خالی) close(remout);
		اگر (waitpid(do_cmd_pid, &حالت_2, 0) == -1)
			errs = 1;
		ورنہ {
			اگر (!WIFEXITED(حالت_2) || WEXITSTATUS(حالت_2) != 0)
				errs = 1;
		}
	}
	باہر_نکلو(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ساکن صحیح
scpio(خالی *_cnt, سائز_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_پیش_رفت_meter(0);
	اگر (حد_بندی_kbps > 0)
		bandwidth_حد_بندی(&bwlimit, s);
	واپس 0;
}

ساکن صحیح
do_times(صحیح fd, صحیح verb, ثابت ساخت stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	حرف buf[(20 + 7 + 2) * 2 + 2];

	(خالی)snprintf(buf, حجم(buf), "T%llu 0 %llu 0\n",
	    (غیرعلامتی طویل طویل) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (غیرعلامتی طویل طویل) (sb->st_atime < 0 ? 0 : sb->st_atime));
	اگر (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (طویل طویل)sb->st_mtime, (طویل طویل)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(خالی) atomicio(vwrite, fd, buf, لڑی_لمبائی(buf));
	واپس (response());
}

ساکن صحیح
parse_scp_uri(ثابت حرف *uri, حرف **userp, حرف **hostp, صحیح *portp,
    حرف **pathp)
{
	صحیح r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	اگر (r == 0 && *pathp == تہی)
		*pathp = xstrdup(".");
	واپس r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
ساکن صحیح
append(حرف *cp, حرف ***ap, سائز_t *np)
{
	حرف **tmp;

	اگر ((tmp = reallocarray(*ap, *np + 1, حجم(*tmp))) == تہی)
		واپس -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	واپس 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
ساکن صحیح
ڈھونڈو_brace(ثابت حرف *نمونہ, صحیح *startp, صحیح *endp)
{
	صحیح i;
	صحیح اندر_bracket, brace_level;

	*startp = *endp = -1;
	اندر_bracket = brace_level = 0;
	برائے (i = 0; i < زیادہ_سے_زیادہ_عدد && *endp < 0 && نمونہ[i] != '\0'; i++) {
		انتخاب (نمونہ[i]) {
		حالت '\\':
			/* skip next character */
			اگر (نمونہ[i + 1] != '\0')
				i++;
			توڑو;
		حالت '[':
			اندر_bracket = 1;
			توڑو;
		حالت ']':
			اندر_bracket = 0;
			توڑو;
		حالت '{':
			اگر (اندر_bracket)
				توڑو;
			اگر (نمونہ[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				توڑو;
			}
			اگر (*startp == -1)
				*startp = i;
			brace_level++;
			توڑو;
		حالت '}':
			اگر (اندر_bracket)
				توڑو;
			اگر (*startp < 0) {
				/* Unbalanced brace */
				واپس -1;
			}
			اگر (--brace_level <= 0)
				*endp = i;
			توڑو;
		}
	}
	/* unbalanced brackets/braces */
	اگر (*endp < 0 && (*startp >= 0 || اندر_bracket))
		واپس -1;
	واپس 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ساکن صحیح
emit_expansion(ثابت حرف *نمونہ, صحیح brace_آغاز, صحیح brace_انتہا,
    صحیح sel_آغاز, صحیح sel_انتہا, حرف ***patternsp, سائز_t *npatternsp)
{
	حرف *cp;
	سائز_t نمونہ_len;
	صحیح o = 0, دم_len;

	اگر ((نمونہ_len = لڑی_لمبائی(نمونہ)) == 0 || نمونہ_len >= زیادہ_سے_زیادہ_عدد)
		واپس -1;

	دم_len = لڑی_لمبائی(نمونہ + brace_انتہا + 1);
	اگر ((cp = حافظہ_دو(brace_آغاز + (sel_انتہا - sel_آغاز) +
	    دم_len + 1)) == تہی)
		واپس -1;

	/* Pattern before initial brace */
	اگر (brace_آغاز > 0) {
		حافظہ_نقل(cp, نمونہ, brace_آغاز);
		o = brace_آغاز;
	}
	/* Current braced selection */
	اگر (sel_انتہا - sel_آغاز > 0) {
		حافظہ_نقل(cp + o, نمونہ + sel_آغاز,
		    sel_انتہا - sel_آغاز);
		o += sel_انتہا - sel_آغاز;
	}
	/* Remainder of pattern after closing brace */
	اگر (دم_len > 0) {
		حافظہ_نقل(cp + o, نمونہ + brace_انتہا + 1, دم_len);
		o += دم_len;
	}
	cp[o] = '\0';
	اگر (append(cp, patternsp, npatternsp) != 0) {
		آزاد(cp);
		واپس -1;
	}
	واپس 0;
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
ساکن صحیح
brace_expand_one(ثابت حرف *نمونہ, حرف ***patternsp, سائز_t *npatternsp,
    صحیح *expanded, صحیح *invalid)
{
	صحیح i;
	صحیح اندر_bracket, brace_آغاز, brace_انتہا, brace_level;
	صحیح sel_آغاز, sel_انتہا;

	*invalid = *expanded = 0;

	اگر (ڈھونڈو_brace(نمونہ, &brace_آغاز, &brace_انتہا) != 0) {
		*invalid = 1;
		واپس 0;
	} ورنہ اگر (brace_آغاز == -1)
		واپس 0;

	اندر_bracket = brace_level = 0;
	برائے (i = sel_آغاز = brace_آغاز + 1; i < brace_انتہا; i++) {
		انتخاب (نمونہ[i]) {
		حالت '{':
			اگر (اندر_bracket)
				توڑو;
			brace_level++;
			توڑو;
		حالت '}':
			اگر (اندر_bracket)
				توڑو;
			brace_level--;
			توڑو;
		حالت '[':
			اندر_bracket = 1;
			توڑو;
		حالت ']':
			اندر_bracket = 0;
			توڑو;
		حالت '\\':
			اگر (i < brace_انتہا - 1)
				i++; /* skip */
			توڑو;
		}
		اگر (نمونہ[i] == ',' || i == brace_انتہا - 1) {
			اگر (اندر_bracket || brace_level > 0)
				جاری;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_انتہا = (i == brace_انتہا - 1) ? brace_انتہا : i;
			اگر (emit_expansion(نمونہ, brace_آغاز, brace_انتہا,
			    sel_آغاز, sel_انتہا, patternsp, npatternsp) != 0)
				واپس -1;
			/* move on to the next selection */
			sel_آغاز = i + 1;
			جاری;
		}
	}
	اگر (اندر_bracket || brace_level > 0) {
		*invalid = 1;
		واپس 0;
	}
	/* success */
	*expanded = 1;
	واپس 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ساکن صحیح
brace_expand(ثابت حرف *نمونہ, حرف ***patternsp, سائز_t *npatternsp)
{
	حرف *cp, *cp2, **فعال = تہی, **مکمل = تہی;
	سائز_t i, nactive = 0, ndone = 0;
	صحیح ret = -1, invalid = 0, expanded = 0;

	*patternsp = تہی;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	اگر ((cp = strdup(نمونہ)) == تہی)
		واپس -1;
	اگر (append(cp, &فعال, &nactive) != 0) {
		آزاد(cp);
		واپس -1;
	}
	جب (nactive > 0) {
		cp = فعال[nactive - 1];
		nactive--;
		اگر (brace_expand_one(cp, &فعال, &nactive,
		    &expanded, &invalid) == -1) {
			آزاد(cp);
			جاؤ fail;
		}
		اگر (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		اگر (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			آزاد(cp);
			جاری;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		اگر ((cp2 = strrchr(cp, '/')) != تہی)
			*cp2++ = '\0';
		ورنہ
			cp2 = cp;
		اگر (append(xstrdup(cp2), &مکمل, &ndone) != 0) {
			آزاد(cp);
			جاؤ fail;
		}
		آزاد(cp);
	}
	/* success */
	*patternsp = مکمل;
	*npatternsp = ndone;
	مکمل = تہی;
	ndone = 0;
	ret = 0;
 fail:
	برائے (i = 0; i < nactive; i++)
		آزاد(فعال[i]);
	آزاد(فعال);
	برائے (i = 0; i < ndone; i++)
		آزاد(مکمل[i]);
	آزاد(مکمل);
	واپس ret;
}

ساکن ساخت sftp_conn *
do_sftp_connect(حرف *host, حرف *user, صحیح پورٹ, حرف *sftp_براہ_راست,
   صحیح *reminp, صحیح *remoutp, صحیح *pidp)
{
	اگر (sftp_براہ_راست == تہی) {
		اگر (do_cmd(ssh_پروگرام, host, user, پورٹ, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			واپس تہی;

	} ورنہ {
		freeargs(&دلائل);
		addargs(&دلائل, "sftp-server");
		اگر (do_cmd(sftp_براہ_راست, host, تہی, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			واپس تہی;
	}
	واپس sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, حد_بندی_kbps);
}

خالی
toremote(صحیح argc, حرف **argv, شمار scp_منوال_e منوال, حرف *sftp_براہ_راست)
{
	حرف *suser = تہی, *host = تہی, *src = تہی;
	حرف *bp, *tuser, *thost, *targ;
	صحیح sport = -1, tport = -1;
	ساخت sftp_conn *conn = تہی, *conn2 = تہی;
	arglist alist;
	صحیح i, r, حالت_2;
	ساخت stat sb;
	u_int j;

	memset(&alist, '\0', حجم(alist));
	alist.list = تہی;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	اگر (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		جاؤ برآمد;
	}
	اگر (r != 0) {
		اگر (parse_user_host_راستہ(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			جاؤ برآمد;
		}
	}

	/* Parse source files */
	برائے (i = 0; i < argc - 1; i++) {
		آزاد(suser);
		آزاد(host);
		آزاد(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		اگر (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			جاری;
		}
		اگر (r != 0) {
			parse_user_host_راستہ(argv[i], &suser, &host, &src);
		}
		اگر (suser != تہی && !okname(suser)) {
			++errs;
			جاری;
		}
		اگر (host && throughlocal) {	/* extended remote to remote */
			اگر (منوال == منوال_SFTP) {
				اگر (remin == -1 || conn == تہی) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_براہ_راست,
					    &remin, &remout, &do_cmd_pid);
					اگر (conn == تہی) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (طویل)do_cmd_pid);
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
				    sport, sftp_براہ_راست,
				    &remin2, &remout2, &do_cmd_pid2);
				اگر (conn2 == تہی) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (طویل)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(خالی) close(remin2);
				(خالی) close(remout2);
				remin2 = remout2 = -1;
				اگر (waitpid(do_cmd_pid2, &حالت_2, 0) == -1)
					++errs;
				ورنہ اگر (!WIFEXITED(حالت_2) ||
				    WEXITSTATUS(حالت_2) != 0)
					++errs;
				do_cmd_pid2 = -1;
				جاری;
			} ورنہ {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				اگر (do_cmd(ssh_پروگرام, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					باہر_نکلو(1);
				آزاد(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				اگر (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					باہر_نکلو(1);
				آزاد(bp);
				(خالی) close(remin);
				(خالی) close(remout);
				remin = remout = -1;
			}
		} ورنہ اگر (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			اگر (tuser != تہی && !okname(tuser)) {
				++errs;
				جاری;
			}
			اگر (tport != -1 && tport != SSH_DEFAULT_پورٹ) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_پروگرام);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			برائے (j = 0; j < remote_remote_دلائل.عدد; j++) {
				addargs(&alist, "%s",
				    remote_remote_دلائل.list[j]);
			}

			اگر (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			اگر (suser) {
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
			اگر (do_local_cmd(&alist) != 0)
				errs = 1;
		} ورنہ {	/* local to remote */
			اگر (منوال == منوال_SFTP) {
				/* no need to glob: already done by shell */
				اگر (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				اگر (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_براہ_راست,
					    &remin, &remout, &do_cmd_pid);
					اگر (conn == تہی) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				ماخذ_sftp(1, argv[i], targ, conn);
				جاری;
			}
			/* SCP */
			اگر (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				اگر (do_cmd(ssh_پروگرام, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					باہر_نکلو(1);
				اگر (response() < 0)
					باہر_نکلو(1);
				آزاد(bp);
			}
			ماخذ(1, argv + i);
		}
	}
برآمد:
	freeargs(&alist);
	آزاد(tuser);
	آزاد(thost);
	آزاد(targ);
	آزاد(suser);
	آزاد(host);
	آزاد(src);
	sftp_free(conn);
	sftp_free(conn2);
}

خالی
tolocal(صحیح argc, حرف **argv, شمار scp_منوال_e منوال, حرف *sftp_براہ_راست)
{
	حرف *bp, *host = تہی, *src = تہی, *suser = تہی;
	arglist alist;
	ساخت sftp_conn *conn = تہی;
	صحیح i, r, sport = -1;

	memset(&alist, '\0', حجم(alist));
	alist.list = تہی;

	برائے (i = 0; i < argc - 1; i++) {
		آزاد(suser);
		آزاد(host);
		آزاد(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		اگر (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			جاری;
		}
		اگر (r != 0)
			parse_user_host_راستہ(argv[i], &suser, &host, &src);
		اگر (suser != تہی && !okname(suser)) {
			++errs;
			جاری;
		}
		اگر (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", راستہ_CP);
			اگر (iamrecursive)
				addargs(&alist, "-r");
			اگر (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			اگر (do_local_cmd(&alist))
				++errs;
			جاری;
		}
		/* Remote to local. */
		اگر (منوال == منوال_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_براہ_راست, &remin, &remout, &do_cmd_pid);
			اگر (conn == تہی) {
				error("sftp connection failed");
				++errs;
				جاری;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(خالی) close(remin);
			(خالی) close(remout);
			remin = remout = -1;
			جاری;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		اگر (do_cmd(ssh_پروگرام, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			آزاد(bp);
			++errs;
			جاری;
		}
		آزاد(bp);
		sink(1, argv + argc - 1, src);
		(خالی) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	آزاد(suser);
	آزاد(host);
	آزاد(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
ساکن حرف *
prepare_remote_راستہ(ساخت sftp_conn *conn, ثابت حرف *راستہ)
{
	سائز_t nslash;

	/* Handle ~ prefixed paths */
	اگر (*راستہ == '\0' || strcmp(راستہ, "~") == 0)
		واپس xstrdup(".");
	اگر (*راستہ != '~')
		واپس xstrdup(راستہ);
	اگر (لڑی_موازنہ(راستہ, "~/", 2) == 0) {
		اگر ((nslash = strspn(راستہ + 2, "/")) == لڑی_لمبائی(راستہ + 2))
			واپس xstrdup(".");
		واپس xstrdup(راستہ + 2 + nslash);
	}
	اگر (sftp_can_expand_راستہ(conn))
		واپس sftp_expand_راستہ(conn, راستہ);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	واپس تہی;
}

خالی
ماخذ_sftp(صحیح argc, حرف *src, حرف *targ, ساخت sftp_conn *conn)
{
	حرف *ہدف = تہی, *filename = تہی, *abs_dst = تہی;
	صحیح src_is_dir, ہدف_is_dir;
	Attrib a;
	ساخت stat st;

	memset(&a, '\0', حجم(a));
	اگر (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	اگر ((filename = basename(src)) == تہی)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	اگر (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	اگر ((ہدف = prepare_remote_راستہ(conn, targ)) == تہی)
		cleanup_exit(255);
	ہدف_is_dir = sftp_remote_is_dir(conn, ہدف);
	اگر (targetshouldbedirectory && !ہدف_is_dir) {
		debug("target directory \"%s\" does not exist", ہدف);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		اگر (sftp_mkdir(conn, ہدف, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		ہدف_is_dir = 1;
	}
	اگر (ہدف_is_dir)
		abs_dst = sftp_راستہ_append(ہدف, filename);
	ورنہ {
		abs_dst = ہدف;
		ہدف = تہی;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	اگر (src_is_dir && iamrecursive) {
		اگر (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_پیش_رفت_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} ورنہ اگر (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	آزاد(abs_dst);
	آزاد(ہدف);
}

خالی
ماخذ(صحیح argc, حرف **argv)
{
	ساخت stat stb;
	ساکن BUF بفر;
	BUF *bp;
	off_t i, statbytes;
	سائز_t amt, nr;
	صحیح fd = -1, haderr, indx;
	حرف *آخری, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	صحیح len;

	برائے (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = لڑی_لمبائی(name);
		جب (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		اگر ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			جاؤ syserr;
		اگر (strchr(name, '\n') != تہی) {
			strnvis(encname, name, حجم(encname), VIS_NL);
			name = encname;
		}
		اگر (fstat(fd, &stb) == -1) {
syserr:			تسلسل_err("%s: %s", name, strerror(errno));
			جاؤ اگلا;
		}
		اگر (stb.st_size < 0) {
			تسلسل_err("%s: %s", name, "Negative file size");
			جاؤ اگلا;
		}
		unset_nonblock(fd);
		انتخاب (stb.st_mode & S_IFMT) {
		حالت S_IFREG:
			توڑو;
		حالت S_IFDIR:
			اگر (iamrecursive) {
				rsource(name, &stb);
				جاؤ اگلا;
			}
			/* FALLTHROUGH */
		طےشدہ:
			تسلسل_err("%s: not a regular file", name);
			جاؤ اگلا;
		}
		اگر ((آخری = strrchr(name, '/')) == تہی)
			آخری = name;
		ورنہ
			++آخری;
		curfile = آخری;
		اگر (pflag) {
			اگر (do_times(remout, verbose_منوال, &stb) < 0)
				جاؤ اگلا;
		}
#تعریف_کرو	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, حجم buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (طویل طویل)stb.st_size, آخری);
		اگر (verbose_منوال)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(خالی) atomicio(vwrite, remout, buf, لڑی_لمبائی(buf));
		اگر (response() < 0)
			جاؤ اگلا;
		اگر ((bp = allocbuf(&بفر, fd, COPY_BUFLEN)) == تہی) {
اگلا:			اگر (fd != -1) {
				(خالی) close(fd);
				fd = -1;
			}
			جاری;
		}
		اگر (showprogress)
			آغاز_پیش_رفت_meter(curfile, stb.st_size, &statbytes);
		سیٹ_nonblock(remout);
		برائے (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			اگر (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			اگر (!haderr) {
				اگر ((nr = atomicio(اقرأ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			اگر (haderr) {
				(خالی)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				جاری;
			}
			اگر (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		اگر (fd != -1) {
			اگر (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		اگر (!haderr)
			(خالی) atomicio(vwrite, remout, "", 1);
		ورنہ
			تسلسل_err("%s: %s", name, strerror(haderr));
		(خالی) response();
		اگر (showprogress)
			stop_پیش_رفت_meter();
	}
}

خالی
rsource(حرف *name, ساخت stat *statp)
{
	DIR *dirp;
	ساخت dirent *dp;
	حرف *آخری, *vect[1], راستہ[PATH_MAX];

	اگر (!(dirp = opendir(name))) {
		تسلسل_err("%s: %s", name, strerror(errno));
		واپس;
	}
	آخری = strrchr(name, '/');
	اگر (آخری == تہی)
		آخری = name;
	ورنہ
		آخری++;
	اگر (pflag) {
		اگر (do_times(remout, verbose_منوال, statp) < 0) {
			closedir(dirp);
			واپس;
		}
	}
	(خالی) snprintf(راستہ, حجم راستہ, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, آخری);
	اگر (verbose_منوال)
		fmprintf(stderr, "Entering directory: %s", راستہ);
	(خالی) atomicio(vwrite, remout, راستہ, لڑی_لمبائی(راستہ));
	اگر (response() < 0) {
		closedir(dirp);
		واپس;
	}
	جب ((dp = readdir(dirp)) != تہی) {
		اگر (dp->d_ino == 0)
			جاری;
		اگر (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			جاری;
		اگر (لڑی_لمبائی(name) + 1 + لڑی_لمبائی(dp->d_name) >= حجم(راستہ) - 1) {
			تسلسل_err("%s/%s: name too long", name, dp->d_name);
			جاری;
		}
		(خالی) snprintf(راستہ, حجم راستہ, "%s/%s", name, dp->d_name);
		vect[0] = راستہ;
		ماخذ(1, vect);
	}
	(خالی) closedir(dirp);
	(خالی) atomicio(vwrite, remout, "E\n", 2);
	(خالی) response();
}

خالی
sink_sftp(صحیح argc, حرف *dst, ثابت حرف *src, ساخت sftp_conn *conn)
{
	حرف *abs_src = تہی;
	حرف *abs_dst = تہی;
	glob_t g;
	حرف *filename, *tmp = تہی;
	صحیح i, r, err = 0, dst_is_dir;
	ساخت stat st;

	memset(&g, 0, حجم(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	اگر ((abs_src = prepare_remote_راستہ(conn, src)) == تہی) {
		err = -1;
		جاؤ برآمد;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	اگر ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    تہی, &g)) != 0) {
		اگر (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ورنہ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		جاؤ برآمد;
	}

	/* Did we actually get any matches back from the glob? */
	اگر (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != تہی) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		اگر (sftp_stat(conn, g.gl_pathv[0], 1, تہی) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			جاؤ برآمد;
		}
	}

	اگر ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	اگر (g.gl_matchc > 1 && !dst_is_dir) {
		اگر (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			جاؤ برآمد;
		}
		debug2_f("creating destination \"%s\"", dst);
		اگر (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			جاؤ برآمد;
		}
		dst_is_dir = 1;
	}

	برائے (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == تہی) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			جاؤ برآمد;
		}

		/* Special handling for destination of '..' */
		اگر (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		اگر (dst_is_dir)
			abs_dst = sftp_راستہ_append(dst, filename);
		ورنہ
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			اگر (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    تہی, pflag, SFTP_پیش_رفت_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} ورنہ {
			اگر (sftp_download(conn, g.gl_pathv[i], abs_dst, تہی,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		آزاد(abs_dst);
		abs_dst = تہی;
		آزاد(tmp);
		tmp = تہی;
	}

برآمد:
	آزاد(abs_src);
	آزاد(tmp);
	globfree(&g);
	اگر (err == -1)
		errs = 1;
}


#تعریف_کرو TYPE_حد_سے_تجاوز(type, val) \
	((حجم(type) == 4 && (val) > INT32_MAX) || \
	 (حجم(type) == 8 && (val) > INT64_MAX) || \
	 (حجم(type) != 4 && حجم(type) != 8))

خالی
sink(صحیح argc, حرف **argv, ثابت حرف *src)
{
	ساکن BUF بفر;
	ساخت stat stb;
	BUF *bp;
	off_t i;
	سائز_t j, گنتی;
	صحیح amt, exists, پہلا, ofd;
	منوال_t منوال, omode, نقاب;
	off_t سائز, statbytes;
	غیرعلامتی طویل طویل ull;
	صحیح setimes, targisdir, wrerr;
	حرف ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	حرف **patterns = تہی;
	سائز_t n, npatterns = 0;
	ساخت timeval tv[2];

#تعریف_کرو	atime	tv[0]
#تعریف_کرو	mtime	tv[1]
#تعریف_کرو	SCREWUP(str)	{ why = str; جاؤ screwup; }

	اگر (TYPE_حد_سے_تجاوز(time_t, 0) || TYPE_حد_سے_تجاوز(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	نقاب = umask(0);
	اگر (!pflag) {
		(خالی) umask(نقاب);
		نقاب |= 07000;
	}
	اگر (argc != 1) {
		تسلسل_err("ambiguous target");
		باہر_نکلو(1);
	}
	targ = *argv;
	اگر (targetshouldbedirectory)
		verifydir(targ);

	(خالی) atomicio(vwrite, remout, "", 1);
	اگر (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	اگر (src != تہی && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		اگر (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	برائے (پہلا = 1;; پہلا = 0) {
		cp = buf;
		اگر (atomicio(اقرأ, remin, cp, 1) != 1)
			جاؤ مکمل;
		اگر (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		کرو {
			اگر (atomicio(اقرأ, remin, &ch, حجم(ch)) != حجم(ch))
				SCREWUP("lost connection");
			اگر (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} جب (cp < &buf[حجم(buf) - 1] && ch != '\n');
		*cp = 0;
		اگر (verbose_منوال)
			fmprintf(stderr, "Sink: %s", buf);

		اگر (buf[0] == '\01' || buf[0] == '\02') {
			اگر (iamremote == 0) {
				(خالی) snmprintf(visbuf, حجم(visbuf),
				    تہی, "%s", buf + 1);
				(خالی) atomicio(vwrite, STDERR_FILENO,
				    visbuf, لڑی_لمبائی(visbuf));
			}
			اگر (buf[0] == '\02')
				باہر_نکلو(1);
			++errs;
			جاری;
		}
		اگر (buf[0] == 'E') {
			(خالی) atomicio(vwrite, remout, "", 1);
			جاؤ مکمل;
		}
		اگر (ch == '\n')
			*--cp = 0;

		cp = buf;
		اگر (*cp == 'T') {
			setimes++;
			cp++;
			اگر (!ہندسہ_ہے((غیرعلامتی حرف)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			اگر (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			اگر (TYPE_حد_سے_تجاوز(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			اگر (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			اگر (!ہندسہ_ہے((غیرعلامتی حرف)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			اگر (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			اگر (TYPE_حد_سے_تجاوز(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			اگر (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(خالی) atomicio(vwrite, remout, "", 1);
			جاری;
		}
		اگر (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			اگر (پہلا) {
				تسلسل_err("%s", cp);
				باہر_نکلو(1);
			}
			SCREWUP("expected control record");
		}
		منوال = 0;
		برائے (++cp; cp < buf + 5; cp++) {
			اگر (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			منوال = (منوال << 3) | (*cp - '0');
		}
		اگر (!pflag)
			منوال &= ~نقاب;
		اگر (*cp++ != ' ')
			SCREWUP("mode not delimited");

		اگر (!ہندسہ_ہے((غیرعلامتی حرف)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		اگر (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		اگر (TYPE_حد_سے_تجاوز(off_t, ull))
			SCREWUP("size out of range");
		سائز = (off_t)ull;

		اگر (*cp == '\0' || strchr(cp, '/') != تہی ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			تسلسل_err("error: unexpected filename: %s", cp);
			باہر_نکلو(1);
		}
		اگر (npatterns > 0) {
			برائے (n = 0; n < npatterns; n++) {
				اگر (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					توڑو;
			}
			اگر (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				برائے (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		اگر (targisdir) {
			ساکن حرف *namebuf;
			ساکن سائز_t cursize;
			سائز_t need;

			need = لڑی_لمبائی(targ) + لڑی_لمبائی(cp) + 250;
			اگر (need > cursize) {
				آزاد(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(خالی) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} ورنہ
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		اگر (buf[0] == 'D') {
			صحیح mod_flag = pflag;
			اگر (!iamrecursive)
				SCREWUP("received directory without -r");
			اگر (exists) {
				اگر (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					جاؤ bad;
				}
				اگر (pflag)
					(خالی) chmod(np, منوال);
			} ورنہ {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				اگر (mkdir(np, منوال | S_IRWXU) == -1)
					جاؤ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			اگر (setimes) {
				setimes = 0;
				(خالی) utimes(vect[0], tv);
			}
			اگر (mod_flag)
				(خالی) chmod(vect[0], منوال);
			آزاد(vect[0]);
			جاری;
		}
		omode = منوال;
		منوال |= S_IWUSR;
		اگر ((ofd = open(np, O_WRONLY|O_CREAT, منوال)) == -1) {
bad:			تسلسل_err("%s: %s", np, strerror(errno));
			جاری;
		}
		(خالی) atomicio(vwrite, remout, "", 1);
		اگر ((bp = allocbuf(&بفر, ofd, COPY_BUFLEN)) == تہی) {
			(خالی) close(ofd);
			جاری;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		اگر (showprogress)
			آغاز_پیش_رفت_meter(curfile, سائز, &statbytes);
		سیٹ_nonblock(remin);
		برائے (گنتی = i = 0; i < سائز; i += bp->cnt) {
			amt = bp->cnt;
			اگر (i + amt > سائز)
				amt = سائز - i;
			گنتی += amt;
			کرو {
				j = atomicio6(اقرأ, remin, cp, amt,
				    scpio, &statbytes);
				اگر (j == 0) {
					تسلسل_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					باہر_نکلو(1);
				}
				amt -= j;
				cp += j;
			} جب (amt > 0);

			اگر (گنتی == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				اگر (!wrerr) {
					اگر (atomicio(vwrite, ofd, bp->buf,
					    گنتی) != گنتی) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				گنتی = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		اگر (گنتی != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, گنتی) != گنتی) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		اگر (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, سائز) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		اگر (pflag) {
			اگر (exists || omode != منوال)
#اگر_تعریف_شدہ HAVE_FCHMOD
				اگر (fchmod(ofd, omode)) {
#ورنہ /* HAVE_FCHMOD */
				اگر (chmod(np, omode)) {
#اگر_ختم /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} ورنہ {
			اگر (!exists && omode != منوال)
#اگر_تعریف_شدہ HAVE_FCHMOD
				اگر (fchmod(ofd, omode & ~نقاب)) {
#ورنہ /* HAVE_FCHMOD */
				اگر (chmod(np, omode & ~نقاب)) {
#اگر_ختم /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		اگر (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(خالی) response();
		اگر (showprogress)
			stop_پیش_رفت_meter();
		اگر (setimes && !wrerr) {
			setimes = 0;
			اگر (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		اگر (note_err(تہی) == 0)
			(خالی) atomicio(vwrite, remout, "", 1);
	}
مکمل:
	برائے (n = 0; n < npatterns; n++)
		آزاد(patterns[n]);
	آزاد(patterns);
	واپس;
screwup:
	برائے (n = 0; n < npatterns; n++)
		آزاد(patterns[n]);
	آزاد(patterns);
	تسلسل_err("protocol error: %s", why);
	باہر_نکلو(1);
}

خالی
throughlocal_sftp(ساخت sftp_conn *from, ساخت sftp_conn *مقصد,
    حرف *src, حرف *targ)
{
	حرف *ہدف = تہی, *filename = تہی, *abs_dst = تہی;
	حرف *abs_src = تہی, *tmp = تہی;
	glob_t g;
	صحیح i, r, targetisdir, err = 0;

	اگر ((filename = basename(src)) == تہی)
		fatal("basename %s: %s", src, strerror(errno));

	اگر ((abs_src = prepare_remote_راستہ(from, src)) == تہی ||
	    (ہدف = prepare_remote_راستہ(مقصد, targ)) == تہی)
		cleanup_exit(255);
	memset(&g, 0, حجم(g));

	targetisdir = sftp_remote_is_dir(مقصد, ہدف);
	اگر (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		جاؤ برآمد;
	}

	debug3_f("copying remote %s to remote %s", abs_src, ہدف);
	اگر ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    تہی, &g)) != 0) {
		اگر (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		ورنہ
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		جاؤ برآمد;
	}

	/* Did we actually get any matches back from the glob? */
	اگر (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != تہی) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		اگر (sftp_stat(from, g.gl_pathv[0], 1, تہی) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			جاؤ برآمد;
		}
	}

	برائے (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == تہی) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			جاؤ برآمد;
		}

		/* Special handling for source of '..' */
		اگر (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		اگر (targetisdir)
			abs_dst = sftp_راستہ_append(ہدف, filename);
		ورنہ
			abs_dst = xstrdup(ہدف);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			اگر (sftp_crossload_dir(from, مقصد, g.gl_pathv[i], abs_dst,
			    تہی, pflag, SFTP_پیش_رفت_ONLY, 1) == -1)
				err = -1;
		} ورنہ {
			اگر (sftp_crossload(from, مقصد, g.gl_pathv[i], abs_dst,
			    تہی, pflag) == -1)
				err = -1;
		}
		آزاد(abs_dst);
		abs_dst = تہی;
		آزاد(tmp);
		tmp = تہی;
	}

برآمد:
	آزاد(abs_src);
	آزاد(abs_dst);
	آزاد(ہدف);
	آزاد(tmp);
	globfree(&g);
	اگر (err == -1)
		errs = 1;
}

صحیح
response(خالی)
{
	حرف ch, *cp, resp, rbuf[2048], visbuf[2048];

	اگر (atomicio(اقرأ, remin, &resp, حجم(resp)) != حجم(resp))
		lostconn(0);

	cp = rbuf;
	انتخاب (resp) {
	حالت 0:		/* ok */
		واپس (0);
	طےشدہ:
		*cp++ = resp;
		/* FALLTHROUGH */
	حالت 1:		/* error, followed by error msg */
	حالت 2:		/* fatal error, "" */
		کرو {
			اگر (atomicio(اقرأ, remin, &ch, حجم(ch)) != حجم(ch))
				lostconn(0);
			*cp++ = ch;
		} جب (cp < &rbuf[حجم(rbuf) - 1] && ch != '\n');

		اگر (!iamremote) {
			cp[-1] = '\0';
			(خالی) snmprintf(visbuf, حجم(visbuf),
			    تہی, "%s\n", rbuf);
			(خالی) atomicio(vwrite, STDERR_FILENO,
			    visbuf, لڑی_لمبائی(visbuf));
		}
		++errs;
		اگر (resp == 1)
			واپس (-1);
		باہر_نکلو(1);
	}
	/* NOTREACHED */
}

خالی
usage(خالی)
{
	(خالی) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	باہر_نکلو(1);
}

خالی
تسلسل_err(ثابت حرف *fmt,...)
{
	ساکن FILE *fp;
	va_list ap;

	++errs;
	اگر (fp != تہی || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(خالی) fprintf(fp, "%c", 0x01);
		(خالی) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(خالی) vfprintf(fp, fmt, ap);
		va_end(ap);
		(خالی) fprintf(fp, "\n");
		(خالی) fflush(fp);
	}

	اگر (!iamremote) {
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
صحیح
note_err(ثابت حرف *fmt, ...)
{
	ساکن حرف *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	اگر (fmt == تہی) {
		اگر (emsg == تہی)
			واپس 0;
		تسلسل_err("%s", emsg);
		آزاد(emsg);
		emsg = تہی;
		واپس -1;
	}

	errs++;
	/* Prefer first-noted error */
	اگر (emsg != تہی)
		واپس -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, زیادہ_سے_زیادہ_عدد, تہی, fmt, ap);
	va_end(ap);
	واپس -1;
}

خالی
verifydir(حرف *cp)
{
	ساخت stat stb;

	اگر (!stat(cp, &stb)) {
		اگر (S_ISDIR(stb.st_mode))
			واپس;
		errno = ENOTDIR;
	}
	تسلسل_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

صحیح
okname(حرف *cp0)
{
	صحیح c;
	حرف *cp;

	cp = cp0;
	کرو {
		c = (صحیح)*cp;
		اگر (c & 0200)
			جاؤ bad;
		اگر (!حرف_ہے(c) && !ہندسہ_ہے((غیرعلامتی حرف)c)) {
			انتخاب (c) {
			حالت '\'':
			حالت '"':
			حالت '`':
			حالت ' ':
			حالت '#':
				جاؤ bad;
			طےشدہ:
				توڑو;
			}
		}
	} جب (*++cp);
	واپس (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	واپس (0);
}

BUF *
allocbuf(BUF *bp, صحیح fd, صحیح blksize)
{
	سائز_t سائز;
#اگر_تعریف_شدہ HAVE_STRUCT_STAT_ST_BLKSIZE
	ساخت stat stb;

	اگر (fstat(fd, &stb) == -1) {
		تسلسل_err("fstat: %s", strerror(errno));
		واپس (تہی);
	}
	سائز = ROUNDUP(stb.st_blksize, blksize);
	اگر (سائز == 0)
		سائز = blksize;
#ورنہ /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	سائز = blksize;
#اگر_ختم /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	اگر (bp->cnt >= سائز)
		واپس (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, سائز, 1);
	bp->cnt = سائز;
	واپس (bp);
}

خالی
lostconn(صحیح signo)
{
	اگر (!iamremote)
		(خالی)اكتب(STDERR_FILENO, "lost connection\n", 16);
	اگر (signo)
		_exit(1);
	ورنہ
		باہر_نکلو(1);
}

خالی
cleanup_exit(صحیح i)
{
	اگر (remin > 0)
		close(remin);
	اگر (remout > 0)
		close(remout);
	اگر (remin2 > 0)
		close(remin2);
	اگر (remout2 > 0)
		close(remout2);
	اگر (do_cmd_pid > 0)
		(خالی)waitpid(do_cmd_pid, تہی, 0);
	اگر (do_cmd_pid2 > 0)
		(خالی)waitpid(do_cmd_pid2, تہی, 0);
	باہر_نکلو(i);
}
