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
#ifdef HAVE_FNMATCH_H
#شامل <fnmatch.h>
#endif
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
#endif

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

بیرونی نویسه *__progname;

#define COPY_BUFLEN	16384

صحیح do_cmd(نویسه *, نویسه *, نویسه *, صحیح, صحیح, نویسه *, صحیح *, صحیح *, pid_t *);
صحیح do_cmd2(نویسه *, نویسه *, صحیح, نویسه *, صحیح, صحیح);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
ساختار bwlimit bwlimit;

/* Name of current file being transferred. */
نویسه *curfile;

/* This is set to non-zero to enable verbose mode. */
صحیح verbose_mode = 0;
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
نویسه *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
فرار sig_atomic_t interrupted = 0;

صحیح sftp_glob(ساختار sftp_conn *, ثابت نویسه *, صحیح,
    صحیح (*)(ثابت نویسه *, صحیح), glob_t *); /* proto for sftp-glob.c */

ایستا تهی
killchild(صحیح signo)
{
	اگر (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(تهی)waitpid(do_cmd_pid, پوچ, 0);
	}
	اگر (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(تهی)waitpid(do_cmd_pid2, پوچ, 0);
	}

	اگر (signo)
		_exit(1);
	exit(1);
}

ایستا تهی
suspone(صحیح pid, صحیح signo)
{
	صحیح status;

	اگر (pid > 1) {
		kill(pid, signo);
		وقتی (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

ایستا تهی
suspchild(صحیح signo)
{
	صحیح save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ایستا صحیح
do_local_cmd(arglist *a)
{
	نویسه *cp;
	صحیح status;
	pid_t pid;

	اگر (a->رقم == 0)
		fatal("do_local_cmd: no arguments");

	اگر (verbose_mode) {
		cp = argv_assemble(a->رقم, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		آزاد(cp);
	}
	اگر ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	اگر (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	وقتی (waitpid(pid, &status, 0) == -1)
		اگر (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	اگر (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		بازگشت (-1);

	بازگشت (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

صحیح
do_cmd(نویسه *program, نویسه *host, نویسه *remuser, صحیح port, صحیح subsystem,
    نویسه *cmd, صحیح *fdin, صحیح *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	صحیح pin[2], pout[2];
#وگرنه
	صحیح sv[2];
#endif

	اگر (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	اگر (port == -1)
		port = sshport;

#ifdef USE_PIPES
	اگر (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#وگرنه
	/* Create a socket pair for communicating with ssh. */
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

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
#ifdef USE_PIPES
		اگر (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#وگرنه
		اگر (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		اگر (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		اگر (remuser != پوچ) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		اگر (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	پیشفرض:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#وگرنه
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		بازگشت 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
صحیح
do_cmd2(نویسه *host, نویسه *remuser, صحیح port, نویسه *cmd,
    صحیح fdin, صحیح fdout)
{
	صحیح status;
	pid_t pid;

	اگر (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	اگر (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	اگر (pid == 0) {
		اگر (dup2(fdin, 0) == -1)
			perror("dup2");
		اگر (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		اگر (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		اگر (remuser != پوچ) {
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
	} وگرنه اگر (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	وقتی (waitpid(pid, &status, 0) == -1)
		اگر (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	بازگشت 0;
}

تعریفنوع ساختار {
	size_t cnt;
	نویسه *buf;
} BUF;

BUF *allocbuf(BUF *, صحیح, صحیح);
تهی lostconn(صحیح);
صحیح okname(نویسه *);
تهی run_err(ثابت نویسه *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
صحیح note_err(ثابت نویسه *,...)
    __attribute__((__format__ (printf, 1, 2)));
تهی verifydir(نویسه *);

ساختار passwd *pwd;
uid_t userid;
صحیح errs, remin, remout, remin2, remout2;
صحیح Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
نویسه cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

شمارش scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

صحیح response(تهی);
تهی rsource(نویسه *, ساختار stat *);
تهی sink(صحیح, نویسه *[], ثابت نویسه *);
تهی source(صحیح, نویسه *[]);
تهی tolocal(صحیح, نویسه *[], شمارش scp_mode_e, نویسه *sftp_direct);
تهی toremote(صحیح, نویسه *[], شمارش scp_mode_e, نویسه *sftp_direct);
تهی usage(تهی);

تهی source_sftp(صحیح, نویسه *, نویسه *, ساختار sftp_conn *);
تهی sink_sftp(صحیح, نویسه *, ثابت نویسه *, ساختار sftp_conn *);
تهی throughlocal_sftp(ساختار sftp_conn *, ساختار sftp_conn *,
    نویسه *, نویسه *);

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	صحیح ch, fflag, tflag, status, r, n;
	نویسه **newargv, *argv0;
	ثابت نویسه *errstr;
	بیرونی نویسه *optarg;
	بیرونی صحیح optind;
	شمارش scp_mode_e mode = MODE_SFTP;
	نویسه *sftp_direct = پوچ;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), اندازه(*newargv));
	برای (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', اندازه(args));
	memset(&remote_remote_args, '\0', اندازه(remote_remote_args));
	args.list = remote_remote_args.list = پوچ;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	وقتی ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		انتخاب (ch) {
		/* User-visible flags. */
		حالت '1':
			fatal("SSH protocol v.1 is no longer supported");
			بشکن;
		حالت '2':
			/* Ignored */
			بشکن;
		حالت 'A':
		حالت '4':
		حالت '6':
		حالت 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			بشکن;
		حالت 'D':
			sftp_direct = optarg;
			بشکن;
		حالت '3':
			throughlocal = 1;
			بشکن;
		حالت 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			بشکن;
		حالت 'o':
		حالت 'c':
		حالت 'i':
		حالت 'F':
		حالت 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			بشکن;
		حالت 'O':
			mode = MODE_SCP;
			بشکن;
		حالت 's':
			/* Ignored */
			بشکن;
		حالت 'P':
			sshport = a2port(optarg);
			اگر (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			بشکن;
		حالت 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			بشکن;
		حالت 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			اگر (errstr != پوچ)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			بشکن;
		حالت 'p':
			pflag = 1;
			بشکن;
		حالت 'r':
			iamrecursive = 1;
			بشکن;
		حالت 'S':
			ssh_program = xstrdup(optarg);
			بشکن;
		حالت 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			اگر (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			وگرنه اگر (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			بشکن;
		حالت 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			بشکن;
		حالت 'X':
			/* Please keep in sync with sftp.c -X */
			اگر (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				اگر (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				اگر (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} وگرنه اگر (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				اگر (errstr != پوچ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} وگرنه {
				fatal("Invalid -X option");
			}
			بشکن;

		/* Server options. */
		حالت 'd':
			targetshouldbedirectory = 1;
			بشکن;
		حالت 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			بشکن;
		حالت 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_دودویی);
#endif
			بشکن;
		حالت 'T':
			Tflag = 1;
			بشکن;
		پیشفرض:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	اگر (iamremote)
		mode = MODE_SCP;

	اگر ((pwd = getpwuid(userid = getuid())) == پوچ)
		fatal("unknown user %u", (u_int) userid);

	اگر (!isatty(STDOUT_FILENO))
		showprogress = 0;

	اگر (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} وگرنه {
		اگر (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    پوچ) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	اگر (fflag) {
		/* Follow "protocol", send data. */
		(تهی) response();
		source(argc, argv);
		exit(errs != 0);
	}
	اگر (tflag) {
		/* Receive data. */
		sink(argc, argv, پوچ);
		exit(errs != 0);
	}
	اگر (argc < 2)
		usage();
	اگر (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(تهی) snprintf(cmd, اندازه cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(تهی) ssh_signal(SIGPIPE, lostconn);

	اگر (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	وگرنه {
		اگر (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	اگر (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		اگر (remin != -1)
		    (تهی) close(remin);
		اگر (remout != -1)
		    (تهی) close(remout);
		اگر (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		وگرنه {
			اگر (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
ایستا صحیح
scpio(تهی *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	اگر (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	بازگشت 0;
}

ایستا صحیح
do_times(صحیح fd, صحیح verb, ثابت ساختار stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	نویسه buf[(20 + 7 + 2) * 2 + 2];

	(تهی)snprintf(buf, اندازه(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	اگر (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(تهی) atomicio(vwrite, fd, buf, strlen(buf));
	بازگشت (response());
}

ایستا صحیح
parse_scp_uri(ثابت نویسه *uri, نویسه **userp, نویسه **hostp, صحیح *portp,
    نویسه **pathp)
{
	صحیح r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	اگر (r == 0 && *pathp == پوچ)
		*pathp = xstrdup(".");
	بازگشت r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
ایستا صحیح
append(نویسه *cp, نویسه ***ap, size_t *np)
{
	نویسه **tmp;

	اگر ((tmp = reallocarray(*ap, *np + 1, اندازه(*tmp))) == پوچ)
		بازگشت -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	بازگشت 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
ایستا صحیح
find_brace(ثابت نویسه *pattern, صحیح *startp, صحیح *endp)
{
	صحیح i;
	صحیح in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	برای (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		انتخاب (pattern[i]) {
		حالت '\\':
			/* skip next character */
			اگر (pattern[i + 1] != '\0')
				i++;
			بشکن;
		حالت '[':
			in_bracket = 1;
			بشکن;
		حالت ']':
			in_bracket = 0;
			بشکن;
		حالت '{':
			اگر (in_bracket)
				بشکن;
			اگر (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				بشکن;
			}
			اگر (*startp == -1)
				*startp = i;
			brace_level++;
			بشکن;
		حالت '}':
			اگر (in_bracket)
				بشکن;
			اگر (*startp < 0) {
				/* Unbalanced brace */
				بازگشت -1;
			}
			اگر (--brace_level <= 0)
				*endp = i;
			بشکن;
		}
	}
	/* unbalanced brackets/braces */
	اگر (*endp < 0 && (*startp >= 0 || in_bracket))
		بازگشت -1;
	بازگشت 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
ایستا صحیح
emit_expansion(ثابت نویسه *pattern, صحیح brace_start, صحیح brace_end,
    صحیح sel_start, صحیح sel_end, نویسه ***patternsp, size_t *npatternsp)
{
	نویسه *cp;
	size_t pattern_len;
	صحیح o = 0, tail_len;

	اگر ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		بازگشت -1;

	tail_len = strlen(pattern + brace_end + 1);
	اگر ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == پوچ)
		بازگشت -1;

	/* Pattern before initial brace */
	اگر (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	اگر (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	اگر (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	اگر (append(cp, patternsp, npatternsp) != 0) {
		آزاد(cp);
		بازگشت -1;
	}
	بازگشت 0;
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
ایستا صحیح
brace_expand_one(ثابت نویسه *pattern, نویسه ***patternsp, size_t *npatternsp,
    صحیح *expanded, صحیح *invalid)
{
	صحیح i;
	صحیح in_bracket, brace_start, brace_end, brace_level;
	صحیح sel_start, sel_end;

	*invalid = *expanded = 0;

	اگر (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		بازگشت 0;
	} وگرنه اگر (brace_start == -1)
		بازگشت 0;

	in_bracket = brace_level = 0;
	برای (i = sel_start = brace_start + 1; i < brace_end; i++) {
		انتخاب (pattern[i]) {
		حالت '{':
			اگر (in_bracket)
				بشکن;
			brace_level++;
			بشکن;
		حالت '}':
			اگر (in_bracket)
				بشکن;
			brace_level--;
			بشکن;
		حالت '[':
			in_bracket = 1;
			بشکن;
		حالت ']':
			in_bracket = 0;
			بشکن;
		حالت '\\':
			اگر (i < brace_end - 1)
				i++; /* skip */
			بشکن;
		}
		اگر (pattern[i] == ',' || i == brace_end - 1) {
			اگر (in_bracket || brace_level > 0)
				ادامه;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			اگر (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				بازگشت -1;
			/* move on to the next selection */
			sel_start = i + 1;
			ادامه;
		}
	}
	اگر (in_bracket || brace_level > 0) {
		*invalid = 1;
		بازگشت 0;
	}
	/* success */
	*expanded = 1;
	بازگشت 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
ایستا صحیح
brace_expand(ثابت نویسه *pattern, نویسه ***patternsp, size_t *npatternsp)
{
	نویسه *cp, *cp2, **active = پوچ, **done = پوچ;
	size_t i, nactive = 0, ndone = 0;
	صحیح ret = -1, invalid = 0, expanded = 0;

	*patternsp = پوچ;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	اگر ((cp = strdup(pattern)) == پوچ)
		بازگشت -1;
	اگر (append(cp, &active, &nactive) != 0) {
		آزاد(cp);
		بازگشت -1;
	}
	وقتی (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		اگر (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			آزاد(cp);
			برو fail;
		}
		اگر (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		اگر (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			آزاد(cp);
			ادامه;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		اگر ((cp2 = strrchr(cp, '/')) != پوچ)
			*cp2++ = '\0';
		وگرنه
			cp2 = cp;
		اگر (append(xstrdup(cp2), &done, &ndone) != 0) {
			آزاد(cp);
			برو fail;
		}
		آزاد(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = پوچ;
	ndone = 0;
	ret = 0;
 fail:
	برای (i = 0; i < nactive; i++)
		آزاد(active[i]);
	آزاد(active);
	برای (i = 0; i < ndone; i++)
		آزاد(done[i]);
	آزاد(done);
	بازگشت ret;
}

ایستا ساختار sftp_conn *
do_sftp_connect(نویسه *host, نویسه *user, صحیح port, نویسه *sftp_direct,
   صحیح *reminp, صحیح *remoutp, صحیح *pidp)
{
	اگر (sftp_direct == پوچ) {
		اگر (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			بازگشت پوچ;

	} وگرنه {
		freeargs(&args);
		addargs(&args, "sftp-server");
		اگر (do_cmd(sftp_direct, host, پوچ, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			بازگشت پوچ;
	}
	بازگشت sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

تهی
toremote(صحیح argc, نویسه **argv, شمارش scp_mode_e mode, نویسه *sftp_direct)
{
	نویسه *suser = پوچ, *host = پوچ, *src = پوچ;
	نویسه *bp, *tuser, *thost, *targ;
	صحیح sport = -1, tport = -1;
	ساختار sftp_conn *conn = پوچ, *conn2 = پوچ;
	arglist alist;
	صحیح i, r, status;
	ساختار stat sb;
	u_int j;

	memset(&alist, '\0', اندازه(alist));
	alist.list = پوچ;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	اگر (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		برو out;
	}
	اگر (r != 0) {
		اگر (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			برو out;
		}
	}

	/* Parse source files */
	برای (i = 0; i < argc - 1; i++) {
		آزاد(suser);
		آزاد(host);
		آزاد(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		اگر (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ادامه;
		}
		اگر (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		اگر (suser != پوچ && !okname(suser)) {
			++errs;
			ادامه;
		}
		اگر (host && throughlocal) {	/* extended remote to remote */
			اگر (mode == MODE_SFTP) {
				اگر (remin == -1 || conn == پوچ) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					اگر (conn == پوچ) {
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
				اگر (conn2 == پوچ) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(تهی) close(remin2);
				(تهی) close(remout2);
				remin2 = remout2 = -1;
				اگر (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				وگرنه اگر (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				ادامه;
			} وگرنه {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				اگر (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				آزاد(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				اگر (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				آزاد(bp);
				(تهی) close(remin);
				(تهی) close(remout);
				remin = remout = -1;
			}
		} وگرنه اگر (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			اگر (tuser != پوچ && !okname(tuser)) {
				++errs;
				ادامه;
			}
			اگر (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			برای (j = 0; j < remote_remote_args.رقم; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
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
		} وگرنه {	/* local to remote */
			اگر (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				اگر (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				اگر (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					اگر (conn == پوچ) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				ادامه;
			}
			/* SCP */
			اگر (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				اگر (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				اگر (response() < 0)
					exit(1);
				آزاد(bp);
			}
			source(1, argv + i);
		}
	}
out:
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

تهی
tolocal(صحیح argc, نویسه **argv, شمارش scp_mode_e mode, نویسه *sftp_direct)
{
	نویسه *bp, *host = پوچ, *src = پوچ, *suser = پوچ;
	arglist alist;
	ساختار sftp_conn *conn = پوچ;
	صحیح i, r, sport = -1;

	memset(&alist, '\0', اندازه(alist));
	alist.list = پوچ;

	برای (i = 0; i < argc - 1; i++) {
		آزاد(suser);
		آزاد(host);
		آزاد(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		اگر (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ادامه;
		}
		اگر (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		اگر (suser != پوچ && !okname(suser)) {
			++errs;
			ادامه;
		}
		اگر (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			اگر (iamrecursive)
				addargs(&alist, "-r");
			اگر (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			اگر (do_local_cmd(&alist))
				++errs;
			ادامه;
		}
		/* Remote to local. */
		اگر (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			اگر (conn == پوچ) {
				error("sftp connection failed");
				++errs;
				ادامه;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(تهی) close(remin);
			(تهی) close(remout);
			remin = remout = -1;
			ادامه;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		اگر (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			آزاد(bp);
			++errs;
			ادامه;
		}
		آزاد(bp);
		sink(1, argv + argc - 1, src);
		(تهی) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	آزاد(suser);
	آزاد(host);
	آزاد(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
ایستا نویسه *
prepare_remote_path(ساختار sftp_conn *conn, ثابت نویسه *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	اگر (*path == '\0' || strcmp(path, "~") == 0)
		بازگشت xstrdup(".");
	اگر (*path != '~')
		بازگشت xstrdup(path);
	اگر (strncmp(path, "~/", 2) == 0) {
		اگر ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			بازگشت xstrdup(".");
		بازگشت xstrdup(path + 2 + nslash);
	}
	اگر (sftp_can_expand_path(conn))
		بازگشت sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	بازگشت پوچ;
}

تهی
source_sftp(صحیح argc, نویسه *src, نویسه *targ, ساختار sftp_conn *conn)
{
	نویسه *target = پوچ, *filename = پوچ, *abs_dst = پوچ;
	صحیح src_is_dir, target_is_dir;
	Attrib a;
	ساختار stat st;

	memset(&a, '\0', اندازه(a));
	اگر (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	اگر ((filename = basename(src)) == پوچ)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	اگر (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	اگر ((target = prepare_remote_path(conn, targ)) == پوچ)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	اگر (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		اگر (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	اگر (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	وگرنه {
		abs_dst = target;
		target = پوچ;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	اگر (src_is_dir && iamrecursive) {
		اگر (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} وگرنه اگر (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	آزاد(abs_dst);
	آزاد(target);
}

تهی
source(صحیح argc, نویسه **argv)
{
	ساختار stat stb;
	ایستا BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	صحیح fd = -1, haderr, indx;
	نویسه *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	صحیح len;

	برای (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		وقتی (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		اگر ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			برو syserr;
		اگر (strchr(name, '\n') != پوچ) {
			strnvis(encname, name, اندازه(encname), VIS_NL);
			name = encname;
		}
		اگر (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			برو next;
		}
		اگر (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			برو next;
		}
		unset_nonblock(fd);
		انتخاب (stb.st_mode & S_IFMT) {
		حالت S_IFREG:
			بشکن;
		حالت S_IFDIR:
			اگر (iamrecursive) {
				rsource(name, &stb);
				برو next;
			}
			/* FALLTHROUGH */
		پیشفرض:
			run_err("%s: not a regular file", name);
			برو next;
		}
		اگر ((last = strrchr(name, '/')) == پوچ)
			last = name;
		وگرنه
			++last;
		curfile = last;
		اگر (pflag) {
			اگر (do_times(remout, verbose_mode, &stb) < 0)
				برو next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, اندازه buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		اگر (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(تهی) atomicio(vwrite, remout, buf, strlen(buf));
		اگر (response() < 0)
			برو next;
		اگر ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == پوچ) {
next:			اگر (fd != -1) {
				(تهی) close(fd);
				fd = -1;
			}
			ادامه;
		}
		اگر (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		برای (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
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
				(تهی)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				ادامه;
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
			(تهی) atomicio(vwrite, remout, "", 1);
		وگرنه
			run_err("%s: %s", name, strerror(haderr));
		(تهی) response();
		اگر (showprogress)
			stop_progress_meter();
	}
}

تهی
rsource(نویسه *name, ساختار stat *statp)
{
	DIR *dirp;
	ساختار dirent *dp;
	نویسه *last, *vect[1], path[PATH_MAX];

	اگر (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		بازگشت;
	}
	last = strrchr(name, '/');
	اگر (last == پوچ)
		last = name;
	وگرنه
		last++;
	اگر (pflag) {
		اگر (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			بازگشت;
		}
	}
	(تهی) snprintf(path, اندازه path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	اگر (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(تهی) atomicio(vwrite, remout, path, strlen(path));
	اگر (response() < 0) {
		closedir(dirp);
		بازگشت;
	}
	وقتی ((dp = readdir(dirp)) != پوچ) {
		اگر (dp->d_ino == 0)
			ادامه;
		اگر (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			ادامه;
		اگر (strlen(name) + 1 + strlen(dp->d_name) >= اندازه(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			ادامه;
		}
		(تهی) snprintf(path, اندازه path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(تهی) closedir(dirp);
	(تهی) atomicio(vwrite, remout, "E\n", 2);
	(تهی) response();
}

تهی
sink_sftp(صحیح argc, نویسه *dst, ثابت نویسه *src, ساختار sftp_conn *conn)
{
	نویسه *abs_src = پوچ;
	نویسه *abs_dst = پوچ;
	glob_t g;
	نویسه *filename, *tmp = پوچ;
	صحیح i, r, err = 0, dst_is_dir;
	ساختار stat st;

	memset(&g, 0, اندازه(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	اگر ((abs_src = prepare_remote_path(conn, src)) == پوچ) {
		err = -1;
		برو out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	اگر ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    پوچ, &g)) != 0) {
		اگر (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		وگرنه
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		برو out;
	}

	/* Did we actually get any matches back from the glob? */
	اگر (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != پوچ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		اگر (sftp_stat(conn, g.gl_pathv[0], 1, پوچ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			برو out;
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
			برو out;
		}
		debug2_f("creating destination \"%s\"", dst);
		اگر (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			برو out;
		}
		dst_is_dir = 1;
	}

	برای (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == پوچ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			برو out;
		}

		/* Special handling for destination of '..' */
		اگر (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		اگر (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		وگرنه
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			اگر (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    پوچ, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} وگرنه {
			اگر (sftp_download(conn, g.gl_pathv[i], abs_dst, پوچ,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		آزاد(abs_dst);
		abs_dst = پوچ;
		آزاد(tmp);
		tmp = پوچ;
	}

out:
	آزاد(abs_src);
	آزاد(tmp);
	globfree(&g);
	اگر (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((اندازه(type) == 4 && (val) > INT32_MAX) || \
	 (اندازه(type) == 8 && (val) > INT64_MAX) || \
	 (اندازه(type) != 4 && اندازه(type) != 8))

تهی
sink(صحیح argc, نویسه **argv, ثابت نویسه *src)
{
	ایستا BUF buffer;
	ساختار stat stb;
	BUF *bp;
	off_t i;
	size_t j, شمار;
	صحیح amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	صحیح setimes, targisdir, wrerr;
	نویسه ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	نویسه **patterns = پوچ;
	size_t n, npatterns = 0;
	ساختار timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; برو screwup; }

	اگر (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	اگر (!pflag) {
		(تهی) umask(mask);
		mask |= 07000;
	}
	اگر (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	اگر (targetshouldbedirectory)
		verifydir(targ);

	(تهی) atomicio(vwrite, remout, "", 1);
	اگر (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	اگر (src != پوچ && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		اگر (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	برای (first = 1;; first = 0) {
		cp = buf;
		اگر (atomicio(اقرأ, remin, cp, 1) != 1)
			برو done;
		اگر (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		انجامبده {
			اگر (atomicio(اقرأ, remin, &ch, اندازه(ch)) != اندازه(ch))
				SCREWUP("lost connection");
			اگر (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} وقتی (cp < &buf[اندازه(buf) - 1] && ch != '\n');
		*cp = 0;
		اگر (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		اگر (buf[0] == '\01' || buf[0] == '\02') {
			اگر (iamremote == 0) {
				(تهی) snmprintf(visbuf, اندازه(visbuf),
				    پوچ, "%s", buf + 1);
				(تهی) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			اگر (buf[0] == '\02')
				exit(1);
			++errs;
			ادامه;
		}
		اگر (buf[0] == 'E') {
			(تهی) atomicio(vwrite, remout, "", 1);
			برو done;
		}
		اگر (ch == '\n')
			*--cp = 0;

		cp = buf;
		اگر (*cp == 'T') {
			setimes++;
			cp++;
			اگر (!isdigit((unsigned نویسه)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			اگر (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			اگر (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			اگر (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			اگر (!isdigit((unsigned نویسه)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			اگر (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			اگر (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			اگر (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(تهی) atomicio(vwrite, remout, "", 1);
			ادامه;
		}
		اگر (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			اگر (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		برای (++cp; cp < buf + 5; cp++) {
			اگر (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		اگر (!pflag)
			mode &= ~mask;
		اگر (*cp++ != ' ')
			SCREWUP("mode not delimited");

		اگر (!isdigit((unsigned نویسه)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		اگر (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		اگر (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		اگر (*cp == '\0' || strchr(cp, '/') != پوچ ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		اگر (npatterns > 0) {
			برای (n = 0; n < npatterns; n++) {
				اگر (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					بشکن;
			}
			اگر (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				برای (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		اگر (targisdir) {
			ایستا نویسه *namebuf;
			ایستا size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			اگر (need > cursize) {
				آزاد(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(تهی) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} وگرنه
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
					برو bad;
				}
				اگر (pflag)
					(تهی) chmod(np, mode);
			} وگرنه {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				اگر (mkdir(np, mode | S_IRWXU) == -1)
					برو bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			اگر (setimes) {
				setimes = 0;
				(تهی) utimes(vect[0], tv);
			}
			اگر (mod_flag)
				(تهی) chmod(vect[0], mode);
			آزاد(vect[0]);
			ادامه;
		}
		omode = mode;
		mode |= S_IWUSR;
		اگر ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			ادامه;
		}
		(تهی) atomicio(vwrite, remout, "", 1);
		اگر ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == پوچ) {
			(تهی) close(ofd);
			ادامه;
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
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		برای (شمار = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			اگر (i + amt > size)
				amt = size - i;
			شمار += amt;
			انجامبده {
				j = atomicio6(اقرأ, remin, cp, amt,
				    scpio, &statbytes);
				اگر (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} وقتی (amt > 0);

			اگر (شمار == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				اگر (!wrerr) {
					اگر (atomicio(vwrite, ofd, bp->buf,
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
		اگر (شمار != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, شمار) != شمار) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		اگر (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		اگر (pflag) {
			اگر (exists || omode != mode)
#ifdef HAVE_FCHMOD
				اگر (fchmod(ofd, omode)) {
#وگرنه /* HAVE_FCHMOD */
				اگر (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} وگرنه {
			اگر (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				اگر (fchmod(ofd, omode & ~mask)) {
#وگرنه /* HAVE_FCHMOD */
				اگر (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		اگر (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(تهی) response();
		اگر (showprogress)
			stop_progress_meter();
		اگر (setimes && !wrerr) {
			setimes = 0;
			اگر (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		اگر (note_err(پوچ) == 0)
			(تهی) atomicio(vwrite, remout, "", 1);
	}
done:
	برای (n = 0; n < npatterns; n++)
		آزاد(patterns[n]);
	آزاد(patterns);
	بازگشت;
screwup:
	برای (n = 0; n < npatterns; n++)
		آزاد(patterns[n]);
	آزاد(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

تهی
throughlocal_sftp(ساختار sftp_conn *from, ساختار sftp_conn *to,
    نویسه *src, نویسه *targ)
{
	نویسه *target = پوچ, *filename = پوچ, *abs_dst = پوچ;
	نویسه *abs_src = پوچ, *tmp = پوچ;
	glob_t g;
	صحیح i, r, targetisdir, err = 0;

	اگر ((filename = basename(src)) == پوچ)
		fatal("basename %s: %s", src, strerror(errno));

	اگر ((abs_src = prepare_remote_path(from, src)) == پوچ ||
	    (target = prepare_remote_path(to, targ)) == پوچ)
		cleanup_exit(255);
	memset(&g, 0, اندازه(g));

	targetisdir = sftp_remote_is_dir(to, target);
	اگر (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		برو out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	اگر ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    پوچ, &g)) != 0) {
		اگر (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		وگرنه
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		برو out;
	}

	/* Did we actually get any matches back from the glob? */
	اگر (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != پوچ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		اگر (sftp_stat(from, g.gl_pathv[0], 1, پوچ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			برو out;
		}
	}

	برای (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == پوچ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			برو out;
		}

		/* Special handling for source of '..' */
		اگر (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		اگر (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		وگرنه
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			اگر (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    پوچ, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} وگرنه {
			اگر (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    پوچ, pflag) == -1)
				err = -1;
		}
		آزاد(abs_dst);
		abs_dst = پوچ;
		آزاد(tmp);
		tmp = پوچ;
	}

out:
	آزاد(abs_src);
	آزاد(abs_dst);
	آزاد(target);
	آزاد(tmp);
	globfree(&g);
	اگر (err == -1)
		errs = 1;
}

صحیح
response(تهی)
{
	نویسه ch, *cp, resp, rbuf[2048], visbuf[2048];

	اگر (atomicio(اقرأ, remin, &resp, اندازه(resp)) != اندازه(resp))
		lostconn(0);

	cp = rbuf;
	انتخاب (resp) {
	حالت 0:		/* ok */
		بازگشت (0);
	پیشفرض:
		*cp++ = resp;
		/* FALLTHROUGH */
	حالت 1:		/* error, followed by error msg */
	حالت 2:		/* fatal error, "" */
		انجامبده {
			اگر (atomicio(اقرأ, remin, &ch, اندازه(ch)) != اندازه(ch))
				lostconn(0);
			*cp++ = ch;
		} وقتی (cp < &rbuf[اندازه(rbuf) - 1] && ch != '\n');

		اگر (!iamremote) {
			cp[-1] = '\0';
			(تهی) snmprintf(visbuf, اندازه(visbuf),
			    پوچ, "%s\n", rbuf);
			(تهی) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		اگر (resp == 1)
			بازگشت (-1);
		exit(1);
	}
	/* NOTREACHED */
}

تهی
usage(تهی)
{
	(تهی) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

تهی
run_err(ثابت نویسه *fmt,...)
{
	ایستا FILE *fp;
	va_list ap;

	++errs;
	اگر (fp != پوچ || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(تهی) fprintf(fp, "%c", 0x01);
		(تهی) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(تهی) vfprintf(fp, fmt, ap);
		va_end(ap);
		(تهی) fprintf(fp, "\n");
		(تهی) fflush(fp);
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
note_err(ثابت نویسه *fmt, ...)
{
	ایستا نویسه *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	اگر (fmt == پوچ) {
		اگر (emsg == پوچ)
			بازگشت 0;
		run_err("%s", emsg);
		آزاد(emsg);
		emsg = پوچ;
		بازگشت -1;
	}

	errs++;
	/* Prefer first-noted error */
	اگر (emsg != پوچ)
		بازگشت -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, پوچ, fmt, ap);
	va_end(ap);
	بازگشت -1;
}

تهی
verifydir(نویسه *cp)
{
	ساختار stat stb;

	اگر (!stat(cp, &stb)) {
		اگر (S_ISDIR(stb.st_mode))
			بازگشت;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

صحیح
okname(نویسه *cp0)
{
	صحیح c;
	نویسه *cp;

	cp = cp0;
	انجامبده {
		c = (صحیح)*cp;
		اگر (c & 0200)
			برو bad;
		اگر (!isalpha(c) && !isdigit((unsigned نویسه)c)) {
			انتخاب (c) {
			حالت '\'':
			حالت '"':
			حالت '`':
			حالت ' ':
			حالت '#':
				برو bad;
			پیشفرض:
				بشکن;
			}
		}
	} وقتی (*++cp);
	بازگشت (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	بازگشت (0);
}

BUF *
allocbuf(BUF *bp, صحیح fd, صحیح blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	ساختار stat stb;

	اگر (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		بازگشت (پوچ);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	اگر (size == 0)
		size = blksize;
#وگرنه /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	اگر (bp->cnt >= size)
		بازگشت (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	بازگشت (bp);
}

تهی
lostconn(صحیح signo)
{
	اگر (!iamremote)
		(تهی)اكتب(STDERR_FILENO, "lost connection\n", 16);
	اگر (signo)
		_exit(1);
	وگرنه
		exit(1);
}

تهی
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
		(تهی)waitpid(do_cmd_pid, پوچ, 0);
	اگر (do_cmd_pid2 > 0)
		(تهی)waitpid(do_cmd_pid2, پوچ, 0);
	exit(i);
}
