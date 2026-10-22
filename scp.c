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

বাহ্যিক অক্ষর *__progname;

#define COPY_BUFLEN	16384

পূর্ণসংখ্যা do_cmd(অক্ষর *, অক্ষর *, অক্ষর *, পূর্ণসংখ্যা, পূর্ণসংখ্যা, অক্ষর *, পূর্ণসংখ্যা *, পূর্ণসংখ্যা *, pid_t *);
পূর্ণসংখ্যা do_cmd2(অক্ষর *, অক্ষর *, পূর্ণসংখ্যা, অক্ষর *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
কাঠামো bwlimit bwlimit;

/* Name of current file being transferred. */
অক্ষর *curfile;

/* This is set to non-zero to enable verbose mode. */
পূর্ণসংখ্যা verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
পূর্ণসংখ্যা showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
পূর্ণসংখ্যা throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
পূর্ণসংখ্যা sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
অক্ষর *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
আকার_t sftp_copy_buflen;
আকার_t sftp_nrequests;

/* Needed for sftp */
অস্থির sig_atomic_t interrupted = 0;

পূর্ণসংখ্যা sftp_glob(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা,
    পূর্ণসংখ্যা (*)(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা), glob_t *); /* proto for sftp-glob.c */

স্থির শূন্য
killchild(পূর্ণসংখ্যা signo)
{
	যদি (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(শূন্য)waitpid(do_cmd_pid, ফাঁকা, 0);
	}
	যদি (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(শূন্য)waitpid(do_cmd_pid2, ফাঁকা, 0);
	}

	যদি (signo)
		_exit(1);
	exit(1);
}

স্থির শূন্য
suspone(পূর্ণসংখ্যা pid, পূর্ণসংখ্যা signo)
{
	পূর্ণসংখ্যা status;

	যদি (pid > 1) {
		kill(pid, signo);
		যখন (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

স্থির শূন্য
suspchild(পূর্ণসংখ্যা signo)
{
	পূর্ণসংখ্যা save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

স্থির পূর্ণসংখ্যা
do_local_cmd(arglist *a)
{
	অক্ষর *cp;
	পূর্ণসংখ্যা status;
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

	যখন (waitpid(pid, &status, 0) == -1)
		যদি (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	যদি (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ফেরত (-1);

	ফেরত (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

পূর্ণসংখ্যা
do_cmd(অক্ষর *program, অক্ষর *host, অক্ষর *remuser, পূর্ণসংখ্যা port, পূর্ণসংখ্যা subsystem,
    অক্ষর *cmd, পূর্ণসংখ্যা *fdin, পূর্ণসংখ্যা *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	পূর্ণসংখ্যা pin[2], pout[2];
#অন্যথা
	পূর্ণসংখ্যা sv[2];
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
	নির্বাচন (*pid) {
	ক্ষেত্র -1:
		fatal("fork: %s", strerror(errno));
	ক্ষেত্র 0:
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
		যদি (remuser != ফাঁকা) {
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
	পূর্বনির্ধারিত:
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
		ফেরত 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
পূর্ণসংখ্যা
do_cmd2(অক্ষর *host, অক্ষর *remuser, পূর্ণসংখ্যা port, অক্ষর *cmd,
    পূর্ণসংখ্যা fdin, পূর্ণসংখ্যা fdout)
{
	পূর্ণসংখ্যা status;
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
		যদি (remuser != ফাঁকা) {
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
	যখন (waitpid(pid, &status, 0) == -1)
		যদি (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	ফেরত 0;
}

প্রকারলেখ কাঠামো {
	আকার_t cnt;
	অক্ষর *buf;
} BUF;

BUF *allocbuf(BUF *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
শূন্য lostconn(পূর্ণসংখ্যা);
পূর্ণসংখ্যা okname(অক্ষর *);
শূন্য run_err(ধ্রুবক অক্ষর *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
পূর্ণসংখ্যা note_err(ধ্রুবক অক্ষর *,...)
    __attribute__((__format__ (printf, 1, 2)));
শূন্য verifydir(অক্ষর *);

কাঠামো passwd *pwd;
uid_t userid;
পূর্ণসংখ্যা errs, remin, remout, remin2, remout2;
পূর্ণসংখ্যা Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
অক্ষর cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

গণনা scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

পূর্ণসংখ্যা response(শূন্য);
শূন্য rsource(অক্ষর *, কাঠামো stat *);
শূন্য sink(পূর্ণসংখ্যা, অক্ষর *[], ধ্রুবক অক্ষর *);
শূন্য source(পূর্ণসংখ্যা, অক্ষর *[]);
শূন্য tolocal(পূর্ণসংখ্যা, অক্ষর *[], গণনা scp_mode_e, অক্ষর *sftp_direct);
শূন্য toremote(পূর্ণসংখ্যা, অক্ষর *[], গণনা scp_mode_e, অক্ষর *sftp_direct);
শূন্য usage(শূন্য);

শূন্য source_sftp(পূর্ণসংখ্যা, অক্ষর *, অক্ষর *, কাঠামো sftp_conn *);
শূন্য sink_sftp(পূর্ণসংখ্যা, অক্ষর *, ধ্রুবক অক্ষর *, কাঠামো sftp_conn *);
শূন্য throughlocal_sftp(কাঠামো sftp_conn *, কাঠামো sftp_conn *,
    অক্ষর *, অক্ষর *);

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	পূর্ণসংখ্যা ch, fflag, tflag, status, r, n;
	অক্ষর **newargv, *argv0;
	ধ্রুবক অক্ষর *errstr;
	বাহ্যিক অক্ষর *optarg;
	বাহ্যিক পূর্ণসংখ্যা optind;
	গণনা scp_mode_e mode = MODE_SFTP;
	অক্ষর *sftp_direct = ফাঁকা;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), আকার(*newargv));
	জন্য (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', আকার(args));
	memset(&remote_remote_args, '\0', আকার(remote_remote_args));
	args.list = remote_remote_args.list = ফাঁকা;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	যখন ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		নির্বাচন (ch) {
		/* User-visible flags. */
		ক্ষেত্র '1':
			fatal("SSH protocol v.1 is no longer supported");
			বিরতি;
		ক্ষেত্র '2':
			/* Ignored */
			বিরতি;
		ক্ষেত্র 'A':
		ক্ষেত্র '4':
		ক্ষেত্র '6':
		ক্ষেত্র 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			বিরতি;
		ক্ষেত্র 'D':
			sftp_direct = optarg;
			বিরতি;
		ক্ষেত্র '3':
			throughlocal = 1;
			বিরতি;
		ক্ষেত্র 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			বিরতি;
		ক্ষেত্র 'o':
		ক্ষেত্র 'c':
		ক্ষেত্র 'i':
		ক্ষেত্র 'F':
		ক্ষেত্র 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			বিরতি;
		ক্ষেত্র 'O':
			mode = MODE_SCP;
			বিরতি;
		ক্ষেত্র 's':
			/* Ignored */
			বিরতি;
		ক্ষেত্র 'P':
			sshport = a2port(optarg);
			যদি (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			বিরতি;
		ক্ষেত্র 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			বিরতি;
		ক্ষেত্র 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			যদি (errstr != ফাঁকা)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			বিরতি;
		ক্ষেত্র 'p':
			pflag = 1;
			বিরতি;
		ক্ষেত্র 'r':
			iamrecursive = 1;
			বিরতি;
		ক্ষেত্র 'S':
			ssh_program = xstrdup(optarg);
			বিরতি;
		ক্ষেত্র 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			যদি (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			অন্যথা যদি (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			বিরতি;
		ক্ষেত্র 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			বিরতি;
		ক্ষেত্র 'X':
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
				sftp_copy_buflen = (আকার_t)llv;
			} অন্যথা যদি (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				যদি (errstr != ফাঁকা) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (আকার_t)llv;
			} অন্যথা {
				fatal("Invalid -X option");
			}
			বিরতি;

		/* Server options. */
		ক্ষেত্র 'd':
			targetshouldbedirectory = 1;
			বিরতি;
		ক্ষেত্র 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			বিরতি;
		ক্ষেত্র 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_দ্বিমিক);
#endif
			বিরতি;
		ক্ষেত্র 'T':
			Tflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
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

	যদি ((pwd = getpwuid(userid = getuid())) == ফাঁকা)
		fatal("unknown user %u", (u_int) userid);

	যদি (!isatty(STDOUT_FILENO))
		showprogress = 0;

	যদি (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} অন্যথা {
		যদি (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ফাঁকা) == -1) {
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
		sink(argc, argv, ফাঁকা);
		exit(errs != 0);
	}
	যদি (argc < 2)
		usage();
	যদি (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(শূন্য) snprintf(cmd, আকার cmd, "scp%s%s%s%s",
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
স্থির পূর্ণসংখ্যা
scpio(শূন্য *_cnt, আকার_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	যদি (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
do_times(পূর্ণসংখ্যা fd, পূর্ণসংখ্যা verb, ধ্রুবক কাঠামো stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	অক্ষর buf[(20 + 7 + 2) * 2 + 2];

	(শূন্য)snprintf(buf, আকার(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	যদি (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(শূন্য) atomicio(vwrite, fd, buf, strlen(buf));
	ফেরত (response());
}

স্থির পূর্ণসংখ্যা
parse_scp_uri(ধ্রুবক অক্ষর *uri, অক্ষর **userp, অক্ষর **hostp, পূর্ণসংখ্যা *portp,
    অক্ষর **pathp)
{
	পূর্ণসংখ্যা r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	যদি (r == 0 && *pathp == ফাঁকা)
		*pathp = xstrdup(".");
	ফেরত r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
স্থির পূর্ণসংখ্যা
append(অক্ষর *cp, অক্ষর ***ap, আকার_t *np)
{
	অক্ষর **tmp;

	যদি ((tmp = reallocarray(*ap, *np + 1, আকার(*tmp))) == ফাঁকা)
		ফেরত -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	ফেরত 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
স্থির পূর্ণসংখ্যা
find_brace(ধ্রুবক অক্ষর *pattern, পূর্ণসংখ্যা *startp, পূর্ণসংখ্যা *endp)
{
	পূর্ণসংখ্যা i;
	পূর্ণসংখ্যা in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	জন্য (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		নির্বাচন (pattern[i]) {
		ক্ষেত্র '\\':
			/* skip next character */
			যদি (pattern[i + 1] != '\0')
				i++;
			বিরতি;
		ক্ষেত্র '[':
			in_bracket = 1;
			বিরতি;
		ক্ষেত্র ']':
			in_bracket = 0;
			বিরতি;
		ক্ষেত্র '{':
			যদি (in_bracket)
				বিরতি;
			যদি (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				বিরতি;
			}
			যদি (*startp == -1)
				*startp = i;
			brace_level++;
			বিরতি;
		ক্ষেত্র '}':
			যদি (in_bracket)
				বিরতি;
			যদি (*startp < 0) {
				/* Unbalanced brace */
				ফেরত -1;
			}
			যদি (--brace_level <= 0)
				*endp = i;
			বিরতি;
		}
	}
	/* unbalanced brackets/braces */
	যদি (*endp < 0 && (*startp >= 0 || in_bracket))
		ফেরত -1;
	ফেরত 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
স্থির পূর্ণসংখ্যা
emit_expansion(ধ্রুবক অক্ষর *pattern, পূর্ণসংখ্যা brace_start, পূর্ণসংখ্যা brace_end,
    পূর্ণসংখ্যা sel_start, পূর্ণসংখ্যা sel_end, অক্ষর ***patternsp, আকার_t *npatternsp)
{
	অক্ষর *cp;
	আকার_t pattern_len;
	পূর্ণসংখ্যা o = 0, লেজ_len;

	যদি ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		ফেরত -1;

	লেজ_len = strlen(pattern + brace_end + 1);
	যদি ((cp = malloc(brace_start + (sel_end - sel_start) +
	    লেজ_len + 1)) == ফাঁকা)
		ফেরত -1;

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
	যদি (লেজ_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, লেজ_len);
		o += লেজ_len;
	}
	cp[o] = '\0';
	যদি (append(cp, patternsp, npatternsp) != 0) {
		মুক্ত(cp);
		ফেরত -1;
	}
	ফেরত 0;
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
স্থির পূর্ণসংখ্যা
brace_expand_one(ধ্রুবক অক্ষর *pattern, অক্ষর ***patternsp, আকার_t *npatternsp,
    পূর্ণসংখ্যা *expanded, পূর্ণসংখ্যা *invalid)
{
	পূর্ণসংখ্যা i;
	পূর্ণসংখ্যা in_bracket, brace_start, brace_end, brace_level;
	পূর্ণসংখ্যা sel_start, sel_end;

	*invalid = *expanded = 0;

	যদি (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		ফেরত 0;
	} অন্যথা যদি (brace_start == -1)
		ফেরত 0;

	in_bracket = brace_level = 0;
	জন্য (i = sel_start = brace_start + 1; i < brace_end; i++) {
		নির্বাচন (pattern[i]) {
		ক্ষেত্র '{':
			যদি (in_bracket)
				বিরতি;
			brace_level++;
			বিরতি;
		ক্ষেত্র '}':
			যদি (in_bracket)
				বিরতি;
			brace_level--;
			বিরতি;
		ক্ষেত্র '[':
			in_bracket = 1;
			বিরতি;
		ক্ষেত্র ']':
			in_bracket = 0;
			বিরতি;
		ক্ষেত্র '\\':
			যদি (i < brace_end - 1)
				i++; /* skip */
			বিরতি;
		}
		যদি (pattern[i] == ',' || i == brace_end - 1) {
			যদি (in_bracket || brace_level > 0)
				চালু;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			যদি (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				ফেরত -1;
			/* move on to the next selection */
			sel_start = i + 1;
			চালু;
		}
	}
	যদি (in_bracket || brace_level > 0) {
		*invalid = 1;
		ফেরত 0;
	}
	/* success */
	*expanded = 1;
	ফেরত 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
স্থির পূর্ণসংখ্যা
brace_expand(ধ্রুবক অক্ষর *pattern, অক্ষর ***patternsp, আকার_t *npatternsp)
{
	অক্ষর *cp, *cp2, **active = ফাঁকা, **done = ফাঁকা;
	আকার_t i, nactive = 0, ndone = 0;
	পূর্ণসংখ্যা ret = -1, invalid = 0, expanded = 0;

	*patternsp = ফাঁকা;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	যদি ((cp = strdup(pattern)) == ফাঁকা)
		ফেরত -1;
	যদি (append(cp, &active, &nactive) != 0) {
		মুক্ত(cp);
		ফেরত -1;
	}
	যখন (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		যদি (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			মুক্ত(cp);
			যাও fail;
		}
		যদি (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		যদি (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			মুক্ত(cp);
			চালু;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		যদি ((cp2 = strrchr(cp, '/')) != ফাঁকা)
			*cp2++ = '\0';
		অন্যথা
			cp2 = cp;
		যদি (append(xstrdup(cp2), &done, &ndone) != 0) {
			মুক্ত(cp);
			যাও fail;
		}
		মুক্ত(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = ফাঁকা;
	ndone = 0;
	ret = 0;
 fail:
	জন্য (i = 0; i < nactive; i++)
		মুক্ত(active[i]);
	মুক্ত(active);
	জন্য (i = 0; i < ndone; i++)
		মুক্ত(done[i]);
	মুক্ত(done);
	ফেরত ret;
}

স্থির কাঠামো sftp_conn *
do_sftp_connect(অক্ষর *host, অক্ষর *user, পূর্ণসংখ্যা port, অক্ষর *sftp_direct,
   পূর্ণসংখ্যা *reminp, পূর্ণসংখ্যা *remoutp, পূর্ণসংখ্যা *pidp)
{
	যদি (sftp_direct == ফাঁকা) {
		যদি (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			ফেরত ফাঁকা;

	} অন্যথা {
		freeargs(&args);
		addargs(&args, "sftp-server");
		যদি (do_cmd(sftp_direct, host, ফাঁকা, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			ফেরত ফাঁকা;
	}
	ফেরত sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

শূন্য
toremote(পূর্ণসংখ্যা argc, অক্ষর **argv, গণনা scp_mode_e mode, অক্ষর *sftp_direct)
{
	অক্ষর *suser = ফাঁকা, *host = ফাঁকা, *src = ফাঁকা;
	অক্ষর *bp, *tuser, *thost, *targ;
	পূর্ণসংখ্যা sport = -1, tport = -1;
	কাঠামো sftp_conn *conn = ফাঁকা, *conn2 = ফাঁকা;
	arglist alist;
	পূর্ণসংখ্যা i, r, status;
	কাঠামো stat sb;
	u_int j;

	memset(&alist, '\0', আকার(alist));
	alist.list = ফাঁকা;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	যদি (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		যাও out;
	}
	যদি (r != 0) {
		যদি (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			যাও out;
		}
	}

	/* Parse source files */
	জন্য (i = 0; i < argc - 1; i++) {
		মুক্ত(suser);
		মুক্ত(host);
		মুক্ত(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		যদি (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			চালু;
		}
		যদি (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		যদি (suser != ফাঁকা && !okname(suser)) {
			++errs;
			চালু;
		}
		যদি (host && throughlocal) {	/* extended remote to remote */
			যদি (mode == MODE_SFTP) {
				যদি (remin == -1 || conn == ফাঁকা) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					যদি (conn == ফাঁকা) {
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
				যদি (conn2 == ফাঁকা) {
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
				চালু;
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
			যদি (tuser != ফাঁকা && !okname(tuser)) {
				++errs;
				চালু;
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
			জন্য (j = 0; j < remote_remote_args.অঙ্ক; j++) {
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
					যদি (conn == ফাঁকা) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				চালু;
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
tolocal(পূর্ণসংখ্যা argc, অক্ষর **argv, গণনা scp_mode_e mode, অক্ষর *sftp_direct)
{
	অক্ষর *bp, *host = ফাঁকা, *src = ফাঁকা, *suser = ফাঁকা;
	arglist alist;
	কাঠামো sftp_conn *conn = ফাঁকা;
	পূর্ণসংখ্যা i, r, sport = -1;

	memset(&alist, '\0', আকার(alist));
	alist.list = ফাঁকা;

	জন্য (i = 0; i < argc - 1; i++) {
		মুক্ত(suser);
		মুক্ত(host);
		মুক্ত(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		যদি (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			চালু;
		}
		যদি (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		যদি (suser != ফাঁকা && !okname(suser)) {
			++errs;
			চালু;
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
			চালু;
		}
		/* Remote to local. */
		যদি (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			যদি (conn == ফাঁকা) {
				error("sftp connection failed");
				++errs;
				চালু;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(শূন্য) close(remin);
			(শূন্য) close(remout);
			remin = remout = -1;
			চালু;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		যদি (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			মুক্ত(bp);
			++errs;
			চালু;
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
স্থির অক্ষর *
prepare_remote_path(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path)
{
	আকার_t nslash;

	/* Handle ~ prefixed paths */
	যদি (*path == '\0' || strcmp(path, "~") == 0)
		ফেরত xstrdup(".");
	যদি (*path != '~')
		ফেরত xstrdup(path);
	যদি (strncmp(path, "~/", 2) == 0) {
		যদি ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			ফেরত xstrdup(".");
		ফেরত xstrdup(path + 2 + nslash);
	}
	যদি (sftp_can_expand_path(conn))
		ফেরত sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	ফেরত ফাঁকা;
}

শূন্য
source_sftp(পূর্ণসংখ্যা argc, অক্ষর *src, অক্ষর *targ, কাঠামো sftp_conn *conn)
{
	অক্ষর *target = ফাঁকা, *filename = ফাঁকা, *abs_dst = ফাঁকা;
	পূর্ণসংখ্যা src_is_dir, target_is_dir;
	Attrib a;
	কাঠামো stat st;

	memset(&a, '\0', আকার(a));
	যদি (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	যদি ((filename = basename(src)) == ফাঁকা)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	যদি (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	যদি ((target = prepare_remote_path(conn, targ)) == ফাঁকা)
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
		target = ফাঁকা;
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
source(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	কাঠামো stat stb;
	স্থির BUF বাফার;
	BUF *bp;
	off_t i, statbytes;
	আকার_t amt, nr;
	পূর্ণসংখ্যা fd = -1, haderr, indx;
	অক্ষর *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	পূর্ণসংখ্যা len;

	জন্য (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		যখন (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		যদি ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			যাও syserr;
		যদি (strchr(name, '\n') != ফাঁকা) {
			strnvis(encname, name, আকার(encname), VIS_NL);
			name = encname;
		}
		যদি (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			যাও পরবর্তী;
		}
		যদি (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			যাও পরবর্তী;
		}
		unset_nonblock(fd);
		নির্বাচন (stb.st_mode & S_IFMT) {
		ক্ষেত্র S_IFREG:
			বিরতি;
		ক্ষেত্র S_IFDIR:
			যদি (iamrecursive) {
				rsource(name, &stb);
				যাও পরবর্তী;
			}
			/* FALLTHROUGH */
		পূর্বনির্ধারিত:
			run_err("%s: not a regular file", name);
			যাও পরবর্তী;
		}
		যদি ((last = strrchr(name, '/')) == ফাঁকা)
			last = name;
		অন্যথা
			++last;
		curfile = last;
		যদি (pflag) {
			যদি (do_times(remout, verbose_mode, &stb) < 0)
				যাও পরবর্তী;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, আকার buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		যদি (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(শূন্য) atomicio(vwrite, remout, buf, strlen(buf));
		যদি (response() < 0)
			যাও পরবর্তী;
		যদি ((bp = allocbuf(&বাফার, fd, COPY_BUFLEN)) == ফাঁকা) {
পরবর্তী:			যদি (fd != -1) {
				(শূন্য) close(fd);
				fd = -1;
			}
			চালু;
		}
		যদি (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		জন্য (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
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
				চালু;
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
rsource(অক্ষর *name, কাঠামো stat *statp)
{
	DIR *dirp;
	কাঠামো dirent *dp;
	অক্ষর *last, *vect[1], path[PATH_MAX];

	যদি (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		ফেরত;
	}
	last = strrchr(name, '/');
	যদি (last == ফাঁকা)
		last = name;
	অন্যথা
		last++;
	যদি (pflag) {
		যদি (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			ফেরত;
		}
	}
	(শূন্য) snprintf(path, আকার path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	যদি (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(শূন্য) atomicio(vwrite, remout, path, strlen(path));
	যদি (response() < 0) {
		closedir(dirp);
		ফেরত;
	}
	যখন ((dp = readdir(dirp)) != ফাঁকা) {
		যদি (dp->d_ino == 0)
			চালু;
		যদি (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			চালু;
		যদি (strlen(name) + 1 + strlen(dp->d_name) >= আকার(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			চালু;
		}
		(শূন্য) snprintf(path, আকার path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(শূন্য) closedir(dirp);
	(শূন্য) atomicio(vwrite, remout, "E\n", 2);
	(শূন্য) response();
}

শূন্য
sink_sftp(পূর্ণসংখ্যা argc, অক্ষর *dst, ধ্রুবক অক্ষর *src, কাঠামো sftp_conn *conn)
{
	অক্ষর *abs_src = ফাঁকা;
	অক্ষর *abs_dst = ফাঁকা;
	glob_t g;
	অক্ষর *filename, *tmp = ফাঁকা;
	পূর্ণসংখ্যা i, r, err = 0, dst_is_dir;
	কাঠামো stat st;

	memset(&g, 0, আকার(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	যদি ((abs_src = prepare_remote_path(conn, src)) == ফাঁকা) {
		err = -1;
		যাও out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	যদি ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ফাঁকা, &g)) != 0) {
		যদি (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		অন্যথা
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		যাও out;
	}

	/* Did we actually get any matches back from the glob? */
	যদি (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ফাঁকা) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		যদি (sftp_stat(conn, g.gl_pathv[0], 1, ফাঁকা) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			যাও out;
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
			যাও out;
		}
		debug2_f("creating destination \"%s\"", dst);
		যদি (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			যাও out;
		}
		dst_is_dir = 1;
	}

	জন্য (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == ফাঁকা) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			যাও out;
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
			    ফাঁকা, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} অন্যথা {
			যদি (sftp_download(conn, g.gl_pathv[i], abs_dst, ফাঁকা,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		মুক্ত(abs_dst);
		abs_dst = ফাঁকা;
		মুক্ত(tmp);
		tmp = ফাঁকা;
	}

out:
	মুক্ত(abs_src);
	মুক্ত(tmp);
	globfree(&g);
	যদি (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((আকার(type) == 4 && (val) > INT32_MAX) || \
	 (আকার(type) == 8 && (val) > INT64_MAX) || \
	 (আকার(type) != 4 && আকার(type) != 8))

শূন্য
sink(পূর্ণসংখ্যা argc, অক্ষর **argv, ধ্রুবক অক্ষর *src)
{
	স্থির BUF বাফার;
	কাঠামো stat stb;
	BUF *bp;
	off_t i;
	আকার_t j, গুনতি;
	পূর্ণসংখ্যা amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t আকার_2, statbytes;
	unsigned long long ull;
	পূর্ণসংখ্যা setimes, targisdir, wrerr;
	অক্ষর ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	অক্ষর **patterns = ফাঁকা;
	আকার_t n, npatterns = 0;
	কাঠামো timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; যাও screwup; }

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
	যদি (src != ফাঁকা && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		যদি (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	জন্য (first = 1;; first = 0) {
		cp = buf;
		যদি (atomicio(পঠ, remin, cp, 1) != 1)
			যাও done;
		যদি (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		করো {
			যদি (atomicio(পঠ, remin, &ch, আকার(ch)) != আকার(ch))
				SCREWUP("lost connection");
			যদি (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} যখন (cp < &buf[আকার(buf) - 1] && ch != '\n');
		*cp = 0;
		যদি (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		যদি (buf[0] == '\01' || buf[0] == '\02') {
			যদি (iamremote == 0) {
				(শূন্য) snmprintf(visbuf, আকার(visbuf),
				    ফাঁকা, "%s", buf + 1);
				(শূন্য) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			যদি (buf[0] == '\02')
				exit(1);
			++errs;
			চালু;
		}
		যদি (buf[0] == 'E') {
			(শূন্য) atomicio(vwrite, remout, "", 1);
			যাও done;
		}
		যদি (ch == '\n')
			*--cp = 0;

		cp = buf;
		যদি (*cp == 'T') {
			setimes++;
			cp++;
			যদি (!isdigit((unsigned অক্ষর)*cp))
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
			যদি (!isdigit((unsigned অক্ষর)*cp))
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
			চালু;
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
		জন্য (++cp; cp < buf + 5; cp++) {
			যদি (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		যদি (!pflag)
			mode &= ~mask;
		যদি (*cp++ != ' ')
			SCREWUP("mode not delimited");

		যদি (!isdigit((unsigned অক্ষর)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		যদি (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		যদি (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		আকার_2 = (off_t)ull;

		যদি (*cp == '\0' || strchr(cp, '/') != ফাঁকা ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		যদি (npatterns > 0) {
			জন্য (n = 0; n < npatterns; n++) {
				যদি (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					বিরতি;
			}
			যদি (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				জন্য (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		যদি (targisdir) {
			স্থির অক্ষর *namebuf;
			স্থির আকার_t cursize;
			আকার_t need;

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
			পূর্ণসংখ্যা mod_flag = pflag;
			যদি (!iamrecursive)
				SCREWUP("received directory without -r");
			যদি (exists) {
				যদি (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					যাও bad;
				}
				যদি (pflag)
					(শূন্য) chmod(np, mode);
			} অন্যথা {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				যদি (mkdir(np, mode | S_IRWXU) == -1)
					যাও bad;
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
			চালু;
		}
		omode = mode;
		mode |= S_IWUSR;
		যদি ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			চালু;
		}
		(শূন্য) atomicio(vwrite, remout, "", 1);
		যদি ((bp = allocbuf(&বাফার, ofd, COPY_BUFLEN)) == ফাঁকা) {
			(শূন্য) close(ofd);
			চালু;
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
			start_progress_meter(curfile, আকার_2, &statbytes);
		set_nonblock(remin);
		জন্য (গুনতি = i = 0; i < আকার_2; i += bp->cnt) {
			amt = bp->cnt;
			যদি (i + amt > আকার_2)
				amt = আকার_2 - i;
			গুনতি += amt;
			করো {
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
			} যখন (amt > 0);

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
		    ftruncate(ofd, আকার_2) != 0)
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
		যদি (note_err(ফাঁকা) == 0)
			(শূন্য) atomicio(vwrite, remout, "", 1);
	}
done:
	জন্য (n = 0; n < npatterns; n++)
		মুক্ত(patterns[n]);
	মুক্ত(patterns);
	ফেরত;
screwup:
	জন্য (n = 0; n < npatterns; n++)
		মুক্ত(patterns[n]);
	মুক্ত(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

শূন্য
throughlocal_sftp(কাঠামো sftp_conn *from, কাঠামো sftp_conn *to,
    অক্ষর *src, অক্ষর *targ)
{
	অক্ষর *target = ফাঁকা, *filename = ফাঁকা, *abs_dst = ফাঁকা;
	অক্ষর *abs_src = ফাঁকা, *tmp = ফাঁকা;
	glob_t g;
	পূর্ণসংখ্যা i, r, targetisdir, err = 0;

	যদি ((filename = basename(src)) == ফাঁকা)
		fatal("basename %s: %s", src, strerror(errno));

	যদি ((abs_src = prepare_remote_path(from, src)) == ফাঁকা ||
	    (target = prepare_remote_path(to, targ)) == ফাঁকা)
		cleanup_exit(255);
	memset(&g, 0, আকার(g));

	targetisdir = sftp_remote_is_dir(to, target);
	যদি (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		যাও out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	যদি ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ফাঁকা, &g)) != 0) {
		যদি (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		অন্যথা
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		যাও out;
	}

	/* Did we actually get any matches back from the glob? */
	যদি (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ফাঁকা) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		যদি (sftp_stat(from, g.gl_pathv[0], 1, ফাঁকা) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			যাও out;
		}
	}

	জন্য (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == ফাঁকা) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			যাও out;
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
			    ফাঁকা, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} অন্যথা {
			যদি (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    ফাঁকা, pflag) == -1)
				err = -1;
		}
		মুক্ত(abs_dst);
		abs_dst = ফাঁকা;
		মুক্ত(tmp);
		tmp = ফাঁকা;
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

পূর্ণসংখ্যা
response(শূন্য)
{
	অক্ষর ch, *cp, resp, rbuf[2048], visbuf[2048];

	যদি (atomicio(পঠ, remin, &resp, আকার(resp)) != আকার(resp))
		lostconn(0);

	cp = rbuf;
	নির্বাচন (resp) {
	ক্ষেত্র 0:		/* ok */
		ফেরত (0);
	পূর্বনির্ধারিত:
		*cp++ = resp;
		/* FALLTHROUGH */
	ক্ষেত্র 1:		/* error, followed by error msg */
	ক্ষেত্র 2:		/* fatal error, "" */
		করো {
			যদি (atomicio(পঠ, remin, &ch, আকার(ch)) != আকার(ch))
				lostconn(0);
			*cp++ = ch;
		} যখন (cp < &rbuf[আকার(rbuf) - 1] && ch != '\n');

		যদি (!iamremote) {
			cp[-1] = '\0';
			(শূন্য) snmprintf(visbuf, আকার(visbuf),
			    ফাঁকা, "%s\n", rbuf);
			(শূন্য) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		যদি (resp == 1)
			ফেরত (-1);
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
run_err(ধ্রুবক অক্ষর *fmt,...)
{
	স্থির FILE *fp;
	va_list ap;

	++errs;
	যদি (fp != ফাঁকা || (remout != -1 && (fp = fdopen(remout, "w")))) {
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
পূর্ণসংখ্যা
note_err(ধ্রুবক অক্ষর *fmt, ...)
{
	স্থির অক্ষর *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	যদি (fmt == ফাঁকা) {
		যদি (emsg == ফাঁকা)
			ফেরত 0;
		run_err("%s", emsg);
		মুক্ত(emsg);
		emsg = ফাঁকা;
		ফেরত -1;
	}

	errs++;
	/* Prefer first-noted error */
	যদি (emsg != ফাঁকা)
		ফেরত -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, ফাঁকা, fmt, ap);
	va_end(ap);
	ফেরত -1;
}

শূন্য
verifydir(অক্ষর *cp)
{
	কাঠামো stat stb;

	যদি (!stat(cp, &stb)) {
		যদি (S_ISDIR(stb.st_mode))
			ফেরত;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

পূর্ণসংখ্যা
okname(অক্ষর *cp0)
{
	পূর্ণসংখ্যা c;
	অক্ষর *cp;

	cp = cp0;
	করো {
		c = (পূর্ণসংখ্যা)*cp;
		যদি (c & 0200)
			যাও bad;
		যদি (!isalpha(c) && !isdigit((unsigned অক্ষর)c)) {
			নির্বাচন (c) {
			ক্ষেত্র '\'':
			ক্ষেত্র '"':
			ক্ষেত্র '`':
			ক্ষেত্র ' ':
			ক্ষেত্র '#':
				যাও bad;
			পূর্বনির্ধারিত:
				বিরতি;
			}
		}
	} যখন (*++cp);
	ফেরত (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	ফেরত (0);
}

BUF *
allocbuf(BUF *bp, পূর্ণসংখ্যা fd, পূর্ণসংখ্যা blksize)
{
	আকার_t আকার_2;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	কাঠামো stat stb;

	যদি (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		ফেরত (ফাঁকা);
	}
	আকার_2 = ROUNDUP(stb.st_blksize, blksize);
	যদি (আকার_2 == 0)
		আকার_2 = blksize;
#অন্যথা /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	আকার_2 = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	যদি (bp->cnt >= আকার_2)
		ফেরত (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, আকার_2, 1);
	bp->cnt = আকার_2;
	ফেরত (bp);
}

শূন্য
lostconn(পূর্ণসংখ্যা signo)
{
	যদি (!iamremote)
		(শূন্য)লিখ(STDERR_FILENO, "lost connection\n", 16);
	যদি (signo)
		_exit(1);
	অন্যথা
		exit(1);
}

শূন্য
cleanup_exit(পূর্ণসংখ্যা i)
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
		(শূন্য)waitpid(do_cmd_pid, ফাঁকা, 0);
	যদি (do_cmd_pid2 > 0)
		(শূন্য)waitpid(do_cmd_pid2, ফাঁকা, 0);
	exit(i);
}
