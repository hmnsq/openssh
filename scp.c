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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/time.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/uio.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <dirent.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#ifdef HAVE_FNMATCH_H
#அந்தர்பாவ <fnmatch.h>
#endif
#அந்தர்பாவ <glob.h>
#அந்தர்பாவ <libgen.h>
#அந்தர்பாவ <locale.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <util.h>
#எனில் defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#அந்தர்பாவ <vis.h>
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "atomicio.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "progressmeter.h"
#அந்தர்பாவ "utf8.h"
#அந்தர்பாவ "sftp.h"

#அந்தர்பாவ "sftp-common.h"
#அந்தர்பாவ "sftp-client.h"

வெளி எழுத்து *__progname;

#define COPY_BUFLEN	16384

முழு do_cmd(எழுத்து *, எழுத்து *, எழுத்து *, முழு, முழு, எழுத்து *, முழு *, முழு *, pid_t *);
முழு do_cmd2(எழுத்து *, எழுத்து *, முழு, எழுத்து *, முழு, முழு);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
கட்டமைப்பு bwlimit bwlimit;

/* Name of current file being transferred. */
எழுத்து *curfile;

/* This is set to non-zero to enable verbose mode. */
முழு verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
முழு showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
முழு throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
முழு sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
எழுத்து *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
நிலையற்ற sig_atomic_t interrupted = 0;

முழு sftp_glob(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, முழு,
    முழு (*)(மாறிலி எழுத்து *, முழு), glob_t *); /* proto for sftp-glob.c */

நிலையான வெறுமை
killchild(முழு signo)
{
	எனில் (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(வெறுமை)waitpid(do_cmd_pid, வெற்று, 0);
	}
	எனில் (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(வெறுமை)waitpid(do_cmd_pid2, வெற்று, 0);
	}

	எனில் (signo)
		_exit(1);
	exit(1);
}

நிலையான வெறுமை
suspone(முழு pid, முழு signo)
{
	முழு status;

	எனில் (pid > 1) {
		kill(pid, signo);
		போது (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

நிலையான வெறுமை
suspchild(முழு signo)
{
	முழு save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

நிலையான முழு
do_local_cmd(arglist *a)
{
	எழுத்து *cp;
	முழு status;
	pid_t pid;

	எனில் (a->இலக்கம் == 0)
		fatal("do_local_cmd: no arguments");

	எனில் (verbose_mode) {
		cp = argv_assemble(a->இலக்கம், a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		விடுவி(cp);
	}
	எனில் ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	எனில் (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	போது (waitpid(pid, &status, 0) == -1)
		எனில் (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	எனில் (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		திரும்பு (-1);

	திரும்பு (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

முழு
do_cmd(எழுத்து *program, எழுத்து *host, எழுத்து *remuser, முழு port, முழு subsystem,
    எழுத்து *cmd, முழு *fdin, முழு *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	முழு pin[2], pout[2];
#இல்லையெனில்
	முழு sv[2];
#endif

	எனில் (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	எனில் (port == -1)
		port = sshport;

#ifdef USE_PIPES
	எனில் (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#இல்லையெனில்
	/* Create a socket pair for communicating with ssh. */
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	தேர்வு (*pid) {
	நிலை -1:
		fatal("fork: %s", strerror(errno));
	நிலை 0:
		/* Child. */
#ifdef USE_PIPES
		எனில் (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#இல்லையெனில்
		எனில் (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		எனில் (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		எனில் (remuser != வெற்று) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		எனில் (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	இயல்பு:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#இல்லையெனில்
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		திரும்பு 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
முழு
do_cmd2(எழுத்து *host, எழுத்து *remuser, முழு port, எழுத்து *cmd,
    முழு fdin, முழு fdout)
{
	முழு status;
	pid_t pid;

	எனில் (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	எனில் (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	எனில் (pid == 0) {
		எனில் (dup2(fdin, 0) == -1)
			perror("dup2");
		எனில் (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		எனில் (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		எனில் (remuser != வெற்று) {
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
	} இல்லையெனில் எனில் (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	போது (waitpid(pid, &status, 0) == -1)
		எனில் (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	திரும்பு 0;
}

வகைவரை கட்டமைப்பு {
	size_t cnt;
	எழுத்து *buf;
} BUF;

BUF *allocbuf(BUF *, முழு, முழு);
வெறுமை lostconn(முழு);
முழு okname(எழுத்து *);
வெறுமை run_err(மாறிலி எழுத்து *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
முழு note_err(மாறிலி எழுத்து *,...)
    __attribute__((__format__ (printf, 1, 2)));
வெறுமை verifydir(எழுத்து *);

கட்டமைப்பு passwd *pwd;
uid_t userid;
முழு errs, remin, remout, remin2, remout2;
முழு Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
எழுத்து cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

எண்ணிக்கை scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

முழு response(வெறுமை);
வெறுமை rsource(எழுத்து *, கட்டமைப்பு stat *);
வெறுமை sink(முழு, எழுத்து *[], மாறிலி எழுத்து *);
வெறுமை source(முழு, எழுத்து *[]);
வெறுமை tolocal(முழு, எழுத்து *[], எண்ணிக்கை scp_mode_e, எழுத்து *sftp_direct);
வெறுமை toremote(முழு, எழுத்து *[], எண்ணிக்கை scp_mode_e, எழுத்து *sftp_direct);
வெறுமை usage(வெறுமை);

வெறுமை source_sftp(முழு, எழுத்து *, எழுத்து *, கட்டமைப்பு sftp_conn *);
வெறுமை sink_sftp(முழு, எழுத்து *, மாறிலி எழுத்து *, கட்டமைப்பு sftp_conn *);
வெறுமை throughlocal_sftp(கட்டமைப்பு sftp_conn *, கட்டமைப்பு sftp_conn *,
    எழுத்து *, எழுத்து *);

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	முழு ch, fflag, tflag, status, r, n;
	எழுத்து **newargv, *argv0;
	மாறிலி எழுத்து *errstr;
	வெளி எழுத்து *optarg;
	வெளி முழு optind;
	எண்ணிக்கை scp_mode_e mode = MODE_SFTP;
	எழுத்து *sftp_direct = வெற்று;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), அளவு(*newargv));
	க்கு (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', அளவு(args));
	memset(&remote_remote_args, '\0', அளவு(remote_remote_args));
	args.list = remote_remote_args.list = வெற்று;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	போது ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		தேர்வு (ch) {
		/* User-visible flags. */
		நிலை '1':
			fatal("SSH protocol v.1 is no longer supported");
			நிறுத்து;
		நிலை '2':
			/* Ignored */
			நிறுத்து;
		நிலை 'A':
		நிலை '4':
		நிலை '6':
		நிலை 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			நிறுத்து;
		நிலை 'D':
			sftp_direct = optarg;
			நிறுத்து;
		நிலை '3':
			throughlocal = 1;
			நிறுத்து;
		நிலை 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			நிறுத்து;
		நிலை 'o':
		நிலை 'c':
		நிலை 'i':
		நிலை 'F':
		நிலை 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			நிறுத்து;
		நிலை 'O':
			mode = MODE_SCP;
			நிறுத்து;
		நிலை 's':
			/* Ignored */
			நிறுத்து;
		நிலை 'P':
			sshport = a2port(optarg);
			எனில் (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			நிறுத்து;
		நிலை 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			நிறுத்து;
		நிலை 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			எனில் (errstr != வெற்று)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			நிறுத்து;
		நிலை 'p':
			pflag = 1;
			நிறுத்து;
		நிலை 'r':
			iamrecursive = 1;
			நிறுத்து;
		நிலை 'S':
			ssh_program = xstrdup(optarg);
			நிறுத்து;
		நிலை 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			எனில் (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			இல்லையெனில் எனில் (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			நிறுத்து;
		நிலை 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			நிறுத்து;
		நிலை 'X':
			/* Please keep in sync with sftp.c -X */
			எனில் (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				எனில் (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				எனில் (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} இல்லையெனில் எனில் (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				எனில் (errstr != வெற்று) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} இல்லையெனில் {
				fatal("Invalid -X option");
			}
			நிறுத்து;

		/* Server options. */
		நிலை 'd':
			targetshouldbedirectory = 1;
			நிறுத்து;
		நிலை 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			நிறுத்து;
		நிலை 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_இருமம்);
#endif
			நிறுத்து;
		நிலை 'T':
			Tflag = 1;
			நிறுத்து;
		இயல்பு:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	எனில் (iamremote)
		mode = MODE_SCP;

	எனில் ((pwd = getpwuid(userid = getuid())) == வெற்று)
		fatal("unknown user %u", (u_int) userid);

	எனில் (!isatty(STDOUT_FILENO))
		showprogress = 0;

	எனில் (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} இல்லையெனில் {
		எனில் (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    வெற்று) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	எனில் (fflag) {
		/* Follow "protocol", send data. */
		(வெறுமை) response();
		source(argc, argv);
		exit(errs != 0);
	}
	எனில் (tflag) {
		/* Receive data. */
		sink(argc, argv, வெற்று);
		exit(errs != 0);
	}
	எனில் (argc < 2)
		usage();
	எனில் (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(வெறுமை) snprintf(cmd, அளவு cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(வெறுமை) ssh_signal(SIGPIPE, lostconn);

	எனில் (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	இல்லையெனில் {
		எனில் (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	எனில் (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		எனில் (remin != -1)
		    (வெறுமை) close(remin);
		எனில் (remout != -1)
		    (வெறுமை) close(remout);
		எனில் (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		இல்லையெனில் {
			எனில் (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
நிலையான முழு
scpio(வெறுமை *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	எனில் (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	திரும்பு 0;
}

நிலையான முழு
do_times(முழு fd, முழு verb, மாறிலி கட்டமைப்பு stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	எழுத்து buf[(20 + 7 + 2) * 2 + 2];

	(வெறுமை)snprintf(buf, அளவு(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	எனில் (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(வெறுமை) atomicio(vwrite, fd, buf, strlen(buf));
	திரும்பு (response());
}

நிலையான முழு
parse_scp_uri(மாறிலி எழுத்து *uri, எழுத்து **userp, எழுத்து **hostp, முழு *portp,
    எழுத்து **pathp)
{
	முழு r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	எனில் (r == 0 && *pathp == வெற்று)
		*pathp = xstrdup(".");
	திரும்பு r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
நிலையான முழு
append(எழுத்து *cp, எழுத்து ***ap, size_t *np)
{
	எழுத்து **tmp;

	எனில் ((tmp = reallocarray(*ap, *np + 1, அளவு(*tmp))) == வெற்று)
		திரும்பு -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	திரும்பு 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
நிலையான முழு
find_brace(மாறிலி எழுத்து *pattern, முழு *startp, முழு *endp)
{
	முழு i;
	முழு in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	க்கு (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		தேர்வு (pattern[i]) {
		நிலை '\\':
			/* skip next character */
			எனில் (pattern[i + 1] != '\0')
				i++;
			நிறுத்து;
		நிலை '[':
			in_bracket = 1;
			நிறுத்து;
		நிலை ']':
			in_bracket = 0;
			நிறுத்து;
		நிலை '{':
			எனில் (in_bracket)
				நிறுத்து;
			எனில் (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				நிறுத்து;
			}
			எனில் (*startp == -1)
				*startp = i;
			brace_level++;
			நிறுத்து;
		நிலை '}':
			எனில் (in_bracket)
				நிறுத்து;
			எனில் (*startp < 0) {
				/* Unbalanced brace */
				திரும்பு -1;
			}
			எனில் (--brace_level <= 0)
				*endp = i;
			நிறுத்து;
		}
	}
	/* unbalanced brackets/braces */
	எனில் (*endp < 0 && (*startp >= 0 || in_bracket))
		திரும்பு -1;
	திரும்பு 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
நிலையான முழு
emit_expansion(மாறிலி எழுத்து *pattern, முழு brace_start, முழு brace_end,
    முழு sel_start, முழு sel_end, எழுத்து ***patternsp, size_t *npatternsp)
{
	எழுத்து *cp;
	size_t pattern_len;
	முழு o = 0, tail_len;

	எனில் ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		திரும்பு -1;

	tail_len = strlen(pattern + brace_end + 1);
	எனில் ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == வெற்று)
		திரும்பு -1;

	/* Pattern before initial brace */
	எனில் (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	எனில் (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	எனில் (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	எனில் (append(cp, patternsp, npatternsp) != 0) {
		விடுவி(cp);
		திரும்பு -1;
	}
	திரும்பு 0;
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
நிலையான முழு
brace_expand_one(மாறிலி எழுத்து *pattern, எழுத்து ***patternsp, size_t *npatternsp,
    முழு *expanded, முழு *invalid)
{
	முழு i;
	முழு in_bracket, brace_start, brace_end, brace_level;
	முழு sel_start, sel_end;

	*invalid = *expanded = 0;

	எனில் (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		திரும்பு 0;
	} இல்லையெனில் எனில் (brace_start == -1)
		திரும்பு 0;

	in_bracket = brace_level = 0;
	க்கு (i = sel_start = brace_start + 1; i < brace_end; i++) {
		தேர்வு (pattern[i]) {
		நிலை '{':
			எனில் (in_bracket)
				நிறுத்து;
			brace_level++;
			நிறுத்து;
		நிலை '}':
			எனில் (in_bracket)
				நிறுத்து;
			brace_level--;
			நிறுத்து;
		நிலை '[':
			in_bracket = 1;
			நிறுத்து;
		நிலை ']':
			in_bracket = 0;
			நிறுத்து;
		நிலை '\\':
			எனில் (i < brace_end - 1)
				i++; /* skip */
			நிறுத்து;
		}
		எனில் (pattern[i] == ',' || i == brace_end - 1) {
			எனில் (in_bracket || brace_level > 0)
				தொடர்;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			எனில் (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				திரும்பு -1;
			/* move on to the next selection */
			sel_start = i + 1;
			தொடர்;
		}
	}
	எனில் (in_bracket || brace_level > 0) {
		*invalid = 1;
		திரும்பு 0;
	}
	/* success */
	*expanded = 1;
	திரும்பு 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
நிலையான முழு
brace_expand(மாறிலி எழுத்து *pattern, எழுத்து ***patternsp, size_t *npatternsp)
{
	எழுத்து *cp, *cp2, **active = வெற்று, **done = வெற்று;
	size_t i, nactive = 0, ndone = 0;
	முழு ret = -1, invalid = 0, expanded = 0;

	*patternsp = வெற்று;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	எனில் ((cp = strdup(pattern)) == வெற்று)
		திரும்பு -1;
	எனில் (append(cp, &active, &nactive) != 0) {
		விடுவி(cp);
		திரும்பு -1;
	}
	போது (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		எனில் (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			விடுவி(cp);
			செல் fail;
		}
		எனில் (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		எனில் (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			விடுவி(cp);
			தொடர்;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		எனில் ((cp2 = strrchr(cp, '/')) != வெற்று)
			*cp2++ = '\0';
		இல்லையெனில்
			cp2 = cp;
		எனில் (append(xstrdup(cp2), &done, &ndone) != 0) {
			விடுவி(cp);
			செல் fail;
		}
		விடுவி(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = வெற்று;
	ndone = 0;
	ret = 0;
 fail:
	க்கு (i = 0; i < nactive; i++)
		விடுவி(active[i]);
	விடுவி(active);
	க்கு (i = 0; i < ndone; i++)
		விடுவி(done[i]);
	விடுவி(done);
	திரும்பு ret;
}

நிலையான கட்டமைப்பு sftp_conn *
do_sftp_connect(எழுத்து *host, எழுத்து *user, முழு port, எழுத்து *sftp_direct,
   முழு *reminp, முழு *remoutp, முழு *pidp)
{
	எனில் (sftp_direct == வெற்று) {
		எனில் (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			திரும்பு வெற்று;

	} இல்லையெனில் {
		freeargs(&args);
		addargs(&args, "sftp-server");
		எனில் (do_cmd(sftp_direct, host, வெற்று, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			திரும்பு வெற்று;
	}
	திரும்பு sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

வெறுமை
toremote(முழு argc, எழுத்து **argv, எண்ணிக்கை scp_mode_e mode, எழுத்து *sftp_direct)
{
	எழுத்து *suser = வெற்று, *host = வெற்று, *src = வெற்று;
	எழுத்து *bp, *tuser, *thost, *targ;
	முழு sport = -1, tport = -1;
	கட்டமைப்பு sftp_conn *conn = வெற்று, *conn2 = வெற்று;
	arglist alist;
	முழு i, r, status;
	கட்டமைப்பு stat sb;
	u_int j;

	memset(&alist, '\0', அளவு(alist));
	alist.list = வெற்று;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	எனில் (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		செல் out;
	}
	எனில் (r != 0) {
		எனில் (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			செல் out;
		}
	}

	/* Parse source files */
	க்கு (i = 0; i < argc - 1; i++) {
		விடுவி(suser);
		விடுவி(host);
		விடுவி(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		எனில் (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			தொடர்;
		}
		எனில் (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		எனில் (suser != வெற்று && !okname(suser)) {
			++errs;
			தொடர்;
		}
		எனில் (host && throughlocal) {	/* extended remote to remote */
			எனில் (mode == MODE_SFTP) {
				எனில் (remin == -1 || conn == வெற்று) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					எனில் (conn == வெற்று) {
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
				எனில் (conn2 == வெற்று) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(வெறுமை) close(remin2);
				(வெறுமை) close(remout2);
				remin2 = remout2 = -1;
				எனில் (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				இல்லையெனில் எனில் (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				தொடர்;
			} இல்லையெனில் {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				எனில் (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				விடுவி(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				எனில் (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				விடுவி(bp);
				(வெறுமை) close(remin);
				(வெறுமை) close(remout);
				remin = remout = -1;
			}
		} இல்லையெனில் எனில் (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			எனில் (tuser != வெற்று && !okname(tuser)) {
				++errs;
				தொடர்;
			}
			எனில் (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			க்கு (j = 0; j < remote_remote_args.இலக்கம்; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			எனில் (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			எனில் (suser) {
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
			எனில் (do_local_cmd(&alist) != 0)
				errs = 1;
		} இல்லையெனில் {	/* local to remote */
			எனில் (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				எனில் (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				எனில் (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					எனில் (conn == வெற்று) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				தொடர்;
			}
			/* SCP */
			எனில் (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				எனில் (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				எனில் (response() < 0)
					exit(1);
				விடுவி(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	விடுவி(tuser);
	விடுவி(thost);
	விடுவி(targ);
	விடுவி(suser);
	விடுவி(host);
	விடுவி(src);
	sftp_free(conn);
	sftp_free(conn2);
}

வெறுமை
tolocal(முழு argc, எழுத்து **argv, எண்ணிக்கை scp_mode_e mode, எழுத்து *sftp_direct)
{
	எழுத்து *bp, *host = வெற்று, *src = வெற்று, *suser = வெற்று;
	arglist alist;
	கட்டமைப்பு sftp_conn *conn = வெற்று;
	முழு i, r, sport = -1;

	memset(&alist, '\0', அளவு(alist));
	alist.list = வெற்று;

	க்கு (i = 0; i < argc - 1; i++) {
		விடுவி(suser);
		விடுவி(host);
		விடுவி(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		எனில் (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			தொடர்;
		}
		எனில் (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		எனில் (suser != வெற்று && !okname(suser)) {
			++errs;
			தொடர்;
		}
		எனில் (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			எனில் (iamrecursive)
				addargs(&alist, "-r");
			எனில் (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			எனில் (do_local_cmd(&alist))
				++errs;
			தொடர்;
		}
		/* Remote to local. */
		எனில் (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			எனில் (conn == வெற்று) {
				error("sftp connection failed");
				++errs;
				தொடர்;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(வெறுமை) close(remin);
			(வெறுமை) close(remout);
			remin = remout = -1;
			தொடர்;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		எனில் (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			விடுவி(bp);
			++errs;
			தொடர்;
		}
		விடுவி(bp);
		sink(1, argv + argc - 1, src);
		(வெறுமை) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	விடுவி(suser);
	விடுவி(host);
	விடுவி(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
நிலையான எழுத்து *
prepare_remote_path(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	எனில் (*path == '\0' || strcmp(path, "~") == 0)
		திரும்பு xstrdup(".");
	எனில் (*path != '~')
		திரும்பு xstrdup(path);
	எனில் (strncmp(path, "~/", 2) == 0) {
		எனில் ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			திரும்பு xstrdup(".");
		திரும்பு xstrdup(path + 2 + nslash);
	}
	எனில் (sftp_can_expand_path(conn))
		திரும்பு sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	திரும்பு வெற்று;
}

வெறுமை
source_sftp(முழு argc, எழுத்து *src, எழுத்து *targ, கட்டமைப்பு sftp_conn *conn)
{
	எழுத்து *target = வெற்று, *filename = வெற்று, *abs_dst = வெற்று;
	முழு src_is_dir, target_is_dir;
	Attrib a;
	கட்டமைப்பு stat st;

	memset(&a, '\0', அளவு(a));
	எனில் (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	எனில் ((filename = basename(src)) == வெற்று)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	எனில் (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	எனில் ((target = prepare_remote_path(conn, targ)) == வெற்று)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	எனில் (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		எனில் (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	எனில் (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	இல்லையெனில் {
		abs_dst = target;
		target = வெற்று;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	எனில் (src_is_dir && iamrecursive) {
		எனில் (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} இல்லையெனில் எனில் (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	விடுவி(abs_dst);
	விடுவி(target);
}

வெறுமை
source(முழு argc, எழுத்து **argv)
{
	கட்டமைப்பு stat stb;
	நிலையான BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	முழு fd = -1, haderr, indx;
	எழுத்து *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	முழு len;

	க்கு (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		போது (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		எனில் ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			செல் syserr;
		எனில் (strchr(name, '\n') != வெற்று) {
			strnvis(encname, name, அளவு(encname), VIS_NL);
			name = encname;
		}
		எனில் (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			செல் next;
		}
		எனில் (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			செல் next;
		}
		unset_nonblock(fd);
		தேர்வு (stb.st_mode & S_IFMT) {
		நிலை S_IFREG:
			நிறுத்து;
		நிலை S_IFDIR:
			எனில் (iamrecursive) {
				rsource(name, &stb);
				செல் next;
			}
			/* FALLTHROUGH */
		இயல்பு:
			run_err("%s: not a regular file", name);
			செல் next;
		}
		எனில் ((last = strrchr(name, '/')) == வெற்று)
			last = name;
		இல்லையெனில்
			++last;
		curfile = last;
		எனில் (pflag) {
			எனில் (do_times(remout, verbose_mode, &stb) < 0)
				செல் next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, அளவு buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		எனில் (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(வெறுமை) atomicio(vwrite, remout, buf, strlen(buf));
		எனில் (response() < 0)
			செல் next;
		எனில் ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == வெற்று) {
next:			எனில் (fd != -1) {
				(வெறுமை) close(fd);
				fd = -1;
			}
			தொடர்;
		}
		எனில் (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		க்கு (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			எனில் (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			எனில் (!haderr) {
				எனில் ((nr = atomicio(பட, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			எனில் (haderr) {
				(வெறுமை)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				தொடர்;
			}
			எனில் (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		எனில் (fd != -1) {
			எனில் (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		எனில் (!haderr)
			(வெறுமை) atomicio(vwrite, remout, "", 1);
		இல்லையெனில்
			run_err("%s: %s", name, strerror(haderr));
		(வெறுமை) response();
		எனில் (showprogress)
			stop_progress_meter();
	}
}

வெறுமை
rsource(எழுத்து *name, கட்டமைப்பு stat *statp)
{
	DIR *dirp;
	கட்டமைப்பு dirent *dp;
	எழுத்து *last, *vect[1], path[PATH_MAX];

	எனில் (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		திரும்பு;
	}
	last = strrchr(name, '/');
	எனில் (last == வெற்று)
		last = name;
	இல்லையெனில்
		last++;
	எனில் (pflag) {
		எனில் (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			திரும்பு;
		}
	}
	(வெறுமை) snprintf(path, அளவு path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	எனில் (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(வெறுமை) atomicio(vwrite, remout, path, strlen(path));
	எனில் (response() < 0) {
		closedir(dirp);
		திரும்பு;
	}
	போது ((dp = readdir(dirp)) != வெற்று) {
		எனில் (dp->d_ino == 0)
			தொடர்;
		எனில் (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			தொடர்;
		எனில் (strlen(name) + 1 + strlen(dp->d_name) >= அளவு(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			தொடர்;
		}
		(வெறுமை) snprintf(path, அளவு path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(வெறுமை) closedir(dirp);
	(வெறுமை) atomicio(vwrite, remout, "E\n", 2);
	(வெறுமை) response();
}

வெறுமை
sink_sftp(முழு argc, எழுத்து *dst, மாறிலி எழுத்து *src, கட்டமைப்பு sftp_conn *conn)
{
	எழுத்து *abs_src = வெற்று;
	எழுத்து *abs_dst = வெற்று;
	glob_t g;
	எழுத்து *filename, *tmp = வெற்று;
	முழு i, r, err = 0, dst_is_dir;
	கட்டமைப்பு stat st;

	memset(&g, 0, அளவு(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	எனில் ((abs_src = prepare_remote_path(conn, src)) == வெற்று) {
		err = -1;
		செல் out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	எனில் ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    வெற்று, &g)) != 0) {
		எனில் (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		இல்லையெனில்
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		செல் out;
	}

	/* Did we actually get any matches back from the glob? */
	எனில் (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != வெற்று) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		எனில் (sftp_stat(conn, g.gl_pathv[0], 1, வெற்று) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			செல் out;
		}
	}

	எனில் ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	எனில் (g.gl_matchc > 1 && !dst_is_dir) {
		எனில் (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			செல் out;
		}
		debug2_f("creating destination \"%s\"", dst);
		எனில் (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			செல் out;
		}
		dst_is_dir = 1;
	}

	க்கு (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		எனில் ((filename = basename(tmp)) == வெற்று) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			செல் out;
		}

		/* Special handling for destination of '..' */
		எனில் (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		எனில் (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		இல்லையெனில்
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		எனில் (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			எனில் (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    வெற்று, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} இல்லையெனில் {
			எனில் (sftp_download(conn, g.gl_pathv[i], abs_dst, வெற்று,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		விடுவி(abs_dst);
		abs_dst = வெற்று;
		விடுவி(tmp);
		tmp = வெற்று;
	}

out:
	விடுவி(abs_src);
	விடுவி(tmp);
	globfree(&g);
	எனில் (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((அளவு(type) == 4 && (val) > INT32_MAX) || \
	 (அளவு(type) == 8 && (val) > INT64_MAX) || \
	 (அளவு(type) != 4 && அளவு(type) != 8))

வெறுமை
sink(முழு argc, எழுத்து **argv, மாறிலி எழுத்து *src)
{
	நிலையான BUF buffer;
	கட்டமைப்பு stat stb;
	BUF *bp;
	off_t i;
	size_t j, மொத்தம்;
	முழு amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	முழு setimes, targisdir, wrerr;
	எழுத்து ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	எழுத்து **patterns = வெற்று;
	size_t n, npatterns = 0;
	கட்டமைப்பு timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; செல் screwup; }

	எனில் (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	எனில் (!pflag) {
		(வெறுமை) umask(mask);
		mask |= 07000;
	}
	எனில் (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	எனில் (targetshouldbedirectory)
		verifydir(targ);

	(வெறுமை) atomicio(vwrite, remout, "", 1);
	எனில் (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	எனில் (src != வெற்று && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		எனில் (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	க்கு (first = 1;; first = 0) {
		cp = buf;
		எனில் (atomicio(பட, remin, cp, 1) != 1)
			செல் done;
		எனில் (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		செய் {
			எனில் (atomicio(பட, remin, &ch, அளவு(ch)) != அளவு(ch))
				SCREWUP("lost connection");
			எனில் (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} போது (cp < &buf[அளவு(buf) - 1] && ch != '\n');
		*cp = 0;
		எனில் (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		எனில் (buf[0] == '\01' || buf[0] == '\02') {
			எனில் (iamremote == 0) {
				(வெறுமை) snmprintf(visbuf, அளவு(visbuf),
				    வெற்று, "%s", buf + 1);
				(வெறுமை) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			எனில் (buf[0] == '\02')
				exit(1);
			++errs;
			தொடர்;
		}
		எனில் (buf[0] == 'E') {
			(வெறுமை) atomicio(vwrite, remout, "", 1);
			செல் done;
		}
		எனில் (ch == '\n')
			*--cp = 0;

		cp = buf;
		எனில் (*cp == 'T') {
			setimes++;
			cp++;
			எனில் (!isdigit((unsigned எழுத்து)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			எனில் (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			எனில் (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			எனில் (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			எனில் (!isdigit((unsigned எழுத்து)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			எனில் (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			எனில் (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			எனில் (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(வெறுமை) atomicio(vwrite, remout, "", 1);
			தொடர்;
		}
		எனில் (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			எனில் (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		க்கு (++cp; cp < buf + 5; cp++) {
			எனில் (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		எனில் (!pflag)
			mode &= ~mask;
		எனில் (*cp++ != ' ')
			SCREWUP("mode not delimited");

		எனில் (!isdigit((unsigned எழுத்து)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		எனில் (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		எனில் (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		எனில் (*cp == '\0' || strchr(cp, '/') != வெற்று ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		எனில் (npatterns > 0) {
			க்கு (n = 0; n < npatterns; n++) {
				எனில் (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					நிறுத்து;
			}
			எனில் (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				க்கு (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		எனில் (targisdir) {
			நிலையான எழுத்து *namebuf;
			நிலையான size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			எனில் (need > cursize) {
				விடுவி(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(வெறுமை) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} இல்லையெனில்
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		எனில் (buf[0] == 'D') {
			முழு mod_flag = pflag;
			எனில் (!iamrecursive)
				SCREWUP("received directory without -r");
			எனில் (exists) {
				எனில் (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					செல் bad;
				}
				எனில் (pflag)
					(வெறுமை) chmod(np, mode);
			} இல்லையெனில் {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				எனில் (mkdir(np, mode | S_IRWXU) == -1)
					செல் bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			எனில் (setimes) {
				setimes = 0;
				(வெறுமை) utimes(vect[0], tv);
			}
			எனில் (mod_flag)
				(வெறுமை) chmod(vect[0], mode);
			விடுவி(vect[0]);
			தொடர்;
		}
		omode = mode;
		mode |= S_IWUSR;
		எனில் ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			தொடர்;
		}
		(வெறுமை) atomicio(vwrite, remout, "", 1);
		எனில் ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == வெற்று) {
			(வெறுமை) close(ofd);
			தொடர்;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		எனில் (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		க்கு (மொத்தம் = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			எனில் (i + amt > size)
				amt = size - i;
			மொத்தம் += amt;
			செய் {
				j = atomicio6(பட, remin, cp, amt,
				    scpio, &statbytes);
				எனில் (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} போது (amt > 0);

			எனில் (மொத்தம் == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				எனில் (!wrerr) {
					எனில் (atomicio(vwrite, ofd, bp->buf,
					    மொத்தம்) != மொத்தம்) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				மொத்தம் = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		எனில் (மொத்தம் != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, மொத்தம்) != மொத்தம்) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		எனில் (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		எனில் (pflag) {
			எனில் (exists || omode != mode)
#ifdef HAVE_FCHMOD
				எனில் (fchmod(ofd, omode)) {
#இல்லையெனில் /* HAVE_FCHMOD */
				எனில் (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} இல்லையெனில் {
			எனில் (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				எனில் (fchmod(ofd, omode & ~mask)) {
#இல்லையெனில் /* HAVE_FCHMOD */
				எனில் (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		எனில் (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(வெறுமை) response();
		எனில் (showprogress)
			stop_progress_meter();
		எனில் (setimes && !wrerr) {
			setimes = 0;
			எனில் (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		எனில் (note_err(வெற்று) == 0)
			(வெறுமை) atomicio(vwrite, remout, "", 1);
	}
done:
	க்கு (n = 0; n < npatterns; n++)
		விடுவி(patterns[n]);
	விடுவி(patterns);
	திரும்பு;
screwup:
	க்கு (n = 0; n < npatterns; n++)
		விடுவி(patterns[n]);
	விடுவி(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

வெறுமை
throughlocal_sftp(கட்டமைப்பு sftp_conn *from, கட்டமைப்பு sftp_conn *to,
    எழுத்து *src, எழுத்து *targ)
{
	எழுத்து *target = வெற்று, *filename = வெற்று, *abs_dst = வெற்று;
	எழுத்து *abs_src = வெற்று, *tmp = வெற்று;
	glob_t g;
	முழு i, r, targetisdir, err = 0;

	எனில் ((filename = basename(src)) == வெற்று)
		fatal("basename %s: %s", src, strerror(errno));

	எனில் ((abs_src = prepare_remote_path(from, src)) == வெற்று ||
	    (target = prepare_remote_path(to, targ)) == வெற்று)
		cleanup_exit(255);
	memset(&g, 0, அளவு(g));

	targetisdir = sftp_remote_is_dir(to, target);
	எனில் (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		செல் out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	எனில் ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    வெற்று, &g)) != 0) {
		எனில் (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		இல்லையெனில்
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		செல் out;
	}

	/* Did we actually get any matches back from the glob? */
	எனில் (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != வெற்று) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		எனில் (sftp_stat(from, g.gl_pathv[0], 1, வெற்று) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			செல் out;
		}
	}

	க்கு (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		எனில் ((filename = basename(tmp)) == வெற்று) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			செல் out;
		}

		/* Special handling for source of '..' */
		எனில் (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		எனில் (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		இல்லையெனில்
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		எனில் (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			எனில் (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    வெற்று, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} இல்லையெனில் {
			எனில் (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    வெற்று, pflag) == -1)
				err = -1;
		}
		விடுவி(abs_dst);
		abs_dst = வெற்று;
		விடுவி(tmp);
		tmp = வெற்று;
	}

out:
	விடுவி(abs_src);
	விடுவி(abs_dst);
	விடுவி(target);
	விடுவி(tmp);
	globfree(&g);
	எனில் (err == -1)
		errs = 1;
}

முழு
response(வெறுமை)
{
	எழுத்து ch, *cp, resp, rbuf[2048], visbuf[2048];

	எனில் (atomicio(பட, remin, &resp, அளவு(resp)) != அளவு(resp))
		lostconn(0);

	cp = rbuf;
	தேர்வு (resp) {
	நிலை 0:		/* ok */
		திரும்பு (0);
	இயல்பு:
		*cp++ = resp;
		/* FALLTHROUGH */
	நிலை 1:		/* error, followed by error msg */
	நிலை 2:		/* fatal error, "" */
		செய் {
			எனில் (atomicio(பட, remin, &ch, அளவு(ch)) != அளவு(ch))
				lostconn(0);
			*cp++ = ch;
		} போது (cp < &rbuf[அளவு(rbuf) - 1] && ch != '\n');

		எனில் (!iamremote) {
			cp[-1] = '\0';
			(வெறுமை) snmprintf(visbuf, அளவு(visbuf),
			    வெற்று, "%s\n", rbuf);
			(வெறுமை) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		எனில் (resp == 1)
			திரும்பு (-1);
		exit(1);
	}
	/* NOTREACHED */
}

வெறுமை
usage(வெறுமை)
{
	(வெறுமை) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

வெறுமை
run_err(மாறிலி எழுத்து *fmt,...)
{
	நிலையான FILE *fp;
	va_list ap;

	++errs;
	எனில் (fp != வெற்று || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(வெறுமை) fprintf(fp, "%c", 0x01);
		(வெறுமை) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(வெறுமை) vfprintf(fp, fmt, ap);
		va_end(ap);
		(வெறுமை) fprintf(fp, "\n");
		(வெறுமை) fflush(fp);
	}

	எனில் (!iamremote) {
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
முழு
note_err(மாறிலி எழுத்து *fmt, ...)
{
	நிலையான எழுத்து *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	எனில் (fmt == வெற்று) {
		எனில் (emsg == வெற்று)
			திரும்பு 0;
		run_err("%s", emsg);
		விடுவி(emsg);
		emsg = வெற்று;
		திரும்பு -1;
	}

	errs++;
	/* Prefer first-noted error */
	எனில் (emsg != வெற்று)
		திரும்பு -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, வெற்று, fmt, ap);
	va_end(ap);
	திரும்பு -1;
}

வெறுமை
verifydir(எழுத்து *cp)
{
	கட்டமைப்பு stat stb;

	எனில் (!stat(cp, &stb)) {
		எனில் (S_ISDIR(stb.st_mode))
			திரும்பு;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

முழு
okname(எழுத்து *cp0)
{
	முழு c;
	எழுத்து *cp;

	cp = cp0;
	செய் {
		c = (முழு)*cp;
		எனில் (c & 0200)
			செல் bad;
		எனில் (!isalpha(c) && !isdigit((unsigned எழுத்து)c)) {
			தேர்வு (c) {
			நிலை '\'':
			நிலை '"':
			நிலை '`':
			நிலை ' ':
			நிலை '#':
				செல் bad;
			இயல்பு:
				நிறுத்து;
			}
		}
	} போது (*++cp);
	திரும்பு (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	திரும்பு (0);
}

BUF *
allocbuf(BUF *bp, முழு fd, முழு blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	கட்டமைப்பு stat stb;

	எனில் (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		திரும்பு (வெற்று);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	எனில் (size == 0)
		size = blksize;
#இல்லையெனில் /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	எனில் (bp->cnt >= size)
		திரும்பு (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	திரும்பு (bp);
}

வெறுமை
lostconn(முழு signo)
{
	எனில் (!iamremote)
		(வெறுமை)லிக(STDERR_FILENO, "lost connection\n", 16);
	எனில் (signo)
		_exit(1);
	இல்லையெனில்
		exit(1);
}

வெறுமை
cleanup_exit(முழு i)
{
	எனில் (remin > 0)
		close(remin);
	எனில் (remout > 0)
		close(remout);
	எனில் (remin2 > 0)
		close(remin2);
	எனில் (remout2 > 0)
		close(remout2);
	எனில் (do_cmd_pid > 0)
		(வெறுமை)waitpid(do_cmd_pid, வெற்று, 0);
	எனில் (do_cmd_pid2 > 0)
		(வெறுமை)waitpid(do_cmd_pid2, வெற்று, 0);
	exit(i);
}
