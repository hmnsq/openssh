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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <sys/wait.h>
#અન્તર્ભાવ <sys/uio.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <dirent.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#ifdef HAVE_FNMATCH_H
#અન્તર્ભાવ <fnmatch.h>
#endif
#અન્તર્ભાવ <glob.h>
#અન્તર્ભાવ <libgen.h>
#અન્તર્ભાવ <locale.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <util.h>
#જો defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#અન્તર્ભાવ <vis.h>
#endif

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "progressmeter.h"
#અન્તર્ભાવ "utf8.h"
#અન્તર્ભાવ "sftp.h"

#અન્તર્ભાવ "sftp-common.h"
#અન્તર્ભાવ "sftp-client.h"

બાહ્ય અક્ષર *__progname;

#define COPY_BUFLEN	16384

પૂર્ણાંક do_cmd(અક્ષર *, અક્ષર *, અક્ષર *, પૂર્ણાંક, પૂર્ણાંક, અક્ષર *, પૂર્ણાંક *, પૂર્ણાંક *, pid_t *);
પૂર્ણાંક do_cmd2(અક્ષર *, અક્ષર *, પૂર્ણાંક, અક્ષર *, પૂર્ણાંક, પૂર્ણાંક);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
સંરચના bwlimit bwlimit;

/* Name of current file being transferred. */
અક્ષર *curfile;

/* This is set to non-zero to enable verbose mode. */
પૂર્ણાંક verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
પૂર્ણાંક showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
પૂર્ણાંક throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
પૂર્ણાંક sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
અક્ષર *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
અસ્થિર sig_atomic_t interrupted = 0;

પૂર્ણાંક sftp_glob(સંરચના sftp_conn *, અચલ અક્ષર *, પૂર્ણાંક,
    પૂર્ણાંક (*)(અચલ અક્ષર *, પૂર્ણાંક), glob_t *); /* proto for sftp-glob.c */

સ્થિર શૂન્ય
killchild(પૂર્ણાંક signo)
{
	જો (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(શૂન્ય)waitpid(do_cmd_pid, ખાલી, 0);
	}
	જો (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(શૂન્ય)waitpid(do_cmd_pid2, ખાલી, 0);
	}

	જો (signo)
		_exit(1);
	exit(1);
}

સ્થિર શૂન્ય
suspone(પૂર્ણાંક pid, પૂર્ણાંક signo)
{
	પૂર્ણાંક status;

	જો (pid > 1) {
		kill(pid, signo);
		જ્યારે (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

સ્થિર શૂન્ય
suspchild(પૂર્ણાંક signo)
{
	પૂર્ણાંક save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

સ્થિર પૂર્ણાંક
do_local_cmd(arglist *a)
{
	અક્ષર *cp;
	પૂર્ણાંક status;
	pid_t pid;

	જો (a->અંક == 0)
		fatal("do_local_cmd: no arguments");

	જો (verbose_mode) {
		cp = argv_assemble(a->અંક, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		મુક્ત(cp);
	}
	જો ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	જો (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	જ્યારે (waitpid(pid, &status, 0) == -1)
		જો (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	જો (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		પાછા (-1);

	પાછા (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

પૂર્ણાંક
do_cmd(અક્ષર *program, અક્ષર *host, અક્ષર *remuser, પૂર્ણાંક port, પૂર્ણાંક subsystem,
    અક્ષર *cmd, પૂર્ણાંક *fdin, પૂર્ણાંક *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	પૂર્ણાંક pin[2], pout[2];
#નહીંતર
	પૂર્ણાંક sv[2];
#endif

	જો (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	જો (port == -1)
		port = sshport;

#ifdef USE_PIPES
	જો (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#નહીંતર
	/* Create a socket pair for communicating with ssh. */
	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	પસંદગી (*pid) {
	સ્થિતિ -1:
		fatal("fork: %s", strerror(errno));
	સ્થિતિ 0:
		/* Child. */
#ifdef USE_PIPES
		જો (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#નહીંતર
		જો (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		જો (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		જો (remuser != ખાલી) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		જો (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	મૂળભૂત:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#નહીંતર
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		પાછા 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
પૂર્ણાંક
do_cmd2(અક્ષર *host, અક્ષર *remuser, પૂર્ણાંક port, અક્ષર *cmd,
    પૂર્ણાંક fdin, પૂર્ણાંક fdout)
{
	પૂર્ણાંક status;
	pid_t pid;

	જો (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	જો (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	જો (pid == 0) {
		જો (dup2(fdin, 0) == -1)
			perror("dup2");
		જો (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		જો (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		જો (remuser != ખાલી) {
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
	} નહીંતર જો (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	જ્યારે (waitpid(pid, &status, 0) == -1)
		જો (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	પાછા 0;
}

પ્રકારવ્યાખ્યા સંરચના {
	size_t cnt;
	અક્ષર *buf;
} BUF;

BUF *allocbuf(BUF *, પૂર્ણાંક, પૂર્ણાંક);
શૂન્ય lostconn(પૂર્ણાંક);
પૂર્ણાંક okname(અક્ષર *);
શૂન્ય run_err(અચલ અક્ષર *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
પૂર્ણાંક note_err(અચલ અક્ષર *,...)
    __attribute__((__format__ (printf, 1, 2)));
શૂન્ય verifydir(અક્ષર *);

સંરચના passwd *pwd;
uid_t userid;
પૂર્ણાંક errs, remin, remout, remin2, remout2;
પૂર્ણાંક Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
અક્ષર cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

ગણના scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

પૂર્ણાંક response(શૂન્ય);
શૂન્ય rsource(અક્ષર *, સંરચના stat *);
શૂન્ય sink(પૂર્ણાંક, અક્ષર *[], અચલ અક્ષર *);
શૂન્ય source(પૂર્ણાંક, અક્ષર *[]);
શૂન્ય tolocal(પૂર્ણાંક, અક્ષર *[], ગણના scp_mode_e, અક્ષર *sftp_direct);
શૂન્ય toremote(પૂર્ણાંક, અક્ષર *[], ગણના scp_mode_e, અક્ષર *sftp_direct);
શૂન્ય usage(શૂન્ય);

શૂન્ય source_sftp(પૂર્ણાંક, અક્ષર *, અક્ષર *, સંરચના sftp_conn *);
શૂન્ય sink_sftp(પૂર્ણાંક, અક્ષર *, અચલ અક્ષર *, સંરચના sftp_conn *);
શૂન્ય throughlocal_sftp(સંરચના sftp_conn *, સંરચના sftp_conn *,
    અક્ષર *, અક્ષર *);

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક ch, fflag, tflag, status, r, n;
	અક્ષર **newargv, *argv0;
	અચલ અક્ષર *errstr;
	બાહ્ય અક્ષર *optarg;
	બાહ્ય પૂર્ણાંક optind;
	ગણના scp_mode_e mode = MODE_SFTP;
	અક્ષર *sftp_direct = ખાલી;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), કદ(*newargv));
	માટે (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', કદ(args));
	memset(&remote_remote_args, '\0', કદ(remote_remote_args));
	args.list = remote_remote_args.list = ખાલી;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	જ્યારે ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		પસંદગી (ch) {
		/* User-visible flags. */
		સ્થિતિ '1':
			fatal("SSH protocol v.1 is no longer supported");
			તોડો;
		સ્થિતિ '2':
			/* Ignored */
			તોડો;
		સ્થિતિ 'A':
		સ્થિતિ '4':
		સ્થિતિ '6':
		સ્થિતિ 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			તોડો;
		સ્થિતિ 'D':
			sftp_direct = optarg;
			તોડો;
		સ્થિતિ '3':
			throughlocal = 1;
			તોડો;
		સ્થિતિ 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			તોડો;
		સ્થિતિ 'o':
		સ્થિતિ 'c':
		સ્થિતિ 'i':
		સ્થિતિ 'F':
		સ્થિતિ 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			તોડો;
		સ્થિતિ 'O':
			mode = MODE_SCP;
			તોડો;
		સ્થિતિ 's':
			/* Ignored */
			તોડો;
		સ્થિતિ 'P':
			sshport = a2port(optarg);
			જો (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			તોડો;
		સ્થિતિ 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			તોડો;
		સ્થિતિ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			જો (errstr != ખાલી)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			તોડો;
		સ્થિતિ 'p':
			pflag = 1;
			તોડો;
		સ્થિતિ 'r':
			iamrecursive = 1;
			તોડો;
		સ્થિતિ 'S':
			ssh_program = xstrdup(optarg);
			તોડો;
		સ્થિતિ 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			જો (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			નહીંતર જો (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			તોડો;
		સ્થિતિ 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			તોડો;
		સ્થિતિ 'X':
			/* Please keep in sync with sftp.c -X */
			જો (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				જો (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				જો (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} નહીંતર જો (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				જો (errstr != ખાલી) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} નહીંતર {
				fatal("Invalid -X option");
			}
			તોડો;

		/* Server options. */
		સ્થિતિ 'd':
			targetshouldbedirectory = 1;
			તોડો;
		સ્થિતિ 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			તોડો;
		સ્થિતિ 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_દ્વિઅંકી);
#endif
			તોડો;
		સ્થિતિ 'T':
			Tflag = 1;
			તોડો;
		મૂળભૂત:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	જો (iamremote)
		mode = MODE_SCP;

	જો ((pwd = getpwuid(userid = getuid())) == ખાલી)
		fatal("unknown user %u", (u_int) userid);

	જો (!isatty(STDOUT_FILENO))
		showprogress = 0;

	જો (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} નહીંતર {
		જો (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ખાલી) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	જો (fflag) {
		/* Follow "protocol", send data. */
		(શૂન્ય) response();
		source(argc, argv);
		exit(errs != 0);
	}
	જો (tflag) {
		/* Receive data. */
		sink(argc, argv, ખાલી);
		exit(errs != 0);
	}
	જો (argc < 2)
		usage();
	જો (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(શૂન્ય) snprintf(cmd, કદ cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(શૂન્ય) ssh_signal(SIGPIPE, lostconn);

	જો (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	નહીંતર {
		જો (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	જો (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		જો (remin != -1)
		    (શૂન્ય) close(remin);
		જો (remout != -1)
		    (શૂન્ય) close(remout);
		જો (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		નહીંતર {
			જો (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
સ્થિર પૂર્ણાંક
scpio(શૂન્ય *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	જો (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
do_times(પૂર્ણાંક fd, પૂર્ણાંક verb, અચલ સંરચના stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	અક્ષર buf[(20 + 7 + 2) * 2 + 2];

	(શૂન્ય)snprintf(buf, કદ(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	જો (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(શૂન્ય) atomicio(vwrite, fd, buf, strlen(buf));
	પાછા (response());
}

સ્થિર પૂર્ણાંક
parse_scp_uri(અચલ અક્ષર *uri, અક્ષર **userp, અક્ષર **hostp, પૂર્ણાંક *portp,
    અક્ષર **pathp)
{
	પૂર્ણાંક r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	જો (r == 0 && *pathp == ખાલી)
		*pathp = xstrdup(".");
	પાછા r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
સ્થિર પૂર્ણાંક
append(અક્ષર *cp, અક્ષર ***ap, size_t *np)
{
	અક્ષર **tmp;

	જો ((tmp = reallocarray(*ap, *np + 1, કદ(*tmp))) == ખાલી)
		પાછા -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	પાછા 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
સ્થિર પૂર્ણાંક
find_brace(અચલ અક્ષર *pattern, પૂર્ણાંક *startp, પૂર્ણાંક *endp)
{
	પૂર્ણાંક i;
	પૂર્ણાંક in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	માટે (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		પસંદગી (pattern[i]) {
		સ્થિતિ '\\':
			/* skip next character */
			જો (pattern[i + 1] != '\0')
				i++;
			તોડો;
		સ્થિતિ '[':
			in_bracket = 1;
			તોડો;
		સ્થિતિ ']':
			in_bracket = 0;
			તોડો;
		સ્થિતિ '{':
			જો (in_bracket)
				તોડો;
			જો (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				તોડો;
			}
			જો (*startp == -1)
				*startp = i;
			brace_level++;
			તોડો;
		સ્થિતિ '}':
			જો (in_bracket)
				તોડો;
			જો (*startp < 0) {
				/* Unbalanced brace */
				પાછા -1;
			}
			જો (--brace_level <= 0)
				*endp = i;
			તોડો;
		}
	}
	/* unbalanced brackets/braces */
	જો (*endp < 0 && (*startp >= 0 || in_bracket))
		પાછા -1;
	પાછા 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
સ્થિર પૂર્ણાંક
emit_expansion(અચલ અક્ષર *pattern, પૂર્ણાંક brace_start, પૂર્ણાંક brace_end,
    પૂર્ણાંક sel_start, પૂર્ણાંક sel_end, અક્ષર ***patternsp, size_t *npatternsp)
{
	અક્ષર *cp;
	size_t pattern_len;
	પૂર્ણાંક o = 0, tail_len;

	જો ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		પાછા -1;

	tail_len = strlen(pattern + brace_end + 1);
	જો ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == ખાલી)
		પાછા -1;

	/* Pattern before initial brace */
	જો (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	જો (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	જો (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	જો (append(cp, patternsp, npatternsp) != 0) {
		મુક્ત(cp);
		પાછા -1;
	}
	પાછા 0;
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
સ્થિર પૂર્ણાંક
brace_expand_one(અચલ અક્ષર *pattern, અક્ષર ***patternsp, size_t *npatternsp,
    પૂર્ણાંક *expanded, પૂર્ણાંક *invalid)
{
	પૂર્ણાંક i;
	પૂર્ણાંક in_bracket, brace_start, brace_end, brace_level;
	પૂર્ણાંક sel_start, sel_end;

	*invalid = *expanded = 0;

	જો (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		પાછા 0;
	} નહીંતર જો (brace_start == -1)
		પાછા 0;

	in_bracket = brace_level = 0;
	માટે (i = sel_start = brace_start + 1; i < brace_end; i++) {
		પસંદગી (pattern[i]) {
		સ્થિતિ '{':
			જો (in_bracket)
				તોડો;
			brace_level++;
			તોડો;
		સ્થિતિ '}':
			જો (in_bracket)
				તોડો;
			brace_level--;
			તોડો;
		સ્થિતિ '[':
			in_bracket = 1;
			તોડો;
		સ્થિતિ ']':
			in_bracket = 0;
			તોડો;
		સ્થિતિ '\\':
			જો (i < brace_end - 1)
				i++; /* skip */
			તોડો;
		}
		જો (pattern[i] == ',' || i == brace_end - 1) {
			જો (in_bracket || brace_level > 0)
				ચાલુ;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			જો (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				પાછા -1;
			/* move on to the next selection */
			sel_start = i + 1;
			ચાલુ;
		}
	}
	જો (in_bracket || brace_level > 0) {
		*invalid = 1;
		પાછા 0;
	}
	/* success */
	*expanded = 1;
	પાછા 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
સ્થિર પૂર્ણાંક
brace_expand(અચલ અક્ષર *pattern, અક્ષર ***patternsp, size_t *npatternsp)
{
	અક્ષર *cp, *cp2, **active = ખાલી, **done = ખાલી;
	size_t i, nactive = 0, ndone = 0;
	પૂર્ણાંક ret = -1, invalid = 0, expanded = 0;

	*patternsp = ખાલી;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	જો ((cp = strdup(pattern)) == ખાલી)
		પાછા -1;
	જો (append(cp, &active, &nactive) != 0) {
		મુક્ત(cp);
		પાછા -1;
	}
	જ્યારે (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		જો (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			મુક્ત(cp);
			જાઓ fail;
		}
		જો (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		જો (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			મુક્ત(cp);
			ચાલુ;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		જો ((cp2 = strrchr(cp, '/')) != ખાલી)
			*cp2++ = '\0';
		નહીંતર
			cp2 = cp;
		જો (append(xstrdup(cp2), &done, &ndone) != 0) {
			મુક્ત(cp);
			જાઓ fail;
		}
		મુક્ત(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = ખાલી;
	ndone = 0;
	ret = 0;
 fail:
	માટે (i = 0; i < nactive; i++)
		મુક્ત(active[i]);
	મુક્ત(active);
	માટે (i = 0; i < ndone; i++)
		મુક્ત(done[i]);
	મુક્ત(done);
	પાછા ret;
}

સ્થિર સંરચના sftp_conn *
do_sftp_connect(અક્ષર *host, અક્ષર *user, પૂર્ણાંક port, અક્ષર *sftp_direct,
   પૂર્ણાંક *reminp, પૂર્ણાંક *remoutp, પૂર્ણાંક *pidp)
{
	જો (sftp_direct == ખાલી) {
		જો (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			પાછા ખાલી;

	} નહીંતર {
		freeargs(&args);
		addargs(&args, "sftp-server");
		જો (do_cmd(sftp_direct, host, ખાલી, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			પાછા ખાલી;
	}
	પાછા sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

શૂન્ય
toremote(પૂર્ણાંક argc, અક્ષર **argv, ગણના scp_mode_e mode, અક્ષર *sftp_direct)
{
	અક્ષર *suser = ખાલી, *host = ખાલી, *src = ખાલી;
	અક્ષર *bp, *tuser, *thost, *targ;
	પૂર્ણાંક sport = -1, tport = -1;
	સંરચના sftp_conn *conn = ખાલી, *conn2 = ખાલી;
	arglist alist;
	પૂર્ણાંક i, r, status;
	સંરચના stat sb;
	u_int j;

	memset(&alist, '\0', કદ(alist));
	alist.list = ખાલી;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	જો (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		જાઓ out;
	}
	જો (r != 0) {
		જો (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			જાઓ out;
		}
	}

	/* Parse source files */
	માટે (i = 0; i < argc - 1; i++) {
		મુક્ત(suser);
		મુક્ત(host);
		મુક્ત(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		જો (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ચાલુ;
		}
		જો (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		જો (suser != ખાલી && !okname(suser)) {
			++errs;
			ચાલુ;
		}
		જો (host && throughlocal) {	/* extended remote to remote */
			જો (mode == MODE_SFTP) {
				જો (remin == -1 || conn == ખાલી) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					જો (conn == ખાલી) {
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
				જો (conn2 == ખાલી) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(શૂન્ય) close(remin2);
				(શૂન્ય) close(remout2);
				remin2 = remout2 = -1;
				જો (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				નહીંતર જો (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				ચાલુ;
			} નહીંતર {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				જો (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				મુક્ત(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				જો (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				મુક્ત(bp);
				(શૂન્ય) close(remin);
				(શૂન્ય) close(remout);
				remin = remout = -1;
			}
		} નહીંતર જો (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			જો (tuser != ખાલી && !okname(tuser)) {
				++errs;
				ચાલુ;
			}
			જો (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			માટે (j = 0; j < remote_remote_args.અંક; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			જો (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			જો (suser) {
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
			જો (do_local_cmd(&alist) != 0)
				errs = 1;
		} નહીંતર {	/* local to remote */
			જો (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				જો (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				જો (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					જો (conn == ખાલી) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				ચાલુ;
			}
			/* SCP */
			જો (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				જો (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				જો (response() < 0)
					exit(1);
				મુક્ત(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	મુક્ત(tuser);
	મુક્ત(thost);
	મુક્ત(targ);
	મુક્ત(suser);
	મુક્ત(host);
	મુક્ત(src);
	sftp_free(conn);
	sftp_free(conn2);
}

શૂન્ય
tolocal(પૂર્ણાંક argc, અક્ષર **argv, ગણના scp_mode_e mode, અક્ષર *sftp_direct)
{
	અક્ષર *bp, *host = ખાલી, *src = ખાલી, *suser = ખાલી;
	arglist alist;
	સંરચના sftp_conn *conn = ખાલી;
	પૂર્ણાંક i, r, sport = -1;

	memset(&alist, '\0', કદ(alist));
	alist.list = ખાલી;

	માટે (i = 0; i < argc - 1; i++) {
		મુક્ત(suser);
		મુક્ત(host);
		મુક્ત(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		જો (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			ચાલુ;
		}
		જો (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		જો (suser != ખાલી && !okname(suser)) {
			++errs;
			ચાલુ;
		}
		જો (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			જો (iamrecursive)
				addargs(&alist, "-r");
			જો (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			જો (do_local_cmd(&alist))
				++errs;
			ચાલુ;
		}
		/* Remote to local. */
		જો (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			જો (conn == ખાલી) {
				error("sftp connection failed");
				++errs;
				ચાલુ;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(શૂન્ય) close(remin);
			(શૂન્ય) close(remout);
			remin = remout = -1;
			ચાલુ;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		જો (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			મુક્ત(bp);
			++errs;
			ચાલુ;
		}
		મુક્ત(bp);
		sink(1, argv + argc - 1, src);
		(શૂન્ય) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	મુક્ત(suser);
	મુક્ત(host);
	મુક્ત(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
સ્થિર અક્ષર *
prepare_remote_path(સંરચના sftp_conn *conn, અચલ અક્ષર *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	જો (*path == '\0' || strcmp(path, "~") == 0)
		પાછા xstrdup(".");
	જો (*path != '~')
		પાછા xstrdup(path);
	જો (strncmp(path, "~/", 2) == 0) {
		જો ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			પાછા xstrdup(".");
		પાછા xstrdup(path + 2 + nslash);
	}
	જો (sftp_can_expand_path(conn))
		પાછા sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	પાછા ખાલી;
}

શૂન્ય
source_sftp(પૂર્ણાંક argc, અક્ષર *src, અક્ષર *targ, સંરચના sftp_conn *conn)
{
	અક્ષર *target = ખાલી, *filename = ખાલી, *abs_dst = ખાલી;
	પૂર્ણાંક src_is_dir, target_is_dir;
	Attrib a;
	સંરચના stat st;

	memset(&a, '\0', કદ(a));
	જો (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	જો ((filename = basename(src)) == ખાલી)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	જો (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	જો ((target = prepare_remote_path(conn, targ)) == ખાલી)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	જો (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		જો (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	જો (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	નહીંતર {
		abs_dst = target;
		target = ખાલી;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	જો (src_is_dir && iamrecursive) {
		જો (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} નહીંતર જો (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	મુક્ત(abs_dst);
	મુક્ત(target);
}

શૂન્ય
source(પૂર્ણાંક argc, અક્ષર **argv)
{
	સંરચના stat stb;
	સ્થિર BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	પૂર્ણાંક fd = -1, haderr, indx;
	અક્ષર *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	પૂર્ણાંક len;

	માટે (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		જ્યારે (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		જો ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			જાઓ syserr;
		જો (strchr(name, '\n') != ખાલી) {
			strnvis(encname, name, કદ(encname), VIS_NL);
			name = encname;
		}
		જો (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			જાઓ next;
		}
		જો (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			જાઓ next;
		}
		unset_nonblock(fd);
		પસંદગી (stb.st_mode & S_IFMT) {
		સ્થિતિ S_IFREG:
			તોડો;
		સ્થિતિ S_IFDIR:
			જો (iamrecursive) {
				rsource(name, &stb);
				જાઓ next;
			}
			/* FALLTHROUGH */
		મૂળભૂત:
			run_err("%s: not a regular file", name);
			જાઓ next;
		}
		જો ((last = strrchr(name, '/')) == ખાલી)
			last = name;
		નહીંતર
			++last;
		curfile = last;
		જો (pflag) {
			જો (do_times(remout, verbose_mode, &stb) < 0)
				જાઓ next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, કદ buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		જો (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(શૂન્ય) atomicio(vwrite, remout, buf, strlen(buf));
		જો (response() < 0)
			જાઓ next;
		જો ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == ખાલી) {
next:			જો (fd != -1) {
				(શૂન્ય) close(fd);
				fd = -1;
			}
			ચાલુ;
		}
		જો (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		માટે (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			જો (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			જો (!haderr) {
				જો ((nr = atomicio(પઠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			જો (haderr) {
				(શૂન્ય)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				ચાલુ;
			}
			જો (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		જો (fd != -1) {
			જો (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		જો (!haderr)
			(શૂન્ય) atomicio(vwrite, remout, "", 1);
		નહીંતર
			run_err("%s: %s", name, strerror(haderr));
		(શૂન્ય) response();
		જો (showprogress)
			stop_progress_meter();
	}
}

શૂન્ય
rsource(અક્ષર *name, સંરચના stat *statp)
{
	DIR *dirp;
	સંરચના dirent *dp;
	અક્ષર *last, *vect[1], path[PATH_MAX];

	જો (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		પાછા;
	}
	last = strrchr(name, '/');
	જો (last == ખાલી)
		last = name;
	નહીંતર
		last++;
	જો (pflag) {
		જો (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			પાછા;
		}
	}
	(શૂન્ય) snprintf(path, કદ path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	જો (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(શૂન્ય) atomicio(vwrite, remout, path, strlen(path));
	જો (response() < 0) {
		closedir(dirp);
		પાછા;
	}
	જ્યારે ((dp = readdir(dirp)) != ખાલી) {
		જો (dp->d_ino == 0)
			ચાલુ;
		જો (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			ચાલુ;
		જો (strlen(name) + 1 + strlen(dp->d_name) >= કદ(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			ચાલુ;
		}
		(શૂન્ય) snprintf(path, કદ path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(શૂન્ય) closedir(dirp);
	(શૂન્ય) atomicio(vwrite, remout, "E\n", 2);
	(શૂન્ય) response();
}

શૂન્ય
sink_sftp(પૂર્ણાંક argc, અક્ષર *dst, અચલ અક્ષર *src, સંરચના sftp_conn *conn)
{
	અક્ષર *abs_src = ખાલી;
	અક્ષર *abs_dst = ખાલી;
	glob_t g;
	અક્ષર *filename, *tmp = ખાલી;
	પૂર્ણાંક i, r, err = 0, dst_is_dir;
	સંરચના stat st;

	memset(&g, 0, કદ(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	જો ((abs_src = prepare_remote_path(conn, src)) == ખાલી) {
		err = -1;
		જાઓ out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	જો ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ખાલી, &g)) != 0) {
		જો (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		નહીંતર
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		જાઓ out;
	}

	/* Did we actually get any matches back from the glob? */
	જો (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ખાલી) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		જો (sftp_stat(conn, g.gl_pathv[0], 1, ખાલી) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			જાઓ out;
		}
	}

	જો ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	જો (g.gl_matchc > 1 && !dst_is_dir) {
		જો (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			જાઓ out;
		}
		debug2_f("creating destination \"%s\"", dst);
		જો (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			જાઓ out;
		}
		dst_is_dir = 1;
	}

	માટે (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		જો ((filename = basename(tmp)) == ખાલી) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			જાઓ out;
		}

		/* Special handling for destination of '..' */
		જો (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		જો (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		નહીંતર
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		જો (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			જો (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ખાલી, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} નહીંતર {
			જો (sftp_download(conn, g.gl_pathv[i], abs_dst, ખાલી,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		મુક્ત(abs_dst);
		abs_dst = ખાલી;
		મુક્ત(tmp);
		tmp = ખાલી;
	}

out:
	મુક્ત(abs_src);
	મુક્ત(tmp);
	globfree(&g);
	જો (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((કદ(type) == 4 && (val) > INT32_MAX) || \
	 (કદ(type) == 8 && (val) > INT64_MAX) || \
	 (કદ(type) != 4 && કદ(type) != 8))

શૂન્ય
sink(પૂર્ણાંક argc, અક્ષર **argv, અચલ અક્ષર *src)
{
	સ્થિર BUF buffer;
	સંરચના stat stb;
	BUF *bp;
	off_t i;
	size_t j, ગણતરી;
	પૂર્ણાંક amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	પૂર્ણાંક setimes, targisdir, wrerr;
	અક્ષર ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	અક્ષર **patterns = ખાલી;
	size_t n, npatterns = 0;
	સંરચના timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; જાઓ screwup; }

	જો (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	જો (!pflag) {
		(શૂન્ય) umask(mask);
		mask |= 07000;
	}
	જો (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	જો (targetshouldbedirectory)
		verifydir(targ);

	(શૂન્ય) atomicio(vwrite, remout, "", 1);
	જો (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	જો (src != ખાલી && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		જો (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	માટે (first = 1;; first = 0) {
		cp = buf;
		જો (atomicio(પઠ, remin, cp, 1) != 1)
			જાઓ done;
		જો (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		કરો {
			જો (atomicio(પઠ, remin, &ch, કદ(ch)) != કદ(ch))
				SCREWUP("lost connection");
			જો (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} જ્યારે (cp < &buf[કદ(buf) - 1] && ch != '\n');
		*cp = 0;
		જો (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		જો (buf[0] == '\01' || buf[0] == '\02') {
			જો (iamremote == 0) {
				(શૂન્ય) snmprintf(visbuf, કદ(visbuf),
				    ખાલી, "%s", buf + 1);
				(શૂન્ય) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			જો (buf[0] == '\02')
				exit(1);
			++errs;
			ચાલુ;
		}
		જો (buf[0] == 'E') {
			(શૂન્ય) atomicio(vwrite, remout, "", 1);
			જાઓ done;
		}
		જો (ch == '\n')
			*--cp = 0;

		cp = buf;
		જો (*cp == 'T') {
			setimes++;
			cp++;
			જો (!isdigit((unsigned અક્ષર)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			જો (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			જો (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			જો (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			જો (!isdigit((unsigned અક્ષર)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			જો (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			જો (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			જો (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(શૂન્ય) atomicio(vwrite, remout, "", 1);
			ચાલુ;
		}
		જો (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			જો (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		માટે (++cp; cp < buf + 5; cp++) {
			જો (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		જો (!pflag)
			mode &= ~mask;
		જો (*cp++ != ' ')
			SCREWUP("mode not delimited");

		જો (!isdigit((unsigned અક્ષર)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		જો (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		જો (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		જો (*cp == '\0' || strchr(cp, '/') != ખાલી ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		જો (npatterns > 0) {
			માટે (n = 0; n < npatterns; n++) {
				જો (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					તોડો;
			}
			જો (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				માટે (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		જો (targisdir) {
			સ્થિર અક્ષર *namebuf;
			સ્થિર size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			જો (need > cursize) {
				મુક્ત(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(શૂન્ય) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} નહીંતર
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		જો (buf[0] == 'D') {
			પૂર્ણાંક mod_flag = pflag;
			જો (!iamrecursive)
				SCREWUP("received directory without -r");
			જો (exists) {
				જો (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					જાઓ bad;
				}
				જો (pflag)
					(શૂન્ય) chmod(np, mode);
			} નહીંતર {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				જો (mkdir(np, mode | S_IRWXU) == -1)
					જાઓ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			જો (setimes) {
				setimes = 0;
				(શૂન્ય) utimes(vect[0], tv);
			}
			જો (mod_flag)
				(શૂન્ય) chmod(vect[0], mode);
			મુક્ત(vect[0]);
			ચાલુ;
		}
		omode = mode;
		mode |= S_IWUSR;
		જો ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			ચાલુ;
		}
		(શૂન્ય) atomicio(vwrite, remout, "", 1);
		જો ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == ખાલી) {
			(શૂન્ય) close(ofd);
			ચાલુ;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		જો (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		માટે (ગણતરી = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			જો (i + amt > size)
				amt = size - i;
			ગણતરી += amt;
			કરો {
				j = atomicio6(પઠ, remin, cp, amt,
				    scpio, &statbytes);
				જો (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} જ્યારે (amt > 0);

			જો (ગણતરી == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				જો (!wrerr) {
					જો (atomicio(vwrite, ofd, bp->buf,
					    ગણતરી) != ગણતરી) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				ગણતરી = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		જો (ગણતરી != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, ગણતરી) != ગણતરી) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		જો (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		જો (pflag) {
			જો (exists || omode != mode)
#ifdef HAVE_FCHMOD
				જો (fchmod(ofd, omode)) {
#નહીંતર /* HAVE_FCHMOD */
				જો (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} નહીંતર {
			જો (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				જો (fchmod(ofd, omode & ~mask)) {
#નહીંતર /* HAVE_FCHMOD */
				જો (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		જો (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(શૂન્ય) response();
		જો (showprogress)
			stop_progress_meter();
		જો (setimes && !wrerr) {
			setimes = 0;
			જો (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		જો (note_err(ખાલી) == 0)
			(શૂન્ય) atomicio(vwrite, remout, "", 1);
	}
done:
	માટે (n = 0; n < npatterns; n++)
		મુક્ત(patterns[n]);
	મુક્ત(patterns);
	પાછા;
screwup:
	માટે (n = 0; n < npatterns; n++)
		મુક્ત(patterns[n]);
	મુક્ત(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

શૂન્ય
throughlocal_sftp(સંરચના sftp_conn *from, સંરચના sftp_conn *to,
    અક્ષર *src, અક્ષર *targ)
{
	અક્ષર *target = ખાલી, *filename = ખાલી, *abs_dst = ખાલી;
	અક્ષર *abs_src = ખાલી, *tmp = ખાલી;
	glob_t g;
	પૂર્ણાંક i, r, targetisdir, err = 0;

	જો ((filename = basename(src)) == ખાલી)
		fatal("basename %s: %s", src, strerror(errno));

	જો ((abs_src = prepare_remote_path(from, src)) == ખાલી ||
	    (target = prepare_remote_path(to, targ)) == ખાલી)
		cleanup_exit(255);
	memset(&g, 0, કદ(g));

	targetisdir = sftp_remote_is_dir(to, target);
	જો (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		જાઓ out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	જો ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ખાલી, &g)) != 0) {
		જો (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		નહીંતર
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		જાઓ out;
	}

	/* Did we actually get any matches back from the glob? */
	જો (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ખાલી) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		જો (sftp_stat(from, g.gl_pathv[0], 1, ખાલી) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			જાઓ out;
		}
	}

	માટે (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		જો ((filename = basename(tmp)) == ખાલી) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			જાઓ out;
		}

		/* Special handling for source of '..' */
		જો (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		જો (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		નહીંતર
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		જો (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			જો (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    ખાલી, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} નહીંતર {
			જો (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    ખાલી, pflag) == -1)
				err = -1;
		}
		મુક્ત(abs_dst);
		abs_dst = ખાલી;
		મુક્ત(tmp);
		tmp = ખાલી;
	}

out:
	મુક્ત(abs_src);
	મુક્ત(abs_dst);
	મુક્ત(target);
	મુક્ત(tmp);
	globfree(&g);
	જો (err == -1)
		errs = 1;
}

પૂર્ણાંક
response(શૂન્ય)
{
	અક્ષર ch, *cp, resp, rbuf[2048], visbuf[2048];

	જો (atomicio(પઠ, remin, &resp, કદ(resp)) != કદ(resp))
		lostconn(0);

	cp = rbuf;
	પસંદગી (resp) {
	સ્થિતિ 0:		/* ok */
		પાછા (0);
	મૂળભૂત:
		*cp++ = resp;
		/* FALLTHROUGH */
	સ્થિતિ 1:		/* error, followed by error msg */
	સ્થિતિ 2:		/* fatal error, "" */
		કરો {
			જો (atomicio(પઠ, remin, &ch, કદ(ch)) != કદ(ch))
				lostconn(0);
			*cp++ = ch;
		} જ્યારે (cp < &rbuf[કદ(rbuf) - 1] && ch != '\n');

		જો (!iamremote) {
			cp[-1] = '\0';
			(શૂન્ય) snmprintf(visbuf, કદ(visbuf),
			    ખાલી, "%s\n", rbuf);
			(શૂન્ય) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		જો (resp == 1)
			પાછા (-1);
		exit(1);
	}
	/* NOTREACHED */
}

શૂન્ય
usage(શૂન્ય)
{
	(શૂન્ય) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

શૂન્ય
run_err(અચલ અક્ષર *fmt,...)
{
	સ્થિર FILE *fp;
	va_list ap;

	++errs;
	જો (fp != ખાલી || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(શૂન્ય) fprintf(fp, "%c", 0x01);
		(શૂન્ય) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(શૂન્ય) vfprintf(fp, fmt, ap);
		va_end(ap);
		(શૂન્ય) fprintf(fp, "\n");
		(શૂન્ય) fflush(fp);
	}

	જો (!iamremote) {
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
પૂર્ણાંક
note_err(અચલ અક્ષર *fmt, ...)
{
	સ્થિર અક્ષર *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	જો (fmt == ખાલી) {
		જો (emsg == ખાલી)
			પાછા 0;
		run_err("%s", emsg);
		મુક્ત(emsg);
		emsg = ખાલી;
		પાછા -1;
	}

	errs++;
	/* Prefer first-noted error */
	જો (emsg != ખાલી)
		પાછા -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, ખાલી, fmt, ap);
	va_end(ap);
	પાછા -1;
}

શૂન્ય
verifydir(અક્ષર *cp)
{
	સંરચના stat stb;

	જો (!stat(cp, &stb)) {
		જો (S_ISDIR(stb.st_mode))
			પાછા;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

પૂર્ણાંક
okname(અક્ષર *cp0)
{
	પૂર્ણાંક c;
	અક્ષર *cp;

	cp = cp0;
	કરો {
		c = (પૂર્ણાંક)*cp;
		જો (c & 0200)
			જાઓ bad;
		જો (!isalpha(c) && !isdigit((unsigned અક્ષર)c)) {
			પસંદગી (c) {
			સ્થિતિ '\'':
			સ્થિતિ '"':
			સ્થિતિ '`':
			સ્થિતિ ' ':
			સ્થિતિ '#':
				જાઓ bad;
			મૂળભૂત:
				તોડો;
			}
		}
	} જ્યારે (*++cp);
	પાછા (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	પાછા (0);
}

BUF *
allocbuf(BUF *bp, પૂર્ણાંક fd, પૂર્ણાંક blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	સંરચના stat stb;

	જો (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		પાછા (ખાલી);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	જો (size == 0)
		size = blksize;
#નહીંતર /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	જો (bp->cnt >= size)
		પાછા (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	પાછા (bp);
}

શૂન્ય
lostconn(પૂર્ણાંક signo)
{
	જો (!iamremote)
		(શૂન્ય)લિખ(STDERR_FILENO, "lost connection\n", 16);
	જો (signo)
		_exit(1);
	નહીંતર
		exit(1);
}

શૂન્ય
cleanup_exit(પૂર્ણાંક i)
{
	જો (remin > 0)
		close(remin);
	જો (remout > 0)
		close(remout);
	જો (remin2 > 0)
		close(remin2);
	જો (remout2 > 0)
		close(remout2);
	જો (do_cmd_pid > 0)
		(શૂન્ય)waitpid(do_cmd_pid, ખાલી, 0);
	જો (do_cmd_pid2 > 0)
		(શૂન્ય)waitpid(do_cmd_pid2, ખાલી, 0);
	exit(i);
}
