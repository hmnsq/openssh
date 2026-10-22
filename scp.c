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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/uio.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <dirent.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#ifdef HAVE_FNMATCH_H
#अन्तर्भाव <fnmatch.h>
#endif
#अन्तर्भाव <glob.h>
#अन्तर्भाव <libgen.h>
#अन्तर्भाव <locale.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <util.h>
#सचे defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#अन्तर्भाव <vis.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "progressmeter.h"
#अन्तर्भाव "utf8.h"
#अन्तर्भाव "sftp.h"

#अन्तर्भाव "sftp-common.h"
#अन्तर्भाव "sftp-client.h"

बाह्य वर्ण *__progname;

#define COPY_BUFLEN	16384

पूर्णाङ्क do_cmd(वर्ण *, वर्ण *, वर्ण *, पूर्णाङ्क, पूर्णाङ्क, वर्ण *, पूर्णाङ्क *, पूर्णाङ्क *, pid_t *);
पूर्णाङ्क do_cmd2(वर्ण *, वर्ण *, पूर्णाङ्क, वर्ण *, पूर्णाङ्क, पूर्णाङ्क);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
संरचना bwlimit bwlimit;

/* Name of current file being transferred. */
वर्ण *curfile;

/* This is set to non-zero to enable verbose mode. */
पूर्णाङ्क verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
पूर्णाङ्क showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
पूर्णाङ्क throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
पूर्णाङ्क sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
वर्ण *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
चञ्चल sig_atomic_t interrupted = 0;

पूर्णाङ्क sftp_glob(संरचना sftp_conn *, ध्रुव वर्ण *, पूर्णाङ्क,
    पूर्णाङ्क (*)(ध्रुव वर्ण *, पूर्णाङ्क), glob_t *); /* proto for sftp-glob.c */

स्थिर शून्य
killchild(पूर्णाङ्क signo)
{
	सचे (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(शून्य)waitpid(do_cmd_pid, रिक्त, 0);
	}
	सचे (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(शून्य)waitpid(do_cmd_pid2, रिक्त, 0);
	}

	सचे (signo)
		_exit(1);
	exit(1);
}

स्थिर शून्य
suspone(पूर्णाङ्क pid, पूर्णाङ्क signo)
{
	पूर्णाङ्क status;

	सचे (pid > 1) {
		kill(pid, signo);
		याव (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

स्थिर शून्य
suspchild(पूर्णाङ्क signo)
{
	पूर्णाङ्क save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

स्थिर पूर्णाङ्क
do_local_cmd(arglist *a)
{
	वर्ण *cp;
	पूर्णाङ्क status;
	pid_t pid;

	सचे (a->अङ्कः == 0)
		fatal("do_local_cmd: no arguments");

	सचे (verbose_mode) {
		cp = argv_assemble(a->अङ्कः, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		मुक्त(cp);
	}
	सचे ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	सचे (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	याव (waitpid(pid, &status, 0) == -1)
		सचे (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	सचे (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		पटिनिवत्त (-1);

	पटिनिवत्त (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

पूर्णाङ्क
do_cmd(वर्ण *program, वर्ण *host, वर्ण *remuser, पूर्णाङ्क port, पूर्णाङ्क subsystem,
    वर्ण *cmd, पूर्णाङ्क *fdin, पूर्णाङ्क *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	पूर्णाङ्क pin[2], pout[2];
#अञ्ञथा
	पूर्णाङ्क sv[2];
#endif

	सचे (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	सचे (port == -1)
		port = sshport;

#ifdef USE_PIPES
	सचे (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#अञ्ञथा
	/* Create a socket pair for communicating with ssh. */
	सचे (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	विकल्प (*pid) {
	पक्ष -1:
		fatal("fork: %s", strerror(errno));
	पक्ष 0:
		/* Child. */
#ifdef USE_PIPES
		सचे (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#अञ्ञथा
		सचे (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		सचे (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		सचे (remuser != रिक्त) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		सचे (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	स्वभाव:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#अञ्ञथा
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		पटिनिवत्त 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
पूर्णाङ्क
do_cmd2(वर्ण *host, वर्ण *remuser, पूर्णाङ्क port, वर्ण *cmd,
    पूर्णाङ्क fdin, पूर्णाङ्क fdout)
{
	पूर्णाङ्क status;
	pid_t pid;

	सचे (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	सचे (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	सचे (pid == 0) {
		सचे (dup2(fdin, 0) == -1)
			perror("dup2");
		सचे (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		सचे (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		सचे (remuser != रिक्त) {
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
	} अञ्ञथा सचे (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	याव (waitpid(pid, &status, 0) == -1)
		सचे (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	पटिनिवत्त 0;
}

प्रकारनिर्देश संरचना {
	size_t cnt;
	वर्ण *buf;
} BUF;

BUF *allocbuf(BUF *, पूर्णाङ्क, पूर्णाङ्क);
शून्य lostconn(पूर्णाङ्क);
पूर्णाङ्क okname(वर्ण *);
शून्य run_err(ध्रुव वर्ण *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
पूर्णाङ्क note_err(ध्रुव वर्ण *,...)
    __attribute__((__format__ (printf, 1, 2)));
शून्य verifydir(वर्ण *);

संरचना passwd *pwd;
uid_t userid;
पूर्णाङ्क errs, remin, remout, remin2, remout2;
पूर्णाङ्क Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
वर्ण cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

गणना scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

पूर्णाङ्क response(शून्य);
शून्य rsource(वर्ण *, संरचना stat *);
शून्य sink(पूर्णाङ्क, वर्ण *[], ध्रुव वर्ण *);
शून्य source(पूर्णाङ्क, वर्ण *[]);
शून्य tolocal(पूर्णाङ्क, वर्ण *[], गणना scp_mode_e, वर्ण *sftp_direct);
शून्य toremote(पूर्णाङ्क, वर्ण *[], गणना scp_mode_e, वर्ण *sftp_direct);
शून्य usage(शून्य);

शून्य source_sftp(पूर्णाङ्क, वर्ण *, वर्ण *, संरचना sftp_conn *);
शून्य sink_sftp(पूर्णाङ्क, वर्ण *, ध्रुव वर्ण *, संरचना sftp_conn *);
शून्य throughlocal_sftp(संरचना sftp_conn *, संरचना sftp_conn *,
    वर्ण *, वर्ण *);

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क ch, fflag, tflag, status, r, n;
	वर्ण **newargv, *argv0;
	ध्रुव वर्ण *errstr;
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	गणना scp_mode_e mode = MODE_SFTP;
	वर्ण *sftp_direct = रिक्त;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), परिमाण(*newargv));
	अत्थाय (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', परिमाण(args));
	memset(&remote_remote_args, '\0', परिमाण(remote_remote_args));
	args.list = remote_remote_args.list = रिक्त;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	याव ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		विकल्प (ch) {
		/* User-visible flags. */
		पक्ष '1':
			fatal("SSH protocol v.1 is no longer supported");
			भङ्ग;
		पक्ष '2':
			/* Ignored */
			भङ्ग;
		पक्ष 'A':
		पक्ष '4':
		पक्ष '6':
		पक्ष 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			भङ्ग;
		पक्ष 'D':
			sftp_direct = optarg;
			भङ्ग;
		पक्ष '3':
			throughlocal = 1;
			भङ्ग;
		पक्ष 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			भङ्ग;
		पक्ष 'o':
		पक्ष 'c':
		पक्ष 'i':
		पक्ष 'F':
		पक्ष 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			भङ्ग;
		पक्ष 'O':
			mode = MODE_SCP;
			भङ्ग;
		पक्ष 's':
			/* Ignored */
			भङ्ग;
		पक्ष 'P':
			sshport = a2port(optarg);
			सचे (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			भङ्ग;
		पक्ष 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			भङ्ग;
		पक्ष 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			सचे (errstr != रिक्त)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			भङ्ग;
		पक्ष 'p':
			pflag = 1;
			भङ्ग;
		पक्ष 'r':
			iamrecursive = 1;
			भङ्ग;
		पक्ष 'S':
			ssh_program = xstrdup(optarg);
			भङ्ग;
		पक्ष 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			सचे (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अञ्ञथा सचे (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			भङ्ग;
		पक्ष 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			भङ्ग;
		पक्ष 'X':
			/* Please keep in sync with sftp.c -X */
			सचे (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				सचे (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				सचे (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} अञ्ञथा सचे (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				सचे (errstr != रिक्त) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} अञ्ञथा {
				fatal("Invalid -X option");
			}
			भङ्ग;

		/* Server options. */
		पक्ष 'd':
			targetshouldbedirectory = 1;
			भङ्ग;
		पक्ष 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			भङ्ग;
		पक्ष 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_द्विमान);
#endif
			भङ्ग;
		पक्ष 'T':
			Tflag = 1;
			भङ्ग;
		स्वभाव:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	सचे (iamremote)
		mode = MODE_SCP;

	सचे ((pwd = getpwuid(userid = getuid())) == रिक्त)
		fatal("unknown user %u", (u_int) userid);

	सचे (!isatty(STDOUT_FILENO))
		showprogress = 0;

	सचे (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} अञ्ञथा {
		सचे (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    रिक्त) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	सचे (fflag) {
		/* Follow "protocol", send data. */
		(शून्य) response();
		source(argc, argv);
		exit(errs != 0);
	}
	सचे (tflag) {
		/* Receive data. */
		sink(argc, argv, रिक्त);
		exit(errs != 0);
	}
	सचे (argc < 2)
		usage();
	सचे (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(शून्य) snprintf(cmd, परिमाण cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(शून्य) ssh_signal(SIGPIPE, lostconn);

	सचे (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	अञ्ञथा {
		सचे (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	सचे (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		सचे (remin != -1)
		    (शून्य) close(remin);
		सचे (remout != -1)
		    (शून्य) close(remout);
		सचे (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		अञ्ञथा {
			सचे (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
स्थिर पूर्णाङ्क
scpio(शून्य *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	सचे (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
do_times(पूर्णाङ्क fd, पूर्णाङ्क verb, ध्रुव संरचना stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	वर्ण buf[(20 + 7 + 2) * 2 + 2];

	(शून्य)snprintf(buf, परिमाण(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	सचे (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(शून्य) atomicio(vwrite, fd, buf, strlen(buf));
	पटिनिवत्त (response());
}

स्थिर पूर्णाङ्क
parse_scp_uri(ध्रुव वर्ण *uri, वर्ण **userp, वर्ण **hostp, पूर्णाङ्क *portp,
    वर्ण **pathp)
{
	पूर्णाङ्क r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	सचे (r == 0 && *pathp == रिक्त)
		*pathp = xstrdup(".");
	पटिनिवत्त r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
स्थिर पूर्णाङ्क
append(वर्ण *cp, वर्ण ***ap, size_t *np)
{
	वर्ण **tmp;

	सचे ((tmp = reallocarray(*ap, *np + 1, परिमाण(*tmp))) == रिक्त)
		पटिनिवत्त -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	पटिनिवत्त 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
स्थिर पूर्णाङ्क
find_brace(ध्रुव वर्ण *pattern, पूर्णाङ्क *startp, पूर्णाङ्क *endp)
{
	पूर्णाङ्क i;
	पूर्णाङ्क in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	अत्थाय (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		विकल्प (pattern[i]) {
		पक्ष '\\':
			/* skip next character */
			सचे (pattern[i + 1] != '\0')
				i++;
			भङ्ग;
		पक्ष '[':
			in_bracket = 1;
			भङ्ग;
		पक्ष ']':
			in_bracket = 0;
			भङ्ग;
		पक्ष '{':
			सचे (in_bracket)
				भङ्ग;
			सचे (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				भङ्ग;
			}
			सचे (*startp == -1)
				*startp = i;
			brace_level++;
			भङ्ग;
		पक्ष '}':
			सचे (in_bracket)
				भङ्ग;
			सचे (*startp < 0) {
				/* Unbalanced brace */
				पटिनिवत्त -1;
			}
			सचे (--brace_level <= 0)
				*endp = i;
			भङ्ग;
		}
	}
	/* unbalanced brackets/braces */
	सचे (*endp < 0 && (*startp >= 0 || in_bracket))
		पटिनिवत्त -1;
	पटिनिवत्त 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
स्थिर पूर्णाङ्क
emit_expansion(ध्रुव वर्ण *pattern, पूर्णाङ्क brace_start, पूर्णाङ्क brace_end,
    पूर्णाङ्क sel_start, पूर्णाङ्क sel_end, वर्ण ***patternsp, size_t *npatternsp)
{
	वर्ण *cp;
	size_t pattern_len;
	पूर्णाङ्क o = 0, tail_len;

	सचे ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		पटिनिवत्त -1;

	tail_len = strlen(pattern + brace_end + 1);
	सचे ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == रिक्त)
		पटिनिवत्त -1;

	/* Pattern before initial brace */
	सचे (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	सचे (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	सचे (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	सचे (append(cp, patternsp, npatternsp) != 0) {
		मुक्त(cp);
		पटिनिवत्त -1;
	}
	पटिनिवत्त 0;
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
स्थिर पूर्णाङ्क
brace_expand_one(ध्रुव वर्ण *pattern, वर्ण ***patternsp, size_t *npatternsp,
    पूर्णाङ्क *expanded, पूर्णाङ्क *invalid)
{
	पूर्णाङ्क i;
	पूर्णाङ्क in_bracket, brace_start, brace_end, brace_level;
	पूर्णाङ्क sel_start, sel_end;

	*invalid = *expanded = 0;

	सचे (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		पटिनिवत्त 0;
	} अञ्ञथा सचे (brace_start == -1)
		पटिनिवत्त 0;

	in_bracket = brace_level = 0;
	अत्थाय (i = sel_start = brace_start + 1; i < brace_end; i++) {
		विकल्प (pattern[i]) {
		पक्ष '{':
			सचे (in_bracket)
				भङ्ग;
			brace_level++;
			भङ्ग;
		पक्ष '}':
			सचे (in_bracket)
				भङ्ग;
			brace_level--;
			भङ्ग;
		पक्ष '[':
			in_bracket = 1;
			भङ्ग;
		पक्ष ']':
			in_bracket = 0;
			भङ्ग;
		पक्ष '\\':
			सचे (i < brace_end - 1)
				i++; /* skip */
			भङ्ग;
		}
		सचे (pattern[i] == ',' || i == brace_end - 1) {
			सचे (in_bracket || brace_level > 0)
				अनुवर्त;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			सचे (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				पटिनिवत्त -1;
			/* move on to the next selection */
			sel_start = i + 1;
			अनुवर्त;
		}
	}
	सचे (in_bracket || brace_level > 0) {
		*invalid = 1;
		पटिनिवत्त 0;
	}
	/* success */
	*expanded = 1;
	पटिनिवत्त 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
स्थिर पूर्णाङ्क
brace_expand(ध्रुव वर्ण *pattern, वर्ण ***patternsp, size_t *npatternsp)
{
	वर्ण *cp, *cp2, **active = रिक्त, **done = रिक्त;
	size_t i, nactive = 0, ndone = 0;
	पूर्णाङ्क ret = -1, invalid = 0, expanded = 0;

	*patternsp = रिक्त;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	सचे ((cp = strdup(pattern)) == रिक्त)
		पटिनिवत्त -1;
	सचे (append(cp, &active, &nactive) != 0) {
		मुक्त(cp);
		पटिनिवत्त -1;
	}
	याव (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		सचे (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			मुक्त(cp);
			गच्छ fail;
		}
		सचे (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		सचे (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			मुक्त(cp);
			अनुवर्त;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		सचे ((cp2 = strrchr(cp, '/')) != रिक्त)
			*cp2++ = '\0';
		अञ्ञथा
			cp2 = cp;
		सचे (append(xstrdup(cp2), &done, &ndone) != 0) {
			मुक्त(cp);
			गच्छ fail;
		}
		मुक्त(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = रिक्त;
	ndone = 0;
	ret = 0;
 fail:
	अत्थाय (i = 0; i < nactive; i++)
		मुक्त(active[i]);
	मुक्त(active);
	अत्थाय (i = 0; i < ndone; i++)
		मुक्त(done[i]);
	मुक्त(done);
	पटिनिवत्त ret;
}

स्थिर संरचना sftp_conn *
do_sftp_connect(वर्ण *host, वर्ण *user, पूर्णाङ्क port, वर्ण *sftp_direct,
   पूर्णाङ्क *reminp, पूर्णाङ्क *remoutp, पूर्णाङ्क *pidp)
{
	सचे (sftp_direct == रिक्त) {
		सचे (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			पटिनिवत्त रिक्त;

	} अञ्ञथा {
		freeargs(&args);
		addargs(&args, "sftp-server");
		सचे (do_cmd(sftp_direct, host, रिक्त, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			पटिनिवत्त रिक्त;
	}
	पटिनिवत्त sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

शून्य
toremote(पूर्णाङ्क argc, वर्ण **argv, गणना scp_mode_e mode, वर्ण *sftp_direct)
{
	वर्ण *suser = रिक्त, *host = रिक्त, *src = रिक्त;
	वर्ण *bp, *tuser, *thost, *targ;
	पूर्णाङ्क sport = -1, tport = -1;
	संरचना sftp_conn *conn = रिक्त, *conn2 = रिक्त;
	arglist alist;
	पूर्णाङ्क i, r, status;
	संरचना stat sb;
	u_int j;

	memset(&alist, '\0', परिमाण(alist));
	alist.list = रिक्त;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	सचे (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		गच्छ out;
	}
	सचे (r != 0) {
		सचे (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			गच्छ out;
		}
	}

	/* Parse source files */
	अत्थाय (i = 0; i < argc - 1; i++) {
		मुक्त(suser);
		मुक्त(host);
		मुक्त(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		सचे (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			अनुवर्त;
		}
		सचे (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		सचे (suser != रिक्त && !okname(suser)) {
			++errs;
			अनुवर्त;
		}
		सचे (host && throughlocal) {	/* extended remote to remote */
			सचे (mode == MODE_SFTP) {
				सचे (remin == -1 || conn == रिक्त) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					सचे (conn == रिक्त) {
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
				सचे (conn2 == रिक्त) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(शून्य) close(remin2);
				(शून्य) close(remout2);
				remin2 = remout2 = -1;
				सचे (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				अञ्ञथा सचे (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				अनुवर्त;
			} अञ्ञथा {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				सचे (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				मुक्त(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				सचे (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				मुक्त(bp);
				(शून्य) close(remin);
				(शून्य) close(remout);
				remin = remout = -1;
			}
		} अञ्ञथा सचे (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			सचे (tuser != रिक्त && !okname(tuser)) {
				++errs;
				अनुवर्त;
			}
			सचे (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			अत्थाय (j = 0; j < remote_remote_args.अङ्कः; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			सचे (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			सचे (suser) {
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
			सचे (do_local_cmd(&alist) != 0)
				errs = 1;
		} अञ्ञथा {	/* local to remote */
			सचे (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				सचे (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				सचे (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					सचे (conn == रिक्त) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				अनुवर्त;
			}
			/* SCP */
			सचे (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				सचे (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				सचे (response() < 0)
					exit(1);
				मुक्त(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	मुक्त(tuser);
	मुक्त(thost);
	मुक्त(targ);
	मुक्त(suser);
	मुक्त(host);
	मुक्त(src);
	sftp_free(conn);
	sftp_free(conn2);
}

शून्य
tolocal(पूर्णाङ्क argc, वर्ण **argv, गणना scp_mode_e mode, वर्ण *sftp_direct)
{
	वर्ण *bp, *host = रिक्त, *src = रिक्त, *suser = रिक्त;
	arglist alist;
	संरचना sftp_conn *conn = रिक्त;
	पूर्णाङ्क i, r, sport = -1;

	memset(&alist, '\0', परिमाण(alist));
	alist.list = रिक्त;

	अत्थाय (i = 0; i < argc - 1; i++) {
		मुक्त(suser);
		मुक्त(host);
		मुक्त(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		सचे (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			अनुवर्त;
		}
		सचे (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		सचे (suser != रिक्त && !okname(suser)) {
			++errs;
			अनुवर्त;
		}
		सचे (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			सचे (iamrecursive)
				addargs(&alist, "-r");
			सचे (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			सचे (do_local_cmd(&alist))
				++errs;
			अनुवर्त;
		}
		/* Remote to local. */
		सचे (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			सचे (conn == रिक्त) {
				error("sftp connection failed");
				++errs;
				अनुवर्त;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(शून्य) close(remin);
			(शून्य) close(remout);
			remin = remout = -1;
			अनुवर्त;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		सचे (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			मुक्त(bp);
			++errs;
			अनुवर्त;
		}
		मुक्त(bp);
		sink(1, argv + argc - 1, src);
		(शून्य) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	मुक्त(suser);
	मुक्त(host);
	मुक्त(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
स्थिर वर्ण *
prepare_remote_path(संरचना sftp_conn *conn, ध्रुव वर्ण *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	सचे (*path == '\0' || strcmp(path, "~") == 0)
		पटिनिवत्त xstrdup(".");
	सचे (*path != '~')
		पटिनिवत्त xstrdup(path);
	सचे (strncmp(path, "~/", 2) == 0) {
		सचे ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			पटिनिवत्त xstrdup(".");
		पटिनिवत्त xstrdup(path + 2 + nslash);
	}
	सचे (sftp_can_expand_path(conn))
		पटिनिवत्त sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	पटिनिवत्त रिक्त;
}

शून्य
source_sftp(पूर्णाङ्क argc, वर्ण *src, वर्ण *targ, संरचना sftp_conn *conn)
{
	वर्ण *target = रिक्त, *filename = रिक्त, *abs_dst = रिक्त;
	पूर्णाङ्क src_is_dir, target_is_dir;
	Attrib a;
	संरचना stat st;

	memset(&a, '\0', परिमाण(a));
	सचे (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	सचे ((filename = basename(src)) == रिक्त)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	सचे (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	सचे ((target = prepare_remote_path(conn, targ)) == रिक्त)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	सचे (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		सचे (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	सचे (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	अञ्ञथा {
		abs_dst = target;
		target = रिक्त;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	सचे (src_is_dir && iamrecursive) {
		सचे (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} अञ्ञथा सचे (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	मुक्त(abs_dst);
	मुक्त(target);
}

शून्य
source(पूर्णाङ्क argc, वर्ण **argv)
{
	संरचना stat stb;
	स्थिर BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	पूर्णाङ्क fd = -1, haderr, indx;
	वर्ण *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	पूर्णाङ्क len;

	अत्थाय (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		याव (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		सचे ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			गच्छ syserr;
		सचे (strchr(name, '\n') != रिक्त) {
			strnvis(encname, name, परिमाण(encname), VIS_NL);
			name = encname;
		}
		सचे (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			गच्छ next;
		}
		सचे (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			गच्छ next;
		}
		unset_nonblock(fd);
		विकल्प (stb.st_mode & S_IFMT) {
		पक्ष S_IFREG:
			भङ्ग;
		पक्ष S_IFDIR:
			सचे (iamrecursive) {
				rsource(name, &stb);
				गच्छ next;
			}
			/* FALLTHROUGH */
		स्वभाव:
			run_err("%s: not a regular file", name);
			गच्छ next;
		}
		सचे ((last = strrchr(name, '/')) == रिक्त)
			last = name;
		अञ्ञथा
			++last;
		curfile = last;
		सचे (pflag) {
			सचे (do_times(remout, verbose_mode, &stb) < 0)
				गच्छ next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, परिमाण buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		सचे (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(शून्य) atomicio(vwrite, remout, buf, strlen(buf));
		सचे (response() < 0)
			गच्छ next;
		सचे ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == रिक्त) {
next:			सचे (fd != -1) {
				(शून्य) close(fd);
				fd = -1;
			}
			अनुवर्त;
		}
		सचे (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		अत्थाय (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			सचे (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			सचे (!haderr) {
				सचे ((nr = atomicio(पठ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			सचे (haderr) {
				(शून्य)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				अनुवर्त;
			}
			सचे (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		सचे (fd != -1) {
			सचे (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		सचे (!haderr)
			(शून्य) atomicio(vwrite, remout, "", 1);
		अञ्ञथा
			run_err("%s: %s", name, strerror(haderr));
		(शून्य) response();
		सचे (showprogress)
			stop_progress_meter();
	}
}

शून्य
rsource(वर्ण *name, संरचना stat *statp)
{
	DIR *dirp;
	संरचना dirent *dp;
	वर्ण *last, *vect[1], path[PATH_MAX];

	सचे (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		पटिनिवत्त;
	}
	last = strrchr(name, '/');
	सचे (last == रिक्त)
		last = name;
	अञ्ञथा
		last++;
	सचे (pflag) {
		सचे (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			पटिनिवत्त;
		}
	}
	(शून्य) snprintf(path, परिमाण path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	सचे (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(शून्य) atomicio(vwrite, remout, path, strlen(path));
	सचे (response() < 0) {
		closedir(dirp);
		पटिनिवत्त;
	}
	याव ((dp = readdir(dirp)) != रिक्त) {
		सचे (dp->d_ino == 0)
			अनुवर्त;
		सचे (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			अनुवर्त;
		सचे (strlen(name) + 1 + strlen(dp->d_name) >= परिमाण(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			अनुवर्त;
		}
		(शून्य) snprintf(path, परिमाण path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(शून्य) closedir(dirp);
	(शून्य) atomicio(vwrite, remout, "E\n", 2);
	(शून्य) response();
}

शून्य
sink_sftp(पूर्णाङ्क argc, वर्ण *dst, ध्रुव वर्ण *src, संरचना sftp_conn *conn)
{
	वर्ण *abs_src = रिक्त;
	वर्ण *abs_dst = रिक्त;
	glob_t g;
	वर्ण *filename, *tmp = रिक्त;
	पूर्णाङ्क i, r, err = 0, dst_is_dir;
	संरचना stat st;

	memset(&g, 0, परिमाण(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	सचे ((abs_src = prepare_remote_path(conn, src)) == रिक्त) {
		err = -1;
		गच्छ out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	सचे ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    रिक्त, &g)) != 0) {
		सचे (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		अञ्ञथा
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		गच्छ out;
	}

	/* Did we actually get any matches back from the glob? */
	सचे (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != रिक्त) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		सचे (sftp_stat(conn, g.gl_pathv[0], 1, रिक्त) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			गच्छ out;
		}
	}

	सचे ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	सचे (g.gl_matchc > 1 && !dst_is_dir) {
		सचे (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			गच्छ out;
		}
		debug2_f("creating destination \"%s\"", dst);
		सचे (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			गच्छ out;
		}
		dst_is_dir = 1;
	}

	अत्थाय (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		सचे ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			गच्छ out;
		}

		/* Special handling for destination of '..' */
		सचे (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		सचे (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		अञ्ञथा
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		सचे (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			सचे (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} अञ्ञथा {
			सचे (sftp_download(conn, g.gl_pathv[i], abs_dst, रिक्त,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		मुक्त(abs_dst);
		abs_dst = रिक्त;
		मुक्त(tmp);
		tmp = रिक्त;
	}

out:
	मुक्त(abs_src);
	मुक्त(tmp);
	globfree(&g);
	सचे (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((परिमाण(type) == 4 && (val) > INT32_MAX) || \
	 (परिमाण(type) == 8 && (val) > INT64_MAX) || \
	 (परिमाण(type) != 4 && परिमाण(type) != 8))

शून्य
sink(पूर्णाङ्क argc, वर्ण **argv, ध्रुव वर्ण *src)
{
	स्थिर BUF buffer;
	संरचना stat stb;
	BUF *bp;
	off_t i;
	size_t j, गणनम्;
	पूर्णाङ्क amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	पूर्णाङ्क setimes, targisdir, wrerr;
	वर्ण ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	वर्ण **patterns = रिक्त;
	size_t n, npatterns = 0;
	संरचना timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; गच्छ screwup; }

	सचे (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	सचे (!pflag) {
		(शून्य) umask(mask);
		mask |= 07000;
	}
	सचे (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	सचे (targetshouldbedirectory)
		verifydir(targ);

	(शून्य) atomicio(vwrite, remout, "", 1);
	सचे (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	सचे (src != रिक्त && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		सचे (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	अत्थाय (first = 1;; first = 0) {
		cp = buf;
		सचे (atomicio(पठ, remin, cp, 1) != 1)
			गच्छ done;
		सचे (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		करोहि {
			सचे (atomicio(पठ, remin, &ch, परिमाण(ch)) != परिमाण(ch))
				SCREWUP("lost connection");
			सचे (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} याव (cp < &buf[परिमाण(buf) - 1] && ch != '\n');
		*cp = 0;
		सचे (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		सचे (buf[0] == '\01' || buf[0] == '\02') {
			सचे (iamremote == 0) {
				(शून्य) snmprintf(visbuf, परिमाण(visbuf),
				    रिक्त, "%s", buf + 1);
				(शून्य) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			सचे (buf[0] == '\02')
				exit(1);
			++errs;
			अनुवर्त;
		}
		सचे (buf[0] == 'E') {
			(शून्य) atomicio(vwrite, remout, "", 1);
			गच्छ done;
		}
		सचे (ch == '\n')
			*--cp = 0;

		cp = buf;
		सचे (*cp == 'T') {
			setimes++;
			cp++;
			सचे (!isdigit((unsigned वर्ण)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			सचे (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			सचे (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			सचे (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			सचे (!isdigit((unsigned वर्ण)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			सचे (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			सचे (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			सचे (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(शून्य) atomicio(vwrite, remout, "", 1);
			अनुवर्त;
		}
		सचे (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			सचे (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		अत्थाय (++cp; cp < buf + 5; cp++) {
			सचे (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		सचे (!pflag)
			mode &= ~mask;
		सचे (*cp++ != ' ')
			SCREWUP("mode not delimited");

		सचे (!isdigit((unsigned वर्ण)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		सचे (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		सचे (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		सचे (*cp == '\0' || strchr(cp, '/') != रिक्त ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		सचे (npatterns > 0) {
			अत्थाय (n = 0; n < npatterns; n++) {
				सचे (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					भङ्ग;
			}
			सचे (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				अत्थाय (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		सचे (targisdir) {
			स्थिर वर्ण *namebuf;
			स्थिर size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			सचे (need > cursize) {
				मुक्त(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(शून्य) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} अञ्ञथा
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		सचे (buf[0] == 'D') {
			पूर्णाङ्क mod_flag = pflag;
			सचे (!iamrecursive)
				SCREWUP("received directory without -r");
			सचे (exists) {
				सचे (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					गच्छ bad;
				}
				सचे (pflag)
					(शून्य) chmod(np, mode);
			} अञ्ञथा {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				सचे (mkdir(np, mode | S_IRWXU) == -1)
					गच्छ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			सचे (setimes) {
				setimes = 0;
				(शून्य) utimes(vect[0], tv);
			}
			सचे (mod_flag)
				(शून्य) chmod(vect[0], mode);
			मुक्त(vect[0]);
			अनुवर्त;
		}
		omode = mode;
		mode |= S_IWUSR;
		सचे ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			अनुवर्त;
		}
		(शून्य) atomicio(vwrite, remout, "", 1);
		सचे ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == रिक्त) {
			(शून्य) close(ofd);
			अनुवर्त;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		सचे (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		अत्थाय (गणनम् = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			सचे (i + amt > size)
				amt = size - i;
			गणनम् += amt;
			करोहि {
				j = atomicio6(पठ, remin, cp, amt,
				    scpio, &statbytes);
				सचे (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} याव (amt > 0);

			सचे (गणनम् == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				सचे (!wrerr) {
					सचे (atomicio(vwrite, ofd, bp->buf,
					    गणनम्) != गणनम्) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				गणनम् = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		सचे (गणनम् != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, गणनम्) != गणनम्) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		सचे (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		सचे (pflag) {
			सचे (exists || omode != mode)
#ifdef HAVE_FCHMOD
				सचे (fchmod(ofd, omode)) {
#अञ्ञथा /* HAVE_FCHMOD */
				सचे (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} अञ्ञथा {
			सचे (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				सचे (fchmod(ofd, omode & ~mask)) {
#अञ्ञथा /* HAVE_FCHMOD */
				सचे (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		सचे (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(शून्य) response();
		सचे (showprogress)
			stop_progress_meter();
		सचे (setimes && !wrerr) {
			setimes = 0;
			सचे (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		सचे (note_err(रिक्त) == 0)
			(शून्य) atomicio(vwrite, remout, "", 1);
	}
done:
	अत्थाय (n = 0; n < npatterns; n++)
		मुक्त(patterns[n]);
	मुक्त(patterns);
	पटिनिवत्त;
screwup:
	अत्थाय (n = 0; n < npatterns; n++)
		मुक्त(patterns[n]);
	मुक्त(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

शून्य
throughlocal_sftp(संरचना sftp_conn *from, संरचना sftp_conn *to,
    वर्ण *src, वर्ण *targ)
{
	वर्ण *target = रिक्त, *filename = रिक्त, *abs_dst = रिक्त;
	वर्ण *abs_src = रिक्त, *tmp = रिक्त;
	glob_t g;
	पूर्णाङ्क i, r, targetisdir, err = 0;

	सचे ((filename = basename(src)) == रिक्त)
		fatal("basename %s: %s", src, strerror(errno));

	सचे ((abs_src = prepare_remote_path(from, src)) == रिक्त ||
	    (target = prepare_remote_path(to, targ)) == रिक्त)
		cleanup_exit(255);
	memset(&g, 0, परिमाण(g));

	targetisdir = sftp_remote_is_dir(to, target);
	सचे (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		गच्छ out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	सचे ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    रिक्त, &g)) != 0) {
		सचे (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		अञ्ञथा
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		गच्छ out;
	}

	/* Did we actually get any matches back from the glob? */
	सचे (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != रिक्त) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		सचे (sftp_stat(from, g.gl_pathv[0], 1, रिक्त) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			गच्छ out;
		}
	}

	अत्थाय (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		सचे ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			गच्छ out;
		}

		/* Special handling for source of '..' */
		सचे (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		सचे (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		अञ्ञथा
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		सचे (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			सचे (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} अञ्ञथा {
			सचे (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag) == -1)
				err = -1;
		}
		मुक्त(abs_dst);
		abs_dst = रिक्त;
		मुक्त(tmp);
		tmp = रिक्त;
	}

out:
	मुक्त(abs_src);
	मुक्त(abs_dst);
	मुक्त(target);
	मुक्त(tmp);
	globfree(&g);
	सचे (err == -1)
		errs = 1;
}

पूर्णाङ्क
response(शून्य)
{
	वर्ण ch, *cp, resp, rbuf[2048], visbuf[2048];

	सचे (atomicio(पठ, remin, &resp, परिमाण(resp)) != परिमाण(resp))
		lostconn(0);

	cp = rbuf;
	विकल्प (resp) {
	पक्ष 0:		/* ok */
		पटिनिवत्त (0);
	स्वभाव:
		*cp++ = resp;
		/* FALLTHROUGH */
	पक्ष 1:		/* error, followed by error msg */
	पक्ष 2:		/* fatal error, "" */
		करोहि {
			सचे (atomicio(पठ, remin, &ch, परिमाण(ch)) != परिमाण(ch))
				lostconn(0);
			*cp++ = ch;
		} याव (cp < &rbuf[परिमाण(rbuf) - 1] && ch != '\n');

		सचे (!iamremote) {
			cp[-1] = '\0';
			(शून्य) snmprintf(visbuf, परिमाण(visbuf),
			    रिक्त, "%s\n", rbuf);
			(शून्य) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		सचे (resp == 1)
			पटिनिवत्त (-1);
		exit(1);
	}
	/* NOTREACHED */
}

शून्य
usage(शून्य)
{
	(शून्य) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

शून्य
run_err(ध्रुव वर्ण *fmt,...)
{
	स्थिर FILE *fp;
	va_list ap;

	++errs;
	सचे (fp != रिक्त || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(शून्य) fprintf(fp, "%c", 0x01);
		(शून्य) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(शून्य) vfprintf(fp, fmt, ap);
		va_end(ap);
		(शून्य) fprintf(fp, "\n");
		(शून्य) fflush(fp);
	}

	सचे (!iamremote) {
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
पूर्णाङ्क
note_err(ध्रुव वर्ण *fmt, ...)
{
	स्थिर वर्ण *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	सचे (fmt == रिक्त) {
		सचे (emsg == रिक्त)
			पटिनिवत्त 0;
		run_err("%s", emsg);
		मुक्त(emsg);
		emsg = रिक्त;
		पटिनिवत्त -1;
	}

	errs++;
	/* Prefer first-noted error */
	सचे (emsg != रिक्त)
		पटिनिवत्त -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, रिक्त, fmt, ap);
	va_end(ap);
	पटिनिवत्त -1;
}

शून्य
verifydir(वर्ण *cp)
{
	संरचना stat stb;

	सचे (!stat(cp, &stb)) {
		सचे (S_ISDIR(stb.st_mode))
			पटिनिवत्त;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

पूर्णाङ्क
okname(वर्ण *cp0)
{
	पूर्णाङ्क c;
	वर्ण *cp;

	cp = cp0;
	करोहि {
		c = (पूर्णाङ्क)*cp;
		सचे (c & 0200)
			गच्छ bad;
		सचे (!isalpha(c) && !isdigit((unsigned वर्ण)c)) {
			विकल्प (c) {
			पक्ष '\'':
			पक्ष '"':
			पक्ष '`':
			पक्ष ' ':
			पक्ष '#':
				गच्छ bad;
			स्वभाव:
				भङ्ग;
			}
		}
	} याव (*++cp);
	पटिनिवत्त (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	पटिनिवत्त (0);
}

BUF *
allocbuf(BUF *bp, पूर्णाङ्क fd, पूर्णाङ्क blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	संरचना stat stb;

	सचे (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		पटिनिवत्त (रिक्त);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	सचे (size == 0)
		size = blksize;
#अञ्ञथा /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	सचे (bp->cnt >= size)
		पटिनिवत्त (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	पटिनिवत्त (bp);
}

शून्य
lostconn(पूर्णाङ्क signo)
{
	सचे (!iamremote)
		(शून्य)लिख(STDERR_FILENO, "lost connection\n", 16);
	सचे (signo)
		_exit(1);
	अञ्ञथा
		exit(1);
}

शून्य
cleanup_exit(पूर्णाङ्क i)
{
	सचे (remin > 0)
		close(remin);
	सचे (remout > 0)
		close(remout);
	सचे (remin2 > 0)
		close(remin2);
	सचे (remout2 > 0)
		close(remout2);
	सचे (do_cmd_pid > 0)
		(शून्य)waitpid(do_cmd_pid, रिक्त, 0);
	सचे (do_cmd_pid2 > 0)
		(शून्य)waitpid(do_cmd_pid2, रिक्त, 0);
	exit(i);
}
