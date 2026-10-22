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
#यदि defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
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
दीर्घ दीर्घ limit_kbps = 0;
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
माप_प्रकार sftp_copy_buflen;
माप_प्रकार sftp_nrequests;

/* Needed for sftp */
चञ्चल संक_पूर्ण_प्रकार interrupted = 0;

पूर्णाङ्क sftp_glob(संरचना sftp_conn *, अचर वर्ण *, पूर्णाङ्क,
    पूर्णाङ्क (*)(अचर वर्ण *, पूर्णाङ्क), glob_t *); /* proto for sftp-glob.c */

स्थिर शून्य
killchild(पूर्णाङ्क signo)
{
	यदि (do_cmd_pid > 1) {
		समाप्त(do_cmd_pid, signo ? signo : संक_इति);
		(शून्य)waitpid(do_cmd_pid, रिक्त, 0);
	}
	यदि (do_cmd_pid2 > 1) {
		समाप्त(do_cmd_pid2, signo ? signo : संक_इति);
		(शून्य)waitpid(do_cmd_pid2, रिक्त, 0);
	}

	यदि (signo)
		_exit(1);
	निकास(1);
}

स्थिर शून्य
suspone(पूर्णाङ्क pid, पूर्णाङ्क signo)
{
	पूर्णाङ्क status;

	यदि (pid > 1) {
		समाप्त(pid, signo);
		जबसम्म (waitpid(pid, &status, WUNTRACED) == -1 &&
		    त्रुटि_सं == EINTR)
			;
	}
}

स्थिर शून्य
suspchild(पूर्णाङ्क signo)
{
	पूर्णाङ्क save_errno = त्रुटि_सं;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	समाप्त(getpid(), SIGSTOP);
	त्रुटि_सं = save_errno;
}

स्थिर पूर्णाङ्क
do_local_cmd(arglist *a)
{
	वर्ण *cp;
	पूर्णाङ्क status;
	pid_t pid;

	यदि (a->अङ्क == 0)
		fatal("do_local_cmd: no arguments");

	यदि (verbose_mode) {
		cp = argv_assemble(a->अङ्क, a->list);
		fmprintf(मानक_त्रुटि, "Executing: %s\n", cp);
		मुक्त(cp);
	}
	यदि ((pid = विभाजन()) == -1)
		fatal("do_local_cmd: fork: %s", म_त्रुटि(त्रुटि_सं));

	यदि (pid == 0) {
		execvp(a->list[0], a->list);
		लिखो_त्रुटि(a->list[0]);
		निकास(1);
	}

	do_cmd_pid = pid;
	ssh_signal(संक_इति, killchild);
	ssh_signal(संक_विघ्न, killchild);
	ssh_signal(SIGHUP, killchild);

	जबसम्म (waitpid(pid, &status, 0) == -1)
		यदि (त्रुटि_सं != EINTR)
			fatal("do_local_cmd: waitpid: %s", म_त्रुटि(त्रुटि_सं));

	do_cmd_pid = -1;

	यदि (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		फर्काऊ (-1);

	फर्काऊ (0);
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
#अन्यथा
	पूर्णाङ्क sv[2];
#endif

	यदि (verbose_mode)
		fmprintf(मानक_त्रुटि,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	यदि (port == -1)
		port = sshport;

#ifdef USE_PIPES
	यदि (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", म_त्रुटि(त्रुटि_सं));
#अन्यथा
	/* Create a socket pair for communicating with ssh. */
	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", म_त्रुटि(त्रुटि_सं));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = विभाजन();
	विकल्प (*pid) {
	पक्ष -1:
		fatal("fork: %s", म_त्रुटि(त्रुटि_सं));
	पक्ष 0:
		/* Child. */
#ifdef USE_PIPES
		यदि (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		बंद(pin[0]);
		बंद(pin[1]);
		बंद(pout[0]);
		बंद(pout[1]);
#अन्यथा
		यदि (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		बंद(sv[0]);
		बंद(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		यदि (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		यदि (remuser != रिक्त) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		यदि (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		लिखो_त्रुटि(program);
		_exit(1);
	स्वभाव:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		बंद(pin[0]);
		बंद(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#अन्यथा
		बंद(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(संक_इति, killchild);
		ssh_signal(संक_विघ्न, killchild);
		ssh_signal(SIGHUP, killchild);
		फर्काऊ 0;
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

	यदि (verbose_mode)
		fmprintf(मानक_त्रुटि,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	यदि (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = विभाजन();
	यदि (pid == 0) {
		यदि (dup2(fdin, 0) == -1)
			लिखो_त्रुटि("dup2");
		यदि (dup2(fdout, 1) == -1)
			लिखो_त्रुटि("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		यदि (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		यदि (remuser != रिक्त) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		addargs(&args, "-oBatchMode=yes");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(ssh_program, args.list);
		लिखो_त्रुटि(ssh_program);
		निकास(1);
	} अन्यथा यदि (pid == -1) {
		fatal("fork: %s", म_त्रुटि(त्रुटि_सं));
	}
	जबसम्म (waitpid(pid, &status, 0) == -1)
		यदि (त्रुटि_सं != EINTR)
			fatal("do_cmd2: waitpid: %s", म_त्रुटि(त्रुटि_सं));
	फर्काऊ 0;
}

प्रकारनिर्देश संरचना {
	माप_प्रकार cnt;
	वर्ण *buf;
} BUF;

BUF *allocbuf(BUF *, पूर्णाङ्क, पूर्णाङ्क);
शून्य lostconn(पूर्णाङ्क);
पूर्णाङ्क okname(वर्ण *);
शून्य run_err(अचर वर्ण *,...)
    __attribute__((__format__ (म_लिखो, 1, 2)))
    __attribute__((__nonnull__ (1)));
पूर्णाङ्क note_err(अचर वर्ण *,...)
    __attribute__((__format__ (म_लिखो, 1, 2)));
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
शून्य sink(पूर्णाङ्क, वर्ण *[], अचर वर्ण *);
शून्य source(पूर्णाङ्क, वर्ण *[]);
शून्य tolocal(पूर्णाङ्क, वर्ण *[], गणना scp_mode_e, वर्ण *sftp_direct);
शून्य toremote(पूर्णाङ्क, वर्ण *[], गणना scp_mode_e, वर्ण *sftp_direct);
शून्य usage(शून्य);

शून्य source_sftp(पूर्णाङ्क, वर्ण *, वर्ण *, संरचना sftp_conn *);
शून्य sink_sftp(पूर्णाङ्क, वर्ण *, अचर वर्ण *, संरचना sftp_conn *);
शून्य throughlocal_sftp(संरचना sftp_conn *, संरचना sftp_conn *,
    वर्ण *, वर्ण *);

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क ch, fflag, tflag, status, r, n;
	वर्ण **newargv, *argv0;
	अचर वर्ण *errstr;
	बाह्य वर्ण *optarg;
	बाह्य पूर्णाङ्क optind;
	गणना scp_mode_e mode = MODE_SFTP;
	वर्ण *sftp_direct = रिक्त;
	दीर्घ दीर्घ llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), परिमाण(*newargv));
	लागि (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	स_रखो(&args, '\0', परिमाण(args));
	स_रखो(&remote_remote_args, '\0', परिमाण(remote_remote_args));
	args.list = remote_remote_args.list = रिक्त;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	जबसम्म ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		विकल्प (ch) {
		/* User-visible flags. */
		पक्ष '1':
			fatal("SSH protocol v.1 is no longer supported");
			रोक;
		पक्ष '2':
			/* Ignored */
			रोक;
		पक्ष 'A':
		पक्ष '4':
		पक्ष '6':
		पक्ष 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			रोक;
		पक्ष 'D':
			sftp_direct = optarg;
			रोक;
		पक्ष '3':
			throughlocal = 1;
			रोक;
		पक्ष 'R':
			ख_लिखो(मानक_त्रुटि, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			रोक;
		पक्ष 'o':
		पक्ष 'c':
		पक्ष 'i':
		पक्ष 'F':
		पक्ष 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			रोक;
		पक्ष 'O':
			mode = MODE_SCP;
			रोक;
		पक्ष 's':
			/* Ignored */
			रोक;
		पक्ष 'P':
			sshport = a2port(optarg);
			यदि (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			रोक;
		पक्ष 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			रोक;
		पक्ष 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			यदि (errstr != रिक्त)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			रोक;
		पक्ष 'p':
			pflag = 1;
			रोक;
		पक्ष 'r':
			iamrecursive = 1;
			रोक;
		पक्ष 'S':
			ssh_program = xstrdup(optarg);
			रोक;
		पक्ष 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			यदि (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा यदि (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			रोक;
		पक्ष 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			रोक;
		पक्ष 'X':
			/* Please keep in sync with sftp.c -X */
			यदि (म_भेदन(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				यदि (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					त्रुटि_सं = EINVAL;
				}
				यदि (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, म_त्रुटि(त्रुटि_सं));
				}
				sftp_copy_buflen = (माप_प्रकार)llv;
			} अन्यथा यदि (म_भेदन(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				यदि (errstr != रिक्त) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (माप_प्रकार)llv;
			} अन्यथा {
				fatal("Invalid -X option");
			}
			रोक;

		/* Server options. */
		पक्ष 'd':
			targetshouldbedirectory = 1;
			रोक;
		पक्ष 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			रोक;
		पक्ष 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_द्विआधारी);
#endif
			रोक;
		पक्ष 'T':
			Tflag = 1;
			रोक;
		स्वभाव:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	यदि (iamremote)
		mode = MODE_SCP;

	यदि ((pwd = getpwuid(userid = getuid())) == रिक्त)
		fatal("unknown user %u", (u_int) userid);

	यदि (!isatty(STDOUT_FILENO))
		showprogress = 0;

	यदि (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} अन्यथा {
		यदि (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    रिक्त) == -1) {
			लिखो_त्रुटि("pledge");
			निकास(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	यदि (fflag) {
		/* Follow "protocol", send data. */
		(शून्य) response();
		source(argc, argv);
		निकास(errs != 0);
	}
	यदि (tflag) {
		/* Receive data. */
		sink(argc, argv, रिक्त);
		निकास(errs != 0);
	}
	यदि (argc < 2)
		usage();
	यदि (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(शून्य) snprintf(cmd, परिमाण cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(शून्य) ssh_signal(SIGPIPE, lostconn);

	यदि (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	अन्यथा {
		यदि (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	यदि (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		यदि (remin != -1)
		    (शून्य) बंद(remin);
		यदि (remout != -1)
		    (शून्य) बंद(remout);
		यदि (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		अन्यथा {
			यदि (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	निकास(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
स्थिर पूर्णाङ्क
scpio(शून्य *_cnt, माप_प्रकार s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	यदि (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
do_times(पूर्णाङ्क fd, पूर्णाङ्क verb, अचर संरचना stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	वर्ण buf[(20 + 7 + 2) * 2 + 2];

	(शून्य)snprintf(buf, परिमाण(buf), "T%llu 0 %llu 0\n",
	    (अचिन्हित दीर्घ दीर्घ) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (अचिन्हित दीर्घ दीर्घ) (sb->st_atime < 0 ? 0 : sb->st_atime));
	यदि (verb) {
		ख_लिखो(मानक_त्रुटि, "File mtime %lld atime %lld\n",
		    (दीर्घ दीर्घ)sb->st_mtime, (दीर्घ दीर्घ)sb->st_atime);
		ख_लिखो(मानक_त्रुटि, "Sending file timestamps: %s", buf);
	}
	(शून्य) atomicio(vwrite, fd, buf, म_माप(buf));
	फर्काऊ (response());
}

स्थिर पूर्णाङ्क
parse_scp_uri(अचर वर्ण *uri, वर्ण **userp, वर्ण **hostp, पूर्णाङ्क *portp,
    वर्ण **pathp)
{
	पूर्णाङ्क r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	यदि (r == 0 && *pathp == रिक्त)
		*pathp = xstrdup(".");
	फर्काऊ r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
स्थिर पूर्णाङ्क
append(वर्ण *cp, वर्ण ***ap, माप_प्रकार *np)
{
	वर्ण **tmp;

	यदि ((tmp = reallocarray(*ap, *np + 1, परिमाण(*tmp))) == रिक्त)
		फर्काऊ -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	फर्काऊ 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
स्थिर पूर्णाङ्क
find_brace(अचर वर्ण *pattern, पूर्णाङ्क *startp, पूर्णाङ्क *endp)
{
	पूर्णाङ्क i;
	पूर्णाङ्क in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	लागि (i = 0; i < पूर्णांक_उच्च && *endp < 0 && pattern[i] != '\0'; i++) {
		विकल्प (pattern[i]) {
		पक्ष '\\':
			/* skip next character */
			यदि (pattern[i + 1] != '\0')
				i++;
			रोक;
		पक्ष '[':
			in_bracket = 1;
			रोक;
		पक्ष ']':
			in_bracket = 0;
			रोक;
		पक्ष '{':
			यदि (in_bracket)
				रोक;
			यदि (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				रोक;
			}
			यदि (*startp == -1)
				*startp = i;
			brace_level++;
			रोक;
		पक्ष '}':
			यदि (in_bracket)
				रोक;
			यदि (*startp < 0) {
				/* Unbalanced brace */
				फर्काऊ -1;
			}
			यदि (--brace_level <= 0)
				*endp = i;
			रोक;
		}
	}
	/* unbalanced brackets/braces */
	यदि (*endp < 0 && (*startp >= 0 || in_bracket))
		फर्काऊ -1;
	फर्काऊ 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
स्थिर पूर्णाङ्क
emit_expansion(अचर वर्ण *pattern, पूर्णाङ्क brace_start, पूर्णाङ्क brace_end,
    पूर्णाङ्क sel_start, पूर्णाङ्क sel_end, वर्ण ***patternsp, माप_प्रकार *npatternsp)
{
	वर्ण *cp;
	माप_प्रकार pattern_len;
	पूर्णाङ्क o = 0, tail_len;

	यदि ((pattern_len = म_माप(pattern)) == 0 || pattern_len >= पूर्णांक_उच्च)
		फर्काऊ -1;

	tail_len = म_माप(pattern + brace_end + 1);
	यदि ((cp = दो_स्मृति(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == रिक्त)
		फर्काऊ -1;

	/* Pattern before initial brace */
	यदि (brace_start > 0) {
		स_नकल(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	यदि (sel_end - sel_start > 0) {
		स_नकल(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	यदि (tail_len > 0) {
		स_नकल(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	यदि (append(cp, patternsp, npatternsp) != 0) {
		मुक्त(cp);
		फर्काऊ -1;
	}
	फर्काऊ 0;
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
brace_expand_one(अचर वर्ण *pattern, वर्ण ***patternsp, माप_प्रकार *npatternsp,
    पूर्णाङ्क *expanded, पूर्णाङ्क *invalid)
{
	पूर्णाङ्क i;
	पूर्णाङ्क in_bracket, brace_start, brace_end, brace_level;
	पूर्णाङ्क sel_start, sel_end;

	*invalid = *expanded = 0;

	यदि (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		फर्काऊ 0;
	} अन्यथा यदि (brace_start == -1)
		फर्काऊ 0;

	in_bracket = brace_level = 0;
	लागि (i = sel_start = brace_start + 1; i < brace_end; i++) {
		विकल्प (pattern[i]) {
		पक्ष '{':
			यदि (in_bracket)
				रोक;
			brace_level++;
			रोक;
		पक्ष '}':
			यदि (in_bracket)
				रोक;
			brace_level--;
			रोक;
		पक्ष '[':
			in_bracket = 1;
			रोक;
		पक्ष ']':
			in_bracket = 0;
			रोक;
		पक्ष '\\':
			यदि (i < brace_end - 1)
				i++; /* skip */
			रोक;
		}
		यदि (pattern[i] == ',' || i == brace_end - 1) {
			यदि (in_bracket || brace_level > 0)
				जारी;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			यदि (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				फर्काऊ -1;
			/* move on to the next selection */
			sel_start = i + 1;
			जारी;
		}
	}
	यदि (in_bracket || brace_level > 0) {
		*invalid = 1;
		फर्काऊ 0;
	}
	/* success */
	*expanded = 1;
	फर्काऊ 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
स्थिर पूर्णाङ्क
brace_expand(अचर वर्ण *pattern, वर्ण ***patternsp, माप_प्रकार *npatternsp)
{
	वर्ण *cp, *cp2, **active = रिक्त, **done = रिक्त;
	माप_प्रकार i, nactive = 0, ndone = 0;
	पूर्णाङ्क ret = -1, invalid = 0, expanded = 0;

	*patternsp = रिक्त;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	यदि ((cp = strdup(pattern)) == रिक्त)
		फर्काऊ -1;
	यदि (append(cp, &active, &nactive) != 0) {
		मुक्त(cp);
		फर्काऊ -1;
	}
	जबसम्म (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		यदि (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			मुक्त(cp);
			गच्छ fail;
		}
		यदि (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		यदि (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			मुक्त(cp);
			जारी;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		यदि ((cp2 = म_खोजप(cp, '/')) != रिक्त)
			*cp2++ = '\0';
		अन्यथा
			cp2 = cp;
		यदि (append(xstrdup(cp2), &done, &ndone) != 0) {
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
	लागि (i = 0; i < nactive; i++)
		मुक्त(active[i]);
	मुक्त(active);
	लागि (i = 0; i < ndone; i++)
		मुक्त(done[i]);
	मुक्त(done);
	फर्काऊ ret;
}

स्थिर संरचना sftp_conn *
do_sftp_connect(वर्ण *host, वर्ण *user, पूर्णाङ्क port, वर्ण *sftp_direct,
   पूर्णाङ्क *reminp, पूर्णाङ्क *remoutp, पूर्णाङ्क *pidp)
{
	यदि (sftp_direct == रिक्त) {
		यदि (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			फर्काऊ रिक्त;

	} अन्यथा {
		freeargs(&args);
		addargs(&args, "sftp-server");
		यदि (do_cmd(sftp_direct, host, रिक्त, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			फर्काऊ रिक्त;
	}
	फर्काऊ sftp_init(*reminp, *remoutp,
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

	स_रखो(&alist, '\0', परिमाण(alist));
	alist.list = रिक्त;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	यदि (r == -1) {
		fmprintf(मानक_त्रुटि, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		गच्छ out;
	}
	यदि (r != 0) {
		यदि (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(मानक_त्रुटि, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			गच्छ out;
		}
	}

	/* Parse source files */
	लागि (i = 0; i < argc - 1; i++) {
		मुक्त(suser);
		मुक्त(host);
		मुक्त(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		यदि (r == -1) {
			fmprintf(मानक_त्रुटि, "%s: invalid uri\n", argv[i]);
			++errs;
			जारी;
		}
		यदि (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		यदि (suser != रिक्त && !okname(suser)) {
			++errs;
			जारी;
		}
		यदि (host && throughlocal) {	/* extended remote to remote */
			यदि (mode == MODE_SFTP) {
				यदि (remin == -1 || conn == रिक्त) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					यदि (conn == रिक्त) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (दीर्घ)do_cmd_pid);
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
				यदि (conn2 == रिक्त) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (दीर्घ)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(शून्य) बंद(remin2);
				(शून्य) बंद(remout2);
				remin2 = remout2 = -1;
				यदि (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				अन्यथा यदि (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				जारी;
			} अन्यथा {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				यदि (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					निकास(1);
				मुक्त(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				यदि (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					निकास(1);
				मुक्त(bp);
				(शून्य) बंद(remin);
				(शून्य) बंद(remout);
				remin = remout = -1;
			}
		} अन्यथा यदि (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			यदि (tuser != रिक्त && !okname(tuser)) {
				++errs;
				जारी;
			}
			यदि (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			लागि (j = 0; j < remote_remote_args.अङ्क; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			यदि (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			यदि (suser) {
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
			यदि (do_local_cmd(&alist) != 0)
				errs = 1;
		} अन्यथा {	/* local to remote */
			यदि (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				यदि (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    म_त्रुटि(त्रुटि_सं));
				}
				यदि (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					यदि (conn == रिक्त) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				जारी;
			}
			/* SCP */
			यदि (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				यदि (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					निकास(1);
				यदि (response() < 0)
					निकास(1);
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

	स_रखो(&alist, '\0', परिमाण(alist));
	alist.list = रिक्त;

	लागि (i = 0; i < argc - 1; i++) {
		मुक्त(suser);
		मुक्त(host);
		मुक्त(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		यदि (r == -1) {
			fmprintf(मानक_त्रुटि, "%s: invalid uri\n", argv[i]);
			++errs;
			जारी;
		}
		यदि (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		यदि (suser != रिक्त && !okname(suser)) {
			++errs;
			जारी;
		}
		यदि (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			यदि (iamrecursive)
				addargs(&alist, "-r");
			यदि (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			यदि (do_local_cmd(&alist))
				++errs;
			जारी;
		}
		/* Remote to local. */
		यदि (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			यदि (conn == रिक्त) {
				error("sftp connection failed");
				++errs;
				जारी;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(शून्य) बंद(remin);
			(शून्य) बंद(remout);
			remin = remout = -1;
			जारी;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		यदि (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			मुक्त(bp);
			++errs;
			जारी;
		}
		मुक्त(bp);
		sink(1, argv + argc - 1, src);
		(शून्य) बंद(remin);
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
prepare_remote_path(संरचना sftp_conn *conn, अचर वर्ण *path)
{
	माप_प्रकार nslash;

	/* Handle ~ prefixed paths */
	यदि (*path == '\0' || म_भेद(path, "~") == 0)
		फर्काऊ xstrdup(".");
	यदि (*path != '~')
		फर्काऊ xstrdup(path);
	यदि (म_भेदन(path, "~/", 2) == 0) {
		यदि ((nslash = म_अखोज(path + 2, "/")) == म_माप(path + 2))
			फर्काऊ xstrdup(".");
		फर्काऊ xstrdup(path + 2 + nslash);
	}
	यदि (sftp_can_expand_path(conn))
		फर्काऊ sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	फर्काऊ रिक्त;
}

शून्य
source_sftp(पूर्णाङ्क argc, वर्ण *src, वर्ण *targ, संरचना sftp_conn *conn)
{
	वर्ण *target = रिक्त, *filename = रिक्त, *abs_dst = रिक्त;
	पूर्णाङ्क src_is_dir, target_is_dir;
	Attrib a;
	संरचना stat st;

	स_रखो(&a, '\0', परिमाण(a));
	यदि (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));
	src_is_dir = S_ISDIR(st.st_mode);
	यदि ((filename = basename(src)) == रिक्त)
		fatal("basename \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));

	/* Special handling for source of '..' */
	यदि (म_भेद(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	यदि ((target = prepare_remote_path(conn, targ)) == रिक्त)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	यदि (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		यदि (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	यदि (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	अन्यथा {
		abs_dst = target;
		target = रिक्त;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	यदि (src_is_dir && iamrecursive) {
		यदि (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} अन्यथा यदि (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
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
	माप_प्रकार amt, nr;
	पूर्णाङ्क fd = -1, haderr, indx;
	वर्ण *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	पूर्णाङ्क len;

	लागि (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = म_माप(name);
		जबसम्म (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		यदि ((fd = खोलो(name, O_RDONLY|O_NONBLOCK)) == -1)
			गच्छ syserr;
		यदि (म_अक्षर(name, '\n') != रिक्त) {
			strnvis(encname, name, परिमाण(encname), VIS_NL);
			name = encname;
		}
		यदि (ख_स्थिति(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, म_त्रुटि(त्रुटि_सं));
			गच्छ next;
		}
		यदि (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			गच्छ next;
		}
		unset_nonblock(fd);
		विकल्प (stb.st_mode & S_IFMT) {
		पक्ष S_IFREG:
			रोक;
		पक्ष S_IFDIR:
			यदि (iamrecursive) {
				rsource(name, &stb);
				गच्छ next;
			}
			/* FALLTHROUGH */
		स्वभाव:
			run_err("%s: not a regular file", name);
			गच्छ next;
		}
		यदि ((last = म_खोजप(name, '/')) == रिक्त)
			last = name;
		अन्यथा
			++last;
		curfile = last;
		यदि (pflag) {
			यदि (do_times(remout, verbose_mode, &stb) < 0)
				गच्छ next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, परिमाण buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (दीर्घ दीर्घ)stb.st_size, last);
		यदि (verbose_mode)
			fmprintf(मानक_त्रुटि, "Sending file modes: %s", buf);
		(शून्य) atomicio(vwrite, remout, buf, म_माप(buf));
		यदि (response() < 0)
			गच्छ next;
		यदि ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == रिक्त) {
next:			यदि (fd != -1) {
				(शून्य) बंद(fd);
				fd = -1;
			}
			जारी;
		}
		यदि (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		लागि (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			यदि (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			यदि (!haderr) {
				यदि ((nr = atomicio(पठ, fd,
				    bp->buf, amt)) != amt) {
					haderr = त्रुटि_सं;
					स_रखो(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			यदि (haderr) {
				(शून्य)atomicio(vwrite, remout, bp->buf, amt);
				स_रखो(bp->buf, 0, amt);
				जारी;
			}
			यदि (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = त्रुटि_सं;
		}
		unset_nonblock(remout);

		यदि (fd != -1) {
			यदि (बंद(fd) == -1 && !haderr)
				haderr = त्रुटि_सं;
			fd = -1;
		}
		यदि (!haderr)
			(शून्य) atomicio(vwrite, remout, "", 1);
		अन्यथा
			run_err("%s: %s", name, म_त्रुटि(haderr));
		(शून्य) response();
		यदि (showprogress)
			stop_progress_meter();
	}
}

शून्य
rsource(वर्ण *name, संरचना stat *statp)
{
	सूची *dirp;
	संरचना dirent *dp;
	वर्ण *last, *vect[1], path[PATH_MAX];

	यदि (!(dirp = सूची_खोलो(name))) {
		run_err("%s: %s", name, म_त्रुटि(त्रुटि_सं));
		फर्काऊ;
	}
	last = म_खोजप(name, '/');
	यदि (last == रिक्त)
		last = name;
	अन्यथा
		last++;
	यदि (pflag) {
		यदि (do_times(remout, verbose_mode, statp) < 0) {
			बंद_सूची(dirp);
			फर्काऊ;
		}
	}
	(शून्य) snprintf(path, परिमाण path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	यदि (verbose_mode)
		fmprintf(मानक_त्रुटि, "Entering directory: %s", path);
	(शून्य) atomicio(vwrite, remout, path, म_माप(path));
	यदि (response() < 0) {
		बंद_सूची(dirp);
		फर्काऊ;
	}
	जबसम्म ((dp = सूची_पढ़ो(dirp)) != रिक्त) {
		यदि (dp->d_ino == 0)
			जारी;
		यदि (!म_भेद(dp->d_name, ".") || !म_भेद(dp->d_name, ".."))
			जारी;
		यदि (म_माप(name) + 1 + म_माप(dp->d_name) >= परिमाण(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			जारी;
		}
		(शून्य) snprintf(path, परिमाण path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(शून्य) बंद_सूची(dirp);
	(शून्य) atomicio(vwrite, remout, "E\n", 2);
	(शून्य) response();
}

शून्य
sink_sftp(पूर्णाङ्क argc, वर्ण *dst, अचर वर्ण *src, संरचना sftp_conn *conn)
{
	वर्ण *abs_src = रिक्त;
	वर्ण *abs_dst = रिक्त;
	glob_t g;
	वर्ण *filename, *tmp = रिक्त;
	पूर्णाङ्क i, r, err = 0, dst_is_dir;
	संरचना stat st;

	स_रखो(&g, 0, परिमाण(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	यदि ((abs_src = prepare_remote_path(conn, src)) == रिक्त) {
		err = -1;
		गच्छ out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	यदि ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    रिक्त, &g)) != 0) {
		यदि (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		अन्यथा
			error("%s: %s", src, म_त्रुटि(ENOENT));
		err = -1;
		गच्छ out;
	}

	/* Did we actually get any matches back from the glob? */
	यदि (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != रिक्त) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		यदि (sftp_stat(conn, g.gl_pathv[0], 1, रिक्त) != 0) {
			error("%s: %s", src, म_त्रुटि(ENOENT));
			err = -1;
			गच्छ out;
		}
	}

	यदि ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, म_त्रुटि(त्रुटि_सं));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	यदि (g.gl_matchc > 1 && !dst_is_dir) {
		यदि (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			गच्छ out;
		}
		debug2_f("creating destination \"%s\"", dst);
		यदि (सूची_गढ़ो(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, म_त्रुटि(त्रुटि_सं));
			err = -1;
			गच्छ out;
		}
		dst_is_dir = 1;
	}

	लागि (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		यदि ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			err = -1;
			गच्छ out;
		}

		/* Special handling for destination of '..' */
		यदि (म_भेद(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		यदि (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		अन्यथा
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		यदि (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			यदि (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} अन्यथा {
			यदि (sftp_download(conn, g.gl_pathv[i], abs_dst, रिक्त,
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
	यदि (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((परिमाण(type) == 4 && (val) > INT32_MAX) || \
	 (परिमाण(type) == 8 && (val) > INT64_MAX) || \
	 (परिमाण(type) != 4 && परिमाण(type) != 8))

शून्य
sink(पूर्णाङ्क argc, वर्ण **argv, अचर वर्ण *src)
{
	स्थिर BUF buffer;
	संरचना stat stb;
	BUF *bp;
	off_t i;
	माप_प्रकार j, गन्ती;
	पूर्णाङ्क amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	अचिन्हित दीर्घ दीर्घ ull;
	पूर्णाङ्क setimes, targisdir, wrerr;
	वर्ण ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	वर्ण **patterns = रिक्त;
	माप_प्रकार n, npatterns = 0;
	संरचना timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; गच्छ screwup; }

	यदि (TYPE_OVERFLOW(समय_प्रकार, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	यदि (!pflag) {
		(शून्य) umask(mask);
		mask |= 07000;
	}
	यदि (argc != 1) {
		run_err("ambiguous target");
		निकास(1);
	}
	targ = *argv;
	यदि (targetshouldbedirectory)
		verifydir(targ);

	(शून्य) atomicio(vwrite, remout, "", 1);
	यदि (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	यदि (src != रिक्त && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		यदि (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	लागि (first = 1;; first = 0) {
		cp = buf;
		यदि (atomicio(पठ, remin, cp, 1) != 1)
			गच्छ done;
		यदि (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		गर {
			यदि (atomicio(पठ, remin, &ch, परिमाण(ch)) != परिमाण(ch))
				SCREWUP("lost connection");
			यदि (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} जबसम्म (cp < &buf[परिमाण(buf) - 1] && ch != '\n');
		*cp = 0;
		यदि (verbose_mode)
			fmprintf(मानक_त्रुटि, "Sink: %s", buf);

		यदि (buf[0] == '\01' || buf[0] == '\02') {
			यदि (iamremote == 0) {
				(शून्य) snmprintf(visbuf, परिमाण(visbuf),
				    रिक्त, "%s", buf + 1);
				(शून्य) atomicio(vwrite, STDERR_FILENO,
				    visbuf, म_माप(visbuf));
			}
			यदि (buf[0] == '\02')
				निकास(1);
			++errs;
			जारी;
		}
		यदि (buf[0] == 'E') {
			(शून्य) atomicio(vwrite, remout, "", 1);
			गच्छ done;
		}
		यदि (ch == '\n')
			*--cp = 0;

		cp = buf;
		यदि (*cp == 'T') {
			setimes++;
			cp++;
			यदि (!है_अंक((अचिन्हित वर्ण)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			यदि (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			यदि (TYPE_OVERFLOW(समय_प्रकार, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = म_से_दीर्घ(cp, &cp, 10);
			यदि (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			यदि (!है_अंक((अचिन्हित वर्ण)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			यदि (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			यदि (TYPE_OVERFLOW(समय_प्रकार, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = म_से_दीर्घ(cp, &cp, 10);
			यदि (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(शून्य) atomicio(vwrite, remout, "", 1);
			जारी;
		}
		यदि (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			यदि (first) {
				run_err("%s", cp);
				निकास(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		लागि (++cp; cp < buf + 5; cp++) {
			यदि (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		यदि (!pflag)
			mode &= ~mask;
		यदि (*cp++ != ' ')
			SCREWUP("mode not delimited");

		यदि (!है_अंक((अचिन्हित वर्ण)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		यदि (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		यदि (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		यदि (*cp == '\0' || म_अक्षर(cp, '/') != रिक्त ||
		    म_भेद(cp, ".") == 0 || म_भेद(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			निकास(1);
		}
		यदि (npatterns > 0) {
			लागि (n = 0; n < npatterns; n++) {
				यदि (म_भेद(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					रोक;
			}
			यदि (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				लागि (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		यदि (targisdir) {
			स्थिर वर्ण *namebuf;
			स्थिर माप_प्रकार cursize;
			माप_प्रकार need;

			need = म_माप(targ) + म_माप(cp) + 250;
			यदि (need > cursize) {
				मुक्त(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(शून्य) snprintf(namebuf, need, "%s%s%s", targ,
			    म_भेद(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} अन्यथा
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		यदि (buf[0] == 'D') {
			पूर्णाङ्क mod_flag = pflag;
			यदि (!iamrecursive)
				SCREWUP("received directory without -r");
			यदि (exists) {
				यदि (!S_ISDIR(stb.st_mode)) {
					त्रुटि_सं = ENOTDIR;
					गच्छ bad;
				}
				यदि (pflag)
					(शून्य) chmod(np, mode);
			} अन्यथा {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				यदि (सूची_गढ़ो(np, mode | S_IRWXU) == -1)
					गच्छ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			यदि (setimes) {
				setimes = 0;
				(शून्य) utimes(vect[0], tv);
			}
			यदि (mod_flag)
				(शून्य) chmod(vect[0], mode);
			मुक्त(vect[0]);
			जारी;
		}
		omode = mode;
		mode |= S_IWUSR;
		यदि ((ofd = खोलो(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		(शून्य) atomicio(vwrite, remout, "", 1);
		यदि ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == रिक्त) {
			(शून्य) बंद(ofd);
			जारी;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		यदि (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		लागि (गन्ती = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			यदि (i + amt > size)
				amt = size - i;
			गन्ती += amt;
			गर {
				j = atomicio6(पठ, remin, cp, amt,
				    scpio, &statbytes);
				यदि (j == 0) {
					run_err("%s", j != EPIPE ?
					    म_त्रुटि(त्रुटि_सं) :
					    "dropped connection");
					निकास(1);
				}
				amt -= j;
				cp += j;
			} जबसम्म (amt > 0);

			यदि (गन्ती == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				यदि (!wrerr) {
					यदि (atomicio(vwrite, ofd, bp->buf,
					    गन्ती) != गन्ती) {
						note_err("%s: %s", np,
						    म_त्रुटि(त्रुटि_सं));
						wrerr = 1;
					}
				}
				गन्ती = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		यदि (गन्ती != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, गन्ती) != गन्ती) {
			note_err("%s: %s", np, म_त्रुटि(त्रुटि_सं));
			wrerr = 1;
		}
		यदि (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, म_त्रुटि(त्रुटि_सं));
		यदि (pflag) {
			यदि (exists || omode != mode)
#ifdef HAVE_FCHMOD
				यदि (fchmod(ofd, omode)) {
#अन्यथा /* HAVE_FCHMOD */
				यदि (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, म_त्रुटि(त्रुटि_सं));
				}
		} अन्यथा {
			यदि (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				यदि (fchmod(ofd, omode & ~mask)) {
#अन्यथा /* HAVE_FCHMOD */
				यदि (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, म_त्रुटि(त्रुटि_सं));
				}
		}
		यदि (बंद(ofd) == -1)
			note_err("%s: close: %s", np, म_त्रुटि(त्रुटि_सं));
		(शून्य) response();
		यदि (showprogress)
			stop_progress_meter();
		यदि (setimes && !wrerr) {
			setimes = 0;
			यदि (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, म_त्रुटि(त्रुटि_सं));
			}
		}
		/* If no error was noted then signal success for this file */
		यदि (note_err(रिक्त) == 0)
			(शून्य) atomicio(vwrite, remout, "", 1);
	}
done:
	लागि (n = 0; n < npatterns; n++)
		मुक्त(patterns[n]);
	मुक्त(patterns);
	फर्काऊ;
screwup:
	लागि (n = 0; n < npatterns; n++)
		मुक्त(patterns[n]);
	मुक्त(patterns);
	run_err("protocol error: %s", why);
	निकास(1);
}

शून्य
throughlocal_sftp(संरचना sftp_conn *from, संरचना sftp_conn *to,
    वर्ण *src, वर्ण *targ)
{
	वर्ण *target = रिक्त, *filename = रिक्त, *abs_dst = रिक्त;
	वर्ण *abs_src = रिक्त, *tmp = रिक्त;
	glob_t g;
	पूर्णाङ्क i, r, targetisdir, err = 0;

	यदि ((filename = basename(src)) == रिक्त)
		fatal("basename %s: %s", src, म_त्रुटि(त्रुटि_सं));

	यदि ((abs_src = prepare_remote_path(from, src)) == रिक्त ||
	    (target = prepare_remote_path(to, targ)) == रिक्त)
		cleanup_exit(255);
	स_रखो(&g, 0, परिमाण(g));

	targetisdir = sftp_remote_is_dir(to, target);
	यदि (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		गच्छ out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	यदि ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    रिक्त, &g)) != 0) {
		यदि (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		अन्यथा
			error("%s: %s", src, म_त्रुटि(ENOENT));
		err = -1;
		गच्छ out;
	}

	/* Did we actually get any matches back from the glob? */
	यदि (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != रिक्त) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		यदि (sftp_stat(from, g.gl_pathv[0], 1, रिक्त) != 0) {
			error("%s: %s", src, म_त्रुटि(ENOENT));
			err = -1;
			गच्छ out;
		}
	}

	लागि (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		यदि ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			err = -1;
			गच्छ out;
		}

		/* Special handling for source of '..' */
		यदि (म_भेद(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		यदि (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		अन्यथा
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		यदि (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			यदि (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} अन्यथा {
			यदि (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
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
	यदि (err == -1)
		errs = 1;
}

पूर्णाङ्क
response(शून्य)
{
	वर्ण ch, *cp, resp, rbuf[2048], visbuf[2048];

	यदि (atomicio(पठ, remin, &resp, परिमाण(resp)) != परिमाण(resp))
		lostconn(0);

	cp = rbuf;
	विकल्प (resp) {
	पक्ष 0:		/* ok */
		फर्काऊ (0);
	स्वभाव:
		*cp++ = resp;
		/* FALLTHROUGH */
	पक्ष 1:		/* error, followed by error msg */
	पक्ष 2:		/* fatal error, "" */
		गर {
			यदि (atomicio(पठ, remin, &ch, परिमाण(ch)) != परिमाण(ch))
				lostconn(0);
			*cp++ = ch;
		} जबसम्म (cp < &rbuf[परिमाण(rbuf) - 1] && ch != '\n');

		यदि (!iamremote) {
			cp[-1] = '\0';
			(शून्य) snmprintf(visbuf, परिमाण(visbuf),
			    रिक्त, "%s\n", rbuf);
			(शून्य) atomicio(vwrite, STDERR_FILENO,
			    visbuf, म_माप(visbuf));
		}
		++errs;
		यदि (resp == 1)
			फर्काऊ (-1);
		निकास(1);
	}
	/* NOTREACHED */
}

शून्य
usage(शून्य)
{
	(शून्य) ख_लिखो(मानक_त्रुटि,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	निकास(1);
}

शून्य
run_err(अचर वर्ण *fmt,...)
{
	स्थिर खाता *fp;
	बहु_सूची ap;

	++errs;
	यदि (fp != रिक्त || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(शून्य) ख_लिखो(fp, "%c", 0x01);
		(शून्य) ख_लिखो(fp, "scp: ");
		बहु_शुरू(ap, fmt);
		(शून्य) भख_लिखो(fp, fmt, ap);
		बहु_पूर्ण(ap);
		(शून्य) ख_लिखो(fp, "\n");
		(शून्य) ख_साफ(fp);
	}

	यदि (!iamremote) {
		बहु_शुरू(ap, fmt);
		vfmprintf(मानक_त्रुटि, fmt, ap);
		बहु_पूर्ण(ap);
		ख_लिखो(मानक_त्रुटि, "\n");
	}
}

/*
 * Notes a sink error for sending at the end of a file transfer. Returns 0 if
 * no error has been noted or -1 otherwise. Use note_err(NULL) to flush
 * any active error at the end of the transfer.
 */
पूर्णाङ्क
note_err(अचर वर्ण *fmt, ...)
{
	स्थिर वर्ण *emsg;
	बहु_सूची ap;

	/* Replay any previously-noted error */
	यदि (fmt == रिक्त) {
		यदि (emsg == रिक्त)
			फर्काऊ 0;
		run_err("%s", emsg);
		मुक्त(emsg);
		emsg = रिक्त;
		फर्काऊ -1;
	}

	errs++;
	/* Prefer first-noted error */
	यदि (emsg != रिक्त)
		फर्काऊ -1;

	बहु_शुरू(ap, fmt);
	vasnmprintf(&emsg, पूर्णांक_उच्च, रिक्त, fmt, ap);
	बहु_पूर्ण(ap);
	फर्काऊ -1;
}

शून्य
verifydir(वर्ण *cp)
{
	संरचना stat stb;

	यदि (!stat(cp, &stb)) {
		यदि (S_ISDIR(stb.st_mode))
			फर्काऊ;
		त्रुटि_सं = ENOTDIR;
	}
	run_err("%s: %s", cp, म_त्रुटि(त्रुटि_सं));
	killchild(0);
}

पूर्णाङ्क
okname(वर्ण *cp0)
{
	पूर्णाङ्क c;
	वर्ण *cp;

	cp = cp0;
	गर {
		c = (पूर्णाङ्क)*cp;
		यदि (c & 0200)
			गच्छ bad;
		यदि (!है_अक्षर(c) && !है_अंक((अचिन्हित वर्ण)c)) {
			विकल्प (c) {
			पक्ष '\'':
			पक्ष '"':
			पक्ष '`':
			पक्ष ' ':
			पक्ष '#':
				गच्छ bad;
			स्वभाव:
				रोक;
			}
		}
	} जबसम्म (*++cp);
	फर्काऊ (1);

bad:	fmprintf(मानक_त्रुटि, "%s: invalid user name\n", cp0);
	फर्काऊ (0);
}

BUF *
allocbuf(BUF *bp, पूर्णाङ्क fd, पूर्णाङ्क blksize)
{
	माप_प्रकार size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	संरचना stat stb;

	यदि (ख_स्थिति(fd, &stb) == -1) {
		run_err("fstat: %s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ (रिक्त);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	यदि (size == 0)
		size = blksize;
#अन्यथा /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	यदि (bp->cnt >= size)
		फर्काऊ (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	फर्काऊ (bp);
}

शून्य
lostconn(पूर्णाङ्क signo)
{
	यदि (!iamremote)
		(शून्य)लिख(STDERR_FILENO, "lost connection\n", 16);
	यदि (signo)
		_exit(1);
	अन्यथा
		निकास(1);
}

शून्य
cleanup_exit(पूर्णाङ्क i)
{
	यदि (remin > 0)
		बंद(remin);
	यदि (remout > 0)
		बंद(remout);
	यदि (remin2 > 0)
		बंद(remin2);
	यदि (remout2 > 0)
		बंद(remout2);
	यदि (do_cmd_pid > 0)
		(शून्य)waitpid(do_cmd_pid, रिक्त, 0);
	यदि (do_cmd_pid2 > 0)
		(शून्य)waitpid(do_cmd_pid2, रिक्त, 0);
	निकास(i);
}
