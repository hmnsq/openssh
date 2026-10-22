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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <sys/time.h>
#समावेश <sys/wait.h>
#समावेश <sys/uio.h>

#समावेश <ctype.h>
#समावेश <dirent.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#अगर_घोषित HAVE_FNMATCH_H
#समावेश <fnmatch.h>
#पूर्ण_अगर
#समावेश <glob.h>
#समावेश <libgen.h>
#समावेश <locale.h>
#समावेश <poll.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <time.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <util.h>
#अगर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#समावेश <vis.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "atomicio.h"
#समावेश "pathnames.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "progressmeter.h"
#समावेश "utf8.h"
#समावेश "sftp.h"

#समावेश "sftp-common.h"
#समावेश "sftp-client.h"

बाह्य अक्षर *__progname;

#घोषणा COPY_BUFLEN	16384

पूर्णांक do_cmd(अक्षर *, अक्षर *, अक्षर *, पूर्णांक, पूर्णांक, अक्षर *, पूर्णांक *, पूर्णांक *, pid_t *);
पूर्णांक do_cmd2(अक्षर *, अक्षर *, पूर्णांक, अक्षर *, पूर्णांक, पूर्णांक);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
दीर्घ दीर्घ limit_kbps = 0;
काष्ठा bwlimit bwlimit;

/* Name of current file being transferred. */
अक्षर *curfile;

/* This is set to non-zero to enable verbose mode. */
पूर्णांक verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
पूर्णांक showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
पूर्णांक throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
पूर्णांक sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
अक्षर *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
माप_प्रकार sftp_copy_buflen;
माप_प्रकार sftp_nrequests;

/* Needed for sftp */
अस्थिर संक_पूर्ण_प्रकार interrupted = 0;

पूर्णांक sftp_glob(काष्ठा sftp_conn *, स्थिर अक्षर *, पूर्णांक,
    पूर्णांक (*)(स्थिर अक्षर *, पूर्णांक), glob_t *); /* proto for sftp-glob.c */

अटल व्योम
killchild(पूर्णांक signo)
{
	अगर (do_cmd_pid > 1) {
		समाप्त(do_cmd_pid, signo ? signo : संक_इति);
		(व्योम)waitpid(do_cmd_pid, शून्य, 0);
	}
	अगर (do_cmd_pid2 > 1) {
		समाप्त(do_cmd_pid2, signo ? signo : संक_इति);
		(व्योम)waitpid(do_cmd_pid2, शून्य, 0);
	}

	अगर (signo)
		_निकास(1);
	निकास(1);
}

अटल व्योम
suspone(पूर्णांक pid, पूर्णांक signo)
{
	पूर्णांक status;

	अगर (pid > 1) {
		समाप्त(pid, signo);
		जबतक (waitpid(pid, &status, WUNTRACED) == -1 &&
		    त्रुटि_सं == EINTR)
			;
	}
}

अटल व्योम
suspchild(पूर्णांक signo)
{
	पूर्णांक save_errno = त्रुटि_सं;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	समाप्त(getpid(), SIGSTOP);
	त्रुटि_सं = save_errno;
}

अटल पूर्णांक
do_local_cmd(arglist *a)
{
	अक्षर *cp;
	पूर्णांक status;
	pid_t pid;

	अगर (a->अंक == 0)
		fatal("do_local_cmd: no arguments");

	अगर (verbose_mode) {
		cp = argv_assemble(a->अंक, a->list);
		fmprintf(मानक_त्रुटि, "Executing: %s\n", cp);
		मुक्त(cp);
	}
	अगर ((pid = विभाजन()) == -1)
		fatal("do_local_cmd: fork: %s", म_त्रुटि(त्रुटि_सं));

	अगर (pid == 0) {
		execvp(a->list[0], a->list);
		लिखो_त्रुटि(a->list[0]);
		निकास(1);
	}

	do_cmd_pid = pid;
	ssh_signal(संक_इति, killchild);
	ssh_signal(संक_विघ्न, killchild);
	ssh_signal(SIGHUP, killchild);

	जबतक (waitpid(pid, &status, 0) == -1)
		अगर (त्रुटि_सं != EINTR)
			fatal("do_local_cmd: waitpid: %s", म_त्रुटि(त्रुटि_सं));

	do_cmd_pid = -1;

	अगर (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		वापस (-1);

	वापस (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

पूर्णांक
do_cmd(अक्षर *program, अक्षर *host, अक्षर *remuser, पूर्णांक port, पूर्णांक subsystem,
    अक्षर *cmd, पूर्णांक *fdin, पूर्णांक *fdout, pid_t *pid)
{
#अगर_घोषित USE_PIPES
	पूर्णांक pin[2], pout[2];
#अन्यथा
	पूर्णांक sv[2];
#पूर्ण_अगर

	अगर (verbose_mode)
		fmprintf(मानक_त्रुटि,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	अगर (port == -1)
		port = sshport;

#अगर_घोषित USE_PIPES
	अगर (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", म_त्रुटि(त्रुटि_सं));
#अन्यथा
	/* Create a socket pair for communicating with ssh. */
	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", म_त्रुटि(त्रुटि_सं));
#पूर्ण_अगर

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = विभाजन();
	चयन (*pid) {
	हाल -1:
		fatal("fork: %s", म_त्रुटि(त्रुटि_सं));
	हाल 0:
		/* Child. */
#अगर_घोषित USE_PIPES
		अगर (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		बंद(pin[0]);
		बंद(pin[1]);
		बंद(pout[0]);
		बंद(pout[1]);
#अन्यथा
		अगर (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", म_त्रुटि(त्रुटि_सं));
			_निकास(1);
		}
		बंद(sv[0]);
		बंद(sv[1]);
#पूर्ण_अगर
		replacearg(&args, 0, "%s", program);
		अगर (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		अगर (remuser != शून्य) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		अगर (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		लिखो_त्रुटि(program);
		_निकास(1);
	शेष:
		/* Parent.  Close the other side, and return the local side. */
#अगर_घोषित USE_PIPES
		बंद(pin[0]);
		बंद(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#अन्यथा
		बंद(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#पूर्ण_अगर
		ssh_signal(संक_इति, killchild);
		ssh_signal(संक_विघ्न, killchild);
		ssh_signal(SIGHUP, killchild);
		वापस 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
पूर्णांक
do_cmd2(अक्षर *host, अक्षर *remuser, पूर्णांक port, अक्षर *cmd,
    पूर्णांक fdin, पूर्णांक fdout)
{
	पूर्णांक status;
	pid_t pid;

	अगर (verbose_mode)
		fmprintf(मानक_त्रुटि,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	अगर (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = विभाजन();
	अगर (pid == 0) {
		अगर (dup2(fdin, 0) == -1)
			लिखो_त्रुटि("dup2");
		अगर (dup2(fdout, 1) == -1)
			लिखो_त्रुटि("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		अगर (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		अगर (remuser != शून्य) {
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
	} अन्यथा अगर (pid == -1) {
		fatal("fork: %s", म_त्रुटि(त्रुटि_सं));
	}
	जबतक (waitpid(pid, &status, 0) == -1)
		अगर (त्रुटि_सं != EINTR)
			fatal("do_cmd2: waitpid: %s", म_त्रुटि(त्रुटि_सं));
	वापस 0;
}

प्रकार काष्ठा {
	माप_प्रकार cnt;
	अक्षर *buf;
} BUF;

BUF *allocbuf(BUF *, पूर्णांक, पूर्णांक);
व्योम lostconn(पूर्णांक);
पूर्णांक okname(अक्षर *);
व्योम run_err(स्थिर अक्षर *,...)
    __attribute__((__format__ (म_लिखो, 1, 2)))
    __attribute__((__nonnull__ (1)));
पूर्णांक note_err(स्थिर अक्षर *,...)
    __attribute__((__format__ (म_लिखो, 1, 2)));
व्योम verifydir(अक्षर *);

काष्ठा passwd *pwd;
uid_t userid;
पूर्णांक errs, remin, remout, remin2, remout2;
पूर्णांक Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#घोषणा	CMDNEEDS	64
अक्षर cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

क्रमागत scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

पूर्णांक response(व्योम);
व्योम rsource(अक्षर *, काष्ठा stat *);
व्योम sink(पूर्णांक, अक्षर *[], स्थिर अक्षर *);
व्योम source(पूर्णांक, अक्षर *[]);
व्योम tolocal(पूर्णांक, अक्षर *[], क्रमागत scp_mode_e, अक्षर *sftp_direct);
व्योम toremote(पूर्णांक, अक्षर *[], क्रमागत scp_mode_e, अक्षर *sftp_direct);
व्योम usage(व्योम);

व्योम source_sftp(पूर्णांक, अक्षर *, अक्षर *, काष्ठा sftp_conn *);
व्योम sink_sftp(पूर्णांक, अक्षर *, स्थिर अक्षर *, काष्ठा sftp_conn *);
व्योम throughlocal_sftp(काष्ठा sftp_conn *, काष्ठा sftp_conn *,
    अक्षर *, अक्षर *);

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक ch, fflag, tflag, status, r, n;
	अक्षर **newargv, *argv0;
	स्थिर अक्षर *errstr;
	बाह्य अक्षर *optarg;
	बाह्य पूर्णांक optind;
	क्रमागत scp_mode_e mode = MODE_SFTP;
	अक्षर *sftp_direct = शून्य;
	दीर्घ दीर्घ llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), माप(*newargv));
	क्रम (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	स_रखो(&args, '\0', माप(args));
	स_रखो(&remote_remote_args, '\0', माप(remote_remote_args));
	args.list = remote_remote_args.list = शून्य;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	जबतक ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		चयन (ch) {
		/* User-visible flags. */
		हाल '1':
			fatal("SSH protocol v.1 is no longer supported");
			अवरोध;
		हाल '2':
			/* Ignored */
			अवरोध;
		हाल 'A':
		हाल '4':
		हाल '6':
		हाल 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			अवरोध;
		हाल 'D':
			sftp_direct = optarg;
			अवरोध;
		हाल '3':
			throughlocal = 1;
			अवरोध;
		हाल 'R':
			ख_लिखो(मानक_त्रुटि, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			अवरोध;
		हाल 'o':
		हाल 'c':
		हाल 'i':
		हाल 'F':
		हाल 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			अवरोध;
		हाल 'O':
			mode = MODE_SCP;
			अवरोध;
		हाल 's':
			/* Ignored */
			अवरोध;
		हाल 'P':
			sshport = a2port(optarg);
			अगर (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			अवरोध;
		हाल 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			अवरोध;
		हाल 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			अगर (errstr != शून्य)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			अवरोध;
		हाल 'p':
			pflag = 1;
			अवरोध;
		हाल 'r':
			iamrecursive = 1;
			अवरोध;
		हाल 'S':
			ssh_program = xstrdup(optarg);
			अवरोध;
		हाल 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			अगर (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			अन्यथा अगर (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			अवरोध;
		हाल 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			अवरोध;
		हाल 'X':
			/* Please keep in sync with sftp.c -X */
			अगर (म_भेदन(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				अगर (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					त्रुटि_सं = EINVAL;
				}
				अगर (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, म_त्रुटि(त्रुटि_सं));
				}
				sftp_copy_buflen = (माप_प्रकार)llv;
			} अन्यथा अगर (म_भेदन(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				अगर (errstr != शून्य) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (माप_प्रकार)llv;
			} अन्यथा {
				fatal("Invalid -X option");
			}
			अवरोध;

		/* Server options. */
		हाल 'd':
			targetshouldbedirectory = 1;
			अवरोध;
		हाल 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			अवरोध;
		हाल 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#अगर_घोषित HAVE_CYGWIN
			setmode(0, O_द्विआधारी);
#पूर्ण_अगर
			अवरोध;
		हाल 'T':
			Tflag = 1;
			अवरोध;
		शेष:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	अगर (iamremote)
		mode = MODE_SCP;

	अगर ((pwd = getpwuid(userid = getuid())) == शून्य)
		fatal("unknown user %u", (u_int) userid);

	अगर (!isatty(STDOUT_FILENO))
		showprogress = 0;

	अगर (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} अन्यथा {
		अगर (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    शून्य) == -1) {
			लिखो_त्रुटि("pledge");
			निकास(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	अगर (fflag) {
		/* Follow "protocol", send data. */
		(व्योम) response();
		source(argc, argv);
		निकास(errs != 0);
	}
	अगर (tflag) {
		/* Receive data. */
		sink(argc, argv, शून्य);
		निकास(errs != 0);
	}
	अगर (argc < 2)
		usage();
	अगर (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(व्योम) snprintf(cmd, माप cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(व्योम) ssh_signal(SIGPIPE, lostconn);

	अगर (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	अन्यथा {
		अगर (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	अगर (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		अगर (remin != -1)
		    (व्योम) बंद(remin);
		अगर (remout != -1)
		    (व्योम) बंद(remout);
		अगर (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		अन्यथा {
			अगर (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	निकास(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
अटल पूर्णांक
scpio(व्योम *_cnt, माप_प्रकार s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	अगर (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	वापस 0;
}

अटल पूर्णांक
do_times(पूर्णांक fd, पूर्णांक verb, स्थिर काष्ठा stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	अक्षर buf[(20 + 7 + 2) * 2 + 2];

	(व्योम)snprintf(buf, माप(buf), "T%llu 0 %llu 0\n",
	    (अचिन्हित दीर्घ दीर्घ) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (अचिन्हित दीर्घ दीर्घ) (sb->st_atime < 0 ? 0 : sb->st_atime));
	अगर (verb) {
		ख_लिखो(मानक_त्रुटि, "File mtime %lld atime %lld\n",
		    (दीर्घ दीर्घ)sb->st_mtime, (दीर्घ दीर्घ)sb->st_atime);
		ख_लिखो(मानक_त्रुटि, "Sending file timestamps: %s", buf);
	}
	(व्योम) atomicio(vwrite, fd, buf, म_माप(buf));
	वापस (response());
}

अटल पूर्णांक
parse_scp_uri(स्थिर अक्षर *uri, अक्षर **userp, अक्षर **hostp, पूर्णांक *portp,
    अक्षर **pathp)
{
	पूर्णांक r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	अगर (r == 0 && *pathp == शून्य)
		*pathp = xstrdup(".");
	वापस r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
अटल पूर्णांक
append(अक्षर *cp, अक्षर ***ap, माप_प्रकार *np)
{
	अक्षर **tmp;

	अगर ((tmp = reallocarray(*ap, *np + 1, माप(*tmp))) == शून्य)
		वापस -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	वापस 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
अटल पूर्णांक
find_brace(स्थिर अक्षर *pattern, पूर्णांक *startp, पूर्णांक *endp)
{
	पूर्णांक i;
	पूर्णांक in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	क्रम (i = 0; i < पूर्णांक_उच्च && *endp < 0 && pattern[i] != '\0'; i++) {
		चयन (pattern[i]) {
		हाल '\\':
			/* skip next character */
			अगर (pattern[i + 1] != '\0')
				i++;
			अवरोध;
		हाल '[':
			in_bracket = 1;
			अवरोध;
		हाल ']':
			in_bracket = 0;
			अवरोध;
		हाल '{':
			अगर (in_bracket)
				अवरोध;
			अगर (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				अवरोध;
			}
			अगर (*startp == -1)
				*startp = i;
			brace_level++;
			अवरोध;
		हाल '}':
			अगर (in_bracket)
				अवरोध;
			अगर (*startp < 0) {
				/* Unbalanced brace */
				वापस -1;
			}
			अगर (--brace_level <= 0)
				*endp = i;
			अवरोध;
		}
	}
	/* unbalanced brackets/braces */
	अगर (*endp < 0 && (*startp >= 0 || in_bracket))
		वापस -1;
	वापस 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
अटल पूर्णांक
emit_expansion(स्थिर अक्षर *pattern, पूर्णांक brace_start, पूर्णांक brace_end,
    पूर्णांक sel_start, पूर्णांक sel_end, अक्षर ***patternsp, माप_प्रकार *npatternsp)
{
	अक्षर *cp;
	माप_प्रकार pattern_len;
	पूर्णांक o = 0, पुच्छ_len;

	अगर ((pattern_len = म_माप(pattern)) == 0 || pattern_len >= पूर्णांक_उच्च)
		वापस -1;

	पुच्छ_len = म_माप(pattern + brace_end + 1);
	अगर ((cp = दो_स्मृति(brace_start + (sel_end - sel_start) +
	    पुच्छ_len + 1)) == शून्य)
		वापस -1;

	/* Pattern before initial brace */
	अगर (brace_start > 0) {
		स_नकल(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	अगर (sel_end - sel_start > 0) {
		स_नकल(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	अगर (पुच्छ_len > 0) {
		स_नकल(cp + o, pattern + brace_end + 1, पुच्छ_len);
		o += पुच्छ_len;
	}
	cp[o] = '\0';
	अगर (append(cp, patternsp, npatternsp) != 0) {
		मुक्त(cp);
		वापस -1;
	}
	वापस 0;
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
अटल पूर्णांक
brace_expand_one(स्थिर अक्षर *pattern, अक्षर ***patternsp, माप_प्रकार *npatternsp,
    पूर्णांक *expanded, पूर्णांक *invalid)
{
	पूर्णांक i;
	पूर्णांक in_bracket, brace_start, brace_end, brace_level;
	पूर्णांक sel_start, sel_end;

	*invalid = *expanded = 0;

	अगर (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		वापस 0;
	} अन्यथा अगर (brace_start == -1)
		वापस 0;

	in_bracket = brace_level = 0;
	क्रम (i = sel_start = brace_start + 1; i < brace_end; i++) {
		चयन (pattern[i]) {
		हाल '{':
			अगर (in_bracket)
				अवरोध;
			brace_level++;
			अवरोध;
		हाल '}':
			अगर (in_bracket)
				अवरोध;
			brace_level--;
			अवरोध;
		हाल '[':
			in_bracket = 1;
			अवरोध;
		हाल ']':
			in_bracket = 0;
			अवरोध;
		हाल '\\':
			अगर (i < brace_end - 1)
				i++; /* skip */
			अवरोध;
		}
		अगर (pattern[i] == ',' || i == brace_end - 1) {
			अगर (in_bracket || brace_level > 0)
				जारी;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			अगर (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				वापस -1;
			/* move on to the next selection */
			sel_start = i + 1;
			जारी;
		}
	}
	अगर (in_bracket || brace_level > 0) {
		*invalid = 1;
		वापस 0;
	}
	/* success */
	*expanded = 1;
	वापस 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
अटल पूर्णांक
brace_expand(स्थिर अक्षर *pattern, अक्षर ***patternsp, माप_प्रकार *npatternsp)
{
	अक्षर *cp, *cp2, **active = शून्य, **done = शून्य;
	माप_प्रकार i, nactive = 0, ndone = 0;
	पूर्णांक ret = -1, invalid = 0, expanded = 0;

	*patternsp = शून्य;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	अगर ((cp = strdup(pattern)) == शून्य)
		वापस -1;
	अगर (append(cp, &active, &nactive) != 0) {
		मुक्त(cp);
		वापस -1;
	}
	जबतक (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		अगर (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			मुक्त(cp);
			जाओ fail;
		}
		अगर (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		अगर (expanded) {
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
		अगर ((cp2 = म_खोजप(cp, '/')) != शून्य)
			*cp2++ = '\0';
		अन्यथा
			cp2 = cp;
		अगर (append(xstrdup(cp2), &done, &ndone) != 0) {
			मुक्त(cp);
			जाओ fail;
		}
		मुक्त(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = शून्य;
	ndone = 0;
	ret = 0;
 fail:
	क्रम (i = 0; i < nactive; i++)
		मुक्त(active[i]);
	मुक्त(active);
	क्रम (i = 0; i < ndone; i++)
		मुक्त(done[i]);
	मुक्त(done);
	वापस ret;
}

अटल काष्ठा sftp_conn *
do_sftp_connect(अक्षर *host, अक्षर *user, पूर्णांक port, अक्षर *sftp_direct,
   पूर्णांक *reminp, पूर्णांक *remoutp, पूर्णांक *pidp)
{
	अगर (sftp_direct == शून्य) {
		अगर (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			वापस शून्य;

	} अन्यथा {
		freeargs(&args);
		addargs(&args, "sftp-server");
		अगर (do_cmd(sftp_direct, host, शून्य, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			वापस शून्य;
	}
	वापस sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

व्योम
toremote(पूर्णांक argc, अक्षर **argv, क्रमागत scp_mode_e mode, अक्षर *sftp_direct)
{
	अक्षर *suser = शून्य, *host = शून्य, *src = शून्य;
	अक्षर *bp, *tuser, *thost, *targ;
	पूर्णांक sport = -1, tport = -1;
	काष्ठा sftp_conn *conn = शून्य, *conn2 = शून्य;
	arglist alist;
	पूर्णांक i, r, status;
	काष्ठा stat sb;
	u_int j;

	स_रखो(&alist, '\0', माप(alist));
	alist.list = शून्य;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	अगर (r == -1) {
		fmprintf(मानक_त्रुटि, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		जाओ out;
	}
	अगर (r != 0) {
		अगर (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(मानक_त्रुटि, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			जाओ out;
		}
	}

	/* Parse source files */
	क्रम (i = 0; i < argc - 1; i++) {
		मुक्त(suser);
		मुक्त(host);
		मुक्त(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		अगर (r == -1) {
			fmprintf(मानक_त्रुटि, "%s: invalid uri\n", argv[i]);
			++errs;
			जारी;
		}
		अगर (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		अगर (suser != शून्य && !okname(suser)) {
			++errs;
			जारी;
		}
		अगर (host && throughlocal) {	/* extended remote to remote */
			अगर (mode == MODE_SFTP) {
				अगर (remin == -1 || conn == शून्य) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					अगर (conn == शून्य) {
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
				अगर (conn2 == शून्य) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (दीर्घ)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(व्योम) बंद(remin2);
				(व्योम) बंद(remout2);
				remin2 = remout2 = -1;
				अगर (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				अन्यथा अगर (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				जारी;
			} अन्यथा {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				अगर (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					निकास(1);
				मुक्त(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				अगर (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					निकास(1);
				मुक्त(bp);
				(व्योम) बंद(remin);
				(व्योम) बंद(remout);
				remin = remout = -1;
			}
		} अन्यथा अगर (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			अगर (tuser != शून्य && !okname(tuser)) {
				++errs;
				जारी;
			}
			अगर (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			क्रम (j = 0; j < remote_remote_args.अंक; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			अगर (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			अगर (suser) {
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
			अगर (do_local_cmd(&alist) != 0)
				errs = 1;
		} अन्यथा {	/* local to remote */
			अगर (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				अगर (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    म_त्रुटि(त्रुटि_सं));
				}
				अगर (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					अगर (conn == शून्य) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				जारी;
			}
			/* SCP */
			अगर (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				अगर (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					निकास(1);
				अगर (response() < 0)
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

व्योम
tolocal(पूर्णांक argc, अक्षर **argv, क्रमागत scp_mode_e mode, अक्षर *sftp_direct)
{
	अक्षर *bp, *host = शून्य, *src = शून्य, *suser = शून्य;
	arglist alist;
	काष्ठा sftp_conn *conn = शून्य;
	पूर्णांक i, r, sport = -1;

	स_रखो(&alist, '\0', माप(alist));
	alist.list = शून्य;

	क्रम (i = 0; i < argc - 1; i++) {
		मुक्त(suser);
		मुक्त(host);
		मुक्त(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		अगर (r == -1) {
			fmprintf(मानक_त्रुटि, "%s: invalid uri\n", argv[i]);
			++errs;
			जारी;
		}
		अगर (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		अगर (suser != शून्य && !okname(suser)) {
			++errs;
			जारी;
		}
		अगर (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			अगर (iamrecursive)
				addargs(&alist, "-r");
			अगर (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			अगर (do_local_cmd(&alist))
				++errs;
			जारी;
		}
		/* Remote to local. */
		अगर (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			अगर (conn == शून्य) {
				error("sftp connection failed");
				++errs;
				जारी;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(व्योम) बंद(remin);
			(व्योम) बंद(remout);
			remin = remout = -1;
			जारी;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		अगर (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			मुक्त(bp);
			++errs;
			जारी;
		}
		मुक्त(bp);
		sink(1, argv + argc - 1, src);
		(व्योम) बंद(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	मुक्त(suser);
	मुक्त(host);
	मुक्त(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
अटल अक्षर *
prepare_remote_path(काष्ठा sftp_conn *conn, स्थिर अक्षर *path)
{
	माप_प्रकार nslash;

	/* Handle ~ prefixed paths */
	अगर (*path == '\0' || म_भेद(path, "~") == 0)
		वापस xstrdup(".");
	अगर (*path != '~')
		वापस xstrdup(path);
	अगर (म_भेदन(path, "~/", 2) == 0) {
		अगर ((nslash = म_अखोज(path + 2, "/")) == म_माप(path + 2))
			वापस xstrdup(".");
		वापस xstrdup(path + 2 + nslash);
	}
	अगर (sftp_can_expand_path(conn))
		वापस sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	वापस शून्य;
}

व्योम
source_sftp(पूर्णांक argc, अक्षर *src, अक्षर *targ, काष्ठा sftp_conn *conn)
{
	अक्षर *target = शून्य, *filename = शून्य, *abs_dst = शून्य;
	पूर्णांक src_is_dir, target_is_dir;
	Attrib a;
	काष्ठा stat st;

	स_रखो(&a, '\0', माप(a));
	अगर (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));
	src_is_dir = S_ISDIR(st.st_mode);
	अगर ((filename = basename(src)) == शून्य)
		fatal("basename \"%s\": %s", src, म_त्रुटि(त्रुटि_सं));

	/* Special handling for source of '..' */
	अगर (म_भेद(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	अगर ((target = prepare_remote_path(conn, targ)) == शून्य)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	अगर (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		अगर (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	अगर (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	अन्यथा {
		abs_dst = target;
		target = शून्य;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	अगर (src_is_dir && iamrecursive) {
		अगर (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} अन्यथा अगर (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	मुक्त(abs_dst);
	मुक्त(target);
}

व्योम
source(पूर्णांक argc, अक्षर **argv)
{
	काष्ठा stat stb;
	अटल BUF बफर;
	BUF *bp;
	off_t i, statbytes;
	माप_प्रकार amt, nr;
	पूर्णांक fd = -1, haderr, indx;
	अक्षर *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	पूर्णांक len;

	क्रम (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = म_माप(name);
		जबतक (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		अगर ((fd = खोलो(name, O_RDONLY|O_NONBLOCK)) == -1)
			जाओ syserr;
		अगर (म_अक्षर(name, '\n') != शून्य) {
			strnvis(encname, name, माप(encname), VIS_NL);
			name = encname;
		}
		अगर (ख_स्थिति(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, म_त्रुटि(त्रुटि_सं));
			जाओ अग्र;
		}
		अगर (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			जाओ अग्र;
		}
		unset_nonblock(fd);
		चयन (stb.st_mode & S_IFMT) {
		हाल S_IFREG:
			अवरोध;
		हाल S_IFDIR:
			अगर (iamrecursive) {
				rsource(name, &stb);
				जाओ अग्र;
			}
			/* FALLTHROUGH */
		शेष:
			run_err("%s: not a regular file", name);
			जाओ अग्र;
		}
		अगर ((last = म_खोजप(name, '/')) == शून्य)
			last = name;
		अन्यथा
			++last;
		curfile = last;
		अगर (pflag) {
			अगर (do_times(remout, verbose_mode, &stb) < 0)
				जाओ अग्र;
		}
#घोषणा	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, माप buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (दीर्घ दीर्घ)stb.st_size, last);
		अगर (verbose_mode)
			fmprintf(मानक_त्रुटि, "Sending file modes: %s", buf);
		(व्योम) atomicio(vwrite, remout, buf, म_माप(buf));
		अगर (response() < 0)
			जाओ अग्र;
		अगर ((bp = allocbuf(&बफर, fd, COPY_BUFLEN)) == शून्य) {
अग्र:			अगर (fd != -1) {
				(व्योम) बंद(fd);
				fd = -1;
			}
			जारी;
		}
		अगर (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		क्रम (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			अगर (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			अगर (!haderr) {
				अगर ((nr = atomicio(पढ़ो, fd,
				    bp->buf, amt)) != amt) {
					haderr = त्रुटि_सं;
					स_रखो(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			अगर (haderr) {
				(व्योम)atomicio(vwrite, remout, bp->buf, amt);
				स_रखो(bp->buf, 0, amt);
				जारी;
			}
			अगर (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = त्रुटि_सं;
		}
		unset_nonblock(remout);

		अगर (fd != -1) {
			अगर (बंद(fd) == -1 && !haderr)
				haderr = त्रुटि_सं;
			fd = -1;
		}
		अगर (!haderr)
			(व्योम) atomicio(vwrite, remout, "", 1);
		अन्यथा
			run_err("%s: %s", name, म_त्रुटि(haderr));
		(व्योम) response();
		अगर (showprogress)
			stop_progress_meter();
	}
}

व्योम
rsource(अक्षर *name, काष्ठा stat *statp)
{
	सूची *dirp;
	काष्ठा dirent *dp;
	अक्षर *last, *vect[1], path[PATH_MAX];

	अगर (!(dirp = सूची_खोलो(name))) {
		run_err("%s: %s", name, म_त्रुटि(त्रुटि_सं));
		वापस;
	}
	last = म_खोजप(name, '/');
	अगर (last == शून्य)
		last = name;
	अन्यथा
		last++;
	अगर (pflag) {
		अगर (do_times(remout, verbose_mode, statp) < 0) {
			बंद_सूची(dirp);
			वापस;
		}
	}
	(व्योम) snprintf(path, माप path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	अगर (verbose_mode)
		fmprintf(मानक_त्रुटि, "Entering directory: %s", path);
	(व्योम) atomicio(vwrite, remout, path, म_माप(path));
	अगर (response() < 0) {
		बंद_सूची(dirp);
		वापस;
	}
	जबतक ((dp = सूची_पढ़ो(dirp)) != शून्य) {
		अगर (dp->d_ino == 0)
			जारी;
		अगर (!म_भेद(dp->d_name, ".") || !म_भेद(dp->d_name, ".."))
			जारी;
		अगर (म_माप(name) + 1 + म_माप(dp->d_name) >= माप(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			जारी;
		}
		(व्योम) snprintf(path, माप path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(व्योम) बंद_सूची(dirp);
	(व्योम) atomicio(vwrite, remout, "E\n", 2);
	(व्योम) response();
}

व्योम
sink_sftp(पूर्णांक argc, अक्षर *dst, स्थिर अक्षर *src, काष्ठा sftp_conn *conn)
{
	अक्षर *abs_src = शून्य;
	अक्षर *abs_dst = शून्य;
	glob_t g;
	अक्षर *filename, *tmp = शून्य;
	पूर्णांक i, r, err = 0, dst_is_dir;
	काष्ठा stat st;

	स_रखो(&g, 0, माप(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	अगर ((abs_src = prepare_remote_path(conn, src)) == शून्य) {
		err = -1;
		जाओ out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	अगर ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    शून्य, &g)) != 0) {
		अगर (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		अन्यथा
			error("%s: %s", src, म_त्रुटि(ENOENT));
		err = -1;
		जाओ out;
	}

	/* Did we actually get any matches back from the glob? */
	अगर (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != शून्य) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		अगर (sftp_stat(conn, g.gl_pathv[0], 1, शून्य) != 0) {
			error("%s: %s", src, म_त्रुटि(ENOENT));
			err = -1;
			जाओ out;
		}
	}

	अगर ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, म_त्रुटि(त्रुटि_सं));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	अगर (g.gl_matchc > 1 && !dst_is_dir) {
		अगर (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			जाओ out;
		}
		debug2_f("creating destination \"%s\"", dst);
		अगर (सूची_गढ़ो(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, म_त्रुटि(त्रुटि_सं));
			err = -1;
			जाओ out;
		}
		dst_is_dir = 1;
	}

	क्रम (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		अगर ((filename = basename(tmp)) == शून्य) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			err = -1;
			जाओ out;
		}

		/* Special handling for destination of '..' */
		अगर (म_भेद(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		अगर (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		अन्यथा
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		अगर (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			अगर (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    शून्य, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} अन्यथा {
			अगर (sftp_download(conn, g.gl_pathv[i], abs_dst, शून्य,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		मुक्त(abs_dst);
		abs_dst = शून्य;
		मुक्त(tmp);
		tmp = शून्य;
	}

out:
	मुक्त(abs_src);
	मुक्त(tmp);
	globfree(&g);
	अगर (err == -1)
		errs = 1;
}


#घोषणा TYPE_OVERFLOW(type, val) \
	((माप(type) == 4 && (val) > INT32_MAX) || \
	 (माप(type) == 8 && (val) > INT64_MAX) || \
	 (माप(type) != 4 && माप(type) != 8))

व्योम
sink(पूर्णांक argc, अक्षर **argv, स्थिर अक्षर *src)
{
	अटल BUF बफर;
	काष्ठा stat stb;
	BUF *bp;
	off_t i;
	माप_प्रकार j, गिनती;
	पूर्णांक amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t आकार, statbytes;
	अचिन्हित दीर्घ दीर्घ ull;
	पूर्णांक setimes, targisdir, wrerr;
	अक्षर ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	अक्षर **patterns = शून्य;
	माप_प्रकार n, npatterns = 0;
	काष्ठा timeval tv[2];

#घोषणा	atime	tv[0]
#घोषणा	mtime	tv[1]
#घोषणा	SCREWUP(str)	{ why = str; जाओ screwup; }

	अगर (TYPE_OVERFLOW(समय_प्रकार, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	अगर (!pflag) {
		(व्योम) umask(mask);
		mask |= 07000;
	}
	अगर (argc != 1) {
		run_err("ambiguous target");
		निकास(1);
	}
	targ = *argv;
	अगर (targetshouldbedirectory)
		verifydir(targ);

	(व्योम) atomicio(vwrite, remout, "", 1);
	अगर (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	अगर (src != शून्य && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		अगर (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	क्रम (first = 1;; first = 0) {
		cp = buf;
		अगर (atomicio(पढ़ो, remin, cp, 1) != 1)
			जाओ done;
		अगर (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		करो {
			अगर (atomicio(पढ़ो, remin, &ch, माप(ch)) != माप(ch))
				SCREWUP("lost connection");
			अगर (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} जबतक (cp < &buf[माप(buf) - 1] && ch != '\n');
		*cp = 0;
		अगर (verbose_mode)
			fmprintf(मानक_त्रुटि, "Sink: %s", buf);

		अगर (buf[0] == '\01' || buf[0] == '\02') {
			अगर (iamremote == 0) {
				(व्योम) snmprintf(visbuf, माप(visbuf),
				    शून्य, "%s", buf + 1);
				(व्योम) atomicio(vwrite, STDERR_FILENO,
				    visbuf, म_माप(visbuf));
			}
			अगर (buf[0] == '\02')
				निकास(1);
			++errs;
			जारी;
		}
		अगर (buf[0] == 'E') {
			(व्योम) atomicio(vwrite, remout, "", 1);
			जाओ done;
		}
		अगर (ch == '\n')
			*--cp = 0;

		cp = buf;
		अगर (*cp == 'T') {
			setimes++;
			cp++;
			अगर (!है_अंक((अचिन्हित अक्षर)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			अगर (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			अगर (TYPE_OVERFLOW(समय_प्रकार, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = म_से_दीर्घ(cp, &cp, 10);
			अगर (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			अगर (!है_अंक((अचिन्हित अक्षर)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			अगर (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			अगर (TYPE_OVERFLOW(समय_प्रकार, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = म_से_दीर्घ(cp, &cp, 10);
			अगर (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(व्योम) atomicio(vwrite, remout, "", 1);
			जारी;
		}
		अगर (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			अगर (first) {
				run_err("%s", cp);
				निकास(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		क्रम (++cp; cp < buf + 5; cp++) {
			अगर (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		अगर (!pflag)
			mode &= ~mask;
		अगर (*cp++ != ' ')
			SCREWUP("mode not delimited");

		अगर (!है_अंक((अचिन्हित अक्षर)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		अगर (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		अगर (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		आकार = (off_t)ull;

		अगर (*cp == '\0' || म_अक्षर(cp, '/') != शून्य ||
		    म_भेद(cp, ".") == 0 || म_भेद(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			निकास(1);
		}
		अगर (npatterns > 0) {
			क्रम (n = 0; n < npatterns; n++) {
				अगर (म_भेद(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					अवरोध;
			}
			अगर (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				क्रम (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		अगर (targisdir) {
			अटल अक्षर *namebuf;
			अटल माप_प्रकार cursize;
			माप_प्रकार need;

			need = म_माप(targ) + म_माप(cp) + 250;
			अगर (need > cursize) {
				मुक्त(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(व्योम) snprintf(namebuf, need, "%s%s%s", targ,
			    म_भेद(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} अन्यथा
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		अगर (buf[0] == 'D') {
			पूर्णांक mod_flag = pflag;
			अगर (!iamrecursive)
				SCREWUP("received directory without -r");
			अगर (exists) {
				अगर (!S_ISDIR(stb.st_mode)) {
					त्रुटि_सं = ENOTDIR;
					जाओ bad;
				}
				अगर (pflag)
					(व्योम) chmod(np, mode);
			} अन्यथा {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				अगर (सूची_गढ़ो(np, mode | S_IRWXU) == -1)
					जाओ bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			अगर (setimes) {
				setimes = 0;
				(व्योम) utimes(vect[0], tv);
			}
			अगर (mod_flag)
				(व्योम) chmod(vect[0], mode);
			मुक्त(vect[0]);
			जारी;
		}
		omode = mode;
		mode |= S_IWUSR;
		अगर ((ofd = खोलो(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, म_त्रुटि(त्रुटि_सं));
			जारी;
		}
		(व्योम) atomicio(vwrite, remout, "", 1);
		अगर ((bp = allocbuf(&बफर, ofd, COPY_BUFLEN)) == शून्य) {
			(व्योम) बंद(ofd);
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
		अगर (showprogress)
			start_progress_meter(curfile, आकार, &statbytes);
		set_nonblock(remin);
		क्रम (गिनती = i = 0; i < आकार; i += bp->cnt) {
			amt = bp->cnt;
			अगर (i + amt > आकार)
				amt = आकार - i;
			गिनती += amt;
			करो {
				j = atomicio6(पढ़ो, remin, cp, amt,
				    scpio, &statbytes);
				अगर (j == 0) {
					run_err("%s", j != EPIPE ?
					    म_त्रुटि(त्रुटि_सं) :
					    "dropped connection");
					निकास(1);
				}
				amt -= j;
				cp += j;
			} जबतक (amt > 0);

			अगर (गिनती == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				अगर (!wrerr) {
					अगर (atomicio(vwrite, ofd, bp->buf,
					    गिनती) != गिनती) {
						note_err("%s: %s", np,
						    म_त्रुटि(त्रुटि_सं));
						wrerr = 1;
					}
				}
				गिनती = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		अगर (गिनती != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, गिनती) != गिनती) {
			note_err("%s: %s", np, म_त्रुटि(त्रुटि_सं));
			wrerr = 1;
		}
		अगर (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, आकार) != 0)
			note_err("%s: truncate: %s", np, म_त्रुटि(त्रुटि_सं));
		अगर (pflag) {
			अगर (exists || omode != mode)
#अगर_घोषित HAVE_FCHMOD
				अगर (fchmod(ofd, omode)) {
#अन्यथा /* HAVE_FCHMOD */
				अगर (chmod(np, omode)) {
#पूर्ण_अगर /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, म_त्रुटि(त्रुटि_सं));
				}
		} अन्यथा {
			अगर (!exists && omode != mode)
#अगर_घोषित HAVE_FCHMOD
				अगर (fchmod(ofd, omode & ~mask)) {
#अन्यथा /* HAVE_FCHMOD */
				अगर (chmod(np, omode & ~mask)) {
#पूर्ण_अगर /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, म_त्रुटि(त्रुटि_सं));
				}
		}
		अगर (बंद(ofd) == -1)
			note_err("%s: close: %s", np, म_त्रुटि(त्रुटि_सं));
		(व्योम) response();
		अगर (showprogress)
			stop_progress_meter();
		अगर (setimes && !wrerr) {
			setimes = 0;
			अगर (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, म_त्रुटि(त्रुटि_सं));
			}
		}
		/* If no error was noted then signal success for this file */
		अगर (note_err(शून्य) == 0)
			(व्योम) atomicio(vwrite, remout, "", 1);
	}
done:
	क्रम (n = 0; n < npatterns; n++)
		मुक्त(patterns[n]);
	मुक्त(patterns);
	वापस;
screwup:
	क्रम (n = 0; n < npatterns; n++)
		मुक्त(patterns[n]);
	मुक्त(patterns);
	run_err("protocol error: %s", why);
	निकास(1);
}

व्योम
throughlocal_sftp(काष्ठा sftp_conn *from, काष्ठा sftp_conn *to,
    अक्षर *src, अक्षर *targ)
{
	अक्षर *target = शून्य, *filename = शून्य, *abs_dst = शून्य;
	अक्षर *abs_src = शून्य, *tmp = शून्य;
	glob_t g;
	पूर्णांक i, r, targetisdir, err = 0;

	अगर ((filename = basename(src)) == शून्य)
		fatal("basename %s: %s", src, म_त्रुटि(त्रुटि_सं));

	अगर ((abs_src = prepare_remote_path(from, src)) == शून्य ||
	    (target = prepare_remote_path(to, targ)) == शून्य)
		cleanup_exit(255);
	स_रखो(&g, 0, माप(g));

	targetisdir = sftp_remote_is_dir(to, target);
	अगर (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		जाओ out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	अगर ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    शून्य, &g)) != 0) {
		अगर (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		अन्यथा
			error("%s: %s", src, म_त्रुटि(ENOENT));
		err = -1;
		जाओ out;
	}

	/* Did we actually get any matches back from the glob? */
	अगर (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != शून्य) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		अगर (sftp_stat(from, g.gl_pathv[0], 1, शून्य) != 0) {
			error("%s: %s", src, म_त्रुटि(ENOENT));
			err = -1;
			जाओ out;
		}
	}

	क्रम (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		अगर ((filename = basename(tmp)) == शून्य) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			err = -1;
			जाओ out;
		}

		/* Special handling for source of '..' */
		अगर (म_भेद(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		अगर (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		अन्यथा
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		अगर (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			अगर (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    शून्य, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} अन्यथा {
			अगर (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    शून्य, pflag) == -1)
				err = -1;
		}
		मुक्त(abs_dst);
		abs_dst = शून्य;
		मुक्त(tmp);
		tmp = शून्य;
	}

out:
	मुक्त(abs_src);
	मुक्त(abs_dst);
	मुक्त(target);
	मुक्त(tmp);
	globfree(&g);
	अगर (err == -1)
		errs = 1;
}

पूर्णांक
response(व्योम)
{
	अक्षर ch, *cp, resp, rbuf[2048], visbuf[2048];

	अगर (atomicio(पढ़ो, remin, &resp, माप(resp)) != माप(resp))
		lostconn(0);

	cp = rbuf;
	चयन (resp) {
	हाल 0:		/* ok */
		वापस (0);
	शेष:
		*cp++ = resp;
		/* FALLTHROUGH */
	हाल 1:		/* error, followed by error msg */
	हाल 2:		/* fatal error, "" */
		करो {
			अगर (atomicio(पढ़ो, remin, &ch, माप(ch)) != माप(ch))
				lostconn(0);
			*cp++ = ch;
		} जबतक (cp < &rbuf[माप(rbuf) - 1] && ch != '\n');

		अगर (!iamremote) {
			cp[-1] = '\0';
			(व्योम) snmprintf(visbuf, माप(visbuf),
			    शून्य, "%s\n", rbuf);
			(व्योम) atomicio(vwrite, STDERR_FILENO,
			    visbuf, म_माप(visbuf));
		}
		++errs;
		अगर (resp == 1)
			वापस (-1);
		निकास(1);
	}
	/* NOTREACHED */
}

व्योम
usage(व्योम)
{
	(व्योम) ख_लिखो(मानक_त्रुटि,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	निकास(1);
}

व्योम
run_err(स्थिर अक्षर *fmt,...)
{
	अटल खाता *fp;
	बहु_सूची ap;

	++errs;
	अगर (fp != शून्य || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(व्योम) ख_लिखो(fp, "%c", 0x01);
		(व्योम) ख_लिखो(fp, "scp: ");
		बहु_शुरू(ap, fmt);
		(व्योम) भख_लिखो(fp, fmt, ap);
		बहु_पूर्ण(ap);
		(व्योम) ख_लिखो(fp, "\n");
		(व्योम) ख_साफ(fp);
	}

	अगर (!iamremote) {
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
पूर्णांक
note_err(स्थिर अक्षर *fmt, ...)
{
	अटल अक्षर *emsg;
	बहु_सूची ap;

	/* Replay any previously-noted error */
	अगर (fmt == शून्य) {
		अगर (emsg == शून्य)
			वापस 0;
		run_err("%s", emsg);
		मुक्त(emsg);
		emsg = शून्य;
		वापस -1;
	}

	errs++;
	/* Prefer first-noted error */
	अगर (emsg != शून्य)
		वापस -1;

	बहु_शुरू(ap, fmt);
	vasnmprintf(&emsg, पूर्णांक_उच्च, शून्य, fmt, ap);
	बहु_पूर्ण(ap);
	वापस -1;
}

व्योम
verifydir(अक्षर *cp)
{
	काष्ठा stat stb;

	अगर (!stat(cp, &stb)) {
		अगर (S_ISDIR(stb.st_mode))
			वापस;
		त्रुटि_सं = ENOTDIR;
	}
	run_err("%s: %s", cp, म_त्रुटि(त्रुटि_सं));
	killchild(0);
}

पूर्णांक
okname(अक्षर *cp0)
{
	पूर्णांक c;
	अक्षर *cp;

	cp = cp0;
	करो {
		c = (पूर्णांक)*cp;
		अगर (c & 0200)
			जाओ bad;
		अगर (!है_अक्षर(c) && !है_अंक((अचिन्हित अक्षर)c)) {
			चयन (c) {
			हाल '\'':
			हाल '"':
			हाल '`':
			हाल ' ':
			हाल '#':
				जाओ bad;
			शेष:
				अवरोध;
			}
		}
	} जबतक (*++cp);
	वापस (1);

bad:	fmprintf(मानक_त्रुटि, "%s: invalid user name\n", cp0);
	वापस (0);
}

BUF *
allocbuf(BUF *bp, पूर्णांक fd, पूर्णांक blksize)
{
	माप_प्रकार आकार;
#अगर_घोषित HAVE_STRUCT_STAT_ST_BLKSIZE
	काष्ठा stat stb;

	अगर (ख_स्थिति(fd, &stb) == -1) {
		run_err("fstat: %s", म_त्रुटि(त्रुटि_सं));
		वापस (शून्य);
	}
	आकार = ROUNDUP(stb.st_blksize, blksize);
	अगर (आकार == 0)
		आकार = blksize;
#अन्यथा /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	आकार = blksize;
#पूर्ण_अगर /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	अगर (bp->cnt >= आकार)
		वापस (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, आकार, 1);
	bp->cnt = आकार;
	वापस (bp);
}

व्योम
lostconn(पूर्णांक signo)
{
	अगर (!iamremote)
		(व्योम)ग_लिखो(STDERR_FILENO, "lost connection\n", 16);
	अगर (signo)
		_निकास(1);
	अन्यथा
		निकास(1);
}

व्योम
cleanup_exit(पूर्णांक i)
{
	अगर (remin > 0)
		बंद(remin);
	अगर (remout > 0)
		बंद(remout);
	अगर (remin2 > 0)
		बंद(remin2);
	अगर (remout2 > 0)
		बंद(remout2);
	अगर (do_cmd_pid > 0)
		(व्योम)waitpid(do_cmd_pid, शून्य, 0);
	अगर (do_cmd_pid2 > 0)
		(व्योम)waitpid(do_cmd_pid2, शून्य, 0);
	निकास(i);
}
