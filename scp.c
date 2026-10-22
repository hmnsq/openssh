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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/uio.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <dirent.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#నిర్వచితమైతే HAVE_FNMATCH_H
#అన్తర్భావ <fnmatch.h>
#అయితే_ముగింపు
#అన్తర్భావ <glob.h>
#అన్తర్భావ <libgen.h>
#అన్తర్భావ <locale.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <util.h>
#ఒకవేళ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#అన్తర్భావ <vis.h>
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "atomicio.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "progressmeter.h"
#అన్తర్భావ "utf8.h"
#అన్తర్భావ "sftp.h"

#అన్తర్భావ "sftp-common.h"
#అన్తర్భావ "sftp-client.h"

బాహ్య అక్షరం *__progname;

#నిర్వచించు COPY_BUFLEN	16384

పూర్ణాంకం do_cmd(అక్షరం *, అక్షరం *, అక్షరం *, పూర్ణాంకం, పూర్ణాంకం, అక్షరం *, పూర్ణాంకం *, పూర్ణాంకం *, pid_t *);
పూర్ణాంకం do_cmd2(అక్షరం *, అక్షరం *, పూర్ణాంకం, అక్షరం *, పూర్ణాంకం, పూర్ణాంకం);

/* Struct for addargs */
arglist వాదనలు;
arglist remote_remote_వాదనలు;

/* Bandwidth limit */
దీర్ఘ దీర్ఘ హద్దు_kbps = 0;
నిర్మాణం bwlimit bwlimit;

/* Name of current file being transferred. */
అక్షరం *curfile;

/* This is set to non-zero to enable verbose mode. */
పూర్ణాంకం verbose_బహుళకం = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
పూర్ణాంకం showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
పూర్ణాంకం throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
పూర్ణాంకం sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
అక్షరం *ssh_కార్యక్రమం = మార్గం_SSH_కార్యక్రమం;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
కొలత_t sftp_copy_buflen;
కొలత_t sftp_nrequests;

/* Needed for sftp */
అస్థిర sig_atomic_t interrupted = 0;

పూర్ణాంకం sftp_glob(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, పూర్ణాంకం,
    పూర్ణాంకం (*)(స్థిరరాశి అక్షరం *, పూర్ణాంకం), glob_t *); /* proto for sftp-glob.c */

స్థిర శూన్య
killchild(పూర్ణాంకం signo)
{
	ఒకవేళ (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(శూన్య)waitpid(do_cmd_pid, ఖాళీ, 0);
	}
	ఒకవేళ (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(శూన్య)waitpid(do_cmd_pid2, ఖాళీ, 0);
	}

	ఒకవేళ (signo)
		_exit(1);
	నిష్క్రమించు(1);
}

స్థిర శూన్య
suspone(పూర్ణాంకం pid, పూర్ణాంకం signo)
{
	పూర్ణాంకం స్థితి_2;

	ఒకవేళ (pid > 1) {
		kill(pid, signo);
		అయితే (waitpid(pid, &స్థితి_2, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

స్థిర శూన్య
suspchild(పూర్ణాంకం signo)
{
	పూర్ణాంకం save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

స్థిర పూర్ణాంకం
do_local_cmd(arglist *a)
{
	అక్షరం *cp;
	పూర్ణాంకం స్థితి_2;
	pid_t pid;

	ఒకవేళ (a->అంకె == 0)
		fatal("do_local_cmd: no arguments");

	ఒకవేళ (verbose_బహుళకం) {
		cp = argv_assemble(a->అంకె, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		విడుదల(cp);
	}
	ఒకవేళ ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	ఒకవేళ (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		నిష్క్రమించు(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	అయితే (waitpid(pid, &స్థితి_2, 0) == -1)
		ఒకవేళ (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	ఒకవేళ (!WIFEXITED(స్థితి_2) || WEXITSTATUS(స్థితి_2) != 0)
		తిరిగి (-1);

	తిరిగి (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

పూర్ణాంకం
do_cmd(అక్షరం *కార్యక్రమం, అక్షరం *host, అక్షరం *remuser, పూర్ణాంకం పోర్టు, పూర్ణాంకం subsystem,
    అక్షరం *cmd, పూర్ణాంకం *fdin, పూర్ణాంకం *fdout, pid_t *pid)
{
#నిర్వచితమైతే USE_PIPES
	పూర్ణాంకం pin[2], pout[2];
#లేకపోతే
	పూర్ణాంకం sv[2];
#అయితే_ముగింపు

	ఒకవేళ (verbose_బహుళకం)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    కార్యక్రమం, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ఒకవేళ (పోర్టు == -1)
		పోర్టు = sshport;

#నిర్వచితమైతే USE_PIPES
	ఒకవేళ (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#లేకపోతే
	/* Create a socket pair for communicating with ssh. */
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#అయితే_ముగింపు

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	ఎంపిక (*pid) {
	స్థితి -1:
		fatal("fork: %s", strerror(errno));
	స్థితి 0:
		/* Child. */
#నిర్వచితమైతే USE_PIPES
		ఒకవేళ (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#లేకపోతే
		ఒకవేళ (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#అయితే_ముగింపు
		replacearg(&వాదనలు, 0, "%s", కార్యక్రమం);
		ఒకవేళ (పోర్టు != -1) {
			addargs(&వాదనలు, "-p");
			addargs(&వాదనలు, "%d", పోర్టు);
		}
		ఒకవేళ (remuser != ఖాళీ) {
			addargs(&వాదనలు, "-l");
			addargs(&వాదనలు, "%s", remuser);
		}
		ఒకవేళ (subsystem)
			addargs(&వాదనలు, "-s");
		addargs(&వాదనలు, "--");
		addargs(&వాదనలు, "%s", host);
		addargs(&వాదనలు, "%s", cmd);

		execvp(కార్యక్రమం, వాదనలు.list);
		perror(కార్యక్రమం);
		_exit(1);
	అప్రమేయ:
		/* Parent.  Close the other side, and return the local side. */
#నిర్వచితమైతే USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#లేకపోతే
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#అయితే_ముగింపు
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		తిరిగి 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
పూర్ణాంకం
do_cmd2(అక్షరం *host, అక్షరం *remuser, పూర్ణాంకం పోర్టు, అక్షరం *cmd,
    పూర్ణాంకం fdin, పూర్ణాంకం fdout)
{
	పూర్ణాంకం స్థితి_2;
	pid_t pid;

	ఒకవేళ (verbose_బహుళకం)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_కార్యక్రమం, host,
		    remuser ? remuser : "(unspecified)", cmd);

	ఒకవేళ (పోర్టు == -1)
		పోర్టు = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	ఒకవేళ (pid == 0) {
		ఒకవేళ (dup2(fdin, 0) == -1)
			perror("dup2");
		ఒకవేళ (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&వాదనలు, 0, "%s", ssh_కార్యక్రమం);
		ఒకవేళ (పోర్టు != -1) {
			addargs(&వాదనలు, "-p");
			addargs(&వాదనలు, "%d", పోర్టు);
		}
		ఒకవేళ (remuser != ఖాళీ) {
			addargs(&వాదనలు, "-l");
			addargs(&వాదనలు, "%s", remuser);
		}
		addargs(&వాదనలు, "-oBatchMode=yes");
		addargs(&వాదనలు, "--");
		addargs(&వాదనలు, "%s", host);
		addargs(&వాదనలు, "%s", cmd);

		execvp(ssh_కార్యక్రమం, వాదనలు.list);
		perror(ssh_కార్యక్రమం);
		నిష్క్రమించు(1);
	} లేకపోతే ఒకవేళ (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	అయితే (waitpid(pid, &స్థితి_2, 0) == -1)
		ఒకవేళ (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	తిరిగి 0;
}

రకనిర్వచనం నిర్మాణం {
	కొలత_t cnt;
	అక్షరం *buf;
} BUF;

BUF *allocbuf(BUF *, పూర్ణాంకం, పూర్ణాంకం);
శూన్య lostconn(పూర్ణాంకం);
పూర్ణాంకం okname(అక్షరం *);
శూన్య నిరంతరం_err(స్థిరరాశి అక్షరం *,...)
    __attribute__((__format__ (రాయి, 1, 2)))
    __attribute__((__nonnull__ (1)));
పూర్ణాంకం note_err(స్థిరరాశి అక్షరం *,...)
    __attribute__((__format__ (రాయి, 1, 2)));
శూన్య verifydir(అక్షరం *);

నిర్మాణం passwd *pwd;
uid_t userid;
పూర్ణాంకం errs, remin, remout, remin2, remout2;
పూర్ణాంకం Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#నిర్వచించు	CMDNEEDS	64
అక్షరం cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

గణన scp_బహుళకం_e {
	బహుళకం_SCP,
	బహుళకం_SFTP
};

పూర్ణాంకం response(శూన్య);
శూన్య rsource(అక్షరం *, నిర్మాణం stat *);
శూన్య sink(పూర్ణాంకం, అక్షరం *[], స్థిరరాశి అక్షరం *);
శూన్య ఆధారం(పూర్ణాంకం, అక్షరం *[]);
శూన్య tolocal(పూర్ణాంకం, అక్షరం *[], గణన scp_బహుళకం_e, అక్షరం *sftp_ప్రత్యక్ష);
శూన్య toremote(పూర్ణాంకం, అక్షరం *[], గణన scp_బహుళకం_e, అక్షరం *sftp_ప్రత్యక్ష);
శూన్య usage(శూన్య);

శూన్య ఆధారం_sftp(పూర్ణాంకం, అక్షరం *, అక్షరం *, నిర్మాణం sftp_conn *);
శూన్య sink_sftp(పూర్ణాంకం, అక్షరం *, స్థిరరాశి అక్షరం *, నిర్మాణం sftp_conn *);
శూన్య throughlocal_sftp(నిర్మాణం sftp_conn *, నిర్మాణం sftp_conn *,
    అక్షరం *, అక్షరం *);

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం ch, fflag, tflag, స్థితి_2, r, n;
	అక్షరం **newargv, *argv0;
	స్థిరరాశి అక్షరం *errstr;
	బాహ్య అక్షరం *optarg;
	బాహ్య పూర్ణాంకం optind;
	గణన scp_బహుళకం_e బహుళకం = బహుళకం_SFTP;
	అక్షరం *sftp_ప్రత్యక్ష = ఖాళీ;
	దీర్ఘ దీర్ఘ llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(గరిష్ఠ(argc + 1, 1), పరిమాణం(*newargv));
	కొరకు (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&వాదనలు, '\0', పరిమాణం(వాదనలు));
	memset(&remote_remote_వాదనలు, '\0', పరిమాణం(remote_remote_వాదనలు));
	వాదనలు.list = remote_remote_వాదనలు.list = ఖాళీ;
	addargs(&వాదనలు, "%s", ssh_కార్యక్రమం);
	addargs(&వాదనలు, "-x");
	addargs(&వాదనలు, "-oPermitLocalCommand=no");
	addargs(&వాదనలు, "-oClearAllForwardings=yes");
	addargs(&వాదనలు, "-oRemoteCommand=none");
	addargs(&వాదనలు, "-oRequestTTY=no");
	addargs(&వాదనలు, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	అయితే ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		ఎంపిక (ch) {
		/* User-visible flags. */
		స్థితి '1':
			fatal("SSH protocol v.1 is no longer supported");
			ఆపు;
		స్థితి '2':
			/* Ignored */
			ఆపు;
		స్థితి 'A':
		స్థితి '4':
		స్థితి '6':
		స్థితి 'C':
			addargs(&వాదనలు, "-%c", ch);
			addargs(&remote_remote_వాదనలు, "-%c", ch);
			ఆపు;
		స్థితి 'D':
			sftp_ప్రత్యక్ష = optarg;
			ఆపు;
		స్థితి '3':
			throughlocal = 1;
			ఆపు;
		స్థితి 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			ఆపు;
		స్థితి 'o':
		స్థితి 'c':
		స్థితి 'i':
		స్థితి 'F':
		స్థితి 'J':
			addargs(&remote_remote_వాదనలు, "-%c", ch);
			addargs(&remote_remote_వాదనలు, "%s", optarg);
			addargs(&వాదనలు, "-%c", ch);
			addargs(&వాదనలు, "%s", optarg);
			ఆపు;
		స్థితి 'O':
			బహుళకం = బహుళకం_SCP;
			ఆపు;
		స్థితి 's':
			/* Ignored */
			ఆపు;
		స్థితి 'P':
			sshport = a2port(optarg);
			ఒకవేళ (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			ఆపు;
		స్థితి 'B':
			addargs(&remote_remote_వాదనలు, "-oBatchmode=yes");
			addargs(&వాదనలు, "-oBatchmode=yes");
			ఆపు;
		స్థితి 'l':
			హద్దు_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ఒకవేళ (errstr != ఖాళీ)
				usage();
			హద్దు_kbps *= 1024; /* kbps */
			bandwidth_హద్దు_init(&bwlimit, హద్దు_kbps, COPY_BUFLEN);
			ఆపు;
		స్థితి 'p':
			pflag = 1;
			ఆపు;
		స్థితి 'r':
			iamrecursive = 1;
			ఆపు;
		స్థితి 'S':
			ssh_కార్యక్రమం = xstrdup(optarg);
			ఆపు;
		స్థితి 'v':
			addargs(&వాదనలు, "-v");
			addargs(&remote_remote_వాదనలు, "-v");
			ఒకవేళ (verbose_బహుళకం == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			లేకపోతే ఒకవేళ (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_బహుళకం = 1;
			ఆపు;
		స్థితి 'q':
			addargs(&వాదనలు, "-q");
			addargs(&remote_remote_వాదనలు, "-q");
			showprogress = 0;
			ఆపు;
		స్థితి 'X':
			/* Please keep in sync with sftp.c -X */
			ఒకవేళ (అక్షరశ్రేణి_పోలిక(optarg, "buffer=", 7) == 0) {
				r = పరిశీలన_scaled(optarg + 7, &llv);
				ఒకవేళ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ఒకవేళ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (కొలత_t)llv;
			} లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ఒకవేళ (errstr != ఖాళీ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (కొలత_t)llv;
			} లేకపోతే {
				fatal("Invalid -X option");
			}
			ఆపు;

		/* Server options. */
		స్థితి 'd':
			targetshouldbedirectory = 1;
			ఆపు;
		స్థితి 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			ఆపు;
		స్థితి 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#నిర్వచితమైతే HAVE_CYGWIN
			setmode(0, O_ద్విమాన);
#అయితే_ముగింపు
			ఆపు;
		స్థితి 'T':
			Tflag = 1;
			ఆపు;
		అప్రమేయ:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&వాదనలు, "-oForwardAgent=no");

	ఒకవేళ (iamremote)
		బహుళకం = బహుళకం_SCP;

	ఒకవేళ ((pwd = getpwuid(userid = getuid())) == ఖాళీ)
		fatal("unknown user %u", (u_int) userid);

	ఒకవేళ (!isatty(STDOUT_FILENO))
		showprogress = 0;

	ఒకవేళ (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} లేకపోతే {
		ఒకవేళ (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    ఖాళీ) == -1) {
			perror("pledge");
			నిష్క్రమించు(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	ఒకవేళ (fflag) {
		/* Follow "protocol", send data. */
		(శూన్య) response();
		ఆధారం(argc, argv);
		నిష్క్రమించు(errs != 0);
	}
	ఒకవేళ (tflag) {
		/* Receive data. */
		sink(argc, argv, ఖాళీ);
		నిష్క్రమించు(errs != 0);
	}
	ఒకవేళ (argc < 2)
		usage();
	ఒకవేళ (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(శూన్య) snprintf(cmd, పరిమాణం cmd, "scp%s%s%s%s",
	    verbose_బహుళకం ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(శూన్య) ssh_signal(SIGPIPE, lostconn);

	ఒకవేళ (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, బహుళకం, sftp_ప్రత్యక్ష);
	లేకపోతే {
		ఒకవేళ (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, బహుళకం, sftp_ప్రత్యక్ష);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	ఒకవేళ (do_cmd_pid != -1 && (బహుళకం == బహుళకం_SFTP || errs == 0)) {
		ఒకవేళ (remin != -1)
		    (శూన్య) close(remin);
		ఒకవేళ (remout != -1)
		    (శూన్య) close(remout);
		ఒకవేళ (waitpid(do_cmd_pid, &స్థితి_2, 0) == -1)
			errs = 1;
		లేకపోతే {
			ఒకవేళ (!WIFEXITED(స్థితి_2) || WEXITSTATUS(స్థితి_2) != 0)
				errs = 1;
		}
	}
	నిష్క్రమించు(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
స్థిర పూర్ణాంకం
scpio(శూన్య *_cnt, కొలత_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_పురోగతి_meter(0);
	ఒకవేళ (హద్దు_kbps > 0)
		bandwidth_హద్దు(&bwlimit, s);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
do_times(పూర్ణాంకం fd, పూర్ణాంకం verb, స్థిరరాశి నిర్మాణం stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	అక్షరం buf[(20 + 7 + 2) * 2 + 2];

	(శూన్య)snprintf(buf, పరిమాణం(buf), "T%llu 0 %llu 0\n",
	    (గుర్తులేని దీర్ఘ దీర్ఘ) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (గుర్తులేని దీర్ఘ దీర్ఘ) (sb->st_atime < 0 ? 0 : sb->st_atime));
	ఒకవేళ (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (దీర్ఘ దీర్ఘ)sb->st_mtime, (దీర్ఘ దీర్ఘ)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(శూన్య) atomicio(vwrite, fd, buf, అక్షరశ్రేణి_పొడవు(buf));
	తిరిగి (response());
}

స్థిర పూర్ణాంకం
parse_scp_uri(స్థిరరాశి అక్షరం *uri, అక్షరం **userp, అక్షరం **hostp, పూర్ణాంకం *portp,
    అక్షరం **pathp)
{
	పూర్ణాంకం r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	ఒకవేళ (r == 0 && *pathp == ఖాళీ)
		*pathp = xstrdup(".");
	తిరిగి r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
స్థిర పూర్ణాంకం
append(అక్షరం *cp, అక్షరం ***ap, కొలత_t *np)
{
	అక్షరం **tmp;

	ఒకవేళ ((tmp = reallocarray(*ap, *np + 1, పరిమాణం(*tmp))) == ఖాళీ)
		తిరిగి -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	తిరిగి 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
స్థిర పూర్ణాంకం
కనుగొను_brace(స్థిరరాశి అక్షరం *నమూనా, పూర్ణాంకం *startp, పూర్ణాంకం *endp)
{
	పూర్ణాంకం i;
	పూర్ణాంకం లోపల_bracket, brace_level;

	*startp = *endp = -1;
	లోపల_bracket = brace_level = 0;
	కొరకు (i = 0; i < గరిష్ఠ_పూర్ణాంకం && *endp < 0 && నమూనా[i] != '\0'; i++) {
		ఎంపిక (నమూనా[i]) {
		స్థితి '\\':
			/* skip next character */
			ఒకవేళ (నమూనా[i + 1] != '\0')
				i++;
			ఆపు;
		స్థితి '[':
			లోపల_bracket = 1;
			ఆపు;
		స్థితి ']':
			లోపల_bracket = 0;
			ఆపు;
		స్థితి '{':
			ఒకవేళ (లోపల_bracket)
				ఆపు;
			ఒకవేళ (నమూనా[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				ఆపు;
			}
			ఒకవేళ (*startp == -1)
				*startp = i;
			brace_level++;
			ఆపు;
		స్థితి '}':
			ఒకవేళ (లోపల_bracket)
				ఆపు;
			ఒకవేళ (*startp < 0) {
				/* Unbalanced brace */
				తిరిగి -1;
			}
			ఒకవేళ (--brace_level <= 0)
				*endp = i;
			ఆపు;
		}
	}
	/* unbalanced brackets/braces */
	ఒకవేళ (*endp < 0 && (*startp >= 0 || లోపల_bracket))
		తిరిగి -1;
	తిరిగి 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
స్థిర పూర్ణాంకం
emit_expansion(స్థిరరాశి అక్షరం *నమూనా, పూర్ణాంకం brace_ప్రారంభం, పూర్ణాంకం brace_చివర,
    పూర్ణాంకం sel_ప్రారంభం, పూర్ణాంకం sel_చివర, అక్షరం ***patternsp, కొలత_t *npatternsp)
{
	అక్షరం *cp;
	కొలత_t నమూనా_len;
	పూర్ణాంకం o = 0, తోక_len;

	ఒకవేళ ((నమూనా_len = అక్షరశ్రేణి_పొడవు(నమూనా)) == 0 || నమూనా_len >= గరిష్ఠ_పూర్ణాంకం)
		తిరిగి -1;

	తోక_len = అక్షరశ్రేణి_పొడవు(నమూనా + brace_చివర + 1);
	ఒకవేళ ((cp = జ్ఞాపకం_ఇవ్వు(brace_ప్రారంభం + (sel_చివర - sel_ప్రారంభం) +
	    తోక_len + 1)) == ఖాళీ)
		తిరిగి -1;

	/* Pattern before initial brace */
	ఒకవేళ (brace_ప్రారంభం > 0) {
		జ్ఞాపకం_నకలు(cp, నమూనా, brace_ప్రారంభం);
		o = brace_ప్రారంభం;
	}
	/* Current braced selection */
	ఒకవేళ (sel_చివర - sel_ప్రారంభం > 0) {
		జ్ఞాపకం_నకలు(cp + o, నమూనా + sel_ప్రారంభం,
		    sel_చివర - sel_ప్రారంభం);
		o += sel_చివర - sel_ప్రారంభం;
	}
	/* Remainder of pattern after closing brace */
	ఒకవేళ (తోక_len > 0) {
		జ్ఞాపకం_నకలు(cp + o, నమూనా + brace_చివర + 1, తోక_len);
		o += తోక_len;
	}
	cp[o] = '\0';
	ఒకవేళ (append(cp, patternsp, npatternsp) != 0) {
		విడుదల(cp);
		తిరిగి -1;
	}
	తిరిగి 0;
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
స్థిర పూర్ణాంకం
brace_expand_one(స్థిరరాశి అక్షరం *నమూనా, అక్షరం ***patternsp, కొలత_t *npatternsp,
    పూర్ణాంకం *expanded, పూర్ణాంకం *invalid)
{
	పూర్ణాంకం i;
	పూర్ణాంకం లోపల_bracket, brace_ప్రారంభం, brace_చివర, brace_level;
	పూర్ణాంకం sel_ప్రారంభం, sel_చివర;

	*invalid = *expanded = 0;

	ఒకవేళ (కనుగొను_brace(నమూనా, &brace_ప్రారంభం, &brace_చివర) != 0) {
		*invalid = 1;
		తిరిగి 0;
	} లేకపోతే ఒకవేళ (brace_ప్రారంభం == -1)
		తిరిగి 0;

	లోపల_bracket = brace_level = 0;
	కొరకు (i = sel_ప్రారంభం = brace_ప్రారంభం + 1; i < brace_చివర; i++) {
		ఎంపిక (నమూనా[i]) {
		స్థితి '{':
			ఒకవేళ (లోపల_bracket)
				ఆపు;
			brace_level++;
			ఆపు;
		స్థితి '}':
			ఒకవేళ (లోపల_bracket)
				ఆపు;
			brace_level--;
			ఆపు;
		స్థితి '[':
			లోపల_bracket = 1;
			ఆపు;
		స్థితి ']':
			లోపల_bracket = 0;
			ఆపు;
		స్థితి '\\':
			ఒకవేళ (i < brace_చివర - 1)
				i++; /* skip */
			ఆపు;
		}
		ఒకవేళ (నమూనా[i] == ',' || i == brace_చివర - 1) {
			ఒకవేళ (లోపల_bracket || brace_level > 0)
				కొనసాగు;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_చివర = (i == brace_చివర - 1) ? brace_చివర : i;
			ఒకవేళ (emit_expansion(నమూనా, brace_ప్రారంభం, brace_చివర,
			    sel_ప్రారంభం, sel_చివర, patternsp, npatternsp) != 0)
				తిరిగి -1;
			/* move on to the next selection */
			sel_ప్రారంభం = i + 1;
			కొనసాగు;
		}
	}
	ఒకవేళ (లోపల_bracket || brace_level > 0) {
		*invalid = 1;
		తిరిగి 0;
	}
	/* success */
	*expanded = 1;
	తిరిగి 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
స్థిర పూర్ణాంకం
brace_expand(స్థిరరాశి అక్షరం *నమూనా, అక్షరం ***patternsp, కొలత_t *npatternsp)
{
	అక్షరం *cp, *cp2, **చురుకైన = ఖాళీ, **పూర్తి = ఖాళీ;
	కొలత_t i, nactive = 0, ndone = 0;
	పూర్ణాంకం ret = -1, invalid = 0, expanded = 0;

	*patternsp = ఖాళీ;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	ఒకవేళ ((cp = strdup(నమూనా)) == ఖాళీ)
		తిరిగి -1;
	ఒకవేళ (append(cp, &చురుకైన, &nactive) != 0) {
		విడుదల(cp);
		తిరిగి -1;
	}
	అయితే (nactive > 0) {
		cp = చురుకైన[nactive - 1];
		nactive--;
		ఒకవేళ (brace_expand_one(cp, &చురుకైన, &nactive,
		    &expanded, &invalid) == -1) {
			విడుదల(cp);
			వెళ్ళు fail;
		}
		ఒకవేళ (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		ఒకవేళ (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			విడుదల(cp);
			కొనసాగు;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		ఒకవేళ ((cp2 = strrchr(cp, '/')) != ఖాళీ)
			*cp2++ = '\0';
		లేకపోతే
			cp2 = cp;
		ఒకవేళ (append(xstrdup(cp2), &పూర్తి, &ndone) != 0) {
			విడుదల(cp);
			వెళ్ళు fail;
		}
		విడుదల(cp);
	}
	/* success */
	*patternsp = పూర్తి;
	*npatternsp = ndone;
	పూర్తి = ఖాళీ;
	ndone = 0;
	ret = 0;
 fail:
	కొరకు (i = 0; i < nactive; i++)
		విడుదల(చురుకైన[i]);
	విడుదల(చురుకైన);
	కొరకు (i = 0; i < ndone; i++)
		విడుదల(పూర్తి[i]);
	విడుదల(పూర్తి);
	తిరిగి ret;
}

స్థిర నిర్మాణం sftp_conn *
do_sftp_connect(అక్షరం *host, అక్షరం *user, పూర్ణాంకం పోర్టు, అక్షరం *sftp_ప్రత్యక్ష,
   పూర్ణాంకం *reminp, పూర్ణాంకం *remoutp, పూర్ణాంకం *pidp)
{
	ఒకవేళ (sftp_ప్రత్యక్ష == ఖాళీ) {
		ఒకవేళ (do_cmd(ssh_కార్యక్రమం, host, user, పోర్టు, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			తిరిగి ఖాళీ;

	} లేకపోతే {
		freeargs(&వాదనలు);
		addargs(&వాదనలు, "sftp-server");
		ఒకవేళ (do_cmd(sftp_ప్రత్యక్ష, host, ఖాళీ, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			తిరిగి ఖాళీ;
	}
	తిరిగి sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, హద్దు_kbps);
}

శూన్య
toremote(పూర్ణాంకం argc, అక్షరం **argv, గణన scp_బహుళకం_e బహుళకం, అక్షరం *sftp_ప్రత్యక్ష)
{
	అక్షరం *suser = ఖాళీ, *host = ఖాళీ, *src = ఖాళీ;
	అక్షరం *bp, *tuser, *thost, *targ;
	పూర్ణాంకం sport = -1, tport = -1;
	నిర్మాణం sftp_conn *conn = ఖాళీ, *conn2 = ఖాళీ;
	arglist alist;
	పూర్ణాంకం i, r, స్థితి_2;
	నిర్మాణం stat sb;
	u_int j;

	memset(&alist, '\0', పరిమాణం(alist));
	alist.list = ఖాళీ;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	ఒకవేళ (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (r != 0) {
		ఒకవేళ (parse_user_host_మార్గం(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Parse source files */
	కొరకు (i = 0; i < argc - 1; i++) {
		విడుదల(suser);
		విడుదల(host);
		విడుదల(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ఒకవేళ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			కొనసాగు;
		}
		ఒకవేళ (r != 0) {
			parse_user_host_మార్గం(argv[i], &suser, &host, &src);
		}
		ఒకవేళ (suser != ఖాళీ && !okname(suser)) {
			++errs;
			కొనసాగు;
		}
		ఒకవేళ (host && throughlocal) {	/* extended remote to remote */
			ఒకవేళ (బహుళకం == బహుళకం_SFTP) {
				ఒకవేళ (remin == -1 || conn == ఖాళీ) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_ప్రత్యక్ష,
					    &remin, &remout, &do_cmd_pid);
					ఒకవేళ (conn == ఖాళీ) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (దీర్ఘ)do_cmd_pid);
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
				    sport, sftp_ప్రత్యక్ష,
				    &remin2, &remout2, &do_cmd_pid2);
				ఒకవేళ (conn2 == ఖాళీ) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (దీర్ఘ)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(శూన్య) close(remin2);
				(శూన్య) close(remout2);
				remin2 = remout2 = -1;
				ఒకవేళ (waitpid(do_cmd_pid2, &స్థితి_2, 0) == -1)
					++errs;
				లేకపోతే ఒకవేళ (!WIFEXITED(స్థితి_2) ||
				    WEXITSTATUS(స్థితి_2) != 0)
					++errs;
				do_cmd_pid2 = -1;
				కొనసాగు;
			} లేకపోతే {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				ఒకవేళ (do_cmd(ssh_కార్యక్రమం, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					నిష్క్రమించు(1);
				విడుదల(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ఒకవేళ (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					నిష్క్రమించు(1);
				విడుదల(bp);
				(శూన్య) close(remin);
				(శూన్య) close(remout);
				remin = remout = -1;
			}
		} లేకపోతే ఒకవేళ (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			ఒకవేళ (tuser != ఖాళీ && !okname(tuser)) {
				++errs;
				కొనసాగు;
			}
			ఒకవేళ (tport != -1 && tport != SSH_DEFAULT_పోర్టు) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_కార్యక్రమం);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			కొరకు (j = 0; j < remote_remote_వాదనలు.అంకె; j++) {
				addargs(&alist, "%s",
				    remote_remote_వాదనలు.list[j]);
			}

			ఒకవేళ (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			ఒకవేళ (suser) {
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
			ఒకవేళ (do_local_cmd(&alist) != 0)
				errs = 1;
		} లేకపోతే {	/* local to remote */
			ఒకవేళ (బహుళకం == బహుళకం_SFTP) {
				/* no need to glob: already done by shell */
				ఒకవేళ (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				ఒకవేళ (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_ప్రత్యక్ష,
					    &remin, &remout, &do_cmd_pid);
					ఒకవేళ (conn == ఖాళీ) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				ఆధారం_sftp(1, argv[i], targ, conn);
				కొనసాగు;
			}
			/* SCP */
			ఒకవేళ (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				ఒకవేళ (do_cmd(ssh_కార్యక్రమం, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					నిష్క్రమించు(1);
				ఒకవేళ (response() < 0)
					నిష్క్రమించు(1);
				విడుదల(bp);
			}
			ఆధారం(1, argv + i);
		}
	}
బహిర్గతం:
	freeargs(&alist);
	విడుదల(tuser);
	విడుదల(thost);
	విడుదల(targ);
	విడుదల(suser);
	విడుదల(host);
	విడుదల(src);
	sftp_free(conn);
	sftp_free(conn2);
}

శూన్య
tolocal(పూర్ణాంకం argc, అక్షరం **argv, గణన scp_బహుళకం_e బహుళకం, అక్షరం *sftp_ప్రత్యక్ష)
{
	అక్షరం *bp, *host = ఖాళీ, *src = ఖాళీ, *suser = ఖాళీ;
	arglist alist;
	నిర్మాణం sftp_conn *conn = ఖాళీ;
	పూర్ణాంకం i, r, sport = -1;

	memset(&alist, '\0', పరిమాణం(alist));
	alist.list = ఖాళీ;

	కొరకు (i = 0; i < argc - 1; i++) {
		విడుదల(suser);
		విడుదల(host);
		విడుదల(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		ఒకవేళ (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			కొనసాగు;
		}
		ఒకవేళ (r != 0)
			parse_user_host_మార్గం(argv[i], &suser, &host, &src);
		ఒకవేళ (suser != ఖాళీ && !okname(suser)) {
			++errs;
			కొనసాగు;
		}
		ఒకవేళ (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", మార్గం_CP);
			ఒకవేళ (iamrecursive)
				addargs(&alist, "-r");
			ఒకవేళ (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			ఒకవేళ (do_local_cmd(&alist))
				++errs;
			కొనసాగు;
		}
		/* Remote to local. */
		ఒకవేళ (బహుళకం == బహుళకం_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_ప్రత్యక్ష, &remin, &remout, &do_cmd_pid);
			ఒకవేళ (conn == ఖాళీ) {
				error("sftp connection failed");
				++errs;
				కొనసాగు;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(శూన్య) close(remin);
			(శూన్య) close(remout);
			remin = remout = -1;
			కొనసాగు;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		ఒకవేళ (do_cmd(ssh_కార్యక్రమం, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			విడుదల(bp);
			++errs;
			కొనసాగు;
		}
		విడుదల(bp);
		sink(1, argv + argc - 1, src);
		(శూన్య) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	విడుదల(suser);
	విడుదల(host);
	విడుదల(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
స్థిర అక్షరం *
prepare_remote_మార్గం(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం)
{
	కొలత_t nslash;

	/* Handle ~ prefixed paths */
	ఒకవేళ (*మార్గం == '\0' || strcmp(మార్గం, "~") == 0)
		తిరిగి xstrdup(".");
	ఒకవేళ (*మార్గం != '~')
		తిరిగి xstrdup(మార్గం);
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(మార్గం, "~/", 2) == 0) {
		ఒకవేళ ((nslash = strspn(మార్గం + 2, "/")) == అక్షరశ్రేణి_పొడవు(మార్గం + 2))
			తిరిగి xstrdup(".");
		తిరిగి xstrdup(మార్గం + 2 + nslash);
	}
	ఒకవేళ (sftp_can_expand_మార్గం(conn))
		తిరిగి sftp_expand_మార్గం(conn, మార్గం);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	తిరిగి ఖాళీ;
}

శూన్య
ఆధారం_sftp(పూర్ణాంకం argc, అక్షరం *src, అక్షరం *targ, నిర్మాణం sftp_conn *conn)
{
	అక్షరం *లక్ష్యం = ఖాళీ, *filename = ఖాళీ, *abs_dst = ఖాళీ;
	పూర్ణాంకం src_is_dir, లక్ష్యం_is_dir;
	Attrib a;
	నిర్మాణం stat st;

	memset(&a, '\0', పరిమాణం(a));
	ఒకవేళ (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	ఒకవేళ ((filename = basename(src)) == ఖాళీ)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	ఒకవేళ (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	ఒకవేళ ((లక్ష్యం = prepare_remote_మార్గం(conn, targ)) == ఖాళీ)
		cleanup_exit(255);
	లక్ష్యం_is_dir = sftp_remote_is_dir(conn, లక్ష్యం);
	ఒకవేళ (targetshouldbedirectory && !లక్ష్యం_is_dir) {
		debug("target directory \"%s\" does not exist", లక్ష్యం);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		ఒకవేళ (sftp_mkdir(conn, లక్ష్యం, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		లక్ష్యం_is_dir = 1;
	}
	ఒకవేళ (లక్ష్యం_is_dir)
		abs_dst = sftp_మార్గం_append(లక్ష్యం, filename);
	లేకపోతే {
		abs_dst = లక్ష్యం;
		లక్ష్యం = ఖాళీ;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	ఒకవేళ (src_is_dir && iamrecursive) {
		ఒకవేళ (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_పురోగతి_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} లేకపోతే ఒకవేళ (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	విడుదల(abs_dst);
	విడుదల(లక్ష్యం);
}

శూన్య
ఆధారం(పూర్ణాంకం argc, అక్షరం **argv)
{
	నిర్మాణం stat stb;
	స్థిర BUF బఫరు;
	BUF *bp;
	off_t i, statbytes;
	కొలత_t amt, nr;
	పూర్ణాంకం fd = -1, haderr, indx;
	అక్షరం *చివరి, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	పూర్ణాంకం len;

	కొరకు (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = అక్షరశ్రేణి_పొడవు(name);
		అయితే (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		ఒకవేళ ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			వెళ్ళు syserr;
		ఒకవేళ (strchr(name, '\n') != ఖాళీ) {
			strnvis(encname, name, పరిమాణం(encname), VIS_NL);
			name = encname;
		}
		ఒకవేళ (fstat(fd, &stb) == -1) {
syserr:			నిరంతరం_err("%s: %s", name, strerror(errno));
			వెళ్ళు తదుపరి;
		}
		ఒకవేళ (stb.st_size < 0) {
			నిరంతరం_err("%s: %s", name, "Negative file size");
			వెళ్ళు తదుపరి;
		}
		unset_nonblock(fd);
		ఎంపిక (stb.st_mode & S_IFMT) {
		స్థితి S_IFREG:
			ఆపు;
		స్థితి S_IFDIR:
			ఒకవేళ (iamrecursive) {
				rsource(name, &stb);
				వెళ్ళు తదుపరి;
			}
			/* FALLTHROUGH */
		అప్రమేయ:
			నిరంతరం_err("%s: not a regular file", name);
			వెళ్ళు తదుపరి;
		}
		ఒకవేళ ((చివరి = strrchr(name, '/')) == ఖాళీ)
			చివరి = name;
		లేకపోతే
			++చివరి;
		curfile = చివరి;
		ఒకవేళ (pflag) {
			ఒకవేళ (do_times(remout, verbose_బహుళకం, &stb) < 0)
				వెళ్ళు తదుపరి;
		}
#నిర్వచించు	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, పరిమాణం buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (దీర్ఘ దీర్ఘ)stb.st_size, చివరి);
		ఒకవేళ (verbose_బహుళకం)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(శూన్య) atomicio(vwrite, remout, buf, అక్షరశ్రేణి_పొడవు(buf));
		ఒకవేళ (response() < 0)
			వెళ్ళు తదుపరి;
		ఒకవేళ ((bp = allocbuf(&బఫరు, fd, COPY_BUFLEN)) == ఖాళీ) {
తదుపరి:			ఒకవేళ (fd != -1) {
				(శూన్య) close(fd);
				fd = -1;
			}
			కొనసాగు;
		}
		ఒకవేళ (showprogress)
			ప్రారంభం_పురోగతి_meter(curfile, stb.st_size, &statbytes);
		సమితి_nonblock(remout);
		కొరకు (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			ఒకవేళ (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			ఒకవేళ (!haderr) {
				ఒకవేళ ((nr = atomicio(పఠ, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			ఒకవేళ (haderr) {
				(శూన్య)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				కొనసాగు;
			}
			ఒకవేళ (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		ఒకవేళ (fd != -1) {
			ఒకవేళ (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		ఒకవేళ (!haderr)
			(శూన్య) atomicio(vwrite, remout, "", 1);
		లేకపోతే
			నిరంతరం_err("%s: %s", name, strerror(haderr));
		(శూన్య) response();
		ఒకవేళ (showprogress)
			stop_పురోగతి_meter();
	}
}

శూన్య
rsource(అక్షరం *name, నిర్మాణం stat *statp)
{
	DIR *dirp;
	నిర్మాణం dirent *dp;
	అక్షరం *చివరి, *vect[1], మార్గం[PATH_MAX];

	ఒకవేళ (!(dirp = opendir(name))) {
		నిరంతరం_err("%s: %s", name, strerror(errno));
		తిరిగి;
	}
	చివరి = strrchr(name, '/');
	ఒకవేళ (చివరి == ఖాళీ)
		చివరి = name;
	లేకపోతే
		చివరి++;
	ఒకవేళ (pflag) {
		ఒకవేళ (do_times(remout, verbose_బహుళకం, statp) < 0) {
			closedir(dirp);
			తిరిగి;
		}
	}
	(శూన్య) snprintf(మార్గం, పరిమాణం మార్గం, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, చివరి);
	ఒకవేళ (verbose_బహుళకం)
		fmprintf(stderr, "Entering directory: %s", మార్గం);
	(శూన్య) atomicio(vwrite, remout, మార్గం, అక్షరశ్రేణి_పొడవు(మార్గం));
	ఒకవేళ (response() < 0) {
		closedir(dirp);
		తిరిగి;
	}
	అయితే ((dp = readdir(dirp)) != ఖాళీ) {
		ఒకవేళ (dp->d_ino == 0)
			కొనసాగు;
		ఒకవేళ (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			కొనసాగు;
		ఒకవేళ (అక్షరశ్రేణి_పొడవు(name) + 1 + అక్షరశ్రేణి_పొడవు(dp->d_name) >= పరిమాణం(మార్గం) - 1) {
			నిరంతరం_err("%s/%s: name too long", name, dp->d_name);
			కొనసాగు;
		}
		(శూన్య) snprintf(మార్గం, పరిమాణం మార్గం, "%s/%s", name, dp->d_name);
		vect[0] = మార్గం;
		ఆధారం(1, vect);
	}
	(శూన్య) closedir(dirp);
	(శూన్య) atomicio(vwrite, remout, "E\n", 2);
	(శూన్య) response();
}

శూన్య
sink_sftp(పూర్ణాంకం argc, అక్షరం *dst, స్థిరరాశి అక్షరం *src, నిర్మాణం sftp_conn *conn)
{
	అక్షరం *abs_src = ఖాళీ;
	అక్షరం *abs_dst = ఖాళీ;
	glob_t g;
	అక్షరం *filename, *tmp = ఖాళీ;
	పూర్ణాంకం i, r, err = 0, dst_is_dir;
	నిర్మాణం stat st;

	memset(&g, 0, పరిమాణం(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	ఒకవేళ ((abs_src = prepare_remote_మార్గం(conn, src)) == ఖాళీ) {
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	ఒకవేళ ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ఖాళీ, &g)) != 0) {
		ఒకవేళ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		లేకపోతే
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	/* Did we actually get any matches back from the glob? */
	ఒకవేళ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ఖాళీ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ఒకవేళ (sftp_stat(conn, g.gl_pathv[0], 1, ఖాళీ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			వెళ్ళు బహిర్గతం;
		}
	}

	ఒకవేళ ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	ఒకవేళ (g.gl_matchc > 1 && !dst_is_dir) {
		ఒకవేళ (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			వెళ్ళు బహిర్గతం;
		}
		debug2_f("creating destination \"%s\"", dst);
		ఒకవేళ (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			వెళ్ళు బహిర్గతం;
		}
		dst_is_dir = 1;
	}

	కొరకు (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ఒకవేళ ((filename = basename(tmp)) == ఖాళీ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			వెళ్ళు బహిర్గతం;
		}

		/* Special handling for destination of '..' */
		ఒకవేళ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ఒకవేళ (dst_is_dir)
			abs_dst = sftp_మార్గం_append(dst, filename);
		లేకపోతే
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ఒకవేళ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ఒకవేళ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ఖాళీ, pflag, SFTP_పురోగతి_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} లేకపోతే {
			ఒకవేళ (sftp_download(conn, g.gl_pathv[i], abs_dst, ఖాళీ,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		విడుదల(abs_dst);
		abs_dst = ఖాళీ;
		విడుదల(tmp);
		tmp = ఖాళీ;
	}

బహిర్గతం:
	విడుదల(abs_src);
	విడుదల(tmp);
	globfree(&g);
	ఒకవేళ (err == -1)
		errs = 1;
}


#నిర్వచించు TYPE_అధికప్రవాహం(type, val) \
	((పరిమాణం(type) == 4 && (val) > INT32_MAX) || \
	 (పరిమాణం(type) == 8 && (val) > INT64_MAX) || \
	 (పరిమాణం(type) != 4 && పరిమాణం(type) != 8))

శూన్య
sink(పూర్ణాంకం argc, అక్షరం **argv, స్థిరరాశి అక్షరం *src)
{
	స్థిర BUF బఫరు;
	నిర్మాణం stat stb;
	BUF *bp;
	off_t i;
	కొలత_t j, లెక్క;
	పూర్ణాంకం amt, exists, మొదటి, ofd;
	బహుళకం_t బహుళకం, omode, ముసుగు;
	off_t కొలత, statbytes;
	గుర్తులేని దీర్ఘ దీర్ఘ ull;
	పూర్ణాంకం setimes, targisdir, wrerr;
	అక్షరం ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	అక్షరం **patterns = ఖాళీ;
	కొలత_t n, npatterns = 0;
	నిర్మాణం timeval tv[2];

#నిర్వచించు	atime	tv[0]
#నిర్వచించు	mtime	tv[1]
#నిర్వచించు	SCREWUP(str)	{ why = str; వెళ్ళు screwup; }

	ఒకవేళ (TYPE_అధికప్రవాహం(time_t, 0) || TYPE_అధికప్రవాహం(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	ముసుగు = umask(0);
	ఒకవేళ (!pflag) {
		(శూన్య) umask(ముసుగు);
		ముసుగు |= 07000;
	}
	ఒకవేళ (argc != 1) {
		నిరంతరం_err("ambiguous target");
		నిష్క్రమించు(1);
	}
	targ = *argv;
	ఒకవేళ (targetshouldbedirectory)
		verifydir(targ);

	(శూన్య) atomicio(vwrite, remout, "", 1);
	ఒకవేళ (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	ఒకవేళ (src != ఖాళీ && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		ఒకవేళ (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	కొరకు (మొదటి = 1;; మొదటి = 0) {
		cp = buf;
		ఒకవేళ (atomicio(పఠ, remin, cp, 1) != 1)
			వెళ్ళు పూర్తి;
		ఒకవేళ (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		చేయి {
			ఒకవేళ (atomicio(పఠ, remin, &ch, పరిమాణం(ch)) != పరిమాణం(ch))
				SCREWUP("lost connection");
			ఒకవేళ (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} అయితే (cp < &buf[పరిమాణం(buf) - 1] && ch != '\n');
		*cp = 0;
		ఒకవేళ (verbose_బహుళకం)
			fmprintf(stderr, "Sink: %s", buf);

		ఒకవేళ (buf[0] == '\01' || buf[0] == '\02') {
			ఒకవేళ (iamremote == 0) {
				(శూన్య) snmprintf(visbuf, పరిమాణం(visbuf),
				    ఖాళీ, "%s", buf + 1);
				(శూన్య) atomicio(vwrite, STDERR_FILENO,
				    visbuf, అక్షరశ్రేణి_పొడవు(visbuf));
			}
			ఒకవేళ (buf[0] == '\02')
				నిష్క్రమించు(1);
			++errs;
			కొనసాగు;
		}
		ఒకవేళ (buf[0] == 'E') {
			(శూన్య) atomicio(vwrite, remout, "", 1);
			వెళ్ళు పూర్తి;
		}
		ఒకవేళ (ch == '\n')
			*--cp = 0;

		cp = buf;
		ఒకవేళ (*cp == 'T') {
			setimes++;
			cp++;
			ఒకవేళ (!అంకెనా((గుర్తులేని అక్షరం)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ఒకవేళ (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			ఒకవేళ (TYPE_అధికప్రవాహం(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			ఒకవేళ (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			ఒకవేళ (!అంకెనా((గుర్తులేని అక్షరం)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			ఒకవేళ (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			ఒకవేళ (TYPE_అధికప్రవాహం(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			ఒకవేళ (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(శూన్య) atomicio(vwrite, remout, "", 1);
			కొనసాగు;
		}
		ఒకవేళ (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			ఒకవేళ (మొదటి) {
				నిరంతరం_err("%s", cp);
				నిష్క్రమించు(1);
			}
			SCREWUP("expected control record");
		}
		బహుళకం = 0;
		కొరకు (++cp; cp < buf + 5; cp++) {
			ఒకవేళ (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			బహుళకం = (బహుళకం << 3) | (*cp - '0');
		}
		ఒకవేళ (!pflag)
			బహుళకం &= ~ముసుగు;
		ఒకవేళ (*cp++ != ' ')
			SCREWUP("mode not delimited");

		ఒకవేళ (!అంకెనా((గుర్తులేని అక్షరం)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		ఒకవేళ (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		ఒకవేళ (TYPE_అధికప్రవాహం(off_t, ull))
			SCREWUP("size out of range");
		కొలత = (off_t)ull;

		ఒకవేళ (*cp == '\0' || strchr(cp, '/') != ఖాళీ ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			నిరంతరం_err("error: unexpected filename: %s", cp);
			నిష్క్రమించు(1);
		}
		ఒకవేళ (npatterns > 0) {
			కొరకు (n = 0; n < npatterns; n++) {
				ఒకవేళ (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					ఆపు;
			}
			ఒకవేళ (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				కొరకు (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		ఒకవేళ (targisdir) {
			స్థిర అక్షరం *namebuf;
			స్థిర కొలత_t cursize;
			కొలత_t need;

			need = అక్షరశ్రేణి_పొడవు(targ) + అక్షరశ్రేణి_పొడవు(cp) + 250;
			ఒకవేళ (need > cursize) {
				విడుదల(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(శూన్య) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} లేకపోతే
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		ఒకవేళ (buf[0] == 'D') {
			పూర్ణాంకం mod_flag = pflag;
			ఒకవేళ (!iamrecursive)
				SCREWUP("received directory without -r");
			ఒకవేళ (exists) {
				ఒకవేళ (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					వెళ్ళు bad;
				}
				ఒకవేళ (pflag)
					(శూన్య) chmod(np, బహుళకం);
			} లేకపోతే {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				ఒకవేళ (mkdir(np, బహుళకం | S_IRWXU) == -1)
					వెళ్ళు bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			ఒకవేళ (setimes) {
				setimes = 0;
				(శూన్య) utimes(vect[0], tv);
			}
			ఒకవేళ (mod_flag)
				(శూన్య) chmod(vect[0], బహుళకం);
			విడుదల(vect[0]);
			కొనసాగు;
		}
		omode = బహుళకం;
		బహుళకం |= S_IWUSR;
		ఒకవేళ ((ofd = open(np, O_WRONLY|O_CREAT, బహుళకం)) == -1) {
bad:			నిరంతరం_err("%s: %s", np, strerror(errno));
			కొనసాగు;
		}
		(శూన్య) atomicio(vwrite, remout, "", 1);
		ఒకవేళ ((bp = allocbuf(&బఫరు, ofd, COPY_BUFLEN)) == ఖాళీ) {
			(శూన్య) close(ofd);
			కొనసాగు;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		ఒకవేళ (showprogress)
			ప్రారంభం_పురోగతి_meter(curfile, కొలత, &statbytes);
		సమితి_nonblock(remin);
		కొరకు (లెక్క = i = 0; i < కొలత; i += bp->cnt) {
			amt = bp->cnt;
			ఒకవేళ (i + amt > కొలత)
				amt = కొలత - i;
			లెక్క += amt;
			చేయి {
				j = atomicio6(పఠ, remin, cp, amt,
				    scpio, &statbytes);
				ఒకవేళ (j == 0) {
					నిరంతరం_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					నిష్క్రమించు(1);
				}
				amt -= j;
				cp += j;
			} అయితే (amt > 0);

			ఒకవేళ (లెక్క == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				ఒకవేళ (!wrerr) {
					ఒకవేళ (atomicio(vwrite, ofd, bp->buf,
					    లెక్క) != లెక్క) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				లెక్క = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		ఒకవేళ (లెక్క != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, లెక్క) != లెక్క) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		ఒకవేళ (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, కొలత) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		ఒకవేళ (pflag) {
			ఒకవేళ (exists || omode != బహుళకం)
#నిర్వచితమైతే HAVE_FCHMOD
				ఒకవేళ (fchmod(ofd, omode)) {
#లేకపోతే /* HAVE_FCHMOD */
				ఒకవేళ (chmod(np, omode)) {
#అయితే_ముగింపు /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} లేకపోతే {
			ఒకవేళ (!exists && omode != బహుళకం)
#నిర్వచితమైతే HAVE_FCHMOD
				ఒకవేళ (fchmod(ofd, omode & ~ముసుగు)) {
#లేకపోతే /* HAVE_FCHMOD */
				ఒకవేళ (chmod(np, omode & ~ముసుగు)) {
#అయితే_ముగింపు /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		ఒకవేళ (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(శూన్య) response();
		ఒకవేళ (showprogress)
			stop_పురోగతి_meter();
		ఒకవేళ (setimes && !wrerr) {
			setimes = 0;
			ఒకవేళ (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		ఒకవేళ (note_err(ఖాళీ) == 0)
			(శూన్య) atomicio(vwrite, remout, "", 1);
	}
పూర్తి:
	కొరకు (n = 0; n < npatterns; n++)
		విడుదల(patterns[n]);
	విడుదల(patterns);
	తిరిగి;
screwup:
	కొరకు (n = 0; n < npatterns; n++)
		విడుదల(patterns[n]);
	విడుదల(patterns);
	నిరంతరం_err("protocol error: %s", why);
	నిష్క్రమించు(1);
}

శూన్య
throughlocal_sftp(నిర్మాణం sftp_conn *from, నిర్మాణం sftp_conn *గమ్యం,
    అక్షరం *src, అక్షరం *targ)
{
	అక్షరం *లక్ష్యం = ఖాళీ, *filename = ఖాళీ, *abs_dst = ఖాళీ;
	అక్షరం *abs_src = ఖాళీ, *tmp = ఖాళీ;
	glob_t g;
	పూర్ణాంకం i, r, targetisdir, err = 0;

	ఒకవేళ ((filename = basename(src)) == ఖాళీ)
		fatal("basename %s: %s", src, strerror(errno));

	ఒకవేళ ((abs_src = prepare_remote_మార్గం(from, src)) == ఖాళీ ||
	    (లక్ష్యం = prepare_remote_మార్గం(గమ్యం, targ)) == ఖాళీ)
		cleanup_exit(255);
	memset(&g, 0, పరిమాణం(g));

	targetisdir = sftp_remote_is_dir(గమ్యం, లక్ష్యం);
	ఒకవేళ (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	debug3_f("copying remote %s to remote %s", abs_src, లక్ష్యం);
	ఒకవేళ ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    ఖాళీ, &g)) != 0) {
		ఒకవేళ (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		లేకపోతే
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	/* Did we actually get any matches back from the glob? */
	ఒకవేళ (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != ఖాళీ) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		ఒకవేళ (sftp_stat(from, g.gl_pathv[0], 1, ఖాళీ) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			వెళ్ళు బహిర్గతం;
		}
	}

	కొరకు (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ఒకవేళ ((filename = basename(tmp)) == ఖాళీ) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			వెళ్ళు బహిర్గతం;
		}

		/* Special handling for source of '..' */
		ఒకవేళ (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		ఒకవేళ (targetisdir)
			abs_dst = sftp_మార్గం_append(లక్ష్యం, filename);
		లేకపోతే
			abs_dst = xstrdup(లక్ష్యం);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		ఒకవేళ (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			ఒకవేళ (sftp_crossload_dir(from, గమ్యం, g.gl_pathv[i], abs_dst,
			    ఖాళీ, pflag, SFTP_పురోగతి_ONLY, 1) == -1)
				err = -1;
		} లేకపోతే {
			ఒకవేళ (sftp_crossload(from, గమ్యం, g.gl_pathv[i], abs_dst,
			    ఖాళీ, pflag) == -1)
				err = -1;
		}
		విడుదల(abs_dst);
		abs_dst = ఖాళీ;
		విడుదల(tmp);
		tmp = ఖాళీ;
	}

బహిర్గతం:
	విడుదల(abs_src);
	విడుదల(abs_dst);
	విడుదల(లక్ష్యం);
	విడుదల(tmp);
	globfree(&g);
	ఒకవేళ (err == -1)
		errs = 1;
}

పూర్ణాంకం
response(శూన్య)
{
	అక్షరం ch, *cp, resp, rbuf[2048], visbuf[2048];

	ఒకవేళ (atomicio(పఠ, remin, &resp, పరిమాణం(resp)) != పరిమాణం(resp))
		lostconn(0);

	cp = rbuf;
	ఎంపిక (resp) {
	స్థితి 0:		/* ok */
		తిరిగి (0);
	అప్రమేయ:
		*cp++ = resp;
		/* FALLTHROUGH */
	స్థితి 1:		/* error, followed by error msg */
	స్థితి 2:		/* fatal error, "" */
		చేయి {
			ఒకవేళ (atomicio(పఠ, remin, &ch, పరిమాణం(ch)) != పరిమాణం(ch))
				lostconn(0);
			*cp++ = ch;
		} అయితే (cp < &rbuf[పరిమాణం(rbuf) - 1] && ch != '\n');

		ఒకవేళ (!iamremote) {
			cp[-1] = '\0';
			(శూన్య) snmprintf(visbuf, పరిమాణం(visbuf),
			    ఖాళీ, "%s\n", rbuf);
			(శూన్య) atomicio(vwrite, STDERR_FILENO,
			    visbuf, అక్షరశ్రేణి_పొడవు(visbuf));
		}
		++errs;
		ఒకవేళ (resp == 1)
			తిరిగి (-1);
		నిష్క్రమించు(1);
	}
	/* NOTREACHED */
}

శూన్య
usage(శూన్య)
{
	(శూన్య) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	నిష్క్రమించు(1);
}

శూన్య
నిరంతరం_err(స్థిరరాశి అక్షరం *fmt,...)
{
	స్థిర FILE *fp;
	va_list ap;

	++errs;
	ఒకవేళ (fp != ఖాళీ || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(శూన్య) fprintf(fp, "%c", 0x01);
		(శూన్య) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(శూన్య) vfprintf(fp, fmt, ap);
		va_end(ap);
		(శూన్య) fprintf(fp, "\n");
		(శూన్య) fflush(fp);
	}

	ఒకవేళ (!iamremote) {
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
పూర్ణాంకం
note_err(స్థిరరాశి అక్షరం *fmt, ...)
{
	స్థిర అక్షరం *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	ఒకవేళ (fmt == ఖాళీ) {
		ఒకవేళ (emsg == ఖాళీ)
			తిరిగి 0;
		నిరంతరం_err("%s", emsg);
		విడుదల(emsg);
		emsg = ఖాళీ;
		తిరిగి -1;
	}

	errs++;
	/* Prefer first-noted error */
	ఒకవేళ (emsg != ఖాళీ)
		తిరిగి -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, గరిష్ఠ_పూర్ణాంకం, ఖాళీ, fmt, ap);
	va_end(ap);
	తిరిగి -1;
}

శూన్య
verifydir(అక్షరం *cp)
{
	నిర్మాణం stat stb;

	ఒకవేళ (!stat(cp, &stb)) {
		ఒకవేళ (S_ISDIR(stb.st_mode))
			తిరిగి;
		errno = ENOTDIR;
	}
	నిరంతరం_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

పూర్ణాంకం
okname(అక్షరం *cp0)
{
	పూర్ణాంకం c;
	అక్షరం *cp;

	cp = cp0;
	చేయి {
		c = (పూర్ణాంకం)*cp;
		ఒకవేళ (c & 0200)
			వెళ్ళు bad;
		ఒకవేళ (!అక్షరమా(c) && !అంకెనా((గుర్తులేని అక్షరం)c)) {
			ఎంపిక (c) {
			స్థితి '\'':
			స్థితి '"':
			స్థితి '`':
			స్థితి ' ':
			స్థితి '#':
				వెళ్ళు bad;
			అప్రమేయ:
				ఆపు;
			}
		}
	} అయితే (*++cp);
	తిరిగి (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	తిరిగి (0);
}

BUF *
allocbuf(BUF *bp, పూర్ణాంకం fd, పూర్ణాంకం blksize)
{
	కొలత_t కొలత;
#నిర్వచితమైతే HAVE_STRUCT_STAT_ST_BLKSIZE
	నిర్మాణం stat stb;

	ఒకవేళ (fstat(fd, &stb) == -1) {
		నిరంతరం_err("fstat: %s", strerror(errno));
		తిరిగి (ఖాళీ);
	}
	కొలత = ROUNDUP(stb.st_blksize, blksize);
	ఒకవేళ (కొలత == 0)
		కొలత = blksize;
#లేకపోతే /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	కొలత = blksize;
#అయితే_ముగింపు /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	ఒకవేళ (bp->cnt >= కొలత)
		తిరిగి (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, కొలత, 1);
	bp->cnt = కొలత;
	తిరిగి (bp);
}

శూన్య
lostconn(పూర్ణాంకం signo)
{
	ఒకవేళ (!iamremote)
		(శూన్య)లిఖ(STDERR_FILENO, "lost connection\n", 16);
	ఒకవేళ (signo)
		_exit(1);
	లేకపోతే
		నిష్క్రమించు(1);
}

శూన్య
cleanup_exit(పూర్ణాంకం i)
{
	ఒకవేళ (remin > 0)
		close(remin);
	ఒకవేళ (remout > 0)
		close(remout);
	ఒకవేళ (remin2 > 0)
		close(remin2);
	ఒకవేళ (remout2 > 0)
		close(remout2);
	ఒకవేళ (do_cmd_pid > 0)
		(శూన్య)waitpid(do_cmd_pid, ఖాళీ, 0);
	ఒకవేళ (do_cmd_pid2 > 0)
		(శూన్య)waitpid(do_cmd_pid2, ఖాళీ, 0);
	నిష్క్రమించు(i);
}
