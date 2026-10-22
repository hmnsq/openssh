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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif
#include <glob.h>
#include <libgen.h>
#include <locale.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <util.h>
#якщо defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#include <vis.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "atomicio.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "progressmeter.h"
#include "utf8.h"
#include "sftp.h"

#include "sftp-common.h"
#include "sftp-client.h"

extern char *__progname;

#define COPY_BUFLEN	16384

ціле do_cmd(char *, char *, char *, ціле, ціле, char *, ціле *, ціле *, pid_t *);
ціле do_cmd2(char *, char *, ціле, char *, ціле, ціле);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
struct bwlimit bwlimit;

/* Name of current file being transferred. */
char *curfile;

/* This is set to non-zero to enable verbose mode. */
ціле verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
ціле showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
ціле throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
ціле sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
char *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;

/* Needed for sftp */
volatile sig_atomic_t interrupted = 0;

ціле sftp_glob(struct sftp_conn *, const char *, ціле,
    ціле (*)(const char *, ціле), glob_t *); /* proto for sftp-glob.c */

static void
killchild(ціле signo)
{
	якщо (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid, NULL, 0);
	}
	якщо (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid2, NULL, 0);
	}

	якщо (signo)
		_exit(1);
	exit(1);
}

static void
suspone(ціле pid, ціле signo)
{
	ціле status;

	якщо (pid > 1) {
		kill(pid, signo);
		поки (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

static void
suspchild(ціле signo)
{
	ціле save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static ціле
do_local_cmd(arglist *a)
{
	char *cp;
	ціле status;
	pid_t pid;

	якщо (a->num == 0)
		fatal("do_local_cmd: no arguments");

	якщо (verbose_mode) {
		cp = argv_assemble(a->num, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		free(cp);
	}
	якщо ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	якщо (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	поки (waitpid(pid, &status, 0) == -1)
		якщо (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	якщо (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		повернути (-1);

	повернути (0);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

ціле
do_cmd(char *program, char *host, char *remuser, ціле port, ціле subsystem,
    char *cmd, ціле *fdin, ціле *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	ціле pin[2], pout[2];
#інакше
	ціле sv[2];
#endif

	якщо (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	якщо (port == -1)
		port = sshport;

#ifdef USE_PIPES
	якщо (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#інакше
	/* Create a socket pair for communicating with ssh. */
	якщо (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	switch (*pid) {
	case -1:
		fatal("fork: %s", strerror(errno));
	case 0:
		/* Child. */
#ifdef USE_PIPES
		якщо (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#інакше
		якщо (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		якщо (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		якщо (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		якщо (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	default:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#інакше
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		повернути 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
ціле
do_cmd2(char *host, char *remuser, ціле port, char *cmd,
    ціле fdin, ціле fdout)
{
	ціле status;
	pid_t pid;

	якщо (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	якщо (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	якщо (pid == 0) {
		якщо (dup2(fdin, 0) == -1)
			perror("dup2");
		якщо (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		якщо (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		якщо (remuser != NULL) {
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
	} інакше якщо (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	поки (waitpid(pid, &status, 0) == -1)
		якщо (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	повернути 0;
}

typedef struct {
	size_t cnt;
	char *buf;
} BUF;

BUF *allocbuf(BUF *, ціле, ціле);
void lostconn(ціле);
ціле okname(char *);
void run_err(const char *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
ціле note_err(const char *,...)
    __attribute__((__format__ (printf, 1, 2)));
void verifydir(char *);

struct passwd *pwd;
uid_t userid;
ціле errs, remin, remout, remin2, remout2;
ціле Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
char cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

enum scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

ціле response(void);
void rsource(char *, struct stat *);
void sink(ціле, char *[], const char *);
void source(ціле, char *[]);
void tolocal(ціле, char *[], enum scp_mode_e, char *sftp_direct);
void toremote(ціле, char *[], enum scp_mode_e, char *sftp_direct);
void usage(void);

void source_sftp(ціле, char *, char *, struct sftp_conn *);
void sink_sftp(ціле, char *, const char *, struct sftp_conn *);
void throughlocal_sftp(struct sftp_conn *, struct sftp_conn *,
    char *, char *);

ціле
main(ціле argc, char **argv)
{
	ціле ch, fflag, tflag, status, r, n;
	char **newargv, *argv0;
	const char *errstr;
	extern char *optarg;
	extern ціле optind;
	enum scp_mode_e mode = MODE_SFTP;
	char *sftp_direct = NULL;
	long long llv;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), sizeof(*newargv));
	для (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', sizeof(args));
	memset(&remote_remote_args, '\0', sizeof(remote_remote_args));
	args.list = remote_remote_args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	поки ((ch = getopt(argc, argv,
	    "12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:")) != -1) {
		switch (ch) {
		/* User-visible flags. */
		case '1':
			fatal("SSH protocol v.1 is no longer supported");
			break;
		case '2':
			/* Ignored */
			break;
		case 'A':
		case '4':
		case '6':
		case 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			break;
		case 'D':
			sftp_direct = optarg;
			break;
		case '3':
			throughlocal = 1;
			break;
		case 'R':
			fprintf(stderr, "warning: remote/remote -R copy mode "
			    "is deprecated and will soon be removed\n");
			throughlocal = 0;
			break;
		case 'o':
		case 'c':
		case 'i':
		case 'F':
		case 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			break;
		case 'O':
			mode = MODE_SCP;
			break;
		case 's':
			/* Ignored */
			break;
		case 'P':
			sshport = a2port(optarg);
			якщо (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			break;
		case 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			break;
		case 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			якщо (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			iamrecursive = 1;
			break;
		case 'S':
			ssh_program = xstrdup(optarg);
			break;
		case 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			якщо (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			інакше якщо (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			break;
		case 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			break;
		case 'X':
			/* Please keep in sync with sftp.c -X */
			якщо (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				якщо (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				якщо (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				sftp_copy_buflen = (size_t)llv;
			} інакше якщо (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				якщо (errstr != NULL) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
			} інакше {
				fatal("Invalid -X option");
			}
			break;

		/* Server options. */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_BINARY);
#endif
			break;
		case 'T':
			Tflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	якщо (iamremote)
		mode = MODE_SCP;

	якщо ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);

	якщо (!isatty(STDOUT_FILENO))
		showprogress = 0;

	якщо (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} інакше {
		якщо (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	якщо (fflag) {
		/* Follow "protocol", send data. */
		(void) response();
		source(argc, argv);
		exit(errs != 0);
	}
	якщо (tflag) {
		/* Receive data. */
		sink(argc, argv, NULL);
		exit(errs != 0);
	}
	якщо (argc < 2)
		usage();
	якщо (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	(void) snprintf(cmd, sizeof cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

	(void) ssh_signal(SIGPIPE, lostconn);

	якщо (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	інакше {
		якщо (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}
	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	якщо (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		якщо (remin != -1)
		    (void) close(remin);
		якщо (remout != -1)
		    (void) close(remout);
		якщо (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		інакше {
			якщо (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
static ціле
scpio(void *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	якщо (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	повернути 0;
}

static ціле
do_times(ціле fd, ціле verb, const struct stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	char buf[(20 + 7 + 2) * 2 + 2];

	(void)snprintf(buf, sizeof(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	якщо (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(void) atomicio(vwrite, fd, buf, strlen(buf));
	повернути (response());
}

static ціле
parse_scp_uri(const char *uri, char **userp, char **hostp, ціле *portp,
    char **pathp)
{
	ціле r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	якщо (r == 0 && *pathp == NULL)
		*pathp = xstrdup(".");
	повернути r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
static ціле
append(char *cp, char ***ap, size_t *np)
{
	char **tmp;

	якщо ((tmp = reallocarray(*ap, *np + 1, sizeof(*tmp))) == NULL)
		повернути -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	повернути 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
static ціле
find_brace(const char *pattern, ціле *startp, ціле *endp)
{
	ціле i;
	ціле in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	для (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		switch (pattern[i]) {
		case '\\':
			/* skip next character */
			якщо (pattern[i + 1] != '\0')
				i++;
			break;
		case '[':
			in_bracket = 1;
			break;
		case ']':
			in_bracket = 0;
			break;
		case '{':
			якщо (in_bracket)
				break;
			якщо (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				break;
			}
			якщо (*startp == -1)
				*startp = i;
			brace_level++;
			break;
		case '}':
			якщо (in_bracket)
				break;
			якщо (*startp < 0) {
				/* Unbalanced brace */
				повернути -1;
			}
			якщо (--brace_level <= 0)
				*endp = i;
			break;
		}
	}
	/* unbalanced brackets/braces */
	якщо (*endp < 0 && (*startp >= 0 || in_bracket))
		повернути -1;
	повернути 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
static ціле
emit_expansion(const char *pattern, ціле brace_start, ціле brace_end,
    ціле sel_start, ціле sel_end, char ***patternsp, size_t *npatternsp)
{
	char *cp;
	size_t pattern_len;
	ціле o = 0, tail_len;

	якщо ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		повернути -1;

	tail_len = strlen(pattern + brace_end + 1);
	якщо ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == NULL)
		повернути -1;

	/* Pattern before initial brace */
	якщо (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	якщо (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	якщо (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	якщо (append(cp, patternsp, npatternsp) != 0) {
		free(cp);
		повернути -1;
	}
	повернути 0;
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
static ціле
brace_expand_one(const char *pattern, char ***patternsp, size_t *npatternsp,
    ціле *expanded, ціле *invalid)
{
	ціле i;
	ціле in_bracket, brace_start, brace_end, brace_level;
	ціле sel_start, sel_end;

	*invalid = *expanded = 0;

	якщо (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		повернути 0;
	} інакше якщо (brace_start == -1)
		повернути 0;

	in_bracket = brace_level = 0;
	для (i = sel_start = brace_start + 1; i < brace_end; i++) {
		switch (pattern[i]) {
		case '{':
			якщо (in_bracket)
				break;
			brace_level++;
			break;
		case '}':
			якщо (in_bracket)
				break;
			brace_level--;
			break;
		case '[':
			in_bracket = 1;
			break;
		case ']':
			in_bracket = 0;
			break;
		case '\\':
			якщо (i < brace_end - 1)
				i++; /* skip */
			break;
		}
		якщо (pattern[i] == ',' || i == brace_end - 1) {
			якщо (in_bracket || brace_level > 0)
				continue;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			якщо (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				повернути -1;
			/* move on to the next selection */
			sel_start = i + 1;
			continue;
		}
	}
	якщо (in_bracket || brace_level > 0) {
		*invalid = 1;
		повернути 0;
	}
	/* success */
	*expanded = 1;
	повернути 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
static ціле
brace_expand(const char *pattern, char ***patternsp, size_t *npatternsp)
{
	char *cp, *cp2, **active = NULL, **done = NULL;
	size_t i, nactive = 0, ndone = 0;
	ціле ret = -1, invalid = 0, expanded = 0;

	*patternsp = NULL;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	якщо ((cp = strdup(pattern)) == NULL)
		повернути -1;
	якщо (append(cp, &active, &nactive) != 0) {
		free(cp);
		повернути -1;
	}
	поки (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		якщо (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			free(cp);
			goto fail;
		}
		якщо (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		якщо (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			free(cp);
			continue;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		якщо ((cp2 = strrchr(cp, '/')) != NULL)
			*cp2++ = '\0';
		інакше
			cp2 = cp;
		якщо (append(xstrdup(cp2), &done, &ndone) != 0) {
			free(cp);
			goto fail;
		}
		free(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = NULL;
	ndone = 0;
	ret = 0;
 fail:
	для (i = 0; i < nactive; i++)
		free(active[i]);
	free(active);
	для (i = 0; i < ndone; i++)
		free(done[i]);
	free(done);
	повернути ret;
}

static struct sftp_conn *
do_sftp_connect(char *host, char *user, ціле port, char *sftp_direct,
   ціле *reminp, ціле *remoutp, ціле *pidp)
{
	якщо (sftp_direct == NULL) {
		якщо (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			повернути NULL;

	} інакше {
		freeargs(&args);
		addargs(&args, "sftp-server");
		якщо (do_cmd(sftp_direct, host, NULL, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			повернути NULL;
	}
	повернути sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

void
toremote(ціле argc, char **argv, enum scp_mode_e mode, char *sftp_direct)
{
	char *suser = NULL, *host = NULL, *src = NULL;
	char *bp, *tuser, *thost, *targ;
	ціле sport = -1, tport = -1;
	struct sftp_conn *conn = NULL, *conn2 = NULL;
	arglist alist;
	ціле i, r, status;
	struct stat sb;
	u_int j;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	якщо (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		goto out;
	}
	якщо (r != 0) {
		якщо (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			goto out;
		}
	}

	/* Parse source files */
	для (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		якщо (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		якщо (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		якщо (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		якщо (host && throughlocal) {	/* extended remote to remote */
			якщо (mode == MODE_SFTP) {
				якщо (remin == -1 || conn == NULL) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					якщо (conn == NULL) {
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
				якщо (conn2 == NULL) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(void) close(remin2);
				(void) close(remout2);
				remin2 = remout2 = -1;
				якщо (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				інакше якщо (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				continue;
			} інакше {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				якщо (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				free(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				якщо (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				free(bp);
				(void) close(remin);
				(void) close(remout);
				remin = remout = -1;
			}
		} інакше якщо (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			якщо (tuser != NULL && !okname(tuser)) {
				++errs;
				continue;
			}
			якщо (tport != -1 && tport != SSH_DEFAULT_PORT) {
				/* This would require the remote support URIs */
				fatal("target port not supported with two "
				    "remote hosts and the -R option");
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			для (j = 0; j < remote_remote_args.num; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			якщо (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			якщо (suser) {
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
			якщо (do_local_cmd(&alist) != 0)
				errs = 1;
		} інакше {	/* local to remote */
			якщо (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				якщо (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				якщо (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					якщо (conn == NULL) {
						fatal("Unable to open sftp "
						    "connection");
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				continue;
			}
			/* SCP */
			якщо (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				якщо (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				якщо (response() < 0)
					exit(1);
				free(bp);
			}
			source(1, argv + i);
		}
	}
out:
	freeargs(&alist);
	free(tuser);
	free(thost);
	free(targ);
	free(suser);
	free(host);
	free(src);
	sftp_free(conn);
	sftp_free(conn2);
}

void
tolocal(ціле argc, char **argv, enum scp_mode_e mode, char *sftp_direct)
{
	char *bp, *host = NULL, *src = NULL, *suser = NULL;
	arglist alist;
	struct sftp_conn *conn = NULL;
	ціле i, r, sport = -1;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	для (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		якщо (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		якщо (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		якщо (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		якщо (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			якщо (iamrecursive)
				addargs(&alist, "-r");
			якщо (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			якщо (do_local_cmd(&alist))
				++errs;
			continue;
		}
		/* Remote to local. */
		якщо (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			якщо (conn == NULL) {
				error("sftp connection failed");
				++errs;
				continue;
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			(void) close(remin);
			(void) close(remout);
			remin = remout = -1;
			continue;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		якщо (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			free(bp);
			++errs;
			continue;
		}
		free(bp);
		sink(1, argv + argc - 1, src);
		(void) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	free(suser);
	free(host);
	free(src);
	sftp_free(conn);
}

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
static char *
prepare_remote_path(struct sftp_conn *conn, const char *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	якщо (*path == '\0' || strcmp(path, "~") == 0)
		повернути xstrdup(".");
	якщо (*path != '~')
		повернути xstrdup(path);
	якщо (strncmp(path, "~/", 2) == 0) {
		якщо ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			повернути xstrdup(".");
		повернути xstrdup(path + 2 + nslash);
	}
	якщо (sftp_can_expand_path(conn))
		повернути sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	повернути NULL;
}

void
source_sftp(ціле argc, char *src, char *targ, struct sftp_conn *conn)
{
	char *target = NULL, *filename = NULL, *abs_dst = NULL;
	ціле src_is_dir, target_is_dir;
	Attrib a;
	struct stat st;

	memset(&a, '\0', sizeof(a));
	якщо (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	якщо ((filename = basename(src)) == NULL)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	якщо (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	якщо ((target = prepare_remote_path(conn, targ)) == NULL)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	якщо (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		якщо (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	якщо (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	інакше {
		abs_dst = target;
		target = NULL;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	якщо (src_is_dir && iamrecursive) {
		якщо (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} інакше якщо (sftp_upload(conn, src, abs_dst, pflag, 0, 0, 1) != 0) {
		error("failed to upload file %s to %s", src, targ);
		errs = 1;
	}

	free(abs_dst);
	free(target);
}

void
source(ціле argc, char **argv)
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i, statbytes;
	size_t amt, nr;
	ціле fd = -1, haderr, indx;
	char *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	ціле len;

	для (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
		statbytes = 0;
		len = strlen(name);
		поки (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		якщо ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			goto syserr;
		якщо (strchr(name, '\n') != NULL) {
			strnvis(encname, name, sizeof(encname), VIS_NL);
			name = encname;
		}
		якщо (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			goto next;
		}
		якщо (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			goto next;
		}
		unset_nonblock(fd);
		switch (stb.st_mode & S_IFMT) {
		case S_IFREG:
			break;
		case S_IFDIR:
			якщо (iamrecursive) {
				rsource(name, &stb);
				goto next;
			}
			/* FALLTHROUGH */
		default:
			run_err("%s: not a regular file", name);
			goto next;
		}
		якщо ((last = strrchr(name, '/')) == NULL)
			last = name;
		інакше
			++last;
		curfile = last;
		якщо (pflag) {
			якщо (do_times(remout, verbose_mode, &stb) < 0)
				goto next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, sizeof buf, "C%04o %lld %s\n",
		    (u_int) (stb.st_mode & FILEMODEMASK),
		    (long long)stb.st_size, last);
		якщо (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(void) atomicio(vwrite, remout, buf, strlen(buf));
		якщо (response() < 0)
			goto next;
		якщо ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == NULL) {
next:			якщо (fd != -1) {
				(void) close(fd);
				fd = -1;
			}
			continue;
		}
		якщо (showprogress)
			start_progress_meter(curfile, stb.st_size, &statbytes);
		set_nonblock(remout);
		для (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			якщо (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			якщо (!haderr) {
				якщо ((nr = atomicio(read, fd,
				    bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			якщо (haderr) {
				(void)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				continue;
			}
			якщо (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		якщо (fd != -1) {
			якщо (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		якщо (!haderr)
			(void) atomicio(vwrite, remout, "", 1);
		інакше
			run_err("%s: %s", name, strerror(haderr));
		(void) response();
		якщо (showprogress)
			stop_progress_meter();
	}
}

void
rsource(char *name, struct stat *statp)
{
	DIR *dirp;
	struct dirent *dp;
	char *last, *vect[1], path[PATH_MAX];

	якщо (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		повернути;
	}
	last = strrchr(name, '/');
	якщо (last == NULL)
		last = name;
	інакше
		last++;
	якщо (pflag) {
		якщо (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			повернути;
		}
	}
	(void) snprintf(path, sizeof path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	якщо (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(void) atomicio(vwrite, remout, path, strlen(path));
	якщо (response() < 0) {
		closedir(dirp);
		повернути;
	}
	поки ((dp = readdir(dirp)) != NULL) {
		якщо (dp->d_ino == 0)
			continue;
		якщо (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		якщо (strlen(name) + 1 + strlen(dp->d_name) >= sizeof(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			continue;
		}
		(void) snprintf(path, sizeof path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(void) closedir(dirp);
	(void) atomicio(vwrite, remout, "E\n", 2);
	(void) response();
}

void
sink_sftp(ціле argc, char *dst, const char *src, struct sftp_conn *conn)
{
	char *abs_src = NULL;
	char *abs_dst = NULL;
	glob_t g;
	char *filename, *tmp = NULL;
	ціле i, r, err = 0, dst_is_dir;
	struct stat st;

	memset(&g, 0, sizeof(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	якщо ((abs_src = prepare_remote_path(conn, src)) == NULL) {
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	якщо ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		якщо (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		інакше
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	якщо (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		якщо (sftp_stat(conn, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	якщо ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	якщо (g.gl_matchc > 1 && !dst_is_dir) {
		якщо (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			goto out;
		}
		debug2_f("creating destination \"%s\"", dst);
		якщо (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			goto out;
		}
		dst_is_dir = 1;
	}

	для (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		якщо ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for destination of '..' */
		якщо (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		якщо (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		інакше
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		якщо (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			якщо (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag, SFTP_PROGRESS_ONLY, 0, 0, 1, 1) == -1)
				err = -1;
		} інакше {
			якщо (sftp_download(conn, g.gl_pathv[i], abs_dst, NULL,
			    pflag, 0, 0, 1) == -1)
				err = -1;
		}
		free(abs_dst);
		abs_dst = NULL;
		free(tmp);
		tmp = NULL;
	}

out:
	free(abs_src);
	free(tmp);
	globfree(&g);
	якщо (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((sizeof(type) == 4 && (val) > INT32_MAX) || \
	 (sizeof(type) == 8 && (val) > INT64_MAX) || \
	 (sizeof(type) != 4 && sizeof(type) != 8))

void
sink(ціле argc, char **argv, const char *src)
{
	static BUF buffer;
	struct stat stb;
	BUF *bp;
	off_t i;
	size_t j, count;
	ціле amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes;
	unsigned long long ull;
	ціле setimes, targisdir, wrerr;
	char ch, *cp, *np, *targ, *why, *vect[1], buf[2048], visbuf[2048];
	char **patterns = NULL;
	size_t n, npatterns = 0;
	struct timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	якщо (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	якщо (!pflag) {
		(void) umask(mask);
		mask |= 07000;
	}
	якщо (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	якщо (targetshouldbedirectory)
		verifydir(targ);

	(void) atomicio(vwrite, remout, "", 1);
	якщо (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	якщо (src != NULL && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		якщо (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	для (first = 1;; first = 0) {
		cp = buf;
		якщо (atomicio(read, remin, cp, 1) != 1)
			goto done;
		якщо (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			якщо (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			якщо (ch == '\0')
				SCREWUP("nul byte in filename");
			*cp++ = ch;
		} поки (cp < &buf[sizeof(buf) - 1] && ch != '\n');
		*cp = 0;
		якщо (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		якщо (buf[0] == '\01' || buf[0] == '\02') {
			якщо (iamremote == 0) {
				(void) snmprintf(visbuf, sizeof(visbuf),
				    NULL, "%s", buf + 1);
				(void) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			якщо (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		якщо (buf[0] == 'E') {
			(void) atomicio(vwrite, remout, "", 1);
			goto done;
		}
		якщо (ch == '\n')
			*--cp = 0;

		cp = buf;
		якщо (*cp == 'T') {
			setimes++;
			cp++;
			якщо (!isdigit((unsigned char)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			якщо (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			якщо (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			якщо (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			якщо (!isdigit((unsigned char)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			якщо (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			якщо (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			якщо (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");
			(void) atomicio(vwrite, remout, "", 1);
			continue;
		}
		якщо (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			якщо (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		для (++cp; cp < buf + 5; cp++) {
			якщо (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		якщо (!pflag)
			mode &= ~mask;
		якщо (*cp++ != ' ')
			SCREWUP("mode not delimited");

		якщо (!isdigit((unsigned char)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		якщо (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		якщо (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		якщо (*cp == '\0' || strchr(cp, '/') != NULL ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		якщо (npatterns > 0) {
			для (n = 0; n < npatterns; n++) {
				якщо (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					break;
			}
			якщо (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				для (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		якщо (targisdir) {
			static char *namebuf;
			static size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			якщо (need > cursize) {
				free(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} інакше
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		якщо (buf[0] == 'D') {
			ціле mod_flag = pflag;
			якщо (!iamrecursive)
				SCREWUP("received directory without -r");
			якщо (exists) {
				якщо (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					goto bad;
				}
				якщо (pflag)
					(void) chmod(np, mode);
			} інакше {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				якщо (mkdir(np, mode | S_IRWXU) == -1)
					goto bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			якщо (setimes) {
				setimes = 0;
				(void) utimes(vect[0], tv);
			}
			якщо (mod_flag)
				(void) chmod(vect[0], mode);
			free(vect[0]);
			continue;
		}
		omode = mode;
		mode |= S_IWUSR;
		якщо ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
		(void) atomicio(vwrite, remout, "", 1);
		якщо ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == NULL) {
			(void) close(ofd);
			continue;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		якщо (showprogress)
			start_progress_meter(curfile, size, &statbytes);
		set_nonblock(remin);
		для (count = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			якщо (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = atomicio6(read, remin, cp, amt,
				    scpio, &statbytes);
				якщо (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} поки (amt > 0);

			якщо (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				якщо (!wrerr) {
					якщо (atomicio(vwrite, ofd, bp->buf,
					    count) != count) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				count = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		якщо (count != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, count) != count) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		якщо (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));
		якщо (pflag) {
			якщо (exists || omode != mode)
#ifdef HAVE_FCHMOD
				якщо (fchmod(ofd, omode)) {
#інакше /* HAVE_FCHMOD */
				якщо (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} інакше {
			якщо (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				якщо (fchmod(ofd, omode & ~mask)) {
#інакше /* HAVE_FCHMOD */
				якщо (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		якщо (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(void) response();
		якщо (showprogress)
			stop_progress_meter();
		якщо (setimes && !wrerr) {
			setimes = 0;
			якщо (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		якщо (note_err(NULL) == 0)
			(void) atomicio(vwrite, remout, "", 1);
	}
done:
	для (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	повернути;
screwup:
	для (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

void
throughlocal_sftp(struct sftp_conn *from, struct sftp_conn *to,
    char *src, char *targ)
{
	char *target = NULL, *filename = NULL, *abs_dst = NULL;
	char *abs_src = NULL, *tmp = NULL;
	glob_t g;
	ціле i, r, targetisdir, err = 0;

	якщо ((filename = basename(src)) == NULL)
		fatal("basename %s: %s", src, strerror(errno));

	якщо ((abs_src = prepare_remote_path(from, src)) == NULL ||
	    (target = prepare_remote_path(to, targ)) == NULL)
		cleanup_exit(255);
	memset(&g, 0, sizeof(g));

	targetisdir = sftp_remote_is_dir(to, target);
	якщо (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	якщо ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		якщо (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		інакше
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	якщо (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		якщо (sftp_stat(from, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	для (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		якщо ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for source of '..' */
		якщо (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		якщо (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		інакше
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		якщо (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			якщо (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    NULL, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} інакше {
			якщо (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    NULL, pflag) == -1)
				err = -1;
		}
		free(abs_dst);
		abs_dst = NULL;
		free(tmp);
		tmp = NULL;
	}

out:
	free(abs_src);
	free(abs_dst);
	free(target);
	free(tmp);
	globfree(&g);
	якщо (err == -1)
		errs = 1;
}

ціле
response(void)
{
	char ch, *cp, resp, rbuf[2048], visbuf[2048];

	якщо (atomicio(read, remin, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;
	switch (resp) {
	case 0:		/* ok */
		повернути (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:		/* error, followed by error msg */
	case 2:		/* fatal error, "" */
		do {
			якщо (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} поки (cp < &rbuf[sizeof(rbuf) - 1] && ch != '\n');

		якщо (!iamremote) {
			cp[-1] = '\0';
			(void) snmprintf(visbuf, sizeof(visbuf),
			    NULL, "%s\n", rbuf);
			(void) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		якщо (resp == 1)
			повернути (-1);
		exit(1);
	}
	/* NOTREACHED */
}

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: scp [-346ABCOpqRrTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n"
	    "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n"
	    "           [-P port] [-S program] [-X sftp_option] source ... target\n");
	exit(1);
}

void
run_err(const char *fmt,...)
{
	static FILE *fp;
	va_list ap;

	++errs;
	якщо (fp != NULL || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(void) fprintf(fp, "%c", 0x01);
		(void) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(void) vfprintf(fp, fmt, ap);
		va_end(ap);
		(void) fprintf(fp, "\n");
		(void) fflush(fp);
	}

	якщо (!iamremote) {
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
ціле
note_err(const char *fmt, ...)
{
	static char *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	якщо (fmt == NULL) {
		якщо (emsg == NULL)
			повернути 0;
		run_err("%s", emsg);
		free(emsg);
		emsg = NULL;
		повернути -1;
	}

	errs++;
	/* Prefer first-noted error */
	якщо (emsg != NULL)
		повернути -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, NULL, fmt, ap);
	va_end(ap);
	повернути -1;
}

void
verifydir(char *cp)
{
	struct stat stb;

	якщо (!stat(cp, &stb)) {
		якщо (S_ISDIR(stb.st_mode))
			повернути;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

ціле
okname(char *cp0)
{
	ціле c;
	char *cp;

	cp = cp0;
	do {
		c = (ціле)*cp;
		якщо (c & 0200)
			goto bad;
		якщо (!isalpha(c) && !isdigit((unsigned char)c)) {
			switch (c) {
			case '\'':
			case '"':
			case '`':
			case ' ':
			case '#':
				goto bad;
			default:
				break;
			}
		}
	} поки (*++cp);
	повернути (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	повернути (0);
}

BUF *
allocbuf(BUF *bp, ціле fd, ціле blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	struct stat stb;

	якщо (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		повернути (NULL);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	якщо (size == 0)
		size = blksize;
#інакше /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	якщо (bp->cnt >= size)
		повернути (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	повернути (bp);
}

void
lostconn(ціле signo)
{
	якщо (!iamremote)
		(void)write(STDERR_FILENO, "lost connection\n", 16);
	якщо (signo)
		_exit(1);
	інакше
		exit(1);
}

void
cleanup_exit(ціле i)
{
	якщо (remin > 0)
		close(remin);
	якщо (remout > 0)
		close(remout);
	якщо (remin2 > 0)
		close(remin2);
	якщо (remout2 > 0)
		close(remout2);
	якщо (do_cmd_pid > 0)
		(void)waitpid(do_cmd_pid, NULL, 0);
	якщо (do_cmd_pid2 > 0)
		(void)waitpid(do_cmd_pid2, NULL, 0);
	exit(i);
}
