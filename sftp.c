/* $OpenBSD: sftp.c,v 1.260 2026/10/01 03:11:49 djm Exp $ */
/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/ioctl.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/statvfs.h>
#অন্তর্ভাব <sys/wait.h>

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#অন্তর্ভাব <histedit.h>
#অন্যথা
প্রকারনির্দেশ শূন্য Edit_সারি;
#endif
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <util.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "utf8.h"

#অন্তর্ভাব "sftp.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sftp-common.h"
#অন্তর্ভাব "sftp-client.h"
#অন্তর্ভাব "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
পূর্ণাঙ্ক batchmode = 0;

/* PID of ssh transport process */
স্থির চঞ্চল pid_t sshpid = -1;

/* Suppress diagnostic messages */
পূর্ণাঙ্ক quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
পূর্ণাঙ্ক showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
পূর্ণাঙ্ক global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
পূর্ণাঙ্ক global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
পূর্ণাঙ্ক global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
পূর্ণাঙ্ক global_fflag = 0;

/* SIGINT received during command processing */
চঞ্চল sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
পূর্ণাঙ্ক sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
সংরচনা complete_ctx {
	সংরচনা sftp_conn *conn;
	বর্ণ **remote_pathp;
};

পূর্ণাঙ্ক sftp_glob(সংরচনা sftp_conn *, ধ্রুব বর্ণ *, পূর্ণাঙ্ক,
    পূর্ণাঙ্ক (*)(ধ্রুব বর্ণ *, পূর্ণাঙ্ক), glob_t *); /* proto for sftp-glob.c */

বাহ্য বর্ণ *__progname;

/* Separators for interactive commands */
#define WHITESPACE " \t\r\n"

/* ls flags */
#define LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#define LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#define LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#define LS_NAME_SORT	0x0008	/* Sort by name (default) */
#define LS_TIME_SORT	0x0010	/* Sort by mtime */
#define LS_SIZE_SORT	0x0020	/* Sort by file size */
#define LS_REVERSE_SORT	0x0040	/* Reverse sort order */
#define LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#define LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#define VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#define SORT_FLAGS	(LS_NAME_SORT|LS_TIME_SORT|LS_SIZE_SORT)

/* Commands for interactive mode */
গণনা sftp_command {
	I_CHDIR = 1,
	I_CHGRP,
	I_CHMOD,
	I_CHOWN,
	I_COPY,
	I_DF,
	I_GET,
	I_HELP,
	I_LCHDIR,
	I_LINK,
	I_LLS,
	I_LMKDIR,
	I_LPWD,
	I_LS,
	I_LUMASK,
	I_MKDIR,
	I_PUT,
	I_PWD,
	I_QUIT,
	I_REGET,
	I_RENAME,
	I_REPUT,
	I_RM,
	I_RMDIR,
	I_SHELL,
	I_SYMLINK,
	I_VERSION,
	I_PROGRESS,
};

সংরচনা CMD {
	ধ্রুব বর্ণ *c;
	ধ্রুব পূর্ণাঙ্ক n;
	ধ্রুব পূর্ণাঙ্ক t;	/* Completion type for the first argument */
	ধ্রুব পূর্ণাঙ্ক t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

স্থির ধ্রুব সংরচনা CMD cmds[] = {
	{ "bye",	I_QUIT,		NOARGS,		NOARGS	},
	{ "cd",		I_CHDIR,	REMOTE,		NOARGS	},
	{ "chdir",	I_CHDIR,	REMOTE,		NOARGS	},
	{ "chgrp",	I_CHGRP,	REMOTE,		NOARGS	},
	{ "chmod",	I_CHMOD,	REMOTE,		NOARGS	},
	{ "chown",	I_CHOWN,	REMOTE,		NOARGS	},
	{ "copy",	I_COPY,		REMOTE,		LOCAL	},
	{ "cp",		I_COPY,		REMOTE,		LOCAL	},
	{ "df",		I_DF,		REMOTE,		NOARGS	},
	{ "dir",	I_LS,		REMOTE,		NOARGS	},
	{ "exit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "get",	I_GET,		REMOTE,		LOCAL	},
	{ "help",	I_HELP,		NOARGS,		NOARGS	},
	{ "lcd",	I_LCHDIR,	LOCAL,		NOARGS	},
	{ "lchdir",	I_LCHDIR,	LOCAL,		NOARGS	},
	{ "lls",	I_LLS,		LOCAL,		NOARGS	},
	{ "lmkdir",	I_LMKDIR,	LOCAL,		NOARGS	},
	{ "ln",		I_LINK,		REMOTE,		REMOTE	},
	{ "lpwd",	I_LPWD,		LOCAL,		NOARGS	},
	{ "ls",		I_LS,		REMOTE,		NOARGS	},
	{ "lumask",	I_LUMASK,	NOARGS,		NOARGS	},
	{ "mkdir",	I_MKDIR,	REMOTE,		NOARGS	},
	{ "mget",	I_GET,		REMOTE,		LOCAL	},
	{ "mput",	I_PUT,		LOCAL,		REMOTE	},
	{ "progress",	I_PROGRESS,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_VERSION,	NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ রিক্ত,		-1,		-1,		-1	}
};

স্থির শূন্য
killchild(পূর্ণাঙ্ক signo)
{
	pid_t pid;

	pid = sshpid;
	যদি (pid > 1) {
		kill(pid, SIGTERM);
		(শূন্য)waitpid(pid, রিক্ত, 0);
	}

	_exit(1);
}

স্থির শূন্য
suspchild(পূর্ণাঙ্ক signo)
{
	পূর্ণাঙ্ক save_errno = errno;
	যদি (sshpid > 1) {
		kill(sshpid, signo);
		যাবত্ (waitpid(sshpid, রিক্ত, WUNTRACED) == -1 && errno == EINTR)
			অনুবর্ত;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

স্থির শূন্য
cmd_interrupt(পূর্ণাঙ্ক signo)
{
	ধ্রুব বর্ণ বার্তা[] = "\rInterrupt  \n";
	পূর্ণাঙ্ক olderrno = errno;

	(শূন্য)লিখ(STDERR_FILENO, বার্তা, পরিমাণ(বার্তা) - 1);
	interrupted = 1;
	errno = olderrno;
}

স্থির শূন্য
read_interrupt(পূর্ণাঙ্ক signo)
{
	interrupted = 1;
}

স্থির শূন্য
sigchld_handler(পূর্ণাঙ্ক sig)
{
	পূর্ণাঙ্ক save_errno = errno;
	pid_t pid;
	ধ্রুব বর্ণ বার্তা[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	যাবত্ ((pid = waitpid(sshpid, রিক্ত, WNOHANG)) == -1 && errno == EINTR)
		অনুবর্ত;
	যদি (pid == sshpid) {
		যদি (!quiet)
		    (শূন্য)লিখ(STDERR_FILENO, বার্তা, পরিমাণ(বার্তা) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

স্থির শূন্য
help(শূন্য)
{
	printf("Available commands:\n"
	    "bye                                Quit sftp\n"
	    "cd path                            Change remote directory to 'path'\n"
	    "chgrp [-h] grp path                Change group of file 'path' to 'grp'\n"
	    "chmod [-h] mode path               Change permissions of file 'path' to 'mode'\n"
	    "chown [-h] own path                Change owner of file 'path' to 'own'\n"
	    "copy oldpath newpath               Copy remote file\n"
	    "cp oldpath newpath                 Copy remote file\n"
	    "df [-hi] [path]                    Display statistics for current directory or\n"
	    "                                   filesystem containing 'path'\n"
	    "exit                               Quit sftp\n"
	    "get [-afpR] remote [local]         Download file\n"
	    "help                               Display this help text\n"
	    "lcd path                           Change local directory to 'path'\n"
	    "lls [ls-options [path]]            Display local directory listing\n"
	    "lmkdir [-p] path                   Create local directory\n"
	    "ln [-s] oldpath newpath            Link remote file (-s for symlink)\n"
	    "lpwd                               Print local working directory\n"
	    "ls [-1afhlnrSt] [path]             Display remote directory listing\n"
	    "lumask umask                       Set local umask to 'umask'\n"
	    "mkdir [-p] path                    Create remote directory\n"
	    "progress                           Toggle display of progress meter\n"
	    "put [-afpR] local [remote]         Upload file\n"
	    "pwd                                Display remote working directory\n"
	    "quit                               Quit sftp\n"
	    "reget [-fpR] remote [local]        Resume download file\n"
	    "rename oldpath newpath             Rename remote file\n"
	    "reput [-fpR] local [remote]        Resume upload file\n"
	    "rm path                            Delete remote file\n"
	    "rmdir path                         Remove remote directory\n"
	    "symlink oldpath newpath            Symlink remote file\n"
	    "version                            Show SFTP version\n"
	    "!command                           Execute 'command' in local shell\n"
	    "!                                  Escape to local shell\n"
	    "?                                  Synonym for help\n");
}

স্থির শূন্য
local_do_shell(ধ্রুব বর্ণ *args)
{
	পূর্ণাঙ্ক status;
	বর্ণ *shell;
	pid_t pid;

	যদি (!*args)
		args = রিক্ত;

	যদি ((shell = getenv("SHELL")) == রিক্ত || *shell == '\0')
		shell = _PATH_BSHELL;

	যদি ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	যদি (pid == 0) {
		যদি (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (বর্ণ *)রিক্ত);
		} অন্যথা {
			debug3("Executing %s", shell);
			execl(shell, shell, (বর্ণ *)রিক্ত);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	যাবত্ (waitpid(pid, &status, 0) == -1)
		যদি (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	যদি (!WIFEXITED(status))
		error("Shell exited abnormally");
	অন্যথা যদি (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

স্থির শূন্য
local_do_ls(ধ্রুব বর্ণ *args)
{
	যদি (!args || !*args)
		local_do_shell(_PATH_LS);
	অন্যথা {
		পূর্ণাঙ্ক len = strlen(_PATH_LS " ") + strlen(args) + 1;
		বর্ণ *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		মুক্ত(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
স্থির বর্ণ *
path_strip(ধ্রুব বর্ণ *path, ধ্রুব বর্ণ *strip)
{
	size_t len;

	যদি (strip == রিক্ত || (len = strlen(strip)) == 0)
		প্রত্যাগম (xstrdup(path));

	যদি (strncmp(path, strip, len) == 0) {
		যদি (strip[len - 1] != '/' && path[len] == '/')
			len++;
		প্রত্যাগম (xstrdup(path + len));
	}

	প্রত্যাগম (xstrdup(path));
}

স্থির পূর্ণাঙ্ক
parse_getput_flags(ধ্রুব বর্ণ *cmd, বর্ণ **argv, পূর্ণাঙ্ক argc,
    পূর্ণাঙ্ক *aflag, পূর্ণাঙ্ক *fflag, পূর্ণাঙ্ক *pflag, পূর্ণাঙ্ক *rflag)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	যাবত্ ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'a':
			*aflag = 1;
			ভঙ্গ;
		পক্ষ 'f':
			*fflag = 1;
			ভঙ্গ;
		পক্ষ 'p':
		পক্ষ 'P':
			*pflag = 1;
			ভঙ্গ;
		পক্ষ 'r':
		পক্ষ 'R':
			*rflag = 1;
			ভঙ্গ;
		স্বভাব:
			error("%s: Invalid flag -%c", cmd, optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির পূর্ণাঙ্ক
parse_mkdir_flags(ধ্রুব বর্ণ *cmd, বর্ণ **argv, পূর্ণাঙ্ক argc, পূর্ণাঙ্ক *pflag)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	যাবত্ ((ch = getopt(argc, argv, "p")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'p':
			*pflag = 1;
			ভঙ্গ;
		স্বভাব:
			error("%s: Invalid flag -%c", cmd, optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির পূর্ণাঙ্ক
parse_link_flags(ধ্রুব বর্ণ *cmd, বর্ণ **argv, পূর্ণাঙ্ক argc, পূর্ণাঙ্ক *sflag)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	যাবত্ ((ch = getopt(argc, argv, "s")) != -1) {
		বিকল্প (ch) {
		পক্ষ 's':
			*sflag = 1;
			ভঙ্গ;
		স্বভাব:
			error("%s: Invalid flag -%c", cmd, optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির পূর্ণাঙ্ক
parse_rename_flags(ধ্রুব বর্ণ *cmd, বর্ণ **argv, পূর্ণাঙ্ক argc, পূর্ণাঙ্ক *lflag)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	যাবত্ ((ch = getopt(argc, argv, "l")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'l':
			*lflag = 1;
			ভঙ্গ;
		স্বভাব:
			error("%s: Invalid flag -%c", cmd, optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির পূর্ণাঙ্ক
parse_ls_flags(বর্ণ **argv, পূর্ণাঙ্ক argc, পূর্ণাঙ্ক *lflag)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	যাবত্ ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		বিকল্প (ch) {
		পক্ষ '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			ভঙ্গ;
		পক্ষ 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			ভঙ্গ;
		পক্ষ 'a':
			*lflag |= LS_SHOW_ALL;
			ভঙ্গ;
		পক্ষ 'f':
			*lflag &= ~SORT_FLAGS;
			ভঙ্গ;
		পক্ষ 'h':
			*lflag |= LS_SI_UNITS;
			ভঙ্গ;
		পক্ষ 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			ভঙ্গ;
		পক্ষ 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			ভঙ্গ;
		পক্ষ 'r':
			*lflag |= LS_REVERSE_SORT;
			ভঙ্গ;
		পক্ষ 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			ভঙ্গ;
		স্বভাব:
			error("ls: Invalid flag -%c", optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির পূর্ণাঙ্ক
parse_df_flags(ধ্রুব বর্ণ *cmd, বর্ণ **argv, পূর্ণাঙ্ক argc, পূর্ণাঙ্ক *hflag, পূর্ণাঙ্ক *iflag)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	যাবত্ ((ch = getopt(argc, argv, "hi")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'h':
			*hflag = 1;
			ভঙ্গ;
		পক্ষ 'i':
			*iflag = 1;
			ভঙ্গ;
		স্বভাব:
			error("%s: Invalid flag -%c", cmd, optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির পূর্ণাঙ্ক
parse_ch_flags(ধ্রুব বর্ণ *cmd, বর্ণ **argv, পূর্ণাঙ্ক argc, পূর্ণাঙ্ক *hflag)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	যাবত্ ((ch = getopt(argc, argv, "h")) != -1) {
		বিকল্প (ch) {
		পক্ষ 'h':
			*hflag = 1;
			ভঙ্গ;
		স্বভাব:
			error("%s: Invalid flag -%c", cmd, optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির পূর্ণাঙ্ক
parse_no_flags(ধ্রুব বর্ণ *cmd, বর্ণ **argv, পূর্ণাঙ্ক argc)
{
	বাহ্য পূর্ণাঙ্ক opterr, optind, optopt, optreset;
	পূর্ণাঙ্ক ch;

	optind = optreset = 1;
	opterr = 0;

	যাবত্ ((ch = getopt(argc, argv, "")) != -1) {
		বিকল্প (ch) {
		স্বভাব:
			error("%s: Invalid flag -%c", cmd, optopt);
			প্রত্যাগম -1;
		}
	}

	প্রত্যাগম optind;
}

স্থির বর্ণ *
escape_glob(ধ্রুব বর্ণ *s)
{
	size_t i, o, len;
	বর্ণ *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	প্রতি (i = o = 0; i < len; i++) {
		যদি (strchr("[]?*\\", s[i]) != রিক্ত)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	প্রত্যাগম ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
স্থির বর্ণ *
make_absolute_pwd_glob(বর্ণ *p, ধ্রুব বর্ণ *pwd)
{
	বর্ণ *ret, *escpwd;

	escpwd = escape_glob(pwd);
	যদি (p == রিক্ত)
		প্রত্যাগম escpwd;
	ret = sftp_make_absolute(p, escpwd);
	মুক্ত(escpwd);
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
local_is_dir(ধ্রুব বর্ণ *path)
{
	সংরচনা stat sb;

	যদি (stat(path, &sb) == -1)
		প্রত্যাগম 0;
	প্রত্যাগম S_ISDIR(sb.st_mode);
}

স্থির পূর্ণাঙ্ক
process_get(সংরচনা sftp_conn *conn, ধ্রুব বর্ণ *src, ধ্রুব বর্ণ *dst,
    ধ্রুব বর্ণ *pwd, পূর্ণাঙ্ক pflag, পূর্ণাঙ্ক rflag, পূর্ণাঙ্ক resume, পূর্ণাঙ্ক fflag)
{
	বর্ণ *filename, *abs_src = রিক্ত, *abs_dst = রিক্ত, *tmp = রিক্ত;
	glob_t g;
	পূর্ণাঙ্ক i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, পরিমাণ(g));

	debug3("Looking up %s", abs_src);
	যদি ((r = sftp_glob(conn, abs_src, GLOB_MARK, রিক্ত, &g)) != 0) {
		যদি (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} অন্যথা {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		গচ্ছ out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	যদি (g.gl_matchc > 1 && dst != রিক্ত && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		গচ্ছ out;
	}

	প্রতি (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == রিক্ত) {
			error("basename %s: %s", tmp, strerror(errno));
			মুক্ত(tmp);
			err = -1;
			গচ্ছ out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		যদি (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		যদি (g.gl_matchc == 1 && dst) {
			যদি (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} অন্যথা {
				abs_dst = xstrdup(dst);
			}
		} অন্যথা যদি (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} অন্যথা {
			abs_dst = xstrdup(filename);
		}
		মুক্ত(tmp);

		resume |= global_aflag;
		যদি (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		অন্যথা যদি (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		যদি (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			যদি (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    রিক্ত, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} অন্যথা {
			যদি (sftp_download(conn, g.gl_pathv[i], abs_dst, রিক্ত,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		মুক্ত(abs_dst);
		abs_dst = রিক্ত;
	}

out:
	মুক্ত(abs_src);
	globfree(&g);
	প্রত্যাগম(err);
}

স্থির পূর্ণাঙ্ক
process_put(সংরচনা sftp_conn *conn, ধ্রুব বর্ণ *src, ধ্রুব বর্ণ *dst,
    ধ্রুব বর্ণ *pwd, পূর্ণাঙ্ক pflag, পূর্ণাঙ্ক rflag, পূর্ণাঙ্ক resume, পূর্ণাঙ্ক fflag)
{
	বর্ণ *tmp_dst = রিক্ত;
	বর্ণ *abs_dst = রিক্ত;
	বর্ণ *tmp = রিক্ত, *filename = রিক্ত;
	glob_t g;
	পূর্ণাঙ্ক err = 0;
	পূর্ণাঙ্ক i, dst_is_dir = 1;
	সংরচনা stat sb;

	যদি (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, পরিমাণ(g));
	debug3("Looking up %s", src);
	যদি (glob(src, GLOB_NOCHECK | GLOB_MARK, রিক্ত, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		গচ্ছ out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	যদি (tmp_dst != রিক্ত)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	যদি (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		গচ্ছ out;
	}

	প্রতি (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		যদি (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			অনুবর্ত;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == রিক্ত) {
			error("basename %s: %s", tmp, strerror(errno));
			মুক্ত(tmp);
			err = -1;
			গচ্ছ out;
		}
		/* Special handling for source of '..' */
		যদি (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		মুক্ত(abs_dst);
		abs_dst = রিক্ত;
		যদি (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			যদি (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			অন্যথা
				abs_dst = xstrdup(tmp_dst);
		} অন্যথা যদি (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} অন্যথা {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		মুক্ত(tmp);

		resume |= global_aflag;
		যদি (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		অন্যথা যদি (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		যদি (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			যদি (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} অন্যথা {
			যদি (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	মুক্ত(abs_dst);
	মুক্ত(tmp_dst);
	globfree(&g);
	প্রত্যাগম(err);
}

স্থির পূর্ণাঙ্ক
sdirent_comp(ধ্রুব শূন্য *aa, ধ্রুব শূন্য *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	পূর্ণাঙ্ক rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	যদি (sort_flag & LS_NAME_SORT)
		প্রত্যাগম (rmul * strcmp(a->filename, b->filename));
	অন্যথা যদি (sort_flag & LS_TIME_SORT)
		প্রত্যাগম (rmul * NCMP(a->a.mtime, b->a.mtime));
	অন্যথা যদি (sort_flag & LS_SIZE_SORT)
		প্রত্যাগম (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
স্থির পূর্ণাঙ্ক
do_ls_dir(সংরচনা sftp_conn *conn, ধ্রুব বর্ণ *path,
    ধ্রুব বর্ণ *strip_path, পূর্ণাঙ্ক lflag)
{
	পূর্ণাঙ্ক n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	যদি ((n = sftp_readdir(conn, path, &d)) != 0)
		প্রত্যাগম (n);

	যদি (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		সংরচনা winsize ws;
		বর্ণ *tmp;

		/* Count entries for sort and find longest filename */
		প্রতি (n = 0; d[n] != রিক্ত; n++) {
			যদি (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		মুক্ত(tmp);

		যদি (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	যদি (lflag & SORT_FLAGS) {
		প্রতি (n = 0; d[n] != রিক্ত; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, পরিমাণ(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	প্রতি (n = 0; d[n] != রিক্ত && !interrupted; n++) {
		বর্ণ *tmp, *fname;

		যদি (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			অনুবর্ত;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		মুক্ত(tmp);

		যদি (lflag & LS_LONG_VIEW) {
			যদি ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				বর্ণ *lname;
				সংরচনা stat sb;
				ধ্রুব বর্ণ *user = রিক্ত, *group = রিক্ত;

				memset(&sb, 0, পরিমাণ(sb));
				attrib_to_stat(&d[n]->a, &sb);
				যদি ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				মুক্ত(lname);
			} অন্যথা
				mprintf("%s\n", d[n]->longname);
		} অন্যথা {
			mprintf("%-*s", colspace, fname);
			যদি (c >= columns) {
				printf("\n");
				c = 1;
			} অন্যথা
				c++;
		}

		মুক্ত(fname);
	}

	যদি (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	প্রত্যাগম (0);
}

স্থির পূর্ণাঙ্ক
sglob_comp(ধ্রুব শূন্য *aa, ধ্রুব শূন্য *bb)
{
	u_int a = *(ধ্রুব u_int *)aa;
	u_int b = *(ধ্রুব u_int *)bb;
	ধ্রুব বর্ণ *ap = sort_glob->gl_pathv[a];
	ধ্রুব বর্ণ *bp = sort_glob->gl_pathv[b];
	ধ্রুব সংরচনা stat *as = sort_glob->gl_statv[a];
	ধ্রুব সংরচনা stat *bs = sort_glob->gl_statv[b];
	পূর্ণাঙ্ক rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	যদি (as == রিক্ত || bs == রিক্ত)
		প্রত্যাগম (as == bs) ? 0 : (as == রিক্ত ? rmul : -rmul);
	যদি (sort_flag & LS_NAME_SORT)
		প্রত্যাগম (rmul * strcmp(ap, bp));
	অন্যথা যদি (sort_flag & LS_TIME_SORT) {
#যদি defined(HAVE_STRUCT_STAT_ST_MTIM)
		যদি (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			প্রত্যাগম 0;
		প্রত্যাগম timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#নোচেদ্যদি defined(HAVE_STRUCT_STAT_ST_MTIME)
		প্রত্যাগম (rmul * NCMP(as->st_mtime, bs->st_mtime));
#অন্যথা
	প্রত্যাগম rmul * 1;
#endif
	} অন্যথা যদি (sort_flag & LS_SIZE_SORT)
		প্রত্যাগম (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
স্থির পূর্ণাঙ্ক
do_globbed_ls(সংরচনা sftp_conn *conn, ধ্রুব বর্ণ *path,
    ধ্রুব বর্ণ *strip_path, পূর্ণাঙ্ক lflag)
{
	বর্ণ *fname, *lname;
	glob_t g;
	পূর্ণাঙ্ক err, r;
	সংরচনা winsize ws;
	u_int i, j, nentries, *indices = রিক্ত, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, পরিমাণ(g));

	যদি ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    রিক্ত, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		যদি (g.gl_pathc)
			globfree(&g);
		যদি (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} অন্যথা {
			error("Can't ls: \"%s\" not found", path);
		}
		প্রত্যাগম -1;
	}

	যদি (interrupted)
		গচ্ছ out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	যদি (g.gl_matchc == 1 && g.gl_statv[0] != রিক্ত &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		প্রত্যাগম err;
	}

	যদি (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	যদি (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		প্রতি (i = 0; g.gl_pathv[i]; i++)
			m = MAXIMUM(m, strlen(g.gl_pathv[i]));

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	প্রতি (nentries = 0; g.gl_pathv[nentries] != রিক্ত; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, পরিমাণ(*indices));
	প্রতি (i = 0; i < nentries; i++)
		indices[i] = i;

	যদি (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, পরিমাণ(*indices), sglob_comp);
		sort_glob = রিক্ত;
	}

	get_remote_user_groups_from_glob(conn, &g);
	প্রতি (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		যদি (lflag & LS_LONG_VIEW) {
			ধ্রুব বর্ণ *user = রিক্ত, *group = রিক্ত;

			যদি (g.gl_statv[i] == রিক্ত) {
				error("no stat information for %s", fname);
				মুক্ত(fname);
				অনুবর্ত;
			}
			যদি ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			মুক্ত(lname);
		} অন্যথা {
			mprintf("%-*s", colspace, fname);
			যদি (c >= columns) {
				printf("\n");
				c = 1;
			} অন্যথা
				c++;
		}
		মুক্ত(fname);
	}

	যদি (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	যদি (g.gl_pathc)
		globfree(&g);
	মুক্ত(indices);

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
do_df(সংরচনা sftp_conn *conn, ধ্রুব বর্ণ *path, পূর্ণাঙ্ক hflag, পূর্ণাঙ্ক iflag)
{
	সংরচনা sftp_statvfs st;
	বর্ণ s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	বর্ণ s_মূল[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	বর্ণ s_icapacity[16], s_dcapacity[16];

	যদি (sftp_statvfs(conn, path, &st, 1) == -1)
		প্রত্যাগম -1;
	যদি (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", পরিমাণ(s_icapacity));
	অন্যথা {
		snprintf(s_icapacity, পরিমাণ(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	যদি (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", পরিমাণ(s_dcapacity));
	অন্যথা {
		snprintf(s_dcapacity, পরিমাণ(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	যদি (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} অন্যথা যদি (hflag) {
		strlcpy(s_used, "error", পরিমাণ(s_used));
		strlcpy(s_avail, "error", পরিমাণ(s_avail));
		strlcpy(s_মূল, "error", পরিমাণ(s_মূল));
		strlcpy(s_total, "error", পরিমাণ(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_মূল);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_মূল, s_dcapacity);
	} অন্যথা {
		printf("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		printf("%12llu %12llu %12llu %12llu         %s\n",
		    (unsigned long long)(st.f_frsize * st.f_blocks / 1024),
		    (unsigned long long)(st.f_frsize *
		    (st.f_blocks - st.f_bfree) / 1024),
		    (unsigned long long)(st.f_frsize * st.f_bavail / 1024),
		    (unsigned long long)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	প্রত্যাগম 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
স্থির শূন্য
undo_glob_escape(বর্ণ *s)
{
	size_t i, j;

	প্রতি (i = j = 0;;) {
		যদি (s[i] == '\0') {
			s[j] = '\0';
			প্রত্যাগম;
		}
		যদি (s[i] != '\\') {
			s[j++] = s[i++];
			অনুবর্ত;
		}
		/* s[i] == '\\' */
		++i;
		বিকল্প (s[i]) {
		পক্ষ '?':
		পক্ষ '[':
		পক্ষ '*':
		পক্ষ '\\':
			s[j++] = s[i++];
			ভঙ্গ;
		পক্ষ '\0':
			s[j++] = '\\';
			s[j] = '\0';
			প্রত্যাগম;
		স্বভাব:
			s[j++] = '\\';
			s[j++] = s[i++];
			ভঙ্গ;
		}
	}
}

/*
 * Split a string into an argument vector using sh(1)-style quoting,
 * comment and escaping rules, but with some tweaks to handle glob(3)
 * wildcards.
 * The "sloppy" flag allows for recovery from missing terminating quote, for
 * use in parsing incomplete commandlines during tab autocompletion.
 *
 * Returns NULL on error or a NULL-terminated array of arguments.
 *
 * If "lastquote" is not NULL, the quoting character used for the last
 * argument is placed in *lastquote ("\0", "'" or "\"").
 *
 * If "terminated" is not NULL, *terminated will be set to 1 when the
 * last argument's quote has been properly terminated or 0 otherwise.
 * This parameter is only of use if "sloppy" is set.
 */
#define MAXARGS		128
#define MAXARGLEN	8192
স্থির বর্ণ **
makeargv(ধ্রুব বর্ণ *arg, পূর্ণাঙ্ক *argcp, পূর্ণাঙ্ক sloppy, বর্ণ *lastquote,
    u_int *terminated)
{
	পূর্ণাঙ্ক argc, quot;
	size_t i, j;
	স্থির বর্ণ argvs[MAXARGLEN];
	স্থির বর্ণ *argv[MAXARGS + 1];
	গণনা { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	যদি (strlen(arg) > পরিমাণ(argvs) - 1) {
 args_too_longs:
		error("string too long");
		প্রত্যাগম রিক্ত;
	}
	যদি (terminated != রিক্ত)
		*terminated = 1;
	যদি (lastquote != রিক্ত)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	প্রতি (;;) {
		যদি ((size_t)argc >= পরিমাণ(argv) / পরিমাণ(*argv)){
			error("Too many arguments.");
			প্রত্যাগম রিক্ত;
		}
		যদি (isspace((unsigned বর্ণ)arg[i])) {
			যদি (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} অন্যথা যদি (state != MA_START)
				argvs[j++] = arg[i];
		} অন্যথা যদি (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			যদি (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				যদি (lastquote != রিক্ত)
					*lastquote = arg[i];
			} অন্যথা যদি (state == MA_UNQUOTED)
				state = q;
			অন্যথা যদি (state == q)
				state = MA_UNQUOTED;
			অন্যথা
				argvs[j++] = arg[i];
		} অন্যথা যদি (arg[i] == '\\') {
			যদি (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				যদি (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} অন্যথা যদি (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					যদি (j >= পরিমাণ(argvs) - 5)
						গচ্ছ args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} অন্যথা {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} অন্যথা {
				যদি (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					যদি (lastquote != রিক্ত)
						*lastquote = '\0';
				}
				যদি (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} অন্যথা {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					যদি (arg[i] == '\0')
						গচ্ছ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} অন্যথা যদি (arg[i] == '#') {
			যদি (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			অন্যথা
				গচ্ছ string_done;
		} অন্যথা যদি (arg[i] == '\0') {
			যদি (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				যদি (sloppy) {
					state = MA_UNQUOTED;
					যদি (terminated != রিক্ত)
						*terminated = 0;
					গচ্ছ string_done;
				}
				error("Unterminated quoted argument");
				প্রত্যাগম রিক্ত;
			}
 string_done:
			যদি (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			ভঙ্গ;
		} অন্যথা {
			যদি (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				যদি (lastquote != রিক্ত)
					*lastquote = '\0';
			}
			যদি ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				যদি (j >= পরিমাণ(argvs) - 3)
					গচ্ছ args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} অন্যথা
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	প্রত্যাগম argv;
}

স্থির পূর্ণাঙ্ক
parse_args(ধ্রুব বর্ণ **cpp, পূর্ণাঙ্ক *ignore_errors, পূর্ণাঙ্ক *disable_echo, পূর্ণাঙ্ক *aflag,
	  পূর্ণাঙ্ক *fflag, পূর্ণাঙ্ক *hflag, পূর্ণাঙ্ক *iflag, পূর্ণাঙ্ক *lflag, পূর্ণাঙ্ক *pflag,
	  পূর্ণাঙ্ক *rflag, পূর্ণাঙ্ক *sflag,
    unsigned long *n_arg, বর্ণ **path1, বর্ণ **path2)
{
	ধ্রুব বর্ণ *cmd, *cp = *cpp;
	বর্ণ *cp2, **argv;
	পূর্ণাঙ্ক base = 0;
	long long ll;
	পূর্ণাঙ্ক path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	প্রতি (;*cp != '\0'; cp++) {
		যদি (*cp == '-') {
			*ignore_errors = 1;
		} অন্যথা যদি (*cp == '@') {
			*disable_echo = 1;
		} অন্যথা {
			/* all other characters terminate prefix processing */
			ভঙ্গ;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	যদি (*cp == '\0' || *cp == '#')
		প্রত্যাগম (0);

	যদি ((argv = makeargv(cp, &argc, 0, রিক্ত, রিক্ত)) == রিক্ত)
		প্রত্যাগম -1;

	/* Figure out which command we have */
	প্রতি (i = 0; cmds[i].c != রিক্ত; i++) {
		যদি (argv[0] != রিক্ত && strcasecmp(cmds[i].c, argv[0]) == 0)
			ভঙ্গ;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	যদি (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} অন্যথা যদি (cmdnum == -1) {
		error("Invalid command.");
		প্রত্যাগম -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = রিক্ত;
	optidx = 1;
	বিকল্প (cmdnum) {
	পক্ষ I_GET:
	পক্ষ I_REGET:
	পক্ষ I_REPUT:
	পক্ষ I_PUT:
		যদি ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			প্রত্যাগম -1;
		/* Get first pathname (mandatory) */
		যদি (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			প্রত্যাগম -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		যদি (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		ভঙ্গ;
	পক্ষ I_LINK:
		যদি ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			প্রত্যাগম -1;
		গচ্ছ parse_two_paths;
	পক্ষ I_COPY:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			প্রত্যাগম -1;
		গচ্ছ parse_two_paths;
	পক্ষ I_RENAME:
		যদি ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			প্রত্যাগম -1;
		গচ্ছ parse_two_paths;
	পক্ষ I_SYMLINK:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			প্রত্যাগম -1;
 parse_two_paths:
		যদি (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			প্রত্যাগম -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		ভঙ্গ;
	পক্ষ I_MKDIR:
	পক্ষ I_LMKDIR:
		যদি ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			প্রত্যাগম -1;
		path1_mandatory = 1;
		গচ্ছ parse_one_path;
	পক্ষ I_RM:
	পক্ষ I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	পক্ষ I_CHDIR:
	পক্ষ I_LCHDIR:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			প্রত্যাগম -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		যদি (argc - optidx < 1) {
			যদি (!path1_mandatory)
				ভঙ্গ; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			প্রত্যাগম -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		যদি (cmdnum != I_RM)
			undo_glob_escape(*path1);
		ভঙ্গ;
	পক্ষ I_DF:
		যদি ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			প্রত্যাগম -1;
		/* Default to current directory if no path specified */
		যদি (argc - optidx < 1)
			*path1 = রিক্ত;
		অন্যথা {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		ভঙ্গ;
	পক্ষ I_LS:
		যদি ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			প্রত্যাগম(-1);
		/* Path is optional */
		যদি (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		ভঙ্গ;
	পক্ষ I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	পক্ষ I_SHELL:
		/* Uses the rest of the line */
		ভঙ্গ;
	পক্ষ I_LUMASK:
	পক্ষ I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	পক্ষ I_CHOWN:
	পক্ষ I_CHGRP:
		যদি ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			প্রত্যাগম -1;
		/* Get numeric arg (mandatory) */
		যদি (argc - optidx < 1)
			গচ্ছ need_অঙ্ক_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		যদি (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_অঙ্ক_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			প্রত্যাগম -1;
		}
		*n_arg = ll;
		যদি (cmdnum == I_LUMASK)
			ভঙ্গ;
		/* Get pathname (mandatory) */
		যদি (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			প্রত্যাগম -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		ভঙ্গ;
	পক্ষ I_QUIT:
	পক্ষ I_PWD:
	পক্ষ I_LPWD:
	পক্ষ I_HELP:
	পক্ষ I_VERSION:
	পক্ষ I_PROGRESS:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			প্রত্যাগম -1;
		ভঙ্গ;
	স্বভাব:
		fatal("Command not implemented");
	}

	*cpp = cp;
	প্রত্যাগম(cmdnum);
}

স্থির পূর্ণাঙ্ক
parse_dispatch_command(সংরচনা sftp_conn *conn, ধ্রুব বর্ণ *cmd, বর্ণ **pwd,
    ধ্রুব বর্ণ *startdir, পূর্ণাঙ্ক err_abort, পূর্ণাঙ্ক echo_command)
{
	ধ্রুব বর্ণ *ocmd = cmd;
	বর্ণ *path1, *path2, *tmp;
	পূর্ণাঙ্ক ignore_errors = 0, disable_echo = 1;
	পূর্ণাঙ্ক aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	পূর্ণাঙ্ক lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	পূর্ণাঙ্ক cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	বর্ণ path_buf[PATH_MAX];
	পূর্ণাঙ্ক err = 0;
	glob_t g;

	path1 = path2 = রিক্ত;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	যদি (ignore_errors != 0)
		err_abort = 0;

	যদি (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, পরিমাণ(g));

	/* Perform command */
	বিকল্প (cmdnum) {
	পক্ষ 0:
		/* Blank line */
		ভঙ্গ;
	পক্ষ -1:
		/* Unrecognized command */
		err = -1;
		ভঙ্গ;
	পক্ষ I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	পক্ষ I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ভঙ্গ;
	পক্ষ I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	পক্ষ I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ভঙ্গ;
	পক্ষ I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		ভঙ্গ;
	পক্ষ I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		ভঙ্গ;
	পক্ষ I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	পক্ষ I_LINK:
		যদি (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		ভঙ্গ;
	পক্ষ I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, রিক্ত, &g);
		প্রতি (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			যদি (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			যদি (err != 0 && err_abort)
				ভঙ্গ;
		}
		ভঙ্গ;
	পক্ষ I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		যদি (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		অন্যথা
			err = sftp_mkdir(conn, path1, &a, 1);
		ভঙ্গ;
	পক্ষ I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		ভঙ্গ;
	পক্ষ I_CHDIR:
		যদি (path1 == রিক্ত || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		যদি ((tmp = sftp_realpath(conn, path1)) == রিক্ত) {
			err = 1;
			ভঙ্গ;
		}
		যদি (sftp_stat(conn, tmp, 0, &aa) != 0) {
			মুক্ত(tmp);
			err = 1;
			ভঙ্গ;
		}
		যদি (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			মুক্ত(tmp);
			err = 1;
			ভঙ্গ;
		}
		যদি (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			মুক্ত(tmp);
			err = 1;
			ভঙ্গ;
		}
		মুক্ত(*pwd);
		*pwd = tmp;
		ভঙ্গ;
	পক্ষ I_LS:
		যদি (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			ভঙ্গ;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = রিক্ত;
		যদি (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		ভঙ্গ;
	পক্ষ I_DF:
		/* Default to current directory if no path specified */
		যদি (path1 == রিক্ত)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		ভঙ্গ;
	পক্ষ I_LCHDIR:
		যদি (path1 == রিক্ত || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		মুক্ত(path1);
		path1 = tmp;
		যদি (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ভঙ্গ;
	পক্ষ I_LMKDIR:
		যদি (pflag) {
			যদি (mkdir_path(path1, 0777) != 0)
				err = 1;
			ভঙ্গ;
		}
		যদি (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ভঙ্গ;
	পক্ষ I_LLS:
		local_do_ls(cmd);
		ভঙ্গ;
	পক্ষ I_SHELL:
		local_do_shell(cmd);
		ভঙ্গ;
	পক্ষ I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		ভঙ্গ;
	পক্ষ I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, রিক্ত, &g);
		প্রতি (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			যদি (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			যদি (err != 0 && err_abort)
				ভঙ্গ;
		}
		ভঙ্গ;
	পক্ষ I_CHOWN:
	পক্ষ I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, রিক্ত, &g);
		প্রতি (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			যদি ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				যদি (err_abort) {
					err = -1;
					ভঙ্গ;
				} অন্যথা
					অনুবর্ত;
			}
			যদি (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				যদি (err_abort) {
					err = -1;
					ভঙ্গ;
				} অন্যথা
					অনুবর্ত;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			যদি (cmdnum == I_CHOWN) {
				যদি (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} অন্যথা {
				যদি (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			যদি (err != 0 && err_abort)
				ভঙ্গ;
		}
		ভঙ্গ;
	পক্ষ I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		ভঙ্গ;
	পক্ষ I_LPWD:
		যদি (!getcwd(path_buf, পরিমাণ(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			ভঙ্গ;
		}
		mprintf("Local working directory: %s\n", path_buf);
		ভঙ্গ;
	পক্ষ I_QUIT:
		/* Processed below */
		ভঙ্গ;
	পক্ষ I_HELP:
		help();
		ভঙ্গ;
	পক্ষ I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		ভঙ্গ;
	পক্ষ I_PROGRESS:
		showprogress = !showprogress;
		যদি (showprogress)
			printf("Progress meter enabled\n");
		অন্যথা
			printf("Progress meter disabled\n");
		ভঙ্গ;
	স্বভাব:
		fatal("%d is not implemented", cmdnum);
	}

	যদি (g.gl_pathc)
		globfree(&g);
	মুক্ত(path1);
	মুক্ত(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	যদি (err_abort && err != 0)
		প্রত্যাগম (-1);
	অন্যথা যদি (cmdnum == I_QUIT)
		প্রত্যাগম (1);

	প্রত্যাগম (0);
}

#ifdef USE_LIBEDIT
স্থির বর্ণ *
prompt(Edit_সারি *el)
{
	প্রত্যাগম ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
স্থির শূন্য
complete_display(বর্ণ **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	সংরচনা winsize ws;
	বর্ণ *tmp;

	/* Count entries for sort and find longest */
	প্রতি (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	যদি (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	প্রতি (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		যদি (m >= columns) {
			printf("\n");
			m = 1;
		} অন্যথা
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
স্থির বর্ণ *
complete_ambiguous(ধ্রুব বর্ণ *word, বর্ণ **list, size_t গুনতি)
{
	size_t i, j, matchlen;
	বর্ণ *tmp;
	পূর্ণাঙ্ক len;

	যদি (word == রিক্ত)
		প্রত্যাগম রিক্ত;

	যদি (গুনতি == 0)
		প্রত্যাগম xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	প্রতি (i = 1; i < গুনতি && list[i] != রিক্ত; i++) {
		প্রতি (j = 0; j < matchlen; j++)
			যদি (list[0][j] != list[i][j])
				ভঙ্গ;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(রিক্ত, 0);
	প্রতি (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		যদি (len <= 0 || i + (size_t)len > matchlen)
			ভঙ্গ;
		i += (size_t)len;
	}
	/* If so, truncate */
	যদি (i < matchlen)
		matchlen = i;

	যদি (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		প্রত্যাগম tmp;
	}

	প্রত্যাগম xstrdup(word);
}

/* Autocomplete a sftp command */
স্থির পূর্ণাঙ্ক
complete_cmd_parse(Edit_সারি *el, বর্ণ *cmd, পূর্ণাঙ্ক lastarg, বর্ণ quote,
    পূর্ণাঙ্ক terminated)
{
	u_int y, গুনতি = 0, cmdlen, tmplen;
	বর্ণ *tmp, **list, argterm[3];
	ধ্রুব সারি_Info *lf;

	list = xcalloc((পরিমাণ(cmds) / পরিমাণ(*cmds)) + 1, পরিমাণ(বর্ণ *));

	/* No command specified: display all available commands */
	যদি (cmd == রিক্ত) {
		প্রতি (y = 0; cmds[y].c; y++)
			list[গুনতি++] = xstrdup(cmds[y].c);

		list[গুনতি] = রিক্ত;
		complete_display(list, 0);

		প্রতি (y = 0; list[y] != রিক্ত; y++)
			মুক্ত(list[y]);
		মুক্ত(list);
		প্রত্যাগম গুনতি;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	প্রতি (y = 0; cmds[y].c; y++)  {
		যদি (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[গুনতি++] = xstrdup(cmds[y].c);
	}
	list[গুনতি] = রিক্ত;

	যদি (গুনতি == 0) {
		মুক্ত(list);
		প্রত্যাগম 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, গুনতি);
	যদি (গুনতি > 1)
		complete_display(list, 0);

	প্রতি (y = 0; list[y]; y++)
		মুক্ত(list[y]);
	মুক্ত(list);

	যদি (tmp != রিক্ত) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		যদি (tmplen > cmdlen)
			যদি (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_সারি(el);
		/* Terminate argument cleanly */
		যদি (গুনতি == 1) {
			y = 0;
			যদি (!terminated)
				argterm[y++] = quote;
			যদি (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			যদি (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		মুক্ত(tmp);
	}

	প্রত্যাগম গুনতি;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
স্থির পূর্ণাঙ্ক
complete_is_remote(বর্ণ *cmd, পূর্ণাঙ্ক cmdarg) {
	পূর্ণাঙ্ক i;

	যদি (cmd == রিক্ত)
		প্রত্যাগম -1;

	প্রতি (i = 0; cmds[i].c; i++) {
		যদি (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			যদি (cmdarg == 1)
				প্রত্যাগম cmds[i].t;
			অন্যথা যদি (cmdarg == 2)
				প্রত্যাগম cmds[i].t2;
			ভঙ্গ;
		}
	}

	প্রত্যাগম -1;
}

/* Autocomplete a filename "file" */
স্থির পূর্ণাঙ্ক
complete_match(Edit_সারি *el, সংরচনা sftp_conn *conn, বর্ণ *remote_path,
    বর্ণ *file, পূর্ণাঙ্ক remote, পূর্ণাঙ্ক lastarg, বর্ণ quote, পূর্ণাঙ্ক terminated)
{
	glob_t g;
	বর্ণ *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	পূর্ণাঙ্ক clen;
	ধ্রুব সারি_Info *lf;

	/* Glob from "file" location */
	যদি (file == রিক্ত)
		tmp = xstrdup("*");
	অন্যথা
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, পরিমাণ(g));
	যদি (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, রিক্ত, &g);
	} অন্যথা
		(শূন্য)glob(tmp, GLOB_DOOFFS|GLOB_MARK, রিক্ত, &g);

	/* Determine length of pwd so we can trim completion display */
	প্রতি (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		যদি (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			যদি (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			ভঙ্গ;
		}
		যদি (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		যদি (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	মুক্ত(tmp);
	tmp = রিক্ত;

	যদি (g.gl_matchc == 0)
		গচ্ছ out;

	যদি (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	যদি (file == রিক্ত || hadglob)
		গচ্ছ out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? রিক্ত : remote_path);
	মুক্ত(tmp2);

	যদি (tmp == রিক্ত)
		গচ্ছ out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	প্রতি (i = 0; i < filelen; i++) {
		যদি (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} অন্যথা
			isesc = 0;
	}

	যদি (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(রিক্ত, 0);
		প্রতি (i = 0; i < len; i += clen) {
			যদি ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > পরিমাণ(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			বিকল্প (tmp2[i]) {
			পক্ষ '\'':
			পক্ষ '"':
			পক্ষ '\\':
			পক্ষ '\t':
			পক্ষ '[':
			পক্ষ ' ':
			পক্ষ '#':
			পক্ষ '*':
				যদি (quote == '\0' || tmp2[i] == quote) {
					যদি (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					ভঙ্গ;
				}
				/* FALLTHROUGH */
			স্বভাব:
				যদি (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				ভঙ্গ;
			}
		}
	}

	lf = el_সারি(el);
	যদি (g.gl_matchc == 1) {
		i = 0;
		যদি (!terminated && quote != '\0')
			ins[i++] = quote;
		যদি (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		যদি (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	মুক্ত(tmp);

 out:
	globfree(&g);
	প্রত্যাগম g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
স্থির unsigned বর্ণ
complete(Edit_সারি *el, পূর্ণাঙ্ক ch)
{
	বর্ণ **argv, *সারি, quote;
	পূর্ণাঙ্ক argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ধ্রুব সারি_Info *lf;
	সংরচনা complete_ctx *complete_ctx;

	lf = el_সারি(el);
	যদি (el_get(el, EL_CLIENTDATA, (শূন্য**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	সারি = xmalloc(cursor + 1);
	memcpy(সারি, lf->buffer, cursor);
	সারি[cursor] = '\0';
	argv = makeargv(সারি, &carg, 1, &quote, &terminated);
	মুক্ত(সারি);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	সারি = xmalloc(len + 1);
	memcpy(সারি, lf->buffer, len);
	সারি[len] = '\0';
	argv = makeargv(সারি, &argc, 1, রিক্ত, রিক্ত);

	/* Ensure cursor is at EOL or a argument boundary */
	যদি (সারি[cursor] != ' ' && সারি[cursor] != '\0' &&
	    সারি[cursor] != '\n') {
		মুক্ত(সারি);
		প্রত্যাগম ret;
	}

	যদি (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, রিক্ত, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} অন্যথা যদি (carg == 1 && cursor > 0 && সারি[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		যদি (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} অন্যথা যদি (carg >= 1) {
		/* Handle file parsing */
		পূর্ণাঙ্ক remote = 0;
		পূর্ণাঙ্ক i = 0, cmdarg = 0;
		বর্ণ *filematch = রিক্ত;

		যদি (carg > 1 && সারি[cursor-1] != ' ')
			filematch = argv[carg - 1];

		প্রতি (i = 1; i < carg; i++) {
			/* Skip flags */
			যদি (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		যদি (সারি[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		যদি ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	মুক্ত(সারি);
	প্রত্যাগম ret;
}
#endif /* USE_LIBEDIT */

স্থির পূর্ণাঙ্ক
interactive_loop(সংরচনা sftp_conn *conn, বর্ণ *file1, বর্ণ *file2)
{
	বর্ণ *remote_path;
	বর্ণ *dir = রিক্ত, *startdir = রিক্ত;
	বর্ণ cmd[2048];
	পূর্ণাঙ্ক err, interactive;
	Edit_সারি *el = রিক্ত;
#ifdef USE_LIBEDIT
	ধ্রুব বর্ণ *editor;
	History *hl = রিক্ত;
	HistEvent hev;
	বাহ্য বর্ণ *__progname;
	সংরচনা complete_ctx complete_ctx;

	যদি (!batchmode && isatty(STDIN_FILENO)) {
		যদি ((el = el_init(__progname, stdin, stdout, stderr)) == রিক্ত)
			fatal("Couldn't initialise editline");
		যদি ((hl = history_init()) == রিক্ত)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, রিক্ত);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, রিক্ত);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (শূন্য*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", রিক্ত);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", রিক্ত);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", রিক্ত);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", রিক্ত);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", রিক্ত);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", রিক্ত);

		/* el_source() may have changed EL_EDITOR to vi */
		যদি (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", রিক্ত);
	}
#endif /* USE_LIBEDIT */

	যদি ((remote_path = sftp_realpath(conn, ".")) == রিক্ত)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	যদি (file1 != রিক্ত) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		যদি (sftp_remote_is_dir(conn, dir) && file2 == রিক্ত) {
			যদি (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, পরিমাণ cmd, "cd \"%s\"", dir);
			যদি (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				মুক্ত(dir);
				মুক্ত(startdir);
				মুক্ত(remote_path);
				মুক্ত(conn);
				প্রত্যাগম (-1);
			}
		} অন্যথা {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			মুক্ত(dir);
			মুক্ত(startdir);
			মুক্ত(remote_path);
			মুক্ত(conn);
			প্রত্যাগম (err);
		}
		মুক্ত(dir);
	}

	setvbuf(stdout, রিক্ত, _IOLBF, 0);
	setvbuf(infile, রিক্ত, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	প্রতি (;;) {
		সংরচনা sigaction sa;

		interrupted = 0;
		memset(&sa, 0, পরিমাণ(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		যদি (sigaction(SIGINT, &sa, রিক্ত) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			ভঙ্গ;
		}
		যদি (el == রিক্ত) {
			যদি (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			যদি (fgets(cmd, পরিমাণ(cmd), infile) == রিক্ত) {
				যদি (interactive)
					printf("\n");
				যদি (interrupted)
					অনুবর্ত;
				ভঙ্গ;
			}
		} অন্যথা {
#ifdef USE_LIBEDIT
			ধ্রুব বর্ণ *সারি;
			পূর্ণাঙ্ক গুনতি = 0;

			যদি ((সারি = el_gets(el, &গুনতি)) == রিক্ত ||
			    গুনতি <= 0) {
				printf("\n");
				যদি (interrupted)
					অনুবর্ত;
				ভঙ্গ;
			}
			history(hl, &hev, H_ENTER, সারি);
			যদি (strlcpy(cmd, সারি, পরিমাণ(cmd)) >= পরিমাণ(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				অনুবর্ত;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == রিক্ত);
		যদি (err != 0)
			ভঙ্গ;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	মুক্ত(remote_path);
	মুক্ত(startdir);
	মুক্ত(conn);

#ifdef USE_LIBEDIT
	যদি (hl != রিক্ত)
		history_end(hl);
	যদি (el != রিক্ত)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	প্রত্যাগম (err >= 0 ? 0 : -1);
}

স্থির শূন্য
connect_to_server(বর্ণ *path, বর্ণ **args, পূর্ণাঙ্ক *in, পূর্ণাঙ্ক *out)
{
	পূর্ণাঙ্ক c_in, c_out;
#ifdef USE_PIPES
	পূর্ণাঙ্ক pin[2], pout[2];

	যদি ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#অন্যথা /* USE_PIPES */
	পূর্ণাঙ্ক inout[2];

	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	যদি ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	অন্যথা যদি (sshpid == 0) {
		যদি ((dup2(c_in, STDIN_FILENO) == -1) ||
		    (dup2(c_out, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*in);
		close(*out);
		close(c_in);
		close(c_out);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(path, args);
		fprintf(stderr, "exec: %s: %s\n", path, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_in);
	close(c_out);
}

স্থির শূন্য
usage(শূন্য)
{
	বাহ্য বর্ণ *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

পূর্ণাঙ্ক
main(পূর্ণাঙ্ক argc, বর্ণ **argv)
{
	পূর্ণাঙ্ক r, in, out, ch, err, tmp, port = -1, noisy = 0;
	বর্ণ *host = রিক্ত, *user, *cp, **cpp, *file2 = রিক্ত;
	পূর্ণাঙ্ক debug_level = 0;
	বর্ণ *file1 = রিক্ত, *sftp_server = রিক্ত;
	বর্ণ *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = রিক্ত;
	ধ্রুব বর্ণ *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	বাহ্য পূর্ণাঙ্ক optind;
	বাহ্য বর্ণ *optarg;
	সংরচনা sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t অঙ্ক_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', পরিমাণ(args));
	args.list = রিক্ত;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	যাবত্ ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		বিকল্প (ch) {
		/* Passed through to ssh(1) */
		পক্ষ 'A':
		পক্ষ '4':
		পক্ষ '6':
		পক্ষ 'C':
			addargs(&args, "-%c", ch);
			ভঙ্গ;
		/* Passed through to ssh(1) with argument */
		পক্ষ 'F':
		পক্ষ 'J':
		পক্ষ 'c':
		পক্ষ 'i':
		পক্ষ 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			ভঙ্গ;
		পক্ষ 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			ভঙ্গ;
		পক্ষ 'P':
			port = a2port(optarg);
			যদি (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			ভঙ্গ;
		পক্ষ 'v':
			যদি (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			ভঙ্গ;
		পক্ষ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ভঙ্গ;
		পক্ষ '2':
			/* accept silently */
			ভঙ্গ;
		পক্ষ 'a':
			global_aflag = 1;
			ভঙ্গ;
		পক্ষ 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			যদি (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			ভঙ্গ;
		পক্ষ 'b':
			যদি (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			যদি (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == রিক্ত)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			ভঙ্গ;
		পক্ষ 'f':
			global_fflag = 1;
			ভঙ্গ;
		পক্ষ 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			ভঙ্গ;
		পক্ষ 'p':
			global_pflag = 1;
			ভঙ্গ;
		পক্ষ 'D':
			sftp_direct = optarg;
			ভঙ্গ;
		পক্ষ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			যদি (errstr != রিক্ত)
				usage();
			limit_kbps *= 1024; /* kbps */
			ভঙ্গ;
		পক্ষ 'r':
			global_rflag = 1;
			ভঙ্গ;
		পক্ষ 'R':
			অঙ্ক_requests = strtol(optarg, &cp, 10);
			যদি (অঙ্ক_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			ভঙ্গ;
		পক্ষ 's':
			sftp_server = optarg;
			ভঙ্গ;
		পক্ষ 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			ভঙ্গ;
		পক্ষ 'X':
			/* Please keep in sync with ssh.c -X */
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
				copy_buffer_len = (size_t)llv;
			} অন্যথা যদি (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				যদি (errstr != রিক্ত) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				অঙ্ক_requests = (size_t)llv;
			} অন্যথা {
				fatal("Invalid -X option");
			}
			ভঙ্গ;
		পক্ষ 'h':
		স্বভাব:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	যদি (!isatty(STDERR_FILENO))
		showprogress = 0;

	যদি (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	যদি (sftp_direct == রিক্ত) {
		যদি (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		বিকল্প (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		পক্ষ -1:
			usage();
			ভঙ্গ;
		পক্ষ 0:
			যদি (tmp != -1)
				port = tmp;
			ভঙ্গ;
		স্বভাব:
			/* Try with user, host and path. */
			যদি (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				ভঙ্গ;
			/* Try with user and host. */
			যদি (parse_user_host_port(*argv, &user, &host, রিক্ত)
			    == 0)
				ভঙ্গ;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			ভঙ্গ;
		}
		file2 = *(argv + 1);

		যদি (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		যদি (port != -1)
			addargs(&args, "-oPort %d", port);
		যদি (user != রিক্ত) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		যদি (sftp_server == রিক্ত || strchr(sftp_server, '/') == রিক্ত)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != রিক্ত ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} অন্যথা {
		যদি ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		যদি (cpp[0] == রিক্ত)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, অঙ্ক_requests, limit_kbps);
	যদি (conn == রিক্ত)
		fatal("Couldn't initialise connection to server");

	যদি (!quiet) {
		যদি (sftp_direct == রিক্ত)
			fprintf(stderr, "Connected to %s.\n", host);
		অন্যথা
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#যদি !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	যদি (batchmode)
		fclose(infile);

	যাবত্ (waitpid(sshpid, রিক্ত, 0) == -1 && sshpid > 1)
		যদি (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
