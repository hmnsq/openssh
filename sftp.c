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
প্রকারলেখ শূন্য Edit_সারি;
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
পূর্ণসংখ্যা batchmode = 0;

/* PID of ssh transport process */
স্থির অস্থির pid_t sshpid = -1;

/* Suppress diagnostic messages */
পূর্ণসংখ্যা quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
পূর্ণসংখ্যা showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
পূর্ণসংখ্যা global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
পূর্ণসংখ্যা global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
পূর্ণসংখ্যা global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
পূর্ণসংখ্যা global_fflag = 0;

/* SIGINT received during command processing */
অস্থির sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
পূর্ণসংখ্যা sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
কাঠামো complete_ctx {
	কাঠামো sftp_conn *conn;
	অক্ষর **remote_pathp;
};

পূর্ণসংখ্যা sftp_glob(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা,
    পূর্ণসংখ্যা (*)(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা), glob_t *); /* proto for sftp-glob.c */

বাহ্যিক অক্ষর *__progname;

/* Separators for interactive commands */
#define WHITESPACE " \t\r\n"

/* ls flags */
#define LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#define LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#define LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#define LS_NAME_SORT	0x0008	/* Sort by name (default) */
#define LS_TIME_SORT	0x0010	/* Sort by mtime */
#define LS_আকার_SORT	0x0020	/* Sort by file size */
#define LS_REVERSE_SORT	0x0040	/* Reverse sort order */
#define LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#define LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#define VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#define SORT_FLAGS	(LS_NAME_SORT|LS_TIME_SORT|LS_আকার_SORT)

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

কাঠামো CMD {
	ধ্রুবক অক্ষর *c;
	ধ্রুবক পূর্ণসংখ্যা n;
	ধ্রুবক পূর্ণসংখ্যা t;	/* Completion type for the first argument */
	ধ্রুবক পূর্ণসংখ্যা t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

স্থির ধ্রুবক কাঠামো CMD cmds[] = {
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
	{ ফাঁকা,		-1,		-1,		-1	}
};

স্থির শূন্য
killchild(পূর্ণসংখ্যা signo)
{
	pid_t pid;

	pid = sshpid;
	যদি (pid > 1) {
		kill(pid, SIGTERM);
		(শূন্য)waitpid(pid, ফাঁকা, 0);
	}

	_exit(1);
}

স্থির শূন্য
suspchild(পূর্ণসংখ্যা signo)
{
	পূর্ণসংখ্যা save_errno = errno;
	যদি (sshpid > 1) {
		kill(sshpid, signo);
		যখন (waitpid(sshpid, ফাঁকা, WUNTRACED) == -1 && errno == EINTR)
			চালু;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

স্থির শূন্য
cmd_interrupt(পূর্ণসংখ্যা signo)
{
	ধ্রুবক অক্ষর বার্তা[] = "\rInterrupt  \n";
	পূর্ণসংখ্যা olderrno = errno;

	(শূন্য)লিখ(STDERR_FILENO, বার্তা, আকার(বার্তা) - 1);
	interrupted = 1;
	errno = olderrno;
}

স্থির শূন্য
read_interrupt(পূর্ণসংখ্যা signo)
{
	interrupted = 1;
}

স্থির শূন্য
sigchld_handler(পূর্ণসংখ্যা sig)
{
	পূর্ণসংখ্যা save_errno = errno;
	pid_t pid;
	ধ্রুবক অক্ষর বার্তা[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	যখন ((pid = waitpid(sshpid, ফাঁকা, WNOHANG)) == -1 && errno == EINTR)
		চালু;
	যদি (pid == sshpid) {
		যদি (!quiet)
		    (শূন্য)লিখ(STDERR_FILENO, বার্তা, আকার(বার্তা) - 1);
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
local_do_shell(ধ্রুবক অক্ষর *args)
{
	পূর্ণসংখ্যা status;
	অক্ষর *shell;
	pid_t pid;

	যদি (!*args)
		args = ফাঁকা;

	যদি ((shell = getenv("SHELL")) == ফাঁকা || *shell == '\0')
		shell = _PATH_BSHELL;

	যদি ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	যদি (pid == 0) {
		যদি (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (অক্ষর *)ফাঁকা);
		} অন্যথা {
			debug3("Executing %s", shell);
			execl(shell, shell, (অক্ষর *)ফাঁকা);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	যখন (waitpid(pid, &status, 0) == -1)
		যদি (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	যদি (!WIFEXITED(status))
		error("Shell exited abnormally");
	অন্যথা যদি (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

স্থির শূন্য
local_do_ls(ধ্রুবক অক্ষর *args)
{
	যদি (!args || !*args)
		local_do_shell(_PATH_LS);
	অন্যথা {
		পূর্ণসংখ্যা len = strlen(_PATH_LS " ") + strlen(args) + 1;
		অক্ষর *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		মুক্ত(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
স্থির অক্ষর *
path_strip(ধ্রুবক অক্ষর *path, ধ্রুবক অক্ষর *strip)
{
	আকার_t len;

	যদি (strip == ফাঁকা || (len = strlen(strip)) == 0)
		ফেরত (xstrdup(path));

	যদি (strncmp(path, strip, len) == 0) {
		যদি (strip[len - 1] != '/' && path[len] == '/')
			len++;
		ফেরত (xstrdup(path + len));
	}

	ফেরত (xstrdup(path));
}

স্থির পূর্ণসংখ্যা
parse_getput_flags(ধ্রুবক অক্ষর *cmd, অক্ষর **argv, পূর্ণসংখ্যা argc,
    পূর্ণসংখ্যা *aflag, পূর্ণসংখ্যা *fflag, পূর্ণসংখ্যা *pflag, পূর্ণসংখ্যা *rflag)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	যখন ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'a':
			*aflag = 1;
			বিরতি;
		ক্ষেত্র 'f':
			*fflag = 1;
			বিরতি;
		ক্ষেত্র 'p':
		ক্ষেত্র 'P':
			*pflag = 1;
			বিরতি;
		ক্ষেত্র 'r':
		ক্ষেত্র 'R':
			*rflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			error("%s: Invalid flag -%c", cmd, optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির পূর্ণসংখ্যা
parse_mkdir_flags(ধ্রুবক অক্ষর *cmd, অক্ষর **argv, পূর্ণসংখ্যা argc, পূর্ণসংখ্যা *pflag)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	যখন ((ch = getopt(argc, argv, "p")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'p':
			*pflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			error("%s: Invalid flag -%c", cmd, optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির পূর্ণসংখ্যা
parse_link_flags(ধ্রুবক অক্ষর *cmd, অক্ষর **argv, পূর্ণসংখ্যা argc, পূর্ণসংখ্যা *sflag)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	যখন ((ch = getopt(argc, argv, "s")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 's':
			*sflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			error("%s: Invalid flag -%c", cmd, optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির পূর্ণসংখ্যা
parse_rename_flags(ধ্রুবক অক্ষর *cmd, অক্ষর **argv, পূর্ণসংখ্যা argc, পূর্ণসংখ্যা *lflag)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	যখন ((ch = getopt(argc, argv, "l")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'l':
			*lflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			error("%s: Invalid flag -%c", cmd, optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির পূর্ণসংখ্যা
parse_ls_flags(অক্ষর **argv, পূর্ণসংখ্যা argc, পূর্ণসংখ্যা *lflag)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	যখন ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			বিরতি;
		ক্ষেত্র 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_আকার_SORT;
			বিরতি;
		ক্ষেত্র 'a':
			*lflag |= LS_SHOW_ALL;
			বিরতি;
		ক্ষেত্র 'f':
			*lflag &= ~SORT_FLAGS;
			বিরতি;
		ক্ষেত্র 'h':
			*lflag |= LS_SI_UNITS;
			বিরতি;
		ক্ষেত্র 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			বিরতি;
		ক্ষেত্র 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			বিরতি;
		ক্ষেত্র 'r':
			*lflag |= LS_REVERSE_SORT;
			বিরতি;
		ক্ষেত্র 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			বিরতি;
		পূর্বনির্ধারিত:
			error("ls: Invalid flag -%c", optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির পূর্ণসংখ্যা
parse_df_flags(ধ্রুবক অক্ষর *cmd, অক্ষর **argv, পূর্ণসংখ্যা argc, পূর্ণসংখ্যা *hflag, পূর্ণসংখ্যা *iflag)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	যখন ((ch = getopt(argc, argv, "hi")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'h':
			*hflag = 1;
			বিরতি;
		ক্ষেত্র 'i':
			*iflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			error("%s: Invalid flag -%c", cmd, optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির পূর্ণসংখ্যা
parse_ch_flags(ধ্রুবক অক্ষর *cmd, অক্ষর **argv, পূর্ণসংখ্যা argc, পূর্ণসংখ্যা *hflag)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	যখন ((ch = getopt(argc, argv, "h")) != -1) {
		নির্বাচন (ch) {
		ক্ষেত্র 'h':
			*hflag = 1;
			বিরতি;
		পূর্বনির্ধারিত:
			error("%s: Invalid flag -%c", cmd, optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির পূর্ণসংখ্যা
parse_no_flags(ধ্রুবক অক্ষর *cmd, অক্ষর **argv, পূর্ণসংখ্যা argc)
{
	বাহ্যিক পূর্ণসংখ্যা opterr, optind, optopt, optreset;
	পূর্ণসংখ্যা ch;

	optind = optreset = 1;
	opterr = 0;

	যখন ((ch = getopt(argc, argv, "")) != -1) {
		নির্বাচন (ch) {
		পূর্বনির্ধারিত:
			error("%s: Invalid flag -%c", cmd, optopt);
			ফেরত -1;
		}
	}

	ফেরত optind;
}

স্থির অক্ষর *
escape_glob(ধ্রুবক অক্ষর *s)
{
	আকার_t i, o, len;
	অক্ষর *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	জন্য (i = o = 0; i < len; i++) {
		যদি (strchr("[]?*\\", s[i]) != ফাঁকা)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	ফেরত ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
স্থির অক্ষর *
make_absolute_pwd_glob(অক্ষর *p, ধ্রুবক অক্ষর *pwd)
{
	অক্ষর *ret, *escpwd;

	escpwd = escape_glob(pwd);
	যদি (p == ফাঁকা)
		ফেরত escpwd;
	ret = sftp_make_absolute(p, escpwd);
	মুক্ত(escpwd);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
local_is_dir(ধ্রুবক অক্ষর *path)
{
	কাঠামো stat sb;

	যদি (stat(path, &sb) == -1)
		ফেরত 0;
	ফেরত S_ISDIR(sb.st_mode);
}

স্থির পূর্ণসংখ্যা
process_get(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *src, ধ্রুবক অক্ষর *dst,
    ধ্রুবক অক্ষর *pwd, পূর্ণসংখ্যা pflag, পূর্ণসংখ্যা rflag, পূর্ণসংখ্যা resume, পূর্ণসংখ্যা fflag)
{
	অক্ষর *filename, *abs_src = ফাঁকা, *abs_dst = ফাঁকা, *tmp = ফাঁকা;
	glob_t g;
	পূর্ণসংখ্যা i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, আকার(g));

	debug3("Looking up %s", abs_src);
	যদি ((r = sftp_glob(conn, abs_src, GLOB_MARK, ফাঁকা, &g)) != 0) {
		যদি (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} অন্যথা {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		যাও out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	যদি (g.gl_matchc > 1 && dst != ফাঁকা && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		যাও out;
	}

	জন্য (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == ফাঁকা) {
			error("basename %s: %s", tmp, strerror(errno));
			মুক্ত(tmp);
			err = -1;
			যাও out;
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
			    ফাঁকা, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} অন্যথা {
			যদি (sftp_download(conn, g.gl_pathv[i], abs_dst, ফাঁকা,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		মুক্ত(abs_dst);
		abs_dst = ফাঁকা;
	}

out:
	মুক্ত(abs_src);
	globfree(&g);
	ফেরত(err);
}

স্থির পূর্ণসংখ্যা
process_put(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *src, ধ্রুবক অক্ষর *dst,
    ধ্রুবক অক্ষর *pwd, পূর্ণসংখ্যা pflag, পূর্ণসংখ্যা rflag, পূর্ণসংখ্যা resume, পূর্ণসংখ্যা fflag)
{
	অক্ষর *tmp_dst = ফাঁকা;
	অক্ষর *abs_dst = ফাঁকা;
	অক্ষর *tmp = ফাঁকা, *filename = ফাঁকা;
	glob_t g;
	পূর্ণসংখ্যা err = 0;
	পূর্ণসংখ্যা i, dst_is_dir = 1;
	কাঠামো stat sb;

	যদি (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, আকার(g));
	debug3("Looking up %s", src);
	যদি (glob(src, GLOB_NOCHECK | GLOB_MARK, ফাঁকা, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		যাও out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	যদি (tmp_dst != ফাঁকা)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	যদি (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		যাও out;
	}

	জন্য (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		যদি (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			চালু;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		যদি ((filename = basename(tmp)) == ফাঁকা) {
			error("basename %s: %s", tmp, strerror(errno));
			মুক্ত(tmp);
			err = -1;
			যাও out;
		}
		/* Special handling for source of '..' */
		যদি (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		মুক্ত(abs_dst);
		abs_dst = ফাঁকা;
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
	ফেরত(err);
}

স্থির পূর্ণসংখ্যা
sdirent_comp(ধ্রুবক শূন্য *aa, ধ্রুবক শূন্য *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	পূর্ণসংখ্যা rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	যদি (sort_flag & LS_NAME_SORT)
		ফেরত (rmul * strcmp(a->filename, b->filename));
	অন্যথা যদি (sort_flag & LS_TIME_SORT)
		ফেরত (rmul * NCMP(a->a.mtime, b->a.mtime));
	অন্যথা যদি (sort_flag & LS_আকার_SORT)
		ফেরত (rmul * NCMP(a->a.আকার_2, b->a.আকার_2));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
স্থির পূর্ণসংখ্যা
do_ls_dir(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path,
    ধ্রুবক অক্ষর *strip_path, পূর্ণসংখ্যা lflag)
{
	পূর্ণসংখ্যা n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	যদি ((n = sftp_readdir(conn, path, &d)) != 0)
		ফেরত (n);

	যদি (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		কাঠামো winsize ws;
		অক্ষর *tmp;

		/* Count entries for sort and find longest filename */
		জন্য (n = 0; d[n] != ফাঁকা; n++) {
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
		জন্য (n = 0; d[n] != ফাঁকা; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, আকার(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	জন্য (n = 0; d[n] != ফাঁকা && !interrupted; n++) {
		অক্ষর *tmp, *fname;

		যদি (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			চালু;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		মুক্ত(tmp);

		যদি (lflag & LS_LONG_VIEW) {
			যদি ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				অক্ষর *lname;
				কাঠামো stat sb;
				ধ্রুবক অক্ষর *user = ফাঁকা, *group = ফাঁকা;

				memset(&sb, 0, আকার(sb));
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
	ফেরত (0);
}

স্থির পূর্ণসংখ্যা
sglob_comp(ধ্রুবক শূন্য *aa, ধ্রুবক শূন্য *bb)
{
	u_int a = *(ধ্রুবক u_int *)aa;
	u_int b = *(ধ্রুবক u_int *)bb;
	ধ্রুবক অক্ষর *ap = sort_glob->gl_pathv[a];
	ধ্রুবক অক্ষর *bp = sort_glob->gl_pathv[b];
	ধ্রুবক কাঠামো stat *as = sort_glob->gl_statv[a];
	ধ্রুবক কাঠামো stat *bs = sort_glob->gl_statv[b];
	পূর্ণসংখ্যা rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	যদি (as == ফাঁকা || bs == ফাঁকা)
		ফেরত (as == bs) ? 0 : (as == ফাঁকা ? rmul : -rmul);
	যদি (sort_flag & LS_NAME_SORT)
		ফেরত (rmul * strcmp(ap, bp));
	অন্যথা যদি (sort_flag & LS_TIME_SORT) {
#যদি defined(HAVE_STRUCT_STAT_ST_MTIM)
		যদি (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			ফেরত 0;
		ফেরত timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#নতুবা_যদি defined(HAVE_STRUCT_STAT_ST_MTIME)
		ফেরত (rmul * NCMP(as->st_mtime, bs->st_mtime));
#অন্যথা
	ফেরত rmul * 1;
#endif
	} অন্যথা যদি (sort_flag & LS_আকার_SORT)
		ফেরত (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
স্থির পূর্ণসংখ্যা
do_globbed_ls(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path,
    ধ্রুবক অক্ষর *strip_path, পূর্ণসংখ্যা lflag)
{
	অক্ষর *fname, *lname;
	glob_t g;
	পূর্ণসংখ্যা err, r;
	কাঠামো winsize ws;
	u_int i, j, nentries, *indices = ফাঁকা, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, আকার(g));

	যদি ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ফাঁকা, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		যদি (g.gl_pathc)
			globfree(&g);
		যদি (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} অন্যথা {
			error("Can't ls: \"%s\" not found", path);
		}
		ফেরত -1;
	}

	যদি (interrupted)
		যাও out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	যদি (g.gl_matchc == 1 && g.gl_statv[0] != ফাঁকা &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		ফেরত err;
	}

	যদি (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	যদি (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		জন্য (i = 0; g.gl_pathv[i]; i++)
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
	জন্য (nentries = 0; g.gl_pathv[nentries] != ফাঁকা; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, আকার(*indices));
	জন্য (i = 0; i < nentries; i++)
		indices[i] = i;

	যদি (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, আকার(*indices), sglob_comp);
		sort_glob = ফাঁকা;
	}

	get_remote_user_groups_from_glob(conn, &g);
	জন্য (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		যদি (lflag & LS_LONG_VIEW) {
			ধ্রুবক অক্ষর *user = ফাঁকা, *group = ফাঁকা;

			যদি (g.gl_statv[i] == ফাঁকা) {
				error("no stat information for %s", fname);
				মুক্ত(fname);
				চালু;
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

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
do_df(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা hflag, পূর্ণসংখ্যা iflag)
{
	কাঠামো sftp_statvfs st;
	অক্ষর s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	অক্ষর s_মূল[FMT_SCALED_STRSIZE], s_যোগ[FMT_SCALED_STRSIZE];
	অক্ষর s_icapacity[16], s_dcapacity[16];

	যদি (sftp_statvfs(conn, path, &st, 1) == -1)
		ফেরত -1;
	যদি (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", আকার(s_icapacity));
	অন্যথা {
		snprintf(s_icapacity, আকার(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	যদি (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", আকার(s_dcapacity));
	অন্যথা {
		snprintf(s_dcapacity, আকার(s_dcapacity), "%3llu%%",
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
		strlcpy(s_used, "error", আকার(s_used));
		strlcpy(s_avail, "error", আকার(s_avail));
		strlcpy(s_মূল, "error", আকার(s_মূল));
		strlcpy(s_যোগ, "error", আকার(s_যোগ));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_মূল);
		fmt_scaled(st.f_blocks * st.f_frsize, s_যোগ);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_যোগ, s_used, s_avail, s_মূল, s_dcapacity);
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
	ফেরত 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
স্থির শূন্য
undo_glob_escape(অক্ষর *s)
{
	আকার_t i, j;

	জন্য (i = j = 0;;) {
		যদি (s[i] == '\0') {
			s[j] = '\0';
			ফেরত;
		}
		যদি (s[i] != '\\') {
			s[j++] = s[i++];
			চালু;
		}
		/* s[i] == '\\' */
		++i;
		নির্বাচন (s[i]) {
		ক্ষেত্র '?':
		ক্ষেত্র '[':
		ক্ষেত্র '*':
		ক্ষেত্র '\\':
			s[j++] = s[i++];
			বিরতি;
		ক্ষেত্র '\0':
			s[j++] = '\\';
			s[j] = '\0';
			ফেরত;
		পূর্বনির্ধারিত:
			s[j++] = '\\';
			s[j++] = s[i++];
			বিরতি;
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
স্থির অক্ষর **
makeargv(ধ্রুবক অক্ষর *arg, পূর্ণসংখ্যা *argcp, পূর্ণসংখ্যা sloppy, অক্ষর *lastquote,
    u_int *terminated)
{
	পূর্ণসংখ্যা argc, quot;
	আকার_t i, j;
	স্থির অক্ষর argvs[MAXARGLEN];
	স্থির অক্ষর *argv[MAXARGS + 1];
	গণনা { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	যদি (strlen(arg) > আকার(argvs) - 1) {
 args_too_longs:
		error("string too long");
		ফেরত ফাঁকা;
	}
	যদি (terminated != ফাঁকা)
		*terminated = 1;
	যদি (lastquote != ফাঁকা)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	জন্য (;;) {
		যদি ((আকার_t)argc >= আকার(argv) / আকার(*argv)){
			error("Too many arguments.");
			ফেরত ফাঁকা;
		}
		যদি (isspace((unsigned অক্ষর)arg[i])) {
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
				যদি (lastquote != ফাঁকা)
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
					যদি (j >= আকার(argvs) - 5)
						যাও args_too_longs;
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
					যদি (lastquote != ফাঁকা)
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
						যাও early_nul;
					argvs[j++] = arg[i];
				}
			}
		} অন্যথা যদি (arg[i] == '#') {
			যদি (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			অন্যথা
				যাও string_done;
		} অন্যথা যদি (arg[i] == '\0') {
			যদি (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				যদি (sloppy) {
					state = MA_UNQUOTED;
					যদি (terminated != ফাঁকা)
						*terminated = 0;
					যাও string_done;
				}
				error("Unterminated quoted argument");
				ফেরত ফাঁকা;
			}
 string_done:
			যদি (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			বিরতি;
		} অন্যথা {
			যদি (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				যদি (lastquote != ফাঁকা)
					*lastquote = '\0';
			}
			যদি ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				যদি (j >= আকার(argvs) - 3)
					যাও args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} অন্যথা
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	ফেরত argv;
}

স্থির পূর্ণসংখ্যা
parse_args(ধ্রুবক অক্ষর **cpp, পূর্ণসংখ্যা *ignore_errors, পূর্ণসংখ্যা *disable_echo, পূর্ণসংখ্যা *aflag,
	  পূর্ণসংখ্যা *fflag, পূর্ণসংখ্যা *hflag, পূর্ণসংখ্যা *iflag, পূর্ণসংখ্যা *lflag, পূর্ণসংখ্যা *pflag,
	  পূর্ণসংখ্যা *rflag, পূর্ণসংখ্যা *sflag,
    unsigned long *n_arg, অক্ষর **path1, অক্ষর **path2)
{
	ধ্রুবক অক্ষর *cmd, *cp = *cpp;
	অক্ষর *cp2, **argv;
	পূর্ণসংখ্যা base = 0;
	long long ll;
	পূর্ণসংখ্যা path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	জন্য (;*cp != '\0'; cp++) {
		যদি (*cp == '-') {
			*ignore_errors = 1;
		} অন্যথা যদি (*cp == '@') {
			*disable_echo = 1;
		} অন্যথা {
			/* all other characters terminate prefix processing */
			বিরতি;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	যদি (*cp == '\0' || *cp == '#')
		ফেরত (0);

	যদি ((argv = makeargv(cp, &argc, 0, ফাঁকা, ফাঁকা)) == ফাঁকা)
		ফেরত -1;

	/* Figure out which command we have */
	জন্য (i = 0; cmds[i].c != ফাঁকা; i++) {
		যদি (argv[0] != ফাঁকা && strcasecmp(cmds[i].c, argv[0]) == 0)
			বিরতি;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	যদি (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} অন্যথা যদি (cmdnum == -1) {
		error("Invalid command.");
		ফেরত -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ফাঁকা;
	optidx = 1;
	নির্বাচন (cmdnum) {
	ক্ষেত্র I_GET:
	ক্ষেত্র I_REGET:
	ক্ষেত্র I_REPUT:
	ক্ষেত্র I_PUT:
		যদি ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			ফেরত -1;
		/* Get first pathname (mandatory) */
		যদি (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			ফেরত -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		যদি (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		বিরতি;
	ক্ষেত্র I_LINK:
		যদি ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			ফেরত -1;
		যাও parse_two_paths;
	ক্ষেত্র I_COPY:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ফেরত -1;
		যাও parse_two_paths;
	ক্ষেত্র I_RENAME:
		যদি ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			ফেরত -1;
		যাও parse_two_paths;
	ক্ষেত্র I_SYMLINK:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ফেরত -1;
 parse_two_paths:
		যদি (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			ফেরত -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		বিরতি;
	ক্ষেত্র I_MKDIR:
	ক্ষেত্র I_LMKDIR:
		যদি ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			ফেরত -1;
		path1_mandatory = 1;
		যাও parse_one_path;
	ক্ষেত্র I_RM:
	ক্ষেত্র I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	ক্ষেত্র I_CHDIR:
	ক্ষেত্র I_LCHDIR:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ফেরত -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		যদি (argc - optidx < 1) {
			যদি (!path1_mandatory)
				বিরতি; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			ফেরত -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		যদি (cmdnum != I_RM)
			undo_glob_escape(*path1);
		বিরতি;
	ক্ষেত্র I_DF:
		যদি ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			ফেরত -1;
		/* Default to current directory if no path specified */
		যদি (argc - optidx < 1)
			*path1 = ফাঁকা;
		অন্যথা {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		বিরতি;
	ক্ষেত্র I_LS:
		যদি ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			ফেরত(-1);
		/* Path is optional */
		যদি (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		বিরতি;
	ক্ষেত্র I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	ক্ষেত্র I_SHELL:
		/* Uses the rest of the line */
		বিরতি;
	ক্ষেত্র I_LUMASK:
	ক্ষেত্র I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	ক্ষেত্র I_CHOWN:
	ক্ষেত্র I_CHGRP:
		যদি ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			ফেরত -1;
		/* Get numeric arg (mandatory) */
		যদি (argc - optidx < 1)
			যাও need_অঙ্ক_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		যদি (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_অঙ্ক_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			ফেরত -1;
		}
		*n_arg = ll;
		যদি (cmdnum == I_LUMASK)
			বিরতি;
		/* Get pathname (mandatory) */
		যদি (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			ফেরত -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		বিরতি;
	ক্ষেত্র I_QUIT:
	ক্ষেত্র I_PWD:
	ক্ষেত্র I_LPWD:
	ক্ষেত্র I_HELP:
	ক্ষেত্র I_VERSION:
	ক্ষেত্র I_PROGRESS:
		যদি ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ফেরত -1;
		বিরতি;
	পূর্বনির্ধারিত:
		fatal("Command not implemented");
	}

	*cpp = cp;
	ফেরত(cmdnum);
}

স্থির পূর্ণসংখ্যা
parse_dispatch_command(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *cmd, অক্ষর **pwd,
    ধ্রুবক অক্ষর *startdir, পূর্ণসংখ্যা err_abort, পূর্ণসংখ্যা echo_command)
{
	ধ্রুবক অক্ষর *ocmd = cmd;
	অক্ষর *path1, *path2, *tmp;
	পূর্ণসংখ্যা ignore_errors = 0, disable_echo = 1;
	পূর্ণসংখ্যা aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	পূর্ণসংখ্যা lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	পূর্ণসংখ্যা cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	অক্ষর path_buf[PATH_MAX];
	পূর্ণসংখ্যা err = 0;
	glob_t g;

	path1 = path2 = ফাঁকা;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	যদি (ignore_errors != 0)
		err_abort = 0;

	যদি (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, আকার(g));

	/* Perform command */
	নির্বাচন (cmdnum) {
	ক্ষেত্র 0:
		/* Blank line */
		বিরতি;
	ক্ষেত্র -1:
		/* Unrecognized command */
		err = -1;
		বিরতি;
	ক্ষেত্র I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	ক্ষেত্র I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		বিরতি;
	ক্ষেত্র I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	ক্ষেত্র I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		বিরতি;
	ক্ষেত্র I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		বিরতি;
	ক্ষেত্র I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		বিরতি;
	ক্ষেত্র I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	ক্ষেত্র I_LINK:
		যদি (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		বিরতি;
	ক্ষেত্র I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ফাঁকা, &g);
		জন্য (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			যদি (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			যদি (err != 0 && err_abort)
				বিরতি;
		}
		বিরতি;
	ক্ষেত্র I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		যদি (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		অন্যথা
			err = sftp_mkdir(conn, path1, &a, 1);
		বিরতি;
	ক্ষেত্র I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		বিরতি;
	ক্ষেত্র I_CHDIR:
		যদি (path1 == ফাঁকা || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		যদি ((tmp = sftp_realpath(conn, path1)) == ফাঁকা) {
			err = 1;
			বিরতি;
		}
		যদি (sftp_stat(conn, tmp, 0, &aa) != 0) {
			মুক্ত(tmp);
			err = 1;
			বিরতি;
		}
		যদি (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			মুক্ত(tmp);
			err = 1;
			বিরতি;
		}
		যদি (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			মুক্ত(tmp);
			err = 1;
			বিরতি;
		}
		মুক্ত(*pwd);
		*pwd = tmp;
		বিরতি;
	ক্ষেত্র I_LS:
		যদি (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			বিরতি;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ফাঁকা;
		যদি (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		বিরতি;
	ক্ষেত্র I_DF:
		/* Default to current directory if no path specified */
		যদি (path1 == ফাঁকা)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		বিরতি;
	ক্ষেত্র I_LCHDIR:
		যদি (path1 == ফাঁকা || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		মুক্ত(path1);
		path1 = tmp;
		যদি (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		বিরতি;
	ক্ষেত্র I_LMKDIR:
		যদি (pflag) {
			যদি (mkdir_path(path1, 0777) != 0)
				err = 1;
			বিরতি;
		}
		যদি (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		বিরতি;
	ক্ষেত্র I_LLS:
		local_do_ls(cmd);
		বিরতি;
	ক্ষেত্র I_SHELL:
		local_do_shell(cmd);
		বিরতি;
	ক্ষেত্র I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		বিরতি;
	ক্ষেত্র I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ফাঁকা, &g);
		জন্য (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			যদি (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			যদি (err != 0 && err_abort)
				বিরতি;
		}
		বিরতি;
	ক্ষেত্র I_CHOWN:
	ক্ষেত্র I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ফাঁকা, &g);
		জন্য (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			যদি ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				যদি (err_abort) {
					err = -1;
					বিরতি;
				} অন্যথা
					চালু;
			}
			যদি (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				যদি (err_abort) {
					err = -1;
					বিরতি;
				} অন্যথা
					চালু;
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
				বিরতি;
		}
		বিরতি;
	ক্ষেত্র I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		বিরতি;
	ক্ষেত্র I_LPWD:
		যদি (!getcwd(path_buf, আকার(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			বিরতি;
		}
		mprintf("Local working directory: %s\n", path_buf);
		বিরতি;
	ক্ষেত্র I_QUIT:
		/* Processed below */
		বিরতি;
	ক্ষেত্র I_HELP:
		help();
		বিরতি;
	ক্ষেত্র I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		বিরতি;
	ক্ষেত্র I_PROGRESS:
		showprogress = !showprogress;
		যদি (showprogress)
			printf("Progress meter enabled\n");
		অন্যথা
			printf("Progress meter disabled\n");
		বিরতি;
	পূর্বনির্ধারিত:
		fatal("%d is not implemented", cmdnum);
	}

	যদি (g.gl_pathc)
		globfree(&g);
	মুক্ত(path1);
	মুক্ত(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	যদি (err_abort && err != 0)
		ফেরত (-1);
	অন্যথা যদি (cmdnum == I_QUIT)
		ফেরত (1);

	ফেরত (0);
}

#ifdef USE_LIBEDIT
স্থির অক্ষর *
prompt(Edit_সারি *el)
{
	ফেরত ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
স্থির শূন্য
complete_display(অক্ষর **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	কাঠামো winsize ws;
	অক্ষর *tmp;

	/* Count entries for sort and find longest */
	জন্য (y = 0; list[y]; y++)
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
	জন্য (y = 0; list[y]; y++) {
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
স্থির অক্ষর *
complete_ambiguous(ধ্রুবক অক্ষর *word, অক্ষর **list, আকার_t গুনতি)
{
	আকার_t i, j, matchlen;
	অক্ষর *tmp;
	পূর্ণসংখ্যা len;

	যদি (word == ফাঁকা)
		ফেরত ফাঁকা;

	যদি (গুনতি == 0)
		ফেরত xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	জন্য (i = 1; i < গুনতি && list[i] != ফাঁকা; i++) {
		জন্য (j = 0; j < matchlen; j++)
			যদি (list[0][j] != list[i][j])
				বিরতি;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ফাঁকা, 0);
	জন্য (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		যদি (len <= 0 || i + (আকার_t)len > matchlen)
			বিরতি;
		i += (আকার_t)len;
	}
	/* If so, truncate */
	যদি (i < matchlen)
		matchlen = i;

	যদি (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		ফেরত tmp;
	}

	ফেরত xstrdup(word);
}

/* Autocomplete a sftp command */
স্থির পূর্ণসংখ্যা
complete_cmd_parse(Edit_সারি *el, অক্ষর *cmd, পূর্ণসংখ্যা lastarg, অক্ষর quote,
    পূর্ণসংখ্যা terminated)
{
	u_int y, গুনতি = 0, cmdlen, tmplen;
	অক্ষর *tmp, **list, argterm[3];
	ধ্রুবক সারি_Info *lf;

	list = xcalloc((আকার(cmds) / আকার(*cmds)) + 1, আকার(অক্ষর *));

	/* No command specified: display all available commands */
	যদি (cmd == ফাঁকা) {
		জন্য (y = 0; cmds[y].c; y++)
			list[গুনতি++] = xstrdup(cmds[y].c);

		list[গুনতি] = ফাঁকা;
		complete_display(list, 0);

		জন্য (y = 0; list[y] != ফাঁকা; y++)
			মুক্ত(list[y]);
		মুক্ত(list);
		ফেরত গুনতি;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	জন্য (y = 0; cmds[y].c; y++)  {
		যদি (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[গুনতি++] = xstrdup(cmds[y].c);
	}
	list[গুনতি] = ফাঁকা;

	যদি (গুনতি == 0) {
		মুক্ত(list);
		ফেরত 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, গুনতি);
	যদি (গুনতি > 1)
		complete_display(list, 0);

	জন্য (y = 0; list[y]; y++)
		মুক্ত(list[y]);
	মুক্ত(list);

	যদি (tmp != ফাঁকা) {
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

	ফেরত গুনতি;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
স্থির পূর্ণসংখ্যা
complete_is_remote(অক্ষর *cmd, পূর্ণসংখ্যা cmdarg) {
	পূর্ণসংখ্যা i;

	যদি (cmd == ফাঁকা)
		ফেরত -1;

	জন্য (i = 0; cmds[i].c; i++) {
		যদি (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			যদি (cmdarg == 1)
				ফেরত cmds[i].t;
			অন্যথা যদি (cmdarg == 2)
				ফেরত cmds[i].t2;
			বিরতি;
		}
	}

	ফেরত -1;
}

/* Autocomplete a filename "file" */
স্থির পূর্ণসংখ্যা
complete_match(Edit_সারি *el, কাঠামো sftp_conn *conn, অক্ষর *remote_path,
    অক্ষর *file, পূর্ণসংখ্যা remote, পূর্ণসংখ্যা lastarg, অক্ষর quote, পূর্ণসংখ্যা terminated)
{
	glob_t g;
	অক্ষর *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	পূর্ণসংখ্যা clen;
	ধ্রুবক সারি_Info *lf;

	/* Glob from "file" location */
	যদি (file == ফাঁকা)
		tmp = xstrdup("*");
	অন্যথা
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, আকার(g));
	যদি (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ফাঁকা, &g);
	} অন্যথা
		(শূন্য)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ফাঁকা, &g);

	/* Determine length of pwd so we can trim completion display */
	জন্য (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		যদি (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			যদি (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			বিরতি;
		}
		যদি (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		যদি (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	মুক্ত(tmp);
	tmp = ফাঁকা;

	যদি (g.gl_matchc == 0)
		যাও out;

	যদি (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	যদি (file == ফাঁকা || hadglob)
		যাও out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? ফাঁকা : remote_path);
	মুক্ত(tmp2);

	যদি (tmp == ফাঁকা)
		যাও out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	জন্য (i = 0; i < filelen; i++) {
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
		mblen(ফাঁকা, 0);
		জন্য (i = 0; i < len; i += clen) {
			যদি ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (আকার_t)clen > আকার(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			নির্বাচন (tmp2[i]) {
			ক্ষেত্র '\'':
			ক্ষেত্র '"':
			ক্ষেত্র '\\':
			ক্ষেত্র '\t':
			ক্ষেত্র '[':
			ক্ষেত্র ' ':
			ক্ষেত্র '#':
			ক্ষেত্র '*':
				যদি (quote == '\0' || tmp2[i] == quote) {
					যদি (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					বিরতি;
				}
				/* FALLTHROUGH */
			পূর্বনির্ধারিত:
				যদি (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				বিরতি;
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
	ফেরত g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
স্থির unsigned অক্ষর
complete(Edit_সারি *el, পূর্ণসংখ্যা ch)
{
	অক্ষর **argv, *সারি, quote;
	পূর্ণসংখ্যা argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ধ্রুবক সারি_Info *lf;
	কাঠামো complete_ctx *complete_ctx;

	lf = el_সারি(el);
	যদি (el_get(el, EL_CLIENTDATA, (শূন্য**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->বাফার;
	সারি = xmalloc(cursor + 1);
	memcpy(সারি, lf->বাফার, cursor);
	সারি[cursor] = '\0';
	argv = makeargv(সারি, &carg, 1, &quote, &terminated);
	মুক্ত(সারি);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->বাফার;
	সারি = xmalloc(len + 1);
	memcpy(সারি, lf->বাফার, len);
	সারি[len] = '\0';
	argv = makeargv(সারি, &argc, 1, ফাঁকা, ফাঁকা);

	/* Ensure cursor is at EOL or a argument boundary */
	যদি (সারি[cursor] != ' ' && সারি[cursor] != '\0' &&
	    সারি[cursor] != '\n') {
		মুক্ত(সারি);
		ফেরত ret;
	}

	যদি (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ফাঁকা, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} অন্যথা যদি (carg == 1 && cursor > 0 && সারি[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		যদি (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} অন্যথা যদি (carg >= 1) {
		/* Handle file parsing */
		পূর্ণসংখ্যা remote = 0;
		পূর্ণসংখ্যা i = 0, cmdarg = 0;
		অক্ষর *filematch = ফাঁকা;

		যদি (carg > 1 && সারি[cursor-1] != ' ')
			filematch = argv[carg - 1];

		জন্য (i = 1; i < carg; i++) {
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
	ফেরত ret;
}
#endif /* USE_LIBEDIT */

স্থির পূর্ণসংখ্যা
interactive_loop(কাঠামো sftp_conn *conn, অক্ষর *file1, অক্ষর *file2)
{
	অক্ষর *remote_path;
	অক্ষর *dir = ফাঁকা, *startdir = ফাঁকা;
	অক্ষর cmd[2048];
	পূর্ণসংখ্যা err, interactive;
	Edit_সারি *el = ফাঁকা;
#ifdef USE_LIBEDIT
	ধ্রুবক অক্ষর *editor;
	History *hl = ফাঁকা;
	HistEvent hev;
	বাহ্যিক অক্ষর *__progname;
	কাঠামো complete_ctx complete_ctx;

	যদি (!batchmode && isatty(STDIN_FILENO)) {
		যদি ((el = el_init(__progname, stdin, stdout, stderr)) == ফাঁকা)
			fatal("Couldn't initialise editline");
		যদি ((hl = history_init()) == ফাঁকা)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, ফাঁকা);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, ফাঁকা);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (শূন্য*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", ফাঁকা);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", ফাঁকা);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", ফাঁকা);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ফাঁকা);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ফাঁকা);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", ফাঁকা);

		/* el_source() may have changed EL_EDITOR to vi */
		যদি (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", ফাঁকা);
	}
#endif /* USE_LIBEDIT */

	যদি ((remote_path = sftp_realpath(conn, ".")) == ফাঁকা)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	যদি (file1 != ফাঁকা) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		যদি (sftp_remote_is_dir(conn, dir) && file2 == ফাঁকা) {
			যদি (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, আকার cmd, "cd \"%s\"", dir);
			যদি (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				মুক্ত(dir);
				মুক্ত(startdir);
				মুক্ত(remote_path);
				মুক্ত(conn);
				ফেরত (-1);
			}
		} অন্যথা {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			মুক্ত(dir);
			মুক্ত(startdir);
			মুক্ত(remote_path);
			মুক্ত(conn);
			ফেরত (err);
		}
		মুক্ত(dir);
	}

	setvbuf(stdout, ফাঁকা, _IOLBF, 0);
	setvbuf(infile, ফাঁকা, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	জন্য (;;) {
		কাঠামো sigaction sa;

		interrupted = 0;
		memset(&sa, 0, আকার(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		যদি (sigaction(SIGINT, &sa, ফাঁকা) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			বিরতি;
		}
		যদি (el == ফাঁকা) {
			যদি (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			যদি (fgets(cmd, আকার(cmd), infile) == ফাঁকা) {
				যদি (interactive)
					printf("\n");
				যদি (interrupted)
					চালু;
				বিরতি;
			}
		} অন্যথা {
#ifdef USE_LIBEDIT
			ধ্রুবক অক্ষর *সারি;
			পূর্ণসংখ্যা গুনতি = 0;

			যদি ((সারি = el_gets(el, &গুনতি)) == ফাঁকা ||
			    গুনতি <= 0) {
				printf("\n");
				যদি (interrupted)
					চালু;
				বিরতি;
			}
			history(hl, &hev, H_ENTER, সারি);
			যদি (strlcpy(cmd, সারি, আকার(cmd)) >= আকার(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				চালু;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == ফাঁকা);
		যদি (err != 0)
			বিরতি;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	মুক্ত(remote_path);
	মুক্ত(startdir);
	মুক্ত(conn);

#ifdef USE_LIBEDIT
	যদি (hl != ফাঁকা)
		history_end(hl);
	যদি (el != ফাঁকা)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	ফেরত (err >= 0 ? 0 : -1);
}

স্থির শূন্য
connect_to_server(অক্ষর *path, অক্ষর **args, পূর্ণসংখ্যা *in, পূর্ণসংখ্যা *out)
{
	পূর্ণসংখ্যা c_in, c_out;
#ifdef USE_PIPES
	পূর্ণসংখ্যা pin[2], pout[2];

	যদি ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#অন্যথা /* USE_PIPES */
	পূর্ণসংখ্যা inout[2];

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
	বাহ্যিক অক্ষর *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

পূর্ণসংখ্যা
প্রধান(পূর্ণসংখ্যা argc, অক্ষর **argv)
{
	পূর্ণসংখ্যা r, in, out, ch, err, tmp, port = -1, noisy = 0;
	অক্ষর *host = ফাঁকা, *user, *cp, **cpp, *file2 = ফাঁকা;
	পূর্ণসংখ্যা debug_level = 0;
	অক্ষর *file1 = ফাঁকা, *sftp_server = ফাঁকা;
	অক্ষর *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = ফাঁকা;
	ধ্রুবক অক্ষর *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	বাহ্যিক পূর্ণসংখ্যা optind;
	বাহ্যিক অক্ষর *optarg;
	কাঠামো sftp_conn *conn;
	আকার_t copy_বাফার_len = 0;
	আকার_t অঙ্ক_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', আকার(args));
	args.list = ফাঁকা;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	যখন ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		নির্বাচন (ch) {
		/* Passed through to ssh(1) */
		ক্ষেত্র 'A':
		ক্ষেত্র '4':
		ক্ষেত্র '6':
		ক্ষেত্র 'C':
			addargs(&args, "-%c", ch);
			বিরতি;
		/* Passed through to ssh(1) with argument */
		ক্ষেত্র 'F':
		ক্ষেত্র 'J':
		ক্ষেত্র 'c':
		ক্ষেত্র 'i':
		ক্ষেত্র 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			বিরতি;
		ক্ষেত্র 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			বিরতি;
		ক্ষেত্র 'P':
			port = a2port(optarg);
			যদি (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			বিরতি;
		ক্ষেত্র 'v':
			যদি (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			বিরতি;
		ক্ষেত্র '1':
			fatal("SSH protocol v.1 is no longer supported");
			বিরতি;
		ক্ষেত্র '2':
			/* accept silently */
			বিরতি;
		ক্ষেত্র 'a':
			global_aflag = 1;
			বিরতি;
		ক্ষেত্র 'B':
			copy_বাফার_len = strtol(optarg, &cp, 10);
			যদি (copy_বাফার_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			বিরতি;
		ক্ষেত্র 'b':
			যদি (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			যদি (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ফাঁকা)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			বিরতি;
		ক্ষেত্র 'f':
			global_fflag = 1;
			বিরতি;
		ক্ষেত্র 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			বিরতি;
		ক্ষেত্র 'p':
			global_pflag = 1;
			বিরতি;
		ক্ষেত্র 'D':
			sftp_direct = optarg;
			বিরতি;
		ক্ষেত্র 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			যদি (errstr != ফাঁকা)
				usage();
			limit_kbps *= 1024; /* kbps */
			বিরতি;
		ক্ষেত্র 'r':
			global_rflag = 1;
			বিরতি;
		ক্ষেত্র 'R':
			অঙ্ক_requests = strtol(optarg, &cp, 10);
			যদি (অঙ্ক_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			বিরতি;
		ক্ষেত্র 's':
			sftp_server = optarg;
			বিরতি;
		ক্ষেত্র 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			বিরতি;
		ক্ষেত্র 'X':
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
				copy_বাফার_len = (আকার_t)llv;
			} অন্যথা যদি (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				যদি (errstr != ফাঁকা) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				অঙ্ক_requests = (আকার_t)llv;
			} অন্যথা {
				fatal("Invalid -X option");
			}
			বিরতি;
		ক্ষেত্র 'h':
		পূর্বনির্ধারিত:
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

	যদি (sftp_direct == ফাঁকা) {
		যদি (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		নির্বাচন (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		ক্ষেত্র -1:
			usage();
			বিরতি;
		ক্ষেত্র 0:
			যদি (tmp != -1)
				port = tmp;
			বিরতি;
		পূর্বনির্ধারিত:
			/* Try with user, host and path. */
			যদি (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				বিরতি;
			/* Try with user and host. */
			যদি (parse_user_host_port(*argv, &user, &host, ফাঁকা)
			    == 0)
				বিরতি;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			বিরতি;
		}
		file2 = *(argv + 1);

		যদি (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		যদি (port != -1)
			addargs(&args, "-oPort %d", port);
		যদি (user != ফাঁকা) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		যদি (sftp_server == ফাঁকা || strchr(sftp_server, '/') == ফাঁকা)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != ফাঁকা ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} অন্যথা {
		যদি ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		যদি (cpp[0] == ফাঁকা)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_বাফার_len, অঙ্ক_requests, limit_kbps);
	যদি (conn == ফাঁকা)
		fatal("Couldn't initialise connection to server");

	যদি (!quiet) {
		যদি (sftp_direct == ফাঁকা)
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

	যখন (waitpid(sshpid, ফাঁকা, 0) == -1 && sshpid > 1)
		যদি (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
