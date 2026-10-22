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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/statvfs.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#ಅನ್ತರ್ಭಾವ <histedit.h>
#ಅನ್ಯಥಾ
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ Edit_ಸಾಲು;
#endif
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <util.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"

#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sftp-common.h"
#ಅನ್ತರ್ಭಾವ "sftp-client.h"
#ಅನ್ತರ್ಭಾವ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
ಪೂರ್ಣಾಙ್ಕ batchmode = 0;

/* PID of ssh transport process */
ಸ್ಥಿರ ಚಞ್ಚಲ pid_t sshpid = -1;

/* Suppress diagnostic messages */
ಪೂರ್ಣಾಙ್ಕ quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
ಪೂರ್ಣಾಙ್ಕ showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
ಪೂರ್ಣಾಙ್ಕ global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
ಪೂರ್ಣಾಙ್ಕ global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
ಪೂರ್ಣಾಙ್ಕ global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
ಪೂರ್ಣಾಙ್ಕ global_fflag = 0;

/* SIGINT received during command processing */
ಚಞ್ಚಲ sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
ಪೂರ್ಣಾಙ್ಕ sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
ಸಂರಚನಾ complete_ctx {
	ಸಂರಚನಾ sftp_conn *conn;
	ವರ್ಣ **remote_pathp;
};

ಪೂರ್ಣಾಙ್ಕ sftp_glob(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ,
    ಪೂರ್ಣಾಙ್ಕ (*)(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ), glob_t *); /* proto for sftp-glob.c */

ಬಾಹ್ಯ ವರ್ಣ *__progname;

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
ಗಣನಾ sftp_command {
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

ಸಂರಚನಾ CMD {
	ಧ್ರುವ ವರ್ಣ *c;
	ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ n;
	ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ t;	/* Completion type for the first argument */
	ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ CMD cmds[] = {
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
	{ ರಿಕ್ತ,		-1,		-1,		-1	}
};

ಸ್ಥಿರ ಶೂನ್ಯ
killchild(ಪೂರ್ಣಾಙ್ಕ signo)
{
	pid_t pid;

	pid = sshpid;
	ಯದಿ (pid > 1) {
		kill(pid, SIGTERM);
		(ಶೂನ್ಯ)waitpid(pid, ರಿಕ್ತ, 0);
	}

	_exit(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
suspchild(ಪೂರ್ಣಾಙ್ಕ signo)
{
	ಪೂರ್ಣಾಙ್ಕ save_errno = errno;
	ಯದಿ (sshpid > 1) {
		kill(sshpid, signo);
		ಯಾವತ್ (waitpid(sshpid, ರಿಕ್ತ, WUNTRACED) == -1 && errno == EINTR)
			ಅನುವರ್ತ;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ಸ್ಥಿರ ಶೂನ್ಯ
cmd_interrupt(ಪೂರ್ಣಾಙ್ಕ signo)
{
	ಧ್ರುವ ವರ್ಣ ಸಂದೇಶ[] = "\rInterrupt  \n";
	ಪೂರ್ಣಾಙ್ಕ olderrno = errno;

	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ) - 1);
	interrupted = 1;
	errno = olderrno;
}

ಸ್ಥಿರ ಶೂನ್ಯ
read_interrupt(ಪೂರ್ಣಾಙ್ಕ signo)
{
	interrupted = 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sigchld_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಪೂರ್ಣಾಙ್ಕ save_errno = errno;
	pid_t pid;
	ಧ್ರುವ ವರ್ಣ ಸಂದೇಶ[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	ಯಾವತ್ ((pid = waitpid(sshpid, ರಿಕ್ತ, WNOHANG)) == -1 && errno == EINTR)
		ಅನುವರ್ತ;
	ಯದಿ (pid == sshpid) {
		ಯದಿ (!quiet)
		    (ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

ಸ್ಥಿರ ಶೂನ್ಯ
help(ಶೂನ್ಯ)
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

ಸ್ಥಿರ ಶೂನ್ಯ
local_do_shell(ಧ್ರುವ ವರ್ಣ *args)
{
	ಪೂರ್ಣಾಙ್ಕ status;
	ವರ್ಣ *shell;
	pid_t pid;

	ಯದಿ (!*args)
		args = ರಿಕ್ತ;

	ಯದಿ ((shell = getenv("SHELL")) == ರಿಕ್ತ || *shell == '\0')
		shell = _PATH_BSHELL;

	ಯದಿ ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	ಯದಿ (pid == 0) {
		ಯದಿ (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (ವರ್ಣ *)ರಿಕ್ತ);
		} ಅನ್ಯಥಾ {
			debug3("Executing %s", shell);
			execl(shell, shell, (ವರ್ಣ *)ರಿಕ್ತ);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	ಯಾವತ್ (waitpid(pid, &status, 0) == -1)
		ಯದಿ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ಯದಿ (!WIFEXITED(status))
		error("Shell exited abnormally");
	ಅನ್ಯಥಾ ಯದಿ (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

ಸ್ಥಿರ ಶೂನ್ಯ
local_do_ls(ಧ್ರುವ ವರ್ಣ *args)
{
	ಯದಿ (!args || !*args)
		local_do_shell(_PATH_LS);
	ಅನ್ಯಥಾ {
		ಪೂರ್ಣಾಙ್ಕ len = strlen(_PATH_LS " ") + strlen(args) + 1;
		ವರ್ಣ *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		ಮುಕ್ತ(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
ಸ್ಥಿರ ವರ್ಣ *
path_strip(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ವರ್ಣ *strip)
{
	size_t len;

	ಯದಿ (strip == ರಿಕ್ತ || (len = strlen(strip)) == 0)
		ಪ್ರತ್ಯಾಗಮ (xstrdup(path));

	ಯದಿ (strncmp(path, strip, len) == 0) {
		ಯದಿ (strip[len - 1] != '/' && path[len] == '/')
			len++;
		ಪ್ರತ್ಯಾಗಮ (xstrdup(path + len));
	}

	ಪ್ರತ್ಯಾಗಮ (xstrdup(path));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_getput_flags(ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc,
    ಪೂರ್ಣಾಙ್ಕ *aflag, ಪೂರ್ಣಾಙ್ಕ *fflag, ಪೂರ್ಣಾಙ್ಕ *pflag, ಪೂರ್ಣಾಙ್ಕ *rflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	ಯಾವತ್ ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'a':
			*aflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			*fflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
		ಪಕ್ಷ 'P':
			*pflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
		ಪಕ್ಷ 'R':
			*rflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_mkdir_flags(ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc, ಪೂರ್ಣಾಙ್ಕ *pflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	ಯಾವತ್ ((ch = getopt(argc, argv, "p")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'p':
			*pflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_link_flags(ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc, ಪೂರ್ಣಾಙ್ಕ *sflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	ಯಾವತ್ ((ch = getopt(argc, argv, "s")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 's':
			*sflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_rename_flags(ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc, ಪೂರ್ಣಾಙ್ಕ *lflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	ಯಾವತ್ ((ch = getopt(argc, argv, "l")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'l':
			*lflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_ls_flags(ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc, ಪೂರ್ಣಾಙ್ಕ *lflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	ಯಾವತ್ ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'a':
			*lflag |= LS_SHOW_ALL;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			*lflag &= ~SORT_FLAGS;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
			*lflag |= LS_SI_UNITS;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
			*lflag |= LS_REVERSE_SORT;
			ಭಙ್ಗ;
		ಪಕ್ಷ 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("ls: Invalid flag -%c", optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_df_flags(ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc, ಪೂರ್ಣಾಙ್ಕ *hflag, ಪೂರ್ಣಾಙ್ಕ *iflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	ಯಾವತ್ ((ch = getopt(argc, argv, "hi")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'h':
			*hflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'i':
			*iflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_ch_flags(ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc, ಪೂರ್ಣಾಙ್ಕ *hflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	ಯಾವತ್ ((ch = getopt(argc, argv, "h")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಪಕ್ಷ 'h':
			*hflag = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_no_flags(ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **argv, ಪೂರ್ಣಾಙ್ಕ argc)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಙ್ಕ ch;

	optind = optreset = 1;
	opterr = 0;

	ಯಾವತ್ ((ch = getopt(argc, argv, "")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		ಸ್ವಭಾವ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	ಪ್ರತ್ಯಾಗಮ optind;
}

ಸ್ಥಿರ ವರ್ಣ *
escape_glob(ಧ್ರುವ ವರ್ಣ *s)
{
	size_t i, o, len;
	ವರ್ಣ *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	ಪ್ರತಿ (i = o = 0; i < len; i++) {
		ಯದಿ (strchr("[]?*\\", s[i]) != ರಿಕ್ತ)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
ಸ್ಥಿರ ವರ್ಣ *
make_absolute_pwd_glob(ವರ್ಣ *p, ಧ್ರುವ ವರ್ಣ *pwd)
{
	ವರ್ಣ *ret, *escpwd;

	escpwd = escape_glob(pwd);
	ಯದಿ (p == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ escpwd;
	ret = sftp_make_absolute(p, escpwd);
	ಮುಕ್ತ(escpwd);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
local_is_dir(ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ stat sb;

	ಯದಿ (stat(path, &sb) == -1)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ S_ISDIR(sb.st_mode);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_get(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *src, ಧ್ರುವ ವರ್ಣ *dst,
    ಧ್ರುವ ವರ್ಣ *pwd, ಪೂರ್ಣಾಙ್ಕ pflag, ಪೂರ್ಣಾಙ್ಕ rflag, ಪೂರ್ಣಾಙ್ಕ resume, ಪೂರ್ಣಾಙ್ಕ fflag)
{
	ವರ್ಣ *filename, *abs_src = ರಿಕ್ತ, *abs_dst = ರಿಕ್ತ, *tmp = ರಿಕ್ತ;
	glob_t g;
	ಪೂರ್ಣಾಙ್ಕ i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, ಪರಿಮಾಣ(g));

	debug3("Looking up %s", abs_src);
	ಯದಿ ((r = sftp_glob(conn, abs_src, GLOB_MARK, ರಿಕ್ತ, &g)) != 0) {
		ಯದಿ (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} ಅನ್ಯಥಾ {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		ಗಚ್ಛ out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	ಯದಿ (g.gl_matchc > 1 && dst != ರಿಕ್ತ && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		ಗಚ್ಛ out;
	}

	ಪ್ರತಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ಯದಿ ((filename = basename(tmp)) == ರಿಕ್ತ) {
			error("basename %s: %s", tmp, strerror(errno));
			ಮುಕ್ತ(tmp);
			err = -1;
			ಗಚ್ಛ out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		ಯದಿ (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		ಯದಿ (g.gl_matchc == 1 && dst) {
			ಯದಿ (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} ಅನ್ಯಥಾ {
				abs_dst = xstrdup(dst);
			}
		} ಅನ್ಯಥಾ ಯದಿ (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} ಅನ್ಯಥಾ {
			abs_dst = xstrdup(filename);
		}
		ಮುಕ್ತ(tmp);

		resume |= global_aflag;
		ಯದಿ (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ಅನ್ಯಥಾ ಯದಿ (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		ಯದಿ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ಯದಿ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ರಿಕ್ತ, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ಅನ್ಯಥಾ {
			ಯದಿ (sftp_download(conn, g.gl_pathv[i], abs_dst, ರಿಕ್ತ,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		ಮುಕ್ತ(abs_dst);
		abs_dst = ರಿಕ್ತ;
	}

out:
	ಮುಕ್ತ(abs_src);
	globfree(&g);
	ಪ್ರತ್ಯಾಗಮ(err);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_put(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *src, ಧ್ರುವ ವರ್ಣ *dst,
    ಧ್ರುವ ವರ್ಣ *pwd, ಪೂರ್ಣಾಙ್ಕ pflag, ಪೂರ್ಣಾಙ್ಕ rflag, ಪೂರ್ಣಾಙ್ಕ resume, ಪೂರ್ಣಾಙ್ಕ fflag)
{
	ವರ್ಣ *tmp_dst = ರಿಕ್ತ;
	ವರ್ಣ *abs_dst = ರಿಕ್ತ;
	ವರ್ಣ *tmp = ರಿಕ್ತ, *filename = ರಿಕ್ತ;
	glob_t g;
	ಪೂರ್ಣಾಙ್ಕ err = 0;
	ಪೂರ್ಣಾಙ್ಕ i, dst_is_dir = 1;
	ಸಂರಚನಾ stat sb;

	ಯದಿ (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, ಪರಿಮಾಣ(g));
	debug3("Looking up %s", src);
	ಯದಿ (glob(src, GLOB_NOCHECK | GLOB_MARK, ರಿಕ್ತ, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		ಗಚ್ಛ out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	ಯದಿ (tmp_dst != ರಿಕ್ತ)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	ಯದಿ (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		ಗಚ್ಛ out;
	}

	ಪ್ರತಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		ಯದಿ (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			ಅನುವರ್ತ;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		ಯದಿ ((filename = basename(tmp)) == ರಿಕ್ತ) {
			error("basename %s: %s", tmp, strerror(errno));
			ಮುಕ್ತ(tmp);
			err = -1;
			ಗಚ್ಛ out;
		}
		/* Special handling for source of '..' */
		ಯದಿ (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		ಮುಕ್ತ(abs_dst);
		abs_dst = ರಿಕ್ತ;
		ಯದಿ (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			ಯದಿ (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			ಅನ್ಯಥಾ
				abs_dst = xstrdup(tmp_dst);
		} ಅನ್ಯಥಾ ಯದಿ (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} ಅನ್ಯಥಾ {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		ಮುಕ್ತ(tmp);

		resume |= global_aflag;
		ಯದಿ (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ಅನ್ಯಥಾ ಯದಿ (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		ಯದಿ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ಯದಿ (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ಅನ್ಯಥಾ {
			ಯದಿ (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	ಮುಕ್ತ(abs_dst);
	ಮುಕ್ತ(tmp_dst);
	globfree(&g);
	ಪ್ರತ್ಯಾಗಮ(err);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sdirent_comp(ಧ್ರುವ ಶೂನ್ಯ *aa, ಧ್ರುವ ಶೂನ್ಯ *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	ಪೂರ್ಣಾಙ್ಕ rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	ಯದಿ (sort_flag & LS_NAME_SORT)
		ಪ್ರತ್ಯಾಗಮ (rmul * strcmp(a->filename, b->filename));
	ಅನ್ಯಥಾ ಯದಿ (sort_flag & LS_TIME_SORT)
		ಪ್ರತ್ಯಾಗಮ (rmul * NCMP(a->a.mtime, b->a.mtime));
	ಅನ್ಯಥಾ ಯದಿ (sort_flag & LS_SIZE_SORT)
		ಪ್ರತ್ಯಾಗಮ (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_ls_dir(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path,
    ಧ್ರುವ ವರ್ಣ *strip_path, ಪೂರ್ಣಾಙ್ಕ lflag)
{
	ಪೂರ್ಣಾಙ್ಕ n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	ಯದಿ ((n = sftp_readdir(conn, path, &d)) != 0)
		ಪ್ರತ್ಯಾಗಮ (n);

	ಯದಿ (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		ಸಂರಚನಾ winsize ws;
		ವರ್ಣ *tmp;

		/* Count entries for sort and find longest filename */
		ಪ್ರತಿ (n = 0; d[n] != ರಿಕ್ತ; n++) {
			ಯದಿ (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		ಮುಕ್ತ(tmp);

		ಯದಿ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	ಯದಿ (lflag & SORT_FLAGS) {
		ಪ್ರತಿ (n = 0; d[n] != ರಿಕ್ತ; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, ಪರಿಮಾಣ(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	ಪ್ರತಿ (n = 0; d[n] != ರಿಕ್ತ && !interrupted; n++) {
		ವರ್ಣ *tmp, *fname;

		ಯದಿ (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			ಅನುವರ್ತ;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		ಮುಕ್ತ(tmp);

		ಯದಿ (lflag & LS_LONG_VIEW) {
			ಯದಿ ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				ವರ್ಣ *lname;
				ಸಂರಚನಾ stat sb;
				ಧ್ರುವ ವರ್ಣ *user = ರಿಕ್ತ, *group = ರಿಕ್ತ;

				memset(&sb, 0, ಪರಿಮಾಣ(sb));
				attrib_to_stat(&d[n]->a, &sb);
				ಯದಿ ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				ಮುಕ್ತ(lname);
			} ಅನ್ಯಥಾ
				mprintf("%s\n", d[n]->longname);
		} ಅನ್ಯಥಾ {
			mprintf("%-*s", colspace, fname);
			ಯದಿ (c >= columns) {
				printf("\n");
				c = 1;
			} ಅನ್ಯಥಾ
				c++;
		}

		ಮುಕ್ತ(fname);
	}

	ಯದಿ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sglob_comp(ಧ್ರುವ ಶೂನ್ಯ *aa, ಧ್ರುವ ಶೂನ್ಯ *bb)
{
	u_int a = *(ಧ್ರುವ u_int *)aa;
	u_int b = *(ಧ್ರುವ u_int *)bb;
	ಧ್ರುವ ವರ್ಣ *ap = sort_glob->gl_pathv[a];
	ಧ್ರುವ ವರ್ಣ *bp = sort_glob->gl_pathv[b];
	ಧ್ರುವ ಸಂರಚನಾ stat *as = sort_glob->gl_statv[a];
	ಧ್ರುವ ಸಂರಚನಾ stat *bs = sort_glob->gl_statv[b];
	ಪೂರ್ಣಾಙ್ಕ rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	ಯದಿ (as == ರಿಕ್ತ || bs == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ (as == bs) ? 0 : (as == ರಿಕ್ತ ? rmul : -rmul);
	ಯದಿ (sort_flag & LS_NAME_SORT)
		ಪ್ರತ್ಯಾಗಮ (rmul * strcmp(ap, bp));
	ಅನ್ಯಥಾ ಯದಿ (sort_flag & LS_TIME_SORT) {
#ಯದಿ defined(HAVE_STRUCT_STAT_ST_MTIM)
		ಯದಿ (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			ಪ್ರತ್ಯಾಗಮ 0;
		ಪ್ರತ್ಯಾಗಮ timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#ನೋಚೇದ್ಯದಿ defined(HAVE_STRUCT_STAT_ST_MTIME)
		ಪ್ರತ್ಯಾಗಮ (rmul * NCMP(as->st_mtime, bs->st_mtime));
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ rmul * 1;
#endif
	} ಅನ್ಯಥಾ ಯದಿ (sort_flag & LS_SIZE_SORT)
		ಪ್ರತ್ಯಾಗಮ (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_globbed_ls(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path,
    ಧ್ರುವ ವರ್ಣ *strip_path, ಪೂರ್ಣಾಙ್ಕ lflag)
{
	ವರ್ಣ *fname, *lname;
	glob_t g;
	ಪೂರ್ಣಾಙ್ಕ err, r;
	ಸಂರಚನಾ winsize ws;
	u_int i, j, nentries, *indices = ರಿಕ್ತ, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, ಪರಿಮಾಣ(g));

	ಯದಿ ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ರಿಕ್ತ, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		ಯದಿ (g.gl_pathc)
			globfree(&g);
		ಯದಿ (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} ಅನ್ಯಥಾ {
			error("Can't ls: \"%s\" not found", path);
		}
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (interrupted)
		ಗಚ್ಛ out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	ಯದಿ (g.gl_matchc == 1 && g.gl_statv[0] != ರಿಕ್ತ &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		ಪ್ರತ್ಯಾಗಮ err;
	}

	ಯದಿ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	ಯದಿ (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		ಪ್ರತಿ (i = 0; g.gl_pathv[i]; i++)
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
	ಪ್ರತಿ (nentries = 0; g.gl_pathv[nentries] != ರಿಕ್ತ; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, ಪರಿಮಾಣ(*indices));
	ಪ್ರತಿ (i = 0; i < nentries; i++)
		indices[i] = i;

	ಯದಿ (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, ಪರಿಮಾಣ(*indices), sglob_comp);
		sort_glob = ರಿಕ್ತ;
	}

	get_remote_user_groups_from_glob(conn, &g);
	ಪ್ರತಿ (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		ಯದಿ (lflag & LS_LONG_VIEW) {
			ಧ್ರುವ ವರ್ಣ *user = ರಿಕ್ತ, *group = ರಿಕ್ತ;

			ಯದಿ (g.gl_statv[i] == ರಿಕ್ತ) {
				error("no stat information for %s", fname);
				ಮುಕ್ತ(fname);
				ಅನುವರ್ತ;
			}
			ಯದಿ ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			ಮುಕ್ತ(lname);
		} ಅನ್ಯಥಾ {
			mprintf("%-*s", colspace, fname);
			ಯದಿ (c >= columns) {
				printf("\n");
				c = 1;
			} ಅನ್ಯಥಾ
				c++;
		}
		ಮುಕ್ತ(fname);
	}

	ಯದಿ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	ಯದಿ (g.gl_pathc)
		globfree(&g);
	ಮುಕ್ತ(indices);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_df(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ hflag, ಪೂರ್ಣಾಙ್ಕ iflag)
{
	ಸಂರಚನಾ sftp_statvfs st;
	ವರ್ಣ s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	ವರ್ಣ s_ಬೇರು[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	ವರ್ಣ s_icapacity[16], s_dcapacity[16];

	ಯದಿ (sftp_statvfs(conn, path, &st, 1) == -1)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", ಪರಿಮಾಣ(s_icapacity));
	ಅನ್ಯಥಾ {
		snprintf(s_icapacity, ಪರಿಮಾಣ(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	ಯದಿ (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", ಪರಿಮಾಣ(s_dcapacity));
	ಅನ್ಯಥಾ {
		snprintf(s_dcapacity, ಪರಿಮಾಣ(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	ಯದಿ (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} ಅನ್ಯಥಾ ಯದಿ (hflag) {
		strlcpy(s_used, "error", ಪರಿಮಾಣ(s_used));
		strlcpy(s_avail, "error", ಪರಿಮಾಣ(s_avail));
		strlcpy(s_ಬೇರು, "error", ಪರಿಮಾಣ(s_ಬೇರು));
		strlcpy(s_total, "error", ಪರಿಮಾಣ(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_ಬೇರು);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_ಬೇರು, s_dcapacity);
	} ಅನ್ಯಥಾ {
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
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
undo_glob_escape(ವರ್ಣ *s)
{
	size_t i, j;

	ಪ್ರತಿ (i = j = 0;;) {
		ಯದಿ (s[i] == '\0') {
			s[j] = '\0';
			ಪ್ರತ್ಯಾಗಮ;
		}
		ಯದಿ (s[i] != '\\') {
			s[j++] = s[i++];
			ಅನುವರ್ತ;
		}
		/* s[i] == '\\' */
		++i;
		ವಿಕಲ್ಪ (s[i]) {
		ಪಕ್ಷ '?':
		ಪಕ್ಷ '[':
		ಪಕ್ಷ '*':
		ಪಕ್ಷ '\\':
			s[j++] = s[i++];
			ಭಙ್ಗ;
		ಪಕ್ಷ '\0':
			s[j++] = '\\';
			s[j] = '\0';
			ಪ್ರತ್ಯಾಗಮ;
		ಸ್ವಭಾವ:
			s[j++] = '\\';
			s[j++] = s[i++];
			ಭಙ್ಗ;
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
ಸ್ಥಿರ ವರ್ಣ **
makeargv(ಧ್ರುವ ವರ್ಣ *arg, ಪೂರ್ಣಾಙ್ಕ *argcp, ಪೂರ್ಣಾಙ್ಕ sloppy, ವರ್ಣ *lastquote,
    u_int *terminated)
{
	ಪೂರ್ಣಾಙ್ಕ argc, quot;
	size_t i, j;
	ಸ್ಥಿರ ವರ್ಣ argvs[MAXARGLEN];
	ಸ್ಥಿರ ವರ್ಣ *argv[MAXARGS + 1];
	ಗಣನಾ { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	ಯದಿ (strlen(arg) > ಪರಿಮಾಣ(argvs) - 1) {
 args_too_longs:
		error("string too long");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (terminated != ರಿಕ್ತ)
		*terminated = 1;
	ಯದಿ (lastquote != ರಿಕ್ತ)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	ಪ್ರತಿ (;;) {
		ಯದಿ ((size_t)argc >= ಪರಿಮಾಣ(argv) / ಪರಿಮಾಣ(*argv)){
			error("Too many arguments.");
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
		ಯದಿ (isspace((unsigned ವರ್ಣ)arg[i])) {
			ಯದಿ (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} ಅನ್ಯಥಾ ಯದಿ (state != MA_START)
				argvs[j++] = arg[i];
		} ಅನ್ಯಥಾ ಯದಿ (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			ಯದಿ (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				ಯದಿ (lastquote != ರಿಕ್ತ)
					*lastquote = arg[i];
			} ಅನ್ಯಥಾ ಯದಿ (state == MA_UNQUOTED)
				state = q;
			ಅನ್ಯಥಾ ಯದಿ (state == q)
				state = MA_UNQUOTED;
			ಅನ್ಯಥಾ
				argvs[j++] = arg[i];
		} ಅನ್ಯಥಾ ಯದಿ (arg[i] == '\\') {
			ಯದಿ (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				ಯದಿ (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} ಅನ್ಯಥಾ ಯದಿ (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					ಯದಿ (j >= ಪರಿಮಾಣ(argvs) - 5)
						ಗಚ್ಛ args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} ಅನ್ಯಥಾ {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} ಅನ್ಯಥಾ {
				ಯದಿ (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					ಯದಿ (lastquote != ರಿಕ್ತ)
						*lastquote = '\0';
				}
				ಯದಿ (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} ಅನ್ಯಥಾ {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					ಯದಿ (arg[i] == '\0')
						ಗಚ್ಛ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} ಅನ್ಯಥಾ ಯದಿ (arg[i] == '#') {
			ಯದಿ (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			ಅನ್ಯಥಾ
				ಗಚ್ಛ string_done;
		} ಅನ್ಯಥಾ ಯದಿ (arg[i] == '\0') {
			ಯದಿ (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				ಯದಿ (sloppy) {
					state = MA_UNQUOTED;
					ಯದಿ (terminated != ರಿಕ್ತ)
						*terminated = 0;
					ಗಚ್ಛ string_done;
				}
				error("Unterminated quoted argument");
				ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
			}
 string_done:
			ಯದಿ (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			ಭಙ್ಗ;
		} ಅನ್ಯಥಾ {
			ಯದಿ (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				ಯದಿ (lastquote != ರಿಕ್ತ)
					*lastquote = '\0';
			}
			ಯದಿ ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				ಯದಿ (j >= ಪರಿಮಾಣ(argvs) - 3)
					ಗಚ್ಛ args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} ಅನ್ಯಥಾ
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	ಪ್ರತ್ಯಾಗಮ argv;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_args(ಧ್ರುವ ವರ್ಣ **cpp, ಪೂರ್ಣಾಙ್ಕ *ignore_errors, ಪೂರ್ಣಾಙ್ಕ *disable_echo, ಪೂರ್ಣಾಙ್ಕ *aflag,
	  ಪೂರ್ಣಾಙ್ಕ *fflag, ಪೂರ್ಣಾಙ್ಕ *hflag, ಪೂರ್ಣಾಙ್ಕ *iflag, ಪೂರ್ಣಾಙ್ಕ *lflag, ಪೂರ್ಣಾಙ್ಕ *pflag,
	  ಪೂರ್ಣಾಙ್ಕ *rflag, ಪೂರ್ಣಾಙ್ಕ *sflag,
    unsigned long *n_arg, ವರ್ಣ **path1, ವರ್ಣ **path2)
{
	ಧ್ರುವ ವರ್ಣ *cmd, *cp = *cpp;
	ವರ್ಣ *cp2, **argv;
	ಪೂರ್ಣಾಙ್ಕ base = 0;
	long long ll;
	ಪೂರ್ಣಾಙ್ಕ path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	ಪ್ರತಿ (;*cp != '\0'; cp++) {
		ಯದಿ (*cp == '-') {
			*ignore_errors = 1;
		} ಅನ್ಯಥಾ ಯದಿ (*cp == '@') {
			*disable_echo = 1;
		} ಅನ್ಯಥಾ {
			/* all other characters terminate prefix processing */
			ಭಙ್ಗ;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	ಯದಿ (*cp == '\0' || *cp == '#')
		ಪ್ರತ್ಯಾಗಮ (0);

	ಯದಿ ((argv = makeargv(cp, &argc, 0, ರಿಕ್ತ, ರಿಕ್ತ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Figure out which command we have */
	ಪ್ರತಿ (i = 0; cmds[i].c != ರಿಕ್ತ; i++) {
		ಯದಿ (argv[0] != ರಿಕ್ತ && strcasecmp(cmds[i].c, argv[0]) == 0)
			ಭಙ್ಗ;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	ಯದಿ (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} ಅನ್ಯಥಾ ಯದಿ (cmdnum == -1) {
		error("Invalid command.");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ರಿಕ್ತ;
	optidx = 1;
	ವಿಕಲ್ಪ (cmdnum) {
	ಪಕ್ಷ I_GET:
	ಪಕ್ಷ I_REGET:
	ಪಕ್ಷ I_REPUT:
	ಪಕ್ಷ I_PUT:
		ಯದಿ ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		/* Get first pathname (mandatory) */
		ಯದಿ (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		ಯದಿ (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LINK:
		ಯದಿ ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಗಚ್ಛ parse_two_paths;
	ಪಕ್ಷ I_COPY:
		ಯದಿ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಗಚ್ಛ parse_two_paths;
	ಪಕ್ಷ I_RENAME:
		ಯದಿ ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಗಚ್ಛ parse_two_paths;
	ಪಕ್ಷ I_SYMLINK:
		ಯದಿ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
 parse_two_paths:
		ಯದಿ (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_MKDIR:
	ಪಕ್ಷ I_LMKDIR:
		ಯದಿ ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		path1_mandatory = 1;
		ಗಚ್ಛ parse_one_path;
	ಪಕ್ಷ I_RM:
	ಪಕ್ಷ I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	ಪಕ್ಷ I_CHDIR:
	ಪಕ್ಷ I_LCHDIR:
		ಯದಿ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		ಯದಿ (argc - optidx < 1) {
			ಯದಿ (!path1_mandatory)
				ಭಙ್ಗ; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		ಯದಿ (cmdnum != I_RM)
			undo_glob_escape(*path1);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_DF:
		ಯದಿ ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		/* Default to current directory if no path specified */
		ಯದಿ (argc - optidx < 1)
			*path1 = ರಿಕ್ತ;
		ಅನ್ಯಥಾ {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LS:
		ಯದಿ ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			ಪ್ರತ್ಯಾಗಮ(-1);
		/* Path is optional */
		ಯದಿ (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	ಪಕ್ಷ I_SHELL:
		/* Uses the rest of the line */
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LUMASK:
	ಪಕ್ಷ I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	ಪಕ್ಷ I_CHOWN:
	ಪಕ್ಷ I_CHGRP:
		ಯದಿ ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		/* Get numeric arg (mandatory) */
		ಯದಿ (argc - optidx < 1)
			ಗಚ್ಛ need_ಅಂಕೆ_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		ಯದಿ (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_ಅಂಕೆ_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		*n_arg = ll;
		ಯದಿ (cmdnum == I_LUMASK)
			ಭಙ್ಗ;
		/* Get pathname (mandatory) */
		ಯದಿ (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_QUIT:
	ಪಕ್ಷ I_PWD:
	ಪಕ್ಷ I_LPWD:
	ಪಕ್ಷ I_HELP:
	ಪಕ್ಷ I_VERSION:
	ಪಕ್ಷ I_PROGRESS:
		ಯದಿ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal("Command not implemented");
	}

	*cpp = cp;
	ಪ್ರತ್ಯಾಗಮ(cmdnum);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_dispatch_command(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *cmd, ವರ್ಣ **pwd,
    ಧ್ರುವ ವರ್ಣ *startdir, ಪೂರ್ಣಾಙ್ಕ err_abort, ಪೂರ್ಣಾಙ್ಕ echo_command)
{
	ಧ್ರುವ ವರ್ಣ *ocmd = cmd;
	ವರ್ಣ *path1, *path2, *tmp;
	ಪೂರ್ಣಾಙ್ಕ ignore_errors = 0, disable_echo = 1;
	ಪೂರ್ಣಾಙ್ಕ aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	ಪೂರ್ಣಾಙ್ಕ lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	ಪೂರ್ಣಾಙ್ಕ cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	ವರ್ಣ path_buf[PATH_MAX];
	ಪೂರ್ಣಾಙ್ಕ err = 0;
	glob_t g;

	path1 = path2 = ರಿಕ್ತ;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	ಯದಿ (ignore_errors != 0)
		err_abort = 0;

	ಯದಿ (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, ಪರಿಮಾಣ(g));

	/* Perform command */
	ವಿಕಲ್ಪ (cmdnum) {
	ಪಕ್ಷ 0:
		/* Blank line */
		ಭಙ್ಗ;
	ಪಕ್ಷ -1:
		/* Unrecognized command */
		err = -1;
		ಭಙ್ಗ;
	ಪಕ್ಷ I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	ಪಕ್ಷ I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	ಪಕ್ಷ I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	ಪಕ್ಷ I_LINK:
		ಯದಿ (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ರಿಕ್ತ, &g);
		ಪ್ರತಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ಯದಿ (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			ಯದಿ (err != 0 && err_abort)
				ಭಙ್ಗ;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		ಯದಿ (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		ಅನ್ಯಥಾ
			err = sftp_mkdir(conn, path1, &a, 1);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_CHDIR:
		ಯದಿ (path1 == ರಿಕ್ತ || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		ಯದಿ ((tmp = sftp_realpath(conn, path1)) == ರಿಕ್ತ) {
			err = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ (sftp_stat(conn, tmp, 0, &aa) != 0) {
			ಮುಕ್ತ(tmp);
			err = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			ಮುಕ್ತ(tmp);
			err = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			ಮುಕ್ತ(tmp);
			err = 1;
			ಭಙ್ಗ;
		}
		ಮುಕ್ತ(*pwd);
		*pwd = tmp;
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LS:
		ಯದಿ (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			ಭಙ್ಗ;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ರಿಕ್ತ;
		ಯದಿ (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_DF:
		/* Default to current directory if no path specified */
		ಯದಿ (path1 == ರಿಕ್ತ)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LCHDIR:
		ಯದಿ (path1 == ರಿಕ್ತ || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		ಮುಕ್ತ(path1);
		path1 = tmp;
		ಯದಿ (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LMKDIR:
		ಯದಿ (pflag) {
			ಯದಿ (mkdir_path(path1, 0777) != 0)
				err = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LLS:
		local_do_ls(cmd);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_SHELL:
		local_do_shell(cmd);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ರಿಕ್ತ, &g);
		ಪ್ರತಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ಯದಿ (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			ಯದಿ (err != 0 && err_abort)
				ಭಙ್ಗ;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ I_CHOWN:
	ಪಕ್ಷ I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ರಿಕ್ತ, &g);
		ಪ್ರತಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ಯದಿ ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				ಯದಿ (err_abort) {
					err = -1;
					ಭಙ್ಗ;
				} ಅನ್ಯಥಾ
					ಅನುವರ್ತ;
			}
			ಯದಿ (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				ಯದಿ (err_abort) {
					err = -1;
					ಭಙ್ಗ;
				} ಅನ್ಯಥಾ
					ಅನುವರ್ತ;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			ಯದಿ (cmdnum == I_CHOWN) {
				ಯದಿ (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} ಅನ್ಯಥಾ {
				ಯದಿ (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			ಯದಿ (err != 0 && err_abort)
				ಭಙ್ಗ;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_LPWD:
		ಯದಿ (!getcwd(path_buf, ಪರಿಮಾಣ(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			ಭಙ್ಗ;
		}
		mprintf("Local working directory: %s\n", path_buf);
		ಭಙ್ಗ;
	ಪಕ್ಷ I_QUIT:
		/* Processed below */
		ಭಙ್ಗ;
	ಪಕ್ಷ I_HELP:
		help();
		ಭಙ್ಗ;
	ಪಕ್ಷ I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		ಭಙ್ಗ;
	ಪಕ್ಷ I_PROGRESS:
		showprogress = !showprogress;
		ಯದಿ (showprogress)
			printf("Progress meter enabled\n");
		ಅನ್ಯಥಾ
			printf("Progress meter disabled\n");
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal("%d is not implemented", cmdnum);
	}

	ಯದಿ (g.gl_pathc)
		globfree(&g);
	ಮುಕ್ತ(path1);
	ಮುಕ್ತ(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	ಯದಿ (err_abort && err != 0)
		ಪ್ರತ್ಯಾಗಮ (-1);
	ಅನ್ಯಥಾ ಯದಿ (cmdnum == I_QUIT)
		ಪ್ರತ್ಯಾಗಮ (1);

	ಪ್ರತ್ಯಾಗಮ (0);
}

#ifdef USE_LIBEDIT
ಸ್ಥಿರ ವರ್ಣ *
prompt(Edit_ಸಾಲು *el)
{
	ಪ್ರತ್ಯಾಗಮ ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
ಸ್ಥಿರ ಶೂನ್ಯ
complete_display(ವರ್ಣ **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	ಸಂರಚನಾ winsize ws;
	ವರ್ಣ *tmp;

	/* Count entries for sort and find longest */
	ಪ್ರತಿ (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	ಯದಿ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	ಪ್ರತಿ (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		ಯದಿ (m >= columns) {
			printf("\n");
			m = 1;
		} ಅನ್ಯಥಾ
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
ಸ್ಥಿರ ವರ್ಣ *
complete_ambiguous(ಧ್ರುವ ವರ್ಣ *word, ವರ್ಣ **list, size_t ಎಣಿಕೆ)
{
	size_t i, j, matchlen;
	ವರ್ಣ *tmp;
	ಪೂರ್ಣಾಙ್ಕ len;

	ಯದಿ (word == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;

	ಯದಿ (ಎಣಿಕೆ == 0)
		ಪ್ರತ್ಯಾಗಮ xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	ಪ್ರತಿ (i = 1; i < ಎಣಿಕೆ && list[i] != ರಿಕ್ತ; i++) {
		ಪ್ರತಿ (j = 0; j < matchlen; j++)
			ಯದಿ (list[0][j] != list[i][j])
				ಭಙ್ಗ;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ರಿಕ್ತ, 0);
	ಪ್ರತಿ (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		ಯದಿ (len <= 0 || i + (size_t)len > matchlen)
			ಭಙ್ಗ;
		i += (size_t)len;
	}
	/* If so, truncate */
	ಯದಿ (i < matchlen)
		matchlen = i;

	ಯದಿ (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		ಪ್ರತ್ಯಾಗಮ tmp;
	}

	ಪ್ರತ್ಯಾಗಮ xstrdup(word);
}

/* Autocomplete a sftp command */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
complete_cmd_parse(Edit_ಸಾಲು *el, ವರ್ಣ *cmd, ಪೂರ್ಣಾಙ್ಕ lastarg, ವರ್ಣ quote,
    ಪೂರ್ಣಾಙ್ಕ terminated)
{
	u_int y, ಎಣಿಕೆ = 0, cmdlen, tmplen;
	ವರ್ಣ *tmp, **list, argterm[3];
	ಧ್ರುವ ಸಾಲು_Info *lf;

	list = xcalloc((ಪರಿಮಾಣ(cmds) / ಪರಿಮಾಣ(*cmds)) + 1, ಪರಿಮಾಣ(ವರ್ಣ *));

	/* No command specified: display all available commands */
	ಯದಿ (cmd == ರಿಕ್ತ) {
		ಪ್ರತಿ (y = 0; cmds[y].c; y++)
			list[ಎಣಿಕೆ++] = xstrdup(cmds[y].c);

		list[ಎಣಿಕೆ] = ರಿಕ್ತ;
		complete_display(list, 0);

		ಪ್ರತಿ (y = 0; list[y] != ರಿಕ್ತ; y++)
			ಮುಕ್ತ(list[y]);
		ಮುಕ್ತ(list);
		ಪ್ರತ್ಯಾಗಮ ಎಣಿಕೆ;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	ಪ್ರತಿ (y = 0; cmds[y].c; y++)  {
		ಯದಿ (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[ಎಣಿಕೆ++] = xstrdup(cmds[y].c);
	}
	list[ಎಣಿಕೆ] = ರಿಕ್ತ;

	ಯದಿ (ಎಣಿಕೆ == 0) {
		ಮುಕ್ತ(list);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, ಎಣಿಕೆ);
	ಯದಿ (ಎಣಿಕೆ > 1)
		complete_display(list, 0);

	ಪ್ರತಿ (y = 0; list[y]; y++)
		ಮುಕ್ತ(list[y]);
	ಮುಕ್ತ(list);

	ಯದಿ (tmp != ರಿಕ್ತ) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		ಯದಿ (tmplen > cmdlen)
			ಯದಿ (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_ಸಾಲು(el);
		/* Terminate argument cleanly */
		ಯದಿ (ಎಣಿಕೆ == 1) {
			y = 0;
			ಯದಿ (!terminated)
				argterm[y++] = quote;
			ಯದಿ (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			ಯದಿ (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		ಮುಕ್ತ(tmp);
	}

	ಪ್ರತ್ಯಾಗಮ ಎಣಿಕೆ;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
complete_is_remote(ವರ್ಣ *cmd, ಪೂರ್ಣಾಙ್ಕ cmdarg) {
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (cmd == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಪ್ರತಿ (i = 0; cmds[i].c; i++) {
		ಯದಿ (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			ಯದಿ (cmdarg == 1)
				ಪ್ರತ್ಯಾಗಮ cmds[i].t;
			ಅನ್ಯಥಾ ಯದಿ (cmdarg == 2)
				ಪ್ರತ್ಯಾಗಮ cmds[i].t2;
			ಭಙ್ಗ;
		}
	}

	ಪ್ರತ್ಯಾಗಮ -1;
}

/* Autocomplete a filename "file" */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
complete_match(Edit_ಸಾಲು *el, ಸಂರಚನಾ sftp_conn *conn, ವರ್ಣ *remote_path,
    ವರ್ಣ *file, ಪೂರ್ಣಾಙ್ಕ remote, ಪೂರ್ಣಾಙ್ಕ lastarg, ವರ್ಣ quote, ಪೂರ್ಣಾಙ್ಕ terminated)
{
	glob_t g;
	ವರ್ಣ *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	ಪೂರ್ಣಾಙ್ಕ clen;
	ಧ್ರುವ ಸಾಲು_Info *lf;

	/* Glob from "file" location */
	ಯದಿ (file == ರಿಕ್ತ)
		tmp = xstrdup("*");
	ಅನ್ಯಥಾ
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, ಪರಿಮಾಣ(g));
	ಯದಿ (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ರಿಕ್ತ, &g);
	} ಅನ್ಯಥಾ
		(ಶೂನ್ಯ)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ರಿಕ್ತ, &g);

	/* Determine length of pwd so we can trim completion display */
	ಪ್ರತಿ (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		ಯದಿ (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			ಯದಿ (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		ಯದಿ (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	ಮುಕ್ತ(tmp);
	tmp = ರಿಕ್ತ;

	ಯದಿ (g.gl_matchc == 0)
		ಗಚ್ಛ out;

	ಯದಿ (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	ಯದಿ (file == ರಿಕ್ತ || hadglob)
		ಗಚ್ಛ out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? ರಿಕ್ತ : remote_path);
	ಮುಕ್ತ(tmp2);

	ಯದಿ (tmp == ರಿಕ್ತ)
		ಗಚ್ಛ out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	ಪ್ರತಿ (i = 0; i < filelen; i++) {
		ಯದಿ (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} ಅನ್ಯಥಾ
			isesc = 0;
	}

	ಯದಿ (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(ರಿಕ್ತ, 0);
		ಪ್ರತಿ (i = 0; i < len; i += clen) {
			ಯದಿ ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > ಪರಿಮಾಣ(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			ವಿಕಲ್ಪ (tmp2[i]) {
			ಪಕ್ಷ '\'':
			ಪಕ್ಷ '"':
			ಪಕ್ಷ '\\':
			ಪಕ್ಷ '\t':
			ಪಕ್ಷ '[':
			ಪಕ್ಷ ' ':
			ಪಕ್ಷ '#':
			ಪಕ್ಷ '*':
				ಯದಿ (quote == '\0' || tmp2[i] == quote) {
					ಯದಿ (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					ಭಙ್ಗ;
				}
				/* FALLTHROUGH */
			ಸ್ವಭಾವ:
				ಯದಿ (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				ಭಙ್ಗ;
			}
		}
	}

	lf = el_ಸಾಲು(el);
	ಯದಿ (g.gl_matchc == 1) {
		i = 0;
		ಯದಿ (!terminated && quote != '\0')
			ins[i++] = quote;
		ಯದಿ (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		ಯದಿ (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	ಮುಕ್ತ(tmp);

 out:
	globfree(&g);
	ಪ್ರತ್ಯಾಗಮ g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
ಸ್ಥಿರ unsigned ವರ್ಣ
complete(Edit_ಸಾಲು *el, ಪೂರ್ಣಾಙ್ಕ ch)
{
	ವರ್ಣ **argv, *ಸಾಲು, quote;
	ಪೂರ್ಣಾಙ್ಕ argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ಧ್ರುವ ಸಾಲು_Info *lf;
	ಸಂರಚನಾ complete_ctx *complete_ctx;

	lf = el_ಸಾಲು(el);
	ಯದಿ (el_get(el, EL_CLIENTDATA, (ಶೂನ್ಯ**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	ಸಾಲು = xmalloc(cursor + 1);
	memcpy(ಸಾಲು, lf->buffer, cursor);
	ಸಾಲು[cursor] = '\0';
	argv = makeargv(ಸಾಲು, &carg, 1, &quote, &terminated);
	ಮುಕ್ತ(ಸಾಲು);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	ಸಾಲು = xmalloc(len + 1);
	memcpy(ಸಾಲು, lf->buffer, len);
	ಸಾಲು[len] = '\0';
	argv = makeargv(ಸಾಲು, &argc, 1, ರಿಕ್ತ, ರಿಕ್ತ);

	/* Ensure cursor is at EOL or a argument boundary */
	ಯದಿ (ಸಾಲು[cursor] != ' ' && ಸಾಲು[cursor] != '\0' &&
	    ಸಾಲು[cursor] != '\n') {
		ಮುಕ್ತ(ಸಾಲು);
		ಪ್ರತ್ಯಾಗಮ ret;
	}

	ಯದಿ (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ರಿಕ್ತ, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} ಅನ್ಯಥಾ ಯದಿ (carg == 1 && cursor > 0 && ಸಾಲು[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		ಯದಿ (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} ಅನ್ಯಥಾ ಯದಿ (carg >= 1) {
		/* Handle file parsing */
		ಪೂರ್ಣಾಙ್ಕ remote = 0;
		ಪೂರ್ಣಾಙ್ಕ i = 0, cmdarg = 0;
		ವರ್ಣ *filematch = ರಿಕ್ತ;

		ಯದಿ (carg > 1 && ಸಾಲು[cursor-1] != ' ')
			filematch = argv[carg - 1];

		ಪ್ರತಿ (i = 1; i < carg; i++) {
			/* Skip flags */
			ಯದಿ (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		ಯದಿ (ಸಾಲು[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		ಯದಿ ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	ಮುಕ್ತ(ಸಾಲು);
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif /* USE_LIBEDIT */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
interactive_loop(ಸಂರಚನಾ sftp_conn *conn, ವರ್ಣ *file1, ವರ್ಣ *file2)
{
	ವರ್ಣ *remote_path;
	ವರ್ಣ *dir = ರಿಕ್ತ, *startdir = ರಿಕ್ತ;
	ವರ್ಣ cmd[2048];
	ಪೂರ್ಣಾಙ್ಕ err, interactive;
	Edit_ಸಾಲು *el = ರಿಕ್ತ;
#ifdef USE_LIBEDIT
	ಧ್ರುವ ವರ್ಣ *editor;
	History *hl = ರಿಕ್ತ;
	HistEvent hev;
	ಬಾಹ್ಯ ವರ್ಣ *__progname;
	ಸಂರಚನಾ complete_ctx complete_ctx;

	ಯದಿ (!batchmode && isatty(STDIN_FILENO)) {
		ಯದಿ ((el = el_init(__progname, stdin, stdout, stderr)) == ರಿಕ್ತ)
			fatal("Couldn't initialise editline");
		ಯದಿ ((hl = history_init()) == ರಿಕ್ತ)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, ರಿಕ್ತ);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, ರಿಕ್ತ);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (ಶೂನ್ಯ*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", ರಿಕ್ತ);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", ರಿಕ್ತ);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", ರಿಕ್ತ);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ರಿಕ್ತ);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ರಿಕ್ತ);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", ರಿಕ್ತ);

		/* el_source() may have changed EL_EDITOR to vi */
		ಯದಿ (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", ರಿಕ್ತ);
	}
#endif /* USE_LIBEDIT */

	ಯದಿ ((remote_path = sftp_realpath(conn, ".")) == ರಿಕ್ತ)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	ಯದಿ (file1 != ರಿಕ್ತ) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		ಯದಿ (sftp_remote_is_dir(conn, dir) && file2 == ರಿಕ್ತ) {
			ಯದಿ (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, ಪರಿಮಾಣ cmd, "cd \"%s\"", dir);
			ಯದಿ (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				ಮುಕ್ತ(dir);
				ಮುಕ್ತ(startdir);
				ಮುಕ್ತ(remote_path);
				ಮುಕ್ತ(conn);
				ಪ್ರತ್ಯಾಗಮ (-1);
			}
		} ಅನ್ಯಥಾ {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			ಮುಕ್ತ(dir);
			ಮುಕ್ತ(startdir);
			ಮುಕ್ತ(remote_path);
			ಮುಕ್ತ(conn);
			ಪ್ರತ್ಯಾಗಮ (err);
		}
		ಮುಕ್ತ(dir);
	}

	setvbuf(stdout, ರಿಕ್ತ, _IOLBF, 0);
	setvbuf(infile, ರಿಕ್ತ, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	ಪ್ರತಿ (;;) {
		ಸಂರಚನಾ sigaction sa;

		interrupted = 0;
		memset(&sa, 0, ಪರಿಮಾಣ(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		ಯದಿ (sigaction(SIGINT, &sa, ರಿಕ್ತ) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			ಭಙ್ಗ;
		}
		ಯದಿ (el == ರಿಕ್ತ) {
			ಯದಿ (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			ಯದಿ (fgets(cmd, ಪರಿಮಾಣ(cmd), infile) == ರಿಕ್ತ) {
				ಯದಿ (interactive)
					printf("\n");
				ಯದಿ (interrupted)
					ಅನುವರ್ತ;
				ಭಙ್ಗ;
			}
		} ಅನ್ಯಥಾ {
#ifdef USE_LIBEDIT
			ಧ್ರುವ ವರ್ಣ *ಸಾಲು;
			ಪೂರ್ಣಾಙ್ಕ ಎಣಿಕೆ = 0;

			ಯದಿ ((ಸಾಲು = el_gets(el, &ಎಣಿಕೆ)) == ರಿಕ್ತ ||
			    ಎಣಿಕೆ <= 0) {
				printf("\n");
				ಯದಿ (interrupted)
					ಅನುವರ್ತ;
				ಭಙ್ಗ;
			}
			history(hl, &hev, H_ENTER, ಸಾಲು);
			ಯದಿ (strlcpy(cmd, ಸಾಲು, ಪರಿಮಾಣ(cmd)) >= ಪರಿಮಾಣ(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				ಅನುವರ್ತ;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == ರಿಕ್ತ);
		ಯದಿ (err != 0)
			ಭಙ್ಗ;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	ಮುಕ್ತ(remote_path);
	ಮುಕ್ತ(startdir);
	ಮುಕ್ತ(conn);

#ifdef USE_LIBEDIT
	ಯದಿ (hl != ರಿಕ್ತ)
		history_end(hl);
	ಯದಿ (el != ರಿಕ್ತ)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	ಪ್ರತ್ಯಾಗಮ (err >= 0 ? 0 : -1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
connect_to_server(ವರ್ಣ *path, ವರ್ಣ **args, ಪೂರ್ಣಾಙ್ಕ *in, ಪೂರ್ಣಾಙ್ಕ *out)
{
	ಪೂರ್ಣಾಙ್ಕ c_in, c_out;
#ifdef USE_PIPES
	ಪೂರ್ಣಾಙ್ಕ pin[2], pout[2];

	ಯದಿ ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#ಅನ್ಯಥಾ /* USE_PIPES */
	ಪೂರ್ಣಾಙ್ಕ inout[2];

	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	ಯದಿ ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	ಅನ್ಯಥಾ ಯದಿ (sshpid == 0) {
		ಯದಿ ((dup2(c_in, STDIN_FILENO) == -1) ||
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

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	ಬಾಹ್ಯ ವರ್ಣ *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv)
{
	ಪೂರ್ಣಾಙ್ಕ r, in, out, ch, err, tmp, port = -1, noisy = 0;
	ವರ್ಣ *host = ರಿಕ್ತ, *user, *cp, **cpp, *file2 = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ debug_level = 0;
	ವರ್ಣ *file1 = ರಿಕ್ತ, *sftp_server = ರಿಕ್ತ;
	ವರ್ಣ *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ optind;
	ಬಾಹ್ಯ ವರ್ಣ *optarg;
	ಸಂರಚನಾ sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t ಅಂಕೆ_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', ಪರಿಮಾಣ(args));
	args.list = ರಿಕ್ತ;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	ಯಾವತ್ ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		ವಿಕಲ್ಪ (ch) {
		/* Passed through to ssh(1) */
		ಪಕ್ಷ 'A':
		ಪಕ್ಷ '4':
		ಪಕ್ಷ '6':
		ಪಕ್ಷ 'C':
			addargs(&args, "-%c", ch);
			ಭಙ್ಗ;
		/* Passed through to ssh(1) with argument */
		ಪಕ್ಷ 'F':
		ಪಕ್ಷ 'J':
		ಪಕ್ಷ 'c':
		ಪಕ್ಷ 'i':
		ಪಕ್ಷ 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'P':
			port = a2port(optarg);
			ಯದಿ (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'v':
			ಯದಿ (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			ಭಙ್ಗ;
		ಪಕ್ಷ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ಭಙ್ಗ;
		ಪಕ್ಷ '2':
			/* accept silently */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'a':
			global_aflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			ಯದಿ (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'b':
			ಯದಿ (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			ಯದಿ (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ರಿಕ್ತ)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			ಭಙ್ಗ;
		ಪಕ್ಷ 'f':
			global_fflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'p':
			global_pflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'D':
			sftp_direct = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ಯದಿ (errstr != ರಿಕ್ತ)
				usage();
			limit_kbps *= 1024; /* kbps */
			ಭಙ್ಗ;
		ಪಕ್ಷ 'r':
			global_rflag = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'R':
			ಅಂಕೆ_requests = strtol(optarg, &cp, 10);
			ಯದಿ (ಅಂಕೆ_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			ಭಙ್ಗ;
		ಪಕ್ಷ 's':
			sftp_server = optarg;
			ಭಙ್ಗ;
		ಪಕ್ಷ 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			ಭಙ್ಗ;
		ಪಕ್ಷ 'X':
			/* Please keep in sync with ssh.c -X */
			ಯದಿ (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				ಯದಿ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ಯದಿ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} ಅನ್ಯಥಾ ಯದಿ (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ಯದಿ (errstr != ರಿಕ್ತ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				ಅಂಕೆ_requests = (size_t)llv;
			} ಅನ್ಯಥಾ {
				fatal("Invalid -X option");
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ 'h':
		ಸ್ವಭಾವ:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	ಯದಿ (!isatty(STDERR_FILENO))
		showprogress = 0;

	ಯದಿ (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	ಯದಿ (sftp_direct == ರಿಕ್ತ) {
		ಯದಿ (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		ವಿಕಲ್ಪ (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		ಪಕ್ಷ -1:
			usage();
			ಭಙ್ಗ;
		ಪಕ್ಷ 0:
			ಯದಿ (tmp != -1)
				port = tmp;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			/* Try with user, host and path. */
			ಯದಿ (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				ಭಙ್ಗ;
			/* Try with user and host. */
			ಯದಿ (parse_user_host_port(*argv, &user, &host, ರಿಕ್ತ)
			    == 0)
				ಭಙ್ಗ;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			ಭಙ್ಗ;
		}
		file2 = *(argv + 1);

		ಯದಿ (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		ಯದಿ (port != -1)
			addargs(&args, "-oPort %d", port);
		ಯದಿ (user != ರಿಕ್ತ) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		ಯದಿ (sftp_server == ರಿಕ್ತ || strchr(sftp_server, '/') == ರಿಕ್ತ)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != ರಿಕ್ತ ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		ಯದಿ (cpp[0] == ರಿಕ್ತ)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, ಅಂಕೆ_requests, limit_kbps);
	ಯದಿ (conn == ರಿಕ್ತ)
		fatal("Couldn't initialise connection to server");

	ಯದಿ (!quiet) {
		ಯದಿ (sftp_direct == ರಿಕ್ತ)
			fprintf(stderr, "Connected to %s.\n", host);
		ಅನ್ಯಥಾ
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#ಯದಿ !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	ಯದಿ (batchmode)
		fclose(infile);

	ಯಾವತ್ (waitpid(sshpid, ರಿಕ್ತ, 0) == -1 && sshpid > 1)
		ಯದಿ (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
