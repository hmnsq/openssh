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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/ioctl.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/statvfs.h>
#അന്തര്ഭാവ <sys/wait.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <glob.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#അന്തര്ഭാവ <histedit.h>
#അല്ലെങ്കിൽ
തരനിർവചനം ശൂന്യം Edit_വരി;
#endif
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <util.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "utf8.h"

#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sftp-common.h"
#അന്തര്ഭാവ "sftp-client.h"
#അന്തര്ഭാവ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
പൂർണ്ണസംഖ്യ batchmode = 0;

/* PID of ssh transport process */
സ്ഥിതം അസ്ഥിര pid_t sshpid = -1;

/* Suppress diagnostic messages */
പൂർണ്ണസംഖ്യ quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
പൂർണ്ണസംഖ്യ showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
പൂർണ്ണസംഖ്യ global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
പൂർണ്ണസംഖ്യ global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
പൂർണ്ണസംഖ്യ global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
പൂർണ്ണസംഖ്യ global_fflag = 0;

/* SIGINT received during command processing */
അസ്ഥിര sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
പൂർണ്ണസംഖ്യ sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
ഘടന complete_ctx {
	ഘടന sftp_conn *conn;
	അക്ഷരം **remote_pathp;
};

പൂർണ്ണസംഖ്യ sftp_glob(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ,
    പൂർണ്ണസംഖ്യ (*)(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ), glob_t *); /* proto for sftp-glob.c */

ബാഹ്യ അക്ഷരം *__progname;

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
എണ്ണൽ sftp_command {
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

ഘടന CMD {
	സ്ഥിരം അക്ഷരം *c;
	സ്ഥിരം പൂർണ്ണസംഖ്യ n;
	സ്ഥിരം പൂർണ്ണസംഖ്യ t;	/* Completion type for the first argument */
	സ്ഥിരം പൂർണ്ണസംഖ്യ t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

സ്ഥിതം സ്ഥിരം ഘടന CMD cmds[] = {
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
	{ ശൂന്യ,		-1,		-1,		-1	}
};

സ്ഥിതം ശൂന്യം
killchild(പൂർണ്ണസംഖ്യ signo)
{
	pid_t pid;

	pid = sshpid;
	എങ്കിൽ (pid > 1) {
		kill(pid, SIGTERM);
		(ശൂന്യം)waitpid(pid, ശൂന്യ, 0);
	}

	_exit(1);
}

സ്ഥിതം ശൂന്യം
suspchild(പൂർണ്ണസംഖ്യ signo)
{
	പൂർണ്ണസംഖ്യ save_errno = errno;
	എങ്കിൽ (sshpid > 1) {
		kill(sshpid, signo);
		ആകുമ്പോൾ (waitpid(sshpid, ശൂന്യ, WUNTRACED) == -1 && errno == EINTR)
			തുടരുക;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

സ്ഥിതം ശൂന്യം
cmd_interrupt(പൂർണ്ണസംഖ്യ signo)
{
	സ്ഥിരം അക്ഷരം സന്ദേശം[] = "\rInterrupt  \n";
	പൂർണ്ണസംഖ്യ olderrno = errno;

	(ശൂന്യം)ലിഖ(STDERR_FILENO, സന്ദേശം, വലുപ്പം(സന്ദേശം) - 1);
	interrupted = 1;
	errno = olderrno;
}

സ്ഥിതം ശൂന്യം
read_interrupt(പൂർണ്ണസംഖ്യ signo)
{
	interrupted = 1;
}

സ്ഥിതം ശൂന്യം
sigchld_handler(പൂർണ്ണസംഖ്യ sig)
{
	പൂർണ്ണസംഖ്യ save_errno = errno;
	pid_t pid;
	സ്ഥിരം അക്ഷരം സന്ദേശം[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	ആകുമ്പോൾ ((pid = waitpid(sshpid, ശൂന്യ, WNOHANG)) == -1 && errno == EINTR)
		തുടരുക;
	എങ്കിൽ (pid == sshpid) {
		എങ്കിൽ (!quiet)
		    (ശൂന്യം)ലിഖ(STDERR_FILENO, സന്ദേശം, വലുപ്പം(സന്ദേശം) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

സ്ഥിതം ശൂന്യം
help(ശൂന്യം)
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

സ്ഥിതം ശൂന്യം
local_do_shell(സ്ഥിരം അക്ഷരം *args)
{
	പൂർണ്ണസംഖ്യ status;
	അക്ഷരം *shell;
	pid_t pid;

	എങ്കിൽ (!*args)
		args = ശൂന്യ;

	എങ്കിൽ ((shell = getenv("SHELL")) == ശൂന്യ || *shell == '\0')
		shell = _PATH_BSHELL;

	എങ്കിൽ ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	എങ്കിൽ (pid == 0) {
		എങ്കിൽ (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (അക്ഷരം *)ശൂന്യ);
		} അല്ലെങ്കിൽ {
			debug3("Executing %s", shell);
			execl(shell, shell, (അക്ഷരം *)ശൂന്യ);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1)
		എങ്കിൽ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	എങ്കിൽ (!WIFEXITED(status))
		error("Shell exited abnormally");
	അല്ലെങ്കിൽ എങ്കിൽ (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

സ്ഥിതം ശൂന്യം
local_do_ls(സ്ഥിരം അക്ഷരം *args)
{
	എങ്കിൽ (!args || !*args)
		local_do_shell(_PATH_LS);
	അല്ലെങ്കിൽ {
		പൂർണ്ണസംഖ്യ len = strlen(_PATH_LS " ") + strlen(args) + 1;
		അക്ഷരം *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		സ്വതന്ത്രം(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
സ്ഥിതം അക്ഷരം *
path_strip(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം അക്ഷരം *strip)
{
	size_t len;

	എങ്കിൽ (strip == ശൂന്യ || (len = strlen(strip)) == 0)
		തിരികെ (xstrdup(path));

	എങ്കിൽ (strncmp(path, strip, len) == 0) {
		എങ്കിൽ (strip[len - 1] != '/' && path[len] == '/')
			len++;
		തിരികെ (xstrdup(path + len));
	}

	തിരികെ (xstrdup(path));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_getput_flags(സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc,
    പൂർണ്ണസംഖ്യ *aflag, പൂർണ്ണസംഖ്യ *fflag, പൂർണ്ണസംഖ്യ *pflag, പൂർണ്ണസംഖ്യ *rflag)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	ആകുമ്പോൾ ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'a':
			*aflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'f':
			*fflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'p':
		അവസ്ഥ 'P':
			*pflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'r':
		അവസ്ഥ 'R':
			*rflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("%s: Invalid flag -%c", cmd, optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_mkdir_flags(സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc, പൂർണ്ണസംഖ്യ *pflag)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	ആകുമ്പോൾ ((ch = getopt(argc, argv, "p")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'p':
			*pflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("%s: Invalid flag -%c", cmd, optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_link_flags(സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc, പൂർണ്ണസംഖ്യ *sflag)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	ആകുമ്പോൾ ((ch = getopt(argc, argv, "s")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 's':
			*sflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("%s: Invalid flag -%c", cmd, optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_rename_flags(സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc, പൂർണ്ണസംഖ്യ *lflag)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	ആകുമ്പോൾ ((ch = getopt(argc, argv, "l")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'l':
			*lflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("%s: Invalid flag -%c", cmd, optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_ls_flags(അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc, പൂർണ്ണസംഖ്യ *lflag)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	ആകുമ്പോൾ ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			നിർത്തുക;
		അവസ്ഥ 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			നിർത്തുക;
		അവസ്ഥ 'a':
			*lflag |= LS_SHOW_ALL;
			നിർത്തുക;
		അവസ്ഥ 'f':
			*lflag &= ~SORT_FLAGS;
			നിർത്തുക;
		അവസ്ഥ 'h':
			*lflag |= LS_SI_UNITS;
			നിർത്തുക;
		അവസ്ഥ 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			നിർത്തുക;
		അവസ്ഥ 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			നിർത്തുക;
		അവസ്ഥ 'r':
			*lflag |= LS_REVERSE_SORT;
			നിർത്തുക;
		അവസ്ഥ 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("ls: Invalid flag -%c", optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_df_flags(സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc, പൂർണ്ണസംഖ്യ *hflag, പൂർണ്ണസംഖ്യ *iflag)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	ആകുമ്പോൾ ((ch = getopt(argc, argv, "hi")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'h':
			*hflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'i':
			*iflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("%s: Invalid flag -%c", cmd, optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_ch_flags(സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc, പൂർണ്ണസംഖ്യ *hflag)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	ആകുമ്പോൾ ((ch = getopt(argc, argv, "h")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		അവസ്ഥ 'h':
			*hflag = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("%s: Invalid flag -%c", cmd, optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_no_flags(സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **argv, പൂർണ്ണസംഖ്യ argc)
{
	ബാഹ്യ പൂർണ്ണസംഖ്യ opterr, optind, optopt, optreset;
	പൂർണ്ണസംഖ്യ ch;

	optind = optreset = 1;
	opterr = 0;

	ആകുമ്പോൾ ((ch = getopt(argc, argv, "")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		സ്ഥിരസ്ഥിതി:
			error("%s: Invalid flag -%c", cmd, optopt);
			തിരികെ -1;
		}
	}

	തിരികെ optind;
}

സ്ഥിതം അക്ഷരം *
escape_glob(സ്ഥിരം അക്ഷരം *s)
{
	size_t i, o, len;
	അക്ഷരം *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	വേണ്ടി (i = o = 0; i < len; i++) {
		എങ്കിൽ (strchr("[]?*\\", s[i]) != ശൂന്യ)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	തിരികെ ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
സ്ഥിതം അക്ഷരം *
make_absolute_pwd_glob(അക്ഷരം *p, സ്ഥിരം അക്ഷരം *pwd)
{
	അക്ഷരം *ret, *escpwd;

	escpwd = escape_glob(pwd);
	എങ്കിൽ (p == ശൂന്യ)
		തിരികെ escpwd;
	ret = sftp_make_absolute(p, escpwd);
	സ്വതന്ത്രം(escpwd);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
local_is_dir(സ്ഥിരം അക്ഷരം *path)
{
	ഘടന stat sb;

	എങ്കിൽ (stat(path, &sb) == -1)
		തിരികെ 0;
	തിരികെ S_ISDIR(sb.st_mode);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
process_get(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *src, സ്ഥിരം അക്ഷരം *dst,
    സ്ഥിരം അക്ഷരം *pwd, പൂർണ്ണസംഖ്യ pflag, പൂർണ്ണസംഖ്യ rflag, പൂർണ്ണസംഖ്യ resume, പൂർണ്ണസംഖ്യ fflag)
{
	അക്ഷരം *filename, *abs_src = ശൂന്യ, *abs_dst = ശൂന്യ, *tmp = ശൂന്യ;
	glob_t g;
	പൂർണ്ണസംഖ്യ i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, വലുപ്പം(g));

	debug3("Looking up %s", abs_src);
	എങ്കിൽ ((r = sftp_glob(conn, abs_src, GLOB_MARK, ശൂന്യ, &g)) != 0) {
		എങ്കിൽ (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} അല്ലെങ്കിൽ {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		പോകുക out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	എങ്കിൽ (g.gl_matchc > 1 && dst != ശൂന്യ && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		പോകുക out;
	}

	വേണ്ടി (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		എങ്കിൽ ((filename = basename(tmp)) == ശൂന്യ) {
			error("basename %s: %s", tmp, strerror(errno));
			സ്വതന്ത്രം(tmp);
			err = -1;
			പോകുക out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		എങ്കിൽ (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		എങ്കിൽ (g.gl_matchc == 1 && dst) {
			എങ്കിൽ (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} അല്ലെങ്കിൽ {
				abs_dst = xstrdup(dst);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} അല്ലെങ്കിൽ {
			abs_dst = xstrdup(filename);
		}
		സ്വതന്ത്രം(tmp);

		resume |= global_aflag;
		എങ്കിൽ (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		അല്ലെങ്കിൽ എങ്കിൽ (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		എങ്കിൽ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			എങ്കിൽ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ശൂന്യ, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (sftp_download(conn, g.gl_pathv[i], abs_dst, ശൂന്യ,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		സ്വതന്ത്രം(abs_dst);
		abs_dst = ശൂന്യ;
	}

out:
	സ്വതന്ത്രം(abs_src);
	globfree(&g);
	തിരികെ(err);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
process_put(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *src, സ്ഥിരം അക്ഷരം *dst,
    സ്ഥിരം അക്ഷരം *pwd, പൂർണ്ണസംഖ്യ pflag, പൂർണ്ണസംഖ്യ rflag, പൂർണ്ണസംഖ്യ resume, പൂർണ്ണസംഖ്യ fflag)
{
	അക്ഷരം *tmp_dst = ശൂന്യ;
	അക്ഷരം *abs_dst = ശൂന്യ;
	അക്ഷരം *tmp = ശൂന്യ, *filename = ശൂന്യ;
	glob_t g;
	പൂർണ്ണസംഖ്യ err = 0;
	പൂർണ്ണസംഖ്യ i, dst_is_dir = 1;
	ഘടന stat sb;

	എങ്കിൽ (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, വലുപ്പം(g));
	debug3("Looking up %s", src);
	എങ്കിൽ (glob(src, GLOB_NOCHECK | GLOB_MARK, ശൂന്യ, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		പോകുക out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	എങ്കിൽ (tmp_dst != ശൂന്യ)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	എങ്കിൽ (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		പോകുക out;
	}

	വേണ്ടി (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		എങ്കിൽ (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			തുടരുക;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		എങ്കിൽ ((filename = basename(tmp)) == ശൂന്യ) {
			error("basename %s: %s", tmp, strerror(errno));
			സ്വതന്ത്രം(tmp);
			err = -1;
			പോകുക out;
		}
		/* Special handling for source of '..' */
		എങ്കിൽ (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		സ്വതന്ത്രം(abs_dst);
		abs_dst = ശൂന്യ;
		എങ്കിൽ (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			എങ്കിൽ (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			അല്ലെങ്കിൽ
				abs_dst = xstrdup(tmp_dst);
		} അല്ലെങ്കിൽ എങ്കിൽ (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} അല്ലെങ്കിൽ {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		സ്വതന്ത്രം(tmp);

		resume |= global_aflag;
		എങ്കിൽ (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		അല്ലെങ്കിൽ എങ്കിൽ (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		എങ്കിൽ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			എങ്കിൽ (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	സ്വതന്ത്രം(abs_dst);
	സ്വതന്ത്രം(tmp_dst);
	globfree(&g);
	തിരികെ(err);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sdirent_comp(സ്ഥിരം ശൂന്യം *aa, സ്ഥിരം ശൂന്യം *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	പൂർണ്ണസംഖ്യ rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	എങ്കിൽ (sort_flag & LS_NAME_SORT)
		തിരികെ (rmul * strcmp(a->filename, b->filename));
	അല്ലെങ്കിൽ എങ്കിൽ (sort_flag & LS_TIME_SORT)
		തിരികെ (rmul * NCMP(a->a.mtime, b->a.mtime));
	അല്ലെങ്കിൽ എങ്കിൽ (sort_flag & LS_SIZE_SORT)
		തിരികെ (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
സ്ഥിതം പൂർണ്ണസംഖ്യ
do_ls_dir(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path,
    സ്ഥിരം അക്ഷരം *strip_path, പൂർണ്ണസംഖ്യ lflag)
{
	പൂർണ്ണസംഖ്യ n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	എങ്കിൽ ((n = sftp_readdir(conn, path, &d)) != 0)
		തിരികെ (n);

	എങ്കിൽ (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		ഘടന winsize ws;
		അക്ഷരം *tmp;

		/* Count entries for sort and find longest filename */
		വേണ്ടി (n = 0; d[n] != ശൂന്യ; n++) {
			എങ്കിൽ (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		സ്വതന്ത്രം(tmp);

		എങ്കിൽ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	എങ്കിൽ (lflag & SORT_FLAGS) {
		വേണ്ടി (n = 0; d[n] != ശൂന്യ; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, വലുപ്പം(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	വേണ്ടി (n = 0; d[n] != ശൂന്യ && !interrupted; n++) {
		അക്ഷരം *tmp, *fname;

		എങ്കിൽ (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			തുടരുക;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		സ്വതന്ത്രം(tmp);

		എങ്കിൽ (lflag & LS_LONG_VIEW) {
			എങ്കിൽ ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				അക്ഷരം *lname;
				ഘടന stat sb;
				സ്ഥിരം അക്ഷരം *user = ശൂന്യ, *group = ശൂന്യ;

				memset(&sb, 0, വലുപ്പം(sb));
				attrib_to_stat(&d[n]->a, &sb);
				എങ്കിൽ ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				സ്വതന്ത്രം(lname);
			} അല്ലെങ്കിൽ
				mprintf("%s\n", d[n]->longname);
		} അല്ലെങ്കിൽ {
			mprintf("%-*s", colspace, fname);
			എങ്കിൽ (c >= columns) {
				printf("\n");
				c = 1;
			} അല്ലെങ്കിൽ
				c++;
		}

		സ്വതന്ത്രം(fname);
	}

	എങ്കിൽ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	തിരികെ (0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sglob_comp(സ്ഥിരം ശൂന്യം *aa, സ്ഥിരം ശൂന്യം *bb)
{
	u_int a = *(സ്ഥിരം u_int *)aa;
	u_int b = *(സ്ഥിരം u_int *)bb;
	സ്ഥിരം അക്ഷരം *ap = sort_glob->gl_pathv[a];
	സ്ഥിരം അക്ഷരം *bp = sort_glob->gl_pathv[b];
	സ്ഥിരം ഘടന stat *as = sort_glob->gl_statv[a];
	സ്ഥിരം ഘടന stat *bs = sort_glob->gl_statv[b];
	പൂർണ്ണസംഖ്യ rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	എങ്കിൽ (as == ശൂന്യ || bs == ശൂന്യ)
		തിരികെ (as == bs) ? 0 : (as == ശൂന്യ ? rmul : -rmul);
	എങ്കിൽ (sort_flag & LS_NAME_SORT)
		തിരികെ (rmul * strcmp(ap, bp));
	അല്ലെങ്കിൽ എങ്കിൽ (sort_flag & LS_TIME_SORT) {
#എങ്കിൽ defined(HAVE_STRUCT_STAT_ST_MTIM)
		എങ്കിൽ (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			തിരികെ 0;
		തിരികെ timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_STRUCT_STAT_ST_MTIME)
		തിരികെ (rmul * NCMP(as->st_mtime, bs->st_mtime));
#അല്ലെങ്കിൽ
	തിരികെ rmul * 1;
#endif
	} അല്ലെങ്കിൽ എങ്കിൽ (sort_flag & LS_SIZE_SORT)
		തിരികെ (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
സ്ഥിതം പൂർണ്ണസംഖ്യ
do_globbed_ls(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path,
    സ്ഥിരം അക്ഷരം *strip_path, പൂർണ്ണസംഖ്യ lflag)
{
	അക്ഷരം *fname, *lname;
	glob_t g;
	പൂർണ്ണസംഖ്യ err, r;
	ഘടന winsize ws;
	u_int i, j, nentries, *indices = ശൂന്യ, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, വലുപ്പം(g));

	എങ്കിൽ ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ശൂന്യ, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		എങ്കിൽ (g.gl_pathc)
			globfree(&g);
		എങ്കിൽ (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} അല്ലെങ്കിൽ {
			error("Can't ls: \"%s\" not found", path);
		}
		തിരികെ -1;
	}

	എങ്കിൽ (interrupted)
		പോകുക out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	എങ്കിൽ (g.gl_matchc == 1 && g.gl_statv[0] != ശൂന്യ &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		തിരികെ err;
	}

	എങ്കിൽ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	എങ്കിൽ (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		വേണ്ടി (i = 0; g.gl_pathv[i]; i++)
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
	വേണ്ടി (nentries = 0; g.gl_pathv[nentries] != ശൂന്യ; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, വലുപ്പം(*indices));
	വേണ്ടി (i = 0; i < nentries; i++)
		indices[i] = i;

	എങ്കിൽ (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, വലുപ്പം(*indices), sglob_comp);
		sort_glob = ശൂന്യ;
	}

	get_remote_user_groups_from_glob(conn, &g);
	വേണ്ടി (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		എങ്കിൽ (lflag & LS_LONG_VIEW) {
			സ്ഥിരം അക്ഷരം *user = ശൂന്യ, *group = ശൂന്യ;

			എങ്കിൽ (g.gl_statv[i] == ശൂന്യ) {
				error("no stat information for %s", fname);
				സ്വതന്ത്രം(fname);
				തുടരുക;
			}
			എങ്കിൽ ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			സ്വതന്ത്രം(lname);
		} അല്ലെങ്കിൽ {
			mprintf("%-*s", colspace, fname);
			എങ്കിൽ (c >= columns) {
				printf("\n");
				c = 1;
			} അല്ലെങ്കിൽ
				c++;
		}
		സ്വതന്ത്രം(fname);
	}

	എങ്കിൽ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	എങ്കിൽ (g.gl_pathc)
		globfree(&g);
	സ്വതന്ത്രം(indices);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_df(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ hflag, പൂർണ്ണസംഖ്യ iflag)
{
	ഘടന sftp_statvfs st;
	അക്ഷരം s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	അക്ഷരം s_വേര്[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	അക്ഷരം s_icapacity[16], s_dcapacity[16];

	എങ്കിൽ (sftp_statvfs(conn, path, &st, 1) == -1)
		തിരികെ -1;
	എങ്കിൽ (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", വലുപ്പം(s_icapacity));
	അല്ലെങ്കിൽ {
		snprintf(s_icapacity, വലുപ്പം(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	എങ്കിൽ (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", വലുപ്പം(s_dcapacity));
	അല്ലെങ്കിൽ {
		snprintf(s_dcapacity, വലുപ്പം(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	എങ്കിൽ (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} അല്ലെങ്കിൽ എങ്കിൽ (hflag) {
		strlcpy(s_used, "error", വലുപ്പം(s_used));
		strlcpy(s_avail, "error", വലുപ്പം(s_avail));
		strlcpy(s_വേര്, "error", വലുപ്പം(s_വേര്));
		strlcpy(s_total, "error", വലുപ്പം(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_വേര്);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_വേര്, s_dcapacity);
	} അല്ലെങ്കിൽ {
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
	തിരികെ 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
സ്ഥിതം ശൂന്യം
undo_glob_escape(അക്ഷരം *s)
{
	size_t i, j;

	വേണ്ടി (i = j = 0;;) {
		എങ്കിൽ (s[i] == '\0') {
			s[j] = '\0';
			തിരികെ;
		}
		എങ്കിൽ (s[i] != '\\') {
			s[j++] = s[i++];
			തുടരുക;
		}
		/* s[i] == '\\' */
		++i;
		തിരഞ്ഞെടുപ്പ് (s[i]) {
		അവസ്ഥ '?':
		അവസ്ഥ '[':
		അവസ്ഥ '*':
		അവസ്ഥ '\\':
			s[j++] = s[i++];
			നിർത്തുക;
		അവസ്ഥ '\0':
			s[j++] = '\\';
			s[j] = '\0';
			തിരികെ;
		സ്ഥിരസ്ഥിതി:
			s[j++] = '\\';
			s[j++] = s[i++];
			നിർത്തുക;
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
സ്ഥിതം അക്ഷരം **
makeargv(സ്ഥിരം അക്ഷരം *arg, പൂർണ്ണസംഖ്യ *argcp, പൂർണ്ണസംഖ്യ sloppy, അക്ഷരം *lastquote,
    u_int *terminated)
{
	പൂർണ്ണസംഖ്യ argc, quot;
	size_t i, j;
	സ്ഥിതം അക്ഷരം argvs[MAXARGLEN];
	സ്ഥിതം അക്ഷരം *argv[MAXARGS + 1];
	എണ്ണൽ { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	എങ്കിൽ (strlen(arg) > വലുപ്പം(argvs) - 1) {
 args_too_longs:
		error("string too long");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (terminated != ശൂന്യ)
		*terminated = 1;
	എങ്കിൽ (lastquote != ശൂന്യ)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	വേണ്ടി (;;) {
		എങ്കിൽ ((size_t)argc >= വലുപ്പം(argv) / വലുപ്പം(*argv)){
			error("Too many arguments.");
			തിരികെ ശൂന്യ;
		}
		എങ്കിൽ (isspace((unsigned അക്ഷരം)arg[i])) {
			എങ്കിൽ (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} അല്ലെങ്കിൽ എങ്കിൽ (state != MA_START)
				argvs[j++] = arg[i];
		} അല്ലെങ്കിൽ എങ്കിൽ (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			എങ്കിൽ (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				എങ്കിൽ (lastquote != ശൂന്യ)
					*lastquote = arg[i];
			} അല്ലെങ്കിൽ എങ്കിൽ (state == MA_UNQUOTED)
				state = q;
			അല്ലെങ്കിൽ എങ്കിൽ (state == q)
				state = MA_UNQUOTED;
			അല്ലെങ്കിൽ
				argvs[j++] = arg[i];
		} അല്ലെങ്കിൽ എങ്കിൽ (arg[i] == '\\') {
			എങ്കിൽ (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				എങ്കിൽ (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} അല്ലെങ്കിൽ എങ്കിൽ (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					എങ്കിൽ (j >= വലുപ്പം(argvs) - 5)
						പോകുക args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} അല്ലെങ്കിൽ {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} അല്ലെങ്കിൽ {
				എങ്കിൽ (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					എങ്കിൽ (lastquote != ശൂന്യ)
						*lastquote = '\0';
				}
				എങ്കിൽ (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} അല്ലെങ്കിൽ {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					എങ്കിൽ (arg[i] == '\0')
						പോകുക early_nul;
					argvs[j++] = arg[i];
				}
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (arg[i] == '#') {
			എങ്കിൽ (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			അല്ലെങ്കിൽ
				പോകുക string_done;
		} അല്ലെങ്കിൽ എങ്കിൽ (arg[i] == '\0') {
			എങ്കിൽ (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				എങ്കിൽ (sloppy) {
					state = MA_UNQUOTED;
					എങ്കിൽ (terminated != ശൂന്യ)
						*terminated = 0;
					പോകുക string_done;
				}
				error("Unterminated quoted argument");
				തിരികെ ശൂന്യ;
			}
 string_done:
			എങ്കിൽ (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			നിർത്തുക;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				എങ്കിൽ (lastquote != ശൂന്യ)
					*lastquote = '\0';
			}
			എങ്കിൽ ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				എങ്കിൽ (j >= വലുപ്പം(argvs) - 3)
					പോകുക args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} അല്ലെങ്കിൽ
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	തിരികെ argv;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_args(സ്ഥിരം അക്ഷരം **cpp, പൂർണ്ണസംഖ്യ *ignore_errors, പൂർണ്ണസംഖ്യ *disable_echo, പൂർണ്ണസംഖ്യ *aflag,
	  പൂർണ്ണസംഖ്യ *fflag, പൂർണ്ണസംഖ്യ *hflag, പൂർണ്ണസംഖ്യ *iflag, പൂർണ്ണസംഖ്യ *lflag, പൂർണ്ണസംഖ്യ *pflag,
	  പൂർണ്ണസംഖ്യ *rflag, പൂർണ്ണസംഖ്യ *sflag,
    unsigned long *n_arg, അക്ഷരം **path1, അക്ഷരം **path2)
{
	സ്ഥിരം അക്ഷരം *cmd, *cp = *cpp;
	അക്ഷരം *cp2, **argv;
	പൂർണ്ണസംഖ്യ base = 0;
	long long ll;
	പൂർണ്ണസംഖ്യ path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	വേണ്ടി (;*cp != '\0'; cp++) {
		എങ്കിൽ (*cp == '-') {
			*ignore_errors = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (*cp == '@') {
			*disable_echo = 1;
		} അല്ലെങ്കിൽ {
			/* all other characters terminate prefix processing */
			നിർത്തുക;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	എങ്കിൽ (*cp == '\0' || *cp == '#')
		തിരികെ (0);

	എങ്കിൽ ((argv = makeargv(cp, &argc, 0, ശൂന്യ, ശൂന്യ)) == ശൂന്യ)
		തിരികെ -1;

	/* Figure out which command we have */
	വേണ്ടി (i = 0; cmds[i].c != ശൂന്യ; i++) {
		എങ്കിൽ (argv[0] != ശൂന്യ && strcasecmp(cmds[i].c, argv[0]) == 0)
			നിർത്തുക;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	എങ്കിൽ (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} അല്ലെങ്കിൽ എങ്കിൽ (cmdnum == -1) {
		error("Invalid command.");
		തിരികെ -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ശൂന്യ;
	optidx = 1;
	തിരഞ്ഞെടുപ്പ് (cmdnum) {
	അവസ്ഥ I_GET:
	അവസ്ഥ I_REGET:
	അവസ്ഥ I_REPUT:
	അവസ്ഥ I_PUT:
		എങ്കിൽ ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			തിരികെ -1;
		/* Get first pathname (mandatory) */
		എങ്കിൽ (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			തിരികെ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		എങ്കിൽ (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		നിർത്തുക;
	അവസ്ഥ I_LINK:
		എങ്കിൽ ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			തിരികെ -1;
		പോകുക parse_two_paths;
	അവസ്ഥ I_COPY:
		എങ്കിൽ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			തിരികെ -1;
		പോകുക parse_two_paths;
	അവസ്ഥ I_RENAME:
		എങ്കിൽ ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			തിരികെ -1;
		പോകുക parse_two_paths;
	അവസ്ഥ I_SYMLINK:
		എങ്കിൽ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			തിരികെ -1;
 parse_two_paths:
		എങ്കിൽ (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			തിരികെ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		നിർത്തുക;
	അവസ്ഥ I_MKDIR:
	അവസ്ഥ I_LMKDIR:
		എങ്കിൽ ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			തിരികെ -1;
		path1_mandatory = 1;
		പോകുക parse_one_path;
	അവസ്ഥ I_RM:
	അവസ്ഥ I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	അവസ്ഥ I_CHDIR:
	അവസ്ഥ I_LCHDIR:
		എങ്കിൽ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			തിരികെ -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		എങ്കിൽ (argc - optidx < 1) {
			എങ്കിൽ (!path1_mandatory)
				നിർത്തുക; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			തിരികെ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		എങ്കിൽ (cmdnum != I_RM)
			undo_glob_escape(*path1);
		നിർത്തുക;
	അവസ്ഥ I_DF:
		എങ്കിൽ ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			തിരികെ -1;
		/* Default to current directory if no path specified */
		എങ്കിൽ (argc - optidx < 1)
			*path1 = ശൂന്യ;
		അല്ലെങ്കിൽ {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		നിർത്തുക;
	അവസ്ഥ I_LS:
		എങ്കിൽ ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			തിരികെ(-1);
		/* Path is optional */
		എങ്കിൽ (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		നിർത്തുക;
	അവസ്ഥ I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	അവസ്ഥ I_SHELL:
		/* Uses the rest of the line */
		നിർത്തുക;
	അവസ്ഥ I_LUMASK:
	അവസ്ഥ I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	അവസ്ഥ I_CHOWN:
	അവസ്ഥ I_CHGRP:
		എങ്കിൽ ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			തിരികെ -1;
		/* Get numeric arg (mandatory) */
		എങ്കിൽ (argc - optidx < 1)
			പോകുക need_അക്കം_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		എങ്കിൽ (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_അക്കം_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			തിരികെ -1;
		}
		*n_arg = ll;
		എങ്കിൽ (cmdnum == I_LUMASK)
			നിർത്തുക;
		/* Get pathname (mandatory) */
		എങ്കിൽ (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			തിരികെ -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		നിർത്തുക;
	അവസ്ഥ I_QUIT:
	അവസ്ഥ I_PWD:
	അവസ്ഥ I_LPWD:
	അവസ്ഥ I_HELP:
	അവസ്ഥ I_VERSION:
	അവസ്ഥ I_PROGRESS:
		എങ്കിൽ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			തിരികെ -1;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal("Command not implemented");
	}

	*cpp = cp;
	തിരികെ(cmdnum);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_dispatch_command(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *cmd, അക്ഷരം **pwd,
    സ്ഥിരം അക്ഷരം *startdir, പൂർണ്ണസംഖ്യ err_abort, പൂർണ്ണസംഖ്യ echo_command)
{
	സ്ഥിരം അക്ഷരം *ocmd = cmd;
	അക്ഷരം *path1, *path2, *tmp;
	പൂർണ്ണസംഖ്യ ignore_errors = 0, disable_echo = 1;
	പൂർണ്ണസംഖ്യ aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	പൂർണ്ണസംഖ്യ lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	പൂർണ്ണസംഖ്യ cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	അക്ഷരം path_buf[PATH_MAX];
	പൂർണ്ണസംഖ്യ err = 0;
	glob_t g;

	path1 = path2 = ശൂന്യ;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	എങ്കിൽ (ignore_errors != 0)
		err_abort = 0;

	എങ്കിൽ (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, വലുപ്പം(g));

	/* Perform command */
	തിരഞ്ഞെടുപ്പ് (cmdnum) {
	അവസ്ഥ 0:
		/* Blank line */
		നിർത്തുക;
	അവസ്ഥ -1:
		/* Unrecognized command */
		err = -1;
		നിർത്തുക;
	അവസ്ഥ I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	അവസ്ഥ I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		നിർത്തുക;
	അവസ്ഥ I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	അവസ്ഥ I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		നിർത്തുക;
	അവസ്ഥ I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		നിർത്തുക;
	അവസ്ഥ I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		നിർത്തുക;
	അവസ്ഥ I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	അവസ്ഥ I_LINK:
		എങ്കിൽ (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		നിർത്തുക;
	അവസ്ഥ I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ശൂന്യ, &g);
		വേണ്ടി (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			എങ്കിൽ (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			എങ്കിൽ (err != 0 && err_abort)
				നിർത്തുക;
		}
		നിർത്തുക;
	അവസ്ഥ I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		എങ്കിൽ (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		അല്ലെങ്കിൽ
			err = sftp_mkdir(conn, path1, &a, 1);
		നിർത്തുക;
	അവസ്ഥ I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		നിർത്തുക;
	അവസ്ഥ I_CHDIR:
		എങ്കിൽ (path1 == ശൂന്യ || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		എങ്കിൽ ((tmp = sftp_realpath(conn, path1)) == ശൂന്യ) {
			err = 1;
			നിർത്തുക;
		}
		എങ്കിൽ (sftp_stat(conn, tmp, 0, &aa) != 0) {
			സ്വതന്ത്രം(tmp);
			err = 1;
			നിർത്തുക;
		}
		എങ്കിൽ (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			സ്വതന്ത്രം(tmp);
			err = 1;
			നിർത്തുക;
		}
		എങ്കിൽ (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			സ്വതന്ത്രം(tmp);
			err = 1;
			നിർത്തുക;
		}
		സ്വതന്ത്രം(*pwd);
		*pwd = tmp;
		നിർത്തുക;
	അവസ്ഥ I_LS:
		എങ്കിൽ (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			നിർത്തുക;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ശൂന്യ;
		എങ്കിൽ (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		നിർത്തുക;
	അവസ്ഥ I_DF:
		/* Default to current directory if no path specified */
		എങ്കിൽ (path1 == ശൂന്യ)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		നിർത്തുക;
	അവസ്ഥ I_LCHDIR:
		എങ്കിൽ (path1 == ശൂന്യ || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		സ്വതന്ത്രം(path1);
		path1 = tmp;
		എങ്കിൽ (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		നിർത്തുക;
	അവസ്ഥ I_LMKDIR:
		എങ്കിൽ (pflag) {
			എങ്കിൽ (mkdir_path(path1, 0777) != 0)
				err = 1;
			നിർത്തുക;
		}
		എങ്കിൽ (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		നിർത്തുക;
	അവസ്ഥ I_LLS:
		local_do_ls(cmd);
		നിർത്തുക;
	അവസ്ഥ I_SHELL:
		local_do_shell(cmd);
		നിർത്തുക;
	അവസ്ഥ I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		നിർത്തുക;
	അവസ്ഥ I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ശൂന്യ, &g);
		വേണ്ടി (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			എങ്കിൽ (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			എങ്കിൽ (err != 0 && err_abort)
				നിർത്തുക;
		}
		നിർത്തുക;
	അവസ്ഥ I_CHOWN:
	അവസ്ഥ I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ശൂന്യ, &g);
		വേണ്ടി (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			എങ്കിൽ ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				എങ്കിൽ (err_abort) {
					err = -1;
					നിർത്തുക;
				} അല്ലെങ്കിൽ
					തുടരുക;
			}
			എങ്കിൽ (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				എങ്കിൽ (err_abort) {
					err = -1;
					നിർത്തുക;
				} അല്ലെങ്കിൽ
					തുടരുക;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			എങ്കിൽ (cmdnum == I_CHOWN) {
				എങ്കിൽ (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} അല്ലെങ്കിൽ {
				എങ്കിൽ (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			എങ്കിൽ (err != 0 && err_abort)
				നിർത്തുക;
		}
		നിർത്തുക;
	അവസ്ഥ I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		നിർത്തുക;
	അവസ്ഥ I_LPWD:
		എങ്കിൽ (!getcwd(path_buf, വലുപ്പം(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			നിർത്തുക;
		}
		mprintf("Local working directory: %s\n", path_buf);
		നിർത്തുക;
	അവസ്ഥ I_QUIT:
		/* Processed below */
		നിർത്തുക;
	അവസ്ഥ I_HELP:
		help();
		നിർത്തുക;
	അവസ്ഥ I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		നിർത്തുക;
	അവസ്ഥ I_PROGRESS:
		showprogress = !showprogress;
		എങ്കിൽ (showprogress)
			printf("Progress meter enabled\n");
		അല്ലെങ്കിൽ
			printf("Progress meter disabled\n");
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal("%d is not implemented", cmdnum);
	}

	എങ്കിൽ (g.gl_pathc)
		globfree(&g);
	സ്വതന്ത്രം(path1);
	സ്വതന്ത്രം(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	എങ്കിൽ (err_abort && err != 0)
		തിരികെ (-1);
	അല്ലെങ്കിൽ എങ്കിൽ (cmdnum == I_QUIT)
		തിരികെ (1);

	തിരികെ (0);
}

#ifdef USE_LIBEDIT
സ്ഥിതം അക്ഷരം *
prompt(Edit_വരി *el)
{
	തിരികെ ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
സ്ഥിതം ശൂന്യം
complete_display(അക്ഷരം **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	ഘടന winsize ws;
	അക്ഷരം *tmp;

	/* Count entries for sort and find longest */
	വേണ്ടി (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	എങ്കിൽ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	വേണ്ടി (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		എങ്കിൽ (m >= columns) {
			printf("\n");
			m = 1;
		} അല്ലെങ്കിൽ
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
സ്ഥിതം അക്ഷരം *
complete_ambiguous(സ്ഥിരം അക്ഷരം *word, അക്ഷരം **list, size_t എണ്ണം)
{
	size_t i, j, matchlen;
	അക്ഷരം *tmp;
	പൂർണ്ണസംഖ്യ len;

	എങ്കിൽ (word == ശൂന്യ)
		തിരികെ ശൂന്യ;

	എങ്കിൽ (എണ്ണം == 0)
		തിരികെ xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	വേണ്ടി (i = 1; i < എണ്ണം && list[i] != ശൂന്യ; i++) {
		വേണ്ടി (j = 0; j < matchlen; j++)
			എങ്കിൽ (list[0][j] != list[i][j])
				നിർത്തുക;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ശൂന്യ, 0);
	വേണ്ടി (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		എങ്കിൽ (len <= 0 || i + (size_t)len > matchlen)
			നിർത്തുക;
		i += (size_t)len;
	}
	/* If so, truncate */
	എങ്കിൽ (i < matchlen)
		matchlen = i;

	എങ്കിൽ (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		തിരികെ tmp;
	}

	തിരികെ xstrdup(word);
}

/* Autocomplete a sftp command */
സ്ഥിതം പൂർണ്ണസംഖ്യ
complete_cmd_parse(Edit_വരി *el, അക്ഷരം *cmd, പൂർണ്ണസംഖ്യ lastarg, അക്ഷരം quote,
    പൂർണ്ണസംഖ്യ terminated)
{
	u_int y, എണ്ണം = 0, cmdlen, tmplen;
	അക്ഷരം *tmp, **list, argterm[3];
	സ്ഥിരം വരി_Info *lf;

	list = xcalloc((വലുപ്പം(cmds) / വലുപ്പം(*cmds)) + 1, വലുപ്പം(അക്ഷരം *));

	/* No command specified: display all available commands */
	എങ്കിൽ (cmd == ശൂന്യ) {
		വേണ്ടി (y = 0; cmds[y].c; y++)
			list[എണ്ണം++] = xstrdup(cmds[y].c);

		list[എണ്ണം] = ശൂന്യ;
		complete_display(list, 0);

		വേണ്ടി (y = 0; list[y] != ശൂന്യ; y++)
			സ്വതന്ത്രം(list[y]);
		സ്വതന്ത്രം(list);
		തിരികെ എണ്ണം;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	വേണ്ടി (y = 0; cmds[y].c; y++)  {
		എങ്കിൽ (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[എണ്ണം++] = xstrdup(cmds[y].c);
	}
	list[എണ്ണം] = ശൂന്യ;

	എങ്കിൽ (എണ്ണം == 0) {
		സ്വതന്ത്രം(list);
		തിരികെ 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, എണ്ണം);
	എങ്കിൽ (എണ്ണം > 1)
		complete_display(list, 0);

	വേണ്ടി (y = 0; list[y]; y++)
		സ്വതന്ത്രം(list[y]);
	സ്വതന്ത്രം(list);

	എങ്കിൽ (tmp != ശൂന്യ) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		എങ്കിൽ (tmplen > cmdlen)
			എങ്കിൽ (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_വരി(el);
		/* Terminate argument cleanly */
		എങ്കിൽ (എണ്ണം == 1) {
			y = 0;
			എങ്കിൽ (!terminated)
				argterm[y++] = quote;
			എങ്കിൽ (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			എങ്കിൽ (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		സ്വതന്ത്രം(tmp);
	}

	തിരികെ എണ്ണം;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
complete_is_remote(അക്ഷരം *cmd, പൂർണ്ണസംഖ്യ cmdarg) {
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (cmd == ശൂന്യ)
		തിരികെ -1;

	വേണ്ടി (i = 0; cmds[i].c; i++) {
		എങ്കിൽ (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			എങ്കിൽ (cmdarg == 1)
				തിരികെ cmds[i].t;
			അല്ലെങ്കിൽ എങ്കിൽ (cmdarg == 2)
				തിരികെ cmds[i].t2;
			നിർത്തുക;
		}
	}

	തിരികെ -1;
}

/* Autocomplete a filename "file" */
സ്ഥിതം പൂർണ്ണസംഖ്യ
complete_match(Edit_വരി *el, ഘടന sftp_conn *conn, അക്ഷരം *remote_path,
    അക്ഷരം *file, പൂർണ്ണസംഖ്യ remote, പൂർണ്ണസംഖ്യ lastarg, അക്ഷരം quote, പൂർണ്ണസംഖ്യ terminated)
{
	glob_t g;
	അക്ഷരം *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	പൂർണ്ണസംഖ്യ clen;
	സ്ഥിരം വരി_Info *lf;

	/* Glob from "file" location */
	എങ്കിൽ (file == ശൂന്യ)
		tmp = xstrdup("*");
	അല്ലെങ്കിൽ
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, വലുപ്പം(g));
	എങ്കിൽ (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ശൂന്യ, &g);
	} അല്ലെങ്കിൽ
		(ശൂന്യം)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ശൂന്യ, &g);

	/* Determine length of pwd so we can trim completion display */
	വേണ്ടി (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		എങ്കിൽ (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			എങ്കിൽ (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			നിർത്തുക;
		}
		എങ്കിൽ (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		എങ്കിൽ (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	സ്വതന്ത്രം(tmp);
	tmp = ശൂന്യ;

	എങ്കിൽ (g.gl_matchc == 0)
		പോകുക out;

	എങ്കിൽ (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	എങ്കിൽ (file == ശൂന്യ || hadglob)
		പോകുക out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? ശൂന്യ : remote_path);
	സ്വതന്ത്രം(tmp2);

	എങ്കിൽ (tmp == ശൂന്യ)
		പോകുക out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	വേണ്ടി (i = 0; i < filelen; i++) {
		എങ്കിൽ (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} അല്ലെങ്കിൽ
			isesc = 0;
	}

	എങ്കിൽ (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(ശൂന്യ, 0);
		വേണ്ടി (i = 0; i < len; i += clen) {
			എങ്കിൽ ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > വലുപ്പം(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			തിരഞ്ഞെടുപ്പ് (tmp2[i]) {
			അവസ്ഥ '\'':
			അവസ്ഥ '"':
			അവസ്ഥ '\\':
			അവസ്ഥ '\t':
			അവസ്ഥ '[':
			അവസ്ഥ ' ':
			അവസ്ഥ '#':
			അവസ്ഥ '*':
				എങ്കിൽ (quote == '\0' || tmp2[i] == quote) {
					എങ്കിൽ (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					നിർത്തുക;
				}
				/* FALLTHROUGH */
			സ്ഥിരസ്ഥിതി:
				എങ്കിൽ (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				നിർത്തുക;
			}
		}
	}

	lf = el_വരി(el);
	എങ്കിൽ (g.gl_matchc == 1) {
		i = 0;
		എങ്കിൽ (!terminated && quote != '\0')
			ins[i++] = quote;
		എങ്കിൽ (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		എങ്കിൽ (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	സ്വതന്ത്രം(tmp);

 out:
	globfree(&g);
	തിരികെ g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
സ്ഥിതം unsigned അക്ഷരം
complete(Edit_വരി *el, പൂർണ്ണസംഖ്യ ch)
{
	അക്ഷരം **argv, *വരി, quote;
	പൂർണ്ണസംഖ്യ argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	സ്ഥിരം വരി_Info *lf;
	ഘടന complete_ctx *complete_ctx;

	lf = el_വരി(el);
	എങ്കിൽ (el_get(el, EL_CLIENTDATA, (ശൂന്യം**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	വരി = xmalloc(cursor + 1);
	memcpy(വരി, lf->buffer, cursor);
	വരി[cursor] = '\0';
	argv = makeargv(വരി, &carg, 1, &quote, &terminated);
	സ്വതന്ത്രം(വരി);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	വരി = xmalloc(len + 1);
	memcpy(വരി, lf->buffer, len);
	വരി[len] = '\0';
	argv = makeargv(വരി, &argc, 1, ശൂന്യ, ശൂന്യ);

	/* Ensure cursor is at EOL or a argument boundary */
	എങ്കിൽ (വരി[cursor] != ' ' && വരി[cursor] != '\0' &&
	    വരി[cursor] != '\n') {
		സ്വതന്ത്രം(വരി);
		തിരികെ ret;
	}

	എങ്കിൽ (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ശൂന്യ, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} അല്ലെങ്കിൽ എങ്കിൽ (carg == 1 && cursor > 0 && വരി[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		എങ്കിൽ (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} അല്ലെങ്കിൽ എങ്കിൽ (carg >= 1) {
		/* Handle file parsing */
		പൂർണ്ണസംഖ്യ remote = 0;
		പൂർണ്ണസംഖ്യ i = 0, cmdarg = 0;
		അക്ഷരം *filematch = ശൂന്യ;

		എങ്കിൽ (carg > 1 && വരി[cursor-1] != ' ')
			filematch = argv[carg - 1];

		വേണ്ടി (i = 1; i < carg; i++) {
			/* Skip flags */
			എങ്കിൽ (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		എങ്കിൽ (വരി[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		എങ്കിൽ ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	സ്വതന്ത്രം(വരി);
	തിരികെ ret;
}
#endif /* USE_LIBEDIT */

സ്ഥിതം പൂർണ്ണസംഖ്യ
interactive_loop(ഘടന sftp_conn *conn, അക്ഷരം *file1, അക്ഷരം *file2)
{
	അക്ഷരം *remote_path;
	അക്ഷരം *dir = ശൂന്യ, *startdir = ശൂന്യ;
	അക്ഷരം cmd[2048];
	പൂർണ്ണസംഖ്യ err, interactive;
	Edit_വരി *el = ശൂന്യ;
#ifdef USE_LIBEDIT
	സ്ഥിരം അക്ഷരം *editor;
	History *hl = ശൂന്യ;
	HistEvent hev;
	ബാഹ്യ അക്ഷരം *__progname;
	ഘടന complete_ctx complete_ctx;

	എങ്കിൽ (!batchmode && isatty(STDIN_FILENO)) {
		എങ്കിൽ ((el = el_init(__progname, stdin, stdout, stderr)) == ശൂന്യ)
			fatal("Couldn't initialise editline");
		എങ്കിൽ ((hl = history_init()) == ശൂന്യ)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, ശൂന്യ);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, ശൂന്യ);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (ശൂന്യം*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", ശൂന്യ);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", ശൂന്യ);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", ശൂന്യ);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ശൂന്യ);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ശൂന്യ);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", ശൂന്യ);

		/* el_source() may have changed EL_EDITOR to vi */
		എങ്കിൽ (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", ശൂന്യ);
	}
#endif /* USE_LIBEDIT */

	എങ്കിൽ ((remote_path = sftp_realpath(conn, ".")) == ശൂന്യ)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	എങ്കിൽ (file1 != ശൂന്യ) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		എങ്കിൽ (sftp_remote_is_dir(conn, dir) && file2 == ശൂന്യ) {
			എങ്കിൽ (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, വലുപ്പം cmd, "cd \"%s\"", dir);
			എങ്കിൽ (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				സ്വതന്ത്രം(dir);
				സ്വതന്ത്രം(startdir);
				സ്വതന്ത്രം(remote_path);
				സ്വതന്ത്രം(conn);
				തിരികെ (-1);
			}
		} അല്ലെങ്കിൽ {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			സ്വതന്ത്രം(dir);
			സ്വതന്ത്രം(startdir);
			സ്വതന്ത്രം(remote_path);
			സ്വതന്ത്രം(conn);
			തിരികെ (err);
		}
		സ്വതന്ത്രം(dir);
	}

	setvbuf(stdout, ശൂന്യ, _IOLBF, 0);
	setvbuf(infile, ശൂന്യ, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	വേണ്ടി (;;) {
		ഘടന sigaction sa;

		interrupted = 0;
		memset(&sa, 0, വലുപ്പം(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		എങ്കിൽ (sigaction(SIGINT, &sa, ശൂന്യ) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			നിർത്തുക;
		}
		എങ്കിൽ (el == ശൂന്യ) {
			എങ്കിൽ (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			എങ്കിൽ (fgets(cmd, വലുപ്പം(cmd), infile) == ശൂന്യ) {
				എങ്കിൽ (interactive)
					printf("\n");
				എങ്കിൽ (interrupted)
					തുടരുക;
				നിർത്തുക;
			}
		} അല്ലെങ്കിൽ {
#ifdef USE_LIBEDIT
			സ്ഥിരം അക്ഷരം *വരി;
			പൂർണ്ണസംഖ്യ എണ്ണം = 0;

			എങ്കിൽ ((വരി = el_gets(el, &എണ്ണം)) == ശൂന്യ ||
			    എണ്ണം <= 0) {
				printf("\n");
				എങ്കിൽ (interrupted)
					തുടരുക;
				നിർത്തുക;
			}
			history(hl, &hev, H_ENTER, വരി);
			എങ്കിൽ (strlcpy(cmd, വരി, വലുപ്പം(cmd)) >= വലുപ്പം(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				തുടരുക;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == ശൂന്യ);
		എങ്കിൽ (err != 0)
			നിർത്തുക;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	സ്വതന്ത്രം(remote_path);
	സ്വതന്ത്രം(startdir);
	സ്വതന്ത്രം(conn);

#ifdef USE_LIBEDIT
	എങ്കിൽ (hl != ശൂന്യ)
		history_end(hl);
	എങ്കിൽ (el != ശൂന്യ)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	തിരികെ (err >= 0 ? 0 : -1);
}

സ്ഥിതം ശൂന്യം
connect_to_server(അക്ഷരം *path, അക്ഷരം **args, പൂർണ്ണസംഖ്യ *in, പൂർണ്ണസംഖ്യ *out)
{
	പൂർണ്ണസംഖ്യ c_in, c_out;
#ifdef USE_PIPES
	പൂർണ്ണസംഖ്യ pin[2], pout[2];

	എങ്കിൽ ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#അല്ലെങ്കിൽ /* USE_PIPES */
	പൂർണ്ണസംഖ്യ inout[2];

	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	എങ്കിൽ ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	അല്ലെങ്കിൽ എങ്കിൽ (sshpid == 0) {
		എങ്കിൽ ((dup2(c_in, STDIN_FILENO) == -1) ||
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

സ്ഥിതം ശൂന്യം
usage(ശൂന്യം)
{
	ബാഹ്യ അക്ഷരം *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

പൂർണ്ണസംഖ്യ
പ്രധാന(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv)
{
	പൂർണ്ണസംഖ്യ r, in, out, ch, err, tmp, port = -1, noisy = 0;
	അക്ഷരം *host = ശൂന്യ, *user, *cp, **cpp, *file2 = ശൂന്യ;
	പൂർണ്ണസംഖ്യ debug_level = 0;
	അക്ഷരം *file1 = ശൂന്യ, *sftp_server = ശൂന്യ;
	അക്ഷരം *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	ബാഹ്യ പൂർണ്ണസംഖ്യ optind;
	ബാഹ്യ അക്ഷരം *optarg;
	ഘടന sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t അക്കം_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', വലുപ്പം(args));
	args.list = ശൂന്യ;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	ആകുമ്പോൾ ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		തിരഞ്ഞെടുപ്പ് (ch) {
		/* Passed through to ssh(1) */
		അവസ്ഥ 'A':
		അവസ്ഥ '4':
		അവസ്ഥ '6':
		അവസ്ഥ 'C':
			addargs(&args, "-%c", ch);
			നിർത്തുക;
		/* Passed through to ssh(1) with argument */
		അവസ്ഥ 'F':
		അവസ്ഥ 'J':
		അവസ്ഥ 'c':
		അവസ്ഥ 'i':
		അവസ്ഥ 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			നിർത്തുക;
		അവസ്ഥ 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			നിർത്തുക;
		അവസ്ഥ 'P':
			port = a2port(optarg);
			എങ്കിൽ (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			നിർത്തുക;
		അവസ്ഥ 'v':
			എങ്കിൽ (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			നിർത്തുക;
		അവസ്ഥ '1':
			fatal("SSH protocol v.1 is no longer supported");
			നിർത്തുക;
		അവസ്ഥ '2':
			/* accept silently */
			നിർത്തുക;
		അവസ്ഥ 'a':
			global_aflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			എങ്കിൽ (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			നിർത്തുക;
		അവസ്ഥ 'b':
			എങ്കിൽ (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			എങ്കിൽ (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ശൂന്യ)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			നിർത്തുക;
		അവസ്ഥ 'f':
			global_fflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			നിർത്തുക;
		അവസ്ഥ 'p':
			global_pflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'D':
			sftp_direct = optarg;
			നിർത്തുക;
		അവസ്ഥ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			എങ്കിൽ (errstr != ശൂന്യ)
				usage();
			limit_kbps *= 1024; /* kbps */
			നിർത്തുക;
		അവസ്ഥ 'r':
			global_rflag = 1;
			നിർത്തുക;
		അവസ്ഥ 'R':
			അക്കം_requests = strtol(optarg, &cp, 10);
			എങ്കിൽ (അക്കം_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			നിർത്തുക;
		അവസ്ഥ 's':
			sftp_server = optarg;
			നിർത്തുക;
		അവസ്ഥ 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			നിർത്തുക;
		അവസ്ഥ 'X':
			/* Please keep in sync with ssh.c -X */
			എങ്കിൽ (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				എങ്കിൽ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				എങ്കിൽ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} അല്ലെങ്കിൽ എങ്കിൽ (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				എങ്കിൽ (errstr != ശൂന്യ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				അക്കം_requests = (size_t)llv;
			} അല്ലെങ്കിൽ {
				fatal("Invalid -X option");
			}
			നിർത്തുക;
		അവസ്ഥ 'h':
		സ്ഥിരസ്ഥിതി:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	എങ്കിൽ (!isatty(STDERR_FILENO))
		showprogress = 0;

	എങ്കിൽ (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	എങ്കിൽ (sftp_direct == ശൂന്യ) {
		എങ്കിൽ (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		തിരഞ്ഞെടുപ്പ് (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		അവസ്ഥ -1:
			usage();
			നിർത്തുക;
		അവസ്ഥ 0:
			എങ്കിൽ (tmp != -1)
				port = tmp;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			/* Try with user, host and path. */
			എങ്കിൽ (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				നിർത്തുക;
			/* Try with user and host. */
			എങ്കിൽ (parse_user_host_port(*argv, &user, &host, ശൂന്യ)
			    == 0)
				നിർത്തുക;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			നിർത്തുക;
		}
		file2 = *(argv + 1);

		എങ്കിൽ (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		എങ്കിൽ (port != -1)
			addargs(&args, "-oPort %d", port);
		എങ്കിൽ (user != ശൂന്യ) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		എങ്കിൽ (sftp_server == ശൂന്യ || strchr(sftp_server, '/') == ശൂന്യ)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != ശൂന്യ ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		എങ്കിൽ (cpp[0] == ശൂന്യ)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, അക്കം_requests, limit_kbps);
	എങ്കിൽ (conn == ശൂന്യ)
		fatal("Couldn't initialise connection to server");

	എങ്കിൽ (!quiet) {
		എങ്കിൽ (sftp_direct == ശൂന്യ)
			fprintf(stderr, "Connected to %s.\n", host);
		അല്ലെങ്കിൽ
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#എങ്കിൽ !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	എങ്കിൽ (batchmode)
		fclose(infile);

	ആകുമ്പോൾ (waitpid(sshpid, ശൂന്യ, 0) == -1 && sshpid > 1)
		എങ്കിൽ (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
