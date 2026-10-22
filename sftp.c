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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/ioctl.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/statvfs.h>
#અન્તર્ભાવ <sys/wait.h>

#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <glob.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#અન્તર્ભાવ <histedit.h>
#નહીંતર
પ્રકારવ્યાખ્યા શૂન્ય Edit_લીટી;
#endif
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <util.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "utf8.h"

#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sftp-common.h"
#અન્તર્ભાવ "sftp-client.h"
#અન્તર્ભાવ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
પૂર્ણાંક batchmode = 0;

/* PID of ssh transport process */
સ્થિર અસ્થિર pid_t sshpid = -1;

/* Suppress diagnostic messages */
પૂર્ણાંક quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
પૂર્ણાંક showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
પૂર્ણાંક global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
પૂર્ણાંક global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
પૂર્ણાંક global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
પૂર્ણાંક global_fflag = 0;

/* SIGINT received during command processing */
અસ્થિર sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
પૂર્ણાંક sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
સંરચના complete_ctx {
	સંરચના sftp_conn *conn;
	અક્ષર **remote_pathp;
};

પૂર્ણાંક sftp_glob(સંરચના sftp_conn *, અચલ અક્ષર *, પૂર્ણાંક,
    પૂર્ણાંક (*)(અચલ અક્ષર *, પૂર્ણાંક), glob_t *); /* proto for sftp-glob.c */

બાહ્ય અક્ષર *__progname;

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
ગણના sftp_command {
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

સંરચના CMD {
	અચલ અક્ષર *c;
	અચલ પૂર્ણાંક n;
	અચલ પૂર્ણાંક t;	/* Completion type for the first argument */
	અચલ પૂર્ણાંક t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

સ્થિર અચલ સંરચના CMD cmds[] = {
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
	{ ખાલી,		-1,		-1,		-1	}
};

સ્થિર શૂન્ય
killchild(પૂર્ણાંક signo)
{
	pid_t pid;

	pid = sshpid;
	જો (pid > 1) {
		kill(pid, SIGTERM);
		(શૂન્ય)waitpid(pid, ખાલી, 0);
	}

	_exit(1);
}

સ્થિર શૂન્ય
suspchild(પૂર્ણાંક signo)
{
	પૂર્ણાંક save_errno = errno;
	જો (sshpid > 1) {
		kill(sshpid, signo);
		જ્યારે (waitpid(sshpid, ખાલી, WUNTRACED) == -1 && errno == EINTR)
			ચાલુ;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

સ્થિર શૂન્ય
cmd_interrupt(પૂર્ણાંક signo)
{
	અચલ અક્ષર સંદેશ[] = "\rInterrupt  \n";
	પૂર્ણાંક olderrno = errno;

	(શૂન્ય)લિખ(STDERR_FILENO, સંદેશ, કદ(સંદેશ) - 1);
	interrupted = 1;
	errno = olderrno;
}

સ્થિર શૂન્ય
read_interrupt(પૂર્ણાંક signo)
{
	interrupted = 1;
}

સ્થિર શૂન્ય
sigchld_handler(પૂર્ણાંક sig)
{
	પૂર્ણાંક save_errno = errno;
	pid_t pid;
	અચલ અક્ષર સંદેશ[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	જ્યારે ((pid = waitpid(sshpid, ખાલી, WNOHANG)) == -1 && errno == EINTR)
		ચાલુ;
	જો (pid == sshpid) {
		જો (!quiet)
		    (શૂન્ય)લિખ(STDERR_FILENO, સંદેશ, કદ(સંદેશ) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

સ્થિર શૂન્ય
help(શૂન્ય)
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

સ્થિર શૂન્ય
local_do_shell(અચલ અક્ષર *args)
{
	પૂર્ણાંક status;
	અક્ષર *shell;
	pid_t pid;

	જો (!*args)
		args = ખાલી;

	જો ((shell = getenv("SHELL")) == ખાલી || *shell == '\0')
		shell = _PATH_BSHELL;

	જો ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	જો (pid == 0) {
		જો (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (અક્ષર *)ખાલી);
		} નહીંતર {
			debug3("Executing %s", shell);
			execl(shell, shell, (અક્ષર *)ખાલી);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	જ્યારે (waitpid(pid, &status, 0) == -1)
		જો (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	જો (!WIFEXITED(status))
		error("Shell exited abnormally");
	નહીંતર જો (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

સ્થિર શૂન્ય
local_do_ls(અચલ અક્ષર *args)
{
	જો (!args || !*args)
		local_do_shell(_PATH_LS);
	નહીંતર {
		પૂર્ણાંક len = strlen(_PATH_LS " ") + strlen(args) + 1;
		અક્ષર *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		મુક્ત(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
સ્થિર અક્ષર *
path_strip(અચલ અક્ષર *path, અચલ અક્ષર *strip)
{
	size_t len;

	જો (strip == ખાલી || (len = strlen(strip)) == 0)
		પાછા (xstrdup(path));

	જો (strncmp(path, strip, len) == 0) {
		જો (strip[len - 1] != '/' && path[len] == '/')
			len++;
		પાછા (xstrdup(path + len));
	}

	પાછા (xstrdup(path));
}

સ્થિર પૂર્ણાંક
parse_getput_flags(અચલ અક્ષર *cmd, અક્ષર **argv, પૂર્ણાંક argc,
    પૂર્ણાંક *aflag, પૂર્ણાંક *fflag, પૂર્ણાંક *pflag, પૂર્ણાંક *rflag)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	જ્યારે ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'a':
			*aflag = 1;
			તોડો;
		સ્થિતિ 'f':
			*fflag = 1;
			તોડો;
		સ્થિતિ 'p':
		સ્થિતિ 'P':
			*pflag = 1;
			તોડો;
		સ્થિતિ 'r':
		સ્થિતિ 'R':
			*rflag = 1;
			તોડો;
		મૂળભૂત:
			error("%s: Invalid flag -%c", cmd, optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર પૂર્ણાંક
parse_mkdir_flags(અચલ અક્ષર *cmd, અક્ષર **argv, પૂર્ણાંક argc, પૂર્ણાંક *pflag)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	જ્યારે ((ch = getopt(argc, argv, "p")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'p':
			*pflag = 1;
			તોડો;
		મૂળભૂત:
			error("%s: Invalid flag -%c", cmd, optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર પૂર્ણાંક
parse_link_flags(અચલ અક્ષર *cmd, અક્ષર **argv, પૂર્ણાંક argc, પૂર્ણાંક *sflag)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	જ્યારે ((ch = getopt(argc, argv, "s")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 's':
			*sflag = 1;
			તોડો;
		મૂળભૂત:
			error("%s: Invalid flag -%c", cmd, optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર પૂર્ણાંક
parse_rename_flags(અચલ અક્ષર *cmd, અક્ષર **argv, પૂર્ણાંક argc, પૂર્ણાંક *lflag)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	જ્યારે ((ch = getopt(argc, argv, "l")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'l':
			*lflag = 1;
			તોડો;
		મૂળભૂત:
			error("%s: Invalid flag -%c", cmd, optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર પૂર્ણાંક
parse_ls_flags(અક્ષર **argv, પૂર્ણાંક argc, પૂર્ણાંક *lflag)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	જ્યારે ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			તોડો;
		સ્થિતિ 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			તોડો;
		સ્થિતિ 'a':
			*lflag |= LS_SHOW_ALL;
			તોડો;
		સ્થિતિ 'f':
			*lflag &= ~SORT_FLAGS;
			તોડો;
		સ્થિતિ 'h':
			*lflag |= LS_SI_UNITS;
			તોડો;
		સ્થિતિ 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			તોડો;
		સ્થિતિ 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			તોડો;
		સ્થિતિ 'r':
			*lflag |= LS_REVERSE_SORT;
			તોડો;
		સ્થિતિ 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			તોડો;
		મૂળભૂત:
			error("ls: Invalid flag -%c", optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર પૂર્ણાંક
parse_df_flags(અચલ અક્ષર *cmd, અક્ષર **argv, પૂર્ણાંક argc, પૂર્ણાંક *hflag, પૂર્ણાંક *iflag)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	જ્યારે ((ch = getopt(argc, argv, "hi")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'h':
			*hflag = 1;
			તોડો;
		સ્થિતિ 'i':
			*iflag = 1;
			તોડો;
		મૂળભૂત:
			error("%s: Invalid flag -%c", cmd, optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર પૂર્ણાંક
parse_ch_flags(અચલ અક્ષર *cmd, અક્ષર **argv, પૂર્ણાંક argc, પૂર્ણાંક *hflag)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	જ્યારે ((ch = getopt(argc, argv, "h")) != -1) {
		પસંદગી (ch) {
		સ્થિતિ 'h':
			*hflag = 1;
			તોડો;
		મૂળભૂત:
			error("%s: Invalid flag -%c", cmd, optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર પૂર્ણાંક
parse_no_flags(અચલ અક્ષર *cmd, અક્ષર **argv, પૂર્ણાંક argc)
{
	બાહ્ય પૂર્ણાંક opterr, optind, optopt, optreset;
	પૂર્ણાંક ch;

	optind = optreset = 1;
	opterr = 0;

	જ્યારે ((ch = getopt(argc, argv, "")) != -1) {
		પસંદગી (ch) {
		મૂળભૂત:
			error("%s: Invalid flag -%c", cmd, optopt);
			પાછા -1;
		}
	}

	પાછા optind;
}

સ્થિર અક્ષર *
escape_glob(અચલ અક્ષર *s)
{
	size_t i, o, len;
	અક્ષર *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	માટે (i = o = 0; i < len; i++) {
		જો (strchr("[]?*\\", s[i]) != ખાલી)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	પાછા ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
સ્થિર અક્ષર *
make_absolute_pwd_glob(અક્ષર *p, અચલ અક્ષર *pwd)
{
	અક્ષર *ret, *escpwd;

	escpwd = escape_glob(pwd);
	જો (p == ખાલી)
		પાછા escpwd;
	ret = sftp_make_absolute(p, escpwd);
	મુક્ત(escpwd);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
local_is_dir(અચલ અક્ષર *path)
{
	સંરચના stat sb;

	જો (stat(path, &sb) == -1)
		પાછા 0;
	પાછા S_ISDIR(sb.st_mode);
}

સ્થિર પૂર્ણાંક
process_get(સંરચના sftp_conn *conn, અચલ અક્ષર *src, અચલ અક્ષર *dst,
    અચલ અક્ષર *pwd, પૂર્ણાંક pflag, પૂર્ણાંક rflag, પૂર્ણાંક resume, પૂર્ણાંક fflag)
{
	અક્ષર *filename, *abs_src = ખાલી, *abs_dst = ખાલી, *tmp = ખાલી;
	glob_t g;
	પૂર્ણાંક i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, કદ(g));

	debug3("Looking up %s", abs_src);
	જો ((r = sftp_glob(conn, abs_src, GLOB_MARK, ખાલી, &g)) != 0) {
		જો (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} નહીંતર {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		જાઓ out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	જો (g.gl_matchc > 1 && dst != ખાલી && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		જાઓ out;
	}

	માટે (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		જો ((filename = basename(tmp)) == ખાલી) {
			error("basename %s: %s", tmp, strerror(errno));
			મુક્ત(tmp);
			err = -1;
			જાઓ out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		જો (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		જો (g.gl_matchc == 1 && dst) {
			જો (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} નહીંતર {
				abs_dst = xstrdup(dst);
			}
		} નહીંતર જો (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} નહીંતર {
			abs_dst = xstrdup(filename);
		}
		મુક્ત(tmp);

		resume |= global_aflag;
		જો (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		નહીંતર જો (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		જો (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			જો (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ખાલી, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} નહીંતર {
			જો (sftp_download(conn, g.gl_pathv[i], abs_dst, ખાલી,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		મુક્ત(abs_dst);
		abs_dst = ખાલી;
	}

out:
	મુક્ત(abs_src);
	globfree(&g);
	પાછા(err);
}

સ્થિર પૂર્ણાંક
process_put(સંરચના sftp_conn *conn, અચલ અક્ષર *src, અચલ અક્ષર *dst,
    અચલ અક્ષર *pwd, પૂર્ણાંક pflag, પૂર્ણાંક rflag, પૂર્ણાંક resume, પૂર્ણાંક fflag)
{
	અક્ષર *tmp_dst = ખાલી;
	અક્ષર *abs_dst = ખાલી;
	અક્ષર *tmp = ખાલી, *filename = ખાલી;
	glob_t g;
	પૂર્ણાંક err = 0;
	પૂર્ણાંક i, dst_is_dir = 1;
	સંરચના stat sb;

	જો (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, કદ(g));
	debug3("Looking up %s", src);
	જો (glob(src, GLOB_NOCHECK | GLOB_MARK, ખાલી, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		જાઓ out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	જો (tmp_dst != ખાલી)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	જો (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		જાઓ out;
	}

	માટે (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		જો (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			ચાલુ;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		જો ((filename = basename(tmp)) == ખાલી) {
			error("basename %s: %s", tmp, strerror(errno));
			મુક્ત(tmp);
			err = -1;
			જાઓ out;
		}
		/* Special handling for source of '..' */
		જો (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		મુક્ત(abs_dst);
		abs_dst = ખાલી;
		જો (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			જો (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			નહીંતર
				abs_dst = xstrdup(tmp_dst);
		} નહીંતર જો (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} નહીંતર {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		મુક્ત(tmp);

		resume |= global_aflag;
		જો (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		નહીંતર જો (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		જો (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			જો (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} નહીંતર {
			જો (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	મુક્ત(abs_dst);
	મુક્ત(tmp_dst);
	globfree(&g);
	પાછા(err);
}

સ્થિર પૂર્ણાંક
sdirent_comp(અચલ શૂન્ય *aa, અચલ શૂન્ય *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	પૂર્ણાંક rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	જો (sort_flag & LS_NAME_SORT)
		પાછા (rmul * strcmp(a->filename, b->filename));
	નહીંતર જો (sort_flag & LS_TIME_SORT)
		પાછા (rmul * NCMP(a->a.mtime, b->a.mtime));
	નહીંતર જો (sort_flag & LS_SIZE_SORT)
		પાછા (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
સ્થિર પૂર્ણાંક
do_ls_dir(સંરચના sftp_conn *conn, અચલ અક્ષર *path,
    અચલ અક્ષર *strip_path, પૂર્ણાંક lflag)
{
	પૂર્ણાંક n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	જો ((n = sftp_readdir(conn, path, &d)) != 0)
		પાછા (n);

	જો (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		સંરચના winsize ws;
		અક્ષર *tmp;

		/* Count entries for sort and find longest filename */
		માટે (n = 0; d[n] != ખાલી; n++) {
			જો (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		મુક્ત(tmp);

		જો (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	જો (lflag & SORT_FLAGS) {
		માટે (n = 0; d[n] != ખાલી; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, કદ(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	માટે (n = 0; d[n] != ખાલી && !interrupted; n++) {
		અક્ષર *tmp, *fname;

		જો (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			ચાલુ;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		મુક્ત(tmp);

		જો (lflag & LS_LONG_VIEW) {
			જો ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				અક્ષર *lname;
				સંરચના stat sb;
				અચલ અક્ષર *user = ખાલી, *group = ખાલી;

				memset(&sb, 0, કદ(sb));
				attrib_to_stat(&d[n]->a, &sb);
				જો ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				મુક્ત(lname);
			} નહીંતર
				mprintf("%s\n", d[n]->longname);
		} નહીંતર {
			mprintf("%-*s", colspace, fname);
			જો (c >= columns) {
				printf("\n");
				c = 1;
			} નહીંતર
				c++;
		}

		મુક્ત(fname);
	}

	જો (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	પાછા (0);
}

સ્થિર પૂર્ણાંક
sglob_comp(અચલ શૂન્ય *aa, અચલ શૂન્ય *bb)
{
	u_int a = *(અચલ u_int *)aa;
	u_int b = *(અચલ u_int *)bb;
	અચલ અક્ષર *ap = sort_glob->gl_pathv[a];
	અચલ અક્ષર *bp = sort_glob->gl_pathv[b];
	અચલ સંરચના stat *as = sort_glob->gl_statv[a];
	અચલ સંરચના stat *bs = sort_glob->gl_statv[b];
	પૂર્ણાંક rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	જો (as == ખાલી || bs == ખાલી)
		પાછા (as == bs) ? 0 : (as == ખાલી ? rmul : -rmul);
	જો (sort_flag & LS_NAME_SORT)
		પાછા (rmul * strcmp(ap, bp));
	નહીંતર જો (sort_flag & LS_TIME_SORT) {
#જો defined(HAVE_STRUCT_STAT_ST_MTIM)
		જો (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			પાછા 0;
		પાછા timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#અથવાજો defined(HAVE_STRUCT_STAT_ST_MTIME)
		પાછા (rmul * NCMP(as->st_mtime, bs->st_mtime));
#નહીંતર
	પાછા rmul * 1;
#endif
	} નહીંતર જો (sort_flag & LS_SIZE_SORT)
		પાછા (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
સ્થિર પૂર્ણાંક
do_globbed_ls(સંરચના sftp_conn *conn, અચલ અક્ષર *path,
    અચલ અક્ષર *strip_path, પૂર્ણાંક lflag)
{
	અક્ષર *fname, *lname;
	glob_t g;
	પૂર્ણાંક err, r;
	સંરચના winsize ws;
	u_int i, j, nentries, *indices = ખાલી, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, કદ(g));

	જો ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ખાલી, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		જો (g.gl_pathc)
			globfree(&g);
		જો (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} નહીંતર {
			error("Can't ls: \"%s\" not found", path);
		}
		પાછા -1;
	}

	જો (interrupted)
		જાઓ out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	જો (g.gl_matchc == 1 && g.gl_statv[0] != ખાલી &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		પાછા err;
	}

	જો (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	જો (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		માટે (i = 0; g.gl_pathv[i]; i++)
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
	માટે (nentries = 0; g.gl_pathv[nentries] != ખાલી; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, કદ(*indices));
	માટે (i = 0; i < nentries; i++)
		indices[i] = i;

	જો (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, કદ(*indices), sglob_comp);
		sort_glob = ખાલી;
	}

	get_remote_user_groups_from_glob(conn, &g);
	માટે (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		જો (lflag & LS_LONG_VIEW) {
			અચલ અક્ષર *user = ખાલી, *group = ખાલી;

			જો (g.gl_statv[i] == ખાલી) {
				error("no stat information for %s", fname);
				મુક્ત(fname);
				ચાલુ;
			}
			જો ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			મુક્ત(lname);
		} નહીંતર {
			mprintf("%-*s", colspace, fname);
			જો (c >= columns) {
				printf("\n");
				c = 1;
			} નહીંતર
				c++;
		}
		મુક્ત(fname);
	}

	જો (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	જો (g.gl_pathc)
		globfree(&g);
	મુક્ત(indices);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
do_df(સંરચના sftp_conn *conn, અચલ અક્ષર *path, પૂર્ણાંક hflag, પૂર્ણાંક iflag)
{
	સંરચના sftp_statvfs st;
	અક્ષર s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	અક્ષર s_મૂળ[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	અક્ષર s_icapacity[16], s_dcapacity[16];

	જો (sftp_statvfs(conn, path, &st, 1) == -1)
		પાછા -1;
	જો (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", કદ(s_icapacity));
	નહીંતર {
		snprintf(s_icapacity, કદ(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	જો (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", કદ(s_dcapacity));
	નહીંતર {
		snprintf(s_dcapacity, કદ(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	જો (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} નહીંતર જો (hflag) {
		strlcpy(s_used, "error", કદ(s_used));
		strlcpy(s_avail, "error", કદ(s_avail));
		strlcpy(s_મૂળ, "error", કદ(s_મૂળ));
		strlcpy(s_total, "error", કદ(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_મૂળ);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_મૂળ, s_dcapacity);
	} નહીંતર {
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
	પાછા 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
સ્થિર શૂન્ય
undo_glob_escape(અક્ષર *s)
{
	size_t i, j;

	માટે (i = j = 0;;) {
		જો (s[i] == '\0') {
			s[j] = '\0';
			પાછા;
		}
		જો (s[i] != '\\') {
			s[j++] = s[i++];
			ચાલુ;
		}
		/* s[i] == '\\' */
		++i;
		પસંદગી (s[i]) {
		સ્થિતિ '?':
		સ્થિતિ '[':
		સ્થિતિ '*':
		સ્થિતિ '\\':
			s[j++] = s[i++];
			તોડો;
		સ્થિતિ '\0':
			s[j++] = '\\';
			s[j] = '\0';
			પાછા;
		મૂળભૂત:
			s[j++] = '\\';
			s[j++] = s[i++];
			તોડો;
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
સ્થિર અક્ષર **
makeargv(અચલ અક્ષર *arg, પૂર્ણાંક *argcp, પૂર્ણાંક sloppy, અક્ષર *lastquote,
    u_int *terminated)
{
	પૂર્ણાંક argc, quot;
	size_t i, j;
	સ્થિર અક્ષર argvs[MAXARGLEN];
	સ્થિર અક્ષર *argv[MAXARGS + 1];
	ગણના { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	જો (strlen(arg) > કદ(argvs) - 1) {
 args_too_longs:
		error("string too long");
		પાછા ખાલી;
	}
	જો (terminated != ખાલી)
		*terminated = 1;
	જો (lastquote != ખાલી)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	માટે (;;) {
		જો ((size_t)argc >= કદ(argv) / કદ(*argv)){
			error("Too many arguments.");
			પાછા ખાલી;
		}
		જો (isspace((unsigned અક્ષર)arg[i])) {
			જો (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} નહીંતર જો (state != MA_START)
				argvs[j++] = arg[i];
		} નહીંતર જો (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			જો (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				જો (lastquote != ખાલી)
					*lastquote = arg[i];
			} નહીંતર જો (state == MA_UNQUOTED)
				state = q;
			નહીંતર જો (state == q)
				state = MA_UNQUOTED;
			નહીંતર
				argvs[j++] = arg[i];
		} નહીંતર જો (arg[i] == '\\') {
			જો (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				જો (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} નહીંતર જો (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					જો (j >= કદ(argvs) - 5)
						જાઓ args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} નહીંતર {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} નહીંતર {
				જો (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					જો (lastquote != ખાલી)
						*lastquote = '\0';
				}
				જો (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} નહીંતર {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					જો (arg[i] == '\0')
						જાઓ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} નહીંતર જો (arg[i] == '#') {
			જો (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			નહીંતર
				જાઓ string_done;
		} નહીંતર જો (arg[i] == '\0') {
			જો (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				જો (sloppy) {
					state = MA_UNQUOTED;
					જો (terminated != ખાલી)
						*terminated = 0;
					જાઓ string_done;
				}
				error("Unterminated quoted argument");
				પાછા ખાલી;
			}
 string_done:
			જો (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			તોડો;
		} નહીંતર {
			જો (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				જો (lastquote != ખાલી)
					*lastquote = '\0';
			}
			જો ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				જો (j >= કદ(argvs) - 3)
					જાઓ args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} નહીંતર
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	પાછા argv;
}

સ્થિર પૂર્ણાંક
parse_args(અચલ અક્ષર **cpp, પૂર્ણાંક *ignore_errors, પૂર્ણાંક *disable_echo, પૂર્ણાંક *aflag,
	  પૂર્ણાંક *fflag, પૂર્ણાંક *hflag, પૂર્ણાંક *iflag, પૂર્ણાંક *lflag, પૂર્ણાંક *pflag,
	  પૂર્ણાંક *rflag, પૂર્ણાંક *sflag,
    unsigned long *n_arg, અક્ષર **path1, અક્ષર **path2)
{
	અચલ અક્ષર *cmd, *cp = *cpp;
	અક્ષર *cp2, **argv;
	પૂર્ણાંક base = 0;
	long long ll;
	પૂર્ણાંક path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	માટે (;*cp != '\0'; cp++) {
		જો (*cp == '-') {
			*ignore_errors = 1;
		} નહીંતર જો (*cp == '@') {
			*disable_echo = 1;
		} નહીંતર {
			/* all other characters terminate prefix processing */
			તોડો;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	જો (*cp == '\0' || *cp == '#')
		પાછા (0);

	જો ((argv = makeargv(cp, &argc, 0, ખાલી, ખાલી)) == ખાલી)
		પાછા -1;

	/* Figure out which command we have */
	માટે (i = 0; cmds[i].c != ખાલી; i++) {
		જો (argv[0] != ખાલી && strcasecmp(cmds[i].c, argv[0]) == 0)
			તોડો;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	જો (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} નહીંતર જો (cmdnum == -1) {
		error("Invalid command.");
		પાછા -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ખાલી;
	optidx = 1;
	પસંદગી (cmdnum) {
	સ્થિતિ I_GET:
	સ્થિતિ I_REGET:
	સ્થિતિ I_REPUT:
	સ્થિતિ I_PUT:
		જો ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			પાછા -1;
		/* Get first pathname (mandatory) */
		જો (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			પાછા -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		જો (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		તોડો;
	સ્થિતિ I_LINK:
		જો ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			પાછા -1;
		જાઓ parse_two_paths;
	સ્થિતિ I_COPY:
		જો ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			પાછા -1;
		જાઓ parse_two_paths;
	સ્થિતિ I_RENAME:
		જો ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			પાછા -1;
		જાઓ parse_two_paths;
	સ્થિતિ I_SYMLINK:
		જો ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			પાછા -1;
 parse_two_paths:
		જો (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			પાછા -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		તોડો;
	સ્થિતિ I_MKDIR:
	સ્થિતિ I_LMKDIR:
		જો ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			પાછા -1;
		path1_mandatory = 1;
		જાઓ parse_one_path;
	સ્થિતિ I_RM:
	સ્થિતિ I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	સ્થિતિ I_CHDIR:
	સ્થિતિ I_LCHDIR:
		જો ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			પાછા -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		જો (argc - optidx < 1) {
			જો (!path1_mandatory)
				તોડો; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			પાછા -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		જો (cmdnum != I_RM)
			undo_glob_escape(*path1);
		તોડો;
	સ્થિતિ I_DF:
		જો ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			પાછા -1;
		/* Default to current directory if no path specified */
		જો (argc - optidx < 1)
			*path1 = ખાલી;
		નહીંતર {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		તોડો;
	સ્થિતિ I_LS:
		જો ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			પાછા(-1);
		/* Path is optional */
		જો (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		તોડો;
	સ્થિતિ I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	સ્થિતિ I_SHELL:
		/* Uses the rest of the line */
		તોડો;
	સ્થિતિ I_LUMASK:
	સ્થિતિ I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	સ્થિતિ I_CHOWN:
	સ્થિતિ I_CHGRP:
		જો ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			પાછા -1;
		/* Get numeric arg (mandatory) */
		જો (argc - optidx < 1)
			જાઓ need_અંક_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		જો (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_અંક_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			પાછા -1;
		}
		*n_arg = ll;
		જો (cmdnum == I_LUMASK)
			તોડો;
		/* Get pathname (mandatory) */
		જો (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			પાછા -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		તોડો;
	સ્થિતિ I_QUIT:
	સ્થિતિ I_PWD:
	સ્થિતિ I_LPWD:
	સ્થિતિ I_HELP:
	સ્થિતિ I_VERSION:
	સ્થિતિ I_PROGRESS:
		જો ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			પાછા -1;
		તોડો;
	મૂળભૂત:
		fatal("Command not implemented");
	}

	*cpp = cp;
	પાછા(cmdnum);
}

સ્થિર પૂર્ણાંક
parse_dispatch_command(સંરચના sftp_conn *conn, અચલ અક્ષર *cmd, અક્ષર **pwd,
    અચલ અક્ષર *startdir, પૂર્ણાંક err_abort, પૂર્ણાંક echo_command)
{
	અચલ અક્ષર *ocmd = cmd;
	અક્ષર *path1, *path2, *tmp;
	પૂર્ણાંક ignore_errors = 0, disable_echo = 1;
	પૂર્ણાંક aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	પૂર્ણાંક lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	પૂર્ણાંક cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	અક્ષર path_buf[PATH_MAX];
	પૂર્ણાંક err = 0;
	glob_t g;

	path1 = path2 = ખાલી;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	જો (ignore_errors != 0)
		err_abort = 0;

	જો (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, કદ(g));

	/* Perform command */
	પસંદગી (cmdnum) {
	સ્થિતિ 0:
		/* Blank line */
		તોડો;
	સ્થિતિ -1:
		/* Unrecognized command */
		err = -1;
		તોડો;
	સ્થિતિ I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	સ્થિતિ I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		તોડો;
	સ્થિતિ I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	સ્થિતિ I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		તોડો;
	સ્થિતિ I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		તોડો;
	સ્થિતિ I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		તોડો;
	સ્થિતિ I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	સ્થિતિ I_LINK:
		જો (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		તોડો;
	સ્થિતિ I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ખાલી, &g);
		માટે (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			જો (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			જો (err != 0 && err_abort)
				તોડો;
		}
		તોડો;
	સ્થિતિ I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		જો (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		નહીંતર
			err = sftp_mkdir(conn, path1, &a, 1);
		તોડો;
	સ્થિતિ I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		તોડો;
	સ્થિતિ I_CHDIR:
		જો (path1 == ખાલી || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		જો ((tmp = sftp_realpath(conn, path1)) == ખાલી) {
			err = 1;
			તોડો;
		}
		જો (sftp_stat(conn, tmp, 0, &aa) != 0) {
			મુક્ત(tmp);
			err = 1;
			તોડો;
		}
		જો (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			મુક્ત(tmp);
			err = 1;
			તોડો;
		}
		જો (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			મુક્ત(tmp);
			err = 1;
			તોડો;
		}
		મુક્ત(*pwd);
		*pwd = tmp;
		તોડો;
	સ્થિતિ I_LS:
		જો (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			તોડો;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ખાલી;
		જો (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		તોડો;
	સ્થિતિ I_DF:
		/* Default to current directory if no path specified */
		જો (path1 == ખાલી)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		તોડો;
	સ્થિતિ I_LCHDIR:
		જો (path1 == ખાલી || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		મુક્ત(path1);
		path1 = tmp;
		જો (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		તોડો;
	સ્થિતિ I_LMKDIR:
		જો (pflag) {
			જો (mkdir_path(path1, 0777) != 0)
				err = 1;
			તોડો;
		}
		જો (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		તોડો;
	સ્થિતિ I_LLS:
		local_do_ls(cmd);
		તોડો;
	સ્થિતિ I_SHELL:
		local_do_shell(cmd);
		તોડો;
	સ્થિતિ I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		તોડો;
	સ્થિતિ I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ખાલી, &g);
		માટે (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			જો (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			જો (err != 0 && err_abort)
				તોડો;
		}
		તોડો;
	સ્થિતિ I_CHOWN:
	સ્થિતિ I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ખાલી, &g);
		માટે (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			જો ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				જો (err_abort) {
					err = -1;
					તોડો;
				} નહીંતર
					ચાલુ;
			}
			જો (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				જો (err_abort) {
					err = -1;
					તોડો;
				} નહીંતર
					ચાલુ;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			જો (cmdnum == I_CHOWN) {
				જો (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} નહીંતર {
				જો (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			જો (err != 0 && err_abort)
				તોડો;
		}
		તોડો;
	સ્થિતિ I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		તોડો;
	સ્થિતિ I_LPWD:
		જો (!getcwd(path_buf, કદ(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			તોડો;
		}
		mprintf("Local working directory: %s\n", path_buf);
		તોડો;
	સ્થિતિ I_QUIT:
		/* Processed below */
		તોડો;
	સ્થિતિ I_HELP:
		help();
		તોડો;
	સ્થિતિ I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		તોડો;
	સ્થિતિ I_PROGRESS:
		showprogress = !showprogress;
		જો (showprogress)
			printf("Progress meter enabled\n");
		નહીંતર
			printf("Progress meter disabled\n");
		તોડો;
	મૂળભૂત:
		fatal("%d is not implemented", cmdnum);
	}

	જો (g.gl_pathc)
		globfree(&g);
	મુક્ત(path1);
	મુક્ત(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	જો (err_abort && err != 0)
		પાછા (-1);
	નહીંતર જો (cmdnum == I_QUIT)
		પાછા (1);

	પાછા (0);
}

#ifdef USE_LIBEDIT
સ્થિર અક્ષર *
prompt(Edit_લીટી *el)
{
	પાછા ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
સ્થિર શૂન્ય
complete_display(અક્ષર **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	સંરચના winsize ws;
	અક્ષર *tmp;

	/* Count entries for sort and find longest */
	માટે (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	જો (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	માટે (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		જો (m >= columns) {
			printf("\n");
			m = 1;
		} નહીંતર
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
સ્થિર અક્ષર *
complete_ambiguous(અચલ અક્ષર *word, અક્ષર **list, size_t ગણતરી)
{
	size_t i, j, matchlen;
	અક્ષર *tmp;
	પૂર્ણાંક len;

	જો (word == ખાલી)
		પાછા ખાલી;

	જો (ગણતરી == 0)
		પાછા xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	માટે (i = 1; i < ગણતરી && list[i] != ખાલી; i++) {
		માટે (j = 0; j < matchlen; j++)
			જો (list[0][j] != list[i][j])
				તોડો;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ખાલી, 0);
	માટે (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		જો (len <= 0 || i + (size_t)len > matchlen)
			તોડો;
		i += (size_t)len;
	}
	/* If so, truncate */
	જો (i < matchlen)
		matchlen = i;

	જો (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		પાછા tmp;
	}

	પાછા xstrdup(word);
}

/* Autocomplete a sftp command */
સ્થિર પૂર્ણાંક
complete_cmd_parse(Edit_લીટી *el, અક્ષર *cmd, પૂર્ણાંક lastarg, અક્ષર quote,
    પૂર્ણાંક terminated)
{
	u_int y, ગણતરી = 0, cmdlen, tmplen;
	અક્ષર *tmp, **list, argterm[3];
	અચલ લીટી_Info *lf;

	list = xcalloc((કદ(cmds) / કદ(*cmds)) + 1, કદ(અક્ષર *));

	/* No command specified: display all available commands */
	જો (cmd == ખાલી) {
		માટે (y = 0; cmds[y].c; y++)
			list[ગણતરી++] = xstrdup(cmds[y].c);

		list[ગણતરી] = ખાલી;
		complete_display(list, 0);

		માટે (y = 0; list[y] != ખાલી; y++)
			મુક્ત(list[y]);
		મુક્ત(list);
		પાછા ગણતરી;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	માટે (y = 0; cmds[y].c; y++)  {
		જો (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[ગણતરી++] = xstrdup(cmds[y].c);
	}
	list[ગણતરી] = ખાલી;

	જો (ગણતરી == 0) {
		મુક્ત(list);
		પાછા 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, ગણતરી);
	જો (ગણતરી > 1)
		complete_display(list, 0);

	માટે (y = 0; list[y]; y++)
		મુક્ત(list[y]);
	મુક્ત(list);

	જો (tmp != ખાલી) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		જો (tmplen > cmdlen)
			જો (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_લીટી(el);
		/* Terminate argument cleanly */
		જો (ગણતરી == 1) {
			y = 0;
			જો (!terminated)
				argterm[y++] = quote;
			જો (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			જો (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		મુક્ત(tmp);
	}

	પાછા ગણતરી;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
સ્થિર પૂર્ણાંક
complete_is_remote(અક્ષર *cmd, પૂર્ણાંક cmdarg) {
	પૂર્ણાંક i;

	જો (cmd == ખાલી)
		પાછા -1;

	માટે (i = 0; cmds[i].c; i++) {
		જો (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			જો (cmdarg == 1)
				પાછા cmds[i].t;
			નહીંતર જો (cmdarg == 2)
				પાછા cmds[i].t2;
			તોડો;
		}
	}

	પાછા -1;
}

/* Autocomplete a filename "file" */
સ્થિર પૂર્ણાંક
complete_match(Edit_લીટી *el, સંરચના sftp_conn *conn, અક્ષર *remote_path,
    અક્ષર *file, પૂર્ણાંક remote, પૂર્ણાંક lastarg, અક્ષર quote, પૂર્ણાંક terminated)
{
	glob_t g;
	અક્ષર *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	પૂર્ણાંક clen;
	અચલ લીટી_Info *lf;

	/* Glob from "file" location */
	જો (file == ખાલી)
		tmp = xstrdup("*");
	નહીંતર
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, કદ(g));
	જો (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ખાલી, &g);
	} નહીંતર
		(શૂન્ય)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ખાલી, &g);

	/* Determine length of pwd so we can trim completion display */
	માટે (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		જો (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			જો (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			તોડો;
		}
		જો (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		જો (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	મુક્ત(tmp);
	tmp = ખાલી;

	જો (g.gl_matchc == 0)
		જાઓ out;

	જો (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	જો (file == ખાલી || hadglob)
		જાઓ out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? ખાલી : remote_path);
	મુક્ત(tmp2);

	જો (tmp == ખાલી)
		જાઓ out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	માટે (i = 0; i < filelen; i++) {
		જો (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} નહીંતર
			isesc = 0;
	}

	જો (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(ખાલી, 0);
		માટે (i = 0; i < len; i += clen) {
			જો ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > કદ(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			પસંદગી (tmp2[i]) {
			સ્થિતિ '\'':
			સ્થિતિ '"':
			સ્થિતિ '\\':
			સ્થિતિ '\t':
			સ્થિતિ '[':
			સ્થિતિ ' ':
			સ્થિતિ '#':
			સ્થિતિ '*':
				જો (quote == '\0' || tmp2[i] == quote) {
					જો (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					તોડો;
				}
				/* FALLTHROUGH */
			મૂળભૂત:
				જો (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				તોડો;
			}
		}
	}

	lf = el_લીટી(el);
	જો (g.gl_matchc == 1) {
		i = 0;
		જો (!terminated && quote != '\0')
			ins[i++] = quote;
		જો (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		જો (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	મુક્ત(tmp);

 out:
	globfree(&g);
	પાછા g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
સ્થિર unsigned અક્ષર
complete(Edit_લીટી *el, પૂર્ણાંક ch)
{
	અક્ષર **argv, *લીટી, quote;
	પૂર્ણાંક argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	અચલ લીટી_Info *lf;
	સંરચના complete_ctx *complete_ctx;

	lf = el_લીટી(el);
	જો (el_get(el, EL_CLIENTDATA, (શૂન્ય**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	લીટી = xmalloc(cursor + 1);
	memcpy(લીટી, lf->buffer, cursor);
	લીટી[cursor] = '\0';
	argv = makeargv(લીટી, &carg, 1, &quote, &terminated);
	મુક્ત(લીટી);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	લીટી = xmalloc(len + 1);
	memcpy(લીટી, lf->buffer, len);
	લીટી[len] = '\0';
	argv = makeargv(લીટી, &argc, 1, ખાલી, ખાલી);

	/* Ensure cursor is at EOL or a argument boundary */
	જો (લીટી[cursor] != ' ' && લીટી[cursor] != '\0' &&
	    લીટી[cursor] != '\n') {
		મુક્ત(લીટી);
		પાછા ret;
	}

	જો (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ખાલી, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} નહીંતર જો (carg == 1 && cursor > 0 && લીટી[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		જો (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} નહીંતર જો (carg >= 1) {
		/* Handle file parsing */
		પૂર્ણાંક remote = 0;
		પૂર્ણાંક i = 0, cmdarg = 0;
		અક્ષર *filematch = ખાલી;

		જો (carg > 1 && લીટી[cursor-1] != ' ')
			filematch = argv[carg - 1];

		માટે (i = 1; i < carg; i++) {
			/* Skip flags */
			જો (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		જો (લીટી[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		જો ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	મુક્ત(લીટી);
	પાછા ret;
}
#endif /* USE_LIBEDIT */

સ્થિર પૂર્ણાંક
interactive_loop(સંરચના sftp_conn *conn, અક્ષર *file1, અક્ષર *file2)
{
	અક્ષર *remote_path;
	અક્ષર *dir = ખાલી, *startdir = ખાલી;
	અક્ષર cmd[2048];
	પૂર્ણાંક err, interactive;
	Edit_લીટી *el = ખાલી;
#ifdef USE_LIBEDIT
	અચલ અક્ષર *editor;
	History *hl = ખાલી;
	HistEvent hev;
	બાહ્ય અક્ષર *__progname;
	સંરચના complete_ctx complete_ctx;

	જો (!batchmode && isatty(STDIN_FILENO)) {
		જો ((el = el_init(__progname, stdin, stdout, stderr)) == ખાલી)
			fatal("Couldn't initialise editline");
		જો ((hl = history_init()) == ખાલી)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, ખાલી);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, ખાલી);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (શૂન્ય*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", ખાલી);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", ખાલી);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", ખાલી);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ખાલી);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ખાલી);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", ખાલી);

		/* el_source() may have changed EL_EDITOR to vi */
		જો (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", ખાલી);
	}
#endif /* USE_LIBEDIT */

	જો ((remote_path = sftp_realpath(conn, ".")) == ખાલી)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	જો (file1 != ખાલી) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		જો (sftp_remote_is_dir(conn, dir) && file2 == ખાલી) {
			જો (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, કદ cmd, "cd \"%s\"", dir);
			જો (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				મુક્ત(dir);
				મુક્ત(startdir);
				મુક્ત(remote_path);
				મુક્ત(conn);
				પાછા (-1);
			}
		} નહીંતર {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			મુક્ત(dir);
			મુક્ત(startdir);
			મુક્ત(remote_path);
			મુક્ત(conn);
			પાછા (err);
		}
		મુક્ત(dir);
	}

	setvbuf(stdout, ખાલી, _IOLBF, 0);
	setvbuf(infile, ખાલી, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	માટે (;;) {
		સંરચના sigaction sa;

		interrupted = 0;
		memset(&sa, 0, કદ(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		જો (sigaction(SIGINT, &sa, ખાલી) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			તોડો;
		}
		જો (el == ખાલી) {
			જો (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			જો (fgets(cmd, કદ(cmd), infile) == ખાલી) {
				જો (interactive)
					printf("\n");
				જો (interrupted)
					ચાલુ;
				તોડો;
			}
		} નહીંતર {
#ifdef USE_LIBEDIT
			અચલ અક્ષર *લીટી;
			પૂર્ણાંક ગણતરી = 0;

			જો ((લીટી = el_gets(el, &ગણતરી)) == ખાલી ||
			    ગણતરી <= 0) {
				printf("\n");
				જો (interrupted)
					ચાલુ;
				તોડો;
			}
			history(hl, &hev, H_ENTER, લીટી);
			જો (strlcpy(cmd, લીટી, કદ(cmd)) >= કદ(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				ચાલુ;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == ખાલી);
		જો (err != 0)
			તોડો;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	મુક્ત(remote_path);
	મુક્ત(startdir);
	મુક્ત(conn);

#ifdef USE_LIBEDIT
	જો (hl != ખાલી)
		history_end(hl);
	જો (el != ખાલી)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	પાછા (err >= 0 ? 0 : -1);
}

સ્થિર શૂન્ય
connect_to_server(અક્ષર *path, અક્ષર **args, પૂર્ણાંક *in, પૂર્ણાંક *out)
{
	પૂર્ણાંક c_in, c_out;
#ifdef USE_PIPES
	પૂર્ણાંક pin[2], pout[2];

	જો ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#નહીંતર /* USE_PIPES */
	પૂર્ણાંક inout[2];

	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	જો ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	નહીંતર જો (sshpid == 0) {
		જો ((dup2(c_in, STDIN_FILENO) == -1) ||
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

સ્થિર શૂન્ય
usage(શૂન્ય)
{
	બાહ્ય અક્ષર *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

પૂર્ણાંક
મુખ્ય(પૂર્ણાંક argc, અક્ષર **argv)
{
	પૂર્ણાંક r, in, out, ch, err, tmp, port = -1, noisy = 0;
	અક્ષર *host = ખાલી, *user, *cp, **cpp, *file2 = ખાલી;
	પૂર્ણાંક debug_level = 0;
	અક્ષર *file1 = ખાલી, *sftp_server = ખાલી;
	અક્ષર *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = ખાલી;
	અચલ અક્ષર *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	બાહ્ય પૂર્ણાંક optind;
	બાહ્ય અક્ષર *optarg;
	સંરચના sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t અંક_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', કદ(args));
	args.list = ખાલી;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	જ્યારે ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		પસંદગી (ch) {
		/* Passed through to ssh(1) */
		સ્થિતિ 'A':
		સ્થિતિ '4':
		સ્થિતિ '6':
		સ્થિતિ 'C':
			addargs(&args, "-%c", ch);
			તોડો;
		/* Passed through to ssh(1) with argument */
		સ્થિતિ 'F':
		સ્થિતિ 'J':
		સ્થિતિ 'c':
		સ્થિતિ 'i':
		સ્થિતિ 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			તોડો;
		સ્થિતિ 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			તોડો;
		સ્થિતિ 'P':
			port = a2port(optarg);
			જો (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			તોડો;
		સ્થિતિ 'v':
			જો (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			તોડો;
		સ્થિતિ '1':
			fatal("SSH protocol v.1 is no longer supported");
			તોડો;
		સ્થિતિ '2':
			/* accept silently */
			તોડો;
		સ્થિતિ 'a':
			global_aflag = 1;
			તોડો;
		સ્થિતિ 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			જો (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			તોડો;
		સ્થિતિ 'b':
			જો (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			જો (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ખાલી)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			તોડો;
		સ્થિતિ 'f':
			global_fflag = 1;
			તોડો;
		સ્થિતિ 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			તોડો;
		સ્થિતિ 'p':
			global_pflag = 1;
			તોડો;
		સ્થિતિ 'D':
			sftp_direct = optarg;
			તોડો;
		સ્થિતિ 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			જો (errstr != ખાલી)
				usage();
			limit_kbps *= 1024; /* kbps */
			તોડો;
		સ્થિતિ 'r':
			global_rflag = 1;
			તોડો;
		સ્થિતિ 'R':
			અંક_requests = strtol(optarg, &cp, 10);
			જો (અંક_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			તોડો;
		સ્થિતિ 's':
			sftp_server = optarg;
			તોડો;
		સ્થિતિ 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			તોડો;
		સ્થિતિ 'X':
			/* Please keep in sync with ssh.c -X */
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
				copy_buffer_len = (size_t)llv;
			} નહીંતર જો (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				જો (errstr != ખાલી) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				અંક_requests = (size_t)llv;
			} નહીંતર {
				fatal("Invalid -X option");
			}
			તોડો;
		સ્થિતિ 'h':
		મૂળભૂત:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	જો (!isatty(STDERR_FILENO))
		showprogress = 0;

	જો (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	જો (sftp_direct == ખાલી) {
		જો (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		પસંદગી (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		સ્થિતિ -1:
			usage();
			તોડો;
		સ્થિતિ 0:
			જો (tmp != -1)
				port = tmp;
			તોડો;
		મૂળભૂત:
			/* Try with user, host and path. */
			જો (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				તોડો;
			/* Try with user and host. */
			જો (parse_user_host_port(*argv, &user, &host, ખાલી)
			    == 0)
				તોડો;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			તોડો;
		}
		file2 = *(argv + 1);

		જો (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		જો (port != -1)
			addargs(&args, "-oPort %d", port);
		જો (user != ખાલી) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		જો (sftp_server == ખાલી || strchr(sftp_server, '/') == ખાલી)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != ખાલી ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} નહીંતર {
		જો ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		જો (cpp[0] == ખાલી)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, અંક_requests, limit_kbps);
	જો (conn == ખાલી)
		fatal("Couldn't initialise connection to server");

	જો (!quiet) {
		જો (sftp_direct == ખાલી)
			fprintf(stderr, "Connected to %s.\n", host);
		નહીંતર
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#જો !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	જો (batchmode)
		fclose(infile);

	જ્યારે (waitpid(sshpid, ખાલી, 0) == -1 && sshpid > 1)
		જો (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
