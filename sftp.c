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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <paths.h>
#include <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#include <histedit.h>
#නැතහොත්
typedef void EditLine;
#endif
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "xmalloc.h"
#include "log.h"
#include "pathnames.h"
#include "misc.h"
#include "utf8.h"

#include "sftp.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
පූර්ණ_සංඛ්‍යා batchmode = 0;

/* PID of ssh transport process */
static ca_ncala pid_t sshpid = -1;

/* Suppress diagnostic messages */
පූර්ණ_සංඛ්‍යා quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
පූර්ණ_සංඛ්‍යා showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
පූර්ණ_සංඛ්‍යා global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
පූර්ණ_සංඛ්‍යා global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
පූර්ණ_සංඛ්‍යා global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
පූර්ණ_සංඛ්‍යා global_fflag = 0;

/* SIGINT received during command processing */
ca_ncala sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
පූර්ණ_සංඛ්‍යා sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
sa_nracanaa complete_ctx {
	sa_nracanaa sftp_conn *conn;
	var_na **remote_pathp;
};

පූර්ණ_සංඛ්‍යා sftp_glob(sa_nracanaa sftp_conn *, const var_na *, පූර්ණ_සංඛ්‍යා,
    පූර්ණ_සංඛ්‍යා (*)(const var_na *, පූර්ණ_සංඛ්‍යා), glob_t *); /* proto for sftp-glob.c */

extern var_na *__progname;

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
ga_nanaa sftp_command {
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

sa_nracanaa CMD {
	const var_na *c;
	const පූර්ණ_සංඛ්‍යා n;
	const පූර්ණ_සංඛ්‍යා t;	/* Completion type for the first argument */
	const පූර්ණ_සංඛ්‍යා t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

static const sa_nracanaa CMD cmds[] = {
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
	{ NULL,		-1,		-1,		-1	}
};

static void
killchild(පූර්ණ_සංඛ්‍යා signo)
{
	pid_t pid;

	pid = sshpid;
	නම් (pid > 1) {
		kill(pid, SIGTERM);
		(void)waitpid(pid, NULL, 0);
	}

	_exit(1);
}

static void
suspchild(පූර්ණ_සංඛ්‍යා signo)
{
	පූර්ණ_සංඛ්‍යා save_errno = errno;
	නම් (sshpid > 1) {
		kill(sshpid, signo);
		අතරතුර (waitpid(sshpid, NULL, WUNTRACED) == -1 && errno == EINTR)
			continue;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static void
cmd_interrupt(පූර්ණ_සංඛ්‍යා signo)
{
	const var_na msg[] = "\rInterrupt  \n";
	පූර්ණ_සංඛ්‍යා olderrno = errno;

	(void)write(STDERR_FILENO, msg, parimaa_na(msg) - 1);
	interrupted = 1;
	errno = olderrno;
}

static void
read_interrupt(පූර්ණ_සංඛ්‍යා signo)
{
	interrupted = 1;
}

static void
sigchld_handler(පූර්ණ_සංඛ්‍යා sig)
{
	පූර්ණ_සංඛ්‍යා save_errno = errno;
	pid_t pid;
	const var_na msg[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	අතරතුර ((pid = waitpid(sshpid, NULL, WNOHANG)) == -1 && errno == EINTR)
		continue;
	නම් (pid == sshpid) {
		නම් (!quiet)
		    (void)write(STDERR_FILENO, msg, parimaa_na(msg) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

static void
help(void)
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

static void
local_do_shell(const var_na *args)
{
	පූර්ණ_සංඛ්‍යා status;
	var_na *shell;
	pid_t pid;

	නම් (!*args)
		args = NULL;

	නම් ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	නම් ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	නම් (pid == 0) {
		නම් (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (var_na *)NULL);
		} නැතහොත් {
			debug3("Executing %s", shell);
			execl(shell, shell, (var_na *)NULL);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	අතරතුර (waitpid(pid, &status, 0) == -1)
		නම් (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	නම් (!WIFEXITED(status))
		error("Shell exited abnormally");
	නැතහොත් නම් (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

static void
local_do_ls(const var_na *args)
{
	නම් (!args || !*args)
		local_do_shell(_PATH_LS);
	නැතහොත් {
		පූර්ණ_සංඛ්‍යා len = strlen(_PATH_LS " ") + strlen(args) + 1;
		var_na *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		free(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
static var_na *
path_strip(const var_na *path, const var_na *strip)
{
	size_t len;

	නම් (strip == NULL || (len = strlen(strip)) == 0)
		ආපසු (xstrdup(path));

	නම් (strncmp(path, strip, len) == 0) {
		නම් (strip[len - 1] != '/' && path[len] == '/')
			len++;
		ආපසු (xstrdup(path + len));
	}

	ආපසු (xstrdup(path));
}

static පූර්ණ_සංඛ්‍යා
parse_getput_flags(const var_na *cmd, var_na **argv, පූර්ණ_සංඛ්‍යා argc,
    පූර්ණ_සංඛ්‍යා *aflag, පූර්ණ_සංඛ්‍යා *fflag, පූර්ණ_සංඛ්‍යා *pflag, පූර්ණ_සංඛ්‍යා *rflag)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	අතරතුර ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		switch (ch) {
		pak_sa 'a':
			*aflag = 1;
			bha_nga;
		pak_sa 'f':
			*fflag = 1;
			bha_nga;
		pak_sa 'p':
		pak_sa 'P':
			*pflag = 1;
			bha_nga;
		pak_sa 'r':
		pak_sa 'R':
			*rflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static පූර්ණ_සංඛ්‍යා
parse_mkdir_flags(const var_na *cmd, var_na **argv, පූර්ණ_සංඛ්‍යා argc, පූර්ණ_සංඛ්‍යා *pflag)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	අතරතුර ((ch = getopt(argc, argv, "p")) != -1) {
		switch (ch) {
		pak_sa 'p':
			*pflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static පූර්ණ_සංඛ්‍යා
parse_link_flags(const var_na *cmd, var_na **argv, පූර්ණ_සංඛ්‍යා argc, පූර්ණ_සංඛ්‍යා *sflag)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	අතරතුර ((ch = getopt(argc, argv, "s")) != -1) {
		switch (ch) {
		pak_sa 's':
			*sflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static පූර්ණ_සංඛ්‍යා
parse_rename_flags(const var_na *cmd, var_na **argv, පූර්ණ_සංඛ්‍යා argc, පූර්ණ_සංඛ්‍යා *lflag)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	අතරතුර ((ch = getopt(argc, argv, "l")) != -1) {
		switch (ch) {
		pak_sa 'l':
			*lflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static පූර්ණ_සංඛ්‍යා
parse_ls_flags(var_na **argv, පූර්ණ_සංඛ්‍යා argc, පූර්ණ_සංඛ්‍යා *lflag)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	අතරතුර ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		switch (ch) {
		pak_sa '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			bha_nga;
		pak_sa 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			bha_nga;
		pak_sa 'a':
			*lflag |= LS_SHOW_ALL;
			bha_nga;
		pak_sa 'f':
			*lflag &= ~SORT_FLAGS;
			bha_nga;
		pak_sa 'h':
			*lflag |= LS_SI_UNITS;
			bha_nga;
		pak_sa 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			bha_nga;
		pak_sa 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			bha_nga;
		pak_sa 'r':
			*lflag |= LS_REVERSE_SORT;
			bha_nga;
		pak_sa 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			bha_nga;
		default:
			error("ls: Invalid flag -%c", optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static පූර්ණ_සංඛ්‍යා
parse_df_flags(const var_na *cmd, var_na **argv, පූර්ණ_සංඛ්‍යා argc, පූර්ණ_සංඛ්‍යා *hflag, පූර්ණ_සංඛ්‍යා *iflag)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	අතරතුර ((ch = getopt(argc, argv, "hi")) != -1) {
		switch (ch) {
		pak_sa 'h':
			*hflag = 1;
			bha_nga;
		pak_sa 'i':
			*iflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static පූර්ණ_සංඛ්‍යා
parse_ch_flags(const var_na *cmd, var_na **argv, පූර්ණ_සංඛ්‍යා argc, පූර්ණ_සංඛ්‍යා *hflag)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	අතරතුර ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		pak_sa 'h':
			*hflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static පූර්ණ_සංඛ්‍යා
parse_no_flags(const var_na *cmd, var_na **argv, පූර්ණ_සංඛ්‍යා argc)
{
	extern පූර්ණ_සංඛ්‍යා opterr, optind, optopt, optreset;
	පූර්ණ_සංඛ්‍යා ch;

	optind = optreset = 1;
	opterr = 0;

	අතරතුර ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ආපසු -1;
		}
	}

	ආපසු optind;
}

static var_na *
escape_glob(const var_na *s)
{
	size_t i, o, len;
	var_na *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	සඳහා (i = o = 0; i < len; i++) {
		නම් (strchr("[]?*\\", s[i]) != NULL)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	ආපසු ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
static var_na *
make_absolute_pwd_glob(var_na *p, const var_na *pwd)
{
	var_na *ret, *escpwd;

	escpwd = escape_glob(pwd);
	නම් (p == NULL)
		ආපසු escpwd;
	ret = sftp_make_absolute(p, escpwd);
	free(escpwd);
	ආපසු ret;
}

static පූර්ණ_සංඛ්‍යා
local_is_dir(const var_na *path)
{
	sa_nracanaa stat sb;

	නම් (stat(path, &sb) == -1)
		ආපසු 0;
	ආපසු S_ISDIR(sb.st_mode);
}

static පූර්ණ_සංඛ්‍යා
process_get(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    const var_na *pwd, පූර්ණ_සංඛ්‍යා pflag, පූර්ණ_සංඛ්‍යා rflag, පූර්ණ_සංඛ්‍යා resume, පූර්ණ_සංඛ්‍යා fflag)
{
	var_na *filename, *abs_src = NULL, *abs_dst = NULL, *tmp = NULL;
	glob_t g;
	පූර්ණ_සංඛ්‍යා i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, parimaa_na(g));

	debug3("Looking up %s", abs_src);
	නම් ((r = sftp_glob(conn, abs_src, GLOB_MARK, NULL, &g)) != 0) {
		නම් (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} නැතහොත් {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		goto out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	නම් (g.gl_matchc > 1 && dst != NULL && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		goto out;
	}

	සඳහා (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		නම් ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			free(tmp);
			err = -1;
			goto out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		නම් (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		නම් (g.gl_matchc == 1 && dst) {
			නම් (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} නැතහොත් {
				abs_dst = xstrdup(dst);
			}
		} නැතහොත් නම් (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} නැතහොත් {
			abs_dst = xstrdup(filename);
		}
		free(tmp);

		resume |= global_aflag;
		නම් (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		නැතහොත් නම් (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		නම් (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			නම් (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} නැතහොත් {
			නම් (sftp_download(conn, g.gl_pathv[i], abs_dst, NULL,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		free(abs_dst);
		abs_dst = NULL;
	}

out:
	free(abs_src);
	globfree(&g);
	ආපසු(err);
}

static පූර්ණ_සංඛ්‍යා
process_put(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    const var_na *pwd, පූර්ණ_සංඛ්‍යා pflag, පූර්ණ_සංඛ්‍යා rflag, පූර්ණ_සංඛ්‍යා resume, පූර්ණ_සංඛ්‍යා fflag)
{
	var_na *tmp_dst = NULL;
	var_na *abs_dst = NULL;
	var_na *tmp = NULL, *filename = NULL;
	glob_t g;
	පූර්ණ_සංඛ්‍යා err = 0;
	පූර්ණ_සංඛ්‍යා i, dst_is_dir = 1;
	sa_nracanaa stat sb;

	නම් (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, parimaa_na(g));
	debug3("Looking up %s", src);
	නම් (glob(src, GLOB_NOCHECK | GLOB_MARK, NULL, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		goto out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	නම් (tmp_dst != NULL)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	නම් (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		goto out;
	}

	සඳහා (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		නම් (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			continue;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		නම් ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			free(tmp);
			err = -1;
			goto out;
		}
		/* Special handling for source of '..' */
		නම් (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		free(abs_dst);
		abs_dst = NULL;
		නම් (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			නම් (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			නැතහොත්
				abs_dst = xstrdup(tmp_dst);
		} නැතහොත් නම් (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} නැතහොත් {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		free(tmp);

		resume |= global_aflag;
		නම් (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		නැතහොත් නම් (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		නම් (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			නම් (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} නැතහොත් {
			නම් (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	free(abs_dst);
	free(tmp_dst);
	globfree(&g);
	ආපසු(err);
}

static පූර්ණ_සංඛ්‍යා
sdirent_comp(const void *aa, const void *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	පූර්ණ_සංඛ්‍යා rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	නම් (sort_flag & LS_NAME_SORT)
		ආපසු (rmul * strcmp(a->filename, b->filename));
	නැතහොත් නම් (sort_flag & LS_TIME_SORT)
		ආපසු (rmul * NCMP(a->a.mtime, b->a.mtime));
	නැතහොත් නම් (sort_flag & LS_SIZE_SORT)
		ආපසු (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
static පූර්ණ_සංඛ්‍යා
do_ls_dir(sa_nracanaa sftp_conn *conn, const var_na *path,
    const var_na *strip_path, පූර්ණ_සංඛ්‍යා lflag)
{
	පූර්ණ_සංඛ්‍යා n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	නම් ((n = sftp_readdir(conn, path, &d)) != 0)
		ආපසු (n);

	නම් (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		sa_nracanaa winsize ws;
		var_na *tmp;

		/* Count entries for sort and find longest filename */
		සඳහා (n = 0; d[n] != NULL; n++) {
			නම් (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		free(tmp);

		නම් (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	නම් (lflag & SORT_FLAGS) {
		සඳහා (n = 0; d[n] != NULL; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, parimaa_na(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	සඳහා (n = 0; d[n] != NULL && !interrupted; n++) {
		var_na *tmp, *fname;

		නම් (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			continue;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		free(tmp);

		නම් (lflag & LS_LONG_VIEW) {
			නම් ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				var_na *lname;
				sa_nracanaa stat sb;
				const var_na *user = NULL, *group = NULL;

				memset(&sb, 0, parimaa_na(sb));
				attrib_to_stat(&d[n]->a, &sb);
				නම් ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				free(lname);
			} නැතහොත්
				mprintf("%s\n", d[n]->longname);
		} නැතහොත් {
			mprintf("%-*s", colspace, fname);
			නම් (c >= columns) {
				printf("\n");
				c = 1;
			} නැතහොත්
				c++;
		}

		free(fname);
	}

	නම් (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	ආපසු (0);
}

static පූර්ණ_සංඛ්‍යා
sglob_comp(const void *aa, const void *bb)
{
	u_int a = *(const u_int *)aa;
	u_int b = *(const u_int *)bb;
	const var_na *ap = sort_glob->gl_pathv[a];
	const var_na *bp = sort_glob->gl_pathv[b];
	const sa_nracanaa stat *as = sort_glob->gl_statv[a];
	const sa_nracanaa stat *bs = sort_glob->gl_statv[b];
	පූර්ණ_සංඛ්‍යා rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	නම් (as == NULL || bs == NULL)
		ආපසු (as == bs) ? 0 : (as == NULL ? rmul : -rmul);
	නම් (sort_flag & LS_NAME_SORT)
		ආපසු (rmul * strcmp(ap, bp));
	නැතහොත් නම් (sort_flag & LS_TIME_SORT) {
#නම් defined(HAVE_STRUCT_STAT_ST_MTIM)
		නම් (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			ආපසු 0;
		ආපසු timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#elif defined(HAVE_STRUCT_STAT_ST_MTIME)
		ආපසු (rmul * NCMP(as->st_mtime, bs->st_mtime));
#නැතහොත්
	ආපසු rmul * 1;
#endif
	} නැතහොත් නම් (sort_flag & LS_SIZE_SORT)
		ආපසු (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
static පූර්ණ_සංඛ්‍යා
do_globbed_ls(sa_nracanaa sftp_conn *conn, const var_na *path,
    const var_na *strip_path, පූර්ණ_සංඛ්‍යා lflag)
{
	var_na *fname, *lname;
	glob_t g;
	පූර්ණ_සංඛ්‍යා err, r;
	sa_nracanaa winsize ws;
	u_int i, j, nentries, *indices = NULL, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, parimaa_na(g));

	නම් ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    NULL, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		නම් (g.gl_pathc)
			globfree(&g);
		නම් (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} නැතහොත් {
			error("Can't ls: \"%s\" not found", path);
		}
		ආපසු -1;
	}

	නම් (interrupted)
		goto out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	නම් (g.gl_matchc == 1 && g.gl_statv[0] != NULL &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		ආපසු err;
	}

	නම් (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	නම් (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		සඳහා (i = 0; g.gl_pathv[i]; i++)
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
	සඳහා (nentries = 0; g.gl_pathv[nentries] != NULL; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, parimaa_na(*indices));
	සඳහා (i = 0; i < nentries; i++)
		indices[i] = i;

	නම් (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, parimaa_na(*indices), sglob_comp);
		sort_glob = NULL;
	}

	get_remote_user_groups_from_glob(conn, &g);
	සඳහා (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		නම් (lflag & LS_LONG_VIEW) {
			const var_na *user = NULL, *group = NULL;

			නම් (g.gl_statv[i] == NULL) {
				error("no stat information for %s", fname);
				free(fname);
				continue;
			}
			නම් ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			free(lname);
		} නැතහොත් {
			mprintf("%-*s", colspace, fname);
			නම් (c >= columns) {
				printf("\n");
				c = 1;
			} නැතහොත්
				c++;
		}
		free(fname);
	}

	නම් (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	නම් (g.gl_pathc)
		globfree(&g);
	free(indices);

	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
do_df(sa_nracanaa sftp_conn *conn, const var_na *path, පූර්ණ_සංඛ්‍යා hflag, පූර්ණ_සංඛ්‍යා iflag)
{
	sa_nracanaa sftp_statvfs st;
	var_na s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	var_na s_root[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	var_na s_icapacity[16], s_dcapacity[16];

	නම් (sftp_statvfs(conn, path, &st, 1) == -1)
		ආපසු -1;
	නම් (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", parimaa_na(s_icapacity));
	නැතහොත් {
		snprintf(s_icapacity, parimaa_na(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	නම් (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", parimaa_na(s_dcapacity));
	නැතහොත් {
		snprintf(s_dcapacity, parimaa_na(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	නම් (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} නැතහොත් නම් (hflag) {
		strlcpy(s_used, "error", parimaa_na(s_used));
		strlcpy(s_avail, "error", parimaa_na(s_avail));
		strlcpy(s_root, "error", parimaa_na(s_root));
		strlcpy(s_total, "error", parimaa_na(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_root);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_root, s_dcapacity);
	} නැතහොත් {
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
	ආපසු 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
static void
undo_glob_escape(var_na *s)
{
	size_t i, j;

	සඳහා (i = j = 0;;) {
		නම් (s[i] == '\0') {
			s[j] = '\0';
			ආපසු;
		}
		නම් (s[i] != '\\') {
			s[j++] = s[i++];
			continue;
		}
		/* s[i] == '\\' */
		++i;
		switch (s[i]) {
		pak_sa '?':
		pak_sa '[':
		pak_sa '*':
		pak_sa '\\':
			s[j++] = s[i++];
			bha_nga;
		pak_sa '\0':
			s[j++] = '\\';
			s[j] = '\0';
			ආපසු;
		default:
			s[j++] = '\\';
			s[j++] = s[i++];
			bha_nga;
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
static var_na **
makeargv(const var_na *arg, පූර්ණ_සංඛ්‍යා *argcp, පූර්ණ_සංඛ්‍යා sloppy, var_na *lastquote,
    u_int *terminated)
{
	පූර්ණ_සංඛ්‍යා argc, quot;
	size_t i, j;
	static var_na argvs[MAXARGLEN];
	static var_na *argv[MAXARGS + 1];
	ga_nanaa { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	නම් (strlen(arg) > parimaa_na(argvs) - 1) {
 args_too_longs:
		error("string too long");
		ආපසු NULL;
	}
	නම් (terminated != NULL)
		*terminated = 1;
	නම් (lastquote != NULL)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	සඳහා (;;) {
		නම් ((size_t)argc >= parimaa_na(argv) / parimaa_na(*argv)){
			error("Too many arguments.");
			ආපසු NULL;
		}
		නම් (isspace((unsigned var_na)arg[i])) {
			නම් (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} නැතහොත් නම් (state != MA_START)
				argvs[j++] = arg[i];
		} නැතහොත් නම් (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			නම් (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				නම් (lastquote != NULL)
					*lastquote = arg[i];
			} නැතහොත් නම් (state == MA_UNQUOTED)
				state = q;
			නැතහොත් නම් (state == q)
				state = MA_UNQUOTED;
			නැතහොත්
				argvs[j++] = arg[i];
		} නැතහොත් නම් (arg[i] == '\\') {
			නම් (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				නම් (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} නැතහොත් නම් (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					නම් (j >= parimaa_na(argvs) - 5)
						goto args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} නැතහොත් {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} නැතහොත් {
				නම් (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					නම් (lastquote != NULL)
						*lastquote = '\0';
				}
				නම් (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} නැතහොත් {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					නම් (arg[i] == '\0')
						goto early_nul;
					argvs[j++] = arg[i];
				}
			}
		} නැතහොත් නම් (arg[i] == '#') {
			නම් (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			නැතහොත්
				goto string_done;
		} නැතහොත් නම් (arg[i] == '\0') {
			නම් (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				නම් (sloppy) {
					state = MA_UNQUOTED;
					නම් (terminated != NULL)
						*terminated = 0;
					goto string_done;
				}
				error("Unterminated quoted argument");
				ආපසු NULL;
			}
 string_done:
			නම් (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			bha_nga;
		} නැතහොත් {
			නම් (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				නම් (lastquote != NULL)
					*lastquote = '\0';
			}
			නම් ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				නම් (j >= parimaa_na(argvs) - 3)
					goto args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} නැතහොත්
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	ආපසු argv;
}

static පූර්ණ_සංඛ්‍යා
parse_args(const var_na **cpp, පූර්ණ_සංඛ්‍යා *ignore_errors, පූර්ණ_සංඛ්‍යා *disable_echo, පූර්ණ_සංඛ්‍යා *aflag,
	  පූර්ණ_සංඛ්‍යා *fflag, පූර්ණ_සංඛ්‍යා *hflag, පූර්ණ_සංඛ්‍යා *iflag, පූර්ණ_සංඛ්‍යා *lflag, පූර්ණ_සංඛ්‍යා *pflag,
	  පූර්ණ_සංඛ්‍යා *rflag, පූර්ණ_සංඛ්‍යා *sflag,
    unsigned long *n_arg, var_na **path1, var_na **path2)
{
	const var_na *cmd, *cp = *cpp;
	var_na *cp2, **argv;
	පූර්ණ_සංඛ්‍යා base = 0;
	long long ll;
	පූර්ණ_සංඛ්‍යා path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	සඳහා (;*cp != '\0'; cp++) {
		නම් (*cp == '-') {
			*ignore_errors = 1;
		} නැතහොත් නම් (*cp == '@') {
			*disable_echo = 1;
		} නැතහොත් {
			/* all other characters terminate prefix processing */
			bha_nga;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	නම් (*cp == '\0' || *cp == '#')
		ආපසු (0);

	නම් ((argv = makeargv(cp, &argc, 0, NULL, NULL)) == NULL)
		ආපසු -1;

	/* Figure out which command we have */
	සඳහා (i = 0; cmds[i].c != NULL; i++) {
		නම් (argv[0] != NULL && strcasecmp(cmds[i].c, argv[0]) == 0)
			bha_nga;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	නම් (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} නැතහොත් නම් (cmdnum == -1) {
		error("Invalid command.");
		ආපසු -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = NULL;
	optidx = 1;
	switch (cmdnum) {
	pak_sa I_GET:
	pak_sa I_REGET:
	pak_sa I_REPUT:
	pak_sa I_PUT:
		නම් ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			ආපසු -1;
		/* Get first pathname (mandatory) */
		නම් (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			ආපසු -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		නම් (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		bha_nga;
	pak_sa I_LINK:
		නම් ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			ආපසු -1;
		goto parse_two_paths;
	pak_sa I_COPY:
		නම් ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ආපසු -1;
		goto parse_two_paths;
	pak_sa I_RENAME:
		නම් ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			ආපසු -1;
		goto parse_two_paths;
	pak_sa I_SYMLINK:
		නම් ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ආපසු -1;
 parse_two_paths:
		නම් (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			ආපසු -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		bha_nga;
	pak_sa I_MKDIR:
	pak_sa I_LMKDIR:
		නම් ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			ආපසු -1;
		path1_mandatory = 1;
		goto parse_one_path;
	pak_sa I_RM:
	pak_sa I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	pak_sa I_CHDIR:
	pak_sa I_LCHDIR:
		නම් ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ආපසු -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		නම් (argc - optidx < 1) {
			නම් (!path1_mandatory)
				bha_nga; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			ආපසු -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		නම් (cmdnum != I_RM)
			undo_glob_escape(*path1);
		bha_nga;
	pak_sa I_DF:
		නම් ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			ආපසු -1;
		/* Default to current directory if no path specified */
		නම් (argc - optidx < 1)
			*path1 = NULL;
		නැතහොත් {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		bha_nga;
	pak_sa I_LS:
		නම් ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			ආපසු(-1);
		/* Path is optional */
		නම් (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		bha_nga;
	pak_sa I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	pak_sa I_SHELL:
		/* Uses the rest of the line */
		bha_nga;
	pak_sa I_LUMASK:
	pak_sa I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	pak_sa I_CHOWN:
	pak_sa I_CHGRP:
		නම් ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			ආපසු -1;
		/* Get numeric arg (mandatory) */
		නම් (argc - optidx < 1)
			goto need_num_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		නම් (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_num_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			ආපසු -1;
		}
		*n_arg = ll;
		නම් (cmdnum == I_LUMASK)
			bha_nga;
		/* Get pathname (mandatory) */
		නම් (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			ආපසු -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		bha_nga;
	pak_sa I_QUIT:
	pak_sa I_PWD:
	pak_sa I_LPWD:
	pak_sa I_HELP:
	pak_sa I_VERSION:
	pak_sa I_PROGRESS:
		නම් ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ආපසු -1;
		bha_nga;
	default:
		fatal("Command not implemented");
	}

	*cpp = cp;
	ආපසු(cmdnum);
}

static පූර්ණ_සංඛ්‍යා
parse_dispatch_command(sa_nracanaa sftp_conn *conn, const var_na *cmd, var_na **pwd,
    const var_na *startdir, පූර්ණ_සංඛ්‍යා err_abort, පූර්ණ_සංඛ්‍යා echo_command)
{
	const var_na *ocmd = cmd;
	var_na *path1, *path2, *tmp;
	පූර්ණ_සංඛ්‍යා ignore_errors = 0, disable_echo = 1;
	පූර්ණ_සංඛ්‍යා aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	පූර්ණ_සංඛ්‍යා lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	පූර්ණ_සංඛ්‍යා cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	var_na path_buf[PATH_MAX];
	පූර්ණ_සංඛ්‍යා err = 0;
	glob_t g;

	path1 = path2 = NULL;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	නම් (ignore_errors != 0)
		err_abort = 0;

	නම් (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, parimaa_na(g));

	/* Perform command */
	switch (cmdnum) {
	pak_sa 0:
		/* Blank line */
		bha_nga;
	pak_sa -1:
		/* Unrecognized command */
		err = -1;
		bha_nga;
	pak_sa I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	pak_sa I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		bha_nga;
	pak_sa I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	pak_sa I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		bha_nga;
	pak_sa I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		bha_nga;
	pak_sa I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		bha_nga;
	pak_sa I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	pak_sa I_LINK:
		නම් (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		bha_nga;
	pak_sa I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		සඳහා (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			නම් (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			නම් (err != 0 && err_abort)
				bha_nga;
		}
		bha_nga;
	pak_sa I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		නම් (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		නැතහොත්
			err = sftp_mkdir(conn, path1, &a, 1);
		bha_nga;
	pak_sa I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		bha_nga;
	pak_sa I_CHDIR:
		නම් (path1 == NULL || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		නම් ((tmp = sftp_realpath(conn, path1)) == NULL) {
			err = 1;
			bha_nga;
		}
		නම් (sftp_stat(conn, tmp, 0, &aa) != 0) {
			free(tmp);
			err = 1;
			bha_nga;
		}
		නම් (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			free(tmp);
			err = 1;
			bha_nga;
		}
		නම් (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			free(tmp);
			err = 1;
			bha_nga;
		}
		free(*pwd);
		*pwd = tmp;
		bha_nga;
	pak_sa I_LS:
		නම් (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			bha_nga;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = NULL;
		නම් (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		bha_nga;
	pak_sa I_DF:
		/* Default to current directory if no path specified */
		නම් (path1 == NULL)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		bha_nga;
	pak_sa I_LCHDIR:
		නම් (path1 == NULL || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		free(path1);
		path1 = tmp;
		නම් (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		bha_nga;
	pak_sa I_LMKDIR:
		නම් (pflag) {
			නම් (mkdir_path(path1, 0777) != 0)
				err = 1;
			bha_nga;
		}
		නම් (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		bha_nga;
	pak_sa I_LLS:
		local_do_ls(cmd);
		bha_nga;
	pak_sa I_SHELL:
		local_do_shell(cmd);
		bha_nga;
	pak_sa I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		bha_nga;
	pak_sa I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		සඳහා (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			නම් (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			නම් (err != 0 && err_abort)
				bha_nga;
		}
		bha_nga;
	pak_sa I_CHOWN:
	pak_sa I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		සඳහා (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			නම් ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				නම් (err_abort) {
					err = -1;
					bha_nga;
				} නැතහොත්
					continue;
			}
			නම් (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				නම් (err_abort) {
					err = -1;
					bha_nga;
				} නැතහොත්
					continue;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			නම් (cmdnum == I_CHOWN) {
				නම් (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} නැතහොත් {
				නම් (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			නම් (err != 0 && err_abort)
				bha_nga;
		}
		bha_nga;
	pak_sa I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		bha_nga;
	pak_sa I_LPWD:
		නම් (!getcwd(path_buf, parimaa_na(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			bha_nga;
		}
		mprintf("Local working directory: %s\n", path_buf);
		bha_nga;
	pak_sa I_QUIT:
		/* Processed below */
		bha_nga;
	pak_sa I_HELP:
		help();
		bha_nga;
	pak_sa I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		bha_nga;
	pak_sa I_PROGRESS:
		showprogress = !showprogress;
		නම් (showprogress)
			printf("Progress meter enabled\n");
		නැතහොත්
			printf("Progress meter disabled\n");
		bha_nga;
	default:
		fatal("%d is not implemented", cmdnum);
	}

	නම් (g.gl_pathc)
		globfree(&g);
	free(path1);
	free(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	නම් (err_abort && err != 0)
		ආපසු (-1);
	නැතහොත් නම් (cmdnum == I_QUIT)
		ආපසු (1);

	ආපසු (0);
}

#ifdef USE_LIBEDIT
static var_na *
prompt(EditLine *el)
{
	ආපසු ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
static void
complete_display(var_na **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	sa_nracanaa winsize ws;
	var_na *tmp;

	/* Count entries for sort and find longest */
	සඳහා (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	නම් (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	සඳහා (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		නම් (m >= columns) {
			printf("\n");
			m = 1;
		} නැතහොත්
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
static var_na *
complete_ambiguous(const var_na *word, var_na **list, size_t count)
{
	size_t i, j, matchlen;
	var_na *tmp;
	පූර්ණ_සංඛ්‍යා len;

	නම් (word == NULL)
		ආපසු NULL;

	නම් (count == 0)
		ආපසු xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	සඳහා (i = 1; i < count && list[i] != NULL; i++) {
		සඳහා (j = 0; j < matchlen; j++)
			නම් (list[0][j] != list[i][j])
				bha_nga;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(NULL, 0);
	සඳහා (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		නම් (len <= 0 || i + (size_t)len > matchlen)
			bha_nga;
		i += (size_t)len;
	}
	/* If so, truncate */
	නම් (i < matchlen)
		matchlen = i;

	නම් (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		ආපසු tmp;
	}

	ආපසු xstrdup(word);
}

/* Autocomplete a sftp command */
static පූර්ණ_සංඛ්‍යා
complete_cmd_parse(EditLine *el, var_na *cmd, පූර්ණ_සංඛ්‍යා lastarg, var_na quote,
    පූර්ණ_සංඛ්‍යා terminated)
{
	u_int y, count = 0, cmdlen, tmplen;
	var_na *tmp, **list, argterm[3];
	const LineInfo *lf;

	list = xcalloc((parimaa_na(cmds) / parimaa_na(*cmds)) + 1, parimaa_na(var_na *));

	/* No command specified: display all available commands */
	නම් (cmd == NULL) {
		සඳහා (y = 0; cmds[y].c; y++)
			list[count++] = xstrdup(cmds[y].c);

		list[count] = NULL;
		complete_display(list, 0);

		සඳහා (y = 0; list[y] != NULL; y++)
			free(list[y]);
		free(list);
		ආපසු count;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	සඳහා (y = 0; cmds[y].c; y++)  {
		නම් (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[count++] = xstrdup(cmds[y].c);
	}
	list[count] = NULL;

	නම් (count == 0) {
		free(list);
		ආපසු 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, count);
	නම් (count > 1)
		complete_display(list, 0);

	සඳහා (y = 0; list[y]; y++)
		free(list[y]);
	free(list);

	නම් (tmp != NULL) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		නම් (tmplen > cmdlen)
			නම් (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_line(el);
		/* Terminate argument cleanly */
		නම් (count == 1) {
			y = 0;
			නම් (!terminated)
				argterm[y++] = quote;
			නම් (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			නම් (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		free(tmp);
	}

	ආපසු count;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
static පූර්ණ_සංඛ්‍යා
complete_is_remote(var_na *cmd, පූර්ණ_සංඛ්‍යා cmdarg) {
	පූර්ණ_සංඛ්‍යා i;

	නම් (cmd == NULL)
		ආපසු -1;

	සඳහා (i = 0; cmds[i].c; i++) {
		නම් (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			නම් (cmdarg == 1)
				ආපසු cmds[i].t;
			නැතහොත් නම් (cmdarg == 2)
				ආපසු cmds[i].t2;
			bha_nga;
		}
	}

	ආපසු -1;
}

/* Autocomplete a filename "file" */
static පූර්ණ_සංඛ්‍යා
complete_match(EditLine *el, sa_nracanaa sftp_conn *conn, var_na *remote_path,
    var_na *file, පූර්ණ_සංඛ්‍යා remote, පූර්ණ_සංඛ්‍යා lastarg, var_na quote, පූර්ණ_සංඛ්‍යා terminated)
{
	glob_t g;
	var_na *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	පූර්ණ_සංඛ්‍යා clen;
	const LineInfo *lf;

	/* Glob from "file" location */
	නම් (file == NULL)
		tmp = xstrdup("*");
	නැතහොත්
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, parimaa_na(g));
	නම් (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);
	} නැතහොත්
		(void)glob(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);

	/* Determine length of pwd so we can trim completion display */
	සඳහා (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		නම් (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			නම් (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			bha_nga;
		}
		නම් (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		නම් (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	free(tmp);
	tmp = NULL;

	නම් (g.gl_matchc == 0)
		goto out;

	නම් (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	නම් (file == NULL || hadglob)
		goto out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? NULL : remote_path);
	free(tmp2);

	නම් (tmp == NULL)
		goto out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	සඳහා (i = 0; i < filelen; i++) {
		නම් (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} නැතහොත්
			isesc = 0;
	}

	නම් (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(NULL, 0);
		සඳහා (i = 0; i < len; i += clen) {
			නම් ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > parimaa_na(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			switch (tmp2[i]) {
			pak_sa '\'':
			pak_sa '"':
			pak_sa '\\':
			pak_sa '\t':
			pak_sa '[':
			pak_sa ' ':
			pak_sa '#':
			pak_sa '*':
				නම් (quote == '\0' || tmp2[i] == quote) {
					නම් (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					bha_nga;
				}
				/* FALLTHROUGH */
			default:
				නම් (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				bha_nga;
			}
		}
	}

	lf = el_line(el);
	නම් (g.gl_matchc == 1) {
		i = 0;
		නම් (!terminated && quote != '\0')
			ins[i++] = quote;
		නම් (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		නම් (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	free(tmp);

 out:
	globfree(&g);
	ආපසු g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
static unsigned var_na
complete(EditLine *el, පූර්ණ_සංඛ්‍යා ch)
{
	var_na **argv, *line, quote;
	පූර්ණ_සංඛ්‍යා argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	const LineInfo *lf;
	sa_nracanaa complete_ctx *complete_ctx;

	lf = el_line(el);
	නම් (el_get(el, EL_CLIENTDATA, (void**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	line = xmalloc(cursor + 1);
	memcpy(line, lf->buffer, cursor);
	line[cursor] = '\0';
	argv = makeargv(line, &carg, 1, &quote, &terminated);
	free(line);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	line = xmalloc(len + 1);
	memcpy(line, lf->buffer, len);
	line[len] = '\0';
	argv = makeargv(line, &argc, 1, NULL, NULL);

	/* Ensure cursor is at EOL or a argument boundary */
	නම් (line[cursor] != ' ' && line[cursor] != '\0' &&
	    line[cursor] != '\n') {
		free(line);
		ආපසු ret;
	}

	නම් (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, NULL, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} නැතහොත් නම් (carg == 1 && cursor > 0 && line[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		නම් (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} නැතහොත් නම් (carg >= 1) {
		/* Handle file parsing */
		පූර්ණ_සංඛ්‍යා remote = 0;
		පූර්ණ_සංඛ්‍යා i = 0, cmdarg = 0;
		var_na *filematch = NULL;

		නම් (carg > 1 && line[cursor-1] != ' ')
			filematch = argv[carg - 1];

		සඳහා (i = 1; i < carg; i++) {
			/* Skip flags */
			නම් (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		නම් (line[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		නම් ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	free(line);
	ආපසු ret;
}
#endif /* USE_LIBEDIT */

static පූර්ණ_සංඛ්‍යා
interactive_loop(sa_nracanaa sftp_conn *conn, var_na *file1, var_na *file2)
{
	var_na *remote_path;
	var_na *dir = NULL, *startdir = NULL;
	var_na cmd[2048];
	පූර්ණ_සංඛ්‍යා err, interactive;
	EditLine *el = NULL;
#ifdef USE_LIBEDIT
	const var_na *editor;
	History *hl = NULL;
	HistEvent hev;
	extern var_na *__progname;
	sa_nracanaa complete_ctx complete_ctx;

	නම් (!batchmode && isatty(STDIN_FILENO)) {
		නම් ((el = el_init(__progname, stdin, stdout, stderr)) == NULL)
			fatal("Couldn't initialise editline");
		නම් ((hl = history_init()) == NULL)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, NULL);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, NULL);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (void*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", NULL);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", NULL);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", NULL);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", NULL);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", NULL);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", NULL);

		/* el_source() may have changed EL_EDITOR to vi */
		නම් (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", NULL);
	}
#endif /* USE_LIBEDIT */

	නම් ((remote_path = sftp_realpath(conn, ".")) == NULL)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	නම් (file1 != NULL) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		නම් (sftp_remote_is_dir(conn, dir) && file2 == NULL) {
			නම් (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, parimaa_na cmd, "cd \"%s\"", dir);
			නම් (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				free(dir);
				free(startdir);
				free(remote_path);
				free(conn);
				ආපසු (-1);
			}
		} නැතහොත් {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			free(dir);
			free(startdir);
			free(remote_path);
			free(conn);
			ආපසු (err);
		}
		free(dir);
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(infile, NULL, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	සඳහා (;;) {
		sa_nracanaa sigaction sa;

		interrupted = 0;
		memset(&sa, 0, parimaa_na(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		නම් (sigaction(SIGINT, &sa, NULL) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			bha_nga;
		}
		නම් (el == NULL) {
			නම් (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			නම් (fgets(cmd, parimaa_na(cmd), infile) == NULL) {
				නම් (interactive)
					printf("\n");
				නම් (interrupted)
					continue;
				bha_nga;
			}
		} නැතහොත් {
#ifdef USE_LIBEDIT
			const var_na *line;
			පූර්ණ_සංඛ්‍යා count = 0;

			නම් ((line = el_gets(el, &count)) == NULL ||
			    count <= 0) {
				printf("\n");
				නම් (interrupted)
					continue;
				bha_nga;
			}
			history(hl, &hev, H_ENTER, line);
			නම් (strlcpy(cmd, line, parimaa_na(cmd)) >= parimaa_na(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				continue;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == NULL);
		නම් (err != 0)
			bha_nga;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	free(remote_path);
	free(startdir);
	free(conn);

#ifdef USE_LIBEDIT
	නම් (hl != NULL)
		history_end(hl);
	නම් (el != NULL)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	ආපසු (err >= 0 ? 0 : -1);
}

static void
connect_to_server(var_na *path, var_na **args, පූර්ණ_සංඛ්‍යා *in, පූර්ණ_සංඛ්‍යා *out)
{
	පූර්ණ_සංඛ්‍යා c_in, c_out;
#ifdef USE_PIPES
	පූර්ණ_සංඛ්‍යා pin[2], pout[2];

	නම් ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#නැතහොත් /* USE_PIPES */
	පූර්ණ_සංඛ්‍යා inout[2];

	නම් (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	නම් ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	නැතහොත් නම් (sshpid == 0) {
		නම් ((dup2(c_in, STDIN_FILENO) == -1) ||
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

static void
usage(void)
{
	extern var_na *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

පූර්ණ_සංඛ්‍යා
main(පූර්ණ_සංඛ්‍යා argc, var_na **argv)
{
	පූර්ණ_සංඛ්‍යා r, in, out, ch, err, tmp, port = -1, noisy = 0;
	var_na *host = NULL, *user, *cp, **cpp, *file2 = NULL;
	පූර්ණ_සංඛ්‍යා debug_level = 0;
	var_na *file1 = NULL, *sftp_server = NULL;
	var_na *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = NULL;
	const var_na *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	extern පූර්ණ_සංඛ්‍යා optind;
	extern var_na *optarg;
	sa_nracanaa sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t num_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', parimaa_na(args));
	args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	අතරතුර ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		switch (ch) {
		/* Passed through to ssh(1) */
		pak_sa 'A':
		pak_sa '4':
		pak_sa '6':
		pak_sa 'C':
			addargs(&args, "-%c", ch);
			bha_nga;
		/* Passed through to ssh(1) with argument */
		pak_sa 'F':
		pak_sa 'J':
		pak_sa 'c':
		pak_sa 'i':
		pak_sa 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			bha_nga;
		pak_sa 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			bha_nga;
		pak_sa 'P':
			port = a2port(optarg);
			නම් (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			bha_nga;
		pak_sa 'v':
			නම් (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			bha_nga;
		pak_sa '1':
			fatal("SSH protocol v.1 is no longer supported");
			bha_nga;
		pak_sa '2':
			/* accept silently */
			bha_nga;
		pak_sa 'a':
			global_aflag = 1;
			bha_nga;
		pak_sa 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			නම් (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			bha_nga;
		pak_sa 'b':
			නම් (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			නම් (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == NULL)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			bha_nga;
		pak_sa 'f':
			global_fflag = 1;
			bha_nga;
		pak_sa 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			bha_nga;
		pak_sa 'p':
			global_pflag = 1;
			bha_nga;
		pak_sa 'D':
			sftp_direct = optarg;
			bha_nga;
		pak_sa 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			නම් (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			bha_nga;
		pak_sa 'r':
			global_rflag = 1;
			bha_nga;
		pak_sa 'R':
			num_requests = strtol(optarg, &cp, 10);
			නම් (num_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			bha_nga;
		pak_sa 's':
			sftp_server = optarg;
			bha_nga;
		pak_sa 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			bha_nga;
		pak_sa 'X':
			/* Please keep in sync with ssh.c -X */
			නම් (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				නම් (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				නම් (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} නැතහොත් නම් (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				නම් (errstr != NULL) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				num_requests = (size_t)llv;
			} නැතහොත් {
				fatal("Invalid -X option");
			}
			bha_nga;
		pak_sa 'h':
		default:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	නම් (!isatty(STDERR_FILENO))
		showprogress = 0;

	නම් (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	නම් (sftp_direct == NULL) {
		නම් (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		switch (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		pak_sa -1:
			usage();
			bha_nga;
		pak_sa 0:
			නම් (tmp != -1)
				port = tmp;
			bha_nga;
		default:
			/* Try with user, host and path. */
			නම් (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				bha_nga;
			/* Try with user and host. */
			නම් (parse_user_host_port(*argv, &user, &host, NULL)
			    == 0)
				bha_nga;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			bha_nga;
		}
		file2 = *(argv + 1);

		නම් (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		නම් (port != -1)
			addargs(&args, "-oPort %d", port);
		නම් (user != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		නම් (sftp_server == NULL || strchr(sftp_server, '/') == NULL)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != NULL ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} නැතහොත් {
		නම් ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		නම් (cpp[0] == NULL)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, num_requests, limit_kbps);
	නම් (conn == NULL)
		fatal("Couldn't initialise connection to server");

	නම් (!quiet) {
		නම් (sftp_direct == NULL)
			fprintf(stderr, "Connected to %s.\n", host);
		නැතහොත්
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#නම් !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	නම් (batchmode)
		fclose(infile);

	අතරතුර (waitpid(sshpid, NULL, 0) == -1 && sshpid > 1)
		නම් (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
