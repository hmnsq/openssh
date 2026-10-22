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
#បើមិនដូច្នេះ
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
ចំនួនគត់ batchmode = 0;

/* PID of ssh transport process */
static ca_ncala pid_t sshpid = -1;

/* Suppress diagnostic messages */
ចំនួនគត់ quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
ចំនួនគត់ showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
ចំនួនគត់ global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
ចំនួនគត់ global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
ចំនួនគត់ global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
ចំនួនគត់ global_fflag = 0;

/* SIGINT received during command processing */
ca_ncala sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
ចំនួនគត់ sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
sa_nracanaa complete_ctx {
	sa_nracanaa sftp_conn *conn;
	var_na **remote_pathp;
};

ចំនួនគត់ sftp_glob(sa_nracanaa sftp_conn *, const var_na *, ចំនួនគត់,
    ចំនួនគត់ (*)(const var_na *, ចំនួនគត់), glob_t *); /* proto for sftp-glob.c */

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
	const ចំនួនគត់ n;
	const ចំនួនគត់ t;	/* Completion type for the first argument */
	const ចំនួនគត់ t2;	/* completion type for the optional second argument */
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
killchild(ចំនួនគត់ signo)
{
	pid_t pid;

	pid = sshpid;
	ប្រសិនបើ (pid > 1) {
		kill(pid, SIGTERM);
		(void)waitpid(pid, NULL, 0);
	}

	_exit(1);
}

static void
suspchild(ចំនួនគត់ signo)
{
	ចំនួនគត់ save_errno = errno;
	ប្រសិនបើ (sshpid > 1) {
		kill(sshpid, signo);
		ខណៈពេល (waitpid(sshpid, NULL, WUNTRACED) == -1 && errno == EINTR)
			continue;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static void
cmd_interrupt(ចំនួនគត់ signo)
{
	const var_na msg[] = "\rInterrupt  \n";
	ចំនួនគត់ olderrno = errno;

	(void)write(STDERR_FILENO, msg, parimaa_na(msg) - 1);
	interrupted = 1;
	errno = olderrno;
}

static void
read_interrupt(ចំនួនគត់ signo)
{
	interrupted = 1;
}

static void
sigchld_handler(ចំនួនគត់ sig)
{
	ចំនួនគត់ save_errno = errno;
	pid_t pid;
	const var_na msg[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	ខណៈពេល ((pid = waitpid(sshpid, NULL, WNOHANG)) == -1 && errno == EINTR)
		continue;
	ប្រសិនបើ (pid == sshpid) {
		ប្រសិនបើ (!quiet)
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
	ចំនួនគត់ status;
	var_na *shell;
	pid_t pid;

	ប្រសិនបើ (!*args)
		args = NULL;

	ប្រសិនបើ ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	ប្រសិនបើ ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	ប្រសិនបើ (pid == 0) {
		ប្រសិនបើ (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (var_na *)NULL);
		} បើមិនដូច្នេះ {
			debug3("Executing %s", shell);
			execl(shell, shell, (var_na *)NULL);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	ខណៈពេល (waitpid(pid, &status, 0) == -1)
		ប្រសិនបើ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ប្រសិនបើ (!WIFEXITED(status))
		error("Shell exited abnormally");
	បើមិនដូច្នេះ ប្រសិនបើ (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

static void
local_do_ls(const var_na *args)
{
	ប្រសិនបើ (!args || !*args)
		local_do_shell(_PATH_LS);
	បើមិនដូច្នេះ {
		ចំនួនគត់ len = strlen(_PATH_LS " ") + strlen(args) + 1;
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

	ប្រសិនបើ (strip == NULL || (len = strlen(strip)) == 0)
		ត្រឡប់ (xstrdup(path));

	ប្រសិនបើ (strncmp(path, strip, len) == 0) {
		ប្រសិនបើ (strip[len - 1] != '/' && path[len] == '/')
			len++;
		ត្រឡប់ (xstrdup(path + len));
	}

	ត្រឡប់ (xstrdup(path));
}

static ចំនួនគត់
parse_getput_flags(const var_na *cmd, var_na **argv, ចំនួនគត់ argc,
    ចំនួនគត់ *aflag, ចំនួនគត់ *fflag, ចំនួនគត់ *pflag, ចំនួនគត់ *rflag)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	ខណៈពេល ((ch = getopt(argc, argv, "afPpRr")) != -1) {
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
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static ចំនួនគត់
parse_mkdir_flags(const var_na *cmd, var_na **argv, ចំនួនគត់ argc, ចំនួនគត់ *pflag)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	ខណៈពេល ((ch = getopt(argc, argv, "p")) != -1) {
		switch (ch) {
		pak_sa 'p':
			*pflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static ចំនួនគត់
parse_link_flags(const var_na *cmd, var_na **argv, ចំនួនគត់ argc, ចំនួនគត់ *sflag)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	ខណៈពេល ((ch = getopt(argc, argv, "s")) != -1) {
		switch (ch) {
		pak_sa 's':
			*sflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static ចំនួនគត់
parse_rename_flags(const var_na *cmd, var_na **argv, ចំនួនគត់ argc, ចំនួនគត់ *lflag)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	ខណៈពេល ((ch = getopt(argc, argv, "l")) != -1) {
		switch (ch) {
		pak_sa 'l':
			*lflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static ចំនួនគត់
parse_ls_flags(var_na **argv, ចំនួនគត់ argc, ចំនួនគត់ *lflag)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	ខណៈពេល ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
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
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static ចំនួនគត់
parse_df_flags(const var_na *cmd, var_na **argv, ចំនួនគត់ argc, ចំនួនគត់ *hflag, ចំនួនគត់ *iflag)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	ខណៈពេល ((ch = getopt(argc, argv, "hi")) != -1) {
		switch (ch) {
		pak_sa 'h':
			*hflag = 1;
			bha_nga;
		pak_sa 'i':
			*iflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static ចំនួនគត់
parse_ch_flags(const var_na *cmd, var_na **argv, ចំនួនគត់ argc, ចំនួនគត់ *hflag)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	ខណៈពេល ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		pak_sa 'h':
			*hflag = 1;
			bha_nga;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static ចំនួនគត់
parse_no_flags(const var_na *cmd, var_na **argv, ចំនួនគត់ argc)
{
	extern ចំនួនគត់ opterr, optind, optopt, optreset;
	ចំនួនគត់ ch;

	optind = optreset = 1;
	opterr = 0;

	ខណៈពេល ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			ត្រឡប់ -1;
		}
	}

	ត្រឡប់ optind;
}

static var_na *
escape_glob(const var_na *s)
{
	size_t i, o, len;
	var_na *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	សម្រាប់ (i = o = 0; i < len; i++) {
		ប្រសិនបើ (strchr("[]?*\\", s[i]) != NULL)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	ត្រឡប់ ret;
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
	ប្រសិនបើ (p == NULL)
		ត្រឡប់ escpwd;
	ret = sftp_make_absolute(p, escpwd);
	free(escpwd);
	ត្រឡប់ ret;
}

static ចំនួនគត់
local_is_dir(const var_na *path)
{
	sa_nracanaa stat sb;

	ប្រសិនបើ (stat(path, &sb) == -1)
		ត្រឡប់ 0;
	ត្រឡប់ S_ISDIR(sb.st_mode);
}

static ចំនួនគត់
process_get(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    const var_na *pwd, ចំនួនគត់ pflag, ចំនួនគត់ rflag, ចំនួនគត់ resume, ចំនួនគត់ fflag)
{
	var_na *filename, *abs_src = NULL, *abs_dst = NULL, *tmp = NULL;
	glob_t g;
	ចំនួនគត់ i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, parimaa_na(g));

	debug3("Looking up %s", abs_src);
	ប្រសិនបើ ((r = sftp_glob(conn, abs_src, GLOB_MARK, NULL, &g)) != 0) {
		ប្រសិនបើ (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} បើមិនដូច្នេះ {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		goto out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	ប្រសិនបើ (g.gl_matchc > 1 && dst != NULL && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		goto out;
	}

	សម្រាប់ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ប្រសិនបើ ((filename = basename(tmp)) == NULL) {
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
		ប្រសិនបើ (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		ប្រសិនបើ (g.gl_matchc == 1 && dst) {
			ប្រសិនបើ (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} បើមិនដូច្នេះ {
				abs_dst = xstrdup(dst);
			}
		} បើមិនដូច្នេះ ប្រសិនបើ (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} បើមិនដូច្នេះ {
			abs_dst = xstrdup(filename);
		}
		free(tmp);

		resume |= global_aflag;
		ប្រសិនបើ (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		បើមិនដូច្នេះ ប្រសិនបើ (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		ប្រសិនបើ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ប្រសិនបើ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} បើមិនដូច្នេះ {
			ប្រសិនបើ (sftp_download(conn, g.gl_pathv[i], abs_dst, NULL,
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
	ត្រឡប់(err);
}

static ចំនួនគត់
process_put(sa_nracanaa sftp_conn *conn, const var_na *src, const var_na *dst,
    const var_na *pwd, ចំនួនគត់ pflag, ចំនួនគត់ rflag, ចំនួនគត់ resume, ចំនួនគត់ fflag)
{
	var_na *tmp_dst = NULL;
	var_na *abs_dst = NULL;
	var_na *tmp = NULL, *filename = NULL;
	glob_t g;
	ចំនួនគត់ err = 0;
	ចំនួនគត់ i, dst_is_dir = 1;
	sa_nracanaa stat sb;

	ប្រសិនបើ (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, parimaa_na(g));
	debug3("Looking up %s", src);
	ប្រសិនបើ (glob(src, GLOB_NOCHECK | GLOB_MARK, NULL, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		goto out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	ប្រសិនបើ (tmp_dst != NULL)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	ប្រសិនបើ (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		goto out;
	}

	សម្រាប់ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		ប្រសិនបើ (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			continue;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		ប្រសិនបើ ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			free(tmp);
			err = -1;
			goto out;
		}
		/* Special handling for source of '..' */
		ប្រសិនបើ (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		free(abs_dst);
		abs_dst = NULL;
		ប្រសិនបើ (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			ប្រសិនបើ (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			បើមិនដូច្នេះ
				abs_dst = xstrdup(tmp_dst);
		} បើមិនដូច្នេះ ប្រសិនបើ (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} បើមិនដូច្នេះ {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		free(tmp);

		resume |= global_aflag;
		ប្រសិនបើ (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		បើមិនដូច្នេះ ប្រសិនបើ (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		ប្រសិនបើ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ប្រសិនបើ (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} បើមិនដូច្នេះ {
			ប្រសិនបើ (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	free(abs_dst);
	free(tmp_dst);
	globfree(&g);
	ត្រឡប់(err);
}

static ចំនួនគត់
sdirent_comp(const void *aa, const void *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	ចំនួនគត់ rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	ប្រសិនបើ (sort_flag & LS_NAME_SORT)
		ត្រឡប់ (rmul * strcmp(a->filename, b->filename));
	បើមិនដូច្នេះ ប្រសិនបើ (sort_flag & LS_TIME_SORT)
		ត្រឡប់ (rmul * NCMP(a->a.mtime, b->a.mtime));
	បើមិនដូច្នេះ ប្រសិនបើ (sort_flag & LS_SIZE_SORT)
		ត្រឡប់ (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
static ចំនួនគត់
do_ls_dir(sa_nracanaa sftp_conn *conn, const var_na *path,
    const var_na *strip_path, ចំនួនគត់ lflag)
{
	ចំនួនគត់ n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	ប្រសិនបើ ((n = sftp_readdir(conn, path, &d)) != 0)
		ត្រឡប់ (n);

	ប្រសិនបើ (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		sa_nracanaa winsize ws;
		var_na *tmp;

		/* Count entries for sort and find longest filename */
		សម្រាប់ (n = 0; d[n] != NULL; n++) {
			ប្រសិនបើ (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		free(tmp);

		ប្រសិនបើ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	ប្រសិនបើ (lflag & SORT_FLAGS) {
		សម្រាប់ (n = 0; d[n] != NULL; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, parimaa_na(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	សម្រាប់ (n = 0; d[n] != NULL && !interrupted; n++) {
		var_na *tmp, *fname;

		ប្រសិនបើ (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			continue;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		free(tmp);

		ប្រសិនបើ (lflag & LS_LONG_VIEW) {
			ប្រសិនបើ ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				var_na *lname;
				sa_nracanaa stat sb;
				const var_na *user = NULL, *group = NULL;

				memset(&sb, 0, parimaa_na(sb));
				attrib_to_stat(&d[n]->a, &sb);
				ប្រសិនបើ ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				free(lname);
			} បើមិនដូច្នេះ
				mprintf("%s\n", d[n]->longname);
		} បើមិនដូច្នេះ {
			mprintf("%-*s", colspace, fname);
			ប្រសិនបើ (c >= columns) {
				printf("\n");
				c = 1;
			} បើមិនដូច្នេះ
				c++;
		}

		free(fname);
	}

	ប្រសិនបើ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	ត្រឡប់ (0);
}

static ចំនួនគត់
sglob_comp(const void *aa, const void *bb)
{
	u_int a = *(const u_int *)aa;
	u_int b = *(const u_int *)bb;
	const var_na *ap = sort_glob->gl_pathv[a];
	const var_na *bp = sort_glob->gl_pathv[b];
	const sa_nracanaa stat *as = sort_glob->gl_statv[a];
	const sa_nracanaa stat *bs = sort_glob->gl_statv[b];
	ចំនួនគត់ rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	ប្រសិនបើ (as == NULL || bs == NULL)
		ត្រឡប់ (as == bs) ? 0 : (as == NULL ? rmul : -rmul);
	ប្រសិនបើ (sort_flag & LS_NAME_SORT)
		ត្រឡប់ (rmul * strcmp(ap, bp));
	បើមិនដូច្នេះ ប្រសិនបើ (sort_flag & LS_TIME_SORT) {
#ប្រសិនបើ defined(HAVE_STRUCT_STAT_ST_MTIM)
		ប្រសិនបើ (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			ត្រឡប់ 0;
		ត្រឡប់ timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#elif defined(HAVE_STRUCT_STAT_ST_MTIME)
		ត្រឡប់ (rmul * NCMP(as->st_mtime, bs->st_mtime));
#បើមិនដូច្នេះ
	ត្រឡប់ rmul * 1;
#endif
	} បើមិនដូច្នេះ ប្រសិនបើ (sort_flag & LS_SIZE_SORT)
		ត្រឡប់ (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
static ចំនួនគត់
do_globbed_ls(sa_nracanaa sftp_conn *conn, const var_na *path,
    const var_na *strip_path, ចំនួនគត់ lflag)
{
	var_na *fname, *lname;
	glob_t g;
	ចំនួនគត់ err, r;
	sa_nracanaa winsize ws;
	u_int i, j, nentries, *indices = NULL, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, parimaa_na(g));

	ប្រសិនបើ ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    NULL, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		ប្រសិនបើ (g.gl_pathc)
			globfree(&g);
		ប្រសិនបើ (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} បើមិនដូច្នេះ {
			error("Can't ls: \"%s\" not found", path);
		}
		ត្រឡប់ -1;
	}

	ប្រសិនបើ (interrupted)
		goto out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	ប្រសិនបើ (g.gl_matchc == 1 && g.gl_statv[0] != NULL &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		ត្រឡប់ err;
	}

	ប្រសិនបើ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	ប្រសិនបើ (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		សម្រាប់ (i = 0; g.gl_pathv[i]; i++)
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
	សម្រាប់ (nentries = 0; g.gl_pathv[nentries] != NULL; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, parimaa_na(*indices));
	សម្រាប់ (i = 0; i < nentries; i++)
		indices[i] = i;

	ប្រសិនបើ (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, parimaa_na(*indices), sglob_comp);
		sort_glob = NULL;
	}

	get_remote_user_groups_from_glob(conn, &g);
	សម្រាប់ (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		ប្រសិនបើ (lflag & LS_LONG_VIEW) {
			const var_na *user = NULL, *group = NULL;

			ប្រសិនបើ (g.gl_statv[i] == NULL) {
				error("no stat information for %s", fname);
				free(fname);
				continue;
			}
			ប្រសិនបើ ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			free(lname);
		} បើមិនដូច្នេះ {
			mprintf("%-*s", colspace, fname);
			ប្រសិនបើ (c >= columns) {
				printf("\n");
				c = 1;
			} បើមិនដូច្នេះ
				c++;
		}
		free(fname);
	}

	ប្រសិនបើ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	ប្រសិនបើ (g.gl_pathc)
		globfree(&g);
	free(indices);

	ត្រឡប់ 0;
}

static ចំនួនគត់
do_df(sa_nracanaa sftp_conn *conn, const var_na *path, ចំនួនគត់ hflag, ចំនួនគត់ iflag)
{
	sa_nracanaa sftp_statvfs st;
	var_na s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	var_na s_root[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	var_na s_icapacity[16], s_dcapacity[16];

	ប្រសិនបើ (sftp_statvfs(conn, path, &st, 1) == -1)
		ត្រឡប់ -1;
	ប្រសិនបើ (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", parimaa_na(s_icapacity));
	បើមិនដូច្នេះ {
		snprintf(s_icapacity, parimaa_na(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	ប្រសិនបើ (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", parimaa_na(s_dcapacity));
	បើមិនដូច្នេះ {
		snprintf(s_dcapacity, parimaa_na(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	ប្រសិនបើ (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} បើមិនដូច្នេះ ប្រសិនបើ (hflag) {
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
	} បើមិនដូច្នេះ {
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
	ត្រឡប់ 0;
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

	សម្រាប់ (i = j = 0;;) {
		ប្រសិនបើ (s[i] == '\0') {
			s[j] = '\0';
			ត្រឡប់;
		}
		ប្រសិនបើ (s[i] != '\\') {
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
			ត្រឡប់;
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
makeargv(const var_na *arg, ចំនួនគត់ *argcp, ចំនួនគត់ sloppy, var_na *lastquote,
    u_int *terminated)
{
	ចំនួនគត់ argc, quot;
	size_t i, j;
	static var_na argvs[MAXARGLEN];
	static var_na *argv[MAXARGS + 1];
	ga_nanaa { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	ប្រសិនបើ (strlen(arg) > parimaa_na(argvs) - 1) {
 args_too_longs:
		error("string too long");
		ត្រឡប់ NULL;
	}
	ប្រសិនបើ (terminated != NULL)
		*terminated = 1;
	ប្រសិនបើ (lastquote != NULL)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	សម្រាប់ (;;) {
		ប្រសិនបើ ((size_t)argc >= parimaa_na(argv) / parimaa_na(*argv)){
			error("Too many arguments.");
			ត្រឡប់ NULL;
		}
		ប្រសិនបើ (isspace((unsigned var_na)arg[i])) {
			ប្រសិនបើ (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} បើមិនដូច្នេះ ប្រសិនបើ (state != MA_START)
				argvs[j++] = arg[i];
		} បើមិនដូច្នេះ ប្រសិនបើ (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			ប្រសិនបើ (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				ប្រសិនបើ (lastquote != NULL)
					*lastquote = arg[i];
			} បើមិនដូច្នេះ ប្រសិនបើ (state == MA_UNQUOTED)
				state = q;
			បើមិនដូច្នេះ ប្រសិនបើ (state == q)
				state = MA_UNQUOTED;
			បើមិនដូច្នេះ
				argvs[j++] = arg[i];
		} បើមិនដូច្នេះ ប្រសិនបើ (arg[i] == '\\') {
			ប្រសិនបើ (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				ប្រសិនបើ (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} បើមិនដូច្នេះ ប្រសិនបើ (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					ប្រសិនបើ (j >= parimaa_na(argvs) - 5)
						goto args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} បើមិនដូច្នេះ {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} បើមិនដូច្នេះ {
				ប្រសិនបើ (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					ប្រសិនបើ (lastquote != NULL)
						*lastquote = '\0';
				}
				ប្រសិនបើ (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} បើមិនដូច្នេះ {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					ប្រសិនបើ (arg[i] == '\0')
						goto early_nul;
					argvs[j++] = arg[i];
				}
			}
		} បើមិនដូច្នេះ ប្រសិនបើ (arg[i] == '#') {
			ប្រសិនបើ (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			បើមិនដូច្នេះ
				goto string_done;
		} បើមិនដូច្នេះ ប្រសិនបើ (arg[i] == '\0') {
			ប្រសិនបើ (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				ប្រសិនបើ (sloppy) {
					state = MA_UNQUOTED;
					ប្រសិនបើ (terminated != NULL)
						*terminated = 0;
					goto string_done;
				}
				error("Unterminated quoted argument");
				ត្រឡប់ NULL;
			}
 string_done:
			ប្រសិនបើ (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			bha_nga;
		} បើមិនដូច្នេះ {
			ប្រសិនបើ (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				ប្រសិនបើ (lastquote != NULL)
					*lastquote = '\0';
			}
			ប្រសិនបើ ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				ប្រសិនបើ (j >= parimaa_na(argvs) - 3)
					goto args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} បើមិនដូច្នេះ
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	ត្រឡប់ argv;
}

static ចំនួនគត់
parse_args(const var_na **cpp, ចំនួនគត់ *ignore_errors, ចំនួនគត់ *disable_echo, ចំនួនគត់ *aflag,
	  ចំនួនគត់ *fflag, ចំនួនគត់ *hflag, ចំនួនគត់ *iflag, ចំនួនគត់ *lflag, ចំនួនគត់ *pflag,
	  ចំនួនគត់ *rflag, ចំនួនគត់ *sflag,
    unsigned long *n_arg, var_na **path1, var_na **path2)
{
	const var_na *cmd, *cp = *cpp;
	var_na *cp2, **argv;
	ចំនួនគត់ base = 0;
	long long ll;
	ចំនួនគត់ path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	សម្រាប់ (;*cp != '\0'; cp++) {
		ប្រសិនបើ (*cp == '-') {
			*ignore_errors = 1;
		} បើមិនដូច្នេះ ប្រសិនបើ (*cp == '@') {
			*disable_echo = 1;
		} បើមិនដូច្នេះ {
			/* all other characters terminate prefix processing */
			bha_nga;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	ប្រសិនបើ (*cp == '\0' || *cp == '#')
		ត្រឡប់ (0);

	ប្រសិនបើ ((argv = makeargv(cp, &argc, 0, NULL, NULL)) == NULL)
		ត្រឡប់ -1;

	/* Figure out which command we have */
	សម្រាប់ (i = 0; cmds[i].c != NULL; i++) {
		ប្រសិនបើ (argv[0] != NULL && strcasecmp(cmds[i].c, argv[0]) == 0)
			bha_nga;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	ប្រសិនបើ (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} បើមិនដូច្នេះ ប្រសិនបើ (cmdnum == -1) {
		error("Invalid command.");
		ត្រឡប់ -1;
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
		ប្រសិនបើ ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			ត្រឡប់ -1;
		/* Get first pathname (mandatory) */
		ប្រសិនបើ (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			ត្រឡប់ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		ប្រសិនបើ (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		bha_nga;
	pak_sa I_LINK:
		ប្រសិនបើ ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			ត្រឡប់ -1;
		goto parse_two_paths;
	pak_sa I_COPY:
		ប្រសិនបើ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ត្រឡប់ -1;
		goto parse_two_paths;
	pak_sa I_RENAME:
		ប្រសិនបើ ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			ត្រឡប់ -1;
		goto parse_two_paths;
	pak_sa I_SYMLINK:
		ប្រសិនបើ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ត្រឡប់ -1;
 parse_two_paths:
		ប្រសិនបើ (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			ត្រឡប់ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		bha_nga;
	pak_sa I_MKDIR:
	pak_sa I_LMKDIR:
		ប្រសិនបើ ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			ត្រឡប់ -1;
		path1_mandatory = 1;
		goto parse_one_path;
	pak_sa I_RM:
	pak_sa I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	pak_sa I_CHDIR:
	pak_sa I_LCHDIR:
		ប្រសិនបើ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ត្រឡប់ -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		ប្រសិនបើ (argc - optidx < 1) {
			ប្រសិនបើ (!path1_mandatory)
				bha_nga; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			ត្រឡប់ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		ប្រសិនបើ (cmdnum != I_RM)
			undo_glob_escape(*path1);
		bha_nga;
	pak_sa I_DF:
		ប្រសិនបើ ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			ត្រឡប់ -1;
		/* Default to current directory if no path specified */
		ប្រសិនបើ (argc - optidx < 1)
			*path1 = NULL;
		បើមិនដូច្នេះ {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		bha_nga;
	pak_sa I_LS:
		ប្រសិនបើ ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			ត្រឡប់(-1);
		/* Path is optional */
		ប្រសិនបើ (argc - optidx > 0)
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
		ប្រសិនបើ ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			ត្រឡប់ -1;
		/* Get numeric arg (mandatory) */
		ប្រសិនបើ (argc - optidx < 1)
			goto need_num_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		ប្រសិនបើ (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_num_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			ត្រឡប់ -1;
		}
		*n_arg = ll;
		ប្រសិនបើ (cmdnum == I_LUMASK)
			bha_nga;
		/* Get pathname (mandatory) */
		ប្រសិនបើ (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			ត្រឡប់ -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		bha_nga;
	pak_sa I_QUIT:
	pak_sa I_PWD:
	pak_sa I_LPWD:
	pak_sa I_HELP:
	pak_sa I_VERSION:
	pak_sa I_PROGRESS:
		ប្រសិនបើ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ត្រឡប់ -1;
		bha_nga;
	default:
		fatal("Command not implemented");
	}

	*cpp = cp;
	ត្រឡប់(cmdnum);
}

static ចំនួនគត់
parse_dispatch_command(sa_nracanaa sftp_conn *conn, const var_na *cmd, var_na **pwd,
    const var_na *startdir, ចំនួនគត់ err_abort, ចំនួនគត់ echo_command)
{
	const var_na *ocmd = cmd;
	var_na *path1, *path2, *tmp;
	ចំនួនគត់ ignore_errors = 0, disable_echo = 1;
	ចំនួនគត់ aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	ចំនួនគត់ lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	ចំនួនគត់ cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	var_na path_buf[PATH_MAX];
	ចំនួនគត់ err = 0;
	glob_t g;

	path1 = path2 = NULL;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	ប្រសិនបើ (ignore_errors != 0)
		err_abort = 0;

	ប្រសិនបើ (echo_command && !disable_echo)
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
		ប្រសិនបើ (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		bha_nga;
	pak_sa I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		សម្រាប់ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ប្រសិនបើ (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			ប្រសិនបើ (err != 0 && err_abort)
				bha_nga;
		}
		bha_nga;
	pak_sa I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		ប្រសិនបើ (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		បើមិនដូច្នេះ
			err = sftp_mkdir(conn, path1, &a, 1);
		bha_nga;
	pak_sa I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		bha_nga;
	pak_sa I_CHDIR:
		ប្រសិនបើ (path1 == NULL || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		ប្រសិនបើ ((tmp = sftp_realpath(conn, path1)) == NULL) {
			err = 1;
			bha_nga;
		}
		ប្រសិនបើ (sftp_stat(conn, tmp, 0, &aa) != 0) {
			free(tmp);
			err = 1;
			bha_nga;
		}
		ប្រសិនបើ (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			free(tmp);
			err = 1;
			bha_nga;
		}
		ប្រសិនបើ (!S_ISDIR(aa.perm)) {
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
		ប្រសិនបើ (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			bha_nga;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = NULL;
		ប្រសិនបើ (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		bha_nga;
	pak_sa I_DF:
		/* Default to current directory if no path specified */
		ប្រសិនបើ (path1 == NULL)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		bha_nga;
	pak_sa I_LCHDIR:
		ប្រសិនបើ (path1 == NULL || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		free(path1);
		path1 = tmp;
		ប្រសិនបើ (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		bha_nga;
	pak_sa I_LMKDIR:
		ប្រសិនបើ (pflag) {
			ប្រសិនបើ (mkdir_path(path1, 0777) != 0)
				err = 1;
			bha_nga;
		}
		ប្រសិនបើ (mkdir(path1, 0777) == -1) {
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
		សម្រាប់ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ប្រសិនបើ (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			ប្រសិនបើ (err != 0 && err_abort)
				bha_nga;
		}
		bha_nga;
	pak_sa I_CHOWN:
	pak_sa I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		សម្រាប់ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ប្រសិនបើ ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				ប្រសិនបើ (err_abort) {
					err = -1;
					bha_nga;
				} បើមិនដូច្នេះ
					continue;
			}
			ប្រសិនបើ (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				ប្រសិនបើ (err_abort) {
					err = -1;
					bha_nga;
				} បើមិនដូច្នេះ
					continue;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			ប្រសិនបើ (cmdnum == I_CHOWN) {
				ប្រសិនបើ (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} បើមិនដូច្នេះ {
				ប្រសិនបើ (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			ប្រសិនបើ (err != 0 && err_abort)
				bha_nga;
		}
		bha_nga;
	pak_sa I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		bha_nga;
	pak_sa I_LPWD:
		ប្រសិនបើ (!getcwd(path_buf, parimaa_na(path_buf))) {
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
		ប្រសិនបើ (showprogress)
			printf("Progress meter enabled\n");
		បើមិនដូច្នេះ
			printf("Progress meter disabled\n");
		bha_nga;
	default:
		fatal("%d is not implemented", cmdnum);
	}

	ប្រសិនបើ (g.gl_pathc)
		globfree(&g);
	free(path1);
	free(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	ប្រសិនបើ (err_abort && err != 0)
		ត្រឡប់ (-1);
	បើមិនដូច្នេះ ប្រសិនបើ (cmdnum == I_QUIT)
		ត្រឡប់ (1);

	ត្រឡប់ (0);
}

#ifdef USE_LIBEDIT
static var_na *
prompt(EditLine *el)
{
	ត្រឡប់ ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
static void
complete_display(var_na **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	sa_nracanaa winsize ws;
	var_na *tmp;

	/* Count entries for sort and find longest */
	សម្រាប់ (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	ប្រសិនបើ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	សម្រាប់ (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		ប្រសិនបើ (m >= columns) {
			printf("\n");
			m = 1;
		} បើមិនដូច្នេះ
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
	ចំនួនគត់ len;

	ប្រសិនបើ (word == NULL)
		ត្រឡប់ NULL;

	ប្រសិនបើ (count == 0)
		ត្រឡប់ xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	សម្រាប់ (i = 1; i < count && list[i] != NULL; i++) {
		សម្រាប់ (j = 0; j < matchlen; j++)
			ប្រសិនបើ (list[0][j] != list[i][j])
				bha_nga;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(NULL, 0);
	សម្រាប់ (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		ប្រសិនបើ (len <= 0 || i + (size_t)len > matchlen)
			bha_nga;
		i += (size_t)len;
	}
	/* If so, truncate */
	ប្រសិនបើ (i < matchlen)
		matchlen = i;

	ប្រសិនបើ (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		ត្រឡប់ tmp;
	}

	ត្រឡប់ xstrdup(word);
}

/* Autocomplete a sftp command */
static ចំនួនគត់
complete_cmd_parse(EditLine *el, var_na *cmd, ចំនួនគត់ lastarg, var_na quote,
    ចំនួនគត់ terminated)
{
	u_int y, count = 0, cmdlen, tmplen;
	var_na *tmp, **list, argterm[3];
	const LineInfo *lf;

	list = xcalloc((parimaa_na(cmds) / parimaa_na(*cmds)) + 1, parimaa_na(var_na *));

	/* No command specified: display all available commands */
	ប្រសិនបើ (cmd == NULL) {
		សម្រាប់ (y = 0; cmds[y].c; y++)
			list[count++] = xstrdup(cmds[y].c);

		list[count] = NULL;
		complete_display(list, 0);

		សម្រាប់ (y = 0; list[y] != NULL; y++)
			free(list[y]);
		free(list);
		ត្រឡប់ count;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	សម្រាប់ (y = 0; cmds[y].c; y++)  {
		ប្រសិនបើ (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[count++] = xstrdup(cmds[y].c);
	}
	list[count] = NULL;

	ប្រសិនបើ (count == 0) {
		free(list);
		ត្រឡប់ 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, count);
	ប្រសិនបើ (count > 1)
		complete_display(list, 0);

	សម្រាប់ (y = 0; list[y]; y++)
		free(list[y]);
	free(list);

	ប្រសិនបើ (tmp != NULL) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		ប្រសិនបើ (tmplen > cmdlen)
			ប្រសិនបើ (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_line(el);
		/* Terminate argument cleanly */
		ប្រសិនបើ (count == 1) {
			y = 0;
			ប្រសិនបើ (!terminated)
				argterm[y++] = quote;
			ប្រសិនបើ (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			ប្រសិនបើ (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		free(tmp);
	}

	ត្រឡប់ count;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
static ចំនួនគត់
complete_is_remote(var_na *cmd, ចំនួនគត់ cmdarg) {
	ចំនួនគត់ i;

	ប្រសិនបើ (cmd == NULL)
		ត្រឡប់ -1;

	សម្រាប់ (i = 0; cmds[i].c; i++) {
		ប្រសិនបើ (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			ប្រសិនបើ (cmdarg == 1)
				ត្រឡប់ cmds[i].t;
			បើមិនដូច្នេះ ប្រសិនបើ (cmdarg == 2)
				ត្រឡប់ cmds[i].t2;
			bha_nga;
		}
	}

	ត្រឡប់ -1;
}

/* Autocomplete a filename "file" */
static ចំនួនគត់
complete_match(EditLine *el, sa_nracanaa sftp_conn *conn, var_na *remote_path,
    var_na *file, ចំនួនគត់ remote, ចំនួនគត់ lastarg, var_na quote, ចំនួនគត់ terminated)
{
	glob_t g;
	var_na *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	ចំនួនគត់ clen;
	const LineInfo *lf;

	/* Glob from "file" location */
	ប្រសិនបើ (file == NULL)
		tmp = xstrdup("*");
	បើមិនដូច្នេះ
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, parimaa_na(g));
	ប្រសិនបើ (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);
	} បើមិនដូច្នេះ
		(void)glob(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);

	/* Determine length of pwd so we can trim completion display */
	សម្រាប់ (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		ប្រសិនបើ (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			ប្រសិនបើ (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			bha_nga;
		}
		ប្រសិនបើ (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		ប្រសិនបើ (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	free(tmp);
	tmp = NULL;

	ប្រសិនបើ (g.gl_matchc == 0)
		goto out;

	ប្រសិនបើ (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	ប្រសិនបើ (file == NULL || hadglob)
		goto out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? NULL : remote_path);
	free(tmp2);

	ប្រសិនបើ (tmp == NULL)
		goto out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	សម្រាប់ (i = 0; i < filelen; i++) {
		ប្រសិនបើ (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} បើមិនដូច្នេះ
			isesc = 0;
	}

	ប្រសិនបើ (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(NULL, 0);
		សម្រាប់ (i = 0; i < len; i += clen) {
			ប្រសិនបើ ((clen = mblen(tmp2 + i, len - i)) < 0 ||
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
				ប្រសិនបើ (quote == '\0' || tmp2[i] == quote) {
					ប្រសិនបើ (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					bha_nga;
				}
				/* FALLTHROUGH */
			default:
				ប្រសិនបើ (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				bha_nga;
			}
		}
	}

	lf = el_line(el);
	ប្រសិនបើ (g.gl_matchc == 1) {
		i = 0;
		ប្រសិនបើ (!terminated && quote != '\0')
			ins[i++] = quote;
		ប្រសិនបើ (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		ប្រសិនបើ (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	free(tmp);

 out:
	globfree(&g);
	ត្រឡប់ g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
static unsigned var_na
complete(EditLine *el, ចំនួនគត់ ch)
{
	var_na **argv, *line, quote;
	ចំនួនគត់ argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	const LineInfo *lf;
	sa_nracanaa complete_ctx *complete_ctx;

	lf = el_line(el);
	ប្រសិនបើ (el_get(el, EL_CLIENTDATA, (void**)&complete_ctx) != 0)
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
	ប្រសិនបើ (line[cursor] != ' ' && line[cursor] != '\0' &&
	    line[cursor] != '\n') {
		free(line);
		ត្រឡប់ ret;
	}

	ប្រសិនបើ (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, NULL, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} បើមិនដូច្នេះ ប្រសិនបើ (carg == 1 && cursor > 0 && line[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		ប្រសិនបើ (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} បើមិនដូច្នេះ ប្រសិនបើ (carg >= 1) {
		/* Handle file parsing */
		ចំនួនគត់ remote = 0;
		ចំនួនគត់ i = 0, cmdarg = 0;
		var_na *filematch = NULL;

		ប្រសិនបើ (carg > 1 && line[cursor-1] != ' ')
			filematch = argv[carg - 1];

		សម្រាប់ (i = 1; i < carg; i++) {
			/* Skip flags */
			ប្រសិនបើ (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		ប្រសិនបើ (line[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		ប្រសិនបើ ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	free(line);
	ត្រឡប់ ret;
}
#endif /* USE_LIBEDIT */

static ចំនួនគត់
interactive_loop(sa_nracanaa sftp_conn *conn, var_na *file1, var_na *file2)
{
	var_na *remote_path;
	var_na *dir = NULL, *startdir = NULL;
	var_na cmd[2048];
	ចំនួនគត់ err, interactive;
	EditLine *el = NULL;
#ifdef USE_LIBEDIT
	const var_na *editor;
	History *hl = NULL;
	HistEvent hev;
	extern var_na *__progname;
	sa_nracanaa complete_ctx complete_ctx;

	ប្រសិនបើ (!batchmode && isatty(STDIN_FILENO)) {
		ប្រសិនបើ ((el = el_init(__progname, stdin, stdout, stderr)) == NULL)
			fatal("Couldn't initialise editline");
		ប្រសិនបើ ((hl = history_init()) == NULL)
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
		ប្រសិនបើ (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", NULL);
	}
#endif /* USE_LIBEDIT */

	ប្រសិនបើ ((remote_path = sftp_realpath(conn, ".")) == NULL)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	ប្រសិនបើ (file1 != NULL) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		ប្រសិនបើ (sftp_remote_is_dir(conn, dir) && file2 == NULL) {
			ប្រសិនបើ (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, parimaa_na cmd, "cd \"%s\"", dir);
			ប្រសិនបើ (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				free(dir);
				free(startdir);
				free(remote_path);
				free(conn);
				ត្រឡប់ (-1);
			}
		} បើមិនដូច្នេះ {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			free(dir);
			free(startdir);
			free(remote_path);
			free(conn);
			ត្រឡប់ (err);
		}
		free(dir);
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(infile, NULL, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	សម្រាប់ (;;) {
		sa_nracanaa sigaction sa;

		interrupted = 0;
		memset(&sa, 0, parimaa_na(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		ប្រសិនបើ (sigaction(SIGINT, &sa, NULL) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			bha_nga;
		}
		ប្រសិនបើ (el == NULL) {
			ប្រសិនបើ (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			ប្រសិនបើ (fgets(cmd, parimaa_na(cmd), infile) == NULL) {
				ប្រសិនបើ (interactive)
					printf("\n");
				ប្រសិនបើ (interrupted)
					continue;
				bha_nga;
			}
		} បើមិនដូច្នេះ {
#ifdef USE_LIBEDIT
			const var_na *line;
			ចំនួនគត់ count = 0;

			ប្រសិនបើ ((line = el_gets(el, &count)) == NULL ||
			    count <= 0) {
				printf("\n");
				ប្រសិនបើ (interrupted)
					continue;
				bha_nga;
			}
			history(hl, &hev, H_ENTER, line);
			ប្រសិនបើ (strlcpy(cmd, line, parimaa_na(cmd)) >= parimaa_na(cmd)) {
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
		ប្រសិនបើ (err != 0)
			bha_nga;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	free(remote_path);
	free(startdir);
	free(conn);

#ifdef USE_LIBEDIT
	ប្រសិនបើ (hl != NULL)
		history_end(hl);
	ប្រសិនបើ (el != NULL)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	ត្រឡប់ (err >= 0 ? 0 : -1);
}

static void
connect_to_server(var_na *path, var_na **args, ចំនួនគត់ *in, ចំនួនគត់ *out)
{
	ចំនួនគត់ c_in, c_out;
#ifdef USE_PIPES
	ចំនួនគត់ pin[2], pout[2];

	ប្រសិនបើ ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#បើមិនដូច្នេះ /* USE_PIPES */
	ចំនួនគត់ inout[2];

	ប្រសិនបើ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	ប្រសិនបើ ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	បើមិនដូច្នេះ ប្រសិនបើ (sshpid == 0) {
		ប្រសិនបើ ((dup2(c_in, STDIN_FILENO) == -1) ||
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

ចំនួនគត់
main(ចំនួនគត់ argc, var_na **argv)
{
	ចំនួនគត់ r, in, out, ch, err, tmp, port = -1, noisy = 0;
	var_na *host = NULL, *user, *cp, **cpp, *file2 = NULL;
	ចំនួនគត់ debug_level = 0;
	var_na *file1 = NULL, *sftp_server = NULL;
	var_na *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = NULL;
	const var_na *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	extern ចំនួនគត់ optind;
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

	ខណៈពេល ((ch = getopt(argc, argv,
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
			ប្រសិនបើ (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			bha_nga;
		pak_sa 'v':
			ប្រសិនបើ (debug_level < 3) {
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
			ប្រសិនបើ (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			bha_nga;
		pak_sa 'b':
			ប្រសិនបើ (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			ប្រសិនបើ (strcmp(optarg, "-") != 0 &&
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
			ប្រសិនបើ (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			bha_nga;
		pak_sa 'r':
			global_rflag = 1;
			bha_nga;
		pak_sa 'R':
			num_requests = strtol(optarg, &cp, 10);
			ប្រសិនបើ (num_requests == 0 || *cp != '\0')
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
			ប្រសិនបើ (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				ប្រសិនបើ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ប្រសិនបើ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} បើមិនដូច្នេះ ប្រសិនបើ (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ប្រសិនបើ (errstr != NULL) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				num_requests = (size_t)llv;
			} បើមិនដូច្នេះ {
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

	ប្រសិនបើ (!isatty(STDERR_FILENO))
		showprogress = 0;

	ប្រសិនបើ (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	ប្រសិនបើ (sftp_direct == NULL) {
		ប្រសិនបើ (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		switch (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		pak_sa -1:
			usage();
			bha_nga;
		pak_sa 0:
			ប្រសិនបើ (tmp != -1)
				port = tmp;
			bha_nga;
		default:
			/* Try with user, host and path. */
			ប្រសិនបើ (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				bha_nga;
			/* Try with user and host. */
			ប្រសិនបើ (parse_user_host_port(*argv, &user, &host, NULL)
			    == 0)
				bha_nga;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			bha_nga;
		}
		file2 = *(argv + 1);

		ប្រសិនបើ (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		ប្រសិនបើ (port != -1)
			addargs(&args, "-oPort %d", port);
		ប្រសិនបើ (user != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		ប្រសិនបើ (sftp_server == NULL || strchr(sftp_server, '/') == NULL)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != NULL ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} បើមិនដូច្នេះ {
		ប្រសិនបើ ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		ប្រសិនបើ (cpp[0] == NULL)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, num_requests, limit_kbps);
	ប្រសិនបើ (conn == NULL)
		fatal("Couldn't initialise connection to server");

	ប្រសិនបើ (!quiet) {
		ប្រសិនបើ (sftp_direct == NULL)
			fprintf(stderr, "Connected to %s.\n", host);
		បើមិនដូច្នេះ
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#ប្រសិនបើ !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	ប្រសិនបើ (batchmode)
		fclose(infile);

	ខណៈពេល (waitpid(sshpid, NULL, 0) == -1 && sshpid > 1)
		ប្រសិនបើ (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
