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
#否则
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
整数 batchmode = 0;

/* PID of ssh transport process */
static volatile pid_t sshpid = -1;

/* Suppress diagnostic messages */
整数 quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
整数 showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
整数 global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
整数 global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
整数 global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
整数 global_fflag = 0;

/* SIGINT received during command processing */
volatile sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
整数 sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
struct complete_ctx {
	struct sftp_conn *conn;
	char **remote_pathp;
};

整数 sftp_glob(struct sftp_conn *, const char *, 整数,
    整数 (*)(const char *, 整数), glob_t *); /* proto for sftp-glob.c */

extern char *__progname;

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
enum sftp_command {
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

struct CMD {
	const char *c;
	const 整数 n;
	const 整数 t;	/* Completion type for the first argument */
	const 整数 t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

static const struct CMD cmds[] = {
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
killchild(整数 signo)
{
	pid_t pid;

	pid = sshpid;
	もし (pid > 1) {
		kill(pid, SIGTERM);
		(void)waitpid(pid, NULL, 0);
	}

	_exit(1);
}

static void
suspchild(整数 signo)
{
	整数 save_errno = errno;
	もし (sshpid > 1) {
		kill(sshpid, signo);
		ながら (waitpid(sshpid, NULL, WUNTRACED) == -1 && errno == EINTR)
			continue;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static void
cmd_interrupt(整数 signo)
{
	const char msg[] = "\rInterrupt  \n";
	整数 olderrno = errno;

	(void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
	interrupted = 1;
	errno = olderrno;
}

static void
read_interrupt(整数 signo)
{
	interrupted = 1;
}

static void
sigchld_handler(整数 sig)
{
	整数 save_errno = errno;
	pid_t pid;
	const char msg[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	ながら ((pid = waitpid(sshpid, NULL, WNOHANG)) == -1 && errno == EINTR)
		continue;
	もし (pid == sshpid) {
		もし (!quiet)
		    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
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
local_do_shell(const char *args)
{
	整数 status;
	char *shell;
	pid_t pid;

	もし (!*args)
		args = NULL;

	もし ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	もし ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	もし (pid == 0) {
		もし (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (char *)NULL);
		} 否则 {
			debug3("Executing %s", shell);
			execl(shell, shell, (char *)NULL);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	ながら (waitpid(pid, &status, 0) == -1)
		もし (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	もし (!WIFEXITED(status))
		error("Shell exited abnormally");
	否则 もし (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

static void
local_do_ls(const char *args)
{
	もし (!args || !*args)
		local_do_shell(_PATH_LS);
	否则 {
		整数 len = strlen(_PATH_LS " ") + strlen(args) + 1;
		char *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		free(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
static char *
path_strip(const char *path, const char *strip)
{
	size_t len;

	もし (strip == NULL || (len = strlen(strip)) == 0)
		戻る (xstrdup(path));

	もし (strncmp(path, strip, len) == 0) {
		もし (strip[len - 1] != '/' && path[len] == '/')
			len++;
		戻る (xstrdup(path + len));
	}

	戻る (xstrdup(path));
}

static 整数
parse_getput_flags(const char *cmd, char **argv, 整数 argc,
    整数 *aflag, 整数 *fflag, 整数 *pflag, 整数 *rflag)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	ながら ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		switch (ch) {
		case 'a':
			*aflag = 1;
			break;
		case 'f':
			*fflag = 1;
			break;
		case 'p':
		case 'P':
			*pflag = 1;
			break;
		case 'r':
		case 'R':
			*rflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static 整数
parse_mkdir_flags(const char *cmd, char **argv, 整数 argc, 整数 *pflag)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	ながら ((ch = getopt(argc, argv, "p")) != -1) {
		switch (ch) {
		case 'p':
			*pflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static 整数
parse_link_flags(const char *cmd, char **argv, 整数 argc, 整数 *sflag)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	ながら ((ch = getopt(argc, argv, "s")) != -1) {
		switch (ch) {
		case 's':
			*sflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static 整数
parse_rename_flags(const char *cmd, char **argv, 整数 argc, 整数 *lflag)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	ながら ((ch = getopt(argc, argv, "l")) != -1) {
		switch (ch) {
		case 'l':
			*lflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static 整数
parse_ls_flags(char **argv, 整数 argc, 整数 *lflag)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	ながら ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		switch (ch) {
		case '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			break;
		case 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			break;
		case 'a':
			*lflag |= LS_SHOW_ALL;
			break;
		case 'f':
			*lflag &= ~SORT_FLAGS;
			break;
		case 'h':
			*lflag |= LS_SI_UNITS;
			break;
		case 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			break;
		case 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			break;
		case 'r':
			*lflag |= LS_REVERSE_SORT;
			break;
		case 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			break;
		default:
			error("ls: Invalid flag -%c", optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static 整数
parse_df_flags(const char *cmd, char **argv, 整数 argc, 整数 *hflag, 整数 *iflag)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	ながら ((ch = getopt(argc, argv, "hi")) != -1) {
		switch (ch) {
		case 'h':
			*hflag = 1;
			break;
		case 'i':
			*iflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static 整数
parse_ch_flags(const char *cmd, char **argv, 整数 argc, 整数 *hflag)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	ながら ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			*hflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static 整数
parse_no_flags(const char *cmd, char **argv, 整数 argc)
{
	extern 整数 opterr, optind, optopt, optreset;
	整数 ch;

	optind = optreset = 1;
	opterr = 0;

	ながら ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			戻る -1;
		}
	}

	戻る optind;
}

static char *
escape_glob(const char *s)
{
	size_t i, o, len;
	char *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	ために (i = o = 0; i < len; i++) {
		もし (strchr("[]?*\\", s[i]) != NULL)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	戻る ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
static char *
make_absolute_pwd_glob(char *p, const char *pwd)
{
	char *ret, *escpwd;

	escpwd = escape_glob(pwd);
	もし (p == NULL)
		戻る escpwd;
	ret = sftp_make_absolute(p, escpwd);
	free(escpwd);
	戻る ret;
}

static 整数
local_is_dir(const char *path)
{
	struct stat sb;

	もし (stat(path, &sb) == -1)
		戻る 0;
	戻る S_ISDIR(sb.st_mode);
}

static 整数
process_get(struct sftp_conn *conn, const char *src, const char *dst,
    const char *pwd, 整数 pflag, 整数 rflag, 整数 resume, 整数 fflag)
{
	char *filename, *abs_src = NULL, *abs_dst = NULL, *tmp = NULL;
	glob_t g;
	整数 i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, sizeof(g));

	debug3("Looking up %s", abs_src);
	もし ((r = sftp_glob(conn, abs_src, GLOB_MARK, NULL, &g)) != 0) {
		もし (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} 否则 {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		goto out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	もし (g.gl_matchc > 1 && dst != NULL && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		goto out;
	}

	ために (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		もし ((filename = basename(tmp)) == NULL) {
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
		もし (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		もし (g.gl_matchc == 1 && dst) {
			もし (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} 否则 {
				abs_dst = xstrdup(dst);
			}
		} 否则 もし (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} 否则 {
			abs_dst = xstrdup(filename);
		}
		free(tmp);

		resume |= global_aflag;
		もし (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		否则 もし (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		もし (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			もし (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} 否则 {
			もし (sftp_download(conn, g.gl_pathv[i], abs_dst, NULL,
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
	戻る(err);
}

static 整数
process_put(struct sftp_conn *conn, const char *src, const char *dst,
    const char *pwd, 整数 pflag, 整数 rflag, 整数 resume, 整数 fflag)
{
	char *tmp_dst = NULL;
	char *abs_dst = NULL;
	char *tmp = NULL, *filename = NULL;
	glob_t g;
	整数 err = 0;
	整数 i, dst_is_dir = 1;
	struct stat sb;

	もし (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, sizeof(g));
	debug3("Looking up %s", src);
	もし (glob(src, GLOB_NOCHECK | GLOB_MARK, NULL, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		goto out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	もし (tmp_dst != NULL)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	もし (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		goto out;
	}

	ために (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		もし (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			continue;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		もし ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			free(tmp);
			err = -1;
			goto out;
		}
		/* Special handling for source of '..' */
		もし (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		free(abs_dst);
		abs_dst = NULL;
		もし (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			もし (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			否则
				abs_dst = xstrdup(tmp_dst);
		} 否则 もし (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} 否则 {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		free(tmp);

		resume |= global_aflag;
		もし (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		否则 もし (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		もし (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			もし (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} 否则 {
			もし (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	free(abs_dst);
	free(tmp_dst);
	globfree(&g);
	戻る(err);
}

static 整数
sdirent_comp(const void *aa, const void *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	整数 rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	もし (sort_flag & LS_NAME_SORT)
		戻る (rmul * strcmp(a->filename, b->filename));
	否则 もし (sort_flag & LS_TIME_SORT)
		戻る (rmul * NCMP(a->a.mtime, b->a.mtime));
	否则 もし (sort_flag & LS_SIZE_SORT)
		戻る (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
static 整数
do_ls_dir(struct sftp_conn *conn, const char *path,
    const char *strip_path, 整数 lflag)
{
	整数 n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	もし ((n = sftp_readdir(conn, path, &d)) != 0)
		戻る (n);

	もし (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		struct winsize ws;
		char *tmp;

		/* Count entries for sort and find longest filename */
		ために (n = 0; d[n] != NULL; n++) {
			もし (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		free(tmp);

		もし (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	もし (lflag & SORT_FLAGS) {
		ために (n = 0; d[n] != NULL; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, sizeof(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	ために (n = 0; d[n] != NULL && !interrupted; n++) {
		char *tmp, *fname;

		もし (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			continue;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		free(tmp);

		もし (lflag & LS_LONG_VIEW) {
			もし ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				char *lname;
				struct stat sb;
				const char *user = NULL, *group = NULL;

				memset(&sb, 0, sizeof(sb));
				attrib_to_stat(&d[n]->a, &sb);
				もし ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				free(lname);
			} 否则
				mprintf("%s\n", d[n]->longname);
		} 否则 {
			mprintf("%-*s", colspace, fname);
			もし (c >= columns) {
				printf("\n");
				c = 1;
			} 否则
				c++;
		}

		free(fname);
	}

	もし (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	戻る (0);
}

static 整数
sglob_comp(const void *aa, const void *bb)
{
	u_int a = *(const u_int *)aa;
	u_int b = *(const u_int *)bb;
	const char *ap = sort_glob->gl_pathv[a];
	const char *bp = sort_glob->gl_pathv[b];
	const struct stat *as = sort_glob->gl_statv[a];
	const struct stat *bs = sort_glob->gl_statv[b];
	整数 rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	もし (as == NULL || bs == NULL)
		戻る (as == bs) ? 0 : (as == NULL ? rmul : -rmul);
	もし (sort_flag & LS_NAME_SORT)
		戻る (rmul * strcmp(ap, bp));
	否则 もし (sort_flag & LS_TIME_SORT) {
#もし defined(HAVE_STRUCT_STAT_ST_MTIM)
		もし (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			戻る 0;
		戻る timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#elif defined(HAVE_STRUCT_STAT_ST_MTIME)
		戻る (rmul * NCMP(as->st_mtime, bs->st_mtime));
#否则
	戻る rmul * 1;
#endif
	} 否则 もし (sort_flag & LS_SIZE_SORT)
		戻る (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
static 整数
do_globbed_ls(struct sftp_conn *conn, const char *path,
    const char *strip_path, 整数 lflag)
{
	char *fname, *lname;
	glob_t g;
	整数 err, r;
	struct winsize ws;
	u_int i, j, nentries, *indices = NULL, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, sizeof(g));

	もし ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    NULL, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		もし (g.gl_pathc)
			globfree(&g);
		もし (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} 否则 {
			error("Can't ls: \"%s\" not found", path);
		}
		戻る -1;
	}

	もし (interrupted)
		goto out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	もし (g.gl_matchc == 1 && g.gl_statv[0] != NULL &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		戻る err;
	}

	もし (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	もし (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		ために (i = 0; g.gl_pathv[i]; i++)
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
	ために (nentries = 0; g.gl_pathv[nentries] != NULL; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, sizeof(*indices));
	ために (i = 0; i < nentries; i++)
		indices[i] = i;

	もし (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, sizeof(*indices), sglob_comp);
		sort_glob = NULL;
	}

	get_remote_user_groups_from_glob(conn, &g);
	ために (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		もし (lflag & LS_LONG_VIEW) {
			const char *user = NULL, *group = NULL;

			もし (g.gl_statv[i] == NULL) {
				error("no stat information for %s", fname);
				free(fname);
				continue;
			}
			もし ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			free(lname);
		} 否则 {
			mprintf("%-*s", colspace, fname);
			もし (c >= columns) {
				printf("\n");
				c = 1;
			} 否则
				c++;
		}
		free(fname);
	}

	もし (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	もし (g.gl_pathc)
		globfree(&g);
	free(indices);

	戻る 0;
}

static 整数
do_df(struct sftp_conn *conn, const char *path, 整数 hflag, 整数 iflag)
{
	struct sftp_statvfs st;
	char s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	char s_root[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	char s_icapacity[16], s_dcapacity[16];

	もし (sftp_statvfs(conn, path, &st, 1) == -1)
		戻る -1;
	もし (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", sizeof(s_icapacity));
	否则 {
		snprintf(s_icapacity, sizeof(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	もし (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", sizeof(s_dcapacity));
	否则 {
		snprintf(s_dcapacity, sizeof(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	もし (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} 否则 もし (hflag) {
		strlcpy(s_used, "error", sizeof(s_used));
		strlcpy(s_avail, "error", sizeof(s_avail));
		strlcpy(s_root, "error", sizeof(s_root));
		strlcpy(s_total, "error", sizeof(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_root);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_root, s_dcapacity);
	} 否则 {
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
	戻る 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
static void
undo_glob_escape(char *s)
{
	size_t i, j;

	ために (i = j = 0;;) {
		もし (s[i] == '\0') {
			s[j] = '\0';
			戻る;
		}
		もし (s[i] != '\\') {
			s[j++] = s[i++];
			continue;
		}
		/* s[i] == '\\' */
		++i;
		switch (s[i]) {
		case '?':
		case '[':
		case '*':
		case '\\':
			s[j++] = s[i++];
			break;
		case '\0':
			s[j++] = '\\';
			s[j] = '\0';
			戻る;
		default:
			s[j++] = '\\';
			s[j++] = s[i++];
			break;
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
static char **
makeargv(const char *arg, 整数 *argcp, 整数 sloppy, char *lastquote,
    u_int *terminated)
{
	整数 argc, quot;
	size_t i, j;
	static char argvs[MAXARGLEN];
	static char *argv[MAXARGS + 1];
	enum { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	もし (strlen(arg) > sizeof(argvs) - 1) {
 args_too_longs:
		error("string too long");
		戻る NULL;
	}
	もし (terminated != NULL)
		*terminated = 1;
	もし (lastquote != NULL)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	ために (;;) {
		もし ((size_t)argc >= sizeof(argv) / sizeof(*argv)){
			error("Too many arguments.");
			戻る NULL;
		}
		もし (isspace((unsigned char)arg[i])) {
			もし (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} 否则 もし (state != MA_START)
				argvs[j++] = arg[i];
		} 否则 もし (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			もし (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				もし (lastquote != NULL)
					*lastquote = arg[i];
			} 否则 もし (state == MA_UNQUOTED)
				state = q;
			否则 もし (state == q)
				state = MA_UNQUOTED;
			否则
				argvs[j++] = arg[i];
		} 否则 もし (arg[i] == '\\') {
			もし (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				もし (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} 否则 もし (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					もし (j >= sizeof(argvs) - 5)
						goto args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} 否则 {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} 否则 {
				もし (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					もし (lastquote != NULL)
						*lastquote = '\0';
				}
				もし (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} 否则 {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					もし (arg[i] == '\0')
						goto early_nul;
					argvs[j++] = arg[i];
				}
			}
		} 否则 もし (arg[i] == '#') {
			もし (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			否则
				goto string_done;
		} 否则 もし (arg[i] == '\0') {
			もし (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				もし (sloppy) {
					state = MA_UNQUOTED;
					もし (terminated != NULL)
						*terminated = 0;
					goto string_done;
				}
				error("Unterminated quoted argument");
				戻る NULL;
			}
 string_done:
			もし (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			break;
		} 否则 {
			もし (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				もし (lastquote != NULL)
					*lastquote = '\0';
			}
			もし ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				もし (j >= sizeof(argvs) - 3)
					goto args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} 否则
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	戻る argv;
}

static 整数
parse_args(const char **cpp, 整数 *ignore_errors, 整数 *disable_echo, 整数 *aflag,
	  整数 *fflag, 整数 *hflag, 整数 *iflag, 整数 *lflag, 整数 *pflag,
	  整数 *rflag, 整数 *sflag,
    unsigned long *n_arg, char **path1, char **path2)
{
	const char *cmd, *cp = *cpp;
	char *cp2, **argv;
	整数 base = 0;
	long long ll;
	整数 path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	ために (;*cp != '\0'; cp++) {
		もし (*cp == '-') {
			*ignore_errors = 1;
		} 否则 もし (*cp == '@') {
			*disable_echo = 1;
		} 否则 {
			/* all other characters terminate prefix processing */
			break;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	もし (*cp == '\0' || *cp == '#')
		戻る (0);

	もし ((argv = makeargv(cp, &argc, 0, NULL, NULL)) == NULL)
		戻る -1;

	/* Figure out which command we have */
	ために (i = 0; cmds[i].c != NULL; i++) {
		もし (argv[0] != NULL && strcasecmp(cmds[i].c, argv[0]) == 0)
			break;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	もし (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} 否则 もし (cmdnum == -1) {
		error("Invalid command.");
		戻る -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = NULL;
	optidx = 1;
	switch (cmdnum) {
	case I_GET:
	case I_REGET:
	case I_REPUT:
	case I_PUT:
		もし ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			戻る -1;
		/* Get first pathname (mandatory) */
		もし (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			戻る -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		もし (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		break;
	case I_LINK:
		もし ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			戻る -1;
		goto parse_two_paths;
	case I_COPY:
		もし ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			戻る -1;
		goto parse_two_paths;
	case I_RENAME:
		もし ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			戻る -1;
		goto parse_two_paths;
	case I_SYMLINK:
		もし ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			戻る -1;
 parse_two_paths:
		もし (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			戻る -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		break;
	case I_MKDIR:
	case I_LMKDIR:
		もし ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			戻る -1;
		path1_mandatory = 1;
		goto parse_one_path;
	case I_RM:
	case I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	case I_CHDIR:
	case I_LCHDIR:
		もし ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			戻る -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		もし (argc - optidx < 1) {
			もし (!path1_mandatory)
				break; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			戻る -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		もし (cmdnum != I_RM)
			undo_glob_escape(*path1);
		break;
	case I_DF:
		もし ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			戻る -1;
		/* Default to current directory if no path specified */
		もし (argc - optidx < 1)
			*path1 = NULL;
		否则 {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		break;
	case I_LS:
		もし ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			戻る(-1);
		/* Path is optional */
		もし (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		break;
	case I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	case I_SHELL:
		/* Uses the rest of the line */
		break;
	case I_LUMASK:
	case I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	case I_CHOWN:
	case I_CHGRP:
		もし ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			戻る -1;
		/* Get numeric arg (mandatory) */
		もし (argc - optidx < 1)
			goto need_num_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		もし (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_num_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			戻る -1;
		}
		*n_arg = ll;
		もし (cmdnum == I_LUMASK)
			break;
		/* Get pathname (mandatory) */
		もし (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			戻る -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		break;
	case I_QUIT:
	case I_PWD:
	case I_LPWD:
	case I_HELP:
	case I_VERSION:
	case I_PROGRESS:
		もし ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			戻る -1;
		break;
	default:
		fatal("Command not implemented");
	}

	*cpp = cp;
	戻る(cmdnum);
}

static 整数
parse_dispatch_command(struct sftp_conn *conn, const char *cmd, char **pwd,
    const char *startdir, 整数 err_abort, 整数 echo_command)
{
	const char *ocmd = cmd;
	char *path1, *path2, *tmp;
	整数 ignore_errors = 0, disable_echo = 1;
	整数 aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	整数 lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	整数 cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	char path_buf[PATH_MAX];
	整数 err = 0;
	glob_t g;

	path1 = path2 = NULL;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	もし (ignore_errors != 0)
		err_abort = 0;

	もし (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, sizeof(g));

	/* Perform command */
	switch (cmdnum) {
	case 0:
		/* Blank line */
		break;
	case -1:
		/* Unrecognized command */
		err = -1;
		break;
	case I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	case I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		break;
	case I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	case I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		break;
	case I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		break;
	case I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		break;
	case I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	case I_LINK:
		もし (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		break;
	case I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		ために (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			もし (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			もし (err != 0 && err_abort)
				break;
		}
		break;
	case I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		もし (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		否则
			err = sftp_mkdir(conn, path1, &a, 1);
		break;
	case I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		break;
	case I_CHDIR:
		もし (path1 == NULL || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		もし ((tmp = sftp_realpath(conn, path1)) == NULL) {
			err = 1;
			break;
		}
		もし (sftp_stat(conn, tmp, 0, &aa) != 0) {
			free(tmp);
			err = 1;
			break;
		}
		もし (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			free(tmp);
			err = 1;
			break;
		}
		もし (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			free(tmp);
			err = 1;
			break;
		}
		free(*pwd);
		*pwd = tmp;
		break;
	case I_LS:
		もし (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			break;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = NULL;
		もし (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		break;
	case I_DF:
		/* Default to current directory if no path specified */
		もし (path1 == NULL)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		break;
	case I_LCHDIR:
		もし (path1 == NULL || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		free(path1);
		path1 = tmp;
		もし (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		break;
	case I_LMKDIR:
		もし (pflag) {
			もし (mkdir_path(path1, 0777) != 0)
				err = 1;
			break;
		}
		もし (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		break;
	case I_LLS:
		local_do_ls(cmd);
		break;
	case I_SHELL:
		local_do_shell(cmd);
		break;
	case I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		break;
	case I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		ために (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			もし (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			もし (err != 0 && err_abort)
				break;
		}
		break;
	case I_CHOWN:
	case I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		ために (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			もし ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				もし (err_abort) {
					err = -1;
					break;
				} 否则
					continue;
			}
			もし (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				もし (err_abort) {
					err = -1;
					break;
				} 否则
					continue;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			もし (cmdnum == I_CHOWN) {
				もし (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} 否则 {
				もし (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			もし (err != 0 && err_abort)
				break;
		}
		break;
	case I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		break;
	case I_LPWD:
		もし (!getcwd(path_buf, sizeof(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			break;
		}
		mprintf("Local working directory: %s\n", path_buf);
		break;
	case I_QUIT:
		/* Processed below */
		break;
	case I_HELP:
		help();
		break;
	case I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		break;
	case I_PROGRESS:
		showprogress = !showprogress;
		もし (showprogress)
			printf("Progress meter enabled\n");
		否则
			printf("Progress meter disabled\n");
		break;
	default:
		fatal("%d is not implemented", cmdnum);
	}

	もし (g.gl_pathc)
		globfree(&g);
	free(path1);
	free(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	もし (err_abort && err != 0)
		戻る (-1);
	否则 もし (cmdnum == I_QUIT)
		戻る (1);

	戻る (0);
}

#ifdef USE_LIBEDIT
static char *
prompt(EditLine *el)
{
	戻る ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
static void
complete_display(char **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	struct winsize ws;
	char *tmp;

	/* Count entries for sort and find longest */
	ために (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	もし (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	ために (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		もし (m >= columns) {
			printf("\n");
			m = 1;
		} 否则
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
static char *
complete_ambiguous(const char *word, char **list, size_t count)
{
	size_t i, j, matchlen;
	char *tmp;
	整数 len;

	もし (word == NULL)
		戻る NULL;

	もし (count == 0)
		戻る xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	ために (i = 1; i < count && list[i] != NULL; i++) {
		ために (j = 0; j < matchlen; j++)
			もし (list[0][j] != list[i][j])
				break;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(NULL, 0);
	ために (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		もし (len <= 0 || i + (size_t)len > matchlen)
			break;
		i += (size_t)len;
	}
	/* If so, truncate */
	もし (i < matchlen)
		matchlen = i;

	もし (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		戻る tmp;
	}

	戻る xstrdup(word);
}

/* Autocomplete a sftp command */
static 整数
complete_cmd_parse(EditLine *el, char *cmd, 整数 lastarg, char quote,
    整数 terminated)
{
	u_int y, count = 0, cmdlen, tmplen;
	char *tmp, **list, argterm[3];
	const LineInfo *lf;

	list = xcalloc((sizeof(cmds) / sizeof(*cmds)) + 1, sizeof(char *));

	/* No command specified: display all available commands */
	もし (cmd == NULL) {
		ために (y = 0; cmds[y].c; y++)
			list[count++] = xstrdup(cmds[y].c);

		list[count] = NULL;
		complete_display(list, 0);

		ために (y = 0; list[y] != NULL; y++)
			free(list[y]);
		free(list);
		戻る count;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	ために (y = 0; cmds[y].c; y++)  {
		もし (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[count++] = xstrdup(cmds[y].c);
	}
	list[count] = NULL;

	もし (count == 0) {
		free(list);
		戻る 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, count);
	もし (count > 1)
		complete_display(list, 0);

	ために (y = 0; list[y]; y++)
		free(list[y]);
	free(list);

	もし (tmp != NULL) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		もし (tmplen > cmdlen)
			もし (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_line(el);
		/* Terminate argument cleanly */
		もし (count == 1) {
			y = 0;
			もし (!terminated)
				argterm[y++] = quote;
			もし (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			もし (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		free(tmp);
	}

	戻る count;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
static 整数
complete_is_remote(char *cmd, 整数 cmdarg) {
	整数 i;

	もし (cmd == NULL)
		戻る -1;

	ために (i = 0; cmds[i].c; i++) {
		もし (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			もし (cmdarg == 1)
				戻る cmds[i].t;
			否则 もし (cmdarg == 2)
				戻る cmds[i].t2;
			break;
		}
	}

	戻る -1;
}

/* Autocomplete a filename "file" */
static 整数
complete_match(EditLine *el, struct sftp_conn *conn, char *remote_path,
    char *file, 整数 remote, 整数 lastarg, char quote, 整数 terminated)
{
	glob_t g;
	char *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	整数 clen;
	const LineInfo *lf;

	/* Glob from "file" location */
	もし (file == NULL)
		tmp = xstrdup("*");
	否则
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, sizeof(g));
	もし (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);
	} 否则
		(void)glob(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);

	/* Determine length of pwd so we can trim completion display */
	ために (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		もし (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			もし (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			break;
		}
		もし (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		もし (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	free(tmp);
	tmp = NULL;

	もし (g.gl_matchc == 0)
		goto out;

	もし (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	もし (file == NULL || hadglob)
		goto out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? NULL : remote_path);
	free(tmp2);

	もし (tmp == NULL)
		goto out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	ために (i = 0; i < filelen; i++) {
		もし (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} 否则
			isesc = 0;
	}

	もし (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(NULL, 0);
		ために (i = 0; i < len; i += clen) {
			もし ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > sizeof(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			switch (tmp2[i]) {
			case '\'':
			case '"':
			case '\\':
			case '\t':
			case '[':
			case ' ':
			case '#':
			case '*':
				もし (quote == '\0' || tmp2[i] == quote) {
					もし (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					break;
				}
				/* FALLTHROUGH */
			default:
				もし (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				break;
			}
		}
	}

	lf = el_line(el);
	もし (g.gl_matchc == 1) {
		i = 0;
		もし (!terminated && quote != '\0')
			ins[i++] = quote;
		もし (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		もし (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	free(tmp);

 out:
	globfree(&g);
	戻る g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
static unsigned char
complete(EditLine *el, 整数 ch)
{
	char **argv, *line, quote;
	整数 argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	const LineInfo *lf;
	struct complete_ctx *complete_ctx;

	lf = el_line(el);
	もし (el_get(el, EL_CLIENTDATA, (void**)&complete_ctx) != 0)
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
	もし (line[cursor] != ' ' && line[cursor] != '\0' &&
	    line[cursor] != '\n') {
		free(line);
		戻る ret;
	}

	もし (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, NULL, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} 否则 もし (carg == 1 && cursor > 0 && line[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		もし (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} 否则 もし (carg >= 1) {
		/* Handle file parsing */
		整数 remote = 0;
		整数 i = 0, cmdarg = 0;
		char *filematch = NULL;

		もし (carg > 1 && line[cursor-1] != ' ')
			filematch = argv[carg - 1];

		ために (i = 1; i < carg; i++) {
			/* Skip flags */
			もし (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		もし (line[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		もし ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	free(line);
	戻る ret;
}
#endif /* USE_LIBEDIT */

static 整数
interactive_loop(struct sftp_conn *conn, char *file1, char *file2)
{
	char *remote_path;
	char *dir = NULL, *startdir = NULL;
	char cmd[2048];
	整数 err, interactive;
	EditLine *el = NULL;
#ifdef USE_LIBEDIT
	const char *editor;
	History *hl = NULL;
	HistEvent hev;
	extern char *__progname;
	struct complete_ctx complete_ctx;

	もし (!batchmode && isatty(STDIN_FILENO)) {
		もし ((el = el_init(__progname, stdin, stdout, stderr)) == NULL)
			fatal("Couldn't initialise editline");
		もし ((hl = history_init()) == NULL)
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
		もし (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", NULL);
	}
#endif /* USE_LIBEDIT */

	もし ((remote_path = sftp_realpath(conn, ".")) == NULL)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	もし (file1 != NULL) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		もし (sftp_remote_is_dir(conn, dir) && file2 == NULL) {
			もし (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, sizeof cmd, "cd \"%s\"", dir);
			もし (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				free(dir);
				free(startdir);
				free(remote_path);
				free(conn);
				戻る (-1);
			}
		} 否则 {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			free(dir);
			free(startdir);
			free(remote_path);
			free(conn);
			戻る (err);
		}
		free(dir);
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(infile, NULL, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	ために (;;) {
		struct sigaction sa;

		interrupted = 0;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		もし (sigaction(SIGINT, &sa, NULL) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			break;
		}
		もし (el == NULL) {
			もし (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			もし (fgets(cmd, sizeof(cmd), infile) == NULL) {
				もし (interactive)
					printf("\n");
				もし (interrupted)
					continue;
				break;
			}
		} 否则 {
#ifdef USE_LIBEDIT
			const char *line;
			整数 count = 0;

			もし ((line = el_gets(el, &count)) == NULL ||
			    count <= 0) {
				printf("\n");
				もし (interrupted)
					continue;
				break;
			}
			history(hl, &hev, H_ENTER, line);
			もし (strlcpy(cmd, line, sizeof(cmd)) >= sizeof(cmd)) {
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
		もし (err != 0)
			break;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	free(remote_path);
	free(startdir);
	free(conn);

#ifdef USE_LIBEDIT
	もし (hl != NULL)
		history_end(hl);
	もし (el != NULL)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	戻る (err >= 0 ? 0 : -1);
}

static void
connect_to_server(char *path, char **args, 整数 *in, 整数 *out)
{
	整数 c_in, c_out;
#ifdef USE_PIPES
	整数 pin[2], pout[2];

	もし ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#否则 /* USE_PIPES */
	整数 inout[2];

	もし (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	もし ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	否则 もし (sshpid == 0) {
		もし ((dup2(c_in, STDIN_FILENO) == -1) ||
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
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

整数
メインページ(整数 argc, char **argv)
{
	整数 r, in, out, ch, err, tmp, port = -1, noisy = 0;
	char *host = NULL, *user, *cp, **cpp, *file2 = NULL;
	整数 debug_level = 0;
	char *file1 = NULL, *sftp_server = NULL;
	char *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = NULL;
	const char *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	extern 整数 optind;
	extern char *optarg;
	struct sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t num_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', sizeof(args));
	args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	ながら ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		switch (ch) {
		/* Passed through to ssh(1) */
		case 'A':
		case '4':
		case '6':
		case 'C':
			addargs(&args, "-%c", ch);
			break;
		/* Passed through to ssh(1) with argument */
		case 'F':
		case 'J':
		case 'c':
		case 'i':
		case 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			break;
		case 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			break;
		case 'P':
			port = a2port(optarg);
			もし (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			break;
		case 'v':
			もし (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			break;
		case '1':
			fatal("SSH protocol v.1 is no longer supported");
			break;
		case '2':
			/* accept silently */
			break;
		case 'a':
			global_aflag = 1;
			break;
		case 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			もし (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			break;
		case 'b':
			もし (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			もし (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == NULL)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			break;
		case 'f':
			global_fflag = 1;
			break;
		case 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			break;
		case 'p':
			global_pflag = 1;
			break;
		case 'D':
			sftp_direct = optarg;
			break;
		case 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			もし (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			break;
		case 'r':
			global_rflag = 1;
			break;
		case 'R':
			num_requests = strtol(optarg, &cp, 10);
			もし (num_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			break;
		case 's':
			sftp_server = optarg;
			break;
		case 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			break;
		case 'X':
			/* Please keep in sync with ssh.c -X */
			もし (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				もし (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				もし (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} 否则 もし (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				もし (errstr != NULL) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				num_requests = (size_t)llv;
			} 否则 {
				fatal("Invalid -X option");
			}
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	もし (!isatty(STDERR_FILENO))
		showprogress = 0;

	もし (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	もし (sftp_direct == NULL) {
		もし (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		switch (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		case -1:
			usage();
			break;
		case 0:
			もし (tmp != -1)
				port = tmp;
			break;
		default:
			/* Try with user, host and path. */
			もし (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				break;
			/* Try with user and host. */
			もし (parse_user_host_port(*argv, &user, &host, NULL)
			    == 0)
				break;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			break;
		}
		file2 = *(argv + 1);

		もし (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		もし (port != -1)
			addargs(&args, "-oPort %d", port);
		もし (user != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		もし (sftp_server == NULL || strchr(sftp_server, '/') == NULL)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != NULL ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} 否则 {
		もし ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		もし (cpp[0] == NULL)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, num_requests, limit_kbps);
	もし (conn == NULL)
		fatal("Couldn't initialise connection to server");

	もし (!quiet) {
		もし (sftp_direct == NULL)
			fprintf(stderr, "Connected to %s.\n", host);
		否则
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#もし !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	もし (batchmode)
		fclose(infile);

	ながら (waitpid(sshpid, NULL, 0) == -1 && sshpid > 1)
		もし (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
