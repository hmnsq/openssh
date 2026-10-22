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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/ioctl.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/statvfs.h>
#شامل <sys/wait.h>

#شامل <ctype.h>
#شامل <errno.h>
#شامل <fcntl.h>
#شامل <glob.h>
#شامل <paths.h>
#شامل <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#شامل <histedit.h>
#وگرنه
تعریفنوع تهی Edit_سطر;
#endif
#شامل <limits.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <util.h>

#شامل "xmalloc.h"
#شامل "log.h"
#شامل "pathnames.h"
#شامل "misc.h"
#شامل "utf8.h"

#شامل "sftp.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "sftp-common.h"
#شامل "sftp-client.h"
#شامل "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
صحیح batchmode = 0;

/* PID of ssh transport process */
ایستا فرار pid_t sshpid = -1;

/* Suppress diagnostic messages */
صحیح quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
صحیح showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
صحیح global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
صحیح global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
صحیح global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
صحیح global_fflag = 0;

/* SIGINT received during command processing */
فرار sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
صحیح sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
ساختار complete_ctx {
	ساختار sftp_conn *conn;
	نویسه **remote_pathp;
};

صحیح sftp_glob(ساختار sftp_conn *, ثابت نویسه *, صحیح,
    صحیح (*)(ثابت نویسه *, صحیح), glob_t *); /* proto for sftp-glob.c */

بیرونی نویسه *__progname;

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
شمارش sftp_command {
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

ساختار CMD {
	ثابت نویسه *c;
	ثابت صحیح n;
	ثابت صحیح t;	/* Completion type for the first argument */
	ثابت صحیح t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

ایستا ثابت ساختار CMD cmds[] = {
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
	{ پوچ,		-1,		-1,		-1	}
};

ایستا تهی
killchild(صحیح signo)
{
	pid_t pid;

	pid = sshpid;
	اگر (pid > 1) {
		kill(pid, SIGTERM);
		(تهی)waitpid(pid, پوچ, 0);
	}

	_exit(1);
}

ایستا تهی
suspchild(صحیح signo)
{
	صحیح save_errno = errno;
	اگر (sshpid > 1) {
		kill(sshpid, signo);
		وقتی (waitpid(sshpid, پوچ, WUNTRACED) == -1 && errno == EINTR)
			ادامه;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ایستا تهی
cmd_interrupt(صحیح signo)
{
	ثابت نویسه پیام[] = "\rInterrupt  \n";
	صحیح olderrno = errno;

	(تهی)اكتب(STDERR_FILENO, پیام, اندازه(پیام) - 1);
	interrupted = 1;
	errno = olderrno;
}

ایستا تهی
read_interrupt(صحیح signo)
{
	interrupted = 1;
}

ایستا تهی
sigchld_handler(صحیح sig)
{
	صحیح save_errno = errno;
	pid_t pid;
	ثابت نویسه پیام[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	وقتی ((pid = waitpid(sshpid, پوچ, WNOHANG)) == -1 && errno == EINTR)
		ادامه;
	اگر (pid == sshpid) {
		اگر (!quiet)
		    (تهی)اكتب(STDERR_FILENO, پیام, اندازه(پیام) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

ایستا تهی
help(تهی)
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

ایستا تهی
local_do_shell(ثابت نویسه *args)
{
	صحیح status;
	نویسه *shell;
	pid_t pid;

	اگر (!*args)
		args = پوچ;

	اگر ((shell = getenv("SHELL")) == پوچ || *shell == '\0')
		shell = _PATH_BSHELL;

	اگر ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	اگر (pid == 0) {
		اگر (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (نویسه *)پوچ);
		} وگرنه {
			debug3("Executing %s", shell);
			execl(shell, shell, (نویسه *)پوچ);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	وقتی (waitpid(pid, &status, 0) == -1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	اگر (!WIFEXITED(status))
		error("Shell exited abnormally");
	وگرنه اگر (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

ایستا تهی
local_do_ls(ثابت نویسه *args)
{
	اگر (!args || !*args)
		local_do_shell(_PATH_LS);
	وگرنه {
		صحیح len = strlen(_PATH_LS " ") + strlen(args) + 1;
		نویسه *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		آزاد(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
ایستا نویسه *
path_strip(ثابت نویسه *path, ثابت نویسه *strip)
{
	size_t len;

	اگر (strip == پوچ || (len = strlen(strip)) == 0)
		بازگشت (xstrdup(path));

	اگر (strncmp(path, strip, len) == 0) {
		اگر (strip[len - 1] != '/' && path[len] == '/')
			len++;
		بازگشت (xstrdup(path + len));
	}

	بازگشت (xstrdup(path));
}

ایستا صحیح
parse_getput_flags(ثابت نویسه *cmd, نویسه **argv, صحیح argc,
    صحیح *aflag, صحیح *fflag, صحیح *pflag, صحیح *rflag)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	وقتی ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		انتخاب (ch) {
		حالت 'a':
			*aflag = 1;
			بشکن;
		حالت 'f':
			*fflag = 1;
			بشکن;
		حالت 'p':
		حالت 'P':
			*pflag = 1;
			بشکن;
		حالت 'r':
		حالت 'R':
			*rflag = 1;
			بشکن;
		پیشفرض:
			error("%s: Invalid flag -%c", cmd, optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا صحیح
parse_mkdir_flags(ثابت نویسه *cmd, نویسه **argv, صحیح argc, صحیح *pflag)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	وقتی ((ch = getopt(argc, argv, "p")) != -1) {
		انتخاب (ch) {
		حالت 'p':
			*pflag = 1;
			بشکن;
		پیشفرض:
			error("%s: Invalid flag -%c", cmd, optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا صحیح
parse_link_flags(ثابت نویسه *cmd, نویسه **argv, صحیح argc, صحیح *sflag)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	وقتی ((ch = getopt(argc, argv, "s")) != -1) {
		انتخاب (ch) {
		حالت 's':
			*sflag = 1;
			بشکن;
		پیشفرض:
			error("%s: Invalid flag -%c", cmd, optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا صحیح
parse_rename_flags(ثابت نویسه *cmd, نویسه **argv, صحیح argc, صحیح *lflag)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	وقتی ((ch = getopt(argc, argv, "l")) != -1) {
		انتخاب (ch) {
		حالت 'l':
			*lflag = 1;
			بشکن;
		پیشفرض:
			error("%s: Invalid flag -%c", cmd, optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا صحیح
parse_ls_flags(نویسه **argv, صحیح argc, صحیح *lflag)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	وقتی ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		انتخاب (ch) {
		حالت '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			بشکن;
		حالت 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			بشکن;
		حالت 'a':
			*lflag |= LS_SHOW_ALL;
			بشکن;
		حالت 'f':
			*lflag &= ~SORT_FLAGS;
			بشکن;
		حالت 'h':
			*lflag |= LS_SI_UNITS;
			بشکن;
		حالت 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			بشکن;
		حالت 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			بشکن;
		حالت 'r':
			*lflag |= LS_REVERSE_SORT;
			بشکن;
		حالت 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			بشکن;
		پیشفرض:
			error("ls: Invalid flag -%c", optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا صحیح
parse_df_flags(ثابت نویسه *cmd, نویسه **argv, صحیح argc, صحیح *hflag, صحیح *iflag)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	وقتی ((ch = getopt(argc, argv, "hi")) != -1) {
		انتخاب (ch) {
		حالت 'h':
			*hflag = 1;
			بشکن;
		حالت 'i':
			*iflag = 1;
			بشکن;
		پیشفرض:
			error("%s: Invalid flag -%c", cmd, optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا صحیح
parse_ch_flags(ثابت نویسه *cmd, نویسه **argv, صحیح argc, صحیح *hflag)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	وقتی ((ch = getopt(argc, argv, "h")) != -1) {
		انتخاب (ch) {
		حالت 'h':
			*hflag = 1;
			بشکن;
		پیشفرض:
			error("%s: Invalid flag -%c", cmd, optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا صحیح
parse_no_flags(ثابت نویسه *cmd, نویسه **argv, صحیح argc)
{
	بیرونی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	وقتی ((ch = getopt(argc, argv, "")) != -1) {
		انتخاب (ch) {
		پیشفرض:
			error("%s: Invalid flag -%c", cmd, optopt);
			بازگشت -1;
		}
	}

	بازگشت optind;
}

ایستا نویسه *
escape_glob(ثابت نویسه *s)
{
	size_t i, o, len;
	نویسه *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	برای (i = o = 0; i < len; i++) {
		اگر (strchr("[]?*\\", s[i]) != پوچ)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	بازگشت ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
ایستا نویسه *
make_absolute_pwd_glob(نویسه *p, ثابت نویسه *pwd)
{
	نویسه *ret, *escpwd;

	escpwd = escape_glob(pwd);
	اگر (p == پوچ)
		بازگشت escpwd;
	ret = sftp_make_absolute(p, escpwd);
	آزاد(escpwd);
	بازگشت ret;
}

ایستا صحیح
local_is_dir(ثابت نویسه *path)
{
	ساختار stat sb;

	اگر (stat(path, &sb) == -1)
		بازگشت 0;
	بازگشت S_ISDIR(sb.st_mode);
}

ایستا صحیح
process_get(ساختار sftp_conn *conn, ثابت نویسه *src, ثابت نویسه *dst,
    ثابت نویسه *pwd, صحیح pflag, صحیح rflag, صحیح resume, صحیح fflag)
{
	نویسه *filename, *abs_src = پوچ, *abs_dst = پوچ, *tmp = پوچ;
	glob_t g;
	صحیح i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, اندازه(g));

	debug3("Looking up %s", abs_src);
	اگر ((r = sftp_glob(conn, abs_src, GLOB_MARK, پوچ, &g)) != 0) {
		اگر (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} وگرنه {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		برو out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	اگر (g.gl_matchc > 1 && dst != پوچ && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		برو out;
	}

	برای (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == پوچ) {
			error("basename %s: %s", tmp, strerror(errno));
			آزاد(tmp);
			err = -1;
			برو out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		اگر (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		اگر (g.gl_matchc == 1 && dst) {
			اگر (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} وگرنه {
				abs_dst = xstrdup(dst);
			}
		} وگرنه اگر (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} وگرنه {
			abs_dst = xstrdup(filename);
		}
		آزاد(tmp);

		resume |= global_aflag;
		اگر (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		وگرنه اگر (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			اگر (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    پوچ, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} وگرنه {
			اگر (sftp_download(conn, g.gl_pathv[i], abs_dst, پوچ,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		آزاد(abs_dst);
		abs_dst = پوچ;
	}

out:
	آزاد(abs_src);
	globfree(&g);
	بازگشت(err);
}

ایستا صحیح
process_put(ساختار sftp_conn *conn, ثابت نویسه *src, ثابت نویسه *dst,
    ثابت نویسه *pwd, صحیح pflag, صحیح rflag, صحیح resume, صحیح fflag)
{
	نویسه *tmp_dst = پوچ;
	نویسه *abs_dst = پوچ;
	نویسه *tmp = پوچ, *filename = پوچ;
	glob_t g;
	صحیح err = 0;
	صحیح i, dst_is_dir = 1;
	ساختار stat sb;

	اگر (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, اندازه(g));
	debug3("Looking up %s", src);
	اگر (glob(src, GLOB_NOCHECK | GLOB_MARK, پوچ, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		برو out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	اگر (tmp_dst != پوچ)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	اگر (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		برو out;
	}

	برای (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		اگر (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			ادامه;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == پوچ) {
			error("basename %s: %s", tmp, strerror(errno));
			آزاد(tmp);
			err = -1;
			برو out;
		}
		/* Special handling for source of '..' */
		اگر (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		آزاد(abs_dst);
		abs_dst = پوچ;
		اگر (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			اگر (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			وگرنه
				abs_dst = xstrdup(tmp_dst);
		} وگرنه اگر (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} وگرنه {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		آزاد(tmp);

		resume |= global_aflag;
		اگر (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		وگرنه اگر (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			اگر (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} وگرنه {
			اگر (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	آزاد(abs_dst);
	آزاد(tmp_dst);
	globfree(&g);
	بازگشت(err);
}

ایستا صحیح
sdirent_comp(ثابت تهی *aa, ثابت تهی *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	صحیح rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	اگر (sort_flag & LS_NAME_SORT)
		بازگشت (rmul * strcmp(a->filename, b->filename));
	وگرنه اگر (sort_flag & LS_TIME_SORT)
		بازگشت (rmul * NCMP(a->a.mtime, b->a.mtime));
	وگرنه اگر (sort_flag & LS_SIZE_SORT)
		بازگشت (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
ایستا صحیح
do_ls_dir(ساختار sftp_conn *conn, ثابت نویسه *path,
    ثابت نویسه *strip_path, صحیح lflag)
{
	صحیح n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	اگر ((n = sftp_readdir(conn, path, &d)) != 0)
		بازگشت (n);

	اگر (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		ساختار winsize ws;
		نویسه *tmp;

		/* Count entries for sort and find longest filename */
		برای (n = 0; d[n] != پوچ; n++) {
			اگر (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		آزاد(tmp);

		اگر (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	اگر (lflag & SORT_FLAGS) {
		برای (n = 0; d[n] != پوچ; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, اندازه(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	برای (n = 0; d[n] != پوچ && !interrupted; n++) {
		نویسه *tmp, *fname;

		اگر (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			ادامه;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		آزاد(tmp);

		اگر (lflag & LS_LONG_VIEW) {
			اگر ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				نویسه *lname;
				ساختار stat sb;
				ثابت نویسه *user = پوچ, *group = پوچ;

				memset(&sb, 0, اندازه(sb));
				attrib_to_stat(&d[n]->a, &sb);
				اگر ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				آزاد(lname);
			} وگرنه
				mprintf("%s\n", d[n]->longname);
		} وگرنه {
			mprintf("%-*s", colspace, fname);
			اگر (c >= columns) {
				printf("\n");
				c = 1;
			} وگرنه
				c++;
		}

		آزاد(fname);
	}

	اگر (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	بازگشت (0);
}

ایستا صحیح
sglob_comp(ثابت تهی *aa, ثابت تهی *bb)
{
	u_int a = *(ثابت u_int *)aa;
	u_int b = *(ثابت u_int *)bb;
	ثابت نویسه *ap = sort_glob->gl_pathv[a];
	ثابت نویسه *bp = sort_glob->gl_pathv[b];
	ثابت ساختار stat *as = sort_glob->gl_statv[a];
	ثابت ساختار stat *bs = sort_glob->gl_statv[b];
	صحیح rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	اگر (as == پوچ || bs == پوچ)
		بازگشت (as == bs) ? 0 : (as == پوچ ? rmul : -rmul);
	اگر (sort_flag & LS_NAME_SORT)
		بازگشت (rmul * strcmp(ap, bp));
	وگرنه اگر (sort_flag & LS_TIME_SORT) {
#اگر defined(HAVE_STRUCT_STAT_ST_MTIM)
		اگر (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			بازگشت 0;
		بازگشت timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#وگرنهاگر defined(HAVE_STRUCT_STAT_ST_MTIME)
		بازگشت (rmul * NCMP(as->st_mtime, bs->st_mtime));
#وگرنه
	بازگشت rmul * 1;
#endif
	} وگرنه اگر (sort_flag & LS_SIZE_SORT)
		بازگشت (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
ایستا صحیح
do_globbed_ls(ساختار sftp_conn *conn, ثابت نویسه *path,
    ثابت نویسه *strip_path, صحیح lflag)
{
	نویسه *fname, *lname;
	glob_t g;
	صحیح err, r;
	ساختار winsize ws;
	u_int i, j, nentries, *indices = پوچ, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, اندازه(g));

	اگر ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    پوچ, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		اگر (g.gl_pathc)
			globfree(&g);
		اگر (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} وگرنه {
			error("Can't ls: \"%s\" not found", path);
		}
		بازگشت -1;
	}

	اگر (interrupted)
		برو out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	اگر (g.gl_matchc == 1 && g.gl_statv[0] != پوچ &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		بازگشت err;
	}

	اگر (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	اگر (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		برای (i = 0; g.gl_pathv[i]; i++)
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
	برای (nentries = 0; g.gl_pathv[nentries] != پوچ; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, اندازه(*indices));
	برای (i = 0; i < nentries; i++)
		indices[i] = i;

	اگر (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, اندازه(*indices), sglob_comp);
		sort_glob = پوچ;
	}

	get_remote_user_groups_from_glob(conn, &g);
	برای (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		اگر (lflag & LS_LONG_VIEW) {
			ثابت نویسه *user = پوچ, *group = پوچ;

			اگر (g.gl_statv[i] == پوچ) {
				error("no stat information for %s", fname);
				آزاد(fname);
				ادامه;
			}
			اگر ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			آزاد(lname);
		} وگرنه {
			mprintf("%-*s", colspace, fname);
			اگر (c >= columns) {
				printf("\n");
				c = 1;
			} وگرنه
				c++;
		}
		آزاد(fname);
	}

	اگر (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	اگر (g.gl_pathc)
		globfree(&g);
	آزاد(indices);

	بازگشت 0;
}

ایستا صحیح
do_df(ساختار sftp_conn *conn, ثابت نویسه *path, صحیح hflag, صحیح iflag)
{
	ساختار sftp_statvfs st;
	نویسه s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	نویسه s_ریشه[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	نویسه s_icapacity[16], s_dcapacity[16];

	اگر (sftp_statvfs(conn, path, &st, 1) == -1)
		بازگشت -1;
	اگر (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", اندازه(s_icapacity));
	وگرنه {
		snprintf(s_icapacity, اندازه(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	اگر (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", اندازه(s_dcapacity));
	وگرنه {
		snprintf(s_dcapacity, اندازه(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	اگر (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} وگرنه اگر (hflag) {
		strlcpy(s_used, "error", اندازه(s_used));
		strlcpy(s_avail, "error", اندازه(s_avail));
		strlcpy(s_ریشه, "error", اندازه(s_ریشه));
		strlcpy(s_total, "error", اندازه(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_ریشه);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_ریشه, s_dcapacity);
	} وگرنه {
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
	بازگشت 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
ایستا تهی
undo_glob_escape(نویسه *s)
{
	size_t i, j;

	برای (i = j = 0;;) {
		اگر (s[i] == '\0') {
			s[j] = '\0';
			بازگشت;
		}
		اگر (s[i] != '\\') {
			s[j++] = s[i++];
			ادامه;
		}
		/* s[i] == '\\' */
		++i;
		انتخاب (s[i]) {
		حالت '?':
		حالت '[':
		حالت '*':
		حالت '\\':
			s[j++] = s[i++];
			بشکن;
		حالت '\0':
			s[j++] = '\\';
			s[j] = '\0';
			بازگشت;
		پیشفرض:
			s[j++] = '\\';
			s[j++] = s[i++];
			بشکن;
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
ایستا نویسه **
makeargv(ثابت نویسه *arg, صحیح *argcp, صحیح sloppy, نویسه *lastquote,
    u_int *terminated)
{
	صحیح argc, quot;
	size_t i, j;
	ایستا نویسه argvs[MAXARGLEN];
	ایستا نویسه *argv[MAXARGS + 1];
	شمارش { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	اگر (strlen(arg) > اندازه(argvs) - 1) {
 args_too_longs:
		error("string too long");
		بازگشت پوچ;
	}
	اگر (terminated != پوچ)
		*terminated = 1;
	اگر (lastquote != پوچ)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	برای (;;) {
		اگر ((size_t)argc >= اندازه(argv) / اندازه(*argv)){
			error("Too many arguments.");
			بازگشت پوچ;
		}
		اگر (isspace((unsigned نویسه)arg[i])) {
			اگر (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} وگرنه اگر (state != MA_START)
				argvs[j++] = arg[i];
		} وگرنه اگر (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			اگر (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				اگر (lastquote != پوچ)
					*lastquote = arg[i];
			} وگرنه اگر (state == MA_UNQUOTED)
				state = q;
			وگرنه اگر (state == q)
				state = MA_UNQUOTED;
			وگرنه
				argvs[j++] = arg[i];
		} وگرنه اگر (arg[i] == '\\') {
			اگر (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				اگر (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} وگرنه اگر (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					اگر (j >= اندازه(argvs) - 5)
						برو args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} وگرنه {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} وگرنه {
				اگر (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					اگر (lastquote != پوچ)
						*lastquote = '\0';
				}
				اگر (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} وگرنه {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					اگر (arg[i] == '\0')
						برو early_nul;
					argvs[j++] = arg[i];
				}
			}
		} وگرنه اگر (arg[i] == '#') {
			اگر (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			وگرنه
				برو string_done;
		} وگرنه اگر (arg[i] == '\0') {
			اگر (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				اگر (sloppy) {
					state = MA_UNQUOTED;
					اگر (terminated != پوچ)
						*terminated = 0;
					برو string_done;
				}
				error("Unterminated quoted argument");
				بازگشت پوچ;
			}
 string_done:
			اگر (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			بشکن;
		} وگرنه {
			اگر (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				اگر (lastquote != پوچ)
					*lastquote = '\0';
			}
			اگر ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				اگر (j >= اندازه(argvs) - 3)
					برو args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} وگرنه
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	بازگشت argv;
}

ایستا صحیح
parse_args(ثابت نویسه **cpp, صحیح *ignore_errors, صحیح *disable_echo, صحیح *aflag,
	  صحیح *fflag, صحیح *hflag, صحیح *iflag, صحیح *lflag, صحیح *pflag,
	  صحیح *rflag, صحیح *sflag,
    unsigned long *n_arg, نویسه **path1, نویسه **path2)
{
	ثابت نویسه *cmd, *cp = *cpp;
	نویسه *cp2, **argv;
	صحیح base = 0;
	long long ll;
	صحیح path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	برای (;*cp != '\0'; cp++) {
		اگر (*cp == '-') {
			*ignore_errors = 1;
		} وگرنه اگر (*cp == '@') {
			*disable_echo = 1;
		} وگرنه {
			/* all other characters terminate prefix processing */
			بشکن;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	اگر (*cp == '\0' || *cp == '#')
		بازگشت (0);

	اگر ((argv = makeargv(cp, &argc, 0, پوچ, پوچ)) == پوچ)
		بازگشت -1;

	/* Figure out which command we have */
	برای (i = 0; cmds[i].c != پوچ; i++) {
		اگر (argv[0] != پوچ && strcasecmp(cmds[i].c, argv[0]) == 0)
			بشکن;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	اگر (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} وگرنه اگر (cmdnum == -1) {
		error("Invalid command.");
		بازگشت -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = پوچ;
	optidx = 1;
	انتخاب (cmdnum) {
	حالت I_GET:
	حالت I_REGET:
	حالت I_REPUT:
	حالت I_PUT:
		اگر ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			بازگشت -1;
		/* Get first pathname (mandatory) */
		اگر (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			بازگشت -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		اگر (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		بشکن;
	حالت I_LINK:
		اگر ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			بازگشت -1;
		برو parse_two_paths;
	حالت I_COPY:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			بازگشت -1;
		برو parse_two_paths;
	حالت I_RENAME:
		اگر ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			بازگشت -1;
		برو parse_two_paths;
	حالت I_SYMLINK:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			بازگشت -1;
 parse_two_paths:
		اگر (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			بازگشت -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		بشکن;
	حالت I_MKDIR:
	حالت I_LMKDIR:
		اگر ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			بازگشت -1;
		path1_mandatory = 1;
		برو parse_one_path;
	حالت I_RM:
	حالت I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	حالت I_CHDIR:
	حالت I_LCHDIR:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			بازگشت -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		اگر (argc - optidx < 1) {
			اگر (!path1_mandatory)
				بشکن; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			بازگشت -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		اگر (cmdnum != I_RM)
			undo_glob_escape(*path1);
		بشکن;
	حالت I_DF:
		اگر ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			بازگشت -1;
		/* Default to current directory if no path specified */
		اگر (argc - optidx < 1)
			*path1 = پوچ;
		وگرنه {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		بشکن;
	حالت I_LS:
		اگر ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			بازگشت(-1);
		/* Path is optional */
		اگر (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		بشکن;
	حالت I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	حالت I_SHELL:
		/* Uses the rest of the line */
		بشکن;
	حالت I_LUMASK:
	حالت I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	حالت I_CHOWN:
	حالت I_CHGRP:
		اگر ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			بازگشت -1;
		/* Get numeric arg (mandatory) */
		اگر (argc - optidx < 1)
			برو need_رقم_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		اگر (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_رقم_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			بازگشت -1;
		}
		*n_arg = ll;
		اگر (cmdnum == I_LUMASK)
			بشکن;
		/* Get pathname (mandatory) */
		اگر (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			بازگشت -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		بشکن;
	حالت I_QUIT:
	حالت I_PWD:
	حالت I_LPWD:
	حالت I_HELP:
	حالت I_VERSION:
	حالت I_PROGRESS:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			بازگشت -1;
		بشکن;
	پیشفرض:
		fatal("Command not implemented");
	}

	*cpp = cp;
	بازگشت(cmdnum);
}

ایستا صحیح
parse_dispatch_command(ساختار sftp_conn *conn, ثابت نویسه *cmd, نویسه **pwd,
    ثابت نویسه *startdir, صحیح err_abort, صحیح echo_command)
{
	ثابت نویسه *ocmd = cmd;
	نویسه *path1, *path2, *tmp;
	صحیح ignore_errors = 0, disable_echo = 1;
	صحیح aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	صحیح lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	صحیح cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	نویسه path_buf[PATH_MAX];
	صحیح err = 0;
	glob_t g;

	path1 = path2 = پوچ;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	اگر (ignore_errors != 0)
		err_abort = 0;

	اگر (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, اندازه(g));

	/* Perform command */
	انتخاب (cmdnum) {
	حالت 0:
		/* Blank line */
		بشکن;
	حالت -1:
		/* Unrecognized command */
		err = -1;
		بشکن;
	حالت I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	حالت I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		بشکن;
	حالت I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	حالت I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		بشکن;
	حالت I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		بشکن;
	حالت I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		بشکن;
	حالت I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	حالت I_LINK:
		اگر (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		بشکن;
	حالت I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, پوچ, &g);
		برای (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			اگر (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			اگر (err != 0 && err_abort)
				بشکن;
		}
		بشکن;
	حالت I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		اگر (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		وگرنه
			err = sftp_mkdir(conn, path1, &a, 1);
		بشکن;
	حالت I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		بشکن;
	حالت I_CHDIR:
		اگر (path1 == پوچ || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		اگر ((tmp = sftp_realpath(conn, path1)) == پوچ) {
			err = 1;
			بشکن;
		}
		اگر (sftp_stat(conn, tmp, 0, &aa) != 0) {
			آزاد(tmp);
			err = 1;
			بشکن;
		}
		اگر (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			آزاد(tmp);
			err = 1;
			بشکن;
		}
		اگر (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			آزاد(tmp);
			err = 1;
			بشکن;
		}
		آزاد(*pwd);
		*pwd = tmp;
		بشکن;
	حالت I_LS:
		اگر (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			بشکن;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = پوچ;
		اگر (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		بشکن;
	حالت I_DF:
		/* Default to current directory if no path specified */
		اگر (path1 == پوچ)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		بشکن;
	حالت I_LCHDIR:
		اگر (path1 == پوچ || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		آزاد(path1);
		path1 = tmp;
		اگر (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		بشکن;
	حالت I_LMKDIR:
		اگر (pflag) {
			اگر (mkdir_path(path1, 0777) != 0)
				err = 1;
			بشکن;
		}
		اگر (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		بشکن;
	حالت I_LLS:
		local_do_ls(cmd);
		بشکن;
	حالت I_SHELL:
		local_do_shell(cmd);
		بشکن;
	حالت I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		بشکن;
	حالت I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, پوچ, &g);
		برای (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			اگر (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			اگر (err != 0 && err_abort)
				بشکن;
		}
		بشکن;
	حالت I_CHOWN:
	حالت I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, پوچ, &g);
		برای (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			اگر ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				اگر (err_abort) {
					err = -1;
					بشکن;
				} وگرنه
					ادامه;
			}
			اگر (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				اگر (err_abort) {
					err = -1;
					بشکن;
				} وگرنه
					ادامه;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			اگر (cmdnum == I_CHOWN) {
				اگر (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} وگرنه {
				اگر (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			اگر (err != 0 && err_abort)
				بشکن;
		}
		بشکن;
	حالت I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		بشکن;
	حالت I_LPWD:
		اگر (!getcwd(path_buf, اندازه(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			بشکن;
		}
		mprintf("Local working directory: %s\n", path_buf);
		بشکن;
	حالت I_QUIT:
		/* Processed below */
		بشکن;
	حالت I_HELP:
		help();
		بشکن;
	حالت I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		بشکن;
	حالت I_PROGRESS:
		showprogress = !showprogress;
		اگر (showprogress)
			printf("Progress meter enabled\n");
		وگرنه
			printf("Progress meter disabled\n");
		بشکن;
	پیشفرض:
		fatal("%d is not implemented", cmdnum);
	}

	اگر (g.gl_pathc)
		globfree(&g);
	آزاد(path1);
	آزاد(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	اگر (err_abort && err != 0)
		بازگشت (-1);
	وگرنه اگر (cmdnum == I_QUIT)
		بازگشت (1);

	بازگشت (0);
}

#ifdef USE_LIBEDIT
ایستا نویسه *
prompt(Edit_سطر *el)
{
	بازگشت ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
ایستا تهی
complete_display(نویسه **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	ساختار winsize ws;
	نویسه *tmp;

	/* Count entries for sort and find longest */
	برای (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	اگر (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	برای (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		اگر (m >= columns) {
			printf("\n");
			m = 1;
		} وگرنه
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
ایستا نویسه *
complete_ambiguous(ثابت نویسه *word, نویسه **list, size_t شمار)
{
	size_t i, j, matchlen;
	نویسه *tmp;
	صحیح len;

	اگر (word == پوچ)
		بازگشت پوچ;

	اگر (شمار == 0)
		بازگشت xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	برای (i = 1; i < شمار && list[i] != پوچ; i++) {
		برای (j = 0; j < matchlen; j++)
			اگر (list[0][j] != list[i][j])
				بشکن;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(پوچ, 0);
	برای (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		اگر (len <= 0 || i + (size_t)len > matchlen)
			بشکن;
		i += (size_t)len;
	}
	/* If so, truncate */
	اگر (i < matchlen)
		matchlen = i;

	اگر (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		بازگشت tmp;
	}

	بازگشت xstrdup(word);
}

/* Autocomplete a sftp command */
ایستا صحیح
complete_cmd_parse(Edit_سطر *el, نویسه *cmd, صحیح lastarg, نویسه quote,
    صحیح terminated)
{
	u_int y, شمار = 0, cmdlen, tmplen;
	نویسه *tmp, **list, argterm[3];
	ثابت سطر_Info *lf;

	list = xcalloc((اندازه(cmds) / اندازه(*cmds)) + 1, اندازه(نویسه *));

	/* No command specified: display all available commands */
	اگر (cmd == پوچ) {
		برای (y = 0; cmds[y].c; y++)
			list[شمار++] = xstrdup(cmds[y].c);

		list[شمار] = پوچ;
		complete_display(list, 0);

		برای (y = 0; list[y] != پوچ; y++)
			آزاد(list[y]);
		آزاد(list);
		بازگشت شمار;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	برای (y = 0; cmds[y].c; y++)  {
		اگر (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[شمار++] = xstrdup(cmds[y].c);
	}
	list[شمار] = پوچ;

	اگر (شمار == 0) {
		آزاد(list);
		بازگشت 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, شمار);
	اگر (شمار > 1)
		complete_display(list, 0);

	برای (y = 0; list[y]; y++)
		آزاد(list[y]);
	آزاد(list);

	اگر (tmp != پوچ) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		اگر (tmplen > cmdlen)
			اگر (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_سطر(el);
		/* Terminate argument cleanly */
		اگر (شمار == 1) {
			y = 0;
			اگر (!terminated)
				argterm[y++] = quote;
			اگر (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			اگر (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		آزاد(tmp);
	}

	بازگشت شمار;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
ایستا صحیح
complete_is_remote(نویسه *cmd, صحیح cmdarg) {
	صحیح i;

	اگر (cmd == پوچ)
		بازگشت -1;

	برای (i = 0; cmds[i].c; i++) {
		اگر (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			اگر (cmdarg == 1)
				بازگشت cmds[i].t;
			وگرنه اگر (cmdarg == 2)
				بازگشت cmds[i].t2;
			بشکن;
		}
	}

	بازگشت -1;
}

/* Autocomplete a filename "file" */
ایستا صحیح
complete_match(Edit_سطر *el, ساختار sftp_conn *conn, نویسه *remote_path,
    نویسه *file, صحیح remote, صحیح lastarg, نویسه quote, صحیح terminated)
{
	glob_t g;
	نویسه *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	صحیح clen;
	ثابت سطر_Info *lf;

	/* Glob from "file" location */
	اگر (file == پوچ)
		tmp = xstrdup("*");
	وگرنه
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, اندازه(g));
	اگر (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, پوچ, &g);
	} وگرنه
		(تهی)glob(tmp, GLOB_DOOFFS|GLOB_MARK, پوچ, &g);

	/* Determine length of pwd so we can trim completion display */
	برای (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		اگر (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			اگر (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			بشکن;
		}
		اگر (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		اگر (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	آزاد(tmp);
	tmp = پوچ;

	اگر (g.gl_matchc == 0)
		برو out;

	اگر (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	اگر (file == پوچ || hadglob)
		برو out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? پوچ : remote_path);
	آزاد(tmp2);

	اگر (tmp == پوچ)
		برو out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	برای (i = 0; i < filelen; i++) {
		اگر (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} وگرنه
			isesc = 0;
	}

	اگر (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(پوچ, 0);
		برای (i = 0; i < len; i += clen) {
			اگر ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > اندازه(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			انتخاب (tmp2[i]) {
			حالت '\'':
			حالت '"':
			حالت '\\':
			حالت '\t':
			حالت '[':
			حالت ' ':
			حالت '#':
			حالت '*':
				اگر (quote == '\0' || tmp2[i] == quote) {
					اگر (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					بشکن;
				}
				/* FALLTHROUGH */
			پیشفرض:
				اگر (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				بشکن;
			}
		}
	}

	lf = el_سطر(el);
	اگر (g.gl_matchc == 1) {
		i = 0;
		اگر (!terminated && quote != '\0')
			ins[i++] = quote;
		اگر (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		اگر (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	آزاد(tmp);

 out:
	globfree(&g);
	بازگشت g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
ایستا unsigned نویسه
complete(Edit_سطر *el, صحیح ch)
{
	نویسه **argv, *سطر, quote;
	صحیح argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ثابت سطر_Info *lf;
	ساختار complete_ctx *complete_ctx;

	lf = el_سطر(el);
	اگر (el_get(el, EL_CLIENTDATA, (تهی**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	سطر = xmalloc(cursor + 1);
	memcpy(سطر, lf->buffer, cursor);
	سطر[cursor] = '\0';
	argv = makeargv(سطر, &carg, 1, &quote, &terminated);
	آزاد(سطر);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	سطر = xmalloc(len + 1);
	memcpy(سطر, lf->buffer, len);
	سطر[len] = '\0';
	argv = makeargv(سطر, &argc, 1, پوچ, پوچ);

	/* Ensure cursor is at EOL or a argument boundary */
	اگر (سطر[cursor] != ' ' && سطر[cursor] != '\0' &&
	    سطر[cursor] != '\n') {
		آزاد(سطر);
		بازگشت ret;
	}

	اگر (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, پوچ, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} وگرنه اگر (carg == 1 && cursor > 0 && سطر[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		اگر (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} وگرنه اگر (carg >= 1) {
		/* Handle file parsing */
		صحیح remote = 0;
		صحیح i = 0, cmdarg = 0;
		نویسه *filematch = پوچ;

		اگر (carg > 1 && سطر[cursor-1] != ' ')
			filematch = argv[carg - 1];

		برای (i = 1; i < carg; i++) {
			/* Skip flags */
			اگر (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		اگر (سطر[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		اگر ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	آزاد(سطر);
	بازگشت ret;
}
#endif /* USE_LIBEDIT */

ایستا صحیح
interactive_loop(ساختار sftp_conn *conn, نویسه *file1, نویسه *file2)
{
	نویسه *remote_path;
	نویسه *dir = پوچ, *startdir = پوچ;
	نویسه cmd[2048];
	صحیح err, interactive;
	Edit_سطر *el = پوچ;
#ifdef USE_LIBEDIT
	ثابت نویسه *editor;
	History *hl = پوچ;
	HistEvent hev;
	بیرونی نویسه *__progname;
	ساختار complete_ctx complete_ctx;

	اگر (!batchmode && isatty(STDIN_FILENO)) {
		اگر ((el = el_init(__progname, stdin, stdout, stderr)) == پوچ)
			fatal("Couldn't initialise editline");
		اگر ((hl = history_init()) == پوچ)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, پوچ);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, پوچ);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (تهی*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", پوچ);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", پوچ);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", پوچ);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", پوچ);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", پوچ);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", پوچ);

		/* el_source() may have changed EL_EDITOR to vi */
		اگر (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", پوچ);
	}
#endif /* USE_LIBEDIT */

	اگر ((remote_path = sftp_realpath(conn, ".")) == پوچ)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	اگر (file1 != پوچ) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		اگر (sftp_remote_is_dir(conn, dir) && file2 == پوچ) {
			اگر (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, اندازه cmd, "cd \"%s\"", dir);
			اگر (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				آزاد(dir);
				آزاد(startdir);
				آزاد(remote_path);
				آزاد(conn);
				بازگشت (-1);
			}
		} وگرنه {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			آزاد(dir);
			آزاد(startdir);
			آزاد(remote_path);
			آزاد(conn);
			بازگشت (err);
		}
		آزاد(dir);
	}

	setvbuf(stdout, پوچ, _IOLBF, 0);
	setvbuf(infile, پوچ, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	برای (;;) {
		ساختار sigaction sa;

		interrupted = 0;
		memset(&sa, 0, اندازه(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		اگر (sigaction(SIGINT, &sa, پوچ) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			بشکن;
		}
		اگر (el == پوچ) {
			اگر (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			اگر (fgets(cmd, اندازه(cmd), infile) == پوچ) {
				اگر (interactive)
					printf("\n");
				اگر (interrupted)
					ادامه;
				بشکن;
			}
		} وگرنه {
#ifdef USE_LIBEDIT
			ثابت نویسه *سطر;
			صحیح شمار = 0;

			اگر ((سطر = el_gets(el, &شمار)) == پوچ ||
			    شمار <= 0) {
				printf("\n");
				اگر (interrupted)
					ادامه;
				بشکن;
			}
			history(hl, &hev, H_ENTER, سطر);
			اگر (strlcpy(cmd, سطر, اندازه(cmd)) >= اندازه(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				ادامه;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == پوچ);
		اگر (err != 0)
			بشکن;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	آزاد(remote_path);
	آزاد(startdir);
	آزاد(conn);

#ifdef USE_LIBEDIT
	اگر (hl != پوچ)
		history_end(hl);
	اگر (el != پوچ)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	بازگشت (err >= 0 ? 0 : -1);
}

ایستا تهی
connect_to_server(نویسه *path, نویسه **args, صحیح *in, صحیح *out)
{
	صحیح c_in, c_out;
#ifdef USE_PIPES
	صحیح pin[2], pout[2];

	اگر ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#وگرنه /* USE_PIPES */
	صحیح inout[2];

	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	اگر ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	وگرنه اگر (sshpid == 0) {
		اگر ((dup2(c_in, STDIN_FILENO) == -1) ||
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

ایستا تهی
usage(تهی)
{
	بیرونی نویسه *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

صحیح
اصلی(صحیح argc, نویسه **argv)
{
	صحیح r, in, out, ch, err, tmp, port = -1, noisy = 0;
	نویسه *host = پوچ, *user, *cp, **cpp, *file2 = پوچ;
	صحیح debug_level = 0;
	نویسه *file1 = پوچ, *sftp_server = پوچ;
	نویسه *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = پوچ;
	ثابت نویسه *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	بیرونی صحیح optind;
	بیرونی نویسه *optarg;
	ساختار sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t رقم_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', اندازه(args));
	args.list = پوچ;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	وقتی ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		انتخاب (ch) {
		/* Passed through to ssh(1) */
		حالت 'A':
		حالت '4':
		حالت '6':
		حالت 'C':
			addargs(&args, "-%c", ch);
			بشکن;
		/* Passed through to ssh(1) with argument */
		حالت 'F':
		حالت 'J':
		حالت 'c':
		حالت 'i':
		حالت 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			بشکن;
		حالت 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			بشکن;
		حالت 'P':
			port = a2port(optarg);
			اگر (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			بشکن;
		حالت 'v':
			اگر (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			بشکن;
		حالت '1':
			fatal("SSH protocol v.1 is no longer supported");
			بشکن;
		حالت '2':
			/* accept silently */
			بشکن;
		حالت 'a':
			global_aflag = 1;
			بشکن;
		حالت 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			اگر (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			بشکن;
		حالت 'b':
			اگر (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			اگر (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == پوچ)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			بشکن;
		حالت 'f':
			global_fflag = 1;
			بشکن;
		حالت 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			بشکن;
		حالت 'p':
			global_pflag = 1;
			بشکن;
		حالت 'D':
			sftp_direct = optarg;
			بشکن;
		حالت 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			اگر (errstr != پوچ)
				usage();
			limit_kbps *= 1024; /* kbps */
			بشکن;
		حالت 'r':
			global_rflag = 1;
			بشکن;
		حالت 'R':
			رقم_requests = strtol(optarg, &cp, 10);
			اگر (رقم_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			بشکن;
		حالت 's':
			sftp_server = optarg;
			بشکن;
		حالت 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			بشکن;
		حالت 'X':
			/* Please keep in sync with ssh.c -X */
			اگر (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				اگر (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				اگر (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} وگرنه اگر (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				اگر (errstr != پوچ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				رقم_requests = (size_t)llv;
			} وگرنه {
				fatal("Invalid -X option");
			}
			بشکن;
		حالت 'h':
		پیشفرض:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	اگر (!isatty(STDERR_FILENO))
		showprogress = 0;

	اگر (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	اگر (sftp_direct == پوچ) {
		اگر (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		انتخاب (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		حالت -1:
			usage();
			بشکن;
		حالت 0:
			اگر (tmp != -1)
				port = tmp;
			بشکن;
		پیشفرض:
			/* Try with user, host and path. */
			اگر (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				بشکن;
			/* Try with user and host. */
			اگر (parse_user_host_port(*argv, &user, &host, پوچ)
			    == 0)
				بشکن;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			بشکن;
		}
		file2 = *(argv + 1);

		اگر (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		اگر (port != -1)
			addargs(&args, "-oPort %d", port);
		اگر (user != پوچ) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		اگر (sftp_server == پوچ || strchr(sftp_server, '/') == پوچ)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != پوچ ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} وگرنه {
		اگر ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		اگر (cpp[0] == پوچ)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, رقم_requests, limit_kbps);
	اگر (conn == پوچ)
		fatal("Couldn't initialise connection to server");

	اگر (!quiet) {
		اگر (sftp_direct == پوچ)
			fprintf(stderr, "Connected to %s.\n", host);
		وگرنه
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#اگر !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	اگر (batchmode)
		fclose(infile);

	وقتی (waitpid(sshpid, پوچ, 0) == -1 && sshpid > 1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
