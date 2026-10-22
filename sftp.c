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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/ioctl.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/statvfs.h>
#ضمن <sys/wait.h>

#ضمن <ctype.h>
#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <glob.h>
#ضمن <paths.h>
#ضمن <libgen.h>
#که_تعریف_شوی HAVE_LOCALE_H
# include <locale.h>
#د_که_پای
#که_تعریف_شوی USE_LIBEDIT
#ضمن <histedit.h>
#وإلا
تعريفنوع فراغ Edit_کرښه;
#د_که_پای
#ضمن <limits.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <util.h>

#ضمن "xmalloc.h"
#ضمن "log.h"
#ضمن "pathnames.h"
#ضمن "misc.h"
#ضمن "utf8.h"

#ضمن "sftp.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "sftp-common.h"
#ضمن "sftp-client.h"
#ضمن "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
صحيح batchmode = 0;

/* PID of ssh transport process */
ساكن متطاير pid_t sshpid = -1;

/* Suppress diagnostic messages */
صحيح quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
صحيح showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
صحيح global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
صحيح global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
صحيح global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
صحيح global_fflag = 0;

/* SIGINT received during command processing */
متطاير sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
صحيح ترتیبول_flag;
glob_t *ترتیبول_glob;

/* Context used for commandline completion */
بنية complete_ctx {
	بنية sftp_conn *conn;
	حرف **remote_pathp;
};

صحيح sftp_glob(بنية sftp_conn *, ثابت حرف *, صحيح,
    صحيح (*)(ثابت حرف *, صحيح), glob_t *); /* proto for sftp-glob.c */

خارجي حرف *__progname;

/* Separators for interactive commands */
#تعریف_کړه WHITESPACE " \t\r\n"

/* ls flags */
#تعریف_کړه LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#تعریف_کړه LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#تعریف_کړه LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#تعریف_کړه LS_NAME_ترتیبول	0x0008	/* Sort by name (default) */
#تعریف_کړه LS_وخت_ترتیبول	0x0010	/* Sort by mtime */
#تعریف_کړه LS_اندازه_ترتیبول	0x0020	/* Sort by file size */
#تعریف_کړه LS_سرچپه_ترتیبول	0x0040	/* Reverse sort order */
#تعریف_کړه LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#تعریف_کړه LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#تعریف_کړه VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#تعریف_کړه ترتیبول_FLAGS	(LS_NAME_ترتیبول|LS_وخت_ترتیبول|LS_اندازه_ترتیبول)

/* Commands for interactive mode */
تعداد sftp_command {
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
	I_نسخه,
	I_پرمختګ,
};

بنية CMD {
	ثابت حرف *c;
	ثابت صحيح n;
	ثابت صحيح t;	/* Completion type for the first argument */
	ثابت صحيح t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#تعریف_کړه NOARGS	0
#تعریف_کړه REMOTE	1
#تعریف_کړه LOCAL	2

ساكن ثابت بنية CMD cmds[] = {
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
	{ "progress",	I_پرمختګ,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_نسخه,	NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ عدم,		-1,		-1,		-1	}
};

ساكن فراغ
killchild(صحيح signo)
{
	pid_t pid;

	pid = sshpid;
	إذا (pid > 1) {
		kill(pid, SIGTERM);
		(فراغ)waitpid(pid, عدم, 0);
	}

	_exit(1);
}

ساكن فراغ
suspchild(صحيح signo)
{
	صحيح save_errno = errno;
	إذا (sshpid > 1) {
		kill(sshpid, signo);
		طالما (waitpid(sshpid, عدم, WUNTRACED) == -1 && errno == EINTR)
			استمر;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ساكن فراغ
cmd_مداخله(صحيح signo)
{
	ثابت حرف پیغام[] = "\rInterrupt  \n";
	صحيح olderrno = errno;

	(فراغ)اكتب(STDERR_FILENO, پیغام, حجم(پیغام) - 1);
	interrupted = 1;
	errno = olderrno;
}

ساكن فراغ
read_مداخله(صحيح signo)
{
	interrupted = 1;
}

ساكن فراغ
sigchld_handler(صحيح sig)
{
	صحيح save_errno = errno;
	pid_t pid;
	ثابت حرف پیغام[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	طالما ((pid = waitpid(sshpid, عدم, WNOHANG)) == -1 && errno == EINTR)
		استمر;
	إذا (pid == sshpid) {
		إذا (!quiet)
		    (فراغ)اكتب(STDERR_FILENO, پیغام, حجم(پیغام) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

ساكن فراغ
help(فراغ)
{
	چاپ_کړه("Available commands:\n"
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

ساكن فراغ
local_do_shell(ثابت حرف *دلیلونه)
{
	صحيح حالت;
	حرف *shell;
	pid_t pid;

	إذا (!*دلیلونه)
		دلیلونه = عدم;

	إذا ((shell = getenv("SHELL")) == عدم || *shell == '\0')
		shell = _PATH_BSHELL;

	إذا ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	إذا (pid == 0) {
		إذا (دلیلونه) {
			debug3("Executing %s -c \"%s\"", shell, دلیلونه);
			execl(shell, shell, "-c", دلیلونه, (حرف *)عدم);
		} وإلا {
			debug3("Executing %s", shell);
			execl(shell, shell, (حرف *)عدم);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	طالما (waitpid(pid, &حالت, 0) == -1)
		إذا (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	إذا (!WIFEXITED(حالت))
		error("Shell exited abnormally");
	وإلا إذا (WEXITSTATUS(حالت))
		error("Shell exited with status %d", WEXITSTATUS(حالت));
}

ساكن فراغ
local_do_ls(ثابت حرف *دلیلونه)
{
	إذا (!دلیلونه || !*دلیلونه)
		local_do_shell(لار_LS);
	وإلا {
		صحيح len = مزي_اوږدوالی(لار_LS " ") + مزي_اوږدوالی(دلیلونه) + 1;
		حرف *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, لار_LS " %s", دلیلونه);
		local_do_shell(buf);
		حرر(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
ساكن حرف *
لار_strip(ثابت حرف *لار, ثابت حرف *strip)
{
	اندازه_t len;

	إذا (strip == عدم || (len = مزي_اوږدوالی(strip)) == 0)
		أرجع (xstrdup(لار));

	إذا (مزي_پرتله(لار, strip, len) == 0) {
		إذا (strip[len - 1] != '/' && لار[len] == '/')
			len++;
		أرجع (xstrdup(لار + len));
	}

	أرجع (xstrdup(لار));
}

ساكن صحيح
parse_getput_flags(ثابت حرف *cmd, حرف **argv, صحيح argc,
    صحيح *aflag, صحيح *fflag, صحيح *pflag, صحيح *rflag)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	طالما ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		بدل (ch) {
		حالة 'a':
			*aflag = 1;
			اكسر;
		حالة 'f':
			*fflag = 1;
			اكسر;
		حالة 'p':
		حالة 'P':
			*pflag = 1;
			اكسر;
		حالة 'r':
		حالة 'R':
			*rflag = 1;
			اكسر;
		افتراضي:
			error("%s: Invalid flag -%c", cmd, optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن صحيح
parse_mkdir_flags(ثابت حرف *cmd, حرف **argv, صحيح argc, صحيح *pflag)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	طالما ((ch = getopt(argc, argv, "p")) != -1) {
		بدل (ch) {
		حالة 'p':
			*pflag = 1;
			اكسر;
		افتراضي:
			error("%s: Invalid flag -%c", cmd, optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن صحيح
parse_link_flags(ثابت حرف *cmd, حرف **argv, صحيح argc, صحيح *sflag)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	طالما ((ch = getopt(argc, argv, "s")) != -1) {
		بدل (ch) {
		حالة 's':
			*sflag = 1;
			اكسر;
		افتراضي:
			error("%s: Invalid flag -%c", cmd, optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن صحيح
parse_rename_flags(ثابت حرف *cmd, حرف **argv, صحيح argc, صحيح *lflag)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	طالما ((ch = getopt(argc, argv, "l")) != -1) {
		بدل (ch) {
		حالة 'l':
			*lflag = 1;
			اكسر;
		افتراضي:
			error("%s: Invalid flag -%c", cmd, optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن صحيح
parse_ls_flags(حرف **argv, صحيح argc, صحيح *lflag)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_ترتیبول;
	طالما ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		بدل (ch) {
		حالة '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			اكسر;
		حالة 'S':
			*lflag &= ~ترتیبول_FLAGS;
			*lflag |= LS_اندازه_ترتیبول;
			اكسر;
		حالة 'a':
			*lflag |= LS_SHOW_ALL;
			اكسر;
		حالة 'f':
			*lflag &= ~ترتیبول_FLAGS;
			اكسر;
		حالة 'h':
			*lflag |= LS_SI_UNITS;
			اكسر;
		حالة 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			اكسر;
		حالة 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			اكسر;
		حالة 'r':
			*lflag |= LS_سرچپه_ترتیبول;
			اكسر;
		حالة 't':
			*lflag &= ~ترتیبول_FLAGS;
			*lflag |= LS_وخت_ترتیبول;
			اكسر;
		افتراضي:
			error("ls: Invalid flag -%c", optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن صحيح
parse_df_flags(ثابت حرف *cmd, حرف **argv, صحيح argc, صحيح *hflag, صحيح *iflag)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	طالما ((ch = getopt(argc, argv, "hi")) != -1) {
		بدل (ch) {
		حالة 'h':
			*hflag = 1;
			اكسر;
		حالة 'i':
			*iflag = 1;
			اكسر;
		افتراضي:
			error("%s: Invalid flag -%c", cmd, optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن صحيح
parse_ch_flags(ثابت حرف *cmd, حرف **argv, صحيح argc, صحيح *hflag)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	طالما ((ch = getopt(argc, argv, "h")) != -1) {
		بدل (ch) {
		حالة 'h':
			*hflag = 1;
			اكسر;
		افتراضي:
			error("%s: Invalid flag -%c", cmd, optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن صحيح
parse_no_flags(ثابت حرف *cmd, حرف **argv, صحيح argc)
{
	خارجي صحيح opterr, optind, optopt, optreset;
	صحيح ch;

	optind = optreset = 1;
	opterr = 0;

	طالما ((ch = getopt(argc, argv, "")) != -1) {
		بدل (ch) {
		افتراضي:
			error("%s: Invalid flag -%c", cmd, optopt);
			أرجع -1;
		}
	}

	أرجع optind;
}

ساكن حرف *
escape_glob(ثابت حرف *s)
{
	اندازه_t i, o, len;
	حرف *ret;

	len = مزي_اوږدوالی(s);
	ret = xcalloc(2, len + 1);
	لكل (i = o = 0; i < len; i++) {
		إذا (strchr("[]?*\\", s[i]) != عدم)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	أرجع ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
ساكن حرف *
make_absolute_pwd_glob(حرف *p, ثابت حرف *pwd)
{
	حرف *ret, *escpwd;

	escpwd = escape_glob(pwd);
	إذا (p == عدم)
		أرجع escpwd;
	ret = sftp_make_absolute(p, escpwd);
	حرر(escpwd);
	أرجع ret;
}

ساكن صحيح
local_is_dir(ثابت حرف *لار)
{
	بنية stat sb;

	إذا (stat(لار, &sb) == -1)
		أرجع 0;
	أرجع S_ISDIR(sb.st_mode);
}

ساكن صحيح
process_get(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    ثابت حرف *pwd, صحيح pflag, صحيح rflag, صحيح resume, صحيح fflag)
{
	حرف *filename, *abs_src = عدم, *abs_dst = عدم, *tmp = عدم;
	glob_t g;
	صحيح i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, حجم(g));

	debug3("Looking up %s", abs_src);
	إذا ((r = sftp_glob(conn, abs_src, GLOB_MARK, عدم, &g)) != 0) {
		إذا (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} وإلا {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		اذهب بهر;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	إذا (g.gl_matchc > 1 && dst != عدم && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		اذهب بهر;
	}

	لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		إذا ((filename = basename(tmp)) == عدم) {
			error("basename %s: %s", tmp, strerror(errno));
			حرر(tmp);
			err = -1;
			اذهب بهر;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		إذا (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		إذا (g.gl_matchc == 1 && dst) {
			إذا (local_is_dir(dst)) {
				abs_dst = sftp_لار_append(dst, filename);
			} وإلا {
				abs_dst = xstrdup(dst);
			}
		} وإلا إذا (dst) {
			abs_dst = sftp_لار_append(dst, filename);
		} وإلا {
			abs_dst = xstrdup(filename);
		}
		حرر(tmp);

		resume |= global_aflag;
		إذا (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		وإلا إذا (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		إذا (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			إذا (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    عدم, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} وإلا {
			إذا (sftp_download(conn, g.gl_pathv[i], abs_dst, عدم,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		حرر(abs_dst);
		abs_dst = عدم;
	}

بهر:
	حرر(abs_src);
	globfree(&g);
	أرجع(err);
}

ساكن صحيح
process_put(بنية sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    ثابت حرف *pwd, صحيح pflag, صحيح rflag, صحيح resume, صحيح fflag)
{
	حرف *tmp_dst = عدم;
	حرف *abs_dst = عدم;
	حرف *tmp = عدم, *filename = عدم;
	glob_t g;
	صحيح err = 0;
	صحيح i, dst_is_dir = 1;
	بنية stat sb;

	إذا (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, حجم(g));
	debug3("Looking up %s", src);
	إذا (glob(src, GLOB_NOCHECK | GLOB_MARK, عدم, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		اذهب بهر;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	إذا (tmp_dst != عدم)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	إذا (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		اذهب بهر;
	}

	لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		إذا (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			استمر;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		إذا ((filename = basename(tmp)) == عدم) {
			error("basename %s: %s", tmp, strerror(errno));
			حرر(tmp);
			err = -1;
			اذهب بهر;
		}
		/* Special handling for source of '..' */
		إذا (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		حرر(abs_dst);
		abs_dst = عدم;
		إذا (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			إذا (dst_is_dir)
				abs_dst = sftp_لار_append(tmp_dst, filename);
			وإلا
				abs_dst = xstrdup(tmp_dst);
		} وإلا إذا (tmp_dst) {
			abs_dst = sftp_لار_append(tmp_dst, filename);
		} وإلا {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		حرر(tmp);

		resume |= global_aflag;
		إذا (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		وإلا إذا (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		إذا (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			إذا (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} وإلا {
			إذا (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

بهر:
	حرر(abs_dst);
	حرر(tmp_dst);
	globfree(&g);
	أرجع(err);
}

ساكن صحيح
sdirent_comp(ثابت فراغ *aa, ثابت فراغ *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	صحيح rmul = ترتیبول_flag & LS_سرچپه_ترتیبول ? -1 : 1;

#تعریف_کړه NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	إذا (ترتیبول_flag & LS_NAME_ترتیبول)
		أرجع (rmul * strcmp(a->filename, b->filename));
	وإلا إذا (ترتیبول_flag & LS_وخت_ترتیبول)
		أرجع (rmul * NCMP(a->a.mtime, b->a.mtime));
	وإلا إذا (ترتیبول_flag & LS_اندازه_ترتیبول)
		أرجع (rmul * NCMP(a->a.اندازه, b->a.اندازه));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
ساكن صحيح
do_ls_dir(بنية sftp_conn *conn, ثابت حرف *لار,
    ثابت حرف *strip_لار, صحيح lflag)
{
	صحيح n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	إذا ((n = sftp_readdir(conn, لار, &d)) != 0)
		أرجع (n);

	إذا (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, پلنوالی = 80;
		بنية winsize ws;
		حرف *tmp;

		/* Count entries for sort and find longest filename */
		لكل (n = 0; d[n] != عدم; n++) {
			إذا (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = اعظمي(m, مزي_اوږدوالی(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = لار_strip(لار, strip_لار);
		m += مزي_اوږدوالی(tmp);
		حرر(tmp);

		إذا (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			پلنوالی = ws.ws_ستون;

		columns = پلنوالی / (m + 2);
		columns = اعظمي(columns, 1);
		colspace = پلنوالی / columns;
		colspace = MINIMUM(colspace, پلنوالی);
	}

	إذا (lflag & ترتیبول_FLAGS) {
		لكل (n = 0; d[n] != عدم; n++)
			;	/* count entries */
		ترتیبول_flag = lflag & (ترتیبول_FLAGS|LS_سرچپه_ترتیبول);
		qsort(d, n, حجم(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	لكل (n = 0; d[n] != عدم && !interrupted; n++) {
		حرف *tmp, *fname;

		إذا (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			استمر;

		tmp = sftp_لار_append(لار, d[n]->filename);
		fname = لار_strip(tmp, strip_لار);
		حرر(tmp);

		إذا (lflag & LS_LONG_VIEW) {
			إذا ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				حرف *lname;
				بنية stat sb;
				ثابت حرف *user = عدم, *ډله = عدم;

				memset(&sb, 0, حجم(sb));
				attrib_منزل_stat(&d[n]->a, &sb);
				إذا ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					ډله = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, ډله);
				mprintf("%s\n", lname);
				حرر(lname);
			} وإلا
				mprintf("%s\n", d[n]->longname);
		} وإلا {
			mprintf("%-*s", colspace, fname);
			إذا (c >= columns) {
				چاپ_کړه("\n");
				c = 1;
			} وإلا
				c++;
		}

		حرر(fname);
	}

	إذا (!(lflag & LS_LONG_VIEW) && (c != 1))
		چاپ_کړه("\n");

	sftp_free_dirents(d);
	أرجع (0);
}

ساكن صحيح
sglob_comp(ثابت فراغ *aa, ثابت فراغ *bb)
{
	u_int a = *(ثابت u_int *)aa;
	u_int b = *(ثابت u_int *)bb;
	ثابت حرف *ap = ترتیبول_glob->gl_pathv[a];
	ثابت حرف *bp = ترتیبول_glob->gl_pathv[b];
	ثابت بنية stat *as = ترتیبول_glob->gl_statv[a];
	ثابت بنية stat *bs = ترتیبول_glob->gl_statv[b];
	صحيح rmul = ترتیبول_flag & LS_سرچپه_ترتیبول ? -1 : 1;

#تعریف_کړه NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	إذا (as == عدم || bs == عدم)
		أرجع (as == bs) ? 0 : (as == عدم ? rmul : -rmul);
	إذا (ترتیبول_flag & LS_NAME_ترتیبول)
		أرجع (rmul * strcmp(ap, bp));
	وإلا إذا (ترتیبول_flag & LS_وخت_ترتیبول) {
#إذا defined(HAVE_STRUCT_STAT_ST_MTIM)
		إذا (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			أرجع 0;
		أرجع timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#وإلاإذا defined(HAVE_STRUCT_STAT_ST_MTIME)
		أرجع (rmul * NCMP(as->st_mtime, bs->st_mtime));
#وإلا
	أرجع rmul * 1;
#د_که_پای
	} وإلا إذا (ترتیبول_flag & LS_اندازه_ترتیبول)
		أرجع (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
ساكن صحيح
do_globbed_ls(بنية sftp_conn *conn, ثابت حرف *لار,
    ثابت حرف *strip_لار, صحيح lflag)
{
	حرف *fname, *lname;
	glob_t g;
	صحيح err, r;
	بنية winsize ws;
	u_int i, j, nentries, *indices = عدم, c = 1;
	u_int colspace = 0, columns = 1, m = 0, پلنوالی = 80;

	memset(&g, 0, حجم(g));

	إذا ((r = sftp_glob(conn, لار,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    عدم, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		إذا (g.gl_pathc)
			globfree(&g);
		إذا (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", لار);
		} وإلا {
			error("Can't ls: \"%s\" not found", لار);
		}
		أرجع -1;
	}

	إذا (interrupted)
		اذهب بهر;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	إذا (g.gl_matchc == 1 && g.gl_statv[0] != عدم &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_لار, lflag);
		globfree(&g);
		أرجع err;
	}

	إذا (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		پلنوالی = ws.ws_ستون;

	إذا (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		لكل (i = 0; g.gl_pathv[i]; i++)
			m = اعظمي(m, مزي_اوږدوالی(g.gl_pathv[i]));

		columns = پلنوالی / (m + 2);
		columns = اعظمي(columns, 1);
		colspace = پلنوالی / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	لكل (nentries = 0; g.gl_pathv[nentries] != عدم; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, حجم(*indices));
	لكل (i = 0; i < nentries; i++)
		indices[i] = i;

	إذا (lflag & ترتیبول_FLAGS) {
		ترتیبول_glob = &g;
		ترتیبول_flag = lflag & (ترتیبول_FLAGS|LS_سرچپه_ترتیبول);
		qsort(indices, nentries, حجم(*indices), sglob_comp);
		ترتیبول_glob = عدم;
	}

	get_remote_user_groups_from_glob(conn, &g);
	لكل (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = لار_strip(g.gl_pathv[i], strip_لار);
		إذا (lflag & LS_LONG_VIEW) {
			ثابت حرف *user = عدم, *ډله = عدم;

			إذا (g.gl_statv[i] == عدم) {
				error("no stat information for %s", fname);
				حرر(fname);
				استمر;
			}
			إذا ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				ډله = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, ډله);
			mprintf("%s\n", lname);
			حرر(lname);
		} وإلا {
			mprintf("%-*s", colspace, fname);
			إذا (c >= columns) {
				چاپ_کړه("\n");
				c = 1;
			} وإلا
				c++;
		}
		حرر(fname);
	}

	إذا (!(lflag & LS_LONG_VIEW) && (c != 1))
		چاپ_کړه("\n");

 بهر:
	إذا (g.gl_pathc)
		globfree(&g);
	حرر(indices);

	أرجع 0;
}

ساكن صحيح
do_df(بنية sftp_conn *conn, ثابت حرف *لار, صحيح hflag, صحيح iflag)
{
	بنية sftp_statvfs st;
	حرف s_کارول_شوی[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	حرف s_ریښه[FMT_SCALED_STRSIZE], s_ټول[FMT_SCALED_STRSIZE];
	حرف s_icapacity[16], s_dcapacity[16];

	إذا (sftp_statvfs(conn, لار, &st, 1) == -1)
		أرجع -1;
	إذا (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", حجم(s_icapacity));
	وإلا {
		snprintf(s_icapacity, حجم(s_icapacity), "%3llu%%",
		    (بینښه اوږد اوږد)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	إذا (st.f_بلاکونه == 0)
		strlcpy(s_dcapacity, "ERR", حجم(s_dcapacity));
	وإلا {
		snprintf(s_dcapacity, حجم(s_dcapacity), "%3llu%%",
		    (بینښه اوږد اوږد)(100 * (st.f_بلاکونه - st.f_bfree) /
		    st.f_بلاکونه));
	}
	إذا (iflag) {
		چاپ_کړه("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		چاپ_کړه("%11llu %11llu %11llu %11llu         %s\n",
		    (بینښه اوږد اوږد)st.f_files,
		    (بینښه اوږد اوږد)(st.f_files - st.f_ffree),
		    (بینښه اوږد اوږد)st.f_favail,
		    (بینښه اوږد اوږد)st.f_ffree, s_icapacity);
	} وإلا إذا (hflag) {
		strlcpy(s_کارول_شوی, "error", حجم(s_کارول_شوی));
		strlcpy(s_avail, "error", حجم(s_avail));
		strlcpy(s_ریښه, "error", حجم(s_ریښه));
		strlcpy(s_ټول, "error", حجم(s_ټول));
		fmt_scaled((st.f_بلاکونه - st.f_bfree) * st.f_frsize, s_کارول_شوی);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_ریښه);
		fmt_scaled(st.f_بلاکونه * st.f_frsize, s_ټول);
		چاپ_کړه("    Size     Used    Avail   (root)    %%Capacity\n");
		چاپ_کړه("%7sB %7sB %7sB %7sB         %s\n",
		    s_ټول, s_کارول_شوی, s_avail, s_ریښه, s_dcapacity);
	} وإلا {
		چاپ_کړه("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		چاپ_کړه("%12llu %12llu %12llu %12llu         %s\n",
		    (بینښه اوږد اوږد)(st.f_frsize * st.f_بلاکونه / 1024),
		    (بینښه اوږد اوږد)(st.f_frsize *
		    (st.f_بلاکونه - st.f_bfree) / 1024),
		    (بینښه اوږد اوږد)(st.f_frsize * st.f_bavail / 1024),
		    (بینښه اوږد اوږد)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	أرجع 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
ساكن فراغ
undo_glob_escape(حرف *s)
{
	اندازه_t i, j;

	لكل (i = j = 0;;) {
		إذا (s[i] == '\0') {
			s[j] = '\0';
			أرجع;
		}
		إذا (s[i] != '\\') {
			s[j++] = s[i++];
			استمر;
		}
		/* s[i] == '\\' */
		++i;
		بدل (s[i]) {
		حالة '?':
		حالة '[':
		حالة '*':
		حالة '\\':
			s[j++] = s[i++];
			اكسر;
		حالة '\0':
			s[j++] = '\\';
			s[j] = '\0';
			أرجع;
		افتراضي:
			s[j++] = '\\';
			s[j++] = s[i++];
			اكسر;
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
#تعریف_کړه MAXARGS		128
#تعریف_کړه MAXARGLEN	8192
ساكن حرف **
makeargv(ثابت حرف *arg, صحيح *argcp, صحيح sloppy, حرف *lastquote,
    u_int *terminated)
{
	صحيح argc, quot;
	اندازه_t i, j;
	ساكن حرف argvs[MAXARGLEN];
	ساكن حرف *argv[MAXARGS + 1];
	تعداد { MA_پیل, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	إذا (مزي_اوږدوالی(arg) > حجم(argvs) - 1) {
 دلیلونه_too_longs:
		error("string too long");
		أرجع عدم;
	}
	إذا (terminated != عدم)
		*terminated = 1;
	إذا (lastquote != عدم)
		*lastquote = '\0';
	state = MA_پیل;
	i = j = 0;
	لكل (;;) {
		إذا ((اندازه_t)argc >= حجم(argv) / حجم(*argv)){
			error("Too many arguments.");
			أرجع عدم;
		}
		إذا (که_تشه((بینښه حرف)arg[i])) {
			إذا (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_پیل;
			} وإلا إذا (state != MA_پیل)
				argvs[j++] = arg[i];
		} وإلا إذا (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			إذا (state == MA_پیل) {
				argv[argc] = argvs + j;
				state = q;
				إذا (lastquote != عدم)
					*lastquote = arg[i];
			} وإلا إذا (state == MA_UNQUOTED)
				state = q;
			وإلا إذا (state == q)
				state = MA_UNQUOTED;
			وإلا
				argvs[j++] = arg[i];
		} وإلا إذا (arg[i] == '\\') {
			إذا (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				إذا (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} وإلا إذا (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					إذا (j >= حجم(argvs) - 5)
						اذهب دلیلونه_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} وإلا {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} وإلا {
				إذا (state == MA_پیل) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					إذا (lastquote != عدم)
						*lastquote = '\0';
				}
				إذا (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} وإلا {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					إذا (arg[i] == '\0')
						اذهب early_nul;
					argvs[j++] = arg[i];
				}
			}
		} وإلا إذا (arg[i] == '#') {
			إذا (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			وإلا
				اذهب string_بشپړ;
		} وإلا إذا (arg[i] == '\0') {
			إذا (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				إذا (sloppy) {
					state = MA_UNQUOTED;
					إذا (terminated != عدم)
						*terminated = 0;
					اذهب string_بشپړ;
				}
				error("Unterminated quoted argument");
				أرجع عدم;
			}
 string_بشپړ:
			إذا (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			اكسر;
		} وإلا {
			إذا (state == MA_پیل) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				إذا (lastquote != عدم)
					*lastquote = '\0';
			}
			إذا ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				إذا (j >= حجم(argvs) - 3)
					اذهب دلیلونه_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} وإلا
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	أرجع argv;
}

ساكن صحيح
parse_دلیلونه(ثابت حرف **cpp, صحيح *ignore_errors, صحيح *disable_echo, صحيح *aflag,
	  صحيح *fflag, صحيح *hflag, صحيح *iflag, صحيح *lflag, صحيح *pflag,
	  صحيح *rflag, صحيح *sflag,
    بینښه اوږد *n_arg, حرف **path1, حرف **path2)
{
	ثابت حرف *cmd, *cp = *cpp;
	حرف *cp2, **argv;
	صحيح بنسټ = 0;
	اوږد اوږد ll;
	صحيح path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	لكل (;*cp != '\0'; cp++) {
		إذا (*cp == '-') {
			*ignore_errors = 1;
		} وإلا إذا (*cp == '@') {
			*disable_echo = 1;
		} وإلا {
			/* all other characters terminate prefix processing */
			اكسر;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	إذا (*cp == '\0' || *cp == '#')
		أرجع (0);

	إذا ((argv = makeargv(cp, &argc, 0, عدم, عدم)) == عدم)
		أرجع -1;

	/* Figure out which command we have */
	لكل (i = 0; cmds[i].c != عدم; i++) {
		إذا (argv[0] != عدم && strcasecmp(cmds[i].c, argv[0]) == 0)
			اكسر;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	إذا (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} وإلا إذا (cmdnum == -1) {
		error("Invalid command.");
		أرجع -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = عدم;
	optidx = 1;
	بدل (cmdnum) {
	حالة I_GET:
	حالة I_REGET:
	حالة I_REPUT:
	حالة I_PUT:
		إذا ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			أرجع -1;
		/* Get first pathname (mandatory) */
		إذا (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			أرجع -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		إذا (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		اكسر;
	حالة I_LINK:
		إذا ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			أرجع -1;
		اذهب parse_two_paths;
	حالة I_COPY:
		إذا ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			أرجع -1;
		اذهب parse_two_paths;
	حالة I_RENAME:
		إذا ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			أرجع -1;
		اذهب parse_two_paths;
	حالة I_SYMLINK:
		إذا ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			أرجع -1;
 parse_two_paths:
		إذا (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			أرجع -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		اكسر;
	حالة I_MKDIR:
	حالة I_LMKDIR:
		إذا ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			أرجع -1;
		path1_mandatory = 1;
		اذهب parse_one_لار;
	حالة I_RM:
	حالة I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	حالة I_CHDIR:
	حالة I_LCHDIR:
		إذا ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			أرجع -1;
 parse_one_لار:
		/* Get pathname (mandatory) */
		إذا (argc - optidx < 1) {
			إذا (!path1_mandatory)
				اكسر; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			أرجع -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		إذا (cmdnum != I_RM)
			undo_glob_escape(*path1);
		اكسر;
	حالة I_DF:
		إذا ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			أرجع -1;
		/* Default to current directory if no path specified */
		إذا (argc - optidx < 1)
			*path1 = عدم;
		وإلا {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		اكسر;
	حالة I_LS:
		إذا ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			أرجع(-1);
		/* Path is optional */
		إذا (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		اكسر;
	حالة I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + مزي_اوږدوالی(cmd) + strspn(cp, WHITESPACE);
	حالة I_SHELL:
		/* Uses the rest of the line */
		اكسر;
	حالة I_LUMASK:
	حالة I_CHMOD:
		بنسټ = 8;
		/* FALLTHROUGH */
	حالة I_CHOWN:
	حالة I_CHGRP:
		إذا ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			أرجع -1;
		/* Get numeric arg (mandatory) */
		إذا (argc - optidx < 1)
			اذهب need_عدد_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, بنسټ);
		إذا (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_عدد_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			أرجع -1;
		}
		*n_arg = ll;
		إذا (cmdnum == I_LUMASK)
			اكسر;
		/* Get pathname (mandatory) */
		إذا (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			أرجع -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		اكسر;
	حالة I_QUIT:
	حالة I_PWD:
	حالة I_LPWD:
	حالة I_HELP:
	حالة I_نسخه:
	حالة I_پرمختګ:
		إذا ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			أرجع -1;
		اكسر;
	افتراضي:
		fatal("Command not implemented");
	}

	*cpp = cp;
	أرجع(cmdnum);
}

ساكن صحيح
parse_dispatch_command(بنية sftp_conn *conn, ثابت حرف *cmd, حرف **pwd,
    ثابت حرف *startdir, صحيح err_abort, صحيح echo_command)
{
	ثابت حرف *ocmd = cmd;
	حرف *path1, *path2, *tmp;
	صحيح ignore_errors = 0, disable_echo = 1;
	صحيح aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	صحيح lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	صحيح cmdnum, i;
	بینښه اوږد n_arg = 0;
	Attrib a, aa;
	حرف لار_buf[PATH_MAX];
	صحيح err = 0;
	glob_t g;

	path1 = path2 = عدم;
	cmdnum = parse_دلیلونه(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	إذا (ignore_errors != 0)
		err_abort = 0;

	إذا (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, حجم(g));

	/* Perform command */
	بدل (cmdnum) {
	حالة 0:
		/* Blank line */
		اكسر;
	حالة -1:
		/* Unrecognized command */
		err = -1;
		اكسر;
	حالة I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	حالة I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		اكسر;
	حالة I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	حالة I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		اكسر;
	حالة I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		اكسر;
	حالة I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		اكسر;
	حالة I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	حالة I_LINK:
		إذا (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		اكسر;
	حالة I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, عدم, &g);
		لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			إذا (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			إذا (err != 0 && err_abort)
				اكسر;
		}
		اكسر;
	حالة I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		إذا (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		وإلا
			err = sftp_mkdir(conn, path1, &a, 1);
		اكسر;
	حالة I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		اكسر;
	حالة I_CHDIR:
		إذا (path1 == عدم || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		إذا ((tmp = sftp_realpath(conn, path1)) == عدم) {
			err = 1;
			اكسر;
		}
		إذا (sftp_stat(conn, tmp, 0, &aa) != 0) {
			حرر(tmp);
			err = 1;
			اكسر;
		}
		إذا (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			حرر(tmp);
			err = 1;
			اكسر;
		}
		إذا (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			حرر(tmp);
			err = 1;
			اكسر;
		}
		حرر(*pwd);
		*pwd = tmp;
		اكسر;
	حالة I_LS:
		إذا (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			اكسر;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = عدم;
		إذا (!لار_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		اكسر;
	حالة I_DF:
		/* Default to current directory if no path specified */
		إذا (path1 == عدم)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		اكسر;
	حالة I_LCHDIR:
		إذا (path1 == عدم || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		حرر(path1);
		path1 = tmp;
		إذا (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		اكسر;
	حالة I_LMKDIR:
		إذا (pflag) {
			إذا (mkdir_لار(path1, 0777) != 0)
				err = 1;
			اكسر;
		}
		إذا (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		اكسر;
	حالة I_LLS:
		local_do_ls(cmd);
		اكسر;
	حالة I_SHELL:
		local_do_shell(cmd);
		اكسر;
	حالة I_LUMASK:
		umask(n_arg);
		چاپ_کړه("Local umask: %03lo\n", n_arg);
		اكسر;
	حالة I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, عدم, &g);
		لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			إذا (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			إذا (err != 0 && err_abort)
				اكسر;
		}
		اكسر;
	حالة I_CHOWN:
	حالة I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, عدم, &g);
		لكل (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			إذا ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				إذا (err_abort) {
					err = -1;
					اكسر;
				} وإلا
					استمر;
			}
			إذا (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				إذا (err_abort) {
					err = -1;
					اكسر;
				} وإلا
					استمر;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			إذا (cmdnum == I_CHOWN) {
				إذا (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} وإلا {
				إذا (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			إذا (err != 0 && err_abort)
				اكسر;
		}
		اكسر;
	حالة I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		اكسر;
	حالة I_LPWD:
		إذا (!getcwd(لار_buf, حجم(لار_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			اكسر;
		}
		mprintf("Local working directory: %s\n", لار_buf);
		اكسر;
	حالة I_QUIT:
		/* Processed below */
		اكسر;
	حالة I_HELP:
		help();
		اكسر;
	حالة I_نسخه:
		چاپ_کړه("SFTP protocol version %u\n", sftp_proto_نسخه(conn));
		اكسر;
	حالة I_پرمختګ:
		showprogress = !showprogress;
		إذا (showprogress)
			چاپ_کړه("Progress meter enabled\n");
		وإلا
			چاپ_کړه("Progress meter disabled\n");
		اكسر;
	افتراضي:
		fatal("%d is not implemented", cmdnum);
	}

	إذا (g.gl_pathc)
		globfree(&g);
	حرر(path1);
	حرر(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	إذا (err_abort && err != 0)
		أرجع (-1);
	وإلا إذا (cmdnum == I_QUIT)
		أرجع (1);

	أرجع (0);
}

#که_تعریف_شوی USE_LIBEDIT
ساكن حرف *
prompt(Edit_کرښه *el)
{
	أرجع ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
ساكن فراغ
complete_display(حرف **list, u_int len)
{
	u_int y, m = 0, پلنوالی = 80, columns = 1, colspace = 0, llen;
	بنية winsize ws;
	حرف *tmp;

	/* Count entries for sort and find longest */
	لكل (y = 0; list[y]; y++)
		m = اعظمي(m, مزي_اوږدوالی(list[y]));

	إذا (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		پلنوالی = ws.ws_ستون;

	m = m > len ? m - len : 0;
	columns = پلنوالی / (m + 2);
	columns = اعظمي(columns, 1);
	colspace = پلنوالی / columns;
	colspace = MINIMUM(colspace, پلنوالی);

	چاپ_کړه("\n");
	m = 1;
	لكل (y = 0; list[y]; y++) {
		llen = مزي_اوږدوالی(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		إذا (m >= columns) {
			چاپ_کړه("\n");
			m = 1;
		} وإلا
			m++;
	}
	چاپ_کړه("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
ساكن حرف *
complete_ambiguous(ثابت حرف *کلمه, حرف **list, اندازه_t شمېر)
{
	اندازه_t i, j, matchlen;
	حرف *tmp;
	صحيح len;

	إذا (کلمه == عدم)
		أرجع عدم;

	إذا (شمېر == 0)
		أرجع xstrdup(کلمه); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = مزي_اوږدوالی(list[0]);
	لكل (i = 1; i < شمېر && list[i] != عدم; i++) {
		لكل (j = 0; j < matchlen; j++)
			إذا (list[0][j] != list[i][j])
				اكسر;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(عدم, 0);
	لكل (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		إذا (len <= 0 || i + (اندازه_t)len > matchlen)
			اكسر;
		i += (اندازه_t)len;
	}
	/* If so, truncate */
	إذا (i < matchlen)
		matchlen = i;

	إذا (matchlen > مزي_اوږدوالی(کلمه)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		أرجع tmp;
	}

	أرجع xstrdup(کلمه);
}

/* Autocomplete a sftp command */
ساكن صحيح
complete_cmd_parse(Edit_کرښه *el, حرف *cmd, صحيح lastarg, حرف quote,
    صحيح terminated)
{
	u_int y, شمېر = 0, cmdlen, tmplen;
	حرف *tmp, **list, argterm[3];
	ثابت کرښه_Info *lf;

	list = xcalloc((حجم(cmds) / حجم(*cmds)) + 1, حجم(حرف *));

	/* No command specified: display all available commands */
	إذا (cmd == عدم) {
		لكل (y = 0; cmds[y].c; y++)
			list[شمېر++] = xstrdup(cmds[y].c);

		list[شمېر] = عدم;
		complete_display(list, 0);

		لكل (y = 0; list[y] != عدم; y++)
			حرر(list[y]);
		حرر(list);
		أرجع شمېر;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = مزي_اوږدوالی(cmd);
	لكل (y = 0; cmds[y].c; y++)  {
		إذا (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[شمېر++] = xstrdup(cmds[y].c);
	}
	list[شمېر] = عدم;

	إذا (شمېر == 0) {
		حرر(list);
		أرجع 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, شمېر);
	إذا (شمېر > 1)
		complete_display(list, 0);

	لكل (y = 0; list[y]; y++)
		حرر(list[y]);
	حرر(list);

	إذا (tmp != عدم) {
		tmplen = مزي_اوږدوالی(tmp);
		cmdlen = مزي_اوږدوالی(cmd);
		/* If cmd may be extended then do so */
		إذا (tmplen > cmdlen)
			إذا (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_کرښه(el);
		/* Terminate argument cleanly */
		إذا (شمېر == 1) {
			y = 0;
			إذا (!terminated)
				argterm[y++] = quote;
			إذا (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			إذا (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		حرر(tmp);
	}

	أرجع شمېر;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
ساكن صحيح
complete_is_remote(حرف *cmd, صحيح cmdarg) {
	صحيح i;

	إذا (cmd == عدم)
		أرجع -1;

	لكل (i = 0; cmds[i].c; i++) {
		إذا (!strncasecmp(cmd, cmds[i].c, مزي_اوږدوالی(cmds[i].c))) {
			إذا (cmdarg == 1)
				أرجع cmds[i].t;
			وإلا إذا (cmdarg == 2)
				أرجع cmds[i].t2;
			اكسر;
		}
	}

	أرجع -1;
}

/* Autocomplete a filename "file" */
ساكن صحيح
complete_سمون(Edit_کرښه *el, بنية sftp_conn *conn, حرف *remote_لار,
    حرف *file, صحيح remote, صحيح lastarg, حرف quote, صحيح terminated)
{
	glob_t g;
	حرف *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	صحيح clen;
	ثابت کرښه_Info *lf;

	/* Glob from "file" location */
	إذا (file == عدم)
		tmp = xstrdup("*");
	وإلا
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = لار_absolute(tmp);

	memset(&g, 0, حجم(g));
	إذا (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_لار);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, عدم, &g);
	} وإلا
		(فراغ)glob(tmp, GLOB_DOOFFS|GLOB_MARK, عدم, &g);

	/* Determine length of pwd so we can trim completion display */
	لكل (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		إذا (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			إذا (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			اكسر;
		}
		إذا (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		إذا (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	حرر(tmp);
	tmp = عدم;

	إذا (g.gl_matchc == 0)
		اذهب بهر;

	إذا (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	إذا (file == عدم || hadglob)
		اذهب بهر;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = لار_strip(tmp2, isabs ? عدم : remote_لار);
	حرر(tmp2);

	إذا (tmp == عدم)
		اذهب بهر;

	tmplen = مزي_اوږدوالی(tmp);
	filelen = مزي_اوږدوالی(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	لكل (i = 0; i < filelen; i++) {
		إذا (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} وإلا
			isesc = 0;
	}

	إذا (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = مزي_اوږدوالی(tmp2);
		/* quote argument on way out */
		mblen(عدم, 0);
		لكل (i = 0; i < len; i += clen) {
			إذا ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (اندازه_t)clen > حجم(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			حافظه_نقل(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			بدل (tmp2[i]) {
			حالة '\'':
			حالة '"':
			حالة '\\':
			حالة '\t':
			حالة '[':
			حالة ' ':
			حالة '#':
			حالة '*':
				إذا (quote == '\0' || tmp2[i] == quote) {
					إذا (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					اكسر;
				}
				/* FALLTHROUGH */
			افتراضي:
				إذا (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				اكسر;
			}
		}
	}

	lf = el_کرښه(el);
	إذا (g.gl_matchc == 1) {
		i = 0;
		إذا (!terminated && quote != '\0')
			ins[i++] = quote;
		إذا (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		إذا (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	حرر(tmp);

 بهر:
	globfree(&g);
	أرجع g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
ساكن بینښه حرف
complete(Edit_کرښه *el, صحيح ch)
{
	حرف **argv, *کرښه, quote;
	صحيح argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ثابت کرښه_Info *lf;
	بنية complete_ctx *complete_ctx;

	lf = el_کرښه(el);
	إذا (el_get(el, EL_CLIENTDATA, (فراغ**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->بفر;
	کرښه = xmalloc(cursor + 1);
	حافظه_نقل(کرښه, lf->بفر, cursor);
	کرښه[cursor] = '\0';
	argv = makeargv(کرښه, &carg, 1, &quote, &terminated);
	حرر(کرښه);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->بفر;
	کرښه = xmalloc(len + 1);
	حافظه_نقل(کرښه, lf->بفر, len);
	کرښه[len] = '\0';
	argv = makeargv(کرښه, &argc, 1, عدم, عدم);

	/* Ensure cursor is at EOL or a argument boundary */
	إذا (کرښه[cursor] != ' ' && کرښه[cursor] != '\0' &&
	    کرښه[cursor] != '\n') {
		حرر(کرښه);
		أرجع ret;
	}

	إذا (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, عدم, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} وإلا إذا (carg == 1 && cursor > 0 && کرښه[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		إذا (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} وإلا إذا (carg >= 1) {
		/* Handle file parsing */
		صحيح remote = 0;
		صحيح i = 0, cmdarg = 0;
		حرف *filematch = عدم;

		إذا (carg > 1 && کرښه[cursor-1] != ' ')
			filematch = argv[carg - 1];

		لكل (i = 1; i < carg; i++) {
			/* Skip flags */
			إذا (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		إذا (کرښه[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		إذا ((remote == REMOTE || remote == LOCAL) &&
		    complete_سمون(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	حرر(کرښه);
	أرجع ret;
}
#د_که_پای /* USE_LIBEDIT */

ساكن صحيح
interactive_loop(بنية sftp_conn *conn, حرف *file1, حرف *file2)
{
	حرف *remote_لار;
	حرف *dir = عدم, *startdir = عدم;
	حرف cmd[2048];
	صحيح err, interactive;
	Edit_کرښه *el = عدم;
#که_تعریف_شوی USE_LIBEDIT
	ثابت حرف *editor;
	History *hl = عدم;
	HistEvent hev;
	خارجي حرف *__progname;
	بنية complete_ctx complete_ctx;

	إذا (!batchmode && isatty(STDIN_FILENO)) {
		إذا ((el = el_init(__progname, stdin, stdout, stderr)) == عدم)
			fatal("Couldn't initialise editline");
		إذا ((hl = history_init()) == عدم)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_سېټ(el, EL_HIST, history, hl);

		el_سېټ(el, EL_PROMPT, prompt);
		el_سېټ(el, EL_EDITOR, "emacs");
		el_سېټ(el, EL_TERMINAL, عدم);
		el_سېټ(el, EL_SIGNAL, 1);
		el_سرچینه(el, عدم);

		/* Tab Completion */
		el_سېټ(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_لار;
		el_سېټ(el, EL_CLIENTDATA, (فراغ*)&complete_ctx);
		el_سېټ(el, EL_BIND, "^I", "ftp-complete", عدم);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_سېټ(el, EL_BIND, "\\e[1;5C", "em-next-word", عدم);
		el_سېټ(el, EL_BIND, "\\e\\e[C", "em-next-word", عدم);
		el_سېټ(el, EL_BIND, "\\e[1;5D", "ed-prev-word", عدم);
		el_سېټ(el, EL_BIND, "\\e\\e[D", "ed-prev-word", عدم);
		/* make ^w match ksh behaviour */
		el_سېټ(el, EL_BIND, "^w", "ed-delete-prev-word", عدم);

		/* el_source() may have changed EL_EDITOR to vi */
		إذا (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_سېټ(el, EL_BIND, "^[", "vi-command-mode", عدم);
	}
#د_که_پای /* USE_LIBEDIT */

	إذا ((remote_لار = sftp_realpath(conn, ".")) == عدم)
		fatal("Need cwd");
	startdir = xstrdup(remote_لار);

	إذا (file1 != عدم) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_لار);

		إذا (sftp_remote_is_dir(conn, dir) && file2 == عدم) {
			إذا (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, حجم cmd, "cd \"%s\"", dir);
			إذا (parse_dispatch_command(conn, cmd,
			    &remote_لار, startdir, 1, 0) != 0) {
				حرر(dir);
				حرر(startdir);
				حرر(remote_لار);
				حرر(conn);
				أرجع (-1);
			}
		} وإلا {
			err = process_get(conn, dir, file2, remote_لار, 0, 0,
			    global_aflag, 0);
			حرر(dir);
			حرر(startdir);
			حرر(remote_لار);
			حرر(conn);
			أرجع (err);
		}
		حرر(dir);
	}

	setvbuf(stdout, عدم, _IOLBF, 0);
	setvbuf(infile, عدم, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	لكل (;;) {
		بنية sigaction sa;

		interrupted = 0;
		memset(&sa, 0, حجم(sa));
		sa.sa_handler = interactive ? read_مداخله : killchild;
		إذا (sigaction(SIGINT, &sa, عدم) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			اكسر;
		}
		إذا (el == عدم) {
			إذا (interactive) {
				چاپ_کړه("sftp> ");
				fflush(stdout);
			}
			إذا (fgets(cmd, حجم(cmd), infile) == عدم) {
				إذا (interactive)
					چاپ_کړه("\n");
				إذا (interrupted)
					استمر;
				اكسر;
			}
		} وإلا {
#که_تعریف_شوی USE_LIBEDIT
			ثابت حرف *کرښه;
			صحيح شمېر = 0;

			إذا ((کرښه = el_gets(el, &شمېر)) == عدم ||
			    شمېر <= 0) {
				چاپ_کړه("\n");
				إذا (interrupted)
					استمر;
				اكسر;
			}
			history(hl, &hev, H_ENTER, کرښه);
			إذا (strlcpy(cmd, کرښه, حجم(cmd)) >= حجم(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				استمر;
			}
#د_که_پای /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_مداخله);

		err = parse_dispatch_command(conn, cmd, &remote_لار,
		    startdir, batchmode, !interactive && el == عدم);
		إذا (err != 0)
			اكسر;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	حرر(remote_لار);
	حرر(startdir);
	حرر(conn);

#که_تعریف_شوی USE_LIBEDIT
	إذا (hl != عدم)
		history_پای_ټکی(hl);
	إذا (el != عدم)
		el_پای_ټکی(el);
#د_که_پای /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	أرجع (err >= 0 ? 0 : -1);
}

ساكن فراغ
connect_منزل_server(حرف *لار, حرف **دلیلونه, صحيح *دننه, صحيح *بهر)
{
	صحيح c_دننه, c_بهر;
#که_تعریف_شوی USE_PIPES
	صحيح pin[2], pout[2];

	إذا ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*دننه = pin[0];
	*بهر = pout[1];
	c_دننه = pout[0];
	c_بهر = pin[1];
#وإلا /* USE_PIPES */
	صحيح inout[2];

	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*دننه = *بهر = inout[0];
	c_دننه = c_بهر = inout[1];
#د_که_پای /* USE_PIPES */
	FD_CLOSEONEXEC(*دننه);
	FD_CLOSEONEXEC(*بهر);

	إذا ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	وإلا إذا (sshpid == 0) {
		إذا ((dup2(c_دننه, STDIN_FILENO) == -1) ||
		    (dup2(c_بهر, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*دننه);
		close(*بهر);
		close(c_دننه);
		close(c_بهر);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(لار, دلیلونه);
		fprintf(stderr, "exec: %s: %s\n", لار, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_دننه);
	close(c_بهر);
}

ساكن فراغ
usage(فراغ)
{
	خارجي حرف *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	وتل(1);
}

صحيح
اصلي(صحيح argc, حرف **argv)
{
	صحيح r, دننه, بهر, ch, err, tmp, پورټ = -1, noisy = 0;
	حرف *host = عدم, *user, *cp, **cpp, *file2 = عدم;
	صحيح debug_level = 0;
	حرف *file1 = عدم, *sftp_server = عدم;
	حرف *ssh_پروګرام = لار_SSH_پروګرام, *sftp_مستقیم = عدم;
	ثابت حرف *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist دلیلونه;
	خارجي صحيح optind;
	خارجي حرف *optarg;
	بنية sftp_conn *conn;
	اندازه_t copy_بفر_len = 0;
	اندازه_t عدد_غوښتنې = 0;
	اوږد اوږد llv, حد_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&دلیلونه, '\0', حجم(دلیلونه));
	دلیلونه.list = عدم;
	addargs(&دلیلونه, "%s", ssh_پروګرام);
	addargs(&دلیلونه, "-oForwardX11 no");
	addargs(&دلیلونه, "-oPermitLocalCommand no");
	addargs(&دلیلونه, "-oClearAllForwardings yes");
	addargs(&دلیلونه, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	طالما ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		بدل (ch) {
		/* Passed through to ssh(1) */
		حالة 'A':
		حالة '4':
		حالة '6':
		حالة 'C':
			addargs(&دلیلونه, "-%c", ch);
			اكسر;
		/* Passed through to ssh(1) with argument */
		حالة 'F':
		حالة 'J':
		حالة 'c':
		حالة 'i':
		حالة 'o':
			addargs(&دلیلونه, "-%c", ch);
			addargs(&دلیلونه, "%s", optarg);
			اكسر;
		حالة 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&دلیلونه, "-%c", ch);
			اكسر;
		حالة 'P':
			پورټ = a2port(optarg);
			إذا (پورټ <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			اكسر;
		حالة 'v':
			إذا (debug_level < 3) {
				addargs(&دلیلونه, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			اكسر;
		حالة '1':
			fatal("SSH protocol v.1 is no longer supported");
			اكسر;
		حالة '2':
			/* accept silently */
			اكسر;
		حالة 'a':
			global_aflag = 1;
			اكسر;
		حالة 'B':
			copy_بفر_len = strtol(optarg, &cp, 10);
			إذا (copy_بفر_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			اكسر;
		حالة 'b':
			إذا (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			إذا (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == عدم)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&دلیلونه, "-obatchmode yes");
			اكسر;
		حالة 'f':
			global_fflag = 1;
			اكسر;
		حالة 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			اكسر;
		حالة 'p':
			global_pflag = 1;
			اكسر;
		حالة 'D':
			sftp_مستقیم = optarg;
			اكسر;
		حالة 'l':
			حد_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			إذا (errstr != عدم)
				usage();
			حد_kbps *= 1024; /* kbps */
			اكسر;
		حالة 'r':
			global_rflag = 1;
			اكسر;
		حالة 'R':
			عدد_غوښتنې = strtol(optarg, &cp, 10);
			إذا (عدد_غوښتنې == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			اكسر;
		حالة 's':
			sftp_server = optarg;
			اكسر;
		حالة 'S':
			ssh_پروګرام = optarg;
			replacearg(&دلیلونه, 0, "%s", ssh_پروګرام);
			اكسر;
		حالة 'X':
			/* Please keep in sync with ssh.c -X */
			إذا (مزي_پرتله(optarg, "buffer=", 7) == 0) {
				r = لټون_scaled(optarg + 7, &llv);
				إذا (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				إذا (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_بفر_len = (اندازه_t)llv;
			} وإلا إذا (مزي_پرتله(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				إذا (errstr != عدم) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				عدد_غوښتنې = (اندازه_t)llv;
			} وإلا {
				fatal("Invalid -X option");
			}
			اكسر;
		حالة 'h':
		افتراضي:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&دلیلونه, "-oForwardAgent no");

	إذا (!isatty(STDERR_FILENO))
		showprogress = 0;

	إذا (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	إذا (sftp_مستقیم == عدم) {
		إذا (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		بدل (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		حالة -1:
			usage();
			اكسر;
		حالة 0:
			إذا (tmp != -1)
				پورټ = tmp;
			اكسر;
		افتراضي:
			/* Try with user, host and path. */
			إذا (parse_user_host_لار(*argv, &user, &host,
			    &file1) == 0)
				اكسر;
			/* Try with user and host. */
			إذا (parse_user_host_پورټ(*argv, &user, &host, عدم)
			    == 0)
				اكسر;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			اكسر;
		}
		file2 = *(argv + 1);

		إذا (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		إذا (پورټ != -1)
			addargs(&دلیلونه, "-oPort %d", پورټ);
		إذا (user != عدم) {
			addargs(&دلیلونه, "-l");
			addargs(&دلیلونه, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		إذا (sftp_server == عدم || strchr(sftp_server, '/') == عدم)
			addargs(&دلیلونه, "-s");

		addargs(&دلیلونه, "--");
		addargs(&دلیلونه, "%s", host);
		addargs(&دلیلونه, "%s", (sftp_server != عدم ?
		    sftp_server : "sftp"));

		connect_منزل_server(ssh_پروګرام, دلیلونه.list, &دننه, &بهر);
	} وإلا {
		إذا ((r = argv_وېشل(sftp_مستقیم, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		إذا (cpp[0] == عدم)
			fatal("No sftp server specified via -D");
		connect_منزل_server(cpp[0], cpp, &دننه, &بهر);
		argv_free(cpp, tmp);
	}
	freeargs(&دلیلونه);

	conn = sftp_init(دننه, بهر, copy_بفر_len, عدد_غوښتنې, حد_kbps);
	إذا (conn == عدم)
		fatal("Couldn't initialise connection to server");

	إذا (!quiet) {
		إذا (sftp_مستقیم == عدم)
			fprintf(stderr, "Connected to %s.\n", host);
		وإلا
			fprintf(stderr, "Attached to %s.\n", sftp_مستقیم);
	}

	err = interactive_loop(conn, file1, file2);

#إذا !defined(USE_PIPES)
	shutdown(دننه, SHUT_RDWR);
	shutdown(بهر, SHUT_RDWR);
#د_که_پای

	close(دننه);
	close(بهر);
	إذا (batchmode)
		fclose(infile);

	طالما (waitpid(sshpid, عدم, 0) == -1 && sshpid > 1)
		إذا (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	وتل(err == 0 ? 0 : 1);
}
