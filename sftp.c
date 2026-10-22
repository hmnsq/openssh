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
#اگر_تعریف_شدہ HAVE_LOCALE_H
# include <locale.h>
#اگر_ختم
#اگر_تعریف_شدہ USE_LIBEDIT
#شامل <histedit.h>
#ورنہ
قسمتعریف خالی Edit_سطر;
#اگر_ختم
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
ساکن متلون pid_t sshpid = -1;

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
متلون sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
صحیح ترتیب_دو_flag;
glob_t *ترتیب_دو_glob;

/* Context used for commandline completion */
ساخت complete_ctx {
	ساخت sftp_conn *conn;
	حرف **remote_pathp;
};

صحیح sftp_glob(ساخت sftp_conn *, ثابت حرف *, صحیح,
    صحیح (*)(ثابت حرف *, صحیح), glob_t *); /* proto for sftp-glob.c */

خارجی حرف *__progname;

/* Separators for interactive commands */
#تعریف_کرو WHITESPACE " \t\r\n"

/* ls flags */
#تعریف_کرو LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#تعریف_کرو LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#تعریف_کرو LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#تعریف_کرو LS_NAME_ترتیب_دو	0x0008	/* Sort by name (default) */
#تعریف_کرو LS_وقت_ترتیب_دو	0x0010	/* Sort by mtime */
#تعریف_کرو LS_سائز_ترتیب_دو	0x0020	/* Sort by file size */
#تعریف_کرو LS_الٹ_ترتیب_دو	0x0040	/* Reverse sort order */
#تعریف_کرو LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#تعریف_کرو LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#تعریف_کرو VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#تعریف_کرو ترتیب_دو_FLAGS	(LS_NAME_ترتیب_دو|LS_وقت_ترتیب_دو|LS_سائز_ترتیب_دو)

/* Commands for interactive mode */
شمار sftp_command {
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
	I_نسخہ,
	I_پیش_رفت,
};

ساخت CMD {
	ثابت حرف *c;
	ثابت صحیح n;
	ثابت صحیح t;	/* Completion type for the first argument */
	ثابت صحیح t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#تعریف_کرو NOARGS	0
#تعریف_کرو REMOTE	1
#تعریف_کرو LOCAL	2

ساکن ثابت ساخت CMD cmds[] = {
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
	{ "progress",	I_پیش_رفت,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_نسخہ,	NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ تہی,		-1,		-1,		-1	}
};

ساکن خالی
killchild(صحیح signo)
{
	pid_t pid;

	pid = sshpid;
	اگر (pid > 1) {
		kill(pid, SIGTERM);
		(خالی)waitpid(pid, تہی, 0);
	}

	_exit(1);
}

ساکن خالی
suspchild(صحیح signo)
{
	صحیح save_errno = errno;
	اگر (sshpid > 1) {
		kill(sshpid, signo);
		جب (waitpid(sshpid, تہی, WUNTRACED) == -1 && errno == EINTR)
			جاری;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ساکن خالی
cmd_مداخلت(صحیح signo)
{
	ثابت حرف پیغام[] = "\rInterrupt  \n";
	صحیح olderrno = errno;

	(خالی)اكتب(STDERR_FILENO, پیغام, حجم(پیغام) - 1);
	interrupted = 1;
	errno = olderrno;
}

ساکن خالی
read_مداخلت(صحیح signo)
{
	interrupted = 1;
}

ساکن خالی
sigchld_handler(صحیح sig)
{
	صحیح save_errno = errno;
	pid_t pid;
	ثابت حرف پیغام[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	جب ((pid = waitpid(sshpid, تہی, WNOHANG)) == -1 && errno == EINTR)
		جاری;
	اگر (pid == sshpid) {
		اگر (!quiet)
		    (خالی)اكتب(STDERR_FILENO, پیغام, حجم(پیغام) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

ساکن خالی
help(خالی)
{
	لکھو("Available commands:\n"
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

ساکن خالی
local_do_shell(ثابت حرف *دلائل)
{
	صحیح حالت_2;
	حرف *shell;
	pid_t pid;

	اگر (!*دلائل)
		دلائل = تہی;

	اگر ((shell = getenv("SHELL")) == تہی || *shell == '\0')
		shell = _PATH_BSHELL;

	اگر ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	اگر (pid == 0) {
		اگر (دلائل) {
			debug3("Executing %s -c \"%s\"", shell, دلائل);
			execl(shell, shell, "-c", دلائل, (حرف *)تہی);
		} ورنہ {
			debug3("Executing %s", shell);
			execl(shell, shell, (حرف *)تہی);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	جب (waitpid(pid, &حالت_2, 0) == -1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	اگر (!WIFEXITED(حالت_2))
		error("Shell exited abnormally");
	ورنہ اگر (WEXITSTATUS(حالت_2))
		error("Shell exited with status %d", WEXITSTATUS(حالت_2));
}

ساکن خالی
local_do_ls(ثابت حرف *دلائل)
{
	اگر (!دلائل || !*دلائل)
		local_do_shell(راستہ_LS);
	ورنہ {
		صحیح len = لڑی_لمبائی(راستہ_LS " ") + لڑی_لمبائی(دلائل) + 1;
		حرف *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, راستہ_LS " %s", دلائل);
		local_do_shell(buf);
		آزاد(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
ساکن حرف *
راستہ_strip(ثابت حرف *راستہ, ثابت حرف *strip)
{
	سائز_t len;

	اگر (strip == تہی || (len = لڑی_لمبائی(strip)) == 0)
		واپس (xstrdup(راستہ));

	اگر (لڑی_موازنہ(راستہ, strip, len) == 0) {
		اگر (strip[len - 1] != '/' && راستہ[len] == '/')
			len++;
		واپس (xstrdup(راستہ + len));
	}

	واپس (xstrdup(راستہ));
}

ساکن صحیح
parse_getput_flags(ثابت حرف *cmd, حرف **argv, صحیح argc,
    صحیح *aflag, صحیح *fflag, صحیح *pflag, صحیح *rflag)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	جب ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		انتخاب (ch) {
		حالت 'a':
			*aflag = 1;
			توڑو;
		حالت 'f':
			*fflag = 1;
			توڑو;
		حالت 'p':
		حالت 'P':
			*pflag = 1;
			توڑو;
		حالت 'r':
		حالت 'R':
			*rflag = 1;
			توڑو;
		طےشدہ:
			error("%s: Invalid flag -%c", cmd, optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن صحیح
parse_mkdir_flags(ثابت حرف *cmd, حرف **argv, صحیح argc, صحیح *pflag)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	جب ((ch = getopt(argc, argv, "p")) != -1) {
		انتخاب (ch) {
		حالت 'p':
			*pflag = 1;
			توڑو;
		طےشدہ:
			error("%s: Invalid flag -%c", cmd, optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن صحیح
parse_link_flags(ثابت حرف *cmd, حرف **argv, صحیح argc, صحیح *sflag)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	جب ((ch = getopt(argc, argv, "s")) != -1) {
		انتخاب (ch) {
		حالت 's':
			*sflag = 1;
			توڑو;
		طےشدہ:
			error("%s: Invalid flag -%c", cmd, optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن صحیح
parse_rename_flags(ثابت حرف *cmd, حرف **argv, صحیح argc, صحیح *lflag)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	جب ((ch = getopt(argc, argv, "l")) != -1) {
		انتخاب (ch) {
		حالت 'l':
			*lflag = 1;
			توڑو;
		طےشدہ:
			error("%s: Invalid flag -%c", cmd, optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن صحیح
parse_ls_flags(حرف **argv, صحیح argc, صحیح *lflag)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_ترتیب_دو;
	جب ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		انتخاب (ch) {
		حالت '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			توڑو;
		حالت 'S':
			*lflag &= ~ترتیب_دو_FLAGS;
			*lflag |= LS_سائز_ترتیب_دو;
			توڑو;
		حالت 'a':
			*lflag |= LS_SHOW_ALL;
			توڑو;
		حالت 'f':
			*lflag &= ~ترتیب_دو_FLAGS;
			توڑو;
		حالت 'h':
			*lflag |= LS_SI_UNITS;
			توڑو;
		حالت 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			توڑو;
		حالت 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			توڑو;
		حالت 'r':
			*lflag |= LS_الٹ_ترتیب_دو;
			توڑو;
		حالت 't':
			*lflag &= ~ترتیب_دو_FLAGS;
			*lflag |= LS_وقت_ترتیب_دو;
			توڑو;
		طےشدہ:
			error("ls: Invalid flag -%c", optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن صحیح
parse_df_flags(ثابت حرف *cmd, حرف **argv, صحیح argc, صحیح *hflag, صحیح *iflag)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	جب ((ch = getopt(argc, argv, "hi")) != -1) {
		انتخاب (ch) {
		حالت 'h':
			*hflag = 1;
			توڑو;
		حالت 'i':
			*iflag = 1;
			توڑو;
		طےشدہ:
			error("%s: Invalid flag -%c", cmd, optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن صحیح
parse_ch_flags(ثابت حرف *cmd, حرف **argv, صحیح argc, صحیح *hflag)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	جب ((ch = getopt(argc, argv, "h")) != -1) {
		انتخاب (ch) {
		حالت 'h':
			*hflag = 1;
			توڑو;
		طےشدہ:
			error("%s: Invalid flag -%c", cmd, optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن صحیح
parse_no_flags(ثابت حرف *cmd, حرف **argv, صحیح argc)
{
	خارجی صحیح opterr, optind, optopt, optreset;
	صحیح ch;

	optind = optreset = 1;
	opterr = 0;

	جب ((ch = getopt(argc, argv, "")) != -1) {
		انتخاب (ch) {
		طےشدہ:
			error("%s: Invalid flag -%c", cmd, optopt);
			واپس -1;
		}
	}

	واپس optind;
}

ساکن حرف *
escape_glob(ثابت حرف *s)
{
	سائز_t i, o, len;
	حرف *ret;

	len = لڑی_لمبائی(s);
	ret = xcalloc(2, len + 1);
	برائے (i = o = 0; i < len; i++) {
		اگر (strchr("[]?*\\", s[i]) != تہی)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	واپس ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
ساکن حرف *
make_absolute_pwd_glob(حرف *p, ثابت حرف *pwd)
{
	حرف *ret, *escpwd;

	escpwd = escape_glob(pwd);
	اگر (p == تہی)
		واپس escpwd;
	ret = sftp_make_absolute(p, escpwd);
	آزاد(escpwd);
	واپس ret;
}

ساکن صحیح
local_is_dir(ثابت حرف *راستہ)
{
	ساخت stat sb;

	اگر (stat(راستہ, &sb) == -1)
		واپس 0;
	واپس S_ISDIR(sb.st_mode);
}

ساکن صحیح
process_get(ساخت sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    ثابت حرف *pwd, صحیح pflag, صحیح rflag, صحیح resume, صحیح fflag)
{
	حرف *filename, *abs_src = تہی, *abs_dst = تہی, *tmp = تہی;
	glob_t g;
	صحیح i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, حجم(g));

	debug3("Looking up %s", abs_src);
	اگر ((r = sftp_glob(conn, abs_src, GLOB_MARK, تہی, &g)) != 0) {
		اگر (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} ورنہ {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		جاؤ برآمد;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	اگر (g.gl_matchc > 1 && dst != تہی && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		جاؤ برآمد;
	}

	برائے (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == تہی) {
			error("basename %s: %s", tmp, strerror(errno));
			آزاد(tmp);
			err = -1;
			جاؤ برآمد;
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
				abs_dst = sftp_راستہ_append(dst, filename);
			} ورنہ {
				abs_dst = xstrdup(dst);
			}
		} ورنہ اگر (dst) {
			abs_dst = sftp_راستہ_append(dst, filename);
		} ورنہ {
			abs_dst = xstrdup(filename);
		}
		آزاد(tmp);

		resume |= global_aflag;
		اگر (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ورنہ اگر (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			اگر (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    تہی, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ورنہ {
			اگر (sftp_download(conn, g.gl_pathv[i], abs_dst, تہی,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		آزاد(abs_dst);
		abs_dst = تہی;
	}

برآمد:
	آزاد(abs_src);
	globfree(&g);
	واپس(err);
}

ساکن صحیح
process_put(ساخت sftp_conn *conn, ثابت حرف *src, ثابت حرف *dst,
    ثابت حرف *pwd, صحیح pflag, صحیح rflag, صحیح resume, صحیح fflag)
{
	حرف *tmp_dst = تہی;
	حرف *abs_dst = تہی;
	حرف *tmp = تہی, *filename = تہی;
	glob_t g;
	صحیح err = 0;
	صحیح i, dst_is_dir = 1;
	ساخت stat sb;

	اگر (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, حجم(g));
	debug3("Looking up %s", src);
	اگر (glob(src, GLOB_NOCHECK | GLOB_MARK, تہی, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		جاؤ برآمد;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	اگر (tmp_dst != تہی)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	اگر (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		جاؤ برآمد;
	}

	برائے (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		اگر (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			جاری;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		اگر ((filename = basename(tmp)) == تہی) {
			error("basename %s: %s", tmp, strerror(errno));
			آزاد(tmp);
			err = -1;
			جاؤ برآمد;
		}
		/* Special handling for source of '..' */
		اگر (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		آزاد(abs_dst);
		abs_dst = تہی;
		اگر (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			اگر (dst_is_dir)
				abs_dst = sftp_راستہ_append(tmp_dst, filename);
			ورنہ
				abs_dst = xstrdup(tmp_dst);
		} ورنہ اگر (tmp_dst) {
			abs_dst = sftp_راستہ_append(tmp_dst, filename);
		} ورنہ {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		آزاد(tmp);

		resume |= global_aflag;
		اگر (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ورنہ اگر (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		اگر (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			اگر (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ورنہ {
			اگر (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

برآمد:
	آزاد(abs_dst);
	آزاد(tmp_dst);
	globfree(&g);
	واپس(err);
}

ساکن صحیح
sdirent_comp(ثابت خالی *aa, ثابت خالی *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	صحیح rmul = ترتیب_دو_flag & LS_الٹ_ترتیب_دو ? -1 : 1;

#تعریف_کرو NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	اگر (ترتیب_دو_flag & LS_NAME_ترتیب_دو)
		واپس (rmul * strcmp(a->filename, b->filename));
	ورنہ اگر (ترتیب_دو_flag & LS_وقت_ترتیب_دو)
		واپس (rmul * NCMP(a->a.mtime, b->a.mtime));
	ورنہ اگر (ترتیب_دو_flag & LS_سائز_ترتیب_دو)
		واپس (rmul * NCMP(a->a.سائز, b->a.سائز));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
ساکن صحیح
do_ls_dir(ساخت sftp_conn *conn, ثابت حرف *راستہ,
    ثابت حرف *strip_راستہ, صحیح lflag)
{
	صحیح n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	اگر ((n = sftp_readdir(conn, راستہ, &d)) != 0)
		واپس (n);

	اگر (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, چوڑائی = 80;
		ساخت winsize ws;
		حرف *tmp;

		/* Count entries for sort and find longest filename */
		برائے (n = 0; d[n] != تہی; n++) {
			اگر (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = زیادہ_سے_زیادہ(m, لڑی_لمبائی(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = راستہ_strip(راستہ, strip_راستہ);
		m += لڑی_لمبائی(tmp);
		آزاد(tmp);

		اگر (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			چوڑائی = ws.ws_ستون;

		columns = چوڑائی / (m + 2);
		columns = زیادہ_سے_زیادہ(columns, 1);
		colspace = چوڑائی / columns;
		colspace = MINIMUM(colspace, چوڑائی);
	}

	اگر (lflag & ترتیب_دو_FLAGS) {
		برائے (n = 0; d[n] != تہی; n++)
			;	/* count entries */
		ترتیب_دو_flag = lflag & (ترتیب_دو_FLAGS|LS_الٹ_ترتیب_دو);
		qsort(d, n, حجم(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	برائے (n = 0; d[n] != تہی && !interrupted; n++) {
		حرف *tmp, *fname;

		اگر (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			جاری;

		tmp = sftp_راستہ_append(راستہ, d[n]->filename);
		fname = راستہ_strip(tmp, strip_راستہ);
		آزاد(tmp);

		اگر (lflag & LS_LONG_VIEW) {
			اگر ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				حرف *lname;
				ساخت stat sb;
				ثابت حرف *user = تہی, *گروہ = تہی;

				memset(&sb, 0, حجم(sb));
				attrib_مقصد_stat(&d[n]->a, &sb);
				اگر ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					گروہ = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, گروہ);
				mprintf("%s\n", lname);
				آزاد(lname);
			} ورنہ
				mprintf("%s\n", d[n]->longname);
		} ورنہ {
			mprintf("%-*s", colspace, fname);
			اگر (c >= columns) {
				لکھو("\n");
				c = 1;
			} ورنہ
				c++;
		}

		آزاد(fname);
	}

	اگر (!(lflag & LS_LONG_VIEW) && (c != 1))
		لکھو("\n");

	sftp_free_dirents(d);
	واپس (0);
}

ساکن صحیح
sglob_comp(ثابت خالی *aa, ثابت خالی *bb)
{
	u_int a = *(ثابت u_int *)aa;
	u_int b = *(ثابت u_int *)bb;
	ثابت حرف *ap = ترتیب_دو_glob->gl_pathv[a];
	ثابت حرف *bp = ترتیب_دو_glob->gl_pathv[b];
	ثابت ساخت stat *as = ترتیب_دو_glob->gl_statv[a];
	ثابت ساخت stat *bs = ترتیب_دو_glob->gl_statv[b];
	صحیح rmul = ترتیب_دو_flag & LS_الٹ_ترتیب_دو ? -1 : 1;

#تعریف_کرو NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	اگر (as == تہی || bs == تہی)
		واپس (as == bs) ? 0 : (as == تہی ? rmul : -rmul);
	اگر (ترتیب_دو_flag & LS_NAME_ترتیب_دو)
		واپس (rmul * strcmp(ap, bp));
	ورنہ اگر (ترتیب_دو_flag & LS_وقت_ترتیب_دو) {
#اگر defined(HAVE_STRUCT_STAT_ST_MTIM)
		اگر (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			واپس 0;
		واپس timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#وگرنہ_اگر defined(HAVE_STRUCT_STAT_ST_MTIME)
		واپس (rmul * NCMP(as->st_mtime, bs->st_mtime));
#ورنہ
	واپس rmul * 1;
#اگر_ختم
	} ورنہ اگر (ترتیب_دو_flag & LS_سائز_ترتیب_دو)
		واپس (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
ساکن صحیح
do_globbed_ls(ساخت sftp_conn *conn, ثابت حرف *راستہ,
    ثابت حرف *strip_راستہ, صحیح lflag)
{
	حرف *fname, *lname;
	glob_t g;
	صحیح err, r;
	ساخت winsize ws;
	u_int i, j, nentries, *indices = تہی, c = 1;
	u_int colspace = 0, columns = 1, m = 0, چوڑائی = 80;

	memset(&g, 0, حجم(g));

	اگر ((r = sftp_glob(conn, راستہ,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    تہی, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		اگر (g.gl_pathc)
			globfree(&g);
		اگر (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", راستہ);
		} ورنہ {
			error("Can't ls: \"%s\" not found", راستہ);
		}
		واپس -1;
	}

	اگر (interrupted)
		جاؤ برآمد;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	اگر (g.gl_matchc == 1 && g.gl_statv[0] != تہی &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_راستہ, lflag);
		globfree(&g);
		واپس err;
	}

	اگر (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		چوڑائی = ws.ws_ستون;

	اگر (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		برائے (i = 0; g.gl_pathv[i]; i++)
			m = زیادہ_سے_زیادہ(m, لڑی_لمبائی(g.gl_pathv[i]));

		columns = چوڑائی / (m + 2);
		columns = زیادہ_سے_زیادہ(columns, 1);
		colspace = چوڑائی / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	برائے (nentries = 0; g.gl_pathv[nentries] != تہی; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, حجم(*indices));
	برائے (i = 0; i < nentries; i++)
		indices[i] = i;

	اگر (lflag & ترتیب_دو_FLAGS) {
		ترتیب_دو_glob = &g;
		ترتیب_دو_flag = lflag & (ترتیب_دو_FLAGS|LS_الٹ_ترتیب_دو);
		qsort(indices, nentries, حجم(*indices), sglob_comp);
		ترتیب_دو_glob = تہی;
	}

	get_remote_user_groups_from_glob(conn, &g);
	برائے (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = راستہ_strip(g.gl_pathv[i], strip_راستہ);
		اگر (lflag & LS_LONG_VIEW) {
			ثابت حرف *user = تہی, *گروہ = تہی;

			اگر (g.gl_statv[i] == تہی) {
				error("no stat information for %s", fname);
				آزاد(fname);
				جاری;
			}
			اگر ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				گروہ = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, گروہ);
			mprintf("%s\n", lname);
			آزاد(lname);
		} ورنہ {
			mprintf("%-*s", colspace, fname);
			اگر (c >= columns) {
				لکھو("\n");
				c = 1;
			} ورنہ
				c++;
		}
		آزاد(fname);
	}

	اگر (!(lflag & LS_LONG_VIEW) && (c != 1))
		لکھو("\n");

 برآمد:
	اگر (g.gl_pathc)
		globfree(&g);
	آزاد(indices);

	واپس 0;
}

ساکن صحیح
do_df(ساخت sftp_conn *conn, ثابت حرف *راستہ, صحیح hflag, صحیح iflag)
{
	ساخت sftp_statvfs st;
	حرف s_مستعمل[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	حرف s_جڑ[FMT_SCALED_STRSIZE], s_کل[FMT_SCALED_STRSIZE];
	حرف s_icapacity[16], s_dcapacity[16];

	اگر (sftp_statvfs(conn, راستہ, &st, 1) == -1)
		واپس -1;
	اگر (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", حجم(s_icapacity));
	ورنہ {
		snprintf(s_icapacity, حجم(s_icapacity), "%3llu%%",
		    (غیرعلامتی طویل طویل)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	اگر (st.f_بلاکیں == 0)
		strlcpy(s_dcapacity, "ERR", حجم(s_dcapacity));
	ورنہ {
		snprintf(s_dcapacity, حجم(s_dcapacity), "%3llu%%",
		    (غیرعلامتی طویل طویل)(100 * (st.f_بلاکیں - st.f_bfree) /
		    st.f_بلاکیں));
	}
	اگر (iflag) {
		لکھو("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		لکھو("%11llu %11llu %11llu %11llu         %s\n",
		    (غیرعلامتی طویل طویل)st.f_files,
		    (غیرعلامتی طویل طویل)(st.f_files - st.f_ffree),
		    (غیرعلامتی طویل طویل)st.f_favail,
		    (غیرعلامتی طویل طویل)st.f_ffree, s_icapacity);
	} ورنہ اگر (hflag) {
		strlcpy(s_مستعمل, "error", حجم(s_مستعمل));
		strlcpy(s_avail, "error", حجم(s_avail));
		strlcpy(s_جڑ, "error", حجم(s_جڑ));
		strlcpy(s_کل, "error", حجم(s_کل));
		fmt_scaled((st.f_بلاکیں - st.f_bfree) * st.f_frsize, s_مستعمل);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_جڑ);
		fmt_scaled(st.f_بلاکیں * st.f_frsize, s_کل);
		لکھو("    Size     Used    Avail   (root)    %%Capacity\n");
		لکھو("%7sB %7sB %7sB %7sB         %s\n",
		    s_کل, s_مستعمل, s_avail, s_جڑ, s_dcapacity);
	} ورنہ {
		لکھو("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		لکھو("%12llu %12llu %12llu %12llu         %s\n",
		    (غیرعلامتی طویل طویل)(st.f_frsize * st.f_بلاکیں / 1024),
		    (غیرعلامتی طویل طویل)(st.f_frsize *
		    (st.f_بلاکیں - st.f_bfree) / 1024),
		    (غیرعلامتی طویل طویل)(st.f_frsize * st.f_bavail / 1024),
		    (غیرعلامتی طویل طویل)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	واپس 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
ساکن خالی
undo_glob_escape(حرف *s)
{
	سائز_t i, j;

	برائے (i = j = 0;;) {
		اگر (s[i] == '\0') {
			s[j] = '\0';
			واپس;
		}
		اگر (s[i] != '\\') {
			s[j++] = s[i++];
			جاری;
		}
		/* s[i] == '\\' */
		++i;
		انتخاب (s[i]) {
		حالت '?':
		حالت '[':
		حالت '*':
		حالت '\\':
			s[j++] = s[i++];
			توڑو;
		حالت '\0':
			s[j++] = '\\';
			s[j] = '\0';
			واپس;
		طےشدہ:
			s[j++] = '\\';
			s[j++] = s[i++];
			توڑو;
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
#تعریف_کرو MAXARGS		128
#تعریف_کرو MAXARGLEN	8192
ساکن حرف **
makeargv(ثابت حرف *arg, صحیح *argcp, صحیح sloppy, حرف *lastquote,
    u_int *terminated)
{
	صحیح argc, quot;
	سائز_t i, j;
	ساکن حرف argvs[MAXARGLEN];
	ساکن حرف *argv[MAXARGS + 1];
	شمار { MA_آغاز, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	اگر (لڑی_لمبائی(arg) > حجم(argvs) - 1) {
 دلائل_too_longs:
		error("string too long");
		واپس تہی;
	}
	اگر (terminated != تہی)
		*terminated = 1;
	اگر (lastquote != تہی)
		*lastquote = '\0';
	state = MA_آغاز;
	i = j = 0;
	برائے (;;) {
		اگر ((سائز_t)argc >= حجم(argv) / حجم(*argv)){
			error("Too many arguments.");
			واپس تہی;
		}
		اگر (خلا_ہے((غیرعلامتی حرف)arg[i])) {
			اگر (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_آغاز;
			} ورنہ اگر (state != MA_آغاز)
				argvs[j++] = arg[i];
		} ورنہ اگر (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			اگر (state == MA_آغاز) {
				argv[argc] = argvs + j;
				state = q;
				اگر (lastquote != تہی)
					*lastquote = arg[i];
			} ورنہ اگر (state == MA_UNQUOTED)
				state = q;
			ورنہ اگر (state == q)
				state = MA_UNQUOTED;
			ورنہ
				argvs[j++] = arg[i];
		} ورنہ اگر (arg[i] == '\\') {
			اگر (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				اگر (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} ورنہ اگر (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					اگر (j >= حجم(argvs) - 5)
						جاؤ دلائل_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} ورنہ {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} ورنہ {
				اگر (state == MA_آغاز) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					اگر (lastquote != تہی)
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
				} ورنہ {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					اگر (arg[i] == '\0')
						جاؤ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} ورنہ اگر (arg[i] == '#') {
			اگر (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			ورنہ
				جاؤ string_مکمل;
		} ورنہ اگر (arg[i] == '\0') {
			اگر (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				اگر (sloppy) {
					state = MA_UNQUOTED;
					اگر (terminated != تہی)
						*terminated = 0;
					جاؤ string_مکمل;
				}
				error("Unterminated quoted argument");
				واپس تہی;
			}
 string_مکمل:
			اگر (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			توڑو;
		} ورنہ {
			اگر (state == MA_آغاز) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				اگر (lastquote != تہی)
					*lastquote = '\0';
			}
			اگر ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				اگر (j >= حجم(argvs) - 3)
					جاؤ دلائل_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} ورنہ
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	واپس argv;
}

ساکن صحیح
parse_دلائل(ثابت حرف **cpp, صحیح *ignore_errors, صحیح *disable_echo, صحیح *aflag,
	  صحیح *fflag, صحیح *hflag, صحیح *iflag, صحیح *lflag, صحیح *pflag,
	  صحیح *rflag, صحیح *sflag,
    غیرعلامتی طویل *n_arg, حرف **path1, حرف **path2)
{
	ثابت حرف *cmd, *cp = *cpp;
	حرف *cp2, **argv;
	صحیح بنیاد = 0;
	طویل طویل ll;
	صحیح path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	برائے (;*cp != '\0'; cp++) {
		اگر (*cp == '-') {
			*ignore_errors = 1;
		} ورنہ اگر (*cp == '@') {
			*disable_echo = 1;
		} ورنہ {
			/* all other characters terminate prefix processing */
			توڑو;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	اگر (*cp == '\0' || *cp == '#')
		واپس (0);

	اگر ((argv = makeargv(cp, &argc, 0, تہی, تہی)) == تہی)
		واپس -1;

	/* Figure out which command we have */
	برائے (i = 0; cmds[i].c != تہی; i++) {
		اگر (argv[0] != تہی && strcasecmp(cmds[i].c, argv[0]) == 0)
			توڑو;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	اگر (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} ورنہ اگر (cmdnum == -1) {
		error("Invalid command.");
		واپس -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = تہی;
	optidx = 1;
	انتخاب (cmdnum) {
	حالت I_GET:
	حالت I_REGET:
	حالت I_REPUT:
	حالت I_PUT:
		اگر ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			واپس -1;
		/* Get first pathname (mandatory) */
		اگر (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			واپس -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		اگر (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		توڑو;
	حالت I_LINK:
		اگر ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			واپس -1;
		جاؤ parse_two_paths;
	حالت I_COPY:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			واپس -1;
		جاؤ parse_two_paths;
	حالت I_RENAME:
		اگر ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			واپس -1;
		جاؤ parse_two_paths;
	حالت I_SYMLINK:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			واپس -1;
 parse_two_paths:
		اگر (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			واپس -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		توڑو;
	حالت I_MKDIR:
	حالت I_LMKDIR:
		اگر ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			واپس -1;
		path1_mandatory = 1;
		جاؤ parse_one_راستہ;
	حالت I_RM:
	حالت I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	حالت I_CHDIR:
	حالت I_LCHDIR:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			واپس -1;
 parse_one_راستہ:
		/* Get pathname (mandatory) */
		اگر (argc - optidx < 1) {
			اگر (!path1_mandatory)
				توڑو; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			واپس -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		اگر (cmdnum != I_RM)
			undo_glob_escape(*path1);
		توڑو;
	حالت I_DF:
		اگر ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			واپس -1;
		/* Default to current directory if no path specified */
		اگر (argc - optidx < 1)
			*path1 = تہی;
		ورنہ {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		توڑو;
	حالت I_LS:
		اگر ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			واپس(-1);
		/* Path is optional */
		اگر (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		توڑو;
	حالت I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + لڑی_لمبائی(cmd) + strspn(cp, WHITESPACE);
	حالت I_SHELL:
		/* Uses the rest of the line */
		توڑو;
	حالت I_LUMASK:
	حالت I_CHMOD:
		بنیاد = 8;
		/* FALLTHROUGH */
	حالت I_CHOWN:
	حالت I_CHGRP:
		اگر ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			واپس -1;
		/* Get numeric arg (mandatory) */
		اگر (argc - optidx < 1)
			جاؤ need_عدد_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, بنیاد);
		اگر (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_عدد_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			واپس -1;
		}
		*n_arg = ll;
		اگر (cmdnum == I_LUMASK)
			توڑو;
		/* Get pathname (mandatory) */
		اگر (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			واپس -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		توڑو;
	حالت I_QUIT:
	حالت I_PWD:
	حالت I_LPWD:
	حالت I_HELP:
	حالت I_نسخہ:
	حالت I_پیش_رفت:
		اگر ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			واپس -1;
		توڑو;
	طےشدہ:
		fatal("Command not implemented");
	}

	*cpp = cp;
	واپس(cmdnum);
}

ساکن صحیح
parse_dispatch_command(ساخت sftp_conn *conn, ثابت حرف *cmd, حرف **pwd,
    ثابت حرف *startdir, صحیح err_abort, صحیح echo_command)
{
	ثابت حرف *ocmd = cmd;
	حرف *path1, *path2, *tmp;
	صحیح ignore_errors = 0, disable_echo = 1;
	صحیح aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	صحیح lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	صحیح cmdnum, i;
	غیرعلامتی طویل n_arg = 0;
	Attrib a, aa;
	حرف راستہ_buf[PATH_MAX];
	صحیح err = 0;
	glob_t g;

	path1 = path2 = تہی;
	cmdnum = parse_دلائل(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	اگر (ignore_errors != 0)
		err_abort = 0;

	اگر (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, حجم(g));

	/* Perform command */
	انتخاب (cmdnum) {
	حالت 0:
		/* Blank line */
		توڑو;
	حالت -1:
		/* Unrecognized command */
		err = -1;
		توڑو;
	حالت I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	حالت I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		توڑو;
	حالت I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	حالت I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		توڑو;
	حالت I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		توڑو;
	حالت I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		توڑو;
	حالت I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	حالت I_LINK:
		اگر (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		توڑو;
	حالت I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, تہی, &g);
		برائے (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			اگر (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			اگر (err != 0 && err_abort)
				توڑو;
		}
		توڑو;
	حالت I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		اگر (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		ورنہ
			err = sftp_mkdir(conn, path1, &a, 1);
		توڑو;
	حالت I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		توڑو;
	حالت I_CHDIR:
		اگر (path1 == تہی || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		اگر ((tmp = sftp_realpath(conn, path1)) == تہی) {
			err = 1;
			توڑو;
		}
		اگر (sftp_stat(conn, tmp, 0, &aa) != 0) {
			آزاد(tmp);
			err = 1;
			توڑو;
		}
		اگر (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			آزاد(tmp);
			err = 1;
			توڑو;
		}
		اگر (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			آزاد(tmp);
			err = 1;
			توڑو;
		}
		آزاد(*pwd);
		*pwd = tmp;
		توڑو;
	حالت I_LS:
		اگر (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			توڑو;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = تہی;
		اگر (!راستہ_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		توڑو;
	حالت I_DF:
		/* Default to current directory if no path specified */
		اگر (path1 == تہی)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		توڑو;
	حالت I_LCHDIR:
		اگر (path1 == تہی || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		آزاد(path1);
		path1 = tmp;
		اگر (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		توڑو;
	حالت I_LMKDIR:
		اگر (pflag) {
			اگر (mkdir_راستہ(path1, 0777) != 0)
				err = 1;
			توڑو;
		}
		اگر (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		توڑو;
	حالت I_LLS:
		local_do_ls(cmd);
		توڑو;
	حالت I_SHELL:
		local_do_shell(cmd);
		توڑو;
	حالت I_LUMASK:
		umask(n_arg);
		لکھو("Local umask: %03lo\n", n_arg);
		توڑو;
	حالت I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, تہی, &g);
		برائے (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			اگر (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			اگر (err != 0 && err_abort)
				توڑو;
		}
		توڑو;
	حالت I_CHOWN:
	حالت I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, تہی, &g);
		برائے (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			اگر ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				اگر (err_abort) {
					err = -1;
					توڑو;
				} ورنہ
					جاری;
			}
			اگر (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				اگر (err_abort) {
					err = -1;
					توڑو;
				} ورنہ
					جاری;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			اگر (cmdnum == I_CHOWN) {
				اگر (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} ورنہ {
				اگر (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			اگر (err != 0 && err_abort)
				توڑو;
		}
		توڑو;
	حالت I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		توڑو;
	حالت I_LPWD:
		اگر (!getcwd(راستہ_buf, حجم(راستہ_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			توڑو;
		}
		mprintf("Local working directory: %s\n", راستہ_buf);
		توڑو;
	حالت I_QUIT:
		/* Processed below */
		توڑو;
	حالت I_HELP:
		help();
		توڑو;
	حالت I_نسخہ:
		لکھو("SFTP protocol version %u\n", sftp_proto_نسخہ(conn));
		توڑو;
	حالت I_پیش_رفت:
		showprogress = !showprogress;
		اگر (showprogress)
			لکھو("Progress meter enabled\n");
		ورنہ
			لکھو("Progress meter disabled\n");
		توڑو;
	طےشدہ:
		fatal("%d is not implemented", cmdnum);
	}

	اگر (g.gl_pathc)
		globfree(&g);
	آزاد(path1);
	آزاد(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	اگر (err_abort && err != 0)
		واپس (-1);
	ورنہ اگر (cmdnum == I_QUIT)
		واپس (1);

	واپس (0);
}

#اگر_تعریف_شدہ USE_LIBEDIT
ساکن حرف *
prompt(Edit_سطر *el)
{
	واپس ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
ساکن خالی
complete_display(حرف **list, u_int len)
{
	u_int y, m = 0, چوڑائی = 80, columns = 1, colspace = 0, llen;
	ساخت winsize ws;
	حرف *tmp;

	/* Count entries for sort and find longest */
	برائے (y = 0; list[y]; y++)
		m = زیادہ_سے_زیادہ(m, لڑی_لمبائی(list[y]));

	اگر (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		چوڑائی = ws.ws_ستون;

	m = m > len ? m - len : 0;
	columns = چوڑائی / (m + 2);
	columns = زیادہ_سے_زیادہ(columns, 1);
	colspace = چوڑائی / columns;
	colspace = MINIMUM(colspace, چوڑائی);

	لکھو("\n");
	m = 1;
	برائے (y = 0; list[y]; y++) {
		llen = لڑی_لمبائی(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		اگر (m >= columns) {
			لکھو("\n");
			m = 1;
		} ورنہ
			m++;
	}
	لکھو("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
ساکن حرف *
complete_ambiguous(ثابت حرف *لفظ, حرف **list, سائز_t گنتی)
{
	سائز_t i, j, matchlen;
	حرف *tmp;
	صحیح len;

	اگر (لفظ == تہی)
		واپس تہی;

	اگر (گنتی == 0)
		واپس xstrdup(لفظ); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = لڑی_لمبائی(list[0]);
	برائے (i = 1; i < گنتی && list[i] != تہی; i++) {
		برائے (j = 0; j < matchlen; j++)
			اگر (list[0][j] != list[i][j])
				توڑو;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(تہی, 0);
	برائے (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		اگر (len <= 0 || i + (سائز_t)len > matchlen)
			توڑو;
		i += (سائز_t)len;
	}
	/* If so, truncate */
	اگر (i < matchlen)
		matchlen = i;

	اگر (matchlen > لڑی_لمبائی(لفظ)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		واپس tmp;
	}

	واپس xstrdup(لفظ);
}

/* Autocomplete a sftp command */
ساکن صحیح
complete_cmd_parse(Edit_سطر *el, حرف *cmd, صحیح lastarg, حرف quote,
    صحیح terminated)
{
	u_int y, گنتی = 0, cmdlen, tmplen;
	حرف *tmp, **list, argterm[3];
	ثابت سطر_Info *lf;

	list = xcalloc((حجم(cmds) / حجم(*cmds)) + 1, حجم(حرف *));

	/* No command specified: display all available commands */
	اگر (cmd == تہی) {
		برائے (y = 0; cmds[y].c; y++)
			list[گنتی++] = xstrdup(cmds[y].c);

		list[گنتی] = تہی;
		complete_display(list, 0);

		برائے (y = 0; list[y] != تہی; y++)
			آزاد(list[y]);
		آزاد(list);
		واپس گنتی;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = لڑی_لمبائی(cmd);
	برائے (y = 0; cmds[y].c; y++)  {
		اگر (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[گنتی++] = xstrdup(cmds[y].c);
	}
	list[گنتی] = تہی;

	اگر (گنتی == 0) {
		آزاد(list);
		واپس 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, گنتی);
	اگر (گنتی > 1)
		complete_display(list, 0);

	برائے (y = 0; list[y]; y++)
		آزاد(list[y]);
	آزاد(list);

	اگر (tmp != تہی) {
		tmplen = لڑی_لمبائی(tmp);
		cmdlen = لڑی_لمبائی(cmd);
		/* If cmd may be extended then do so */
		اگر (tmplen > cmdlen)
			اگر (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_سطر(el);
		/* Terminate argument cleanly */
		اگر (گنتی == 1) {
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

	واپس گنتی;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
ساکن صحیح
complete_is_remote(حرف *cmd, صحیح cmdarg) {
	صحیح i;

	اگر (cmd == تہی)
		واپس -1;

	برائے (i = 0; cmds[i].c; i++) {
		اگر (!strncasecmp(cmd, cmds[i].c, لڑی_لمبائی(cmds[i].c))) {
			اگر (cmdarg == 1)
				واپس cmds[i].t;
			ورنہ اگر (cmdarg == 2)
				واپس cmds[i].t2;
			توڑو;
		}
	}

	واپس -1;
}

/* Autocomplete a filename "file" */
ساکن صحیح
complete_مطابقت(Edit_سطر *el, ساخت sftp_conn *conn, حرف *remote_راستہ,
    حرف *file, صحیح remote, صحیح lastarg, حرف quote, صحیح terminated)
{
	glob_t g;
	حرف *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	صحیح clen;
	ثابت سطر_Info *lf;

	/* Glob from "file" location */
	اگر (file == تہی)
		tmp = xstrdup("*");
	ورنہ
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = راستہ_absolute(tmp);

	memset(&g, 0, حجم(g));
	اگر (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_راستہ);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, تہی, &g);
	} ورنہ
		(خالی)glob(tmp, GLOB_DOOFFS|GLOB_MARK, تہی, &g);

	/* Determine length of pwd so we can trim completion display */
	برائے (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		اگر (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			اگر (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			توڑو;
		}
		اگر (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		اگر (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	آزاد(tmp);
	tmp = تہی;

	اگر (g.gl_matchc == 0)
		جاؤ برآمد;

	اگر (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	اگر (file == تہی || hadglob)
		جاؤ برآمد;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = راستہ_strip(tmp2, isabs ? تہی : remote_راستہ);
	آزاد(tmp2);

	اگر (tmp == تہی)
		جاؤ برآمد;

	tmplen = لڑی_لمبائی(tmp);
	filelen = لڑی_لمبائی(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	برائے (i = 0; i < filelen; i++) {
		اگر (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} ورنہ
			isesc = 0;
	}

	اگر (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = لڑی_لمبائی(tmp2);
		/* quote argument on way out */
		mblen(تہی, 0);
		برائے (i = 0; i < len; i += clen) {
			اگر ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (سائز_t)clen > حجم(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			حافظہ_نقل(ins + 1, tmp2 + i, clen);
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
					توڑو;
				}
				/* FALLTHROUGH */
			طےشدہ:
				اگر (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				توڑو;
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

 برآمد:
	globfree(&g);
	واپس g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
ساکن غیرعلامتی حرف
complete(Edit_سطر *el, صحیح ch)
{
	حرف **argv, *سطر, quote;
	صحیح argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ثابت سطر_Info *lf;
	ساخت complete_ctx *complete_ctx;

	lf = el_سطر(el);
	اگر (el_get(el, EL_CLIENTDATA, (خالی**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->بفر;
	سطر = xmalloc(cursor + 1);
	حافظہ_نقل(سطر, lf->بفر, cursor);
	سطر[cursor] = '\0';
	argv = makeargv(سطر, &carg, 1, &quote, &terminated);
	آزاد(سطر);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->بفر;
	سطر = xmalloc(len + 1);
	حافظہ_نقل(سطر, lf->بفر, len);
	سطر[len] = '\0';
	argv = makeargv(سطر, &argc, 1, تہی, تہی);

	/* Ensure cursor is at EOL or a argument boundary */
	اگر (سطر[cursor] != ' ' && سطر[cursor] != '\0' &&
	    سطر[cursor] != '\n') {
		آزاد(سطر);
		واپس ret;
	}

	اگر (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, تہی, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} ورنہ اگر (carg == 1 && cursor > 0 && سطر[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		اگر (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} ورنہ اگر (carg >= 1) {
		/* Handle file parsing */
		صحیح remote = 0;
		صحیح i = 0, cmdarg = 0;
		حرف *filematch = تہی;

		اگر (carg > 1 && سطر[cursor-1] != ' ')
			filematch = argv[carg - 1];

		برائے (i = 1; i < carg; i++) {
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
		    complete_مطابقت(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	آزاد(سطر);
	واپس ret;
}
#اگر_ختم /* USE_LIBEDIT */

ساکن صحیح
interactive_loop(ساخت sftp_conn *conn, حرف *file1, حرف *file2)
{
	حرف *remote_راستہ;
	حرف *dir = تہی, *startdir = تہی;
	حرف cmd[2048];
	صحیح err, interactive;
	Edit_سطر *el = تہی;
#اگر_تعریف_شدہ USE_LIBEDIT
	ثابت حرف *editor;
	History *hl = تہی;
	HistEvent hev;
	خارجی حرف *__progname;
	ساخت complete_ctx complete_ctx;

	اگر (!batchmode && isatty(STDIN_FILENO)) {
		اگر ((el = el_init(__progname, stdin, stdout, stderr)) == تہی)
			fatal("Couldn't initialise editline");
		اگر ((hl = history_init()) == تہی)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_سیٹ(el, EL_HIST, history, hl);

		el_سیٹ(el, EL_PROMPT, prompt);
		el_سیٹ(el, EL_EDITOR, "emacs");
		el_سیٹ(el, EL_TERMINAL, تہی);
		el_سیٹ(el, EL_SIGNAL, 1);
		el_ماخذ(el, تہی);

		/* Tab Completion */
		el_سیٹ(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_راستہ;
		el_سیٹ(el, EL_CLIENTDATA, (خالی*)&complete_ctx);
		el_سیٹ(el, EL_BIND, "^I", "ftp-complete", تہی);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_سیٹ(el, EL_BIND, "\\e[1;5C", "em-next-word", تہی);
		el_سیٹ(el, EL_BIND, "\\e\\e[C", "em-next-word", تہی);
		el_سیٹ(el, EL_BIND, "\\e[1;5D", "ed-prev-word", تہی);
		el_سیٹ(el, EL_BIND, "\\e\\e[D", "ed-prev-word", تہی);
		/* make ^w match ksh behaviour */
		el_سیٹ(el, EL_BIND, "^w", "ed-delete-prev-word", تہی);

		/* el_source() may have changed EL_EDITOR to vi */
		اگر (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_سیٹ(el, EL_BIND, "^[", "vi-command-mode", تہی);
	}
#اگر_ختم /* USE_LIBEDIT */

	اگر ((remote_راستہ = sftp_realpath(conn, ".")) == تہی)
		fatal("Need cwd");
	startdir = xstrdup(remote_راستہ);

	اگر (file1 != تہی) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_راستہ);

		اگر (sftp_remote_is_dir(conn, dir) && file2 == تہی) {
			اگر (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, حجم cmd, "cd \"%s\"", dir);
			اگر (parse_dispatch_command(conn, cmd,
			    &remote_راستہ, startdir, 1, 0) != 0) {
				آزاد(dir);
				آزاد(startdir);
				آزاد(remote_راستہ);
				آزاد(conn);
				واپس (-1);
			}
		} ورنہ {
			err = process_get(conn, dir, file2, remote_راستہ, 0, 0,
			    global_aflag, 0);
			آزاد(dir);
			آزاد(startdir);
			آزاد(remote_راستہ);
			آزاد(conn);
			واپس (err);
		}
		آزاد(dir);
	}

	setvbuf(stdout, تہی, _IOLBF, 0);
	setvbuf(infile, تہی, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	برائے (;;) {
		ساخت sigaction sa;

		interrupted = 0;
		memset(&sa, 0, حجم(sa));
		sa.sa_handler = interactive ? read_مداخلت : killchild;
		اگر (sigaction(SIGINT, &sa, تہی) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			توڑو;
		}
		اگر (el == تہی) {
			اگر (interactive) {
				لکھو("sftp> ");
				fflush(stdout);
			}
			اگر (fgets(cmd, حجم(cmd), infile) == تہی) {
				اگر (interactive)
					لکھو("\n");
				اگر (interrupted)
					جاری;
				توڑو;
			}
		} ورنہ {
#اگر_تعریف_شدہ USE_LIBEDIT
			ثابت حرف *سطر;
			صحیح گنتی = 0;

			اگر ((سطر = el_gets(el, &گنتی)) == تہی ||
			    گنتی <= 0) {
				لکھو("\n");
				اگر (interrupted)
					جاری;
				توڑو;
			}
			history(hl, &hev, H_ENTER, سطر);
			اگر (strlcpy(cmd, سطر, حجم(cmd)) >= حجم(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				جاری;
			}
#اگر_ختم /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_مداخلت);

		err = parse_dispatch_command(conn, cmd, &remote_راستہ,
		    startdir, batchmode, !interactive && el == تہی);
		اگر (err != 0)
			توڑو;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	آزاد(remote_راستہ);
	آزاد(startdir);
	آزاد(conn);

#اگر_تعریف_شدہ USE_LIBEDIT
	اگر (hl != تہی)
		history_انتہا(hl);
	اگر (el != تہی)
		el_انتہا(el);
#اگر_ختم /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	واپس (err >= 0 ? 0 : -1);
}

ساکن خالی
connect_مقصد_server(حرف *راستہ, حرف **دلائل, صحیح *اندر, صحیح *برآمد)
{
	صحیح c_اندر, c_برآمد;
#اگر_تعریف_شدہ USE_PIPES
	صحیح pin[2], pout[2];

	اگر ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*اندر = pin[0];
	*برآمد = pout[1];
	c_اندر = pout[0];
	c_برآمد = pin[1];
#ورنہ /* USE_PIPES */
	صحیح inout[2];

	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*اندر = *برآمد = inout[0];
	c_اندر = c_برآمد = inout[1];
#اگر_ختم /* USE_PIPES */
	FD_CLOSEONEXEC(*اندر);
	FD_CLOSEONEXEC(*برآمد);

	اگر ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	ورنہ اگر (sshpid == 0) {
		اگر ((dup2(c_اندر, STDIN_FILENO) == -1) ||
		    (dup2(c_برآمد, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*اندر);
		close(*برآمد);
		close(c_اندر);
		close(c_برآمد);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(راستہ, دلائل);
		fprintf(stderr, "exec: %s: %s\n", راستہ, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_اندر);
	close(c_برآمد);
}

ساکن خالی
usage(خالی)
{
	خارجی حرف *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	باہر_نکلو(1);
}

صحیح
مین(صحیح argc, حرف **argv)
{
	صحیح r, اندر, برآمد, ch, err, tmp, پورٹ = -1, noisy = 0;
	حرف *host = تہی, *user, *cp, **cpp, *file2 = تہی;
	صحیح debug_level = 0;
	حرف *file1 = تہی, *sftp_server = تہی;
	حرف *ssh_پروگرام = راستہ_SSH_پروگرام, *sftp_براہ_راست = تہی;
	ثابت حرف *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist دلائل;
	خارجی صحیح optind;
	خارجی حرف *optarg;
	ساخت sftp_conn *conn;
	سائز_t copy_بفر_len = 0;
	سائز_t عدد_درخواستیں = 0;
	طویل طویل llv, حد_بندی_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&دلائل, '\0', حجم(دلائل));
	دلائل.list = تہی;
	addargs(&دلائل, "%s", ssh_پروگرام);
	addargs(&دلائل, "-oForwardX11 no");
	addargs(&دلائل, "-oPermitLocalCommand no");
	addargs(&دلائل, "-oClearAllForwardings yes");
	addargs(&دلائل, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	جب ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		انتخاب (ch) {
		/* Passed through to ssh(1) */
		حالت 'A':
		حالت '4':
		حالت '6':
		حالت 'C':
			addargs(&دلائل, "-%c", ch);
			توڑو;
		/* Passed through to ssh(1) with argument */
		حالت 'F':
		حالت 'J':
		حالت 'c':
		حالت 'i':
		حالت 'o':
			addargs(&دلائل, "-%c", ch);
			addargs(&دلائل, "%s", optarg);
			توڑو;
		حالت 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&دلائل, "-%c", ch);
			توڑو;
		حالت 'P':
			پورٹ = a2port(optarg);
			اگر (پورٹ <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			توڑو;
		حالت 'v':
			اگر (debug_level < 3) {
				addargs(&دلائل, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			توڑو;
		حالت '1':
			fatal("SSH protocol v.1 is no longer supported");
			توڑو;
		حالت '2':
			/* accept silently */
			توڑو;
		حالت 'a':
			global_aflag = 1;
			توڑو;
		حالت 'B':
			copy_بفر_len = strtol(optarg, &cp, 10);
			اگر (copy_بفر_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			توڑو;
		حالت 'b':
			اگر (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			اگر (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == تہی)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&دلائل, "-obatchmode yes");
			توڑو;
		حالت 'f':
			global_fflag = 1;
			توڑو;
		حالت 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			توڑو;
		حالت 'p':
			global_pflag = 1;
			توڑو;
		حالت 'D':
			sftp_براہ_راست = optarg;
			توڑو;
		حالت 'l':
			حد_بندی_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			اگر (errstr != تہی)
				usage();
			حد_بندی_kbps *= 1024; /* kbps */
			توڑو;
		حالت 'r':
			global_rflag = 1;
			توڑو;
		حالت 'R':
			عدد_درخواستیں = strtol(optarg, &cp, 10);
			اگر (عدد_درخواستیں == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			توڑو;
		حالت 's':
			sftp_server = optarg;
			توڑو;
		حالت 'S':
			ssh_پروگرام = optarg;
			replacearg(&دلائل, 0, "%s", ssh_پروگرام);
			توڑو;
		حالت 'X':
			/* Please keep in sync with ssh.c -X */
			اگر (لڑی_موازنہ(optarg, "buffer=", 7) == 0) {
				r = جائزہ_scaled(optarg + 7, &llv);
				اگر (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				اگر (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_بفر_len = (سائز_t)llv;
			} ورنہ اگر (لڑی_موازنہ(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				اگر (errstr != تہی) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				عدد_درخواستیں = (سائز_t)llv;
			} ورنہ {
				fatal("Invalid -X option");
			}
			توڑو;
		حالت 'h':
		طےشدہ:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&دلائل, "-oForwardAgent no");

	اگر (!isatty(STDERR_FILENO))
		showprogress = 0;

	اگر (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	اگر (sftp_براہ_راست == تہی) {
		اگر (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		انتخاب (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		حالت -1:
			usage();
			توڑو;
		حالت 0:
			اگر (tmp != -1)
				پورٹ = tmp;
			توڑو;
		طےشدہ:
			/* Try with user, host and path. */
			اگر (parse_user_host_راستہ(*argv, &user, &host,
			    &file1) == 0)
				توڑو;
			/* Try with user and host. */
			اگر (parse_user_host_پورٹ(*argv, &user, &host, تہی)
			    == 0)
				توڑو;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			توڑو;
		}
		file2 = *(argv + 1);

		اگر (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		اگر (پورٹ != -1)
			addargs(&دلائل, "-oPort %d", پورٹ);
		اگر (user != تہی) {
			addargs(&دلائل, "-l");
			addargs(&دلائل, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		اگر (sftp_server == تہی || strchr(sftp_server, '/') == تہی)
			addargs(&دلائل, "-s");

		addargs(&دلائل, "--");
		addargs(&دلائل, "%s", host);
		addargs(&دلائل, "%s", (sftp_server != تہی ?
		    sftp_server : "sftp"));

		connect_مقصد_server(ssh_پروگرام, دلائل.list, &اندر, &برآمد);
	} ورنہ {
		اگر ((r = argv_بانٹو(sftp_براہ_راست, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		اگر (cpp[0] == تہی)
			fatal("No sftp server specified via -D");
		connect_مقصد_server(cpp[0], cpp, &اندر, &برآمد);
		argv_free(cpp, tmp);
	}
	freeargs(&دلائل);

	conn = sftp_init(اندر, برآمد, copy_بفر_len, عدد_درخواستیں, حد_بندی_kbps);
	اگر (conn == تہی)
		fatal("Couldn't initialise connection to server");

	اگر (!quiet) {
		اگر (sftp_براہ_راست == تہی)
			fprintf(stderr, "Connected to %s.\n", host);
		ورنہ
			fprintf(stderr, "Attached to %s.\n", sftp_براہ_راست);
	}

	err = interactive_loop(conn, file1, file2);

#اگر !defined(USE_PIPES)
	shutdown(اندر, SHUT_RDWR);
	shutdown(برآمد, SHUT_RDWR);
#اگر_ختم

	close(اندر);
	close(برآمد);
	اگر (batchmode)
		fclose(infile);

	جب (waitpid(sshpid, تہی, 0) == -1 && sshpid > 1)
		اگر (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	باہر_نکلو(err == 0 ? 0 : 1);
}
