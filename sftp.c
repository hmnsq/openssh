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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/ioctl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/statvfs.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <glob.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <libgen.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOCALE_H
# include <locale.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBEDIT
#ਅਨ੍ਤਰ੍ਭਾਵ <histedit.h>
#ਨਹੀਂਤਾਂ
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ Edit_ਸਤਰ;
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-client.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
ਪੂਰਨ batchmode = 0;

/* PID of ssh transport process */
ਸਥਿਰ ਅਸਥਿਰ pid_t sshpid = -1;

/* Suppress diagnostic messages */
ਪੂਰਨ quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
ਪੂਰਨ showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
ਪੂਰਨ global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
ਪੂਰਨ global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
ਪੂਰਨ global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
ਪੂਰਨ global_fflag = 0;

/* SIGINT received during command processing */
ਅਸਥਿਰ sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
ਪੂਰਨ ਛਾਂਟੋ_flag;
glob_t *ਛਾਂਟੋ_glob;

/* Context used for commandline completion */
ਬਣਤਰ complete_ctx {
	ਬਣਤਰ sftp_conn *conn;
	ਅੱਖਰ **remote_pathp;
};

ਪੂਰਨ sftp_glob(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ,
    ਪੂਰਨ (*)(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ), glob_t *); /* proto for sftp-glob.c */

ਬਾਹਰੀ ਅੱਖਰ *__progname;

/* Separators for interactive commands */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WHITESPACE " \t\r\n"

/* ls flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_NAME_ਛਾਂਟੋ	0x0008	/* Sort by name (default) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_ਸਮਾਂ_ਛਾਂਟੋ	0x0010	/* Sort by mtime */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_ਮਾਪ_ਛਾਂਟੋ	0x0020	/* Sort by file size */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_ਉਲਟ_ਛਾਂਟੋ	0x0040	/* Reverse sort order */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਛਾਂਟੋ_FLAGS	(LS_NAME_ਛਾਂਟੋ|LS_ਸਮਾਂ_ਛਾਂਟੋ|LS_ਮਾਪ_ਛਾਂਟੋ)

/* Commands for interactive mode */
ਗਿਣਤੀ sftp_command {
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
	I_ਸੰਸਕਰਣ,
	I_ਤਰੱਕੀ,
};

ਬਣਤਰ CMD {
	ਅਚਲ ਅੱਖਰ *c;
	ਅਚਲ ਪੂਰਨ n;
	ਅਚਲ ਪੂਰਨ t;	/* Completion type for the first argument */
	ਅਚਲ ਪੂਰਨ t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NOARGS	0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ REMOTE	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ LOCAL	2

ਸਥਿਰ ਅਚਲ ਬਣਤਰ CMD cmds[] = {
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
	{ "progress",	I_ਤਰੱਕੀ,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_ਸੰਸਕਰਣ,	NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ ਨਿਰਾ,		-1,		-1,		-1	}
};

ਸਥਿਰ ਖਾਲੀ
killchild(ਪੂਰਨ signo)
{
	pid_t pid;

	pid = sshpid;
	ਜੇ (pid > 1) {
		kill(pid, SIGTERM);
		(ਖਾਲੀ)waitpid(pid, ਨਿਰਾ, 0);
	}

	_exit(1);
}

ਸਥਿਰ ਖਾਲੀ
suspchild(ਪੂਰਨ signo)
{
	ਪੂਰਨ save_errno = errno;
	ਜੇ (sshpid > 1) {
		kill(sshpid, signo);
		ਜਦੋਂ (waitpid(sshpid, ਨਿਰਾ, WUNTRACED) == -1 && errno == EINTR)
			ਜਾਰੀ;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ਸਥਿਰ ਖਾਲੀ
cmd_ਰੁਕਾਵਟ(ਪੂਰਨ signo)
{
	ਅਚਲ ਅੱਖਰ ਸੁਨੇਹਾ[] = "\rInterrupt  \n";
	ਪੂਰਨ olderrno = errno;

	(ਖਾਲੀ)ਲਿਖ(STDERR_FILENO, ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ) - 1);
	interrupted = 1;
	errno = olderrno;
}

ਸਥਿਰ ਖਾਲੀ
read_ਰੁਕਾਵਟ(ਪੂਰਨ signo)
{
	interrupted = 1;
}

ਸਥਿਰ ਖਾਲੀ
sigchld_handler(ਪੂਰਨ sig)
{
	ਪੂਰਨ save_errno = errno;
	pid_t pid;
	ਅਚਲ ਅੱਖਰ ਸੁਨੇਹਾ[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	ਜਦੋਂ ((pid = waitpid(sshpid, ਨਿਰਾ, WNOHANG)) == -1 && errno == EINTR)
		ਜਾਰੀ;
	ਜੇ (pid == sshpid) {
		ਜੇ (!quiet)
		    (ਖਾਲੀ)ਲਿਖ(STDERR_FILENO, ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

ਸਥਿਰ ਖਾਲੀ
help(ਖਾਲੀ)
{
	ਲਿਖੋ("Available commands:\n"
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

ਸਥਿਰ ਖਾਲੀ
local_do_shell(ਅਚਲ ਅੱਖਰ *ਦਲੀਲਾਂ)
{
	ਪੂਰਨ ਸਥਿਤੀ;
	ਅੱਖਰ *shell;
	pid_t pid;

	ਜੇ (!*ਦਲੀਲਾਂ)
		ਦਲੀਲਾਂ = ਨਿਰਾ;

	ਜੇ ((shell = getenv("SHELL")) == ਨਿਰਾ || *shell == '\0')
		shell = _PATH_BSHELL;

	ਜੇ ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	ਜੇ (pid == 0) {
		ਜੇ (ਦਲੀਲਾਂ) {
			debug3("Executing %s -c \"%s\"", shell, ਦਲੀਲਾਂ);
			execl(shell, shell, "-c", ਦਲੀਲਾਂ, (ਅੱਖਰ *)ਨਿਰਾ);
		} ਨਹੀਂਤਾਂ {
			debug3("Executing %s", shell);
			execl(shell, shell, (ਅੱਖਰ *)ਨਿਰਾ);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1)
		ਜੇ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ਜੇ (!WIFEXITED(ਸਥਿਤੀ))
		error("Shell exited abnormally");
	ਨਹੀਂਤਾਂ ਜੇ (WEXITSTATUS(ਸਥਿਤੀ))
		error("Shell exited with status %d", WEXITSTATUS(ਸਥਿਤੀ));
}

ਸਥਿਰ ਖਾਲੀ
local_do_ls(ਅਚਲ ਅੱਖਰ *ਦਲੀਲਾਂ)
{
	ਜੇ (!ਦਲੀਲਾਂ || !*ਦਲੀਲਾਂ)
		local_do_shell(ਰਸਤਾ_LS);
	ਨਹੀਂਤਾਂ {
		ਪੂਰਨ len = ਲੜੀ_ਲੰਬਾਈ(ਰਸਤਾ_LS " ") + ਲੜੀ_ਲੰਬਾਈ(ਦਲੀਲਾਂ) + 1;
		ਅੱਖਰ *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, ਰਸਤਾ_LS " %s", ਦਲੀਲਾਂ);
		local_do_shell(buf);
		ਮੁਕਤ(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
ਸਥਿਰ ਅੱਖਰ *
ਰਸਤਾ_strip(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *strip)
{
	ਮਾਪ_t len;

	ਜੇ (strip == ਨਿਰਾ || (len = ਲੜੀ_ਲੰਬਾਈ(strip)) == 0)
		ਵਾਪਸ (xstrdup(ਰਸਤਾ));

	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(ਰਸਤਾ, strip, len) == 0) {
		ਜੇ (strip[len - 1] != '/' && ਰਸਤਾ[len] == '/')
			len++;
		ਵਾਪਸ (xstrdup(ਰਸਤਾ + len));
	}

	ਵਾਪਸ (xstrdup(ਰਸਤਾ));
}

ਸਥਿਰ ਪੂਰਨ
parse_getput_flags(ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **argv, ਪੂਰਨ argc,
    ਪੂਰਨ *aflag, ਪੂਰਨ *fflag, ਪੂਰਨ *pflag, ਪੂਰਨ *rflag)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	ਜਦੋਂ ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'a':
			*aflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			*fflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
		ਹਾਲਤ 'P':
			*pflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
		ਹਾਲਤ 'R':
			*rflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਪੂਰਨ
parse_mkdir_flags(ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **argv, ਪੂਰਨ argc, ਪੂਰਨ *pflag)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	ਜਦੋਂ ((ch = getopt(argc, argv, "p")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'p':
			*pflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਪੂਰਨ
parse_link_flags(ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **argv, ਪੂਰਨ argc, ਪੂਰਨ *sflag)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	ਜਦੋਂ ((ch = getopt(argc, argv, "s")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 's':
			*sflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਪੂਰਨ
parse_rename_flags(ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **argv, ਪੂਰਨ argc, ਪੂਰਨ *lflag)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	ਜਦੋਂ ((ch = getopt(argc, argv, "l")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'l':
			*lflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਪੂਰਨ
parse_ls_flags(ਅੱਖਰ **argv, ਪੂਰਨ argc, ਪੂਰਨ *lflag)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_ਛਾਂਟੋ;
	ਜਦੋਂ ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			ਰੋਕੋ;
		ਹਾਲਤ 'S':
			*lflag &= ~ਛਾਂਟੋ_FLAGS;
			*lflag |= LS_ਮਾਪ_ਛਾਂਟੋ;
			ਰੋਕੋ;
		ਹਾਲਤ 'a':
			*lflag |= LS_SHOW_ALL;
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			*lflag &= ~ਛਾਂਟੋ_FLAGS;
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
			*lflag |= LS_SI_UNITS;
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			ਰੋਕੋ;
		ਹਾਲਤ 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
			*lflag |= LS_ਉਲਟ_ਛਾਂਟੋ;
			ਰੋਕੋ;
		ਹਾਲਤ 't':
			*lflag &= ~ਛਾਂਟੋ_FLAGS;
			*lflag |= LS_ਸਮਾਂ_ਛਾਂਟੋ;
			ਰੋਕੋ;
		ਮੂਲ:
			error("ls: Invalid flag -%c", optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਪੂਰਨ
parse_df_flags(ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **argv, ਪੂਰਨ argc, ਪੂਰਨ *hflag, ਪੂਰਨ *iflag)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	ਜਦੋਂ ((ch = getopt(argc, argv, "hi")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'h':
			*hflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'i':
			*iflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਪੂਰਨ
parse_ch_flags(ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **argv, ਪੂਰਨ argc, ਪੂਰਨ *hflag)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	ਜਦੋਂ ((ch = getopt(argc, argv, "h")) != -1) {
		ਚੋਣ (ch) {
		ਹਾਲਤ 'h':
			*hflag = 1;
			ਰੋਕੋ;
		ਮੂਲ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਪੂਰਨ
parse_no_flags(ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **argv, ਪੂਰਨ argc)
{
	ਬਾਹਰੀ ਪੂਰਨ opterr, optind, optopt, optreset;
	ਪੂਰਨ ch;

	optind = optreset = 1;
	opterr = 0;

	ਜਦੋਂ ((ch = getopt(argc, argv, "")) != -1) {
		ਚੋਣ (ch) {
		ਮੂਲ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ਵਾਪਸ -1;
		}
	}

	ਵਾਪਸ optind;
}

ਸਥਿਰ ਅੱਖਰ *
escape_glob(ਅਚਲ ਅੱਖਰ *s)
{
	ਮਾਪ_t i, o, len;
	ਅੱਖਰ *ret;

	len = ਲੜੀ_ਲੰਬਾਈ(s);
	ret = xcalloc(2, len + 1);
	ਲਈ (i = o = 0; i < len; i++) {
		ਜੇ (strchr("[]?*\\", s[i]) != ਨਿਰਾ)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	ਵਾਪਸ ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
ਸਥਿਰ ਅੱਖਰ *
make_absolute_pwd_glob(ਅੱਖਰ *p, ਅਚਲ ਅੱਖਰ *pwd)
{
	ਅੱਖਰ *ret, *escpwd;

	escpwd = escape_glob(pwd);
	ਜੇ (p == ਨਿਰਾ)
		ਵਾਪਸ escpwd;
	ret = sftp_make_absolute(p, escpwd);
	ਮੁਕਤ(escpwd);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
local_is_dir(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ stat sb;

	ਜੇ (stat(ਰਸਤਾ, &sb) == -1)
		ਵਾਪਸ 0;
	ਵਾਪਸ S_ISDIR(sb.st_mode);
}

ਸਥਿਰ ਪੂਰਨ
process_get(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *src, ਅਚਲ ਅੱਖਰ *dst,
    ਅਚਲ ਅੱਖਰ *pwd, ਪੂਰਨ pflag, ਪੂਰਨ rflag, ਪੂਰਨ resume, ਪੂਰਨ fflag)
{
	ਅੱਖਰ *filename, *abs_src = ਨਿਰਾ, *abs_dst = ਨਿਰਾ, *tmp = ਨਿਰਾ;
	glob_t g;
	ਪੂਰਨ i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, ਆਕਾਰ(g));

	debug3("Looking up %s", abs_src);
	ਜੇ ((r = sftp_glob(conn, abs_src, GLOB_MARK, ਨਿਰਾ, &g)) != 0) {
		ਜੇ (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} ਨਹੀਂਤਾਂ {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	ਜੇ (g.gl_matchc > 1 && dst != ਨਿਰਾ && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਲਈ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ਜੇ ((filename = basename(tmp)) == ਨਿਰਾ) {
			error("basename %s: %s", tmp, strerror(errno));
			ਮੁਕਤ(tmp);
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		ਜੇ (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		ਜੇ (g.gl_matchc == 1 && dst) {
			ਜੇ (local_is_dir(dst)) {
				abs_dst = sftp_ਰਸਤਾ_append(dst, filename);
			} ਨਹੀਂਤਾਂ {
				abs_dst = xstrdup(dst);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (dst) {
			abs_dst = sftp_ਰਸਤਾ_append(dst, filename);
		} ਨਹੀਂਤਾਂ {
			abs_dst = xstrdup(filename);
		}
		ਮੁਕਤ(tmp);

		resume |= global_aflag;
		ਜੇ (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ਨਹੀਂਤਾਂ ਜੇ (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		ਜੇ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ਜੇ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ਨਿਰਾ, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (sftp_download(conn, g.gl_pathv[i], abs_dst, ਨਿਰਾ,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		ਮੁਕਤ(abs_dst);
		abs_dst = ਨਿਰਾ;
	}

ਬਾਹਰਲਾ:
	ਮੁਕਤ(abs_src);
	globfree(&g);
	ਵਾਪਸ(err);
}

ਸਥਿਰ ਪੂਰਨ
process_put(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *src, ਅਚਲ ਅੱਖਰ *dst,
    ਅਚਲ ਅੱਖਰ *pwd, ਪੂਰਨ pflag, ਪੂਰਨ rflag, ਪੂਰਨ resume, ਪੂਰਨ fflag)
{
	ਅੱਖਰ *tmp_dst = ਨਿਰਾ;
	ਅੱਖਰ *abs_dst = ਨਿਰਾ;
	ਅੱਖਰ *tmp = ਨਿਰਾ, *filename = ਨਿਰਾ;
	glob_t g;
	ਪੂਰਨ err = 0;
	ਪੂਰਨ i, dst_is_dir = 1;
	ਬਣਤਰ stat sb;

	ਜੇ (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, ਆਕਾਰ(g));
	debug3("Looking up %s", src);
	ਜੇ (glob(src, GLOB_NOCHECK | GLOB_MARK, ਨਿਰਾ, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	ਜੇ (tmp_dst != ਨਿਰਾ)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	ਜੇ (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਲਈ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		ਜੇ (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			ਜਾਰੀ;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		ਜੇ ((filename = basename(tmp)) == ਨਿਰਾ) {
			error("basename %s: %s", tmp, strerror(errno));
			ਮੁਕਤ(tmp);
			err = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Special handling for source of '..' */
		ਜੇ (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		ਮੁਕਤ(abs_dst);
		abs_dst = ਨਿਰਾ;
		ਜੇ (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			ਜੇ (dst_is_dir)
				abs_dst = sftp_ਰਸਤਾ_append(tmp_dst, filename);
			ਨਹੀਂਤਾਂ
				abs_dst = xstrdup(tmp_dst);
		} ਨਹੀਂਤਾਂ ਜੇ (tmp_dst) {
			abs_dst = sftp_ਰਸਤਾ_append(tmp_dst, filename);
		} ਨਹੀਂਤਾਂ {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		ਮੁਕਤ(tmp);

		resume |= global_aflag;
		ਜੇ (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ਨਹੀਂਤਾਂ ਜੇ (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		ਜੇ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ਜੇ (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

ਬਾਹਰਲਾ:
	ਮੁਕਤ(abs_dst);
	ਮੁਕਤ(tmp_dst);
	globfree(&g);
	ਵਾਪਸ(err);
}

ਸਥਿਰ ਪੂਰਨ
sdirent_comp(ਅਚਲ ਖਾਲੀ *aa, ਅਚਲ ਖਾਲੀ *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	ਪੂਰਨ rmul = ਛਾਂਟੋ_flag & LS_ਉਲਟ_ਛਾਂਟੋ ? -1 : 1;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	ਜੇ (ਛਾਂਟੋ_flag & LS_NAME_ਛਾਂਟੋ)
		ਵਾਪਸ (rmul * strcmp(a->filename, b->filename));
	ਨਹੀਂਤਾਂ ਜੇ (ਛਾਂਟੋ_flag & LS_ਸਮਾਂ_ਛਾਂਟੋ)
		ਵਾਪਸ (rmul * NCMP(a->a.mtime, b->a.mtime));
	ਨਹੀਂਤਾਂ ਜੇ (ਛਾਂਟੋ_flag & LS_ਮਾਪ_ਛਾਂਟੋ)
		ਵਾਪਸ (rmul * NCMP(a->a.ਮਾਪ, b->a.ਮਾਪ));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
ਸਥਿਰ ਪੂਰਨ
do_ls_dir(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    ਅਚਲ ਅੱਖਰ *strip_ਰਸਤਾ, ਪੂਰਨ lflag)
{
	ਪੂਰਨ n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	ਜੇ ((n = sftp_readdir(conn, ਰਸਤਾ, &d)) != 0)
		ਵਾਪਸ (n);

	ਜੇ (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, ਚੌੜਾਈ = 80;
		ਬਣਤਰ winsize ws;
		ਅੱਖਰ *tmp;

		/* Count entries for sort and find longest filename */
		ਲਈ (n = 0; d[n] != ਨਿਰਾ; n++) {
			ਜੇ (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = ਵੱਧ_ਤੋਂ_ਵੱਧ(m, ਲੜੀ_ਲੰਬਾਈ(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = ਰਸਤਾ_strip(ਰਸਤਾ, strip_ਰਸਤਾ);
		m += ਲੜੀ_ਲੰਬਾਈ(tmp);
		ਮੁਕਤ(tmp);

		ਜੇ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			ਚੌੜਾਈ = ws.ws_ਖਾਨਾ;

		columns = ਚੌੜਾਈ / (m + 2);
		columns = ਵੱਧ_ਤੋਂ_ਵੱਧ(columns, 1);
		colspace = ਚੌੜਾਈ / columns;
		colspace = MINIMUM(colspace, ਚੌੜਾਈ);
	}

	ਜੇ (lflag & ਛਾਂਟੋ_FLAGS) {
		ਲਈ (n = 0; d[n] != ਨਿਰਾ; n++)
			;	/* count entries */
		ਛਾਂਟੋ_flag = lflag & (ਛਾਂਟੋ_FLAGS|LS_ਉਲਟ_ਛਾਂਟੋ);
		qsort(d, n, ਆਕਾਰ(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	ਲਈ (n = 0; d[n] != ਨਿਰਾ && !interrupted; n++) {
		ਅੱਖਰ *tmp, *fname;

		ਜੇ (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			ਜਾਰੀ;

		tmp = sftp_ਰਸਤਾ_append(ਰਸਤਾ, d[n]->filename);
		fname = ਰਸਤਾ_strip(tmp, strip_ਰਸਤਾ);
		ਮੁਕਤ(tmp);

		ਜੇ (lflag & LS_LONG_VIEW) {
			ਜੇ ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				ਅੱਖਰ *lname;
				ਬਣਤਰ stat sb;
				ਅਚਲ ਅੱਖਰ *user = ਨਿਰਾ, *ਸਮੂਹ = ਨਿਰਾ;

				memset(&sb, 0, ਆਕਾਰ(sb));
				attrib_ਮੰਜ਼ਿਲ_stat(&d[n]->a, &sb);
				ਜੇ ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					ਸਮੂਹ = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, ਸਮੂਹ);
				mprintf("%s\n", lname);
				ਮੁਕਤ(lname);
			} ਨਹੀਂਤਾਂ
				mprintf("%s\n", d[n]->longname);
		} ਨਹੀਂਤਾਂ {
			mprintf("%-*s", colspace, fname);
			ਜੇ (c >= columns) {
				ਲਿਖੋ("\n");
				c = 1;
			} ਨਹੀਂਤਾਂ
				c++;
		}

		ਮੁਕਤ(fname);
	}

	ਜੇ (!(lflag & LS_LONG_VIEW) && (c != 1))
		ਲਿਖੋ("\n");

	sftp_free_dirents(d);
	ਵਾਪਸ (0);
}

ਸਥਿਰ ਪੂਰਨ
sglob_comp(ਅਚਲ ਖਾਲੀ *aa, ਅਚਲ ਖਾਲੀ *bb)
{
	u_int a = *(ਅਚਲ u_int *)aa;
	u_int b = *(ਅਚਲ u_int *)bb;
	ਅਚਲ ਅੱਖਰ *ap = ਛਾਂਟੋ_glob->gl_pathv[a];
	ਅਚਲ ਅੱਖਰ *bp = ਛਾਂਟੋ_glob->gl_pathv[b];
	ਅਚਲ ਬਣਤਰ stat *as = ਛਾਂਟੋ_glob->gl_statv[a];
	ਅਚਲ ਬਣਤਰ stat *bs = ਛਾਂਟੋ_glob->gl_statv[b];
	ਪੂਰਨ rmul = ਛਾਂਟੋ_flag & LS_ਉਲਟ_ਛਾਂਟੋ ? -1 : 1;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	ਜੇ (as == ਨਿਰਾ || bs == ਨਿਰਾ)
		ਵਾਪਸ (as == bs) ? 0 : (as == ਨਿਰਾ ? rmul : -rmul);
	ਜੇ (ਛਾਂਟੋ_flag & LS_NAME_ਛਾਂਟੋ)
		ਵਾਪਸ (rmul * strcmp(ap, bp));
	ਨਹੀਂਤਾਂ ਜੇ (ਛਾਂਟੋ_flag & LS_ਸਮਾਂ_ਛਾਂਟੋ) {
#ਜੇ defined(HAVE_STRUCT_STAT_ST_MTIM)
		ਜੇ (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			ਵਾਪਸ 0;
		ਵਾਪਸ timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#ਜਾਂਜੇ defined(HAVE_STRUCT_STAT_ST_MTIME)
		ਵਾਪਸ (rmul * NCMP(as->st_mtime, bs->st_mtime));
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ rmul * 1;
#ਜੇ_ਅੰਤ
	} ਨਹੀਂਤਾਂ ਜੇ (ਛਾਂਟੋ_flag & LS_ਮਾਪ_ਛਾਂਟੋ)
		ਵਾਪਸ (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
ਸਥਿਰ ਪੂਰਨ
do_globbed_ls(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
    ਅਚਲ ਅੱਖਰ *strip_ਰਸਤਾ, ਪੂਰਨ lflag)
{
	ਅੱਖਰ *fname, *lname;
	glob_t g;
	ਪੂਰਨ err, r;
	ਬਣਤਰ winsize ws;
	u_int i, j, nentries, *indices = ਨਿਰਾ, c = 1;
	u_int colspace = 0, columns = 1, m = 0, ਚੌੜਾਈ = 80;

	memset(&g, 0, ਆਕਾਰ(g));

	ਜੇ ((r = sftp_glob(conn, ਰਸਤਾ,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ਨਿਰਾ, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		ਜੇ (g.gl_pathc)
			globfree(&g);
		ਜੇ (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", ਰਸਤਾ);
		} ਨਹੀਂਤਾਂ {
			error("Can't ls: \"%s\" not found", ਰਸਤਾ);
		}
		ਵਾਪਸ -1;
	}

	ਜੇ (interrupted)
		ਜਾਓ ਬਾਹਰਲਾ;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	ਜੇ (g.gl_matchc == 1 && g.gl_statv[0] != ਨਿਰਾ &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_ਰਸਤਾ, lflag);
		globfree(&g);
		ਵਾਪਸ err;
	}

	ਜੇ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		ਚੌੜਾਈ = ws.ws_ਖਾਨਾ;

	ਜੇ (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		ਲਈ (i = 0; g.gl_pathv[i]; i++)
			m = ਵੱਧ_ਤੋਂ_ਵੱਧ(m, ਲੜੀ_ਲੰਬਾਈ(g.gl_pathv[i]));

		columns = ਚੌੜਾਈ / (m + 2);
		columns = ਵੱਧ_ਤੋਂ_ਵੱਧ(columns, 1);
		colspace = ਚੌੜਾਈ / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	ਲਈ (nentries = 0; g.gl_pathv[nentries] != ਨਿਰਾ; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, ਆਕਾਰ(*indices));
	ਲਈ (i = 0; i < nentries; i++)
		indices[i] = i;

	ਜੇ (lflag & ਛਾਂਟੋ_FLAGS) {
		ਛਾਂਟੋ_glob = &g;
		ਛਾਂਟੋ_flag = lflag & (ਛਾਂਟੋ_FLAGS|LS_ਉਲਟ_ਛਾਂਟੋ);
		qsort(indices, nentries, ਆਕਾਰ(*indices), sglob_comp);
		ਛਾਂਟੋ_glob = ਨਿਰਾ;
	}

	get_remote_user_groups_from_glob(conn, &g);
	ਲਈ (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = ਰਸਤਾ_strip(g.gl_pathv[i], strip_ਰਸਤਾ);
		ਜੇ (lflag & LS_LONG_VIEW) {
			ਅਚਲ ਅੱਖਰ *user = ਨਿਰਾ, *ਸਮੂਹ = ਨਿਰਾ;

			ਜੇ (g.gl_statv[i] == ਨਿਰਾ) {
				error("no stat information for %s", fname);
				ਮੁਕਤ(fname);
				ਜਾਰੀ;
			}
			ਜੇ ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				ਸਮੂਹ = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, ਸਮੂਹ);
			mprintf("%s\n", lname);
			ਮੁਕਤ(lname);
		} ਨਹੀਂਤਾਂ {
			mprintf("%-*s", colspace, fname);
			ਜੇ (c >= columns) {
				ਲਿਖੋ("\n");
				c = 1;
			} ਨਹੀਂਤਾਂ
				c++;
		}
		ਮੁਕਤ(fname);
	}

	ਜੇ (!(lflag & LS_LONG_VIEW) && (c != 1))
		ਲਿਖੋ("\n");

 ਬਾਹਰਲਾ:
	ਜੇ (g.gl_pathc)
		globfree(&g);
	ਮੁਕਤ(indices);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
do_df(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ hflag, ਪੂਰਨ iflag)
{
	ਬਣਤਰ sftp_statvfs st;
	ਅੱਖਰ s_ਵਰਤਿਆ[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	ਅੱਖਰ s_ਜੜ੍ਹ[FMT_SCALED_STRSIZE], s_ਕੁੱਲ[FMT_SCALED_STRSIZE];
	ਅੱਖਰ s_icapacity[16], s_dcapacity[16];

	ਜੇ (sftp_statvfs(conn, ਰਸਤਾ, &st, 1) == -1)
		ਵਾਪਸ -1;
	ਜੇ (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", ਆਕਾਰ(s_icapacity));
	ਨਹੀਂਤਾਂ {
		snprintf(s_icapacity, ਆਕਾਰ(s_icapacity), "%3llu%%",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	ਜੇ (st.f_ਖੰਡਾਂ == 0)
		strlcpy(s_dcapacity, "ERR", ਆਕਾਰ(s_dcapacity));
	ਨਹੀਂਤਾਂ {
		snprintf(s_dcapacity, ਆਕਾਰ(s_dcapacity), "%3llu%%",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)(100 * (st.f_ਖੰਡਾਂ - st.f_bfree) /
		    st.f_ਖੰਡਾਂ));
	}
	ਜੇ (iflag) {
		ਲਿਖੋ("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		ਲਿਖੋ("%11llu %11llu %11llu %11llu         %s\n",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)st.f_files,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)(st.f_files - st.f_ffree),
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)st.f_favail,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)st.f_ffree, s_icapacity);
	} ਨਹੀਂਤਾਂ ਜੇ (hflag) {
		strlcpy(s_ਵਰਤਿਆ, "error", ਆਕਾਰ(s_ਵਰਤਿਆ));
		strlcpy(s_avail, "error", ਆਕਾਰ(s_avail));
		strlcpy(s_ਜੜ੍ਹ, "error", ਆਕਾਰ(s_ਜੜ੍ਹ));
		strlcpy(s_ਕੁੱਲ, "error", ਆਕਾਰ(s_ਕੁੱਲ));
		fmt_scaled((st.f_ਖੰਡਾਂ - st.f_bfree) * st.f_frsize, s_ਵਰਤਿਆ);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_ਜੜ੍ਹ);
		fmt_scaled(st.f_ਖੰਡਾਂ * st.f_frsize, s_ਕੁੱਲ);
		ਲਿਖੋ("    Size     Used    Avail   (root)    %%Capacity\n");
		ਲਿਖੋ("%7sB %7sB %7sB %7sB         %s\n",
		    s_ਕੁੱਲ, s_ਵਰਤਿਆ, s_avail, s_ਜੜ੍ਹ, s_dcapacity);
	} ਨਹੀਂਤਾਂ {
		ਲਿਖੋ("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		ਲਿਖੋ("%12llu %12llu %12llu %12llu         %s\n",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)(st.f_frsize * st.f_ਖੰਡਾਂ / 1024),
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)(st.f_frsize *
		    (st.f_ਖੰਡਾਂ - st.f_bfree) / 1024),
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)(st.f_frsize * st.f_bavail / 1024),
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	ਵਾਪਸ 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
ਸਥਿਰ ਖਾਲੀ
undo_glob_escape(ਅੱਖਰ *s)
{
	ਮਾਪ_t i, j;

	ਲਈ (i = j = 0;;) {
		ਜੇ (s[i] == '\0') {
			s[j] = '\0';
			ਵਾਪਸ;
		}
		ਜੇ (s[i] != '\\') {
			s[j++] = s[i++];
			ਜਾਰੀ;
		}
		/* s[i] == '\\' */
		++i;
		ਚੋਣ (s[i]) {
		ਹਾਲਤ '?':
		ਹਾਲਤ '[':
		ਹਾਲਤ '*':
		ਹਾਲਤ '\\':
			s[j++] = s[i++];
			ਰੋਕੋ;
		ਹਾਲਤ '\0':
			s[j++] = '\\';
			s[j] = '\0';
			ਵਾਪਸ;
		ਮੂਲ:
			s[j++] = '\\';
			s[j++] = s[i++];
			ਰੋਕੋ;
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
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAXARGS		128
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAXARGLEN	8192
ਸਥਿਰ ਅੱਖਰ **
makeargv(ਅਚਲ ਅੱਖਰ *arg, ਪੂਰਨ *argcp, ਪੂਰਨ sloppy, ਅੱਖਰ *lastquote,
    u_int *terminated)
{
	ਪੂਰਨ argc, quot;
	ਮਾਪ_t i, j;
	ਸਥਿਰ ਅੱਖਰ argvs[MAXARGLEN];
	ਸਥਿਰ ਅੱਖਰ *argv[MAXARGS + 1];
	ਗਿਣਤੀ { MA_ਸ਼ੁਰੂ, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(arg) > ਆਕਾਰ(argvs) - 1) {
 ਦਲੀਲਾਂ_too_longs:
		error("string too long");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (terminated != ਨਿਰਾ)
		*terminated = 1;
	ਜੇ (lastquote != ਨਿਰਾ)
		*lastquote = '\0';
	state = MA_ਸ਼ੁਰੂ;
	i = j = 0;
	ਲਈ (;;) {
		ਜੇ ((ਮਾਪ_t)argc >= ਆਕਾਰ(argv) / ਆਕਾਰ(*argv)){
			error("Too many arguments.");
			ਵਾਪਸ ਨਿਰਾ;
		}
		ਜੇ (ਖਾਲੀ_ਥਾਂ_ਹੈ((ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ)arg[i])) {
			ਜੇ (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_ਸ਼ੁਰੂ;
			} ਨਹੀਂਤਾਂ ਜੇ (state != MA_ਸ਼ੁਰੂ)
				argvs[j++] = arg[i];
		} ਨਹੀਂਤਾਂ ਜੇ (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			ਜੇ (state == MA_ਸ਼ੁਰੂ) {
				argv[argc] = argvs + j;
				state = q;
				ਜੇ (lastquote != ਨਿਰਾ)
					*lastquote = arg[i];
			} ਨਹੀਂਤਾਂ ਜੇ (state == MA_UNQUOTED)
				state = q;
			ਨਹੀਂਤਾਂ ਜੇ (state == q)
				state = MA_UNQUOTED;
			ਨਹੀਂਤਾਂ
				argvs[j++] = arg[i];
		} ਨਹੀਂਤਾਂ ਜੇ (arg[i] == '\\') {
			ਜੇ (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				ਜੇ (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} ਨਹੀਂਤਾਂ ਜੇ (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					ਜੇ (j >= ਆਕਾਰ(argvs) - 5)
						ਜਾਓ ਦਲੀਲਾਂ_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} ਨਹੀਂਤਾਂ {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} ਨਹੀਂਤਾਂ {
				ਜੇ (state == MA_ਸ਼ੁਰੂ) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					ਜੇ (lastquote != ਨਿਰਾ)
						*lastquote = '\0';
				}
				ਜੇ (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} ਨਹੀਂਤਾਂ {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					ਜੇ (arg[i] == '\0')
						ਜਾਓ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} ਨਹੀਂਤਾਂ ਜੇ (arg[i] == '#') {
			ਜੇ (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			ਨਹੀਂਤਾਂ
				ਜਾਓ string_ਪੂਰਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (arg[i] == '\0') {
			ਜੇ (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				ਜੇ (sloppy) {
					state = MA_UNQUOTED;
					ਜੇ (terminated != ਨਿਰਾ)
						*terminated = 0;
					ਜਾਓ string_ਪੂਰਾ;
				}
				error("Unterminated quoted argument");
				ਵਾਪਸ ਨਿਰਾ;
			}
 string_ਪੂਰਾ:
			ਜੇ (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			ਰੋਕੋ;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (state == MA_ਸ਼ੁਰੂ) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				ਜੇ (lastquote != ਨਿਰਾ)
					*lastquote = '\0';
			}
			ਜੇ ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				ਜੇ (j >= ਆਕਾਰ(argvs) - 3)
					ਜਾਓ ਦਲੀਲਾਂ_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} ਨਹੀਂਤਾਂ
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	ਵਾਪਸ argv;
}

ਸਥਿਰ ਪੂਰਨ
parse_ਦਲੀਲਾਂ(ਅਚਲ ਅੱਖਰ **cpp, ਪੂਰਨ *ignore_errors, ਪੂਰਨ *disable_echo, ਪੂਰਨ *aflag,
	  ਪੂਰਨ *fflag, ਪੂਰਨ *hflag, ਪੂਰਨ *iflag, ਪੂਰਨ *lflag, ਪੂਰਨ *pflag,
	  ਪੂਰਨ *rflag, ਪੂਰਨ *sflag,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *n_arg, ਅੱਖਰ **path1, ਅੱਖਰ **path2)
{
	ਅਚਲ ਅੱਖਰ *cmd, *cp = *cpp;
	ਅੱਖਰ *cp2, **argv;
	ਪੂਰਨ ਅਧਾਰ = 0;
	ਲੰਮਾ ਲੰਮਾ ll;
	ਪੂਰਨ path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	ਲਈ (;*cp != '\0'; cp++) {
		ਜੇ (*cp == '-') {
			*ignore_errors = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (*cp == '@') {
			*disable_echo = 1;
		} ਨਹੀਂਤਾਂ {
			/* all other characters terminate prefix processing */
			ਰੋਕੋ;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	ਜੇ (*cp == '\0' || *cp == '#')
		ਵਾਪਸ (0);

	ਜੇ ((argv = makeargv(cp, &argc, 0, ਨਿਰਾ, ਨਿਰਾ)) == ਨਿਰਾ)
		ਵਾਪਸ -1;

	/* Figure out which command we have */
	ਲਈ (i = 0; cmds[i].c != ਨਿਰਾ; i++) {
		ਜੇ (argv[0] != ਨਿਰਾ && strcasecmp(cmds[i].c, argv[0]) == 0)
			ਰੋਕੋ;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	ਜੇ (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} ਨਹੀਂਤਾਂ ਜੇ (cmdnum == -1) {
		error("Invalid command.");
		ਵਾਪਸ -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ਨਿਰਾ;
	optidx = 1;
	ਚੋਣ (cmdnum) {
	ਹਾਲਤ I_GET:
	ਹਾਲਤ I_REGET:
	ਹਾਲਤ I_REPUT:
	ਹਾਲਤ I_PUT:
		ਜੇ ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			ਵਾਪਸ -1;
		/* Get first pathname (mandatory) */
		ਜੇ (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			ਵਾਪਸ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		ਜੇ (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		ਰੋਕੋ;
	ਹਾਲਤ I_LINK:
		ਜੇ ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			ਵਾਪਸ -1;
		ਜਾਓ parse_two_paths;
	ਹਾਲਤ I_COPY:
		ਜੇ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ਵਾਪਸ -1;
		ਜਾਓ parse_two_paths;
	ਹਾਲਤ I_RENAME:
		ਜੇ ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			ਵਾਪਸ -1;
		ਜਾਓ parse_two_paths;
	ਹਾਲਤ I_SYMLINK:
		ਜੇ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ਵਾਪਸ -1;
 parse_two_paths:
		ਜੇ (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			ਵਾਪਸ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		ਰੋਕੋ;
	ਹਾਲਤ I_MKDIR:
	ਹਾਲਤ I_LMKDIR:
		ਜੇ ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			ਵਾਪਸ -1;
		path1_mandatory = 1;
		ਜਾਓ parse_one_ਰਸਤਾ;
	ਹਾਲਤ I_RM:
	ਹਾਲਤ I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	ਹਾਲਤ I_CHDIR:
	ਹਾਲਤ I_LCHDIR:
		ਜੇ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ਵਾਪਸ -1;
 parse_one_ਰਸਤਾ:
		/* Get pathname (mandatory) */
		ਜੇ (argc - optidx < 1) {
			ਜੇ (!path1_mandatory)
				ਰੋਕੋ; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			ਵਾਪਸ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		ਜੇ (cmdnum != I_RM)
			undo_glob_escape(*path1);
		ਰੋਕੋ;
	ਹਾਲਤ I_DF:
		ਜੇ ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			ਵਾਪਸ -1;
		/* Default to current directory if no path specified */
		ਜੇ (argc - optidx < 1)
			*path1 = ਨਿਰਾ;
		ਨਹੀਂਤਾਂ {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		ਰੋਕੋ;
	ਹਾਲਤ I_LS:
		ਜੇ ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			ਵਾਪਸ(-1);
		/* Path is optional */
		ਜੇ (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		ਰੋਕੋ;
	ਹਾਲਤ I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + ਲੜੀ_ਲੰਬਾਈ(cmd) + strspn(cp, WHITESPACE);
	ਹਾਲਤ I_SHELL:
		/* Uses the rest of the line */
		ਰੋਕੋ;
	ਹਾਲਤ I_LUMASK:
	ਹਾਲਤ I_CHMOD:
		ਅਧਾਰ = 8;
		/* FALLTHROUGH */
	ਹਾਲਤ I_CHOWN:
	ਹਾਲਤ I_CHGRP:
		ਜੇ ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			ਵਾਪਸ -1;
		/* Get numeric arg (mandatory) */
		ਜੇ (argc - optidx < 1)
			ਜਾਓ need_ਅੰਕ_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, ਅਧਾਰ);
		ਜੇ (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_ਅੰਕ_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			ਵਾਪਸ -1;
		}
		*n_arg = ll;
		ਜੇ (cmdnum == I_LUMASK)
			ਰੋਕੋ;
		/* Get pathname (mandatory) */
		ਜੇ (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			ਵਾਪਸ -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		ਰੋਕੋ;
	ਹਾਲਤ I_QUIT:
	ਹਾਲਤ I_PWD:
	ਹਾਲਤ I_LPWD:
	ਹਾਲਤ I_HELP:
	ਹਾਲਤ I_ਸੰਸਕਰਣ:
	ਹਾਲਤ I_ਤਰੱਕੀ:
		ਜੇ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ਵਾਪਸ -1;
		ਰੋਕੋ;
	ਮੂਲ:
		fatal("Command not implemented");
	}

	*cpp = cp;
	ਵਾਪਸ(cmdnum);
}

ਸਥਿਰ ਪੂਰਨ
parse_dispatch_command(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *cmd, ਅੱਖਰ **pwd,
    ਅਚਲ ਅੱਖਰ *startdir, ਪੂਰਨ err_abort, ਪੂਰਨ echo_command)
{
	ਅਚਲ ਅੱਖਰ *ocmd = cmd;
	ਅੱਖਰ *path1, *path2, *tmp;
	ਪੂਰਨ ignore_errors = 0, disable_echo = 1;
	ਪੂਰਨ aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	ਪੂਰਨ lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	ਪੂਰਨ cmdnum, i;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ n_arg = 0;
	Attrib a, aa;
	ਅੱਖਰ ਰਸਤਾ_buf[PATH_MAX];
	ਪੂਰਨ err = 0;
	glob_t g;

	path1 = path2 = ਨਿਰਾ;
	cmdnum = parse_ਦਲੀਲਾਂ(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	ਜੇ (ignore_errors != 0)
		err_abort = 0;

	ਜੇ (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, ਆਕਾਰ(g));

	/* Perform command */
	ਚੋਣ (cmdnum) {
	ਹਾਲਤ 0:
		/* Blank line */
		ਰੋਕੋ;
	ਹਾਲਤ -1:
		/* Unrecognized command */
		err = -1;
		ਰੋਕੋ;
	ਹਾਲਤ I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	ਹਾਲਤ I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ਰੋਕੋ;
	ਹਾਲਤ I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	ਹਾਲਤ I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ਰੋਕੋ;
	ਹਾਲਤ I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		ਰੋਕੋ;
	ਹਾਲਤ I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		ਰੋਕੋ;
	ਹਾਲਤ I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	ਹਾਲਤ I_LINK:
		ਜੇ (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		ਰੋਕੋ;
	ਹਾਲਤ I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ਨਿਰਾ, &g);
		ਲਈ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ਜੇ (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			ਜੇ (err != 0 && err_abort)
				ਰੋਕੋ;
		}
		ਰੋਕੋ;
	ਹਾਲਤ I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		ਜੇ (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		ਨਹੀਂਤਾਂ
			err = sftp_mkdir(conn, path1, &a, 1);
		ਰੋਕੋ;
	ਹਾਲਤ I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		ਰੋਕੋ;
	ਹਾਲਤ I_CHDIR:
		ਜੇ (path1 == ਨਿਰਾ || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		ਜੇ ((tmp = sftp_realpath(conn, path1)) == ਨਿਰਾ) {
			err = 1;
			ਰੋਕੋ;
		}
		ਜੇ (sftp_stat(conn, tmp, 0, &aa) != 0) {
			ਮੁਕਤ(tmp);
			err = 1;
			ਰੋਕੋ;
		}
		ਜੇ (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			ਮੁਕਤ(tmp);
			err = 1;
			ਰੋਕੋ;
		}
		ਜੇ (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			ਮੁਕਤ(tmp);
			err = 1;
			ਰੋਕੋ;
		}
		ਮੁਕਤ(*pwd);
		*pwd = tmp;
		ਰੋਕੋ;
	ਹਾਲਤ I_LS:
		ਜੇ (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			ਰੋਕੋ;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ਨਿਰਾ;
		ਜੇ (!ਰਸਤਾ_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		ਰੋਕੋ;
	ਹਾਲਤ I_DF:
		/* Default to current directory if no path specified */
		ਜੇ (path1 == ਨਿਰਾ)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		ਰੋਕੋ;
	ਹਾਲਤ I_LCHDIR:
		ਜੇ (path1 == ਨਿਰਾ || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		ਮੁਕਤ(path1);
		path1 = tmp;
		ਜੇ (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ਰੋਕੋ;
	ਹਾਲਤ I_LMKDIR:
		ਜੇ (pflag) {
			ਜੇ (mkdir_ਰਸਤਾ(path1, 0777) != 0)
				err = 1;
			ਰੋਕੋ;
		}
		ਜੇ (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ਰੋਕੋ;
	ਹਾਲਤ I_LLS:
		local_do_ls(cmd);
		ਰੋਕੋ;
	ਹਾਲਤ I_SHELL:
		local_do_shell(cmd);
		ਰੋਕੋ;
	ਹਾਲਤ I_LUMASK:
		umask(n_arg);
		ਲਿਖੋ("Local umask: %03lo\n", n_arg);
		ਰੋਕੋ;
	ਹਾਲਤ I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ਨਿਰਾ, &g);
		ਲਈ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ਜੇ (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			ਜੇ (err != 0 && err_abort)
				ਰੋਕੋ;
		}
		ਰੋਕੋ;
	ਹਾਲਤ I_CHOWN:
	ਹਾਲਤ I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ਨਿਰਾ, &g);
		ਲਈ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ਜੇ ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				ਜੇ (err_abort) {
					err = -1;
					ਰੋਕੋ;
				} ਨਹੀਂਤਾਂ
					ਜਾਰੀ;
			}
			ਜੇ (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				ਜੇ (err_abort) {
					err = -1;
					ਰੋਕੋ;
				} ਨਹੀਂਤਾਂ
					ਜਾਰੀ;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			ਜੇ (cmdnum == I_CHOWN) {
				ਜੇ (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} ਨਹੀਂਤਾਂ {
				ਜੇ (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			ਜੇ (err != 0 && err_abort)
				ਰੋਕੋ;
		}
		ਰੋਕੋ;
	ਹਾਲਤ I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		ਰੋਕੋ;
	ਹਾਲਤ I_LPWD:
		ਜੇ (!getcwd(ਰਸਤਾ_buf, ਆਕਾਰ(ਰਸਤਾ_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			ਰੋਕੋ;
		}
		mprintf("Local working directory: %s\n", ਰਸਤਾ_buf);
		ਰੋਕੋ;
	ਹਾਲਤ I_QUIT:
		/* Processed below */
		ਰੋਕੋ;
	ਹਾਲਤ I_HELP:
		help();
		ਰੋਕੋ;
	ਹਾਲਤ I_ਸੰਸਕਰਣ:
		ਲਿਖੋ("SFTP protocol version %u\n", sftp_proto_ਸੰਸਕਰਣ(conn));
		ਰੋਕੋ;
	ਹਾਲਤ I_ਤਰੱਕੀ:
		showprogress = !showprogress;
		ਜੇ (showprogress)
			ਲਿਖੋ("Progress meter enabled\n");
		ਨਹੀਂਤਾਂ
			ਲਿਖੋ("Progress meter disabled\n");
		ਰੋਕੋ;
	ਮੂਲ:
		fatal("%d is not implemented", cmdnum);
	}

	ਜੇ (g.gl_pathc)
		globfree(&g);
	ਮੁਕਤ(path1);
	ਮੁਕਤ(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	ਜੇ (err_abort && err != 0)
		ਵਾਪਸ (-1);
	ਨਹੀਂਤਾਂ ਜੇ (cmdnum == I_QUIT)
		ਵਾਪਸ (1);

	ਵਾਪਸ (0);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBEDIT
ਸਥਿਰ ਅੱਖਰ *
prompt(Edit_ਸਤਰ *el)
{
	ਵਾਪਸ ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
ਸਥਿਰ ਖਾਲੀ
complete_display(ਅੱਖਰ **list, u_int len)
{
	u_int y, m = 0, ਚੌੜਾਈ = 80, columns = 1, colspace = 0, llen;
	ਬਣਤਰ winsize ws;
	ਅੱਖਰ *tmp;

	/* Count entries for sort and find longest */
	ਲਈ (y = 0; list[y]; y++)
		m = ਵੱਧ_ਤੋਂ_ਵੱਧ(m, ਲੜੀ_ਲੰਬਾਈ(list[y]));

	ਜੇ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		ਚੌੜਾਈ = ws.ws_ਖਾਨਾ;

	m = m > len ? m - len : 0;
	columns = ਚੌੜਾਈ / (m + 2);
	columns = ਵੱਧ_ਤੋਂ_ਵੱਧ(columns, 1);
	colspace = ਚੌੜਾਈ / columns;
	colspace = MINIMUM(colspace, ਚੌੜਾਈ);

	ਲਿਖੋ("\n");
	m = 1;
	ਲਈ (y = 0; list[y]; y++) {
		llen = ਲੜੀ_ਲੰਬਾਈ(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		ਜੇ (m >= columns) {
			ਲਿਖੋ("\n");
			m = 1;
		} ਨਹੀਂਤਾਂ
			m++;
	}
	ਲਿਖੋ("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
ਸਥਿਰ ਅੱਖਰ *
complete_ambiguous(ਅਚਲ ਅੱਖਰ *ਸ਼ਬਦ_2, ਅੱਖਰ **list, ਮਾਪ_t ਗਿਣਤੀ_2)
{
	ਮਾਪ_t i, j, matchlen;
	ਅੱਖਰ *tmp;
	ਪੂਰਨ len;

	ਜੇ (ਸ਼ਬਦ_2 == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	ਜੇ (ਗਿਣਤੀ_2 == 0)
		ਵਾਪਸ xstrdup(ਸ਼ਬਦ_2); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = ਲੜੀ_ਲੰਬਾਈ(list[0]);
	ਲਈ (i = 1; i < ਗਿਣਤੀ_2 && list[i] != ਨਿਰਾ; i++) {
		ਲਈ (j = 0; j < matchlen; j++)
			ਜੇ (list[0][j] != list[i][j])
				ਰੋਕੋ;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ਨਿਰਾ, 0);
	ਲਈ (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		ਜੇ (len <= 0 || i + (ਮਾਪ_t)len > matchlen)
			ਰੋਕੋ;
		i += (ਮਾਪ_t)len;
	}
	/* If so, truncate */
	ਜੇ (i < matchlen)
		matchlen = i;

	ਜੇ (matchlen > ਲੜੀ_ਲੰਬਾਈ(ਸ਼ਬਦ_2)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		ਵਾਪਸ tmp;
	}

	ਵਾਪਸ xstrdup(ਸ਼ਬਦ_2);
}

/* Autocomplete a sftp command */
ਸਥਿਰ ਪੂਰਨ
complete_cmd_parse(Edit_ਸਤਰ *el, ਅੱਖਰ *cmd, ਪੂਰਨ lastarg, ਅੱਖਰ quote,
    ਪੂਰਨ terminated)
{
	u_int y, ਗਿਣਤੀ_2 = 0, cmdlen, tmplen;
	ਅੱਖਰ *tmp, **list, argterm[3];
	ਅਚਲ ਸਤਰ_Info *lf;

	list = xcalloc((ਆਕਾਰ(cmds) / ਆਕਾਰ(*cmds)) + 1, ਆਕਾਰ(ਅੱਖਰ *));

	/* No command specified: display all available commands */
	ਜੇ (cmd == ਨਿਰਾ) {
		ਲਈ (y = 0; cmds[y].c; y++)
			list[ਗਿਣਤੀ_2++] = xstrdup(cmds[y].c);

		list[ਗਿਣਤੀ_2] = ਨਿਰਾ;
		complete_display(list, 0);

		ਲਈ (y = 0; list[y] != ਨਿਰਾ; y++)
			ਮੁਕਤ(list[y]);
		ਮੁਕਤ(list);
		ਵਾਪਸ ਗਿਣਤੀ_2;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = ਲੜੀ_ਲੰਬਾਈ(cmd);
	ਲਈ (y = 0; cmds[y].c; y++)  {
		ਜੇ (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[ਗਿਣਤੀ_2++] = xstrdup(cmds[y].c);
	}
	list[ਗਿਣਤੀ_2] = ਨਿਰਾ;

	ਜੇ (ਗਿਣਤੀ_2 == 0) {
		ਮੁਕਤ(list);
		ਵਾਪਸ 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, ਗਿਣਤੀ_2);
	ਜੇ (ਗਿਣਤੀ_2 > 1)
		complete_display(list, 0);

	ਲਈ (y = 0; list[y]; y++)
		ਮੁਕਤ(list[y]);
	ਮੁਕਤ(list);

	ਜੇ (tmp != ਨਿਰਾ) {
		tmplen = ਲੜੀ_ਲੰਬਾਈ(tmp);
		cmdlen = ਲੜੀ_ਲੰਬਾਈ(cmd);
		/* If cmd may be extended then do so */
		ਜੇ (tmplen > cmdlen)
			ਜੇ (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_ਸਤਰ(el);
		/* Terminate argument cleanly */
		ਜੇ (ਗਿਣਤੀ_2 == 1) {
			y = 0;
			ਜੇ (!terminated)
				argterm[y++] = quote;
			ਜੇ (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			ਜੇ (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		ਮੁਕਤ(tmp);
	}

	ਵਾਪਸ ਗਿਣਤੀ_2;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
ਸਥਿਰ ਪੂਰਨ
complete_is_remote(ਅੱਖਰ *cmd, ਪੂਰਨ cmdarg) {
	ਪੂਰਨ i;

	ਜੇ (cmd == ਨਿਰਾ)
		ਵਾਪਸ -1;

	ਲਈ (i = 0; cmds[i].c; i++) {
		ਜੇ (!strncasecmp(cmd, cmds[i].c, ਲੜੀ_ਲੰਬਾਈ(cmds[i].c))) {
			ਜੇ (cmdarg == 1)
				ਵਾਪਸ cmds[i].t;
			ਨਹੀਂਤਾਂ ਜੇ (cmdarg == 2)
				ਵਾਪਸ cmds[i].t2;
			ਰੋਕੋ;
		}
	}

	ਵਾਪਸ -1;
}

/* Autocomplete a filename "file" */
ਸਥਿਰ ਪੂਰਨ
complete_ਮੇਲ(Edit_ਸਤਰ *el, ਬਣਤਰ sftp_conn *conn, ਅੱਖਰ *remote_ਰਸਤਾ,
    ਅੱਖਰ *file, ਪੂਰਨ remote, ਪੂਰਨ lastarg, ਅੱਖਰ quote, ਪੂਰਨ terminated)
{
	glob_t g;
	ਅੱਖਰ *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	ਪੂਰਨ clen;
	ਅਚਲ ਸਤਰ_Info *lf;

	/* Glob from "file" location */
	ਜੇ (file == ਨਿਰਾ)
		tmp = xstrdup("*");
	ਨਹੀਂਤਾਂ
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = ਰਸਤਾ_absolute(tmp);

	memset(&g, 0, ਆਕਾਰ(g));
	ਜੇ (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_ਰਸਤਾ);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ਨਿਰਾ, &g);
	} ਨਹੀਂਤਾਂ
		(ਖਾਲੀ)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ਨਿਰਾ, &g);

	/* Determine length of pwd so we can trim completion display */
	ਲਈ (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		ਜੇ (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			ਜੇ (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			ਰੋਕੋ;
		}
		ਜੇ (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		ਜੇ (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	ਮੁਕਤ(tmp);
	tmp = ਨਿਰਾ;

	ਜੇ (g.gl_matchc == 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	ਜੇ (file == ਨਿਰਾ || hadglob)
		ਜਾਓ ਬਾਹਰਲਾ;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = ਰਸਤਾ_strip(tmp2, isabs ? ਨਿਰਾ : remote_ਰਸਤਾ);
	ਮੁਕਤ(tmp2);

	ਜੇ (tmp == ਨਿਰਾ)
		ਜਾਓ ਬਾਹਰਲਾ;

	tmplen = ਲੜੀ_ਲੰਬਾਈ(tmp);
	filelen = ਲੜੀ_ਲੰਬਾਈ(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	ਲਈ (i = 0; i < filelen; i++) {
		ਜੇ (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} ਨਹੀਂਤਾਂ
			isesc = 0;
	}

	ਜੇ (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = ਲੜੀ_ਲੰਬਾਈ(tmp2);
		/* quote argument on way out */
		mblen(ਨਿਰਾ, 0);
		ਲਈ (i = 0; i < len; i += clen) {
			ਜੇ ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (ਮਾਪ_t)clen > ਆਕਾਰ(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			ਚੋਣ (tmp2[i]) {
			ਹਾਲਤ '\'':
			ਹਾਲਤ '"':
			ਹਾਲਤ '\\':
			ਹਾਲਤ '\t':
			ਹਾਲਤ '[':
			ਹਾਲਤ ' ':
			ਹਾਲਤ '#':
			ਹਾਲਤ '*':
				ਜੇ (quote == '\0' || tmp2[i] == quote) {
					ਜੇ (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					ਰੋਕੋ;
				}
				/* FALLTHROUGH */
			ਮੂਲ:
				ਜੇ (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				ਰੋਕੋ;
			}
		}
	}

	lf = el_ਸਤਰ(el);
	ਜੇ (g.gl_matchc == 1) {
		i = 0;
		ਜੇ (!terminated && quote != '\0')
			ins[i++] = quote;
		ਜੇ (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		ਜੇ (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	ਮੁਕਤ(tmp);

 ਬਾਹਰਲਾ:
	globfree(&g);
	ਵਾਪਸ g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
ਸਥਿਰ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ
complete(Edit_ਸਤਰ *el, ਪੂਰਨ ch)
{
	ਅੱਖਰ **argv, *ਸਤਰ, quote;
	ਪੂਰਨ argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ਅਚਲ ਸਤਰ_Info *lf;
	ਬਣਤਰ complete_ctx *complete_ctx;

	lf = el_ਸਤਰ(el);
	ਜੇ (el_get(el, EL_CLIENTDATA, (ਖਾਲੀ**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->ਬਫਰ;
	ਸਤਰ = xmalloc(cursor + 1);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਸਤਰ, lf->ਬਫਰ, cursor);
	ਸਤਰ[cursor] = '\0';
	argv = makeargv(ਸਤਰ, &carg, 1, &quote, &terminated);
	ਮੁਕਤ(ਸਤਰ);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->ਬਫਰ;
	ਸਤਰ = xmalloc(len + 1);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਸਤਰ, lf->ਬਫਰ, len);
	ਸਤਰ[len] = '\0';
	argv = makeargv(ਸਤਰ, &argc, 1, ਨਿਰਾ, ਨਿਰਾ);

	/* Ensure cursor is at EOL or a argument boundary */
	ਜੇ (ਸਤਰ[cursor] != ' ' && ਸਤਰ[cursor] != '\0' &&
	    ਸਤਰ[cursor] != '\n') {
		ਮੁਕਤ(ਸਤਰ);
		ਵਾਪਸ ret;
	}

	ਜੇ (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ਨਿਰਾ, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} ਨਹੀਂਤਾਂ ਜੇ (carg == 1 && cursor > 0 && ਸਤਰ[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		ਜੇ (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} ਨਹੀਂਤਾਂ ਜੇ (carg >= 1) {
		/* Handle file parsing */
		ਪੂਰਨ remote = 0;
		ਪੂਰਨ i = 0, cmdarg = 0;
		ਅੱਖਰ *filematch = ਨਿਰਾ;

		ਜੇ (carg > 1 && ਸਤਰ[cursor-1] != ' ')
			filematch = argv[carg - 1];

		ਲਈ (i = 1; i < carg; i++) {
			/* Skip flags */
			ਜੇ (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		ਜੇ (ਸਤਰ[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		ਜੇ ((remote == REMOTE || remote == LOCAL) &&
		    complete_ਮੇਲ(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	ਮੁਕਤ(ਸਤਰ);
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ /* USE_LIBEDIT */

ਸਥਿਰ ਪੂਰਨ
interactive_loop(ਬਣਤਰ sftp_conn *conn, ਅੱਖਰ *file1, ਅੱਖਰ *file2)
{
	ਅੱਖਰ *remote_ਰਸਤਾ;
	ਅੱਖਰ *dir = ਨਿਰਾ, *startdir = ਨਿਰਾ;
	ਅੱਖਰ cmd[2048];
	ਪੂਰਨ err, interactive;
	Edit_ਸਤਰ *el = ਨਿਰਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBEDIT
	ਅਚਲ ਅੱਖਰ *editor;
	History *hl = ਨਿਰਾ;
	HistEvent hev;
	ਬਾਹਰੀ ਅੱਖਰ *__progname;
	ਬਣਤਰ complete_ctx complete_ctx;

	ਜੇ (!batchmode && isatty(STDIN_FILENO)) {
		ਜੇ ((el = el_init(__progname, stdin, stdout, stderr)) == ਨਿਰਾ)
			fatal("Couldn't initialise editline");
		ਜੇ ((hl = history_init()) == ਨਿਰਾ)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_ਸੈੱਟ(el, EL_HIST, history, hl);

		el_ਸੈੱਟ(el, EL_PROMPT, prompt);
		el_ਸੈੱਟ(el, EL_EDITOR, "emacs");
		el_ਸੈੱਟ(el, EL_TERMINAL, ਨਿਰਾ);
		el_ਸੈੱਟ(el, EL_SIGNAL, 1);
		el_ਸਰੋਤ(el, ਨਿਰਾ);

		/* Tab Completion */
		el_ਸੈੱਟ(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_ਰਸਤਾ;
		el_ਸੈੱਟ(el, EL_CLIENTDATA, (ਖਾਲੀ*)&complete_ctx);
		el_ਸੈੱਟ(el, EL_BIND, "^I", "ftp-complete", ਨਿਰਾ);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_ਸੈੱਟ(el, EL_BIND, "\\e[1;5C", "em-next-word", ਨਿਰਾ);
		el_ਸੈੱਟ(el, EL_BIND, "\\e\\e[C", "em-next-word", ਨਿਰਾ);
		el_ਸੈੱਟ(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ਨਿਰਾ);
		el_ਸੈੱਟ(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ਨਿਰਾ);
		/* make ^w match ksh behaviour */
		el_ਸੈੱਟ(el, EL_BIND, "^w", "ed-delete-prev-word", ਨਿਰਾ);

		/* el_source() may have changed EL_EDITOR to vi */
		ਜੇ (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_ਸੈੱਟ(el, EL_BIND, "^[", "vi-command-mode", ਨਿਰਾ);
	}
#ਜੇ_ਅੰਤ /* USE_LIBEDIT */

	ਜੇ ((remote_ਰਸਤਾ = sftp_realpath(conn, ".")) == ਨਿਰਾ)
		fatal("Need cwd");
	startdir = xstrdup(remote_ਰਸਤਾ);

	ਜੇ (file1 != ਨਿਰਾ) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_ਰਸਤਾ);

		ਜੇ (sftp_remote_is_dir(conn, dir) && file2 == ਨਿਰਾ) {
			ਜੇ (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, ਆਕਾਰ cmd, "cd \"%s\"", dir);
			ਜੇ (parse_dispatch_command(conn, cmd,
			    &remote_ਰਸਤਾ, startdir, 1, 0) != 0) {
				ਮੁਕਤ(dir);
				ਮੁਕਤ(startdir);
				ਮੁਕਤ(remote_ਰਸਤਾ);
				ਮੁਕਤ(conn);
				ਵਾਪਸ (-1);
			}
		} ਨਹੀਂਤਾਂ {
			err = process_get(conn, dir, file2, remote_ਰਸਤਾ, 0, 0,
			    global_aflag, 0);
			ਮੁਕਤ(dir);
			ਮੁਕਤ(startdir);
			ਮੁਕਤ(remote_ਰਸਤਾ);
			ਮੁਕਤ(conn);
			ਵਾਪਸ (err);
		}
		ਮੁਕਤ(dir);
	}

	setvbuf(stdout, ਨਿਰਾ, _IOLBF, 0);
	setvbuf(infile, ਨਿਰਾ, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	ਲਈ (;;) {
		ਬਣਤਰ sigaction sa;

		interrupted = 0;
		memset(&sa, 0, ਆਕਾਰ(sa));
		sa.sa_handler = interactive ? read_ਰੁਕਾਵਟ : killchild;
		ਜੇ (sigaction(SIGINT, &sa, ਨਿਰਾ) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			ਰੋਕੋ;
		}
		ਜੇ (el == ਨਿਰਾ) {
			ਜੇ (interactive) {
				ਲਿਖੋ("sftp> ");
				fflush(stdout);
			}
			ਜੇ (fgets(cmd, ਆਕਾਰ(cmd), infile) == ਨਿਰਾ) {
				ਜੇ (interactive)
					ਲਿਖੋ("\n");
				ਜੇ (interrupted)
					ਜਾਰੀ;
				ਰੋਕੋ;
			}
		} ਨਹੀਂਤਾਂ {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBEDIT
			ਅਚਲ ਅੱਖਰ *ਸਤਰ;
			ਪੂਰਨ ਗਿਣਤੀ_2 = 0;

			ਜੇ ((ਸਤਰ = el_gets(el, &ਗਿਣਤੀ_2)) == ਨਿਰਾ ||
			    ਗਿਣਤੀ_2 <= 0) {
				ਲਿਖੋ("\n");
				ਜੇ (interrupted)
					ਜਾਰੀ;
				ਰੋਕੋ;
			}
			history(hl, &hev, H_ENTER, ਸਤਰ);
			ਜੇ (strlcpy(cmd, ਸਤਰ, ਆਕਾਰ(cmd)) >= ਆਕਾਰ(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				ਜਾਰੀ;
			}
#ਜੇ_ਅੰਤ /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_ਰੁਕਾਵਟ);

		err = parse_dispatch_command(conn, cmd, &remote_ਰਸਤਾ,
		    startdir, batchmode, !interactive && el == ਨਿਰਾ);
		ਜੇ (err != 0)
			ਰੋਕੋ;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	ਮੁਕਤ(remote_ਰਸਤਾ);
	ਮੁਕਤ(startdir);
	ਮੁਕਤ(conn);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBEDIT
	ਜੇ (hl != ਨਿਰਾ)
		history_ਸਿਰਾ(hl);
	ਜੇ (el != ਨਿਰਾ)
		el_ਸਿਰਾ(el);
#ਜੇ_ਅੰਤ /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	ਵਾਪਸ (err >= 0 ? 0 : -1);
}

ਸਥਿਰ ਖਾਲੀ
connect_ਮੰਜ਼ਿਲ_server(ਅੱਖਰ *ਰਸਤਾ, ਅੱਖਰ **ਦਲੀਲਾਂ, ਪੂਰਨ *ਵਿੱਚ, ਪੂਰਨ *ਬਾਹਰਲਾ)
{
	ਪੂਰਨ c_ਵਿੱਚ, c_ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PIPES
	ਪੂਰਨ pin[2], pout[2];

	ਜੇ ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*ਵਿੱਚ = pin[0];
	*ਬਾਹਰਲਾ = pout[1];
	c_ਵਿੱਚ = pout[0];
	c_ਬਾਹਰਲਾ = pin[1];
#ਨਹੀਂਤਾਂ /* USE_PIPES */
	ਪੂਰਨ inout[2];

	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*ਵਿੱਚ = *ਬਾਹਰਲਾ = inout[0];
	c_ਵਿੱਚ = c_ਬਾਹਰਲਾ = inout[1];
#ਜੇ_ਅੰਤ /* USE_PIPES */
	FD_CLOSEONEXEC(*ਵਿੱਚ);
	FD_CLOSEONEXEC(*ਬਾਹਰਲਾ);

	ਜੇ ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	ਨਹੀਂਤਾਂ ਜੇ (sshpid == 0) {
		ਜੇ ((dup2(c_ਵਿੱਚ, STDIN_FILENO) == -1) ||
		    (dup2(c_ਬਾਹਰਲਾ, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*ਵਿੱਚ);
		close(*ਬਾਹਰਲਾ);
		close(c_ਵਿੱਚ);
		close(c_ਬਾਹਰਲਾ);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(ਰਸਤਾ, ਦਲੀਲਾਂ);
		fprintf(stderr, "exec: %s: %s\n", ਰਸਤਾ, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_ਵਿੱਚ);
	close(c_ਬਾਹਰਲਾ);
}

ਸਥਿਰ ਖਾਲੀ
usage(ਖਾਲੀ)
{
	ਬਾਹਰੀ ਅੱਖਰ *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	ਬਾਹਰ_ਨਿਕਲੋ(1);
}

ਪੂਰਨ
ਮੁੱਖ(ਪੂਰਨ argc, ਅੱਖਰ **argv)
{
	ਪੂਰਨ r, ਵਿੱਚ, ਬਾਹਰਲਾ, ch, err, tmp, ਪੋਰਟ = -1, noisy = 0;
	ਅੱਖਰ *host = ਨਿਰਾ, *user, *cp, **cpp, *file2 = ਨਿਰਾ;
	ਪੂਰਨ debug_level = 0;
	ਅੱਖਰ *file1 = ਨਿਰਾ, *sftp_server = ਨਿਰਾ;
	ਅੱਖਰ *ssh_ਪ੍ਰੋਗਰਾਮ = ਰਸਤਾ_SSH_ਪ੍ਰੋਗਰਾਮ, *sftp_ਸਿੱਧਾ = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist ਦਲੀਲਾਂ;
	ਬਾਹਰੀ ਪੂਰਨ optind;
	ਬਾਹਰੀ ਅੱਖਰ *optarg;
	ਬਣਤਰ sftp_conn *conn;
	ਮਾਪ_t copy_ਬਫਰ_len = 0;
	ਮਾਪ_t ਅੰਕ_ਬੇਨਤੀਆਂ = 0;
	ਲੰਮਾ ਲੰਮਾ llv, ਹੱਦਬੰਦੀ_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&ਦਲੀਲਾਂ, '\0', ਆਕਾਰ(ਦਲੀਲਾਂ));
	ਦਲੀਲਾਂ.list = ਨਿਰਾ;
	addargs(&ਦਲੀਲਾਂ, "%s", ssh_ਪ੍ਰੋਗਰਾਮ);
	addargs(&ਦਲੀਲਾਂ, "-oForwardX11 no");
	addargs(&ਦਲੀਲਾਂ, "-oPermitLocalCommand no");
	addargs(&ਦਲੀਲਾਂ, "-oClearAllForwardings yes");
	addargs(&ਦਲੀਲਾਂ, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	ਜਦੋਂ ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		ਚੋਣ (ch) {
		/* Passed through to ssh(1) */
		ਹਾਲਤ 'A':
		ਹਾਲਤ '4':
		ਹਾਲਤ '6':
		ਹਾਲਤ 'C':
			addargs(&ਦਲੀਲਾਂ, "-%c", ch);
			ਰੋਕੋ;
		/* Passed through to ssh(1) with argument */
		ਹਾਲਤ 'F':
		ਹਾਲਤ 'J':
		ਹਾਲਤ 'c':
		ਹਾਲਤ 'i':
		ਹਾਲਤ 'o':
			addargs(&ਦਲੀਲਾਂ, "-%c", ch);
			addargs(&ਦਲੀਲਾਂ, "%s", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&ਦਲੀਲਾਂ, "-%c", ch);
			ਰੋਕੋ;
		ਹਾਲਤ 'P':
			ਪੋਰਟ = a2port(optarg);
			ਜੇ (ਪੋਰਟ <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'v':
			ਜੇ (debug_level < 3) {
				addargs(&ਦਲੀਲਾਂ, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			ਰੋਕੋ;
		ਹਾਲਤ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ਰੋਕੋ;
		ਹਾਲਤ '2':
			/* accept silently */
			ਰੋਕੋ;
		ਹਾਲਤ 'a':
			global_aflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'B':
			copy_ਬਫਰ_len = strtol(optarg, &cp, 10);
			ਜੇ (copy_ਬਫਰ_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 'b':
			ਜੇ (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			ਜੇ (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ਨਿਰਾ)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&ਦਲੀਲਾਂ, "-obatchmode yes");
			ਰੋਕੋ;
		ਹਾਲਤ 'f':
			global_fflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			ਰੋਕੋ;
		ਹਾਲਤ 'p':
			global_pflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'D':
			sftp_ਸਿੱਧਾ = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'l':
			ਹੱਦਬੰਦੀ_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ਜੇ (errstr != ਨਿਰਾ)
				usage();
			ਹੱਦਬੰਦੀ_kbps *= 1024; /* kbps */
			ਰੋਕੋ;
		ਹਾਲਤ 'r':
			global_rflag = 1;
			ਰੋਕੋ;
		ਹਾਲਤ 'R':
			ਅੰਕ_ਬੇਨਤੀਆਂ = strtol(optarg, &cp, 10);
			ਜੇ (ਅੰਕ_ਬੇਨਤੀਆਂ == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			ਰੋਕੋ;
		ਹਾਲਤ 's':
			sftp_server = optarg;
			ਰੋਕੋ;
		ਹਾਲਤ 'S':
			ssh_ਪ੍ਰੋਗਰਾਮ = optarg;
			replacearg(&ਦਲੀਲਾਂ, 0, "%s", ssh_ਪ੍ਰੋਗਰਾਮ);
			ਰੋਕੋ;
		ਹਾਲਤ 'X':
			/* Please keep in sync with ssh.c -X */
			ਜੇ (ਲੜੀ_ਤੁਲਨਾ(optarg, "buffer=", 7) == 0) {
				r = ਜਾਂਚ_scaled(optarg + 7, &llv);
				ਜੇ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ਜੇ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_ਬਫਰ_len = (ਮਾਪ_t)llv;
			} ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ਜੇ (errstr != ਨਿਰਾ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				ਅੰਕ_ਬੇਨਤੀਆਂ = (ਮਾਪ_t)llv;
			} ਨਹੀਂਤਾਂ {
				fatal("Invalid -X option");
			}
			ਰੋਕੋ;
		ਹਾਲਤ 'h':
		ਮੂਲ:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&ਦਲੀਲਾਂ, "-oForwardAgent no");

	ਜੇ (!isatty(STDERR_FILENO))
		showprogress = 0;

	ਜੇ (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	ਜੇ (sftp_ਸਿੱਧਾ == ਨਿਰਾ) {
		ਜੇ (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		ਚੋਣ (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		ਹਾਲਤ -1:
			usage();
			ਰੋਕੋ;
		ਹਾਲਤ 0:
			ਜੇ (tmp != -1)
				ਪੋਰਟ = tmp;
			ਰੋਕੋ;
		ਮੂਲ:
			/* Try with user, host and path. */
			ਜੇ (parse_user_host_ਰਸਤਾ(*argv, &user, &host,
			    &file1) == 0)
				ਰੋਕੋ;
			/* Try with user and host. */
			ਜੇ (parse_user_host_ਪੋਰਟ(*argv, &user, &host, ਨਿਰਾ)
			    == 0)
				ਰੋਕੋ;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			ਰੋਕੋ;
		}
		file2 = *(argv + 1);

		ਜੇ (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		ਜੇ (ਪੋਰਟ != -1)
			addargs(&ਦਲੀਲਾਂ, "-oPort %d", ਪੋਰਟ);
		ਜੇ (user != ਨਿਰਾ) {
			addargs(&ਦਲੀਲਾਂ, "-l");
			addargs(&ਦਲੀਲਾਂ, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		ਜੇ (sftp_server == ਨਿਰਾ || strchr(sftp_server, '/') == ਨਿਰਾ)
			addargs(&ਦਲੀਲਾਂ, "-s");

		addargs(&ਦਲੀਲਾਂ, "--");
		addargs(&ਦਲੀਲਾਂ, "%s", host);
		addargs(&ਦਲੀਲਾਂ, "%s", (sftp_server != ਨਿਰਾ ?
		    sftp_server : "sftp"));

		connect_ਮੰਜ਼ਿਲ_server(ssh_ਪ੍ਰੋਗਰਾਮ, ਦਲੀਲਾਂ.list, &ਵਿੱਚ, &ਬਾਹਰਲਾ);
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = argv_ਵੰਡੋ(sftp_ਸਿੱਧਾ, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		ਜੇ (cpp[0] == ਨਿਰਾ)
			fatal("No sftp server specified via -D");
		connect_ਮੰਜ਼ਿਲ_server(cpp[0], cpp, &ਵਿੱਚ, &ਬਾਹਰਲਾ);
		argv_free(cpp, tmp);
	}
	freeargs(&ਦਲੀਲਾਂ);

	conn = sftp_init(ਵਿੱਚ, ਬਾਹਰਲਾ, copy_ਬਫਰ_len, ਅੰਕ_ਬੇਨਤੀਆਂ, ਹੱਦਬੰਦੀ_kbps);
	ਜੇ (conn == ਨਿਰਾ)
		fatal("Couldn't initialise connection to server");

	ਜੇ (!quiet) {
		ਜੇ (sftp_ਸਿੱਧਾ == ਨਿਰਾ)
			fprintf(stderr, "Connected to %s.\n", host);
		ਨਹੀਂਤਾਂ
			fprintf(stderr, "Attached to %s.\n", sftp_ਸਿੱਧਾ);
	}

	err = interactive_loop(conn, file1, file2);

#ਜੇ !defined(USE_PIPES)
	shutdown(ਵਿੱਚ, SHUT_RDWR);
	shutdown(ਬਾਹਰਲਾ, SHUT_RDWR);
#ਜੇ_ਅੰਤ

	close(ਵਿੱਚ);
	close(ਬਾਹਰਲਾ);
	ਜੇ (batchmode)
		fclose(infile);

	ਜਦੋਂ (waitpid(sshpid, ਨਿਰਾ, 0) == -1 && sshpid > 1)
		ਜੇ (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	ਬਾਹਰ_ਨਿਕਲੋ(err == 0 ? 0 : 1);
}
