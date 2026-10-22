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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/ioctl.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/statvfs.h>
#அந்தர்பாவ <sys/wait.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <glob.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#அந்தர்பாவ <histedit.h>
#இல்லையெனில்
வகைவரை வெறுமை Edit_வரி;
#endif
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <util.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "utf8.h"

#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sftp-common.h"
#அந்தர்பாவ "sftp-client.h"
#அந்தர்பாவ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
முழு batchmode = 0;

/* PID of ssh transport process */
நிலையான நிலையற்ற pid_t sshpid = -1;

/* Suppress diagnostic messages */
முழு quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
முழு showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
முழு global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
முழு global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
முழு global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
முழு global_fflag = 0;

/* SIGINT received during command processing */
நிலையற்ற sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
முழு sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
கட்டமைப்பு complete_ctx {
	கட்டமைப்பு sftp_conn *conn;
	எழுத்து **remote_pathp;
};

முழு sftp_glob(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, முழு,
    முழு (*)(மாறிலி எழுத்து *, முழு), glob_t *); /* proto for sftp-glob.c */

வெளி எழுத்து *__progname;

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
எண்ணிக்கை sftp_command {
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

கட்டமைப்பு CMD {
	மாறிலி எழுத்து *c;
	மாறிலி முழு n;
	மாறிலி முழு t;	/* Completion type for the first argument */
	மாறிலி முழு t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

நிலையான மாறிலி கட்டமைப்பு CMD cmds[] = {
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
	{ வெற்று,		-1,		-1,		-1	}
};

நிலையான வெறுமை
killchild(முழு signo)
{
	pid_t pid;

	pid = sshpid;
	எனில் (pid > 1) {
		kill(pid, SIGTERM);
		(வெறுமை)waitpid(pid, வெற்று, 0);
	}

	_exit(1);
}

நிலையான வெறுமை
suspchild(முழு signo)
{
	முழு save_errno = errno;
	எனில் (sshpid > 1) {
		kill(sshpid, signo);
		போது (waitpid(sshpid, வெற்று, WUNTRACED) == -1 && errno == EINTR)
			தொடர்;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

நிலையான வெறுமை
cmd_interrupt(முழு signo)
{
	மாறிலி எழுத்து செய்தி[] = "\rInterrupt  \n";
	முழு olderrno = errno;

	(வெறுமை)லிக(STDERR_FILENO, செய்தி, அளவு(செய்தி) - 1);
	interrupted = 1;
	errno = olderrno;
}

நிலையான வெறுமை
read_interrupt(முழு signo)
{
	interrupted = 1;
}

நிலையான வெறுமை
sigchld_handler(முழு sig)
{
	முழு save_errno = errno;
	pid_t pid;
	மாறிலி எழுத்து செய்தி[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	போது ((pid = waitpid(sshpid, வெற்று, WNOHANG)) == -1 && errno == EINTR)
		தொடர்;
	எனில் (pid == sshpid) {
		எனில் (!quiet)
		    (வெறுமை)லிக(STDERR_FILENO, செய்தி, அளவு(செய்தி) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

நிலையான வெறுமை
help(வெறுமை)
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

நிலையான வெறுமை
local_do_shell(மாறிலி எழுத்து *args)
{
	முழு status;
	எழுத்து *shell;
	pid_t pid;

	எனில் (!*args)
		args = வெற்று;

	எனில் ((shell = getenv("SHELL")) == வெற்று || *shell == '\0')
		shell = _PATH_BSHELL;

	எனில் ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	எனில் (pid == 0) {
		எனில் (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (எழுத்து *)வெற்று);
		} இல்லையெனில் {
			debug3("Executing %s", shell);
			execl(shell, shell, (எழுத்து *)வெற்று);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	போது (waitpid(pid, &status, 0) == -1)
		எனில் (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	எனில் (!WIFEXITED(status))
		error("Shell exited abnormally");
	இல்லையெனில் எனில் (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

நிலையான வெறுமை
local_do_ls(மாறிலி எழுத்து *args)
{
	எனில் (!args || !*args)
		local_do_shell(_PATH_LS);
	இல்லையெனில் {
		முழு len = strlen(_PATH_LS " ") + strlen(args) + 1;
		எழுத்து *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		விடுவி(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
நிலையான எழுத்து *
path_strip(மாறிலி எழுத்து *path, மாறிலி எழுத்து *strip)
{
	size_t len;

	எனில் (strip == வெற்று || (len = strlen(strip)) == 0)
		திரும்பு (xstrdup(path));

	எனில் (strncmp(path, strip, len) == 0) {
		எனில் (strip[len - 1] != '/' && path[len] == '/')
			len++;
		திரும்பு (xstrdup(path + len));
	}

	திரும்பு (xstrdup(path));
}

நிலையான முழு
parse_getput_flags(மாறிலி எழுத்து *cmd, எழுத்து **argv, முழு argc,
    முழு *aflag, முழு *fflag, முழு *pflag, முழு *rflag)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	போது ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		தேர்வு (ch) {
		நிலை 'a':
			*aflag = 1;
			நிறுத்து;
		நிலை 'f':
			*fflag = 1;
			நிறுத்து;
		நிலை 'p':
		நிலை 'P':
			*pflag = 1;
			நிறுத்து;
		நிலை 'r':
		நிலை 'R':
			*rflag = 1;
			நிறுத்து;
		இயல்பு:
			error("%s: Invalid flag -%c", cmd, optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான முழு
parse_mkdir_flags(மாறிலி எழுத்து *cmd, எழுத்து **argv, முழு argc, முழு *pflag)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	போது ((ch = getopt(argc, argv, "p")) != -1) {
		தேர்வு (ch) {
		நிலை 'p':
			*pflag = 1;
			நிறுத்து;
		இயல்பு:
			error("%s: Invalid flag -%c", cmd, optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான முழு
parse_link_flags(மாறிலி எழுத்து *cmd, எழுத்து **argv, முழு argc, முழு *sflag)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	போது ((ch = getopt(argc, argv, "s")) != -1) {
		தேர்வு (ch) {
		நிலை 's':
			*sflag = 1;
			நிறுத்து;
		இயல்பு:
			error("%s: Invalid flag -%c", cmd, optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான முழு
parse_rename_flags(மாறிலி எழுத்து *cmd, எழுத்து **argv, முழு argc, முழு *lflag)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	போது ((ch = getopt(argc, argv, "l")) != -1) {
		தேர்வு (ch) {
		நிலை 'l':
			*lflag = 1;
			நிறுத்து;
		இயல்பு:
			error("%s: Invalid flag -%c", cmd, optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான முழு
parse_ls_flags(எழுத்து **argv, முழு argc, முழு *lflag)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	போது ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		தேர்வு (ch) {
		நிலை '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			நிறுத்து;
		நிலை 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			நிறுத்து;
		நிலை 'a':
			*lflag |= LS_SHOW_ALL;
			நிறுத்து;
		நிலை 'f':
			*lflag &= ~SORT_FLAGS;
			நிறுத்து;
		நிலை 'h':
			*lflag |= LS_SI_UNITS;
			நிறுத்து;
		நிலை 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			நிறுத்து;
		நிலை 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			நிறுத்து;
		நிலை 'r':
			*lflag |= LS_REVERSE_SORT;
			நிறுத்து;
		நிலை 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			நிறுத்து;
		இயல்பு:
			error("ls: Invalid flag -%c", optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான முழு
parse_df_flags(மாறிலி எழுத்து *cmd, எழுத்து **argv, முழு argc, முழு *hflag, முழு *iflag)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	போது ((ch = getopt(argc, argv, "hi")) != -1) {
		தேர்வு (ch) {
		நிலை 'h':
			*hflag = 1;
			நிறுத்து;
		நிலை 'i':
			*iflag = 1;
			நிறுத்து;
		இயல்பு:
			error("%s: Invalid flag -%c", cmd, optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான முழு
parse_ch_flags(மாறிலி எழுத்து *cmd, எழுத்து **argv, முழு argc, முழு *hflag)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	போது ((ch = getopt(argc, argv, "h")) != -1) {
		தேர்வு (ch) {
		நிலை 'h':
			*hflag = 1;
			நிறுத்து;
		இயல்பு:
			error("%s: Invalid flag -%c", cmd, optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான முழு
parse_no_flags(மாறிலி எழுத்து *cmd, எழுத்து **argv, முழு argc)
{
	வெளி முழு opterr, optind, optopt, optreset;
	முழு ch;

	optind = optreset = 1;
	opterr = 0;

	போது ((ch = getopt(argc, argv, "")) != -1) {
		தேர்வு (ch) {
		இயல்பு:
			error("%s: Invalid flag -%c", cmd, optopt);
			திரும்பு -1;
		}
	}

	திரும்பு optind;
}

நிலையான எழுத்து *
escape_glob(மாறிலி எழுத்து *s)
{
	size_t i, o, len;
	எழுத்து *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	க்கு (i = o = 0; i < len; i++) {
		எனில் (strchr("[]?*\\", s[i]) != வெற்று)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	திரும்பு ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
நிலையான எழுத்து *
make_absolute_pwd_glob(எழுத்து *p, மாறிலி எழுத்து *pwd)
{
	எழுத்து *ret, *escpwd;

	escpwd = escape_glob(pwd);
	எனில் (p == வெற்று)
		திரும்பு escpwd;
	ret = sftp_make_absolute(p, escpwd);
	விடுவி(escpwd);
	திரும்பு ret;
}

நிலையான முழு
local_is_dir(மாறிலி எழுத்து *path)
{
	கட்டமைப்பு stat sb;

	எனில் (stat(path, &sb) == -1)
		திரும்பு 0;
	திரும்பு S_ISDIR(sb.st_mode);
}

நிலையான முழு
process_get(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *src, மாறிலி எழுத்து *dst,
    மாறிலி எழுத்து *pwd, முழு pflag, முழு rflag, முழு resume, முழு fflag)
{
	எழுத்து *filename, *abs_src = வெற்று, *abs_dst = வெற்று, *tmp = வெற்று;
	glob_t g;
	முழு i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, அளவு(g));

	debug3("Looking up %s", abs_src);
	எனில் ((r = sftp_glob(conn, abs_src, GLOB_MARK, வெற்று, &g)) != 0) {
		எனில் (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} இல்லையெனில் {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		செல் out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	எனில் (g.gl_matchc > 1 && dst != வெற்று && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		செல் out;
	}

	க்கு (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		எனில் ((filename = basename(tmp)) == வெற்று) {
			error("basename %s: %s", tmp, strerror(errno));
			விடுவி(tmp);
			err = -1;
			செல் out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		எனில் (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		எனில் (g.gl_matchc == 1 && dst) {
			எனில் (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} இல்லையெனில் {
				abs_dst = xstrdup(dst);
			}
		} இல்லையெனில் எனில் (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} இல்லையெனில் {
			abs_dst = xstrdup(filename);
		}
		விடுவி(tmp);

		resume |= global_aflag;
		எனில் (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		இல்லையெனில் எனில் (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		எனில் (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			எனில் (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    வெற்று, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} இல்லையெனில் {
			எனில் (sftp_download(conn, g.gl_pathv[i], abs_dst, வெற்று,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		விடுவி(abs_dst);
		abs_dst = வெற்று;
	}

out:
	விடுவி(abs_src);
	globfree(&g);
	திரும்பு(err);
}

நிலையான முழு
process_put(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *src, மாறிலி எழுத்து *dst,
    மாறிலி எழுத்து *pwd, முழு pflag, முழு rflag, முழு resume, முழு fflag)
{
	எழுத்து *tmp_dst = வெற்று;
	எழுத்து *abs_dst = வெற்று;
	எழுத்து *tmp = வெற்று, *filename = வெற்று;
	glob_t g;
	முழு err = 0;
	முழு i, dst_is_dir = 1;
	கட்டமைப்பு stat sb;

	எனில் (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, அளவு(g));
	debug3("Looking up %s", src);
	எனில் (glob(src, GLOB_NOCHECK | GLOB_MARK, வெற்று, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		செல் out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	எனில் (tmp_dst != வெற்று)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	எனில் (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		செல் out;
	}

	க்கு (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		எனில் (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			தொடர்;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		எனில் ((filename = basename(tmp)) == வெற்று) {
			error("basename %s: %s", tmp, strerror(errno));
			விடுவி(tmp);
			err = -1;
			செல் out;
		}
		/* Special handling for source of '..' */
		எனில் (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		விடுவி(abs_dst);
		abs_dst = வெற்று;
		எனில் (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			எனில் (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			இல்லையெனில்
				abs_dst = xstrdup(tmp_dst);
		} இல்லையெனில் எனில் (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} இல்லையெனில் {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		விடுவி(tmp);

		resume |= global_aflag;
		எனில் (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		இல்லையெனில் எனில் (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		எனில் (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			எனில் (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} இல்லையெனில் {
			எனில் (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	விடுவி(abs_dst);
	விடுவி(tmp_dst);
	globfree(&g);
	திரும்பு(err);
}

நிலையான முழு
sdirent_comp(மாறிலி வெறுமை *aa, மாறிலி வெறுமை *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	முழு rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	எனில் (sort_flag & LS_NAME_SORT)
		திரும்பு (rmul * strcmp(a->filename, b->filename));
	இல்லையெனில் எனில் (sort_flag & LS_TIME_SORT)
		திரும்பு (rmul * NCMP(a->a.mtime, b->a.mtime));
	இல்லையெனில் எனில் (sort_flag & LS_SIZE_SORT)
		திரும்பு (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
நிலையான முழு
do_ls_dir(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path,
    மாறிலி எழுத்து *strip_path, முழு lflag)
{
	முழு n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	எனில் ((n = sftp_readdir(conn, path, &d)) != 0)
		திரும்பு (n);

	எனில் (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		கட்டமைப்பு winsize ws;
		எழுத்து *tmp;

		/* Count entries for sort and find longest filename */
		க்கு (n = 0; d[n] != வெற்று; n++) {
			எனில் (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		விடுவி(tmp);

		எனில் (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	எனில் (lflag & SORT_FLAGS) {
		க்கு (n = 0; d[n] != வெற்று; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, அளவு(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	க்கு (n = 0; d[n] != வெற்று && !interrupted; n++) {
		எழுத்து *tmp, *fname;

		எனில் (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			தொடர்;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		விடுவி(tmp);

		எனில் (lflag & LS_LONG_VIEW) {
			எனில் ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				எழுத்து *lname;
				கட்டமைப்பு stat sb;
				மாறிலி எழுத்து *user = வெற்று, *group = வெற்று;

				memset(&sb, 0, அளவு(sb));
				attrib_to_stat(&d[n]->a, &sb);
				எனில் ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				விடுவி(lname);
			} இல்லையெனில்
				mprintf("%s\n", d[n]->longname);
		} இல்லையெனில் {
			mprintf("%-*s", colspace, fname);
			எனில் (c >= columns) {
				printf("\n");
				c = 1;
			} இல்லையெனில்
				c++;
		}

		விடுவி(fname);
	}

	எனில் (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	திரும்பு (0);
}

நிலையான முழு
sglob_comp(மாறிலி வெறுமை *aa, மாறிலி வெறுமை *bb)
{
	u_int a = *(மாறிலி u_int *)aa;
	u_int b = *(மாறிலி u_int *)bb;
	மாறிலி எழுத்து *ap = sort_glob->gl_pathv[a];
	மாறிலி எழுத்து *bp = sort_glob->gl_pathv[b];
	மாறிலி கட்டமைப்பு stat *as = sort_glob->gl_statv[a];
	மாறிலி கட்டமைப்பு stat *bs = sort_glob->gl_statv[b];
	முழு rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	எனில் (as == வெற்று || bs == வெற்று)
		திரும்பு (as == bs) ? 0 : (as == வெற்று ? rmul : -rmul);
	எனில் (sort_flag & LS_NAME_SORT)
		திரும்பு (rmul * strcmp(ap, bp));
	இல்லையெனில் எனில் (sort_flag & LS_TIME_SORT) {
#எனில் defined(HAVE_STRUCT_STAT_ST_MTIM)
		எனில் (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			திரும்பு 0;
		திரும்பு timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#அல்லதெனில் defined(HAVE_STRUCT_STAT_ST_MTIME)
		திரும்பு (rmul * NCMP(as->st_mtime, bs->st_mtime));
#இல்லையெனில்
	திரும்பு rmul * 1;
#endif
	} இல்லையெனில் எனில் (sort_flag & LS_SIZE_SORT)
		திரும்பு (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
நிலையான முழு
do_globbed_ls(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path,
    மாறிலி எழுத்து *strip_path, முழு lflag)
{
	எழுத்து *fname, *lname;
	glob_t g;
	முழு err, r;
	கட்டமைப்பு winsize ws;
	u_int i, j, nentries, *indices = வெற்று, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, அளவு(g));

	எனில் ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    வெற்று, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		எனில் (g.gl_pathc)
			globfree(&g);
		எனில் (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} இல்லையெனில் {
			error("Can't ls: \"%s\" not found", path);
		}
		திரும்பு -1;
	}

	எனில் (interrupted)
		செல் out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	எனில் (g.gl_matchc == 1 && g.gl_statv[0] != வெற்று &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		திரும்பு err;
	}

	எனில் (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	எனில் (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		க்கு (i = 0; g.gl_pathv[i]; i++)
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
	க்கு (nentries = 0; g.gl_pathv[nentries] != வெற்று; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, அளவு(*indices));
	க்கு (i = 0; i < nentries; i++)
		indices[i] = i;

	எனில் (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, அளவு(*indices), sglob_comp);
		sort_glob = வெற்று;
	}

	get_remote_user_groups_from_glob(conn, &g);
	க்கு (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		எனில் (lflag & LS_LONG_VIEW) {
			மாறிலி எழுத்து *user = வெற்று, *group = வெற்று;

			எனில் (g.gl_statv[i] == வெற்று) {
				error("no stat information for %s", fname);
				விடுவி(fname);
				தொடர்;
			}
			எனில் ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			விடுவி(lname);
		} இல்லையெனில் {
			mprintf("%-*s", colspace, fname);
			எனில் (c >= columns) {
				printf("\n");
				c = 1;
			} இல்லையெனில்
				c++;
		}
		விடுவி(fname);
	}

	எனில் (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	எனில் (g.gl_pathc)
		globfree(&g);
	விடுவி(indices);

	திரும்பு 0;
}

நிலையான முழு
do_df(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *path, முழு hflag, முழு iflag)
{
	கட்டமைப்பு sftp_statvfs st;
	எழுத்து s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	எழுத்து s_வேர்[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	எழுத்து s_icapacity[16], s_dcapacity[16];

	எனில் (sftp_statvfs(conn, path, &st, 1) == -1)
		திரும்பு -1;
	எனில் (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", அளவு(s_icapacity));
	இல்லையெனில் {
		snprintf(s_icapacity, அளவு(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	எனில் (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", அளவு(s_dcapacity));
	இல்லையெனில் {
		snprintf(s_dcapacity, அளவு(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	எனில் (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} இல்லையெனில் எனில் (hflag) {
		strlcpy(s_used, "error", அளவு(s_used));
		strlcpy(s_avail, "error", அளவு(s_avail));
		strlcpy(s_வேர், "error", அளவு(s_வேர்));
		strlcpy(s_total, "error", அளவு(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_வேர்);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_வேர், s_dcapacity);
	} இல்லையெனில் {
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
	திரும்பு 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
நிலையான வெறுமை
undo_glob_escape(எழுத்து *s)
{
	size_t i, j;

	க்கு (i = j = 0;;) {
		எனில் (s[i] == '\0') {
			s[j] = '\0';
			திரும்பு;
		}
		எனில் (s[i] != '\\') {
			s[j++] = s[i++];
			தொடர்;
		}
		/* s[i] == '\\' */
		++i;
		தேர்வு (s[i]) {
		நிலை '?':
		நிலை '[':
		நிலை '*':
		நிலை '\\':
			s[j++] = s[i++];
			நிறுத்து;
		நிலை '\0':
			s[j++] = '\\';
			s[j] = '\0';
			திரும்பு;
		இயல்பு:
			s[j++] = '\\';
			s[j++] = s[i++];
			நிறுத்து;
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
நிலையான எழுத்து **
makeargv(மாறிலி எழுத்து *arg, முழு *argcp, முழு sloppy, எழுத்து *lastquote,
    u_int *terminated)
{
	முழு argc, quot;
	size_t i, j;
	நிலையான எழுத்து argvs[MAXARGLEN];
	நிலையான எழுத்து *argv[MAXARGS + 1];
	எண்ணிக்கை { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	எனில் (strlen(arg) > அளவு(argvs) - 1) {
 args_too_longs:
		error("string too long");
		திரும்பு வெற்று;
	}
	எனில் (terminated != வெற்று)
		*terminated = 1;
	எனில் (lastquote != வெற்று)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	க்கு (;;) {
		எனில் ((size_t)argc >= அளவு(argv) / அளவு(*argv)){
			error("Too many arguments.");
			திரும்பு வெற்று;
		}
		எனில் (isspace((unsigned எழுத்து)arg[i])) {
			எனில் (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} இல்லையெனில் எனில் (state != MA_START)
				argvs[j++] = arg[i];
		} இல்லையெனில் எனில் (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			எனில் (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				எனில் (lastquote != வெற்று)
					*lastquote = arg[i];
			} இல்லையெனில் எனில் (state == MA_UNQUOTED)
				state = q;
			இல்லையெனில் எனில் (state == q)
				state = MA_UNQUOTED;
			இல்லையெனில்
				argvs[j++] = arg[i];
		} இல்லையெனில் எனில் (arg[i] == '\\') {
			எனில் (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				எனில் (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} இல்லையெனில் எனில் (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					எனில் (j >= அளவு(argvs) - 5)
						செல் args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} இல்லையெனில் {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} இல்லையெனில் {
				எனில் (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					எனில் (lastquote != வெற்று)
						*lastquote = '\0';
				}
				எனில் (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} இல்லையெனில் {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					எனில் (arg[i] == '\0')
						செல் early_nul;
					argvs[j++] = arg[i];
				}
			}
		} இல்லையெனில் எனில் (arg[i] == '#') {
			எனில் (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			இல்லையெனில்
				செல் string_done;
		} இல்லையெனில் எனில் (arg[i] == '\0') {
			எனில் (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				எனில் (sloppy) {
					state = MA_UNQUOTED;
					எனில் (terminated != வெற்று)
						*terminated = 0;
					செல் string_done;
				}
				error("Unterminated quoted argument");
				திரும்பு வெற்று;
			}
 string_done:
			எனில் (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			நிறுத்து;
		} இல்லையெனில் {
			எனில் (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				எனில் (lastquote != வெற்று)
					*lastquote = '\0';
			}
			எனில் ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				எனில் (j >= அளவு(argvs) - 3)
					செல் args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} இல்லையெனில்
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	திரும்பு argv;
}

நிலையான முழு
parse_args(மாறிலி எழுத்து **cpp, முழு *ignore_errors, முழு *disable_echo, முழு *aflag,
	  முழு *fflag, முழு *hflag, முழு *iflag, முழு *lflag, முழு *pflag,
	  முழு *rflag, முழு *sflag,
    unsigned long *n_arg, எழுத்து **path1, எழுத்து **path2)
{
	மாறிலி எழுத்து *cmd, *cp = *cpp;
	எழுத்து *cp2, **argv;
	முழு base = 0;
	long long ll;
	முழு path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	க்கு (;*cp != '\0'; cp++) {
		எனில் (*cp == '-') {
			*ignore_errors = 1;
		} இல்லையெனில் எனில் (*cp == '@') {
			*disable_echo = 1;
		} இல்லையெனில் {
			/* all other characters terminate prefix processing */
			நிறுத்து;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	எனில் (*cp == '\0' || *cp == '#')
		திரும்பு (0);

	எனில் ((argv = makeargv(cp, &argc, 0, வெற்று, வெற்று)) == வெற்று)
		திரும்பு -1;

	/* Figure out which command we have */
	க்கு (i = 0; cmds[i].c != வெற்று; i++) {
		எனில் (argv[0] != வெற்று && strcasecmp(cmds[i].c, argv[0]) == 0)
			நிறுத்து;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	எனில் (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} இல்லையெனில் எனில் (cmdnum == -1) {
		error("Invalid command.");
		திரும்பு -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = வெற்று;
	optidx = 1;
	தேர்வு (cmdnum) {
	நிலை I_GET:
	நிலை I_REGET:
	நிலை I_REPUT:
	நிலை I_PUT:
		எனில் ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			திரும்பு -1;
		/* Get first pathname (mandatory) */
		எனில் (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			திரும்பு -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		எனில் (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		நிறுத்து;
	நிலை I_LINK:
		எனில் ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			திரும்பு -1;
		செல் parse_two_paths;
	நிலை I_COPY:
		எனில் ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			திரும்பு -1;
		செல் parse_two_paths;
	நிலை I_RENAME:
		எனில் ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			திரும்பு -1;
		செல் parse_two_paths;
	நிலை I_SYMLINK:
		எனில் ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			திரும்பு -1;
 parse_two_paths:
		எனில் (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			திரும்பு -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		நிறுத்து;
	நிலை I_MKDIR:
	நிலை I_LMKDIR:
		எனில் ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			திரும்பு -1;
		path1_mandatory = 1;
		செல் parse_one_path;
	நிலை I_RM:
	நிலை I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	நிலை I_CHDIR:
	நிலை I_LCHDIR:
		எனில் ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			திரும்பு -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		எனில் (argc - optidx < 1) {
			எனில் (!path1_mandatory)
				நிறுத்து; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			திரும்பு -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		எனில் (cmdnum != I_RM)
			undo_glob_escape(*path1);
		நிறுத்து;
	நிலை I_DF:
		எனில் ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			திரும்பு -1;
		/* Default to current directory if no path specified */
		எனில் (argc - optidx < 1)
			*path1 = வெற்று;
		இல்லையெனில் {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		நிறுத்து;
	நிலை I_LS:
		எனில் ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			திரும்பு(-1);
		/* Path is optional */
		எனில் (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		நிறுத்து;
	நிலை I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	நிலை I_SHELL:
		/* Uses the rest of the line */
		நிறுத்து;
	நிலை I_LUMASK:
	நிலை I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	நிலை I_CHOWN:
	நிலை I_CHGRP:
		எனில் ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			திரும்பு -1;
		/* Get numeric arg (mandatory) */
		எனில் (argc - optidx < 1)
			செல் need_இலக்கம்_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		எனில் (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_இலக்கம்_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			திரும்பு -1;
		}
		*n_arg = ll;
		எனில் (cmdnum == I_LUMASK)
			நிறுத்து;
		/* Get pathname (mandatory) */
		எனில் (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			திரும்பு -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		நிறுத்து;
	நிலை I_QUIT:
	நிலை I_PWD:
	நிலை I_LPWD:
	நிலை I_HELP:
	நிலை I_VERSION:
	நிலை I_PROGRESS:
		எனில் ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			திரும்பு -1;
		நிறுத்து;
	இயல்பு:
		fatal("Command not implemented");
	}

	*cpp = cp;
	திரும்பு(cmdnum);
}

நிலையான முழு
parse_dispatch_command(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *cmd, எழுத்து **pwd,
    மாறிலி எழுத்து *startdir, முழு err_abort, முழு echo_command)
{
	மாறிலி எழுத்து *ocmd = cmd;
	எழுத்து *path1, *path2, *tmp;
	முழு ignore_errors = 0, disable_echo = 1;
	முழு aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	முழு lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	முழு cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	எழுத்து path_buf[PATH_MAX];
	முழு err = 0;
	glob_t g;

	path1 = path2 = வெற்று;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	எனில் (ignore_errors != 0)
		err_abort = 0;

	எனில் (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, அளவு(g));

	/* Perform command */
	தேர்வு (cmdnum) {
	நிலை 0:
		/* Blank line */
		நிறுத்து;
	நிலை -1:
		/* Unrecognized command */
		err = -1;
		நிறுத்து;
	நிலை I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	நிலை I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		நிறுத்து;
	நிலை I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	நிலை I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		நிறுத்து;
	நிலை I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		நிறுத்து;
	நிலை I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		நிறுத்து;
	நிலை I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	நிலை I_LINK:
		எனில் (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		நிறுத்து;
	நிலை I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, வெற்று, &g);
		க்கு (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			எனில் (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			எனில் (err != 0 && err_abort)
				நிறுத்து;
		}
		நிறுத்து;
	நிலை I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		எனில் (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		இல்லையெனில்
			err = sftp_mkdir(conn, path1, &a, 1);
		நிறுத்து;
	நிலை I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		நிறுத்து;
	நிலை I_CHDIR:
		எனில் (path1 == வெற்று || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		எனில் ((tmp = sftp_realpath(conn, path1)) == வெற்று) {
			err = 1;
			நிறுத்து;
		}
		எனில் (sftp_stat(conn, tmp, 0, &aa) != 0) {
			விடுவி(tmp);
			err = 1;
			நிறுத்து;
		}
		எனில் (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			விடுவி(tmp);
			err = 1;
			நிறுத்து;
		}
		எனில் (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			விடுவி(tmp);
			err = 1;
			நிறுத்து;
		}
		விடுவி(*pwd);
		*pwd = tmp;
		நிறுத்து;
	நிலை I_LS:
		எனில் (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			நிறுத்து;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = வெற்று;
		எனில் (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		நிறுத்து;
	நிலை I_DF:
		/* Default to current directory if no path specified */
		எனில் (path1 == வெற்று)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		நிறுத்து;
	நிலை I_LCHDIR:
		எனில் (path1 == வெற்று || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		விடுவி(path1);
		path1 = tmp;
		எனில் (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		நிறுத்து;
	நிலை I_LMKDIR:
		எனில் (pflag) {
			எனில் (mkdir_path(path1, 0777) != 0)
				err = 1;
			நிறுத்து;
		}
		எனில் (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		நிறுத்து;
	நிலை I_LLS:
		local_do_ls(cmd);
		நிறுத்து;
	நிலை I_SHELL:
		local_do_shell(cmd);
		நிறுத்து;
	நிலை I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		நிறுத்து;
	நிலை I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, வெற்று, &g);
		க்கு (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			எனில் (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			எனில் (err != 0 && err_abort)
				நிறுத்து;
		}
		நிறுத்து;
	நிலை I_CHOWN:
	நிலை I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, வெற்று, &g);
		க்கு (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			எனில் ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				எனில் (err_abort) {
					err = -1;
					நிறுத்து;
				} இல்லையெனில்
					தொடர்;
			}
			எனில் (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				எனில் (err_abort) {
					err = -1;
					நிறுத்து;
				} இல்லையெனில்
					தொடர்;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			எனில் (cmdnum == I_CHOWN) {
				எனில் (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} இல்லையெனில் {
				எனில் (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			எனில் (err != 0 && err_abort)
				நிறுத்து;
		}
		நிறுத்து;
	நிலை I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		நிறுத்து;
	நிலை I_LPWD:
		எனில் (!getcwd(path_buf, அளவு(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			நிறுத்து;
		}
		mprintf("Local working directory: %s\n", path_buf);
		நிறுத்து;
	நிலை I_QUIT:
		/* Processed below */
		நிறுத்து;
	நிலை I_HELP:
		help();
		நிறுத்து;
	நிலை I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		நிறுத்து;
	நிலை I_PROGRESS:
		showprogress = !showprogress;
		எனில் (showprogress)
			printf("Progress meter enabled\n");
		இல்லையெனில்
			printf("Progress meter disabled\n");
		நிறுத்து;
	இயல்பு:
		fatal("%d is not implemented", cmdnum);
	}

	எனில் (g.gl_pathc)
		globfree(&g);
	விடுவி(path1);
	விடுவி(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	எனில் (err_abort && err != 0)
		திரும்பு (-1);
	இல்லையெனில் எனில் (cmdnum == I_QUIT)
		திரும்பு (1);

	திரும்பு (0);
}

#ifdef USE_LIBEDIT
நிலையான எழுத்து *
prompt(Edit_வரி *el)
{
	திரும்பு ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
நிலையான வெறுமை
complete_display(எழுத்து **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	கட்டமைப்பு winsize ws;
	எழுத்து *tmp;

	/* Count entries for sort and find longest */
	க்கு (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	எனில் (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	க்கு (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		எனில் (m >= columns) {
			printf("\n");
			m = 1;
		} இல்லையெனில்
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
நிலையான எழுத்து *
complete_ambiguous(மாறிலி எழுத்து *word, எழுத்து **list, size_t மொத்தம்)
{
	size_t i, j, matchlen;
	எழுத்து *tmp;
	முழு len;

	எனில் (word == வெற்று)
		திரும்பு வெற்று;

	எனில் (மொத்தம் == 0)
		திரும்பு xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	க்கு (i = 1; i < மொத்தம் && list[i] != வெற்று; i++) {
		க்கு (j = 0; j < matchlen; j++)
			எனில் (list[0][j] != list[i][j])
				நிறுத்து;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(வெற்று, 0);
	க்கு (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		எனில் (len <= 0 || i + (size_t)len > matchlen)
			நிறுத்து;
		i += (size_t)len;
	}
	/* If so, truncate */
	எனில் (i < matchlen)
		matchlen = i;

	எனில் (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		திரும்பு tmp;
	}

	திரும்பு xstrdup(word);
}

/* Autocomplete a sftp command */
நிலையான முழு
complete_cmd_parse(Edit_வரி *el, எழுத்து *cmd, முழு lastarg, எழுத்து quote,
    முழு terminated)
{
	u_int y, மொத்தம் = 0, cmdlen, tmplen;
	எழுத்து *tmp, **list, argterm[3];
	மாறிலி வரி_Info *lf;

	list = xcalloc((அளவு(cmds) / அளவு(*cmds)) + 1, அளவு(எழுத்து *));

	/* No command specified: display all available commands */
	எனில் (cmd == வெற்று) {
		க்கு (y = 0; cmds[y].c; y++)
			list[மொத்தம்++] = xstrdup(cmds[y].c);

		list[மொத்தம்] = வெற்று;
		complete_display(list, 0);

		க்கு (y = 0; list[y] != வெற்று; y++)
			விடுவி(list[y]);
		விடுவி(list);
		திரும்பு மொத்தம்;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	க்கு (y = 0; cmds[y].c; y++)  {
		எனில் (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[மொத்தம்++] = xstrdup(cmds[y].c);
	}
	list[மொத்தம்] = வெற்று;

	எனில் (மொத்தம் == 0) {
		விடுவி(list);
		திரும்பு 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, மொத்தம்);
	எனில் (மொத்தம் > 1)
		complete_display(list, 0);

	க்கு (y = 0; list[y]; y++)
		விடுவி(list[y]);
	விடுவி(list);

	எனில் (tmp != வெற்று) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		எனில் (tmplen > cmdlen)
			எனில் (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_வரி(el);
		/* Terminate argument cleanly */
		எனில் (மொத்தம் == 1) {
			y = 0;
			எனில் (!terminated)
				argterm[y++] = quote;
			எனில் (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			எனில் (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		விடுவி(tmp);
	}

	திரும்பு மொத்தம்;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
நிலையான முழு
complete_is_remote(எழுத்து *cmd, முழு cmdarg) {
	முழு i;

	எனில் (cmd == வெற்று)
		திரும்பு -1;

	க்கு (i = 0; cmds[i].c; i++) {
		எனில் (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			எனில் (cmdarg == 1)
				திரும்பு cmds[i].t;
			இல்லையெனில் எனில் (cmdarg == 2)
				திரும்பு cmds[i].t2;
			நிறுத்து;
		}
	}

	திரும்பு -1;
}

/* Autocomplete a filename "file" */
நிலையான முழு
complete_match(Edit_வரி *el, கட்டமைப்பு sftp_conn *conn, எழுத்து *remote_path,
    எழுத்து *file, முழு remote, முழு lastarg, எழுத்து quote, முழு terminated)
{
	glob_t g;
	எழுத்து *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	முழு clen;
	மாறிலி வரி_Info *lf;

	/* Glob from "file" location */
	எனில் (file == வெற்று)
		tmp = xstrdup("*");
	இல்லையெனில்
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, அளவு(g));
	எனில் (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, வெற்று, &g);
	} இல்லையெனில்
		(வெறுமை)glob(tmp, GLOB_DOOFFS|GLOB_MARK, வெற்று, &g);

	/* Determine length of pwd so we can trim completion display */
	க்கு (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		எனில் (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			எனில் (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			நிறுத்து;
		}
		எனில் (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		எனில் (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	விடுவி(tmp);
	tmp = வெற்று;

	எனில் (g.gl_matchc == 0)
		செல் out;

	எனில் (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	எனில் (file == வெற்று || hadglob)
		செல் out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? வெற்று : remote_path);
	விடுவி(tmp2);

	எனில் (tmp == வெற்று)
		செல் out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	க்கு (i = 0; i < filelen; i++) {
		எனில் (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} இல்லையெனில்
			isesc = 0;
	}

	எனில் (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(வெற்று, 0);
		க்கு (i = 0; i < len; i += clen) {
			எனில் ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > அளவு(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			தேர்வு (tmp2[i]) {
			நிலை '\'':
			நிலை '"':
			நிலை '\\':
			நிலை '\t':
			நிலை '[':
			நிலை ' ':
			நிலை '#':
			நிலை '*':
				எனில் (quote == '\0' || tmp2[i] == quote) {
					எனில் (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					நிறுத்து;
				}
				/* FALLTHROUGH */
			இயல்பு:
				எனில் (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				நிறுத்து;
			}
		}
	}

	lf = el_வரி(el);
	எனில் (g.gl_matchc == 1) {
		i = 0;
		எனில் (!terminated && quote != '\0')
			ins[i++] = quote;
		எனில் (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		எனில் (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	விடுவி(tmp);

 out:
	globfree(&g);
	திரும்பு g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
நிலையான unsigned எழுத்து
complete(Edit_வரி *el, முழு ch)
{
	எழுத்து **argv, *வரி, quote;
	முழு argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	மாறிலி வரி_Info *lf;
	கட்டமைப்பு complete_ctx *complete_ctx;

	lf = el_வரி(el);
	எனில் (el_get(el, EL_CLIENTDATA, (வெறுமை**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	வரி = xmalloc(cursor + 1);
	memcpy(வரி, lf->buffer, cursor);
	வரி[cursor] = '\0';
	argv = makeargv(வரி, &carg, 1, &quote, &terminated);
	விடுவி(வரி);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	வரி = xmalloc(len + 1);
	memcpy(வரி, lf->buffer, len);
	வரி[len] = '\0';
	argv = makeargv(வரி, &argc, 1, வெற்று, வெற்று);

	/* Ensure cursor is at EOL or a argument boundary */
	எனில் (வரி[cursor] != ' ' && வரி[cursor] != '\0' &&
	    வரி[cursor] != '\n') {
		விடுவி(வரி);
		திரும்பு ret;
	}

	எனில் (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, வெற்று, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} இல்லையெனில் எனில் (carg == 1 && cursor > 0 && வரி[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		எனில் (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} இல்லையெனில் எனில் (carg >= 1) {
		/* Handle file parsing */
		முழு remote = 0;
		முழு i = 0, cmdarg = 0;
		எழுத்து *filematch = வெற்று;

		எனில் (carg > 1 && வரி[cursor-1] != ' ')
			filematch = argv[carg - 1];

		க்கு (i = 1; i < carg; i++) {
			/* Skip flags */
			எனில் (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		எனில் (வரி[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		எனில் ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	விடுவி(வரி);
	திரும்பு ret;
}
#endif /* USE_LIBEDIT */

நிலையான முழு
interactive_loop(கட்டமைப்பு sftp_conn *conn, எழுத்து *file1, எழுத்து *file2)
{
	எழுத்து *remote_path;
	எழுத்து *dir = வெற்று, *startdir = வெற்று;
	எழுத்து cmd[2048];
	முழு err, interactive;
	Edit_வரி *el = வெற்று;
#ifdef USE_LIBEDIT
	மாறிலி எழுத்து *editor;
	History *hl = வெற்று;
	HistEvent hev;
	வெளி எழுத்து *__progname;
	கட்டமைப்பு complete_ctx complete_ctx;

	எனில் (!batchmode && isatty(STDIN_FILENO)) {
		எனில் ((el = el_init(__progname, stdin, stdout, stderr)) == வெற்று)
			fatal("Couldn't initialise editline");
		எனில் ((hl = history_init()) == வெற்று)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, வெற்று);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, வெற்று);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (வெறுமை*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", வெற்று);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", வெற்று);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", வெற்று);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", வெற்று);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", வெற்று);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", வெற்று);

		/* el_source() may have changed EL_EDITOR to vi */
		எனில் (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", வெற்று);
	}
#endif /* USE_LIBEDIT */

	எனில் ((remote_path = sftp_realpath(conn, ".")) == வெற்று)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	எனில் (file1 != வெற்று) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		எனில் (sftp_remote_is_dir(conn, dir) && file2 == வெற்று) {
			எனில் (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, அளவு cmd, "cd \"%s\"", dir);
			எனில் (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				விடுவி(dir);
				விடுவி(startdir);
				விடுவி(remote_path);
				விடுவி(conn);
				திரும்பு (-1);
			}
		} இல்லையெனில் {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			விடுவி(dir);
			விடுவி(startdir);
			விடுவி(remote_path);
			விடுவி(conn);
			திரும்பு (err);
		}
		விடுவி(dir);
	}

	setvbuf(stdout, வெற்று, _IOLBF, 0);
	setvbuf(infile, வெற்று, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	க்கு (;;) {
		கட்டமைப்பு sigaction sa;

		interrupted = 0;
		memset(&sa, 0, அளவு(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		எனில் (sigaction(SIGINT, &sa, வெற்று) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			நிறுத்து;
		}
		எனில் (el == வெற்று) {
			எனில் (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			எனில் (fgets(cmd, அளவு(cmd), infile) == வெற்று) {
				எனில் (interactive)
					printf("\n");
				எனில் (interrupted)
					தொடர்;
				நிறுத்து;
			}
		} இல்லையெனில் {
#ifdef USE_LIBEDIT
			மாறிலி எழுத்து *வரி;
			முழு மொத்தம் = 0;

			எனில் ((வரி = el_gets(el, &மொத்தம்)) == வெற்று ||
			    மொத்தம் <= 0) {
				printf("\n");
				எனில் (interrupted)
					தொடர்;
				நிறுத்து;
			}
			history(hl, &hev, H_ENTER, வரி);
			எனில் (strlcpy(cmd, வரி, அளவு(cmd)) >= அளவு(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				தொடர்;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == வெற்று);
		எனில் (err != 0)
			நிறுத்து;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	விடுவி(remote_path);
	விடுவி(startdir);
	விடுவி(conn);

#ifdef USE_LIBEDIT
	எனில் (hl != வெற்று)
		history_end(hl);
	எனில் (el != வெற்று)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	திரும்பு (err >= 0 ? 0 : -1);
}

நிலையான வெறுமை
connect_to_server(எழுத்து *path, எழுத்து **args, முழு *in, முழு *out)
{
	முழு c_in, c_out;
#ifdef USE_PIPES
	முழு pin[2], pout[2];

	எனில் ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#இல்லையெனில் /* USE_PIPES */
	முழு inout[2];

	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	எனில் ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	இல்லையெனில் எனில் (sshpid == 0) {
		எனில் ((dup2(c_in, STDIN_FILENO) == -1) ||
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

நிலையான வெறுமை
usage(வெறுமை)
{
	வெளி எழுத்து *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

முழு
முதன்மை(முழு argc, எழுத்து **argv)
{
	முழு r, in, out, ch, err, tmp, port = -1, noisy = 0;
	எழுத்து *host = வெற்று, *user, *cp, **cpp, *file2 = வெற்று;
	முழு debug_level = 0;
	எழுத்து *file1 = வெற்று, *sftp_server = வெற்று;
	எழுத்து *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = வெற்று;
	மாறிலி எழுத்து *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	வெளி முழு optind;
	வெளி எழுத்து *optarg;
	கட்டமைப்பு sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t இலக்கம்_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', அளவு(args));
	args.list = வெற்று;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	போது ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		தேர்வு (ch) {
		/* Passed through to ssh(1) */
		நிலை 'A':
		நிலை '4':
		நிலை '6':
		நிலை 'C':
			addargs(&args, "-%c", ch);
			நிறுத்து;
		/* Passed through to ssh(1) with argument */
		நிலை 'F':
		நிலை 'J':
		நிலை 'c':
		நிலை 'i':
		நிலை 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			நிறுத்து;
		நிலை 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			நிறுத்து;
		நிலை 'P':
			port = a2port(optarg);
			எனில் (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			நிறுத்து;
		நிலை 'v':
			எனில் (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			நிறுத்து;
		நிலை '1':
			fatal("SSH protocol v.1 is no longer supported");
			நிறுத்து;
		நிலை '2':
			/* accept silently */
			நிறுத்து;
		நிலை 'a':
			global_aflag = 1;
			நிறுத்து;
		நிலை 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			எனில் (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			நிறுத்து;
		நிலை 'b':
			எனில் (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			எனில் (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == வெற்று)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			நிறுத்து;
		நிலை 'f':
			global_fflag = 1;
			நிறுத்து;
		நிலை 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			நிறுத்து;
		நிலை 'p':
			global_pflag = 1;
			நிறுத்து;
		நிலை 'D':
			sftp_direct = optarg;
			நிறுத்து;
		நிலை 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			எனில் (errstr != வெற்று)
				usage();
			limit_kbps *= 1024; /* kbps */
			நிறுத்து;
		நிலை 'r':
			global_rflag = 1;
			நிறுத்து;
		நிலை 'R':
			இலக்கம்_requests = strtol(optarg, &cp, 10);
			எனில் (இலக்கம்_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			நிறுத்து;
		நிலை 's':
			sftp_server = optarg;
			நிறுத்து;
		நிலை 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			நிறுத்து;
		நிலை 'X':
			/* Please keep in sync with ssh.c -X */
			எனில் (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				எனில் (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				எனில் (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} இல்லையெனில் எனில் (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				எனில் (errstr != வெற்று) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				இலக்கம்_requests = (size_t)llv;
			} இல்லையெனில் {
				fatal("Invalid -X option");
			}
			நிறுத்து;
		நிலை 'h':
		இயல்பு:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	எனில் (!isatty(STDERR_FILENO))
		showprogress = 0;

	எனில் (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	எனில் (sftp_direct == வெற்று) {
		எனில் (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		தேர்வு (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		நிலை -1:
			usage();
			நிறுத்து;
		நிலை 0:
			எனில் (tmp != -1)
				port = tmp;
			நிறுத்து;
		இயல்பு:
			/* Try with user, host and path. */
			எனில் (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				நிறுத்து;
			/* Try with user and host. */
			எனில் (parse_user_host_port(*argv, &user, &host, வெற்று)
			    == 0)
				நிறுத்து;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			நிறுத்து;
		}
		file2 = *(argv + 1);

		எனில் (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		எனில் (port != -1)
			addargs(&args, "-oPort %d", port);
		எனில் (user != வெற்று) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		எனில் (sftp_server == வெற்று || strchr(sftp_server, '/') == வெற்று)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != வெற்று ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} இல்லையெனில் {
		எனில் ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		எனில் (cpp[0] == வெற்று)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, இலக்கம்_requests, limit_kbps);
	எனில் (conn == வெற்று)
		fatal("Couldn't initialise connection to server");

	எனில் (!quiet) {
		எனில் (sftp_direct == வெற்று)
			fprintf(stderr, "Connected to %s.\n", host);
		இல்லையெனில்
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#எனில் !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	எனில் (batchmode)
		fclose(infile);

	போது (waitpid(sshpid, வெற்று, 0) == -1 && sshpid > 1)
		எனில் (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
