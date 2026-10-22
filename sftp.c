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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/ioctl.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/statvfs.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <glob.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#ଅନ୍ତର୍ଭାଵ <histedit.h>
#ଅନ୍ୟଥା
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ Edit_ଧାଡ଼ି;
#endif
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <util.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"

#ଅନ୍ତର୍ଭାଵ "sftp.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sftp-common.h"
#ଅନ୍ତର୍ଭାଵ "sftp-client.h"
#ଅନ୍ତର୍ଭାଵ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା batchmode = 0;

/* PID of ssh transport process */
ସ୍ଥିର ଅସ୍ଥିର pid_t sshpid = -1;

/* Suppress diagnostic messages */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା global_fflag = 0;

/* SIGINT received during command processing */
ଅସ୍ଥିର sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
ସଂରଚନା complete_ctx {
	ସଂରଚନା sftp_conn *conn;
	ଅକ୍ଷର **remote_pathp;
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_glob(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*)(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା), glob_t *); /* proto for sftp-glob.c */

ବାହ୍ୟ ଅକ୍ଷର *__progname;

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
ଗଣନା sftp_command {
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

ସଂରଚନା CMD {
	ଅଚଳ ଅକ୍ଷର *c;
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା n;
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା t;	/* Completion type for the first argument */
	ଅଚଳ ପୂର୍ଣ୍ଣସଂଖ୍ୟା t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

ସ୍ଥିର ଅଚଳ ସଂରଚନା CMD cmds[] = {
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
	{ ଖାଲି,		-1,		-1,		-1	}
};

ସ୍ଥିର ଶୂନ୍ୟ
killchild(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	pid_t pid;

	pid = sshpid;
	ଯଦି (pid > 1) {
		kill(pid, SIGTERM);
		(ଶୂନ୍ୟ)waitpid(pid, ଖାଲି, 0);
	}

	_exit(1);
}

ସ୍ଥିର ଶୂନ୍ୟ
suspchild(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା save_errno = errno;
	ଯଦି (sshpid > 1) {
		kill(sshpid, signo);
		ଯେତେବେଳେ (waitpid(sshpid, ଖାଲି, WUNTRACED) == -1 && errno == EINTR)
			ଜାରି;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ସ୍ଥିର ଶୂନ୍ୟ
cmd_interrupt(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	ଅଚଳ ଅକ୍ଷର ସନ୍ଦେଶ[] = "\rInterrupt  \n";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା olderrno = errno;

	(ଶୂନ୍ୟ)ଲିଖ(STDERR_FILENO, ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ) - 1);
	interrupted = 1;
	errno = olderrno;
}

ସ୍ଥିର ଶୂନ୍ୟ
read_interrupt(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	interrupted = 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
sigchld_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା save_errno = errno;
	pid_t pid;
	ଅଚଳ ଅକ୍ଷର ସନ୍ଦେଶ[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	ଯେତେବେଳେ ((pid = waitpid(sshpid, ଖାଲି, WNOHANG)) == -1 && errno == EINTR)
		ଜାରି;
	ଯଦି (pid == sshpid) {
		ଯଦି (!quiet)
		    (ଶୂନ୍ୟ)ଲିଖ(STDERR_FILENO, ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

ସ୍ଥିର ଶୂନ୍ୟ
help(ଶୂନ୍ୟ)
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

ସ୍ଥିର ଶୂନ୍ୟ
local_do_shell(ଅଚଳ ଅକ୍ଷର *args)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;
	ଅକ୍ଷର *shell;
	pid_t pid;

	ଯଦି (!*args)
		args = ଖାଲି;

	ଯଦି ((shell = getenv("SHELL")) == ଖାଲି || *shell == '\0')
		shell = _PATH_BSHELL;

	ଯଦି ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	ଯଦି (pid == 0) {
		ଯଦି (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (ଅକ୍ଷର *)ଖାଲି);
		} ଅନ୍ୟଥା {
			debug3("Executing %s", shell);
			execl(shell, shell, (ଅକ୍ଷର *)ଖାଲି);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1)
		ଯଦି (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ଯଦି (!WIFEXITED(status))
		error("Shell exited abnormally");
	ଅନ୍ୟଥା ଯଦି (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

ସ୍ଥିର ଶୂନ୍ୟ
local_do_ls(ଅଚଳ ଅକ୍ଷର *args)
{
	ଯଦି (!args || !*args)
		local_do_shell(_PATH_LS);
	ଅନ୍ୟଥା {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା len = strlen(_PATH_LS " ") + strlen(args) + 1;
		ଅକ୍ଷର *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		ମୁକ୍ତ(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
ସ୍ଥିର ଅକ୍ଷର *
path_strip(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ଅକ୍ଷର *strip)
{
	size_t len;

	ଯଦି (strip == ଖାଲି || (len = strlen(strip)) == 0)
		ଫେରନ୍ତୁ (xstrdup(path));

	ଯଦି (strncmp(path, strip, len) == 0) {
		ଯଦି (strip[len - 1] != '/' && path[len] == '/')
			len++;
		ଫେରନ୍ତୁ (xstrdup(path + len));
	}

	ଫେରନ୍ତୁ (xstrdup(path));
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_getput_flags(ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *aflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *pflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *rflag)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	ଯେତେବେଳେ ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'a':
			*aflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			*fflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
		ସ୍ଥିତି 'P':
			*pflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'r':
		ସ୍ଥିତି 'R':
			*rflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_mkdir_flags(ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *pflag)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	ଯେତେବେଳେ ((ch = getopt(argc, argv, "p")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'p':
			*pflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_link_flags(ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *sflag)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	ଯେତେବେଳେ ((ch = getopt(argc, argv, "s")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 's':
			*sflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_rename_flags(ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *lflag)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	ଯେତେବେଳେ ((ch = getopt(argc, argv, "l")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'l':
			*lflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_ls_flags(ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *lflag)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	ଯେତେବେଳେ ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'a':
			*lflag |= LS_SHOW_ALL;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			*lflag &= ~SORT_FLAGS;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
			*lflag |= LS_SI_UNITS;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'r':
			*lflag |= LS_REVERSE_SORT;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("ls: Invalid flag -%c", optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_df_flags(ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *hflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *iflag)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	ଯେତେବେଳେ ((ch = getopt(argc, argv, "hi")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'h':
			*hflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'i':
			*iflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_ch_flags(ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *hflag)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	ଯେତେବେଳେ ((ch = getopt(argc, argv, "h")) != -1) {
		ବାଛ (ch) {
		ସ୍ଥିତି 'h':
			*hflag = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_no_flags(ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **argv, ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc)
{
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା opterr, optind, optopt, optreset;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch;

	optind = optreset = 1;
	opterr = 0;

	ଯେତେବେଳେ ((ch = getopt(argc, argv, "")) != -1) {
		ବାଛ (ch) {
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ଫେରନ୍ତୁ -1;
		}
	}

	ଫେରନ୍ତୁ optind;
}

ସ୍ଥିର ଅକ୍ଷର *
escape_glob(ଅଚଳ ଅକ୍ଷର *s)
{
	size_t i, o, len;
	ଅକ୍ଷର *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	ପାଇଁ (i = o = 0; i < len; i++) {
		ଯଦି (strchr("[]?*\\", s[i]) != ଖାଲି)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	ଫେରନ୍ତୁ ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
ସ୍ଥିର ଅକ୍ଷର *
make_absolute_pwd_glob(ଅକ୍ଷର *p, ଅଚଳ ଅକ୍ଷର *pwd)
{
	ଅକ୍ଷର *ret, *escpwd;

	escpwd = escape_glob(pwd);
	ଯଦି (p == ଖାଲି)
		ଫେରନ୍ତୁ escpwd;
	ret = sftp_make_absolute(p, escpwd);
	ମୁକ୍ତ(escpwd);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
local_is_dir(ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା stat sb;

	ଯଦି (stat(path, &sb) == -1)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ S_ISDIR(sb.st_mode);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_get(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *src, ଅଚଳ ଅକ୍ଷର *dst,
    ଅଚଳ ଅକ୍ଷର *pwd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା pflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fflag)
{
	ଅକ୍ଷର *filename, *abs_src = ଖାଲି, *abs_dst = ଖାଲି, *tmp = ଖାଲି;
	glob_t g;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, ଆକାର(g));

	debug3("Looking up %s", abs_src);
	ଯଦି ((r = sftp_glob(conn, abs_src, GLOB_MARK, ଖାଲି, &g)) != 0) {
		ଯଦି (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} ଅନ୍ୟଥା {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		ଯାଅ out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	ଯଦି (g.gl_matchc > 1 && dst != ଖାଲି && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		ଯାଅ out;
	}

	ପାଇଁ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ଯଦି ((filename = basename(tmp)) == ଖାଲି) {
			error("basename %s: %s", tmp, strerror(errno));
			ମୁକ୍ତ(tmp);
			err = -1;
			ଯାଅ out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		ଯଦି (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		ଯଦି (g.gl_matchc == 1 && dst) {
			ଯଦି (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} ଅନ୍ୟଥା {
				abs_dst = xstrdup(dst);
			}
		} ଅନ୍ୟଥା ଯଦି (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} ଅନ୍ୟଥା {
			abs_dst = xstrdup(filename);
		}
		ମୁକ୍ତ(tmp);

		resume |= global_aflag;
		ଯଦି (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ଅନ୍ୟଥା ଯଦି (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		ଯଦି (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ଯଦି (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ଖାଲି, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ଅନ୍ୟଥା {
			ଯଦି (sftp_download(conn, g.gl_pathv[i], abs_dst, ଖାଲି,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		ମୁକ୍ତ(abs_dst);
		abs_dst = ଖାଲି;
	}

out:
	ମୁକ୍ତ(abs_src);
	globfree(&g);
	ଫେରନ୍ତୁ(err);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_put(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *src, ଅଚଳ ଅକ୍ଷର *dst,
    ଅଚଳ ଅକ୍ଷର *pwd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା pflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା rflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା resume, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fflag)
{
	ଅକ୍ଷର *tmp_dst = ଖାଲି;
	ଅକ୍ଷର *abs_dst = ଖାଲି;
	ଅକ୍ଷର *tmp = ଖାଲି, *filename = ଖାଲି;
	glob_t g;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, dst_is_dir = 1;
	ସଂରଚନା stat sb;

	ଯଦି (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, ଆକାର(g));
	debug3("Looking up %s", src);
	ଯଦି (glob(src, GLOB_NOCHECK | GLOB_MARK, ଖାଲି, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		ଯାଅ out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	ଯଦି (tmp_dst != ଖାଲି)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	ଯଦି (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		ଯାଅ out;
	}

	ପାଇଁ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		ଯଦି (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			ଜାରି;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		ଯଦି ((filename = basename(tmp)) == ଖାଲି) {
			error("basename %s: %s", tmp, strerror(errno));
			ମୁକ୍ତ(tmp);
			err = -1;
			ଯାଅ out;
		}
		/* Special handling for source of '..' */
		ଯଦି (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		ମୁକ୍ତ(abs_dst);
		abs_dst = ଖାଲି;
		ଯଦି (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			ଯଦି (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			ଅନ୍ୟଥା
				abs_dst = xstrdup(tmp_dst);
		} ଅନ୍ୟଥା ଯଦି (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} ଅନ୍ୟଥା {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		ମୁକ୍ତ(tmp);

		resume |= global_aflag;
		ଯଦି (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ଅନ୍ୟଥା ଯଦି (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		ଯଦି (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ଯଦି (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ଅନ୍ୟଥା {
			ଯଦି (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	ମୁକ୍ତ(abs_dst);
	ମୁକ୍ତ(tmp_dst);
	globfree(&g);
	ଫେରନ୍ତୁ(err);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sdirent_comp(ଅଚଳ ଶୂନ୍ୟ *aa, ଅଚଳ ଶୂନ୍ୟ *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	ଯଦି (sort_flag & LS_NAME_SORT)
		ଫେରନ୍ତୁ (rmul * strcmp(a->filename, b->filename));
	ଅନ୍ୟଥା ଯଦି (sort_flag & LS_TIME_SORT)
		ଫେରନ୍ତୁ (rmul * NCMP(a->a.mtime, b->a.mtime));
	ଅନ୍ୟଥା ଯଦି (sort_flag & LS_SIZE_SORT)
		ଫେରନ୍ତୁ (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_ls_dir(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path,
    ଅଚଳ ଅକ୍ଷର *strip_path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lflag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	ଯଦି ((n = sftp_readdir(conn, path, &d)) != 0)
		ଫେରନ୍ତୁ (n);

	ଯଦି (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		ସଂରଚନା winsize ws;
		ଅକ୍ଷର *tmp;

		/* Count entries for sort and find longest filename */
		ପାଇଁ (n = 0; d[n] != ଖାଲି; n++) {
			ଯଦି (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		ମୁକ୍ତ(tmp);

		ଯଦି (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	ଯଦି (lflag & SORT_FLAGS) {
		ପାଇଁ (n = 0; d[n] != ଖାଲି; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, ଆକାର(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	ପାଇଁ (n = 0; d[n] != ଖାଲି && !interrupted; n++) {
		ଅକ୍ଷର *tmp, *fname;

		ଯଦି (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			ଜାରି;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		ମୁକ୍ତ(tmp);

		ଯଦି (lflag & LS_LONG_VIEW) {
			ଯଦି ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				ଅକ୍ଷର *lname;
				ସଂରଚନା stat sb;
				ଅଚଳ ଅକ୍ଷର *user = ଖାଲି, *group = ଖାଲି;

				memset(&sb, 0, ଆକାର(sb));
				attrib_to_stat(&d[n]->a, &sb);
				ଯଦି ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				ମୁକ୍ତ(lname);
			} ଅନ୍ୟଥା
				mprintf("%s\n", d[n]->longname);
		} ଅନ୍ୟଥା {
			mprintf("%-*s", colspace, fname);
			ଯଦି (c >= columns) {
				printf("\n");
				c = 1;
			} ଅନ୍ୟଥା
				c++;
		}

		ମୁକ୍ତ(fname);
	}

	ଯଦି (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sglob_comp(ଅଚଳ ଶୂନ୍ୟ *aa, ଅଚଳ ଶୂନ୍ୟ *bb)
{
	u_int a = *(ଅଚଳ u_int *)aa;
	u_int b = *(ଅଚଳ u_int *)bb;
	ଅଚଳ ଅକ୍ଷର *ap = sort_glob->gl_pathv[a];
	ଅଚଳ ଅକ୍ଷର *bp = sort_glob->gl_pathv[b];
	ଅଚଳ ସଂରଚନା stat *as = sort_glob->gl_statv[a];
	ଅଚଳ ସଂରଚନା stat *bs = sort_glob->gl_statv[b];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	ଯଦି (as == ଖାଲି || bs == ଖାଲି)
		ଫେରନ୍ତୁ (as == bs) ? 0 : (as == ଖାଲି ? rmul : -rmul);
	ଯଦି (sort_flag & LS_NAME_SORT)
		ଫେରନ୍ତୁ (rmul * strcmp(ap, bp));
	ଅନ୍ୟଥା ଯଦି (sort_flag & LS_TIME_SORT) {
#ଯଦି defined(HAVE_STRUCT_STAT_ST_MTIM)
		ଯଦି (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			ଫେରନ୍ତୁ 0;
		ଫେରନ୍ତୁ timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#ନଚେତଯଦି defined(HAVE_STRUCT_STAT_ST_MTIME)
		ଫେରନ୍ତୁ (rmul * NCMP(as->st_mtime, bs->st_mtime));
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ rmul * 1;
#endif
	} ଅନ୍ୟଥା ଯଦି (sort_flag & LS_SIZE_SORT)
		ଫେରନ୍ତୁ (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_globbed_ls(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path,
    ଅଚଳ ଅକ୍ଷର *strip_path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lflag)
{
	ଅକ୍ଷର *fname, *lname;
	glob_t g;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err, r;
	ସଂରଚନା winsize ws;
	u_int i, j, nentries, *indices = ଖାଲି, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, ଆକାର(g));

	ଯଦି ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ଖାଲି, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		ଯଦି (g.gl_pathc)
			globfree(&g);
		ଯଦି (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} ଅନ୍ୟଥା {
			error("Can't ls: \"%s\" not found", path);
		}
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (interrupted)
		ଯାଅ out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	ଯଦି (g.gl_matchc == 1 && g.gl_statv[0] != ଖାଲି &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		ଫେରନ୍ତୁ err;
	}

	ଯଦି (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	ଯଦି (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		ପାଇଁ (i = 0; g.gl_pathv[i]; i++)
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
	ପାଇଁ (nentries = 0; g.gl_pathv[nentries] != ଖାଲି; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, ଆକାର(*indices));
	ପାଇଁ (i = 0; i < nentries; i++)
		indices[i] = i;

	ଯଦି (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, ଆକାର(*indices), sglob_comp);
		sort_glob = ଖାଲି;
	}

	get_remote_user_groups_from_glob(conn, &g);
	ପାଇଁ (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		ଯଦି (lflag & LS_LONG_VIEW) {
			ଅଚଳ ଅକ୍ଷର *user = ଖାଲି, *group = ଖାଲି;

			ଯଦି (g.gl_statv[i] == ଖାଲି) {
				error("no stat information for %s", fname);
				ମୁକ୍ତ(fname);
				ଜାରି;
			}
			ଯଦି ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			ମୁକ୍ତ(lname);
		} ଅନ୍ୟଥା {
			mprintf("%-*s", colspace, fname);
			ଯଦି (c >= columns) {
				printf("\n");
				c = 1;
			} ଅନ୍ୟଥା
				c++;
		}
		ମୁକ୍ତ(fname);
	}

	ଯଦି (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	ଯଦି (g.gl_pathc)
		globfree(&g);
	ମୁକ୍ତ(indices);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_df(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା hflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା iflag)
{
	ସଂରଚନା sftp_statvfs st;
	ଅକ୍ଷର s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	ଅକ୍ଷର s_ମୂଳ[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	ଅକ୍ଷର s_icapacity[16], s_dcapacity[16];

	ଯଦି (sftp_statvfs(conn, path, &st, 1) == -1)
		ଫେରନ୍ତୁ -1;
	ଯଦି (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", ଆକାର(s_icapacity));
	ଅନ୍ୟଥା {
		snprintf(s_icapacity, ଆକାର(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	ଯଦି (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", ଆକାର(s_dcapacity));
	ଅନ୍ୟଥା {
		snprintf(s_dcapacity, ଆକାର(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	ଯଦି (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} ଅନ୍ୟଥା ଯଦି (hflag) {
		strlcpy(s_used, "error", ଆକାର(s_used));
		strlcpy(s_avail, "error", ଆକାର(s_avail));
		strlcpy(s_ମୂଳ, "error", ଆକାର(s_ମୂଳ));
		strlcpy(s_total, "error", ଆକାର(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_ମୂଳ);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_ମୂଳ, s_dcapacity);
	} ଅନ୍ୟଥା {
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
	ଫେରନ୍ତୁ 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
ସ୍ଥିର ଶୂନ୍ୟ
undo_glob_escape(ଅକ୍ଷର *s)
{
	size_t i, j;

	ପାଇଁ (i = j = 0;;) {
		ଯଦି (s[i] == '\0') {
			s[j] = '\0';
			ଫେରନ୍ତୁ;
		}
		ଯଦି (s[i] != '\\') {
			s[j++] = s[i++];
			ଜାରି;
		}
		/* s[i] == '\\' */
		++i;
		ବାଛ (s[i]) {
		ସ୍ଥିତି '?':
		ସ୍ଥିତି '[':
		ସ୍ଥିତି '*':
		ସ୍ଥିତି '\\':
			s[j++] = s[i++];
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '\0':
			s[j++] = '\\';
			s[j] = '\0';
			ଫେରନ୍ତୁ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			s[j++] = '\\';
			s[j++] = s[i++];
			ଭାଙ୍ଗ;
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
ସ୍ଥିର ଅକ୍ଷର **
makeargv(ଅଚଳ ଅକ୍ଷର *arg, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *argcp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sloppy, ଅକ୍ଷର *lastquote,
    u_int *terminated)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, quot;
	size_t i, j;
	ସ୍ଥିର ଅକ୍ଷର argvs[MAXARGLEN];
	ସ୍ଥିର ଅକ୍ଷର *argv[MAXARGS + 1];
	ଗଣନା { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	ଯଦି (strlen(arg) > ଆକାର(argvs) - 1) {
 args_too_longs:
		error("string too long");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (terminated != ଖାଲି)
		*terminated = 1;
	ଯଦି (lastquote != ଖାଲି)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	ପାଇଁ (;;) {
		ଯଦି ((size_t)argc >= ଆକାର(argv) / ଆକାର(*argv)){
			error("Too many arguments.");
			ଫେରନ୍ତୁ ଖାଲି;
		}
		ଯଦି (isspace((unsigned ଅକ୍ଷର)arg[i])) {
			ଯଦି (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} ଅନ୍ୟଥା ଯଦି (state != MA_START)
				argvs[j++] = arg[i];
		} ଅନ୍ୟଥା ଯଦି (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			ଯଦି (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				ଯଦି (lastquote != ଖାଲି)
					*lastquote = arg[i];
			} ଅନ୍ୟଥା ଯଦି (state == MA_UNQUOTED)
				state = q;
			ଅନ୍ୟଥା ଯଦି (state == q)
				state = MA_UNQUOTED;
			ଅନ୍ୟଥା
				argvs[j++] = arg[i];
		} ଅନ୍ୟଥା ଯଦି (arg[i] == '\\') {
			ଯଦି (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				ଯଦି (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} ଅନ୍ୟଥା ଯଦି (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					ଯଦି (j >= ଆକାର(argvs) - 5)
						ଯାଅ args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} ଅନ୍ୟଥା {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} ଅନ୍ୟଥା {
				ଯଦି (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					ଯଦି (lastquote != ଖାଲି)
						*lastquote = '\0';
				}
				ଯଦି (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} ଅନ୍ୟଥା {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					ଯଦି (arg[i] == '\0')
						ଯାଅ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} ଅନ୍ୟଥା ଯଦି (arg[i] == '#') {
			ଯଦି (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			ଅନ୍ୟଥା
				ଯାଅ string_done;
		} ଅନ୍ୟଥା ଯଦି (arg[i] == '\0') {
			ଯଦି (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				ଯଦି (sloppy) {
					state = MA_UNQUOTED;
					ଯଦି (terminated != ଖାଲି)
						*terminated = 0;
					ଯାଅ string_done;
				}
				error("Unterminated quoted argument");
				ଫେରନ୍ତୁ ଖାଲି;
			}
 string_done:
			ଯଦି (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			ଭାଙ୍ଗ;
		} ଅନ୍ୟଥା {
			ଯଦି (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				ଯଦି (lastquote != ଖାଲି)
					*lastquote = '\0';
			}
			ଯଦି ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				ଯଦି (j >= ଆକାର(argvs) - 3)
					ଯାଅ args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} ଅନ୍ୟଥା
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	ଫେରନ୍ତୁ argv;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_args(ଅଚଳ ଅକ୍ଷର **cpp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ignore_errors, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *disable_echo, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *aflag,
	  ପୂର୍ଣ୍ଣସଂଖ୍ୟା *fflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *hflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *iflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *lflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *pflag,
	  ପୂର୍ଣ୍ଣସଂଖ୍ୟା *rflag, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *sflag,
    unsigned long *n_arg, ଅକ୍ଷର **path1, ଅକ୍ଷର **path2)
{
	ଅଚଳ ଅକ୍ଷର *cmd, *cp = *cpp;
	ଅକ୍ଷର *cp2, **argv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା base = 0;
	long long ll;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	ପାଇଁ (;*cp != '\0'; cp++) {
		ଯଦି (*cp == '-') {
			*ignore_errors = 1;
		} ଅନ୍ୟଥା ଯଦି (*cp == '@') {
			*disable_echo = 1;
		} ଅନ୍ୟଥା {
			/* all other characters terminate prefix processing */
			ଭାଙ୍ଗ;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	ଯଦି (*cp == '\0' || *cp == '#')
		ଫେରନ୍ତୁ (0);

	ଯଦି ((argv = makeargv(cp, &argc, 0, ଖାଲି, ଖାଲି)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	/* Figure out which command we have */
	ପାଇଁ (i = 0; cmds[i].c != ଖାଲି; i++) {
		ଯଦି (argv[0] != ଖାଲି && strcasecmp(cmds[i].c, argv[0]) == 0)
			ଭାଙ୍ଗ;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	ଯଦି (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} ଅନ୍ୟଥା ଯଦି (cmdnum == -1) {
		error("Invalid command.");
		ଫେରନ୍ତୁ -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ଖାଲି;
	optidx = 1;
	ବାଛ (cmdnum) {
	ସ୍ଥିତି I_GET:
	ସ୍ଥିତି I_REGET:
	ସ୍ଥିତି I_REPUT:
	ସ୍ଥିତି I_PUT:
		ଯଦି ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			ଫେରନ୍ତୁ -1;
		/* Get first pathname (mandatory) */
		ଯଦି (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			ଫେରନ୍ତୁ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		ଯଦି (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LINK:
		ଯଦି ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			ଫେରନ୍ତୁ -1;
		ଯାଅ parse_two_paths;
	ସ୍ଥିତି I_COPY:
		ଯଦି ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ଫେରନ୍ତୁ -1;
		ଯାଅ parse_two_paths;
	ସ୍ଥିତି I_RENAME:
		ଯଦି ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			ଫେରନ୍ତୁ -1;
		ଯାଅ parse_two_paths;
	ସ୍ଥିତି I_SYMLINK:
		ଯଦି ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ଫେରନ୍ତୁ -1;
 parse_two_paths:
		ଯଦି (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			ଫେରନ୍ତୁ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_MKDIR:
	ସ୍ଥିତି I_LMKDIR:
		ଯଦି ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			ଫେରନ୍ତୁ -1;
		path1_mandatory = 1;
		ଯାଅ parse_one_path;
	ସ୍ଥିତି I_RM:
	ସ୍ଥିତି I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	ସ୍ଥିତି I_CHDIR:
	ସ୍ଥିତି I_LCHDIR:
		ଯଦି ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ଫେରନ୍ତୁ -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		ଯଦି (argc - optidx < 1) {
			ଯଦି (!path1_mandatory)
				ଭାଙ୍ଗ; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			ଫେରନ୍ତୁ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		ଯଦି (cmdnum != I_RM)
			undo_glob_escape(*path1);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_DF:
		ଯଦି ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			ଫେରନ୍ତୁ -1;
		/* Default to current directory if no path specified */
		ଯଦି (argc - optidx < 1)
			*path1 = ଖାଲି;
		ଅନ୍ୟଥା {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LS:
		ଯଦି ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			ଫେରନ୍ତୁ(-1);
		/* Path is optional */
		ଯଦି (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	ସ୍ଥିତି I_SHELL:
		/* Uses the rest of the line */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LUMASK:
	ସ୍ଥିତି I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	ସ୍ଥିତି I_CHOWN:
	ସ୍ଥିତି I_CHGRP:
		ଯଦି ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			ଫେରନ୍ତୁ -1;
		/* Get numeric arg (mandatory) */
		ଯଦି (argc - optidx < 1)
			ଯାଅ need_ଅଙ୍କ_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		ଯଦି (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_ଅଙ୍କ_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			ଫେରନ୍ତୁ -1;
		}
		*n_arg = ll;
		ଯଦି (cmdnum == I_LUMASK)
			ଭାଙ୍ଗ;
		/* Get pathname (mandatory) */
		ଯଦି (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			ଫେରନ୍ତୁ -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_QUIT:
	ସ୍ଥିତି I_PWD:
	ସ୍ଥିତି I_LPWD:
	ସ୍ଥିତି I_HELP:
	ସ୍ଥିତି I_VERSION:
	ସ୍ଥିତି I_PROGRESS:
		ଯଦି ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ଫେରନ୍ତୁ -1;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("Command not implemented");
	}

	*cpp = cp;
	ଫେରନ୍ତୁ(cmdnum);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_dispatch_command(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *cmd, ଅକ୍ଷର **pwd,
    ଅଚଳ ଅକ୍ଷର *startdir, ପୂର୍ଣ୍ଣସଂଖ୍ୟା err_abort, ପୂର୍ଣ୍ଣସଂଖ୍ୟା echo_command)
{
	ଅଚଳ ଅକ୍ଷର *ocmd = cmd;
	ଅକ୍ଷର *path1, *path2, *tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ignore_errors = 0, disable_echo = 1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	ଅକ୍ଷର path_buf[PATH_MAX];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err = 0;
	glob_t g;

	path1 = path2 = ଖାଲି;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	ଯଦି (ignore_errors != 0)
		err_abort = 0;

	ଯଦି (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, ଆକାର(g));

	/* Perform command */
	ବାଛ (cmdnum) {
	ସ୍ଥିତି 0:
		/* Blank line */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି -1:
		/* Unrecognized command */
		err = -1;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	ସ୍ଥିତି I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	ସ୍ଥିତି I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	ସ୍ଥିତି I_LINK:
		ଯଦି (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ଖାଲି, &g);
		ପାଇଁ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ଯଦି (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			ଯଦି (err != 0 && err_abort)
				ଭାଙ୍ଗ;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		ଯଦି (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		ଅନ୍ୟଥା
			err = sftp_mkdir(conn, path1, &a, 1);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_CHDIR:
		ଯଦି (path1 == ଖାଲି || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		ଯଦି ((tmp = sftp_realpath(conn, path1)) == ଖାଲି) {
			err = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି (sftp_stat(conn, tmp, 0, &aa) != 0) {
			ମୁକ୍ତ(tmp);
			err = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			ମୁକ୍ତ(tmp);
			err = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			ମୁକ୍ତ(tmp);
			err = 1;
			ଭାଙ୍ଗ;
		}
		ମୁକ୍ତ(*pwd);
		*pwd = tmp;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LS:
		ଯଦି (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			ଭାଙ୍ଗ;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ଖାଲି;
		ଯଦି (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_DF:
		/* Default to current directory if no path specified */
		ଯଦି (path1 == ଖାଲି)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LCHDIR:
		ଯଦି (path1 == ଖାଲି || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		ମୁକ୍ତ(path1);
		path1 = tmp;
		ଯଦି (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LMKDIR:
		ଯଦି (pflag) {
			ଯଦି (mkdir_path(path1, 0777) != 0)
				err = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LLS:
		local_do_ls(cmd);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_SHELL:
		local_do_shell(cmd);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ଖାଲି, &g);
		ପାଇଁ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ଯଦି (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			ଯଦି (err != 0 && err_abort)
				ଭାଙ୍ଗ;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_CHOWN:
	ସ୍ଥିତି I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ଖାଲି, &g);
		ପାଇଁ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ଯଦି ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				ଯଦି (err_abort) {
					err = -1;
					ଭାଙ୍ଗ;
				} ଅନ୍ୟଥା
					ଜାରି;
			}
			ଯଦି (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				ଯଦି (err_abort) {
					err = -1;
					ଭାଙ୍ଗ;
				} ଅନ୍ୟଥା
					ଜାରି;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			ଯଦି (cmdnum == I_CHOWN) {
				ଯଦି (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} ଅନ୍ୟଥା {
				ଯଦି (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			ଯଦି (err != 0 && err_abort)
				ଭାଙ୍ଗ;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_LPWD:
		ଯଦି (!getcwd(path_buf, ଆକାର(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			ଭାଙ୍ଗ;
		}
		mprintf("Local working directory: %s\n", path_buf);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_QUIT:
		/* Processed below */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_HELP:
		help();
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		ଭାଙ୍ଗ;
	ସ୍ଥିତି I_PROGRESS:
		showprogress = !showprogress;
		ଯଦି (showprogress)
			printf("Progress meter enabled\n");
		ଅନ୍ୟଥା
			printf("Progress meter disabled\n");
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("%d is not implemented", cmdnum);
	}

	ଯଦି (g.gl_pathc)
		globfree(&g);
	ମୁକ୍ତ(path1);
	ମୁକ୍ତ(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	ଯଦି (err_abort && err != 0)
		ଫେରନ୍ତୁ (-1);
	ଅନ୍ୟଥା ଯଦି (cmdnum == I_QUIT)
		ଫେରନ୍ତୁ (1);

	ଫେରନ୍ତୁ (0);
}

#ifdef USE_LIBEDIT
ସ୍ଥିର ଅକ୍ଷର *
prompt(Edit_ଧାଡ଼ି *el)
{
	ଫେରନ୍ତୁ ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
ସ୍ଥିର ଶୂନ୍ୟ
complete_display(ଅକ୍ଷର **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	ସଂରଚନା winsize ws;
	ଅକ୍ଷର *tmp;

	/* Count entries for sort and find longest */
	ପାଇଁ (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	ଯଦି (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	ପାଇଁ (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		ଯଦି (m >= columns) {
			printf("\n");
			m = 1;
		} ଅନ୍ୟଥା
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
ସ୍ଥିର ଅକ୍ଷର *
complete_ambiguous(ଅଚଳ ଅକ୍ଷର *word, ଅକ୍ଷର **list, size_t ଗଣନା_2)
{
	size_t i, j, matchlen;
	ଅକ୍ଷର *tmp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len;

	ଯଦି (word == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;

	ଯଦି (ଗଣନା_2 == 0)
		ଫେରନ୍ତୁ xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	ପାଇଁ (i = 1; i < ଗଣନା_2 && list[i] != ଖାଲି; i++) {
		ପାଇଁ (j = 0; j < matchlen; j++)
			ଯଦି (list[0][j] != list[i][j])
				ଭାଙ୍ଗ;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ଖାଲି, 0);
	ପାଇଁ (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		ଯଦି (len <= 0 || i + (size_t)len > matchlen)
			ଭାଙ୍ଗ;
		i += (size_t)len;
	}
	/* If so, truncate */
	ଯଦି (i < matchlen)
		matchlen = i;

	ଯଦି (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		ଫେରନ୍ତୁ tmp;
	}

	ଫେରନ୍ତୁ xstrdup(word);
}

/* Autocomplete a sftp command */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
complete_cmd_parse(Edit_ଧାଡ଼ି *el, ଅକ୍ଷର *cmd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lastarg, ଅକ୍ଷର quote,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା terminated)
{
	u_int y, ଗଣନା_2 = 0, cmdlen, tmplen;
	ଅକ୍ଷର *tmp, **list, argterm[3];
	ଅଚଳ ଧାଡ଼ି_Info *lf;

	list = xcalloc((ଆକାର(cmds) / ଆକାର(*cmds)) + 1, ଆକାର(ଅକ୍ଷର *));

	/* No command specified: display all available commands */
	ଯଦି (cmd == ଖାଲି) {
		ପାଇଁ (y = 0; cmds[y].c; y++)
			list[ଗଣନା_2++] = xstrdup(cmds[y].c);

		list[ଗଣନା_2] = ଖାଲି;
		complete_display(list, 0);

		ପାଇଁ (y = 0; list[y] != ଖାଲି; y++)
			ମୁକ୍ତ(list[y]);
		ମୁକ୍ତ(list);
		ଫେରନ୍ତୁ ଗଣନା_2;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	ପାଇଁ (y = 0; cmds[y].c; y++)  {
		ଯଦି (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[ଗଣନା_2++] = xstrdup(cmds[y].c);
	}
	list[ଗଣନା_2] = ଖାଲି;

	ଯଦି (ଗଣନା_2 == 0) {
		ମୁକ୍ତ(list);
		ଫେରନ୍ତୁ 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, ଗଣନା_2);
	ଯଦି (ଗଣନା_2 > 1)
		complete_display(list, 0);

	ପାଇଁ (y = 0; list[y]; y++)
		ମୁକ୍ତ(list[y]);
	ମୁକ୍ତ(list);

	ଯଦି (tmp != ଖାଲି) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		ଯଦି (tmplen > cmdlen)
			ଯଦି (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_ଧାଡ଼ି(el);
		/* Terminate argument cleanly */
		ଯଦି (ଗଣନା_2 == 1) {
			y = 0;
			ଯଦି (!terminated)
				argterm[y++] = quote;
			ଯଦି (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			ଯଦି (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		ମୁକ୍ତ(tmp);
	}

	ଫେରନ୍ତୁ ଗଣନା_2;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
complete_is_remote(ଅକ୍ଷର *cmd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cmdarg) {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (cmd == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	ପାଇଁ (i = 0; cmds[i].c; i++) {
		ଯଦି (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			ଯଦି (cmdarg == 1)
				ଫେରନ୍ତୁ cmds[i].t;
			ଅନ୍ୟଥା ଯଦି (cmdarg == 2)
				ଫେରନ୍ତୁ cmds[i].t2;
			ଭାଙ୍ଗ;
		}
	}

	ଫେରନ୍ତୁ -1;
}

/* Autocomplete a filename "file" */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
complete_match(Edit_ଧାଡ଼ି *el, ସଂରଚନା sftp_conn *conn, ଅକ୍ଷର *remote_path,
    ଅକ୍ଷର *file, ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lastarg, ଅକ୍ଷର quote, ପୂର୍ଣ୍ଣସଂଖ୍ୟା terminated)
{
	glob_t g;
	ଅକ୍ଷର *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା clen;
	ଅଚଳ ଧାଡ଼ି_Info *lf;

	/* Glob from "file" location */
	ଯଦି (file == ଖାଲି)
		tmp = xstrdup("*");
	ଅନ୍ୟଥା
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, ଆକାର(g));
	ଯଦି (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ଖାଲି, &g);
	} ଅନ୍ୟଥା
		(ଶୂନ୍ୟ)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ଖାଲି, &g);

	/* Determine length of pwd so we can trim completion display */
	ପାଇଁ (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		ଯଦି (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			ଯଦି (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			ଭାଙ୍ଗ;
		}
		ଯଦି (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		ଯଦି (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	ମୁକ୍ତ(tmp);
	tmp = ଖାଲି;

	ଯଦି (g.gl_matchc == 0)
		ଯାଅ out;

	ଯଦି (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	ଯଦି (file == ଖାଲି || hadglob)
		ଯାଅ out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? ଖାଲି : remote_path);
	ମୁକ୍ତ(tmp2);

	ଯଦି (tmp == ଖାଲି)
		ଯାଅ out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	ପାଇଁ (i = 0; i < filelen; i++) {
		ଯଦି (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} ଅନ୍ୟଥା
			isesc = 0;
	}

	ଯଦି (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(ଖାଲି, 0);
		ପାଇଁ (i = 0; i < len; i += clen) {
			ଯଦି ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > ଆକାର(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			ବାଛ (tmp2[i]) {
			ସ୍ଥିତି '\'':
			ସ୍ଥିତି '"':
			ସ୍ଥିତି '\\':
			ସ୍ଥିତି '\t':
			ସ୍ଥିତି '[':
			ସ୍ଥିତି ' ':
			ସ୍ଥିତି '#':
			ସ୍ଥିତି '*':
				ଯଦି (quote == '\0' || tmp2[i] == quote) {
					ଯଦି (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					ଭାଙ୍ଗ;
				}
				/* FALLTHROUGH */
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				ଯଦି (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				ଭାଙ୍ଗ;
			}
		}
	}

	lf = el_ଧାଡ଼ି(el);
	ଯଦି (g.gl_matchc == 1) {
		i = 0;
		ଯଦି (!terminated && quote != '\0')
			ins[i++] = quote;
		ଯଦି (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		ଯଦି (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	ମୁକ୍ତ(tmp);

 out:
	globfree(&g);
	ଫେରନ୍ତୁ g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
ସ୍ଥିର unsigned ଅକ୍ଷର
complete(Edit_ଧାଡ଼ି *el, ପୂର୍ଣ୍ଣସଂଖ୍ୟା ch)
{
	ଅକ୍ଷର **argv, *ଧାଡ଼ି, quote;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ଅଚଳ ଧାଡ଼ି_Info *lf;
	ସଂରଚନା complete_ctx *complete_ctx;

	lf = el_ଧାଡ଼ି(el);
	ଯଦି (el_get(el, EL_CLIENTDATA, (ଶୂନ୍ୟ**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	ଧାଡ଼ି = xmalloc(cursor + 1);
	memcpy(ଧାଡ଼ି, lf->buffer, cursor);
	ଧାଡ଼ି[cursor] = '\0';
	argv = makeargv(ଧାଡ଼ି, &carg, 1, &quote, &terminated);
	ମୁକ୍ତ(ଧାଡ଼ି);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	ଧାଡ଼ି = xmalloc(len + 1);
	memcpy(ଧାଡ଼ି, lf->buffer, len);
	ଧାଡ଼ି[len] = '\0';
	argv = makeargv(ଧାଡ଼ି, &argc, 1, ଖାଲି, ଖାଲି);

	/* Ensure cursor is at EOL or a argument boundary */
	ଯଦି (ଧାଡ଼ି[cursor] != ' ' && ଧାଡ଼ି[cursor] != '\0' &&
	    ଧାଡ଼ି[cursor] != '\n') {
		ମୁକ୍ତ(ଧାଡ଼ି);
		ଫେରନ୍ତୁ ret;
	}

	ଯଦି (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ଖାଲି, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} ଅନ୍ୟଥା ଯଦି (carg == 1 && cursor > 0 && ଧାଡ଼ି[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		ଯଦି (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} ଅନ୍ୟଥା ଯଦି (carg >= 1) {
		/* Handle file parsing */
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote = 0;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା i = 0, cmdarg = 0;
		ଅକ୍ଷର *filematch = ଖାଲି;

		ଯଦି (carg > 1 && ଧାଡ଼ି[cursor-1] != ' ')
			filematch = argv[carg - 1];

		ପାଇଁ (i = 1; i < carg; i++) {
			/* Skip flags */
			ଯଦି (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		ଯଦି (ଧାଡ଼ି[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		ଯଦି ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	ମୁକ୍ତ(ଧାଡ଼ି);
	ଫେରନ୍ତୁ ret;
}
#endif /* USE_LIBEDIT */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
interactive_loop(ସଂରଚନା sftp_conn *conn, ଅକ୍ଷର *file1, ଅକ୍ଷର *file2)
{
	ଅକ୍ଷର *remote_path;
	ଅକ୍ଷର *dir = ଖାଲି, *startdir = ଖାଲି;
	ଅକ୍ଷର cmd[2048];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା err, interactive;
	Edit_ଧାଡ଼ି *el = ଖାଲି;
#ifdef USE_LIBEDIT
	ଅଚଳ ଅକ୍ଷର *editor;
	History *hl = ଖାଲି;
	HistEvent hev;
	ବାହ୍ୟ ଅକ୍ଷର *__progname;
	ସଂରଚନା complete_ctx complete_ctx;

	ଯଦି (!batchmode && isatty(STDIN_FILENO)) {
		ଯଦି ((el = el_init(__progname, stdin, stdout, stderr)) == ଖାଲି)
			fatal("Couldn't initialise editline");
		ଯଦି ((hl = history_init()) == ଖାଲି)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, ଖାଲି);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, ଖାଲି);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (ଶୂନ୍ୟ*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", ଖାଲି);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", ଖାଲି);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", ଖାଲି);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ଖାଲି);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ଖାଲି);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", ଖାଲି);

		/* el_source() may have changed EL_EDITOR to vi */
		ଯଦି (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", ଖାଲି);
	}
#endif /* USE_LIBEDIT */

	ଯଦି ((remote_path = sftp_realpath(conn, ".")) == ଖାଲି)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	ଯଦି (file1 != ଖାଲି) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		ଯଦି (sftp_remote_is_dir(conn, dir) && file2 == ଖାଲି) {
			ଯଦି (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, ଆକାର cmd, "cd \"%s\"", dir);
			ଯଦି (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				ମୁକ୍ତ(dir);
				ମୁକ୍ତ(startdir);
				ମୁକ୍ତ(remote_path);
				ମୁକ୍ତ(conn);
				ଫେରନ୍ତୁ (-1);
			}
		} ଅନ୍ୟଥା {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			ମୁକ୍ତ(dir);
			ମୁକ୍ତ(startdir);
			ମୁକ୍ତ(remote_path);
			ମୁକ୍ତ(conn);
			ଫେରନ୍ତୁ (err);
		}
		ମୁକ୍ତ(dir);
	}

	setvbuf(stdout, ଖାଲି, _IOLBF, 0);
	setvbuf(infile, ଖାଲି, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	ପାଇଁ (;;) {
		ସଂରଚନା sigaction sa;

		interrupted = 0;
		memset(&sa, 0, ଆକାର(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		ଯଦି (sigaction(SIGINT, &sa, ଖାଲି) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			ଭାଙ୍ଗ;
		}
		ଯଦି (el == ଖାଲି) {
			ଯଦି (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			ଯଦି (fgets(cmd, ଆକାର(cmd), infile) == ଖାଲି) {
				ଯଦି (interactive)
					printf("\n");
				ଯଦି (interrupted)
					ଜାରି;
				ଭାଙ୍ଗ;
			}
		} ଅନ୍ୟଥା {
#ifdef USE_LIBEDIT
			ଅଚଳ ଅକ୍ଷର *ଧାଡ଼ି;
			ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଗଣନା_2 = 0;

			ଯଦି ((ଧାଡ଼ି = el_gets(el, &ଗଣନା_2)) == ଖାଲି ||
			    ଗଣନା_2 <= 0) {
				printf("\n");
				ଯଦି (interrupted)
					ଜାରି;
				ଭାଙ୍ଗ;
			}
			history(hl, &hev, H_ENTER, ଧାଡ଼ି);
			ଯଦି (strlcpy(cmd, ଧାଡ଼ି, ଆକାର(cmd)) >= ଆକାର(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				ଜାରି;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == ଖାଲି);
		ଯଦି (err != 0)
			ଭାଙ୍ଗ;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	ମୁକ୍ତ(remote_path);
	ମୁକ୍ତ(startdir);
	ମୁକ୍ତ(conn);

#ifdef USE_LIBEDIT
	ଯଦି (hl != ଖାଲି)
		history_end(hl);
	ଯଦି (el != ଖାଲି)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	ଫେରନ୍ତୁ (err >= 0 ? 0 : -1);
}

ସ୍ଥିର ଶୂନ୍ୟ
connect_to_server(ଅକ୍ଷର *path, ଅକ୍ଷର **args, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *in, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *out)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା c_in, c_out;
#ifdef USE_PIPES
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pin[2], pout[2];

	ଯଦି ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#ଅନ୍ୟଥା /* USE_PIPES */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା inout[2];

	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	ଯଦି ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	ଅନ୍ୟଥା ଯଦି (sshpid == 0) {
		ଯଦି ((dup2(c_in, STDIN_FILENO) == -1) ||
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

ସ୍ଥିର ଶୂନ୍ୟ
usage(ଶୂନ୍ୟ)
{
	ବାହ୍ୟ ଅକ୍ଷର *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	exit(1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ମୁଖ୍ୟ(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, in, out, ch, err, tmp, port = -1, noisy = 0;
	ଅକ୍ଷର *host = ଖାଲି, *user, *cp, **cpp, *file2 = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_level = 0;
	ଅକ୍ଷର *file1 = ଖାଲି, *sftp_server = ଖାଲି;
	ଅକ୍ଷର *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା optind;
	ବାହ୍ୟ ଅକ୍ଷର *optarg;
	ସଂରଚନା sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t ଅଙ୍କ_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', ଆକାର(args));
	args.list = ଖାଲି;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	ଯେତେବେଳେ ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		ବାଛ (ch) {
		/* Passed through to ssh(1) */
		ସ୍ଥିତି 'A':
		ସ୍ଥିତି '4':
		ସ୍ଥିତି '6':
		ସ୍ଥିତି 'C':
			addargs(&args, "-%c", ch);
			ଭାଙ୍ଗ;
		/* Passed through to ssh(1) with argument */
		ସ୍ଥିତି 'F':
		ସ୍ଥିତି 'J':
		ସ୍ଥିତି 'c':
		ସ୍ଥିତି 'i':
		ସ୍ଥିତି 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'P':
			port = a2port(optarg);
			ଯଦି (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'v':
			ଯଦି (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '1':
			fatal("SSH protocol v.1 is no longer supported");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '2':
			/* accept silently */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'a':
			global_aflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			ଯଦି (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'b':
			ଯଦି (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			ଯଦି (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ଖାଲି)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'f':
			global_fflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'p':
			global_pflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'D':
			sftp_direct = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ଯଦି (errstr != ଖାଲି)
				usage();
			limit_kbps *= 1024; /* kbps */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'r':
			global_rflag = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'R':
			ଅଙ୍କ_requests = strtol(optarg, &cp, 10);
			ଯଦି (ଅଙ୍କ_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 's':
			sftp_server = optarg;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'X':
			/* Please keep in sync with ssh.c -X */
			ଯଦି (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				ଯଦି (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ଯଦି (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} ଅନ୍ୟଥା ଯଦି (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ଯଦି (errstr != ଖାଲି) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				ଅଙ୍କ_requests = (size_t)llv;
			} ଅନ୍ୟଥା {
				fatal("Invalid -X option");
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 'h':
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	ଯଦି (!isatty(STDERR_FILENO))
		showprogress = 0;

	ଯଦି (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	ଯଦି (sftp_direct == ଖାଲି) {
		ଯଦି (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		ବାଛ (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		ସ୍ଥିତି -1:
			usage();
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 0:
			ଯଦି (tmp != -1)
				port = tmp;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			/* Try with user, host and path. */
			ଯଦି (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				ଭାଙ୍ଗ;
			/* Try with user and host. */
			ଯଦି (parse_user_host_port(*argv, &user, &host, ଖାଲି)
			    == 0)
				ଭାଙ୍ଗ;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			ଭାଙ୍ଗ;
		}
		file2 = *(argv + 1);

		ଯଦି (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		ଯଦି (port != -1)
			addargs(&args, "-oPort %d", port);
		ଯଦି (user != ଖାଲି) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		ଯଦି (sftp_server == ଖାଲି || strchr(sftp_server, '/') == ଖାଲି)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != ଖାଲି ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} ଅନ୍ୟଥା {
		ଯଦି ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		ଯଦି (cpp[0] == ଖାଲି)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, ଅଙ୍କ_requests, limit_kbps);
	ଯଦି (conn == ଖାଲି)
		fatal("Couldn't initialise connection to server");

	ଯଦି (!quiet) {
		ଯଦି (sftp_direct == ଖାଲି)
			fprintf(stderr, "Connected to %s.\n", host);
		ଅନ୍ୟଥା
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#ଯଦି !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	ଯଦି (batchmode)
		fclose(infile);

	ଯେତେବେଳେ (waitpid(sshpid, ଖାଲି, 0) == -1 && sshpid > 1)
		ଯଦି (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
