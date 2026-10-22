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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/ioctl.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/statvfs.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <libgen.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOCALE_H
# include <locale.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBEDIT
#ಅನ್ತರ್ಭಾವ <histedit.h>
#ಇಲ್ಲದಿದ್ದರೆ
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ Edit_ಸಾಲು;
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <util.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"

#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sftp-common.h"
#ಅನ್ತರ್ಭಾವ "sftp-client.h"
#ಅನ್ತರ್ಭಾವ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
ಪೂರ್ಣಾಂಕ batchmode = 0;

/* PID of ssh transport process */
ಸ್ಥಿರ ಅಸ್ಥಿರ pid_t sshpid = -1;

/* Suppress diagnostic messages */
ಪೂರ್ಣಾಂಕ quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
ಪೂರ್ಣಾಂಕ showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
ಪೂರ್ಣಾಂಕ global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
ಪೂರ್ಣಾಂಕ global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
ಪೂರ್ಣಾಂಕ global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
ಪೂರ್ಣಾಂಕ global_fflag = 0;

/* SIGINT received during command processing */
ಅಸ್ಥಿರ sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
ಪೂರ್ಣಾಂಕ ವಿಂಗಡಿಸು_flag;
glob_t *ವಿಂಗಡಿಸು_glob;

/* Context used for commandline completion */
ರಚನೆ complete_ctx {
	ರಚನೆ sftp_conn *conn;
	ಅಕ್ಷರ **remote_pathp;
};

ಪೂರ್ಣಾಂಕ sftp_glob(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ,
    ಪೂರ್ಣಾಂಕ (*)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ), glob_t *); /* proto for sftp-glob.c */

ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

/* Separators for interactive commands */
#ವ್ಯಾಖ್ಯಾನಿಸು WHITESPACE " \t\r\n"

/* ls flags */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_NAME_ವಿಂಗಡಿಸು	0x0008	/* Sort by name (default) */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_ಸಮಯ_ವಿಂಗಡಿಸು	0x0010	/* Sort by mtime */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_ಗಾತ್ರ_ವಿಂಗಡಿಸು	0x0020	/* Sort by file size */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_ಹಿಮ್ಮುಖ_ವಿಂಗಡಿಸು	0x0040	/* Reverse sort order */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#ವ್ಯಾಖ್ಯಾನಿಸು LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#ವ್ಯಾಖ್ಯಾನಿಸು VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#ವ್ಯಾಖ್ಯಾನಿಸು ವಿಂಗಡಿಸು_FLAGS	(LS_NAME_ವಿಂಗಡಿಸು|LS_ಸಮಯ_ವಿಂಗಡಿಸು|LS_ಗಾತ್ರ_ವಿಂಗಡಿಸು)

/* Commands for interactive mode */
ಎಣಿಕೆ sftp_command {
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
	I_ಆವೃತ್ತಿ,
	I_ಪ್ರಗತಿ,
};

ರಚನೆ CMD {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *c;
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ n;
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ t;	/* Completion type for the first argument */
	ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#ವ್ಯಾಖ್ಯಾನಿಸು NOARGS	0
#ವ್ಯಾಖ್ಯಾನಿಸು REMOTE	1
#ವ್ಯಾಖ್ಯಾನಿಸು LOCAL	2

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ CMD cmds[] = {
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
	{ "progress",	I_ಪ್ರಗತಿ,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_ಆವೃತ್ತಿ,	NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ ಖಾಲಿ,		-1,		-1,		-1	}
};

ಸ್ಥಿರ ಶೂನ್ಯ
killchild(ಪೂರ್ಣಾಂಕ signo)
{
	pid_t pid;

	pid = sshpid;
	ಆದರೆ (pid > 1) {
		kill(pid, SIGTERM);
		(ಶೂನ್ಯ)waitpid(pid, ಖಾಲಿ, 0);
	}

	_exit(1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
suspchild(ಪೂರ್ಣಾಂಕ signo)
{
	ಪೂರ್ಣಾಂಕ save_errno = errno;
	ಆದರೆ (sshpid > 1) {
		kill(sshpid, signo);
		ಆಗ (waitpid(sshpid, ಖಾಲಿ, WUNTRACED) == -1 && errno == EINTR)
			ಮುಂದುವರಿ;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

ಸ್ಥಿರ ಶೂನ್ಯ
cmd_ಅಡಚಣೆ(ಪೂರ್ಣಾಂಕ signo)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ ಸಂದೇಶ[] = "\rInterrupt  \n";
	ಪೂರ್ಣಾಂಕ olderrno = errno;

	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ) - 1);
	interrupted = 1;
	errno = olderrno;
}

ಸ್ಥಿರ ಶೂನ್ಯ
read_ಅಡಚಣೆ(ಪೂರ್ಣಾಂಕ signo)
{
	interrupted = 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sigchld_handler(ಪೂರ್ಣಾಂಕ sig)
{
	ಪೂರ್ಣಾಂಕ save_errno = errno;
	pid_t pid;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ ಸಂದೇಶ[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	ಆಗ ((pid = waitpid(sshpid, ಖಾಲಿ, WNOHANG)) == -1 && errno == EINTR)
		ಮುಂದುವರಿ;
	ಆದರೆ (pid == sshpid) {
		ಆದರೆ (!quiet)
		    (ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

ಸ್ಥಿರ ಶೂನ್ಯ
help(ಶೂನ್ಯ)
{
	ಬರೆ("Available commands:\n"
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

ಸ್ಥಿರ ಶೂನ್ಯ
local_do_shell(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಾದಗಳು)
{
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;
	ಅಕ್ಷರ *shell;
	pid_t pid;

	ಆದರೆ (!*ವಾದಗಳು)
		ವಾದಗಳು = ಖಾಲಿ;

	ಆದರೆ ((shell = getenv("SHELL")) == ಖಾಲಿ || *shell == '\0')
		shell = _PATH_BSHELL;

	ಆದರೆ ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	ಆದರೆ (pid == 0) {
		ಆದರೆ (ವಾದಗಳು) {
			debug3("Executing %s -c \"%s\"", shell, ವಾದಗಳು);
			execl(shell, shell, "-c", ವಾದಗಳು, (ಅಕ್ಷರ *)ಖಾಲಿ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug3("Executing %s", shell);
			execl(shell, shell, (ಅಕ್ಷರ *)ಖಾಲಿ);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1)
		ಆದರೆ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2))
		error("Shell exited abnormally");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (WEXITSTATUS(ಸ್ಥಿತಿ_2))
		error("Shell exited with status %d", WEXITSTATUS(ಸ್ಥಿತಿ_2));
}

ಸ್ಥಿರ ಶೂನ್ಯ
local_do_ls(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಾದಗಳು)
{
	ಆದರೆ (!ವಾದಗಳು || !*ವಾದಗಳು)
		local_do_shell(ಮಾರ್ಗ_LS);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಪೂರ್ಣಾಂಕ len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಮಾರ್ಗ_LS " ") + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ವಾದಗಳು) + 1;
		ಅಕ್ಷರ *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, ಮಾರ್ಗ_LS " %s", ವಾದಗಳು);
		local_do_shell(buf);
		ಬಿಡುಗಡೆ(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
ಸ್ಥಿರ ಅಕ್ಷರ *
ಮಾರ್ಗ_strip(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *strip)
{
	ಗಾತ್ರ_t len;

	ಆದರೆ (strip == ಖಾಲಿ || (len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(strip)) == 0)
		ಹಿಂತಿರುಗಿ (xstrdup(ಮಾರ್ಗ));

	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ಮಾರ್ಗ, strip, len) == 0) {
		ಆದರೆ (strip[len - 1] != '/' && ಮಾರ್ಗ[len] == '/')
			len++;
		ಹಿಂತಿರುಗಿ (xstrdup(ಮಾರ್ಗ + len));
	}

	ಹಿಂತಿರುಗಿ (xstrdup(ಮಾರ್ಗ));
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_getput_flags(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc,
    ಪೂರ್ಣಾಂಕ *aflag, ಪೂರ್ಣಾಂಕ *fflag, ಪೂರ್ಣಾಂಕ *pflag, ಪೂರ್ಣಾಂಕ *rflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	ಆಗ ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'a':
			*aflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			*fflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
		ಸ್ಥಿತಿ 'P':
			*pflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
		ಸ್ಥಿತಿ 'R':
			*rflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_mkdir_flags(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc, ಪೂರ್ಣಾಂಕ *pflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	ಆಗ ((ch = getopt(argc, argv, "p")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'p':
			*pflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_link_flags(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc, ಪೂರ್ಣಾಂಕ *sflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	ಆಗ ((ch = getopt(argc, argv, "s")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 's':
			*sflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_rename_flags(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc, ಪೂರ್ಣಾಂಕ *lflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	ಆಗ ((ch = getopt(argc, argv, "l")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'l':
			*lflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_ls_flags(ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc, ಪೂರ್ಣಾಂಕ *lflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_ವಿಂಗಡಿಸು;
	ಆಗ ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'S':
			*lflag &= ~ವಿಂಗಡಿಸು_FLAGS;
			*lflag |= LS_ಗಾತ್ರ_ವಿಂಗಡಿಸು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'a':
			*lflag |= LS_SHOW_ALL;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			*lflag &= ~ವಿಂಗಡಿಸು_FLAGS;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
			*lflag |= LS_SI_UNITS;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
			*lflag |= LS_ಹಿಮ್ಮುಖ_ವಿಂಗಡಿಸು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 't':
			*lflag &= ~ವಿಂಗಡಿಸು_FLAGS;
			*lflag |= LS_ಸಮಯ_ವಿಂಗಡಿಸು;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("ls: Invalid flag -%c", optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_df_flags(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc, ಪೂರ್ಣಾಂಕ *hflag, ಪೂರ್ಣಾಂಕ *iflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	ಆಗ ((ch = getopt(argc, argv, "hi")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'h':
			*hflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'i':
			*iflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_ch_flags(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc, ಪೂರ್ಣಾಂಕ *hflag)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	ಆಗ ((ch = getopt(argc, argv, "h")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಸ್ಥಿತಿ 'h':
			*hflag = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_no_flags(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **argv, ಪೂರ್ಣಾಂಕ argc)
{
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ opterr, optind, optopt, optreset;
	ಪೂರ್ಣಾಂಕ ch;

	optind = optreset = 1;
	opterr = 0;

	ಆಗ ((ch = getopt(argc, argv, "")) != -1) {
		ಆಯ್ಕೆ (ch) {
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("%s: Invalid flag -%c", cmd, optopt);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	ಹಿಂತಿರುಗಿ optind;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
escape_glob(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t i, o, len;
	ಅಕ್ಷರ *ret;

	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s);
	ret = xcalloc(2, len + 1);
	ಗಾಗಿ (i = o = 0; i < len; i++) {
		ಆದರೆ (strchr("[]?*\\", s[i]) != ಖಾಲಿ)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
make_absolute_pwd_glob(ಅಕ್ಷರ *p, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pwd)
{
	ಅಕ್ಷರ *ret, *escpwd;

	escpwd = escape_glob(pwd);
	ಆದರೆ (p == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ escpwd;
	ret = sftp_make_absolute(p, escpwd);
	ಬಿಡುಗಡೆ(escpwd);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
local_is_dir(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ stat sb;

	ಆದರೆ (stat(ಮಾರ್ಗ, &sb) == -1)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ S_ISDIR(sb.st_mode);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_get(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dst,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pwd, ಪೂರ್ಣಾಂಕ pflag, ಪೂರ್ಣಾಂಕ rflag, ಪೂರ್ಣಾಂಕ resume, ಪೂರ್ಣಾಂಕ fflag)
{
	ಅಕ್ಷರ *filename, *abs_src = ಖಾಲಿ, *abs_dst = ಖಾಲಿ, *tmp = ಖಾಲಿ;
	glob_t g;
	ಪೂರ್ಣಾಂಕ i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, ಗಾತ್ರ(g));

	debug3("Looking up %s", abs_src);
	ಆದರೆ ((r = sftp_glob(conn, abs_src, GLOB_MARK, ಖಾಲಿ, &g)) != 0) {
		ಆದರೆ (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	ಆದರೆ (g.gl_matchc > 1 && dst != ಖಾಲಿ && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಗಾಗಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ಆದರೆ ((filename = basename(tmp)) == ಖಾಲಿ) {
			error("basename %s: %s", tmp, strerror(errno));
			ಬಿಡುಗಡೆ(tmp);
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		ಆದರೆ (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		ಆದರೆ (g.gl_matchc == 1 && dst) {
			ಆದರೆ (local_is_dir(dst)) {
				abs_dst = sftp_ಮಾರ್ಗ_append(dst, filename);
			} ಇಲ್ಲದಿದ್ದರೆ {
				abs_dst = xstrdup(dst);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (dst) {
			abs_dst = sftp_ಮಾರ್ಗ_append(dst, filename);
		} ಇಲ್ಲದಿದ್ದರೆ {
			abs_dst = xstrdup(filename);
		}
		ಬಿಡುಗಡೆ(tmp);

		resume |= global_aflag;
		ಆದರೆ (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		ಆದರೆ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ಆದರೆ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ಖಾಲಿ, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (sftp_download(conn, g.gl_pathv[i], abs_dst, ಖಾಲಿ,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		ಬಿಡುಗಡೆ(abs_dst);
		abs_dst = ಖಾಲಿ;
	}

ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(abs_src);
	globfree(&g);
	ಹಿಂತಿರುಗಿ(err);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_put(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dst,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pwd, ಪೂರ್ಣಾಂಕ pflag, ಪೂರ್ಣಾಂಕ rflag, ಪೂರ್ಣಾಂಕ resume, ಪೂರ್ಣಾಂಕ fflag)
{
	ಅಕ್ಷರ *tmp_dst = ಖಾಲಿ;
	ಅಕ್ಷರ *abs_dst = ಖಾಲಿ;
	ಅಕ್ಷರ *tmp = ಖಾಲಿ, *filename = ಖಾಲಿ;
	glob_t g;
	ಪೂರ್ಣಾಂಕ err = 0;
	ಪೂರ್ಣಾಂಕ i, dst_is_dir = 1;
	ರಚನೆ stat sb;

	ಆದರೆ (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, ಗಾತ್ರ(g));
	debug3("Looking up %s", src);
	ಆದರೆ (glob(src, GLOB_NOCHECK | GLOB_MARK, ಖಾಲಿ, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	ಆದರೆ (tmp_dst != ಖಾಲಿ)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	ಆದರೆ (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಗಾಗಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		ಆದರೆ (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			ಮುಂದುವರಿ;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		ಆದರೆ ((filename = basename(tmp)) == ಖಾಲಿ) {
			error("basename %s: %s", tmp, strerror(errno));
			ಬಿಡುಗಡೆ(tmp);
			err = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Special handling for source of '..' */
		ಆದರೆ (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		ಬಿಡುಗಡೆ(abs_dst);
		abs_dst = ಖಾಲಿ;
		ಆದರೆ (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			ಆದರೆ (dst_is_dir)
				abs_dst = sftp_ಮಾರ್ಗ_append(tmp_dst, filename);
			ಇಲ್ಲದಿದ್ದರೆ
				abs_dst = xstrdup(tmp_dst);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (tmp_dst) {
			abs_dst = sftp_ಮಾರ್ಗ_append(tmp_dst, filename);
		} ಇಲ್ಲದಿದ್ದರೆ {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		ಬಿಡುಗಡೆ(tmp);

		resume |= global_aflag;
		ಆದರೆ (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		ಆದರೆ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ಆದರೆ (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(abs_dst);
	ಬಿಡುಗಡೆ(tmp_dst);
	globfree(&g);
	ಹಿಂತಿರುಗಿ(err);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sdirent_comp(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	ಪೂರ್ಣಾಂಕ rmul = ವಿಂಗಡಿಸು_flag & LS_ಹಿಮ್ಮುಖ_ವಿಂಗಡಿಸು ? -1 : 1;

#ವ್ಯಾಖ್ಯಾನಿಸು NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	ಆದರೆ (ವಿಂಗಡಿಸು_flag & LS_NAME_ವಿಂಗಡಿಸು)
		ಹಿಂತಿರುಗಿ (rmul * strcmp(a->filename, b->filename));
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ವಿಂಗಡಿಸು_flag & LS_ಸಮಯ_ವಿಂಗಡಿಸು)
		ಹಿಂತಿರುಗಿ (rmul * NCMP(a->a.mtime, b->a.mtime));
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ವಿಂಗಡಿಸು_flag & LS_ಗಾತ್ರ_ವಿಂಗಡಿಸು)
		ಹಿಂತಿರುಗಿ (rmul * NCMP(a->a.ಗಾತ್ರ_2, b->a.ಗಾತ್ರ_2));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_ls_dir(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *strip_ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ lflag)
{
	ಪೂರ್ಣಾಂಕ n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	ಆದರೆ ((n = sftp_readdir(conn, ಮಾರ್ಗ, &d)) != 0)
		ಹಿಂತಿರುಗಿ (n);

	ಆದರೆ (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, ಅಗಲ = 80;
		ರಚನೆ winsize ws;
		ಅಕ್ಷರ *tmp;

		/* Count entries for sort and find longest filename */
		ಗಾಗಿ (n = 0; d[n] != ಖಾಲಿ; n++) {
			ಆದರೆ (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = ಗರಿಷ್ಠ(m, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = ಮಾರ್ಗ_strip(ಮಾರ್ಗ, strip_ಮಾರ್ಗ);
		m += ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(tmp);
		ಬಿಡುಗಡೆ(tmp);

		ಆದರೆ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			ಅಗಲ = ws.ws_ಲಂಬಸಾಲು;

		columns = ಅಗಲ / (m + 2);
		columns = ಗರಿಷ್ಠ(columns, 1);
		colspace = ಅಗಲ / columns;
		colspace = MINIMUM(colspace, ಅಗಲ);
	}

	ಆದರೆ (lflag & ವಿಂಗಡಿಸು_FLAGS) {
		ಗಾಗಿ (n = 0; d[n] != ಖಾಲಿ; n++)
			;	/* count entries */
		ವಿಂಗಡಿಸು_flag = lflag & (ವಿಂಗಡಿಸು_FLAGS|LS_ಹಿಮ್ಮುಖ_ವಿಂಗಡಿಸು);
		qsort(d, n, ಗಾತ್ರ(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	ಗಾಗಿ (n = 0; d[n] != ಖಾಲಿ && !interrupted; n++) {
		ಅಕ್ಷರ *tmp, *fname;

		ಆದರೆ (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			ಮುಂದುವರಿ;

		tmp = sftp_ಮಾರ್ಗ_append(ಮಾರ್ಗ, d[n]->filename);
		fname = ಮಾರ್ಗ_strip(tmp, strip_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(tmp);

		ಆದರೆ (lflag & LS_LONG_VIEW) {
			ಆದರೆ ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				ಅಕ್ಷರ *lname;
				ರಚನೆ stat sb;
				ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user = ಖಾಲಿ, *ಗುಂಪು = ಖಾಲಿ;

				memset(&sb, 0, ಗಾತ್ರ(sb));
				attrib_ಗಮ್ಯ_stat(&d[n]->a, &sb);
				ಆದರೆ ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					ಗುಂಪು = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, ಗುಂಪು);
				mprintf("%s\n", lname);
				ಬಿಡುಗಡೆ(lname);
			} ಇಲ್ಲದಿದ್ದರೆ
				mprintf("%s\n", d[n]->longname);
		} ಇಲ್ಲದಿದ್ದರೆ {
			mprintf("%-*s", colspace, fname);
			ಆದರೆ (c >= columns) {
				ಬರೆ("\n");
				c = 1;
			} ಇಲ್ಲದಿದ್ದರೆ
				c++;
		}

		ಬಿಡುಗಡೆ(fname);
	}

	ಆದರೆ (!(lflag & LS_LONG_VIEW) && (c != 1))
		ಬರೆ("\n");

	sftp_free_dirents(d);
	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sglob_comp(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *bb)
{
	u_int a = *(ಸ್ಥಿರಾಂಕ u_int *)aa;
	u_int b = *(ಸ್ಥಿರಾಂಕ u_int *)bb;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ap = ವಿಂಗಡಿಸು_glob->gl_pathv[a];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *bp = ವಿಂಗಡಿಸು_glob->gl_pathv[b];
	ಸ್ಥಿರಾಂಕ ರಚನೆ stat *as = ವಿಂಗಡಿಸು_glob->gl_statv[a];
	ಸ್ಥಿರಾಂಕ ರಚನೆ stat *bs = ವಿಂಗಡಿಸು_glob->gl_statv[b];
	ಪೂರ್ಣಾಂಕ rmul = ವಿಂಗಡಿಸು_flag & LS_ಹಿಮ್ಮುಖ_ವಿಂಗಡಿಸು ? -1 : 1;

#ವ್ಯಾಖ್ಯಾನಿಸು NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	ಆದರೆ (as == ಖಾಲಿ || bs == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (as == bs) ? 0 : (as == ಖಾಲಿ ? rmul : -rmul);
	ಆದರೆ (ವಿಂಗಡಿಸು_flag & LS_NAME_ವಿಂಗಡಿಸು)
		ಹಿಂತಿರುಗಿ (rmul * strcmp(ap, bp));
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ವಿಂಗಡಿಸು_flag & LS_ಸಮಯ_ವಿಂಗಡಿಸು) {
#ಆದರೆ defined(HAVE_STRUCT_STAT_ST_MTIM)
		ಆದರೆ (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			ಹಿಂತಿರುಗಿ 0;
		ಹಿಂತಿರುಗಿ timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#ಅಥವಾಆದರೆ defined(HAVE_STRUCT_STAT_ST_MTIME)
		ಹಿಂತಿರುಗಿ (rmul * NCMP(as->st_mtime, bs->st_mtime));
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ rmul * 1;
#ಆದರೆ_ಅಂತ್ಯ
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ವಿಂಗಡಿಸು_flag & LS_ಗಾತ್ರ_ವಿಂಗಡಿಸು)
		ಹಿಂತಿರುಗಿ (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_globbed_ls(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *strip_ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ lflag)
{
	ಅಕ್ಷರ *fname, *lname;
	glob_t g;
	ಪೂರ್ಣಾಂಕ err, r;
	ರಚನೆ winsize ws;
	u_int i, j, nentries, *indices = ಖಾಲಿ, c = 1;
	u_int colspace = 0, columns = 1, m = 0, ಅಗಲ = 80;

	memset(&g, 0, ಗಾತ್ರ(g));

	ಆದರೆ ((r = sftp_glob(conn, ಮಾರ್ಗ,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ಖಾಲಿ, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		ಆದರೆ (g.gl_pathc)
			globfree(&g);
		ಆದರೆ (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", ಮಾರ್ಗ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("Can't ls: \"%s\" not found", ಮಾರ್ಗ);
		}
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (interrupted)
		ಹೋಗು ಹೊರಹೋಗು;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	ಆದರೆ (g.gl_matchc == 1 && g.gl_statv[0] != ಖಾಲಿ &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_ಮಾರ್ಗ, lflag);
		globfree(&g);
		ಹಿಂತಿರುಗಿ err;
	}

	ಆದರೆ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		ಅಗಲ = ws.ws_ಲಂಬಸಾಲು;

	ಆದರೆ (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		ಗಾಗಿ (i = 0; g.gl_pathv[i]; i++)
			m = ಗರಿಷ್ಠ(m, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(g.gl_pathv[i]));

		columns = ಅಗಲ / (m + 2);
		columns = ಗರಿಷ್ಠ(columns, 1);
		colspace = ಅಗಲ / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	ಗಾಗಿ (nentries = 0; g.gl_pathv[nentries] != ಖಾಲಿ; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, ಗಾತ್ರ(*indices));
	ಗಾಗಿ (i = 0; i < nentries; i++)
		indices[i] = i;

	ಆದರೆ (lflag & ವಿಂಗಡಿಸು_FLAGS) {
		ವಿಂಗಡಿಸು_glob = &g;
		ವಿಂಗಡಿಸು_flag = lflag & (ವಿಂಗಡಿಸು_FLAGS|LS_ಹಿಮ್ಮುಖ_ವಿಂಗಡಿಸು);
		qsort(indices, nentries, ಗಾತ್ರ(*indices), sglob_comp);
		ವಿಂಗಡಿಸು_glob = ಖಾಲಿ;
	}

	get_remote_user_groups_from_glob(conn, &g);
	ಗಾಗಿ (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = ಮಾರ್ಗ_strip(g.gl_pathv[i], strip_ಮಾರ್ಗ);
		ಆದರೆ (lflag & LS_LONG_VIEW) {
			ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user = ಖಾಲಿ, *ಗುಂಪು = ಖಾಲಿ;

			ಆದರೆ (g.gl_statv[i] == ಖಾಲಿ) {
				error("no stat information for %s", fname);
				ಬಿಡುಗಡೆ(fname);
				ಮುಂದುವರಿ;
			}
			ಆದರೆ ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				ಗುಂಪು = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, ಗುಂಪು);
			mprintf("%s\n", lname);
			ಬಿಡುಗಡೆ(lname);
		} ಇಲ್ಲದಿದ್ದರೆ {
			mprintf("%-*s", colspace, fname);
			ಆದರೆ (c >= columns) {
				ಬರೆ("\n");
				c = 1;
			} ಇಲ್ಲದಿದ್ದರೆ
				c++;
		}
		ಬಿಡುಗಡೆ(fname);
	}

	ಆದರೆ (!(lflag & LS_LONG_VIEW) && (c != 1))
		ಬರೆ("\n");

 ಹೊರಹೋಗು:
	ಆದರೆ (g.gl_pathc)
		globfree(&g);
	ಬಿಡುಗಡೆ(indices);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_df(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ hflag, ಪೂರ್ಣಾಂಕ iflag)
{
	ರಚನೆ sftp_statvfs st;
	ಅಕ್ಷರ s_ಬಳಸಿದ[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	ಅಕ್ಷರ s_ಬೇರು[FMT_SCALED_STRSIZE], s_ಒಟ್ಟು[FMT_SCALED_STRSIZE];
	ಅಕ್ಷರ s_icapacity[16], s_dcapacity[16];

	ಆದರೆ (sftp_statvfs(conn, ಮಾರ್ಗ, &st, 1) == -1)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", ಗಾತ್ರ(s_icapacity));
	ಇಲ್ಲದಿದ್ದರೆ {
		snprintf(s_icapacity, ಗಾತ್ರ(s_icapacity), "%3llu%%",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	ಆದರೆ (st.f_ಖಂಡಗಳು == 0)
		strlcpy(s_dcapacity, "ERR", ಗಾತ್ರ(s_dcapacity));
	ಇಲ್ಲದಿದ್ದರೆ {
		snprintf(s_dcapacity, ಗಾತ್ರ(s_dcapacity), "%3llu%%",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)(100 * (st.f_ಖಂಡಗಳು - st.f_bfree) /
		    st.f_ಖಂಡಗಳು));
	}
	ಆದರೆ (iflag) {
		ಬರೆ("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		ಬರೆ("%11llu %11llu %11llu %11llu         %s\n",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)st.f_files,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)(st.f_files - st.f_ffree),
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)st.f_favail,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)st.f_ffree, s_icapacity);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (hflag) {
		strlcpy(s_ಬಳಸಿದ, "error", ಗಾತ್ರ(s_ಬಳಸಿದ));
		strlcpy(s_avail, "error", ಗಾತ್ರ(s_avail));
		strlcpy(s_ಬೇರು, "error", ಗಾತ್ರ(s_ಬೇರು));
		strlcpy(s_ಒಟ್ಟು, "error", ಗಾತ್ರ(s_ಒಟ್ಟು));
		fmt_scaled((st.f_ಖಂಡಗಳು - st.f_bfree) * st.f_frsize, s_ಬಳಸಿದ);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_ಬೇರು);
		fmt_scaled(st.f_ಖಂಡಗಳು * st.f_frsize, s_ಒಟ್ಟು);
		ಬರೆ("    Size     Used    Avail   (root)    %%Capacity\n");
		ಬರೆ("%7sB %7sB %7sB %7sB         %s\n",
		    s_ಒಟ್ಟು, s_ಬಳಸಿದ, s_avail, s_ಬೇರು, s_dcapacity);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಬರೆ("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		ಬರೆ("%12llu %12llu %12llu %12llu         %s\n",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)(st.f_frsize * st.f_ಖಂಡಗಳು / 1024),
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)(st.f_frsize *
		    (st.f_ಖಂಡಗಳು - st.f_bfree) / 1024),
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)(st.f_frsize * st.f_bavail / 1024),
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
undo_glob_escape(ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t i, j;

	ಗಾಗಿ (i = j = 0;;) {
		ಆದರೆ (s[i] == '\0') {
			s[j] = '\0';
			ಹಿಂತಿರುಗಿ;
		}
		ಆದರೆ (s[i] != '\\') {
			s[j++] = s[i++];
			ಮುಂದುವರಿ;
		}
		/* s[i] == '\\' */
		++i;
		ಆಯ್ಕೆ (s[i]) {
		ಸ್ಥಿತಿ '?':
		ಸ್ಥಿತಿ '[':
		ಸ್ಥಿತಿ '*':
		ಸ್ಥಿತಿ '\\':
			s[j++] = s[i++];
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '\0':
			s[j++] = '\\';
			s[j] = '\0';
			ಹಿಂತಿರುಗಿ;
		ಪೂರ್ವನಿಯೋಜಿತ:
			s[j++] = '\\';
			s[j++] = s[i++];
			ನಿಲ್ಲಿಸು;
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
#ವ್ಯಾಖ್ಯಾನಿಸು MAXARGS		128
#ವ್ಯಾಖ್ಯಾನಿಸು MAXARGLEN	8192
ಸ್ಥಿರ ಅಕ್ಷರ **
makeargv(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *arg, ಪೂರ್ಣಾಂಕ *argcp, ಪೂರ್ಣಾಂಕ sloppy, ಅಕ್ಷರ *lastquote,
    u_int *terminated)
{
	ಪೂರ್ಣಾಂಕ argc, quot;
	ಗಾತ್ರ_t i, j;
	ಸ್ಥಿರ ಅಕ್ಷರ argvs[MAXARGLEN];
	ಸ್ಥಿರ ಅಕ್ಷರ *argv[MAXARGS + 1];
	ಎಣಿಕೆ { MA_ಆರಂಭ, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(arg) > ಗಾತ್ರ(argvs) - 1) {
 ವಾದಗಳು_too_longs:
		error("string too long");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (terminated != ಖಾಲಿ)
		*terminated = 1;
	ಆದರೆ (lastquote != ಖಾಲಿ)
		*lastquote = '\0';
	state = MA_ಆರಂಭ;
	i = j = 0;
	ಗಾಗಿ (;;) {
		ಆದರೆ ((ಗಾತ್ರ_t)argc >= ಗಾತ್ರ(argv) / ಗಾತ್ರ(*argv)){
			error("Too many arguments.");
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
		ಆದರೆ (ಖಾಲಿಯೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)arg[i])) {
			ಆದರೆ (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_ಆರಂಭ;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (state != MA_ಆರಂಭ)
				argvs[j++] = arg[i];
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			ಆದರೆ (state == MA_ಆರಂಭ) {
				argv[argc] = argvs + j;
				state = q;
				ಆದರೆ (lastquote != ಖಾಲಿ)
					*lastquote = arg[i];
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (state == MA_UNQUOTED)
				state = q;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (state == q)
				state = MA_UNQUOTED;
			ಇಲ್ಲದಿದ್ದರೆ
				argvs[j++] = arg[i];
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (arg[i] == '\\') {
			ಆದರೆ (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				ಆದರೆ (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					ಆದರೆ (j >= ಗಾತ್ರ(argvs) - 5)
						ಹೋಗು ವಾದಗಳು_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} ಇಲ್ಲದಿದ್ದರೆ {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				ಆದರೆ (state == MA_ಆರಂಭ) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					ಆದರೆ (lastquote != ಖಾಲಿ)
						*lastquote = '\0';
				}
				ಆದರೆ (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} ಇಲ್ಲದಿದ್ದರೆ {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					ಆದರೆ (arg[i] == '\0')
						ಹೋಗು early_nul;
					argvs[j++] = arg[i];
				}
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (arg[i] == '#') {
			ಆದರೆ (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			ಇಲ್ಲದಿದ್ದರೆ
				ಹೋಗು string_ಮುಗಿದ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (arg[i] == '\0') {
			ಆದರೆ (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				ಆದರೆ (sloppy) {
					state = MA_UNQUOTED;
					ಆದರೆ (terminated != ಖಾಲಿ)
						*terminated = 0;
					ಹೋಗು string_ಮುಗಿದ;
				}
				error("Unterminated quoted argument");
				ಹಿಂತಿರುಗಿ ಖಾಲಿ;
			}
 string_ಮುಗಿದ:
			ಆದರೆ (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			ನಿಲ್ಲಿಸು;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (state == MA_ಆರಂಭ) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				ಆದರೆ (lastquote != ಖಾಲಿ)
					*lastquote = '\0';
			}
			ಆದರೆ ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				ಆದರೆ (j >= ಗಾತ್ರ(argvs) - 3)
					ಹೋಗು ವಾದಗಳು_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} ಇಲ್ಲದಿದ್ದರೆ
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	ಹಿಂತಿರುಗಿ argv;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_ವಾದಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **cpp, ಪೂರ್ಣಾಂಕ *ignore_errors, ಪೂರ್ಣಾಂಕ *disable_echo, ಪೂರ್ಣಾಂಕ *aflag,
	  ಪೂರ್ಣಾಂಕ *fflag, ಪೂರ್ಣಾಂಕ *hflag, ಪೂರ್ಣಾಂಕ *iflag, ಪೂರ್ಣಾಂಕ *lflag, ಪೂರ್ಣಾಂಕ *pflag,
	  ಪೂರ್ಣಾಂಕ *rflag, ಪೂರ್ಣಾಂಕ *sflag,
    ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ *n_arg, ಅಕ್ಷರ **path1, ಅಕ್ಷರ **path2)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, *cp = *cpp;
	ಅಕ್ಷರ *cp2, **argv;
	ಪೂರ್ಣಾಂಕ ತಳ = 0;
	ದೀರ್ಘ ದೀರ್ಘ ll;
	ಪೂರ್ಣಾಂಕ path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	ಗಾಗಿ (;*cp != '\0'; cp++) {
		ಆದರೆ (*cp == '-') {
			*ignore_errors = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*cp == '@') {
			*disable_echo = 1;
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* all other characters terminate prefix processing */
			ನಿಲ್ಲಿಸು;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	ಆದರೆ (*cp == '\0' || *cp == '#')
		ಹಿಂತಿರುಗಿ (0);

	ಆದರೆ ((argv = makeargv(cp, &argc, 0, ಖಾಲಿ, ಖಾಲಿ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	/* Figure out which command we have */
	ಗಾಗಿ (i = 0; cmds[i].c != ಖಾಲಿ; i++) {
		ಆದರೆ (argv[0] != ಖಾಲಿ && strcasecmp(cmds[i].c, argv[0]) == 0)
			ನಿಲ್ಲಿಸು;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	ಆದರೆ (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cmdnum == -1) {
		error("Invalid command.");
		ಹಿಂತಿರುಗಿ -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ಖಾಲಿ;
	optidx = 1;
	ಆಯ್ಕೆ (cmdnum) {
	ಸ್ಥಿತಿ I_GET:
	ಸ್ಥಿತಿ I_REGET:
	ಸ್ಥಿತಿ I_REPUT:
	ಸ್ಥಿತಿ I_PUT:
		ಆದರೆ ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		/* Get first pathname (mandatory) */
		ಆದರೆ (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			ಹಿಂತಿರುಗಿ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		ಆದರೆ (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LINK:
		ಆದರೆ ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		ಹೋಗು parse_two_paths;
	ಸ್ಥಿತಿ I_COPY:
		ಆದರೆ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		ಹೋಗು parse_two_paths;
	ಸ್ಥಿತಿ I_RENAME:
		ಆದರೆ ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		ಹೋಗು parse_two_paths;
	ಸ್ಥಿತಿ I_SYMLINK:
		ಆದರೆ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಹಿಂತಿರುಗಿ -1;
 parse_two_paths:
		ಆದರೆ (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			ಹಿಂತಿರುಗಿ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_MKDIR:
	ಸ್ಥಿತಿ I_LMKDIR:
		ಆದರೆ ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		path1_mandatory = 1;
		ಹೋಗು parse_one_ಮಾರ್ಗ;
	ಸ್ಥಿತಿ I_RM:
	ಸ್ಥಿತಿ I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ I_CHDIR:
	ಸ್ಥಿತಿ I_LCHDIR:
		ಆದರೆ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಹಿಂತಿರುಗಿ -1;
 parse_one_ಮಾರ್ಗ:
		/* Get pathname (mandatory) */
		ಆದರೆ (argc - optidx < 1) {
			ಆದರೆ (!path1_mandatory)
				ನಿಲ್ಲಿಸು; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			ಹಿಂತಿರುಗಿ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		ಆದರೆ (cmdnum != I_RM)
			undo_glob_escape(*path1);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_DF:
		ಆದರೆ ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		/* Default to current directory if no path specified */
		ಆದರೆ (argc - optidx < 1)
			*path1 = ಖಾಲಿ;
		ಇಲ್ಲದಿದ್ದರೆ {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LS:
		ಆದರೆ ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			ಹಿಂತಿರುಗಿ(-1);
		/* Path is optional */
		ಆದರೆ (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cmd) + strspn(cp, WHITESPACE);
	ಸ್ಥಿತಿ I_SHELL:
		/* Uses the rest of the line */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LUMASK:
	ಸ್ಥಿತಿ I_CHMOD:
		ತಳ = 8;
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ I_CHOWN:
	ಸ್ಥಿತಿ I_CHGRP:
		ಆದರೆ ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		/* Get numeric arg (mandatory) */
		ಆದರೆ (argc - optidx < 1)
			ಹೋಗು need_ಅಂಕೆ_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, ತಳ);
		ಆದರೆ (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_ಅಂಕೆ_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			ಹಿಂತಿರುಗಿ -1;
		}
		*n_arg = ll;
		ಆದರೆ (cmdnum == I_LUMASK)
			ನಿಲ್ಲಿಸು;
		/* Get pathname (mandatory) */
		ಆದರೆ (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			ಹಿಂತಿರುಗಿ -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_QUIT:
	ಸ್ಥಿತಿ I_PWD:
	ಸ್ಥಿತಿ I_LPWD:
	ಸ್ಥಿತಿ I_HELP:
	ಸ್ಥಿತಿ I_ಆವೃತ್ತಿ:
	ಸ್ಥಿತಿ I_ಪ್ರಗತಿ:
		ಆದರೆ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			ಹಿಂತಿರುಗಿ -1;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("Command not implemented");
	}

	*cpp = cp;
	ಹಿಂತಿರುಗಿ(cmdnum);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_dispatch_command(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd, ಅಕ್ಷರ **pwd,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *startdir, ಪೂರ್ಣಾಂಕ err_abort, ಪೂರ್ಣಾಂಕ echo_command)
{
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ocmd = cmd;
	ಅಕ್ಷರ *path1, *path2, *tmp;
	ಪೂರ್ಣಾಂಕ ignore_errors = 0, disable_echo = 1;
	ಪೂರ್ಣಾಂಕ aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	ಪೂರ್ಣಾಂಕ lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	ಪೂರ್ಣಾಂಕ cmdnum, i;
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ n_arg = 0;
	Attrib a, aa;
	ಅಕ್ಷರ ಮಾರ್ಗ_buf[PATH_MAX];
	ಪೂರ್ಣಾಂಕ err = 0;
	glob_t g;

	path1 = path2 = ಖಾಲಿ;
	cmdnum = parse_ವಾದಗಳು(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	ಆದರೆ (ignore_errors != 0)
		err_abort = 0;

	ಆದರೆ (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, ಗಾತ್ರ(g));

	/* Perform command */
	ಆಯ್ಕೆ (cmdnum) {
	ಸ್ಥಿತಿ 0:
		/* Blank line */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ -1:
		/* Unrecognized command */
		err = -1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ I_LINK:
		ಆದರೆ (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ಖಾಲಿ, &g);
		ಗಾಗಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ಆದರೆ (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			ಆದರೆ (err != 0 && err_abort)
				ನಿಲ್ಲಿಸು;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		ಆದರೆ (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		ಇಲ್ಲದಿದ್ದರೆ
			err = sftp_mkdir(conn, path1, &a, 1);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_CHDIR:
		ಆದರೆ (path1 == ಖಾಲಿ || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		ಆದರೆ ((tmp = sftp_realpath(conn, path1)) == ಖಾಲಿ) {
			err = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (sftp_stat(conn, tmp, 0, &aa) != 0) {
			ಬಿಡುಗಡೆ(tmp);
			err = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			ಬಿಡುಗಡೆ(tmp);
			err = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			ಬಿಡುಗಡೆ(tmp);
			err = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಬಿಡುಗಡೆ(*pwd);
		*pwd = tmp;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LS:
		ಆದರೆ (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			ನಿಲ್ಲಿಸು;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ಖಾಲಿ;
		ಆದರೆ (!ಮಾರ್ಗ_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_DF:
		/* Default to current directory if no path specified */
		ಆದರೆ (path1 == ಖಾಲಿ)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LCHDIR:
		ಆದರೆ (path1 == ಖಾಲಿ || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		ಬಿಡುಗಡೆ(path1);
		path1 = tmp;
		ಆದರೆ (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LMKDIR:
		ಆದರೆ (pflag) {
			ಆದರೆ (mkdir_ಮಾರ್ಗ(path1, 0777) != 0)
				err = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LLS:
		local_do_ls(cmd);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_SHELL:
		local_do_shell(cmd);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LUMASK:
		umask(n_arg);
		ಬರೆ("Local umask: %03lo\n", n_arg);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ಖಾಲಿ, &g);
		ಗಾಗಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ಆದರೆ (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			ಆದರೆ (err != 0 && err_abort)
				ನಿಲ್ಲಿಸು;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_CHOWN:
	ಸ್ಥಿತಿ I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ಖಾಲಿ, &g);
		ಗಾಗಿ (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ಆದರೆ ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				ಆದರೆ (err_abort) {
					err = -1;
					ನಿಲ್ಲಿಸು;
				} ಇಲ್ಲದಿದ್ದರೆ
					ಮುಂದುವರಿ;
			}
			ಆದರೆ (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				ಆದರೆ (err_abort) {
					err = -1;
					ನಿಲ್ಲಿಸು;
				} ಇಲ್ಲದಿದ್ದರೆ
					ಮುಂದುವರಿ;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			ಆದರೆ (cmdnum == I_CHOWN) {
				ಆದರೆ (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} ಇಲ್ಲದಿದ್ದರೆ {
				ಆದರೆ (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			ಆದರೆ (err != 0 && err_abort)
				ನಿಲ್ಲಿಸು;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_LPWD:
		ಆದರೆ (!getcwd(ಮಾರ್ಗ_buf, ಗಾತ್ರ(ಮಾರ್ಗ_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			ನಿಲ್ಲಿಸು;
		}
		mprintf("Local working directory: %s\n", ಮಾರ್ಗ_buf);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_QUIT:
		/* Processed below */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_HELP:
		help();
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_ಆವೃತ್ತಿ:
		ಬರೆ("SFTP protocol version %u\n", sftp_proto_ಆವೃತ್ತಿ(conn));
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ I_ಪ್ರಗತಿ:
		showprogress = !showprogress;
		ಆದರೆ (showprogress)
			ಬರೆ("Progress meter enabled\n");
		ಇಲ್ಲದಿದ್ದರೆ
			ಬರೆ("Progress meter disabled\n");
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("%d is not implemented", cmdnum);
	}

	ಆದರೆ (g.gl_pathc)
		globfree(&g);
	ಬಿಡುಗಡೆ(path1);
	ಬಿಡುಗಡೆ(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	ಆದರೆ (err_abort && err != 0)
		ಹಿಂತಿರುಗಿ (-1);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cmdnum == I_QUIT)
		ಹಿಂತಿರುಗಿ (1);

	ಹಿಂತಿರುಗಿ (0);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBEDIT
ಸ್ಥಿರ ಅಕ್ಷರ *
prompt(Edit_ಸಾಲು *el)
{
	ಹಿಂತಿರುಗಿ ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
ಸ್ಥಿರ ಶೂನ್ಯ
complete_display(ಅಕ್ಷರ **list, u_int len)
{
	u_int y, m = 0, ಅಗಲ = 80, columns = 1, colspace = 0, llen;
	ರಚನೆ winsize ws;
	ಅಕ್ಷರ *tmp;

	/* Count entries for sort and find longest */
	ಗಾಗಿ (y = 0; list[y]; y++)
		m = ಗರಿಷ್ಠ(m, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(list[y]));

	ಆದರೆ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		ಅಗಲ = ws.ws_ಲಂಬಸಾಲು;

	m = m > len ? m - len : 0;
	columns = ಅಗಲ / (m + 2);
	columns = ಗರಿಷ್ಠ(columns, 1);
	colspace = ಅಗಲ / columns;
	colspace = MINIMUM(colspace, ಅಗಲ);

	ಬರೆ("\n");
	m = 1;
	ಗಾಗಿ (y = 0; list[y]; y++) {
		llen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		ಆದರೆ (m >= columns) {
			ಬರೆ("\n");
			m = 1;
		} ಇಲ್ಲದಿದ್ದರೆ
			m++;
	}
	ಬರೆ("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
complete_ambiguous(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಶಬ್ದ, ಅಕ್ಷರ **list, ಗಾತ್ರ_t ಎಣಿಕೆ_2)
{
	ಗಾತ್ರ_t i, j, matchlen;
	ಅಕ್ಷರ *tmp;
	ಪೂರ್ಣಾಂಕ len;

	ಆದರೆ (ಶಬ್ದ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	ಆದರೆ (ಎಣಿಕೆ_2 == 0)
		ಹಿಂತಿರುಗಿ xstrdup(ಶಬ್ದ); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(list[0]);
	ಗಾಗಿ (i = 1; i < ಎಣಿಕೆ_2 && list[i] != ಖಾಲಿ; i++) {
		ಗಾಗಿ (j = 0; j < matchlen; j++)
			ಆದರೆ (list[0][j] != list[i][j])
				ನಿಲ್ಲಿಸು;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ಖಾಲಿ, 0);
	ಗಾಗಿ (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		ಆದರೆ (len <= 0 || i + (ಗಾತ್ರ_t)len > matchlen)
			ನಿಲ್ಲಿಸು;
		i += (ಗಾತ್ರ_t)len;
	}
	/* If so, truncate */
	ಆದರೆ (i < matchlen)
		matchlen = i;

	ಆದರೆ (matchlen > ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಶಬ್ದ)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		ಹಿಂತಿರುಗಿ tmp;
	}

	ಹಿಂತಿರುಗಿ xstrdup(ಶಬ್ದ);
}

/* Autocomplete a sftp command */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
complete_cmd_parse(Edit_ಸಾಲು *el, ಅಕ್ಷರ *cmd, ಪೂರ್ಣಾಂಕ lastarg, ಅಕ್ಷರ quote,
    ಪೂರ್ಣಾಂಕ terminated)
{
	u_int y, ಎಣಿಕೆ_2 = 0, cmdlen, tmplen;
	ಅಕ್ಷರ *tmp, **list, argterm[3];
	ಸ್ಥಿರಾಂಕ ಸಾಲು_Info *lf;

	list = xcalloc((ಗಾತ್ರ(cmds) / ಗಾತ್ರ(*cmds)) + 1, ಗಾತ್ರ(ಅಕ್ಷರ *));

	/* No command specified: display all available commands */
	ಆದರೆ (cmd == ಖಾಲಿ) {
		ಗಾಗಿ (y = 0; cmds[y].c; y++)
			list[ಎಣಿಕೆ_2++] = xstrdup(cmds[y].c);

		list[ಎಣಿಕೆ_2] = ಖಾಲಿ;
		complete_display(list, 0);

		ಗಾಗಿ (y = 0; list[y] != ಖಾಲಿ; y++)
			ಬಿಡುಗಡೆ(list[y]);
		ಬಿಡುಗಡೆ(list);
		ಹಿಂತಿರುಗಿ ಎಣಿಕೆ_2;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cmd);
	ಗಾಗಿ (y = 0; cmds[y].c; y++)  {
		ಆದರೆ (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[ಎಣಿಕೆ_2++] = xstrdup(cmds[y].c);
	}
	list[ಎಣಿಕೆ_2] = ಖಾಲಿ;

	ಆದರೆ (ಎಣಿಕೆ_2 == 0) {
		ಬಿಡುಗಡೆ(list);
		ಹಿಂತಿರುಗಿ 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, ಎಣಿಕೆ_2);
	ಆದರೆ (ಎಣಿಕೆ_2 > 1)
		complete_display(list, 0);

	ಗಾಗಿ (y = 0; list[y]; y++)
		ಬಿಡುಗಡೆ(list[y]);
	ಬಿಡುಗಡೆ(list);

	ಆದರೆ (tmp != ಖಾಲಿ) {
		tmplen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(tmp);
		cmdlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cmd);
		/* If cmd may be extended then do so */
		ಆದರೆ (tmplen > cmdlen)
			ಆದರೆ (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_ಸಾಲು(el);
		/* Terminate argument cleanly */
		ಆದರೆ (ಎಣಿಕೆ_2 == 1) {
			y = 0;
			ಆದರೆ (!terminated)
				argterm[y++] = quote;
			ಆದರೆ (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			ಆದರೆ (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		ಬಿಡುಗಡೆ(tmp);
	}

	ಹಿಂತಿರುಗಿ ಎಣಿಕೆ_2;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
complete_is_remote(ಅಕ್ಷರ *cmd, ಪೂರ್ಣಾಂಕ cmdarg) {
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (cmd == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	ಗಾಗಿ (i = 0; cmds[i].c; i++) {
		ಆದರೆ (!strncasecmp(cmd, cmds[i].c, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cmds[i].c))) {
			ಆದರೆ (cmdarg == 1)
				ಹಿಂತಿರುಗಿ cmds[i].t;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (cmdarg == 2)
				ಹಿಂತಿರುಗಿ cmds[i].t2;
			ನಿಲ್ಲಿಸು;
		}
	}

	ಹಿಂತಿರುಗಿ -1;
}

/* Autocomplete a filename "file" */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
complete_ಹೊಂದಿಕೆ(Edit_ಸಾಲು *el, ರಚನೆ sftp_conn *conn, ಅಕ್ಷರ *remote_ಮಾರ್ಗ,
    ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ remote, ಪೂರ್ಣಾಂಕ lastarg, ಅಕ್ಷರ quote, ಪೂರ್ಣಾಂಕ terminated)
{
	glob_t g;
	ಅಕ್ಷರ *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	ಪೂರ್ಣಾಂಕ clen;
	ಸ್ಥಿರಾಂಕ ಸಾಲು_Info *lf;

	/* Glob from "file" location */
	ಆದರೆ (file == ಖಾಲಿ)
		tmp = xstrdup("*");
	ಇಲ್ಲದಿದ್ದರೆ
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = ಮಾರ್ಗ_absolute(tmp);

	memset(&g, 0, ಗಾತ್ರ(g));
	ಆದರೆ (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_ಮಾರ್ಗ);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ಖಾಲಿ, &g);
	} ಇಲ್ಲದಿದ್ದರೆ
		(ಶೂನ್ಯ)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ಖಾಲಿ, &g);

	/* Determine length of pwd so we can trim completion display */
	ಗಾಗಿ (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		ಆದರೆ (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			ಆದರೆ (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		ಆದರೆ (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	ಬಿಡುಗಡೆ(tmp);
	tmp = ಖಾಲಿ;

	ಆದರೆ (g.gl_matchc == 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	ಆದರೆ (file == ಖಾಲಿ || hadglob)
		ಹೋಗು ಹೊರಹೋಗು;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = ಮಾರ್ಗ_strip(tmp2, isabs ? ಖಾಲಿ : remote_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(tmp2);

	ಆದರೆ (tmp == ಖಾಲಿ)
		ಹೋಗು ಹೊರಹೋಗು;

	tmplen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(tmp);
	filelen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	ಗಾಗಿ (i = 0; i < filelen; i++) {
		ಆದರೆ (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} ಇಲ್ಲದಿದ್ದರೆ
			isesc = 0;
	}

	ಆದರೆ (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(tmp2);
		/* quote argument on way out */
		mblen(ಖಾಲಿ, 0);
		ಗಾಗಿ (i = 0; i < len; i += clen) {
			ಆದರೆ ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (ಗಾತ್ರ_t)clen > ಗಾತ್ರ(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			ಸ್ಮರಣೆ_ನಕಲು(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			ಆಯ್ಕೆ (tmp2[i]) {
			ಸ್ಥಿತಿ '\'':
			ಸ್ಥಿತಿ '"':
			ಸ್ಥಿತಿ '\\':
			ಸ್ಥಿತಿ '\t':
			ಸ್ಥಿತಿ '[':
			ಸ್ಥಿತಿ ' ':
			ಸ್ಥಿತಿ '#':
			ಸ್ಥಿತಿ '*':
				ಆದರೆ (quote == '\0' || tmp2[i] == quote) {
					ಆದರೆ (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					ನಿಲ್ಲಿಸು;
				}
				/* FALLTHROUGH */
			ಪೂರ್ವನಿಯೋಜಿತ:
				ಆದರೆ (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				ನಿಲ್ಲಿಸು;
			}
		}
	}

	lf = el_ಸಾಲು(el);
	ಆದರೆ (g.gl_matchc == 1) {
		i = 0;
		ಆದರೆ (!terminated && quote != '\0')
			ins[i++] = quote;
		ಆದರೆ (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		ಆದರೆ (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	ಬಿಡುಗಡೆ(tmp);

 ಹೊರಹೋಗು:
	globfree(&g);
	ಹಿಂತಿರುಗಿ g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
ಸ್ಥಿರ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ
complete(Edit_ಸಾಲು *el, ಪೂರ್ಣಾಂಕ ch)
{
	ಅಕ್ಷರ **argv, *ಸಾಲು, quote;
	ಪೂರ್ಣಾಂಕ argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ಸ್ಥಿರಾಂಕ ಸಾಲು_Info *lf;
	ರಚನೆ complete_ctx *complete_ctx;

	lf = el_ಸಾಲು(el);
	ಆದರೆ (el_get(el, EL_CLIENTDATA, (ಶೂನ್ಯ**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->ಬಫರ್;
	ಸಾಲು = xmalloc(cursor + 1);
	ಸ್ಮರಣೆ_ನಕಲು(ಸಾಲು, lf->ಬಫರ್, cursor);
	ಸಾಲು[cursor] = '\0';
	argv = makeargv(ಸಾಲು, &carg, 1, &quote, &terminated);
	ಬಿಡುಗಡೆ(ಸಾಲು);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->ಬಫರ್;
	ಸಾಲು = xmalloc(len + 1);
	ಸ್ಮರಣೆ_ನಕಲು(ಸಾಲು, lf->ಬಫರ್, len);
	ಸಾಲು[len] = '\0';
	argv = makeargv(ಸಾಲು, &argc, 1, ಖಾಲಿ, ಖಾಲಿ);

	/* Ensure cursor is at EOL or a argument boundary */
	ಆದರೆ (ಸಾಲು[cursor] != ' ' && ಸಾಲು[cursor] != '\0' &&
	    ಸಾಲು[cursor] != '\n') {
		ಬಿಡುಗಡೆ(ಸಾಲು);
		ಹಿಂತಿರುಗಿ ret;
	}

	ಆದರೆ (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ಖಾಲಿ, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (carg == 1 && cursor > 0 && ಸಾಲು[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		ಆದರೆ (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (carg >= 1) {
		/* Handle file parsing */
		ಪೂರ್ಣಾಂಕ remote = 0;
		ಪೂರ್ಣಾಂಕ i = 0, cmdarg = 0;
		ಅಕ್ಷರ *filematch = ಖಾಲಿ;

		ಆದರೆ (carg > 1 && ಸಾಲು[cursor-1] != ' ')
			filematch = argv[carg - 1];

		ಗಾಗಿ (i = 1; i < carg; i++) {
			/* Skip flags */
			ಆದರೆ (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		ಆದರೆ (ಸಾಲು[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		ಆದರೆ ((remote == REMOTE || remote == LOCAL) &&
		    complete_ಹೊಂದಿಕೆ(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	ಬಿಡುಗಡೆ(ಸಾಲು);
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_LIBEDIT */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
interactive_loop(ರಚನೆ sftp_conn *conn, ಅಕ್ಷರ *file1, ಅಕ್ಷರ *file2)
{
	ಅಕ್ಷರ *remote_ಮಾರ್ಗ;
	ಅಕ್ಷರ *dir = ಖಾಲಿ, *startdir = ಖಾಲಿ;
	ಅಕ್ಷರ cmd[2048];
	ಪೂರ್ಣಾಂಕ err, interactive;
	Edit_ಸಾಲು *el = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBEDIT
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *editor;
	History *hl = ಖಾಲಿ;
	HistEvent hev;
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;
	ರಚನೆ complete_ctx complete_ctx;

	ಆದರೆ (!batchmode && isatty(STDIN_FILENO)) {
		ಆದರೆ ((el = el_init(__progname, stdin, stdout, stderr)) == ಖಾಲಿ)
			fatal("Couldn't initialise editline");
		ಆದರೆ ((hl = history_init()) == ಖಾಲಿ)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_ಗಣ(el, EL_HIST, history, hl);

		el_ಗಣ(el, EL_PROMPT, prompt);
		el_ಗಣ(el, EL_EDITOR, "emacs");
		el_ಗಣ(el, EL_TERMINAL, ಖಾಲಿ);
		el_ಗಣ(el, EL_SIGNAL, 1);
		el_ಮೂಲ(el, ಖಾಲಿ);

		/* Tab Completion */
		el_ಗಣ(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_ಮಾರ್ಗ;
		el_ಗಣ(el, EL_CLIENTDATA, (ಶೂನ್ಯ*)&complete_ctx);
		el_ಗಣ(el, EL_BIND, "^I", "ftp-complete", ಖಾಲಿ);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_ಗಣ(el, EL_BIND, "\\e[1;5C", "em-next-word", ಖಾಲಿ);
		el_ಗಣ(el, EL_BIND, "\\e\\e[C", "em-next-word", ಖಾಲಿ);
		el_ಗಣ(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ಖಾಲಿ);
		el_ಗಣ(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ಖಾಲಿ);
		/* make ^w match ksh behaviour */
		el_ಗಣ(el, EL_BIND, "^w", "ed-delete-prev-word", ಖಾಲಿ);

		/* el_source() may have changed EL_EDITOR to vi */
		ಆದರೆ (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_ಗಣ(el, EL_BIND, "^[", "vi-command-mode", ಖಾಲಿ);
	}
#ಆದರೆ_ಅಂತ್ಯ /* USE_LIBEDIT */

	ಆದರೆ ((remote_ಮಾರ್ಗ = sftp_realpath(conn, ".")) == ಖಾಲಿ)
		fatal("Need cwd");
	startdir = xstrdup(remote_ಮಾರ್ಗ);

	ಆದರೆ (file1 != ಖಾಲಿ) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_ಮಾರ್ಗ);

		ಆದರೆ (sftp_remote_is_dir(conn, dir) && file2 == ಖಾಲಿ) {
			ಆದರೆ (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, ಗಾತ್ರ cmd, "cd \"%s\"", dir);
			ಆದರೆ (parse_dispatch_command(conn, cmd,
			    &remote_ಮಾರ್ಗ, startdir, 1, 0) != 0) {
				ಬಿಡುಗಡೆ(dir);
				ಬಿಡುಗಡೆ(startdir);
				ಬಿಡುಗಡೆ(remote_ಮಾರ್ಗ);
				ಬಿಡುಗಡೆ(conn);
				ಹಿಂತಿರುಗಿ (-1);
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
			err = process_get(conn, dir, file2, remote_ಮಾರ್ಗ, 0, 0,
			    global_aflag, 0);
			ಬಿಡುಗಡೆ(dir);
			ಬಿಡುಗಡೆ(startdir);
			ಬಿಡುಗಡೆ(remote_ಮಾರ್ಗ);
			ಬಿಡುಗಡೆ(conn);
			ಹಿಂತಿರುಗಿ (err);
		}
		ಬಿಡುಗಡೆ(dir);
	}

	setvbuf(stdout, ಖಾಲಿ, _IOLBF, 0);
	setvbuf(infile, ಖಾಲಿ, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	ಗಾಗಿ (;;) {
		ರಚನೆ sigaction sa;

		interrupted = 0;
		memset(&sa, 0, ಗಾತ್ರ(sa));
		sa.sa_handler = interactive ? read_ಅಡಚಣೆ : killchild;
		ಆದರೆ (sigaction(SIGINT, &sa, ಖಾಲಿ) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (el == ಖಾಲಿ) {
			ಆದರೆ (interactive) {
				ಬರೆ("sftp> ");
				fflush(stdout);
			}
			ಆದರೆ (fgets(cmd, ಗಾತ್ರ(cmd), infile) == ಖಾಲಿ) {
				ಆದರೆ (interactive)
					ಬರೆ("\n");
				ಆದರೆ (interrupted)
					ಮುಂದುವರಿ;
				ನಿಲ್ಲಿಸು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBEDIT
			ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಾಲು;
			ಪೂರ್ಣಾಂಕ ಎಣಿಕೆ_2 = 0;

			ಆದರೆ ((ಸಾಲು = el_gets(el, &ಎಣಿಕೆ_2)) == ಖಾಲಿ ||
			    ಎಣಿಕೆ_2 <= 0) {
				ಬರೆ("\n");
				ಆದರೆ (interrupted)
					ಮುಂದುವರಿ;
				ನಿಲ್ಲಿಸು;
			}
			history(hl, &hev, H_ENTER, ಸಾಲು);
			ಆದರೆ (strlcpy(cmd, ಸಾಲು, ಗಾತ್ರ(cmd)) >= ಗಾತ್ರ(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				ಮುಂದುವರಿ;
			}
#ಆದರೆ_ಅಂತ್ಯ /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_ಅಡಚಣೆ);

		err = parse_dispatch_command(conn, cmd, &remote_ಮಾರ್ಗ,
		    startdir, batchmode, !interactive && el == ಖಾಲಿ);
		ಆದರೆ (err != 0)
			ನಿಲ್ಲಿಸು;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	ಬಿಡುಗಡೆ(remote_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(startdir);
	ಬಿಡುಗಡೆ(conn);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBEDIT
	ಆದರೆ (hl != ಖಾಲಿ)
		history_ಕೊನೆ(hl);
	ಆದರೆ (el != ಖಾಲಿ)
		el_ಕೊನೆ(el);
#ಆದರೆ_ಅಂತ್ಯ /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	ಹಿಂತಿರುಗಿ (err >= 0 ? 0 : -1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
connect_ಗಮ್ಯ_server(ಅಕ್ಷರ *ಮಾರ್ಗ, ಅಕ್ಷರ **ವಾದಗಳು, ಪೂರ್ಣಾಂಕ *ಒಳ, ಪೂರ್ಣಾಂಕ *ಹೊರಹೋಗು)
{
	ಪೂರ್ಣಾಂಕ c_ಒಳ, c_ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PIPES
	ಪೂರ್ಣಾಂಕ pin[2], pout[2];

	ಆದರೆ ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*ಒಳ = pin[0];
	*ಹೊರಹೋಗು = pout[1];
	c_ಒಳ = pout[0];
	c_ಹೊರಹೋಗು = pin[1];
#ಇಲ್ಲದಿದ್ದರೆ /* USE_PIPES */
	ಪೂರ್ಣಾಂಕ inout[2];

	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*ಒಳ = *ಹೊರಹೋಗು = inout[0];
	c_ಒಳ = c_ಹೊರಹೋಗು = inout[1];
#ಆದರೆ_ಅಂತ್ಯ /* USE_PIPES */
	FD_CLOSEONEXEC(*ಒಳ);
	FD_CLOSEONEXEC(*ಹೊರಹೋಗು);

	ಆದರೆ ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshpid == 0) {
		ಆದರೆ ((dup2(c_ಒಳ, STDIN_FILENO) == -1) ||
		    (dup2(c_ಹೊರಹೋಗು, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*ಒಳ);
		close(*ಹೊರಹೋಗು);
		close(c_ಒಳ);
		close(c_ಹೊರಹೋಗು);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(ಮಾರ್ಗ, ವಾದಗಳು);
		fprintf(stderr, "exec: %s: %s\n", ಮಾರ್ಗ, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_ಒಳ);
	close(c_ಹೊರಹೋಗು);
}

ಸ್ಥಿರ ಶೂನ್ಯ
usage(ಶೂನ್ಯ)
{
	ಬಾಹ್ಯ ಅಕ್ಷರ *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	ನಿರ್ಗಮಿಸು(1);
}

ಪೂರ್ಣಾಂಕ
ಮುಖ್ಯ(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv)
{
	ಪೂರ್ಣಾಂಕ r, ಒಳ, ಹೊರಹೋಗು, ch, err, tmp, ಪೋರ್ಟ್ = -1, noisy = 0;
	ಅಕ್ಷರ *host = ಖಾಲಿ, *user, *cp, **cpp, *file2 = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ debug_level = 0;
	ಅಕ್ಷರ *file1 = ಖಾಲಿ, *sftp_server = ಖಾಲಿ;
	ಅಕ್ಷರ *ssh_ಕಾರ್ಯಕ್ರಮ = ಮಾರ್ಗ_SSH_ಕಾರ್ಯಕ್ರಮ, *sftp_ನೇರ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist ವಾದಗಳು;
	ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ optind;
	ಬಾಹ್ಯ ಅಕ್ಷರ *optarg;
	ರಚನೆ sftp_conn *conn;
	ಗಾತ್ರ_t copy_ಬಫರ್_len = 0;
	ಗಾತ್ರ_t ಅಂಕೆ_ವಿನಂತಿಗಳು = 0;
	ದೀರ್ಘ ದೀರ್ಘ llv, ಎಲ್ಲೆ_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&ವಾದಗಳು, '\0', ಗಾತ್ರ(ವಾದಗಳು));
	ವಾದಗಳು.list = ಖಾಲಿ;
	addargs(&ವಾದಗಳು, "%s", ssh_ಕಾರ್ಯಕ್ರಮ);
	addargs(&ವಾದಗಳು, "-oForwardX11 no");
	addargs(&ವಾದಗಳು, "-oPermitLocalCommand no");
	addargs(&ವಾದಗಳು, "-oClearAllForwardings yes");
	addargs(&ವಾದಗಳು, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	ಆಗ ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		ಆಯ್ಕೆ (ch) {
		/* Passed through to ssh(1) */
		ಸ್ಥಿತಿ 'A':
		ಸ್ಥಿತಿ '4':
		ಸ್ಥಿತಿ '6':
		ಸ್ಥಿತಿ 'C':
			addargs(&ವಾದಗಳು, "-%c", ch);
			ನಿಲ್ಲಿಸು;
		/* Passed through to ssh(1) with argument */
		ಸ್ಥಿತಿ 'F':
		ಸ್ಥಿತಿ 'J':
		ಸ್ಥಿತಿ 'c':
		ಸ್ಥಿತಿ 'i':
		ಸ್ಥಿತಿ 'o':
			addargs(&ವಾದಗಳು, "-%c", ch);
			addargs(&ವಾದಗಳು, "%s", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&ವಾದಗಳು, "-%c", ch);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'P':
			ಪೋರ್ಟ್ = a2port(optarg);
			ಆದರೆ (ಪೋರ್ಟ್ <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'v':
			ಆದರೆ (debug_level < 3) {
				addargs(&ವಾದಗಳು, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '1':
			fatal("SSH protocol v.1 is no longer supported");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '2':
			/* accept silently */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'a':
			global_aflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'B':
			copy_ಬಫರ್_len = strtol(optarg, &cp, 10);
			ಆದರೆ (copy_ಬಫರ್_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'b':
			ಆದರೆ (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			ಆದರೆ (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ಖಾಲಿ)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&ವಾದಗಳು, "-obatchmode yes");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'f':
			global_fflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'p':
			global_pflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'D':
			sftp_ನೇರ = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'l':
			ಎಲ್ಲೆ_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ಆದರೆ (errstr != ಖಾಲಿ)
				usage();
			ಎಲ್ಲೆ_kbps *= 1024; /* kbps */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'r':
			global_rflag = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'R':
			ಅಂಕೆ_ವಿನಂತಿಗಳು = strtol(optarg, &cp, 10);
			ಆದರೆ (ಅಂಕೆ_ವಿನಂತಿಗಳು == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 's':
			sftp_server = optarg;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'S':
			ssh_ಕಾರ್ಯಕ್ರಮ = optarg;
			replacearg(&ವಾದಗಳು, 0, "%s", ssh_ಕಾರ್ಯಕ್ರಮ);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'X':
			/* Please keep in sync with ssh.c -X */
			ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(optarg, "buffer=", 7) == 0) {
				r = ಪರಿಶೀಲನೆ_scaled(optarg + 7, &llv);
				ಆದರೆ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ಆದರೆ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_ಬಫರ್_len = (ಗಾತ್ರ_t)llv;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ಆದರೆ (errstr != ಖಾಲಿ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				ಅಂಕೆ_ವಿನಂತಿಗಳು = (ಗಾತ್ರ_t)llv;
			} ಇಲ್ಲದಿದ್ದರೆ {
				fatal("Invalid -X option");
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 'h':
		ಪೂರ್ವನಿಯೋಜಿತ:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&ವಾದಗಳು, "-oForwardAgent no");

	ಆದರೆ (!isatty(STDERR_FILENO))
		showprogress = 0;

	ಆದರೆ (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	ಆದರೆ (sftp_ನೇರ == ಖಾಲಿ) {
		ಆದರೆ (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		ಆಯ್ಕೆ (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		ಸ್ಥಿತಿ -1:
			usage();
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 0:
			ಆದರೆ (tmp != -1)
				ಪೋರ್ಟ್ = tmp;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			/* Try with user, host and path. */
			ಆದರೆ (parse_user_host_ಮಾರ್ಗ(*argv, &user, &host,
			    &file1) == 0)
				ನಿಲ್ಲಿಸು;
			/* Try with user and host. */
			ಆದರೆ (parse_user_host_ಪೋರ್ಟ್(*argv, &user, &host, ಖಾಲಿ)
			    == 0)
				ನಿಲ್ಲಿಸು;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			ನಿಲ್ಲಿಸು;
		}
		file2 = *(argv + 1);

		ಆದರೆ (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		ಆದರೆ (ಪೋರ್ಟ್ != -1)
			addargs(&ವಾದಗಳು, "-oPort %d", ಪೋರ್ಟ್);
		ಆದರೆ (user != ಖಾಲಿ) {
			addargs(&ವಾದಗಳು, "-l");
			addargs(&ವಾದಗಳು, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		ಆದರೆ (sftp_server == ಖಾಲಿ || strchr(sftp_server, '/') == ಖಾಲಿ)
			addargs(&ವಾದಗಳು, "-s");

		addargs(&ವಾದಗಳು, "--");
		addargs(&ವಾದಗಳು, "%s", host);
		addargs(&ವಾದಗಳು, "%s", (sftp_server != ಖಾಲಿ ?
		    sftp_server : "sftp"));

		connect_ಗಮ್ಯ_server(ssh_ಕಾರ್ಯಕ್ರಮ, ವಾದಗಳು.list, &ಒಳ, &ಹೊರಹೋಗು);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = argv_ವಿಭಜಿಸು(sftp_ನೇರ, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		ಆದರೆ (cpp[0] == ಖಾಲಿ)
			fatal("No sftp server specified via -D");
		connect_ಗಮ್ಯ_server(cpp[0], cpp, &ಒಳ, &ಹೊರಹೋಗು);
		argv_free(cpp, tmp);
	}
	freeargs(&ವಾದಗಳು);

	conn = sftp_init(ಒಳ, ಹೊರಹೋಗು, copy_ಬಫರ್_len, ಅಂಕೆ_ವಿನಂತಿಗಳು, ಎಲ್ಲೆ_kbps);
	ಆದರೆ (conn == ಖಾಲಿ)
		fatal("Couldn't initialise connection to server");

	ಆದರೆ (!quiet) {
		ಆದರೆ (sftp_ನೇರ == ಖಾಲಿ)
			fprintf(stderr, "Connected to %s.\n", host);
		ಇಲ್ಲದಿದ್ದರೆ
			fprintf(stderr, "Attached to %s.\n", sftp_ನೇರ);
	}

	err = interactive_loop(conn, file1, file2);

#ಆದರೆ !defined(USE_PIPES)
	shutdown(ಒಳ, SHUT_RDWR);
	shutdown(ಹೊರಹೋಗು, SHUT_RDWR);
#ಆದರೆ_ಅಂತ್ಯ

	close(ಒಳ);
	close(ಹೊರಹೋಗು);
	ಆದರೆ (batchmode)
		fclose(infile);

	ಆಗ (waitpid(sshpid, ಖಾಲಿ, 0) == -1 && sshpid > 1)
		ಆದರೆ (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	ನಿರ್ಗಮಿಸು(err == 0 ? 0 : 1);
}
