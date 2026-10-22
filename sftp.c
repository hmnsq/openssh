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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/ioctl.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/statvfs.h>
#అన్తర్భావ <sys/wait.h>

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <glob.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <libgen.h>
#నిర్వచితమైతే HAVE_LOCALE_H
# include <locale.h>
#అయితే_ముగింపు
#నిర్వచితమైతే USE_LIBEDIT
#అన్తర్భావ <histedit.h>
#లేకపోతే
రకనిర్వచనం శూన్య Edit_పంక్తి;
#అయితే_ముగింపు
#అన్తర్భావ <limits.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <util.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "utf8.h"

#అన్తర్భావ "sftp.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sftp-common.h"
#అన్తర్భావ "sftp-client.h"
#అన్తర్భావ "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
పూర్ణాంకం batchmode = 0;

/* PID of ssh transport process */
స్థిర అస్థిర pid_t sshpid = -1;

/* Suppress diagnostic messages */
పూర్ణాంకం quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
పూర్ణాంకం showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
పూర్ణాంకం global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
పూర్ణాంకం global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
పూర్ణాంకం global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
పూర్ణాంకం global_fflag = 0;

/* SIGINT received during command processing */
అస్థిర sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
పూర్ణాంకం క్రమీకరించు_flag;
glob_t *క్రమీకరించు_glob;

/* Context used for commandline completion */
నిర్మాణం complete_ctx {
	నిర్మాణం sftp_conn *conn;
	అక్షరం **remote_pathp;
};

పూర్ణాంకం sftp_glob(నిర్మాణం sftp_conn *, స్థిరరాశి అక్షరం *, పూర్ణాంకం,
    పూర్ణాంకం (*)(స్థిరరాశి అక్షరం *, పూర్ణాంకం), glob_t *); /* proto for sftp-glob.c */

బాహ్య అక్షరం *__progname;

/* Separators for interactive commands */
#నిర్వచించు WHITESPACE " \t\r\n"

/* ls flags */
#నిర్వచించు LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#నిర్వచించు LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#నిర్వచించు LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#నిర్వచించు LS_NAME_క్రమీకరించు	0x0008	/* Sort by name (default) */
#నిర్వచించు LS_సమయం_క్రమీకరించు	0x0010	/* Sort by mtime */
#నిర్వచించు LS_కొలత_క్రమీకరించు	0x0020	/* Sort by file size */
#నిర్వచించు LS_తిరగేయి_క్రమీకరించు	0x0040	/* Reverse sort order */
#నిర్వచించు LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#నిర్వచించు LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#నిర్వచించు VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#నిర్వచించు క్రమీకరించు_FLAGS	(LS_NAME_క్రమీకరించు|LS_సమయం_క్రమీకరించు|LS_కొలత_క్రమీకరించు)

/* Commands for interactive mode */
గణన sftp_command {
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
	I_సంస్కరణ,
	I_పురోగతి,
};

నిర్మాణం CMD {
	స్థిరరాశి అక్షరం *c;
	స్థిరరాశి పూర్ణాంకం n;
	స్థిరరాశి పూర్ణాంకం t;	/* Completion type for the first argument */
	స్థిరరాశి పూర్ణాంకం t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#నిర్వచించు NOARGS	0
#నిర్వచించు REMOTE	1
#నిర్వచించు LOCAL	2

స్థిర స్థిరరాశి నిర్మాణం CMD cmds[] = {
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
	{ "progress",	I_పురోగతి,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_సంస్కరణ,	NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ ఖాళీ,		-1,		-1,		-1	}
};

స్థిర శూన్య
killchild(పూర్ణాంకం signo)
{
	pid_t pid;

	pid = sshpid;
	ఒకవేళ (pid > 1) {
		kill(pid, SIGTERM);
		(శూన్య)waitpid(pid, ఖాళీ, 0);
	}

	_exit(1);
}

స్థిర శూన్య
suspchild(పూర్ణాంకం signo)
{
	పూర్ణాంకం save_errno = errno;
	ఒకవేళ (sshpid > 1) {
		kill(sshpid, signo);
		అయితే (waitpid(sshpid, ఖాళీ, WUNTRACED) == -1 && errno == EINTR)
			కొనసాగు;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

స్థిర శూన్య
cmd_అంతరాయం(పూర్ణాంకం signo)
{
	స్థిరరాశి అక్షరం సందేశం[] = "\rInterrupt  \n";
	పూర్ణాంకం olderrno = errno;

	(శూన్య)లిఖ(STDERR_FILENO, సందేశం, పరిమాణం(సందేశం) - 1);
	interrupted = 1;
	errno = olderrno;
}

స్థిర శూన్య
read_అంతరాయం(పూర్ణాంకం signo)
{
	interrupted = 1;
}

స్థిర శూన్య
sigchld_handler(పూర్ణాంకం sig)
{
	పూర్ణాంకం save_errno = errno;
	pid_t pid;
	స్థిరరాశి అక్షరం సందేశం[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	అయితే ((pid = waitpid(sshpid, ఖాళీ, WNOHANG)) == -1 && errno == EINTR)
		కొనసాగు;
	ఒకవేళ (pid == sshpid) {
		ఒకవేళ (!quiet)
		    (శూన్య)లిఖ(STDERR_FILENO, సందేశం, పరిమాణం(సందేశం) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

స్థిర శూన్య
help(శూన్య)
{
	రాయి("Available commands:\n"
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

స్థిర శూన్య
local_do_shell(స్థిరరాశి అక్షరం *వాదనలు)
{
	పూర్ణాంకం స్థితి_2;
	అక్షరం *shell;
	pid_t pid;

	ఒకవేళ (!*వాదనలు)
		వాదనలు = ఖాళీ;

	ఒకవేళ ((shell = getenv("SHELL")) == ఖాళీ || *shell == '\0')
		shell = _PATH_BSHELL;

	ఒకవేళ ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	ఒకవేళ (pid == 0) {
		ఒకవేళ (వాదనలు) {
			debug3("Executing %s -c \"%s\"", shell, వాదనలు);
			execl(shell, shell, "-c", వాదనలు, (అక్షరం *)ఖాళీ);
		} లేకపోతే {
			debug3("Executing %s", shell);
			execl(shell, shell, (అక్షరం *)ఖాళీ);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	అయితే (waitpid(pid, &స్థితి_2, 0) == -1)
		ఒకవేళ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	ఒకవేళ (!WIFEXITED(స్థితి_2))
		error("Shell exited abnormally");
	లేకపోతే ఒకవేళ (WEXITSTATUS(స్థితి_2))
		error("Shell exited with status %d", WEXITSTATUS(స్థితి_2));
}

స్థిర శూన్య
local_do_ls(స్థిరరాశి అక్షరం *వాదనలు)
{
	ఒకవేళ (!వాదనలు || !*వాదనలు)
		local_do_shell(మార్గం_LS);
	లేకపోతే {
		పూర్ణాంకం len = అక్షరశ్రేణి_పొడవు(మార్గం_LS " ") + అక్షరశ్రేణి_పొడవు(వాదనలు) + 1;
		అక్షరం *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, మార్గం_LS " %s", వాదనలు);
		local_do_shell(buf);
		విడుదల(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
స్థిర అక్షరం *
మార్గం_strip(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి అక్షరం *strip)
{
	కొలత_t len;

	ఒకవేళ (strip == ఖాళీ || (len = అక్షరశ్రేణి_పొడవు(strip)) == 0)
		తిరిగి (xstrdup(మార్గం));

	ఒకవేళ (అక్షరశ్రేణి_పోలిక(మార్గం, strip, len) == 0) {
		ఒకవేళ (strip[len - 1] != '/' && మార్గం[len] == '/')
			len++;
		తిరిగి (xstrdup(మార్గం + len));
	}

	తిరిగి (xstrdup(మార్గం));
}

స్థిర పూర్ణాంకం
parse_getput_flags(స్థిరరాశి అక్షరం *cmd, అక్షరం **argv, పూర్ణాంకం argc,
    పూర్ణాంకం *aflag, పూర్ణాంకం *fflag, పూర్ణాంకం *pflag, పూర్ణాంకం *rflag)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	అయితే ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'a':
			*aflag = 1;
			ఆపు;
		స్థితి 'f':
			*fflag = 1;
			ఆపు;
		స్థితి 'p':
		స్థితి 'P':
			*pflag = 1;
			ఆపు;
		స్థితి 'r':
		స్థితి 'R':
			*rflag = 1;
			ఆపు;
		అప్రమేయ:
			error("%s: Invalid flag -%c", cmd, optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర పూర్ణాంకం
parse_mkdir_flags(స్థిరరాశి అక్షరం *cmd, అక్షరం **argv, పూర్ణాంకం argc, పూర్ణాంకం *pflag)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	అయితే ((ch = getopt(argc, argv, "p")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'p':
			*pflag = 1;
			ఆపు;
		అప్రమేయ:
			error("%s: Invalid flag -%c", cmd, optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర పూర్ణాంకం
parse_link_flags(స్థిరరాశి అక్షరం *cmd, అక్షరం **argv, పూర్ణాంకం argc, పూర్ణాంకం *sflag)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	అయితే ((ch = getopt(argc, argv, "s")) != -1) {
		ఎంపిక (ch) {
		స్థితి 's':
			*sflag = 1;
			ఆపు;
		అప్రమేయ:
			error("%s: Invalid flag -%c", cmd, optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర పూర్ణాంకం
parse_rename_flags(స్థిరరాశి అక్షరం *cmd, అక్షరం **argv, పూర్ణాంకం argc, పూర్ణాంకం *lflag)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	అయితే ((ch = getopt(argc, argv, "l")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'l':
			*lflag = 1;
			ఆపు;
		అప్రమేయ:
			error("%s: Invalid flag -%c", cmd, optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర పూర్ణాంకం
parse_ls_flags(అక్షరం **argv, పూర్ణాంకం argc, పూర్ణాంకం *lflag)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_క్రమీకరించు;
	అయితే ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		ఎంపిక (ch) {
		స్థితి '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			ఆపు;
		స్థితి 'S':
			*lflag &= ~క్రమీకరించు_FLAGS;
			*lflag |= LS_కొలత_క్రమీకరించు;
			ఆపు;
		స్థితి 'a':
			*lflag |= LS_SHOW_ALL;
			ఆపు;
		స్థితి 'f':
			*lflag &= ~క్రమీకరించు_FLAGS;
			ఆపు;
		స్థితి 'h':
			*lflag |= LS_SI_UNITS;
			ఆపు;
		స్థితి 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			ఆపు;
		స్థితి 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			ఆపు;
		స్థితి 'r':
			*lflag |= LS_తిరగేయి_క్రమీకరించు;
			ఆపు;
		స్థితి 't':
			*lflag &= ~క్రమీకరించు_FLAGS;
			*lflag |= LS_సమయం_క్రమీకరించు;
			ఆపు;
		అప్రమేయ:
			error("ls: Invalid flag -%c", optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర పూర్ణాంకం
parse_df_flags(స్థిరరాశి అక్షరం *cmd, అక్షరం **argv, పూర్ణాంకం argc, పూర్ణాంకం *hflag, పూర్ణాంకం *iflag)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	అయితే ((ch = getopt(argc, argv, "hi")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'h':
			*hflag = 1;
			ఆపు;
		స్థితి 'i':
			*iflag = 1;
			ఆపు;
		అప్రమేయ:
			error("%s: Invalid flag -%c", cmd, optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర పూర్ణాంకం
parse_ch_flags(స్థిరరాశి అక్షరం *cmd, అక్షరం **argv, పూర్ణాంకం argc, పూర్ణాంకం *hflag)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	అయితే ((ch = getopt(argc, argv, "h")) != -1) {
		ఎంపిక (ch) {
		స్థితి 'h':
			*hflag = 1;
			ఆపు;
		అప్రమేయ:
			error("%s: Invalid flag -%c", cmd, optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర పూర్ణాంకం
parse_no_flags(స్థిరరాశి అక్షరం *cmd, అక్షరం **argv, పూర్ణాంకం argc)
{
	బాహ్య పూర్ణాంకం opterr, optind, optopt, optreset;
	పూర్ణాంకం ch;

	optind = optreset = 1;
	opterr = 0;

	అయితే ((ch = getopt(argc, argv, "")) != -1) {
		ఎంపిక (ch) {
		అప్రమేయ:
			error("%s: Invalid flag -%c", cmd, optopt);
			తిరిగి -1;
		}
	}

	తిరిగి optind;
}

స్థిర అక్షరం *
escape_glob(స్థిరరాశి అక్షరం *s)
{
	కొలత_t i, o, len;
	అక్షరం *ret;

	len = అక్షరశ్రేణి_పొడవు(s);
	ret = xcalloc(2, len + 1);
	కొరకు (i = o = 0; i < len; i++) {
		ఒకవేళ (strchr("[]?*\\", s[i]) != ఖాళీ)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	తిరిగి ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
స్థిర అక్షరం *
make_absolute_pwd_glob(అక్షరం *p, స్థిరరాశి అక్షరం *pwd)
{
	అక్షరం *ret, *escpwd;

	escpwd = escape_glob(pwd);
	ఒకవేళ (p == ఖాళీ)
		తిరిగి escpwd;
	ret = sftp_make_absolute(p, escpwd);
	విడుదల(escpwd);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
local_is_dir(స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం stat sb;

	ఒకవేళ (stat(మార్గం, &sb) == -1)
		తిరిగి 0;
	తిరిగి S_ISDIR(sb.st_mode);
}

స్థిర పూర్ణాంకం
process_get(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *src, స్థిరరాశి అక్షరం *dst,
    స్థిరరాశి అక్షరం *pwd, పూర్ణాంకం pflag, పూర్ణాంకం rflag, పూర్ణాంకం resume, పూర్ణాంకం fflag)
{
	అక్షరం *filename, *abs_src = ఖాళీ, *abs_dst = ఖాళీ, *tmp = ఖాళీ;
	glob_t g;
	పూర్ణాంకం i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, పరిమాణం(g));

	debug3("Looking up %s", abs_src);
	ఒకవేళ ((r = sftp_glob(conn, abs_src, GLOB_MARK, ఖాళీ, &g)) != 0) {
		ఒకవేళ (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} లేకపోతే {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	ఒకవేళ (g.gl_matchc > 1 && dst != ఖాళీ && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	కొరకు (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		ఒకవేళ ((filename = basename(tmp)) == ఖాళీ) {
			error("basename %s: %s", tmp, strerror(errno));
			విడుదల(tmp);
			err = -1;
			వెళ్ళు బహిర్గతం;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		ఒకవేళ (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		ఒకవేళ (g.gl_matchc == 1 && dst) {
			ఒకవేళ (local_is_dir(dst)) {
				abs_dst = sftp_మార్గం_append(dst, filename);
			} లేకపోతే {
				abs_dst = xstrdup(dst);
			}
		} లేకపోతే ఒకవేళ (dst) {
			abs_dst = sftp_మార్గం_append(dst, filename);
		} లేకపోతే {
			abs_dst = xstrdup(filename);
		}
		విడుదల(tmp);

		resume |= global_aflag;
		ఒకవేళ (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		లేకపోతే ఒకవేళ (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		ఒకవేళ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ఒకవేళ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    ఖాళీ, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} లేకపోతే {
			ఒకవేళ (sftp_download(conn, g.gl_pathv[i], abs_dst, ఖాళీ,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		విడుదల(abs_dst);
		abs_dst = ఖాళీ;
	}

బహిర్గతం:
	విడుదల(abs_src);
	globfree(&g);
	తిరిగి(err);
}

స్థిర పూర్ణాంకం
process_put(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *src, స్థిరరాశి అక్షరం *dst,
    స్థిరరాశి అక్షరం *pwd, పూర్ణాంకం pflag, పూర్ణాంకం rflag, పూర్ణాంకం resume, పూర్ణాంకం fflag)
{
	అక్షరం *tmp_dst = ఖాళీ;
	అక్షరం *abs_dst = ఖాళీ;
	అక్షరం *tmp = ఖాళీ, *filename = ఖాళీ;
	glob_t g;
	పూర్ణాంకం err = 0;
	పూర్ణాంకం i, dst_is_dir = 1;
	నిర్మాణం stat sb;

	ఒకవేళ (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, పరిమాణం(g));
	debug3("Looking up %s", src);
	ఒకవేళ (glob(src, GLOB_NOCHECK | GLOB_MARK, ఖాళీ, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	ఒకవేళ (tmp_dst != ఖాళీ)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	ఒకవేళ (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		వెళ్ళు బహిర్గతం;
	}

	కొరకు (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		ఒకవేళ (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			కొనసాగు;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		ఒకవేళ ((filename = basename(tmp)) == ఖాళీ) {
			error("basename %s: %s", tmp, strerror(errno));
			విడుదల(tmp);
			err = -1;
			వెళ్ళు బహిర్గతం;
		}
		/* Special handling for source of '..' */
		ఒకవేళ (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		విడుదల(abs_dst);
		abs_dst = ఖాళీ;
		ఒకవేళ (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			ఒకవేళ (dst_is_dir)
				abs_dst = sftp_మార్గం_append(tmp_dst, filename);
			లేకపోతే
				abs_dst = xstrdup(tmp_dst);
		} లేకపోతే ఒకవేళ (tmp_dst) {
			abs_dst = sftp_మార్గం_append(tmp_dst, filename);
		} లేకపోతే {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		విడుదల(tmp);

		resume |= global_aflag;
		ఒకవేళ (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		లేకపోతే ఒకవేళ (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		ఒకవేళ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			ఒకవేళ (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} లేకపోతే {
			ఒకవేళ (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

బహిర్గతం:
	విడుదల(abs_dst);
	విడుదల(tmp_dst);
	globfree(&g);
	తిరిగి(err);
}

స్థిర పూర్ణాంకం
sdirent_comp(స్థిరరాశి శూన్య *aa, స్థిరరాశి శూన్య *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	పూర్ణాంకం rmul = క్రమీకరించు_flag & LS_తిరగేయి_క్రమీకరించు ? -1 : 1;

#నిర్వచించు NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	ఒకవేళ (క్రమీకరించు_flag & LS_NAME_క్రమీకరించు)
		తిరిగి (rmul * strcmp(a->filename, b->filename));
	లేకపోతే ఒకవేళ (క్రమీకరించు_flag & LS_సమయం_క్రమీకరించు)
		తిరిగి (rmul * NCMP(a->a.mtime, b->a.mtime));
	లేకపోతే ఒకవేళ (క్రమీకరించు_flag & LS_కొలత_క్రమీకరించు)
		తిరిగి (rmul * NCMP(a->a.కొలత, b->a.కొలత));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
స్థిర పూర్ణాంకం
do_ls_dir(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం,
    స్థిరరాశి అక్షరం *strip_మార్గం, పూర్ణాంకం lflag)
{
	పూర్ణాంకం n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	ఒకవేళ ((n = sftp_readdir(conn, మార్గం, &d)) != 0)
		తిరిగి (n);

	ఒకవేళ (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, వెడల్పు = 80;
		నిర్మాణం winsize ws;
		అక్షరం *tmp;

		/* Count entries for sort and find longest filename */
		కొరకు (n = 0; d[n] != ఖాళీ; n++) {
			ఒకవేళ (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = గరిష్ఠ(m, అక్షరశ్రేణి_పొడవు(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = మార్గం_strip(మార్గం, strip_మార్గం);
		m += అక్షరశ్రేణి_పొడవు(tmp);
		విడుదల(tmp);

		ఒకవేళ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			వెడల్పు = ws.ws_నిలువు;

		columns = వెడల్పు / (m + 2);
		columns = గరిష్ఠ(columns, 1);
		colspace = వెడల్పు / columns;
		colspace = MINIMUM(colspace, వెడల్పు);
	}

	ఒకవేళ (lflag & క్రమీకరించు_FLAGS) {
		కొరకు (n = 0; d[n] != ఖాళీ; n++)
			;	/* count entries */
		క్రమీకరించు_flag = lflag & (క్రమీకరించు_FLAGS|LS_తిరగేయి_క్రమీకరించు);
		qsort(d, n, పరిమాణం(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	కొరకు (n = 0; d[n] != ఖాళీ && !interrupted; n++) {
		అక్షరం *tmp, *fname;

		ఒకవేళ (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			కొనసాగు;

		tmp = sftp_మార్గం_append(మార్గం, d[n]->filename);
		fname = మార్గం_strip(tmp, strip_మార్గం);
		విడుదల(tmp);

		ఒకవేళ (lflag & LS_LONG_VIEW) {
			ఒకవేళ ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				అక్షరం *lname;
				నిర్మాణం stat sb;
				స్థిరరాశి అక్షరం *user = ఖాళీ, *సమూహం = ఖాళీ;

				memset(&sb, 0, పరిమాణం(sb));
				attrib_గమ్యం_stat(&d[n]->a, &sb);
				ఒకవేళ ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					సమూహం = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, సమూహం);
				mprintf("%s\n", lname);
				విడుదల(lname);
			} లేకపోతే
				mprintf("%s\n", d[n]->longname);
		} లేకపోతే {
			mprintf("%-*s", colspace, fname);
			ఒకవేళ (c >= columns) {
				రాయి("\n");
				c = 1;
			} లేకపోతే
				c++;
		}

		విడుదల(fname);
	}

	ఒకవేళ (!(lflag & LS_LONG_VIEW) && (c != 1))
		రాయి("\n");

	sftp_free_dirents(d);
	తిరిగి (0);
}

స్థిర పూర్ణాంకం
sglob_comp(స్థిరరాశి శూన్య *aa, స్థిరరాశి శూన్య *bb)
{
	u_int a = *(స్థిరరాశి u_int *)aa;
	u_int b = *(స్థిరరాశి u_int *)bb;
	స్థిరరాశి అక్షరం *ap = క్రమీకరించు_glob->gl_pathv[a];
	స్థిరరాశి అక్షరం *bp = క్రమీకరించు_glob->gl_pathv[b];
	స్థిరరాశి నిర్మాణం stat *as = క్రమీకరించు_glob->gl_statv[a];
	స్థిరరాశి నిర్మాణం stat *bs = క్రమీకరించు_glob->gl_statv[b];
	పూర్ణాంకం rmul = క్రమీకరించు_flag & LS_తిరగేయి_క్రమీకరించు ? -1 : 1;

#నిర్వచించు NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	ఒకవేళ (as == ఖాళీ || bs == ఖాళీ)
		తిరిగి (as == bs) ? 0 : (as == ఖాళీ ? rmul : -rmul);
	ఒకవేళ (క్రమీకరించు_flag & LS_NAME_క్రమీకరించు)
		తిరిగి (rmul * strcmp(ap, bp));
	లేకపోతే ఒకవేళ (క్రమీకరించు_flag & LS_సమయం_క్రమీకరించు) {
#ఒకవేళ defined(HAVE_STRUCT_STAT_ST_MTIM)
		ఒకవేళ (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			తిరిగి 0;
		తిరిగి timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#లేదావేళ defined(HAVE_STRUCT_STAT_ST_MTIME)
		తిరిగి (rmul * NCMP(as->st_mtime, bs->st_mtime));
#లేకపోతే
	తిరిగి rmul * 1;
#అయితే_ముగింపు
	} లేకపోతే ఒకవేళ (క్రమీకరించు_flag & LS_కొలత_క్రమీకరించు)
		తిరిగి (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
స్థిర పూర్ణాంకం
do_globbed_ls(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం,
    స్థిరరాశి అక్షరం *strip_మార్గం, పూర్ణాంకం lflag)
{
	అక్షరం *fname, *lname;
	glob_t g;
	పూర్ణాంకం err, r;
	నిర్మాణం winsize ws;
	u_int i, j, nentries, *indices = ఖాళీ, c = 1;
	u_int colspace = 0, columns = 1, m = 0, వెడల్పు = 80;

	memset(&g, 0, పరిమాణం(g));

	ఒకవేళ ((r = sftp_glob(conn, మార్గం,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    ఖాళీ, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		ఒకవేళ (g.gl_pathc)
			globfree(&g);
		ఒకవేళ (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", మార్గం);
		} లేకపోతే {
			error("Can't ls: \"%s\" not found", మార్గం);
		}
		తిరిగి -1;
	}

	ఒకవేళ (interrupted)
		వెళ్ళు బహిర్గతం;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	ఒకవేళ (g.gl_matchc == 1 && g.gl_statv[0] != ఖాళీ &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_మార్గం, lflag);
		globfree(&g);
		తిరిగి err;
	}

	ఒకవేళ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		వెడల్పు = ws.ws_నిలువు;

	ఒకవేళ (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		కొరకు (i = 0; g.gl_pathv[i]; i++)
			m = గరిష్ఠ(m, అక్షరశ్రేణి_పొడవు(g.gl_pathv[i]));

		columns = వెడల్పు / (m + 2);
		columns = గరిష్ఠ(columns, 1);
		colspace = వెడల్పు / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	కొరకు (nentries = 0; g.gl_pathv[nentries] != ఖాళీ; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, పరిమాణం(*indices));
	కొరకు (i = 0; i < nentries; i++)
		indices[i] = i;

	ఒకవేళ (lflag & క్రమీకరించు_FLAGS) {
		క్రమీకరించు_glob = &g;
		క్రమీకరించు_flag = lflag & (క్రమీకరించు_FLAGS|LS_తిరగేయి_క్రమీకరించు);
		qsort(indices, nentries, పరిమాణం(*indices), sglob_comp);
		క్రమీకరించు_glob = ఖాళీ;
	}

	get_remote_user_groups_from_glob(conn, &g);
	కొరకు (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = మార్గం_strip(g.gl_pathv[i], strip_మార్గం);
		ఒకవేళ (lflag & LS_LONG_VIEW) {
			స్థిరరాశి అక్షరం *user = ఖాళీ, *సమూహం = ఖాళీ;

			ఒకవేళ (g.gl_statv[i] == ఖాళీ) {
				error("no stat information for %s", fname);
				విడుదల(fname);
				కొనసాగు;
			}
			ఒకవేళ ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				సమూహం = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, సమూహం);
			mprintf("%s\n", lname);
			విడుదల(lname);
		} లేకపోతే {
			mprintf("%-*s", colspace, fname);
			ఒకవేళ (c >= columns) {
				రాయి("\n");
				c = 1;
			} లేకపోతే
				c++;
		}
		విడుదల(fname);
	}

	ఒకవేళ (!(lflag & LS_LONG_VIEW) && (c != 1))
		రాయి("\n");

 బహిర్గతం:
	ఒకవేళ (g.gl_pathc)
		globfree(&g);
	విడుదల(indices);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
do_df(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం hflag, పూర్ణాంకం iflag)
{
	నిర్మాణం sftp_statvfs st;
	అక్షరం s_వాడిన[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	అక్షరం s_మూలం[FMT_SCALED_STRSIZE], s_మొత్తం[FMT_SCALED_STRSIZE];
	అక్షరం s_icapacity[16], s_dcapacity[16];

	ఒకవేళ (sftp_statvfs(conn, మార్గం, &st, 1) == -1)
		తిరిగి -1;
	ఒకవేళ (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", పరిమాణం(s_icapacity));
	లేకపోతే {
		snprintf(s_icapacity, పరిమాణం(s_icapacity), "%3llu%%",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	ఒకవేళ (st.f_ఖండాలు == 0)
		strlcpy(s_dcapacity, "ERR", పరిమాణం(s_dcapacity));
	లేకపోతే {
		snprintf(s_dcapacity, పరిమాణం(s_dcapacity), "%3llu%%",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)(100 * (st.f_ఖండాలు - st.f_bfree) /
		    st.f_ఖండాలు));
	}
	ఒకవేళ (iflag) {
		రాయి("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		రాయి("%11llu %11llu %11llu %11llu         %s\n",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)st.f_files,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)(st.f_files - st.f_ffree),
		    (గుర్తులేని దీర్ఘ దీర్ఘ)st.f_favail,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)st.f_ffree, s_icapacity);
	} లేకపోతే ఒకవేళ (hflag) {
		strlcpy(s_వాడిన, "error", పరిమాణం(s_వాడిన));
		strlcpy(s_avail, "error", పరిమాణం(s_avail));
		strlcpy(s_మూలం, "error", పరిమాణం(s_మూలం));
		strlcpy(s_మొత్తం, "error", పరిమాణం(s_మొత్తం));
		fmt_scaled((st.f_ఖండాలు - st.f_bfree) * st.f_frsize, s_వాడిన);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_మూలం);
		fmt_scaled(st.f_ఖండాలు * st.f_frsize, s_మొత్తం);
		రాయి("    Size     Used    Avail   (root)    %%Capacity\n");
		రాయి("%7sB %7sB %7sB %7sB         %s\n",
		    s_మొత్తం, s_వాడిన, s_avail, s_మూలం, s_dcapacity);
	} లేకపోతే {
		రాయి("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		రాయి("%12llu %12llu %12llu %12llu         %s\n",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)(st.f_frsize * st.f_ఖండాలు / 1024),
		    (గుర్తులేని దీర్ఘ దీర్ఘ)(st.f_frsize *
		    (st.f_ఖండాలు - st.f_bfree) / 1024),
		    (గుర్తులేని దీర్ఘ దీర్ఘ)(st.f_frsize * st.f_bavail / 1024),
		    (గుర్తులేని దీర్ఘ దీర్ఘ)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	తిరిగి 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
స్థిర శూన్య
undo_glob_escape(అక్షరం *s)
{
	కొలత_t i, j;

	కొరకు (i = j = 0;;) {
		ఒకవేళ (s[i] == '\0') {
			s[j] = '\0';
			తిరిగి;
		}
		ఒకవేళ (s[i] != '\\') {
			s[j++] = s[i++];
			కొనసాగు;
		}
		/* s[i] == '\\' */
		++i;
		ఎంపిక (s[i]) {
		స్థితి '?':
		స్థితి '[':
		స్థితి '*':
		స్థితి '\\':
			s[j++] = s[i++];
			ఆపు;
		స్థితి '\0':
			s[j++] = '\\';
			s[j] = '\0';
			తిరిగి;
		అప్రమేయ:
			s[j++] = '\\';
			s[j++] = s[i++];
			ఆపు;
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
#నిర్వచించు MAXARGS		128
#నిర్వచించు MAXARGLEN	8192
స్థిర అక్షరం **
makeargv(స్థిరరాశి అక్షరం *arg, పూర్ణాంకం *argcp, పూర్ణాంకం sloppy, అక్షరం *lastquote,
    u_int *terminated)
{
	పూర్ణాంకం argc, quot;
	కొలత_t i, j;
	స్థిర అక్షరం argvs[MAXARGLEN];
	స్థిర అక్షరం *argv[MAXARGS + 1];
	గణన { MA_ప్రారంభం, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(arg) > పరిమాణం(argvs) - 1) {
 వాదనలు_too_longs:
		error("string too long");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (terminated != ఖాళీ)
		*terminated = 1;
	ఒకవేళ (lastquote != ఖాళీ)
		*lastquote = '\0';
	state = MA_ప్రారంభం;
	i = j = 0;
	కొరకు (;;) {
		ఒకవేళ ((కొలత_t)argc >= పరిమాణం(argv) / పరిమాణం(*argv)){
			error("Too many arguments.");
			తిరిగి ఖాళీ;
		}
		ఒకవేళ (ఖాళీనా((గుర్తులేని అక్షరం)arg[i])) {
			ఒకవేళ (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_ప్రారంభం;
			} లేకపోతే ఒకవేళ (state != MA_ప్రారంభం)
				argvs[j++] = arg[i];
		} లేకపోతే ఒకవేళ (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			ఒకవేళ (state == MA_ప్రారంభం) {
				argv[argc] = argvs + j;
				state = q;
				ఒకవేళ (lastquote != ఖాళీ)
					*lastquote = arg[i];
			} లేకపోతే ఒకవేళ (state == MA_UNQUOTED)
				state = q;
			లేకపోతే ఒకవేళ (state == q)
				state = MA_UNQUOTED;
			లేకపోతే
				argvs[j++] = arg[i];
		} లేకపోతే ఒకవేళ (arg[i] == '\\') {
			ఒకవేళ (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				ఒకవేళ (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} లేకపోతే ఒకవేళ (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					ఒకవేళ (j >= పరిమాణం(argvs) - 5)
						వెళ్ళు వాదనలు_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} లేకపోతే {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} లేకపోతే {
				ఒకవేళ (state == MA_ప్రారంభం) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					ఒకవేళ (lastquote != ఖాళీ)
						*lastquote = '\0';
				}
				ఒకవేళ (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} లేకపోతే {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					ఒకవేళ (arg[i] == '\0')
						వెళ్ళు early_nul;
					argvs[j++] = arg[i];
				}
			}
		} లేకపోతే ఒకవేళ (arg[i] == '#') {
			ఒకవేళ (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			లేకపోతే
				వెళ్ళు string_పూర్తి;
		} లేకపోతే ఒకవేళ (arg[i] == '\0') {
			ఒకవేళ (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				ఒకవేళ (sloppy) {
					state = MA_UNQUOTED;
					ఒకవేళ (terminated != ఖాళీ)
						*terminated = 0;
					వెళ్ళు string_పూర్తి;
				}
				error("Unterminated quoted argument");
				తిరిగి ఖాళీ;
			}
 string_పూర్తి:
			ఒకవేళ (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			ఆపు;
		} లేకపోతే {
			ఒకవేళ (state == MA_ప్రారంభం) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				ఒకవేళ (lastquote != ఖాళీ)
					*lastquote = '\0';
			}
			ఒకవేళ ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				ఒకవేళ (j >= పరిమాణం(argvs) - 3)
					వెళ్ళు వాదనలు_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} లేకపోతే
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	తిరిగి argv;
}

స్థిర పూర్ణాంకం
parse_వాదనలు(స్థిరరాశి అక్షరం **cpp, పూర్ణాంకం *ignore_errors, పూర్ణాంకం *disable_echo, పూర్ణాంకం *aflag,
	  పూర్ణాంకం *fflag, పూర్ణాంకం *hflag, పూర్ణాంకం *iflag, పూర్ణాంకం *lflag, పూర్ణాంకం *pflag,
	  పూర్ణాంకం *rflag, పూర్ణాంకం *sflag,
    గుర్తులేని దీర్ఘ *n_arg, అక్షరం **path1, అక్షరం **path2)
{
	స్థిరరాశి అక్షరం *cmd, *cp = *cpp;
	అక్షరం *cp2, **argv;
	పూర్ణాంకం పునాది = 0;
	దీర్ఘ దీర్ఘ ll;
	పూర్ణాంకం path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	కొరకు (;*cp != '\0'; cp++) {
		ఒకవేళ (*cp == '-') {
			*ignore_errors = 1;
		} లేకపోతే ఒకవేళ (*cp == '@') {
			*disable_echo = 1;
		} లేకపోతే {
			/* all other characters terminate prefix processing */
			ఆపు;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	ఒకవేళ (*cp == '\0' || *cp == '#')
		తిరిగి (0);

	ఒకవేళ ((argv = makeargv(cp, &argc, 0, ఖాళీ, ఖాళీ)) == ఖాళీ)
		తిరిగి -1;

	/* Figure out which command we have */
	కొరకు (i = 0; cmds[i].c != ఖాళీ; i++) {
		ఒకవేళ (argv[0] != ఖాళీ && strcasecmp(cmds[i].c, argv[0]) == 0)
			ఆపు;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	ఒకవేళ (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} లేకపోతే ఒకవేళ (cmdnum == -1) {
		error("Invalid command.");
		తిరిగి -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = ఖాళీ;
	optidx = 1;
	ఎంపిక (cmdnum) {
	స్థితి I_GET:
	స్థితి I_REGET:
	స్థితి I_REPUT:
	స్థితి I_PUT:
		ఒకవేళ ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			తిరిగి -1;
		/* Get first pathname (mandatory) */
		ఒకవేళ (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			తిరిగి -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		ఒకవేళ (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		ఆపు;
	స్థితి I_LINK:
		ఒకవేళ ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			తిరిగి -1;
		వెళ్ళు parse_two_paths;
	స్థితి I_COPY:
		ఒకవేళ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			తిరిగి -1;
		వెళ్ళు parse_two_paths;
	స్థితి I_RENAME:
		ఒకవేళ ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			తిరిగి -1;
		వెళ్ళు parse_two_paths;
	స్థితి I_SYMLINK:
		ఒకవేళ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			తిరిగి -1;
 parse_two_paths:
		ఒకవేళ (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			తిరిగి -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		ఆపు;
	స్థితి I_MKDIR:
	స్థితి I_LMKDIR:
		ఒకవేళ ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			తిరిగి -1;
		path1_mandatory = 1;
		వెళ్ళు parse_one_మార్గం;
	స్థితి I_RM:
	స్థితి I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	స్థితి I_CHDIR:
	స్థితి I_LCHDIR:
		ఒకవేళ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			తిరిగి -1;
 parse_one_మార్గం:
		/* Get pathname (mandatory) */
		ఒకవేళ (argc - optidx < 1) {
			ఒకవేళ (!path1_mandatory)
				ఆపు; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			తిరిగి -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		ఒకవేళ (cmdnum != I_RM)
			undo_glob_escape(*path1);
		ఆపు;
	స్థితి I_DF:
		ఒకవేళ ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			తిరిగి -1;
		/* Default to current directory if no path specified */
		ఒకవేళ (argc - optidx < 1)
			*path1 = ఖాళీ;
		లేకపోతే {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		ఆపు;
	స్థితి I_LS:
		ఒకవేళ ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			తిరిగి(-1);
		/* Path is optional */
		ఒకవేళ (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		ఆపు;
	స్థితి I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + అక్షరశ్రేణి_పొడవు(cmd) + strspn(cp, WHITESPACE);
	స్థితి I_SHELL:
		/* Uses the rest of the line */
		ఆపు;
	స్థితి I_LUMASK:
	స్థితి I_CHMOD:
		పునాది = 8;
		/* FALLTHROUGH */
	స్థితి I_CHOWN:
	స్థితి I_CHGRP:
		ఒకవేళ ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			తిరిగి -1;
		/* Get numeric arg (mandatory) */
		ఒకవేళ (argc - optidx < 1)
			వెళ్ళు need_అంకె_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, పునాది);
		ఒకవేళ (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_అంకె_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			తిరిగి -1;
		}
		*n_arg = ll;
		ఒకవేళ (cmdnum == I_LUMASK)
			ఆపు;
		/* Get pathname (mandatory) */
		ఒకవేళ (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			తిరిగి -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		ఆపు;
	స్థితి I_QUIT:
	స్థితి I_PWD:
	స్థితి I_LPWD:
	స్థితి I_HELP:
	స్థితి I_సంస్కరణ:
	స్థితి I_పురోగతి:
		ఒకవేళ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			తిరిగి -1;
		ఆపు;
	అప్రమేయ:
		fatal("Command not implemented");
	}

	*cpp = cp;
	తిరిగి(cmdnum);
}

స్థిర పూర్ణాంకం
parse_dispatch_command(నిర్మాణం sftp_conn *conn, స్థిరరాశి అక్షరం *cmd, అక్షరం **pwd,
    స్థిరరాశి అక్షరం *startdir, పూర్ణాంకం err_abort, పూర్ణాంకం echo_command)
{
	స్థిరరాశి అక్షరం *ocmd = cmd;
	అక్షరం *path1, *path2, *tmp;
	పూర్ణాంకం ignore_errors = 0, disable_echo = 1;
	పూర్ణాంకం aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	పూర్ణాంకం lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	పూర్ణాంకం cmdnum, i;
	గుర్తులేని దీర్ఘ n_arg = 0;
	Attrib a, aa;
	అక్షరం మార్గం_buf[PATH_MAX];
	పూర్ణాంకం err = 0;
	glob_t g;

	path1 = path2 = ఖాళీ;
	cmdnum = parse_వాదనలు(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	ఒకవేళ (ignore_errors != 0)
		err_abort = 0;

	ఒకవేళ (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, పరిమాణం(g));

	/* Perform command */
	ఎంపిక (cmdnum) {
	స్థితి 0:
		/* Blank line */
		ఆపు;
	స్థితి -1:
		/* Unrecognized command */
		err = -1;
		ఆపు;
	స్థితి I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	స్థితి I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ఆపు;
	స్థితి I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	స్థితి I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		ఆపు;
	స్థితి I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		ఆపు;
	స్థితి I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		ఆపు;
	స్థితి I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	స్థితి I_LINK:
		ఒకవేళ (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		ఆపు;
	స్థితి I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ఖాళీ, &g);
		కొరకు (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ఒకవేళ (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			ఒకవేళ (err != 0 && err_abort)
				ఆపు;
		}
		ఆపు;
	స్థితి I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		ఒకవేళ (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		లేకపోతే
			err = sftp_mkdir(conn, path1, &a, 1);
		ఆపు;
	స్థితి I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		ఆపు;
	స్థితి I_CHDIR:
		ఒకవేళ (path1 == ఖాళీ || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		ఒకవేళ ((tmp = sftp_realpath(conn, path1)) == ఖాళీ) {
			err = 1;
			ఆపు;
		}
		ఒకవేళ (sftp_stat(conn, tmp, 0, &aa) != 0) {
			విడుదల(tmp);
			err = 1;
			ఆపు;
		}
		ఒకవేళ (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			విడుదల(tmp);
			err = 1;
			ఆపు;
		}
		ఒకవేళ (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			విడుదల(tmp);
			err = 1;
			ఆపు;
		}
		విడుదల(*pwd);
		*pwd = tmp;
		ఆపు;
	స్థితి I_LS:
		ఒకవేళ (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			ఆపు;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = ఖాళీ;
		ఒకవేళ (!మార్గం_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		ఆపు;
	స్థితి I_DF:
		/* Default to current directory if no path specified */
		ఒకవేళ (path1 == ఖాళీ)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		ఆపు;
	స్థితి I_LCHDIR:
		ఒకవేళ (path1 == ఖాళీ || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		విడుదల(path1);
		path1 = tmp;
		ఒకవేళ (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ఆపు;
	స్థితి I_LMKDIR:
		ఒకవేళ (pflag) {
			ఒకవేళ (mkdir_మార్గం(path1, 0777) != 0)
				err = 1;
			ఆపు;
		}
		ఒకవేళ (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		ఆపు;
	స్థితి I_LLS:
		local_do_ls(cmd);
		ఆపు;
	స్థితి I_SHELL:
		local_do_shell(cmd);
		ఆపు;
	స్థితి I_LUMASK:
		umask(n_arg);
		రాయి("Local umask: %03lo\n", n_arg);
		ఆపు;
	స్థితి I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, ఖాళీ, &g);
		కొరకు (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ఒకవేళ (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			ఒకవేళ (err != 0 && err_abort)
				ఆపు;
		}
		ఆపు;
	స్థితి I_CHOWN:
	స్థితి I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, ఖాళీ, &g);
		కొరకు (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			ఒకవేళ ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				ఒకవేళ (err_abort) {
					err = -1;
					ఆపు;
				} లేకపోతే
					కొనసాగు;
			}
			ఒకవేళ (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				ఒకవేళ (err_abort) {
					err = -1;
					ఆపు;
				} లేకపోతే
					కొనసాగు;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			ఒకవేళ (cmdnum == I_CHOWN) {
				ఒకవేళ (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} లేకపోతే {
				ఒకవేళ (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			ఒకవేళ (err != 0 && err_abort)
				ఆపు;
		}
		ఆపు;
	స్థితి I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		ఆపు;
	స్థితి I_LPWD:
		ఒకవేళ (!getcwd(మార్గం_buf, పరిమాణం(మార్గం_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			ఆపు;
		}
		mprintf("Local working directory: %s\n", మార్గం_buf);
		ఆపు;
	స్థితి I_QUIT:
		/* Processed below */
		ఆపు;
	స్థితి I_HELP:
		help();
		ఆపు;
	స్థితి I_సంస్కరణ:
		రాయి("SFTP protocol version %u\n", sftp_proto_సంస్కరణ(conn));
		ఆపు;
	స్థితి I_పురోగతి:
		showprogress = !showprogress;
		ఒకవేళ (showprogress)
			రాయి("Progress meter enabled\n");
		లేకపోతే
			రాయి("Progress meter disabled\n");
		ఆపు;
	అప్రమేయ:
		fatal("%d is not implemented", cmdnum);
	}

	ఒకవేళ (g.gl_pathc)
		globfree(&g);
	విడుదల(path1);
	విడుదల(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	ఒకవేళ (err_abort && err != 0)
		తిరిగి (-1);
	లేకపోతే ఒకవేళ (cmdnum == I_QUIT)
		తిరిగి (1);

	తిరిగి (0);
}

#నిర్వచితమైతే USE_LIBEDIT
స్థిర అక్షరం *
prompt(Edit_పంక్తి *el)
{
	తిరిగి ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
స్థిర శూన్య
complete_display(అక్షరం **list, u_int len)
{
	u_int y, m = 0, వెడల్పు = 80, columns = 1, colspace = 0, llen;
	నిర్మాణం winsize ws;
	అక్షరం *tmp;

	/* Count entries for sort and find longest */
	కొరకు (y = 0; list[y]; y++)
		m = గరిష్ఠ(m, అక్షరశ్రేణి_పొడవు(list[y]));

	ఒకవేళ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		వెడల్పు = ws.ws_నిలువు;

	m = m > len ? m - len : 0;
	columns = వెడల్పు / (m + 2);
	columns = గరిష్ఠ(columns, 1);
	colspace = వెడల్పు / columns;
	colspace = MINIMUM(colspace, వెడల్పు);

	రాయి("\n");
	m = 1;
	కొరకు (y = 0; list[y]; y++) {
		llen = అక్షరశ్రేణి_పొడవు(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		ఒకవేళ (m >= columns) {
			రాయి("\n");
			m = 1;
		} లేకపోతే
			m++;
	}
	రాయి("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
స్థిర అక్షరం *
complete_ambiguous(స్థిరరాశి అక్షరం *మాట, అక్షరం **list, కొలత_t లెక్క)
{
	కొలత_t i, j, matchlen;
	అక్షరం *tmp;
	పూర్ణాంకం len;

	ఒకవేళ (మాట == ఖాళీ)
		తిరిగి ఖాళీ;

	ఒకవేళ (లెక్క == 0)
		తిరిగి xstrdup(మాట); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = అక్షరశ్రేణి_పొడవు(list[0]);
	కొరకు (i = 1; i < లెక్క && list[i] != ఖాళీ; i++) {
		కొరకు (j = 0; j < matchlen; j++)
			ఒకవేళ (list[0][j] != list[i][j])
				ఆపు;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(ఖాళీ, 0);
	కొరకు (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		ఒకవేళ (len <= 0 || i + (కొలత_t)len > matchlen)
			ఆపు;
		i += (కొలత_t)len;
	}
	/* If so, truncate */
	ఒకవేళ (i < matchlen)
		matchlen = i;

	ఒకవేళ (matchlen > అక్షరశ్రేణి_పొడవు(మాట)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		తిరిగి tmp;
	}

	తిరిగి xstrdup(మాట);
}

/* Autocomplete a sftp command */
స్థిర పూర్ణాంకం
complete_cmd_parse(Edit_పంక్తి *el, అక్షరం *cmd, పూర్ణాంకం lastarg, అక్షరం quote,
    పూర్ణాంకం terminated)
{
	u_int y, లెక్క = 0, cmdlen, tmplen;
	అక్షరం *tmp, **list, argterm[3];
	స్థిరరాశి పంక్తి_Info *lf;

	list = xcalloc((పరిమాణం(cmds) / పరిమాణం(*cmds)) + 1, పరిమాణం(అక్షరం *));

	/* No command specified: display all available commands */
	ఒకవేళ (cmd == ఖాళీ) {
		కొరకు (y = 0; cmds[y].c; y++)
			list[లెక్క++] = xstrdup(cmds[y].c);

		list[లెక్క] = ఖాళీ;
		complete_display(list, 0);

		కొరకు (y = 0; list[y] != ఖాళీ; y++)
			విడుదల(list[y]);
		విడుదల(list);
		తిరిగి లెక్క;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = అక్షరశ్రేణి_పొడవు(cmd);
	కొరకు (y = 0; cmds[y].c; y++)  {
		ఒకవేళ (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[లెక్క++] = xstrdup(cmds[y].c);
	}
	list[లెక్క] = ఖాళీ;

	ఒకవేళ (లెక్క == 0) {
		విడుదల(list);
		తిరిగి 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, లెక్క);
	ఒకవేళ (లెక్క > 1)
		complete_display(list, 0);

	కొరకు (y = 0; list[y]; y++)
		విడుదల(list[y]);
	విడుదల(list);

	ఒకవేళ (tmp != ఖాళీ) {
		tmplen = అక్షరశ్రేణి_పొడవు(tmp);
		cmdlen = అక్షరశ్రేణి_పొడవు(cmd);
		/* If cmd may be extended then do so */
		ఒకవేళ (tmplen > cmdlen)
			ఒకవేళ (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_పంక్తి(el);
		/* Terminate argument cleanly */
		ఒకవేళ (లెక్క == 1) {
			y = 0;
			ఒకవేళ (!terminated)
				argterm[y++] = quote;
			ఒకవేళ (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			ఒకవేళ (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		విడుదల(tmp);
	}

	తిరిగి లెక్క;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
స్థిర పూర్ణాంకం
complete_is_remote(అక్షరం *cmd, పూర్ణాంకం cmdarg) {
	పూర్ణాంకం i;

	ఒకవేళ (cmd == ఖాళీ)
		తిరిగి -1;

	కొరకు (i = 0; cmds[i].c; i++) {
		ఒకవేళ (!strncasecmp(cmd, cmds[i].c, అక్షరశ్రేణి_పొడవు(cmds[i].c))) {
			ఒకవేళ (cmdarg == 1)
				తిరిగి cmds[i].t;
			లేకపోతే ఒకవేళ (cmdarg == 2)
				తిరిగి cmds[i].t2;
			ఆపు;
		}
	}

	తిరిగి -1;
}

/* Autocomplete a filename "file" */
స్థిర పూర్ణాంకం
complete_సరిపోలిక(Edit_పంక్తి *el, నిర్మాణం sftp_conn *conn, అక్షరం *remote_మార్గం,
    అక్షరం *file, పూర్ణాంకం remote, పూర్ణాంకం lastarg, అక్షరం quote, పూర్ణాంకం terminated)
{
	glob_t g;
	అక్షరం *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	పూర్ణాంకం clen;
	స్థిరరాశి పంక్తి_Info *lf;

	/* Glob from "file" location */
	ఒకవేళ (file == ఖాళీ)
		tmp = xstrdup("*");
	లేకపోతే
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = మార్గం_absolute(tmp);

	memset(&g, 0, పరిమాణం(g));
	ఒకవేళ (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_మార్గం);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, ఖాళీ, &g);
	} లేకపోతే
		(శూన్య)glob(tmp, GLOB_DOOFFS|GLOB_MARK, ఖాళీ, &g);

	/* Determine length of pwd so we can trim completion display */
	కొరకు (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		ఒకవేళ (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			ఒకవేళ (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			ఆపు;
		}
		ఒకవేళ (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		ఒకవేళ (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	విడుదల(tmp);
	tmp = ఖాళీ;

	ఒకవేళ (g.gl_matchc == 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	ఒకవేళ (file == ఖాళీ || hadglob)
		వెళ్ళు బహిర్గతం;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = మార్గం_strip(tmp2, isabs ? ఖాళీ : remote_మార్గం);
	విడుదల(tmp2);

	ఒకవేళ (tmp == ఖాళీ)
		వెళ్ళు బహిర్గతం;

	tmplen = అక్షరశ్రేణి_పొడవు(tmp);
	filelen = అక్షరశ్రేణి_పొడవు(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	కొరకు (i = 0; i < filelen; i++) {
		ఒకవేళ (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} లేకపోతే
			isesc = 0;
	}

	ఒకవేళ (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = అక్షరశ్రేణి_పొడవు(tmp2);
		/* quote argument on way out */
		mblen(ఖాళీ, 0);
		కొరకు (i = 0; i < len; i += clen) {
			ఒకవేళ ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (కొలత_t)clen > పరిమాణం(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			జ్ఞాపకం_నకలు(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			ఎంపిక (tmp2[i]) {
			స్థితి '\'':
			స్థితి '"':
			స్థితి '\\':
			స్థితి '\t':
			స్థితి '[':
			స్థితి ' ':
			స్థితి '#':
			స్థితి '*':
				ఒకవేళ (quote == '\0' || tmp2[i] == quote) {
					ఒకవేళ (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					ఆపు;
				}
				/* FALLTHROUGH */
			అప్రమేయ:
				ఒకవేళ (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				ఆపు;
			}
		}
	}

	lf = el_పంక్తి(el);
	ఒకవేళ (g.gl_matchc == 1) {
		i = 0;
		ఒకవేళ (!terminated && quote != '\0')
			ins[i++] = quote;
		ఒకవేళ (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		ఒకవేళ (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	విడుదల(tmp);

 బహిర్గతం:
	globfree(&g);
	తిరిగి g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
స్థిర గుర్తులేని అక్షరం
complete(Edit_పంక్తి *el, పూర్ణాంకం ch)
{
	అక్షరం **argv, *పంక్తి, quote;
	పూర్ణాంకం argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	స్థిరరాశి పంక్తి_Info *lf;
	నిర్మాణం complete_ctx *complete_ctx;

	lf = el_పంక్తి(el);
	ఒకవేళ (el_get(el, EL_CLIENTDATA, (శూన్య**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->బఫరు;
	పంక్తి = xmalloc(cursor + 1);
	జ్ఞాపకం_నకలు(పంక్తి, lf->బఫరు, cursor);
	పంక్తి[cursor] = '\0';
	argv = makeargv(పంక్తి, &carg, 1, &quote, &terminated);
	విడుదల(పంక్తి);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->బఫరు;
	పంక్తి = xmalloc(len + 1);
	జ్ఞాపకం_నకలు(పంక్తి, lf->బఫరు, len);
	పంక్తి[len] = '\0';
	argv = makeargv(పంక్తి, &argc, 1, ఖాళీ, ఖాళీ);

	/* Ensure cursor is at EOL or a argument boundary */
	ఒకవేళ (పంక్తి[cursor] != ' ' && పంక్తి[cursor] != '\0' &&
	    పంక్తి[cursor] != '\n') {
		విడుదల(పంక్తి);
		తిరిగి ret;
	}

	ఒకవేళ (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, ఖాళీ, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} లేకపోతే ఒకవేళ (carg == 1 && cursor > 0 && పంక్తి[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		ఒకవేళ (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} లేకపోతే ఒకవేళ (carg >= 1) {
		/* Handle file parsing */
		పూర్ణాంకం remote = 0;
		పూర్ణాంకం i = 0, cmdarg = 0;
		అక్షరం *filematch = ఖాళీ;

		ఒకవేళ (carg > 1 && పంక్తి[cursor-1] != ' ')
			filematch = argv[carg - 1];

		కొరకు (i = 1; i < carg; i++) {
			/* Skip flags */
			ఒకవేళ (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		ఒకవేళ (పంక్తి[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		ఒకవేళ ((remote == REMOTE || remote == LOCAL) &&
		    complete_సరిపోలిక(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	విడుదల(పంక్తి);
	తిరిగి ret;
}
#అయితే_ముగింపు /* USE_LIBEDIT */

స్థిర పూర్ణాంకం
interactive_loop(నిర్మాణం sftp_conn *conn, అక్షరం *file1, అక్షరం *file2)
{
	అక్షరం *remote_మార్గం;
	అక్షరం *dir = ఖాళీ, *startdir = ఖాళీ;
	అక్షరం cmd[2048];
	పూర్ణాంకం err, interactive;
	Edit_పంక్తి *el = ఖాళీ;
#నిర్వచితమైతే USE_LIBEDIT
	స్థిరరాశి అక్షరం *editor;
	History *hl = ఖాళీ;
	HistEvent hev;
	బాహ్య అక్షరం *__progname;
	నిర్మాణం complete_ctx complete_ctx;

	ఒకవేళ (!batchmode && isatty(STDIN_FILENO)) {
		ఒకవేళ ((el = el_init(__progname, stdin, stdout, stderr)) == ఖాళీ)
			fatal("Couldn't initialise editline");
		ఒకవేళ ((hl = history_init()) == ఖాళీ)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_సమితి(el, EL_HIST, history, hl);

		el_సమితి(el, EL_PROMPT, prompt);
		el_సమితి(el, EL_EDITOR, "emacs");
		el_సమితి(el, EL_TERMINAL, ఖాళీ);
		el_సమితి(el, EL_SIGNAL, 1);
		el_ఆధారం(el, ఖాళీ);

		/* Tab Completion */
		el_సమితి(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_మార్గం;
		el_సమితి(el, EL_CLIENTDATA, (శూన్య*)&complete_ctx);
		el_సమితి(el, EL_BIND, "^I", "ftp-complete", ఖాళీ);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_సమితి(el, EL_BIND, "\\e[1;5C", "em-next-word", ఖాళీ);
		el_సమితి(el, EL_BIND, "\\e\\e[C", "em-next-word", ఖాళీ);
		el_సమితి(el, EL_BIND, "\\e[1;5D", "ed-prev-word", ఖాళీ);
		el_సమితి(el, EL_BIND, "\\e\\e[D", "ed-prev-word", ఖాళీ);
		/* make ^w match ksh behaviour */
		el_సమితి(el, EL_BIND, "^w", "ed-delete-prev-word", ఖాళీ);

		/* el_source() may have changed EL_EDITOR to vi */
		ఒకవేళ (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_సమితి(el, EL_BIND, "^[", "vi-command-mode", ఖాళీ);
	}
#అయితే_ముగింపు /* USE_LIBEDIT */

	ఒకవేళ ((remote_మార్గం = sftp_realpath(conn, ".")) == ఖాళీ)
		fatal("Need cwd");
	startdir = xstrdup(remote_మార్గం);

	ఒకవేళ (file1 != ఖాళీ) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_మార్గం);

		ఒకవేళ (sftp_remote_is_dir(conn, dir) && file2 == ఖాళీ) {
			ఒకవేళ (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, పరిమాణం cmd, "cd \"%s\"", dir);
			ఒకవేళ (parse_dispatch_command(conn, cmd,
			    &remote_మార్గం, startdir, 1, 0) != 0) {
				విడుదల(dir);
				విడుదల(startdir);
				విడుదల(remote_మార్గం);
				విడుదల(conn);
				తిరిగి (-1);
			}
		} లేకపోతే {
			err = process_get(conn, dir, file2, remote_మార్గం, 0, 0,
			    global_aflag, 0);
			విడుదల(dir);
			విడుదల(startdir);
			విడుదల(remote_మార్గం);
			విడుదల(conn);
			తిరిగి (err);
		}
		విడుదల(dir);
	}

	setvbuf(stdout, ఖాళీ, _IOLBF, 0);
	setvbuf(infile, ఖాళీ, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	కొరకు (;;) {
		నిర్మాణం sigaction sa;

		interrupted = 0;
		memset(&sa, 0, పరిమాణం(sa));
		sa.sa_handler = interactive ? read_అంతరాయం : killchild;
		ఒకవేళ (sigaction(SIGINT, &sa, ఖాళీ) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			ఆపు;
		}
		ఒకవేళ (el == ఖాళీ) {
			ఒకవేళ (interactive) {
				రాయి("sftp> ");
				fflush(stdout);
			}
			ఒకవేళ (fgets(cmd, పరిమాణం(cmd), infile) == ఖాళీ) {
				ఒకవేళ (interactive)
					రాయి("\n");
				ఒకవేళ (interrupted)
					కొనసాగు;
				ఆపు;
			}
		} లేకపోతే {
#నిర్వచితమైతే USE_LIBEDIT
			స్థిరరాశి అక్షరం *పంక్తి;
			పూర్ణాంకం లెక్క = 0;

			ఒకవేళ ((పంక్తి = el_gets(el, &లెక్క)) == ఖాళీ ||
			    లెక్క <= 0) {
				రాయి("\n");
				ఒకవేళ (interrupted)
					కొనసాగు;
				ఆపు;
			}
			history(hl, &hev, H_ENTER, పంక్తి);
			ఒకవేళ (strlcpy(cmd, పంక్తి, పరిమాణం(cmd)) >= పరిమాణం(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				కొనసాగు;
			}
#అయితే_ముగింపు /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_అంతరాయం);

		err = parse_dispatch_command(conn, cmd, &remote_మార్గం,
		    startdir, batchmode, !interactive && el == ఖాళీ);
		ఒకవేళ (err != 0)
			ఆపు;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	విడుదల(remote_మార్గం);
	విడుదల(startdir);
	విడుదల(conn);

#నిర్వచితమైతే USE_LIBEDIT
	ఒకవేళ (hl != ఖాళీ)
		history_చివర(hl);
	ఒకవేళ (el != ఖాళీ)
		el_చివర(el);
#అయితే_ముగింపు /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	తిరిగి (err >= 0 ? 0 : -1);
}

స్థిర శూన్య
connect_గమ్యం_server(అక్షరం *మార్గం, అక్షరం **వాదనలు, పూర్ణాంకం *లోపల, పూర్ణాంకం *బహిర్గతం)
{
	పూర్ణాంకం c_లోపల, c_బహిర్గతం;
#నిర్వచితమైతే USE_PIPES
	పూర్ణాంకం pin[2], pout[2];

	ఒకవేళ ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*లోపల = pin[0];
	*బహిర్గతం = pout[1];
	c_లోపల = pout[0];
	c_బహిర్గతం = pin[1];
#లేకపోతే /* USE_PIPES */
	పూర్ణాంకం inout[2];

	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*లోపల = *బహిర్గతం = inout[0];
	c_లోపల = c_బహిర్గతం = inout[1];
#అయితే_ముగింపు /* USE_PIPES */
	FD_CLOSEONEXEC(*లోపల);
	FD_CLOSEONEXEC(*బహిర్గతం);

	ఒకవేళ ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	లేకపోతే ఒకవేళ (sshpid == 0) {
		ఒకవేళ ((dup2(c_లోపల, STDIN_FILENO) == -1) ||
		    (dup2(c_బహిర్గతం, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*లోపల);
		close(*బహిర్గతం);
		close(c_లోపల);
		close(c_బహిర్గతం);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(మార్గం, వాదనలు);
		fprintf(stderr, "exec: %s: %s\n", మార్గం, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_లోపల);
	close(c_బహిర్గతం);
}

స్థిర శూన్య
usage(శూన్య)
{
	బాహ్య అక్షరం *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	నిష్క్రమించు(1);
}

పూర్ణాంకం
ప్రధాన(పూర్ణాంకం argc, అక్షరం **argv)
{
	పూర్ణాంకం r, లోపల, బహిర్గతం, ch, err, tmp, పోర్టు = -1, noisy = 0;
	అక్షరం *host = ఖాళీ, *user, *cp, **cpp, *file2 = ఖాళీ;
	పూర్ణాంకం debug_level = 0;
	అక్షరం *file1 = ఖాళీ, *sftp_server = ఖాళీ;
	అక్షరం *ssh_కార్యక్రమం = మార్గం_SSH_కార్యక్రమం, *sftp_ప్రత్యక్ష = ఖాళీ;
	స్థిరరాశి అక్షరం *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist వాదనలు;
	బాహ్య పూర్ణాంకం optind;
	బాహ్య అక్షరం *optarg;
	నిర్మాణం sftp_conn *conn;
	కొలత_t copy_బఫరు_len = 0;
	కొలత_t అంకె_అభ్యర్థనలు = 0;
	దీర్ఘ దీర్ఘ llv, హద్దు_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&వాదనలు, '\0', పరిమాణం(వాదనలు));
	వాదనలు.list = ఖాళీ;
	addargs(&వాదనలు, "%s", ssh_కార్యక్రమం);
	addargs(&వాదనలు, "-oForwardX11 no");
	addargs(&వాదనలు, "-oPermitLocalCommand no");
	addargs(&వాదనలు, "-oClearAllForwardings yes");
	addargs(&వాదనలు, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	అయితే ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		ఎంపిక (ch) {
		/* Passed through to ssh(1) */
		స్థితి 'A':
		స్థితి '4':
		స్థితి '6':
		స్థితి 'C':
			addargs(&వాదనలు, "-%c", ch);
			ఆపు;
		/* Passed through to ssh(1) with argument */
		స్థితి 'F':
		స్థితి 'J':
		స్థితి 'c':
		స్థితి 'i':
		స్థితి 'o':
			addargs(&వాదనలు, "-%c", ch);
			addargs(&వాదనలు, "%s", optarg);
			ఆపు;
		స్థితి 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&వాదనలు, "-%c", ch);
			ఆపు;
		స్థితి 'P':
			పోర్టు = a2port(optarg);
			ఒకవేళ (పోర్టు <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			ఆపు;
		స్థితి 'v':
			ఒకవేళ (debug_level < 3) {
				addargs(&వాదనలు, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			ఆపు;
		స్థితి '1':
			fatal("SSH protocol v.1 is no longer supported");
			ఆపు;
		స్థితి '2':
			/* accept silently */
			ఆపు;
		స్థితి 'a':
			global_aflag = 1;
			ఆపు;
		స్థితి 'B':
			copy_బఫరు_len = strtol(optarg, &cp, 10);
			ఒకవేళ (copy_బఫరు_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			ఆపు;
		స్థితి 'b':
			ఒకవేళ (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			ఒకవేళ (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == ఖాళీ)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&వాదనలు, "-obatchmode yes");
			ఆపు;
		స్థితి 'f':
			global_fflag = 1;
			ఆపు;
		స్థితి 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			ఆపు;
		స్థితి 'p':
			global_pflag = 1;
			ఆపు;
		స్థితి 'D':
			sftp_ప్రత్యక్ష = optarg;
			ఆపు;
		స్థితి 'l':
			హద్దు_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			ఒకవేళ (errstr != ఖాళీ)
				usage();
			హద్దు_kbps *= 1024; /* kbps */
			ఆపు;
		స్థితి 'r':
			global_rflag = 1;
			ఆపు;
		స్థితి 'R':
			అంకె_అభ్యర్థనలు = strtol(optarg, &cp, 10);
			ఒకవేళ (అంకె_అభ్యర్థనలు == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			ఆపు;
		స్థితి 's':
			sftp_server = optarg;
			ఆపు;
		స్థితి 'S':
			ssh_కార్యక్రమం = optarg;
			replacearg(&వాదనలు, 0, "%s", ssh_కార్యక్రమం);
			ఆపు;
		స్థితి 'X':
			/* Please keep in sync with ssh.c -X */
			ఒకవేళ (అక్షరశ్రేణి_పోలిక(optarg, "buffer=", 7) == 0) {
				r = పరిశీలన_scaled(optarg + 7, &llv);
				ఒకవేళ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				ఒకవేళ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_బఫరు_len = (కొలత_t)llv;
			} లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				ఒకవేళ (errstr != ఖాళీ) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				అంకె_అభ్యర్థనలు = (కొలత_t)llv;
			} లేకపోతే {
				fatal("Invalid -X option");
			}
			ఆపు;
		స్థితి 'h':
		అప్రమేయ:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&వాదనలు, "-oForwardAgent no");

	ఒకవేళ (!isatty(STDERR_FILENO))
		showprogress = 0;

	ఒకవేళ (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	ఒకవేళ (sftp_ప్రత్యక్ష == ఖాళీ) {
		ఒకవేళ (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		ఎంపిక (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		స్థితి -1:
			usage();
			ఆపు;
		స్థితి 0:
			ఒకవేళ (tmp != -1)
				పోర్టు = tmp;
			ఆపు;
		అప్రమేయ:
			/* Try with user, host and path. */
			ఒకవేళ (parse_user_host_మార్గం(*argv, &user, &host,
			    &file1) == 0)
				ఆపు;
			/* Try with user and host. */
			ఒకవేళ (parse_user_host_పోర్టు(*argv, &user, &host, ఖాళీ)
			    == 0)
				ఆపు;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			ఆపు;
		}
		file2 = *(argv + 1);

		ఒకవేళ (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		ఒకవేళ (పోర్టు != -1)
			addargs(&వాదనలు, "-oPort %d", పోర్టు);
		ఒకవేళ (user != ఖాళీ) {
			addargs(&వాదనలు, "-l");
			addargs(&వాదనలు, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		ఒకవేళ (sftp_server == ఖాళీ || strchr(sftp_server, '/') == ఖాళీ)
			addargs(&వాదనలు, "-s");

		addargs(&వాదనలు, "--");
		addargs(&వాదనలు, "%s", host);
		addargs(&వాదనలు, "%s", (sftp_server != ఖాళీ ?
		    sftp_server : "sftp"));

		connect_గమ్యం_server(ssh_కార్యక్రమం, వాదనలు.list, &లోపల, &బహిర్గతం);
	} లేకపోతే {
		ఒకవేళ ((r = argv_విభజించు(sftp_ప్రత్యక్ష, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		ఒకవేళ (cpp[0] == ఖాళీ)
			fatal("No sftp server specified via -D");
		connect_గమ్యం_server(cpp[0], cpp, &లోపల, &బహిర్గతం);
		argv_free(cpp, tmp);
	}
	freeargs(&వాదనలు);

	conn = sftp_init(లోపల, బహిర్గతం, copy_బఫరు_len, అంకె_అభ్యర్థనలు, హద్దు_kbps);
	ఒకవేళ (conn == ఖాళీ)
		fatal("Couldn't initialise connection to server");

	ఒకవేళ (!quiet) {
		ఒకవేళ (sftp_ప్రత్యక్ష == ఖాళీ)
			fprintf(stderr, "Connected to %s.\n", host);
		లేకపోతే
			fprintf(stderr, "Attached to %s.\n", sftp_ప్రత్యక్ష);
	}

	err = interactive_loop(conn, file1, file2);

#ఒకవేళ !defined(USE_PIPES)
	shutdown(లోపల, SHUT_RDWR);
	shutdown(బహిర్గతం, SHUT_RDWR);
#అయితే_ముగింపు

	close(లోపల);
	close(బహిర్గతం);
	ఒకవేళ (batchmode)
		fclose(infile);

	అయితే (waitpid(sshpid, ఖాళీ, 0) == -1 && sshpid > 1)
		ఒకవేళ (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	నిష్క్రమించు(err == 0 ? 0 : 1);
}
