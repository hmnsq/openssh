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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/ioctl.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/statvfs.h>
#अन्तर्भाव <sys/wait.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <libgen.h>
#यदि_परिभाषितम् HAVE_LOCALE_H
# include <locale.h>
#यदि_अन्तः
#यदि_परिभाषितम् USE_LIBEDIT
#अन्तर्भाव <histedit.h>
#अन्यथा
प्रकारनिर्देश शून्य Edit_पङ्क्तिः;
#यदि_अन्तः
#अन्तर्भाव <limits.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "utf8.h"

#अन्तर्भाव "sftp.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sftp-common.h"
#अन्तर्भाव "sftp-client.h"
#अन्तर्भाव "sftp-usergroup.h"

/* File to read commands from */
FILE* infile;

/* Are we in batchfile mode? */
पूर्णाङ्क batchmode = 0;

/* PID of ssh transport process */
स्थिर चञ्चल pid_t sshpid = -1;

/* Suppress diagnostic messages */
पूर्णाङ्क quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
पूर्णाङ्क showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
पूर्णाङ्क global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
पूर्णाङ्क global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
पूर्णाङ्क global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
पूर्णाङ्क global_fflag = 0;

/* SIGINT received during command processing */
चञ्चल sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
पूर्णाङ्क क्रमय_flag;
glob_t *क्रमय_glob;

/* Context used for commandline completion */
संरचना complete_ctx {
	संरचना sftp_conn *conn;
	वर्ण **remote_pathp;
};

पूर्णाङ्क sftp_glob(संरचना sftp_conn *, ध्रुव वर्ण *, पूर्णाङ्क,
    पूर्णाङ्क (*)(ध्रुव वर्ण *, पूर्णाङ्क), glob_t *); /* proto for sftp-glob.c */

बाह्य वर्ण *__progname;

/* Separators for interactive commands */
#परिभाषय WHITESPACE " \t\r\n"

/* ls flags */
#परिभाषय LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#परिभाषय LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#परिभाषय LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#परिभाषय LS_NAME_क्रमय	0x0008	/* Sort by name (default) */
#परिभाषय LS_TIME_क्रमय	0x0010	/* Sort by mtime */
#परिभाषय LS_आकार_क्रमय	0x0020	/* Sort by file size */
#परिभाषय LS_REVERSE_क्रमय	0x0040	/* Reverse sort order */
#परिभाषय LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#परिभाषय LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#परिभाषय VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#परिभाषय क्रमय_FLAGS	(LS_NAME_क्रमय|LS_TIME_क्रमय|LS_आकार_क्रमय)

/* Commands for interactive mode */
गणना sftp_command {
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
	I_संस्करणम्,
	I_प्रगतिः,
};

संरचना CMD {
	ध्रुव वर्ण *c;
	ध्रुव पूर्णाङ्क n;
	ध्रुव पूर्णाङ्क t;	/* Completion type for the first argument */
	ध्रुव पूर्णाङ्क t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#परिभाषय NOARGS	0
#परिभाषय REMOTE	1
#परिभाषय LOCAL	2

स्थिर ध्रुव संरचना CMD cmds[] = {
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
	{ "progress",	I_प्रगतिः,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_संस्करणम्,	NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ रिक्त,		-1,		-1,		-1	}
};

स्थिर शून्य
killchild(पूर्णाङ्क signo)
{
	pid_t pid;

	pid = sshpid;
	यदि (pid > 1) {
		kill(pid, SIGTERM);
		(शून्य)waitpid(pid, रिक्त, 0);
	}

	_exit(1);
}

स्थिर शून्य
suspchild(पूर्णाङ्क signo)
{
	पूर्णाङ्क save_errno = errno;
	यदि (sshpid > 1) {
		kill(sshpid, signo);
		यावत् (waitpid(sshpid, रिक्त, WUNTRACED) == -1 && errno == EINTR)
			अनुवर्त;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

स्थिर शून्य
cmd_व्यवधानम्(पूर्णाङ्क signo)
{
	ध्रुव वर्ण सन्देशः[] = "\rInterrupt  \n";
	पूर्णाङ्क olderrno = errno;

	(शून्य)लिख(STDERR_FILENO, सन्देशः, परिमाण(सन्देशः) - 1);
	interrupted = 1;
	errno = olderrno;
}

स्थिर शून्य
read_व्यवधानम्(पूर्णाङ्क signo)
{
	interrupted = 1;
}

स्थिर शून्य
sigchld_handler(पूर्णाङ्क sig)
{
	पूर्णाङ्क save_errno = errno;
	pid_t pid;
	ध्रुव वर्ण सन्देशः[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	यावत् ((pid = waitpid(sshpid, रिक्त, WNOHANG)) == -1 && errno == EINTR)
		अनुवर्त;
	यदि (pid == sshpid) {
		यदि (!quiet)
		    (शून्य)लिख(STDERR_FILENO, सन्देशः, परिमाण(सन्देशः) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

स्थिर शून्य
help(शून्य)
{
	प्रारूप_लिख("Available commands:\n"
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

स्थिर शून्य
local_do_shell(ध्रुव वर्ण *तर्काः)
{
	पूर्णाङ्क स्थितिः;
	वर्ण *shell;
	pid_t pid;

	यदि (!*तर्काः)
		तर्काः = रिक्त;

	यदि ((shell = getenv("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	यदि ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	यदि (pid == 0) {
		यदि (तर्काः) {
			debug3("Executing %s -c \"%s\"", shell, तर्काः);
			execl(shell, shell, "-c", तर्काः, (वर्ण *)रिक्त);
		} अन्यथा {
			debug3("Executing %s", shell);
			execl(shell, shell, (वर्ण *)रिक्त);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	यावत् (waitpid(pid, &स्थितिः, 0) == -1)
		यदि (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	यदि (!WIFEXITED(स्थितिः))
		error("Shell exited abnormally");
	अन्यथा यदि (WEXITSTATUS(स्थितिः))
		error("Shell exited with status %d", WEXITSTATUS(स्थितिः));
}

स्थिर शून्य
local_do_ls(ध्रुव वर्ण *तर्काः)
{
	यदि (!तर्काः || !*तर्काः)
		local_do_shell(मार्गः_LS);
	अन्यथा {
		पूर्णाङ्क len = वाक्यदैर्घ्यम्(मार्गः_LS " ") + वाक्यदैर्घ्यम्(तर्काः) + 1;
		वर्ण *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, मार्गः_LS " %s", तर्काः);
		local_do_shell(buf);
		मुक्त(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
स्थिर वर्ण *
मार्गः_strip(ध्रुव वर्ण *मार्गः, ध्रुव वर्ण *strip)
{
	आकार_t len;

	यदि (strip == रिक्त || (len = वाक्यदैर्घ्यम्(strip)) == 0)
		प्रत्यागम (xstrdup(मार्गः));

	यदि (वाक्ये_तुलय(मार्गः, strip, len) == 0) {
		यदि (strip[len - 1] != '/' && मार्गः[len] == '/')
			len++;
		प्रत्यागम (xstrdup(मार्गः + len));
	}

	प्रत्यागम (xstrdup(मार्गः));
}

स्थिर पूर्णाङ्क
parse_getput_flags(ध्रुव वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc,
    पूर्णाङ्क *aflag, पूर्णाङ्क *fflag, पूर्णाङ्क *pflag, पूर्णाङ्क *rflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	यावत् ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		विकल्प (ch) {
		पक्ष 'a':
			*aflag = 1;
			भङ्ग;
		पक्ष 'f':
			*fflag = 1;
			भङ्ग;
		पक्ष 'p':
		पक्ष 'P':
			*pflag = 1;
			भङ्ग;
		पक्ष 'r':
		पक्ष 'R':
			*rflag = 1;
			भङ्ग;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर पूर्णाङ्क
parse_mkdir_flags(ध्रुव वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *pflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	यावत् ((ch = getopt(argc, argv, "p")) != -1) {
		विकल्प (ch) {
		पक्ष 'p':
			*pflag = 1;
			भङ्ग;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर पूर्णाङ्क
parse_link_flags(ध्रुव वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *sflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	यावत् ((ch = getopt(argc, argv, "s")) != -1) {
		विकल्प (ch) {
		पक्ष 's':
			*sflag = 1;
			भङ्ग;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर पूर्णाङ्क
parse_rename_flags(ध्रुव वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *lflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	यावत् ((ch = getopt(argc, argv, "l")) != -1) {
		विकल्प (ch) {
		पक्ष 'l':
			*lflag = 1;
			भङ्ग;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर पूर्णाङ्क
parse_ls_flags(वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *lflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_क्रमय;
	यावत् ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		विकल्प (ch) {
		पक्ष '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			भङ्ग;
		पक्ष 'S':
			*lflag &= ~क्रमय_FLAGS;
			*lflag |= LS_आकार_क्रमय;
			भङ्ग;
		पक्ष 'a':
			*lflag |= LS_SHOW_ALL;
			भङ्ग;
		पक्ष 'f':
			*lflag &= ~क्रमय_FLAGS;
			भङ्ग;
		पक्ष 'h':
			*lflag |= LS_SI_UNITS;
			भङ्ग;
		पक्ष 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			भङ्ग;
		पक्ष 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			भङ्ग;
		पक्ष 'r':
			*lflag |= LS_REVERSE_क्रमय;
			भङ्ग;
		पक्ष 't':
			*lflag &= ~क्रमय_FLAGS;
			*lflag |= LS_TIME_क्रमय;
			भङ्ग;
		स्वभाव:
			error("ls: Invalid flag -%c", optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर पूर्णाङ्क
parse_df_flags(ध्रुव वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *hflag, पूर्णाङ्क *iflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	यावत् ((ch = getopt(argc, argv, "hi")) != -1) {
		विकल्प (ch) {
		पक्ष 'h':
			*hflag = 1;
			भङ्ग;
		पक्ष 'i':
			*iflag = 1;
			भङ्ग;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर पूर्णाङ्क
parse_ch_flags(ध्रुव वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *hflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	यावत् ((ch = getopt(argc, argv, "h")) != -1) {
		विकल्प (ch) {
		पक्ष 'h':
			*hflag = 1;
			भङ्ग;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर पूर्णाङ्क
parse_no_flags(ध्रुव वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	यावत् ((ch = getopt(argc, argv, "")) != -1) {
		विकल्प (ch) {
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			प्रत्यागम -1;
		}
	}

	प्रत्यागम optind;
}

स्थिर वर्ण *
escape_glob(ध्रुव वर्ण *s)
{
	आकार_t i, o, len;
	वर्ण *ret;

	len = वाक्यदैर्घ्यम्(s);
	ret = xcalloc(2, len + 1);
	प्रति (i = o = 0; i < len; i++) {
		यदि (strchr("[]?*\\", s[i]) != रिक्त)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	प्रत्यागम ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
स्थिर वर्ण *
make_absolute_pwd_glob(वर्ण *p, ध्रुव वर्ण *pwd)
{
	वर्ण *ret, *escpwd;

	escpwd = escape_glob(pwd);
	यदि (p == रिक्त)
		प्रत्यागम escpwd;
	ret = sftp_make_absolute(p, escpwd);
	मुक्त(escpwd);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
local_is_dir(ध्रुव वर्ण *मार्गः)
{
	संरचना stat sb;

	यदि (stat(मार्गः, &sb) == -1)
		प्रत्यागम 0;
	प्रत्यागम S_ISDIR(sb.st_mode);
}

स्थिर पूर्णाङ्क
process_get(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    ध्रुव वर्ण *pwd, पूर्णाङ्क pflag, पूर्णाङ्क rflag, पूर्णाङ्क resume, पूर्णाङ्क fflag)
{
	वर्ण *filename, *abs_src = रिक्त, *abs_dst = रिक्त, *tmp = रिक्त;
	glob_t g;
	पूर्णाङ्क i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	स्मृतिं_पूरय(&g, 0, परिमाण(g));

	debug3("Looking up %s", abs_src);
	यदि ((r = sftp_glob(conn, abs_src, GLOB_MARK, रिक्त, &g)) != 0) {
		यदि (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} अन्यथा {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		गच्छ बहिर्गमनम्;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	यदि (g.gl_matchc > 1 && dst != रिक्त && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		गच्छ बहिर्गमनम्;
	}

	प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		यदि ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, strerror(errno));
			मुक्त(tmp);
			err = -1;
			गच्छ बहिर्गमनम्;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		यदि (वाक्यं_तुलय(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		यदि (g.gl_matchc == 1 && dst) {
			यदि (local_is_dir(dst)) {
				abs_dst = sftp_मार्गः_append(dst, filename);
			} अन्यथा {
				abs_dst = xstrdup(dst);
			}
		} अन्यथा यदि (dst) {
			abs_dst = sftp_मार्गः_append(dst, filename);
		} अन्यथा {
			abs_dst = xstrdup(filename);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		यदि (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अन्यथा यदि (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		यदि (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			यदि (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अन्यथा {
			यदि (sftp_download(conn, g.gl_pathv[i], abs_dst, रिक्त,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		मुक्त(abs_dst);
		abs_dst = रिक्त;
	}

बहिर्गमनम्:
	मुक्त(abs_src);
	globfree(&g);
	प्रत्यागम(err);
}

स्थिर पूर्णाङ्क
process_put(संरचना sftp_conn *conn, ध्रुव वर्ण *src, ध्रुव वर्ण *dst,
    ध्रुव वर्ण *pwd, पूर्णाङ्क pflag, पूर्णाङ्क rflag, पूर्णाङ्क resume, पूर्णाङ्क fflag)
{
	वर्ण *tmp_dst = रिक्त;
	वर्ण *abs_dst = रिक्त;
	वर्ण *tmp = रिक्त, *filename = रिक्त;
	glob_t g;
	पूर्णाङ्क err = 0;
	पूर्णाङ्क i, dst_is_dir = 1;
	संरचना stat sb;

	यदि (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	स्मृतिं_पूरय(&g, 0, परिमाण(g));
	debug3("Looking up %s", src);
	यदि (glob(src, GLOB_NOCHECK | GLOB_MARK, रिक्त, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		गच्छ बहिर्गमनम्;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	यदि (tmp_dst != रिक्त)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	यदि (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		गच्छ बहिर्गमनम्;
	}

	प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		यदि (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			अनुवर्त;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		यदि ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, strerror(errno));
			मुक्त(tmp);
			err = -1;
			गच्छ बहिर्गमनम्;
		}
		/* Special handling for source of '..' */
		यदि (वाक्यं_तुलय(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		मुक्त(abs_dst);
		abs_dst = रिक्त;
		यदि (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			यदि (dst_is_dir)
				abs_dst = sftp_मार्गः_append(tmp_dst, filename);
			अन्यथा
				abs_dst = xstrdup(tmp_dst);
		} अन्यथा यदि (tmp_dst) {
			abs_dst = sftp_मार्गः_append(tmp_dst, filename);
		} अन्यथा {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		यदि (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अन्यथा यदि (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		यदि (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			यदि (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अन्यथा {
			यदि (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

बहिर्गमनम्:
	मुक्त(abs_dst);
	मुक्त(tmp_dst);
	globfree(&g);
	प्रत्यागम(err);
}

स्थिर पूर्णाङ्क
sdirent_comp(ध्रुव शून्य *aa, ध्रुव शून्य *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	पूर्णाङ्क rmul = क्रमय_flag & LS_REVERSE_क्रमय ? -1 : 1;

#परिभाषय NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	यदि (क्रमय_flag & LS_NAME_क्रमय)
		प्रत्यागम (rmul * वाक्यं_तुलय(a->filename, b->filename));
	अन्यथा यदि (क्रमय_flag & LS_TIME_क्रमय)
		प्रत्यागम (rmul * NCMP(a->a.mtime, b->a.mtime));
	अन्यथा यदि (क्रमय_flag & LS_आकार_क्रमय)
		प्रत्यागम (rmul * NCMP(a->a.आकार, b->a.आकार));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
स्थिर पूर्णाङ्क
do_ls_dir(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः,
    ध्रुव वर्ण *strip_मार्गः, पूर्णाङ्क lflag)
{
	पूर्णाङ्क n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	यदि ((n = sftp_readdir(conn, मार्गः, &d)) != 0)
		प्रत्यागम (n);

	यदि (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, विस्तारः = 80;
		संरचना winsize ws;
		वर्ण *tmp;

		/* Count entries for sort and find longest filename */
		प्रति (n = 0; d[n] != रिक्त; n++) {
			यदि (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = अधिकतमम्(m, वाक्यदैर्घ्यम्(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = मार्गः_strip(मार्गः, strip_मार्गः);
		m += वाक्यदैर्घ्यम्(tmp);
		मुक्त(tmp);

		यदि (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			विस्तारः = ws.ws_col;

		columns = विस्तारः / (m + 2);
		columns = अधिकतमम्(columns, 1);
		colspace = विस्तारः / columns;
		colspace = MINIMUM(colspace, विस्तारः);
	}

	यदि (lflag & क्रमय_FLAGS) {
		प्रति (n = 0; d[n] != रिक्त; n++)
			;	/* count entries */
		क्रमय_flag = lflag & (क्रमय_FLAGS|LS_REVERSE_क्रमय);
		शीघ्रं_क्रमय(d, n, परिमाण(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	प्रति (n = 0; d[n] != रिक्त && !interrupted; n++) {
		वर्ण *tmp, *fname;

		यदि (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			अनुवर्त;

		tmp = sftp_मार्गः_append(मार्गः, d[n]->filename);
		fname = मार्गः_strip(tmp, strip_मार्गः);
		मुक्त(tmp);

		यदि (lflag & LS_LONG_VIEW) {
			यदि ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				वर्ण *lname;
				संरचना stat sb;
				ध्रुव वर्ण *user = रिक्त, *गणः = रिक्त;

				स्मृतिं_पूरय(&sb, 0, परिमाण(sb));
				attrib_गन्तव्यम्_stat(&d[n]->a, &sb);
				यदि ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					गणः = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, गणः);
				mprintf("%s\n", lname);
				मुक्त(lname);
			} अन्यथा
				mprintf("%s\n", d[n]->longname);
		} अन्यथा {
			mprintf("%-*s", colspace, fname);
			यदि (c >= columns) {
				प्रारूप_लिख("\n");
				c = 1;
			} अन्यथा
				c++;
		}

		मुक्त(fname);
	}

	यदि (!(lflag & LS_LONG_VIEW) && (c != 1))
		प्रारूप_लिख("\n");

	sftp_free_dirents(d);
	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
sglob_comp(ध्रुव शून्य *aa, ध्रुव शून्य *bb)
{
	u_int a = *(ध्रुव u_int *)aa;
	u_int b = *(ध्रुव u_int *)bb;
	ध्रुव वर्ण *ap = क्रमय_glob->gl_pathv[a];
	ध्रुव वर्ण *bp = क्रमय_glob->gl_pathv[b];
	ध्रुव संरचना stat *as = क्रमय_glob->gl_statv[a];
	ध्रुव संरचना stat *bs = क्रमय_glob->gl_statv[b];
	पूर्णाङ्क rmul = क्रमय_flag & LS_REVERSE_क्रमय ? -1 : 1;

#परिभाषय NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	यदि (as == रिक्त || bs == रिक्त)
		प्रत्यागम (as == bs) ? 0 : (as == रिक्त ? rmul : -rmul);
	यदि (क्रमय_flag & LS_NAME_क्रमय)
		प्रत्यागम (rmul * वाक्यं_तुलय(ap, bp));
	अन्यथा यदि (क्रमय_flag & LS_TIME_क्रमय) {
#यदि defined(HAVE_STRUCT_STAT_ST_MTIM)
		यदि (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			प्रत्यागम 0;
		प्रत्यागम timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#नोचेद्यदि defined(HAVE_STRUCT_STAT_ST_MTIME)
		प्रत्यागम (rmul * NCMP(as->st_mtime, bs->st_mtime));
#अन्यथा
	प्रत्यागम rmul * 1;
#यदि_अन्तः
	} अन्यथा यदि (क्रमय_flag & LS_आकार_क्रमय)
		प्रत्यागम (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
स्थिर पूर्णाङ्क
do_globbed_ls(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः,
    ध्रुव वर्ण *strip_मार्गः, पूर्णाङ्क lflag)
{
	वर्ण *fname, *lname;
	glob_t g;
	पूर्णाङ्क err, r;
	संरचना winsize ws;
	u_int i, j, nentries, *indices = रिक्त, c = 1;
	u_int colspace = 0, columns = 1, m = 0, विस्तारः = 80;

	स्मृतिं_पूरय(&g, 0, परिमाण(g));

	यदि ((r = sftp_glob(conn, मार्गः,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    रिक्त, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		यदि (g.gl_pathc)
			globfree(&g);
		यदि (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", मार्गः);
		} अन्यथा {
			error("Can't ls: \"%s\" not found", मार्गः);
		}
		प्रत्यागम -1;
	}

	यदि (interrupted)
		गच्छ बहिर्गमनम्;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	यदि (g.gl_matchc == 1 && g.gl_statv[0] != रिक्त &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_मार्गः, lflag);
		globfree(&g);
		प्रत्यागम err;
	}

	यदि (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		विस्तारः = ws.ws_col;

	यदि (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		प्रति (i = 0; g.gl_pathv[i]; i++)
			m = अधिकतमम्(m, वाक्यदैर्घ्यम्(g.gl_pathv[i]));

		columns = विस्तारः / (m + 2);
		columns = अधिकतमम्(columns, 1);
		colspace = विस्तारः / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	प्रति (nentries = 0; g.gl_pathv[nentries] != रिक्त; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, परिमाण(*indices));
	प्रति (i = 0; i < nentries; i++)
		indices[i] = i;

	यदि (lflag & क्रमय_FLAGS) {
		क्रमय_glob = &g;
		क्रमय_flag = lflag & (क्रमय_FLAGS|LS_REVERSE_क्रमय);
		शीघ्रं_क्रमय(indices, nentries, परिमाण(*indices), sglob_comp);
		क्रमय_glob = रिक्त;
	}

	get_remote_user_groups_from_glob(conn, &g);
	प्रति (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = मार्गः_strip(g.gl_pathv[i], strip_मार्गः);
		यदि (lflag & LS_LONG_VIEW) {
			ध्रुव वर्ण *user = रिक्त, *गणः = रिक्त;

			यदि (g.gl_statv[i] == रिक्त) {
				error("no stat information for %s", fname);
				मुक्त(fname);
				अनुवर्त;
			}
			यदि ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				गणः = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, गणः);
			mprintf("%s\n", lname);
			मुक्त(lname);
		} अन्यथा {
			mprintf("%-*s", colspace, fname);
			यदि (c >= columns) {
				प्रारूप_लिख("\n");
				c = 1;
			} अन्यथा
				c++;
		}
		मुक्त(fname);
	}

	यदि (!(lflag & LS_LONG_VIEW) && (c != 1))
		प्रारूप_लिख("\n");

 बहिर्गमनम्:
	यदि (g.gl_pathc)
		globfree(&g);
	मुक्त(indices);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
do_df(संरचना sftp_conn *conn, ध्रुव वर्ण *मार्गः, पूर्णाङ्क hflag, पूर्णाङ्क iflag)
{
	संरचना sftp_statvfs st;
	वर्ण s_प्रयुक्तम्[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	वर्ण s_मूलम्[FMT_SCALED_STRSIZE], s_योग[FMT_SCALED_STRSIZE];
	वर्ण s_icapacity[16], s_dcapacity[16];

	यदि (sftp_statvfs(conn, मार्गः, &st, 1) == -1)
		प्रत्यागम -1;
	यदि (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", परिमाण(s_icapacity));
	अन्यथा {
		snprintf(s_icapacity, परिमाण(s_icapacity), "%3llu%%",
		    (अचिह्नित दीर्घ दीर्घ)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	यदि (st.f_खण्डानि == 0)
		strlcpy(s_dcapacity, "ERR", परिमाण(s_dcapacity));
	अन्यथा {
		snprintf(s_dcapacity, परिमाण(s_dcapacity), "%3llu%%",
		    (अचिह्नित दीर्घ दीर्घ)(100 * (st.f_खण्डानि - st.f_bfree) /
		    st.f_खण्डानि));
	}
	यदि (iflag) {
		प्रारूप_लिख("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		प्रारूप_लिख("%11llu %11llu %11llu %11llu         %s\n",
		    (अचिह्नित दीर्घ दीर्घ)st.f_files,
		    (अचिह्नित दीर्घ दीर्घ)(st.f_files - st.f_ffree),
		    (अचिह्नित दीर्घ दीर्घ)st.f_favail,
		    (अचिह्नित दीर्घ दीर्घ)st.f_ffree, s_icapacity);
	} अन्यथा यदि (hflag) {
		strlcpy(s_प्रयुक्तम्, "error", परिमाण(s_प्रयुक्तम्));
		strlcpy(s_avail, "error", परिमाण(s_avail));
		strlcpy(s_मूलम्, "error", परिमाण(s_मूलम्));
		strlcpy(s_योग, "error", परिमाण(s_योग));
		fmt_scaled((st.f_खण्डानि - st.f_bfree) * st.f_frsize, s_प्रयुक्तम्);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_मूलम्);
		fmt_scaled(st.f_खण्डानि * st.f_frsize, s_योग);
		प्रारूप_लिख("    Size     Used    Avail   (root)    %%Capacity\n");
		प्रारूप_लिख("%7sB %7sB %7sB %7sB         %s\n",
		    s_योग, s_प्रयुक्तम्, s_avail, s_मूलम्, s_dcapacity);
	} अन्यथा {
		प्रारूप_लिख("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		प्रारूप_लिख("%12llu %12llu %12llu %12llu         %s\n",
		    (अचिह्नित दीर्घ दीर्घ)(st.f_frsize * st.f_खण्डानि / 1024),
		    (अचिह्नित दीर्घ दीर्घ)(st.f_frsize *
		    (st.f_खण्डानि - st.f_bfree) / 1024),
		    (अचिह्नित दीर्घ दीर्घ)(st.f_frsize * st.f_bavail / 1024),
		    (अचिह्नित दीर्घ दीर्घ)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	प्रत्यागम 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
स्थिर शून्य
undo_glob_escape(वर्ण *s)
{
	आकार_t i, j;

	प्रति (i = j = 0;;) {
		यदि (s[i] == '\0') {
			s[j] = '\0';
			प्रत्यागम;
		}
		यदि (s[i] != '\\') {
			s[j++] = s[i++];
			अनुवर्त;
		}
		/* s[i] == '\\' */
		++i;
		विकल्प (s[i]) {
		पक्ष '?':
		पक्ष '[':
		पक्ष '*':
		पक्ष '\\':
			s[j++] = s[i++];
			भङ्ग;
		पक्ष '\0':
			s[j++] = '\\';
			s[j] = '\0';
			प्रत्यागम;
		स्वभाव:
			s[j++] = '\\';
			s[j++] = s[i++];
			भङ्ग;
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
#परिभाषय MAXARGS		128
#परिभाषय MAXARGLEN	8192
स्थिर वर्ण **
makeargv(ध्रुव वर्ण *arg, पूर्णाङ्क *argcp, पूर्णाङ्क sloppy, वर्ण *lastquote,
    u_int *terminated)
{
	पूर्णाङ्क argc, quot;
	आकार_t i, j;
	स्थिर वर्ण argvs[MAXARGLEN];
	स्थिर वर्ण *argv[MAXARGS + 1];
	गणना { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	यदि (वाक्यदैर्घ्यम्(arg) > परिमाण(argvs) - 1) {
 तर्काः_too_longs:
		error("string too long");
		प्रत्यागम रिक्त;
	}
	यदि (terminated != रिक्त)
		*terminated = 1;
	यदि (lastquote != रिक्त)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	प्रति (;;) {
		यदि ((आकार_t)argc >= परिमाण(argv) / परिमाण(*argv)){
			error("Too many arguments.");
			प्रत्यागम रिक्त;
		}
		यदि (रिक्तम्_वा((अचिह्नित वर्ण)arg[i])) {
			यदि (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} अन्यथा यदि (state != MA_START)
				argvs[j++] = arg[i];
		} अन्यथा यदि (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			यदि (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				यदि (lastquote != रिक्त)
					*lastquote = arg[i];
			} अन्यथा यदि (state == MA_UNQUOTED)
				state = q;
			अन्यथा यदि (state == q)
				state = MA_UNQUOTED;
			अन्यथा
				argvs[j++] = arg[i];
		} अन्यथा यदि (arg[i] == '\\') {
			यदि (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				यदि (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} अन्यथा यदि (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					यदि (j >= परिमाण(argvs) - 5)
						गच्छ तर्काः_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} अन्यथा {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} अन्यथा {
				यदि (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					यदि (lastquote != रिक्त)
						*lastquote = '\0';
				}
				यदि (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} अन्यथा {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					यदि (arg[i] == '\0')
						गच्छ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} अन्यथा यदि (arg[i] == '#') {
			यदि (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			अन्यथा
				गच्छ string_समाप्तम्;
		} अन्यथा यदि (arg[i] == '\0') {
			यदि (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				यदि (sloppy) {
					state = MA_UNQUOTED;
					यदि (terminated != रिक्त)
						*terminated = 0;
					गच्छ string_समाप्तम्;
				}
				error("Unterminated quoted argument");
				प्रत्यागम रिक्त;
			}
 string_समाप्तम्:
			यदि (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			भङ्ग;
		} अन्यथा {
			यदि (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				यदि (lastquote != रिक्त)
					*lastquote = '\0';
			}
			यदि ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				यदि (j >= परिमाण(argvs) - 3)
					गच्छ तर्काः_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} अन्यथा
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	प्रत्यागम argv;
}

स्थिर पूर्णाङ्क
parse_तर्काः(ध्रुव वर्ण **cpp, पूर्णाङ्क *ignore_errors, पूर्णाङ्क *disable_echo, पूर्णाङ्क *aflag,
	  पूर्णाङ्क *fflag, पूर्णाङ्क *hflag, पूर्णाङ्क *iflag, पूर्णाङ्क *lflag, पूर्णाङ्क *pflag,
	  पूर्णाङ्क *rflag, पूर्णाङ्क *sflag,
    अचिह्नित दीर्घ *n_arg, वर्ण **path1, वर्ण **path2)
{
	ध्रुव वर्ण *cmd, *cp = *cpp;
	वर्ण *cp2, **argv;
	पूर्णाङ्क आधारः = 0;
	दीर्घ दीर्घ ll;
	पूर्णाङ्क path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	प्रति (;*cp != '\0'; cp++) {
		यदि (*cp == '-') {
			*ignore_errors = 1;
		} अन्यथा यदि (*cp == '@') {
			*disable_echo = 1;
		} अन्यथा {
			/* all other characters terminate prefix processing */
			भङ्ग;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	यदि (*cp == '\0' || *cp == '#')
		प्रत्यागम (0);

	यदि ((argv = makeargv(cp, &argc, 0, रिक्त, रिक्त)) == रिक्त)
		प्रत्यागम -1;

	/* Figure out which command we have */
	प्रति (i = 0; cmds[i].c != रिक्त; i++) {
		यदि (argv[0] != रिक्त && strcasecmp(cmds[i].c, argv[0]) == 0)
			भङ्ग;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	यदि (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} अन्यथा यदि (cmdnum == -1) {
		error("Invalid command.");
		प्रत्यागम -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = रिक्त;
	optidx = 1;
	विकल्प (cmdnum) {
	पक्ष I_GET:
	पक्ष I_REGET:
	पक्ष I_REPUT:
	पक्ष I_PUT:
		यदि ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			प्रत्यागम -1;
		/* Get first pathname (mandatory) */
		यदि (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			प्रत्यागम -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		यदि (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		भङ्ग;
	पक्ष I_LINK:
		यदि ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			प्रत्यागम -1;
		गच्छ parse_two_paths;
	पक्ष I_COPY:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			प्रत्यागम -1;
		गच्छ parse_two_paths;
	पक्ष I_RENAME:
		यदि ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			प्रत्यागम -1;
		गच्छ parse_two_paths;
	पक्ष I_SYMLINK:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			प्रत्यागम -1;
 parse_two_paths:
		यदि (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			प्रत्यागम -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		भङ्ग;
	पक्ष I_MKDIR:
	पक्ष I_LMKDIR:
		यदि ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			प्रत्यागम -1;
		path1_mandatory = 1;
		गच्छ parse_one_मार्गः;
	पक्ष I_RM:
	पक्ष I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	पक्ष I_CHDIR:
	पक्ष I_LCHDIR:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			प्रत्यागम -1;
 parse_one_मार्गः:
		/* Get pathname (mandatory) */
		यदि (argc - optidx < 1) {
			यदि (!path1_mandatory)
				भङ्ग; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			प्रत्यागम -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		यदि (cmdnum != I_RM)
			undo_glob_escape(*path1);
		भङ्ग;
	पक्ष I_DF:
		यदि ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			प्रत्यागम -1;
		/* Default to current directory if no path specified */
		यदि (argc - optidx < 1)
			*path1 = रिक्त;
		अन्यथा {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		भङ्ग;
	पक्ष I_LS:
		यदि ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			प्रत्यागम(-1);
		/* Path is optional */
		यदि (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		भङ्ग;
	पक्ष I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + वाक्यदैर्घ्यम्(cmd) + strspn(cp, WHITESPACE);
	पक्ष I_SHELL:
		/* Uses the rest of the line */
		भङ्ग;
	पक्ष I_LUMASK:
	पक्ष I_CHMOD:
		आधारः = 8;
		/* FALLTHROUGH */
	पक्ष I_CHOWN:
	पक्ष I_CHGRP:
		यदि ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			प्रत्यागम -1;
		/* Get numeric arg (mandatory) */
		यदि (argc - optidx < 1)
			गच्छ need_अङ्कः_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, आधारः);
		यदि (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_अङ्कः_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			प्रत्यागम -1;
		}
		*n_arg = ll;
		यदि (cmdnum == I_LUMASK)
			भङ्ग;
		/* Get pathname (mandatory) */
		यदि (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			प्रत्यागम -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		भङ्ग;
	पक्ष I_QUIT:
	पक्ष I_PWD:
	पक्ष I_LPWD:
	पक्ष I_HELP:
	पक्ष I_संस्करणम्:
	पक्ष I_प्रगतिः:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			प्रत्यागम -1;
		भङ्ग;
	स्वभाव:
		fatal("Command not implemented");
	}

	*cpp = cp;
	प्रत्यागम(cmdnum);
}

स्थिर पूर्णाङ्क
parse_dispatch_command(संरचना sftp_conn *conn, ध्रुव वर्ण *cmd, वर्ण **pwd,
    ध्रुव वर्ण *startdir, पूर्णाङ्क err_abort, पूर्णाङ्क echo_command)
{
	ध्रुव वर्ण *ocmd = cmd;
	वर्ण *path1, *path2, *tmp;
	पूर्णाङ्क ignore_errors = 0, disable_echo = 1;
	पूर्णाङ्क aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	पूर्णाङ्क lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	पूर्णाङ्क cmdnum, i;
	अचिह्नित दीर्घ n_arg = 0;
	Attrib a, aa;
	वर्ण मार्गः_buf[PATH_MAX];
	पूर्णाङ्क err = 0;
	glob_t g;

	path1 = path2 = रिक्त;
	cmdnum = parse_तर्काः(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	यदि (ignore_errors != 0)
		err_abort = 0;

	यदि (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	स्मृतिं_पूरय(&g, 0, परिमाण(g));

	/* Perform command */
	विकल्प (cmdnum) {
	पक्ष 0:
		/* Blank line */
		भङ्ग;
	पक्ष -1:
		/* Unrecognized command */
		err = -1;
		भङ्ग;
	पक्ष I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	पक्ष I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		भङ्ग;
	पक्ष I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	पक्ष I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		भङ्ग;
	पक्ष I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		भङ्ग;
	पक्ष I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		भङ्ग;
	पक्ष I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	पक्ष I_LINK:
		यदि (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		भङ्ग;
	पक्ष I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			यदि (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			यदि (err != 0 && err_abort)
				भङ्ग;
		}
		भङ्ग;
	पक्ष I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		यदि (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		अन्यथा
			err = sftp_mkdir(conn, path1, &a, 1);
		भङ्ग;
	पक्ष I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		भङ्ग;
	पक्ष I_CHDIR:
		यदि (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		यदि ((tmp = sftp_realpath(conn, path1)) == रिक्त) {
			err = 1;
			भङ्ग;
		}
		यदि (sftp_stat(conn, tmp, 0, &aa) != 0) {
			मुक्त(tmp);
			err = 1;
			भङ्ग;
		}
		यदि (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			मुक्त(tmp);
			err = 1;
			भङ्ग;
		}
		यदि (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			मुक्त(tmp);
			err = 1;
			भङ्ग;
		}
		मुक्त(*pwd);
		*pwd = tmp;
		भङ्ग;
	पक्ष I_LS:
		यदि (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			भङ्ग;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = रिक्त;
		यदि (!मार्गः_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		भङ्ग;
	पक्ष I_DF:
		/* Default to current directory if no path specified */
		यदि (path1 == रिक्त)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		भङ्ग;
	पक्ष I_LCHDIR:
		यदि (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		मुक्त(path1);
		path1 = tmp;
		यदि (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		भङ्ग;
	पक्ष I_LMKDIR:
		यदि (pflag) {
			यदि (mkdir_मार्गः(path1, 0777) != 0)
				err = 1;
			भङ्ग;
		}
		यदि (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		भङ्ग;
	पक्ष I_LLS:
		local_do_ls(cmd);
		भङ्ग;
	पक्ष I_SHELL:
		local_do_shell(cmd);
		भङ्ग;
	पक्ष I_LUMASK:
		umask(n_arg);
		प्रारूप_लिख("Local umask: %03lo\n", n_arg);
		भङ्ग;
	पक्ष I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			यदि (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			यदि (err != 0 && err_abort)
				भङ्ग;
		}
		भङ्ग;
	पक्ष I_CHOWN:
	पक्ष I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			यदि ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				यदि (err_abort) {
					err = -1;
					भङ्ग;
				} अन्यथा
					अनुवर्त;
			}
			यदि (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				यदि (err_abort) {
					err = -1;
					भङ्ग;
				} अन्यथा
					अनुवर्त;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			यदि (cmdnum == I_CHOWN) {
				यदि (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} अन्यथा {
				यदि (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			यदि (err != 0 && err_abort)
				भङ्ग;
		}
		भङ्ग;
	पक्ष I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		भङ्ग;
	पक्ष I_LPWD:
		यदि (!getcwd(मार्गः_buf, परिमाण(मार्गः_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			भङ्ग;
		}
		mprintf("Local working directory: %s\n", मार्गः_buf);
		भङ्ग;
	पक्ष I_QUIT:
		/* Processed below */
		भङ्ग;
	पक्ष I_HELP:
		help();
		भङ्ग;
	पक्ष I_संस्करणम्:
		प्रारूप_लिख("SFTP protocol version %u\n", sftp_proto_संस्करणम्(conn));
		भङ्ग;
	पक्ष I_प्रगतिः:
		showprogress = !showprogress;
		यदि (showprogress)
			प्रारूप_लिख("Progress meter enabled\n");
		अन्यथा
			प्रारूप_लिख("Progress meter disabled\n");
		भङ्ग;
	स्वभाव:
		fatal("%d is not implemented", cmdnum);
	}

	यदि (g.gl_pathc)
		globfree(&g);
	मुक्त(path1);
	मुक्त(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	यदि (err_abort && err != 0)
		प्रत्यागम (-1);
	अन्यथा यदि (cmdnum == I_QUIT)
		प्रत्यागम (1);

	प्रत्यागम (0);
}

#यदि_परिभाषितम् USE_LIBEDIT
स्थिर वर्ण *
prompt(Edit_पङ्क्तिः *el)
{
	प्रत्यागम ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
स्थिर शून्य
complete_display(वर्ण **list, u_int len)
{
	u_int y, m = 0, विस्तारः = 80, columns = 1, colspace = 0, llen;
	संरचना winsize ws;
	वर्ण *tmp;

	/* Count entries for sort and find longest */
	प्रति (y = 0; list[y]; y++)
		m = अधिकतमम्(m, वाक्यदैर्घ्यम्(list[y]));

	यदि (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		विस्तारः = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = विस्तारः / (m + 2);
	columns = अधिकतमम्(columns, 1);
	colspace = विस्तारः / columns;
	colspace = MINIMUM(colspace, विस्तारः);

	प्रारूप_लिख("\n");
	m = 1;
	प्रति (y = 0; list[y]; y++) {
		llen = वाक्यदैर्घ्यम्(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		यदि (m >= columns) {
			प्रारूप_लिख("\n");
			m = 1;
		} अन्यथा
			m++;
	}
	प्रारूप_लिख("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
स्थिर वर्ण *
complete_ambiguous(ध्रुव वर्ण *word, वर्ण **list, आकार_t गणनम्)
{
	आकार_t i, j, matchlen;
	वर्ण *tmp;
	पूर्णाङ्क len;

	यदि (word == रिक्त)
		प्रत्यागम रिक्त;

	यदि (गणनम् == 0)
		प्रत्यागम xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = वाक्यदैर्घ्यम्(list[0]);
	प्रति (i = 1; i < गणनम् && list[i] != रिक्त; i++) {
		प्रति (j = 0; j < matchlen; j++)
			यदि (list[0][j] != list[i][j])
				भङ्ग;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(रिक्त, 0);
	प्रति (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		यदि (len <= 0 || i + (आकार_t)len > matchlen)
			भङ्ग;
		i += (आकार_t)len;
	}
	/* If so, truncate */
	यदि (i < matchlen)
		matchlen = i;

	यदि (matchlen > वाक्यदैर्घ्यम्(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		प्रत्यागम tmp;
	}

	प्रत्यागम xstrdup(word);
}

/* Autocomplete a sftp command */
स्थिर पूर्णाङ्क
complete_cmd_parse(Edit_पङ्क्तिः *el, वर्ण *cmd, पूर्णाङ्क lastarg, वर्ण quote,
    पूर्णाङ्क terminated)
{
	u_int y, गणनम् = 0, cmdlen, tmplen;
	वर्ण *tmp, **list, argterm[3];
	ध्रुव पङ्क्तिः_Info *lf;

	list = xcalloc((परिमाण(cmds) / परिमाण(*cmds)) + 1, परिमाण(वर्ण *));

	/* No command specified: display all available commands */
	यदि (cmd == रिक्त) {
		प्रति (y = 0; cmds[y].c; y++)
			list[गणनम्++] = xstrdup(cmds[y].c);

		list[गणनम्] = रिक्त;
		complete_display(list, 0);

		प्रति (y = 0; list[y] != रिक्त; y++)
			मुक्त(list[y]);
		मुक्त(list);
		प्रत्यागम गणनम्;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = वाक्यदैर्घ्यम्(cmd);
	प्रति (y = 0; cmds[y].c; y++)  {
		यदि (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[गणनम्++] = xstrdup(cmds[y].c);
	}
	list[गणनम्] = रिक्त;

	यदि (गणनम् == 0) {
		मुक्त(list);
		प्रत्यागम 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, गणनम्);
	यदि (गणनम् > 1)
		complete_display(list, 0);

	प्रति (y = 0; list[y]; y++)
		मुक्त(list[y]);
	मुक्त(list);

	यदि (tmp != रिक्त) {
		tmplen = वाक्यदैर्घ्यम्(tmp);
		cmdlen = वाक्यदैर्घ्यम्(cmd);
		/* If cmd may be extended then do so */
		यदि (tmplen > cmdlen)
			यदि (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_पङ्क्तिः(el);
		/* Terminate argument cleanly */
		यदि (गणनम् == 1) {
			y = 0;
			यदि (!terminated)
				argterm[y++] = quote;
			यदि (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			यदि (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		मुक्त(tmp);
	}

	प्रत्यागम गणनम्;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
स्थिर पूर्णाङ्क
complete_is_remote(वर्ण *cmd, पूर्णाङ्क cmdarg) {
	पूर्णाङ्क i;

	यदि (cmd == रिक्त)
		प्रत्यागम -1;

	प्रति (i = 0; cmds[i].c; i++) {
		यदि (!strncasecmp(cmd, cmds[i].c, वाक्यदैर्घ्यम्(cmds[i].c))) {
			यदि (cmdarg == 1)
				प्रत्यागम cmds[i].t;
			अन्यथा यदि (cmdarg == 2)
				प्रत्यागम cmds[i].t2;
			भङ्ग;
		}
	}

	प्रत्यागम -1;
}

/* Autocomplete a filename "file" */
स्थिर पूर्णाङ्क
complete_मेलनम्(Edit_पङ्क्तिः *el, संरचना sftp_conn *conn, वर्ण *remote_मार्गः,
    वर्ण *file, पूर्णाङ्क remote, पूर्णाङ्क lastarg, वर्ण quote, पूर्णाङ्क terminated)
{
	glob_t g;
	वर्ण *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	पूर्णाङ्क clen;
	ध्रुव पङ्क्तिः_Info *lf;

	/* Glob from "file" location */
	यदि (file == रिक्त)
		tmp = xstrdup("*");
	अन्यथा
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = मार्गः_absolute(tmp);

	स्मृतिं_पूरय(&g, 0, परिमाण(g));
	यदि (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_मार्गः);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);
	} अन्यथा
		(शून्य)glob(tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);

	/* Determine length of pwd so we can trim completion display */
	प्रति (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		यदि (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			यदि (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			भङ्ग;
		}
		यदि (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		यदि (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	मुक्त(tmp);
	tmp = रिक्त;

	यदि (g.gl_matchc == 0)
		गच्छ बहिर्गमनम्;

	यदि (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	यदि (file == रिक्त || hadglob)
		गच्छ बहिर्गमनम्;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = मार्गः_strip(tmp2, isabs ? रिक्त : remote_मार्गः);
	मुक्त(tmp2);

	यदि (tmp == रिक्त)
		गच्छ बहिर्गमनम्;

	tmplen = वाक्यदैर्घ्यम्(tmp);
	filelen = वाक्यदैर्घ्यम्(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	प्रति (i = 0; i < filelen; i++) {
		यदि (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} अन्यथा
			isesc = 0;
	}

	यदि (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = वाक्यदैर्घ्यम्(tmp2);
		/* quote argument on way out */
		mblen(रिक्त, 0);
		प्रति (i = 0; i < len; i += clen) {
			यदि ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (आकार_t)clen > परिमाण(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			स्मृतिं_प्रतिलिख(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			विकल्प (tmp2[i]) {
			पक्ष '\'':
			पक्ष '"':
			पक्ष '\\':
			पक्ष '\t':
			पक्ष '[':
			पक्ष ' ':
			पक्ष '#':
			पक्ष '*':
				यदि (quote == '\0' || tmp2[i] == quote) {
					यदि (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					भङ्ग;
				}
				/* FALLTHROUGH */
			स्वभाव:
				यदि (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				भङ्ग;
			}
		}
	}

	lf = el_पङ्क्तिः(el);
	यदि (g.gl_matchc == 1) {
		i = 0;
		यदि (!terminated && quote != '\0')
			ins[i++] = quote;
		यदि (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		यदि (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	मुक्त(tmp);

 बहिर्गमनम्:
	globfree(&g);
	प्रत्यागम g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
स्थिर अचिह्नित वर्ण
complete(Edit_पङ्क्तिः *el, पूर्णाङ्क ch)
{
	वर्ण **argv, *पङ्क्तिः, quote;
	पूर्णाङ्क argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ध्रुव पङ्क्तिः_Info *lf;
	संरचना complete_ctx *complete_ctx;

	lf = el_पङ्क्तिः(el);
	यदि (el_get(el, EL_CLIENTDATA, (शून्य**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->बफर;
	पङ्क्तिः = xmalloc(cursor + 1);
	स्मृतिं_प्रतिलिख(पङ्क्तिः, lf->बफर, cursor);
	पङ्क्तिः[cursor] = '\0';
	argv = makeargv(पङ्क्तिः, &carg, 1, &quote, &terminated);
	मुक्त(पङ्क्तिः);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->बफर;
	पङ्क्तिः = xmalloc(len + 1);
	स्मृतिं_प्रतिलिख(पङ्क्तिः, lf->बफर, len);
	पङ्क्तिः[len] = '\0';
	argv = makeargv(पङ्क्तिः, &argc, 1, रिक्त, रिक्त);

	/* Ensure cursor is at EOL or a argument boundary */
	यदि (पङ्क्तिः[cursor] != ' ' && पङ्क्तिः[cursor] != '\0' &&
	    पङ्क्तिः[cursor] != '\n') {
		मुक्त(पङ्क्तिः);
		प्रत्यागम ret;
	}

	यदि (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, रिक्त, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} अन्यथा यदि (carg == 1 && cursor > 0 && पङ्क्तिः[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		यदि (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} अन्यथा यदि (carg >= 1) {
		/* Handle file parsing */
		पूर्णाङ्क remote = 0;
		पूर्णाङ्क i = 0, cmdarg = 0;
		वर्ण *filematch = रिक्त;

		यदि (carg > 1 && पङ्क्तिः[cursor-1] != ' ')
			filematch = argv[carg - 1];

		प्रति (i = 1; i < carg; i++) {
			/* Skip flags */
			यदि (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		यदि (पङ्क्तिः[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		यदि ((remote == REMOTE || remote == LOCAL) &&
		    complete_मेलनम्(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	मुक्त(पङ्क्तिः);
	प्रत्यागम ret;
}
#यदि_अन्तः /* USE_LIBEDIT */

स्थिर पूर्णाङ्क
interactive_loop(संरचना sftp_conn *conn, वर्ण *file1, वर्ण *file2)
{
	वर्ण *remote_मार्गः;
	वर्ण *dir = रिक्त, *startdir = रिक्त;
	वर्ण cmd[2048];
	पूर्णाङ्क err, interactive;
	Edit_पङ्क्तिः *el = रिक्त;
#यदि_परिभाषितम् USE_LIBEDIT
	ध्रुव वर्ण *editor;
	History *hl = रिक्त;
	HistEvent hev;
	बाह्य वर्ण *__progname;
	संरचना complete_ctx complete_ctx;

	यदि (!batchmode && isatty(STDIN_FILENO)) {
		यदि ((el = el_init(__progname, stdin, stdout, stderr)) == रिक्त)
			fatal("Couldn't initialise editline");
		यदि ((hl = history_init()) == रिक्त)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_समुच्चयः(el, EL_HIST, history, hl);

		el_समुच्चयः(el, EL_PROMPT, prompt);
		el_समुच्चयः(el, EL_EDITOR, "emacs");
		el_समुच्चयः(el, EL_TERMINAL, रिक्त);
		el_समुच्चयः(el, EL_SIGNAL, 1);
		el_source(el, रिक्त);

		/* Tab Completion */
		el_समुच्चयः(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_मार्गः;
		el_समुच्चयः(el, EL_CLIENTDATA, (शून्य*)&complete_ctx);
		el_समुच्चयः(el, EL_BIND, "^I", "ftp-complete", रिक्त);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_समुच्चयः(el, EL_BIND, "\\e[1;5C", "em-next-word", रिक्त);
		el_समुच्चयः(el, EL_BIND, "\\e\\e[C", "em-next-word", रिक्त);
		el_समुच्चयः(el, EL_BIND, "\\e[1;5D", "ed-prev-word", रिक्त);
		el_समुच्चयः(el, EL_BIND, "\\e\\e[D", "ed-prev-word", रिक्त);
		/* make ^w match ksh behaviour */
		el_समुच्चयः(el, EL_BIND, "^w", "ed-delete-prev-word", रिक्त);

		/* el_source() may have changed EL_EDITOR to vi */
		यदि (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_समुच्चयः(el, EL_BIND, "^[", "vi-command-mode", रिक्त);
	}
#यदि_अन्तः /* USE_LIBEDIT */

	यदि ((remote_मार्गः = sftp_realpath(conn, ".")) == रिक्त)
		fatal("Need cwd");
	startdir = xstrdup(remote_मार्गः);

	यदि (file1 != रिक्त) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_मार्गः);

		यदि (sftp_remote_is_dir(conn, dir) && file2 == रिक्त) {
			यदि (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, परिमाण cmd, "cd \"%s\"", dir);
			यदि (parse_dispatch_command(conn, cmd,
			    &remote_मार्गः, startdir, 1, 0) != 0) {
				मुक्त(dir);
				मुक्त(startdir);
				मुक्त(remote_मार्गः);
				मुक्त(conn);
				प्रत्यागम (-1);
			}
		} अन्यथा {
			err = process_get(conn, dir, file2, remote_मार्गः, 0, 0,
			    global_aflag, 0);
			मुक्त(dir);
			मुक्त(startdir);
			मुक्त(remote_मार्गः);
			मुक्त(conn);
			प्रत्यागम (err);
		}
		मुक्त(dir);
	}

	setvbuf(stdout, रिक्त, _IOLBF, 0);
	setvbuf(infile, रिक्त, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	प्रति (;;) {
		संरचना sigaction sa;

		interrupted = 0;
		स्मृतिं_पूरय(&sa, 0, परिमाण(sa));
		sa.sa_handler = interactive ? read_व्यवधानम् : killchild;
		यदि (sigaction(SIGINT, &sa, रिक्त) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			भङ्ग;
		}
		यदि (el == रिक्त) {
			यदि (interactive) {
				प्रारूप_लिख("sftp> ");
				fflush(stdout);
			}
			यदि (fgets(cmd, परिमाण(cmd), infile) == रिक्त) {
				यदि (interactive)
					प्रारूप_लिख("\n");
				यदि (interrupted)
					अनुवर्त;
				भङ्ग;
			}
		} अन्यथा {
#यदि_परिभाषितम् USE_LIBEDIT
			ध्रुव वर्ण *पङ्क्तिः;
			पूर्णाङ्क गणनम् = 0;

			यदि ((पङ्क्तिः = el_gets(el, &गणनम्)) == रिक्त ||
			    गणनम् <= 0) {
				प्रारूप_लिख("\n");
				यदि (interrupted)
					अनुवर्त;
				भङ्ग;
			}
			history(hl, &hev, H_ENTER, पङ्क्तिः);
			यदि (strlcpy(cmd, पङ्क्तिः, परिमाण(cmd)) >= परिमाण(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				अनुवर्त;
			}
#यदि_अन्तः /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_व्यवधानम्);

		err = parse_dispatch_command(conn, cmd, &remote_मार्गः,
		    startdir, batchmode, !interactive && el == रिक्त);
		यदि (err != 0)
			भङ्ग;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	मुक्त(remote_मार्गः);
	मुक्त(startdir);
	मुक्त(conn);

#यदि_परिभाषितम् USE_LIBEDIT
	यदि (hl != रिक्त)
		history_अन्तः(hl);
	यदि (el != रिक्त)
		el_अन्तः(el);
#यदि_अन्तः /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	प्रत्यागम (err >= 0 ? 0 : -1);
}

स्थिर शून्य
connect_गन्तव्यम्_server(वर्ण *मार्गः, वर्ण **तर्काः, पूर्णाङ्क *अन्तर्, पूर्णाङ्क *बहिर्गमनम्)
{
	पूर्णाङ्क c_अन्तर्, c_बहिर्गमनम्;
#यदि_परिभाषितम् USE_PIPES
	पूर्णाङ्क pin[2], pout[2];

	यदि ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*अन्तर् = pin[0];
	*बहिर्गमनम् = pout[1];
	c_अन्तर् = pout[0];
	c_बहिर्गमनम् = pin[1];
#अन्यथा /* USE_PIPES */
	पूर्णाङ्क inout[2];

	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*अन्तर् = *बहिर्गमनम् = inout[0];
	c_अन्तर् = c_बहिर्गमनम् = inout[1];
#यदि_अन्तः /* USE_PIPES */
	FD_CLOSEONEXEC(*अन्तर्);
	FD_CLOSEONEXEC(*बहिर्गमनम्);

	यदि ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	अन्यथा यदि (sshpid == 0) {
		यदि ((dup2(c_अन्तर्, STDIN_FILENO) == -1) ||
		    (dup2(c_बहिर्गमनम्, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*अन्तर्);
		close(*बहिर्गमनम्);
		close(c_अन्तर्);
		close(c_बहिर्गमनम्);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(मार्गः, तर्काः);
		fprintf(stderr, "exec: %s: %s\n", मार्गः, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_अन्तर्);
	close(c_बहिर्गमनम्);
}

स्थिर शून्य
usage(शून्य)
{
	बाह्य वर्ण *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	निर्गच्छ(1);
}

पूर्णाङ्क
मुख्यम्(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क r, अन्तर्, बहिर्गमनम्, ch, err, tmp, पत्तनम् = -1, noisy = 0;
	वर्ण *host = रिक्त, *user, *cp, **cpp, *file2 = रिक्त;
	पूर्णाङ्क debug_level = 0;
	वर्ण *file1 = रिक्त, *sftp_server = रिक्त;
	वर्ण *ssh_क्रमादेशः = मार्गः_SSH_क्रमादेशः, *sftp_प्रत्यक्षम् = रिक्त;
	ध्रुव वर्ण *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist तर्काः;
	बाह्य पूर्णाङ्क optind;
	बाह्य वर्ण *optarg;
	संरचना sftp_conn *conn;
	आकार_t copy_बफर_len = 0;
	आकार_t अङ्कः_अनुरोधाः = 0;
	दीर्घ दीर्घ llv, सीमा_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	स्मृतिं_पूरय(&तर्काः, '\0', परिमाण(तर्काः));
	तर्काः.list = रिक्त;
	addargs(&तर्काः, "%s", ssh_क्रमादेशः);
	addargs(&तर्काः, "-oForwardX11 no");
	addargs(&तर्काः, "-oPermitLocalCommand no");
	addargs(&तर्काः, "-oClearAllForwardings yes");
	addargs(&तर्काः, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	यावत् ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		विकल्प (ch) {
		/* Passed through to ssh(1) */
		पक्ष 'A':
		पक्ष '4':
		पक्ष '6':
		पक्ष 'C':
			addargs(&तर्काः, "-%c", ch);
			भङ्ग;
		/* Passed through to ssh(1) with argument */
		पक्ष 'F':
		पक्ष 'J':
		पक्ष 'c':
		पक्ष 'i':
		पक्ष 'o':
			addargs(&तर्काः, "-%c", ch);
			addargs(&तर्काः, "%s", optarg);
			भङ्ग;
		पक्ष 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&तर्काः, "-%c", ch);
			भङ्ग;
		पक्ष 'P':
			पत्तनम् = a2port(optarg);
			यदि (पत्तनम् <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			भङ्ग;
		पक्ष 'v':
			यदि (debug_level < 3) {
				addargs(&तर्काः, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			भङ्ग;
		पक्ष '1':
			fatal("SSH protocol v.1 is no longer supported");
			भङ्ग;
		पक्ष '2':
			/* accept silently */
			भङ्ग;
		पक्ष 'a':
			global_aflag = 1;
			भङ्ग;
		पक्ष 'B':
			copy_बफर_len = strtol(optarg, &cp, 10);
			यदि (copy_बफर_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			भङ्ग;
		पक्ष 'b':
			यदि (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			यदि (वाक्यं_तुलय(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == रिक्त)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&तर्काः, "-obatchmode yes");
			भङ्ग;
		पक्ष 'f':
			global_fflag = 1;
			भङ्ग;
		पक्ष 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			भङ्ग;
		पक्ष 'p':
			global_pflag = 1;
			भङ्ग;
		पक्ष 'D':
			sftp_प्रत्यक्षम् = optarg;
			भङ्ग;
		पक्ष 'l':
			सीमा_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			यदि (errstr != रिक्त)
				usage();
			सीमा_kbps *= 1024; /* kbps */
			भङ्ग;
		पक्ष 'r':
			global_rflag = 1;
			भङ्ग;
		पक्ष 'R':
			अङ्कः_अनुरोधाः = strtol(optarg, &cp, 10);
			यदि (अङ्कः_अनुरोधाः == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			भङ्ग;
		पक्ष 's':
			sftp_server = optarg;
			भङ्ग;
		पक्ष 'S':
			ssh_क्रमादेशः = optarg;
			replacearg(&तर्काः, 0, "%s", ssh_क्रमादेशः);
			भङ्ग;
		पक्ष 'X':
			/* Please keep in sync with ssh.c -X */
			यदि (वाक्ये_तुलय(optarg, "buffer=", 7) == 0) {
				r = अवलोकनम्_scaled(optarg + 7, &llv);
				यदि (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				यदि (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_बफर_len = (आकार_t)llv;
			} अन्यथा यदि (वाक्ये_तुलय(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				यदि (errstr != रिक्त) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				अङ्कः_अनुरोधाः = (आकार_t)llv;
			} अन्यथा {
				fatal("Invalid -X option");
			}
			भङ्ग;
		पक्ष 'h':
		स्वभाव:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&तर्काः, "-oForwardAgent no");

	यदि (!isatty(STDERR_FILENO))
		showprogress = 0;

	यदि (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	यदि (sftp_प्रत्यक्षम् == रिक्त) {
		यदि (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		विकल्प (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		पक्ष -1:
			usage();
			भङ्ग;
		पक्ष 0:
			यदि (tmp != -1)
				पत्तनम् = tmp;
			भङ्ग;
		स्वभाव:
			/* Try with user, host and path. */
			यदि (parse_user_host_मार्गः(*argv, &user, &host,
			    &file1) == 0)
				भङ्ग;
			/* Try with user and host. */
			यदि (parse_user_host_पत्तनम्(*argv, &user, &host, रिक्त)
			    == 0)
				भङ्ग;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			भङ्ग;
		}
		file2 = *(argv + 1);

		यदि (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		यदि (पत्तनम् != -1)
			addargs(&तर्काः, "-oPort %d", पत्तनम्);
		यदि (user != रिक्त) {
			addargs(&तर्काः, "-l");
			addargs(&तर्काः, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		यदि (sftp_server == रिक्त || strchr(sftp_server, '/') == रिक्त)
			addargs(&तर्काः, "-s");

		addargs(&तर्काः, "--");
		addargs(&तर्काः, "%s", host);
		addargs(&तर्काः, "%s", (sftp_server != रिक्त ?
		    sftp_server : "sftp"));

		connect_गन्तव्यम्_server(ssh_क्रमादेशः, तर्काः.list, &अन्तर्, &बहिर्गमनम्);
	} अन्यथा {
		यदि ((r = argv_विभज(sftp_प्रत्यक्षम्, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		यदि (cpp[0] == रिक्त)
			fatal("No sftp server specified via -D");
		connect_गन्तव्यम्_server(cpp[0], cpp, &अन्तर्, &बहिर्गमनम्);
		argv_free(cpp, tmp);
	}
	freeargs(&तर्काः);

	conn = sftp_init(अन्तर्, बहिर्गमनम्, copy_बफर_len, अङ्कः_अनुरोधाः, सीमा_kbps);
	यदि (conn == रिक्त)
		fatal("Couldn't initialise connection to server");

	यदि (!quiet) {
		यदि (sftp_प्रत्यक्षम् == रिक्त)
			fprintf(stderr, "Connected to %s.\n", host);
		अन्यथा
			fprintf(stderr, "Attached to %s.\n", sftp_प्रत्यक्षम्);
	}

	err = interactive_loop(conn, file1, file2);

#यदि !defined(USE_PIPES)
	shutdown(अन्तर्, SHUT_RDWR);
	shutdown(बहिर्गमनम्, SHUT_RDWR);
#यदि_अन्तः

	close(अन्तर्);
	close(बहिर्गमनम्);
	यदि (batchmode)
		fclose(infile);

	यावत् (waitpid(sshpid, रिक्त, 0) == -1 && sshpid > 1)
		यदि (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	निर्गच्छ(err == 0 ? 0 : 1);
}
