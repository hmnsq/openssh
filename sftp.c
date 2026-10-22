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
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#अन्तर्भाव <histedit.h>
#अण्णहा
प्रकारनिर्देश शून्य Edit_पङ्क्तिः;
#endif
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
पूर्णाङ्क sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
संरचना complete_ctx {
	संरचना sftp_conn *conn;
	वर्ण **remote_pathp;
};

पूर्णाङ्क sftp_glob(संरचना sftp_conn *, ध्रुव वर्ण *, पूर्णाङ्क,
    पूर्णाङ्क (*)(ध्रुव वर्ण *, पूर्णाङ्क), glob_t *); /* proto for sftp-glob.c */

बाह्य वर्ण *__progname;

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
	I_VERSION,
	I_PROGRESS,
};

संरचना CMD {
	ध्रुव वर्ण *c;
	ध्रुव पूर्णाङ्क n;
	ध्रुव पूर्णाङ्क t;	/* Completion type for the first argument */
	ध्रुव पूर्णाङ्क t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

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
	{ रिक्त,		-1,		-1,		-1	}
};

स्थिर शून्य
killchild(पूर्णाङ्क signo)
{
	pid_t pid;

	pid = sshpid;
	जइ (pid > 1) {
		kill(pid, SIGTERM);
		(शून्य)waitpid(pid, रिक्त, 0);
	}

	_exit(1);
}

स्थिर शून्य
suspchild(पूर्णाङ्क signo)
{
	पूर्णाङ्क save_errno = errno;
	जइ (sshpid > 1) {
		kill(sshpid, signo);
		जाव (waitpid(sshpid, रिक्त, WUNTRACED) == -1 && errno == EINTR)
			अनुवर्त;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

स्थिर शून्य
cmd_interrupt(पूर्णाङ्क signo)
{
	ध्रुव वर्ण सन्देशः[] = "\rInterrupt  \n";
	पूर्णाङ्क olderrno = errno;

	(शून्य)लिख(STDERR_FILENO, सन्देशः, परिमाण(सन्देशः) - 1);
	interrupted = 1;
	errno = olderrno;
}

स्थिर शून्य
read_interrupt(पूर्णाङ्क signo)
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
	जाव ((pid = waitpid(sshpid, रिक्त, WNOHANG)) == -1 && errno == EINTR)
		अनुवर्त;
	जइ (pid == sshpid) {
		जइ (!quiet)
		    (शून्य)लिख(STDERR_FILENO, सन्देशः, परिमाण(सन्देशः) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

स्थिर शून्य
help(शून्य)
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

स्थिर शून्य
local_do_shell(ध्रुव वर्ण *args)
{
	पूर्णाङ्क status;
	वर्ण *shell;
	pid_t pid;

	जइ (!*args)
		args = रिक्त;

	जइ ((shell = getenv("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	जइ ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	जइ (pid == 0) {
		जइ (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (वर्ण *)रिक्त);
		} अण्णहा {
			debug3("Executing %s", shell);
			execl(shell, shell, (वर्ण *)रिक्त);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	जाव (waitpid(pid, &status, 0) == -1)
		जइ (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	जइ (!WIFEXITED(status))
		error("Shell exited abnormally");
	अण्णहा जइ (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

स्थिर शून्य
local_do_ls(ध्रुव वर्ण *args)
{
	जइ (!args || !*args)
		local_do_shell(_PATH_LS);
	अण्णहा {
		पूर्णाङ्क len = strlen(_PATH_LS " ") + strlen(args) + 1;
		वर्ण *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		मुक्त(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
स्थिर वर्ण *
path_strip(ध्रुव वर्ण *path, ध्रुव वर्ण *strip)
{
	size_t len;

	जइ (strip == रिक्त || (len = strlen(strip)) == 0)
		प्रत्यागम (xstrdup(path));

	जइ (strncmp(path, strip, len) == 0) {
		जइ (strip[len - 1] != '/' && path[len] == '/')
			len++;
		प्रत्यागम (xstrdup(path + len));
	}

	प्रत्यागम (xstrdup(path));
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
	जाव ((ch = getopt(argc, argv, "afPpRr")) != -1) {
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
	जाव ((ch = getopt(argc, argv, "p")) != -1) {
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
	जाव ((ch = getopt(argc, argv, "s")) != -1) {
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
	जाव ((ch = getopt(argc, argv, "l")) != -1) {
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

	*lflag = LS_NAME_SORT;
	जाव ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		विकल्प (ch) {
		पक्ष '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			भङ्ग;
		पक्ष 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			भङ्ग;
		पक्ष 'a':
			*lflag |= LS_SHOW_ALL;
			भङ्ग;
		पक्ष 'f':
			*lflag &= ~SORT_FLAGS;
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
			*lflag |= LS_REVERSE_SORT;
			भङ्ग;
		पक्ष 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
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
	जाव ((ch = getopt(argc, argv, "hi")) != -1) {
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
	जाव ((ch = getopt(argc, argv, "h")) != -1) {
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

	जाव ((ch = getopt(argc, argv, "")) != -1) {
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
	size_t i, o, len;
	वर्ण *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	प्रति (i = o = 0; i < len; i++) {
		जइ (strchr("[]?*\\", s[i]) != रिक्त)
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
	जइ (p == रिक्त)
		प्रत्यागम escpwd;
	ret = sftp_make_absolute(p, escpwd);
	मुक्त(escpwd);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
local_is_dir(ध्रुव वर्ण *path)
{
	संरचना stat sb;

	जइ (stat(path, &sb) == -1)
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
	memset(&g, 0, परिमाण(g));

	debug3("Looking up %s", abs_src);
	जइ ((r = sftp_glob(conn, abs_src, GLOB_MARK, रिक्त, &g)) != 0) {
		जइ (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} अण्णहा {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		गच्छ out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	जइ (g.gl_matchc > 1 && dst != रिक्त && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		गच्छ out;
	}

	प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		जइ ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, strerror(errno));
			मुक्त(tmp);
			err = -1;
			गच्छ out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		जइ (strcmp(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[strspn(filename, "/")] == '\0'))
			filename = ".";

		जइ (g.gl_matchc == 1 && dst) {
			जइ (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} अण्णहा {
				abs_dst = xstrdup(dst);
			}
		} अण्णहा जइ (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} अण्णहा {
			abs_dst = xstrdup(filename);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		जइ (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अण्णहा जइ (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		जइ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			जइ (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अण्णहा {
			जइ (sftp_download(conn, g.gl_pathv[i], abs_dst, रिक्त,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		मुक्त(abs_dst);
		abs_dst = रिक्त;
	}

out:
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

	जइ (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, परिमाण(g));
	debug3("Looking up %s", src);
	जइ (glob(src, GLOB_NOCHECK | GLOB_MARK, रिक्त, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		गच्छ out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	जइ (tmp_dst != रिक्त)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	जइ (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		गच्छ out;
	}

	प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		जइ (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			अनुवर्त;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		जइ ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, strerror(errno));
			मुक्त(tmp);
			err = -1;
			गच्छ out;
		}
		/* Special handling for source of '..' */
		जइ (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		मुक्त(abs_dst);
		abs_dst = रिक्त;
		जइ (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			जइ (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			अण्णहा
				abs_dst = xstrdup(tmp_dst);
		} अण्णहा जइ (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} अण्णहा {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		जइ (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अण्णहा जइ (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		जइ (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			जइ (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अण्णहा {
			जइ (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
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
	पूर्णाङ्क rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	जइ (sort_flag & LS_NAME_SORT)
		प्रत्यागम (rmul * strcmp(a->filename, b->filename));
	अण्णहा जइ (sort_flag & LS_TIME_SORT)
		प्रत्यागम (rmul * NCMP(a->a.mtime, b->a.mtime));
	अण्णहा जइ (sort_flag & LS_SIZE_SORT)
		प्रत्यागम (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
स्थिर पूर्णाङ्क
do_ls_dir(संरचना sftp_conn *conn, ध्रुव वर्ण *path,
    ध्रुव वर्ण *strip_path, पूर्णाङ्क lflag)
{
	पूर्णाङ्क n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	जइ ((n = sftp_readdir(conn, path, &d)) != 0)
		प्रत्यागम (n);

	जइ (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		संरचना winsize ws;
		वर्ण *tmp;

		/* Count entries for sort and find longest filename */
		प्रति (n = 0; d[n] != रिक्त; n++) {
			जइ (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		मुक्त(tmp);

		जइ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	जइ (lflag & SORT_FLAGS) {
		प्रति (n = 0; d[n] != रिक्त; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, परिमाण(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	प्रति (n = 0; d[n] != रिक्त && !interrupted; n++) {
		वर्ण *tmp, *fname;

		जइ (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			अनुवर्त;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		मुक्त(tmp);

		जइ (lflag & LS_LONG_VIEW) {
			जइ ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				वर्ण *lname;
				संरचना stat sb;
				ध्रुव वर्ण *user = रिक्त, *group = रिक्त;

				memset(&sb, 0, परिमाण(sb));
				attrib_to_stat(&d[n]->a, &sb);
				जइ ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				मुक्त(lname);
			} अण्णहा
				mprintf("%s\n", d[n]->longname);
		} अण्णहा {
			mprintf("%-*s", colspace, fname);
			जइ (c >= columns) {
				printf("\n");
				c = 1;
			} अण्णहा
				c++;
		}

		मुक्त(fname);
	}

	जइ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
sglob_comp(ध्रुव शून्य *aa, ध्रुव शून्य *bb)
{
	u_int a = *(ध्रुव u_int *)aa;
	u_int b = *(ध्रुव u_int *)bb;
	ध्रुव वर्ण *ap = sort_glob->gl_pathv[a];
	ध्रुव वर्ण *bp = sort_glob->gl_pathv[b];
	ध्रुव संरचना stat *as = sort_glob->gl_statv[a];
	ध्रुव संरचना stat *bs = sort_glob->gl_statv[b];
	पूर्णाङ्क rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	जइ (as == रिक्त || bs == रिक्त)
		प्रत्यागम (as == bs) ? 0 : (as == रिक्त ? rmul : -rmul);
	जइ (sort_flag & LS_NAME_SORT)
		प्रत्यागम (rmul * strcmp(ap, bp));
	अण्णहा जइ (sort_flag & LS_TIME_SORT) {
#जइ defined(HAVE_STRUCT_STAT_ST_MTIM)
		जइ (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			प्रत्यागम 0;
		प्रत्यागम timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#नोचेद्यदि defined(HAVE_STRUCT_STAT_ST_MTIME)
		प्रत्यागम (rmul * NCMP(as->st_mtime, bs->st_mtime));
#अण्णहा
	प्रत्यागम rmul * 1;
#endif
	} अण्णहा जइ (sort_flag & LS_SIZE_SORT)
		प्रत्यागम (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
स्थिर पूर्णाङ्क
do_globbed_ls(संरचना sftp_conn *conn, ध्रुव वर्ण *path,
    ध्रुव वर्ण *strip_path, पूर्णाङ्क lflag)
{
	वर्ण *fname, *lname;
	glob_t g;
	पूर्णाङ्क err, r;
	संरचना winsize ws;
	u_int i, j, nentries, *indices = रिक्त, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, परिमाण(g));

	जइ ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    रिक्त, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		जइ (g.gl_pathc)
			globfree(&g);
		जइ (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} अण्णहा {
			error("Can't ls: \"%s\" not found", path);
		}
		प्रत्यागम -1;
	}

	जइ (interrupted)
		गच्छ out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	जइ (g.gl_matchc == 1 && g.gl_statv[0] != रिक्त &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		प्रत्यागम err;
	}

	जइ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	जइ (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		प्रति (i = 0; g.gl_pathv[i]; i++)
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
	प्रति (nentries = 0; g.gl_pathv[nentries] != रिक्त; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, परिमाण(*indices));
	प्रति (i = 0; i < nentries; i++)
		indices[i] = i;

	जइ (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, परिमाण(*indices), sglob_comp);
		sort_glob = रिक्त;
	}

	get_remote_user_groups_from_glob(conn, &g);
	प्रति (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		जइ (lflag & LS_LONG_VIEW) {
			ध्रुव वर्ण *user = रिक्त, *group = रिक्त;

			जइ (g.gl_statv[i] == रिक्त) {
				error("no stat information for %s", fname);
				मुक्त(fname);
				अनुवर्त;
			}
			जइ ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			मुक्त(lname);
		} अण्णहा {
			mprintf("%-*s", colspace, fname);
			जइ (c >= columns) {
				printf("\n");
				c = 1;
			} अण्णहा
				c++;
		}
		मुक्त(fname);
	}

	जइ (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	जइ (g.gl_pathc)
		globfree(&g);
	मुक्त(indices);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
do_df(संरचना sftp_conn *conn, ध्रुव वर्ण *path, पूर्णाङ्क hflag, पूर्णाङ्क iflag)
{
	संरचना sftp_statvfs st;
	वर्ण s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	वर्ण s_मूलम्[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	वर्ण s_icapacity[16], s_dcapacity[16];

	जइ (sftp_statvfs(conn, path, &st, 1) == -1)
		प्रत्यागम -1;
	जइ (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", परिमाण(s_icapacity));
	अण्णहा {
		snprintf(s_icapacity, परिमाण(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	जइ (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", परिमाण(s_dcapacity));
	अण्णहा {
		snprintf(s_dcapacity, परिमाण(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	जइ (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} अण्णहा जइ (hflag) {
		strlcpy(s_used, "error", परिमाण(s_used));
		strlcpy(s_avail, "error", परिमाण(s_avail));
		strlcpy(s_मूलम्, "error", परिमाण(s_मूलम्));
		strlcpy(s_total, "error", परिमाण(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_मूलम्);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_मूलम्, s_dcapacity);
	} अण्णहा {
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
	size_t i, j;

	प्रति (i = j = 0;;) {
		जइ (s[i] == '\0') {
			s[j] = '\0';
			प्रत्यागम;
		}
		जइ (s[i] != '\\') {
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
#define MAXARGS		128
#define MAXARGLEN	8192
स्थिर वर्ण **
makeargv(ध्रुव वर्ण *arg, पूर्णाङ्क *argcp, पूर्णाङ्क sloppy, वर्ण *lastquote,
    u_int *terminated)
{
	पूर्णाङ्क argc, quot;
	size_t i, j;
	स्थिर वर्ण argvs[MAXARGLEN];
	स्थिर वर्ण *argv[MAXARGS + 1];
	गणना { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	जइ (strlen(arg) > परिमाण(argvs) - 1) {
 args_too_longs:
		error("string too long");
		प्रत्यागम रिक्त;
	}
	जइ (terminated != रिक्त)
		*terminated = 1;
	जइ (lastquote != रिक्त)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	प्रति (;;) {
		जइ ((size_t)argc >= परिमाण(argv) / परिमाण(*argv)){
			error("Too many arguments.");
			प्रत्यागम रिक्त;
		}
		जइ (isspace((unsigned वर्ण)arg[i])) {
			जइ (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} अण्णहा जइ (state != MA_START)
				argvs[j++] = arg[i];
		} अण्णहा जइ (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			जइ (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				जइ (lastquote != रिक्त)
					*lastquote = arg[i];
			} अण्णहा जइ (state == MA_UNQUOTED)
				state = q;
			अण्णहा जइ (state == q)
				state = MA_UNQUOTED;
			अण्णहा
				argvs[j++] = arg[i];
		} अण्णहा जइ (arg[i] == '\\') {
			जइ (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				जइ (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} अण्णहा जइ (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					जइ (j >= परिमाण(argvs) - 5)
						गच्छ args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} अण्णहा {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} अण्णहा {
				जइ (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					जइ (lastquote != रिक्त)
						*lastquote = '\0';
				}
				जइ (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} अण्णहा {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					जइ (arg[i] == '\0')
						गच्छ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} अण्णहा जइ (arg[i] == '#') {
			जइ (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			अण्णहा
				गच्छ string_done;
		} अण्णहा जइ (arg[i] == '\0') {
			जइ (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				जइ (sloppy) {
					state = MA_UNQUOTED;
					जइ (terminated != रिक्त)
						*terminated = 0;
					गच्छ string_done;
				}
				error("Unterminated quoted argument");
				प्रत्यागम रिक्त;
			}
 string_done:
			जइ (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			भङ्ग;
		} अण्णहा {
			जइ (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				जइ (lastquote != रिक्त)
					*lastquote = '\0';
			}
			जइ ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				जइ (j >= परिमाण(argvs) - 3)
					गच्छ args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} अण्णहा
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	प्रत्यागम argv;
}

स्थिर पूर्णाङ्क
parse_args(ध्रुव वर्ण **cpp, पूर्णाङ्क *ignore_errors, पूर्णाङ्क *disable_echo, पूर्णाङ्क *aflag,
	  पूर्णाङ्क *fflag, पूर्णाङ्क *hflag, पूर्णाङ्क *iflag, पूर्णाङ्क *lflag, पूर्णाङ्क *pflag,
	  पूर्णाङ्क *rflag, पूर्णाङ्क *sflag,
    unsigned long *n_arg, वर्ण **path1, वर्ण **path2)
{
	ध्रुव वर्ण *cmd, *cp = *cpp;
	वर्ण *cp2, **argv;
	पूर्णाङ्क base = 0;
	long long ll;
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
		जइ (*cp == '-') {
			*ignore_errors = 1;
		} अण्णहा जइ (*cp == '@') {
			*disable_echo = 1;
		} अण्णहा {
			/* all other characters terminate prefix processing */
			भङ्ग;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	जइ (*cp == '\0' || *cp == '#')
		प्रत्यागम (0);

	जइ ((argv = makeargv(cp, &argc, 0, रिक्त, रिक्त)) == रिक्त)
		प्रत्यागम -1;

	/* Figure out which command we have */
	प्रति (i = 0; cmds[i].c != रिक्त; i++) {
		जइ (argv[0] != रिक्त && strcasecmp(cmds[i].c, argv[0]) == 0)
			भङ्ग;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	जइ (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} अण्णहा जइ (cmdnum == -1) {
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
		जइ ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			प्रत्यागम -1;
		/* Get first pathname (mandatory) */
		जइ (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			प्रत्यागम -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		जइ (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		भङ्ग;
	पक्ष I_LINK:
		जइ ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			प्रत्यागम -1;
		गच्छ parse_two_paths;
	पक्ष I_COPY:
		जइ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			प्रत्यागम -1;
		गच्छ parse_two_paths;
	पक्ष I_RENAME:
		जइ ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			प्रत्यागम -1;
		गच्छ parse_two_paths;
	पक्ष I_SYMLINK:
		जइ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			प्रत्यागम -1;
 parse_two_paths:
		जइ (argc - optidx < 2) {
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
		जइ ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			प्रत्यागम -1;
		path1_mandatory = 1;
		गच्छ parse_one_path;
	पक्ष I_RM:
	पक्ष I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	पक्ष I_CHDIR:
	पक्ष I_LCHDIR:
		जइ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			प्रत्यागम -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		जइ (argc - optidx < 1) {
			जइ (!path1_mandatory)
				भङ्ग; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			प्रत्यागम -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		जइ (cmdnum != I_RM)
			undo_glob_escape(*path1);
		भङ्ग;
	पक्ष I_DF:
		जइ ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			प्रत्यागम -1;
		/* Default to current directory if no path specified */
		जइ (argc - optidx < 1)
			*path1 = रिक्त;
		अण्णहा {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		भङ्ग;
	पक्ष I_LS:
		जइ ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			प्रत्यागम(-1);
		/* Path is optional */
		जइ (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		भङ्ग;
	पक्ष I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	पक्ष I_SHELL:
		/* Uses the rest of the line */
		भङ्ग;
	पक्ष I_LUMASK:
	पक्ष I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	पक्ष I_CHOWN:
	पक्ष I_CHGRP:
		जइ ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			प्रत्यागम -1;
		/* Get numeric arg (mandatory) */
		जइ (argc - optidx < 1)
			गच्छ need_अङ्कः_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		जइ (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_अङ्कः_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			प्रत्यागम -1;
		}
		*n_arg = ll;
		जइ (cmdnum == I_LUMASK)
			भङ्ग;
		/* Get pathname (mandatory) */
		जइ (argc - optidx < 2) {
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
	पक्ष I_VERSION:
	पक्ष I_PROGRESS:
		जइ ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
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
	unsigned long n_arg = 0;
	Attrib a, aa;
	वर्ण path_buf[PATH_MAX];
	पूर्णाङ्क err = 0;
	glob_t g;

	path1 = path2 = रिक्त;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	जइ (ignore_errors != 0)
		err_abort = 0;

	जइ (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, परिमाण(g));

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
		जइ (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		भङ्ग;
	पक्ष I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			जइ (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			जइ (err != 0 && err_abort)
				भङ्ग;
		}
		भङ्ग;
	पक्ष I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		जइ (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		अण्णहा
			err = sftp_mkdir(conn, path1, &a, 1);
		भङ्ग;
	पक्ष I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		भङ्ग;
	पक्ष I_CHDIR:
		जइ (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		जइ ((tmp = sftp_realpath(conn, path1)) == रिक्त) {
			err = 1;
			भङ्ग;
		}
		जइ (sftp_stat(conn, tmp, 0, &aa) != 0) {
			मुक्त(tmp);
			err = 1;
			भङ्ग;
		}
		जइ (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			मुक्त(tmp);
			err = 1;
			भङ्ग;
		}
		जइ (!S_ISDIR(aa.perm)) {
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
		जइ (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			भङ्ग;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = रिक्त;
		जइ (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		भङ्ग;
	पक्ष I_DF:
		/* Default to current directory if no path specified */
		जइ (path1 == रिक्त)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		भङ्ग;
	पक्ष I_LCHDIR:
		जइ (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		मुक्त(path1);
		path1 = tmp;
		जइ (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		भङ्ग;
	पक्ष I_LMKDIR:
		जइ (pflag) {
			जइ (mkdir_path(path1, 0777) != 0)
				err = 1;
			भङ्ग;
		}
		जइ (mkdir(path1, 0777) == -1) {
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
		printf("Local umask: %03lo\n", n_arg);
		भङ्ग;
	पक्ष I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			जइ (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			जइ (err != 0 && err_abort)
				भङ्ग;
		}
		भङ्ग;
	पक्ष I_CHOWN:
	पक्ष I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		प्रति (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			जइ ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				जइ (err_abort) {
					err = -1;
					भङ्ग;
				} अण्णहा
					अनुवर्त;
			}
			जइ (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				जइ (err_abort) {
					err = -1;
					भङ्ग;
				} अण्णहा
					अनुवर्त;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			जइ (cmdnum == I_CHOWN) {
				जइ (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} अण्णहा {
				जइ (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			जइ (err != 0 && err_abort)
				भङ्ग;
		}
		भङ्ग;
	पक्ष I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		भङ्ग;
	पक्ष I_LPWD:
		जइ (!getcwd(path_buf, परिमाण(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			भङ्ग;
		}
		mprintf("Local working directory: %s\n", path_buf);
		भङ्ग;
	पक्ष I_QUIT:
		/* Processed below */
		भङ्ग;
	पक्ष I_HELP:
		help();
		भङ्ग;
	पक्ष I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		भङ्ग;
	पक्ष I_PROGRESS:
		showprogress = !showprogress;
		जइ (showprogress)
			printf("Progress meter enabled\n");
		अण्णहा
			printf("Progress meter disabled\n");
		भङ्ग;
	स्वभाव:
		fatal("%d is not implemented", cmdnum);
	}

	जइ (g.gl_pathc)
		globfree(&g);
	मुक्त(path1);
	मुक्त(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	जइ (err_abort && err != 0)
		प्रत्यागम (-1);
	अण्णहा जइ (cmdnum == I_QUIT)
		प्रत्यागम (1);

	प्रत्यागम (0);
}

#ifdef USE_LIBEDIT
स्थिर वर्ण *
prompt(Edit_पङ्क्तिः *el)
{
	प्रत्यागम ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
स्थिर शून्य
complete_display(वर्ण **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	संरचना winsize ws;
	वर्ण *tmp;

	/* Count entries for sort and find longest */
	प्रति (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	जइ (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	प्रति (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		जइ (m >= columns) {
			printf("\n");
			m = 1;
		} अण्णहा
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
स्थिर वर्ण *
complete_ambiguous(ध्रुव वर्ण *word, वर्ण **list, size_t गणनम्)
{
	size_t i, j, matchlen;
	वर्ण *tmp;
	पूर्णाङ्क len;

	जइ (word == रिक्त)
		प्रत्यागम रिक्त;

	जइ (गणनम् == 0)
		प्रत्यागम xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	प्रति (i = 1; i < गणनम् && list[i] != रिक्त; i++) {
		प्रति (j = 0; j < matchlen; j++)
			जइ (list[0][j] != list[i][j])
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
		जइ (len <= 0 || i + (size_t)len > matchlen)
			भङ्ग;
		i += (size_t)len;
	}
	/* If so, truncate */
	जइ (i < matchlen)
		matchlen = i;

	जइ (matchlen > strlen(word)) {
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
	जइ (cmd == रिक्त) {
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
	cmdlen = strlen(cmd);
	प्रति (y = 0; cmds[y].c; y++)  {
		जइ (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[गणनम्++] = xstrdup(cmds[y].c);
	}
	list[गणनम्] = रिक्त;

	जइ (गणनम् == 0) {
		मुक्त(list);
		प्रत्यागम 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, गणनम्);
	जइ (गणनम् > 1)
		complete_display(list, 0);

	प्रति (y = 0; list[y]; y++)
		मुक्त(list[y]);
	मुक्त(list);

	जइ (tmp != रिक्त) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		जइ (tmplen > cmdlen)
			जइ (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_पङ्क्तिः(el);
		/* Terminate argument cleanly */
		जइ (गणनम् == 1) {
			y = 0;
			जइ (!terminated)
				argterm[y++] = quote;
			जइ (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			जइ (y > 0 && el_insertstr(el, argterm) == -1)
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

	जइ (cmd == रिक्त)
		प्रत्यागम -1;

	प्रति (i = 0; cmds[i].c; i++) {
		जइ (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			जइ (cmdarg == 1)
				प्रत्यागम cmds[i].t;
			अण्णहा जइ (cmdarg == 2)
				प्रत्यागम cmds[i].t2;
			भङ्ग;
		}
	}

	प्रत्यागम -1;
}

/* Autocomplete a filename "file" */
स्थिर पूर्णाङ्क
complete_match(Edit_पङ्क्तिः *el, संरचना sftp_conn *conn, वर्ण *remote_path,
    वर्ण *file, पूर्णाङ्क remote, पूर्णाङ्क lastarg, वर्ण quote, पूर्णाङ्क terminated)
{
	glob_t g;
	वर्ण *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	पूर्णाङ्क clen;
	ध्रुव पङ्क्तिः_Info *lf;

	/* Glob from "file" location */
	जइ (file == रिक्त)
		tmp = xstrdup("*");
	अण्णहा
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, परिमाण(g));
	जइ (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);
	} अण्णहा
		(शून्य)glob(tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);

	/* Determine length of pwd so we can trim completion display */
	प्रति (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		जइ (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			जइ (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			भङ्ग;
		}
		जइ (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		जइ (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	मुक्त(tmp);
	tmp = रिक्त;

	जइ (g.gl_matchc == 0)
		गच्छ out;

	जइ (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	जइ (file == रिक्त || hadglob)
		गच्छ out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? रिक्त : remote_path);
	मुक्त(tmp2);

	जइ (tmp == रिक्त)
		गच्छ out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	प्रति (i = 0; i < filelen; i++) {
		जइ (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} अण्णहा
			isesc = 0;
	}

	जइ (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(रिक्त, 0);
		प्रति (i = 0; i < len; i += clen) {
			जइ ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > परिमाण(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
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
				जइ (quote == '\0' || tmp2[i] == quote) {
					जइ (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					भङ्ग;
				}
				/* FALLTHROUGH */
			स्वभाव:
				जइ (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				भङ्ग;
			}
		}
	}

	lf = el_पङ्क्तिः(el);
	जइ (g.gl_matchc == 1) {
		i = 0;
		जइ (!terminated && quote != '\0')
			ins[i++] = quote;
		जइ (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		जइ (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	मुक्त(tmp);

 out:
	globfree(&g);
	प्रत्यागम g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
स्थिर unsigned वर्ण
complete(Edit_पङ्क्तिः *el, पूर्णाङ्क ch)
{
	वर्ण **argv, *पङ्क्तिः, quote;
	पूर्णाङ्क argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	ध्रुव पङ्क्तिः_Info *lf;
	संरचना complete_ctx *complete_ctx;

	lf = el_पङ्क्तिः(el);
	जइ (el_get(el, EL_CLIENTDATA, (शून्य**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	पङ्क्तिः = xmalloc(cursor + 1);
	memcpy(पङ्क्तिः, lf->buffer, cursor);
	पङ्क्तिः[cursor] = '\0';
	argv = makeargv(पङ्क्तिः, &carg, 1, &quote, &terminated);
	मुक्त(पङ्क्तिः);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	पङ्क्तिः = xmalloc(len + 1);
	memcpy(पङ्क्तिः, lf->buffer, len);
	पङ्क्तिः[len] = '\0';
	argv = makeargv(पङ्क्तिः, &argc, 1, रिक्त, रिक्त);

	/* Ensure cursor is at EOL or a argument boundary */
	जइ (पङ्क्तिः[cursor] != ' ' && पङ्क्तिः[cursor] != '\0' &&
	    पङ्क्तिः[cursor] != '\n') {
		मुक्त(पङ्क्तिः);
		प्रत्यागम ret;
	}

	जइ (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, रिक्त, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} अण्णहा जइ (carg == 1 && cursor > 0 && पङ्क्तिः[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		जइ (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} अण्णहा जइ (carg >= 1) {
		/* Handle file parsing */
		पूर्णाङ्क remote = 0;
		पूर्णाङ्क i = 0, cmdarg = 0;
		वर्ण *filematch = रिक्त;

		जइ (carg > 1 && पङ्क्तिः[cursor-1] != ' ')
			filematch = argv[carg - 1];

		प्रति (i = 1; i < carg; i++) {
			/* Skip flags */
			जइ (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		जइ (पङ्क्तिः[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		जइ ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	मुक्त(पङ्क्तिः);
	प्रत्यागम ret;
}
#endif /* USE_LIBEDIT */

स्थिर पूर्णाङ्क
interactive_loop(संरचना sftp_conn *conn, वर्ण *file1, वर्ण *file2)
{
	वर्ण *remote_path;
	वर्ण *dir = रिक्त, *startdir = रिक्त;
	वर्ण cmd[2048];
	पूर्णाङ्क err, interactive;
	Edit_पङ्क्तिः *el = रिक्त;
#ifdef USE_LIBEDIT
	ध्रुव वर्ण *editor;
	History *hl = रिक्त;
	HistEvent hev;
	बाह्य वर्ण *__progname;
	संरचना complete_ctx complete_ctx;

	जइ (!batchmode && isatty(STDIN_FILENO)) {
		जइ ((el = el_init(__progname, stdin, stdout, stderr)) == रिक्त)
			fatal("Couldn't initialise editline");
		जइ ((hl = history_init()) == रिक्त)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, रिक्त);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, रिक्त);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (शून्य*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", रिक्त);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", रिक्त);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", रिक्त);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", रिक्त);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", रिक्त);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", रिक्त);

		/* el_source() may have changed EL_EDITOR to vi */
		जइ (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", रिक्त);
	}
#endif /* USE_LIBEDIT */

	जइ ((remote_path = sftp_realpath(conn, ".")) == रिक्त)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	जइ (file1 != रिक्त) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		जइ (sftp_remote_is_dir(conn, dir) && file2 == रिक्त) {
			जइ (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, परिमाण cmd, "cd \"%s\"", dir);
			जइ (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				मुक्त(dir);
				मुक्त(startdir);
				मुक्त(remote_path);
				मुक्त(conn);
				प्रत्यागम (-1);
			}
		} अण्णहा {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			मुक्त(dir);
			मुक्त(startdir);
			मुक्त(remote_path);
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
		memset(&sa, 0, परिमाण(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		जइ (sigaction(SIGINT, &sa, रिक्त) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			भङ्ग;
		}
		जइ (el == रिक्त) {
			जइ (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			जइ (fgets(cmd, परिमाण(cmd), infile) == रिक्त) {
				जइ (interactive)
					printf("\n");
				जइ (interrupted)
					अनुवर्त;
				भङ्ग;
			}
		} अण्णहा {
#ifdef USE_LIBEDIT
			ध्रुव वर्ण *पङ्क्तिः;
			पूर्णाङ्क गणनम् = 0;

			जइ ((पङ्क्तिः = el_gets(el, &गणनम्)) == रिक्त ||
			    गणनम् <= 0) {
				printf("\n");
				जइ (interrupted)
					अनुवर्त;
				भङ्ग;
			}
			history(hl, &hev, H_ENTER, पङ्क्तिः);
			जइ (strlcpy(cmd, पङ्क्तिः, परिमाण(cmd)) >= परिमाण(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				अनुवर्त;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == रिक्त);
		जइ (err != 0)
			भङ्ग;
	}
	ssh_signal(SIGCHLD, SIG_DFL);
	मुक्त(remote_path);
	मुक्त(startdir);
	मुक्त(conn);

#ifdef USE_LIBEDIT
	जइ (hl != रिक्त)
		history_end(hl);
	जइ (el != रिक्त)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	प्रत्यागम (err >= 0 ? 0 : -1);
}

स्थिर शून्य
connect_to_server(वर्ण *path, वर्ण **args, पूर्णाङ्क *in, पूर्णाङ्क *out)
{
	पूर्णाङ्क c_in, c_out;
#ifdef USE_PIPES
	पूर्णाङ्क pin[2], pout[2];

	जइ ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#अण्णहा /* USE_PIPES */
	पूर्णाङ्क inout[2];

	जइ (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	जइ ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	अण्णहा जइ (sshpid == 0) {
		जइ ((dup2(c_in, STDIN_FILENO) == -1) ||
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
	exit(1);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क r, in, out, ch, err, tmp, port = -1, noisy = 0;
	वर्ण *host = रिक्त, *user, *cp, **cpp, *file2 = रिक्त;
	पूर्णाङ्क debug_level = 0;
	वर्ण *file1 = रिक्त, *sftp_server = रिक्त;
	वर्ण *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = रिक्त;
	ध्रुव वर्ण *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	बाह्य पूर्णाङ्क optind;
	बाह्य वर्ण *optarg;
	संरचना sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t अङ्कः_requests = 0;
	long long llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', परिमाण(args));
	args.list = रिक्त;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	जाव ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		विकल्प (ch) {
		/* Passed through to ssh(1) */
		पक्ष 'A':
		पक्ष '4':
		पक्ष '6':
		पक्ष 'C':
			addargs(&args, "-%c", ch);
			भङ्ग;
		/* Passed through to ssh(1) with argument */
		पक्ष 'F':
		पक्ष 'J':
		पक्ष 'c':
		पक्ष 'i':
		पक्ष 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			भङ्ग;
		पक्ष 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			भङ्ग;
		पक्ष 'P':
			port = a2port(optarg);
			जइ (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			भङ्ग;
		पक्ष 'v':
			जइ (debug_level < 3) {
				addargs(&args, "-v");
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
			copy_buffer_len = strtol(optarg, &cp, 10);
			जइ (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			भङ्ग;
		पक्ष 'b':
			जइ (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			जइ (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == रिक्त)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
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
			sftp_direct = optarg;
			भङ्ग;
		पक्ष 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			जइ (errstr != रिक्त)
				usage();
			limit_kbps *= 1024; /* kbps */
			भङ्ग;
		पक्ष 'r':
			global_rflag = 1;
			भङ्ग;
		पक्ष 'R':
			अङ्कः_requests = strtol(optarg, &cp, 10);
			जइ (अङ्कः_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			भङ्ग;
		पक्ष 's':
			sftp_server = optarg;
			भङ्ग;
		पक्ष 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			भङ्ग;
		पक्ष 'X':
			/* Please keep in sync with ssh.c -X */
			जइ (strncmp(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				जइ (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					errno = EINVAL;
				}
				जइ (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, strerror(errno));
				}
				copy_buffer_len = (size_t)llv;
			} अण्णहा जइ (strncmp(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				जइ (errstr != रिक्त) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				अङ्कः_requests = (size_t)llv;
			} अण्णहा {
				fatal("Invalid -X option");
			}
			भङ्ग;
		पक्ष 'h':
		स्वभाव:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	जइ (!isatty(STDERR_FILENO))
		showprogress = 0;

	जइ (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	जइ (sftp_direct == रिक्त) {
		जइ (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		विकल्प (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		पक्ष -1:
			usage();
			भङ्ग;
		पक्ष 0:
			जइ (tmp != -1)
				port = tmp;
			भङ्ग;
		स्वभाव:
			/* Try with user, host and path. */
			जइ (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				भङ्ग;
			/* Try with user and host. */
			जइ (parse_user_host_port(*argv, &user, &host, रिक्त)
			    == 0)
				भङ्ग;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			भङ्ग;
		}
		file2 = *(argv + 1);

		जइ (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		जइ (port != -1)
			addargs(&args, "-oPort %d", port);
		जइ (user != रिक्त) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		जइ (sftp_server == रिक्त || strchr(sftp_server, '/') == रिक्त)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != रिक्त ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} अण्णहा {
		जइ ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		जइ (cpp[0] == रिक्त)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, अङ्कः_requests, limit_kbps);
	जइ (conn == रिक्त)
		fatal("Couldn't initialise connection to server");

	जइ (!quiet) {
		जइ (sftp_direct == रिक्त)
			fprintf(stderr, "Connected to %s.\n", host);
		अण्णहा
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#जइ !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	जइ (batchmode)
		fclose(infile);

	जाव (waitpid(sshpid, रिक्त, 0) == -1 && sshpid > 1)
		जइ (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	exit(err == 0 ? 0 : 1);
}
