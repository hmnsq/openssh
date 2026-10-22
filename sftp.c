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
#अन्यथा
प्रकारनिर्देश शून्य Edit_पङ्क्ति;
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
खाता* infile;

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
चञ्चल संक_पूर्ण_प्रकार interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
पूर्णाङ्क sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
संरचना complete_ctx {
	संरचना sftp_conn *conn;
	वर्ण **remote_pathp;
};

पूर्णाङ्क sftp_glob(संरचना sftp_conn *, अचर वर्ण *, पूर्णाङ्क,
    पूर्णाङ्क (*)(अचर वर्ण *, पूर्णाङ्क), glob_t *); /* proto for sftp-glob.c */

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
	अचर वर्ण *c;
	अचर पूर्णाङ्क n;
	अचर पूर्णाङ्क t;	/* Completion type for the first argument */
	अचर पूर्णाङ्क t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

स्थिर अचर संरचना CMD cmds[] = {
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
	यदि (pid > 1) {
		समाप्त(pid, संक_इति);
		(शून्य)waitpid(pid, रिक्त, 0);
	}

	_exit(1);
}

स्थिर शून्य
suspchild(पूर्णाङ्क signo)
{
	पूर्णाङ्क save_errno = त्रुटि_सं;
	यदि (sshpid > 1) {
		समाप्त(sshpid, signo);
		जबसम्म (waitpid(sshpid, रिक्त, WUNTRACED) == -1 && त्रुटि_सं == EINTR)
			जारी;
	}
	समाप्त(getpid(), SIGSTOP);
	त्रुटि_सं = save_errno;
}

स्थिर शून्य
cmd_interrupt(पूर्णाङ्क signo)
{
	अचर वर्ण सन्देश[] = "\rInterrupt  \n";
	पूर्णाङ्क olderrno = त्रुटि_सं;

	(शून्य)लिख(STDERR_FILENO, सन्देश, परिमाण(सन्देश) - 1);
	interrupted = 1;
	त्रुटि_सं = olderrno;
}

स्थिर शून्य
read_interrupt(पूर्णाङ्क signo)
{
	interrupted = 1;
}

स्थिर शून्य
sigchld_handler(पूर्णाङ्क sig)
{
	पूर्णाङ्क save_errno = त्रुटि_सं;
	pid_t pid;
	अचर वर्ण सन्देश[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	जबसम्म ((pid = waitpid(sshpid, रिक्त, WNOHANG)) == -1 && त्रुटि_सं == EINTR)
		जारी;
	यदि (pid == sshpid) {
		यदि (!quiet)
		    (शून्य)लिख(STDERR_FILENO, सन्देश, परिमाण(सन्देश) - 1);
		sshpid = -1;
	}

	त्रुटि_सं = save_errno;
}

स्थिर शून्य
help(शून्य)
{
	म_लिखो("Available commands:\n"
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
local_do_shell(अचर वर्ण *args)
{
	पूर्णाङ्क status;
	वर्ण *shell;
	pid_t pid;

	यदि (!*args)
		args = रिक्त;

	यदि ((shell = दो_पर्या("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	यदि ((pid = विभाजन()) == -1)
		fatal("Couldn't fork: %s", म_त्रुटि(त्रुटि_सं));

	यदि (pid == 0) {
		यदि (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (वर्ण *)रिक्त);
		} अन्यथा {
			debug3("Executing %s", shell);
			execl(shell, shell, (वर्ण *)रिक्त);
		}
		ख_लिखो(मानक_त्रुटि, "Couldn't execute \"%s\": %s\n", shell,
		    म_त्रुटि(त्रुटि_सं));
		_exit(1);
	}
	जबसम्म (waitpid(pid, &status, 0) == -1)
		यदि (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));
	यदि (!WIFEXITED(status))
		error("Shell exited abnormally");
	अन्यथा यदि (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

स्थिर शून्य
local_do_ls(अचर वर्ण *args)
{
	यदि (!args || !*args)
		local_do_shell(_PATH_LS);
	अन्यथा {
		पूर्णाङ्क len = म_माप(_PATH_LS " ") + म_माप(args) + 1;
		वर्ण *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		मुक्त(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
स्थिर वर्ण *
path_strip(अचर वर्ण *path, अचर वर्ण *strip)
{
	माप_प्रकार len;

	यदि (strip == रिक्त || (len = म_माप(strip)) == 0)
		फर्काऊ (xstrdup(path));

	यदि (म_भेदन(path, strip, len) == 0) {
		यदि (strip[len - 1] != '/' && path[len] == '/')
			len++;
		फर्काऊ (xstrdup(path + len));
	}

	फर्काऊ (xstrdup(path));
}

स्थिर पूर्णाङ्क
parse_getput_flags(अचर वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc,
    पूर्णाङ्क *aflag, पूर्णाङ्क *fflag, पूर्णाङ्क *pflag, पूर्णाङ्क *rflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	जबसम्म ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		विकल्प (ch) {
		पक्ष 'a':
			*aflag = 1;
			रोक;
		पक्ष 'f':
			*fflag = 1;
			रोक;
		पक्ष 'p':
		पक्ष 'P':
			*pflag = 1;
			रोक;
		पक्ष 'r':
		पक्ष 'R':
			*rflag = 1;
			रोक;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर पूर्णाङ्क
parse_mkdir_flags(अचर वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *pflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	जबसम्म ((ch = getopt(argc, argv, "p")) != -1) {
		विकल्प (ch) {
		पक्ष 'p':
			*pflag = 1;
			रोक;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर पूर्णाङ्क
parse_link_flags(अचर वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *sflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	जबसम्म ((ch = getopt(argc, argv, "s")) != -1) {
		विकल्प (ch) {
		पक्ष 's':
			*sflag = 1;
			रोक;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर पूर्णाङ्क
parse_rename_flags(अचर वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *lflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	जबसम्म ((ch = getopt(argc, argv, "l")) != -1) {
		विकल्प (ch) {
		पक्ष 'l':
			*lflag = 1;
			रोक;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर पूर्णाङ्क
parse_ls_flags(वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *lflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	जबसम्म ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		विकल्प (ch) {
		पक्ष '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			रोक;
		पक्ष 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			रोक;
		पक्ष 'a':
			*lflag |= LS_SHOW_ALL;
			रोक;
		पक्ष 'f':
			*lflag &= ~SORT_FLAGS;
			रोक;
		पक्ष 'h':
			*lflag |= LS_SI_UNITS;
			रोक;
		पक्ष 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			रोक;
		पक्ष 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			रोक;
		पक्ष 'r':
			*lflag |= LS_REVERSE_SORT;
			रोक;
		पक्ष 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			रोक;
		स्वभाव:
			error("ls: Invalid flag -%c", optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर पूर्णाङ्क
parse_df_flags(अचर वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *hflag, पूर्णाङ्क *iflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	जबसम्म ((ch = getopt(argc, argv, "hi")) != -1) {
		विकल्प (ch) {
		पक्ष 'h':
			*hflag = 1;
			रोक;
		पक्ष 'i':
			*iflag = 1;
			रोक;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर पूर्णाङ्क
parse_ch_flags(अचर वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc, पूर्णाङ्क *hflag)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	जबसम्म ((ch = getopt(argc, argv, "h")) != -1) {
		विकल्प (ch) {
		पक्ष 'h':
			*hflag = 1;
			रोक;
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर पूर्णाङ्क
parse_no_flags(अचर वर्ण *cmd, वर्ण **argv, पूर्णाङ्क argc)
{
	बाह्य पूर्णाङ्क opterr, optind, optopt, optreset;
	पूर्णाङ्क ch;

	optind = optreset = 1;
	opterr = 0;

	जबसम्म ((ch = getopt(argc, argv, "")) != -1) {
		विकल्प (ch) {
		स्वभाव:
			error("%s: Invalid flag -%c", cmd, optopt);
			फर्काऊ -1;
		}
	}

	फर्काऊ optind;
}

स्थिर वर्ण *
escape_glob(अचर वर्ण *s)
{
	माप_प्रकार i, o, len;
	वर्ण *ret;

	len = म_माप(s);
	ret = xcalloc(2, len + 1);
	लागि (i = o = 0; i < len; i++) {
		यदि (म_अक्षर("[]?*\\", s[i]) != रिक्त)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	फर्काऊ ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
स्थिर वर्ण *
make_absolute_pwd_glob(वर्ण *p, अचर वर्ण *pwd)
{
	वर्ण *ret, *escpwd;

	escpwd = escape_glob(pwd);
	यदि (p == रिक्त)
		फर्काऊ escpwd;
	ret = sftp_make_absolute(p, escpwd);
	मुक्त(escpwd);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
local_is_dir(अचर वर्ण *path)
{
	संरचना stat sb;

	यदि (stat(path, &sb) == -1)
		फर्काऊ 0;
	फर्काऊ S_ISDIR(sb.st_mode);
}

स्थिर पूर्णाङ्क
process_get(संरचना sftp_conn *conn, अचर वर्ण *src, अचर वर्ण *dst,
    अचर वर्ण *pwd, पूर्णाङ्क pflag, पूर्णाङ्क rflag, पूर्णाङ्क resume, पूर्णाङ्क fflag)
{
	वर्ण *filename, *abs_src = रिक्त, *abs_dst = रिक्त, *tmp = रिक्त;
	glob_t g;
	पूर्णाङ्क i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	स_रखो(&g, 0, परिमाण(g));

	debug3("Looking up %s", abs_src);
	यदि ((r = sftp_glob(conn, abs_src, GLOB_MARK, रिक्त, &g)) != 0) {
		यदि (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} अन्यथा {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		गच्छ out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	यदि (g.gl_matchc > 1 && dst != रिक्त && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		गच्छ out;
	}

	लागि (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		यदि ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			मुक्त(tmp);
			err = -1;
			गच्छ out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		यदि (म_भेद(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[म_अखोज(filename, "/")] == '\0'))
			filename = ".";

		यदि (g.gl_matchc == 1 && dst) {
			यदि (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} अन्यथा {
				abs_dst = xstrdup(dst);
			}
		} अन्यथा यदि (dst) {
			abs_dst = sftp_path_append(dst, filename);
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

out:
	मुक्त(abs_src);
	globfree(&g);
	फर्काऊ(err);
}

स्थिर पूर्णाङ्क
process_put(संरचना sftp_conn *conn, अचर वर्ण *src, अचर वर्ण *dst,
    अचर वर्ण *pwd, पूर्णाङ्क pflag, पूर्णाङ्क rflag, पूर्णाङ्क resume, पूर्णाङ्क fflag)
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

	स_रखो(&g, 0, परिमाण(g));
	debug3("Looking up %s", src);
	यदि (glob(src, GLOB_NOCHECK | GLOB_MARK, रिक्त, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		गच्छ out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	यदि (tmp_dst != रिक्त)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	यदि (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		गच्छ out;
	}

	लागि (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		यदि (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], म_त्रुटि(त्रुटि_सं));
			जारी;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		यदि ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			मुक्त(tmp);
			err = -1;
			गच्छ out;
		}
		/* Special handling for source of '..' */
		यदि (म_भेद(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		मुक्त(abs_dst);
		abs_dst = रिक्त;
		यदि (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			यदि (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			अन्यथा
				abs_dst = xstrdup(tmp_dst);
		} अन्यथा यदि (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
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

out:
	मुक्त(abs_dst);
	मुक्त(tmp_dst);
	globfree(&g);
	फर्काऊ(err);
}

स्थिर पूर्णाङ्क
sdirent_comp(अचर शून्य *aa, अचर शून्य *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	पूर्णाङ्क rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	यदि (sort_flag & LS_NAME_SORT)
		फर्काऊ (rmul * म_भेद(a->filename, b->filename));
	अन्यथा यदि (sort_flag & LS_TIME_SORT)
		फर्काऊ (rmul * NCMP(a->a.mtime, b->a.mtime));
	अन्यथा यदि (sort_flag & LS_SIZE_SORT)
		फर्काऊ (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
स्थिर पूर्णाङ्क
do_ls_dir(संरचना sftp_conn *conn, अचर वर्ण *path,
    अचर वर्ण *strip_path, पूर्णाङ्क lflag)
{
	पूर्णाङ्क n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	यदि ((n = sftp_readdir(conn, path, &d)) != 0)
		फर्काऊ (n);

	यदि (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		संरचना winsize ws;
		वर्ण *tmp;

		/* Count entries for sort and find longest filename */
		लागि (n = 0; d[n] != रिक्त; n++) {
			यदि (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, म_माप(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += म_माप(tmp);
		मुक्त(tmp);

		यदि (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	यदि (lflag & SORT_FLAGS) {
		लागि (n = 0; d[n] != रिक्त; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		क्विक(d, n, परिमाण(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	लागि (n = 0; d[n] != रिक्त && !interrupted; n++) {
		वर्ण *tmp, *fname;

		यदि (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			जारी;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		मुक्त(tmp);

		यदि (lflag & LS_LONG_VIEW) {
			यदि ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				वर्ण *lname;
				संरचना stat sb;
				अचर वर्ण *user = रिक्त, *group = रिक्त;

				स_रखो(&sb, 0, परिमाण(sb));
				attrib_to_stat(&d[n]->a, &sb);
				यदि ((lflag & LS_NUMERIC_VIEW) == 0) {
					user = ruser_name(sb.st_uid);
					group = rgroup_name(sb.st_gid);
				}
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS), user, group);
				mprintf("%s\n", lname);
				मुक्त(lname);
			} अन्यथा
				mprintf("%s\n", d[n]->longname);
		} अन्यथा {
			mprintf("%-*s", colspace, fname);
			यदि (c >= columns) {
				म_लिखो("\n");
				c = 1;
			} अन्यथा
				c++;
		}

		मुक्त(fname);
	}

	यदि (!(lflag & LS_LONG_VIEW) && (c != 1))
		म_लिखो("\n");

	sftp_free_dirents(d);
	फर्काऊ (0);
}

स्थिर पूर्णाङ्क
sglob_comp(अचर शून्य *aa, अचर शून्य *bb)
{
	u_int a = *(अचर u_int *)aa;
	u_int b = *(अचर u_int *)bb;
	अचर वर्ण *ap = sort_glob->gl_pathv[a];
	अचर वर्ण *bp = sort_glob->gl_pathv[b];
	अचर संरचना stat *as = sort_glob->gl_statv[a];
	अचर संरचना stat *bs = sort_glob->gl_statv[b];
	पूर्णाङ्क rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	यदि (as == रिक्त || bs == रिक्त)
		फर्काऊ (as == bs) ? 0 : (as == रिक्त ? rmul : -rmul);
	यदि (sort_flag & LS_NAME_SORT)
		फर्काऊ (rmul * म_भेद(ap, bp));
	अन्यथा यदि (sort_flag & LS_TIME_SORT) {
#यदि defined(HAVE_STRUCT_STAT_ST_MTIM)
		यदि (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			फर्काऊ 0;
		फर्काऊ timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#अथवायदि defined(HAVE_STRUCT_STAT_ST_MTIME)
		फर्काऊ (rmul * NCMP(as->st_mtime, bs->st_mtime));
#अन्यथा
	फर्काऊ rmul * 1;
#endif
	} अन्यथा यदि (sort_flag & LS_SIZE_SORT)
		फर्काऊ (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
स्थिर पूर्णाङ्क
do_globbed_ls(संरचना sftp_conn *conn, अचर वर्ण *path,
    अचर वर्ण *strip_path, पूर्णाङ्क lflag)
{
	वर्ण *fname, *lname;
	glob_t g;
	पूर्णाङ्क err, r;
	संरचना winsize ws;
	u_int i, j, nentries, *indices = रिक्त, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	स_रखो(&g, 0, परिमाण(g));

	यदि ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    रिक्त, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		यदि (g.gl_pathc)
			globfree(&g);
		यदि (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} अन्यथा {
			error("Can't ls: \"%s\" not found", path);
		}
		फर्काऊ -1;
	}

	यदि (interrupted)
		गच्छ out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	यदि (g.gl_matchc == 1 && g.gl_statv[0] != रिक्त &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		फर्काऊ err;
	}

	यदि (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	यदि (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		लागि (i = 0; g.gl_pathv[i]; i++)
			m = MAXIMUM(m, म_माप(g.gl_pathv[i]));

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	लागि (nentries = 0; g.gl_pathv[nentries] != रिक्त; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, परिमाण(*indices));
	लागि (i = 0; i < nentries; i++)
		indices[i] = i;

	यदि (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		क्विक(indices, nentries, परिमाण(*indices), sglob_comp);
		sort_glob = रिक्त;
	}

	get_remote_user_groups_from_glob(conn, &g);
	लागि (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		यदि (lflag & LS_LONG_VIEW) {
			अचर वर्ण *user = रिक्त, *group = रिक्त;

			यदि (g.gl_statv[i] == रिक्त) {
				error("no stat information for %s", fname);
				मुक्त(fname);
				जारी;
			}
			यदि ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			मुक्त(lname);
		} अन्यथा {
			mprintf("%-*s", colspace, fname);
			यदि (c >= columns) {
				म_लिखो("\n");
				c = 1;
			} अन्यथा
				c++;
		}
		मुक्त(fname);
	}

	यदि (!(lflag & LS_LONG_VIEW) && (c != 1))
		म_लिखो("\n");

 out:
	यदि (g.gl_pathc)
		globfree(&g);
	मुक्त(indices);

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
do_df(संरचना sftp_conn *conn, अचर वर्ण *path, पूर्णाङ्क hflag, पूर्णाङ्क iflag)
{
	संरचना sftp_statvfs st;
	वर्ण s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	वर्ण s_जरा[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	वर्ण s_icapacity[16], s_dcapacity[16];

	यदि (sftp_statvfs(conn, path, &st, 1) == -1)
		फर्काऊ -1;
	यदि (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", परिमाण(s_icapacity));
	अन्यथा {
		snprintf(s_icapacity, परिमाण(s_icapacity), "%3llu%%",
		    (अचिन्हित दीर्घ दीर्घ)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	यदि (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", परिमाण(s_dcapacity));
	अन्यथा {
		snprintf(s_dcapacity, परिमाण(s_dcapacity), "%3llu%%",
		    (अचिन्हित दीर्घ दीर्घ)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	यदि (iflag) {
		म_लिखो("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		म_लिखो("%11llu %11llu %11llu %11llu         %s\n",
		    (अचिन्हित दीर्घ दीर्घ)st.f_files,
		    (अचिन्हित दीर्घ दीर्घ)(st.f_files - st.f_ffree),
		    (अचिन्हित दीर्घ दीर्घ)st.f_favail,
		    (अचिन्हित दीर्घ दीर्घ)st.f_ffree, s_icapacity);
	} अन्यथा यदि (hflag) {
		strlcpy(s_used, "error", परिमाण(s_used));
		strlcpy(s_avail, "error", परिमाण(s_avail));
		strlcpy(s_जरा, "error", परिमाण(s_जरा));
		strlcpy(s_total, "error", परिमाण(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_जरा);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		म_लिखो("    Size     Used    Avail   (root)    %%Capacity\n");
		म_लिखो("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_जरा, s_dcapacity);
	} अन्यथा {
		म_लिखो("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		म_लिखो("%12llu %12llu %12llu %12llu         %s\n",
		    (अचिन्हित दीर्घ दीर्घ)(st.f_frsize * st.f_blocks / 1024),
		    (अचिन्हित दीर्घ दीर्घ)(st.f_frsize *
		    (st.f_blocks - st.f_bfree) / 1024),
		    (अचिन्हित दीर्घ दीर्घ)(st.f_frsize * st.f_bavail / 1024),
		    (अचिन्हित दीर्घ दीर्घ)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	फर्काऊ 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
स्थिर शून्य
undo_glob_escape(वर्ण *s)
{
	माप_प्रकार i, j;

	लागि (i = j = 0;;) {
		यदि (s[i] == '\0') {
			s[j] = '\0';
			फर्काऊ;
		}
		यदि (s[i] != '\\') {
			s[j++] = s[i++];
			जारी;
		}
		/* s[i] == '\\' */
		++i;
		विकल्प (s[i]) {
		पक्ष '?':
		पक्ष '[':
		पक्ष '*':
		पक्ष '\\':
			s[j++] = s[i++];
			रोक;
		पक्ष '\0':
			s[j++] = '\\';
			s[j] = '\0';
			फर्काऊ;
		स्वभाव:
			s[j++] = '\\';
			s[j++] = s[i++];
			रोक;
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
makeargv(अचर वर्ण *arg, पूर्णाङ्क *argcp, पूर्णाङ्क sloppy, वर्ण *lastquote,
    u_int *terminated)
{
	पूर्णाङ्क argc, quot;
	माप_प्रकार i, j;
	स्थिर वर्ण argvs[MAXARGLEN];
	स्थिर वर्ण *argv[MAXARGS + 1];
	गणना { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	यदि (म_माप(arg) > परिमाण(argvs) - 1) {
 args_too_longs:
		error("string too long");
		फर्काऊ रिक्त;
	}
	यदि (terminated != रिक्त)
		*terminated = 1;
	यदि (lastquote != रिक्त)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	लागि (;;) {
		यदि ((माप_प्रकार)argc >= परिमाण(argv) / परिमाण(*argv)){
			error("Too many arguments.");
			फर्काऊ रिक्त;
		}
		यदि (है_खाली((अचिन्हित वर्ण)arg[i])) {
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
						गच्छ args_too_longs;
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
				गच्छ string_done;
		} अन्यथा यदि (arg[i] == '\0') {
			यदि (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				यदि (sloppy) {
					state = MA_UNQUOTED;
					यदि (terminated != रिक्त)
						*terminated = 0;
					गच्छ string_done;
				}
				error("Unterminated quoted argument");
				फर्काऊ रिक्त;
			}
 string_done:
			यदि (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			रोक;
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
					गच्छ args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} अन्यथा
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	फर्काऊ argv;
}

स्थिर पूर्णाङ्क
parse_args(अचर वर्ण **cpp, पूर्णाङ्क *ignore_errors, पूर्णाङ्क *disable_echo, पूर्णाङ्क *aflag,
	  पूर्णाङ्क *fflag, पूर्णाङ्क *hflag, पूर्णाङ्क *iflag, पूर्णाङ्क *lflag, पूर्णाङ्क *pflag,
	  पूर्णाङ्क *rflag, पूर्णाङ्क *sflag,
    अचिन्हित दीर्घ *n_arg, वर्ण **path1, वर्ण **path2)
{
	अचर वर्ण *cmd, *cp = *cpp;
	वर्ण *cp2, **argv;
	पूर्णाङ्क base = 0;
	दीर्घ दीर्घ ll;
	पूर्णाङ्क path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + म_अखोज(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	लागि (;*cp != '\0'; cp++) {
		यदि (*cp == '-') {
			*ignore_errors = 1;
		} अन्यथा यदि (*cp == '@') {
			*disable_echo = 1;
		} अन्यथा {
			/* all other characters terminate prefix processing */
			रोक;
		}
	}
	cp = cp + म_अखोज(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	यदि (*cp == '\0' || *cp == '#')
		फर्काऊ (0);

	यदि ((argv = makeargv(cp, &argc, 0, रिक्त, रिक्त)) == रिक्त)
		फर्काऊ -1;

	/* Figure out which command we have */
	लागि (i = 0; cmds[i].c != रिक्त; i++) {
		यदि (argv[0] != रिक्त && strcasecmp(cmds[i].c, argv[0]) == 0)
			रोक;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	यदि (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} अन्यथा यदि (cmdnum == -1) {
		error("Invalid command.");
		फर्काऊ -1;
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
			फर्काऊ -1;
		/* Get first pathname (mandatory) */
		यदि (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			फर्काऊ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		यदि (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		रोक;
	पक्ष I_LINK:
		यदि ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			फर्काऊ -1;
		गच्छ parse_two_paths;
	पक्ष I_COPY:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			फर्काऊ -1;
		गच्छ parse_two_paths;
	पक्ष I_RENAME:
		यदि ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			फर्काऊ -1;
		गच्छ parse_two_paths;
	पक्ष I_SYMLINK:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			फर्काऊ -1;
 parse_two_paths:
		यदि (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			फर्काऊ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		रोक;
	पक्ष I_MKDIR:
	पक्ष I_LMKDIR:
		यदि ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			फर्काऊ -1;
		path1_mandatory = 1;
		गच्छ parse_one_path;
	पक्ष I_RM:
	पक्ष I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	पक्ष I_CHDIR:
	पक्ष I_LCHDIR:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			फर्काऊ -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		यदि (argc - optidx < 1) {
			यदि (!path1_mandatory)
				रोक; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			फर्काऊ -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		यदि (cmdnum != I_RM)
			undo_glob_escape(*path1);
		रोक;
	पक्ष I_DF:
		यदि ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			फर्काऊ -1;
		/* Default to current directory if no path specified */
		यदि (argc - optidx < 1)
			*path1 = रिक्त;
		अन्यथा {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		रोक;
	पक्ष I_LS:
		यदि ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			फर्काऊ(-1);
		/* Path is optional */
		यदि (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		रोक;
	पक्ष I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + म_माप(cmd) + म_अखोज(cp, WHITESPACE);
	पक्ष I_SHELL:
		/* Uses the rest of the line */
		रोक;
	पक्ष I_LUMASK:
	पक्ष I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	पक्ष I_CHOWN:
	पक्ष I_CHGRP:
		यदि ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			फर्काऊ -1;
		/* Get numeric arg (mandatory) */
		यदि (argc - optidx < 1)
			गच्छ need_अङ्क_arg;
		त्रुटि_सं = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		यदि (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && त्रुटि_सं == दुस्फल) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_अङ्क_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			फर्काऊ -1;
		}
		*n_arg = ll;
		यदि (cmdnum == I_LUMASK)
			रोक;
		/* Get pathname (mandatory) */
		यदि (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			फर्काऊ -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		रोक;
	पक्ष I_QUIT:
	पक्ष I_PWD:
	पक्ष I_LPWD:
	पक्ष I_HELP:
	पक्ष I_VERSION:
	पक्ष I_PROGRESS:
		यदि ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			फर्काऊ -1;
		रोक;
	स्वभाव:
		fatal("Command not implemented");
	}

	*cpp = cp;
	फर्काऊ(cmdnum);
}

स्थिर पूर्णाङ्क
parse_dispatch_command(संरचना sftp_conn *conn, अचर वर्ण *cmd, वर्ण **pwd,
    अचर वर्ण *startdir, पूर्णाङ्क err_abort, पूर्णाङ्क echo_command)
{
	अचर वर्ण *ocmd = cmd;
	वर्ण *path1, *path2, *tmp;
	पूर्णाङ्क ignore_errors = 0, disable_echo = 1;
	पूर्णाङ्क aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	पूर्णाङ्क lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	पूर्णाङ्क cmdnum, i;
	अचिन्हित दीर्घ n_arg = 0;
	Attrib a, aa;
	वर्ण path_buf[PATH_MAX];
	पूर्णाङ्क err = 0;
	glob_t g;

	path1 = path2 = रिक्त;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	यदि (ignore_errors != 0)
		err_abort = 0;

	यदि (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	स_रखो(&g, 0, परिमाण(g));

	/* Perform command */
	विकल्प (cmdnum) {
	पक्ष 0:
		/* Blank line */
		रोक;
	पक्ष -1:
		/* Unrecognized command */
		err = -1;
		रोक;
	पक्ष I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	पक्ष I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		रोक;
	पक्ष I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	पक्ष I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		रोक;
	पक्ष I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		रोक;
	पक्ष I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		रोक;
	पक्ष I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	पक्ष I_LINK:
		यदि (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		रोक;
	पक्ष I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		लागि (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			यदि (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			यदि (err != 0 && err_abort)
				रोक;
		}
		रोक;
	पक्ष I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		यदि (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		अन्यथा
			err = sftp_mkdir(conn, path1, &a, 1);
		रोक;
	पक्ष I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		रोक;
	पक्ष I_CHDIR:
		यदि (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		यदि ((tmp = sftp_realpath(conn, path1)) == रिक्त) {
			err = 1;
			रोक;
		}
		यदि (sftp_stat(conn, tmp, 0, &aa) != 0) {
			मुक्त(tmp);
			err = 1;
			रोक;
		}
		यदि (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			मुक्त(tmp);
			err = 1;
			रोक;
		}
		यदि (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			मुक्त(tmp);
			err = 1;
			रोक;
		}
		मुक्त(*pwd);
		*pwd = tmp;
		रोक;
	पक्ष I_LS:
		यदि (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			रोक;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = रिक्त;
		यदि (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		रोक;
	पक्ष I_DF:
		/* Default to current directory if no path specified */
		यदि (path1 == रिक्त)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		रोक;
	पक्ष I_LCHDIR:
		यदि (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		मुक्त(path1);
		path1 = tmp;
		यदि (स_बदलो(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, म_त्रुटि(त्रुटि_सं));
			err = 1;
		}
		रोक;
	पक्ष I_LMKDIR:
		यदि (pflag) {
			यदि (mkdir_path(path1, 0777) != 0)
				err = 1;
			रोक;
		}
		यदि (सूची_गढ़ो(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, म_त्रुटि(त्रुटि_सं));
			err = 1;
		}
		रोक;
	पक्ष I_LLS:
		local_do_ls(cmd);
		रोक;
	पक्ष I_SHELL:
		local_do_shell(cmd);
		रोक;
	पक्ष I_LUMASK:
		umask(n_arg);
		म_लिखो("Local umask: %03lo\n", n_arg);
		रोक;
	पक्ष I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		लागि (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			यदि (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			यदि (err != 0 && err_abort)
				रोक;
		}
		रोक;
	पक्ष I_CHOWN:
	पक्ष I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		लागि (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			यदि ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				यदि (err_abort) {
					err = -1;
					रोक;
				} अन्यथा
					जारी;
			}
			यदि (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				यदि (err_abort) {
					err = -1;
					रोक;
				} अन्यथा
					जारी;
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
				रोक;
		}
		रोक;
	पक्ष I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		रोक;
	पक्ष I_LPWD:
		यदि (!getcwd(path_buf, परिमाण(path_buf))) {
			error("Couldn't get local cwd: %s", म_त्रुटि(त्रुटि_सं));
			err = -1;
			रोक;
		}
		mprintf("Local working directory: %s\n", path_buf);
		रोक;
	पक्ष I_QUIT:
		/* Processed below */
		रोक;
	पक्ष I_HELP:
		help();
		रोक;
	पक्ष I_VERSION:
		म_लिखो("SFTP protocol version %u\n", sftp_proto_version(conn));
		रोक;
	पक्ष I_PROGRESS:
		showprogress = !showprogress;
		यदि (showprogress)
			म_लिखो("Progress meter enabled\n");
		अन्यथा
			म_लिखो("Progress meter disabled\n");
		रोक;
	स्वभाव:
		fatal("%d is not implemented", cmdnum);
	}

	यदि (g.gl_pathc)
		globfree(&g);
	मुक्त(path1);
	मुक्त(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	यदि (err_abort && err != 0)
		फर्काऊ (-1);
	अन्यथा यदि (cmdnum == I_QUIT)
		फर्काऊ (1);

	फर्काऊ (0);
}

#ifdef USE_LIBEDIT
स्थिर वर्ण *
prompt(Edit_पङ्क्ति *el)
{
	फर्काऊ ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
स्थिर शून्य
complete_display(वर्ण **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	संरचना winsize ws;
	वर्ण *tmp;

	/* Count entries for sort and find longest */
	लागि (y = 0; list[y]; y++)
		m = MAXIMUM(m, म_माप(list[y]));

	यदि (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	म_लिखो("\n");
	m = 1;
	लागि (y = 0; list[y]; y++) {
		llen = म_माप(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		यदि (m >= columns) {
			म_लिखो("\n");
			m = 1;
		} अन्यथा
			m++;
	}
	म_लिखो("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
स्थिर वर्ण *
complete_ambiguous(अचर वर्ण *word, वर्ण **list, माप_प्रकार गन्ती)
{
	माप_प्रकार i, j, matchlen;
	वर्ण *tmp;
	पूर्णाङ्क len;

	यदि (word == रिक्त)
		फर्काऊ रिक्त;

	यदि (गन्ती == 0)
		फर्काऊ xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = म_माप(list[0]);
	लागि (i = 1; i < गन्ती && list[i] != रिक्त; i++) {
		लागि (j = 0; j < matchlen; j++)
			यदि (list[0][j] != list[i][j])
				रोक;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(रिक्त, 0);
	लागि (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		यदि (len <= 0 || i + (माप_प्रकार)len > matchlen)
			रोक;
		i += (माप_प्रकार)len;
	}
	/* If so, truncate */
	यदि (i < matchlen)
		matchlen = i;

	यदि (matchlen > म_माप(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		फर्काऊ tmp;
	}

	फर्काऊ xstrdup(word);
}

/* Autocomplete a sftp command */
स्थिर पूर्णाङ्क
complete_cmd_parse(Edit_पङ्क्ति *el, वर्ण *cmd, पूर्णाङ्क lastarg, वर्ण quote,
    पूर्णाङ्क terminated)
{
	u_int y, गन्ती = 0, cmdlen, tmplen;
	वर्ण *tmp, **list, argterm[3];
	अचर पङ्क्ति_Info *lf;

	list = xcalloc((परिमाण(cmds) / परिमाण(*cmds)) + 1, परिमाण(वर्ण *));

	/* No command specified: display all available commands */
	यदि (cmd == रिक्त) {
		लागि (y = 0; cmds[y].c; y++)
			list[गन्ती++] = xstrdup(cmds[y].c);

		list[गन्ती] = रिक्त;
		complete_display(list, 0);

		लागि (y = 0; list[y] != रिक्त; y++)
			मुक्त(list[y]);
		मुक्त(list);
		फर्काऊ गन्ती;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = म_माप(cmd);
	लागि (y = 0; cmds[y].c; y++)  {
		यदि (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[गन्ती++] = xstrdup(cmds[y].c);
	}
	list[गन्ती] = रिक्त;

	यदि (गन्ती == 0) {
		मुक्त(list);
		फर्काऊ 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, गन्ती);
	यदि (गन्ती > 1)
		complete_display(list, 0);

	लागि (y = 0; list[y]; y++)
		मुक्त(list[y]);
	मुक्त(list);

	यदि (tmp != रिक्त) {
		tmplen = म_माप(tmp);
		cmdlen = म_माप(cmd);
		/* If cmd may be extended then do so */
		यदि (tmplen > cmdlen)
			यदि (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_पङ्क्ति(el);
		/* Terminate argument cleanly */
		यदि (गन्ती == 1) {
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

	फर्काऊ गन्ती;
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
		फर्काऊ -1;

	लागि (i = 0; cmds[i].c; i++) {
		यदि (!strncasecmp(cmd, cmds[i].c, म_माप(cmds[i].c))) {
			यदि (cmdarg == 1)
				फर्काऊ cmds[i].t;
			अन्यथा यदि (cmdarg == 2)
				फर्काऊ cmds[i].t2;
			रोक;
		}
	}

	फर्काऊ -1;
}

/* Autocomplete a filename "file" */
स्थिर पूर्णाङ्क
complete_match(Edit_पङ्क्ति *el, संरचना sftp_conn *conn, वर्ण *remote_path,
    वर्ण *file, पूर्णाङ्क remote, पूर्णाङ्क lastarg, वर्ण quote, पूर्णाङ्क terminated)
{
	glob_t g;
	वर्ण *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	पूर्णाङ्क clen;
	अचर पङ्क्ति_Info *lf;

	/* Glob from "file" location */
	यदि (file == रिक्त)
		tmp = xstrdup("*");
	अन्यथा
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	स_रखो(&g, 0, परिमाण(g));
	यदि (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);
	} अन्यथा
		(शून्य)glob(tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);

	/* Determine length of pwd so we can trim completion display */
	लागि (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		यदि (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			यदि (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			रोक;
		}
		यदि (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		यदि (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	मुक्त(tmp);
	tmp = रिक्त;

	यदि (g.gl_matchc == 0)
		गच्छ out;

	यदि (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	यदि (file == रिक्त || hadglob)
		गच्छ out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? रिक्त : remote_path);
	मुक्त(tmp2);

	यदि (tmp == रिक्त)
		गच्छ out;

	tmplen = म_माप(tmp);
	filelen = म_माप(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	लागि (i = 0; i < filelen; i++) {
		यदि (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} अन्यथा
			isesc = 0;
	}

	यदि (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = म_माप(tmp2);
		/* quote argument on way out */
		mblen(रिक्त, 0);
		लागि (i = 0; i < len; i += clen) {
			यदि ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (माप_प्रकार)clen > परिमाण(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			स_नकल(ins + 1, tmp2 + i, clen);
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
					रोक;
				}
				/* FALLTHROUGH */
			स्वभाव:
				यदि (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				रोक;
			}
		}
	}

	lf = el_पङ्क्ति(el);
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

 out:
	globfree(&g);
	फर्काऊ g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
स्थिर अचिन्हित वर्ण
complete(Edit_पङ्क्ति *el, पूर्णाङ्क ch)
{
	वर्ण **argv, *पङ्क्ति, quote;
	पूर्णाङ्क argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	अचर पङ्क्ति_Info *lf;
	संरचना complete_ctx *complete_ctx;

	lf = el_पङ्क्ति(el);
	यदि (el_get(el, EL_CLIENTDATA, (शून्य**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	पङ्क्ति = xmalloc(cursor + 1);
	स_नकल(पङ्क्ति, lf->buffer, cursor);
	पङ्क्ति[cursor] = '\0';
	argv = makeargv(पङ्क्ति, &carg, 1, &quote, &terminated);
	मुक्त(पङ्क्ति);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	पङ्क्ति = xmalloc(len + 1);
	स_नकल(पङ्क्ति, lf->buffer, len);
	पङ्क्ति[len] = '\0';
	argv = makeargv(पङ्क्ति, &argc, 1, रिक्त, रिक्त);

	/* Ensure cursor is at EOL or a argument boundary */
	यदि (पङ्क्ति[cursor] != ' ' && पङ्क्ति[cursor] != '\0' &&
	    पङ्क्ति[cursor] != '\n') {
		मुक्त(पङ्क्ति);
		फर्काऊ ret;
	}

	यदि (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, रिक्त, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} अन्यथा यदि (carg == 1 && cursor > 0 && पङ्क्ति[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		यदि (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} अन्यथा यदि (carg >= 1) {
		/* Handle file parsing */
		पूर्णाङ्क remote = 0;
		पूर्णाङ्क i = 0, cmdarg = 0;
		वर्ण *filematch = रिक्त;

		यदि (carg > 1 && पङ्क्ति[cursor-1] != ' ')
			filematch = argv[carg - 1];

		लागि (i = 1; i < carg; i++) {
			/* Skip flags */
			यदि (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		यदि (पङ्क्ति[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		यदि ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	मुक्त(पङ्क्ति);
	फर्काऊ ret;
}
#endif /* USE_LIBEDIT */

स्थिर पूर्णाङ्क
interactive_loop(संरचना sftp_conn *conn, वर्ण *file1, वर्ण *file2)
{
	वर्ण *remote_path;
	वर्ण *dir = रिक्त, *startdir = रिक्त;
	वर्ण cmd[2048];
	पूर्णाङ्क err, interactive;
	Edit_पङ्क्ति *el = रिक्त;
#ifdef USE_LIBEDIT
	अचर वर्ण *editor;
	History *hl = रिक्त;
	HistEvent hev;
	बाह्य वर्ण *__progname;
	संरचना complete_ctx complete_ctx;

	यदि (!batchmode && isatty(STDIN_FILENO)) {
		यदि ((el = el_init(__progname, मानक_निवेश, मानक_निकास, मानक_त्रुटि)) == रिक्त)
			fatal("Couldn't initialise editline");
		यदि ((hl = history_init()) == रिक्त)
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
		यदि (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", रिक्त);
	}
#endif /* USE_LIBEDIT */

	यदि ((remote_path = sftp_realpath(conn, ".")) == रिक्त)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	यदि (file1 != रिक्त) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		यदि (sftp_remote_is_dir(conn, dir) && file2 == रिक्त) {
			यदि (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, परिमाण cmd, "cd \"%s\"", dir);
			यदि (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				मुक्त(dir);
				मुक्त(startdir);
				मुक्त(remote_path);
				मुक्त(conn);
				फर्काऊ (-1);
			}
		} अन्यथा {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			मुक्त(dir);
			मुक्त(startdir);
			मुक्त(remote_path);
			मुक्त(conn);
			फर्काऊ (err);
		}
		मुक्त(dir);
	}

	रखो_भबफ(मानक_निकास, रिक्त, _IOLBF, 0);
	रखो_भबफ(infile, रिक्त, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	लागि (;;) {
		संरचना sigaction sa;

		interrupted = 0;
		स_रखो(&sa, 0, परिमाण(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		यदि (sigaction(संक_विघ्न, &sa, रिक्त) == -1) {
			debug3("sigaction(%s): %s", strsignal(संक_विघ्न),
			    म_त्रुटि(त्रुटि_सं));
			रोक;
		}
		यदि (el == रिक्त) {
			यदि (interactive) {
				म_लिखो("sftp> ");
				ख_साफ(मानक_निकास);
			}
			यदि (ख_माला_लो(cmd, परिमाण(cmd), infile) == रिक्त) {
				यदि (interactive)
					म_लिखो("\n");
				यदि (interrupted)
					जारी;
				रोक;
			}
		} अन्यथा {
#ifdef USE_LIBEDIT
			अचर वर्ण *पङ्क्ति;
			पूर्णाङ्क गन्ती = 0;

			यदि ((पङ्क्ति = el_gets(el, &गन्ती)) == रिक्त ||
			    गन्ती <= 0) {
				म_लिखो("\n");
				यदि (interrupted)
					जारी;
				रोक;
			}
			history(hl, &hev, H_ENTER, पङ्क्ति);
			यदि (strlcpy(cmd, पङ्क्ति, परिमाण(cmd)) >= परिमाण(cmd)) {
				ख_लिखो(मानक_त्रुटि, "Error: input line too long\n");
				जारी;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[म_खोज(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(संक_विघ्न, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == रिक्त);
		यदि (err != 0)
			रोक;
	}
	ssh_signal(SIGCHLD, संक_पूर्व);
	मुक्त(remote_path);
	मुक्त(startdir);
	मुक्त(conn);

#ifdef USE_LIBEDIT
	यदि (hl != रिक्त)
		history_end(hl);
	यदि (el != रिक्त)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	फर्काऊ (err >= 0 ? 0 : -1);
}

स्थिर शून्य
connect_to_server(वर्ण *path, वर्ण **args, पूर्णाङ्क *in, पूर्णाङ्क *out)
{
	पूर्णाङ्क c_in, c_out;
#ifdef USE_PIPES
	पूर्णाङ्क pin[2], pout[2];

	यदि ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", म_त्रुटि(त्रुटि_सं));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#अन्यथा /* USE_PIPES */
	पूर्णाङ्क inout[2];

	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", म_त्रुटि(त्रुटि_सं));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	यदि ((sshpid = विभाजन()) == -1)
		fatal("fork: %s", म_त्रुटि(त्रुटि_सं));
	अन्यथा यदि (sshpid == 0) {
		यदि ((dup2(c_in, STDIN_FILENO) == -1) ||
		    (dup2(c_out, STDOUT_FILENO) == -1)) {
			ख_लिखो(मानक_त्रुटि, "dup2: %s\n", म_त्रुटि(त्रुटि_सं));
			_exit(1);
		}
		बंद(*in);
		बंद(*out);
		बंद(c_in);
		बंद(c_out);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(संक_विघ्न, संक_छोड़ो);
		ssh_signal(संक_इति, संक_पूर्व);
		execvp(path, args);
		ख_लिखो(मानक_त्रुटि, "exec: %s: %s\n", path, म_त्रुटि(त्रुटि_सं));
		_exit(1);
	}

	ssh_signal(संक_इति, killchild);
	ssh_signal(संक_विघ्न, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	बंद(c_in);
	बंद(c_out);
}

स्थिर शून्य
usage(शून्य)
{
	बाह्य वर्ण *__progname;

	ख_लिखो(मानक_त्रुटि,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	निकास(1);
}

पूर्णाङ्क
main(पूर्णाङ्क argc, वर्ण **argv)
{
	पूर्णाङ्क r, in, out, ch, err, tmp, port = -1, noisy = 0;
	वर्ण *host = रिक्त, *user, *cp, **cpp, *file2 = रिक्त;
	पूर्णाङ्क debug_level = 0;
	वर्ण *file1 = रिक्त, *sftp_server = रिक्त;
	वर्ण *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = रिक्त;
	अचर वर्ण *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	बाह्य पूर्णाङ्क optind;
	बाह्य वर्ण *optarg;
	संरचना sftp_conn *conn;
	माप_प्रकार copy_buffer_len = 0;
	माप_प्रकार अङ्क_requests = 0;
	दीर्घ दीर्घ llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	स_रखो(&args, '\0', परिमाण(args));
	args.list = रिक्त;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = मानक_निवेश;

	जबसम्म ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		विकल्प (ch) {
		/* Passed through to ssh(1) */
		पक्ष 'A':
		पक्ष '4':
		पक्ष '6':
		पक्ष 'C':
			addargs(&args, "-%c", ch);
			रोक;
		/* Passed through to ssh(1) with argument */
		पक्ष 'F':
		पक्ष 'J':
		पक्ष 'c':
		पक्ष 'i':
		पक्ष 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			रोक;
		पक्ष 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			रोक;
		पक्ष 'P':
			port = a2port(optarg);
			यदि (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			रोक;
		पक्ष 'v':
			यदि (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			रोक;
		पक्ष '1':
			fatal("SSH protocol v.1 is no longer supported");
			रोक;
		पक्ष '2':
			/* accept silently */
			रोक;
		पक्ष 'a':
			global_aflag = 1;
			रोक;
		पक्ष 'B':
			copy_buffer_len = म_से_दीर्घ(optarg, &cp, 10);
			यदि (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			रोक;
		पक्ष 'b':
			यदि (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			यदि (म_भेद(optarg, "-") != 0 &&
			    (infile = ख_खोलो(optarg, "r")) == रिक्त)
				fatal("%s (%s).", म_त्रुटि(त्रुटि_सं), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			रोक;
		पक्ष 'f':
			global_fflag = 1;
			रोक;
		पक्ष 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			रोक;
		पक्ष 'p':
			global_pflag = 1;
			रोक;
		पक्ष 'D':
			sftp_direct = optarg;
			रोक;
		पक्ष 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			यदि (errstr != रिक्त)
				usage();
			limit_kbps *= 1024; /* kbps */
			रोक;
		पक्ष 'r':
			global_rflag = 1;
			रोक;
		पक्ष 'R':
			अङ्क_requests = म_से_दीर्घ(optarg, &cp, 10);
			यदि (अङ्क_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			रोक;
		पक्ष 's':
			sftp_server = optarg;
			रोक;
		पक्ष 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			रोक;
		पक्ष 'X':
			/* Please keep in sync with ssh.c -X */
			यदि (म_भेदन(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				यदि (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					त्रुटि_सं = EINVAL;
				}
				यदि (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, म_त्रुटि(त्रुटि_सं));
				}
				copy_buffer_len = (माप_प्रकार)llv;
			} अन्यथा यदि (म_भेदन(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				यदि (errstr != रिक्त) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				अङ्क_requests = (माप_प्रकार)llv;
			} अन्यथा {
				fatal("Invalid -X option");
			}
			रोक;
		पक्ष 'h':
		स्वभाव:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	यदि (!isatty(STDERR_FILENO))
		showprogress = 0;

	यदि (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	यदि (sftp_direct == रिक्त) {
		यदि (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		विकल्प (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		पक्ष -1:
			usage();
			रोक;
		पक्ष 0:
			यदि (tmp != -1)
				port = tmp;
			रोक;
		स्वभाव:
			/* Try with user, host and path. */
			यदि (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				रोक;
			/* Try with user and host. */
			यदि (parse_user_host_port(*argv, &user, &host, रिक्त)
			    == 0)
				रोक;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			रोक;
		}
		file2 = *(argv + 1);

		यदि (!*host) {
			ख_लिखो(मानक_त्रुटि, "Missing hostname\n");
			usage();
		}

		यदि (port != -1)
			addargs(&args, "-oPort %d", port);
		यदि (user != रिक्त) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		यदि (sftp_server == रिक्त || म_अक्षर(sftp_server, '/') == रिक्त)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != रिक्त ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} अन्यथा {
		यदि ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		यदि (cpp[0] == रिक्त)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, अङ्क_requests, limit_kbps);
	यदि (conn == रिक्त)
		fatal("Couldn't initialise connection to server");

	यदि (!quiet) {
		यदि (sftp_direct == रिक्त)
			ख_लिखो(मानक_त्रुटि, "Connected to %s.\n", host);
		अन्यथा
			ख_लिखो(मानक_त्रुटि, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#यदि !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	बंद(in);
	बंद(out);
	यदि (batchmode)
		ख_बंद(infile);

	जबसम्म (waitpid(sshpid, रिक्त, 0) == -1 && sshpid > 1)
		यदि (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    म_त्रुटि(त्रुटि_सं));

	निकास(err == 0 ? 0 : 1);
}
