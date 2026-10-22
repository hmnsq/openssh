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
प्रकारव्याख्या शून्य Edit_ओळ;
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
पूर्णांक batchmode = 0;

/* PID of ssh transport process */
स्थिर अस्थिर pid_t sshpid = -1;

/* Suppress diagnostic messages */
पूर्णांक quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
पूर्णांक showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
पूर्णांक global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
पूर्णांक global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
पूर्णांक global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
पूर्णांक global_fflag = 0;

/* SIGINT received during command processing */
अस्थिर संक_पूर्ण_प्रकार interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
पूर्णांक sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
संरचना complete_ctx {
	संरचना sftp_conn *conn;
	अक्षर **remote_pathp;
};

पूर्णांक sftp_glob(संरचना sftp_conn *, स्थिरांक अक्षर *, पूर्णांक,
    पूर्णांक (*)(स्थिरांक अक्षर *, पूर्णांक), glob_t *); /* proto for sftp-glob.c */

बाह्य अक्षर *__progname;

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
	स्थिरांक अक्षर *c;
	स्थिरांक पूर्णांक n;
	स्थिरांक पूर्णांक t;	/* Completion type for the first argument */
	स्थिरांक पूर्णांक t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

स्थिर स्थिरांक संरचना CMD cmds[] = {
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
killchild(पूर्णांक signo)
{
	pid_t pid;

	pid = sshpid;
	जर (pid > 1) {
		समाप्त(pid, संक_इति);
		(शून्य)waitpid(pid, रिक्त, 0);
	}

	_exit(1);
}

स्थिर शून्य
suspchild(पूर्णांक signo)
{
	पूर्णांक save_errno = त्रुटि_सं;
	जर (sshpid > 1) {
		समाप्त(sshpid, signo);
		पर्यंत (waitpid(sshpid, रिक्त, WUNTRACED) == -1 && त्रुटि_सं == EINTR)
			सुरूठेवा;
	}
	समाप्त(getpid(), SIGSTOP);
	त्रुटि_सं = save_errno;
}

स्थिर शून्य
cmd_interrupt(पूर्णांक signo)
{
	स्थिरांक अक्षर संदेश[] = "\rInterrupt  \n";
	पूर्णांक olderrno = त्रुटि_सं;

	(शून्य)लिख(STDERR_FILENO, संदेश, आकार(संदेश) - 1);
	interrupted = 1;
	त्रुटि_सं = olderrno;
}

स्थिर शून्य
read_interrupt(पूर्णांक signo)
{
	interrupted = 1;
}

स्थिर शून्य
sigchld_handler(पूर्णांक sig)
{
	पूर्णांक save_errno = त्रुटि_सं;
	pid_t pid;
	स्थिरांक अक्षर संदेश[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	पर्यंत ((pid = waitpid(sshpid, रिक्त, WNOHANG)) == -1 && त्रुटि_सं == EINTR)
		सुरूठेवा;
	जर (pid == sshpid) {
		जर (!quiet)
		    (शून्य)लिख(STDERR_FILENO, संदेश, आकार(संदेश) - 1);
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
local_do_shell(स्थिरांक अक्षर *args)
{
	पूर्णांक status;
	अक्षर *shell;
	pid_t pid;

	जर (!*args)
		args = रिक्त;

	जर ((shell = दो_पर्या("SHELL")) == रिक्त || *shell == '\0')
		shell = _PATH_BSHELL;

	जर ((pid = विभाजन()) == -1)
		fatal("Couldn't fork: %s", म_त्रुटि(त्रुटि_सं));

	जर (pid == 0) {
		जर (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (अक्षर *)रिक्त);
		} अन्यथा {
			debug3("Executing %s", shell);
			execl(shell, shell, (अक्षर *)रिक्त);
		}
		ख_लिखो(मानक_त्रुटि, "Couldn't execute \"%s\": %s\n", shell,
		    म_त्रुटि(त्रुटि_सं));
		_exit(1);
	}
	पर्यंत (waitpid(pid, &status, 0) == -1)
		जर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));
	जर (!WIFEXITED(status))
		error("Shell exited abnormally");
	अन्यथा जर (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

स्थिर शून्य
local_do_ls(स्थिरांक अक्षर *args)
{
	जर (!args || !*args)
		local_do_shell(_PATH_LS);
	अन्यथा {
		पूर्णांक len = म_माप(_PATH_LS " ") + म_माप(args) + 1;
		अक्षर *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		मुक्त(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
स्थिर अक्षर *
path_strip(स्थिरांक अक्षर *path, स्थिरांक अक्षर *strip)
{
	माप_प्रकार len;

	जर (strip == रिक्त || (len = म_माप(strip)) == 0)
		परत (xstrdup(path));

	जर (म_भेदन(path, strip, len) == 0) {
		जर (strip[len - 1] != '/' && path[len] == '/')
			len++;
		परत (xstrdup(path + len));
	}

	परत (xstrdup(path));
}

स्थिर पूर्णांक
parse_getput_flags(स्थिरांक अक्षर *cmd, अक्षर **argv, पूर्णांक argc,
    पूर्णांक *aflag, पूर्णांक *fflag, पूर्णांक *pflag, पूर्णांक *rflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	पर्यंत ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		निवड (ch) {
		स्थिती 'a':
			*aflag = 1;
			थांबा;
		स्थिती 'f':
			*fflag = 1;
			थांबा;
		स्थिती 'p':
		स्थिती 'P':
			*pflag = 1;
			थांबा;
		स्थिती 'r':
		स्थिती 'R':
			*rflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			error("%s: Invalid flag -%c", cmd, optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर पूर्णांक
parse_mkdir_flags(स्थिरांक अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *pflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	पर्यंत ((ch = getopt(argc, argv, "p")) != -1) {
		निवड (ch) {
		स्थिती 'p':
			*pflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			error("%s: Invalid flag -%c", cmd, optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर पूर्णांक
parse_link_flags(स्थिरांक अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *sflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	पर्यंत ((ch = getopt(argc, argv, "s")) != -1) {
		निवड (ch) {
		स्थिती 's':
			*sflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			error("%s: Invalid flag -%c", cmd, optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर पूर्णांक
parse_rename_flags(स्थिरांक अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *lflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	पर्यंत ((ch = getopt(argc, argv, "l")) != -1) {
		निवड (ch) {
		स्थिती 'l':
			*lflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			error("%s: Invalid flag -%c", cmd, optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर पूर्णांक
parse_ls_flags(अक्षर **argv, पूर्णांक argc, पूर्णांक *lflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	पर्यंत ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		निवड (ch) {
		स्थिती '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			थांबा;
		स्थिती 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			थांबा;
		स्थिती 'a':
			*lflag |= LS_SHOW_ALL;
			थांबा;
		स्थिती 'f':
			*lflag &= ~SORT_FLAGS;
			थांबा;
		स्थिती 'h':
			*lflag |= LS_SI_UNITS;
			थांबा;
		स्थिती 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			थांबा;
		स्थिती 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			थांबा;
		स्थिती 'r':
			*lflag |= LS_REVERSE_SORT;
			थांबा;
		स्थिती 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			थांबा;
		पूर्वनिर्धारित:
			error("ls: Invalid flag -%c", optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर पूर्णांक
parse_df_flags(स्थिरांक अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *hflag, पूर्णांक *iflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	पर्यंत ((ch = getopt(argc, argv, "hi")) != -1) {
		निवड (ch) {
		स्थिती 'h':
			*hflag = 1;
			थांबा;
		स्थिती 'i':
			*iflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			error("%s: Invalid flag -%c", cmd, optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर पूर्णांक
parse_ch_flags(स्थिरांक अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *hflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	पर्यंत ((ch = getopt(argc, argv, "h")) != -1) {
		निवड (ch) {
		स्थिती 'h':
			*hflag = 1;
			थांबा;
		पूर्वनिर्धारित:
			error("%s: Invalid flag -%c", cmd, optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर पूर्णांक
parse_no_flags(स्थिरांक अक्षर *cmd, अक्षर **argv, पूर्णांक argc)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	पर्यंत ((ch = getopt(argc, argv, "")) != -1) {
		निवड (ch) {
		पूर्वनिर्धारित:
			error("%s: Invalid flag -%c", cmd, optopt);
			परत -1;
		}
	}

	परत optind;
}

स्थिर अक्षर *
escape_glob(स्थिरांक अक्षर *s)
{
	माप_प्रकार i, o, len;
	अक्षर *ret;

	len = म_माप(s);
	ret = xcalloc(2, len + 1);
	साठी (i = o = 0; i < len; i++) {
		जर (म_अक्षर("[]?*\\", s[i]) != रिक्त)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	परत ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
स्थिर अक्षर *
make_absolute_pwd_glob(अक्षर *p, स्थिरांक अक्षर *pwd)
{
	अक्षर *ret, *escpwd;

	escpwd = escape_glob(pwd);
	जर (p == रिक्त)
		परत escpwd;
	ret = sftp_make_absolute(p, escpwd);
	मुक्त(escpwd);
	परत ret;
}

स्थिर पूर्णांक
local_is_dir(स्थिरांक अक्षर *path)
{
	संरचना stat sb;

	जर (stat(path, &sb) == -1)
		परत 0;
	परत S_ISDIR(sb.st_mode);
}

स्थिर पूर्णांक
process_get(संरचना sftp_conn *conn, स्थिरांक अक्षर *src, स्थिरांक अक्षर *dst,
    स्थिरांक अक्षर *pwd, पूर्णांक pflag, पूर्णांक rflag, पूर्णांक resume, पूर्णांक fflag)
{
	अक्षर *filename, *abs_src = रिक्त, *abs_dst = रिक्त, *tmp = रिक्त;
	glob_t g;
	पूर्णांक i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	स_रखो(&g, 0, आकार(g));

	debug3("Looking up %s", abs_src);
	जर ((r = sftp_glob(conn, abs_src, GLOB_MARK, रिक्त, &g)) != 0) {
		जर (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} अन्यथा {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		जा out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	जर (g.gl_matchc > 1 && dst != रिक्त && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		जा out;
	}

	साठी (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		जर ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			मुक्त(tmp);
			err = -1;
			जा out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		जर (म_भेद(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[म_अखोज(filename, "/")] == '\0'))
			filename = ".";

		जर (g.gl_matchc == 1 && dst) {
			जर (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} अन्यथा {
				abs_dst = xstrdup(dst);
			}
		} अन्यथा जर (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} अन्यथा {
			abs_dst = xstrdup(filename);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		जर (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अन्यथा जर (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		जर (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			जर (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    रिक्त, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अन्यथा {
			जर (sftp_download(conn, g.gl_pathv[i], abs_dst, रिक्त,
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
	परत(err);
}

स्थिर पूर्णांक
process_put(संरचना sftp_conn *conn, स्थिरांक अक्षर *src, स्थिरांक अक्षर *dst,
    स्थिरांक अक्षर *pwd, पूर्णांक pflag, पूर्णांक rflag, पूर्णांक resume, पूर्णांक fflag)
{
	अक्षर *tmp_dst = रिक्त;
	अक्षर *abs_dst = रिक्त;
	अक्षर *tmp = रिक्त, *filename = रिक्त;
	glob_t g;
	पूर्णांक err = 0;
	पूर्णांक i, dst_is_dir = 1;
	संरचना stat sb;

	जर (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	स_रखो(&g, 0, आकार(g));
	debug3("Looking up %s", src);
	जर (glob(src, GLOB_NOCHECK | GLOB_MARK, रिक्त, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		जा out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	जर (tmp_dst != रिक्त)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	जर (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		जा out;
	}

	साठी (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		जर (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], म_त्रुटि(त्रुटि_सं));
			सुरूठेवा;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		जर ((filename = basename(tmp)) == रिक्त) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			मुक्त(tmp);
			err = -1;
			जा out;
		}
		/* Special handling for source of '..' */
		जर (म_भेद(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		मुक्त(abs_dst);
		abs_dst = रिक्त;
		जर (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			जर (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			अन्यथा
				abs_dst = xstrdup(tmp_dst);
		} अन्यथा जर (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} अन्यथा {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		जर (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अन्यथा जर (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		जर (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			जर (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अन्यथा {
			जर (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	मुक्त(abs_dst);
	मुक्त(tmp_dst);
	globfree(&g);
	परत(err);
}

स्थिर पूर्णांक
sdirent_comp(स्थिरांक शून्य *aa, स्थिरांक शून्य *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	पूर्णांक rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	जर (sort_flag & LS_NAME_SORT)
		परत (rmul * म_भेद(a->filename, b->filename));
	अन्यथा जर (sort_flag & LS_TIME_SORT)
		परत (rmul * NCMP(a->a.mtime, b->a.mtime));
	अन्यथा जर (sort_flag & LS_SIZE_SORT)
		परत (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
स्थिर पूर्णांक
do_ls_dir(संरचना sftp_conn *conn, स्थिरांक अक्षर *path,
    स्थिरांक अक्षर *strip_path, पूर्णांक lflag)
{
	पूर्णांक n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	जर ((n = sftp_readdir(conn, path, &d)) != 0)
		परत (n);

	जर (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		संरचना winsize ws;
		अक्षर *tmp;

		/* Count entries for sort and find longest filename */
		साठी (n = 0; d[n] != रिक्त; n++) {
			जर (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, म_माप(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += म_माप(tmp);
		मुक्त(tmp);

		जर (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	जर (lflag & SORT_FLAGS) {
		साठी (n = 0; d[n] != रिक्त; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		क्विक(d, n, आकार(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	साठी (n = 0; d[n] != रिक्त && !interrupted; n++) {
		अक्षर *tmp, *fname;

		जर (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			सुरूठेवा;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		मुक्त(tmp);

		जर (lflag & LS_LONG_VIEW) {
			जर ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				अक्षर *lname;
				संरचना stat sb;
				स्थिरांक अक्षर *user = रिक्त, *group = रिक्त;

				स_रखो(&sb, 0, आकार(sb));
				attrib_to_stat(&d[n]->a, &sb);
				जर ((lflag & LS_NUMERIC_VIEW) == 0) {
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
			जर (c >= columns) {
				म_लिखो("\n");
				c = 1;
			} अन्यथा
				c++;
		}

		मुक्त(fname);
	}

	जर (!(lflag & LS_LONG_VIEW) && (c != 1))
		म_लिखो("\n");

	sftp_free_dirents(d);
	परत (0);
}

स्थिर पूर्णांक
sglob_comp(स्थिरांक शून्य *aa, स्थिरांक शून्य *bb)
{
	u_int a = *(स्थिरांक u_int *)aa;
	u_int b = *(स्थिरांक u_int *)bb;
	स्थिरांक अक्षर *ap = sort_glob->gl_pathv[a];
	स्थिरांक अक्षर *bp = sort_glob->gl_pathv[b];
	स्थिरांक संरचना stat *as = sort_glob->gl_statv[a];
	स्थिरांक संरचना stat *bs = sort_glob->gl_statv[b];
	पूर्णांक rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	जर (as == रिक्त || bs == रिक्त)
		परत (as == bs) ? 0 : (as == रिक्त ? rmul : -rmul);
	जर (sort_flag & LS_NAME_SORT)
		परत (rmul * म_भेद(ap, bp));
	अन्यथा जर (sort_flag & LS_TIME_SORT) {
#जर defined(HAVE_STRUCT_STAT_ST_MTIM)
		जर (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			परत 0;
		परत timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#किंवाजर defined(HAVE_STRUCT_STAT_ST_MTIME)
		परत (rmul * NCMP(as->st_mtime, bs->st_mtime));
#अन्यथा
	परत rmul * 1;
#endif
	} अन्यथा जर (sort_flag & LS_SIZE_SORT)
		परत (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
स्थिर पूर्णांक
do_globbed_ls(संरचना sftp_conn *conn, स्थिरांक अक्षर *path,
    स्थिरांक अक्षर *strip_path, पूर्णांक lflag)
{
	अक्षर *fname, *lname;
	glob_t g;
	पूर्णांक err, r;
	संरचना winsize ws;
	u_int i, j, nentries, *indices = रिक्त, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	स_रखो(&g, 0, आकार(g));

	जर ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    रिक्त, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		जर (g.gl_pathc)
			globfree(&g);
		जर (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} अन्यथा {
			error("Can't ls: \"%s\" not found", path);
		}
		परत -1;
	}

	जर (interrupted)
		जा out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	जर (g.gl_matchc == 1 && g.gl_statv[0] != रिक्त &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		परत err;
	}

	जर (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	जर (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		साठी (i = 0; g.gl_pathv[i]; i++)
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
	साठी (nentries = 0; g.gl_pathv[nentries] != रिक्त; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, आकार(*indices));
	साठी (i = 0; i < nentries; i++)
		indices[i] = i;

	जर (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		क्विक(indices, nentries, आकार(*indices), sglob_comp);
		sort_glob = रिक्त;
	}

	get_remote_user_groups_from_glob(conn, &g);
	साठी (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		जर (lflag & LS_LONG_VIEW) {
			स्थिरांक अक्षर *user = रिक्त, *group = रिक्त;

			जर (g.gl_statv[i] == रिक्त) {
				error("no stat information for %s", fname);
				मुक्त(fname);
				सुरूठेवा;
			}
			जर ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			मुक्त(lname);
		} अन्यथा {
			mprintf("%-*s", colspace, fname);
			जर (c >= columns) {
				म_लिखो("\n");
				c = 1;
			} अन्यथा
				c++;
		}
		मुक्त(fname);
	}

	जर (!(lflag & LS_LONG_VIEW) && (c != 1))
		म_लिखो("\n");

 out:
	जर (g.gl_pathc)
		globfree(&g);
	मुक्त(indices);

	परत 0;
}

स्थिर पूर्णांक
do_df(संरचना sftp_conn *conn, स्थिरांक अक्षर *path, पूर्णांक hflag, पूर्णांक iflag)
{
	संरचना sftp_statvfs st;
	अक्षर s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	अक्षर s_मूळ[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	अक्षर s_icapacity[16], s_dcapacity[16];

	जर (sftp_statvfs(conn, path, &st, 1) == -1)
		परत -1;
	जर (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", आकार(s_icapacity));
	अन्यथा {
		snprintf(s_icapacity, आकार(s_icapacity), "%3llu%%",
		    (अचिन्हित दीर्घ दीर्घ)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	जर (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", आकार(s_dcapacity));
	अन्यथा {
		snprintf(s_dcapacity, आकार(s_dcapacity), "%3llu%%",
		    (अचिन्हित दीर्घ दीर्घ)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	जर (iflag) {
		म_लिखो("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		म_लिखो("%11llu %11llu %11llu %11llu         %s\n",
		    (अचिन्हित दीर्घ दीर्घ)st.f_files,
		    (अचिन्हित दीर्घ दीर्घ)(st.f_files - st.f_ffree),
		    (अचिन्हित दीर्घ दीर्घ)st.f_favail,
		    (अचिन्हित दीर्घ दीर्घ)st.f_ffree, s_icapacity);
	} अन्यथा जर (hflag) {
		strlcpy(s_used, "error", आकार(s_used));
		strlcpy(s_avail, "error", आकार(s_avail));
		strlcpy(s_मूळ, "error", आकार(s_मूळ));
		strlcpy(s_total, "error", आकार(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_मूळ);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		म_लिखो("    Size     Used    Avail   (root)    %%Capacity\n");
		म_लिखो("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_मूळ, s_dcapacity);
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
	परत 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
स्थिर शून्य
undo_glob_escape(अक्षर *s)
{
	माप_प्रकार i, j;

	साठी (i = j = 0;;) {
		जर (s[i] == '\0') {
			s[j] = '\0';
			परत;
		}
		जर (s[i] != '\\') {
			s[j++] = s[i++];
			सुरूठेवा;
		}
		/* s[i] == '\\' */
		++i;
		निवड (s[i]) {
		स्थिती '?':
		स्थिती '[':
		स्थिती '*':
		स्थिती '\\':
			s[j++] = s[i++];
			थांबा;
		स्थिती '\0':
			s[j++] = '\\';
			s[j] = '\0';
			परत;
		पूर्वनिर्धारित:
			s[j++] = '\\';
			s[j++] = s[i++];
			थांबा;
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
स्थिर अक्षर **
makeargv(स्थिरांक अक्षर *arg, पूर्णांक *argcp, पूर्णांक sloppy, अक्षर *lastquote,
    u_int *terminated)
{
	पूर्णांक argc, quot;
	माप_प्रकार i, j;
	स्थिर अक्षर argvs[MAXARGLEN];
	स्थिर अक्षर *argv[MAXARGS + 1];
	गणना { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	जर (म_माप(arg) > आकार(argvs) - 1) {
 args_too_longs:
		error("string too long");
		परत रिक्त;
	}
	जर (terminated != रिक्त)
		*terminated = 1;
	जर (lastquote != रिक्त)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	साठी (;;) {
		जर ((माप_प्रकार)argc >= आकार(argv) / आकार(*argv)){
			error("Too many arguments.");
			परत रिक्त;
		}
		जर (है_खाली((अचिन्हित अक्षर)arg[i])) {
			जर (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} अन्यथा जर (state != MA_START)
				argvs[j++] = arg[i];
		} अन्यथा जर (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			जर (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				जर (lastquote != रिक्त)
					*lastquote = arg[i];
			} अन्यथा जर (state == MA_UNQUOTED)
				state = q;
			अन्यथा जर (state == q)
				state = MA_UNQUOTED;
			अन्यथा
				argvs[j++] = arg[i];
		} अन्यथा जर (arg[i] == '\\') {
			जर (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				जर (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} अन्यथा जर (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					जर (j >= आकार(argvs) - 5)
						जा args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} अन्यथा {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} अन्यथा {
				जर (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					जर (lastquote != रिक्त)
						*lastquote = '\0';
				}
				जर (arg[i + 1] == '?' || arg[i + 1] == '[' ||
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
					जर (arg[i] == '\0')
						जा early_nul;
					argvs[j++] = arg[i];
				}
			}
		} अन्यथा जर (arg[i] == '#') {
			जर (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			अन्यथा
				जा string_done;
		} अन्यथा जर (arg[i] == '\0') {
			जर (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				जर (sloppy) {
					state = MA_UNQUOTED;
					जर (terminated != रिक्त)
						*terminated = 0;
					जा string_done;
				}
				error("Unterminated quoted argument");
				परत रिक्त;
			}
 string_done:
			जर (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			थांबा;
		} अन्यथा {
			जर (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				जर (lastquote != रिक्त)
					*lastquote = '\0';
			}
			जर ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				जर (j >= आकार(argvs) - 3)
					जा args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} अन्यथा
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	परत argv;
}

स्थिर पूर्णांक
parse_args(स्थिरांक अक्षर **cpp, पूर्णांक *ignore_errors, पूर्णांक *disable_echo, पूर्णांक *aflag,
	  पूर्णांक *fflag, पूर्णांक *hflag, पूर्णांक *iflag, पूर्णांक *lflag, पूर्णांक *pflag,
	  पूर्णांक *rflag, पूर्णांक *sflag,
    अचिन्हित दीर्घ *n_arg, अक्षर **path1, अक्षर **path2)
{
	स्थिरांक अक्षर *cmd, *cp = *cpp;
	अक्षर *cp2, **argv;
	पूर्णांक base = 0;
	दीर्घ दीर्घ ll;
	पूर्णांक path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + म_अखोज(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	साठी (;*cp != '\0'; cp++) {
		जर (*cp == '-') {
			*ignore_errors = 1;
		} अन्यथा जर (*cp == '@') {
			*disable_echo = 1;
		} अन्यथा {
			/* all other characters terminate prefix processing */
			थांबा;
		}
	}
	cp = cp + म_अखोज(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	जर (*cp == '\0' || *cp == '#')
		परत (0);

	जर ((argv = makeargv(cp, &argc, 0, रिक्त, रिक्त)) == रिक्त)
		परत -1;

	/* Figure out which command we have */
	साठी (i = 0; cmds[i].c != रिक्त; i++) {
		जर (argv[0] != रिक्त && strcasecmp(cmds[i].c, argv[0]) == 0)
			थांबा;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	जर (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} अन्यथा जर (cmdnum == -1) {
		error("Invalid command.");
		परत -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = रिक्त;
	optidx = 1;
	निवड (cmdnum) {
	स्थिती I_GET:
	स्थिती I_REGET:
	स्थिती I_REPUT:
	स्थिती I_PUT:
		जर ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			परत -1;
		/* Get first pathname (mandatory) */
		जर (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			परत -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		जर (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		थांबा;
	स्थिती I_LINK:
		जर ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			परत -1;
		जा parse_two_paths;
	स्थिती I_COPY:
		जर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			परत -1;
		जा parse_two_paths;
	स्थिती I_RENAME:
		जर ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			परत -1;
		जा parse_two_paths;
	स्थिती I_SYMLINK:
		जर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			परत -1;
 parse_two_paths:
		जर (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			परत -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		थांबा;
	स्थिती I_MKDIR:
	स्थिती I_LMKDIR:
		जर ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			परत -1;
		path1_mandatory = 1;
		जा parse_one_path;
	स्थिती I_RM:
	स्थिती I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	स्थिती I_CHDIR:
	स्थिती I_LCHDIR:
		जर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			परत -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		जर (argc - optidx < 1) {
			जर (!path1_mandatory)
				थांबा; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			परत -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		जर (cmdnum != I_RM)
			undo_glob_escape(*path1);
		थांबा;
	स्थिती I_DF:
		जर ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			परत -1;
		/* Default to current directory if no path specified */
		जर (argc - optidx < 1)
			*path1 = रिक्त;
		अन्यथा {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		थांबा;
	स्थिती I_LS:
		जर ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			परत(-1);
		/* Path is optional */
		जर (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		थांबा;
	स्थिती I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + म_माप(cmd) + म_अखोज(cp, WHITESPACE);
	स्थिती I_SHELL:
		/* Uses the rest of the line */
		थांबा;
	स्थिती I_LUMASK:
	स्थिती I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	स्थिती I_CHOWN:
	स्थिती I_CHGRP:
		जर ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			परत -1;
		/* Get numeric arg (mandatory) */
		जर (argc - optidx < 1)
			जा need_अंक_arg;
		त्रुटि_सं = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		जर (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && त्रुटि_सं == दुस्फल) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_अंक_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			परत -1;
		}
		*n_arg = ll;
		जर (cmdnum == I_LUMASK)
			थांबा;
		/* Get pathname (mandatory) */
		जर (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			परत -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		थांबा;
	स्थिती I_QUIT:
	स्थिती I_PWD:
	स्थिती I_LPWD:
	स्थिती I_HELP:
	स्थिती I_VERSION:
	स्थिती I_PROGRESS:
		जर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			परत -1;
		थांबा;
	पूर्वनिर्धारित:
		fatal("Command not implemented");
	}

	*cpp = cp;
	परत(cmdnum);
}

स्थिर पूर्णांक
parse_dispatch_command(संरचना sftp_conn *conn, स्थिरांक अक्षर *cmd, अक्षर **pwd,
    स्थिरांक अक्षर *startdir, पूर्णांक err_abort, पूर्णांक echo_command)
{
	स्थिरांक अक्षर *ocmd = cmd;
	अक्षर *path1, *path2, *tmp;
	पूर्णांक ignore_errors = 0, disable_echo = 1;
	पूर्णांक aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	पूर्णांक lflag = 0, pflag = 0, rflag = 0, sflag = 0;
	पूर्णांक cmdnum, i;
	अचिन्हित दीर्घ n_arg = 0;
	Attrib a, aa;
	अक्षर path_buf[PATH_MAX];
	पूर्णांक err = 0;
	glob_t g;

	path1 = path2 = रिक्त;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	जर (ignore_errors != 0)
		err_abort = 0;

	जर (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	स_रखो(&g, 0, आकार(g));

	/* Perform command */
	निवड (cmdnum) {
	स्थिती 0:
		/* Blank line */
		थांबा;
	स्थिती -1:
		/* Unrecognized command */
		err = -1;
		थांबा;
	स्थिती I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	स्थिती I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		थांबा;
	स्थिती I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	स्थिती I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		थांबा;
	स्थिती I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		थांबा;
	स्थिती I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		थांबा;
	स्थिती I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	स्थिती I_LINK:
		जर (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		थांबा;
	स्थिती I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		साठी (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			जर (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			जर (err != 0 && err_abort)
				थांबा;
		}
		थांबा;
	स्थिती I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		जर (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		अन्यथा
			err = sftp_mkdir(conn, path1, &a, 1);
		थांबा;
	स्थिती I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		थांबा;
	स्थिती I_CHDIR:
		जर (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		जर ((tmp = sftp_realpath(conn, path1)) == रिक्त) {
			err = 1;
			थांबा;
		}
		जर (sftp_stat(conn, tmp, 0, &aa) != 0) {
			मुक्त(tmp);
			err = 1;
			थांबा;
		}
		जर (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			मुक्त(tmp);
			err = 1;
			थांबा;
		}
		जर (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			मुक्त(tmp);
			err = 1;
			थांबा;
		}
		मुक्त(*pwd);
		*pwd = tmp;
		थांबा;
	स्थिती I_LS:
		जर (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			थांबा;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = रिक्त;
		जर (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		थांबा;
	स्थिती I_DF:
		/* Default to current directory if no path specified */
		जर (path1 == रिक्त)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		थांबा;
	स्थिती I_LCHDIR:
		जर (path1 == रिक्त || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		मुक्त(path1);
		path1 = tmp;
		जर (स_बदलो(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, म_त्रुटि(त्रुटि_सं));
			err = 1;
		}
		थांबा;
	स्थिती I_LMKDIR:
		जर (pflag) {
			जर (mkdir_path(path1, 0777) != 0)
				err = 1;
			थांबा;
		}
		जर (सूची_गढ़ो(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, म_त्रुटि(त्रुटि_सं));
			err = 1;
		}
		थांबा;
	स्थिती I_LLS:
		local_do_ls(cmd);
		थांबा;
	स्थिती I_SHELL:
		local_do_shell(cmd);
		थांबा;
	स्थिती I_LUMASK:
		umask(n_arg);
		म_लिखो("Local umask: %03lo\n", n_arg);
		थांबा;
	स्थिती I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		साठी (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			जर (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			जर (err != 0 && err_abort)
				थांबा;
		}
		थांबा;
	स्थिती I_CHOWN:
	स्थिती I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, रिक्त, &g);
		साठी (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			जर ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				जर (err_abort) {
					err = -1;
					थांबा;
				} अन्यथा
					सुरूठेवा;
			}
			जर (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				जर (err_abort) {
					err = -1;
					थांबा;
				} अन्यथा
					सुरूठेवा;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			जर (cmdnum == I_CHOWN) {
				जर (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} अन्यथा {
				जर (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			जर (err != 0 && err_abort)
				थांबा;
		}
		थांबा;
	स्थिती I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		थांबा;
	स्थिती I_LPWD:
		जर (!getcwd(path_buf, आकार(path_buf))) {
			error("Couldn't get local cwd: %s", म_त्रुटि(त्रुटि_सं));
			err = -1;
			थांबा;
		}
		mprintf("Local working directory: %s\n", path_buf);
		थांबा;
	स्थिती I_QUIT:
		/* Processed below */
		थांबा;
	स्थिती I_HELP:
		help();
		थांबा;
	स्थिती I_VERSION:
		म_लिखो("SFTP protocol version %u\n", sftp_proto_version(conn));
		थांबा;
	स्थिती I_PROGRESS:
		showprogress = !showprogress;
		जर (showprogress)
			म_लिखो("Progress meter enabled\n");
		अन्यथा
			म_लिखो("Progress meter disabled\n");
		थांबा;
	पूर्वनिर्धारित:
		fatal("%d is not implemented", cmdnum);
	}

	जर (g.gl_pathc)
		globfree(&g);
	मुक्त(path1);
	मुक्त(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	जर (err_abort && err != 0)
		परत (-1);
	अन्यथा जर (cmdnum == I_QUIT)
		परत (1);

	परत (0);
}

#ifdef USE_LIBEDIT
स्थिर अक्षर *
prompt(Edit_ओळ *el)
{
	परत ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
स्थिर शून्य
complete_display(अक्षर **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	संरचना winsize ws;
	अक्षर *tmp;

	/* Count entries for sort and find longest */
	साठी (y = 0; list[y]; y++)
		m = MAXIMUM(m, म_माप(list[y]));

	जर (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	म_लिखो("\n");
	m = 1;
	साठी (y = 0; list[y]; y++) {
		llen = म_माप(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		जर (m >= columns) {
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
स्थिर अक्षर *
complete_ambiguous(स्थिरांक अक्षर *word, अक्षर **list, माप_प्रकार मोजणी)
{
	माप_प्रकार i, j, matchlen;
	अक्षर *tmp;
	पूर्णांक len;

	जर (word == रिक्त)
		परत रिक्त;

	जर (मोजणी == 0)
		परत xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = म_माप(list[0]);
	साठी (i = 1; i < मोजणी && list[i] != रिक्त; i++) {
		साठी (j = 0; j < matchlen; j++)
			जर (list[0][j] != list[i][j])
				थांबा;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(रिक्त, 0);
	साठी (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		जर (len <= 0 || i + (माप_प्रकार)len > matchlen)
			थांबा;
		i += (माप_प्रकार)len;
	}
	/* If so, truncate */
	जर (i < matchlen)
		matchlen = i;

	जर (matchlen > म_माप(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		परत tmp;
	}

	परत xstrdup(word);
}

/* Autocomplete a sftp command */
स्थिर पूर्णांक
complete_cmd_parse(Edit_ओळ *el, अक्षर *cmd, पूर्णांक lastarg, अक्षर quote,
    पूर्णांक terminated)
{
	u_int y, मोजणी = 0, cmdlen, tmplen;
	अक्षर *tmp, **list, argterm[3];
	स्थिरांक ओळ_Info *lf;

	list = xcalloc((आकार(cmds) / आकार(*cmds)) + 1, आकार(अक्षर *));

	/* No command specified: display all available commands */
	जर (cmd == रिक्त) {
		साठी (y = 0; cmds[y].c; y++)
			list[मोजणी++] = xstrdup(cmds[y].c);

		list[मोजणी] = रिक्त;
		complete_display(list, 0);

		साठी (y = 0; list[y] != रिक्त; y++)
			मुक्त(list[y]);
		मुक्त(list);
		परत मोजणी;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = म_माप(cmd);
	साठी (y = 0; cmds[y].c; y++)  {
		जर (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[मोजणी++] = xstrdup(cmds[y].c);
	}
	list[मोजणी] = रिक्त;

	जर (मोजणी == 0) {
		मुक्त(list);
		परत 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, मोजणी);
	जर (मोजणी > 1)
		complete_display(list, 0);

	साठी (y = 0; list[y]; y++)
		मुक्त(list[y]);
	मुक्त(list);

	जर (tmp != रिक्त) {
		tmplen = म_माप(tmp);
		cmdlen = म_माप(cmd);
		/* If cmd may be extended then do so */
		जर (tmplen > cmdlen)
			जर (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_ओळ(el);
		/* Terminate argument cleanly */
		जर (मोजणी == 1) {
			y = 0;
			जर (!terminated)
				argterm[y++] = quote;
			जर (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			जर (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		मुक्त(tmp);
	}

	परत मोजणी;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
स्थिर पूर्णांक
complete_is_remote(अक्षर *cmd, पूर्णांक cmdarg) {
	पूर्णांक i;

	जर (cmd == रिक्त)
		परत -1;

	साठी (i = 0; cmds[i].c; i++) {
		जर (!strncasecmp(cmd, cmds[i].c, म_माप(cmds[i].c))) {
			जर (cmdarg == 1)
				परत cmds[i].t;
			अन्यथा जर (cmdarg == 2)
				परत cmds[i].t2;
			थांबा;
		}
	}

	परत -1;
}

/* Autocomplete a filename "file" */
स्थिर पूर्णांक
complete_match(Edit_ओळ *el, संरचना sftp_conn *conn, अक्षर *remote_path,
    अक्षर *file, पूर्णांक remote, पूर्णांक lastarg, अक्षर quote, पूर्णांक terminated)
{
	glob_t g;
	अक्षर *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	पूर्णांक clen;
	स्थिरांक ओळ_Info *lf;

	/* Glob from "file" location */
	जर (file == रिक्त)
		tmp = xstrdup("*");
	अन्यथा
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	स_रखो(&g, 0, आकार(g));
	जर (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);
	} अन्यथा
		(शून्य)glob(tmp, GLOB_DOOFFS|GLOB_MARK, रिक्त, &g);

	/* Determine length of pwd so we can trim completion display */
	साठी (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		जर (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			जर (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			थांबा;
		}
		जर (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		जर (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	मुक्त(tmp);
	tmp = रिक्त;

	जर (g.gl_matchc == 0)
		जा out;

	जर (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	जर (file == रिक्त || hadglob)
		जा out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? रिक्त : remote_path);
	मुक्त(tmp2);

	जर (tmp == रिक्त)
		जा out;

	tmplen = म_माप(tmp);
	filelen = म_माप(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	साठी (i = 0; i < filelen; i++) {
		जर (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} अन्यथा
			isesc = 0;
	}

	जर (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = म_माप(tmp2);
		/* quote argument on way out */
		mblen(रिक्त, 0);
		साठी (i = 0; i < len; i += clen) {
			जर ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (माप_प्रकार)clen > आकार(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			स_नकल(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			निवड (tmp2[i]) {
			स्थिती '\'':
			स्थिती '"':
			स्थिती '\\':
			स्थिती '\t':
			स्थिती '[':
			स्थिती ' ':
			स्थिती '#':
			स्थिती '*':
				जर (quote == '\0' || tmp2[i] == quote) {
					जर (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					थांबा;
				}
				/* FALLTHROUGH */
			पूर्वनिर्धारित:
				जर (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				थांबा;
			}
		}
	}

	lf = el_ओळ(el);
	जर (g.gl_matchc == 1) {
		i = 0;
		जर (!terminated && quote != '\0')
			ins[i++] = quote;
		जर (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		जर (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	मुक्त(tmp);

 out:
	globfree(&g);
	परत g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
स्थिर अचिन्हित अक्षर
complete(Edit_ओळ *el, पूर्णांक ch)
{
	अक्षर **argv, *ओळ, quote;
	पूर्णांक argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	स्थिरांक ओळ_Info *lf;
	संरचना complete_ctx *complete_ctx;

	lf = el_ओळ(el);
	जर (el_get(el, EL_CLIENTDATA, (शून्य**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	ओळ = xmalloc(cursor + 1);
	स_नकल(ओळ, lf->buffer, cursor);
	ओळ[cursor] = '\0';
	argv = makeargv(ओळ, &carg, 1, &quote, &terminated);
	मुक्त(ओळ);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	ओळ = xmalloc(len + 1);
	स_नकल(ओळ, lf->buffer, len);
	ओळ[len] = '\0';
	argv = makeargv(ओळ, &argc, 1, रिक्त, रिक्त);

	/* Ensure cursor is at EOL or a argument boundary */
	जर (ओळ[cursor] != ' ' && ओळ[cursor] != '\0' &&
	    ओळ[cursor] != '\n') {
		मुक्त(ओळ);
		परत ret;
	}

	जर (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, रिक्त, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} अन्यथा जर (carg == 1 && cursor > 0 && ओळ[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		जर (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} अन्यथा जर (carg >= 1) {
		/* Handle file parsing */
		पूर्णांक remote = 0;
		पूर्णांक i = 0, cmdarg = 0;
		अक्षर *filematch = रिक्त;

		जर (carg > 1 && ओळ[cursor-1] != ' ')
			filematch = argv[carg - 1];

		साठी (i = 1; i < carg; i++) {
			/* Skip flags */
			जर (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		जर (ओळ[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		जर ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	मुक्त(ओळ);
	परत ret;
}
#endif /* USE_LIBEDIT */

स्थिर पूर्णांक
interactive_loop(संरचना sftp_conn *conn, अक्षर *file1, अक्षर *file2)
{
	अक्षर *remote_path;
	अक्षर *dir = रिक्त, *startdir = रिक्त;
	अक्षर cmd[2048];
	पूर्णांक err, interactive;
	Edit_ओळ *el = रिक्त;
#ifdef USE_LIBEDIT
	स्थिरांक अक्षर *editor;
	History *hl = रिक्त;
	HistEvent hev;
	बाह्य अक्षर *__progname;
	संरचना complete_ctx complete_ctx;

	जर (!batchmode && isatty(STDIN_FILENO)) {
		जर ((el = el_init(__progname, मानक_निवेश, मानक_निकास, मानक_त्रुटि)) == रिक्त)
			fatal("Couldn't initialise editline");
		जर ((hl = history_init()) == रिक्त)
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
		जर (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", रिक्त);
	}
#endif /* USE_LIBEDIT */

	जर ((remote_path = sftp_realpath(conn, ".")) == रिक्त)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	जर (file1 != रिक्त) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		जर (sftp_remote_is_dir(conn, dir) && file2 == रिक्त) {
			जर (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, आकार cmd, "cd \"%s\"", dir);
			जर (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				मुक्त(dir);
				मुक्त(startdir);
				मुक्त(remote_path);
				मुक्त(conn);
				परत (-1);
			}
		} अन्यथा {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			मुक्त(dir);
			मुक्त(startdir);
			मुक्त(remote_path);
			मुक्त(conn);
			परत (err);
		}
		मुक्त(dir);
	}

	रखो_भबफ(मानक_निकास, रिक्त, _IOLBF, 0);
	रखो_भबफ(infile, रिक्त, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	साठी (;;) {
		संरचना sigaction sa;

		interrupted = 0;
		स_रखो(&sa, 0, आकार(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		जर (sigaction(संक_विघ्न, &sa, रिक्त) == -1) {
			debug3("sigaction(%s): %s", strsignal(संक_विघ्न),
			    म_त्रुटि(त्रुटि_सं));
			थांबा;
		}
		जर (el == रिक्त) {
			जर (interactive) {
				म_लिखो("sftp> ");
				ख_साफ(मानक_निकास);
			}
			जर (ख_माला_लो(cmd, आकार(cmd), infile) == रिक्त) {
				जर (interactive)
					म_लिखो("\n");
				जर (interrupted)
					सुरूठेवा;
				थांबा;
			}
		} अन्यथा {
#ifdef USE_LIBEDIT
			स्थिरांक अक्षर *ओळ;
			पूर्णांक मोजणी = 0;

			जर ((ओळ = el_gets(el, &मोजणी)) == रिक्त ||
			    मोजणी <= 0) {
				म_लिखो("\n");
				जर (interrupted)
					सुरूठेवा;
				थांबा;
			}
			history(hl, &hev, H_ENTER, ओळ);
			जर (strlcpy(cmd, ओळ, आकार(cmd)) >= आकार(cmd)) {
				ख_लिखो(मानक_त्रुटि, "Error: input line too long\n");
				सुरूठेवा;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[म_खोज(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(संक_विघ्न, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == रिक्त);
		जर (err != 0)
			थांबा;
	}
	ssh_signal(SIGCHLD, संक_पूर्व);
	मुक्त(remote_path);
	मुक्त(startdir);
	मुक्त(conn);

#ifdef USE_LIBEDIT
	जर (hl != रिक्त)
		history_end(hl);
	जर (el != रिक्त)
		el_end(el);
#endif /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	परत (err >= 0 ? 0 : -1);
}

स्थिर शून्य
connect_to_server(अक्षर *path, अक्षर **args, पूर्णांक *in, पूर्णांक *out)
{
	पूर्णांक c_in, c_out;
#ifdef USE_PIPES
	पूर्णांक pin[2], pout[2];

	जर ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", म_त्रुटि(त्रुटि_सं));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#अन्यथा /* USE_PIPES */
	पूर्णांक inout[2];

	जर (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", म_त्रुटि(त्रुटि_सं));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	जर ((sshpid = विभाजन()) == -1)
		fatal("fork: %s", म_त्रुटि(त्रुटि_सं));
	अन्यथा जर (sshpid == 0) {
		जर ((dup2(c_in, STDIN_FILENO) == -1) ||
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
	बाह्य अक्षर *__progname;

	ख_लिखो(मानक_त्रुटि,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-l limit] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n"
	    "          [-X sftp_option] destination\n",
	    __progname);
	निकास(1);
}

पूर्णांक
main(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक r, in, out, ch, err, tmp, port = -1, noisy = 0;
	अक्षर *host = रिक्त, *user, *cp, **cpp, *file2 = रिक्त;
	पूर्णांक debug_level = 0;
	अक्षर *file1 = रिक्त, *sftp_server = रिक्त;
	अक्षर *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = रिक्त;
	स्थिरांक अक्षर *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	बाह्य पूर्णांक optind;
	बाह्य अक्षर *optarg;
	संरचना sftp_conn *conn;
	माप_प्रकार copy_buffer_len = 0;
	माप_प्रकार अंक_requests = 0;
	दीर्घ दीर्घ llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	स_रखो(&args, '\0', आकार(args));
	args.list = रिक्त;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = मानक_निवेश;

	पर्यंत ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		निवड (ch) {
		/* Passed through to ssh(1) */
		स्थिती 'A':
		स्थिती '4':
		स्थिती '6':
		स्थिती 'C':
			addargs(&args, "-%c", ch);
			थांबा;
		/* Passed through to ssh(1) with argument */
		स्थिती 'F':
		स्थिती 'J':
		स्थिती 'c':
		स्थिती 'i':
		स्थिती 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			थांबा;
		स्थिती 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			थांबा;
		स्थिती 'P':
			port = a2port(optarg);
			जर (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			थांबा;
		स्थिती 'v':
			जर (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			थांबा;
		स्थिती '1':
			fatal("SSH protocol v.1 is no longer supported");
			थांबा;
		स्थिती '2':
			/* accept silently */
			थांबा;
		स्थिती 'a':
			global_aflag = 1;
			थांबा;
		स्थिती 'B':
			copy_buffer_len = म_से_दीर्घ(optarg, &cp, 10);
			जर (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			थांबा;
		स्थिती 'b':
			जर (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			जर (म_भेद(optarg, "-") != 0 &&
			    (infile = ख_खोलो(optarg, "r")) == रिक्त)
				fatal("%s (%s).", म_त्रुटि(त्रुटि_सं), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			थांबा;
		स्थिती 'f':
			global_fflag = 1;
			थांबा;
		स्थिती 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			थांबा;
		स्थिती 'p':
			global_pflag = 1;
			थांबा;
		स्थिती 'D':
			sftp_direct = optarg;
			थांबा;
		स्थिती 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			जर (errstr != रिक्त)
				usage();
			limit_kbps *= 1024; /* kbps */
			थांबा;
		स्थिती 'r':
			global_rflag = 1;
			थांबा;
		स्थिती 'R':
			अंक_requests = म_से_दीर्घ(optarg, &cp, 10);
			जर (अंक_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			थांबा;
		स्थिती 's':
			sftp_server = optarg;
			थांबा;
		स्थिती 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			थांबा;
		स्थिती 'X':
			/* Please keep in sync with ssh.c -X */
			जर (म_भेदन(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				जर (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					त्रुटि_सं = EINVAL;
				}
				जर (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, म_त्रुटि(त्रुटि_सं));
				}
				copy_buffer_len = (माप_प्रकार)llv;
			} अन्यथा जर (म_भेदन(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				जर (errstr != रिक्त) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				अंक_requests = (माप_प्रकार)llv;
			} अन्यथा {
				fatal("Invalid -X option");
			}
			थांबा;
		स्थिती 'h':
		पूर्वनिर्धारित:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	जर (!isatty(STDERR_FILENO))
		showprogress = 0;

	जर (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	जर (sftp_direct == रिक्त) {
		जर (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		निवड (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		स्थिती -1:
			usage();
			थांबा;
		स्थिती 0:
			जर (tmp != -1)
				port = tmp;
			थांबा;
		पूर्वनिर्धारित:
			/* Try with user, host and path. */
			जर (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				थांबा;
			/* Try with user and host. */
			जर (parse_user_host_port(*argv, &user, &host, रिक्त)
			    == 0)
				थांबा;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			थांबा;
		}
		file2 = *(argv + 1);

		जर (!*host) {
			ख_लिखो(मानक_त्रुटि, "Missing hostname\n");
			usage();
		}

		जर (port != -1)
			addargs(&args, "-oPort %d", port);
		जर (user != रिक्त) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		जर (sftp_server == रिक्त || म_अक्षर(sftp_server, '/') == रिक्त)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != रिक्त ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} अन्यथा {
		जर ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		जर (cpp[0] == रिक्त)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, अंक_requests, limit_kbps);
	जर (conn == रिक्त)
		fatal("Couldn't initialise connection to server");

	जर (!quiet) {
		जर (sftp_direct == रिक्त)
			ख_लिखो(मानक_त्रुटि, "Connected to %s.\n", host);
		अन्यथा
			ख_लिखो(मानक_त्रुटि, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#जर !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	बंद(in);
	बंद(out);
	जर (batchmode)
		ख_बंद(infile);

	पर्यंत (waitpid(sshpid, रिक्त, 0) == -1 && sshpid > 1)
		जर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    म_त्रुटि(त्रुटि_सं));

	निकास(err == 0 ? 0 : 1);
}
