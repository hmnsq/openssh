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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/ioctl.h>
#समावेश <sys/stat.h>
#समावेश <sys/socket.h>
#समावेश <sys/statvfs.h>
#समावेश <sys/wait.h>

#समावेश <ctype.h>
#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <glob.h>
#समावेश <paths.h>
#समावेश <libgen.h>
#अगर_घोषित HAVE_LOCALE_H
# include <locale.h>
#पूर्ण_अगर
#अगर_घोषित USE_LIBEDIT
#समावेश <histedit.h>
#अन्यथा
प्रकार व्योम Edit_पंक्ति;
#पूर्ण_अगर
#समावेश <limits.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <util.h>

#समावेश "xmalloc.h"
#समावेश "log.h"
#समावेश "pathnames.h"
#समावेश "misc.h"
#समावेश "utf8.h"

#समावेश "sftp.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "sftp-common.h"
#समावेश "sftp-client.h"
#समावेश "sftp-usergroup.h"

/* File to read commands from */
खाता* infile;

/* Are we in batchfile mode? */
पूर्णांक batchmode = 0;

/* PID of ssh transport process */
अटल अस्थिर pid_t sshpid = -1;

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
काष्ठा complete_ctx {
	काष्ठा sftp_conn *conn;
	अक्षर **remote_pathp;
};

पूर्णांक sftp_glob(काष्ठा sftp_conn *, स्थिर अक्षर *, पूर्णांक,
    पूर्णांक (*)(स्थिर अक्षर *, पूर्णांक), glob_t *); /* proto for sftp-glob.c */

बाह्य अक्षर *__progname;

/* Separators for interactive commands */
#घोषणा WHITESPACE " \t\r\n"

/* ls flags */
#घोषणा LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#घोषणा LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#घोषणा LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#घोषणा LS_NAME_SORT	0x0008	/* Sort by name (default) */
#घोषणा LS_TIME_SORT	0x0010	/* Sort by mtime */
#घोषणा LS_आकार_SORT	0x0020	/* Sort by file size */
#घोषणा LS_REVERSE_SORT	0x0040	/* Reverse sort order */
#घोषणा LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#घोषणा LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#घोषणा VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#घोषणा SORT_FLAGS	(LS_NAME_SORT|LS_TIME_SORT|LS_आकार_SORT)

/* Commands for interactive mode */
क्रमागत sftp_command {
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

काष्ठा CMD {
	स्थिर अक्षर *c;
	स्थिर पूर्णांक n;
	स्थिर पूर्णांक t;	/* Completion type for the first argument */
	स्थिर पूर्णांक t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#घोषणा NOARGS	0
#घोषणा REMOTE	1
#घोषणा LOCAL	2

अटल स्थिर काष्ठा CMD cmds[] = {
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
	{ शून्य,		-1,		-1,		-1	}
};

अटल व्योम
killchild(पूर्णांक signo)
{
	pid_t pid;

	pid = sshpid;
	अगर (pid > 1) {
		समाप्त(pid, संक_इति);
		(व्योम)waitpid(pid, शून्य, 0);
	}

	_निकास(1);
}

अटल व्योम
suspchild(पूर्णांक signo)
{
	पूर्णांक save_errno = त्रुटि_सं;
	अगर (sshpid > 1) {
		समाप्त(sshpid, signo);
		जबतक (waitpid(sshpid, शून्य, WUNTRACED) == -1 && त्रुटि_सं == EINTR)
			जारी;
	}
	समाप्त(getpid(), SIGSTOP);
	त्रुटि_सं = save_errno;
}

अटल व्योम
cmd_interrupt(पूर्णांक signo)
{
	स्थिर अक्षर संदेश[] = "\rInterrupt  \n";
	पूर्णांक olderrno = त्रुटि_सं;

	(व्योम)ग_लिखो(STDERR_FILENO, संदेश, माप(संदेश) - 1);
	interrupted = 1;
	त्रुटि_सं = olderrno;
}

अटल व्योम
read_interrupt(पूर्णांक signo)
{
	interrupted = 1;
}

अटल व्योम
sigchld_handler(पूर्णांक sig)
{
	पूर्णांक save_errno = त्रुटि_सं;
	pid_t pid;
	स्थिर अक्षर संदेश[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	जबतक ((pid = waitpid(sshpid, शून्य, WNOHANG)) == -1 && त्रुटि_सं == EINTR)
		जारी;
	अगर (pid == sshpid) {
		अगर (!quiet)
		    (व्योम)ग_लिखो(STDERR_FILENO, संदेश, माप(संदेश) - 1);
		sshpid = -1;
	}

	त्रुटि_सं = save_errno;
}

अटल व्योम
help(व्योम)
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

अटल व्योम
local_do_shell(स्थिर अक्षर *args)
{
	पूर्णांक status;
	अक्षर *shell;
	pid_t pid;

	अगर (!*args)
		args = शून्य;

	अगर ((shell = दो_पर्या("SHELL")) == शून्य || *shell == '\0')
		shell = _PATH_BSHELL;

	अगर ((pid = विभाजन()) == -1)
		fatal("Couldn't fork: %s", म_त्रुटि(त्रुटि_सं));

	अगर (pid == 0) {
		अगर (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (अक्षर *)शून्य);
		} अन्यथा {
			debug3("Executing %s", shell);
			execl(shell, shell, (अक्षर *)शून्य);
		}
		ख_लिखो(मानक_त्रुटि, "Couldn't execute \"%s\": %s\n", shell,
		    म_त्रुटि(त्रुटि_सं));
		_निकास(1);
	}
	जबतक (waitpid(pid, &status, 0) == -1)
		अगर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for child: %s", म_त्रुटि(त्रुटि_सं));
	अगर (!WIFEXITED(status))
		error("Shell exited abnormally");
	अन्यथा अगर (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

अटल व्योम
local_do_ls(स्थिर अक्षर *args)
{
	अगर (!args || !*args)
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
अटल अक्षर *
path_strip(स्थिर अक्षर *path, स्थिर अक्षर *strip)
{
	माप_प्रकार len;

	अगर (strip == शून्य || (len = म_माप(strip)) == 0)
		वापस (xstrdup(path));

	अगर (म_भेदन(path, strip, len) == 0) {
		अगर (strip[len - 1] != '/' && path[len] == '/')
			len++;
		वापस (xstrdup(path + len));
	}

	वापस (xstrdup(path));
}

अटल पूर्णांक
parse_getput_flags(स्थिर अक्षर *cmd, अक्षर **argv, पूर्णांक argc,
    पूर्णांक *aflag, पूर्णांक *fflag, पूर्णांक *pflag, पूर्णांक *rflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = 0;
	जबतक ((ch = getopt(argc, argv, "afPpRr")) != -1) {
		चयन (ch) {
		हाल 'a':
			*aflag = 1;
			अवरोध;
		हाल 'f':
			*fflag = 1;
			अवरोध;
		हाल 'p':
		हाल 'P':
			*pflag = 1;
			अवरोध;
		हाल 'r':
		हाल 'R':
			*rflag = 1;
			अवरोध;
		शेष:
			error("%s: Invalid flag -%c", cmd, optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल पूर्णांक
parse_mkdir_flags(स्थिर अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *pflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*pflag = 0;
	जबतक ((ch = getopt(argc, argv, "p")) != -1) {
		चयन (ch) {
		हाल 'p':
			*pflag = 1;
			अवरोध;
		शेष:
			error("%s: Invalid flag -%c", cmd, optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल पूर्णांक
parse_link_flags(स्थिर अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *sflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	जबतक ((ch = getopt(argc, argv, "s")) != -1) {
		चयन (ch) {
		हाल 's':
			*sflag = 1;
			अवरोध;
		शेष:
			error("%s: Invalid flag -%c", cmd, optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल पूर्णांक
parse_rename_flags(स्थिर अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *lflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	जबतक ((ch = getopt(argc, argv, "l")) != -1) {
		चयन (ch) {
		हाल 'l':
			*lflag = 1;
			अवरोध;
		शेष:
			error("%s: Invalid flag -%c", cmd, optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल पूर्णांक
parse_ls_flags(अक्षर **argv, पूर्णांक argc, पूर्णांक *lflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	जबतक ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		चयन (ch) {
		हाल '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			अवरोध;
		हाल 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_आकार_SORT;
			अवरोध;
		हाल 'a':
			*lflag |= LS_SHOW_ALL;
			अवरोध;
		हाल 'f':
			*lflag &= ~SORT_FLAGS;
			अवरोध;
		हाल 'h':
			*lflag |= LS_SI_UNITS;
			अवरोध;
		हाल 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			अवरोध;
		हाल 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			अवरोध;
		हाल 'r':
			*lflag |= LS_REVERSE_SORT;
			अवरोध;
		हाल 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			अवरोध;
		शेष:
			error("ls: Invalid flag -%c", optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल पूर्णांक
parse_df_flags(स्थिर अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *hflag, पूर्णांक *iflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	जबतक ((ch = getopt(argc, argv, "hi")) != -1) {
		चयन (ch) {
		हाल 'h':
			*hflag = 1;
			अवरोध;
		हाल 'i':
			*iflag = 1;
			अवरोध;
		शेष:
			error("%s: Invalid flag -%c", cmd, optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल पूर्णांक
parse_ch_flags(स्थिर अक्षर *cmd, अक्षर **argv, पूर्णांक argc, पूर्णांक *hflag)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	जबतक ((ch = getopt(argc, argv, "h")) != -1) {
		चयन (ch) {
		हाल 'h':
			*hflag = 1;
			अवरोध;
		शेष:
			error("%s: Invalid flag -%c", cmd, optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल पूर्णांक
parse_no_flags(स्थिर अक्षर *cmd, अक्षर **argv, पूर्णांक argc)
{
	बाह्य पूर्णांक opterr, optind, optopt, optreset;
	पूर्णांक ch;

	optind = optreset = 1;
	opterr = 0;

	जबतक ((ch = getopt(argc, argv, "")) != -1) {
		चयन (ch) {
		शेष:
			error("%s: Invalid flag -%c", cmd, optopt);
			वापस -1;
		}
	}

	वापस optind;
}

अटल अक्षर *
escape_glob(स्थिर अक्षर *s)
{
	माप_प्रकार i, o, len;
	अक्षर *ret;

	len = म_माप(s);
	ret = xcalloc(2, len + 1);
	क्रम (i = o = 0; i < len; i++) {
		अगर (म_अक्षर("[]?*\\", s[i]) != शून्य)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	वापस ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
अटल अक्षर *
make_absolute_pwd_glob(अक्षर *p, स्थिर अक्षर *pwd)
{
	अक्षर *ret, *escpwd;

	escpwd = escape_glob(pwd);
	अगर (p == शून्य)
		वापस escpwd;
	ret = sftp_make_absolute(p, escpwd);
	मुक्त(escpwd);
	वापस ret;
}

अटल पूर्णांक
local_is_dir(स्थिर अक्षर *path)
{
	काष्ठा stat sb;

	अगर (stat(path, &sb) == -1)
		वापस 0;
	वापस S_ISDIR(sb.st_mode);
}

अटल पूर्णांक
process_get(काष्ठा sftp_conn *conn, स्थिर अक्षर *src, स्थिर अक्षर *dst,
    स्थिर अक्षर *pwd, पूर्णांक pflag, पूर्णांक rflag, पूर्णांक resume, पूर्णांक fflag)
{
	अक्षर *filename, *abs_src = शून्य, *abs_dst = शून्य, *tmp = शून्य;
	glob_t g;
	पूर्णांक i, r, err = 0;

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	स_रखो(&g, 0, माप(g));

	debug3("Looking up %s", abs_src);
	अगर ((r = sftp_glob(conn, abs_src, GLOB_MARK, शून्य, &g)) != 0) {
		अगर (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} अन्यथा {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		जाओ out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	अगर (g.gl_matchc > 1 && dst != शून्य && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		जाओ out;
	}

	क्रम (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		अगर ((filename = basename(tmp)) == शून्य) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			मुक्त(tmp);
			err = -1;
			जाओ out;
		}

		/*
		 * Special handling for destinations of '..' and remote roots.
		 * In particular, never select the local root as an implicit
		 * destination for a remote root.
		 */
		अगर (म_भेद(filename, "..") == 0 ||
		    (filename[0] != '\0' &&
		    filename[म_अखोज(filename, "/")] == '\0'))
			filename = ".";

		अगर (g.gl_matchc == 1 && dst) {
			अगर (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} अन्यथा {
				abs_dst = xstrdup(dst);
			}
		} अन्यथा अगर (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} अन्यथा {
			abs_dst = xstrdup(filename);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		अगर (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अन्यथा अगर (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		अगर (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			अगर (sftp_download_dir(conn, g.gl_pathv[i], abs_dst,
			    शून्य, pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अन्यथा {
			अगर (sftp_download(conn, g.gl_pathv[i], abs_dst, शून्य,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
		मुक्त(abs_dst);
		abs_dst = शून्य;
	}

out:
	मुक्त(abs_src);
	globfree(&g);
	वापस(err);
}

अटल पूर्णांक
process_put(काष्ठा sftp_conn *conn, स्थिर अक्षर *src, स्थिर अक्षर *dst,
    स्थिर अक्षर *pwd, पूर्णांक pflag, पूर्णांक rflag, पूर्णांक resume, पूर्णांक fflag)
{
	अक्षर *tmp_dst = शून्य;
	अक्षर *abs_dst = शून्य;
	अक्षर *tmp = शून्य, *filename = शून्य;
	glob_t g;
	पूर्णांक err = 0;
	पूर्णांक i, dst_is_dir = 1;
	काष्ठा stat sb;

	अगर (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	स_रखो(&g, 0, माप(g));
	debug3("Looking up %s", src);
	अगर (glob(src, GLOB_NOCHECK | GLOB_MARK, शून्य, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		जाओ out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	अगर (tmp_dst != शून्य)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	अगर (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		जाओ out;
	}

	क्रम (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		अगर (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], म_त्रुटि(त्रुटि_सं));
			जारी;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		अगर ((filename = basename(tmp)) == शून्य) {
			error("basename %s: %s", tmp, म_त्रुटि(त्रुटि_सं));
			मुक्त(tmp);
			err = -1;
			जाओ out;
		}
		/* Special handling for source of '..' */
		अगर (म_भेद(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		मुक्त(abs_dst);
		abs_dst = शून्य;
		अगर (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			अगर (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			अन्यथा
				abs_dst = xstrdup(tmp_dst);
		} अन्यथा अगर (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} अन्यथा {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		मुक्त(tmp);

		resume |= global_aflag;
		अगर (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		अन्यथा अगर (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		अगर (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			अगर (sftp_upload_dir(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, 1, resume,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} अन्यथा {
			अगर (sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume,
			    fflag || global_fflag, 0) == -1)
				err = -1;
		}
	}

out:
	मुक्त(abs_dst);
	मुक्त(tmp_dst);
	globfree(&g);
	वापस(err);
}

अटल पूर्णांक
sdirent_comp(स्थिर व्योम *aa, स्थिर व्योम *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	पूर्णांक rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#घोषणा NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	अगर (sort_flag & LS_NAME_SORT)
		वापस (rmul * म_भेद(a->filename, b->filename));
	अन्यथा अगर (sort_flag & LS_TIME_SORT)
		वापस (rmul * NCMP(a->a.mtime, b->a.mtime));
	अन्यथा अगर (sort_flag & LS_आकार_SORT)
		वापस (rmul * NCMP(a->a.आकार, b->a.आकार));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
अटल पूर्णांक
do_ls_dir(काष्ठा sftp_conn *conn, स्थिर अक्षर *path,
    स्थिर अक्षर *strip_path, पूर्णांक lflag)
{
	पूर्णांक n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	अगर ((n = sftp_readdir(conn, path, &d)) != 0)
		वापस (n);

	अगर (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		काष्ठा winsize ws;
		अक्षर *tmp;

		/* Count entries for sort and find longest filename */
		क्रम (n = 0; d[n] != शून्य; n++) {
			अगर (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, म_माप(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += म_माप(tmp);
		मुक्त(tmp);

		अगर (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	अगर (lflag & SORT_FLAGS) {
		क्रम (n = 0; d[n] != शून्य; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		क्विक(d, n, माप(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	क्रम (n = 0; d[n] != शून्य && !interrupted; n++) {
		अक्षर *tmp, *fname;

		अगर (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			जारी;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		मुक्त(tmp);

		अगर (lflag & LS_LONG_VIEW) {
			अगर ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				अक्षर *lname;
				काष्ठा stat sb;
				स्थिर अक्षर *user = शून्य, *group = शून्य;

				स_रखो(&sb, 0, माप(sb));
				attrib_to_stat(&d[n]->a, &sb);
				अगर ((lflag & LS_NUMERIC_VIEW) == 0) {
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
			अगर (c >= columns) {
				म_लिखो("\n");
				c = 1;
			} अन्यथा
				c++;
		}

		मुक्त(fname);
	}

	अगर (!(lflag & LS_LONG_VIEW) && (c != 1))
		म_लिखो("\n");

	sftp_free_dirents(d);
	वापस (0);
}

अटल पूर्णांक
sglob_comp(स्थिर व्योम *aa, स्थिर व्योम *bb)
{
	u_int a = *(स्थिर u_int *)aa;
	u_int b = *(स्थिर u_int *)bb;
	स्थिर अक्षर *ap = sort_glob->gl_pathv[a];
	स्थिर अक्षर *bp = sort_glob->gl_pathv[b];
	स्थिर काष्ठा stat *as = sort_glob->gl_statv[a];
	स्थिर काष्ठा stat *bs = sort_glob->gl_statv[b];
	पूर्णांक rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#घोषणा NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	/* order entries without stat information last */
	अगर (as == शून्य || bs == शून्य)
		वापस (as == bs) ? 0 : (as == शून्य ? rmul : -rmul);
	अगर (sort_flag & LS_NAME_SORT)
		वापस (rmul * म_भेद(ap, bp));
	अन्यथा अगर (sort_flag & LS_TIME_SORT) {
#अगर defined(HAVE_STRUCT_STAT_ST_MTIM)
		अगर (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			वापस 0;
		वापस timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#या_अगर defined(HAVE_STRUCT_STAT_ST_MTIME)
		वापस (rmul * NCMP(as->st_mtime, bs->st_mtime));
#अन्यथा
	वापस rmul * 1;
#पूर्ण_अगर
	} अन्यथा अगर (sort_flag & LS_आकार_SORT)
		वापस (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
अटल पूर्णांक
do_globbed_ls(काष्ठा sftp_conn *conn, स्थिर अक्षर *path,
    स्थिर अक्षर *strip_path, पूर्णांक lflag)
{
	अक्षर *fname, *lname;
	glob_t g;
	पूर्णांक err, r;
	काष्ठा winsize ws;
	u_int i, j, nentries, *indices = शून्य, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	स_रखो(&g, 0, माप(g));

	अगर ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    शून्य, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		अगर (g.gl_pathc)
			globfree(&g);
		अगर (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} अन्यथा {
			error("Can't ls: \"%s\" not found", path);
		}
		वापस -1;
	}

	अगर (interrupted)
		जाओ out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	अगर (g.gl_matchc == 1 && g.gl_statv[0] != शून्य &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		वापस err;
	}

	अगर (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	अगर (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		क्रम (i = 0; g.gl_pathv[i]; i++)
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
	क्रम (nentries = 0; g.gl_pathv[nentries] != शून्य; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, माप(*indices));
	क्रम (i = 0; i < nentries; i++)
		indices[i] = i;

	अगर (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		क्विक(indices, nentries, माप(*indices), sglob_comp);
		sort_glob = शून्य;
	}

	get_remote_user_groups_from_glob(conn, &g);
	क्रम (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		अगर (lflag & LS_LONG_VIEW) {
			स्थिर अक्षर *user = शून्य, *group = शून्य;

			अगर (g.gl_statv[i] == शून्य) {
				error("no stat information for %s", fname);
				मुक्त(fname);
				जारी;
			}
			अगर ((lflag & LS_NUMERIC_VIEW) == 0) {
				user = ruser_name(g.gl_statv[i]->st_uid);
				group = rgroup_name(g.gl_statv[i]->st_gid);
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS), user, group);
			mprintf("%s\n", lname);
			मुक्त(lname);
		} अन्यथा {
			mprintf("%-*s", colspace, fname);
			अगर (c >= columns) {
				म_लिखो("\n");
				c = 1;
			} अन्यथा
				c++;
		}
		मुक्त(fname);
	}

	अगर (!(lflag & LS_LONG_VIEW) && (c != 1))
		म_लिखो("\n");

 out:
	अगर (g.gl_pathc)
		globfree(&g);
	मुक्त(indices);

	वापस 0;
}

अटल पूर्णांक
do_df(काष्ठा sftp_conn *conn, स्थिर अक्षर *path, पूर्णांक hflag, पूर्णांक iflag)
{
	काष्ठा sftp_statvfs st;
	अक्षर s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	अक्षर s_मूल[FMT_SCALED_STRSIZE], s_योग[FMT_SCALED_STRSIZE];
	अक्षर s_icapacity[16], s_dcapacity[16];

	अगर (sftp_statvfs(conn, path, &st, 1) == -1)
		वापस -1;
	अगर (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", माप(s_icapacity));
	अन्यथा {
		snprintf(s_icapacity, माप(s_icapacity), "%3llu%%",
		    (अचिन्हित दीर्घ दीर्घ)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	अगर (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", माप(s_dcapacity));
	अन्यथा {
		snprintf(s_dcapacity, माप(s_dcapacity), "%3llu%%",
		    (अचिन्हित दीर्घ दीर्घ)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	अगर (iflag) {
		म_लिखो("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		म_लिखो("%11llu %11llu %11llu %11llu         %s\n",
		    (अचिन्हित दीर्घ दीर्घ)st.f_files,
		    (अचिन्हित दीर्घ दीर्घ)(st.f_files - st.f_ffree),
		    (अचिन्हित दीर्घ दीर्घ)st.f_favail,
		    (अचिन्हित दीर्घ दीर्घ)st.f_ffree, s_icapacity);
	} अन्यथा अगर (hflag) {
		strlcpy(s_used, "error", माप(s_used));
		strlcpy(s_avail, "error", माप(s_avail));
		strlcpy(s_मूल, "error", माप(s_मूल));
		strlcpy(s_योग, "error", माप(s_योग));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_मूल);
		fmt_scaled(st.f_blocks * st.f_frsize, s_योग);
		म_लिखो("    Size     Used    Avail   (root)    %%Capacity\n");
		म_लिखो("%7sB %7sB %7sB %7sB         %s\n",
		    s_योग, s_used, s_avail, s_मूल, s_dcapacity);
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
	वापस 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
अटल व्योम
undo_glob_escape(अक्षर *s)
{
	माप_प्रकार i, j;

	क्रम (i = j = 0;;) {
		अगर (s[i] == '\0') {
			s[j] = '\0';
			वापस;
		}
		अगर (s[i] != '\\') {
			s[j++] = s[i++];
			जारी;
		}
		/* s[i] == '\\' */
		++i;
		चयन (s[i]) {
		हाल '?':
		हाल '[':
		हाल '*':
		हाल '\\':
			s[j++] = s[i++];
			अवरोध;
		हाल '\0':
			s[j++] = '\\';
			s[j] = '\0';
			वापस;
		शेष:
			s[j++] = '\\';
			s[j++] = s[i++];
			अवरोध;
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
#घोषणा MAXARGS		128
#घोषणा MAXARGLEN	8192
अटल अक्षर **
makeargv(स्थिर अक्षर *arg, पूर्णांक *argcp, पूर्णांक sloppy, अक्षर *lastquote,
    u_int *terminated)
{
	पूर्णांक argc, quot;
	माप_प्रकार i, j;
	अटल अक्षर argvs[MAXARGLEN];
	अटल अक्षर *argv[MAXARGS + 1];
	क्रमागत { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	अगर (म_माप(arg) > माप(argvs) - 1) {
 args_too_longs:
		error("string too long");
		वापस शून्य;
	}
	अगर (terminated != शून्य)
		*terminated = 1;
	अगर (lastquote != शून्य)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	क्रम (;;) {
		अगर ((माप_प्रकार)argc >= माप(argv) / माप(*argv)){
			error("Too many arguments.");
			वापस शून्य;
		}
		अगर (है_खाली((अचिन्हित अक्षर)arg[i])) {
			अगर (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} अन्यथा अगर (state != MA_START)
				argvs[j++] = arg[i];
		} अन्यथा अगर (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			अगर (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				अगर (lastquote != शून्य)
					*lastquote = arg[i];
			} अन्यथा अगर (state == MA_UNQUOTED)
				state = q;
			अन्यथा अगर (state == q)
				state = MA_UNQUOTED;
			अन्यथा
				argvs[j++] = arg[i];
		} अन्यथा अगर (arg[i] == '\\') {
			अगर (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				अगर (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} अन्यथा अगर (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					अगर (j >= माप(argvs) - 5)
						जाओ args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} अन्यथा {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} अन्यथा {
				अगर (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					अगर (lastquote != शून्य)
						*lastquote = '\0';
				}
				अगर (arg[i + 1] == '?' || arg[i + 1] == '[' ||
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
					अगर (arg[i] == '\0')
						जाओ early_nul;
					argvs[j++] = arg[i];
				}
			}
		} अन्यथा अगर (arg[i] == '#') {
			अगर (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			अन्यथा
				जाओ string_done;
		} अन्यथा अगर (arg[i] == '\0') {
			अगर (state == MA_SQUOTE || state == MA_DQUOTE) {
 early_nul:
				अगर (sloppy) {
					state = MA_UNQUOTED;
					अगर (terminated != शून्य)
						*terminated = 0;
					जाओ string_done;
				}
				error("Unterminated quoted argument");
				वापस शून्य;
			}
 string_done:
			अगर (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			अवरोध;
		} अन्यथा {
			अगर (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				अगर (lastquote != शून्य)
					*lastquote = '\0';
			}
			अगर ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				अगर (j >= माप(argvs) - 3)
					जाओ args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} अन्यथा
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	वापस argv;
}

अटल पूर्णांक
parse_args(स्थिर अक्षर **cpp, पूर्णांक *ignore_errors, पूर्णांक *disable_echo, पूर्णांक *aflag,
	  पूर्णांक *fflag, पूर्णांक *hflag, पूर्णांक *iflag, पूर्णांक *lflag, पूर्णांक *pflag,
	  पूर्णांक *rflag, पूर्णांक *sflag,
    अचिन्हित दीर्घ *n_arg, अक्षर **path1, अक्षर **path2)
{
	स्थिर अक्षर *cmd, *cp = *cpp;
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
	क्रम (;*cp != '\0'; cp++) {
		अगर (*cp == '-') {
			*ignore_errors = 1;
		} अन्यथा अगर (*cp == '@') {
			*disable_echo = 1;
		} अन्यथा {
			/* all other characters terminate prefix processing */
			अवरोध;
		}
	}
	cp = cp + म_अखोज(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	अगर (*cp == '\0' || *cp == '#')
		वापस (0);

	अगर ((argv = makeargv(cp, &argc, 0, शून्य, शून्य)) == शून्य)
		वापस -1;

	/* Figure out which command we have */
	क्रम (i = 0; cmds[i].c != शून्य; i++) {
		अगर (argv[0] != शून्य && strcasecmp(cmds[i].c, argv[0]) == 0)
			अवरोध;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	अगर (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} अन्यथा अगर (cmdnum == -1) {
		error("Invalid command.");
		वापस -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = शून्य;
	optidx = 1;
	चयन (cmdnum) {
	हाल I_GET:
	हाल I_REGET:
	हाल I_REPUT:
	हाल I_PUT:
		अगर ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag)) == -1)
			वापस -1;
		/* Get first pathname (mandatory) */
		अगर (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			वापस -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		अगर (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		अवरोध;
	हाल I_LINK:
		अगर ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			वापस -1;
		जाओ parse_two_paths;
	हाल I_COPY:
		अगर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			वापस -1;
		जाओ parse_two_paths;
	हाल I_RENAME:
		अगर ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			वापस -1;
		जाओ parse_two_paths;
	हाल I_SYMLINK:
		अगर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			वापस -1;
 parse_two_paths:
		अगर (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			वापस -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		अवरोध;
	हाल I_MKDIR:
	हाल I_LMKDIR:
		अगर ((optidx = parse_mkdir_flags(cmd, argv, argc, pflag)) == -1)
			वापस -1;
		path1_mandatory = 1;
		जाओ parse_one_path;
	हाल I_RM:
	हाल I_RMDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	हाल I_CHDIR:
	हाल I_LCHDIR:
		अगर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			वापस -1;
 parse_one_path:
		/* Get pathname (mandatory) */
		अगर (argc - optidx < 1) {
			अगर (!path1_mandatory)
				अवरोध; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			वापस -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		अगर (cmdnum != I_RM)
			undo_glob_escape(*path1);
		अवरोध;
	हाल I_DF:
		अगर ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			वापस -1;
		/* Default to current directory if no path specified */
		अगर (argc - optidx < 1)
			*path1 = शून्य;
		अन्यथा {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		अवरोध;
	हाल I_LS:
		अगर ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			वापस(-1);
		/* Path is optional */
		अगर (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		अवरोध;
	हाल I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + म_माप(cmd) + म_अखोज(cp, WHITESPACE);
	हाल I_SHELL:
		/* Uses the rest of the line */
		अवरोध;
	हाल I_LUMASK:
	हाल I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	हाल I_CHOWN:
	हाल I_CHGRP:
		अगर ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			वापस -1;
		/* Get numeric arg (mandatory) */
		अगर (argc - optidx < 1)
			जाओ need_अंक_arg;
		त्रुटि_सं = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		अगर (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && त्रुटि_सं == दुस्फल) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_अंक_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			वापस -1;
		}
		*n_arg = ll;
		अगर (cmdnum == I_LUMASK)
			अवरोध;
		/* Get pathname (mandatory) */
		अगर (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			वापस -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		अवरोध;
	हाल I_QUIT:
	हाल I_PWD:
	हाल I_LPWD:
	हाल I_HELP:
	हाल I_VERSION:
	हाल I_PROGRESS:
		अगर ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			वापस -1;
		अवरोध;
	शेष:
		fatal("Command not implemented");
	}

	*cpp = cp;
	वापस(cmdnum);
}

अटल पूर्णांक
parse_dispatch_command(काष्ठा sftp_conn *conn, स्थिर अक्षर *cmd, अक्षर **pwd,
    स्थिर अक्षर *startdir, पूर्णांक err_abort, पूर्णांक echo_command)
{
	स्थिर अक्षर *ocmd = cmd;
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

	path1 = path2 = शून्य;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &n_arg,
	    &path1, &path2);
	अगर (ignore_errors != 0)
		err_abort = 0;

	अगर (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	स_रखो(&g, 0, माप(g));

	/* Perform command */
	चयन (cmdnum) {
	हाल 0:
		/* Blank line */
		अवरोध;
	हाल -1:
		/* Unrecognized command */
		err = -1;
		अवरोध;
	हाल I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	हाल I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		अवरोध;
	हाल I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	हाल I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag);
		अवरोध;
	हाल I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		अवरोध;
	हाल I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		अवरोध;
	हाल I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	हाल I_LINK:
		अगर (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		अवरोध;
	हाल I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, शून्य, &g);
		क्रम (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			अगर (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			अगर (err != 0 && err_abort)
				अवरोध;
		}
		अवरोध;
	हाल I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		अगर (pflag)
			err = sftp_mkpath(conn, path1, &a, 1);
		अन्यथा
			err = sftp_mkdir(conn, path1, &a, 1);
		अवरोध;
	हाल I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		अवरोध;
	हाल I_CHDIR:
		अगर (path1 == शून्य || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		अगर ((tmp = sftp_realpath(conn, path1)) == शून्य) {
			err = 1;
			अवरोध;
		}
		अगर (sftp_stat(conn, tmp, 0, &aa) != 0) {
			मुक्त(tmp);
			err = 1;
			अवरोध;
		}
		अगर (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			मुक्त(tmp);
			err = 1;
			अवरोध;
		}
		अगर (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			मुक्त(tmp);
			err = 1;
			अवरोध;
		}
		मुक्त(*pwd);
		*pwd = tmp;
		अवरोध;
	हाल I_LS:
		अगर (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			अवरोध;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = शून्य;
		अगर (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		अवरोध;
	हाल I_DF:
		/* Default to current directory if no path specified */
		अगर (path1 == शून्य)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		अवरोध;
	हाल I_LCHDIR:
		अगर (path1 == शून्य || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		मुक्त(path1);
		path1 = tmp;
		अगर (स_बदलो(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, म_त्रुटि(त्रुटि_सं));
			err = 1;
		}
		अवरोध;
	हाल I_LMKDIR:
		अगर (pflag) {
			अगर (mkdir_path(path1, 0777) != 0)
				err = 1;
			अवरोध;
		}
		अगर (सूची_गढ़ो(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, म_त्रुटि(त्रुटि_सं));
			err = 1;
		}
		अवरोध;
	हाल I_LLS:
		local_do_ls(cmd);
		अवरोध;
	हाल I_SHELL:
		local_do_shell(cmd);
		अवरोध;
	हाल I_LUMASK:
		umask(n_arg);
		म_लिखो("Local umask: %03lo\n", n_arg);
		अवरोध;
	हाल I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, शून्य, &g);
		क्रम (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			अगर (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			अगर (err != 0 && err_abort)
				अवरोध;
		}
		अवरोध;
	हाल I_CHOWN:
	हाल I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, शून्य, &g);
		क्रम (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			अगर ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				अगर (err_abort) {
					err = -1;
					अवरोध;
				} अन्यथा
					जारी;
			}
			अगर (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				अगर (err_abort) {
					err = -1;
					अवरोध;
				} अन्यथा
					जारी;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			अगर (cmdnum == I_CHOWN) {
				अगर (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} अन्यथा {
				अगर (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			अगर (err != 0 && err_abort)
				अवरोध;
		}
		अवरोध;
	हाल I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		अवरोध;
	हाल I_LPWD:
		अगर (!getcwd(path_buf, माप(path_buf))) {
			error("Couldn't get local cwd: %s", म_त्रुटि(त्रुटि_सं));
			err = -1;
			अवरोध;
		}
		mprintf("Local working directory: %s\n", path_buf);
		अवरोध;
	हाल I_QUIT:
		/* Processed below */
		अवरोध;
	हाल I_HELP:
		help();
		अवरोध;
	हाल I_VERSION:
		म_लिखो("SFTP protocol version %u\n", sftp_proto_version(conn));
		अवरोध;
	हाल I_PROGRESS:
		showprogress = !showprogress;
		अगर (showprogress)
			म_लिखो("Progress meter enabled\n");
		अन्यथा
			म_लिखो("Progress meter disabled\n");
		अवरोध;
	शेष:
		fatal("%d is not implemented", cmdnum);
	}

	अगर (g.gl_pathc)
		globfree(&g);
	मुक्त(path1);
	मुक्त(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	अगर (err_abort && err != 0)
		वापस (-1);
	अन्यथा अगर (cmdnum == I_QUIT)
		वापस (1);

	वापस (0);
}

#अगर_घोषित USE_LIBEDIT
अटल अक्षर *
prompt(Edit_पंक्ति *el)
{
	वापस ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
अटल व्योम
complete_display(अक्षर **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	काष्ठा winsize ws;
	अक्षर *tmp;

	/* Count entries for sort and find longest */
	क्रम (y = 0; list[y]; y++)
		m = MAXIMUM(m, म_माप(list[y]));

	अगर (ioctl(fileno(मानक_निवेश), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	म_लिखो("\n");
	m = 1;
	क्रम (y = 0; list[y]; y++) {
		llen = म_माप(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		अगर (m >= columns) {
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
अटल अक्षर *
complete_ambiguous(स्थिर अक्षर *word, अक्षर **list, माप_प्रकार गिनती)
{
	माप_प्रकार i, j, matchlen;
	अक्षर *tmp;
	पूर्णांक len;

	अगर (word == शून्य)
		वापस शून्य;

	अगर (गिनती == 0)
		वापस xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = म_माप(list[0]);
	क्रम (i = 1; i < गिनती && list[i] != शून्य; i++) {
		क्रम (j = 0; j < matchlen; j++)
			अगर (list[0][j] != list[i][j])
				अवरोध;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(शून्य, 0);
	क्रम (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		अगर (len <= 0 || i + (माप_प्रकार)len > matchlen)
			अवरोध;
		i += (माप_प्रकार)len;
	}
	/* If so, truncate */
	अगर (i < matchlen)
		matchlen = i;

	अगर (matchlen > म_माप(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		वापस tmp;
	}

	वापस xstrdup(word);
}

/* Autocomplete a sftp command */
अटल पूर्णांक
complete_cmd_parse(Edit_पंक्ति *el, अक्षर *cmd, पूर्णांक lastarg, अक्षर quote,
    पूर्णांक terminated)
{
	u_int y, गिनती = 0, cmdlen, tmplen;
	अक्षर *tmp, **list, argterm[3];
	स्थिर पंक्ति_Info *lf;

	list = xcalloc((माप(cmds) / माप(*cmds)) + 1, माप(अक्षर *));

	/* No command specified: display all available commands */
	अगर (cmd == शून्य) {
		क्रम (y = 0; cmds[y].c; y++)
			list[गिनती++] = xstrdup(cmds[y].c);

		list[गिनती] = शून्य;
		complete_display(list, 0);

		क्रम (y = 0; list[y] != शून्य; y++)
			मुक्त(list[y]);
		मुक्त(list);
		वापस गिनती;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = म_माप(cmd);
	क्रम (y = 0; cmds[y].c; y++)  {
		अगर (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[गिनती++] = xstrdup(cmds[y].c);
	}
	list[गिनती] = शून्य;

	अगर (गिनती == 0) {
		मुक्त(list);
		वापस 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, गिनती);
	अगर (गिनती > 1)
		complete_display(list, 0);

	क्रम (y = 0; list[y]; y++)
		मुक्त(list[y]);
	मुक्त(list);

	अगर (tmp != शून्य) {
		tmplen = म_माप(tmp);
		cmdlen = म_माप(cmd);
		/* If cmd may be extended then do so */
		अगर (tmplen > cmdlen)
			अगर (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_पंक्ति(el);
		/* Terminate argument cleanly */
		अगर (गिनती == 1) {
			y = 0;
			अगर (!terminated)
				argterm[y++] = quote;
			अगर (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			अगर (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		मुक्त(tmp);
	}

	वापस गिनती;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
अटल पूर्णांक
complete_is_remote(अक्षर *cmd, पूर्णांक cmdarg) {
	पूर्णांक i;

	अगर (cmd == शून्य)
		वापस -1;

	क्रम (i = 0; cmds[i].c; i++) {
		अगर (!strncasecmp(cmd, cmds[i].c, म_माप(cmds[i].c))) {
			अगर (cmdarg == 1)
				वापस cmds[i].t;
			अन्यथा अगर (cmdarg == 2)
				वापस cmds[i].t2;
			अवरोध;
		}
	}

	वापस -1;
}

/* Autocomplete a filename "file" */
अटल पूर्णांक
complete_match(Edit_पंक्ति *el, काष्ठा sftp_conn *conn, अक्षर *remote_path,
    अक्षर *file, पूर्णांक remote, पूर्णांक lastarg, अक्षर quote, पूर्णांक terminated)
{
	glob_t g;
	अक्षर *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	पूर्णांक clen;
	स्थिर पंक्ति_Info *lf;

	/* Glob from "file" location */
	अगर (file == शून्य)
		tmp = xstrdup("*");
	अन्यथा
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	स_रखो(&g, 0, माप(g));
	अगर (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, शून्य, &g);
	} अन्यथा
		(व्योम)glob(tmp, GLOB_DOOFFS|GLOB_MARK, शून्य, &g);

	/* Determine length of pwd so we can trim completion display */
	क्रम (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		अगर (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			अगर (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			अवरोध;
		}
		अगर (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		अगर (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	मुक्त(tmp);
	tmp = शून्य;

	अगर (g.gl_matchc == 0)
		जाओ out;

	अगर (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	अगर (file == शून्य || hadglob)
		जाओ out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? शून्य : remote_path);
	मुक्त(tmp2);

	अगर (tmp == शून्य)
		जाओ out;

	tmplen = म_माप(tmp);
	filelen = म_माप(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	क्रम (i = 0; i < filelen; i++) {
		अगर (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} अन्यथा
			isesc = 0;
	}

	अगर (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = म_माप(tmp2);
		/* quote argument on way out */
		mblen(शून्य, 0);
		क्रम (i = 0; i < len; i += clen) {
			अगर ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (माप_प्रकार)clen > माप(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			स_नकल(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			चयन (tmp2[i]) {
			हाल '\'':
			हाल '"':
			हाल '\\':
			हाल '\t':
			हाल '[':
			हाल ' ':
			हाल '#':
			हाल '*':
				अगर (quote == '\0' || tmp2[i] == quote) {
					अगर (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					अवरोध;
				}
				/* FALLTHROUGH */
			शेष:
				अगर (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				अवरोध;
			}
		}
	}

	lf = el_पंक्ति(el);
	अगर (g.gl_matchc == 1) {
		i = 0;
		अगर (!terminated && quote != '\0')
			ins[i++] = quote;
		अगर (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		अगर (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	मुक्त(tmp);

 out:
	globfree(&g);
	वापस g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
अटल अचिन्हित अक्षर
complete(Edit_पंक्ति *el, पूर्णांक ch)
{
	अक्षर **argv, *पंक्ति, quote;
	पूर्णांक argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	स्थिर पंक्ति_Info *lf;
	काष्ठा complete_ctx *complete_ctx;

	lf = el_पंक्ति(el);
	अगर (el_get(el, EL_CLIENTDATA, (व्योम**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->बफर;
	पंक्ति = xmalloc(cursor + 1);
	स_नकल(पंक्ति, lf->बफर, cursor);
	पंक्ति[cursor] = '\0';
	argv = makeargv(पंक्ति, &carg, 1, &quote, &terminated);
	मुक्त(पंक्ति);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->बफर;
	पंक्ति = xmalloc(len + 1);
	स_नकल(पंक्ति, lf->बफर, len);
	पंक्ति[len] = '\0';
	argv = makeargv(पंक्ति, &argc, 1, शून्य, शून्य);

	/* Ensure cursor is at EOL or a argument boundary */
	अगर (पंक्ति[cursor] != ' ' && पंक्ति[cursor] != '\0' &&
	    पंक्ति[cursor] != '\n') {
		मुक्त(पंक्ति);
		वापस ret;
	}

	अगर (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, शून्य, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} अन्यथा अगर (carg == 1 && cursor > 0 && पंक्ति[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		अगर (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} अन्यथा अगर (carg >= 1) {
		/* Handle file parsing */
		पूर्णांक remote = 0;
		पूर्णांक i = 0, cmdarg = 0;
		अक्षर *filematch = शून्य;

		अगर (carg > 1 && पंक्ति[cursor-1] != ' ')
			filematch = argv[carg - 1];

		क्रम (i = 1; i < carg; i++) {
			/* Skip flags */
			अगर (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		अगर (पंक्ति[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		अगर ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	मुक्त(पंक्ति);
	वापस ret;
}
#पूर्ण_अगर /* USE_LIBEDIT */

अटल पूर्णांक
interactive_loop(काष्ठा sftp_conn *conn, अक्षर *file1, अक्षर *file2)
{
	अक्षर *remote_path;
	अक्षर *dir = शून्य, *startdir = शून्य;
	अक्षर cmd[2048];
	पूर्णांक err, interactive;
	Edit_पंक्ति *el = शून्य;
#अगर_घोषित USE_LIBEDIT
	स्थिर अक्षर *editor;
	History *hl = शून्य;
	HistEvent hev;
	बाह्य अक्षर *__progname;
	काष्ठा complete_ctx complete_ctx;

	अगर (!batchmode && isatty(STDIN_FILENO)) {
		अगर ((el = el_init(__progname, मानक_निवेश, मानक_निकास, मानक_त्रुटि)) == शून्य)
			fatal("Couldn't initialise editline");
		अगर ((hl = history_init()) == शून्य)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, शून्य);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, शून्य);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (व्योम*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", शून्य);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", शून्य);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", शून्य);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", शून्य);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", शून्य);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", शून्य);

		/* el_source() may have changed EL_EDITOR to vi */
		अगर (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", शून्य);
	}
#पूर्ण_अगर /* USE_LIBEDIT */

	अगर ((remote_path = sftp_realpath(conn, ".")) == शून्य)
		fatal("Need cwd");
	startdir = xstrdup(remote_path);

	अगर (file1 != शून्य) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		अगर (sftp_remote_is_dir(conn, dir) && file2 == शून्य) {
			अगर (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, माप cmd, "cd \"%s\"", dir);
			अगर (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				मुक्त(dir);
				मुक्त(startdir);
				मुक्त(remote_path);
				मुक्त(conn);
				वापस (-1);
			}
		} अन्यथा {
			err = process_get(conn, dir, file2, remote_path, 0, 0,
			    global_aflag, 0);
			मुक्त(dir);
			मुक्त(startdir);
			मुक्त(remote_path);
			मुक्त(conn);
			वापस (err);
		}
		मुक्त(dir);
	}

	रखो_भबफ(मानक_निकास, शून्य, _IOLBF, 0);
	रखो_भबफ(infile, शून्य, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	क्रम (;;) {
		काष्ठा sigaction sa;

		interrupted = 0;
		स_रखो(&sa, 0, माप(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		अगर (sigaction(संक_विघ्न, &sa, शून्य) == -1) {
			debug3("sigaction(%s): %s", strsignal(संक_विघ्न),
			    म_त्रुटि(त्रुटि_सं));
			अवरोध;
		}
		अगर (el == शून्य) {
			अगर (interactive) {
				म_लिखो("sftp> ");
				ख_साफ(मानक_निकास);
			}
			अगर (ख_माला_लो(cmd, माप(cmd), infile) == शून्य) {
				अगर (interactive)
					म_लिखो("\n");
				अगर (interrupted)
					जारी;
				अवरोध;
			}
		} अन्यथा {
#अगर_घोषित USE_LIBEDIT
			स्थिर अक्षर *पंक्ति;
			पूर्णांक गिनती = 0;

			अगर ((पंक्ति = el_gets(el, &गिनती)) == शून्य ||
			    गिनती <= 0) {
				म_लिखो("\n");
				अगर (interrupted)
					जारी;
				अवरोध;
			}
			history(hl, &hev, H_ENTER, पंक्ति);
			अगर (strlcpy(cmd, पंक्ति, माप(cmd)) >= माप(cmd)) {
				ख_लिखो(मानक_त्रुटि, "Error: input line too long\n");
				जारी;
			}
#पूर्ण_अगर /* USE_LIBEDIT */
		}

		cmd[म_खोज(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(संक_विघ्न, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == शून्य);
		अगर (err != 0)
			अवरोध;
	}
	ssh_signal(SIGCHLD, संक_पूर्व);
	मुक्त(remote_path);
	मुक्त(startdir);
	मुक्त(conn);

#अगर_घोषित USE_LIBEDIT
	अगर (hl != शून्य)
		history_end(hl);
	अगर (el != शून्य)
		el_end(el);
#पूर्ण_अगर /* USE_LIBEDIT */

	/* err == 1 signifies normal "quit" exit */
	वापस (err >= 0 ? 0 : -1);
}

अटल व्योम
connect_to_server(अक्षर *path, अक्षर **args, पूर्णांक *in, पूर्णांक *out)
{
	पूर्णांक c_in, c_out;
#अगर_घोषित USE_PIPES
	पूर्णांक pin[2], pout[2];

	अगर ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", म_त्रुटि(त्रुटि_सं));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#अन्यथा /* USE_PIPES */
	पूर्णांक inout[2];

	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", म_त्रुटि(त्रुटि_सं));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#पूर्ण_अगर /* USE_PIPES */
	FD_CLOSEONEXEC(*in);
	FD_CLOSEONEXEC(*out);

	अगर ((sshpid = विभाजन()) == -1)
		fatal("fork: %s", म_त्रुटि(त्रुटि_सं));
	अन्यथा अगर (sshpid == 0) {
		अगर ((dup2(c_in, STDIN_FILENO) == -1) ||
		    (dup2(c_out, STDOUT_FILENO) == -1)) {
			ख_लिखो(मानक_त्रुटि, "dup2: %s\n", म_त्रुटि(त्रुटि_सं));
			_निकास(1);
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
		_निकास(1);
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

अटल व्योम
usage(व्योम)
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
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	पूर्णांक r, in, out, ch, err, tmp, port = -1, noisy = 0;
	अक्षर *host = शून्य, *user, *cp, **cpp, *file2 = शून्य;
	पूर्णांक debug_level = 0;
	अक्षर *file1 = शून्य, *sftp_server = शून्य;
	अक्षर *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = शून्य;
	स्थिर अक्षर *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	बाह्य पूर्णांक optind;
	बाह्य अक्षर *optarg;
	काष्ठा sftp_conn *conn;
	माप_प्रकार copy_बफर_len = 0;
	माप_प्रकार अंक_requests = 0;
	दीर्घ दीर्घ llv, limit_kbps = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	__progname = ssh_get_progname(argv[0]);
	स_रखो(&args, '\0', माप(args));
	args.list = शून्य;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = मानक_निवेश;

	जबतक ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:")) != -1) {
		चयन (ch) {
		/* Passed through to ssh(1) */
		हाल 'A':
		हाल '4':
		हाल '6':
		हाल 'C':
			addargs(&args, "-%c", ch);
			अवरोध;
		/* Passed through to ssh(1) with argument */
		हाल 'F':
		हाल 'J':
		हाल 'c':
		हाल 'i':
		हाल 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			अवरोध;
		हाल 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			अवरोध;
		हाल 'P':
			port = a2port(optarg);
			अगर (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			अवरोध;
		हाल 'v':
			अगर (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			अवरोध;
		हाल '1':
			fatal("SSH protocol v.1 is no longer supported");
			अवरोध;
		हाल '2':
			/* accept silently */
			अवरोध;
		हाल 'a':
			global_aflag = 1;
			अवरोध;
		हाल 'B':
			copy_बफर_len = म_से_दीर्घ(optarg, &cp, 10);
			अगर (copy_बफर_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			अवरोध;
		हाल 'b':
			अगर (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			अगर (म_भेद(optarg, "-") != 0 &&
			    (infile = ख_खोलो(optarg, "r")) == शून्य)
				fatal("%s (%s).", म_त्रुटि(त्रुटि_सं), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			addargs(&args, "-obatchmode yes");
			अवरोध;
		हाल 'f':
			global_fflag = 1;
			अवरोध;
		हाल 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			अवरोध;
		हाल 'p':
			global_pflag = 1;
			अवरोध;
		हाल 'D':
			sftp_direct = optarg;
			अवरोध;
		हाल 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			अगर (errstr != शून्य)
				usage();
			limit_kbps *= 1024; /* kbps */
			अवरोध;
		हाल 'r':
			global_rflag = 1;
			अवरोध;
		हाल 'R':
			अंक_requests = म_से_दीर्घ(optarg, &cp, 10);
			अगर (अंक_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			अवरोध;
		हाल 's':
			sftp_server = optarg;
			अवरोध;
		हाल 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			अवरोध;
		हाल 'X':
			/* Please keep in sync with ssh.c -X */
			अगर (म_भेदन(optarg, "buffer=", 7) == 0) {
				r = scan_scaled(optarg + 7, &llv);
				अगर (r == 0 && (llv <= 0 || llv > 256 * 1024)) {
					r = -1;
					त्रुटि_सं = EINVAL;
				}
				अगर (r == -1) {
					fatal("Invalid buffer size \"%s\": %s",
					     optarg + 7, म_त्रुटि(त्रुटि_सं));
				}
				copy_बफर_len = (माप_प्रकार)llv;
			} अन्यथा अगर (म_भेदन(optarg, "nrequests=", 10) == 0) {
				llv = strtonum(optarg + 10, 1, 256 * 1024,
				    &errstr);
				अगर (errstr != शून्य) {
					fatal("Invalid number of requests "
					    "\"%s\": %s", optarg + 10, errstr);
				}
				अंक_requests = (माप_प्रकार)llv;
			} अन्यथा {
				fatal("Invalid -X option");
			}
			अवरोध;
		हाल 'h':
		शेष:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	अगर (!isatty(STDERR_FILENO))
		showprogress = 0;

	अगर (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	अगर (sftp_direct == शून्य) {
		अगर (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		चयन (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		हाल -1:
			usage();
			अवरोध;
		हाल 0:
			अगर (tmp != -1)
				port = tmp;
			अवरोध;
		शेष:
			/* Try with user, host and path. */
			अगर (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				अवरोध;
			/* Try with user and host. */
			अगर (parse_user_host_port(*argv, &user, &host, शून्य)
			    == 0)
				अवरोध;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			अवरोध;
		}
		file2 = *(argv + 1);

		अगर (!*host) {
			ख_लिखो(मानक_त्रुटि, "Missing hostname\n");
			usage();
		}

		अगर (port != -1)
			addargs(&args, "-oPort %d", port);
		अगर (user != शून्य) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		अगर (sftp_server == शून्य || म_अक्षर(sftp_server, '/') == शून्य)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != शून्य ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} अन्यथा {
		अगर ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		अगर (cpp[0] == शून्य)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_बफर_len, अंक_requests, limit_kbps);
	अगर (conn == शून्य)
		fatal("Couldn't initialise connection to server");

	अगर (!quiet) {
		अगर (sftp_direct == शून्य)
			ख_लिखो(मानक_त्रुटि, "Connected to %s.\n", host);
		अन्यथा
			ख_लिखो(मानक_त्रुटि, "Attached to %s.\n", sftp_direct);
	}

	err = interactive_loop(conn, file1, file2);

#अगर !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#पूर्ण_अगर

	बंद(in);
	बंद(out);
	अगर (batchmode)
		ख_बंद(infile);

	जबतक (waitpid(sshpid, शून्य, 0) == -1 && sshpid > 1)
		अगर (त्रुटि_सं != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    म_त्रुटि(त्रुटि_सं));

	निकास(err == 0 ? 0 : 1);
}
