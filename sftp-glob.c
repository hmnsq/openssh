/* $OpenBSD: sftp-glob.c,v 1.33 2023/09/10 23:12:32 djm Exp $ */
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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <dirent.h>
#അന്തര്ഭാവ <glob.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "sftp-common.h"
#അന്തര്ഭാവ "sftp-client.h"

പൂർണ്ണസംഖ്യ sftp_glob(ഘടന sftp_conn *, സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ,
    പൂർണ്ണസംഖ്യ (*)(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ), glob_t *);

ഘടന SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	പൂർണ്ണസംഖ്യ offset;
};

സ്ഥിതം ഘടന {
	ഘടന sftp_conn *conn;
} cur;

സ്ഥിതം ശൂന്യം *
fudge_opendir(സ്ഥിരം അക്ഷരം *path)
{
	ഘടന SFTP_OPENDIR *r;

	r = xcalloc(1, വലുപ്പം(*r));

	എങ്കിൽ (sftp_readdir(cur.conn, path, &r->dir)) {
		സ്വതന്ത്രം(r);
		തിരികെ(ശൂന്യ);
	}

	r->offset = 0;

	തിരികെ((ശൂന്യം *)r);
}

സ്ഥിതം ഘടന dirent *
fudge_readdir(ഘടന SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	സ്ഥിതം അക്ഷരം buf[വലുപ്പം(ഘടന dirent) + MAXPATHLEN];
	ഘടന dirent *ret = (ഘടന dirent *)buf;
#ifdef __GNU_LIBRARY__
	സ്ഥിതം പൂർണ്ണസംഖ്യ inum = 1;
#endif /* __GNU_LIBRARY__ */

	എങ്കിൽ (od->dir[od->offset] == ശൂന്യ)
		തിരികെ(ശൂന്യ);

	memset(buf, 0, വലുപ്പം(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#അല്ലെങ്കിൽ
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    വലുപ്പം(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	എങ്കിൽ (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	തിരികെ(ret);
}

സ്ഥിതം ശൂന്യം
fudge_closedir(ഘടന SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	സ്വതന്ത്രം(od);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
fudge_lstat(സ്ഥിരം അക്ഷരം *path, ഘടന stat *st)
{
	Attrib a;

	എങ്കിൽ (sftp_lstat(cur.conn, path, 1, &a) != 0)
		തിരികെ -1;

	attrib_to_stat(&a, st);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
fudge_stat(സ്ഥിരം അക്ഷരം *path, ഘടന stat *st)
{
	Attrib a;

	എങ്കിൽ (sftp_stat(cur.conn, path, 1, &a) != 0)
		തിരികെ -1;

	attrib_to_stat(&a, st);

	തിരികെ(0);
}

പൂർണ്ണസംഖ്യ
sftp_glob(ഘടന sftp_conn *conn, സ്ഥിരം അക്ഷരം *pattern, പൂർണ്ണസംഖ്യ flags,
    പൂർണ്ണസംഖ്യ (*errfunc)(സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ), glob_t *pglob)
{
	പൂർണ്ണസംഖ്യ r;
	size_t l;
	അക്ഷരം *s;
	ഘടന stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (ഘടന dirent *(*)(ശൂന്യം *))fudge_readdir;
	pglob->gl_closedir = (ശൂന്യം (*)(ശൂന്യം *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, വലുപ്പം(cur));
	cur.conn = conn;

	എങ്കിൽ ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		തിരികെ r;
	/*
	 * When both GLOB_NOCHECK and GLOB_MARK are active, a single gl_pathv
	 * entry has been returned and that entry has not already been marked,
	 * then check whether it needs a '/' appended as a directory mark.
	 *
	 * This ensures that a NOCHECK result is annotated as a directory.
	 * The glob(3) spec doesn't promise to mark NOCHECK entries, but doing
	 * it simplifies our callers (sftp/scp) considerably.
	 *
	 * XXX doesn't try to handle gl_offs.
	 */
	എങ്കിൽ ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ശൂന്യ &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		എങ്കിൽ (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			എങ്കിൽ ((s = realloc(s, l + 2)) != ശൂന്യ) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	തിരികെ 0;
}
