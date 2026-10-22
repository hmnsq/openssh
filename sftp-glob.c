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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>

#ضمن <dirent.h>
#ضمن <glob.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "xmalloc.h"
#ضمن "sftp.h"
#ضمن "sftp-common.h"
#ضمن "sftp-client.h"

صحيح sftp_glob(بنية sftp_conn *, ثابت حرف *, صحيح,
    صحيح (*)(ثابت حرف *, صحيح), glob_t *);

بنية SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	صحيح جابه_جایی;
};

ساكن بنية {
	بنية sftp_conn *conn;
} cur;

ساكن فراغ *
fudge_opendir(ثابت حرف *مسیر)
{
	بنية SFTP_OPENDIR *r;

	r = xcalloc(1, حجم(*r));

	إذا (sftp_readdir(cur.conn, مسیر, &r->dir)) {
		حرر(r);
		أرجع(عدم);
	}

	r->جابه_جایی = 0;

	أرجع((فراغ *)r);
}

ساكن بنية dirent *
fudge_readdir(بنية SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	ساكن حرف buf[حجم(بنية dirent) + MAXPATHLEN];
	بنية dirent *ret = (بنية dirent *)buf;
#اگر_تعریف_شده __GNU_LIBRARY__
	ساكن صحيح inum = 1;
#پایان_اگر /* __GNU_LIBRARY__ */

	إذا (od->dir[od->جابه_جایی] == عدم)
		أرجع(عدم);

	memset(buf, 0, حجم(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#اگر_تعریف_شده BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->جابه_جایی++]->filename, MAXPATHLEN);
#وإلا
	strlcpy(ret->d_name, od->dir[od->جابه_جایی++]->filename,
	    حجم(ret->d_name));
#پایان_اگر
#اگر_تعریف_شده __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	إذا (!inum)
		inum = 1;
#پایان_اگر /* __GNU_LIBRARY__ */

	أرجع(ret);
}

ساكن فراغ
fudge_closedir(بنية SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	حرر(od);
}

ساكن صحيح
fudge_lstat(ثابت حرف *مسیر, بنية stat *st)
{
	Attrib a;

	إذا (sftp_lstat(cur.conn, مسیر, 1, &a) != 0)
		أرجع -1;

	attrib_مقصد_stat(&a, st);

	أرجع 0;
}

ساكن صحيح
fudge_stat(ثابت حرف *مسیر, بنية stat *st)
{
	Attrib a;

	إذا (sftp_stat(cur.conn, مسیر, 1, &a) != 0)
		أرجع -1;

	attrib_مقصد_stat(&a, st);

	أرجع(0);
}

صحيح
sftp_glob(بنية sftp_conn *conn, ثابت حرف *الگو, صحيح flags,
    صحيح (*errfunc)(ثابت حرف *, صحيح), glob_t *pglob)
{
	صحيح r;
	اندازه_t l;
	حرف *s;
	بنية stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (بنية dirent *(*)(فراغ *))fudge_readdir;
	pglob->gl_closedir = (فراغ (*)(فراغ *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, حجم(cur));
	cur.conn = conn;

	إذا ((r = glob(الگو, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		أرجع r;
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
	إذا ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != عدم &&
	    (l = طول_رشته(s)) > 0 && s[l-1] != '/') {
		إذا (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			إذا ((s = realloc(s, l + 2)) != عدم) {
				کپی_حافظه(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	أرجع 0;
}
