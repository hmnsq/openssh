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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>

#شامل <dirent.h>
#شامل <glob.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>

#شامل "xmalloc.h"
#شامل "sftp.h"
#شامل "sftp-common.h"
#شامل "sftp-client.h"

صحیح sftp_glob(ساخت sftp_conn *, ثابت حرف *, صحیح,
    صحیح (*)(ثابت حرف *, صحیح), glob_t *);

ساخت SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	صحیح انحراف;
};

ساکن ساخت {
	ساخت sftp_conn *conn;
} cur;

ساکن خالی *
fudge_opendir(ثابت حرف *راستہ)
{
	ساخت SFTP_OPENDIR *r;

	r = xcalloc(1, حجم(*r));

	اگر (sftp_readdir(cur.conn, راستہ, &r->dir)) {
		آزاد(r);
		واپس(تہی);
	}

	r->انحراف = 0;

	واپس((خالی *)r);
}

ساکن ساخت dirent *
fudge_readdir(ساخت SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	ساکن حرف buf[حجم(ساخت dirent) + MAXPATHLEN];
	ساخت dirent *ret = (ساخت dirent *)buf;
#اگر_تعریف_شدہ __GNU_LIBRARY__
	ساکن صحیح inum = 1;
#اگر_ختم /* __GNU_LIBRARY__ */

	اگر (od->dir[od->انحراف] == تہی)
		واپس(تہی);

	memset(buf, 0, حجم(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#اگر_تعریف_شدہ BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->انحراف++]->filename, MAXPATHLEN);
#ورنہ
	strlcpy(ret->d_name, od->dir[od->انحراف++]->filename,
	    حجم(ret->d_name));
#اگر_ختم
#اگر_تعریف_شدہ __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	اگر (!inum)
		inum = 1;
#اگر_ختم /* __GNU_LIBRARY__ */

	واپس(ret);
}

ساکن خالی
fudge_closedir(ساخت SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	آزاد(od);
}

ساکن صحیح
fudge_lstat(ثابت حرف *راستہ, ساخت stat *st)
{
	Attrib a;

	اگر (sftp_lstat(cur.conn, راستہ, 1, &a) != 0)
		واپس -1;

	attrib_مقصد_stat(&a, st);

	واپس 0;
}

ساکن صحیح
fudge_stat(ثابت حرف *راستہ, ساخت stat *st)
{
	Attrib a;

	اگر (sftp_stat(cur.conn, راستہ, 1, &a) != 0)
		واپس -1;

	attrib_مقصد_stat(&a, st);

	واپس(0);
}

صحیح
sftp_glob(ساخت sftp_conn *conn, ثابت حرف *نمونہ, صحیح flags,
    صحیح (*errfunc)(ثابت حرف *, صحیح), glob_t *pglob)
{
	صحیح r;
	سائز_t l;
	حرف *s;
	ساخت stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (ساخت dirent *(*)(خالی *))fudge_readdir;
	pglob->gl_closedir = (خالی (*)(خالی *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, حجم(cur));
	cur.conn = conn;

	اگر ((r = glob(نمونہ, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		واپس r;
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
	اگر ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != تہی &&
	    (l = لڑی_لمبائی(s)) > 0 && s[l-1] != '/') {
		اگر (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			اگر ((s = realloc(s, l + 2)) != تہی) {
				حافظہ_نقل(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	واپس 0;
}
