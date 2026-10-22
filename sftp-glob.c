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

صحیح sftp_glob(ساختار sftp_conn *, ثابت نویسه *, صحیح,
    صحیح (*)(ثابت نویسه *, صحیح), glob_t *);

ساختار SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	صحیح offset;
};

ایستا ساختار {
	ساختار sftp_conn *conn;
} cur;

ایستا تهی *
fudge_opendir(ثابت نویسه *path)
{
	ساختار SFTP_OPENDIR *r;

	r = xcalloc(1, اندازه(*r));

	اگر (sftp_readdir(cur.conn, path, &r->dir)) {
		آزاد(r);
		بازگشت(پوچ);
	}

	r->offset = 0;

	بازگشت((تهی *)r);
}

ایستا ساختار dirent *
fudge_readdir(ساختار SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	ایستا نویسه buf[اندازه(ساختار dirent) + MAXPATHLEN];
	ساختار dirent *ret = (ساختار dirent *)buf;
#ifdef __GNU_LIBRARY__
	ایستا صحیح inum = 1;
#endif /* __GNU_LIBRARY__ */

	اگر (od->dir[od->offset] == پوچ)
		بازگشت(پوچ);

	memset(buf, 0, اندازه(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#وگرنه
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    اندازه(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	اگر (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	بازگشت(ret);
}

ایستا تهی
fudge_closedir(ساختار SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	آزاد(od);
}

ایستا صحیح
fudge_lstat(ثابت نویسه *path, ساختار stat *st)
{
	Attrib a;

	اگر (sftp_lstat(cur.conn, path, 1, &a) != 0)
		بازگشت -1;

	attrib_to_stat(&a, st);

	بازگشت 0;
}

ایستا صحیح
fudge_stat(ثابت نویسه *path, ساختار stat *st)
{
	Attrib a;

	اگر (sftp_stat(cur.conn, path, 1, &a) != 0)
		بازگشت -1;

	attrib_to_stat(&a, st);

	بازگشت(0);
}

صحیح
sftp_glob(ساختار sftp_conn *conn, ثابت نویسه *pattern, صحیح flags,
    صحیح (*errfunc)(ثابت نویسه *, صحیح), glob_t *pglob)
{
	صحیح r;
	size_t l;
	نویسه *s;
	ساختار stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (ساختار dirent *(*)(تهی *))fudge_readdir;
	pglob->gl_closedir = (تهی (*)(تهی *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, اندازه(cur));
	cur.conn = conn;

	اگر ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		بازگشت r;
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
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != پوچ &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		اگر (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			اگر ((s = realloc(s, l + 2)) != پوچ) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	بازگشت 0;
}
