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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>

#அந்தர்பாவ <dirent.h>
#அந்தர்பாவ <glob.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "sftp-common.h"
#அந்தர்பாவ "sftp-client.h"

முழு sftp_glob(கட்டமைப்பு sftp_conn *, மாறிலி எழுத்து *, முழு,
    முழு (*)(மாறிலி எழுத்து *, முழு), glob_t *);

கட்டமைப்பு SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	முழு offset;
};

நிலையான கட்டமைப்பு {
	கட்டமைப்பு sftp_conn *conn;
} cur;

நிலையான வெறுமை *
fudge_opendir(மாறிலி எழுத்து *path)
{
	கட்டமைப்பு SFTP_OPENDIR *r;

	r = xcalloc(1, அளவு(*r));

	எனில் (sftp_readdir(cur.conn, path, &r->dir)) {
		விடுவி(r);
		திரும்பு(வெற்று);
	}

	r->offset = 0;

	திரும்பு((வெறுமை *)r);
}

நிலையான கட்டமைப்பு dirent *
fudge_readdir(கட்டமைப்பு SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	நிலையான எழுத்து buf[அளவு(கட்டமைப்பு dirent) + MAXPATHLEN];
	கட்டமைப்பு dirent *ret = (கட்டமைப்பு dirent *)buf;
#ifdef __GNU_LIBRARY__
	நிலையான முழு inum = 1;
#endif /* __GNU_LIBRARY__ */

	எனில் (od->dir[od->offset] == வெற்று)
		திரும்பு(வெற்று);

	memset(buf, 0, அளவு(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#இல்லையெனில்
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    அளவு(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	எனில் (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	திரும்பு(ret);
}

நிலையான வெறுமை
fudge_closedir(கட்டமைப்பு SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	விடுவி(od);
}

நிலையான முழு
fudge_lstat(மாறிலி எழுத்து *path, கட்டமைப்பு stat *st)
{
	Attrib a;

	எனில் (sftp_lstat(cur.conn, path, 1, &a) != 0)
		திரும்பு -1;

	attrib_to_stat(&a, st);

	திரும்பு 0;
}

நிலையான முழு
fudge_stat(மாறிலி எழுத்து *path, கட்டமைப்பு stat *st)
{
	Attrib a;

	எனில் (sftp_stat(cur.conn, path, 1, &a) != 0)
		திரும்பு -1;

	attrib_to_stat(&a, st);

	திரும்பு(0);
}

முழு
sftp_glob(கட்டமைப்பு sftp_conn *conn, மாறிலி எழுத்து *pattern, முழு flags,
    முழு (*errfunc)(மாறிலி எழுத்து *, முழு), glob_t *pglob)
{
	முழு r;
	size_t l;
	எழுத்து *s;
	கட்டமைப்பு stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (கட்டமைப்பு dirent *(*)(வெறுமை *))fudge_readdir;
	pglob->gl_closedir = (வெறுமை (*)(வெறுமை *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, அளவு(cur));
	cur.conn = conn;

	எனில் ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		திரும்பு r;
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
	எனில் ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != வெற்று &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		எனில் (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			எனில் ((s = realloc(s, l + 2)) != வெற்று) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	திரும்பு 0;
}
