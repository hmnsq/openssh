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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <dirent.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <glob.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-client.h"

ਪੂਰਨ sftp_glob(ਬਣਤਰ sftp_conn *, ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ,
    ਪੂਰਨ (*)(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ), glob_t *);

ਬਣਤਰ SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	ਪੂਰਨ ਵਿੱਥ;
};

ਸਥਿਰ ਬਣਤਰ {
	ਬਣਤਰ sftp_conn *conn;
} cur;

ਸਥਿਰ ਖਾਲੀ *
fudge_opendir(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ SFTP_OPENDIR *r;

	r = xcalloc(1, ਆਕਾਰ(*r));

	ਜੇ (sftp_readdir(cur.conn, ਰਸਤਾ, &r->dir)) {
		ਮੁਕਤ(r);
		ਵਾਪਸ(ਨਿਰਾ);
	}

	r->ਵਿੱਥ = 0;

	ਵਾਪਸ((ਖਾਲੀ *)r);
}

ਸਥਿਰ ਬਣਤਰ dirent *
fudge_readdir(ਬਣਤਰ SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	ਸਥਿਰ ਅੱਖਰ buf[ਆਕਾਰ(ਬਣਤਰ dirent) + MAXPATHLEN];
	ਬਣਤਰ dirent *ret = (ਬਣਤਰ dirent *)buf;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __GNU_LIBRARY__
	ਸਥਿਰ ਪੂਰਨ inum = 1;
#ਜੇ_ਅੰਤ /* __GNU_LIBRARY__ */

	ਜੇ (od->dir[od->ਵਿੱਥ] == ਨਿਰਾ)
		ਵਾਪਸ(ਨਿਰਾ);

	memset(buf, 0, ਆਕਾਰ(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->ਵਿੱਥ++]->filename, MAXPATHLEN);
#ਨਹੀਂਤਾਂ
	strlcpy(ret->d_name, od->dir[od->ਵਿੱਥ++]->filename,
	    ਆਕਾਰ(ret->d_name));
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	ਜੇ (!inum)
		inum = 1;
#ਜੇ_ਅੰਤ /* __GNU_LIBRARY__ */

	ਵਾਪਸ(ret);
}

ਸਥਿਰ ਖਾਲੀ
fudge_closedir(ਬਣਤਰ SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	ਮੁਕਤ(od);
}

ਸਥਿਰ ਪੂਰਨ
fudge_lstat(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ stat *st)
{
	Attrib a;

	ਜੇ (sftp_lstat(cur.conn, ਰਸਤਾ, 1, &a) != 0)
		ਵਾਪਸ -1;

	attrib_ਮੰਜ਼ਿਲ_stat(&a, st);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
fudge_stat(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ stat *st)
{
	Attrib a;

	ਜੇ (sftp_stat(cur.conn, ਰਸਤਾ, 1, &a) != 0)
		ਵਾਪਸ -1;

	attrib_ਮੰਜ਼ਿਲ_stat(&a, st);

	ਵਾਪਸ(0);
}

ਪੂਰਨ
sftp_glob(ਬਣਤਰ sftp_conn *conn, ਅਚਲ ਅੱਖਰ *ਨਮੂਨਾ, ਪੂਰਨ flags,
    ਪੂਰਨ (*errfunc)(ਅਚਲ ਅੱਖਰ *, ਪੂਰਨ), glob_t *pglob)
{
	ਪੂਰਨ r;
	ਮਾਪ_t l;
	ਅੱਖਰ *s;
	ਬਣਤਰ stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (ਬਣਤਰ dirent *(*)(ਖਾਲੀ *))fudge_readdir;
	pglob->gl_closedir = (ਖਾਲੀ (*)(ਖਾਲੀ *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, ਆਕਾਰ(cur));
	cur.conn = conn;

	ਜੇ ((r = glob(ਨਮੂਨਾ, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		ਵਾਪਸ r;
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
	ਜੇ ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ਨਿਰਾ &&
	    (l = ਲੜੀ_ਲੰਬਾਈ(s)) > 0 && s[l-1] != '/') {
		ਜੇ (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			ਜੇ ((s = realloc(s, l + 2)) != ਨਿਰਾ) {
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	ਵਾਪਸ 0;
}
