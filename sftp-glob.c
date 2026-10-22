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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sftp.h"
#ಅನ್ತರ್ಭಾವ "sftp-common.h"
#ಅನ್ತರ್ಭಾವ "sftp-client.h"

ಪೂರ್ಣಾಙ್ಕ sftp_glob(ಸಂರಚನಾ sftp_conn *, ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ,
    ಪೂರ್ಣಾಙ್ಕ (*)(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ), glob_t *);

ಸಂರಚನಾ SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	ಪೂರ್ಣಾಙ್ಕ offset;
};

ಸ್ಥಿರ ಸಂರಚನಾ {
	ಸಂರಚನಾ sftp_conn *conn;
} cur;

ಸ್ಥಿರ ಶೂನ್ಯ *
fudge_opendir(ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ SFTP_OPENDIR *r;

	r = xcalloc(1, ಪರಿಮಾಣ(*r));

	ಯದಿ (sftp_readdir(cur.conn, path, &r->dir)) {
		ಮುಕ್ತ(r);
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
	}

	r->offset = 0;

	ಪ್ರತ್ಯಾಗಮ((ಶೂನ್ಯ *)r);
}

ಸ್ಥಿರ ಸಂರಚನಾ dirent *
fudge_readdir(ಸಂರಚನಾ SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	ಸ್ಥಿರ ವರ್ಣ buf[ಪರಿಮಾಣ(ಸಂರಚನಾ dirent) + MAXPATHLEN];
	ಸಂರಚನಾ dirent *ret = (ಸಂರಚನಾ dirent *)buf;
#ifdef __GNU_LIBRARY__
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ inum = 1;
#endif /* __GNU_LIBRARY__ */

	ಯದಿ (od->dir[od->offset] == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);

	memset(buf, 0, ಪರಿಮಾಣ(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#ಅನ್ಯಥಾ
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    ಪರಿಮಾಣ(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	ಯದಿ (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	ಪ್ರತ್ಯಾಗಮ(ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
fudge_closedir(ಸಂರಚನಾ SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	ಮುಕ್ತ(od);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fudge_lstat(ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ stat *st)
{
	Attrib a;

	ಯದಿ (sftp_lstat(cur.conn, path, 1, &a) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	attrib_to_stat(&a, st);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fudge_stat(ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ stat *st)
{
	Attrib a;

	ಯದಿ (sftp_stat(cur.conn, path, 1, &a) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	attrib_to_stat(&a, st);

	ಪ್ರತ್ಯಾಗಮ(0);
}

ಪೂರ್ಣಾಙ್ಕ
sftp_glob(ಸಂರಚನಾ sftp_conn *conn, ಧ್ರುವ ವರ್ಣ *pattern, ಪೂರ್ಣಾಙ್ಕ flags,
    ಪೂರ್ಣಾಙ್ಕ (*errfunc)(ಧ್ರುವ ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ), glob_t *pglob)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t l;
	ವರ್ಣ *s;
	ಸಂರಚನಾ stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (ಸಂರಚನಾ dirent *(*)(ಶೂನ್ಯ *))fudge_readdir;
	pglob->gl_closedir = (ಶೂನ್ಯ (*)(ಶೂನ್ಯ *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, ಪರಿಮಾಣ(cur));
	cur.conn = conn;

	ಯದಿ ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
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
	ಯದಿ ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ರಿಕ್ತ &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		ಯದಿ (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			ಯದಿ ((s = realloc(s, l + 2)) != ರಿಕ್ತ) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}
