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

ಪೂರ್ಣಾಂಕ sftp_glob(ರಚನೆ sftp_conn *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ,
    ಪೂರ್ಣಾಂಕ (*)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ), glob_t *);

ರಚನೆ SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಾನಾಂತರ;
};

ಸ್ಥಿರ ರಚನೆ {
	ರಚನೆ sftp_conn *conn;
} cur;

ಸ್ಥಿರ ಶೂನ್ಯ *
fudge_opendir(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ SFTP_OPENDIR *r;

	r = xcalloc(1, ಗಾತ್ರ(*r));

	ಆದರೆ (sftp_readdir(cur.conn, ಮಾರ್ಗ, &r->dir)) {
		ಬಿಡುಗಡೆ(r);
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
	}

	r->ಸ್ಥಾನಾಂತರ = 0;

	ಹಿಂತಿರುಗಿ((ಶೂನ್ಯ *)r);
}

ಸ್ಥಿರ ರಚನೆ dirent *
fudge_readdir(ರಚನೆ SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	ಸ್ಥಿರ ಅಕ್ಷರ buf[ಗಾತ್ರ(ರಚನೆ dirent) + MAXPATHLEN];
	ರಚನೆ dirent *ret = (ರಚನೆ dirent *)buf;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __GNU_LIBRARY__
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ inum = 1;
#ಆದರೆ_ಅಂತ್ಯ /* __GNU_LIBRARY__ */

	ಆದರೆ (od->dir[od->ಸ್ಥಾನಾಂತರ] == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);

	memset(buf, 0, ಗಾತ್ರ(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->ಸ್ಥಾನಾಂತರ++]->filename, MAXPATHLEN);
#ಇಲ್ಲದಿದ್ದರೆ
	strlcpy(ret->d_name, od->dir[od->ಸ್ಥಾನಾಂತರ++]->filename,
	    ಗಾತ್ರ(ret->d_name));
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	ಆದರೆ (!inum)
		inum = 1;
#ಆದರೆ_ಅಂತ್ಯ /* __GNU_LIBRARY__ */

	ಹಿಂತಿರುಗಿ(ret);
}

ಸ್ಥಿರ ಶೂನ್ಯ
fudge_closedir(ರಚನೆ SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	ಬಿಡುಗಡೆ(od);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fudge_lstat(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ stat *st)
{
	Attrib a;

	ಆದರೆ (sftp_lstat(cur.conn, ಮಾರ್ಗ, 1, &a) != 0)
		ಹಿಂತಿರುಗಿ -1;

	attrib_ಗಮ್ಯ_stat(&a, st);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fudge_stat(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ stat *st)
{
	Attrib a;

	ಆದರೆ (sftp_stat(cur.conn, ಮಾರ್ಗ, 1, &a) != 0)
		ಹಿಂತಿರುಗಿ -1;

	attrib_ಗಮ್ಯ_stat(&a, st);

	ಹಿಂತಿರುಗಿ(0);
}

ಪೂರ್ಣಾಂಕ
sftp_glob(ರಚನೆ sftp_conn *conn, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ನಮೂನೆ, ಪೂರ್ಣಾಂಕ flags,
    ಪೂರ್ಣಾಂಕ (*errfunc)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ), glob_t *pglob)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t l;
	ಅಕ್ಷರ *s;
	ರಚನೆ stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (ರಚನೆ dirent *(*)(ಶೂನ್ಯ *))fudge_readdir;
	pglob->gl_closedir = (ಶೂನ್ಯ (*)(ಶೂನ್ಯ *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, ಗಾತ್ರ(cur));
	cur.conn = conn;

	ಆದರೆ ((r = glob(ನಮೂನೆ, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		ಹಿಂತಿರುಗಿ r;
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
	ಆದರೆ ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ಖಾಲಿ &&
	    (l = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s)) > 0 && s[l-1] != '/') {
		ಆದರೆ (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			ಆದರೆ ((s = realloc(s, l + 2)) != ಖಾಲಿ) {
				ಸ್ಮರಣೆ_ನಕಲು(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}
