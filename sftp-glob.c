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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"

ຈຳນວນເຕັມ sftp_glob(sa_nracanaa sftp_conn *, const var_na *, ຈຳນວນເຕັມ,
    ຈຳນວນເຕັມ (*)(const var_na *, ຈຳນວນເຕັມ), glob_t *);

sa_nracanaa SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	ຈຳນວນເຕັມ offset;
};

static sa_nracanaa {
	sa_nracanaa sftp_conn *conn;
} cur;

static void *
fudge_opendir(const var_na *path)
{
	sa_nracanaa SFTP_OPENDIR *r;

	r = xcalloc(1, parimaa_na(*r));

	ຖ້າ (sftp_readdir(cur.conn, path, &r->dir)) {
		free(r);
		ສົ່ງຄືນ(NULL);
	}

	r->offset = 0;

	ສົ່ງຄືນ((void *)r);
}

static sa_nracanaa dirent *
fudge_readdir(sa_nracanaa SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	static var_na buf[parimaa_na(sa_nracanaa dirent) + MAXPATHLEN];
	sa_nracanaa dirent *ret = (sa_nracanaa dirent *)buf;
#ifdef __GNU_LIBRARY__
	static ຈຳນວນເຕັມ inum = 1;
#endif /* __GNU_LIBRARY__ */

	ຖ້າ (od->dir[od->offset] == NULL)
		ສົ່ງຄືນ(NULL);

	memset(buf, 0, parimaa_na(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#ບໍ່ດັ່ງນັ້ນ
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    parimaa_na(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	ຖ້າ (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	ສົ່ງຄືນ(ret);
}

static void
fudge_closedir(sa_nracanaa SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	free(od);
}

static ຈຳນວນເຕັມ
fudge_lstat(const var_na *path, sa_nracanaa stat *st)
{
	Attrib a;

	ຖ້າ (sftp_lstat(cur.conn, path, 1, &a) != 0)
		ສົ່ງຄືນ -1;

	attrib_to_stat(&a, st);

	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
fudge_stat(const var_na *path, sa_nracanaa stat *st)
{
	Attrib a;

	ຖ້າ (sftp_stat(cur.conn, path, 1, &a) != 0)
		ສົ່ງຄືນ -1;

	attrib_to_stat(&a, st);

	ສົ່ງຄືນ(0);
}

ຈຳນວນເຕັມ
sftp_glob(sa_nracanaa sftp_conn *conn, const var_na *pattern, ຈຳນວນເຕັມ flags,
    ຈຳນວນເຕັມ (*errfunc)(const var_na *, ຈຳນວນເຕັມ), glob_t *pglob)
{
	ຈຳນວນເຕັມ r;
	size_t l;
	var_na *s;
	sa_nracanaa stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (sa_nracanaa dirent *(*)(void *))fudge_readdir;
	pglob->gl_closedir = (void (*)(void *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, parimaa_na(cur));
	cur.conn = conn;

	ຖ້າ ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		ສົ່ງຄືນ r;
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
	ຖ້າ ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != NULL &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		ຖ້າ (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			ຖ້າ ((s = realloc(s, l + 2)) != NULL) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	ສົ່ງຄືນ 0;
}
