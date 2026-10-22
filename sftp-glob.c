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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>

#অন্তর্ভাৱ <dirent.h>
#অন্তর্ভাৱ <glob.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "sftp.h"
#অন্তর্ভাৱ "sftp-common.h"
#অন্তর্ভাৱ "sftp-client.h"

পূর্ণাঙ্ক sftp_glob(সংরচনা sftp_conn *, ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক,
    পূর্ণাঙ্ক (*)(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক), glob_t *);

সংরচনা SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	পূর্ণাঙ্ক offset;
};

স্থির সংরচনা {
	সংরচনা sftp_conn *conn;
} cur;

স্থির শূন্য *
fudge_opendir(ধ্রুৱ ৱর্ণ *path)
{
	সংরচনা SFTP_OPENDIR *r;

	r = xcalloc(1, পরিমাণ(*r));

	যদি (sftp_readdir(cur.conn, path, &r->dir)) {
		মুক্ত(r);
		ঘূৰাই(রিক্ত);
	}

	r->offset = 0;

	ঘূৰাই((শূন্য *)r);
}

স্থির সংরচনা dirent *
fudge_readdir(সংরচনা SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	স্থির ৱর্ণ buf[পরিমাণ(সংরচনা dirent) + MAXPATHLEN];
	সংরচনা dirent *ret = (সংরচনা dirent *)buf;
#ifdef __GNU_LIBRARY__
	স্থির পূর্ণাঙ্ক inum = 1;
#endif /* __GNU_LIBRARY__ */

	যদি (od->dir[od->offset] == রিক্ত)
		ঘূৰাই(রিক্ত);

	memset(buf, 0, পরিমাণ(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#অন্যথা
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    পরিমাণ(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	যদি (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	ঘূৰাই(ret);
}

স্থির শূন্য
fudge_closedir(সংরচনা SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	মুক্ত(od);
}

স্থির পূর্ণাঙ্ক
fudge_lstat(ধ্রুৱ ৱর্ণ *path, সংরচনা stat *st)
{
	Attrib a;

	যদি (sftp_lstat(cur.conn, path, 1, &a) != 0)
		ঘূৰাই -1;

	attrib_to_stat(&a, st);

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
fudge_stat(ধ্রুৱ ৱর্ণ *path, সংরচনা stat *st)
{
	Attrib a;

	যদি (sftp_stat(cur.conn, path, 1, &a) != 0)
		ঘূৰাই -1;

	attrib_to_stat(&a, st);

	ঘূৰাই(0);
}

পূর্ণাঙ্ক
sftp_glob(সংরচনা sftp_conn *conn, ধ্রুৱ ৱর্ণ *pattern, পূর্ণাঙ্ক flags,
    পূর্ণাঙ্ক (*errfunc)(ধ্রুৱ ৱর্ণ *, পূর্ণাঙ্ক), glob_t *pglob)
{
	পূর্ণাঙ্ক r;
	size_t l;
	ৱর্ণ *s;
	সংরচনা stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (সংরচনা dirent *(*)(শূন্য *))fudge_readdir;
	pglob->gl_closedir = (শূন্য (*)(শূন্য *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, পরিমাণ(cur));
	cur.conn = conn;

	যদি ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		ঘূৰাই r;
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
	যদি ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != রিক্ত &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		যদি (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			যদি ((s = realloc(s, l + 2)) != রিক্ত) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	ঘূৰাই 0;
}
