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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>

#অন্তর্ভাব <dirent.h>
#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sftp.h"
#অন্তর্ভাব "sftp-common.h"
#অন্তর্ভাব "sftp-client.h"

পূর্ণসংখ্যা sftp_glob(কাঠামো sftp_conn *, ধ্রুবক অক্ষর *, পূর্ণসংখ্যা,
    পূর্ণসংখ্যা (*)(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা), glob_t *);

কাঠামো SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	পূর্ণসংখ্যা offset;
};

স্থির কাঠামো {
	কাঠামো sftp_conn *conn;
} cur;

স্থির শূন্য *
fudge_opendir(ধ্রুবক অক্ষর *path)
{
	কাঠামো SFTP_OPENDIR *r;

	r = xcalloc(1, আকার(*r));

	যদি (sftp_readdir(cur.conn, path, &r->dir)) {
		মুক্ত(r);
		ফেরত(ফাঁকা);
	}

	r->offset = 0;

	ফেরত((শূন্য *)r);
}

স্থির কাঠামো dirent *
fudge_readdir(কাঠামো SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	স্থির অক্ষর buf[আকার(কাঠামো dirent) + MAXPATHLEN];
	কাঠামো dirent *ret = (কাঠামো dirent *)buf;
#ifdef __GNU_LIBRARY__
	স্থির পূর্ণসংখ্যা inum = 1;
#endif /* __GNU_LIBRARY__ */

	যদি (od->dir[od->offset] == ফাঁকা)
		ফেরত(ফাঁকা);

	memset(buf, 0, আকার(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#অন্যথা
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    আকার(ret->d_name));
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

	ফেরত(ret);
}

স্থির শূন্য
fudge_closedir(কাঠামো SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	মুক্ত(od);
}

স্থির পূর্ণসংখ্যা
fudge_lstat(ধ্রুবক অক্ষর *path, কাঠামো stat *st)
{
	Attrib a;

	যদি (sftp_lstat(cur.conn, path, 1, &a) != 0)
		ফেরত -1;

	attrib_to_stat(&a, st);

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
fudge_stat(ধ্রুবক অক্ষর *path, কাঠামো stat *st)
{
	Attrib a;

	যদি (sftp_stat(cur.conn, path, 1, &a) != 0)
		ফেরত -1;

	attrib_to_stat(&a, st);

	ফেরত(0);
}

পূর্ণসংখ্যা
sftp_glob(কাঠামো sftp_conn *conn, ধ্রুবক অক্ষর *pattern, পূর্ণসংখ্যা flags,
    পূর্ণসংখ্যা (*errfunc)(ধ্রুবক অক্ষর *, পূর্ণসংখ্যা), glob_t *pglob)
{
	পূর্ণসংখ্যা r;
	আকার_t l;
	অক্ষর *s;
	কাঠামো stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (কাঠামো dirent *(*)(শূন্য *))fudge_readdir;
	pglob->gl_closedir = (শূন্য (*)(শূন্য *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, আকার(cur));
	cur.conn = conn;

	যদি ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		ফেরত r;
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
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ফাঁকা &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		যদি (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			যদি ((s = realloc(s, l + 2)) != ফাঁকা) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	ফেরত 0;
}
