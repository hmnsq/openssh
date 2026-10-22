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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>

#ଅନ୍ତର୍ଭାଵ <dirent.h>
#ଅନ୍ତର୍ଭାଵ <glob.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sftp.h"
#ଅନ୍ତର୍ଭାଵ "sftp-common.h"
#ଅନ୍ତର୍ଭାଵ "sftp-client.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_glob(ସଂରଚନା sftp_conn *, ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*)(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା), glob_t *);

ସଂରଚନା SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା offset;
};

ସ୍ଥିର ସଂରଚନା {
	ସଂରଚନା sftp_conn *conn;
} cur;

ସ୍ଥିର ଶୂନ୍ୟ *
fudge_opendir(ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା SFTP_OPENDIR *r;

	r = xcalloc(1, ଆକାର(*r));

	ଯଦି (sftp_readdir(cur.conn, path, &r->dir)) {
		ମୁକ୍ତ(r);
		ଫେରନ୍ତୁ(ଖାଲି);
	}

	r->offset = 0;

	ଫେରନ୍ତୁ((ଶୂନ୍ୟ *)r);
}

ସ୍ଥିର ସଂରଚନା dirent *
fudge_readdir(ସଂରଚନା SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	ସ୍ଥିର ଅକ୍ଷର buf[ଆକାର(ସଂରଚନା dirent) + MAXPATHLEN];
	ସଂରଚନା dirent *ret = (ସଂରଚନା dirent *)buf;
#ifdef __GNU_LIBRARY__
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା inum = 1;
#endif /* __GNU_LIBRARY__ */

	ଯଦି (od->dir[od->offset] == ଖାଲି)
		ଫେରନ୍ତୁ(ଖାଲି);

	memset(buf, 0, ଆକାର(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#ଅନ୍ୟଥା
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    ଆକାର(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	ଯଦି (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	ଫେରନ୍ତୁ(ret);
}

ସ୍ଥିର ଶୂନ୍ୟ
fudge_closedir(ସଂରଚନା SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	ମୁକ୍ତ(od);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fudge_lstat(ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା stat *st)
{
	Attrib a;

	ଯଦି (sftp_lstat(cur.conn, path, 1, &a) != 0)
		ଫେରନ୍ତୁ -1;

	attrib_to_stat(&a, st);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fudge_stat(ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା stat *st)
{
	Attrib a;

	ଯଦି (sftp_stat(cur.conn, path, 1, &a) != 0)
		ଫେରନ୍ତୁ -1;

	attrib_to_stat(&a, st);

	ଫେରନ୍ତୁ(0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sftp_glob(ସଂରଚନା sftp_conn *conn, ଅଚଳ ଅକ୍ଷର *pattern, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*errfunc)(ଅଚଳ ଅକ୍ଷର *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା), glob_t *pglob)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t l;
	ଅକ୍ଷର *s;
	ସଂରଚନା stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (ସଂରଚନା dirent *(*)(ଶୂନ୍ୟ *))fudge_readdir;
	pglob->gl_closedir = (ଶୂନ୍ୟ (*)(ଶୂନ୍ୟ *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, ଆକାର(cur));
	cur.conn = conn;

	ଯଦି ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		ଫେରନ୍ତୁ r;
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
	ଯଦି ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ଖାଲି &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		ଯଦି (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			ଯଦି ((s = realloc(s, l + 2)) != ଖାଲି) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	ଫେରନ୍ତୁ 0;
}
