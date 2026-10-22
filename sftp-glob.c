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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>

#અન્તર્ભાવ <dirent.h>
#અન્તર્ભાવ <glob.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "sftp-common.h"
#અન્તર્ભાવ "sftp-client.h"

પૂર્ણાંક sftp_glob(સંરચના sftp_conn *, અચલ અક્ષર *, પૂર્ણાંક,
    પૂર્ણાંક (*)(અચલ અક્ષર *, પૂર્ણાંક), glob_t *);

સંરચના SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	પૂર્ણાંક offset;
};

સ્થિર સંરચના {
	સંરચના sftp_conn *conn;
} cur;

સ્થિર શૂન્ય *
fudge_opendir(અચલ અક્ષર *path)
{
	સંરચના SFTP_OPENDIR *r;

	r = xcalloc(1, કદ(*r));

	જો (sftp_readdir(cur.conn, path, &r->dir)) {
		મુક્ત(r);
		પાછા(ખાલી);
	}

	r->offset = 0;

	પાછા((શૂન્ય *)r);
}

સ્થિર સંરચના dirent *
fudge_readdir(સંરચના SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	સ્થિર અક્ષર buf[કદ(સંરચના dirent) + MAXPATHLEN];
	સંરચના dirent *ret = (સંરચના dirent *)buf;
#ifdef __GNU_LIBRARY__
	સ્થિર પૂર્ણાંક inum = 1;
#endif /* __GNU_LIBRARY__ */

	જો (od->dir[od->offset] == ખાલી)
		પાછા(ખાલી);

	memset(buf, 0, કદ(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#નહીંતર
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    કદ(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	જો (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	પાછા(ret);
}

સ્થિર શૂન્ય
fudge_closedir(સંરચના SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	મુક્ત(od);
}

સ્થિર પૂર્ણાંક
fudge_lstat(અચલ અક્ષર *path, સંરચના stat *st)
{
	Attrib a;

	જો (sftp_lstat(cur.conn, path, 1, &a) != 0)
		પાછા -1;

	attrib_to_stat(&a, st);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
fudge_stat(અચલ અક્ષર *path, સંરચના stat *st)
{
	Attrib a;

	જો (sftp_stat(cur.conn, path, 1, &a) != 0)
		પાછા -1;

	attrib_to_stat(&a, st);

	પાછા(0);
}

પૂર્ણાંક
sftp_glob(સંરચના sftp_conn *conn, અચલ અક્ષર *pattern, પૂર્ણાંક flags,
    પૂર્ણાંક (*errfunc)(અચલ અક્ષર *, પૂર્ણાંક), glob_t *pglob)
{
	પૂર્ણાંક r;
	size_t l;
	અક્ષર *s;
	સંરચના stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (સંરચના dirent *(*)(શૂન્ય *))fudge_readdir;
	pglob->gl_closedir = (શૂન્ય (*)(શૂન્ય *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	memset(&cur, 0, કદ(cur));
	cur.conn = conn;

	જો ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		પાછા r;
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
	જો ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != ખાલી &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		જો (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			જો ((s = realloc(s, l + 2)) != ખાલી) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	પાછા 0;
}
