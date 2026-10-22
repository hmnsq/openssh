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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>

#समावेश <dirent.h>
#समावेश <glob.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "xmalloc.h"
#समावेश "sftp.h"
#समावेश "sftp-common.h"
#समावेश "sftp-client.h"

पूर्णांक sftp_glob(काष्ठा sftp_conn *, स्थिर अक्षर *, पूर्णांक,
    पूर्णांक (*)(स्थिर अक्षर *, पूर्णांक), glob_t *);

काष्ठा SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	पूर्णांक offset;
};

अटल काष्ठा {
	काष्ठा sftp_conn *conn;
} cur;

अटल व्योम *
fudge_opendir(स्थिर अक्षर *path)
{
	काष्ठा SFTP_OPENDIR *r;

	r = xcalloc(1, माप(*r));

	अगर (sftp_readdir(cur.conn, path, &r->dir)) {
		मुक्त(r);
		वापस(शून्य);
	}

	r->offset = 0;

	वापस((व्योम *)r);
}

अटल काष्ठा dirent *
fudge_readdir(काष्ठा SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	अटल अक्षर buf[माप(काष्ठा dirent) + MAXPATHLEN];
	काष्ठा dirent *ret = (काष्ठा dirent *)buf;
#अगर_घोषित __GNU_LIBRARY__
	अटल पूर्णांक inum = 1;
#पूर्ण_अगर /* __GNU_LIBRARY__ */

	अगर (od->dir[od->offset] == शून्य)
		वापस(शून्य);

	स_रखो(buf, 0, माप(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#अगर_घोषित BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#अन्यथा
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    माप(ret->d_name));
#पूर्ण_अगर
#अगर_घोषित __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	अगर (!inum)
		inum = 1;
#पूर्ण_अगर /* __GNU_LIBRARY__ */

	वापस(ret);
}

अटल व्योम
fudge_closedir(काष्ठा SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	मुक्त(od);
}

अटल पूर्णांक
fudge_lstat(स्थिर अक्षर *path, काष्ठा stat *st)
{
	Attrib a;

	अगर (sftp_lstat(cur.conn, path, 1, &a) != 0)
		वापस -1;

	attrib_to_stat(&a, st);

	वापस 0;
}

अटल पूर्णांक
fudge_stat(स्थिर अक्षर *path, काष्ठा stat *st)
{
	Attrib a;

	अगर (sftp_stat(cur.conn, path, 1, &a) != 0)
		वापस -1;

	attrib_to_stat(&a, st);

	वापस(0);
}

पूर्णांक
sftp_glob(काष्ठा sftp_conn *conn, स्थिर अक्षर *pattern, पूर्णांक flags,
    पूर्णांक (*errfunc)(स्थिर अक्षर *, पूर्णांक), glob_t *pglob)
{
	पूर्णांक r;
	माप_प्रकार l;
	अक्षर *s;
	काष्ठा stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (काष्ठा dirent *(*)(व्योम *))fudge_readdir;
	pglob->gl_closedir = (व्योम (*)(व्योम *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	स_रखो(&cur, 0, माप(cur));
	cur.conn = conn;

	अगर ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		वापस r;
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
	अगर ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != शून्य &&
	    (l = म_माप(s)) > 0 && s[l-1] != '/') {
		अगर (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			अगर ((s = पुनः_स्मृति(s, l + 2)) != शून्य) {
				स_नकल(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	वापस 0;
}
