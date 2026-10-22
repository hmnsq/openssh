/*	$OpenBSD: getcwd.c,v 1.14 2005/08/08 08:05:34 espie Exp */
/*
 * Copyright (c) 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/getcwd.c */

#समावेश "includes.h"

#अगर !defined(HAVE_GETCWD)

#समावेश <sys/stat.h>
#समावेश <errno.h>
#समावेश <dirent.h>
#समावेश <sys/dir.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश "includes.h"

#घोषणा	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

अक्षर *
getcwd(अक्षर *pt, माप_प्रकार आकार)
{
	काष्ठा dirent *dp;
	सूची *dir = शून्य;
	dev_t dev;
	ino_t ino;
	पूर्णांक first;
	अक्षर *bpt, *bup;
	काष्ठा stat s;
	dev_t मूल_dev;
	ino_t मूल_ino;
	माप_प्रकार ptsize, upsize;
	पूर्णांक save_errno;
	अक्षर *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	अगर (pt) {
		ptsize = 0;
		अगर (आकार == 0) {
			त्रुटि_सं = EINVAL;
			वापस (शून्य);
		} अन्यथा अगर (आकार == 1) {
			त्रुटि_सं = दुस्फल;
			वापस (शून्य);
		}
		ept = pt + आकार;
	} अन्यथा {
		अगर ((pt = दो_स्मृति(ptsize = MAXPATHLEN)) == शून्य)
			वापस (शून्य);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	अगर ((up = दो_स्मृति(upsize = MAXPATHLEN)) == शून्य)
		जाओ err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	अगर (stat("/", &s))
		जाओ err;
	मूल_dev = s.st_dev;
	मूल_ino = s.st_ino;

	त्रुटि_सं = 0;			/* XXX readdir has no error return. */

	क्रम (first = 1;; first = 0) {
		/* Stat the current level. */
		अगर (lstat(up, &s))
			जाओ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		अगर (मूल_dev == dev && मूल_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			स_हटाओ(pt, bpt, ept - bpt);
			मुक्त(up);
			वापस (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		अगर (bup + 3  + MAXNAMLEN + 1 >= eup) {
			अक्षर *nup;

			अगर ((nup = पुनः_स्मृति(up, upsize *= 2)) == शून्य)
				जाओ err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		अगर (!(dir = सूची_खोलो(up)) || ख_स्थिति(dirfd(dir), &s))
			जाओ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		अगर (s.st_dev == dev) {
			क्रम (;;) {
				अगर (!(dp = सूची_पढ़ो(dir)))
					जाओ notfound;
				अगर (dp->d_fileno == ino)
					अवरोध;
			}
		} अन्यथा
			क्रम (;;) {
				अगर (!(dp = सूची_पढ़ो(dir)))
					जाओ notfound;
				अगर (ISDOT(dp))
					जारी;
				स_नकल(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				अगर (lstat(up, &s)) {
					अगर (!save_errno)
						save_errno = त्रुटि_सं;
					त्रुटि_सं = 0;
					जारी;
				}
				अगर (s.st_dev == dev && s.st_ino == ino)
					अवरोध;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		अगर (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			माप_प्रकार len;
			अक्षर *npt;

			अगर (!ptsize) {
				त्रुटि_सं = दुस्फल;
				जाओ err;
			}
			len = ept - bpt;
			अगर ((npt = पुनः_स्मृति(pt, ptsize *= 2)) == शून्य)
				जाओ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			स_हटाओ(ept - len, bpt, len);
			bpt = ept - len;
		}
		अगर (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		स_नकल(bpt, dp->d_name, dp->d_namlen);
		(व्योम)बंद_सूची(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	अगर (!त्रुटि_सं)
		त्रुटि_सं = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = त्रुटि_सं;

	अगर (ptsize)
		मुक्त(pt);
	मुक्त(up);
	अगर (dir)
		(व्योम)बंद_सूची(dir);

	त्रुटि_सं = save_errno;

	वापस (शून्य);
}

#पूर्ण_अगर /* !defined(HAVE_GETCWD) */
