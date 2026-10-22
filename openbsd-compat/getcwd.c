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

#अन्तर्भाव "includes.h"

#यदि !defined(HAVE_GETCWD)

#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <dirent.h>
#अन्तर्भाव <sys/dir.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव "includes.h"

#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

वर्ण *
getcwd(वर्ण *pt, माप_प्रकार size)
{
	संरचना dirent *dp;
	सूची *dir = रिक्त;
	dev_t dev;
	ino_t ino;
	पूर्णाङ्क first;
	वर्ण *bpt, *bup;
	संरचना stat s;
	dev_t जरा_dev;
	ino_t जरा_ino;
	माप_प्रकार ptsize, upsize;
	पूर्णाङ्क save_errno;
	वर्ण *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	यदि (pt) {
		ptsize = 0;
		यदि (size == 0) {
			त्रुटि_सं = EINVAL;
			फर्काऊ (रिक्त);
		} अन्यथा यदि (size == 1) {
			त्रुटि_सं = दुस्फल;
			फर्काऊ (रिक्त);
		}
		ept = pt + size;
	} अन्यथा {
		यदि ((pt = दो_स्मृति(ptsize = MAXPATHLEN)) == रिक्त)
			फर्काऊ (रिक्त);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	यदि ((up = दो_स्मृति(upsize = MAXPATHLEN)) == रिक्त)
		गच्छ err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	यदि (stat("/", &s))
		गच्छ err;
	जरा_dev = s.st_dev;
	जरा_ino = s.st_ino;

	त्रुटि_सं = 0;			/* XXX readdir has no error return. */

	लागि (first = 1;; first = 0) {
		/* Stat the current level. */
		यदि (lstat(up, &s))
			गच्छ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		यदि (जरा_dev == dev && जरा_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			स_हटाओ(pt, bpt, ept - bpt);
			मुक्त(up);
			फर्काऊ (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		यदि (bup + 3  + MAXNAMLEN + 1 >= eup) {
			वर्ण *nup;

			यदि ((nup = पुनः_स्मृति(up, upsize *= 2)) == रिक्त)
				गच्छ err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		यदि (!(dir = सूची_खोलो(up)) || ख_स्थिति(dirfd(dir), &s))
			गच्छ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		यदि (s.st_dev == dev) {
			लागि (;;) {
				यदि (!(dp = सूची_पढ़ो(dir)))
					गच्छ notfound;
				यदि (dp->d_fileno == ino)
					रोक;
			}
		} अन्यथा
			लागि (;;) {
				यदि (!(dp = सूची_पढ़ो(dir)))
					गच्छ notfound;
				यदि (ISDOT(dp))
					जारी;
				स_नकल(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				यदि (lstat(up, &s)) {
					यदि (!save_errno)
						save_errno = त्रुटि_सं;
					त्रुटि_सं = 0;
					जारी;
				}
				यदि (s.st_dev == dev && s.st_ino == ino)
					रोक;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		यदि (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			माप_प्रकार len;
			वर्ण *npt;

			यदि (!ptsize) {
				त्रुटि_सं = दुस्फल;
				गच्छ err;
			}
			len = ept - bpt;
			यदि ((npt = पुनः_स्मृति(pt, ptsize *= 2)) == रिक्त)
				गच्छ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			स_हटाओ(ept - len, bpt, len);
			bpt = ept - len;
		}
		यदि (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		स_नकल(bpt, dp->d_name, dp->d_namlen);
		(शून्य)बंद_सूची(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	यदि (!त्रुटि_सं)
		त्रुटि_सं = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = त्रुटि_सं;

	यदि (ptsize)
		मुक्त(pt);
	मुक्त(up);
	यदि (dir)
		(शून्य)बंद_सूची(dir);

	त्रुटि_सं = save_errno;

	फर्काऊ (रिक्त);
}

#endif /* !defined(HAVE_GETCWD) */
