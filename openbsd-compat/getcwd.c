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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ !defined(HAVE_GETCWD)

#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <sys/dir.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ "includes.h"

#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

ವರ್ಣ *
getcwd(ವರ್ಣ *pt, size_t size)
{
	ಸಂರಚನಾ dirent *dp;
	DIR *dir = ರಿಕ್ತ;
	dev_t dev;
	ino_t ino;
	ಪೂರ್ಣಾಙ್ಕ first;
	ವರ್ಣ *bpt, *bup;
	ಸಂರಚನಾ stat s;
	dev_t ಬೇರು_dev;
	ino_t ಬೇರು_ino;
	size_t ptsize, upsize;
	ಪೂರ್ಣಾಙ್ಕ save_errno;
	ವರ್ಣ *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	ಯದಿ (pt) {
		ptsize = 0;
		ಯದಿ (size == 0) {
			errno = EINVAL;
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		} ಅನ್ಯಥಾ ಯದಿ (size == 1) {
			errno = ERANGE;
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		}
		ept = pt + size;
	} ಅನ್ಯಥಾ {
		ಯದಿ ((pt = malloc(ptsize = MAXPATHLEN)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	ಯದಿ ((up = malloc(upsize = MAXPATHLEN)) == ರಿಕ್ತ)
		ಗಚ್ಛ err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	ಯದಿ (stat("/", &s))
		ಗಚ್ಛ err;
	ಬೇರು_dev = s.st_dev;
	ಬೇರು_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	ಪ್ರತಿ (first = 1;; first = 0) {
		/* Stat the current level. */
		ಯದಿ (lstat(up, &s))
			ಗಚ್ಛ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		ಯದಿ (ಬೇರು_dev == dev && ಬೇರು_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			ಮುಕ್ತ(up);
			ಪ್ರತ್ಯಾಗಮ (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		ಯದಿ (bup + 3  + MAXNAMLEN + 1 >= eup) {
			ವರ್ಣ *nup;

			ಯದಿ ((nup = realloc(up, upsize *= 2)) == ರಿಕ್ತ)
				ಗಚ್ಛ err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		ಯದಿ (!(dir = opendir(up)) || fstat(dirfd(dir), &s))
			ಗಚ್ಛ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		ಯದಿ (s.st_dev == dev) {
			ಪ್ರತಿ (;;) {
				ಯದಿ (!(dp = readdir(dir)))
					ಗಚ್ಛ notfound;
				ಯದಿ (dp->d_fileno == ino)
					ಭಙ್ಗ;
			}
		} ಅನ್ಯಥಾ
			ಪ್ರತಿ (;;) {
				ಯದಿ (!(dp = readdir(dir)))
					ಗಚ್ಛ notfound;
				ಯದಿ (ISDOT(dp))
					ಅನುವರ್ತ;
				memcpy(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				ಯದಿ (lstat(up, &s)) {
					ಯದಿ (!save_errno)
						save_errno = errno;
					errno = 0;
					ಅನುವರ್ತ;
				}
				ಯದಿ (s.st_dev == dev && s.st_ino == ino)
					ಭಙ್ಗ;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		ಯದಿ (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			size_t len;
			ವರ್ಣ *npt;

			ಯದಿ (!ptsize) {
				errno = ERANGE;
				ಗಚ್ಛ err;
			}
			len = ept - bpt;
			ಯದಿ ((npt = realloc(pt, ptsize *= 2)) == ರಿಕ್ತ)
				ಗಚ್ಛ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		ಯದಿ (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		memcpy(bpt, dp->d_name, dp->d_namlen);
		(ಶೂನ್ಯ)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	ಯದಿ (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	ಯದಿ (ptsize)
		ಮುಕ್ತ(pt);
	ಮುಕ್ತ(up);
	ಯದಿ (dir)
		(ಶೂನ್ಯ)closedir(dir);

	errno = save_errno;

	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

#endif /* !defined(HAVE_GETCWD) */
