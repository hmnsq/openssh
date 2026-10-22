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

#ಆದರೆ !defined(HAVE_GETCWD)

#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <dirent.h>
#ಅನ್ತರ್ಭಾವ <sys/dir.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿಸು	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

ಅಕ್ಷರ *
getcwd(ಅಕ್ಷರ *pt, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ರಚನೆ dirent *dp;
	DIR *dir = ಖಾಲಿ;
	dev_t dev;
	ino_t ino;
	ಪೂರ್ಣಾಂಕ ಮೊದಲ;
	ಅಕ್ಷರ *bpt, *bup;
	ರಚನೆ stat s;
	dev_t ಬೇರು_dev;
	ino_t ಬೇರು_ino;
	ಗಾತ್ರ_t ptsize, upsize;
	ಪೂರ್ಣಾಂಕ save_errno;
	ಅಕ್ಷರ *ept, *eup, *ಮೇಲೆ;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	ಆದರೆ (pt) {
		ptsize = 0;
		ಆದರೆ (ಗಾತ್ರ_2 == 0) {
			errno = EINVAL;
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಗಾತ್ರ_2 == 1) {
			errno = ERANGE;
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		}
		ept = pt + ಗಾತ್ರ_2;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((pt = ಸ್ಮರಣೆ_ಕೊಡು(ptsize = MAXPATHLEN)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	ಆದರೆ ((ಮೇಲೆ = ಸ್ಮರಣೆ_ಕೊಡು(upsize = MAXPATHLEN)) == ಖಾಲಿ)
		ಹೋಗು err;
	eup = ಮೇಲೆ + upsize;
	bup = ಮೇಲೆ;
	ಮೇಲೆ[0] = '.';
	ಮೇಲೆ[1] = '\0';

	/* Save root values, so know when to stop. */
	ಆದರೆ (stat("/", &s))
		ಹೋಗು err;
	ಬೇರು_dev = s.st_dev;
	ಬೇರು_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	ಗಾಗಿ (ಮೊದಲ = 1;; ಮೊದಲ = 0) {
		/* Stat the current level. */
		ಆದರೆ (lstat(ಮೇಲೆ, &s))
			ಹೋಗು err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		ಆದರೆ (ಬೇರು_dev == dev && ಬೇರು_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			ಬಿಡುಗಡೆ(ಮೇಲೆ);
			ಹಿಂತಿರುಗಿ (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		ಆದರೆ (bup + 3  + MAXNAMLEN + 1 >= eup) {
			ಅಕ್ಷರ *nup;

			ಆದರೆ ((nup = realloc(ಮೇಲೆ, upsize *= 2)) == ಖಾಲಿ)
				ಹೋಗು err;
			bup = nup + (bup - ಮೇಲೆ);
			ಮೇಲೆ = nup;
			eup = ಮೇಲೆ + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		ಆದರೆ (!(dir = opendir(ಮೇಲೆ)) || fstat(dirfd(dir), &s))
			ಹೋಗು err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		ಆದರೆ (s.st_dev == dev) {
			ಗಾಗಿ (;;) {
				ಆದರೆ (!(dp = readdir(dir)))
					ಹೋಗು notfound;
				ಆದರೆ (dp->d_fileno == ino)
					ನಿಲ್ಲಿಸು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ
			ಗಾಗಿ (;;) {
				ಆದರೆ (!(dp = readdir(dir)))
					ಹೋಗು notfound;
				ಆದರೆ (ISDOT(dp))
					ಮುಂದುವರಿ;
				ಸ್ಮರಣೆ_ನಕಲು(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				ಆದರೆ (lstat(ಮೇಲೆ, &s)) {
					ಆದರೆ (!save_errno)
						save_errno = errno;
					errno = 0;
					ಮುಂದುವರಿ;
				}
				ಆದರೆ (s.st_dev == dev && s.st_ino == ino)
					ನಿಲ್ಲಿಸು;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		ಆದರೆ (bpt - pt < dp->d_namlen + (ಮೊದಲ ? 1 : 2)) {
			ಗಾತ್ರ_t len;
			ಅಕ್ಷರ *npt;

			ಆದರೆ (!ptsize) {
				errno = ERANGE;
				ಹೋಗು err;
			}
			len = ept - bpt;
			ಆದರೆ ((npt = realloc(pt, ptsize *= 2)) == ಖಾಲಿ)
				ಹೋಗು err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		ಆದರೆ (!ಮೊದಲ)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		ಸ್ಮರಣೆ_ನಕಲು(bpt, dp->d_name, dp->d_namlen);
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
	ಆದರೆ (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	ಆದರೆ (ptsize)
		ಬಿಡುಗಡೆ(pt);
	ಬಿಡುಗಡೆ(ಮೇಲೆ);
	ಆದರೆ (dir)
		(ಶೂನ್ಯ)closedir(dir);

	errno = save_errno;

	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_GETCWD) */
