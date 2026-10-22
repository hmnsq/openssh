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

#ضمن "includes.h"

#אם !defined(HAVE_GETCWD)

#ضمن <sys/stat.h>
#ضمن <errno.h>
#ضمن <dirent.h>
#ضمن <sys/dir.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن "includes.h"

#define	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

حرف *
getcwd(حرف *pt, size_t size)
{
	بنية dirent *dp;
	DIR *dir = عدم;
	dev_t dev;
	ino_t ino;
	صحيح first;
	حرف *bpt, *bup;
	بنية stat s;
	dev_t root_dev;
	ino_t root_ino;
	size_t ptsize, upsize;
	صحيح save_errno;
	حرف *ept, *eup, *up;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	אם (pt) {
		ptsize = 0;
		אם (size == 0) {
			errno = EINVAL;
			החזר (عدم);
		} אחרת אם (size == 1) {
			errno = ERANGE;
			החזר (عدم);
		}
		ept = pt + size;
	} אחרת {
		אם ((pt = malloc(ptsize = MAXPATHLEN)) == عدم)
			החזר (عدم);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	אם ((up = malloc(upsize = MAXPATHLEN)) == عدم)
		اذهب err;
	eup = up + upsize;
	bup = up;
	up[0] = '.';
	up[1] = '\0';

	/* Save root values, so know when to stop. */
	אם (stat("/", &s))
		اذهب err;
	root_dev = s.st_dev;
	root_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	עבור (first = 1;; first = 0) {
		/* Stat the current level. */
		אם (lstat(up, &s))
			اذهب err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		אם (root_dev == dev && root_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			حرر(up);
			החזר (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		אם (bup + 3  + MAXNAMLEN + 1 >= eup) {
			حرف *nup;

			אם ((nup = realloc(up, upsize *= 2)) == عدم)
				اذهب err;
			bup = nup + (bup - up);
			up = nup;
			eup = up + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		אם (!(dir = opendir(up)) || fstat(dirfd(dir), &s))
			اذهب err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		אם (s.st_dev == dev) {
			עבור (;;) {
				אם (!(dp = readdir(dir)))
					اذهب notfound;
				אם (dp->d_fileno == ino)
					اكسر;
			}
		} אחרת
			עבור (;;) {
				אם (!(dp = readdir(dir)))
					اذهب notfound;
				אם (ISDOT(dp))
					استمر;
				memcpy(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				אם (lstat(up, &s)) {
					אם (!save_errno)
						save_errno = errno;
					errno = 0;
					استمر;
				}
				אם (s.st_dev == dev && s.st_ino == ino)
					اكسر;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		אם (bpt - pt < dp->d_namlen + (first ? 1 : 2)) {
			size_t len;
			حرف *npt;

			אם (!ptsize) {
				errno = ERANGE;
				اذهب err;
			}
			len = ept - bpt;
			אם ((npt = realloc(pt, ptsize *= 2)) == عدم)
				اذهب err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		אם (!first)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		memcpy(bpt, dp->d_name, dp->d_namlen);
		(فراغ)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	אם (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	אם (ptsize)
		حرر(pt);
	حرر(up);
	אם (dir)
		(فراغ)closedir(dir);

	errno = save_errno;

	החזר (عدم);
}

#endif /* !defined(HAVE_GETCWD) */
