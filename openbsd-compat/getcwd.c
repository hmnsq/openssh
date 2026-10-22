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

#شامل "includes.h"

#اگر !defined(HAVE_GETCWD)

#شامل <sys/stat.h>
#شامل <errno.h>
#شامل <dirent.h>
#شامل <sys/dir.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل "includes.h"

#تعریف_کرو	ISDOT(dp) \
	(dp->d_name[0] == '.' && (dp->d_name[1] == '\0' || \
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))

حرف *
getcwd(حرف *pt, سائز_t سائز)
{
	ساخت dirent *dp;
	DIR *dir = تہی;
	dev_t dev;
	ino_t ino;
	صحیح پہلا;
	حرف *bpt, *bup;
	ساخت stat s;
	dev_t جڑ_dev;
	ino_t جڑ_ino;
	سائز_t ptsize, upsize;
	صحیح save_errno;
	حرف *ept, *eup, *اوپر;

	/*
	 * If no buffer specified by the user, allocate one as necessary.
	 * If a buffer is specified, the size has to be non-zero.  The path
	 * is built from the end of the buffer backwards.
	 */
	اگر (pt) {
		ptsize = 0;
		اگر (سائز == 0) {
			errno = EINVAL;
			واپس (تہی);
		} ورنہ اگر (سائز == 1) {
			errno = ERANGE;
			واپس (تہی);
		}
		ept = pt + سائز;
	} ورنہ {
		اگر ((pt = حافظہ_دو(ptsize = MAXPATHLEN)) == تہی)
			واپس (تہی);
		ept = pt + ptsize;
	}
	bpt = ept - 1;
	*bpt = '\0';

	/*
	 * Allocate bytes for the string of "../"'s.
	 * Should always be enough (it's 340 levels).  If it's not, allocate
	 * as necessary.  Special * case the first stat, it's ".", not "..".
	 */
	اگر ((اوپر = حافظہ_دو(upsize = MAXPATHLEN)) == تہی)
		جاؤ err;
	eup = اوپر + upsize;
	bup = اوپر;
	اوپر[0] = '.';
	اوپر[1] = '\0';

	/* Save root values, so know when to stop. */
	اگر (stat("/", &s))
		جاؤ err;
	جڑ_dev = s.st_dev;
	جڑ_ino = s.st_ino;

	errno = 0;			/* XXX readdir has no error return. */

	برائے (پہلا = 1;; پہلا = 0) {
		/* Stat the current level. */
		اگر (lstat(اوپر, &s))
			جاؤ err;

		/* Save current node values. */
		ino = s.st_ino;
		dev = s.st_dev;

		/* Check for reaching root. */
		اگر (جڑ_dev == dev && جڑ_ino == ino) {
			*--bpt = '/';
			/*
			 * It's unclear that it's a requirement to copy the
			 * path to the beginning of the buffer, but it's always
			 * been that way and stuff would probably break.
			 */
			memmove(pt, bpt, ept - bpt);
			آزاد(اوپر);
			واپس (pt);
		}

		/*
		 * Build pointer to the parent directory, allocating memory
		 * as necessary.  Max length is 3 for "../", the largest
		 * possible component name, plus a trailing NUL.
		 */
		اگر (bup + 3  + MAXNAMLEN + 1 >= eup) {
			حرف *nup;

			اگر ((nup = realloc(اوپر, upsize *= 2)) == تہی)
				جاؤ err;
			bup = nup + (bup - اوپر);
			اوپر = nup;
			eup = اوپر + upsize;
		}
		*bup++ = '.';
		*bup++ = '.';
		*bup = '\0';

		/* Open and stat parent directory. */
		اگر (!(dir = opendir(اوپر)) || fstat(dirfd(dir), &s))
			جاؤ err;

		/* Add trailing slash for next directory. */
		*bup++ = '/';

		/*
		 * If it's a mount point, have to stat each element because
		 * the inode number in the directory is for the entry in the
		 * parent directory, not the inode number of the mounted file.
		 */
		save_errno = 0;
		اگر (s.st_dev == dev) {
			برائے (;;) {
				اگر (!(dp = readdir(dir)))
					جاؤ notfound;
				اگر (dp->d_fileno == ino)
					توڑو;
			}
		} ورنہ
			برائے (;;) {
				اگر (!(dp = readdir(dir)))
					جاؤ notfound;
				اگر (ISDOT(dp))
					جاری;
				حافظہ_نقل(bup, dp->d_name, dp->d_namlen + 1);

				/* Save the first error for later. */
				اگر (lstat(اوپر, &s)) {
					اگر (!save_errno)
						save_errno = errno;
					errno = 0;
					جاری;
				}
				اگر (s.st_dev == dev && s.st_ino == ino)
					توڑو;
			}

		/*
		 * Check for length of the current name, preceding slash,
		 * leading slash.
		 */
		اگر (bpt - pt < dp->d_namlen + (پہلا ? 1 : 2)) {
			سائز_t len;
			حرف *npt;

			اگر (!ptsize) {
				errno = ERANGE;
				جاؤ err;
			}
			len = ept - bpt;
			اگر ((npt = realloc(pt, ptsize *= 2)) == تہی)
				جاؤ err;
			bpt = npt + (bpt - pt);
			pt = npt;
			ept = pt + ptsize;
			memmove(ept - len, bpt, len);
			bpt = ept - len;
		}
		اگر (!پہلا)
			*--bpt = '/';
		bpt -= dp->d_namlen;
		حافظہ_نقل(bpt, dp->d_name, dp->d_namlen);
		(خالی)closedir(dir);

		/* Truncate any file name. */
		*bup = '\0';
	}

notfound:
	/*
	 * If readdir set errno, use it, not any saved error; otherwise,
	 * didn't find the current directory in its parent directory, set
	 * errno to ENOENT.
	 */
	اگر (!errno)
		errno = save_errno ? save_errno : ENOENT;
	/* FALLTHROUGH */
err:
	save_errno = errno;

	اگر (ptsize)
		آزاد(pt);
	آزاد(اوپر);
	اگر (dir)
		(خالی)closedir(dir);

	errno = save_errno;

	واپس (تہی);
}

#اگر_ختم /* !defined(HAVE_GETCWD) */
