/*	$OpenBSD: strmode.c,v 1.7 2005/08/08 08:05:37 espie Exp $ */
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
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

/* OPENBSD ORIGINAL: lib/libc/string/strmode.c */

#ಅನ್ತರ್ಭಾವ "includes.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_STRMODE

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <string.h>

/* XXX mode should be mode_t */

ಶೂನ್ಯ
strmode(ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, ಅಕ್ಷರ *p)
{
	 /* print type */
	ಆಯ್ಕೆ (ಬಹುಲಕ & S_IFMT) {
	ಸ್ಥಿತಿ S_IFDIR:			/* directory */
		*p++ = 'd';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IFCHR:			/* character special */
		*p++ = 'c';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IFBLK:			/* block special */
		*p++ = 'b';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IFREG:			/* regular */
		*p++ = '-';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ S_IFSOCK
	ಸ್ಥಿತಿ S_IFSOCK:			/* socket */
		*p++ = 's';
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ S_IFIFO
	ಸ್ಥಿತಿ S_IFIFO:			/* fifo */
		*p++ = 'p';
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
	ಪೂರ್ವನಿಯೋಜಿತ:			/* unknown */
		*p++ = '?';
		ನಿಲ್ಲಿಸು;
	}
	/* usr */
	ಆದರೆ (ಬಹುಲಕ & S_IRUSR)
		*p++ = 'r';
	ಇಲ್ಲದಿದ್ದರೆ
		*p++ = '-';
	ಆದರೆ (ಬಹುಲಕ & S_IWUSR)
		*p++ = 'w';
	ಇಲ್ಲದಿದ್ದರೆ
		*p++ = '-';
	ಆಯ್ಕೆ (ಬಹುಲಕ & (S_IXUSR | S_ISUID)) {
	ಸ್ಥಿತಿ 0:
		*p++ = '-';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IXUSR:
		*p++ = 'x';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_ISUID:
		*p++ = 'S';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IXUSR | S_ISUID:
		*p++ = 's';
		ನಿಲ್ಲಿಸು;
	}
	/*ಗುಂಪು*/
	ಆದರೆ (ಬಹುಲಕ & S_IRGRP)
		*p++ = 'r';
	ಇಲ್ಲದಿದ್ದರೆ
		*p++ = '-';
	ಆದರೆ (ಬಹುಲಕ & S_IWGRP)
		*p++ = 'w';
	ಇಲ್ಲದಿದ್ದರೆ
		*p++ = '-';
	ಆಯ್ಕೆ (ಬಹುಲಕ & (S_IXGRP | S_ISGID)) {
	ಸ್ಥಿತಿ 0:
		*p++ = '-';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IXGRP:
		*p++ = 'x';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_ISGID:
		*p++ = 'S';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IXGRP | S_ISGID:
		*p++ = 's';
		ನಿಲ್ಲಿಸು;
	}
	/* other */
	ಆದರೆ (ಬಹುಲಕ & S_IROTH)
		*p++ = 'r';
	ಇಲ್ಲದಿದ್ದರೆ
		*p++ = '-';
	ಆದರೆ (ಬಹುಲಕ & S_IWOTH)
		*p++ = 'w';
	ಇಲ್ಲದಿದ್ದರೆ
		*p++ = '-';
	ಆಯ್ಕೆ (ಬಹುಲಕ & (S_IXOTH | S_ISVTX)) {
	ಸ್ಥಿತಿ 0:
		*p++ = '-';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IXOTH:
		*p++ = 'x';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_ISVTX:
		*p++ = 'T';
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ S_IXOTH | S_ISVTX:
		*p++ = 't';
		ನಿಲ್ಲಿಸು;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#ಆದರೆ_ಅಂತ್ಯ
