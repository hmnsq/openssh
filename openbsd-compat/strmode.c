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

#अन्तर्भाव "includes.h"
#ifndef HAVE_STRMODE

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <string.h>

/* XXX mode should be mode_t */

शून्य
strmode(पूर्णाङ्क mode, वर्ण *p)
{
	 /* print type */
	विकल्प (mode & S_IFMT) {
	पक्ष S_IFDIR:			/* directory */
		*p++ = 'd';
		भङ्ग;
	पक्ष S_IFCHR:			/* character special */
		*p++ = 'c';
		भङ्ग;
	पक्ष S_IFBLK:			/* block special */
		*p++ = 'b';
		भङ्ग;
	पक्ष S_IFREG:			/* regular */
		*p++ = '-';
		भङ्ग;
	पक्ष S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		भङ्ग;
#ifdef S_IFSOCK
	पक्ष S_IFSOCK:			/* socket */
		*p++ = 's';
		भङ्ग;
#endif
#ifdef S_IFIFO
	पक्ष S_IFIFO:			/* fifo */
		*p++ = 'p';
		भङ्ग;
#endif
	स्वभाव:			/* unknown */
		*p++ = '?';
		भङ्ग;
	}
	/* usr */
	यदि (mode & S_IRUSR)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	यदि (mode & S_IWUSR)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	विकल्प (mode & (S_IXUSR | S_ISUID)) {
	पक्ष 0:
		*p++ = '-';
		भङ्ग;
	पक्ष S_IXUSR:
		*p++ = 'x';
		भङ्ग;
	पक्ष S_ISUID:
		*p++ = 'S';
		भङ्ग;
	पक्ष S_IXUSR | S_ISUID:
		*p++ = 's';
		भङ्ग;
	}
	/* group */
	यदि (mode & S_IRGRP)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	यदि (mode & S_IWGRP)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	विकल्प (mode & (S_IXGRP | S_ISGID)) {
	पक्ष 0:
		*p++ = '-';
		भङ्ग;
	पक्ष S_IXGRP:
		*p++ = 'x';
		भङ्ग;
	पक्ष S_ISGID:
		*p++ = 'S';
		भङ्ग;
	पक्ष S_IXGRP | S_ISGID:
		*p++ = 's';
		भङ्ग;
	}
	/* other */
	यदि (mode & S_IROTH)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	यदि (mode & S_IWOTH)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	विकल्प (mode & (S_IXOTH | S_ISVTX)) {
	पक्ष 0:
		*p++ = '-';
		भङ्ग;
	पक्ष S_IXOTH:
		*p++ = 'x';
		भङ्ग;
	पक्ष S_ISVTX:
		*p++ = 'T';
		भङ्ग;
	पक्ष S_IXOTH | S_ISVTX:
		*p++ = 't';
		भङ्ग;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
