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
strmode(पूर्णांक mode, अक्षर *p)
{
	 /* print type */
	निवड (mode & S_IFMT) {
	स्थिती S_IFDIR:			/* directory */
		*p++ = 'd';
		थांबा;
	स्थिती S_IFCHR:			/* character special */
		*p++ = 'c';
		थांबा;
	स्थिती S_IFBLK:			/* block special */
		*p++ = 'b';
		थांबा;
	स्थिती S_IFREG:			/* regular */
		*p++ = '-';
		थांबा;
	स्थिती S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		थांबा;
#ifdef S_IFSOCK
	स्थिती S_IFSOCK:			/* socket */
		*p++ = 's';
		थांबा;
#endif
#ifdef S_IFIFO
	स्थिती S_IFIFO:			/* fifo */
		*p++ = 'p';
		थांबा;
#endif
	पूर्वनिर्धारित:			/* unknown */
		*p++ = '?';
		थांबा;
	}
	/* usr */
	जर (mode & S_IRUSR)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	जर (mode & S_IWUSR)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	निवड (mode & (S_IXUSR | S_ISUID)) {
	स्थिती 0:
		*p++ = '-';
		थांबा;
	स्थिती S_IXUSR:
		*p++ = 'x';
		थांबा;
	स्थिती S_ISUID:
		*p++ = 'S';
		थांबा;
	स्थिती S_IXUSR | S_ISUID:
		*p++ = 's';
		थांबा;
	}
	/* group */
	जर (mode & S_IRGRP)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	जर (mode & S_IWGRP)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	निवड (mode & (S_IXGRP | S_ISGID)) {
	स्थिती 0:
		*p++ = '-';
		थांबा;
	स्थिती S_IXGRP:
		*p++ = 'x';
		थांबा;
	स्थिती S_ISGID:
		*p++ = 'S';
		थांबा;
	स्थिती S_IXGRP | S_ISGID:
		*p++ = 's';
		थांबा;
	}
	/* other */
	जर (mode & S_IROTH)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	जर (mode & S_IWOTH)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	निवड (mode & (S_IXOTH | S_ISVTX)) {
	स्थिती 0:
		*p++ = '-';
		थांबा;
	स्थिती S_IXOTH:
		*p++ = 'x';
		थांबा;
	स्थिती S_ISVTX:
		*p++ = 'T';
		थांबा;
	स्थिती S_IXOTH | S_ISVTX:
		*p++ = 't';
		थांबा;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
