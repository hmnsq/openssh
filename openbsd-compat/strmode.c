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

#समावेश "includes.h"
#अगर_अघोषित HAVE_STRMODE

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <string.h>

/* XXX mode should be mode_t */

व्योम
strmode(पूर्णांक mode, अक्षर *p)
{
	 /* print type */
	चयन (mode & S_IFMT) {
	हाल S_IFDIR:			/* directory */
		*p++ = 'd';
		अवरोध;
	हाल S_IFCHR:			/* character special */
		*p++ = 'c';
		अवरोध;
	हाल S_IFBLK:			/* block special */
		*p++ = 'b';
		अवरोध;
	हाल S_IFREG:			/* regular */
		*p++ = '-';
		अवरोध;
	हाल S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		अवरोध;
#अगर_घोषित S_IFSOCK
	हाल S_IFSOCK:			/* socket */
		*p++ = 's';
		अवरोध;
#पूर्ण_अगर
#अगर_घोषित S_IFIFO
	हाल S_IFIFO:			/* fifo */
		*p++ = 'p';
		अवरोध;
#पूर्ण_अगर
	शेष:			/* unknown */
		*p++ = '?';
		अवरोध;
	}
	/* usr */
	अगर (mode & S_IRUSR)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	अगर (mode & S_IWUSR)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	चयन (mode & (S_IXUSR | S_ISUID)) {
	हाल 0:
		*p++ = '-';
		अवरोध;
	हाल S_IXUSR:
		*p++ = 'x';
		अवरोध;
	हाल S_ISUID:
		*p++ = 'S';
		अवरोध;
	हाल S_IXUSR | S_ISUID:
		*p++ = 's';
		अवरोध;
	}
	/* group */
	अगर (mode & S_IRGRP)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	अगर (mode & S_IWGRP)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	चयन (mode & (S_IXGRP | S_ISGID)) {
	हाल 0:
		*p++ = '-';
		अवरोध;
	हाल S_IXGRP:
		*p++ = 'x';
		अवरोध;
	हाल S_ISGID:
		*p++ = 'S';
		अवरोध;
	हाल S_IXGRP | S_ISGID:
		*p++ = 's';
		अवरोध;
	}
	/* other */
	अगर (mode & S_IROTH)
		*p++ = 'r';
	अन्यथा
		*p++ = '-';
	अगर (mode & S_IWOTH)
		*p++ = 'w';
	अन्यथा
		*p++ = '-';
	चयन (mode & (S_IXOTH | S_ISVTX)) {
	हाल 0:
		*p++ = '-';
		अवरोध;
	हाल S_IXOTH:
		*p++ = 'x';
		अवरोध;
	हाल S_ISVTX:
		*p++ = 'T';
		अवरोध;
	हाल S_IXOTH | S_ISVTX:
		*p++ = 't';
		अवरोध;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#पूर्ण_अगर
