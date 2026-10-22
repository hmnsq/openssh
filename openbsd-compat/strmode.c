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

#অন্তর্ভাব "includes.h"
#ifndef HAVE_STRMODE

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <string.h>

/* XXX mode should be mode_t */

শূন্য
strmode(পূর্ণাঙ্ক mode, বর্ণ *p)
{
	 /* print type */
	বিকল্প (mode & S_IFMT) {
	পক্ষ S_IFDIR:			/* directory */
		*p++ = 'd';
		ভঙ্গ;
	পক্ষ S_IFCHR:			/* character special */
		*p++ = 'c';
		ভঙ্গ;
	পক্ষ S_IFBLK:			/* block special */
		*p++ = 'b';
		ভঙ্গ;
	পক্ষ S_IFREG:			/* regular */
		*p++ = '-';
		ভঙ্গ;
	পক্ষ S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		ভঙ্গ;
#ifdef S_IFSOCK
	পক্ষ S_IFSOCK:			/* socket */
		*p++ = 's';
		ভঙ্গ;
#endif
#ifdef S_IFIFO
	পক্ষ S_IFIFO:			/* fifo */
		*p++ = 'p';
		ভঙ্গ;
#endif
	স্বভাব:			/* unknown */
		*p++ = '?';
		ভঙ্গ;
	}
	/* usr */
	যদি (mode & S_IRUSR)
		*p++ = 'r';
	অন্যথা
		*p++ = '-';
	যদি (mode & S_IWUSR)
		*p++ = 'w';
	অন্যথা
		*p++ = '-';
	বিকল্প (mode & (S_IXUSR | S_ISUID)) {
	পক্ষ 0:
		*p++ = '-';
		ভঙ্গ;
	পক্ষ S_IXUSR:
		*p++ = 'x';
		ভঙ্গ;
	পক্ষ S_ISUID:
		*p++ = 'S';
		ভঙ্গ;
	পক্ষ S_IXUSR | S_ISUID:
		*p++ = 's';
		ভঙ্গ;
	}
	/* group */
	যদি (mode & S_IRGRP)
		*p++ = 'r';
	অন্যথা
		*p++ = '-';
	যদি (mode & S_IWGRP)
		*p++ = 'w';
	অন্যথা
		*p++ = '-';
	বিকল্প (mode & (S_IXGRP | S_ISGID)) {
	পক্ষ 0:
		*p++ = '-';
		ভঙ্গ;
	পক্ষ S_IXGRP:
		*p++ = 'x';
		ভঙ্গ;
	পক্ষ S_ISGID:
		*p++ = 'S';
		ভঙ্গ;
	পক্ষ S_IXGRP | S_ISGID:
		*p++ = 's';
		ভঙ্গ;
	}
	/* other */
	যদি (mode & S_IROTH)
		*p++ = 'r';
	অন্যথা
		*p++ = '-';
	যদি (mode & S_IWOTH)
		*p++ = 'w';
	অন্যথা
		*p++ = '-';
	বিকল্প (mode & (S_IXOTH | S_ISVTX)) {
	পক্ষ 0:
		*p++ = '-';
		ভঙ্গ;
	পক্ষ S_IXOTH:
		*p++ = 'x';
		ভঙ্গ;
	পক্ষ S_ISVTX:
		*p++ = 'T';
		ভঙ্গ;
	পক্ষ S_IXOTH | S_ISVTX:
		*p++ = 't';
		ভঙ্গ;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
