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

#شامل "includes.h"
#اگر_غیر_تعریف_شدہ HAVE_STRMODE

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <string.h>

/* XXX mode should be mode_t */

خالی
strmode(صحیح منوال, حرف *p)
{
	 /* print type */
	انتخاب (منوال & S_IFMT) {
	حالت S_IFDIR:			/* directory */
		*p++ = 'd';
		توڑو;
	حالت S_IFCHR:			/* character special */
		*p++ = 'c';
		توڑو;
	حالت S_IFBLK:			/* block special */
		*p++ = 'b';
		توڑو;
	حالت S_IFREG:			/* regular */
		*p++ = '-';
		توڑو;
	حالت S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		توڑو;
#اگر_تعریف_شدہ S_IFSOCK
	حالت S_IFSOCK:			/* socket */
		*p++ = 's';
		توڑو;
#اگر_ختم
#اگر_تعریف_شدہ S_IFIFO
	حالت S_IFIFO:			/* fifo */
		*p++ = 'p';
		توڑو;
#اگر_ختم
	طےشدہ:			/* unknown */
		*p++ = '?';
		توڑو;
	}
	/* usr */
	اگر (منوال & S_IRUSR)
		*p++ = 'r';
	ورنہ
		*p++ = '-';
	اگر (منوال & S_IWUSR)
		*p++ = 'w';
	ورنہ
		*p++ = '-';
	انتخاب (منوال & (S_IXUSR | S_ISUID)) {
	حالت 0:
		*p++ = '-';
		توڑو;
	حالت S_IXUSR:
		*p++ = 'x';
		توڑو;
	حالت S_ISUID:
		*p++ = 'S';
		توڑو;
	حالت S_IXUSR | S_ISUID:
		*p++ = 's';
		توڑو;
	}
	/*گروہ*/
	اگر (منوال & S_IRGRP)
		*p++ = 'r';
	ورنہ
		*p++ = '-';
	اگر (منوال & S_IWGRP)
		*p++ = 'w';
	ورنہ
		*p++ = '-';
	انتخاب (منوال & (S_IXGRP | S_ISGID)) {
	حالت 0:
		*p++ = '-';
		توڑو;
	حالت S_IXGRP:
		*p++ = 'x';
		توڑو;
	حالت S_ISGID:
		*p++ = 'S';
		توڑو;
	حالت S_IXGRP | S_ISGID:
		*p++ = 's';
		توڑو;
	}
	/* other */
	اگر (منوال & S_IROTH)
		*p++ = 'r';
	ورنہ
		*p++ = '-';
	اگر (منوال & S_IWOTH)
		*p++ = 'w';
	ورنہ
		*p++ = '-';
	انتخاب (منوال & (S_IXOTH | S_ISVTX)) {
	حالت 0:
		*p++ = '-';
		توڑو;
	حالت S_IXOTH:
		*p++ = 'x';
		توڑو;
	حالت S_ISVTX:
		*p++ = 'T';
		توڑو;
	حالت S_IXOTH | S_ISVTX:
		*p++ = 't';
		توڑو;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#اگر_ختم
