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

#അന്തര്ഭാവ "includes.h"
#ifndef HAVE_STRMODE

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <string.h>

/* XXX mode should be mode_t */

ശൂന്യം
strmode(പൂർണ്ണസംഖ്യ mode, അക്ഷരം *p)
{
	 /* print type */
	തിരഞ്ഞെടുപ്പ് (mode & S_IFMT) {
	അവസ്ഥ S_IFDIR:			/* directory */
		*p++ = 'd';
		നിർത്തുക;
	അവസ്ഥ S_IFCHR:			/* character special */
		*p++ = 'c';
		നിർത്തുക;
	അവസ്ഥ S_IFBLK:			/* block special */
		*p++ = 'b';
		നിർത്തുക;
	അവസ്ഥ S_IFREG:			/* regular */
		*p++ = '-';
		നിർത്തുക;
	അവസ്ഥ S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		നിർത്തുക;
#ifdef S_IFSOCK
	അവസ്ഥ S_IFSOCK:			/* socket */
		*p++ = 's';
		നിർത്തുക;
#endif
#ifdef S_IFIFO
	അവസ്ഥ S_IFIFO:			/* fifo */
		*p++ = 'p';
		നിർത്തുക;
#endif
	സ്ഥിരസ്ഥിതി:			/* unknown */
		*p++ = '?';
		നിർത്തുക;
	}
	/* usr */
	എങ്കിൽ (mode & S_IRUSR)
		*p++ = 'r';
	അല്ലെങ്കിൽ
		*p++ = '-';
	എങ്കിൽ (mode & S_IWUSR)
		*p++ = 'w';
	അല്ലെങ്കിൽ
		*p++ = '-';
	തിരഞ്ഞെടുപ്പ് (mode & (S_IXUSR | S_ISUID)) {
	അവസ്ഥ 0:
		*p++ = '-';
		നിർത്തുക;
	അവസ്ഥ S_IXUSR:
		*p++ = 'x';
		നിർത്തുക;
	അവസ്ഥ S_ISUID:
		*p++ = 'S';
		നിർത്തുക;
	അവസ്ഥ S_IXUSR | S_ISUID:
		*p++ = 's';
		നിർത്തുക;
	}
	/* group */
	എങ്കിൽ (mode & S_IRGRP)
		*p++ = 'r';
	അല്ലെങ്കിൽ
		*p++ = '-';
	എങ്കിൽ (mode & S_IWGRP)
		*p++ = 'w';
	അല്ലെങ്കിൽ
		*p++ = '-';
	തിരഞ്ഞെടുപ്പ് (mode & (S_IXGRP | S_ISGID)) {
	അവസ്ഥ 0:
		*p++ = '-';
		നിർത്തുക;
	അവസ്ഥ S_IXGRP:
		*p++ = 'x';
		നിർത്തുക;
	അവസ്ഥ S_ISGID:
		*p++ = 'S';
		നിർത്തുക;
	അവസ്ഥ S_IXGRP | S_ISGID:
		*p++ = 's';
		നിർത്തുക;
	}
	/* other */
	എങ്കിൽ (mode & S_IROTH)
		*p++ = 'r';
	അല്ലെങ്കിൽ
		*p++ = '-';
	എങ്കിൽ (mode & S_IWOTH)
		*p++ = 'w';
	അല്ലെങ്കിൽ
		*p++ = '-';
	തിരഞ്ഞെടുപ്പ് (mode & (S_IXOTH | S_ISVTX)) {
	അവസ്ഥ 0:
		*p++ = '-';
		നിർത്തുക;
	അവസ്ഥ S_IXOTH:
		*p++ = 'x';
		നിർത്തുക;
	അവസ്ഥ S_ISVTX:
		*p++ = 'T';
		നിർത്തുക;
	അവസ്ഥ S_IXOTH | S_ISVTX:
		*p++ = 't';
		നിർത്തുക;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
