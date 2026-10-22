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

#அந்தர்பாவ "includes.h"
#ifndef HAVE_STRMODE

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <string.h>

/* XXX mode should be mode_t */

வெறுமை
strmode(முழு mode, எழுத்து *p)
{
	 /* print type */
	தேர்வு (mode & S_IFMT) {
	நிலை S_IFDIR:			/* directory */
		*p++ = 'd';
		நிறுத்து;
	நிலை S_IFCHR:			/* character special */
		*p++ = 'c';
		நிறுத்து;
	நிலை S_IFBLK:			/* block special */
		*p++ = 'b';
		நிறுத்து;
	நிலை S_IFREG:			/* regular */
		*p++ = '-';
		நிறுத்து;
	நிலை S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		நிறுத்து;
#ifdef S_IFSOCK
	நிலை S_IFSOCK:			/* socket */
		*p++ = 's';
		நிறுத்து;
#endif
#ifdef S_IFIFO
	நிலை S_IFIFO:			/* fifo */
		*p++ = 'p';
		நிறுத்து;
#endif
	இயல்பு:			/* unknown */
		*p++ = '?';
		நிறுத்து;
	}
	/* usr */
	எனில் (mode & S_IRUSR)
		*p++ = 'r';
	இல்லையெனில்
		*p++ = '-';
	எனில் (mode & S_IWUSR)
		*p++ = 'w';
	இல்லையெனில்
		*p++ = '-';
	தேர்வு (mode & (S_IXUSR | S_ISUID)) {
	நிலை 0:
		*p++ = '-';
		நிறுத்து;
	நிலை S_IXUSR:
		*p++ = 'x';
		நிறுத்து;
	நிலை S_ISUID:
		*p++ = 'S';
		நிறுத்து;
	நிலை S_IXUSR | S_ISUID:
		*p++ = 's';
		நிறுத்து;
	}
	/* group */
	எனில் (mode & S_IRGRP)
		*p++ = 'r';
	இல்லையெனில்
		*p++ = '-';
	எனில் (mode & S_IWGRP)
		*p++ = 'w';
	இல்லையெனில்
		*p++ = '-';
	தேர்வு (mode & (S_IXGRP | S_ISGID)) {
	நிலை 0:
		*p++ = '-';
		நிறுத்து;
	நிலை S_IXGRP:
		*p++ = 'x';
		நிறுத்து;
	நிலை S_ISGID:
		*p++ = 'S';
		நிறுத்து;
	நிலை S_IXGRP | S_ISGID:
		*p++ = 's';
		நிறுத்து;
	}
	/* other */
	எனில் (mode & S_IROTH)
		*p++ = 'r';
	இல்லையெனில்
		*p++ = '-';
	எனில் (mode & S_IWOTH)
		*p++ = 'w';
	இல்லையெனில்
		*p++ = '-';
	தேர்வு (mode & (S_IXOTH | S_ISVTX)) {
	நிலை 0:
		*p++ = '-';
		நிறுத்து;
	நிலை S_IXOTH:
		*p++ = 'x';
		நிறுத்து;
	நிலை S_ISVTX:
		*p++ = 'T';
		நிறுத்து;
	நிலை S_IXOTH | S_ISVTX:
		*p++ = 't';
		நிறுத்து;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}
#endif
