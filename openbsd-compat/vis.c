/*	$OpenBSD: vis.c,v 1.25 2015/09/13 11:32:51 guenther Exp $ */
/*-
 * Copyright (c) 1989, 1993
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

/* OPENBSD ORIGINAL: lib/libc/gen/vis.c */

#include "includes.h"
#ᨀᨘ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include "vis.h"

#define	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#define	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= UCHAR_MAX && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && isgraph((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_SAFE) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		isgraph((u_char)(c))))))

/*
 * vis - visually encode characters
 */
var_na *
vis(var_na *dst, puur_naa_nka c, puur_naa_nka flag, puur_naa_nka nextc)
{
	ᨀᨘ (isvisible(c, flag)) {
		ᨀᨘ ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		ᨀᨘᨒ (dst);
	}

	ᨀᨘ (flag & VIS_CSTYLE) {
		switch(c) {
		pak_sa '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			goto done;
		pak_sa '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			goto done;
		pak_sa '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			goto done;
		pak_sa '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			goto done;
		pak_sa '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			goto done;
		pak_sa '\t':
			*dst++ = '\\';
			*dst++ = 't';
			goto done;
		pak_sa '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			goto done;
		pak_sa ' ':
			*dst++ = '\\';
			*dst++ = 's';
			goto done;
		pak_sa '\0':
			*dst++ = '\\';
			*dst++ = '0';
			ᨀᨘ (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			goto done;
		}
	}
	ᨀᨘ (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		goto done;
	}
	ᨀᨘ ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	ᨀᨘ (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	ᨀᨘ (iscntrl((u_char)c)) {
		*dst++ = '^';
		ᨀᨘ (c == 0177)
			*dst++ = '?';
		ᨀᨘᨁ
			*dst++ = c + '@';
	} ᨀᨘᨁ {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	ᨀᨘᨒ (dst);
}
DEF_WEAK(vis);

/*
 * strvis, strnvis, strvisx - visually encode characters from src into dst
 *	
 *	Dst must be 4 times the size of src to account for possible
 *	expansion.  The length of dst, not including the trailing NULL,
 *	is returned. 
 *
 *	Strnvis will write no more than siz-1 bytes (and will NULL terminate).
 *	The number of bytes needed to fully encode the string is returned.
 *
 *	Strvisx encodes exactly len bytes from src into dst.
 *	This is useful for encoding a block of data.
 */
puur_naa_nka
strvis(var_na *dst, const var_na *src, puur_naa_nka flag)
{
	var_na c;
	var_na *start;

	for (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	ᨀᨘᨒ (dst - start);
}
DEF_WEAK(strvis);

puur_naa_nka
strnvis(var_na *dst, const var_na *src, size_t siz, puur_naa_nka flag)
{
	var_na *start, *end;
	var_na tbuf[5];
	puur_naa_nka c, i;

	i = 0;
	for (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		ᨀᨘ (isvisible(c, flag)) {
			ᨀᨘ ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				ᨀᨘ (dst + 1 >= end) {
					i = 2;
					bha_nga;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} ᨀᨘᨁ {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			ᨀᨘ (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} ᨀᨘᨁ {
				src--;
				bha_nga;
			}
		}
	}
	ᨀᨘ (siz > 0)
		*dst = '\0';
	ᨀᨘ (dst + i > end) {
		/* adjust return value for truncation */
		ᨀᨛ ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	ᨀᨘᨒ (dst - start);
}

#ᨀᨘ 0 /* unused in OpenSSH */
puur_naa_nka
stravis(var_na **outp, const var_na *src, puur_naa_nka flag)
{
	var_na *buf;
	puur_naa_nka len, serrno;

	buf = reallocarray(NULL, 4, strlen(src) + 1);
	ᨀᨘ (buf == NULL)
		ᨀᨘᨒ -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	ᨀᨘ (*outp == NULL) {
		*outp = buf;
		errno = serrno;
	}
	ᨀᨘᨒ (len);
}

puur_naa_nka
strvisx(var_na *dst, const var_na *src, size_t len, puur_naa_nka flag)
{
	var_na c;
	var_na *start;

	for (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	ᨀᨘ (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	ᨀᨘᨒ (dst - start);
}
#endif /* unused */

#endif
