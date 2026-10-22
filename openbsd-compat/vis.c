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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "vis.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= UCHAR_MAX && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && isgraph((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_ਸੁਰੱਖਿਅਤ) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		isgraph((u_char)(c))))))

/*
 * vis - visually encode characters
 */
ਅੱਖਰ *
vis(ਅੱਖਰ *dst, ਪੂਰਨ c, ਪੂਰਨ flag, ਪੂਰਨ nextc)
{
	ਜੇ (isvisible(c, flag)) {
		ਜੇ ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		ਵਾਪਸ (dst);
	}

	ਜੇ (flag & VIS_CSTYLE) {
		ਚੋਣ(c) {
		ਹਾਲਤ '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ '\t':
			*dst++ = '\\';
			*dst++ = 't';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ ' ':
			*dst++ = '\\';
			*dst++ = 's';
			ਜਾਓ ਪੂਰਾ;
		ਹਾਲਤ '\0':
			*dst++ = '\\';
			*dst++ = '0';
			ਜੇ (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			ਜਾਓ ਪੂਰਾ;
		}
	}
	ਜੇ (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	ਜੇ (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	ਜੇ (iscntrl((u_char)c)) {
		*dst++ = '^';
		ਜੇ (c == 0177)
			*dst++ = '?';
		ਨਹੀਂਤਾਂ
			*dst++ = c + '@';
	} ਨਹੀਂਤਾਂ {
		*dst++ = '-';
		*dst++ = c;
	}
ਪੂਰਾ:
	*dst = '\0';
	ਵਾਪਸ (dst);
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
ਪੂਰਨ
strvis(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਪੂਰਨ flag)
{
	ਅੱਖਰ c;
	ਅੱਖਰ *ਸ਼ੁਰੂ;

	ਲਈ (ਸ਼ੁਰੂ = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	ਵਾਪਸ (dst - ਸ਼ੁਰੂ);
}
DEF_WEAK(strvis);

ਪੂਰਨ
strnvis(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਮਾਪ_t siz, ਪੂਰਨ flag)
{
	ਅੱਖਰ *ਸ਼ੁਰੂ, *ਸਿਰਾ;
	ਅੱਖਰ tbuf[5];
	ਪੂਰਨ c, i;

	i = 0;
	ਲਈ (ਸ਼ੁਰੂ = dst, ਸਿਰਾ = ਸ਼ੁਰੂ + siz - 1; (c = *src) && dst < ਸਿਰਾ; ) {
		ਜੇ (isvisible(c, flag)) {
			ਜੇ ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				ਜੇ (dst + 1 >= ਸਿਰਾ) {
					i = 2;
					ਰੋਕੋ;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} ਨਹੀਂਤਾਂ {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			ਜੇ (dst + i <= ਸਿਰਾ) {
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(dst, tbuf, i);
				dst += i;
			} ਨਹੀਂਤਾਂ {
				src--;
				ਰੋਕੋ;
			}
		}
	}
	ਜੇ (siz > 0)
		*dst = '\0';
	ਜੇ (dst + i > ਸਿਰਾ) {
		/* adjust return value for truncation */
		ਜਦੋਂ ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	ਵਾਪਸ (dst - ਸ਼ੁਰੂ);
}

#ਜੇ 0 /* unused in OpenSSH */
ਪੂਰਨ
stravis(ਅੱਖਰ **outp, ਅਚਲ ਅੱਖਰ *src, ਪੂਰਨ flag)
{
	ਅੱਖਰ *buf;
	ਪੂਰਨ len, serrno;

	buf = reallocarray(ਨਿਰਾ, 4, ਲੜੀ_ਲੰਬਾਈ(src) + 1);
	ਜੇ (buf == ਨਿਰਾ)
		ਵਾਪਸ -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	ਜੇ (*outp == ਨਿਰਾ) {
		*outp = buf;
		errno = serrno;
	}
	ਵਾਪਸ (len);
}

ਪੂਰਨ
strvisx(ਅੱਖਰ *dst, ਅਚਲ ਅੱਖਰ *src, ਮਾਪ_t len, ਪੂਰਨ flag)
{
	ਅੱਖਰ c;
	ਅੱਖਰ *ਸ਼ੁਰੂ;

	ਲਈ (ਸ਼ੁਰੂ = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	ਜੇ (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	ਵਾਪਸ (dst - ਸ਼ੁਰੂ);
}
#ਜੇ_ਅੰਤ /*ਅਣਵਰਤਿਆ*/

#ਜੇ_ਅੰਤ
