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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಆದರೆ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "vis.h"

#ವ್ಯಾಖ್ಯಾನಿಸು	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#ವ್ಯಾಖ್ಯಾನಿಸು	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= UCHAR_MAX && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && isgraph((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_ಸುರಕ್ಷಿತ) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		isgraph((u_char)(c))))))

/*
 * vis - visually encode characters
 */
ಅಕ್ಷರ *
vis(ಅಕ್ಷರ *dst, ಪೂರ್ಣಾಂಕ c, ಪೂರ್ಣಾಂಕ flag, ಪೂರ್ಣಾಂಕ nextc)
{
	ಆದರೆ (isvisible(c, flag)) {
		ಆದರೆ ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		ಹಿಂತಿರುಗಿ (dst);
	}

	ಆದರೆ (flag & VIS_CSTYLE) {
		ಆಯ್ಕೆ(c) {
		ಸ್ಥಿತಿ '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ '\t':
			*dst++ = '\\';
			*dst++ = 't';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ ' ':
			*dst++ = '\\';
			*dst++ = 's';
			ಹೋಗು ಮುಗಿದ;
		ಸ್ಥಿತಿ '\0':
			*dst++ = '\\';
			*dst++ = '0';
			ಆದರೆ (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			ಹೋಗು ಮುಗಿದ;
		}
	}
	ಆದರೆ (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	ಆದರೆ (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	ಆದರೆ (iscntrl((u_char)c)) {
		*dst++ = '^';
		ಆದರೆ (c == 0177)
			*dst++ = '?';
		ಇಲ್ಲದಿದ್ದರೆ
			*dst++ = c + '@';
	} ಇಲ್ಲದಿದ್ದರೆ {
		*dst++ = '-';
		*dst++ = c;
	}
ಮುಗಿದ:
	*dst = '\0';
	ಹಿಂತಿರುಗಿ (dst);
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
ಪೂರ್ಣಾಂಕ
strvis(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಪೂರ್ಣಾಂಕ flag)
{
	ಅಕ್ಷರ c;
	ಅಕ್ಷರ *ಆರಂಭ;

	ಗಾಗಿ (ಆರಂಭ = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	ಹಿಂತಿರುಗಿ (dst - ಆರಂಭ);
}
DEF_WEAK(strvis);

ಪೂರ್ಣಾಂಕ
strnvis(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಗಾತ್ರ_t siz, ಪೂರ್ಣಾಂಕ flag)
{
	ಅಕ್ಷರ *ಆರಂಭ, *ಕೊನೆ;
	ಅಕ್ಷರ tbuf[5];
	ಪೂರ್ಣಾಂಕ c, i;

	i = 0;
	ಗಾಗಿ (ಆರಂಭ = dst, ಕೊನೆ = ಆರಂಭ + siz - 1; (c = *src) && dst < ಕೊನೆ; ) {
		ಆದರೆ (isvisible(c, flag)) {
			ಆದರೆ ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				ಆದರೆ (dst + 1 >= ಕೊನೆ) {
					i = 2;
					ನಿಲ್ಲಿಸು;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} ಇಲ್ಲದಿದ್ದರೆ {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			ಆದರೆ (dst + i <= ಕೊನೆ) {
				ಸ್ಮರಣೆ_ನಕಲು(dst, tbuf, i);
				dst += i;
			} ಇಲ್ಲದಿದ್ದರೆ {
				src--;
				ನಿಲ್ಲಿಸು;
			}
		}
	}
	ಆದರೆ (siz > 0)
		*dst = '\0';
	ಆದರೆ (dst + i > ಕೊನೆ) {
		/* adjust return value for truncation */
		ಆಗ ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	ಹಿಂತಿರುಗಿ (dst - ಆರಂಭ);
}

#ಆದರೆ 0 /* unused in OpenSSH */
ಪೂರ್ಣಾಂಕ
stravis(ಅಕ್ಷರ **outp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಪೂರ್ಣಾಂಕ flag)
{
	ಅಕ್ಷರ *buf;
	ಪೂರ್ಣಾಂಕ len, serrno;

	buf = reallocarray(ಖಾಲಿ, 4, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(src) + 1);
	ಆದರೆ (buf == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	ಆದರೆ (*outp == ಖಾಲಿ) {
		*outp = buf;
		errno = serrno;
	}
	ಹಿಂತಿರುಗಿ (len);
}

ಪೂರ್ಣಾಂಕ
strvisx(ಅಕ್ಷರ *dst, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *src, ಗಾತ್ರ_t len, ಪೂರ್ಣಾಂಕ flag)
{
	ಅಕ್ಷರ c;
	ಅಕ್ಷರ *ಆರಂಭ;

	ಗಾಗಿ (ಆರಂಭ = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	ಆದರೆ (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	ಹಿಂತಿರುಗಿ (dst - ಆರಂಭ);
}
#ಆದರೆ_ಅಂತ್ಯ /*ಬಳಸದ*/

#ಆದರೆ_ಅಂತ್ಯ
