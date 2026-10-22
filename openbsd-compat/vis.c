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
#ಯದಿ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "vis.h"

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
ವರ್ಣ *
vis(ವರ್ಣ *dst, ಪೂರ್ಣಾಙ್ಕ c, ಪೂರ್ಣಾಙ್ಕ flag, ಪೂರ್ಣಾಙ್ಕ nextc)
{
	ಯದಿ (isvisible(c, flag)) {
		ಯದಿ ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		ಪ್ರತ್ಯಾಗಮ (dst);
	}

	ಯದಿ (flag & VIS_CSTYLE) {
		ವಿಕಲ್ಪ(c) {
		ಪಕ್ಷ '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			ಗಚ್ಛ done;
		ಪಕ್ಷ '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			ಗಚ್ಛ done;
		ಪಕ್ಷ '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			ಗಚ್ಛ done;
		ಪಕ್ಷ '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			ಗಚ್ಛ done;
		ಪಕ್ಷ '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			ಗಚ್ಛ done;
		ಪಕ್ಷ '\t':
			*dst++ = '\\';
			*dst++ = 't';
			ಗಚ್ಛ done;
		ಪಕ್ಷ '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			ಗಚ್ಛ done;
		ಪಕ್ಷ ' ':
			*dst++ = '\\';
			*dst++ = 's';
			ಗಚ್ಛ done;
		ಪಕ್ಷ '\0':
			*dst++ = '\\';
			*dst++ = '0';
			ಯದಿ (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			ಗಚ್ಛ done;
		}
	}
	ಯದಿ (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		ಗಚ್ಛ done;
	}
	ಯದಿ ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	ಯದಿ (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	ಯದಿ (iscntrl((u_char)c)) {
		*dst++ = '^';
		ಯದಿ (c == 0177)
			*dst++ = '?';
		ಅನ್ಯಥಾ
			*dst++ = c + '@';
	} ಅನ್ಯಥಾ {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	ಪ್ರತ್ಯಾಗಮ (dst);
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
ಪೂರ್ಣಾಙ್ಕ
strvis(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ವರ್ಣ c;
	ವರ್ಣ *start;

	ಪ್ರತಿ (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	ಪ್ರತ್ಯಾಗಮ (dst - start);
}
DEF_WEAK(strvis);

ಪೂರ್ಣಾಙ್ಕ
strnvis(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, size_t siz, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ವರ್ಣ *start, *end;
	ವರ್ಣ tbuf[5];
	ಪೂರ್ಣಾಙ್ಕ c, i;

	i = 0;
	ಪ್ರತಿ (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		ಯದಿ (isvisible(c, flag)) {
			ಯದಿ ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				ಯದಿ (dst + 1 >= end) {
					i = 2;
					ಭಙ್ಗ;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} ಅನ್ಯಥಾ {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			ಯದಿ (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} ಅನ್ಯಥಾ {
				src--;
				ಭಙ್ಗ;
			}
		}
	}
	ಯದಿ (siz > 0)
		*dst = '\0';
	ಯದಿ (dst + i > end) {
		/* adjust return value for truncation */
		ಯಾವತ್ ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	ಪ್ರತ್ಯಾಗಮ (dst - start);
}

#ಯದಿ 0 /* unused in OpenSSH */
ಪೂರ್ಣಾಙ್ಕ
stravis(ವರ್ಣ **outp, ಧ್ರುವ ವರ್ಣ *src, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ವರ್ಣ *buf;
	ಪೂರ್ಣಾಙ್ಕ len, serrno;

	buf = reallocarray(ರಿಕ್ತ, 4, strlen(src) + 1);
	ಯದಿ (buf == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	ಯದಿ (*outp == ರಿಕ್ತ) {
		*outp = buf;
		errno = serrno;
	}
	ಪ್ರತ್ಯಾಗಮ (len);
}

ಪೂರ್ಣಾಙ್ಕ
strvisx(ವರ್ಣ *dst, ಧ್ರುವ ವರ್ಣ *src, size_t len, ಪೂರ್ಣಾಙ್ಕ flag)
{
	ವರ್ಣ c;
	ವರ್ಣ *start;

	ಪ್ರತಿ (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	ಯದಿ (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	ಪ್ರತ್ಯಾಗಮ (dst - start);
}
#endif /* unused */

#endif
