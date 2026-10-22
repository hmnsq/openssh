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

#અન્તર્ભાવ "includes.h"
#જો !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>

#અન્તર્ભાવ "vis.h"

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
અક્ષર *
vis(અક્ષર *dst, પૂર્ણાંક c, પૂર્ણાંક flag, પૂર્ણાંક nextc)
{
	જો (isvisible(c, flag)) {
		જો ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		પાછા (dst);
	}

	જો (flag & VIS_CSTYLE) {
		પસંદગી(c) {
		સ્થિતિ '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			જાઓ done;
		સ્થિતિ '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			જાઓ done;
		સ્થિતિ '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			જાઓ done;
		સ્થિતિ '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			જાઓ done;
		સ્થિતિ '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			જાઓ done;
		સ્થિતિ '\t':
			*dst++ = '\\';
			*dst++ = 't';
			જાઓ done;
		સ્થિતિ '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			જાઓ done;
		સ્થિતિ ' ':
			*dst++ = '\\';
			*dst++ = 's';
			જાઓ done;
		સ્થિતિ '\0':
			*dst++ = '\\';
			*dst++ = '0';
			જો (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			જાઓ done;
		}
	}
	જો (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		જાઓ done;
	}
	જો ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	જો (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	જો (iscntrl((u_char)c)) {
		*dst++ = '^';
		જો (c == 0177)
			*dst++ = '?';
		નહીંતર
			*dst++ = c + '@';
	} નહીંતર {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	પાછા (dst);
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
પૂર્ણાંક
strvis(અક્ષર *dst, અચલ અક્ષર *src, પૂર્ણાંક flag)
{
	અક્ષર c;
	અક્ષર *start;

	માટે (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	પાછા (dst - start);
}
DEF_WEAK(strvis);

પૂર્ણાંક
strnvis(અક્ષર *dst, અચલ અક્ષર *src, size_t siz, પૂર્ણાંક flag)
{
	અક્ષર *start, *end;
	અક્ષર tbuf[5];
	પૂર્ણાંક c, i;

	i = 0;
	માટે (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		જો (isvisible(c, flag)) {
			જો ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				જો (dst + 1 >= end) {
					i = 2;
					તોડો;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} નહીંતર {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			જો (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} નહીંતર {
				src--;
				તોડો;
			}
		}
	}
	જો (siz > 0)
		*dst = '\0';
	જો (dst + i > end) {
		/* adjust return value for truncation */
		જ્યારે ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	પાછા (dst - start);
}

#જો 0 /* unused in OpenSSH */
પૂર્ણાંક
stravis(અક્ષર **outp, અચલ અક્ષર *src, પૂર્ણાંક flag)
{
	અક્ષર *buf;
	પૂર્ણાંક len, serrno;

	buf = reallocarray(ખાલી, 4, strlen(src) + 1);
	જો (buf == ખાલી)
		પાછા -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	જો (*outp == ખાલી) {
		*outp = buf;
		errno = serrno;
	}
	પાછા (len);
}

પૂર્ણાંક
strvisx(અક્ષર *dst, અચલ અક્ષર *src, size_t len, પૂર્ણાંક flag)
{
	અક્ષર c;
	અક્ષર *start;

	માટે (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	જો (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	પાછા (dst - start);
}
#endif /* unused */

#endif
