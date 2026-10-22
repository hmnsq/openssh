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

#அந்தர்பாவ "includes.h"
#எனில் !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>

#அந்தர்பாவ "vis.h"

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
எழுத்து *
vis(எழுத்து *dst, முழு c, முழு flag, முழு nextc)
{
	எனில் (isvisible(c, flag)) {
		எனில் ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		திரும்பு (dst);
	}

	எனில் (flag & VIS_CSTYLE) {
		தேர்வு(c) {
		நிலை '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			செல் done;
		நிலை '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			செல் done;
		நிலை '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			செல் done;
		நிலை '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			செல் done;
		நிலை '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			செல் done;
		நிலை '\t':
			*dst++ = '\\';
			*dst++ = 't';
			செல் done;
		நிலை '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			செல் done;
		நிலை ' ':
			*dst++ = '\\';
			*dst++ = 's';
			செல் done;
		நிலை '\0':
			*dst++ = '\\';
			*dst++ = '0';
			எனில் (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			செல் done;
		}
	}
	எனில் (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		செல் done;
	}
	எனில் ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	எனில் (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	எனில் (iscntrl((u_char)c)) {
		*dst++ = '^';
		எனில் (c == 0177)
			*dst++ = '?';
		இல்லையெனில்
			*dst++ = c + '@';
	} இல்லையெனில் {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	திரும்பு (dst);
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
முழு
strvis(எழுத்து *dst, மாறிலி எழுத்து *src, முழு flag)
{
	எழுத்து c;
	எழுத்து *start;

	க்கு (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	திரும்பு (dst - start);
}
DEF_WEAK(strvis);

முழு
strnvis(எழுத்து *dst, மாறிலி எழுத்து *src, size_t siz, முழு flag)
{
	எழுத்து *start, *end;
	எழுத்து tbuf[5];
	முழு c, i;

	i = 0;
	க்கு (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		எனில் (isvisible(c, flag)) {
			எனில் ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				எனில் (dst + 1 >= end) {
					i = 2;
					நிறுத்து;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} இல்லையெனில் {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			எனில் (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} இல்லையெனில் {
				src--;
				நிறுத்து;
			}
		}
	}
	எனில் (siz > 0)
		*dst = '\0';
	எனில் (dst + i > end) {
		/* adjust return value for truncation */
		போது ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	திரும்பு (dst - start);
}

#எனில் 0 /* unused in OpenSSH */
முழு
stravis(எழுத்து **outp, மாறிலி எழுத்து *src, முழு flag)
{
	எழுத்து *buf;
	முழு len, serrno;

	buf = reallocarray(வெற்று, 4, strlen(src) + 1);
	எனில் (buf == வெற்று)
		திரும்பு -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	எனில் (*outp == வெற்று) {
		*outp = buf;
		errno = serrno;
	}
	திரும்பு (len);
}

முழு
strvisx(எழுத்து *dst, மாறிலி எழுத்து *src, size_t len, முழு flag)
{
	எழுத்து c;
	எழுத்து *start;

	க்கு (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	எனில் (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	திரும்பு (dst - start);
}
#endif /* unused */

#endif
