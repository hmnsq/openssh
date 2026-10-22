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
#නම් !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

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
vis(var_na *dst, පූර්ණ_සංඛ්‍යා c, පූර්ණ_සංඛ්‍යා flag, පූර්ණ_සංඛ්‍යා nextc)
{
	නම් (isvisible(c, flag)) {
		නම් ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		ආපසු (dst);
	}

	නම් (flag & VIS_CSTYLE) {
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
			නම් (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			goto done;
		}
	}
	නම් (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		goto done;
	}
	නම් ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	නම් (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	නම් (iscntrl((u_char)c)) {
		*dst++ = '^';
		නම් (c == 0177)
			*dst++ = '?';
		නැතහොත්
			*dst++ = c + '@';
	} නැතහොත් {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	ආපසු (dst);
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
පූර්ණ_සංඛ්‍යා
strvis(var_na *dst, const var_na *src, පූර්ණ_සංඛ්‍යා flag)
{
	var_na c;
	var_na *start;

	සඳහා (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	ආපසු (dst - start);
}
DEF_WEAK(strvis);

පූර්ණ_සංඛ්‍යා
strnvis(var_na *dst, const var_na *src, size_t siz, පූර්ණ_සංඛ්‍යා flag)
{
	var_na *start, *end;
	var_na tbuf[5];
	පූර්ණ_සංඛ්‍යා c, i;

	i = 0;
	සඳහා (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		නම් (isvisible(c, flag)) {
			නම් ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				නම් (dst + 1 >= end) {
					i = 2;
					bha_nga;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} නැතහොත් {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			නම් (dst + i <= end) {
				memcpy(dst, tbuf, i);
				dst += i;
			} නැතහොත් {
				src--;
				bha_nga;
			}
		}
	}
	නම් (siz > 0)
		*dst = '\0';
	නම් (dst + i > end) {
		/* adjust return value for truncation */
		අතරතුර ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	ආපසු (dst - start);
}

#නම් 0 /* unused in OpenSSH */
පූර්ණ_සංඛ්‍යා
stravis(var_na **outp, const var_na *src, පූර්ණ_සංඛ්‍යා flag)
{
	var_na *buf;
	පූර්ණ_සංඛ්‍යා len, serrno;

	buf = reallocarray(NULL, 4, strlen(src) + 1);
	නම් (buf == NULL)
		ආපසු -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	නම් (*outp == NULL) {
		*outp = buf;
		errno = serrno;
	}
	ආපසු (len);
}

පූර්ණ_සංඛ්‍යා
strvisx(var_na *dst, const var_na *src, size_t len, පූර්ණ_සංඛ්‍යා flag)
{
	var_na c;
	var_na *start;

	සඳහා (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	නම් (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	ආපසු (dst - start);
}
#endif /* unused */

#endif
