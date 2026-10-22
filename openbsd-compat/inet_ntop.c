/*	$OpenBSD: inet_ntop.c,v 1.8 2008/12/09 19:38:38 otto Exp $	*/

/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/net/inet_ntop.c */

#ضمن "includes.h"

#ifndef HAVE_INET_NTOP

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <netinet/in.h>
#ضمن <arpa/inet.h>
#ضمن <arpa/nameser.h>
#ضمن <string.h>
#ضمن <errno.h>
#ضمن <stdio.h>

#ifndef IN6ADDRSZ
#define IN6ADDRSZ   16   /* IPv6 T_AAAA */                 
#endif

#ifndef INT16SZ
#define INT16SZ     2    /* for systems without 16-bit ints */
#endif

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

ساكن ثابت حرف *inet_ntop4(ثابت u_char *src, حرف *dst, size_t size);
ساكن ثابت حرف *inet_ntop6(ثابت u_char *src, حرف *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ثابت حرف *
inet_ntop(صحيح af, ثابت فراغ *src, حرف *dst, socklen_t size)
{
	بدل (af) {
	حالة AF_INET:
		إرجاع (inet_ntop4(src, dst, (size_t)size));
	حالة AF_INET6:
		إرجاع (inet_ntop6(src, dst, (size_t)size));
	افتراضي:
		errno = EAFNOSUPPORT;
		إرجاع (عدم);
	}
	/* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
ساكن ثابت حرف *
inet_ntop4(ثابت u_char *src, حرف *dst, size_t size)
{
	ساكن ثابت حرف fmt[] = "%u.%u.%u.%u";
	حرف tmp[حجم "255.255.255.255"];
	صحيح l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	إذا (l <= 0 || l >= size) {
		errno = ENOSPC;
		إرجاع (عدم);
	}
	strlcpy(dst, tmp, size);
	إرجاع (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
ساكن ثابت حرف *
inet_ntop6(ثابت u_char *src, حرف *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	حرف tmp[حجم "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	حرف *tp, *ep;
	بنية { صحيح base, len; } best, cur;
	u_int كلمات[IN6ADDRSZ / INT16SZ];
	صحيح i;
	صحيح advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(كلمات, '\0', حجم كلمات);
	لكل (i = 0; i < IN6ADDRSZ; i++)
		كلمات[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	لكل (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		إذا (كلمات[i] == 0) {
			إذا (cur.base == -1)
				cur.base = i, cur.len = 1;
			وإلا
				cur.len++;
		} وإلا {
			إذا (cur.base != -1) {
				إذا (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	إذا (cur.base != -1) {
		إذا (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	إذا (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + حجم(tmp);
	لكل (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		إذا (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			إذا (i == best.base) {
				إذا (tp + 1 >= ep)
					إرجاع (عدم);
				*tp++ = ':';
			}
			استمر;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		إذا (i != 0) {
			إذا (tp + 1 >= ep)
				إرجاع (عدم);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		إذا (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && كلمات[5] == 0xffff))) {
			إذا (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				إرجاع (عدم);
			tp += strlen(tp);
			اكسر;
		}
		advance = snprintf(tp, ep - tp, "%x", كلمات[i]);
		إذا (advance <= 0 || advance >= ep - tp)
			إرجاع (عدم);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	إذا (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		إذا (tp + 1 >= ep)
			إرجاع (عدم);
		*tp++ = ':';
	}
	إذا (tp + 1 >= ep)
		إرجاع (عدم);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	إذا ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		إرجاع (عدم);
	}
	strlcpy(dst, tmp, size);
	إرجاع (dst);
}

#endif /* !HAVE_INET_NTOP */
