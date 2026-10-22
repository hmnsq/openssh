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

#include "includes.h"

#ifndef HAVE_INET_NTOP

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

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

static const char *inet_ntop4(const u_char *src, char *dst, size_t size);
static const char *inet_ntop6(const u_char *src, char *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *
inet_ntop(цяло af, const void *src, char *dst, socklen_t size)
{
	switch (af) {
	case AF_INET:
		върни (inet_ntop4(src, dst, (size_t)size));
	case AF_INET6:
		върни (inet_ntop6(src, dst, (size_t)size));
	default:
		errno = EAFNOSUPPORT;
		върни (NULL);
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
static const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	цяло l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	ако (l <= 0 || l >= size) {
		errno = ENOSPC;
		върни (NULL);
	}
	strlcpy(dst, tmp, size);
	върни (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const u_char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	char *tp, *ep;
	struct { цяло base, len; } best, cur;
	u_int words[IN6ADDRSZ / INT16SZ];
	цяло i;
	цяло advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	за (i = 0; i < IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	за (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		ако (words[i] == 0) {
			ако (cur.base == -1)
				cur.base = i, cur.len = 1;
			иначе
				cur.len++;
		} иначе {
			ако (cur.base != -1) {
				ако (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	ако (cur.base != -1) {
		ако (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	ако (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + sizeof(tmp);
	за (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		ако (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			ако (i == best.base) {
				ако (tp + 1 >= ep)
					върни (NULL);
				*tp++ = ':';
			}
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		ако (i != 0) {
			ако (tp + 1 >= ep)
				върни (NULL);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		ако (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			ако (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				върни (NULL);
			tp += strlen(tp);
			break;
		}
		advance = snprintf(tp, ep - tp, "%x", words[i]);
		ако (advance <= 0 || advance >= ep - tp)
			върни (NULL);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	ако (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		ако (tp + 1 >= ep)
			върни (NULL);
		*tp++ = ':';
	}
	ако (tp + 1 >= ep)
		върни (NULL);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	ако ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		върни (NULL);
	}
	strlcpy(dst, tmp, size);
	върни (dst);
}

#endif /* !HAVE_INET_NTOP */
