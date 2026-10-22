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

#অন্তর্ভাৱ "includes.h"

#ifndef HAVE_INET_NTOP

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <arpa/inet.h>
#অন্তর্ভাৱ <arpa/nameser.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <stdio.h>

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

স্থির ধ্রুৱ ৱর্ণ *inet_ntop4(ধ্রুৱ u_char *src, ৱর্ণ *dst, size_t size);
স্থির ধ্রুৱ ৱর্ণ *inet_ntop6(ধ্রুৱ u_char *src, ৱর্ণ *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ধ্রুৱ ৱর্ণ *
inet_ntop(পূর্ণাঙ্ক af, ধ্রুৱ শূন্য *src, ৱর্ণ *dst, socklen_t size)
{
	ৱিকল্প (af) {
	পক্ষ AF_INET:
		ঘূৰাই (inet_ntop4(src, dst, (size_t)size));
	পক্ষ AF_INET6:
		ঘূৰাই (inet_ntop6(src, dst, (size_t)size));
	স্ৱভাৱ:
		errno = EAFNOSUPPORT;
		ঘূৰাই (রিক্ত);
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
স্থির ধ্রুৱ ৱর্ণ *
inet_ntop4(ধ্রুৱ u_char *src, ৱর্ণ *dst, size_t size)
{
	স্থির ধ্রুৱ ৱর্ণ fmt[] = "%u.%u.%u.%u";
	ৱর্ণ tmp[পরিমাণ "255.255.255.255"];
	পূর্ণাঙ্ক l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	যদি (l <= 0 || l >= size) {
		errno = ENOSPC;
		ঘূৰাই (রিক্ত);
	}
	strlcpy(dst, tmp, size);
	ঘূৰাই (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
স্থির ধ্রুৱ ৱর্ণ *
inet_ntop6(ধ্রুৱ u_char *src, ৱর্ণ *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	ৱর্ণ tmp[পরিমাণ "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	ৱর্ণ *tp, *ep;
	সংরচনা { পূর্ণাঙ্ক base, len; } best, cur;
	u_int শব্দগুলি[IN6ADDRSZ / INT16SZ];
	পূর্ণাঙ্ক i;
	পূর্ণাঙ্ক advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(শব্দগুলি, '\0', পরিমাণ শব্দগুলি);
	বাবে (i = 0; i < IN6ADDRSZ; i++)
		শব্দগুলি[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	বাবে (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		যদি (শব্দগুলি[i] == 0) {
			যদি (cur.base == -1)
				cur.base = i, cur.len = 1;
			অন্যথা
				cur.len++;
		} অন্যথা {
			যদি (cur.base != -1) {
				যদি (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	যদি (cur.base != -1) {
		যদি (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	যদি (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + পরিমাণ(tmp);
	বাবে (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		যদি (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			যদি (i == best.base) {
				যদি (tp + 1 >= ep)
					ঘূৰাই (রিক্ত);
				*tp++ = ':';
			}
			অনুৱর্ত;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		যদি (i != 0) {
			যদি (tp + 1 >= ep)
				ঘূৰাই (রিক্ত);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		যদি (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && শব্দগুলি[5] == 0xffff))) {
			যদি (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				ঘূৰাই (রিক্ত);
			tp += strlen(tp);
			ভঙ্গ;
		}
		advance = snprintf(tp, ep - tp, "%x", শব্দগুলি[i]);
		যদি (advance <= 0 || advance >= ep - tp)
			ঘূৰাই (রিক্ত);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	যদি (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		যদি (tp + 1 >= ep)
			ঘূৰাই (রিক্ত);
		*tp++ = ':';
	}
	যদি (tp + 1 >= ep)
		ঘূৰাই (রিক্ত);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	যদি ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		ঘূৰাই (রিক্ত);
	}
	strlcpy(dst, tmp, size);
	ঘূৰাই (dst);
}

#endif /* !HAVE_INET_NTOP */
