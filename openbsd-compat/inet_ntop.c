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

#شامل "includes.h"

#ifndef HAVE_INET_NTOP

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <netinet/in.h>
#شامل <arpa/inet.h>
#شامل <arpa/nameser.h>
#شامل <string.h>
#شامل <errno.h>
#شامل <stdio.h>

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

ایستا ثابت نویسه *inet_ntop4(ثابت u_char *src, نویسه *dst, size_t size);
ایستا ثابت نویسه *inet_ntop6(ثابت u_char *src, نویسه *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ثابت نویسه *
inet_ntop(صحیح af, ثابت تهی *src, نویسه *dst, socklen_t size)
{
	انتخاب (af) {
	حالت AF_INET:
		بازگشت (inet_ntop4(src, dst, (size_t)size));
	حالت AF_INET6:
		بازگشت (inet_ntop6(src, dst, (size_t)size));
	پیشفرض:
		errno = EAFNOSUPPORT;
		بازگشت (پوچ);
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
ایستا ثابت نویسه *
inet_ntop4(ثابت u_char *src, نویسه *dst, size_t size)
{
	ایستا ثابت نویسه fmt[] = "%u.%u.%u.%u";
	نویسه tmp[اندازه "255.255.255.255"];
	صحیح l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	اگر (l <= 0 || l >= size) {
		errno = ENOSPC;
		بازگشت (پوچ);
	}
	strlcpy(dst, tmp, size);
	بازگشت (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
ایستا ثابت نویسه *
inet_ntop6(ثابت u_char *src, نویسه *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	نویسه tmp[اندازه "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	نویسه *tp, *ep;
	ساختار { صحیح base, len; } best, cur;
	u_int واژگان[IN6ADDRSZ / INT16SZ];
	صحیح i;
	صحیح advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(واژگان, '\0', اندازه واژگان);
	برای (i = 0; i < IN6ADDRSZ; i++)
		واژگان[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	برای (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		اگر (واژگان[i] == 0) {
			اگر (cur.base == -1)
				cur.base = i, cur.len = 1;
			وگرنه
				cur.len++;
		} وگرنه {
			اگر (cur.base != -1) {
				اگر (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	اگر (cur.base != -1) {
		اگر (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	اگر (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + اندازه(tmp);
	برای (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		اگر (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			اگر (i == best.base) {
				اگر (tp + 1 >= ep)
					بازگشت (پوچ);
				*tp++ = ':';
			}
			ادامه;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		اگر (i != 0) {
			اگر (tp + 1 >= ep)
				بازگشت (پوچ);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		اگر (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && واژگان[5] == 0xffff))) {
			اگر (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				بازگشت (پوچ);
			tp += strlen(tp);
			بشکن;
		}
		advance = snprintf(tp, ep - tp, "%x", واژگان[i]);
		اگر (advance <= 0 || advance >= ep - tp)
			بازگشت (پوچ);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	اگر (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		اگر (tp + 1 >= ep)
			بازگشت (پوچ);
		*tp++ = ':';
	}
	اگر (tp + 1 >= ep)
		بازگشت (پوچ);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	اگر ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		بازگشت (پوچ);
	}
	strlcpy(dst, tmp, size);
	بازگشت (dst);
}

#endif /* !HAVE_INET_NTOP */
