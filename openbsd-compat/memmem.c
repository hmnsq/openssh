/*	$OpenBSD: memmem.c,v 1.5 2020/04/16 12:39:28 claudio Exp $ */

/*
 * Copyright (c) 2005-2020 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/string/memmem.c */

#شامل "includes.h"

#ifndef HAVE_MEMMEM

#شامل <string.h>
#شامل <stdint.h>

ایستا نویسه *
twobyte_memmem(ثابت unsigned نویسه *h, size_t k, ثابت unsigned نویسه *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	برای (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		اگر (hw == nw) بازگشت (نویسه *)h-2;
	بازگشت hw == nw ? (نویسه *)h-2 : 0;
}

ایستا نویسه *
threebyte_memmem(ثابت unsigned نویسه *h, size_t k, ثابت unsigned نویسه *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	برای (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		اگر (hw == nw) بازگشت (نویسه *)h-3;
	بازگشت hw == nw ? (نویسه *)h-3 : 0;
}

ایستا نویسه *
fourbyte_memmem(ثابت unsigned نویسه *h, size_t k, ثابت unsigned نویسه *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	برای (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		اگر (hw == nw) بازگشت (نویسه *)h-4;
	بازگشت hw == nw ? (نویسه *)h-4 : 0;
}

#اگر 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*اندازه *(a))] op (size_t)1<<((size_t)(b)%(8*اندازه *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ایستا نویسه *
twoway_memmem(ثابت unsigned نویسه *h, ثابت unsigned نویسه *z,
    ثابت unsigned نویسه *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / اندازه(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	برای (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	وقتی (jp+k<l) {
		اگر (n[ip+k] == n[jp+k]) {
			اگر (k == p) {
				jp += p;
				k = 1;
			} وگرنه k++;
		} وگرنه اگر (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} وگرنه {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	وقتی (jp+k<l) {
		اگر (n[ip+k] == n[jp+k]) {
			اگر (k == p) {
				jp += p;
				k = 1;
			} وگرنه k++;
		} وگرنه اگر (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} وگرنه {
			ip = jp++;
			k = p = 1;
		}
	}
	اگر (ip+1 > ms+1) ms = ip;
	وگرنه p = p0;

	/* Periodic needle? */
	اگر (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} وگرنه mem0 = l-p;
	mem = 0;

	/* Search loop */
	برای (;;) {
		/* If remainder of haystack is shorter than needle, done */
		اگر (z-h < l) بازگشت 0;

		/* Check last byte first; advance by shift on mismatch */
		اگر (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			اگر (k) {
				اگر (k < mem) k = mem;
				h += k;
				mem = 0;
				ادامه;
			}
		} وگرنه {
			h += l;
			mem = 0;
			ادامه;
		}

		/* Compare right half */
		برای (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		اگر (k < l) {
			h += k-ms;
			mem = 0;
			ادامه;
		}
		/* Compare left half */
		برای (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		اگر (k <= mem) بازگشت (نویسه *)h;
		h += p;
		mem = mem0;
	}
}

تهی *
memmem(ثابت تهی *h0, size_t k, ثابت تهی *n0, size_t l)
{
	ثابت unsigned نویسه *h = h0, *n = n0;

	/* Return immediately on empty needle */
	اگر (!l) بازگشت (تهی *)h;

	/* Return immediately when needle is longer than haystack */
	اگر (k<l) بازگشت 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	اگر (!h || l==1) بازگشت (تهی *)h;
	k -= h - (ثابت unsigned نویسه *)h0;
	اگر (k<l) بازگشت 0;
	اگر (l==2) بازگشت twobyte_memmem(h, k, n);
	اگر (l==3) بازگشت threebyte_memmem(h, k, n);
	اگر (l==4) بازگشت fourbyte_memmem(h, k, n);

	بازگشت twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
