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

#ضمن "includes.h"

#ifndef HAVE_MEMMEM

#ضمن <string.h>
#ضمن <stdint.h>

ساكن حرف *
twobyte_memmem(ثابت unsigned حرف *h, size_t k, ثابت unsigned حرف *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	עבור (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		אם (hw == nw) החזר (حرف *)h-2;
	החזר hw == nw ? (حرف *)h-2 : 0;
}

ساكن حرف *
threebyte_memmem(ثابت unsigned حرف *h, size_t k, ثابت unsigned حرف *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	עבור (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		אם (hw == nw) החזר (حرف *)h-3;
	החזר hw == nw ? (حرف *)h-3 : 0;
}

ساكن حرف *
fourbyte_memmem(ثابت unsigned حرف *h, size_t k, ثابت unsigned حرف *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	עבור (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		אם (hw == nw) החזר (حرف *)h-4;
	החזר hw == nw ? (حرف *)h-4 : 0;
}

#אם 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*حجم *(a))] op (size_t)1<<((size_t)(b)%(8*حجم *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ساكن حرف *
twoway_memmem(ثابت unsigned حرف *h, ثابت unsigned حرف *z,
    ثابت unsigned حرف *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / حجم(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	עבור (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	כלעוד (jp+k<l) {
		אם (n[ip+k] == n[jp+k]) {
			אם (k == p) {
				jp += p;
				k = 1;
			} אחרת k++;
		} אחרת אם (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} אחרת {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	כלעוד (jp+k<l) {
		אם (n[ip+k] == n[jp+k]) {
			אם (k == p) {
				jp += p;
				k = 1;
			} אחרת k++;
		} אחרת אם (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} אחרת {
			ip = jp++;
			k = p = 1;
		}
	}
	אם (ip+1 > ms+1) ms = ip;
	אחרת p = p0;

	/* Periodic needle? */
	אם (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} אחרת mem0 = l-p;
	mem = 0;

	/* Search loop */
	עבור (;;) {
		/* If remainder of haystack is shorter than needle, done */
		אם (z-h < l) החזר 0;

		/* Check last byte first; advance by shift on mismatch */
		אם (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			אם (k) {
				אם (k < mem) k = mem;
				h += k;
				mem = 0;
				استمر;
			}
		} אחרת {
			h += l;
			mem = 0;
			استمر;
		}

		/* Compare right half */
		עבור (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		אם (k < l) {
			h += k-ms;
			mem = 0;
			استمر;
		}
		/* Compare left half */
		עבור (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		אם (k <= mem) החזר (حرف *)h;
		h += p;
		mem = mem0;
	}
}

فراغ *
memmem(ثابت فراغ *h0, size_t k, ثابت فراغ *n0, size_t l)
{
	ثابت unsigned حرف *h = h0, *n = n0;

	/* Return immediately on empty needle */
	אם (!l) החזר (فراغ *)h;

	/* Return immediately when needle is longer than haystack */
	אם (k<l) החזר 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	אם (!h || l==1) החזר (فراغ *)h;
	k -= h - (ثابت unsigned حرف *)h0;
	אם (k<l) החזר 0;
	אם (l==2) החזר twobyte_memmem(h, k, n);
	אם (l==3) החזר threebyte_memmem(h, k, n);
	אם (l==4) החזר fourbyte_memmem(h, k, n);

	החזר twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
