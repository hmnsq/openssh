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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_MEMMEM

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

ಸ್ಥಿರ ವರ್ಣ *
twobyte_memmem(ಧ್ರುವ unsigned ವರ್ಣ *h, size_t k, ಧ್ರುವ unsigned ವರ್ಣ *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	ಪ್ರತಿ (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		ಯದಿ (hw == nw) ಪ್ರತ್ಯಾಗಮ (ವರ್ಣ *)h-2;
	ಪ್ರತ್ಯಾಗಮ hw == nw ? (ವರ್ಣ *)h-2 : 0;
}

ಸ್ಥಿರ ವರ್ಣ *
threebyte_memmem(ಧ್ರುವ unsigned ವರ್ಣ *h, size_t k, ಧ್ರುವ unsigned ವರ್ಣ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	ಪ್ರತಿ (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		ಯದಿ (hw == nw) ಪ್ರತ್ಯಾಗಮ (ವರ್ಣ *)h-3;
	ಪ್ರತ್ಯಾಗಮ hw == nw ? (ವರ್ಣ *)h-3 : 0;
}

ಸ್ಥಿರ ವರ್ಣ *
fourbyte_memmem(ಧ್ರುವ unsigned ವರ್ಣ *h, size_t k, ಧ್ರುವ unsigned ವರ್ಣ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	ಪ್ರತಿ (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		ಯದಿ (hw == nw) ಪ್ರತ್ಯಾಗಮ (ವರ್ಣ *)h-4;
	ಪ್ರತ್ಯಾಗಮ hw == nw ? (ವರ್ಣ *)h-4 : 0;
}

#ಯದಿ 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*ಪರಿಮಾಣ *(a))] op (size_t)1<<((size_t)(b)%(8*ಪರಿಮಾಣ *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ಸ್ಥಿರ ವರ್ಣ *
twoway_memmem(ಧ್ರುವ unsigned ವರ್ಣ *h, ಧ್ರುವ unsigned ವರ್ಣ *z,
    ಧ್ರುವ unsigned ವರ್ಣ *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / ಪರಿಮಾಣ(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	ಪ್ರತಿ (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	ಯಾವತ್ (jp+k<l) {
		ಯದಿ (n[ip+k] == n[jp+k]) {
			ಯದಿ (k == p) {
				jp += p;
				k = 1;
			} ಅನ್ಯಥಾ k++;
		} ಅನ್ಯಥಾ ಯದಿ (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ಅನ್ಯಥಾ {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	ಯಾವತ್ (jp+k<l) {
		ಯದಿ (n[ip+k] == n[jp+k]) {
			ಯದಿ (k == p) {
				jp += p;
				k = 1;
			} ಅನ್ಯಥಾ k++;
		} ಅನ್ಯಥಾ ಯದಿ (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ಅನ್ಯಥಾ {
			ip = jp++;
			k = p = 1;
		}
	}
	ಯದಿ (ip+1 > ms+1) ms = ip;
	ಅನ್ಯಥಾ p = p0;

	/* Periodic needle? */
	ಯದಿ (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} ಅನ್ಯಥಾ mem0 = l-p;
	mem = 0;

	/* Search loop */
	ಪ್ರತಿ (;;) {
		/* If remainder of haystack is shorter than needle, done */
		ಯದಿ (z-h < l) ಪ್ರತ್ಯಾಗಮ 0;

		/* Check last byte first; advance by shift on mismatch */
		ಯದಿ (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			ಯದಿ (k) {
				ಯದಿ (k < mem) k = mem;
				h += k;
				mem = 0;
				ಅನುವರ್ತ;
			}
		} ಅನ್ಯಥಾ {
			h += l;
			mem = 0;
			ಅನುವರ್ತ;
		}

		/* Compare right half */
		ಪ್ರತಿ (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		ಯದಿ (k < l) {
			h += k-ms;
			mem = 0;
			ಅನುವರ್ತ;
		}
		/* Compare left half */
		ಪ್ರತಿ (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		ಯದಿ (k <= mem) ಪ್ರತ್ಯಾಗಮ (ವರ್ಣ *)h;
		h += p;
		mem = mem0;
	}
}

ಶೂನ್ಯ *
memmem(ಧ್ರುವ ಶೂನ್ಯ *h0, size_t k, ಧ್ರುವ ಶೂನ್ಯ *n0, size_t l)
{
	ಧ್ರುವ unsigned ವರ್ಣ *h = h0, *n = n0;

	/* Return immediately on empty needle */
	ಯದಿ (!l) ಪ್ರತ್ಯಾಗಮ (ಶೂನ್ಯ *)h;

	/* Return immediately when needle is longer than haystack */
	ಯದಿ (k<l) ಪ್ರತ್ಯಾಗಮ 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	ಯದಿ (!h || l==1) ಪ್ರತ್ಯಾಗಮ (ಶೂನ್ಯ *)h;
	k -= h - (ಧ್ರುವ unsigned ವರ್ಣ *)h0;
	ಯದಿ (k<l) ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (l==2) ಪ್ರತ್ಯಾಗಮ twobyte_memmem(h, k, n);
	ಯದಿ (l==3) ಪ್ರತ್ಯಾಗಮ threebyte_memmem(h, k, n);
	ಯದಿ (l==4) ಪ್ರತ್ಯಾಗಮ fourbyte_memmem(h, k, n);

	ಪ್ರತ್ಯಾಗಮ twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
