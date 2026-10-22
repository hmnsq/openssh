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

#অন্তর্ভাব "includes.h"

#ifndef HAVE_MEMMEM

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdint.h>

স্থির বর্ণ *
twobyte_memmem(ধ্রুব unsigned বর্ণ *h, size_t k, ধ্রুব unsigned বর্ণ *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	প্রতি (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		যদি (hw == nw) প্রত্যাগম (বর্ণ *)h-2;
	প্রত্যাগম hw == nw ? (বর্ণ *)h-2 : 0;
}

স্থির বর্ণ *
threebyte_memmem(ধ্রুব unsigned বর্ণ *h, size_t k, ধ্রুব unsigned বর্ণ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	প্রতি (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		যদি (hw == nw) প্রত্যাগম (বর্ণ *)h-3;
	প্রত্যাগম hw == nw ? (বর্ণ *)h-3 : 0;
}

স্থির বর্ণ *
fourbyte_memmem(ধ্রুব unsigned বর্ণ *h, size_t k, ধ্রুব unsigned বর্ণ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	প্রতি (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		যদি (hw == nw) প্রত্যাগম (বর্ণ *)h-4;
	প্রত্যাগম hw == nw ? (বর্ণ *)h-4 : 0;
}

#যদি 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*পরিমাণ *(a))] op (size_t)1<<((size_t)(b)%(8*পরিমাণ *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
স্থির বর্ণ *
twoway_memmem(ধ্রুব unsigned বর্ণ *h, ধ্রুব unsigned বর্ণ *z,
    ধ্রুব unsigned বর্ণ *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / পরিমাণ(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	প্রতি (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	যাবত্ (jp+k<l) {
		যদি (n[ip+k] == n[jp+k]) {
			যদি (k == p) {
				jp += p;
				k = 1;
			} অন্যথা k++;
		} অন্যথা যদি (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} অন্যথা {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	যাবত্ (jp+k<l) {
		যদি (n[ip+k] == n[jp+k]) {
			যদি (k == p) {
				jp += p;
				k = 1;
			} অন্যথা k++;
		} অন্যথা যদি (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} অন্যথা {
			ip = jp++;
			k = p = 1;
		}
	}
	যদি (ip+1 > ms+1) ms = ip;
	অন্যথা p = p0;

	/* Periodic needle? */
	যদি (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} অন্যথা mem0 = l-p;
	mem = 0;

	/* Search loop */
	প্রতি (;;) {
		/* If remainder of haystack is shorter than needle, done */
		যদি (z-h < l) প্রত্যাগম 0;

		/* Check last byte first; advance by shift on mismatch */
		যদি (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			যদি (k) {
				যদি (k < mem) k = mem;
				h += k;
				mem = 0;
				অনুবর্ত;
			}
		} অন্যথা {
			h += l;
			mem = 0;
			অনুবর্ত;
		}

		/* Compare right half */
		প্রতি (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		যদি (k < l) {
			h += k-ms;
			mem = 0;
			অনুবর্ত;
		}
		/* Compare left half */
		প্রতি (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		যদি (k <= mem) প্রত্যাগম (বর্ণ *)h;
		h += p;
		mem = mem0;
	}
}

শূন্য *
memmem(ধ্রুব শূন্য *h0, size_t k, ধ্রুব শূন্য *n0, size_t l)
{
	ধ্রুব unsigned বর্ণ *h = h0, *n = n0;

	/* Return immediately on empty needle */
	যদি (!l) প্রত্যাগম (শূন্য *)h;

	/* Return immediately when needle is longer than haystack */
	যদি (k<l) প্রত্যাগম 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	যদি (!h || l==1) প্রত্যাগম (শূন্য *)h;
	k -= h - (ধ্রুব unsigned বর্ণ *)h0;
	যদি (k<l) প্রত্যাগম 0;
	যদি (l==2) প্রত্যাগম twobyte_memmem(h, k, n);
	যদি (l==3) প্রত্যাগম threebyte_memmem(h, k, n);
	যদি (l==4) প্রত্যাগম fourbyte_memmem(h, k, n);

	প্রত্যাগম twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
