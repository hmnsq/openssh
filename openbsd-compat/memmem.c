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

#که_نه_تعریف_شوی HAVE_MEMMEM

#ضمن <string.h>
#ضمن <stdint.h>

ساكن حرف *
twobyte_memmem(ثابت بینښه حرف *h, اندازه_t k, ثابت بینښه حرف *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	لكل (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		إذا (hw == nw) أرجع (حرف *)h-2;
	أرجع hw == nw ? (حرف *)h-2 : 0;
}

ساكن حرف *
threebyte_memmem(ثابت بینښه حرف *h, اندازه_t k, ثابت بینښه حرف *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	لكل (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		إذا (hw == nw) أرجع (حرف *)h-3;
	أرجع hw == nw ? (حرف *)h-3 : 0;
}

ساكن حرف *
fourbyte_memmem(ثابت بینښه حرف *h, اندازه_t k, ثابت بینښه حرف *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	لكل (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		إذا (hw == nw) أرجع (حرف *)h-4;
	أرجع hw == nw ? (حرف *)h-4 : 0;
}

#إذا 0
/* In -portable, defines.h ensures that these are already defined. */
#تعریف_کړه MAX(a,b) ((a)>(b)?(a):(b))
#تعریف_کړه MIN(a,b) ((a)<(b)?(a):(b))
#د_که_پای

#تعریف_کړه BITOP(a,b,op) \
 ((a)[(اندازه_t)(b)/(8*حجم *(a))] op (اندازه_t)1<<((اندازه_t)(b)%(8*حجم *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ساكن حرف *
twoway_memmem(ثابت بینښه حرف *h, ثابت بینښه حرف *z,
    ثابت بینښه حرف *n, اندازه_t l)
{
	اندازه_t i, ip, jp, k, p, ms, p0, mem, mem0;
	اندازه_t byteset[32 / حجم(اندازه_t)] = { 0 };
	اندازه_t ښويدنه[256];

	/* Computing length of needle and fill shift table */
	لكل (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), ښويدنه[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	طالما (jp+k<l) {
		إذا (n[ip+k] == n[jp+k]) {
			إذا (k == p) {
				jp += p;
				k = 1;
			} وإلا k++;
		} وإلا إذا (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} وإلا {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	طالما (jp+k<l) {
		إذا (n[ip+k] == n[jp+k]) {
			إذا (k == p) {
				jp += p;
				k = 1;
			} وإلا k++;
		} وإلا إذا (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} وإلا {
			ip = jp++;
			k = p = 1;
		}
	}
	إذا (ip+1 > ms+1) ms = ip;
	وإلا p = p0;

	/* Periodic needle? */
	إذا (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} وإلا mem0 = l-p;
	mem = 0;

	/* Search loop */
	لكل (;;) {
		/* If remainder of haystack is shorter than needle, done */
		إذا (z-h < l) أرجع 0;

		/* Check last byte first; advance by shift on mismatch */
		إذا (BITOP(byteset, h[l-1], &)) {
			k = l-ښويدنه[h[l-1]];
			إذا (k) {
				إذا (k < mem) k = mem;
				h += k;
				mem = 0;
				استمر;
			}
		} وإلا {
			h += l;
			mem = 0;
			استمر;
		}

		/* Compare right half */
		لكل (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		إذا (k < l) {
			h += k-ms;
			mem = 0;
			استمر;
		}
		/* Compare left half */
		لكل (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		إذا (k <= mem) أرجع (حرف *)h;
		h += p;
		mem = mem0;
	}
}

فراغ *
memmem(ثابت فراغ *h0, اندازه_t k, ثابت فراغ *n0, اندازه_t l)
{
	ثابت بینښه حرف *h = h0, *n = n0;

	/* Return immediately on empty needle */
	إذا (!l) أرجع (فراغ *)h;

	/* Return immediately when needle is longer than haystack */
	إذا (k<l) أرجع 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	إذا (!h || l==1) أرجع (فراغ *)h;
	k -= h - (ثابت بینښه حرف *)h0;
	إذا (k<l) أرجع 0;
	إذا (l==2) أرجع twobyte_memmem(h, k, n);
	إذا (l==3) أرجع threebyte_memmem(h, k, n);
	إذا (l==4) أرجع fourbyte_memmem(h, k, n);

	أرجع twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#د_که_پای /* HAVE_MEMMEM */
