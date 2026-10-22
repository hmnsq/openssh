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

#اگر_غیر_تعریف_شدہ HAVE_MEMMEM

#شامل <string.h>
#شامل <stdint.h>

ساکن حرف *
twobyte_memmem(ثابت غیرعلامتی حرف *h, سائز_t k, ثابت غیرعلامتی حرف *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	برائے (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		اگر (hw == nw) واپس (حرف *)h-2;
	واپس hw == nw ? (حرف *)h-2 : 0;
}

ساکن حرف *
threebyte_memmem(ثابت غیرعلامتی حرف *h, سائز_t k, ثابت غیرعلامتی حرف *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	برائے (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		اگر (hw == nw) واپس (حرف *)h-3;
	واپس hw == nw ? (حرف *)h-3 : 0;
}

ساکن حرف *
fourbyte_memmem(ثابت غیرعلامتی حرف *h, سائز_t k, ثابت غیرعلامتی حرف *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	برائے (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		اگر (hw == nw) واپس (حرف *)h-4;
	واپس hw == nw ? (حرف *)h-4 : 0;
}

#اگر 0
/* In -portable, defines.h ensures that these are already defined. */
#تعریف_کرو MAX(a,b) ((a)>(b)?(a):(b))
#تعریف_کرو MIN(a,b) ((a)<(b)?(a):(b))
#اگر_ختم

#تعریف_کرو BITOP(a,b,op) \
 ((a)[(سائز_t)(b)/(8*حجم *(a))] op (سائز_t)1<<((سائز_t)(b)%(8*حجم *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ساکن حرف *
twoway_memmem(ثابت غیرعلامتی حرف *h, ثابت غیرعلامتی حرف *z,
    ثابت غیرعلامتی حرف *n, سائز_t l)
{
	سائز_t i, ip, jp, k, p, ms, p0, mem, mem0;
	سائز_t byteset[32 / حجم(سائز_t)] = { 0 };
	سائز_t سرکاؤ[256];

	/* Computing length of needle and fill shift table */
	برائے (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), سرکاؤ[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	جب (jp+k<l) {
		اگر (n[ip+k] == n[jp+k]) {
			اگر (k == p) {
				jp += p;
				k = 1;
			} ورنہ k++;
		} ورنہ اگر (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ورنہ {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	جب (jp+k<l) {
		اگر (n[ip+k] == n[jp+k]) {
			اگر (k == p) {
				jp += p;
				k = 1;
			} ورنہ k++;
		} ورنہ اگر (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ورنہ {
			ip = jp++;
			k = p = 1;
		}
	}
	اگر (ip+1 > ms+1) ms = ip;
	ورنہ p = p0;

	/* Periodic needle? */
	اگر (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} ورنہ mem0 = l-p;
	mem = 0;

	/* Search loop */
	برائے (;;) {
		/* If remainder of haystack is shorter than needle, done */
		اگر (z-h < l) واپس 0;

		/* Check last byte first; advance by shift on mismatch */
		اگر (BITOP(byteset, h[l-1], &)) {
			k = l-سرکاؤ[h[l-1]];
			اگر (k) {
				اگر (k < mem) k = mem;
				h += k;
				mem = 0;
				جاری;
			}
		} ورنہ {
			h += l;
			mem = 0;
			جاری;
		}

		/* Compare right half */
		برائے (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		اگر (k < l) {
			h += k-ms;
			mem = 0;
			جاری;
		}
		/* Compare left half */
		برائے (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		اگر (k <= mem) واپس (حرف *)h;
		h += p;
		mem = mem0;
	}
}

خالی *
memmem(ثابت خالی *h0, سائز_t k, ثابت خالی *n0, سائز_t l)
{
	ثابت غیرعلامتی حرف *h = h0, *n = n0;

	/* Return immediately on empty needle */
	اگر (!l) واپس (خالی *)h;

	/* Return immediately when needle is longer than haystack */
	اگر (k<l) واپس 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	اگر (!h || l==1) واپس (خالی *)h;
	k -= h - (ثابت غیرعلامتی حرف *)h0;
	اگر (k<l) واپس 0;
	اگر (l==2) واپس twobyte_memmem(h, k, n);
	اگر (l==3) واپس threebyte_memmem(h, k, n);
	اگر (l==4) واپس fourbyte_memmem(h, k, n);

	واپس twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#اگر_ختم /* HAVE_MEMMEM */
