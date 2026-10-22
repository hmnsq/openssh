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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_MEMMEM

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>

ਸਥਿਰ ਅੱਖਰ *
twobyte_memmem(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *h, ਮਾਪ_t k, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	ਲਈ (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		ਜੇ (hw == nw) ਵਾਪਸ (ਅੱਖਰ *)h-2;
	ਵਾਪਸ hw == nw ? (ਅੱਖਰ *)h-2 : 0;
}

ਸਥਿਰ ਅੱਖਰ *
threebyte_memmem(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *h, ਮਾਪ_t k, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	ਲਈ (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		ਜੇ (hw == nw) ਵਾਪਸ (ਅੱਖਰ *)h-3;
	ਵਾਪਸ hw == nw ? (ਅੱਖਰ *)h-3 : 0;
}

ਸਥਿਰ ਅੱਖਰ *
fourbyte_memmem(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *h, ਮਾਪ_t k, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	ਲਈ (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		ਜੇ (hw == nw) ਵਾਪਸ (ਅੱਖਰ *)h-4;
	ਵਾਪਸ hw == nw ? (ਅੱਖਰ *)h-4 : 0;
}

#ਜੇ 0
/* In -portable, defines.h ensures that these are already defined. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX(a,b) ((a)>(b)?(a):(b))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MIN(a,b) ((a)<(b)?(a):(b))
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BITOP(a,b,op) \
 ((a)[(ਮਾਪ_t)(b)/(8*ਆਕਾਰ *(a))] op (ਮਾਪ_t)1<<((ਮਾਪ_t)(b)%(8*ਆਕਾਰ *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
ਸਥਿਰ ਅੱਖਰ *
twoway_memmem(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *h, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *z,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *n, ਮਾਪ_t l)
{
	ਮਾਪ_t i, ip, jp, k, p, ms, p0, mem, mem0;
	ਮਾਪ_t byteset[32 / ਆਕਾਰ(ਮਾਪ_t)] = { 0 };
	ਮਾਪ_t ਖਿਸਕਾਓ[256];

	/* Computing length of needle and fill shift table */
	ਲਈ (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), ਖਿਸਕਾਓ[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	ਜਦੋਂ (jp+k<l) {
		ਜੇ (n[ip+k] == n[jp+k]) {
			ਜੇ (k == p) {
				jp += p;
				k = 1;
			} ਨਹੀਂਤਾਂ k++;
		} ਨਹੀਂਤਾਂ ਜੇ (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ਨਹੀਂਤਾਂ {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	ਜਦੋਂ (jp+k<l) {
		ਜੇ (n[ip+k] == n[jp+k]) {
			ਜੇ (k == p) {
				jp += p;
				k = 1;
			} ਨਹੀਂਤਾਂ k++;
		} ਨਹੀਂਤਾਂ ਜੇ (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} ਨਹੀਂਤਾਂ {
			ip = jp++;
			k = p = 1;
		}
	}
	ਜੇ (ip+1 > ms+1) ms = ip;
	ਨਹੀਂਤਾਂ p = p0;

	/* Periodic needle? */
	ਜੇ (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} ਨਹੀਂਤਾਂ mem0 = l-p;
	mem = 0;

	/* Search loop */
	ਲਈ (;;) {
		/* If remainder of haystack is shorter than needle, done */
		ਜੇ (z-h < l) ਵਾਪਸ 0;

		/* Check last byte first; advance by shift on mismatch */
		ਜੇ (BITOP(byteset, h[l-1], &)) {
			k = l-ਖਿਸਕਾਓ[h[l-1]];
			ਜੇ (k) {
				ਜੇ (k < mem) k = mem;
				h += k;
				mem = 0;
				ਜਾਰੀ;
			}
		} ਨਹੀਂਤਾਂ {
			h += l;
			mem = 0;
			ਜਾਰੀ;
		}

		/* Compare right half */
		ਲਈ (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		ਜੇ (k < l) {
			h += k-ms;
			mem = 0;
			ਜਾਰੀ;
		}
		/* Compare left half */
		ਲਈ (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		ਜੇ (k <= mem) ਵਾਪਸ (ਅੱਖਰ *)h;
		h += p;
		mem = mem0;
	}
}

ਖਾਲੀ *
memmem(ਅਚਲ ਖਾਲੀ *h0, ਮਾਪ_t k, ਅਚਲ ਖਾਲੀ *n0, ਮਾਪ_t l)
{
	ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *h = h0, *n = n0;

	/* Return immediately on empty needle */
	ਜੇ (!l) ਵਾਪਸ (ਖਾਲੀ *)h;

	/* Return immediately when needle is longer than haystack */
	ਜੇ (k<l) ਵਾਪਸ 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	ਜੇ (!h || l==1) ਵਾਪਸ (ਖਾਲੀ *)h;
	k -= h - (ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *)h0;
	ਜੇ (k<l) ਵਾਪਸ 0;
	ਜੇ (l==2) ਵਾਪਸ twobyte_memmem(h, k, n);
	ਜੇ (l==3) ਵਾਪਸ threebyte_memmem(h, k, n);
	ਜੇ (l==4) ਵਾਪਸ fourbyte_memmem(h, k, n);

	ਵਾਪਸ twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#ਜੇ_ਅੰਤ /* HAVE_MEMMEM */
