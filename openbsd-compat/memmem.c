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

#अन्तर्भाव "includes.h"

#ifndef HAVE_MEMMEM

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdint.h>

स्थिर वर्ण *
twobyte_memmem(ध्रुव unsigned वर्ण *h, size_t k, ध्रुव unsigned वर्ण *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	अत्थाय (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		सचे (hw == nw) पटिनिवत्त (वर्ण *)h-2;
	पटिनिवत्त hw == nw ? (वर्ण *)h-2 : 0;
}

स्थिर वर्ण *
threebyte_memmem(ध्रुव unsigned वर्ण *h, size_t k, ध्रुव unsigned वर्ण *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	अत्थाय (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		सचे (hw == nw) पटिनिवत्त (वर्ण *)h-3;
	पटिनिवत्त hw == nw ? (वर्ण *)h-3 : 0;
}

स्थिर वर्ण *
fourbyte_memmem(ध्रुव unsigned वर्ण *h, size_t k, ध्रुव unsigned वर्ण *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	अत्थाय (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		सचे (hw == nw) पटिनिवत्त (वर्ण *)h-4;
	पटिनिवत्त hw == nw ? (वर्ण *)h-4 : 0;
}

#सचे 0
/* In -portable, defines.h ensures that these are already defined. */
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*परिमाण *(a))] op (size_t)1<<((size_t)(b)%(8*परिमाण *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
स्थिर वर्ण *
twoway_memmem(ध्रुव unsigned वर्ण *h, ध्रुव unsigned वर्ण *z,
    ध्रुव unsigned वर्ण *n, size_t l)
{
	size_t i, ip, jp, k, p, ms, p0, mem, mem0;
	size_t byteset[32 / परिमाण(size_t)] = { 0 };
	size_t shift[256];

	/* Computing length of needle and fill shift table */
	अत्थाय (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	याव (jp+k<l) {
		सचे (n[ip+k] == n[jp+k]) {
			सचे (k == p) {
				jp += p;
				k = 1;
			} अञ्ञथा k++;
		} अञ्ञथा सचे (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} अञ्ञथा {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	याव (jp+k<l) {
		सचे (n[ip+k] == n[jp+k]) {
			सचे (k == p) {
				jp += p;
				k = 1;
			} अञ्ञथा k++;
		} अञ्ञथा सचे (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} अञ्ञथा {
			ip = jp++;
			k = p = 1;
		}
	}
	सचे (ip+1 > ms+1) ms = ip;
	अञ्ञथा p = p0;

	/* Periodic needle? */
	सचे (memcmp(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} अञ्ञथा mem0 = l-p;
	mem = 0;

	/* Search loop */
	अत्थाय (;;) {
		/* If remainder of haystack is shorter than needle, done */
		सचे (z-h < l) पटिनिवत्त 0;

		/* Check last byte first; advance by shift on mismatch */
		सचे (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			सचे (k) {
				सचे (k < mem) k = mem;
				h += k;
				mem = 0;
				अनुवर्त;
			}
		} अञ्ञथा {
			h += l;
			mem = 0;
			अनुवर्त;
		}

		/* Compare right half */
		अत्थाय (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		सचे (k < l) {
			h += k-ms;
			mem = 0;
			अनुवर्त;
		}
		/* Compare left half */
		अत्थाय (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		सचे (k <= mem) पटिनिवत्त (वर्ण *)h;
		h += p;
		mem = mem0;
	}
}

शून्य *
memmem(ध्रुव शून्य *h0, size_t k, ध्रुव शून्य *n0, size_t l)
{
	ध्रुव unsigned वर्ण *h = h0, *n = n0;

	/* Return immediately on empty needle */
	सचे (!l) पटिनिवत्त (शून्य *)h;

	/* Return immediately when needle is longer than haystack */
	सचे (k<l) पटिनिवत्त 0;

	/* Use faster algorithms for short needles */
	h = memchr(h0, *n, k);
	सचे (!h || l==1) पटिनिवत्त (शून्य *)h;
	k -= h - (ध्रुव unsigned वर्ण *)h0;
	सचे (k<l) पटिनिवत्त 0;
	सचे (l==2) पटिनिवत्त twobyte_memmem(h, k, n);
	सचे (l==3) पटिनिवत्त threebyte_memmem(h, k, n);
	सचे (l==4) पटिनिवत्त fourbyte_memmem(h, k, n);

	पटिनिवत्त twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#endif /* HAVE_MEMMEM */
