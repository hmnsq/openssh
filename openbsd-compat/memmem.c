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

#समावेश "includes.h"

#अगर_अघोषित HAVE_MEMMEM

#समावेश <string.h>
#समावेश <stdint.h>

अटल अक्षर *
twobyte_memmem(स्थिर अचिन्हित अक्षर *h, माप_प्रकार k, स्थिर अचिन्हित अक्षर *n)
{
	uint16_t nw = n[0]<<8 | n[1], hw = h[0]<<8 | h[1];
	क्रम (h+=2, k-=2; k; k--, hw = hw<<8 | *h++)
		अगर (hw == nw) वापस (अक्षर *)h-2;
	वापस hw == nw ? (अक्षर *)h-2 : 0;
}

अटल अक्षर *
threebyte_memmem(स्थिर अचिन्हित अक्षर *h, माप_प्रकार k, स्थिर अचिन्हित अक्षर *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8;
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8;
	क्रम (h+=3, k-=3; k; k--, hw = (hw|*h++)<<8)
		अगर (hw == nw) वापस (अक्षर *)h-3;
	वापस hw == nw ? (अक्षर *)h-3 : 0;
}

अटल अक्षर *
fourbyte_memmem(स्थिर अचिन्हित अक्षर *h, माप_प्रकार k, स्थिर अचिन्हित अक्षर *n)
{
	uint32_t nw = n[0]<<24 | n[1]<<16 | n[2]<<8 | n[3];
	uint32_t hw = h[0]<<24 | h[1]<<16 | h[2]<<8 | h[3];
	क्रम (h+=4, k-=4; k; k--, hw = hw<<8 | *h++)
		अगर (hw == nw) वापस (अक्षर *)h-4;
	वापस hw == nw ? (अक्षर *)h-4 : 0;
}

#अगर 0
/* In -portable, defines.h ensures that these are already defined. */
#घोषणा MAX(a,b) ((a)>(b)?(a):(b))
#घोषणा MIN(a,b) ((a)<(b)?(a):(b))
#पूर्ण_अगर

#घोषणा BITOP(a,b,op) \
 ((a)[(माप_प्रकार)(b)/(8*माप *(a))] op (माप_प्रकार)1<<((माप_प्रकार)(b)%(8*माप *(a))))

/*
 * Maxime Crochemore and Dominique Perrin, Two-way string-matching,
 * Journal of the ACM, 38(3):651-675, July 1991.
 */
अटल अक्षर *
twoway_memmem(स्थिर अचिन्हित अक्षर *h, स्थिर अचिन्हित अक्षर *z,
    स्थिर अचिन्हित अक्षर *n, माप_प्रकार l)
{
	माप_प्रकार i, ip, jp, k, p, ms, p0, mem, mem0;
	माप_प्रकार byteset[32 / माप(माप_प्रकार)] = { 0 };
	माप_प्रकार shift[256];

	/* Computing length of needle and fill shift table */
	क्रम (i=0; i<l; i++)
		BITOP(byteset, n[i], |=), shift[n[i]] = i+1;

	/* Compute maximal suffix */
	ip = -1; jp = 0; k = p = 1;
	जबतक (jp+k<l) {
		अगर (n[ip+k] == n[jp+k]) {
			अगर (k == p) {
				jp += p;
				k = 1;
			} अन्यथा k++;
		} अन्यथा अगर (n[ip+k] > n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} अन्यथा {
			ip = jp++;
			k = p = 1;
		}
	}
	ms = ip;
	p0 = p;

	/* And with the opposite comparison */
	ip = -1; jp = 0; k = p = 1;
	जबतक (jp+k<l) {
		अगर (n[ip+k] == n[jp+k]) {
			अगर (k == p) {
				jp += p;
				k = 1;
			} अन्यथा k++;
		} अन्यथा अगर (n[ip+k] < n[jp+k]) {
			jp += k;
			k = 1;
			p = jp - ip;
		} अन्यथा {
			ip = jp++;
			k = p = 1;
		}
	}
	अगर (ip+1 > ms+1) ms = ip;
	अन्यथा p = p0;

	/* Periodic needle? */
	अगर (स_भेद(n, n+p, ms+1)) {
		mem0 = 0;
		p = MAX(ms, l-ms-1) + 1;
	} अन्यथा mem0 = l-p;
	mem = 0;

	/* Search loop */
	क्रम (;;) {
		/* If remainder of haystack is shorter than needle, done */
		अगर (z-h < l) वापस 0;

		/* Check last byte first; advance by shift on mismatch */
		अगर (BITOP(byteset, h[l-1], &)) {
			k = l-shift[h[l-1]];
			अगर (k) {
				अगर (k < mem) k = mem;
				h += k;
				mem = 0;
				जारी;
			}
		} अन्यथा {
			h += l;
			mem = 0;
			जारी;
		}

		/* Compare right half */
		क्रम (k=MAX(ms+1,mem); k<l && n[k] == h[k]; k++);
		अगर (k < l) {
			h += k-ms;
			mem = 0;
			जारी;
		}
		/* Compare left half */
		क्रम (k=ms+1; k>mem && n[k-1] == h[k-1]; k--);
		अगर (k <= mem) वापस (अक्षर *)h;
		h += p;
		mem = mem0;
	}
}

व्योम *
memmem(स्थिर व्योम *h0, माप_प्रकार k, स्थिर व्योम *n0, माप_प्रकार l)
{
	स्थिर अचिन्हित अक्षर *h = h0, *n = n0;

	/* Return immediately on empty needle */
	अगर (!l) वापस (व्योम *)h;

	/* Return immediately when needle is longer than haystack */
	अगर (k<l) वापस 0;

	/* Use faster algorithms for short needles */
	h = स_प्रथम(h0, *n, k);
	अगर (!h || l==1) वापस (व्योम *)h;
	k -= h - (स्थिर अचिन्हित अक्षर *)h0;
	अगर (k<l) वापस 0;
	अगर (l==2) वापस twobyte_memmem(h, k, n);
	अगर (l==3) वापस threebyte_memmem(h, k, n);
	अगर (l==4) वापस fourbyte_memmem(h, k, n);

	वापस twoway_memmem(h, h+k, n, l);
}
DEF_WEAK(memmem);
#पूर्ण_अगर /* HAVE_MEMMEM */
