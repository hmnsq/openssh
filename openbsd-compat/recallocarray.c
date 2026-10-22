/*	$OpenBSD: recallocarray.c,v 1.1 2017/03/06 18:44:21 otto Exp $	*/
/*
 * Copyright (c) 2008, 2017 Otto Moerbeek <otto@drijf.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/stdlib/recallocarray.c */

#अन्तर्भाव "includes.h"
#यदि_अपरिभाषितम् HAVE_RECALLOCARRAY

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#परिभाषय MUL_NO_अतिप्रवाहः ((आकार_t)1 << (परिमाण(आकार_t) * 4))

शून्य *
recallocarray(शून्य *ptr, आकार_t oldnmemb, आकार_t newnmemb, आकार_t आकार)
{
	आकार_t oldsize, newsize;
	शून्य *newptr;

	यदि (ptr == रिक्त)
		प्रत्यागम शून्यस्मृतिं_देहि(newnmemb, आकार);

	यदि ((newnmemb >= MUL_NO_अतिप्रवाहः || आकार >= MUL_NO_अतिप्रवाहः) &&
	    newnmemb > 0 && SIZE_MAX / newnmemb < आकार) {
		errno = ENOMEM;
		प्रत्यागम रिक्त;
	}
	newsize = newnmemb * आकार;

	यदि ((oldnmemb >= MUL_NO_अतिप्रवाहः || आकार >= MUL_NO_अतिप्रवाहः) &&
	    oldnmemb > 0 && SIZE_MAX / oldnmemb < आकार) {
		errno = EINVAL;
		प्रत्यागम रिक्त;
	}
	oldsize = oldnmemb * आकार;
	
	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	यदि (newsize <= oldsize) {
		आकार_t d = oldsize - newsize;

		यदि (d < oldsize / 2 && d < (आकार_t)getpagesize()) {
			स्मृतिं_पूरय((वर्ण *)ptr + newsize, 0, d);
			प्रत्यागम ptr;
		}
	}

	newptr = स्मृतिं_देहि(newsize);
	यदि (newptr == रिक्त)
		प्रत्यागम रिक्त;

	यदि (newsize > oldsize) {
		स्मृतिं_प्रतिलिख(newptr, ptr, oldsize);
		स्मृतिं_पूरय((वर्ण *)newptr + oldsize, 0, newsize - oldsize);
	} अन्यथा
		स्मृतिं_प्रतिलिख(newptr, ptr, newsize);

	explicit_bzero(ptr, oldsize);
	मुक्त(ptr);

	प्रत्यागम newptr;
}
/* DEF_WEAK(recallocarray); */

#यदि_अन्तः /* HAVE_RECALLOCARRAY */
