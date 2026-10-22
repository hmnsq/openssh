/*	$OpenBSD: arc4random_uniform.c,v 1.3 2019/01/20 02:59:07 bcook Exp $	*/

/*
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
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

/* OPENBSD ORIGINAL: lib/libc/crypto/arc4random_uniform.c */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>

#నిర్వచితం_కాకపోతే HAVE_ARC4_RANDOM_ఏకరీతి
/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
uint32_t
arc4random_ఏకరీతి(uint32_t పై_bound)
{
	uint32_t r, min;

	ఒకవేళ (పై_bound < 2)
		తిరిగి 0;

	/* 2**32 % x == (2**32 - x) % x */
	min = -పై_bound % పై_bound;

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	కొరకు (;;) {
		r = arc4random();
		ఒకవేళ (r >= min)
			ఆపు;
	}

	తిరిగి r % పై_bound;
}
#అయితే_ముగింపు /* !HAVE_ARC4RANDOM_UNIFORM */
