/*	$OpenBSD: fuzz.c,v 1.9 2025/06/13 07:23:07 dtucker Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller <djm@mindrot.org>
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

/* Utility functions/framework for fuzz tests */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/uio.h>

#அந்தர்பாவ <assert.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "test_helper.h"
#அந்தர்பாவ "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) செய் { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} போது (0)
#இல்லையெனில்
# define FUZZ_DBG(x)
#endif

/* For brevity later */
வகைவரை unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
நிலையான மாறிலி எழுத்து fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

கட்டமைப்பு fuzz {
	/* Fuzz method currently in use */
	முழு strategy;

	/* Fuzz methods remaining */
	முழு strategies;

	/* Original seed data blob */
	வெறுமை *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

நிலையான மாறிலி எழுத்து *
fuzz_ntop(u_int n)
{
	தேர்வு (n) {
	நிலை 0:
		திரும்பு "NONE";
	நிலை FUZZ_1_BIT_FLIP:
		திரும்பு "FUZZ_1_BIT_FLIP";
	நிலை FUZZ_2_BIT_FLIP:
		திரும்பு "FUZZ_2_BIT_FLIP";
	நிலை FUZZ_1_BYTE_FLIP:
		திரும்பு "FUZZ_1_BYTE_FLIP";
	நிலை FUZZ_2_BYTE_FLIP:
		திரும்பு "FUZZ_2_BYTE_FLIP";
	நிலை FUZZ_TRUNCATE_START:
		திரும்பு "FUZZ_TRUNCATE_START";
	நிலை FUZZ_TRUNCATE_END:
		திரும்பு "FUZZ_TRUNCATE_END";
	நிலை FUZZ_BASE64:
		திரும்பு "FUZZ_BASE64";
	இயல்பு:
		abort();
	}
}

நிலையான முழு
fuzz_fmt(கட்டமைப்பு fuzz *fuzz, எழுத்து *s, size_t n)
{
	எனில் (fuzz == வெற்று)
		திரும்பு -1;

	தேர்வு (fuzz->strategy) {
	நிலை FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		திரும்பு 0;
	நிலை FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		திரும்பு 0;
	நிலை FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		திரும்பு 0;
	நிலை FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		திரும்பு 0;
	நிலை FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		திரும்பு 0;
	நிலை FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		திரும்பு 0;
	நிலை FUZZ_BASE64:
		ப்ரதிஜ்ஞா(fuzz->o2 < அளவு(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		திரும்பு 0;
	இயல்பு:
		திரும்பு -1;
	}
}

நிலையான வெறுமை
dump(u_char *p, size_t len)
{
	size_t i, j;

	க்கு (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		க்கு (j = i; j < i + 16; j++) {
			எனில் (j < len)
				fprintf(stderr, "%02x ", p[j]);
			இல்லையெனில்
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		க்கு (j = i; j < i + 16; j++) {
			எனில் (j < len) {
				எனில்  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				இல்லையெனில்
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

வெறுமை
fuzz_dump(கட்டமைப்பு fuzz *fuzz)
{
	எழுத்து buf[256];

	எனில் (fuzz_fmt(fuzz, buf, அளவு(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

நிலையான கட்டமைப்பு fuzz *last_fuzz;

நிலையான வெறுமை
siginfo(முழு unused __attribute__((__unused__)))
{
	எழுத்து buf[256];

	test_info(buf, அளவு(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	எனில் (last_fuzz != வெற்று) {
		fuzz_fmt(last_fuzz, buf, அளவு(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

கட்டமைப்பு fuzz *
fuzz_begin(u_int strategies, மாறிலி வெறுமை *p, size_t l)
{
	கட்டமைப்பு fuzz *ret = calloc(1, அளவு(*ret));

	ப்ரதிஜ்ஞா(p != வெற்று);
	ப்ரதிஜ்ஞா(ret != வெற்று);
	ret->seed = malloc(l);
	ப்ரதிஜ்ஞா(ret->seed != வெற்று);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	ப்ரதிஜ்ஞா(ret->slen < SIZE_MAX / 8);
	ப்ரதிஜ்ஞா(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	சமிக்ஞை(SIGINFO, siginfo);
#endif
	சமிக்ஞை(SIGUSR1, siginfo);

	திரும்பு ret;
}

வெறுமை
fuzz_cleanup(கட்டமைப்பு fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = வெற்று;
#ifdef SIGINFO
	சமிக்ஞை(SIGINFO, SIG_DFL);
#endif
	சமிக்ஞை(SIGUSR1, SIG_DFL);
	ப்ரதிஜ்ஞா(fuzz != வெற்று);
	ப்ரதிஜ்ஞா(fuzz->seed != வெற்று);
	ப்ரதிஜ்ஞா(fuzz->fuzzed != வெற்று);
	விடுவி(fuzz->seed);
	விடுவி(fuzz->fuzzed);
	விடுவி(fuzz);
}

நிலையான முழு
fuzz_strategy_done(கட்டமைப்பு fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	தேர்வு (fuzz->strategy) {
	நிலை FUZZ_1_BIT_FLIP:
		திரும்பு fuzz->o1 >= fuzz->slen * 8;
	நிலை FUZZ_2_BIT_FLIP:
		திரும்பு fuzz->o2 >= fuzz->slen * 8;
	நிலை FUZZ_2_BYTE_FLIP:
		திரும்பு fuzz->o2 >= fuzz->slen;
	நிலை FUZZ_1_BYTE_FLIP:
	நிலை FUZZ_TRUNCATE_START:
	நிலை FUZZ_TRUNCATE_END:
	நிலை FUZZ_BASE64:
		திரும்பு fuzz->o1 >= fuzz->slen;
	இயல்பு:
		abort();
	}
}

வெறுமை
fuzz_next(கட்டமைப்பு fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	எனில் (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		எனில் (fuzz->fuzzed == வெற்று) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		க்கு (i = 1; i <= FUZZ_MAX; i <<= 1) {
			எனில் ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				நிறுத்து;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		எனில் (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			திரும்பு;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	ப்ரதிஜ்ஞா(fuzz->fuzzed != வெற்று);

	தேர்வு (fuzz->strategy) {
	நிலை FUZZ_1_BIT_FLIP:
		ப்ரதிஜ்ஞா(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		நிறுத்து;
	நிலை FUZZ_2_BIT_FLIP:
		ப்ரதிஜ்ஞா(fuzz->o1 / 8 < fuzz->slen);
		ப்ரதிஜ்ஞா(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		எனில் (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		நிறுத்து;
	நிலை FUZZ_1_BYTE_FLIP:
		ப்ரதிஜ்ஞா(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		நிறுத்து;
	நிலை FUZZ_2_BYTE_FLIP:
		ப்ரதிஜ்ஞா(fuzz->o1 < fuzz->slen);
		ப்ரதிஜ்ஞா(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		எனில் (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		நிறுத்து;
	நிலை FUZZ_TRUNCATE_START:
	நிலை FUZZ_TRUNCATE_END:
		ப்ரதிஜ்ஞா(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		நிறுத்து;
	நிலை FUZZ_BASE64:
		ப்ரதிஜ்ஞா(fuzz->o1 < fuzz->slen);
		ப்ரதிஜ்ஞா(fuzz->o2 < அளவு(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		எனில் (fuzz->o2 >= அளவு(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		நிறுத்து;
	இயல்பு:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

முழு
fuzz_matches_original(கட்டமைப்பு fuzz *fuzz)
{
	எனில் (fuzz_len(fuzz) != fuzz->slen)
		திரும்பு 0;
	திரும்பு memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

முழு
fuzz_done(கட்டமைப்பு fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	திரும்பு fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(கட்டமைப்பு fuzz *fuzz)
{
	ப்ரதிஜ்ஞா(fuzz->fuzzed != வெற்று);
	தேர்வு (fuzz->strategy) {
	நிலை FUZZ_1_BIT_FLIP:
	நிலை FUZZ_2_BIT_FLIP:
	நிலை FUZZ_1_BYTE_FLIP:
	நிலை FUZZ_2_BYTE_FLIP:
	நிலை FUZZ_BASE64:
		திரும்பு fuzz->slen;
	நிலை FUZZ_TRUNCATE_START:
	நிலை FUZZ_TRUNCATE_END:
		ப்ரதிஜ்ஞா(fuzz->o1 <= fuzz->slen);
		திரும்பு fuzz->slen - fuzz->o1;
	இயல்பு:
		abort();
	}
}

u_char *
fuzz_ptr(கட்டமைப்பு fuzz *fuzz)
{
	ப்ரதிஜ்ஞா(fuzz->fuzzed != வெற்று);
	தேர்வு (fuzz->strategy) {
	நிலை FUZZ_1_BIT_FLIP:
	நிலை FUZZ_2_BIT_FLIP:
	நிலை FUZZ_1_BYTE_FLIP:
	நிலை FUZZ_2_BYTE_FLIP:
	நிலை FUZZ_BASE64:
		திரும்பு fuzz->fuzzed;
	நிலை FUZZ_TRUNCATE_START:
		ப்ரதிஜ்ஞா(fuzz->o1 <= fuzz->slen);
		திரும்பு fuzz->fuzzed + fuzz->o1;
	நிலை FUZZ_TRUNCATE_END:
		ப்ரதிஜ்ஞா(fuzz->o1 <= fuzz->slen);
		திரும்பு fuzz->fuzzed;
	இயல்பு:
		abort();
	}
}

