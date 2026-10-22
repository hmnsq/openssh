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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/uio.h>

#অন্তর্ভাৱ <assert.h>
#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "test_helper.h"
#অন্তর্ভাৱ "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) কৰা { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} যেতিয়ালৈ (0)
#অন্যথা
# define FUZZ_DBG(x)
#endif

/* For brevity later */
প্রকারনির্দেশ unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
স্থির ধ্রুৱ ৱর্ণ fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

সংরচনা fuzz {
	/* Fuzz method currently in use */
	পূর্ণাঙ্ক strategy;

	/* Fuzz methods remaining */
	পূর্ণাঙ্ক strategies;

	/* Original seed data blob */
	শূন্য *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

স্থির ধ্রুৱ ৱর্ণ *
fuzz_ntop(u_int n)
{
	ৱিকল্প (n) {
	পক্ষ 0:
		ঘূৰাই "NONE";
	পক্ষ FUZZ_1_BIT_FLIP:
		ঘূৰাই "FUZZ_1_BIT_FLIP";
	পক্ষ FUZZ_2_BIT_FLIP:
		ঘূৰাই "FUZZ_2_BIT_FLIP";
	পক্ষ FUZZ_1_BYTE_FLIP:
		ঘূৰাই "FUZZ_1_BYTE_FLIP";
	পক্ষ FUZZ_2_BYTE_FLIP:
		ঘূৰাই "FUZZ_2_BYTE_FLIP";
	পক্ষ FUZZ_TRUNCATE_START:
		ঘূৰাই "FUZZ_TRUNCATE_START";
	পক্ষ FUZZ_TRUNCATE_END:
		ঘূৰাই "FUZZ_TRUNCATE_END";
	পক্ষ FUZZ_BASE64:
		ঘূৰাই "FUZZ_BASE64";
	স্ৱভাৱ:
		abort();
	}
}

স্থির পূর্ণাঙ্ক
fuzz_fmt(সংরচনা fuzz *fuzz, ৱর্ণ *s, size_t n)
{
	যদি (fuzz == রিক্ত)
		ঘূৰাই -1;

	ৱিকল্প (fuzz->strategy) {
	পক্ষ FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		ঘূৰাই 0;
	পক্ষ FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		ঘূৰাই 0;
	পক্ষ FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ঘূৰাই 0;
	পক্ষ FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		ঘূৰাই 0;
	পক্ষ FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ঘূৰাই 0;
	পক্ষ FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ঘূৰাই 0;
	পক্ষ FUZZ_BASE64:
		প্রতিজ্ঞা(fuzz->o2 < পরিমাণ(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		ঘূৰাই 0;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

স্থির শূন্য
dump(u_char *p, size_t len)
{
	size_t i, j;

	বাবে (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		বাবে (j = i; j < i + 16; j++) {
			যদি (j < len)
				fprintf(stderr, "%02x ", p[j]);
			অন্যথা
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		বাবে (j = i; j < i + 16; j++) {
			যদি (j < len) {
				যদি  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				অন্যথা
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

শূন্য
fuzz_dump(সংরচনা fuzz *fuzz)
{
	ৱর্ণ buf[256];

	যদি (fuzz_fmt(fuzz, buf, পরিমাণ(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

স্থির সংরচনা fuzz *last_fuzz;

স্থির শূন্য
siginfo(পূর্ণাঙ্ক unused __attribute__((__unused__)))
{
	ৱর্ণ buf[256];

	test_info(buf, পরিমাণ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	যদি (last_fuzz != রিক্ত) {
		fuzz_fmt(last_fuzz, buf, পরিমাণ(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

সংরচনা fuzz *
fuzz_begin(u_int strategies, ধ্রুৱ শূন্য *p, size_t l)
{
	সংরচনা fuzz *ret = calloc(1, পরিমাণ(*ret));

	প্রতিজ্ঞা(p != রিক্ত);
	প্রতিজ্ঞা(ret != রিক্ত);
	ret->seed = malloc(l);
	প্রতিজ্ঞা(ret->seed != রিক্ত);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	প্রতিজ্ঞা(ret->slen < SIZE_MAX / 8);
	প্রতিজ্ঞা(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	সঙ্কেত(SIGINFO, siginfo);
#endif
	সঙ্কেত(SIGUSR1, siginfo);

	ঘূৰাই ret;
}

শূন্য
fuzz_cleanup(সংরচনা fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = রিক্ত;
#ifdef SIGINFO
	সঙ্কেত(SIGINFO, SIG_DFL);
#endif
	সঙ্কেত(SIGUSR1, SIG_DFL);
	প্রতিজ্ঞা(fuzz != রিক্ত);
	প্রতিজ্ঞা(fuzz->seed != রিক্ত);
	প্রতিজ্ঞা(fuzz->fuzzed != রিক্ত);
	মুক্ত(fuzz->seed);
	মুক্ত(fuzz->fuzzed);
	মুক্ত(fuzz);
}

স্থির পূর্ণাঙ্ক
fuzz_strategy_done(সংরচনা fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	ৱিকল্প (fuzz->strategy) {
	পক্ষ FUZZ_1_BIT_FLIP:
		ঘূৰাই fuzz->o1 >= fuzz->slen * 8;
	পক্ষ FUZZ_2_BIT_FLIP:
		ঘূৰাই fuzz->o2 >= fuzz->slen * 8;
	পক্ষ FUZZ_2_BYTE_FLIP:
		ঘূৰাই fuzz->o2 >= fuzz->slen;
	পক্ষ FUZZ_1_BYTE_FLIP:
	পক্ষ FUZZ_TRUNCATE_START:
	পক্ষ FUZZ_TRUNCATE_END:
	পক্ষ FUZZ_BASE64:
		ঘূৰাই fuzz->o1 >= fuzz->slen;
	স্ৱভাৱ:
		abort();
	}
}

শূন্য
fuzz_next(সংরচনা fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	যদি (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		যদি (fuzz->fuzzed == রিক্ত) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		বাবে (i = 1; i <= FUZZ_MAX; i <<= 1) {
			যদি ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				ভঙ্গ;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		যদি (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			ঘূৰাই;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	প্রতিজ্ঞা(fuzz->fuzzed != রিক্ত);

	ৱিকল্প (fuzz->strategy) {
	পক্ষ FUZZ_1_BIT_FLIP:
		প্রতিজ্ঞা(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		ভঙ্গ;
	পক্ষ FUZZ_2_BIT_FLIP:
		প্রতিজ্ঞা(fuzz->o1 / 8 < fuzz->slen);
		প্রতিজ্ঞা(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		যদি (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ভঙ্গ;
	পক্ষ FUZZ_1_BYTE_FLIP:
		প্রতিজ্ঞা(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		ভঙ্গ;
	পক্ষ FUZZ_2_BYTE_FLIP:
		প্রতিজ্ঞা(fuzz->o1 < fuzz->slen);
		প্রতিজ্ঞা(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		যদি (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ভঙ্গ;
	পক্ষ FUZZ_TRUNCATE_START:
	পক্ষ FUZZ_TRUNCATE_END:
		প্রতিজ্ঞা(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		ভঙ্গ;
	পক্ষ FUZZ_BASE64:
		প্রতিজ্ঞা(fuzz->o1 < fuzz->slen);
		প্রতিজ্ঞা(fuzz->o2 < পরিমাণ(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		যদি (fuzz->o2 >= পরিমাণ(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		ভঙ্গ;
	স্ৱভাৱ:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

পূর্ণাঙ্ক
fuzz_matches_original(সংরচনা fuzz *fuzz)
{
	যদি (fuzz_len(fuzz) != fuzz->slen)
		ঘূৰাই 0;
	ঘূৰাই memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

পূর্ণাঙ্ক
fuzz_done(সংরচনা fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	ঘূৰাই fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(সংরচনা fuzz *fuzz)
{
	প্রতিজ্ঞা(fuzz->fuzzed != রিক্ত);
	ৱিকল্প (fuzz->strategy) {
	পক্ষ FUZZ_1_BIT_FLIP:
	পক্ষ FUZZ_2_BIT_FLIP:
	পক্ষ FUZZ_1_BYTE_FLIP:
	পক্ষ FUZZ_2_BYTE_FLIP:
	পক্ষ FUZZ_BASE64:
		ঘূৰাই fuzz->slen;
	পক্ষ FUZZ_TRUNCATE_START:
	পক্ষ FUZZ_TRUNCATE_END:
		প্রতিজ্ঞা(fuzz->o1 <= fuzz->slen);
		ঘূৰাই fuzz->slen - fuzz->o1;
	স্ৱভাৱ:
		abort();
	}
}

u_char *
fuzz_ptr(সংরচনা fuzz *fuzz)
{
	প্রতিজ্ঞা(fuzz->fuzzed != রিক্ত);
	ৱিকল্প (fuzz->strategy) {
	পক্ষ FUZZ_1_BIT_FLIP:
	পক্ষ FUZZ_2_BIT_FLIP:
	পক্ষ FUZZ_1_BYTE_FLIP:
	পক্ষ FUZZ_2_BYTE_FLIP:
	পক্ষ FUZZ_BASE64:
		ঘূৰাই fuzz->fuzzed;
	পক্ষ FUZZ_TRUNCATE_START:
		প্রতিজ্ঞা(fuzz->o1 <= fuzz->slen);
		ঘূৰাই fuzz->fuzzed + fuzz->o1;
	পক্ষ FUZZ_TRUNCATE_END:
		প্রতিজ্ঞা(fuzz->o1 <= fuzz->slen);
		ঘূৰাই fuzz->fuzzed;
	স্ৱভাৱ:
		abort();
	}
}

