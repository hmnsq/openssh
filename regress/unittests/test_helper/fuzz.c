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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/uio.h>

#অন্তর্ভাব <assert.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "test_helper.h"
#অন্তর্ভাব "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) করো { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} যখন (0)
#অন্যথা
# define FUZZ_DBG(x)
#endif

/* For brevity later */
প্রকারলেখ unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
স্থির ধ্রুবক অক্ষর fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

কাঠামো fuzz {
	/* Fuzz method currently in use */
	পূর্ণসংখ্যা strategy;

	/* Fuzz methods remaining */
	পূর্ণসংখ্যা strategies;

	/* Original seed data blob */
	শূন্য *seed;
	আকার_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	আকার_t o1, o2;
};

স্থির ধ্রুবক অক্ষর *
fuzz_ntop(u_int n)
{
	নির্বাচন (n) {
	ক্ষেত্র 0:
		ফেরত "NONE";
	ক্ষেত্র FUZZ_1_BIT_FLIP:
		ফেরত "FUZZ_1_BIT_FLIP";
	ক্ষেত্র FUZZ_2_BIT_FLIP:
		ফেরত "FUZZ_2_BIT_FLIP";
	ক্ষেত্র FUZZ_1_BYTE_FLIP:
		ফেরত "FUZZ_1_BYTE_FLIP";
	ক্ষেত্র FUZZ_2_BYTE_FLIP:
		ফেরত "FUZZ_2_BYTE_FLIP";
	ক্ষেত্র FUZZ_TRUNCATE_START:
		ফেরত "FUZZ_TRUNCATE_START";
	ক্ষেত্র FUZZ_TRUNCATE_END:
		ফেরত "FUZZ_TRUNCATE_END";
	ক্ষেত্র FUZZ_BASE64:
		ফেরত "FUZZ_BASE64";
	পূর্বনির্ধারিত:
		abort();
	}
}

স্থির পূর্ণসংখ্যা
fuzz_fmt(কাঠামো fuzz *fuzz, অক্ষর *s, আকার_t n)
{
	যদি (fuzz == ফাঁকা)
		ফেরত -1;

	নির্বাচন (fuzz->strategy) {
	ক্ষেত্র FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		ফেরত 0;
	ক্ষেত্র FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		ফেরত 0;
	ক্ষেত্র FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ফেরত 0;
	ক্ষেত্র FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		ফেরত 0;
	ক্ষেত্র FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ফেরত 0;
	ক্ষেত্র FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ফেরত 0;
	ক্ষেত্র FUZZ_BASE64:
		প্রতিজ্ঞা(fuzz->o2 < আকার(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		ফেরত 0;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

স্থির শূন্য
dump(u_char *p, আকার_t len)
{
	আকার_t i, j;

	জন্য (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		জন্য (j = i; j < i + 16; j++) {
			যদি (j < len)
				fprintf(stderr, "%02x ", p[j]);
			অন্যথা
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		জন্য (j = i; j < i + 16; j++) {
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
fuzz_dump(কাঠামো fuzz *fuzz)
{
	অক্ষর buf[256];

	যদি (fuzz_fmt(fuzz, buf, আকার(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

স্থির কাঠামো fuzz *last_fuzz;

স্থির শূন্য
siginfo(পূর্ণসংখ্যা unused __attribute__((__unused__)))
{
	অক্ষর buf[256];

	test_info(buf, আকার(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	যদি (last_fuzz != ফাঁকা) {
		fuzz_fmt(last_fuzz, buf, আকার(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

কাঠামো fuzz *
fuzz_begin(u_int strategies, ধ্রুবক শূন্য *p, আকার_t l)
{
	কাঠামো fuzz *ret = calloc(1, আকার(*ret));

	প্রতিজ্ঞা(p != ফাঁকা);
	প্রতিজ্ঞা(ret != ফাঁকা);
	ret->seed = malloc(l);
	প্রতিজ্ঞা(ret->seed != ফাঁকা);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	প্রতিজ্ঞা(ret->slen < SIZE_MAX / 8);
	প্রতিজ্ঞা(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_পরবর্তী(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	সংকেত(SIGINFO, siginfo);
#endif
	সংকেত(SIGUSR1, siginfo);

	ফেরত ret;
}

শূন্য
fuzz_cleanup(কাঠামো fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = ফাঁকা;
#ifdef SIGINFO
	সংকেত(SIGINFO, SIG_DFL);
#endif
	সংকেত(SIGUSR1, SIG_DFL);
	প্রতিজ্ঞা(fuzz != ফাঁকা);
	প্রতিজ্ঞা(fuzz->seed != ফাঁকা);
	প্রতিজ্ঞা(fuzz->fuzzed != ফাঁকা);
	মুক্ত(fuzz->seed);
	মুক্ত(fuzz->fuzzed);
	মুক্ত(fuzz);
}

স্থির পূর্ণসংখ্যা
fuzz_strategy_done(কাঠামো fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	নির্বাচন (fuzz->strategy) {
	ক্ষেত্র FUZZ_1_BIT_FLIP:
		ফেরত fuzz->o1 >= fuzz->slen * 8;
	ক্ষেত্র FUZZ_2_BIT_FLIP:
		ফেরত fuzz->o2 >= fuzz->slen * 8;
	ক্ষেত্র FUZZ_2_BYTE_FLIP:
		ফেরত fuzz->o2 >= fuzz->slen;
	ক্ষেত্র FUZZ_1_BYTE_FLIP:
	ক্ষেত্র FUZZ_TRUNCATE_START:
	ক্ষেত্র FUZZ_TRUNCATE_END:
	ক্ষেত্র FUZZ_BASE64:
		ফেরত fuzz->o1 >= fuzz->slen;
	পূর্বনির্ধারিত:
		abort();
	}
}

শূন্য
fuzz_পরবর্তী(কাঠামো fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	যদি (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		যদি (fuzz->fuzzed == ফাঁকা) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		জন্য (i = 1; i <= FUZZ_MAX; i <<= 1) {
			যদি ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				বিরতি;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		যদি (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			ফেরত;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	প্রতিজ্ঞা(fuzz->fuzzed != ফাঁকা);

	নির্বাচন (fuzz->strategy) {
	ক্ষেত্র FUZZ_1_BIT_FLIP:
		প্রতিজ্ঞা(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		বিরতি;
	ক্ষেত্র FUZZ_2_BIT_FLIP:
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
		বিরতি;
	ক্ষেত্র FUZZ_1_BYTE_FLIP:
		প্রতিজ্ঞা(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		বিরতি;
	ক্ষেত্র FUZZ_2_BYTE_FLIP:
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
		বিরতি;
	ক্ষেত্র FUZZ_TRUNCATE_START:
	ক্ষেত্র FUZZ_TRUNCATE_END:
		প্রতিজ্ঞা(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		বিরতি;
	ক্ষেত্র FUZZ_BASE64:
		প্রতিজ্ঞা(fuzz->o1 < fuzz->slen);
		প্রতিজ্ঞা(fuzz->o2 < আকার(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		যদি (fuzz->o2 >= আকার(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		বিরতি;
	পূর্বনির্ধারিত:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

পূর্ণসংখ্যা
fuzz_matches_original(কাঠামো fuzz *fuzz)
{
	যদি (fuzz_len(fuzz) != fuzz->slen)
		ফেরত 0;
	ফেরত memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

পূর্ণসংখ্যা
fuzz_done(কাঠামো fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	ফেরত fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

আকার_t
fuzz_len(কাঠামো fuzz *fuzz)
{
	প্রতিজ্ঞা(fuzz->fuzzed != ফাঁকা);
	নির্বাচন (fuzz->strategy) {
	ক্ষেত্র FUZZ_1_BIT_FLIP:
	ক্ষেত্র FUZZ_2_BIT_FLIP:
	ক্ষেত্র FUZZ_1_BYTE_FLIP:
	ক্ষেত্র FUZZ_2_BYTE_FLIP:
	ক্ষেত্র FUZZ_BASE64:
		ফেরত fuzz->slen;
	ক্ষেত্র FUZZ_TRUNCATE_START:
	ক্ষেত্র FUZZ_TRUNCATE_END:
		প্রতিজ্ঞা(fuzz->o1 <= fuzz->slen);
		ফেরত fuzz->slen - fuzz->o1;
	পূর্বনির্ধারিত:
		abort();
	}
}

u_char *
fuzz_ptr(কাঠামো fuzz *fuzz)
{
	প্রতিজ্ঞা(fuzz->fuzzed != ফাঁকা);
	নির্বাচন (fuzz->strategy) {
	ক্ষেত্র FUZZ_1_BIT_FLIP:
	ক্ষেত্র FUZZ_2_BIT_FLIP:
	ক্ষেত্র FUZZ_1_BYTE_FLIP:
	ক্ষেত্র FUZZ_2_BYTE_FLIP:
	ক্ষেত্র FUZZ_BASE64:
		ফেরত fuzz->fuzzed;
	ক্ষেত্র FUZZ_TRUNCATE_START:
		প্রতিজ্ঞা(fuzz->o1 <= fuzz->slen);
		ফেরত fuzz->fuzzed + fuzz->o1;
	ক্ষেত্র FUZZ_TRUNCATE_END:
		প্রতিজ্ঞা(fuzz->o1 <= fuzz->slen);
		ফেরত fuzz->fuzzed;
	পূর্বনির্ধারিত:
		abort();
	}
}

