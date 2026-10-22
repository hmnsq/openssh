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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/uio.h>

#شامل <assert.h>
#شامل <ctype.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <signal.h>
#شامل <unistd.h>

#شامل "test_helper.h"
#شامل "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) انجامبده { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} وقتی (0)
#وگرنه
# define FUZZ_DBG(x)
#endif

/* For brevity later */
تعریفنوع unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
ایستا ثابت نویسه fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ساختار fuzz {
	/* Fuzz method currently in use */
	صحیح strategy;

	/* Fuzz methods remaining */
	صحیح strategies;

	/* Original seed data blob */
	تهی *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

ایستا ثابت نویسه *
fuzz_ntop(u_int n)
{
	انتخاب (n) {
	حالت 0:
		بازگشت "NONE";
	حالت FUZZ_1_BIT_FLIP:
		بازگشت "FUZZ_1_BIT_FLIP";
	حالت FUZZ_2_BIT_FLIP:
		بازگشت "FUZZ_2_BIT_FLIP";
	حالت FUZZ_1_BYTE_FLIP:
		بازگشت "FUZZ_1_BYTE_FLIP";
	حالت FUZZ_2_BYTE_FLIP:
		بازگشت "FUZZ_2_BYTE_FLIP";
	حالت FUZZ_TRUNCATE_START:
		بازگشت "FUZZ_TRUNCATE_START";
	حالت FUZZ_TRUNCATE_END:
		بازگشت "FUZZ_TRUNCATE_END";
	حالت FUZZ_BASE64:
		بازگشت "FUZZ_BASE64";
	پیشفرض:
		abort();
	}
}

ایستا صحیح
fuzz_fmt(ساختار fuzz *fuzz, نویسه *s, size_t n)
{
	اگر (fuzz == پوچ)
		بازگشت -1;

	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		بازگشت 0;
	حالت FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		بازگشت 0;
	حالت FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		بازگشت 0;
	حالت FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		بازگشت 0;
	حالت FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		بازگشت 0;
	حالت FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		بازگشت 0;
	حالت FUZZ_BASE64:
		أكد(fuzz->o2 < اندازه(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		بازگشت 0;
	پیشفرض:
		بازگشت -1;
	}
}

ایستا تهی
dump(u_char *p, size_t len)
{
	size_t i, j;

	برای (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		برای (j = i; j < i + 16; j++) {
			اگر (j < len)
				fprintf(stderr, "%02x ", p[j]);
			وگرنه
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		برای (j = i; j < i + 16; j++) {
			اگر (j < len) {
				اگر  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				وگرنه
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

تهی
fuzz_dump(ساختار fuzz *fuzz)
{
	نویسه buf[256];

	اگر (fuzz_fmt(fuzz, buf, اندازه(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

ایستا ساختار fuzz *last_fuzz;

ایستا تهی
siginfo(صحیح unused __attribute__((__unused__)))
{
	نویسه buf[256];

	test_info(buf, اندازه(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	اگر (last_fuzz != پوچ) {
		fuzz_fmt(last_fuzz, buf, اندازه(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

ساختار fuzz *
fuzz_begin(u_int strategies, ثابت تهی *p, size_t l)
{
	ساختار fuzz *ret = calloc(1, اندازه(*ret));

	أكد(p != پوچ);
	أكد(ret != پوچ);
	ret->seed = malloc(l);
	أكد(ret->seed != پوچ);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	أكد(ret->slen < SIZE_MAX / 8);
	أكد(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	سیگنال(SIGINFO, siginfo);
#endif
	سیگنال(SIGUSR1, siginfo);

	بازگشت ret;
}

تهی
fuzz_cleanup(ساختار fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = پوچ;
#ifdef SIGINFO
	سیگنال(SIGINFO, SIG_DFL);
#endif
	سیگنال(SIGUSR1, SIG_DFL);
	أكد(fuzz != پوچ);
	أكد(fuzz->seed != پوچ);
	أكد(fuzz->fuzzed != پوچ);
	آزاد(fuzz->seed);
	آزاد(fuzz->fuzzed);
	آزاد(fuzz);
}

ایستا صحیح
fuzz_strategy_done(ساختار fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_BIT_FLIP:
		بازگشت fuzz->o1 >= fuzz->slen * 8;
	حالت FUZZ_2_BIT_FLIP:
		بازگشت fuzz->o2 >= fuzz->slen * 8;
	حالت FUZZ_2_BYTE_FLIP:
		بازگشت fuzz->o2 >= fuzz->slen;
	حالت FUZZ_1_BYTE_FLIP:
	حالت FUZZ_TRUNCATE_START:
	حالت FUZZ_TRUNCATE_END:
	حالت FUZZ_BASE64:
		بازگشت fuzz->o1 >= fuzz->slen;
	پیشفرض:
		abort();
	}
}

تهی
fuzz_next(ساختار fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	اگر (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		اگر (fuzz->fuzzed == پوچ) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		برای (i = 1; i <= FUZZ_MAX; i <<= 1) {
			اگر ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				بشکن;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		اگر (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			بازگشت;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	أكد(fuzz->fuzzed != پوچ);

	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_BIT_FLIP:
		أكد(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		بشکن;
	حالت FUZZ_2_BIT_FLIP:
		أكد(fuzz->o1 / 8 < fuzz->slen);
		أكد(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		اگر (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		بشکن;
	حالت FUZZ_1_BYTE_FLIP:
		أكد(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		بشکن;
	حالت FUZZ_2_BYTE_FLIP:
		أكد(fuzz->o1 < fuzz->slen);
		أكد(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		اگر (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		بشکن;
	حالت FUZZ_TRUNCATE_START:
	حالت FUZZ_TRUNCATE_END:
		أكد(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		بشکن;
	حالت FUZZ_BASE64:
		أكد(fuzz->o1 < fuzz->slen);
		أكد(fuzz->o2 < اندازه(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		اگر (fuzz->o2 >= اندازه(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		بشکن;
	پیشفرض:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

صحیح
fuzz_matches_original(ساختار fuzz *fuzz)
{
	اگر (fuzz_len(fuzz) != fuzz->slen)
		بازگشت 0;
	بازگشت memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

صحیح
fuzz_done(ساختار fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	بازگشت fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(ساختار fuzz *fuzz)
{
	أكد(fuzz->fuzzed != پوچ);
	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_BIT_FLIP:
	حالت FUZZ_2_BIT_FLIP:
	حالت FUZZ_1_BYTE_FLIP:
	حالت FUZZ_2_BYTE_FLIP:
	حالت FUZZ_BASE64:
		بازگشت fuzz->slen;
	حالت FUZZ_TRUNCATE_START:
	حالت FUZZ_TRUNCATE_END:
		أكد(fuzz->o1 <= fuzz->slen);
		بازگشت fuzz->slen - fuzz->o1;
	پیشفرض:
		abort();
	}
}

u_char *
fuzz_ptr(ساختار fuzz *fuzz)
{
	أكد(fuzz->fuzzed != پوچ);
	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_BIT_FLIP:
	حالت FUZZ_2_BIT_FLIP:
	حالت FUZZ_1_BYTE_FLIP:
	حالت FUZZ_2_BYTE_FLIP:
	حالت FUZZ_BASE64:
		بازگشت fuzz->fuzzed;
	حالت FUZZ_TRUNCATE_START:
		أكد(fuzz->o1 <= fuzz->slen);
		بازگشت fuzz->fuzzed + fuzz->o1;
	حالت FUZZ_TRUNCATE_END:
		أكد(fuzz->o1 <= fuzz->slen);
		بازگشت fuzz->fuzzed;
	پیشفرض:
		abort();
	}
}

