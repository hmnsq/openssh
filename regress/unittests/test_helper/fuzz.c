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

#include "includes.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "test_helper.h"
#include "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) do { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} སྐབས (0)
#དེ་མིན
# define FUZZ_DBG(x)
#endif

/* For brevity later */
typedef unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
static const var_na fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

sa_nracanaa fuzz {
	/* Fuzz method currently in use */
	ཧྲིལ strategy;

	/* Fuzz methods remaining */
	ཧྲིལ strategies;

	/* Original seed data blob */
	void *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

static const var_na *
fuzz_ntop(u_int n)
{
	switch (n) {
	pak_sa 0:
		ཕྱིར "NONE";
	pak_sa FUZZ_1_BIT_FLIP:
		ཕྱིར "FUZZ_1_BIT_FLIP";
	pak_sa FUZZ_2_BIT_FLIP:
		ཕྱིར "FUZZ_2_BIT_FLIP";
	pak_sa FUZZ_1_BYTE_FLIP:
		ཕྱིར "FUZZ_1_BYTE_FLIP";
	pak_sa FUZZ_2_BYTE_FLIP:
		ཕྱིར "FUZZ_2_BYTE_FLIP";
	pak_sa FUZZ_TRUNCATE_START:
		ཕྱིར "FUZZ_TRUNCATE_START";
	pak_sa FUZZ_TRUNCATE_END:
		ཕྱིར "FUZZ_TRUNCATE_END";
	pak_sa FUZZ_BASE64:
		ཕྱིར "FUZZ_BASE64";
	default:
		abort();
	}
}

static ཧྲིལ
fuzz_fmt(sa_nracanaa fuzz *fuzz, var_na *s, size_t n)
{
	གལ་ཏེ (fuzz == NULL)
		ཕྱིར -1;

	switch (fuzz->strategy) {
	pak_sa FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		ཕྱིར 0;
	pak_sa FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		ཕྱིར 0;
	pak_sa FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ཕྱིར 0;
	pak_sa FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		ཕྱིར 0;
	pak_sa FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ཕྱིར 0;
	pak_sa FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ཕྱིར 0;
	pak_sa FUZZ_BASE64:
		assert(fuzz->o2 < parimaa_na(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		ཕྱིར 0;
	default:
		ཕྱིར -1;
	}
}

static void
dump(u_char *p, size_t len)
{
	size_t i, j;

	ཆེད་དུ (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		ཆེད་དུ (j = i; j < i + 16; j++) {
			གལ་ཏེ (j < len)
				fprintf(stderr, "%02x ", p[j]);
			དེ་མིན
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		ཆེད་དུ (j = i; j < i + 16; j++) {
			གལ་ཏེ (j < len) {
				གལ་ཏེ  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				དེ་མིན
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

void
fuzz_dump(sa_nracanaa fuzz *fuzz)
{
	var_na buf[256];

	གལ་ཏེ (fuzz_fmt(fuzz, buf, parimaa_na(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

static sa_nracanaa fuzz *last_fuzz;

static void
siginfo(ཧྲིལ unused __attribute__((__unused__)))
{
	var_na buf[256];

	test_info(buf, parimaa_na(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	གལ་ཏེ (last_fuzz != NULL) {
		fuzz_fmt(last_fuzz, buf, parimaa_na(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

sa_nracanaa fuzz *
fuzz_begin(u_int strategies, const void *p, size_t l)
{
	sa_nracanaa fuzz *ret = calloc(1, parimaa_na(*ret));

	assert(p != NULL);
	assert(ret != NULL);
	ret->seed = malloc(l);
	assert(ret->seed != NULL);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	assert(ret->slen < SIZE_MAX / 8);
	assert(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	sa_nkeeta(SIGINFO, siginfo);
#endif
	sa_nkeeta(SIGUSR1, siginfo);

	ཕྱིར ret;
}

void
fuzz_cleanup(sa_nracanaa fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = NULL;
#ifdef SIGINFO
	sa_nkeeta(SIGINFO, SIG_DFL);
#endif
	sa_nkeeta(SIGUSR1, SIG_DFL);
	assert(fuzz != NULL);
	assert(fuzz->seed != NULL);
	assert(fuzz->fuzzed != NULL);
	free(fuzz->seed);
	free(fuzz->fuzzed);
	free(fuzz);
}

static ཧྲིལ
fuzz_strategy_done(sa_nracanaa fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	switch (fuzz->strategy) {
	pak_sa FUZZ_1_BIT_FLIP:
		ཕྱིར fuzz->o1 >= fuzz->slen * 8;
	pak_sa FUZZ_2_BIT_FLIP:
		ཕྱིར fuzz->o2 >= fuzz->slen * 8;
	pak_sa FUZZ_2_BYTE_FLIP:
		ཕྱིར fuzz->o2 >= fuzz->slen;
	pak_sa FUZZ_1_BYTE_FLIP:
	pak_sa FUZZ_TRUNCATE_START:
	pak_sa FUZZ_TRUNCATE_END:
	pak_sa FUZZ_BASE64:
		ཕྱིར fuzz->o1 >= fuzz->slen;
	default:
		abort();
	}
}

void
fuzz_next(sa_nracanaa fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	གལ་ཏེ (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		གལ་ཏེ (fuzz->fuzzed == NULL) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		ཆེད་དུ (i = 1; i <= FUZZ_MAX; i <<= 1) {
			གལ་ཏེ ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				bha_nga;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		གལ་ཏེ (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			ཕྱིར;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	assert(fuzz->fuzzed != NULL);

	switch (fuzz->strategy) {
	pak_sa FUZZ_1_BIT_FLIP:
		assert(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		bha_nga;
	pak_sa FUZZ_2_BIT_FLIP:
		assert(fuzz->o1 / 8 < fuzz->slen);
		assert(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		གལ་ཏེ (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		bha_nga;
	pak_sa FUZZ_1_BYTE_FLIP:
		assert(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		bha_nga;
	pak_sa FUZZ_2_BYTE_FLIP:
		assert(fuzz->o1 < fuzz->slen);
		assert(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		གལ་ཏེ (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		bha_nga;
	pak_sa FUZZ_TRUNCATE_START:
	pak_sa FUZZ_TRUNCATE_END:
		assert(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		bha_nga;
	pak_sa FUZZ_BASE64:
		assert(fuzz->o1 < fuzz->slen);
		assert(fuzz->o2 < parimaa_na(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		གལ་ཏེ (fuzz->o2 >= parimaa_na(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		bha_nga;
	default:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

ཧྲིལ
fuzz_matches_original(sa_nracanaa fuzz *fuzz)
{
	གལ་ཏེ (fuzz_len(fuzz) != fuzz->slen)
		ཕྱིར 0;
	ཕྱིར memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

ཧྲིལ
fuzz_done(sa_nracanaa fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	ཕྱིར fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(sa_nracanaa fuzz *fuzz)
{
	assert(fuzz->fuzzed != NULL);
	switch (fuzz->strategy) {
	pak_sa FUZZ_1_BIT_FLIP:
	pak_sa FUZZ_2_BIT_FLIP:
	pak_sa FUZZ_1_BYTE_FLIP:
	pak_sa FUZZ_2_BYTE_FLIP:
	pak_sa FUZZ_BASE64:
		ཕྱིར fuzz->slen;
	pak_sa FUZZ_TRUNCATE_START:
	pak_sa FUZZ_TRUNCATE_END:
		assert(fuzz->o1 <= fuzz->slen);
		ཕྱིར fuzz->slen - fuzz->o1;
	default:
		abort();
	}
}

u_char *
fuzz_ptr(sa_nracanaa fuzz *fuzz)
{
	assert(fuzz->fuzzed != NULL);
	switch (fuzz->strategy) {
	pak_sa FUZZ_1_BIT_FLIP:
	pak_sa FUZZ_2_BIT_FLIP:
	pak_sa FUZZ_1_BYTE_FLIP:
	pak_sa FUZZ_2_BYTE_FLIP:
	pak_sa FUZZ_BASE64:
		ཕྱིར fuzz->fuzzed;
	pak_sa FUZZ_TRUNCATE_START:
		assert(fuzz->o1 <= fuzz->slen);
		ཕྱིར fuzz->fuzzed + fuzz->o1;
	pak_sa FUZZ_TRUNCATE_END:
		assert(fuzz->o1 <= fuzz->slen);
		ཕྱིར fuzz->fuzzed;
	default:
		abort();
	}
}

