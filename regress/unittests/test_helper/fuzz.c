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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/uio.h>

#ಅನ್ತರ್ಭಾವ <assert.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "test_helper.h"
#ಅನ್ತರ್ಭಾವ "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) ಕುರು { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ಯಾವತ್ (0)
#ಅನ್ಯಥಾ
# define FUZZ_DBG(x)
#endif

/* For brevity later */
ಪ್ರಕಾರನಿರ್ದೇಶ unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ಸಂರಚನಾ fuzz {
	/* Fuzz method currently in use */
	ಪೂರ್ಣಾಙ್ಕ strategy;

	/* Fuzz methods remaining */
	ಪೂರ್ಣಾಙ್ಕ strategies;

	/* Original seed data blob */
	ಶೂನ್ಯ *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
fuzz_ntop(u_int n)
{
	ವಿಕಲ್ಪ (n) {
	ಪಕ್ಷ 0:
		ಪ್ರತ್ಯಾಗಮ "NONE";
	ಪಕ್ಷ FUZZ_1_BIT_FLIP:
		ಪ್ರತ್ಯಾಗಮ "FUZZ_1_BIT_FLIP";
	ಪಕ್ಷ FUZZ_2_BIT_FLIP:
		ಪ್ರತ್ಯಾಗಮ "FUZZ_2_BIT_FLIP";
	ಪಕ್ಷ FUZZ_1_BYTE_FLIP:
		ಪ್ರತ್ಯಾಗಮ "FUZZ_1_BYTE_FLIP";
	ಪಕ್ಷ FUZZ_2_BYTE_FLIP:
		ಪ್ರತ್ಯಾಗಮ "FUZZ_2_BYTE_FLIP";
	ಪಕ್ಷ FUZZ_TRUNCATE_START:
		ಪ್ರತ್ಯಾಗಮ "FUZZ_TRUNCATE_START";
	ಪಕ್ಷ FUZZ_TRUNCATE_END:
		ಪ್ರತ್ಯಾಗಮ "FUZZ_TRUNCATE_END";
	ಪಕ್ಷ FUZZ_BASE64:
		ಪ್ರತ್ಯಾಗಮ "FUZZ_BASE64";
	ಸ್ವಭಾವ:
		abort();
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fuzz_fmt(ಸಂರಚನಾ fuzz *fuzz, ವರ್ಣ *s, size_t n)
{
	ಯದಿ (fuzz == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	ವಿಕಲ್ಪ (fuzz->strategy) {
	ಪಕ್ಷ FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ FUZZ_BASE64:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 < ಪರಿಮಾಣ(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump(u_char *p, size_t len)
{
	size_t i, j;

	ಪ್ರತಿ (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		ಪ್ರತಿ (j = i; j < i + 16; j++) {
			ಯದಿ (j < len)
				fprintf(stderr, "%02x ", p[j]);
			ಅನ್ಯಥಾ
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		ಪ್ರತಿ (j = i; j < i + 16; j++) {
			ಯದಿ (j < len) {
				ಯದಿ  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				ಅನ್ಯಥಾ
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

ಶೂನ್ಯ
fuzz_dump(ಸಂರಚನಾ fuzz *fuzz)
{
	ವರ್ಣ buf[256];

	ಯದಿ (fuzz_fmt(fuzz, buf, ಪರಿಮಾಣ(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

ಸ್ಥಿರ ಸಂರಚನಾ fuzz *last_fuzz;

ಸ್ಥಿರ ಶೂನ್ಯ
siginfo(ಪೂರ್ಣಾಙ್ಕ unused __attribute__((__unused__)))
{
	ವರ್ಣ buf[256];

	test_info(buf, ಪರಿಮಾಣ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	ಯದಿ (last_fuzz != ರಿಕ್ತ) {
		fuzz_fmt(last_fuzz, buf, ಪರಿಮಾಣ(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

ಸಂರಚನಾ fuzz *
fuzz_begin(u_int strategies, ಧ್ರುವ ಶೂನ್ಯ *p, size_t l)
{
	ಸಂರಚನಾ fuzz *ret = calloc(1, ಪರಿಮಾಣ(*ret));

	ಪ್ರತಿಜ್ಞಾ(p != ರಿಕ್ತ);
	ಪ್ರತಿಜ್ಞಾ(ret != ರಿಕ್ತ);
	ret->seed = malloc(l);
	ಪ್ರತಿಜ್ಞಾ(ret->seed != ರಿಕ್ತ);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	ಪ್ರತಿಜ್ಞಾ(ret->slen < SIZE_MAX / 8);
	ಪ್ರತಿಜ್ಞಾ(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	ಸಙ್ಕೇತ(SIGINFO, siginfo);
#endif
	ಸಙ್ಕೇತ(SIGUSR1, siginfo);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
fuzz_cleanup(ಸಂರಚನಾ fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = ರಿಕ್ತ;
#ifdef SIGINFO
	ಸಙ್ಕೇತ(SIGINFO, SIG_DFL);
#endif
	ಸಙ್ಕೇತ(SIGUSR1, SIG_DFL);
	ಪ್ರತಿಜ್ಞಾ(fuzz != ರಿಕ್ತ);
	ಪ್ರತಿಜ್ಞಾ(fuzz->seed != ರಿಕ್ತ);
	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ರಿಕ್ತ);
	ಮುಕ್ತ(fuzz->seed);
	ಮುಕ್ತ(fuzz->fuzzed);
	ಮುಕ್ತ(fuzz);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fuzz_strategy_done(ಸಂರಚನಾ fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	ವಿಕಲ್ಪ (fuzz->strategy) {
	ಪಕ್ಷ FUZZ_1_BIT_FLIP:
		ಪ್ರತ್ಯಾಗಮ fuzz->o1 >= fuzz->slen * 8;
	ಪಕ್ಷ FUZZ_2_BIT_FLIP:
		ಪ್ರತ್ಯಾಗಮ fuzz->o2 >= fuzz->slen * 8;
	ಪಕ್ಷ FUZZ_2_BYTE_FLIP:
		ಪ್ರತ್ಯಾಗಮ fuzz->o2 >= fuzz->slen;
	ಪಕ್ಷ FUZZ_1_BYTE_FLIP:
	ಪಕ್ಷ FUZZ_TRUNCATE_START:
	ಪಕ್ಷ FUZZ_TRUNCATE_END:
	ಪಕ್ಷ FUZZ_BASE64:
		ಪ್ರತ್ಯಾಗಮ fuzz->o1 >= fuzz->slen;
	ಸ್ವಭಾವ:
		abort();
	}
}

ಶೂನ್ಯ
fuzz_next(ಸಂರಚನಾ fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	ಯದಿ (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		ಯದಿ (fuzz->fuzzed == ರಿಕ್ತ) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		ಪ್ರತಿ (i = 1; i <= FUZZ_MAX; i <<= 1) {
			ಯದಿ ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				ಭಙ್ಗ;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		ಯದಿ (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			ಪ್ರತ್ಯಾಗಮ;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ರಿಕ್ತ);

	ವಿಕಲ್ಪ (fuzz->strategy) {
	ಪಕ್ಷ FUZZ_1_BIT_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		ಭಙ್ಗ;
	ಪಕ್ಷ FUZZ_2_BIT_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 / 8 < fuzz->slen);
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		ಯದಿ (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ FUZZ_1_BYTE_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		ಭಙ್ಗ;
	ಪಕ್ಷ FUZZ_2_BYTE_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		ಯದಿ (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ FUZZ_TRUNCATE_START:
	ಪಕ್ಷ FUZZ_TRUNCATE_END:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		ಭಙ್ಗ;
	ಪಕ್ಷ FUZZ_BASE64:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 < ಪರಿಮಾಣ(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		ಯದಿ (fuzz->o2 >= ಪರಿಮಾಣ(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

ಪೂರ್ಣಾಙ್ಕ
fuzz_matches_original(ಸಂರಚನಾ fuzz *fuzz)
{
	ಯದಿ (fuzz_len(fuzz) != fuzz->slen)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

ಪೂರ್ಣಾಙ್ಕ
fuzz_done(ಸಂರಚನಾ fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	ಪ್ರತ್ಯಾಗಮ fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(ಸಂರಚನಾ fuzz *fuzz)
{
	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ರಿಕ್ತ);
	ವಿಕಲ್ಪ (fuzz->strategy) {
	ಪಕ್ಷ FUZZ_1_BIT_FLIP:
	ಪಕ್ಷ FUZZ_2_BIT_FLIP:
	ಪಕ್ಷ FUZZ_1_BYTE_FLIP:
	ಪಕ್ಷ FUZZ_2_BYTE_FLIP:
	ಪಕ್ಷ FUZZ_BASE64:
		ಪ್ರತ್ಯಾಗಮ fuzz->slen;
	ಪಕ್ಷ FUZZ_TRUNCATE_START:
	ಪಕ್ಷ FUZZ_TRUNCATE_END:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 <= fuzz->slen);
		ಪ್ರತ್ಯಾಗಮ fuzz->slen - fuzz->o1;
	ಸ್ವಭಾವ:
		abort();
	}
}

u_char *
fuzz_ptr(ಸಂರಚನಾ fuzz *fuzz)
{
	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ರಿಕ್ತ);
	ವಿಕಲ್ಪ (fuzz->strategy) {
	ಪಕ್ಷ FUZZ_1_BIT_FLIP:
	ಪಕ್ಷ FUZZ_2_BIT_FLIP:
	ಪಕ್ಷ FUZZ_1_BYTE_FLIP:
	ಪಕ್ಷ FUZZ_2_BYTE_FLIP:
	ಪಕ್ಷ FUZZ_BASE64:
		ಪ್ರತ್ಯಾಗಮ fuzz->fuzzed;
	ಪಕ್ಷ FUZZ_TRUNCATE_START:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 <= fuzz->slen);
		ಪ್ರತ್ಯಾಗಮ fuzz->fuzzed + fuzz->o1;
	ಪಕ್ಷ FUZZ_TRUNCATE_END:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 <= fuzz->slen);
		ಪ್ರತ್ಯಾಗಮ fuzz->fuzzed;
	ಸ್ವಭಾವ:
		abort();
	}
}

