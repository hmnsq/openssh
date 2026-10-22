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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ FUZZ_DEBUG
# define FUZZ_DBG(x) ಮಾಡು { \
		ಬರೆ("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		ಬರೆ x; \
		ಬರೆ("\n"); \
		fflush(stdout); \
	} ಆಗ (0)
#ಇಲ್ಲದಿದ್ದರೆ
# define FUZZ_DBG(x)
#ಆದರೆ_ಅಂತ್ಯ

/* For brevity later */
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ fuzz_ullong;

/* For base-64 fuzzing */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ರಚನೆ fuzz {
	/* Fuzz method currently in use */
	ಪೂರ್ಣಾಂಕ strategy;

	/* Fuzz methods remaining */
	ಪೂರ್ಣಾಂಕ strategies;

	/* Original seed data blob */
	ಶೂನ್ಯ *ಬೀಜ;
	ಗಾತ್ರ_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	ಗಾತ್ರ_t o1, o2;
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fuzz_ntop(u_int n)
{
	ಆಯ್ಕೆ (n) {
	ಸ್ಥಿತಿ 0:
		ಹಿಂತಿರುಗಿ "NONE";
	ಸ್ಥಿತಿ FUZZ_1_ಬಿಟ್_FLIP:
		ಹಿಂತಿರುಗಿ "FUZZ_1_BIT_FLIP";
	ಸ್ಥಿತಿ FUZZ_2_ಬಿಟ್_FLIP:
		ಹಿಂತಿರುಗಿ "FUZZ_2_BIT_FLIP";
	ಸ್ಥಿತಿ FUZZ_1_BYTE_FLIP:
		ಹಿಂತಿರುಗಿ "FUZZ_1_BYTE_FLIP";
	ಸ್ಥಿತಿ FUZZ_2_BYTE_FLIP:
		ಹಿಂತಿರುಗಿ "FUZZ_2_BYTE_FLIP";
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಆರಂಭ:
		ಹಿಂತಿರುಗಿ "FUZZ_TRUNCATE_START";
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಕೊನೆ:
		ಹಿಂತಿರುಗಿ "FUZZ_TRUNCATE_END";
	ಸ್ಥಿತಿ FUZZ_BASE64:
		ಹಿಂತಿರುಗಿ "FUZZ_BASE64";
	ಪೂರ್ವನಿಯೋಜಿತ:
		abort();
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fuzz_fmt(ರಚನೆ fuzz *fuzz, ಅಕ್ಷರ *s, ಗಾತ್ರ_t n)
{
	ಆದರೆ (fuzz == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	ಆಯ್ಕೆ (fuzz->strategy) {
	ಸ್ಥಿತಿ FUZZ_1_ಬಿಟ್_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ FUZZ_2_ಬಿಟ್_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಆರಂಭ:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಕೊನೆ:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ FUZZ_BASE64:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 < ಗಾತ್ರ(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump(u_char *p, ಗಾತ್ರ_t len)
{
	ಗಾತ್ರ_t i, j;

	ಗಾಗಿ (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		ಗಾಗಿ (j = i; j < i + 16; j++) {
			ಆದರೆ (j < len)
				fprintf(stderr, "%02x ", p[j]);
			ಇಲ್ಲದಿದ್ದರೆ
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		ಗಾಗಿ (j = i; j < i + 16; j++) {
			ಆದರೆ (j < len) {
				ಆದರೆ  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				ಇಲ್ಲದಿದ್ದರೆ
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

ಶೂನ್ಯ
fuzz_dump(ರಚನೆ fuzz *fuzz)
{
	ಅಕ್ಷರ buf[256];

	ಆದರೆ (fuzz_fmt(fuzz, buf, ಗಾತ್ರ(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->ಬೀಜ, fuzz->slen);
	dump(fuzz->ಬೀಜ, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

ಸ್ಥಿರ ರಚನೆ fuzz *ಕೊನೆಯ_fuzz;

ಸ್ಥಿರ ಶೂನ್ಯ
siginfo(ಪೂರ್ಣಾಂಕ ಬಳಸದ __attribute__((__unused__)))
{
	ಅಕ್ಷರ buf[256];

	test_info(buf, ಗಾತ್ರ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf));
	ಆದರೆ (ಕೊನೆಯ_fuzz != ಖಾಲಿ) {
		fuzz_fmt(ಕೊನೆಯ_fuzz, buf, ಗಾತ್ರ(buf));
		atomicio(vwrite, STDERR_FILENO, buf, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(buf));
	}
}

ರಚನೆ fuzz *
fuzz_begin(u_int strategies, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, ಗಾತ್ರ_t l)
{
	ರಚನೆ fuzz *ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret));

	ಪ್ರತಿಜ್ಞಾ(p != ಖಾಲಿ);
	ಪ್ರತಿಜ್ಞಾ(ret != ಖಾಲಿ);
	ret->ಬೀಜ = ಸ್ಮರಣೆ_ಕೊಡು(l);
	ಪ್ರತಿಜ್ಞಾ(ret->ಬೀಜ != ಖಾಲಿ);
	ಸ್ಮರಣೆ_ನಕಲು(ret->ಬೀಜ, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	ಪ್ರತಿಜ್ಞಾ(ret->slen < SIZE_MAX / 8);
	ಪ್ರತಿಜ್ಞಾ(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_ಮುಂದಿನ(ret);

	ಕೊನೆಯ_fuzz = ret;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	ಸಂಕೇತ(SIGINFO, siginfo);
#ಆದರೆ_ಅಂತ್ಯ
	ಸಂಕೇತ(SIGUSR1, siginfo);

	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
fuzz_cleanup(ರಚನೆ fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	ಕೊನೆಯ_fuzz = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SIGINFO
	ಸಂಕೇತ(SIGINFO, SIG_DFL);
#ಆದರೆ_ಅಂತ್ಯ
	ಸಂಕೇತ(SIGUSR1, SIG_DFL);
	ಪ್ರತಿಜ್ಞಾ(fuzz != ಖಾಲಿ);
	ಪ್ರತಿಜ್ಞಾ(fuzz->ಬೀಜ != ಖಾಲಿ);
	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ಖಾಲಿ);
	ಬಿಡುಗಡೆ(fuzz->ಬೀಜ);
	ಬಿಡುಗಡೆ(fuzz->fuzzed);
	ಬಿಡುಗಡೆ(fuzz);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fuzz_strategy_ಮುಗಿದ(ರಚನೆ fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	ಆಯ್ಕೆ (fuzz->strategy) {
	ಸ್ಥಿತಿ FUZZ_1_ಬಿಟ್_FLIP:
		ಹಿಂತಿರುಗಿ fuzz->o1 >= fuzz->slen * 8;
	ಸ್ಥಿತಿ FUZZ_2_ಬಿಟ್_FLIP:
		ಹಿಂತಿರುಗಿ fuzz->o2 >= fuzz->slen * 8;
	ಸ್ಥಿತಿ FUZZ_2_BYTE_FLIP:
		ಹಿಂತಿರುಗಿ fuzz->o2 >= fuzz->slen;
	ಸ್ಥಿತಿ FUZZ_1_BYTE_FLIP:
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಆರಂಭ:
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಕೊನೆ:
	ಸ್ಥಿತಿ FUZZ_BASE64:
		ಹಿಂತಿರುಗಿ fuzz->o1 >= fuzz->slen;
	ಪೂರ್ವನಿಯೋಜಿತ:
		abort();
	}
}

ಶೂನ್ಯ
fuzz_ಮುಂದಿನ(ರಚನೆ fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	ಆದರೆ (fuzz->strategy == 0 || fuzz_strategy_ಮುಗಿದ(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		ಆದರೆ (fuzz->fuzzed == ಖಾಲಿ) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		ಗಾಗಿ (i = 1; i <= FUZZ_MAX; i <<= 1) {
			ಆದರೆ ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				ನಿಲ್ಲಿಸು;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		ಆದರೆ (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			ಹಿಂತಿರುಗಿ;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ಖಾಲಿ);

	ಆಯ್ಕೆ (fuzz->strategy) {
	ಸ್ಥಿತಿ FUZZ_1_ಬಿಟ್_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 / 8 < fuzz->slen);
		ಸ್ಮರಣೆ_ನಕಲು(fuzz->fuzzed, fuzz->ಬೀಜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FUZZ_2_ಬಿಟ್_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 / 8 < fuzz->slen);
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 / 8 < fuzz->slen);
		ಸ್ಮರಣೆ_ನಕಲು(fuzz->fuzzed, fuzz->ಬೀಜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		ಆದರೆ (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FUZZ_1_BYTE_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		ಸ್ಮರಣೆ_ನಕಲು(fuzz->fuzzed, fuzz->ಬೀಜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FUZZ_2_BYTE_FLIP:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 < fuzz->slen);
		ಸ್ಮರಣೆ_ನಕಲು(fuzz->fuzzed, fuzz->ಬೀಜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		ಆದರೆ (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಆರಂಭ:
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಕೊನೆ:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		ಸ್ಮರಣೆ_ನಕಲು(fuzz->fuzzed, fuzz->ಬೀಜ, fuzz->slen);
		fuzz->o1++;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ FUZZ_BASE64:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 < fuzz->slen);
		ಪ್ರತಿಜ್ಞಾ(fuzz->o2 < ಗಾತ್ರ(fuzz_b64chars) - 1);
		ಸ್ಮರಣೆ_ನಕಲು(fuzz->fuzzed, fuzz->ಬೀಜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		ಆದರೆ (fuzz->o2 >= ಗಾತ್ರ(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

ಪೂರ್ಣಾಂಕ
fuzz_matches_original(ರಚನೆ fuzz *fuzz)
{
	ಆದರೆ (fuzz_len(fuzz) != fuzz->slen)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ memcmp(fuzz_ptr(fuzz), fuzz->ಬೀಜ, fuzz->slen) == 0;
}

ಪೂರ್ಣಾಂಕ
fuzz_ಮುಗಿದ(ರಚನೆ fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	ಹಿಂತಿರುಗಿ fuzz_strategy_ಮುಗಿದ(fuzz) && fuzz->strategies == 0;
}

ಗಾತ್ರ_t
fuzz_len(ರಚನೆ fuzz *fuzz)
{
	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ಖಾಲಿ);
	ಆಯ್ಕೆ (fuzz->strategy) {
	ಸ್ಥಿತಿ FUZZ_1_ಬಿಟ್_FLIP:
	ಸ್ಥಿತಿ FUZZ_2_ಬಿಟ್_FLIP:
	ಸ್ಥಿತಿ FUZZ_1_BYTE_FLIP:
	ಸ್ಥಿತಿ FUZZ_2_BYTE_FLIP:
	ಸ್ಥಿತಿ FUZZ_BASE64:
		ಹಿಂತಿರುಗಿ fuzz->slen;
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಆರಂಭ:
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಕೊನೆ:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 <= fuzz->slen);
		ಹಿಂತಿರುಗಿ fuzz->slen - fuzz->o1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		abort();
	}
}

u_char *
fuzz_ptr(ರಚನೆ fuzz *fuzz)
{
	ಪ್ರತಿಜ್ಞಾ(fuzz->fuzzed != ಖಾಲಿ);
	ಆಯ್ಕೆ (fuzz->strategy) {
	ಸ್ಥಿತಿ FUZZ_1_ಬಿಟ್_FLIP:
	ಸ್ಥಿತಿ FUZZ_2_ಬಿಟ್_FLIP:
	ಸ್ಥಿತಿ FUZZ_1_BYTE_FLIP:
	ಸ್ಥಿತಿ FUZZ_2_BYTE_FLIP:
	ಸ್ಥಿತಿ FUZZ_BASE64:
		ಹಿಂತಿರುಗಿ fuzz->fuzzed;
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಆರಂಭ:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 <= fuzz->slen);
		ಹಿಂತಿರುಗಿ fuzz->fuzzed + fuzz->o1;
	ಸ್ಥಿತಿ FUZZ_TRUNCATE_ಕೊನೆ:
		ಪ್ರತಿಜ್ಞಾ(fuzz->o1 <= fuzz->slen);
		ಹಿಂತಿರುಗಿ fuzz->fuzzed;
	ಪೂರ್ವನಿಯೋಜಿತ:
		abort();
	}
}

