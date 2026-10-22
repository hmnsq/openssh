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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/uio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <assert.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "test_helper.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "atomicio.h"

/* #define FUZZ_DEBUG */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ FUZZ_DEBUG
# define FUZZ_DBG(x) ਕਰੋ { \
		ਲਿਖੋ("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		ਲਿਖੋ x; \
		ਲਿਖੋ("\n"); \
		fflush(stdout); \
	} ਜਦੋਂ (0)
#ਨਹੀਂਤਾਂ
# define FUZZ_DBG(x)
#ਜੇ_ਅੰਤ

/* For brevity later */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ fuzz_ullong;

/* For base-64 fuzzing */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ਬਣਤਰ fuzz {
	/* Fuzz method currently in use */
	ਪੂਰਨ strategy;

	/* Fuzz methods remaining */
	ਪੂਰਨ strategies;

	/* Original seed data blob */
	ਖਾਲੀ *ਬੀਜ;
	ਮਾਪ_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	ਮਾਪ_t o1, o2;
};

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
fuzz_ntop(u_int n)
{
	ਚੋਣ (n) {
	ਹਾਲਤ 0:
		ਵਾਪਸ "NONE";
	ਹਾਲਤ FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		ਵਾਪਸ "FUZZ_1_BIT_FLIP";
	ਹਾਲਤ FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		ਵਾਪਸ "FUZZ_2_BIT_FLIP";
	ਹਾਲਤ FUZZ_1_BYTE_FLIP:
		ਵਾਪਸ "FUZZ_1_BYTE_FLIP";
	ਹਾਲਤ FUZZ_2_BYTE_FLIP:
		ਵਾਪਸ "FUZZ_2_BYTE_FLIP";
	ਹਾਲਤ FUZZ_TRUNCATE_ਸ਼ੁਰੂ:
		ਵਾਪਸ "FUZZ_TRUNCATE_START";
	ਹਾਲਤ FUZZ_TRUNCATE_ਸਿਰਾ:
		ਵਾਪਸ "FUZZ_TRUNCATE_END";
	ਹਾਲਤ FUZZ_BASE64:
		ਵਾਪਸ "FUZZ_BASE64";
	ਮੂਲ:
		abort();
	}
}

ਸਥਿਰ ਪੂਰਨ
fuzz_fmt(ਬਣਤਰ fuzz *fuzz, ਅੱਖਰ *s, ਮਾਪ_t n)
{
	ਜੇ (fuzz == ਨਿਰਾ)
		ਵਾਪਸ -1;

	ਚੋਣ (fuzz->strategy) {
	ਹਾਲਤ FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		ਵਾਪਸ 0;
	ਹਾਲਤ FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		ਵਾਪਸ 0;
	ਹਾਲਤ FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ਵਾਪਸ 0;
	ਹਾਲਤ FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		ਵਾਪਸ 0;
	ਹਾਲਤ FUZZ_TRUNCATE_ਸ਼ੁਰੂ:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ਵਾਪਸ 0;
	ਹਾਲਤ FUZZ_TRUNCATE_ਸਿਰਾ:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ਵਾਪਸ 0;
	ਹਾਲਤ FUZZ_BASE64:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o2 < ਆਕਾਰ(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਸਥਿਰ ਖਾਲੀ
dump(u_char *p, ਮਾਪ_t len)
{
	ਮਾਪ_t i, j;

	ਲਈ (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		ਲਈ (j = i; j < i + 16; j++) {
			ਜੇ (j < len)
				fprintf(stderr, "%02x ", p[j]);
			ਨਹੀਂਤਾਂ
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		ਲਈ (j = i; j < i + 16; j++) {
			ਜੇ (j < len) {
				ਜੇ  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				ਨਹੀਂਤਾਂ
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

ਖਾਲੀ
fuzz_dump(ਬਣਤਰ fuzz *fuzz)
{
	ਅੱਖਰ buf[256];

	ਜੇ (fuzz_fmt(fuzz, buf, ਆਕਾਰ(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->ਬੀਜ, fuzz->slen);
	dump(fuzz->ਬੀਜ, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

ਸਥਿਰ ਬਣਤਰ fuzz *ਆਖਰੀ_fuzz;

ਸਥਿਰ ਖਾਲੀ
siginfo(ਪੂਰਨ ਅਣਵਰਤਿਆ __attribute__((__unused__)))
{
	ਅੱਖਰ buf[256];

	test_info(buf, ਆਕਾਰ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, ਲੜੀ_ਲੰਬਾਈ(buf));
	ਜੇ (ਆਖਰੀ_fuzz != ਨਿਰਾ) {
		fuzz_fmt(ਆਖਰੀ_fuzz, buf, ਆਕਾਰ(buf));
		atomicio(vwrite, STDERR_FILENO, buf, ਲੜੀ_ਲੰਬਾਈ(buf));
	}
}

ਬਣਤਰ fuzz *
fuzz_begin(u_int strategies, ਅਚਲ ਖਾਲੀ *p, ਮਾਪ_t l)
{
	ਬਣਤਰ fuzz *ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret));

	ਪ੍ਰਤਿਜ੍ਞਾ(p != ਨਿਰਾ);
	ਪ੍ਰਤਿਜ੍ਞਾ(ret != ਨਿਰਾ);
	ret->ਬੀਜ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(l);
	ਪ੍ਰਤਿਜ੍ਞਾ(ret->ਬੀਜ != ਨਿਰਾ);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ret->ਬੀਜ, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	ਪ੍ਰਤਿਜ੍ਞਾ(ret->slen < SIZE_MAX / 8);
	ਪ੍ਰਤਿਜ੍ਞਾ(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_ਅਗਲਾ(ret);

	ਆਖਰੀ_fuzz = ret;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	ਸੰਕੇਤ(SIGINFO, siginfo);
#ਜੇ_ਅੰਤ
	ਸੰਕੇਤ(SIGUSR1, siginfo);

	ਵਾਪਸ ret;
}

ਖਾਲੀ
fuzz_cleanup(ਬਣਤਰ fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	ਆਖਰੀ_fuzz = ਨਿਰਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SIGINFO
	ਸੰਕੇਤ(SIGINFO, SIG_DFL);
#ਜੇ_ਅੰਤ
	ਸੰਕੇਤ(SIGUSR1, SIG_DFL);
	ਪ੍ਰਤਿਜ੍ਞਾ(fuzz != ਨਿਰਾ);
	ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->ਬੀਜ != ਨਿਰਾ);
	ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->fuzzed != ਨਿਰਾ);
	ਮੁਕਤ(fuzz->ਬੀਜ);
	ਮੁਕਤ(fuzz->fuzzed);
	ਮੁਕਤ(fuzz);
}

ਸਥਿਰ ਪੂਰਨ
fuzz_strategy_ਪੂਰਾ(ਬਣਤਰ fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	ਚੋਣ (fuzz->strategy) {
	ਹਾਲਤ FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		ਵਾਪਸ fuzz->o1 >= fuzz->slen * 8;
	ਹਾਲਤ FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		ਵਾਪਸ fuzz->o2 >= fuzz->slen * 8;
	ਹਾਲਤ FUZZ_2_BYTE_FLIP:
		ਵਾਪਸ fuzz->o2 >= fuzz->slen;
	ਹਾਲਤ FUZZ_1_BYTE_FLIP:
	ਹਾਲਤ FUZZ_TRUNCATE_ਸ਼ੁਰੂ:
	ਹਾਲਤ FUZZ_TRUNCATE_ਸਿਰਾ:
	ਹਾਲਤ FUZZ_BASE64:
		ਵਾਪਸ fuzz->o1 >= fuzz->slen;
	ਮੂਲ:
		abort();
	}
}

ਖਾਲੀ
fuzz_ਅਗਲਾ(ਬਣਤਰ fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	ਜੇ (fuzz->strategy == 0 || fuzz_strategy_ਪੂਰਾ(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		ਜੇ (fuzz->fuzzed == ਨਿਰਾ) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		ਲਈ (i = 1; i <= FUZZ_MAX; i <<= 1) {
			ਜੇ ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				ਰੋਕੋ;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		ਜੇ (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			ਵਾਪਸ;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->fuzzed != ਨਿਰਾ);

	ਚੋਣ (fuzz->strategy) {
	ਹਾਲਤ FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 / 8 < fuzz->slen);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(fuzz->fuzzed, fuzz->ਬੀਜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		ਰੋਕੋ;
	ਹਾਲਤ FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 / 8 < fuzz->slen);
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o2 / 8 < fuzz->slen);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(fuzz->fuzzed, fuzz->ਬੀਜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		ਜੇ (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ਰੋਕੋ;
	ਹਾਲਤ FUZZ_1_BYTE_FLIP:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 < fuzz->slen);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(fuzz->fuzzed, fuzz->ਬੀਜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		ਰੋਕੋ;
	ਹਾਲਤ FUZZ_2_BYTE_FLIP:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 < fuzz->slen);
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o2 < fuzz->slen);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(fuzz->fuzzed, fuzz->ਬੀਜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		ਜੇ (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ਰੋਕੋ;
	ਹਾਲਤ FUZZ_TRUNCATE_ਸ਼ੁਰੂ:
	ਹਾਲਤ FUZZ_TRUNCATE_ਸਿਰਾ:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 < fuzz->slen);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(fuzz->fuzzed, fuzz->ਬੀਜ, fuzz->slen);
		fuzz->o1++;
		ਰੋਕੋ;
	ਹਾਲਤ FUZZ_BASE64:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 < fuzz->slen);
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o2 < ਆਕਾਰ(fuzz_b64chars) - 1);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(fuzz->fuzzed, fuzz->ਬੀਜ, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		ਜੇ (fuzz->o2 >= ਆਕਾਰ(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		ਰੋਕੋ;
	ਮੂਲ:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

ਪੂਰਨ
fuzz_matches_original(ਬਣਤਰ fuzz *fuzz)
{
	ਜੇ (fuzz_len(fuzz) != fuzz->slen)
		ਵਾਪਸ 0;
	ਵਾਪਸ memcmp(fuzz_ptr(fuzz), fuzz->ਬੀਜ, fuzz->slen) == 0;
}

ਪੂਰਨ
fuzz_ਪੂਰਾ(ਬਣਤਰ fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	ਵਾਪਸ fuzz_strategy_ਪੂਰਾ(fuzz) && fuzz->strategies == 0;
}

ਮਾਪ_t
fuzz_len(ਬਣਤਰ fuzz *fuzz)
{
	ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->fuzzed != ਨਿਰਾ);
	ਚੋਣ (fuzz->strategy) {
	ਹਾਲਤ FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
	ਹਾਲਤ FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
	ਹਾਲਤ FUZZ_1_BYTE_FLIP:
	ਹਾਲਤ FUZZ_2_BYTE_FLIP:
	ਹਾਲਤ FUZZ_BASE64:
		ਵਾਪਸ fuzz->slen;
	ਹਾਲਤ FUZZ_TRUNCATE_ਸ਼ੁਰੂ:
	ਹਾਲਤ FUZZ_TRUNCATE_ਸਿਰਾ:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 <= fuzz->slen);
		ਵਾਪਸ fuzz->slen - fuzz->o1;
	ਮੂਲ:
		abort();
	}
}

u_char *
fuzz_ptr(ਬਣਤਰ fuzz *fuzz)
{
	ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->fuzzed != ਨਿਰਾ);
	ਚੋਣ (fuzz->strategy) {
	ਹਾਲਤ FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
	ਹਾਲਤ FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP:
	ਹਾਲਤ FUZZ_1_BYTE_FLIP:
	ਹਾਲਤ FUZZ_2_BYTE_FLIP:
	ਹਾਲਤ FUZZ_BASE64:
		ਵਾਪਸ fuzz->fuzzed;
	ਹਾਲਤ FUZZ_TRUNCATE_ਸ਼ੁਰੂ:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 <= fuzz->slen);
		ਵਾਪਸ fuzz->fuzzed + fuzz->o1;
	ਹਾਲਤ FUZZ_TRUNCATE_ਸਿਰਾ:
		ਪ੍ਰਤਿਜ੍ਞਾ(fuzz->o1 <= fuzz->slen);
		ਵਾਪਸ fuzz->fuzzed;
	ਮੂਲ:
		abort();
	}
}

