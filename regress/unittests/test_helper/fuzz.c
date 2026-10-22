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

#اگر_تعریف_شدہ FUZZ_DEBUG
# define FUZZ_DBG(x) کرو { \
		لکھو("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		لکھو x; \
		لکھو("\n"); \
		fflush(stdout); \
	} جب (0)
#ورنہ
# define FUZZ_DBG(x)
#اگر_ختم

/* For brevity later */
قسمتعریف غیرعلامتی طویل طویل fuzz_ullong;

/* For base-64 fuzzing */
ساکن ثابت حرف fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ساخت fuzz {
	/* Fuzz method currently in use */
	صحیح strategy;

	/* Fuzz methods remaining */
	صحیح strategies;

	/* Original seed data blob */
	خالی *بیج;
	سائز_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	سائز_t o1, o2;
};

ساکن ثابت حرف *
fuzz_ntop(u_int n)
{
	انتخاب (n) {
	حالت 0:
		واپس "NONE";
	حالت FUZZ_1_ثنائی_ہندسہ_FLIP:
		واپس "FUZZ_1_BIT_FLIP";
	حالت FUZZ_2_ثنائی_ہندسہ_FLIP:
		واپس "FUZZ_2_BIT_FLIP";
	حالت FUZZ_1_BYTE_FLIP:
		واپس "FUZZ_1_BYTE_FLIP";
	حالت FUZZ_2_BYTE_FLIP:
		واپس "FUZZ_2_BYTE_FLIP";
	حالت FUZZ_TRUNCATE_آغاز:
		واپس "FUZZ_TRUNCATE_START";
	حالت FUZZ_TRUNCATE_انتہا:
		واپس "FUZZ_TRUNCATE_END";
	حالت FUZZ_BASE64:
		واپس "FUZZ_BASE64";
	طےشدہ:
		abort();
	}
}

ساکن صحیح
fuzz_fmt(ساخت fuzz *fuzz, حرف *s, سائز_t n)
{
	اگر (fuzz == تہی)
		واپس -1;

	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_ثنائی_ہندسہ_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		واپس 0;
	حالت FUZZ_2_ثنائی_ہندسہ_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		واپس 0;
	حالت FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		واپس 0;
	حالت FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		واپس 0;
	حالت FUZZ_TRUNCATE_آغاز:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		واپس 0;
	حالت FUZZ_TRUNCATE_انتہا:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		واپس 0;
	حالت FUZZ_BASE64:
		أكد(fuzz->o2 < حجم(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		واپس 0;
	طےشدہ:
		واپس -1;
	}
}

ساکن خالی
dump(u_char *p, سائز_t len)
{
	سائز_t i, j;

	برائے (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		برائے (j = i; j < i + 16; j++) {
			اگر (j < len)
				fprintf(stderr, "%02x ", p[j]);
			ورنہ
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		برائے (j = i; j < i + 16; j++) {
			اگر (j < len) {
				اگر  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				ورنہ
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

خالی
fuzz_dump(ساخت fuzz *fuzz)
{
	حرف buf[256];

	اگر (fuzz_fmt(fuzz, buf, حجم(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->بیج, fuzz->slen);
	dump(fuzz->بیج, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

ساکن ساخت fuzz *آخری_fuzz;

ساکن خالی
siginfo(صحیح غیر_مستعمل __attribute__((__unused__)))
{
	حرف buf[256];

	test_info(buf, حجم(buf));
	atomicio(vwrite, STDERR_FILENO, buf, لڑی_لمبائی(buf));
	اگر (آخری_fuzz != تہی) {
		fuzz_fmt(آخری_fuzz, buf, حجم(buf));
		atomicio(vwrite, STDERR_FILENO, buf, لڑی_لمبائی(buf));
	}
}

ساخت fuzz *
fuzz_begin(u_int strategies, ثابت خالی *p, سائز_t l)
{
	ساخت fuzz *ret = صفر_حافظہ_دو(1, حجم(*ret));

	أكد(p != تہی);
	أكد(ret != تہی);
	ret->بیج = حافظہ_دو(l);
	أكد(ret->بیج != تہی);
	حافظہ_نقل(ret->بیج, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	أكد(ret->slen < SIZE_MAX / 8);
	أكد(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_اگلا(ret);

	آخری_fuzz = ret;
#اگر_تعریف_شدہ SIGINFO
	اشارہ(SIGINFO, siginfo);
#اگر_ختم
	اشارہ(SIGUSR1, siginfo);

	واپس ret;
}

خالی
fuzz_cleanup(ساخت fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	آخری_fuzz = تہی;
#اگر_تعریف_شدہ SIGINFO
	اشارہ(SIGINFO, SIG_DFL);
#اگر_ختم
	اشارہ(SIGUSR1, SIG_DFL);
	أكد(fuzz != تہی);
	أكد(fuzz->بیج != تہی);
	أكد(fuzz->fuzzed != تہی);
	آزاد(fuzz->بیج);
	آزاد(fuzz->fuzzed);
	آزاد(fuzz);
}

ساکن صحیح
fuzz_strategy_مکمل(ساخت fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_ثنائی_ہندسہ_FLIP:
		واپس fuzz->o1 >= fuzz->slen * 8;
	حالت FUZZ_2_ثنائی_ہندسہ_FLIP:
		واپس fuzz->o2 >= fuzz->slen * 8;
	حالت FUZZ_2_BYTE_FLIP:
		واپس fuzz->o2 >= fuzz->slen;
	حالت FUZZ_1_BYTE_FLIP:
	حالت FUZZ_TRUNCATE_آغاز:
	حالت FUZZ_TRUNCATE_انتہا:
	حالت FUZZ_BASE64:
		واپس fuzz->o1 >= fuzz->slen;
	طےشدہ:
		abort();
	}
}

خالی
fuzz_اگلا(ساخت fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	اگر (fuzz->strategy == 0 || fuzz_strategy_مکمل(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		اگر (fuzz->fuzzed == تہی) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = صفر_حافظہ_دو(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		برائے (i = 1; i <= FUZZ_MAX; i <<= 1) {
			اگر ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				توڑو;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		اگر (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			واپس;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	أكد(fuzz->fuzzed != تہی);

	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_ثنائی_ہندسہ_FLIP:
		أكد(fuzz->o1 / 8 < fuzz->slen);
		حافظہ_نقل(fuzz->fuzzed, fuzz->بیج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		توڑو;
	حالت FUZZ_2_ثنائی_ہندسہ_FLIP:
		أكد(fuzz->o1 / 8 < fuzz->slen);
		أكد(fuzz->o2 / 8 < fuzz->slen);
		حافظہ_نقل(fuzz->fuzzed, fuzz->بیج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		اگر (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		توڑو;
	حالت FUZZ_1_BYTE_FLIP:
		أكد(fuzz->o1 < fuzz->slen);
		حافظہ_نقل(fuzz->fuzzed, fuzz->بیج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		توڑو;
	حالت FUZZ_2_BYTE_FLIP:
		أكد(fuzz->o1 < fuzz->slen);
		أكد(fuzz->o2 < fuzz->slen);
		حافظہ_نقل(fuzz->fuzzed, fuzz->بیج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		اگر (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		توڑو;
	حالت FUZZ_TRUNCATE_آغاز:
	حالت FUZZ_TRUNCATE_انتہا:
		أكد(fuzz->o1 < fuzz->slen);
		حافظہ_نقل(fuzz->fuzzed, fuzz->بیج, fuzz->slen);
		fuzz->o1++;
		توڑو;
	حالت FUZZ_BASE64:
		أكد(fuzz->o1 < fuzz->slen);
		أكد(fuzz->o2 < حجم(fuzz_b64chars) - 1);
		حافظہ_نقل(fuzz->fuzzed, fuzz->بیج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		اگر (fuzz->o2 >= حجم(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		توڑو;
	طےشدہ:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

صحیح
fuzz_matches_original(ساخت fuzz *fuzz)
{
	اگر (fuzz_len(fuzz) != fuzz->slen)
		واپس 0;
	واپس memcmp(fuzz_ptr(fuzz), fuzz->بیج, fuzz->slen) == 0;
}

صحیح
fuzz_مکمل(ساخت fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	واپس fuzz_strategy_مکمل(fuzz) && fuzz->strategies == 0;
}

سائز_t
fuzz_len(ساخت fuzz *fuzz)
{
	أكد(fuzz->fuzzed != تہی);
	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_ثنائی_ہندسہ_FLIP:
	حالت FUZZ_2_ثنائی_ہندسہ_FLIP:
	حالت FUZZ_1_BYTE_FLIP:
	حالت FUZZ_2_BYTE_FLIP:
	حالت FUZZ_BASE64:
		واپس fuzz->slen;
	حالت FUZZ_TRUNCATE_آغاز:
	حالت FUZZ_TRUNCATE_انتہا:
		أكد(fuzz->o1 <= fuzz->slen);
		واپس fuzz->slen - fuzz->o1;
	طےشدہ:
		abort();
	}
}

u_char *
fuzz_ptr(ساخت fuzz *fuzz)
{
	أكد(fuzz->fuzzed != تہی);
	انتخاب (fuzz->strategy) {
	حالت FUZZ_1_ثنائی_ہندسہ_FLIP:
	حالت FUZZ_2_ثنائی_ہندسہ_FLIP:
	حالت FUZZ_1_BYTE_FLIP:
	حالت FUZZ_2_BYTE_FLIP:
	حالت FUZZ_BASE64:
		واپس fuzz->fuzzed;
	حالت FUZZ_TRUNCATE_آغاز:
		أكد(fuzz->o1 <= fuzz->slen);
		واپس fuzz->fuzzed + fuzz->o1;
	حالت FUZZ_TRUNCATE_انتہا:
		أكد(fuzz->o1 <= fuzz->slen);
		واپس fuzz->fuzzed;
	طےشدہ:
		abort();
	}
}

