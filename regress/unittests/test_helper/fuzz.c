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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/uio.h>

#ضمن <assert.h>
#ضمن <ctype.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <unistd.h>

#ضمن "test_helper.h"
#ضمن "atomicio.h"

/* #define FUZZ_DEBUG */

#جيڪڏهن_وصف_ٿيل FUZZ_DEBUG
# define FUZZ_DBG(x) افعل { \
		لکو("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		لکو x; \
		لکو("\n"); \
		fflush(stdout); \
	} طالما (0)
#وإلا
# define FUZZ_DBG(x)
#جيڪڏهن_پورو

/* For brevity later */
تعريفنوع بنانشان ڊگهو ڊگهو fuzz_ullong;

/* For base-64 fuzzing */
ساكن ثابت حرف fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

بنية fuzz {
	/* Fuzz method currently in use */
	صحيح strategy;

	/* Fuzz methods remaining */
	صحيح strategies;

	/* Original seed data blob */
	فراغ *ٻج;
	سائيز_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	سائيز_t o1, o2;
};

ساكن ثابت حرف *
fuzz_ntop(u_int n)
{
	بدل (n) {
	حالة 0:
		أرجع "NONE";
	حالة FUZZ_1_ٻٽو_انگ_FLIP:
		أرجع "FUZZ_1_BIT_FLIP";
	حالة FUZZ_2_ٻٽو_انگ_FLIP:
		أرجع "FUZZ_2_BIT_FLIP";
	حالة FUZZ_1_BYTE_FLIP:
		أرجع "FUZZ_1_BYTE_FLIP";
	حالة FUZZ_2_BYTE_FLIP:
		أرجع "FUZZ_2_BYTE_FLIP";
	حالة FUZZ_TRUNCATE_شروعات:
		أرجع "FUZZ_TRUNCATE_START";
	حالة FUZZ_TRUNCATE_پڇاڙي:
		أرجع "FUZZ_TRUNCATE_END";
	حالة FUZZ_BASE64:
		أرجع "FUZZ_BASE64";
	افتراضي:
		abort();
	}
}

ساكن صحيح
fuzz_fmt(بنية fuzz *fuzz, حرف *s, سائيز_t n)
{
	إذا (fuzz == عدم)
		أرجع -1;

	بدل (fuzz->strategy) {
	حالة FUZZ_1_ٻٽو_انگ_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		أرجع 0;
	حالة FUZZ_2_ٻٽو_انگ_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		أرجع 0;
	حالة FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		أرجع 0;
	حالة FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		أرجع 0;
	حالة FUZZ_TRUNCATE_شروعات:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		أرجع 0;
	حالة FUZZ_TRUNCATE_پڇاڙي:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		أرجع 0;
	حالة FUZZ_BASE64:
		أكد(fuzz->o2 < حجم(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		أرجع 0;
	افتراضي:
		أرجع -1;
	}
}

ساكن فراغ
dump(u_char *p, سائيز_t len)
{
	سائيز_t i, j;

	لكل (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		لكل (j = i; j < i + 16; j++) {
			إذا (j < len)
				fprintf(stderr, "%02x ", p[j]);
			وإلا
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		لكل (j = i; j < i + 16; j++) {
			إذا (j < len) {
				إذا  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				وإلا
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

فراغ
fuzz_dump(بنية fuzz *fuzz)
{
	حرف buf[256];

	إذا (fuzz_fmt(fuzz, buf, حجم(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->ٻج, fuzz->slen);
	dump(fuzz->ٻج, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

ساكن بنية fuzz *آخري_fuzz;

ساكن فراغ
siginfo(صحيح اڻ_استعمال_ٿيل __attribute__((__unused__)))
{
	حرف buf[256];

	test_info(buf, حجم(buf));
	atomicio(vwrite, STDERR_FILENO, buf, لڙي_ڊيگهه(buf));
	إذا (آخري_fuzz != عدم) {
		fuzz_fmt(آخري_fuzz, buf, حجم(buf));
		atomicio(vwrite, STDERR_FILENO, buf, لڙي_ڊيگهه(buf));
	}
}

بنية fuzz *
fuzz_begin(u_int strategies, ثابت فراغ *p, سائيز_t l)
{
	بنية fuzz *ret = صفر_يادگيري_ڏيو(1, حجم(*ret));

	أكد(p != عدم);
	أكد(ret != عدم);
	ret->ٻج = يادگيري_ڏيو(l);
	أكد(ret->ٻج != عدم);
	يادگيري_نقل(ret->ٻج, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	أكد(ret->slen < SIZE_MAX / 8);
	أكد(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_ايندڙ(ret);

	آخري_fuzz = ret;
#جيڪڏهن_وصف_ٿيل SIGINFO
	إشارة(SIGINFO, siginfo);
#جيڪڏهن_پورو
	إشارة(SIGUSR1, siginfo);

	أرجع ret;
}

فراغ
fuzz_cleanup(بنية fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	آخري_fuzz = عدم;
#جيڪڏهن_وصف_ٿيل SIGINFO
	إشارة(SIGINFO, SIG_DFL);
#جيڪڏهن_پورو
	إشارة(SIGUSR1, SIG_DFL);
	أكد(fuzz != عدم);
	أكد(fuzz->ٻج != عدم);
	أكد(fuzz->fuzzed != عدم);
	حرر(fuzz->ٻج);
	حرر(fuzz->fuzzed);
	حرر(fuzz);
}

ساكن صحيح
fuzz_strategy_پورو(بنية fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	بدل (fuzz->strategy) {
	حالة FUZZ_1_ٻٽو_انگ_FLIP:
		أرجع fuzz->o1 >= fuzz->slen * 8;
	حالة FUZZ_2_ٻٽو_انگ_FLIP:
		أرجع fuzz->o2 >= fuzz->slen * 8;
	حالة FUZZ_2_BYTE_FLIP:
		أرجع fuzz->o2 >= fuzz->slen;
	حالة FUZZ_1_BYTE_FLIP:
	حالة FUZZ_TRUNCATE_شروعات:
	حالة FUZZ_TRUNCATE_پڇاڙي:
	حالة FUZZ_BASE64:
		أرجع fuzz->o1 >= fuzz->slen;
	افتراضي:
		abort();
	}
}

فراغ
fuzz_ايندڙ(بنية fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	إذا (fuzz->strategy == 0 || fuzz_strategy_پورو(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		إذا (fuzz->fuzzed == عدم) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = صفر_يادگيري_ڏيو(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		لكل (i = 1; i <= FUZZ_MAX; i <<= 1) {
			إذا ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				اكسر;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		إذا (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			أرجع;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	أكد(fuzz->fuzzed != عدم);

	بدل (fuzz->strategy) {
	حالة FUZZ_1_ٻٽو_انگ_FLIP:
		أكد(fuzz->o1 / 8 < fuzz->slen);
		يادگيري_نقل(fuzz->fuzzed, fuzz->ٻج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		اكسر;
	حالة FUZZ_2_ٻٽو_انگ_FLIP:
		أكد(fuzz->o1 / 8 < fuzz->slen);
		أكد(fuzz->o2 / 8 < fuzz->slen);
		يادگيري_نقل(fuzz->fuzzed, fuzz->ٻج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		إذا (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		اكسر;
	حالة FUZZ_1_BYTE_FLIP:
		أكد(fuzz->o1 < fuzz->slen);
		يادگيري_نقل(fuzz->fuzzed, fuzz->ٻج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		اكسر;
	حالة FUZZ_2_BYTE_FLIP:
		أكد(fuzz->o1 < fuzz->slen);
		أكد(fuzz->o2 < fuzz->slen);
		يادگيري_نقل(fuzz->fuzzed, fuzz->ٻج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		إذا (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		اكسر;
	حالة FUZZ_TRUNCATE_شروعات:
	حالة FUZZ_TRUNCATE_پڇاڙي:
		أكد(fuzz->o1 < fuzz->slen);
		يادگيري_نقل(fuzz->fuzzed, fuzz->ٻج, fuzz->slen);
		fuzz->o1++;
		اكسر;
	حالة FUZZ_BASE64:
		أكد(fuzz->o1 < fuzz->slen);
		أكد(fuzz->o2 < حجم(fuzz_b64chars) - 1);
		يادگيري_نقل(fuzz->fuzzed, fuzz->ٻج, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		إذا (fuzz->o2 >= حجم(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		اكسر;
	افتراضي:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

صحيح
fuzz_matches_original(بنية fuzz *fuzz)
{
	إذا (fuzz_len(fuzz) != fuzz->slen)
		أرجع 0;
	أرجع memcmp(fuzz_ptr(fuzz), fuzz->ٻج, fuzz->slen) == 0;
}

صحيح
fuzz_پورو(بنية fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	أرجع fuzz_strategy_پورو(fuzz) && fuzz->strategies == 0;
}

سائيز_t
fuzz_len(بنية fuzz *fuzz)
{
	أكد(fuzz->fuzzed != عدم);
	بدل (fuzz->strategy) {
	حالة FUZZ_1_ٻٽو_انگ_FLIP:
	حالة FUZZ_2_ٻٽو_انگ_FLIP:
	حالة FUZZ_1_BYTE_FLIP:
	حالة FUZZ_2_BYTE_FLIP:
	حالة FUZZ_BASE64:
		أرجع fuzz->slen;
	حالة FUZZ_TRUNCATE_شروعات:
	حالة FUZZ_TRUNCATE_پڇاڙي:
		أكد(fuzz->o1 <= fuzz->slen);
		أرجع fuzz->slen - fuzz->o1;
	افتراضي:
		abort();
	}
}

u_char *
fuzz_ptr(بنية fuzz *fuzz)
{
	أكد(fuzz->fuzzed != عدم);
	بدل (fuzz->strategy) {
	حالة FUZZ_1_ٻٽو_انگ_FLIP:
	حالة FUZZ_2_ٻٽو_انگ_FLIP:
	حالة FUZZ_1_BYTE_FLIP:
	حالة FUZZ_2_BYTE_FLIP:
	حالة FUZZ_BASE64:
		أرجع fuzz->fuzzed;
	حالة FUZZ_TRUNCATE_شروعات:
		أكد(fuzz->o1 <= fuzz->slen);
		أرجع fuzz->fuzzed + fuzz->o1;
	حالة FUZZ_TRUNCATE_پڇاڙي:
		أكد(fuzz->o1 <= fuzz->slen);
		أرجع fuzz->fuzzed;
	افتراضي:
		abort();
	}
}

