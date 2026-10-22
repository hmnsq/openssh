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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/uio.h>

#અન્તર્ભાવ <assert.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "test_helper.h"
#અન્તર્ભાવ "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) કરો { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} જ્યારે (0)
#નહીંતર
# define FUZZ_DBG(x)
#endif

/* For brevity later */
પ્રકારવ્યાખ્યા unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
સ્થિર અચલ અક્ષર fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

સંરચના fuzz {
	/* Fuzz method currently in use */
	પૂર્ણાંક strategy;

	/* Fuzz methods remaining */
	પૂર્ણાંક strategies;

	/* Original seed data blob */
	શૂન્ય *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

સ્થિર અચલ અક્ષર *
fuzz_ntop(u_int n)
{
	પસંદગી (n) {
	સ્થિતિ 0:
		પાછા "NONE";
	સ્થિતિ FUZZ_1_BIT_FLIP:
		પાછા "FUZZ_1_BIT_FLIP";
	સ્થિતિ FUZZ_2_BIT_FLIP:
		પાછા "FUZZ_2_BIT_FLIP";
	સ્થિતિ FUZZ_1_BYTE_FLIP:
		પાછા "FUZZ_1_BYTE_FLIP";
	સ્થિતિ FUZZ_2_BYTE_FLIP:
		પાછા "FUZZ_2_BYTE_FLIP";
	સ્થિતિ FUZZ_TRUNCATE_START:
		પાછા "FUZZ_TRUNCATE_START";
	સ્થિતિ FUZZ_TRUNCATE_END:
		પાછા "FUZZ_TRUNCATE_END";
	સ્થિતિ FUZZ_BASE64:
		પાછા "FUZZ_BASE64";
	મૂળભૂત:
		abort();
	}
}

સ્થિર પૂર્ણાંક
fuzz_fmt(સંરચના fuzz *fuzz, અક્ષર *s, size_t n)
{
	જો (fuzz == ખાલી)
		પાછા -1;

	પસંદગી (fuzz->strategy) {
	સ્થિતિ FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		પાછા 0;
	સ્થિતિ FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		પાછા 0;
	સ્થિતિ FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		પાછા 0;
	સ્થિતિ FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		પાછા 0;
	સ્થિતિ FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		પાછા 0;
	સ્થિતિ FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		પાછા 0;
	સ્થિતિ FUZZ_BASE64:
		પ્રતિજ્ઞા(fuzz->o2 < કદ(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		પાછા 0;
	મૂળભૂત:
		પાછા -1;
	}
}

સ્થિર શૂન્ય
dump(u_char *p, size_t len)
{
	size_t i, j;

	માટે (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		માટે (j = i; j < i + 16; j++) {
			જો (j < len)
				fprintf(stderr, "%02x ", p[j]);
			નહીંતર
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		માટે (j = i; j < i + 16; j++) {
			જો (j < len) {
				જો  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				નહીંતર
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

શૂન્ય
fuzz_dump(સંરચના fuzz *fuzz)
{
	અક્ષર buf[256];

	જો (fuzz_fmt(fuzz, buf, કદ(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

સ્થિર સંરચના fuzz *last_fuzz;

સ્થિર શૂન્ય
siginfo(પૂર્ણાંક unused __attribute__((__unused__)))
{
	અક્ષર buf[256];

	test_info(buf, કદ(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	જો (last_fuzz != ખાલી) {
		fuzz_fmt(last_fuzz, buf, કદ(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

સંરચના fuzz *
fuzz_begin(u_int strategies, અચલ શૂન્ય *p, size_t l)
{
	સંરચના fuzz *ret = calloc(1, કદ(*ret));

	પ્રતિજ્ઞા(p != ખાલી);
	પ્રતિજ્ઞા(ret != ખાલી);
	ret->seed = malloc(l);
	પ્રતિજ્ઞા(ret->seed != ખાલી);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	પ્રતિજ્ઞા(ret->slen < SIZE_MAX / 8);
	પ્રતિજ્ઞા(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	સંકેત(SIGINFO, siginfo);
#endif
	સંકેત(SIGUSR1, siginfo);

	પાછા ret;
}

શૂન્ય
fuzz_cleanup(સંરચના fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = ખાલી;
#ifdef SIGINFO
	સંકેત(SIGINFO, SIG_DFL);
#endif
	સંકેત(SIGUSR1, SIG_DFL);
	પ્રતિજ્ઞા(fuzz != ખાલી);
	પ્રતિજ્ઞા(fuzz->seed != ખાલી);
	પ્રતિજ્ઞા(fuzz->fuzzed != ખાલી);
	મુક્ત(fuzz->seed);
	મુક્ત(fuzz->fuzzed);
	મુક્ત(fuzz);
}

સ્થિર પૂર્ણાંક
fuzz_strategy_done(સંરચના fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	પસંદગી (fuzz->strategy) {
	સ્થિતિ FUZZ_1_BIT_FLIP:
		પાછા fuzz->o1 >= fuzz->slen * 8;
	સ્થિતિ FUZZ_2_BIT_FLIP:
		પાછા fuzz->o2 >= fuzz->slen * 8;
	સ્થિતિ FUZZ_2_BYTE_FLIP:
		પાછા fuzz->o2 >= fuzz->slen;
	સ્થિતિ FUZZ_1_BYTE_FLIP:
	સ્થિતિ FUZZ_TRUNCATE_START:
	સ્થિતિ FUZZ_TRUNCATE_END:
	સ્થિતિ FUZZ_BASE64:
		પાછા fuzz->o1 >= fuzz->slen;
	મૂળભૂત:
		abort();
	}
}

શૂન્ય
fuzz_next(સંરચના fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	જો (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		જો (fuzz->fuzzed == ખાલી) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		માટે (i = 1; i <= FUZZ_MAX; i <<= 1) {
			જો ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				તોડો;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		જો (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			પાછા;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	પ્રતિજ્ઞા(fuzz->fuzzed != ખાલી);

	પસંદગી (fuzz->strategy) {
	સ્થિતિ FUZZ_1_BIT_FLIP:
		પ્રતિજ્ઞા(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		તોડો;
	સ્થિતિ FUZZ_2_BIT_FLIP:
		પ્રતિજ્ઞા(fuzz->o1 / 8 < fuzz->slen);
		પ્રતિજ્ઞા(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		જો (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		તોડો;
	સ્થિતિ FUZZ_1_BYTE_FLIP:
		પ્રતિજ્ઞા(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		તોડો;
	સ્થિતિ FUZZ_2_BYTE_FLIP:
		પ્રતિજ્ઞા(fuzz->o1 < fuzz->slen);
		પ્રતિજ્ઞા(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		જો (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		તોડો;
	સ્થિતિ FUZZ_TRUNCATE_START:
	સ્થિતિ FUZZ_TRUNCATE_END:
		પ્રતિજ્ઞા(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		તોડો;
	સ્થિતિ FUZZ_BASE64:
		પ્રતિજ્ઞા(fuzz->o1 < fuzz->slen);
		પ્રતિજ્ઞા(fuzz->o2 < કદ(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		જો (fuzz->o2 >= કદ(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		તોડો;
	મૂળભૂત:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

પૂર્ણાંક
fuzz_matches_original(સંરચના fuzz *fuzz)
{
	જો (fuzz_len(fuzz) != fuzz->slen)
		પાછા 0;
	પાછા memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

પૂર્ણાંક
fuzz_done(સંરચના fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	પાછા fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(સંરચના fuzz *fuzz)
{
	પ્રતિજ્ઞા(fuzz->fuzzed != ખાલી);
	પસંદગી (fuzz->strategy) {
	સ્થિતિ FUZZ_1_BIT_FLIP:
	સ્થિતિ FUZZ_2_BIT_FLIP:
	સ્થિતિ FUZZ_1_BYTE_FLIP:
	સ્થિતિ FUZZ_2_BYTE_FLIP:
	સ્થિતિ FUZZ_BASE64:
		પાછા fuzz->slen;
	સ્થિતિ FUZZ_TRUNCATE_START:
	સ્થિતિ FUZZ_TRUNCATE_END:
		પ્રતિજ્ઞા(fuzz->o1 <= fuzz->slen);
		પાછા fuzz->slen - fuzz->o1;
	મૂળભૂત:
		abort();
	}
}

u_char *
fuzz_ptr(સંરચના fuzz *fuzz)
{
	પ્રતિજ્ઞા(fuzz->fuzzed != ખાલી);
	પસંદગી (fuzz->strategy) {
	સ્થિતિ FUZZ_1_BIT_FLIP:
	સ્થિતિ FUZZ_2_BIT_FLIP:
	સ્થિતિ FUZZ_1_BYTE_FLIP:
	સ્થિતિ FUZZ_2_BYTE_FLIP:
	સ્થિતિ FUZZ_BASE64:
		પાછા fuzz->fuzzed;
	સ્થિતિ FUZZ_TRUNCATE_START:
		પ્રતિજ્ઞા(fuzz->o1 <= fuzz->slen);
		પાછા fuzz->fuzzed + fuzz->o1;
	સ્થિતિ FUZZ_TRUNCATE_END:
		પ્રતિજ્ઞા(fuzz->o1 <= fuzz->slen);
		પાછા fuzz->fuzzed;
	મૂળભૂત:
		abort();
	}
}

