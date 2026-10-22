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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/uio.h>

#ଅନ୍ତର୍ଭାଵ <assert.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "test_helper.h"
#ଅନ୍ତର୍ଭାଵ "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) କର { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ଯେତେବେଳେ (0)
#ଅନ୍ୟଥା
# define FUZZ_DBG(x)
#endif

/* For brevity later */
ପ୍ରକାରବ୍ୟାଖ୍ୟା unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ସଂରଚନା fuzz {
	/* Fuzz method currently in use */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା strategy;

	/* Fuzz methods remaining */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା strategies;

	/* Original seed data blob */
	ଶୂନ୍ୟ *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
fuzz_ntop(u_int n)
{
	ବାଛ (n) {
	ସ୍ଥିତି 0:
		ଫେରନ୍ତୁ "NONE";
	ସ୍ଥିତି FUZZ_1_BIT_FLIP:
		ଫେରନ୍ତୁ "FUZZ_1_BIT_FLIP";
	ସ୍ଥିତି FUZZ_2_BIT_FLIP:
		ଫେରନ୍ତୁ "FUZZ_2_BIT_FLIP";
	ସ୍ଥିତି FUZZ_1_BYTE_FLIP:
		ଫେରନ୍ତୁ "FUZZ_1_BYTE_FLIP";
	ସ୍ଥିତି FUZZ_2_BYTE_FLIP:
		ଫେରନ୍ତୁ "FUZZ_2_BYTE_FLIP";
	ସ୍ଥିତି FUZZ_TRUNCATE_START:
		ଫେରନ୍ତୁ "FUZZ_TRUNCATE_START";
	ସ୍ଥିତି FUZZ_TRUNCATE_END:
		ଫେରନ୍ତୁ "FUZZ_TRUNCATE_END";
	ସ୍ଥିତି FUZZ_BASE64:
		ଫେରନ୍ତୁ "FUZZ_BASE64";
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		abort();
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fuzz_fmt(ସଂରଚନା fuzz *fuzz, ଅକ୍ଷର *s, size_t n)
{
	ଯଦି (fuzz == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	ବାଛ (fuzz->strategy) {
	ସ୍ଥିତି FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି FUZZ_BASE64:
		ପ୍ରତିଜ୍ଞା(fuzz->o2 < ଆକାର(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
dump(u_char *p, size_t len)
{
	size_t i, j;

	ପାଇଁ (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		ପାଇଁ (j = i; j < i + 16; j++) {
			ଯଦି (j < len)
				fprintf(stderr, "%02x ", p[j]);
			ଅନ୍ୟଥା
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		ପାଇଁ (j = i; j < i + 16; j++) {
			ଯଦି (j < len) {
				ଯଦି  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				ଅନ୍ୟଥା
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

ଶୂନ୍ୟ
fuzz_dump(ସଂରଚନା fuzz *fuzz)
{
	ଅକ୍ଷର buf[256];

	ଯଦି (fuzz_fmt(fuzz, buf, ଆକାର(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

ସ୍ଥିର ସଂରଚନା fuzz *last_fuzz;

ସ୍ଥିର ଶୂନ୍ୟ
siginfo(ପୂର୍ଣ୍ଣସଂଖ୍ୟା unused __attribute__((__unused__)))
{
	ଅକ୍ଷର buf[256];

	test_info(buf, ଆକାର(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	ଯଦି (last_fuzz != ଖାଲି) {
		fuzz_fmt(last_fuzz, buf, ଆକାର(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

ସଂରଚନା fuzz *
fuzz_begin(u_int strategies, ଅଚଳ ଶୂନ୍ୟ *p, size_t l)
{
	ସଂରଚନା fuzz *ret = calloc(1, ଆକାର(*ret));

	ପ୍ରତିଜ୍ଞା(p != ଖାଲି);
	ପ୍ରତିଜ୍ଞା(ret != ଖାଲି);
	ret->seed = malloc(l);
	ପ୍ରତିଜ୍ଞା(ret->seed != ଖାଲି);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	ପ୍ରତିଜ୍ଞା(ret->slen < SIZE_MAX / 8);
	ପ୍ରତିଜ୍ଞା(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	ସଙ୍କେତ(SIGINFO, siginfo);
#endif
	ସଙ୍କେତ(SIGUSR1, siginfo);

	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
fuzz_cleanup(ସଂରଚନା fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = ଖାଲି;
#ifdef SIGINFO
	ସଙ୍କେତ(SIGINFO, SIG_DFL);
#endif
	ସଙ୍କେତ(SIGUSR1, SIG_DFL);
	ପ୍ରତିଜ୍ଞା(fuzz != ଖାଲି);
	ପ୍ରତିଜ୍ଞା(fuzz->seed != ଖାଲି);
	ପ୍ରତିଜ୍ଞା(fuzz->fuzzed != ଖାଲି);
	ମୁକ୍ତ(fuzz->seed);
	ମୁକ୍ତ(fuzz->fuzzed);
	ମୁକ୍ତ(fuzz);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fuzz_strategy_done(ସଂରଚନା fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	ବାଛ (fuzz->strategy) {
	ସ୍ଥିତି FUZZ_1_BIT_FLIP:
		ଫେରନ୍ତୁ fuzz->o1 >= fuzz->slen * 8;
	ସ୍ଥିତି FUZZ_2_BIT_FLIP:
		ଫେରନ୍ତୁ fuzz->o2 >= fuzz->slen * 8;
	ସ୍ଥିତି FUZZ_2_BYTE_FLIP:
		ଫେରନ୍ତୁ fuzz->o2 >= fuzz->slen;
	ସ୍ଥିତି FUZZ_1_BYTE_FLIP:
	ସ୍ଥିତି FUZZ_TRUNCATE_START:
	ସ୍ଥିତି FUZZ_TRUNCATE_END:
	ସ୍ଥିତି FUZZ_BASE64:
		ଫେରନ୍ତୁ fuzz->o1 >= fuzz->slen;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		abort();
	}
}

ଶୂନ୍ୟ
fuzz_next(ସଂରଚନା fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	ଯଦି (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		ଯଦି (fuzz->fuzzed == ଖାଲି) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		ପାଇଁ (i = 1; i <= FUZZ_MAX; i <<= 1) {
			ଯଦି ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				ଭାଙ୍ଗ;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		ଯଦି (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			ଫେରନ୍ତୁ;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	ପ୍ରତିଜ୍ଞା(fuzz->fuzzed != ଖାଲି);

	ବାଛ (fuzz->strategy) {
	ସ୍ଥିତି FUZZ_1_BIT_FLIP:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FUZZ_2_BIT_FLIP:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 / 8 < fuzz->slen);
		ପ୍ରତିଜ୍ଞା(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		ଯଦି (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FUZZ_1_BYTE_FLIP:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FUZZ_2_BYTE_FLIP:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 < fuzz->slen);
		ପ୍ରତିଜ୍ଞା(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		ଯଦି (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FUZZ_TRUNCATE_START:
	ସ୍ଥିତି FUZZ_TRUNCATE_END:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି FUZZ_BASE64:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 < fuzz->slen);
		ପ୍ରତିଜ୍ଞା(fuzz->o2 < ଆକାର(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		ଯଦି (fuzz->o2 >= ଆକାର(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fuzz_matches_original(ସଂରଚନା fuzz *fuzz)
{
	ଯଦି (fuzz_len(fuzz) != fuzz->slen)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fuzz_done(ସଂରଚନା fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	ଫେରନ୍ତୁ fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(ସଂରଚନା fuzz *fuzz)
{
	ପ୍ରତିଜ୍ଞା(fuzz->fuzzed != ଖାଲି);
	ବାଛ (fuzz->strategy) {
	ସ୍ଥିତି FUZZ_1_BIT_FLIP:
	ସ୍ଥିତି FUZZ_2_BIT_FLIP:
	ସ୍ଥିତି FUZZ_1_BYTE_FLIP:
	ସ୍ଥିତି FUZZ_2_BYTE_FLIP:
	ସ୍ଥିତି FUZZ_BASE64:
		ଫେରନ୍ତୁ fuzz->slen;
	ସ୍ଥିତି FUZZ_TRUNCATE_START:
	ସ୍ଥିତି FUZZ_TRUNCATE_END:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 <= fuzz->slen);
		ଫେରନ୍ତୁ fuzz->slen - fuzz->o1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		abort();
	}
}

u_char *
fuzz_ptr(ସଂରଚନା fuzz *fuzz)
{
	ପ୍ରତିଜ୍ଞା(fuzz->fuzzed != ଖାଲି);
	ବାଛ (fuzz->strategy) {
	ସ୍ଥିତି FUZZ_1_BIT_FLIP:
	ସ୍ଥିତି FUZZ_2_BIT_FLIP:
	ସ୍ଥିତି FUZZ_1_BYTE_FLIP:
	ସ୍ଥିତି FUZZ_2_BYTE_FLIP:
	ସ୍ଥିତି FUZZ_BASE64:
		ଫେରନ୍ତୁ fuzz->fuzzed;
	ସ୍ଥିତି FUZZ_TRUNCATE_START:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 <= fuzz->slen);
		ଫେରନ୍ତୁ fuzz->fuzzed + fuzz->o1;
	ସ୍ଥିତି FUZZ_TRUNCATE_END:
		ପ୍ରତିଜ୍ଞା(fuzz->o1 <= fuzz->slen);
		ଫେରନ୍ତୁ fuzz->fuzzed;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		abort();
	}
}

