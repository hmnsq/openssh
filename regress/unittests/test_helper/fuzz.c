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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/uio.h>

#अन्तर्भाव <assert.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "test_helper.h"
#अन्तर्भाव "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) कुरु { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} यावत् (0)
#अन्यथा
# define FUZZ_DBG(x)
#endif

/* For brevity later */
प्रकारनिर्देश unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
स्थिर ध्रुव वर्ण fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

संरचना fuzz {
	/* Fuzz method currently in use */
	पूर्णाङ्क strategy;

	/* Fuzz methods remaining */
	पूर्णाङ्क strategies;

	/* Original seed data blob */
	शून्य *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

स्थिर ध्रुव वर्ण *
fuzz_ntop(u_int n)
{
	विकल्प (n) {
	पक्ष 0:
		प्रत्यागम "NONE";
	पक्ष FUZZ_1_BIT_FLIP:
		प्रत्यागम "FUZZ_1_BIT_FLIP";
	पक्ष FUZZ_2_BIT_FLIP:
		प्रत्यागम "FUZZ_2_BIT_FLIP";
	पक्ष FUZZ_1_BYTE_FLIP:
		प्रत्यागम "FUZZ_1_BYTE_FLIP";
	पक्ष FUZZ_2_BYTE_FLIP:
		प्रत्यागम "FUZZ_2_BYTE_FLIP";
	पक्ष FUZZ_TRUNCATE_START:
		प्रत्यागम "FUZZ_TRUNCATE_START";
	पक्ष FUZZ_TRUNCATE_END:
		प्रत्यागम "FUZZ_TRUNCATE_END";
	पक्ष FUZZ_BASE64:
		प्रत्यागम "FUZZ_BASE64";
	स्वभाव:
		abort();
	}
}

स्थिर पूर्णाङ्क
fuzz_fmt(संरचना fuzz *fuzz, वर्ण *s, size_t n)
{
	यदि (fuzz == रिक्त)
		प्रत्यागम -1;

	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		प्रत्यागम 0;
	पक्ष FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		प्रत्यागम 0;
	पक्ष FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		प्रत्यागम 0;
	पक्ष FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		प्रत्यागम 0;
	पक्ष FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		प्रत्यागम 0;
	पक्ष FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		प्रत्यागम 0;
	पक्ष FUZZ_BASE64:
		प्रतिज्ञा(fuzz->o2 < परिमाण(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम -1;
	}
}

स्थिर शून्य
dump(u_char *p, size_t len)
{
	size_t i, j;

	प्रति (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		प्रति (j = i; j < i + 16; j++) {
			यदि (j < len)
				fprintf(stderr, "%02x ", p[j]);
			अन्यथा
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		प्रति (j = i; j < i + 16; j++) {
			यदि (j < len) {
				यदि  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				अन्यथा
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

शून्य
fuzz_dump(संरचना fuzz *fuzz)
{
	वर्ण buf[256];

	यदि (fuzz_fmt(fuzz, buf, परिमाण(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

स्थिर संरचना fuzz *last_fuzz;

स्थिर शून्य
siginfo(पूर्णाङ्क unused __attribute__((__unused__)))
{
	वर्ण buf[256];

	test_info(buf, परिमाण(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	यदि (last_fuzz != रिक्त) {
		fuzz_fmt(last_fuzz, buf, परिमाण(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

संरचना fuzz *
fuzz_begin(u_int strategies, ध्रुव शून्य *p, size_t l)
{
	संरचना fuzz *ret = calloc(1, परिमाण(*ret));

	प्रतिज्ञा(p != रिक्त);
	प्रतिज्ञा(ret != रिक्त);
	ret->seed = malloc(l);
	प्रतिज्ञा(ret->seed != रिक्त);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	प्रतिज्ञा(ret->slen < SIZE_MAX / 8);
	प्रतिज्ञा(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	सङ्केत(SIGINFO, siginfo);
#endif
	सङ्केत(SIGUSR1, siginfo);

	प्रत्यागम ret;
}

शून्य
fuzz_cleanup(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = रिक्त;
#ifdef SIGINFO
	सङ्केत(SIGINFO, SIG_DFL);
#endif
	सङ्केत(SIGUSR1, SIG_DFL);
	प्रतिज्ञा(fuzz != रिक्त);
	प्रतिज्ञा(fuzz->seed != रिक्त);
	प्रतिज्ञा(fuzz->fuzzed != रिक्त);
	मुक्त(fuzz->seed);
	मुक्त(fuzz->fuzzed);
	मुक्त(fuzz);
}

स्थिर पूर्णाङ्क
fuzz_strategy_done(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
		प्रत्यागम fuzz->o1 >= fuzz->slen * 8;
	पक्ष FUZZ_2_BIT_FLIP:
		प्रत्यागम fuzz->o2 >= fuzz->slen * 8;
	पक्ष FUZZ_2_BYTE_FLIP:
		प्रत्यागम fuzz->o2 >= fuzz->slen;
	पक्ष FUZZ_1_BYTE_FLIP:
	पक्ष FUZZ_TRUNCATE_START:
	पक्ष FUZZ_TRUNCATE_END:
	पक्ष FUZZ_BASE64:
		प्रत्यागम fuzz->o1 >= fuzz->slen;
	स्वभाव:
		abort();
	}
}

शून्य
fuzz_next(संरचना fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	यदि (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		यदि (fuzz->fuzzed == रिक्त) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		प्रति (i = 1; i <= FUZZ_MAX; i <<= 1) {
			यदि ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				भङ्ग;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		यदि (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			प्रत्यागम;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	प्रतिज्ञा(fuzz->fuzzed != रिक्त);

	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
		प्रतिज्ञा(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		भङ्ग;
	पक्ष FUZZ_2_BIT_FLIP:
		प्रतिज्ञा(fuzz->o1 / 8 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		यदि (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		भङ्ग;
	पक्ष FUZZ_1_BYTE_FLIP:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		भङ्ग;
	पक्ष FUZZ_2_BYTE_FLIP:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		यदि (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		भङ्ग;
	पक्ष FUZZ_TRUNCATE_START:
	पक्ष FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		भङ्ग;
	पक्ष FUZZ_BASE64:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 < परिमाण(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		यदि (fuzz->o2 >= परिमाण(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		भङ्ग;
	स्वभाव:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

पूर्णाङ्क
fuzz_matches_original(संरचना fuzz *fuzz)
{
	यदि (fuzz_len(fuzz) != fuzz->slen)
		प्रत्यागम 0;
	प्रत्यागम memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

पूर्णाङ्क
fuzz_done(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	प्रत्यागम fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(संरचना fuzz *fuzz)
{
	प्रतिज्ञा(fuzz->fuzzed != रिक्त);
	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
	पक्ष FUZZ_2_BIT_FLIP:
	पक्ष FUZZ_1_BYTE_FLIP:
	पक्ष FUZZ_2_BYTE_FLIP:
	पक्ष FUZZ_BASE64:
		प्रत्यागम fuzz->slen;
	पक्ष FUZZ_TRUNCATE_START:
	पक्ष FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		प्रत्यागम fuzz->slen - fuzz->o1;
	स्वभाव:
		abort();
	}
}

u_char *
fuzz_ptr(संरचना fuzz *fuzz)
{
	प्रतिज्ञा(fuzz->fuzzed != रिक्त);
	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
	पक्ष FUZZ_2_BIT_FLIP:
	पक्ष FUZZ_1_BYTE_FLIP:
	पक्ष FUZZ_2_BYTE_FLIP:
	पक्ष FUZZ_BASE64:
		प्रत्यागम fuzz->fuzzed;
	पक्ष FUZZ_TRUNCATE_START:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		प्रत्यागम fuzz->fuzzed + fuzz->o1;
	पक्ष FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		प्रत्यागम fuzz->fuzzed;
	स्वभाव:
		abort();
	}
}

