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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/uio.h>

#അന്തര്ഭാവ <assert.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "test_helper.h"
#അന്തര്ഭാവ "atomicio.h"

/* #define FUZZ_DEBUG */

#ifdef FUZZ_DEBUG
# define FUZZ_DBG(x) ചെയ്യുക { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ആകുമ്പോൾ (0)
#അല്ലെങ്കിൽ
# define FUZZ_DBG(x)
#endif

/* For brevity later */
തരനിർവചനം unsigned long long fuzz_ullong;

/* For base-64 fuzzing */
സ്ഥിതം സ്ഥിരം അക്ഷരം fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ഘടന fuzz {
	/* Fuzz method currently in use */
	പൂർണ്ണസംഖ്യ strategy;

	/* Fuzz methods remaining */
	പൂർണ്ണസംഖ്യ strategies;

	/* Original seed data blob */
	ശൂന്യം *seed;
	size_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	size_t o1, o2;
};

സ്ഥിതം സ്ഥിരം അക്ഷരം *
fuzz_ntop(u_int n)
{
	തിരഞ്ഞെടുപ്പ് (n) {
	അവസ്ഥ 0:
		തിരികെ "NONE";
	അവസ്ഥ FUZZ_1_BIT_FLIP:
		തിരികെ "FUZZ_1_BIT_FLIP";
	അവസ്ഥ FUZZ_2_BIT_FLIP:
		തിരികെ "FUZZ_2_BIT_FLIP";
	അവസ്ഥ FUZZ_1_BYTE_FLIP:
		തിരികെ "FUZZ_1_BYTE_FLIP";
	അവസ്ഥ FUZZ_2_BYTE_FLIP:
		തിരികെ "FUZZ_2_BYTE_FLIP";
	അവസ്ഥ FUZZ_TRUNCATE_START:
		തിരികെ "FUZZ_TRUNCATE_START";
	അവസ്ഥ FUZZ_TRUNCATE_END:
		തിരികെ "FUZZ_TRUNCATE_END";
	അവസ്ഥ FUZZ_BASE64:
		തിരികെ "FUZZ_BASE64";
	സ്ഥിരസ്ഥിതി:
		abort();
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
fuzz_fmt(ഘടന fuzz *fuzz, അക്ഷരം *s, size_t n)
{
	എങ്കിൽ (fuzz == ശൂന്യ)
		തിരികെ -1;

	തിരഞ്ഞെടുപ്പ് (fuzz->strategy) {
	അവസ്ഥ FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		തിരികെ 0;
	അവസ്ഥ FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		തിരികെ 0;
	അവസ്ഥ FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		തിരികെ 0;
	അവസ്ഥ FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		തിരികെ 0;
	അവസ്ഥ FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		തിരികെ 0;
	അവസ്ഥ FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		തിരികെ 0;
	അവസ്ഥ FUZZ_BASE64:
		പ്രതിജ്ഞാ(fuzz->o2 < വലുപ്പം(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിതം ശൂന്യം
dump(u_char *p, size_t len)
{
	size_t i, j;

	വേണ്ടി (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		വേണ്ടി (j = i; j < i + 16; j++) {
			എങ്കിൽ (j < len)
				fprintf(stderr, "%02x ", p[j]);
			അല്ലെങ്കിൽ
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		വേണ്ടി (j = i; j < i + 16; j++) {
			എങ്കിൽ (j < len) {
				എങ്കിൽ  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				അല്ലെങ്കിൽ
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

ശൂന്യം
fuzz_dump(ഘടന fuzz *fuzz)
{
	അക്ഷരം buf[256];

	എങ്കിൽ (fuzz_fmt(fuzz, buf, വലുപ്പം(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

സ്ഥിതം ഘടന fuzz *last_fuzz;

സ്ഥിതം ശൂന്യം
siginfo(പൂർണ്ണസംഖ്യ unused __attribute__((__unused__)))
{
	അക്ഷരം buf[256];

	test_info(buf, വലുപ്പം(buf));
	atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	എങ്കിൽ (last_fuzz != ശൂന്യ) {
		fuzz_fmt(last_fuzz, buf, വലുപ്പം(buf));
		atomicio(vwrite, STDERR_FILENO, buf, strlen(buf));
	}
}

ഘടന fuzz *
fuzz_begin(u_int strategies, സ്ഥിരം ശൂന്യം *p, size_t l)
{
	ഘടന fuzz *ret = calloc(1, വലുപ്പം(*ret));

	പ്രതിജ്ഞാ(p != ശൂന്യ);
	പ്രതിജ്ഞാ(ret != ശൂന്യ);
	ret->seed = malloc(l);
	പ്രതിജ്ഞാ(ret->seed != ശൂന്യ);
	memcpy(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	പ്രതിജ്ഞാ(ret->slen < SIZE_MAX / 8);
	പ്രതിജ്ഞാ(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_next(ret);

	last_fuzz = ret;
#ifdef SIGINFO
	സൂചന(SIGINFO, siginfo);
#endif
	സൂചന(SIGUSR1, siginfo);

	തിരികെ ret;
}

ശൂന്യം
fuzz_cleanup(ഘടന fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = ശൂന്യ;
#ifdef SIGINFO
	സൂചന(SIGINFO, SIG_DFL);
#endif
	സൂചന(SIGUSR1, SIG_DFL);
	പ്രതിജ്ഞാ(fuzz != ശൂന്യ);
	പ്രതിജ്ഞാ(fuzz->seed != ശൂന്യ);
	പ്രതിജ്ഞാ(fuzz->fuzzed != ശൂന്യ);
	സ്വതന്ത്രം(fuzz->seed);
	സ്വതന്ത്രം(fuzz->fuzzed);
	സ്വതന്ത്രം(fuzz);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
fuzz_strategy_done(ഘടന fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	തിരഞ്ഞെടുപ്പ് (fuzz->strategy) {
	അവസ്ഥ FUZZ_1_BIT_FLIP:
		തിരികെ fuzz->o1 >= fuzz->slen * 8;
	അവസ്ഥ FUZZ_2_BIT_FLIP:
		തിരികെ fuzz->o2 >= fuzz->slen * 8;
	അവസ്ഥ FUZZ_2_BYTE_FLIP:
		തിരികെ fuzz->o2 >= fuzz->slen;
	അവസ്ഥ FUZZ_1_BYTE_FLIP:
	അവസ്ഥ FUZZ_TRUNCATE_START:
	അവസ്ഥ FUZZ_TRUNCATE_END:
	അവസ്ഥ FUZZ_BASE64:
		തിരികെ fuzz->o1 >= fuzz->slen;
	സ്ഥിരസ്ഥിതി:
		abort();
	}
}

ശൂന്യം
fuzz_next(ഘടന fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	എങ്കിൽ (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		എങ്കിൽ (fuzz->fuzzed == ശൂന്യ) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = calloc(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		വേണ്ടി (i = 1; i <= FUZZ_MAX; i <<= 1) {
			എങ്കിൽ ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				നിർത്തുക;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		എങ്കിൽ (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			തിരികെ;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	പ്രതിജ്ഞാ(fuzz->fuzzed != ശൂന്യ);

	തിരഞ്ഞെടുപ്പ് (fuzz->strategy) {
	അവസ്ഥ FUZZ_1_BIT_FLIP:
		പ്രതിജ്ഞാ(fuzz->o1 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		നിർത്തുക;
	അവസ്ഥ FUZZ_2_BIT_FLIP:
		പ്രതിജ്ഞാ(fuzz->o1 / 8 < fuzz->slen);
		പ്രതിജ്ഞാ(fuzz->o2 / 8 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		എങ്കിൽ (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		നിർത്തുക;
	അവസ്ഥ FUZZ_1_BYTE_FLIP:
		പ്രതിജ്ഞാ(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		നിർത്തുക;
	അവസ്ഥ FUZZ_2_BYTE_FLIP:
		പ്രതിജ്ഞാ(fuzz->o1 < fuzz->slen);
		പ്രതിജ്ഞാ(fuzz->o2 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		എങ്കിൽ (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		നിർത്തുക;
	അവസ്ഥ FUZZ_TRUNCATE_START:
	അവസ്ഥ FUZZ_TRUNCATE_END:
		പ്രതിജ്ഞാ(fuzz->o1 < fuzz->slen);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		നിർത്തുക;
	അവസ്ഥ FUZZ_BASE64:
		പ്രതിജ്ഞാ(fuzz->o1 < fuzz->slen);
		പ്രതിജ്ഞാ(fuzz->o2 < വലുപ്പം(fuzz_b64chars) - 1);
		memcpy(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		എങ്കിൽ (fuzz->o2 >= വലുപ്പം(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

പൂർണ്ണസംഖ്യ
fuzz_matches_original(ഘടന fuzz *fuzz)
{
	എങ്കിൽ (fuzz_len(fuzz) != fuzz->slen)
		തിരികെ 0;
	തിരികെ memcmp(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

പൂർണ്ണസംഖ്യ
fuzz_done(ഘടന fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	തിരികെ fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

size_t
fuzz_len(ഘടന fuzz *fuzz)
{
	പ്രതിജ്ഞാ(fuzz->fuzzed != ശൂന്യ);
	തിരഞ്ഞെടുപ്പ് (fuzz->strategy) {
	അവസ്ഥ FUZZ_1_BIT_FLIP:
	അവസ്ഥ FUZZ_2_BIT_FLIP:
	അവസ്ഥ FUZZ_1_BYTE_FLIP:
	അവസ്ഥ FUZZ_2_BYTE_FLIP:
	അവസ്ഥ FUZZ_BASE64:
		തിരികെ fuzz->slen;
	അവസ്ഥ FUZZ_TRUNCATE_START:
	അവസ്ഥ FUZZ_TRUNCATE_END:
		പ്രതിജ്ഞാ(fuzz->o1 <= fuzz->slen);
		തിരികെ fuzz->slen - fuzz->o1;
	സ്ഥിരസ്ഥിതി:
		abort();
	}
}

u_char *
fuzz_ptr(ഘടന fuzz *fuzz)
{
	പ്രതിജ്ഞാ(fuzz->fuzzed != ശൂന്യ);
	തിരഞ്ഞെടുപ്പ് (fuzz->strategy) {
	അവസ്ഥ FUZZ_1_BIT_FLIP:
	അവസ്ഥ FUZZ_2_BIT_FLIP:
	അവസ്ഥ FUZZ_1_BYTE_FLIP:
	അവസ്ഥ FUZZ_2_BYTE_FLIP:
	അവസ്ഥ FUZZ_BASE64:
		തിരികെ fuzz->fuzzed;
	അവസ്ഥ FUZZ_TRUNCATE_START:
		പ്രതിജ്ഞാ(fuzz->o1 <= fuzz->slen);
		തിരികെ fuzz->fuzzed + fuzz->o1;
	അവസ്ഥ FUZZ_TRUNCATE_END:
		പ്രതിജ്ഞാ(fuzz->o1 <= fuzz->slen);
		തിരികെ fuzz->fuzzed;
	സ്ഥിരസ്ഥിതി:
		abort();
	}
}

