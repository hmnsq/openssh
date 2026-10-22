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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/uio.h>

#అన్తర్భావ <assert.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "test_helper.h"
#అన్తర్భావ "atomicio.h"

/* #define FUZZ_DEBUG */

#నిర్వచితమైతే FUZZ_DEBUG
# define FUZZ_DBG(x) చేయి { \
		రాయి("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		రాయి x; \
		రాయి("\n"); \
		fflush(stdout); \
	} అయితే (0)
#లేకపోతే
# define FUZZ_DBG(x)
#అయితే_ముగింపు

/* For brevity later */
రకనిర్వచనం గుర్తులేని దీర్ఘ దీర్ఘ fuzz_ullong;

/* For base-64 fuzzing */
స్థిర స్థిరరాశి అక్షరం fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

నిర్మాణం fuzz {
	/* Fuzz method currently in use */
	పూర్ణాంకం strategy;

	/* Fuzz methods remaining */
	పూర్ణాంకం strategies;

	/* Original seed data blob */
	శూన్య *విత్తనం;
	కొలత_t slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	కొలత_t o1, o2;
};

స్థిర స్థిరరాశి అక్షరం *
fuzz_ntop(u_int n)
{
	ఎంపిక (n) {
	స్థితి 0:
		తిరిగి "NONE";
	స్థితి FUZZ_1_బిట్టు_FLIP:
		తిరిగి "FUZZ_1_BIT_FLIP";
	స్థితి FUZZ_2_బిట్టు_FLIP:
		తిరిగి "FUZZ_2_BIT_FLIP";
	స్థితి FUZZ_1_BYTE_FLIP:
		తిరిగి "FUZZ_1_BYTE_FLIP";
	స్థితి FUZZ_2_BYTE_FLIP:
		తిరిగి "FUZZ_2_BYTE_FLIP";
	స్థితి FUZZ_TRUNCATE_ప్రారంభం:
		తిరిగి "FUZZ_TRUNCATE_START";
	స్థితి FUZZ_TRUNCATE_చివర:
		తిరిగి "FUZZ_TRUNCATE_END";
	స్థితి FUZZ_BASE64:
		తిరిగి "FUZZ_BASE64";
	అప్రమేయ:
		abort();
	}
}

స్థిర పూర్ణాంకం
fuzz_fmt(నిర్మాణం fuzz *fuzz, అక్షరం *s, కొలత_t n)
{
	ఒకవేళ (fuzz == ఖాళీ)
		తిరిగి -1;

	ఎంపిక (fuzz->strategy) {
	స్థితి FUZZ_1_బిట్టు_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		తిరిగి 0;
	స్థితి FUZZ_2_బిట్టు_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		తిరిగి 0;
	స్థితి FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		తిరిగి 0;
	స్థితి FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		తిరిగి 0;
	స్థితి FUZZ_TRUNCATE_ప్రారంభం:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		తిరిగి 0;
	స్థితి FUZZ_TRUNCATE_చివర:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		తిరిగి 0;
	స్థితి FUZZ_BASE64:
		ప్రతిజ్ఞా(fuzz->o2 < పరిమాణం(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిర శూన్య
dump(u_char *p, కొలత_t len)
{
	కొలత_t i, j;

	కొరకు (i = 0; i < len; i += 16) {
		fprintf(stderr, "%.4zd: ", i);
		కొరకు (j = i; j < i + 16; j++) {
			ఒకవేళ (j < len)
				fprintf(stderr, "%02x ", p[j]);
			లేకపోతే
				fprintf(stderr, "   ");
		}
		fprintf(stderr, " ");
		కొరకు (j = i; j < i + 16; j++) {
			ఒకవేళ (j < len) {
				ఒకవేళ  (isascii(p[j]) && isprint(p[j]))
					fprintf(stderr, "%c", p[j]);
				లేకపోతే
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

శూన్య
fuzz_dump(నిర్మాణం fuzz *fuzz)
{
	అక్షరం buf[256];

	ఒకవేళ (fuzz_fmt(fuzz, buf, పరిమాణం(buf)) != 0) {
		fprintf(stderr, "%s: fuzz invalid\n", __func__);
		abort();
	}
	fputs(buf, stderr);
	fprintf(stderr, "fuzz original %p len = %zu\n", fuzz->విత్తనం, fuzz->slen);
	dump(fuzz->విత్తనం, fuzz->slen);
	fprintf(stderr, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

స్థిర నిర్మాణం fuzz *చివరి_fuzz;

స్థిర శూన్య
siginfo(పూర్ణాంకం వాడని __attribute__((__unused__)))
{
	అక్షరం buf[256];

	test_info(buf, పరిమాణం(buf));
	atomicio(vwrite, STDERR_FILENO, buf, అక్షరశ్రేణి_పొడవు(buf));
	ఒకవేళ (చివరి_fuzz != ఖాళీ) {
		fuzz_fmt(చివరి_fuzz, buf, పరిమాణం(buf));
		atomicio(vwrite, STDERR_FILENO, buf, అక్షరశ్రేణి_పొడవు(buf));
	}
}

నిర్మాణం fuzz *
fuzz_begin(u_int strategies, స్థిరరాశి శూన్య *p, కొలత_t l)
{
	నిర్మాణం fuzz *ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret));

	ప్రతిజ్ఞా(p != ఖాళీ);
	ప్రతిజ్ఞా(ret != ఖాళీ);
	ret->విత్తనం = జ్ఞాపకం_ఇవ్వు(l);
	ప్రతిజ్ఞా(ret->విత్తనం != ఖాళీ);
	జ్ఞాపకం_నకలు(ret->విత్తనం, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	ప్రతిజ్ఞా(ret->slen < SIZE_MAX / 8);
	ప్రతిజ్ఞా(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_తదుపరి(ret);

	చివరి_fuzz = ret;
#నిర్వచితమైతే SIGINFO
	సంకేతం(SIGINFO, siginfo);
#అయితే_ముగింపు
	సంకేతం(SIGUSR1, siginfo);

	తిరిగి ret;
}

శూన్య
fuzz_cleanup(నిర్మాణం fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	చివరి_fuzz = ఖాళీ;
#నిర్వచితమైతే SIGINFO
	సంకేతం(SIGINFO, SIG_DFL);
#అయితే_ముగింపు
	సంకేతం(SIGUSR1, SIG_DFL);
	ప్రతిజ్ఞా(fuzz != ఖాళీ);
	ప్రతిజ్ఞా(fuzz->విత్తనం != ఖాళీ);
	ప్రతిజ్ఞా(fuzz->fuzzed != ఖాళీ);
	విడుదల(fuzz->విత్తనం);
	విడుదల(fuzz->fuzzed);
	విడుదల(fuzz);
}

స్థిర పూర్ణాంకం
fuzz_strategy_పూర్తి(నిర్మాణం fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	ఎంపిక (fuzz->strategy) {
	స్థితి FUZZ_1_బిట్టు_FLIP:
		తిరిగి fuzz->o1 >= fuzz->slen * 8;
	స్థితి FUZZ_2_బిట్టు_FLIP:
		తిరిగి fuzz->o2 >= fuzz->slen * 8;
	స్థితి FUZZ_2_BYTE_FLIP:
		తిరిగి fuzz->o2 >= fuzz->slen;
	స్థితి FUZZ_1_BYTE_FLIP:
	స్థితి FUZZ_TRUNCATE_ప్రారంభం:
	స్థితి FUZZ_TRUNCATE_చివర:
	స్థితి FUZZ_BASE64:
		తిరిగి fuzz->o1 >= fuzz->slen;
	అప్రమేయ:
		abort();
	}
}

శూన్య
fuzz_తదుపరి(నిర్మాణం fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	ఒకవేళ (fuzz->strategy == 0 || fuzz_strategy_పూర్తి(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		ఒకవేళ (fuzz->fuzzed == ఖాళీ) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = సున్నా_జ్ఞాపకం_ఇవ్వు(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		కొరకు (i = 1; i <= FUZZ_MAX; i <<= 1) {
			ఒకవేళ ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				ఆపు;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		ఒకవేళ (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			తిరిగి;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	ప్రతిజ్ఞా(fuzz->fuzzed != ఖాళీ);

	ఎంపిక (fuzz->strategy) {
	స్థితి FUZZ_1_బిట్టు_FLIP:
		ప్రతిజ్ఞా(fuzz->o1 / 8 < fuzz->slen);
		జ్ఞాపకం_నకలు(fuzz->fuzzed, fuzz->విత్తనం, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		ఆపు;
	స్థితి FUZZ_2_బిట్టు_FLIP:
		ప్రతిజ్ఞా(fuzz->o1 / 8 < fuzz->slen);
		ప్రతిజ్ఞా(fuzz->o2 / 8 < fuzz->slen);
		జ్ఞాపకం_నకలు(fuzz->fuzzed, fuzz->విత్తనం, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		ఒకవేళ (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ఆపు;
	స్థితి FUZZ_1_BYTE_FLIP:
		ప్రతిజ్ఞా(fuzz->o1 < fuzz->slen);
		జ్ఞాపకం_నకలు(fuzz->fuzzed, fuzz->విత్తనం, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		ఆపు;
	స్థితి FUZZ_2_BYTE_FLIP:
		ప్రతిజ్ఞా(fuzz->o1 < fuzz->slen);
		ప్రతిజ్ఞా(fuzz->o2 < fuzz->slen);
		జ్ఞాపకం_నకలు(fuzz->fuzzed, fuzz->విత్తనం, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		ఒకవేళ (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		ఆపు;
	స్థితి FUZZ_TRUNCATE_ప్రారంభం:
	స్థితి FUZZ_TRUNCATE_చివర:
		ప్రతిజ్ఞా(fuzz->o1 < fuzz->slen);
		జ్ఞాపకం_నకలు(fuzz->fuzzed, fuzz->విత్తనం, fuzz->slen);
		fuzz->o1++;
		ఆపు;
	స్థితి FUZZ_BASE64:
		ప్రతిజ్ఞా(fuzz->o1 < fuzz->slen);
		ప్రతిజ్ఞా(fuzz->o2 < పరిమాణం(fuzz_b64chars) - 1);
		జ్ఞాపకం_నకలు(fuzz->fuzzed, fuzz->విత్తనం, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		ఒకవేళ (fuzz->o2 >= పరిమాణం(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		ఆపు;
	అప్రమేయ:
		abort();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

పూర్ణాంకం
fuzz_matches_original(నిర్మాణం fuzz *fuzz)
{
	ఒకవేళ (fuzz_len(fuzz) != fuzz->slen)
		తిరిగి 0;
	తిరిగి memcmp(fuzz_ptr(fuzz), fuzz->విత్తనం, fuzz->slen) == 0;
}

పూర్ణాంకం
fuzz_పూర్తి(నిర్మాణం fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	తిరిగి fuzz_strategy_పూర్తి(fuzz) && fuzz->strategies == 0;
}

కొలత_t
fuzz_len(నిర్మాణం fuzz *fuzz)
{
	ప్రతిజ్ఞా(fuzz->fuzzed != ఖాళీ);
	ఎంపిక (fuzz->strategy) {
	స్థితి FUZZ_1_బిట్టు_FLIP:
	స్థితి FUZZ_2_బిట్టు_FLIP:
	స్థితి FUZZ_1_BYTE_FLIP:
	స్థితి FUZZ_2_BYTE_FLIP:
	స్థితి FUZZ_BASE64:
		తిరిగి fuzz->slen;
	స్థితి FUZZ_TRUNCATE_ప్రారంభం:
	స్థితి FUZZ_TRUNCATE_చివర:
		ప్రతిజ్ఞా(fuzz->o1 <= fuzz->slen);
		తిరిగి fuzz->slen - fuzz->o1;
	అప్రమేయ:
		abort();
	}
}

u_char *
fuzz_ptr(నిర్మాణం fuzz *fuzz)
{
	ప్రతిజ్ఞా(fuzz->fuzzed != ఖాళీ);
	ఎంపిక (fuzz->strategy) {
	స్థితి FUZZ_1_బిట్టు_FLIP:
	స్థితి FUZZ_2_బిట్టు_FLIP:
	స్థితి FUZZ_1_BYTE_FLIP:
	స్థితి FUZZ_2_BYTE_FLIP:
	స్థితి FUZZ_BASE64:
		తిరిగి fuzz->fuzzed;
	స్థితి FUZZ_TRUNCATE_ప్రారంభం:
		ప్రతిజ్ఞా(fuzz->o1 <= fuzz->slen);
		తిరిగి fuzz->fuzzed + fuzz->o1;
	స్థితి FUZZ_TRUNCATE_చివర:
		ప్రతిజ్ఞా(fuzz->o1 <= fuzz->slen);
		తిరిగి fuzz->fuzzed;
	అప్రమేయ:
		abort();
	}
}

