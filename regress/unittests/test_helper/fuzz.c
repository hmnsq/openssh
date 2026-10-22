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
# define FUZZ_DBG(x) गर { \
		म_लिखो("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		म_लिखो x; \
		म_लिखो("\n"); \
		ख_साफ(मानक_निकास); \
	} जबसम्म (0)
#अन्यथा
# define FUZZ_DBG(x)
#endif

/* For brevity later */
प्रकारनिर्देश अचिन्हित दीर्घ दीर्घ fuzz_ullong;

/* For base-64 fuzzing */
स्थिर अचर वर्ण fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

संरचना fuzz {
	/* Fuzz method currently in use */
	पूर्णाङ्क strategy;

	/* Fuzz methods remaining */
	पूर्णाङ्क strategies;

	/* Original seed data blob */
	शून्य *seed;
	माप_प्रकार slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	माप_प्रकार o1, o2;
};

स्थिर अचर वर्ण *
fuzz_ntop(u_int n)
{
	विकल्प (n) {
	पक्ष 0:
		फर्काऊ "NONE";
	पक्ष FUZZ_1_BIT_FLIP:
		फर्काऊ "FUZZ_1_BIT_FLIP";
	पक्ष FUZZ_2_BIT_FLIP:
		फर्काऊ "FUZZ_2_BIT_FLIP";
	पक्ष FUZZ_1_BYTE_FLIP:
		फर्काऊ "FUZZ_1_BYTE_FLIP";
	पक्ष FUZZ_2_BYTE_FLIP:
		फर्काऊ "FUZZ_2_BYTE_FLIP";
	पक्ष FUZZ_TRUNCATE_START:
		फर्काऊ "FUZZ_TRUNCATE_START";
	पक्ष FUZZ_TRUNCATE_END:
		फर्काऊ "FUZZ_TRUNCATE_END";
	पक्ष FUZZ_BASE64:
		फर्काऊ "FUZZ_BASE64";
	स्वभाव:
		पात();
	}
}

स्थिर पूर्णाङ्क
fuzz_fmt(संरचना fuzz *fuzz, वर्ण *s, माप_प्रकार n)
{
	यदि (fuzz == रिक्त)
		फर्काऊ -1;

	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		फर्काऊ 0;
	पक्ष FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		फर्काऊ 0;
	पक्ष FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		फर्काऊ 0;
	पक्ष FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		फर्काऊ 0;
	पक्ष FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		फर्काऊ 0;
	पक्ष FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		फर्काऊ 0;
	पक्ष FUZZ_BASE64:
		प्रतिज्ञा(fuzz->o2 < परिमाण(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		फर्काऊ 0;
	स्वभाव:
		फर्काऊ -1;
	}
}

स्थिर शून्य
dump(u_char *p, माप_प्रकार len)
{
	माप_प्रकार i, j;

	लागि (i = 0; i < len; i += 16) {
		ख_लिखो(मानक_त्रुटि, "%.4zd: ", i);
		लागि (j = i; j < i + 16; j++) {
			यदि (j < len)
				ख_लिखो(मानक_त्रुटि, "%02x ", p[j]);
			अन्यथा
				ख_लिखो(मानक_त्रुटि, "   ");
		}
		ख_लिखो(मानक_त्रुटि, " ");
		लागि (j = i; j < i + 16; j++) {
			यदि (j < len) {
				यदि  (isascii(p[j]) && है_छाप(p[j]))
					ख_लिखो(मानक_त्रुटि, "%c", p[j]);
				अन्यथा
					ख_लिखो(मानक_त्रुटि, ".");
			}
		}
		ख_लिखो(मानक_त्रुटि, "\n");
	}
}

शून्य
fuzz_dump(संरचना fuzz *fuzz)
{
	वर्ण buf[256];

	यदि (fuzz_fmt(fuzz, buf, परिमाण(buf)) != 0) {
		ख_लिखो(मानक_त्रुटि, "%s: fuzz invalid\n", __func__);
		पात();
	}
	ख_माला_दो(buf, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	ख_लिखो(मानक_त्रुटि, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

स्थिर संरचना fuzz *last_fuzz;

स्थिर शून्य
siginfo(पूर्णाङ्क unused __attribute__((__unused__)))
{
	वर्ण buf[256];

	test_info(buf, परिमाण(buf));
	atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
	यदि (last_fuzz != रिक्त) {
		fuzz_fmt(last_fuzz, buf, परिमाण(buf));
		atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
	}
}

संरचना fuzz *
fuzz_begin(u_int strategies, अचर शून्य *p, माप_प्रकार l)
{
	संरचना fuzz *ret = सुस्मृति(1, परिमाण(*ret));

	प्रतिज्ञा(p != रिक्त);
	प्रतिज्ञा(ret != रिक्त);
	ret->seed = दो_स्मृति(l);
	प्रतिज्ञा(ret->seed != रिक्त);
	स_नकल(ret->seed, p, l);
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

	फर्काऊ ret;
}

शून्य
fuzz_cleanup(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = रिक्त;
#ifdef SIGINFO
	सङ्केत(SIGINFO, संक_पूर्व);
#endif
	सङ्केत(SIGUSR1, संक_पूर्व);
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
		फर्काऊ fuzz->o1 >= fuzz->slen * 8;
	पक्ष FUZZ_2_BIT_FLIP:
		फर्काऊ fuzz->o2 >= fuzz->slen * 8;
	पक्ष FUZZ_2_BYTE_FLIP:
		फर्काऊ fuzz->o2 >= fuzz->slen;
	पक्ष FUZZ_1_BYTE_FLIP:
	पक्ष FUZZ_TRUNCATE_START:
	पक्ष FUZZ_TRUNCATE_END:
	पक्ष FUZZ_BASE64:
		फर्काऊ fuzz->o1 >= fuzz->slen;
	स्वभाव:
		पात();
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
			fuzz->fuzzed = सुस्मृति(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		लागि (i = 1; i <= FUZZ_MAX; i <<= 1) {
			यदि ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				रोक;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		यदि (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			फर्काऊ;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	प्रतिज्ञा(fuzz->fuzzed != रिक्त);

	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
		प्रतिज्ञा(fuzz->o1 / 8 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		रोक;
	पक्ष FUZZ_2_BIT_FLIP:
		प्रतिज्ञा(fuzz->o1 / 8 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 / 8 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		यदि (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		रोक;
	पक्ष FUZZ_1_BYTE_FLIP:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		रोक;
	पक्ष FUZZ_2_BYTE_FLIP:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		यदि (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		रोक;
	पक्ष FUZZ_TRUNCATE_START:
	पक्ष FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		रोक;
	पक्ष FUZZ_BASE64:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 < परिमाण(fuzz_b64chars) - 1);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		यदि (fuzz->o2 >= परिमाण(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		रोक;
	स्वभाव:
		पात();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

पूर्णाङ्क
fuzz_matches_original(संरचना fuzz *fuzz)
{
	यदि (fuzz_len(fuzz) != fuzz->slen)
		फर्काऊ 0;
	फर्काऊ स_भेद(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

पूर्णाङ्क
fuzz_done(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	फर्काऊ fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

माप_प्रकार
fuzz_len(संरचना fuzz *fuzz)
{
	प्रतिज्ञा(fuzz->fuzzed != रिक्त);
	विकल्प (fuzz->strategy) {
	पक्ष FUZZ_1_BIT_FLIP:
	पक्ष FUZZ_2_BIT_FLIP:
	पक्ष FUZZ_1_BYTE_FLIP:
	पक्ष FUZZ_2_BYTE_FLIP:
	पक्ष FUZZ_BASE64:
		फर्काऊ fuzz->slen;
	पक्ष FUZZ_TRUNCATE_START:
	पक्ष FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		फर्काऊ fuzz->slen - fuzz->o1;
	स्वभाव:
		पात();
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
		फर्काऊ fuzz->fuzzed;
	पक्ष FUZZ_TRUNCATE_START:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		फर्काऊ fuzz->fuzzed + fuzz->o1;
	पक्ष FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		फर्काऊ fuzz->fuzzed;
	स्वभाव:
		पात();
	}
}

