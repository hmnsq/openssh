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
# define FUZZ_DBG(x) करा { \
		म_लिखो("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		म_लिखो x; \
		म_लिखो("\n"); \
		ख_साफ(मानक_निकास); \
	} पर्यंत (0)
#अन्यथा
# define FUZZ_DBG(x)
#endif

/* For brevity later */
प्रकारव्याख्या अचिन्हित दीर्घ दीर्घ fuzz_ullong;

/* For base-64 fuzzing */
स्थिर स्थिरांक अक्षर fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

संरचना fuzz {
	/* Fuzz method currently in use */
	पूर्णांक strategy;

	/* Fuzz methods remaining */
	पूर्णांक strategies;

	/* Original seed data blob */
	शून्य *seed;
	माप_प्रकार slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	माप_प्रकार o1, o2;
};

स्थिर स्थिरांक अक्षर *
fuzz_ntop(u_int n)
{
	निवड (n) {
	स्थिती 0:
		परत "NONE";
	स्थिती FUZZ_1_BIT_FLIP:
		परत "FUZZ_1_BIT_FLIP";
	स्थिती FUZZ_2_BIT_FLIP:
		परत "FUZZ_2_BIT_FLIP";
	स्थिती FUZZ_1_BYTE_FLIP:
		परत "FUZZ_1_BYTE_FLIP";
	स्थिती FUZZ_2_BYTE_FLIP:
		परत "FUZZ_2_BYTE_FLIP";
	स्थिती FUZZ_TRUNCATE_START:
		परत "FUZZ_TRUNCATE_START";
	स्थिती FUZZ_TRUNCATE_END:
		परत "FUZZ_TRUNCATE_END";
	स्थिती FUZZ_BASE64:
		परत "FUZZ_BASE64";
	पूर्वनिर्धारित:
		पात();
	}
}

स्थिर पूर्णांक
fuzz_fmt(संरचना fuzz *fuzz, अक्षर *s, माप_प्रकार n)
{
	जर (fuzz == रिक्त)
		परत -1;

	निवड (fuzz->strategy) {
	स्थिती FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		परत 0;
	स्थिती FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		परत 0;
	स्थिती FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		परत 0;
	स्थिती FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		परत 0;
	स्थिती FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		परत 0;
	स्थिती FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		परत 0;
	स्थिती FUZZ_BASE64:
		प्रतिज्ञा(fuzz->o2 < आकार(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		परत 0;
	पूर्वनिर्धारित:
		परत -1;
	}
}

स्थिर शून्य
dump(u_char *p, माप_प्रकार len)
{
	माप_प्रकार i, j;

	साठी (i = 0; i < len; i += 16) {
		ख_लिखो(मानक_त्रुटि, "%.4zd: ", i);
		साठी (j = i; j < i + 16; j++) {
			जर (j < len)
				ख_लिखो(मानक_त्रुटि, "%02x ", p[j]);
			अन्यथा
				ख_लिखो(मानक_त्रुटि, "   ");
		}
		ख_लिखो(मानक_त्रुटि, " ");
		साठी (j = i; j < i + 16; j++) {
			जर (j < len) {
				जर  (isascii(p[j]) && है_छाप(p[j]))
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
	अक्षर buf[256];

	जर (fuzz_fmt(fuzz, buf, आकार(buf)) != 0) {
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
siginfo(पूर्णांक unused __attribute__((__unused__)))
{
	अक्षर buf[256];

	test_info(buf, आकार(buf));
	atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
	जर (last_fuzz != रिक्त) {
		fuzz_fmt(last_fuzz, buf, आकार(buf));
		atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
	}
}

संरचना fuzz *
fuzz_begin(u_int strategies, स्थिरांक शून्य *p, माप_प्रकार l)
{
	संरचना fuzz *ret = सुस्मृति(1, आकार(*ret));

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
	संकेत(SIGINFO, siginfo);
#endif
	संकेत(SIGUSR1, siginfo);

	परत ret;
}

शून्य
fuzz_cleanup(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = रिक्त;
#ifdef SIGINFO
	संकेत(SIGINFO, संक_पूर्व);
#endif
	संकेत(SIGUSR1, संक_पूर्व);
	प्रतिज्ञा(fuzz != रिक्त);
	प्रतिज्ञा(fuzz->seed != रिक्त);
	प्रतिज्ञा(fuzz->fuzzed != रिक्त);
	मुक्त(fuzz->seed);
	मुक्त(fuzz->fuzzed);
	मुक्त(fuzz);
}

स्थिर पूर्णांक
fuzz_strategy_done(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	निवड (fuzz->strategy) {
	स्थिती FUZZ_1_BIT_FLIP:
		परत fuzz->o1 >= fuzz->slen * 8;
	स्थिती FUZZ_2_BIT_FLIP:
		परत fuzz->o2 >= fuzz->slen * 8;
	स्थिती FUZZ_2_BYTE_FLIP:
		परत fuzz->o2 >= fuzz->slen;
	स्थिती FUZZ_1_BYTE_FLIP:
	स्थिती FUZZ_TRUNCATE_START:
	स्थिती FUZZ_TRUNCATE_END:
	स्थिती FUZZ_BASE64:
		परत fuzz->o1 >= fuzz->slen;
	पूर्वनिर्धारित:
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

	जर (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		जर (fuzz->fuzzed == रिक्त) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = सुस्मृति(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		साठी (i = 1; i <= FUZZ_MAX; i <<= 1) {
			जर ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				थांबा;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		जर (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			परत;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	प्रतिज्ञा(fuzz->fuzzed != रिक्त);

	निवड (fuzz->strategy) {
	स्थिती FUZZ_1_BIT_FLIP:
		प्रतिज्ञा(fuzz->o1 / 8 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		थांबा;
	स्थिती FUZZ_2_BIT_FLIP:
		प्रतिज्ञा(fuzz->o1 / 8 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 / 8 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		जर (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		थांबा;
	स्थिती FUZZ_1_BYTE_FLIP:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		थांबा;
	स्थिती FUZZ_2_BYTE_FLIP:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		जर (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		थांबा;
	स्थिती FUZZ_TRUNCATE_START:
	स्थिती FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		थांबा;
	स्थिती FUZZ_BASE64:
		प्रतिज्ञा(fuzz->o1 < fuzz->slen);
		प्रतिज्ञा(fuzz->o2 < आकार(fuzz_b64chars) - 1);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		जर (fuzz->o2 >= आकार(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		थांबा;
	पूर्वनिर्धारित:
		पात();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

पूर्णांक
fuzz_matches_original(संरचना fuzz *fuzz)
{
	जर (fuzz_len(fuzz) != fuzz->slen)
		परत 0;
	परत स_भेद(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

पूर्णांक
fuzz_done(संरचना fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	परत fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

माप_प्रकार
fuzz_len(संरचना fuzz *fuzz)
{
	प्रतिज्ञा(fuzz->fuzzed != रिक्त);
	निवड (fuzz->strategy) {
	स्थिती FUZZ_1_BIT_FLIP:
	स्थिती FUZZ_2_BIT_FLIP:
	स्थिती FUZZ_1_BYTE_FLIP:
	स्थिती FUZZ_2_BYTE_FLIP:
	स्थिती FUZZ_BASE64:
		परत fuzz->slen;
	स्थिती FUZZ_TRUNCATE_START:
	स्थिती FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		परत fuzz->slen - fuzz->o1;
	पूर्वनिर्धारित:
		पात();
	}
}

u_char *
fuzz_ptr(संरचना fuzz *fuzz)
{
	प्रतिज्ञा(fuzz->fuzzed != रिक्त);
	निवड (fuzz->strategy) {
	स्थिती FUZZ_1_BIT_FLIP:
	स्थिती FUZZ_2_BIT_FLIP:
	स्थिती FUZZ_1_BYTE_FLIP:
	स्थिती FUZZ_2_BYTE_FLIP:
	स्थिती FUZZ_BASE64:
		परत fuzz->fuzzed;
	स्थिती FUZZ_TRUNCATE_START:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		परत fuzz->fuzzed + fuzz->o1;
	स्थिती FUZZ_TRUNCATE_END:
		प्रतिज्ञा(fuzz->o1 <= fuzz->slen);
		परत fuzz->fuzzed;
	पूर्वनिर्धारित:
		पात();
	}
}

