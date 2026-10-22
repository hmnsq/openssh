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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/uio.h>

#समावेश <assert.h>
#समावेश <ctype.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <signal.h>
#समावेश <unistd.h>

#समावेश "test_helper.h"
#समावेश "atomicio.h"

/* #define FUZZ_DEBUG */

#अगर_घोषित FUZZ_DEBUG
# define FUZZ_DBG(x) करो { \
		म_लिखो("%s:%d %s: ", __खाता__, __LINE__, __func__); \
		म_लिखो x; \
		म_लिखो("\n"); \
		ख_साफ(मानक_निकास); \
	} जबतक (0)
#अन्यथा
# define FUZZ_DBG(x)
#पूर्ण_अगर

/* For brevity later */
प्रकार अचिन्हित दीर्घ दीर्घ fuzz_ullong;

/* For base-64 fuzzing */
अटल स्थिर अक्षर fuzz_b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

काष्ठा fuzz {
	/* Fuzz method currently in use */
	पूर्णांक strategy;

	/* Fuzz methods remaining */
	पूर्णांक strategies;

	/* Original seed data blob */
	व्योम *seed;
	माप_प्रकार slen;

	/* Current working copy of seed with fuzz mutations applied */
	u_char *fuzzed;

	/* Used by fuzz methods */
	माप_प्रकार o1, o2;
};

अटल स्थिर अक्षर *
fuzz_ntop(u_int n)
{
	चयन (n) {
	हाल 0:
		वापस "NONE";
	हाल FUZZ_1_BIT_FLIP:
		वापस "FUZZ_1_BIT_FLIP";
	हाल FUZZ_2_BIT_FLIP:
		वापस "FUZZ_2_BIT_FLIP";
	हाल FUZZ_1_BYTE_FLIP:
		वापस "FUZZ_1_BYTE_FLIP";
	हाल FUZZ_2_BYTE_FLIP:
		वापस "FUZZ_2_BYTE_FLIP";
	हाल FUZZ_TRUNCATE_START:
		वापस "FUZZ_TRUNCATE_START";
	हाल FUZZ_TRUNCATE_END:
		वापस "FUZZ_TRUNCATE_END";
	हाल FUZZ_BASE64:
		वापस "FUZZ_BASE64";
	शेष:
		पात();
	}
}

अटल पूर्णांक
fuzz_fmt(काष्ठा fuzz *fuzz, अक्षर *s, माप_प्रकार n)
{
	अगर (fuzz == शून्य)
		वापस -1;

	चयन (fuzz->strategy) {
	हाल FUZZ_1_BIT_FLIP:
		snprintf(s, n, "%s case %zu of %zu (bit: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen * 8, fuzz->o1);
		वापस 0;
	हाल FUZZ_2_BIT_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bits: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen * 8) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen * 8) * fuzz->slen * 8,
		    fuzz->o1, fuzz->o2);
		वापस 0;
	हाल FUZZ_1_BYTE_FLIP:
		snprintf(s, n, "%s case %zu of %zu (byte: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		वापस 0;
	हाल FUZZ_2_BYTE_FLIP:
		snprintf(s, n, "%s case %llu of %llu (bytes: %zu, %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    (((fuzz_ullong)fuzz->o2) * fuzz->slen) + fuzz->o1,
		    ((fuzz_ullong)fuzz->slen) * fuzz->slen,
		    fuzz->o1, fuzz->o2);
		वापस 0;
	हाल FUZZ_TRUNCATE_START:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		वापस 0;
	हाल FUZZ_TRUNCATE_END:
		snprintf(s, n, "%s case %zu of %zu (offset: %zu)\n",
		    fuzz_ntop(fuzz->strategy),
		    fuzz->o1, fuzz->slen, fuzz->o1);
		वापस 0;
	हाल FUZZ_BASE64:
		निश्चित(fuzz->o2 < माप(fuzz_b64chars) - 1);
		snprintf(s, n, "%s case %llu of %llu (offset: %zu char: %c)\n",
		    fuzz_ntop(fuzz->strategy),
		    (fuzz->o1 * (fuzz_ullong)64) + fuzz->o2,
		    fuzz->slen * (fuzz_ullong)64, fuzz->o1,
		    fuzz_b64chars[fuzz->o2]);
		वापस 0;
	शेष:
		वापस -1;
	}
}

अटल व्योम
dump(u_char *p, माप_प्रकार len)
{
	माप_प्रकार i, j;

	क्रम (i = 0; i < len; i += 16) {
		ख_लिखो(मानक_त्रुटि, "%.4zd: ", i);
		क्रम (j = i; j < i + 16; j++) {
			अगर (j < len)
				ख_लिखो(मानक_त्रुटि, "%02x ", p[j]);
			अन्यथा
				ख_लिखो(मानक_त्रुटि, "   ");
		}
		ख_लिखो(मानक_त्रुटि, " ");
		क्रम (j = i; j < i + 16; j++) {
			अगर (j < len) {
				अगर  (isascii(p[j]) && है_छाप(p[j]))
					ख_लिखो(मानक_त्रुटि, "%c", p[j]);
				अन्यथा
					ख_लिखो(मानक_त्रुटि, ".");
			}
		}
		ख_लिखो(मानक_त्रुटि, "\n");
	}
}

व्योम
fuzz_dump(काष्ठा fuzz *fuzz)
{
	अक्षर buf[256];

	अगर (fuzz_fmt(fuzz, buf, माप(buf)) != 0) {
		ख_लिखो(मानक_त्रुटि, "%s: fuzz invalid\n", __func__);
		पात();
	}
	ख_माला_दो(buf, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "fuzz original %p len = %zu\n", fuzz->seed, fuzz->slen);
	dump(fuzz->seed, fuzz->slen);
	ख_लिखो(मानक_त्रुटि, "fuzz context %p len = %zu\n", fuzz, fuzz_len(fuzz));
	dump(fuzz_ptr(fuzz), fuzz_len(fuzz));
}

अटल काष्ठा fuzz *last_fuzz;

अटल व्योम
siginfo(पूर्णांक unused __attribute__((__unused__)))
{
	अक्षर buf[256];

	test_info(buf, माप(buf));
	atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
	अगर (last_fuzz != शून्य) {
		fuzz_fmt(last_fuzz, buf, माप(buf));
		atomicio(vwrite, STDERR_FILENO, buf, म_माप(buf));
	}
}

काष्ठा fuzz *
fuzz_begin(u_int strategies, स्थिर व्योम *p, माप_प्रकार l)
{
	काष्ठा fuzz *ret = सुस्मृति(1, माप(*ret));

	निश्चित(p != शून्य);
	निश्चित(ret != शून्य);
	ret->seed = दो_स्मृति(l);
	निश्चित(ret->seed != शून्य);
	स_नकल(ret->seed, p, l);
	ret->slen = l;
	ret->strategies = strategies;

	निश्चित(ret->slen < SIZE_MAX / 8);
	निश्चित(ret->strategies <= (FUZZ_MAX|(FUZZ_MAX-1)));

	FUZZ_DBG(("begin, ret = %p", ret));

	fuzz_अग्र(ret);

	last_fuzz = ret;
#अगर_घोषित SIGINFO
	संकेत(SIGINFO, siginfo);
#पूर्ण_अगर
	संकेत(SIGUSR1, siginfo);

	वापस ret;
}

व्योम
fuzz_cleanup(काष्ठा fuzz *fuzz)
{
	FUZZ_DBG(("cleanup, fuzz = %p", fuzz));
	last_fuzz = शून्य;
#अगर_घोषित SIGINFO
	संकेत(SIGINFO, संक_पूर्व);
#पूर्ण_अगर
	संकेत(SIGUSR1, संक_पूर्व);
	निश्चित(fuzz != शून्य);
	निश्चित(fuzz->seed != शून्य);
	निश्चित(fuzz->fuzzed != शून्य);
	मुक्त(fuzz->seed);
	मुक्त(fuzz->fuzzed);
	मुक्त(fuzz);
}

अटल पूर्णांक
fuzz_strategy_done(काष्ठा fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategy = %s, o1 = %zu, o2 = %zu, slen = %zu",
	    fuzz, fuzz_ntop(fuzz->strategy), fuzz->o1, fuzz->o2, fuzz->slen));

	चयन (fuzz->strategy) {
	हाल FUZZ_1_BIT_FLIP:
		वापस fuzz->o1 >= fuzz->slen * 8;
	हाल FUZZ_2_BIT_FLIP:
		वापस fuzz->o2 >= fuzz->slen * 8;
	हाल FUZZ_2_BYTE_FLIP:
		वापस fuzz->o2 >= fuzz->slen;
	हाल FUZZ_1_BYTE_FLIP:
	हाल FUZZ_TRUNCATE_START:
	हाल FUZZ_TRUNCATE_END:
	हाल FUZZ_BASE64:
		वापस fuzz->o1 >= fuzz->slen;
	शेष:
		पात();
	}
}

व्योम
fuzz_अग्र(काष्ठा fuzz *fuzz)
{
	u_int i;

	FUZZ_DBG(("start, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));

	अगर (fuzz->strategy == 0 || fuzz_strategy_done(fuzz)) {
		/* If we are just starting out, we need to allocate too */
		अगर (fuzz->fuzzed == शून्य) {
			FUZZ_DBG(("alloc"));
			fuzz->fuzzed = सुस्मृति(fuzz->slen, 1);
		}
		/* Pick next strategy */
		FUZZ_DBG(("advance"));
		क्रम (i = 1; i <= FUZZ_MAX; i <<= 1) {
			अगर ((fuzz->strategies & i) != 0) {
				fuzz->strategy = i;
				अवरोध;
			}
		}
		FUZZ_DBG(("selected = %u", fuzz->strategy));
		अगर (fuzz->strategy == 0) {
			FUZZ_DBG(("done, no more strategies"));
			वापस;
		}
		fuzz->strategies &= ~(fuzz->strategy);
		fuzz->o1 = fuzz->o2 = 0;
	}

	निश्चित(fuzz->fuzzed != शून्य);

	चयन (fuzz->strategy) {
	हाल FUZZ_1_BIT_FLIP:
		निश्चित(fuzz->o1 / 8 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->o1++;
		अवरोध;
	हाल FUZZ_2_BIT_FLIP:
		निश्चित(fuzz->o1 / 8 < fuzz->slen);
		निश्चित(fuzz->o2 / 8 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1 / 8] ^= 1 << (fuzz->o1 % 8);
		fuzz->fuzzed[fuzz->o2 / 8] ^= 1 << (fuzz->o2 % 8);
		fuzz->o1++;
		अगर (fuzz->o1 >= fuzz->slen * 8) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		अवरोध;
	हाल FUZZ_1_BYTE_FLIP:
		निश्चित(fuzz->o1 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->o1++;
		अवरोध;
	हाल FUZZ_2_BYTE_FLIP:
		निश्चित(fuzz->o1 < fuzz->slen);
		निश्चित(fuzz->o2 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] ^= 0xff;
		fuzz->fuzzed[fuzz->o2] ^= 0xff;
		fuzz->o1++;
		अगर (fuzz->o1 >= fuzz->slen) {
			fuzz->o1 = 0;
			fuzz->o2++;
		}
		अवरोध;
	हाल FUZZ_TRUNCATE_START:
	हाल FUZZ_TRUNCATE_END:
		निश्चित(fuzz->o1 < fuzz->slen);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->o1++;
		अवरोध;
	हाल FUZZ_BASE64:
		निश्चित(fuzz->o1 < fuzz->slen);
		निश्चित(fuzz->o2 < माप(fuzz_b64chars) - 1);
		स_नकल(fuzz->fuzzed, fuzz->seed, fuzz->slen);
		fuzz->fuzzed[fuzz->o1] = fuzz_b64chars[fuzz->o2];
		fuzz->o2++;
		अगर (fuzz->o2 >= माप(fuzz_b64chars) - 1) {
			fuzz->o2 = 0;
			fuzz->o1++;
		}
		अवरोध;
	शेष:
		पात();
	}

	FUZZ_DBG(("done, fuzz = %p, strategy = %s, strategies = 0x%lx, "
	    "o1 = %zu, o2 = %zu, slen = %zu", fuzz, fuzz_ntop(fuzz->strategy),
	    (u_long)fuzz->strategies, fuzz->o1, fuzz->o2, fuzz->slen));
}

पूर्णांक
fuzz_matches_original(काष्ठा fuzz *fuzz)
{
	अगर (fuzz_len(fuzz) != fuzz->slen)
		वापस 0;
	वापस स_भेद(fuzz_ptr(fuzz), fuzz->seed, fuzz->slen) == 0;
}

पूर्णांक
fuzz_done(काष्ठा fuzz *fuzz)
{
	FUZZ_DBG(("fuzz = %p, strategies = 0x%lx", fuzz,
	    (u_long)fuzz->strategies));

	वापस fuzz_strategy_done(fuzz) && fuzz->strategies == 0;
}

माप_प्रकार
fuzz_len(काष्ठा fuzz *fuzz)
{
	निश्चित(fuzz->fuzzed != शून्य);
	चयन (fuzz->strategy) {
	हाल FUZZ_1_BIT_FLIP:
	हाल FUZZ_2_BIT_FLIP:
	हाल FUZZ_1_BYTE_FLIP:
	हाल FUZZ_2_BYTE_FLIP:
	हाल FUZZ_BASE64:
		वापस fuzz->slen;
	हाल FUZZ_TRUNCATE_START:
	हाल FUZZ_TRUNCATE_END:
		निश्चित(fuzz->o1 <= fuzz->slen);
		वापस fuzz->slen - fuzz->o1;
	शेष:
		पात();
	}
}

u_char *
fuzz_ptr(काष्ठा fuzz *fuzz)
{
	निश्चित(fuzz->fuzzed != शून्य);
	चयन (fuzz->strategy) {
	हाल FUZZ_1_BIT_FLIP:
	हाल FUZZ_2_BIT_FLIP:
	हाल FUZZ_1_BYTE_FLIP:
	हाल FUZZ_2_BYTE_FLIP:
	हाल FUZZ_BASE64:
		वापस fuzz->fuzzed;
	हाल FUZZ_TRUNCATE_START:
		निश्चित(fuzz->o1 <= fuzz->slen);
		वापस fuzz->fuzzed + fuzz->o1;
	हाल FUZZ_TRUNCATE_END:
		निश्चित(fuzz->o1 <= fuzz->slen);
		वापस fuzz->fuzzed;
	शेष:
		पात();
	}
}

