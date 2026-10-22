/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Per-iteration allocation arena for fuzz harnesses.
 *
 * Intercepts malloc / calloc / realloc / free / strdup via linker
 * --wrap and tracks every live allocation made between
 * fuzz_arena_begin() and the next release or cleanup call.
 *
 * Exit semantics:
 * - fuzz_arena_release(): stop tracking, leave allocations in place.
 *   Use when the code under test owns its allocations across iterations.
 * - fuzz_arena_cleanup(): free every still-tracked allocation. Use on
 *   longjmp recovery or when the code under test is treated as a pure
 *   per-iteration scratch user.
 *
 * Tracking is disabled outside of a begin/release-or-cleanup window
 * so libFuzzer's own bookkeeping allocations are not touched. The
 * implementation is single-threaded.
 */

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य शून्य *__real_malloc(आकार_t);
बाह्य शून्य *__real_calloc(आकार_t, आकार_t);
बाह्य शून्य *__real_realloc(शून्य *, आकार_t);
बाह्य शून्य __real_free(शून्य *);
बाह्य वर्ण *__real_strdup(ध्रुव वर्ण *);

संरचना arena_ग्रन्थिः {
	शून्य *ptr;
	संरचना arena_ग्रन्थिः *अग्र;
};

स्थिर संरचना arena_ग्रन्थिः *arena_शीर्ष;
स्थिर पूर्णाङ्क tracking;

स्थिर अन्तःस्थ शून्य
arena_track(शून्य *p)
{
	संरचना arena_ग्रन्थिः *n;
	यदि (!tracking || p == रिक्त)
		प्रत्यागम;
	n = (संरचना arena_ग्रन्थिः *)__real_malloc(परिमाण(*n));
	यदि (n == रिक्त)
		प्रत्यागम;
	n->ptr = p;
	n->अग्र = arena_शीर्ष;
	arena_शीर्ष = n;
}

स्थिर अन्तःस्थ शून्य
arena_untrack(शून्य *p)
{
	संरचना arena_ग्रन्थिः **pp;
	यदि (p == रिक्त)
		प्रत्यागम;
	प्रति (pp = &arena_शीर्ष; *pp != रिक्त; pp = &(*pp)->अग्र) {
		यदि ((*pp)->ptr == p) {
			संरचना arena_ग्रन्थिः *n = *pp;
			*pp = n->अग्र;
			__real_free(n);
			प्रत्यागम;
		}
	}
}

शून्य *
__wrap_malloc(आकार_t आकार)
{
	शून्य *p = __real_malloc(आकार);
	arena_track(p);
	प्रत्यागम p;
}

शून्य *
__wrap_calloc(आकार_t nmemb, आकार_t आकार)
{
	शून्य *p = __real_calloc(nmemb, आकार);
	arena_track(p);
	प्रत्यागम p;
}

शून्य *
__wrap_realloc(शून्य *ptr, आकार_t आकार)
{
	arena_untrack(ptr);
	शून्य *p = __real_realloc(ptr, आकार);
	arena_track(p);
	प्रत्यागम p;
}

शून्य
__wrap_free(शून्य *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

वर्ण *
__wrap_strdup(ध्रुव वर्ण *s)
{
	आकार_t len;
	वर्ण *p;
	यदि (s == रिक्त)
		प्रत्यागम रिक्त;
	len = वाक्यदैर्घ्यम्(s) + 1;
	p = (वर्ण *)__real_malloc(len);
	यदि (p == रिक्त)
		प्रत्यागम रिक्त;
	स्मृतिं_प्रतिलिख(p, s, len);
	arena_track(p);
	प्रत्यागम p;
}

शून्य
fuzz_arena_begin(शून्य)
{
	tracking = 1;
}

शून्य
fuzz_arena_release(शून्य)
{
	संरचना arena_ग्रन्थिः *n;
	tracking = 0;
	यावत् (arena_शीर्ष != रिक्त) {
		n = arena_शीर्ष;
		arena_शीर्ष = n->अग्र;
		__real_free(n);
	}
}

शून्य
fuzz_arena_cleanup(शून्य)
{
	संरचना arena_ग्रन्थिः *n;
	tracking = 0;
	यावत् (arena_शीर्ष != रिक्त) {
		n = arena_शीर्ष;
		arena_शीर्ष = n->अग्र;
		__real_free(n->ptr);
		__real_free(n);
	}
}
