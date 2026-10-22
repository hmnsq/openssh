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

बाह्य शून्य *__real_malloc(माप_प्रकार);
बाह्य शून्य *__real_calloc(माप_प्रकार, माप_प्रकार);
बाह्य शून्य *__real_realloc(शून्य *, माप_प्रकार);
बाह्य शून्य __real_free(शून्य *);
बाह्य वर्ण *__real_strdup(अचर वर्ण *);

संरचना arena_गाँठो {
	शून्य *ptr;
	संरचना arena_गाँठो *next;
};

स्थिर संरचना arena_गाँठो *arena_head;
स्थिर पूर्णाङ्क tracking;

स्थिर अन्तःस्थ शून्य
arena_track(शून्य *p)
{
	संरचना arena_गाँठो *n;
	यदि (!tracking || p == रिक्त)
		फर्काऊ;
	n = (संरचना arena_गाँठो *)__real_malloc(परिमाण(*n));
	यदि (n == रिक्त)
		फर्काऊ;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

स्थिर अन्तःस्थ शून्य
arena_untrack(शून्य *p)
{
	संरचना arena_गाँठो **pp;
	यदि (p == रिक्त)
		फर्काऊ;
	लागि (pp = &arena_head; *pp != रिक्त; pp = &(*pp)->next) {
		यदि ((*pp)->ptr == p) {
			संरचना arena_गाँठो *n = *pp;
			*pp = n->next;
			__real_free(n);
			फर्काऊ;
		}
	}
}

शून्य *
__wrap_malloc(माप_प्रकार size)
{
	शून्य *p = __real_malloc(size);
	arena_track(p);
	फर्काऊ p;
}

शून्य *
__wrap_calloc(माप_प्रकार nmemb, माप_प्रकार size)
{
	शून्य *p = __real_calloc(nmemb, size);
	arena_track(p);
	फर्काऊ p;
}

शून्य *
__wrap_realloc(शून्य *ptr, माप_प्रकार size)
{
	arena_untrack(ptr);
	शून्य *p = __real_realloc(ptr, size);
	arena_track(p);
	फर्काऊ p;
}

शून्य
__wrap_free(शून्य *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

वर्ण *
__wrap_strdup(अचर वर्ण *s)
{
	माप_प्रकार len;
	वर्ण *p;
	यदि (s == रिक्त)
		फर्काऊ रिक्त;
	len = म_माप(s) + 1;
	p = (वर्ण *)__real_malloc(len);
	यदि (p == रिक्त)
		फर्काऊ रिक्त;
	स_नकल(p, s, len);
	arena_track(p);
	फर्काऊ p;
}

शून्य
fuzz_arena_begin(शून्य)
{
	tracking = 1;
}

शून्य
fuzz_arena_release(शून्य)
{
	संरचना arena_गाँठो *n;
	tracking = 0;
	जबसम्म (arena_head != रिक्त) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

शून्य
fuzz_arena_cleanup(शून्य)
{
	संरचना arena_गाँठो *n;
	tracking = 0;
	जबसम्म (arena_head != रिक्त) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
