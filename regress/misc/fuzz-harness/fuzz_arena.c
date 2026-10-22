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

#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

बाह्य व्योम *__real_malloc(माप_प्रकार);
बाह्य व्योम *__real_calloc(माप_प्रकार, माप_प्रकार);
बाह्य व्योम *__real_realloc(व्योम *, माप_प्रकार);
बाह्य व्योम __real_free(व्योम *);
बाह्य अक्षर *__real_strdup(स्थिर अक्षर *);

काष्ठा arena_गाँठ {
	व्योम *ptr;
	काष्ठा arena_गाँठ *अग्र;
};

अटल काष्ठा arena_गाँठ *arena_शीर्ष;
अटल पूर्णांक tracking;

अटल अंतरभूत व्योम
arena_track(व्योम *p)
{
	काष्ठा arena_गाँठ *n;
	अगर (!tracking || p == शून्य)
		वापस;
	n = (काष्ठा arena_गाँठ *)__real_malloc(माप(*n));
	अगर (n == शून्य)
		वापस;
	n->ptr = p;
	n->अग्र = arena_शीर्ष;
	arena_शीर्ष = n;
}

अटल अंतरभूत व्योम
arena_untrack(व्योम *p)
{
	काष्ठा arena_गाँठ **pp;
	अगर (p == शून्य)
		वापस;
	क्रम (pp = &arena_शीर्ष; *pp != शून्य; pp = &(*pp)->अग्र) {
		अगर ((*pp)->ptr == p) {
			काष्ठा arena_गाँठ *n = *pp;
			*pp = n->अग्र;
			__real_free(n);
			वापस;
		}
	}
}

व्योम *
__wrap_malloc(माप_प्रकार आकार)
{
	व्योम *p = __real_malloc(आकार);
	arena_track(p);
	वापस p;
}

व्योम *
__wrap_calloc(माप_प्रकार nmemb, माप_प्रकार आकार)
{
	व्योम *p = __real_calloc(nmemb, आकार);
	arena_track(p);
	वापस p;
}

व्योम *
__wrap_realloc(व्योम *ptr, माप_प्रकार आकार)
{
	arena_untrack(ptr);
	व्योम *p = __real_realloc(ptr, आकार);
	arena_track(p);
	वापस p;
}

व्योम
__wrap_free(व्योम *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

अक्षर *
__wrap_strdup(स्थिर अक्षर *s)
{
	माप_प्रकार len;
	अक्षर *p;
	अगर (s == शून्य)
		वापस शून्य;
	len = म_माप(s) + 1;
	p = (अक्षर *)__real_malloc(len);
	अगर (p == शून्य)
		वापस शून्य;
	स_नकल(p, s, len);
	arena_track(p);
	वापस p;
}

व्योम
fuzz_arena_begin(व्योम)
{
	tracking = 1;
}

व्योम
fuzz_arena_release(व्योम)
{
	काष्ठा arena_गाँठ *n;
	tracking = 0;
	जबतक (arena_शीर्ष != शून्य) {
		n = arena_शीर्ष;
		arena_शीर्ष = n->अग्र;
		__real_free(n);
	}
}

व्योम
fuzz_arena_cleanup(व्योम)
{
	काष्ठा arena_गाँठ *n;
	tracking = 0;
	जबतक (arena_शीर्ष != शून्य) {
		n = arena_शीर्ष;
		arena_शीर्ष = n->अग्र;
		__real_free(n->ptr);
		__real_free(n);
	}
}
