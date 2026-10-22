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

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

বাহ্যিক শূন্য *__real_malloc(আকার_t);
বাহ্যিক শূন্য *__real_calloc(আকার_t, আকার_t);
বাহ্যিক শূন্য *__real_realloc(শূন্য *, আকার_t);
বাহ্যিক শূন্য __real_free(শূন্য *);
বাহ্যিক অক্ষর *__real_strdup(ধ্রুবক অক্ষর *);

কাঠামো arena_গ্রন্থি {
	শূন্য *ptr;
	কাঠামো arena_গ্রন্থি *পরবর্তী;
};

স্থির কাঠামো arena_গ্রন্থি *arena_শীর্ষ;
স্থির পূর্ণসংখ্যা tracking;

স্থির অন্তঃরেখ শূন্য
arena_track(শূন্য *p)
{
	কাঠামো arena_গ্রন্থি *n;
	যদি (!tracking || p == ফাঁকা)
		ফেরত;
	n = (কাঠামো arena_গ্রন্থি *)__real_malloc(আকার(*n));
	যদি (n == ফাঁকা)
		ফেরত;
	n->ptr = p;
	n->পরবর্তী = arena_শীর্ষ;
	arena_শীর্ষ = n;
}

স্থির অন্তঃরেখ শূন্য
arena_untrack(শূন্য *p)
{
	কাঠামো arena_গ্রন্থি **pp;
	যদি (p == ফাঁকা)
		ফেরত;
	জন্য (pp = &arena_শীর্ষ; *pp != ফাঁকা; pp = &(*pp)->পরবর্তী) {
		যদি ((*pp)->ptr == p) {
			কাঠামো arena_গ্রন্থি *n = *pp;
			*pp = n->পরবর্তী;
			__real_free(n);
			ফেরত;
		}
	}
}

শূন্য *
__wrap_malloc(আকার_t আকার_2)
{
	শূন্য *p = __real_malloc(আকার_2);
	arena_track(p);
	ফেরত p;
}

শূন্য *
__wrap_calloc(আকার_t nmemb, আকার_t আকার_2)
{
	শূন্য *p = __real_calloc(nmemb, আকার_2);
	arena_track(p);
	ফেরত p;
}

শূন্য *
__wrap_realloc(শূন্য *ptr, আকার_t আকার_2)
{
	arena_untrack(ptr);
	শূন্য *p = __real_realloc(ptr, আকার_2);
	arena_track(p);
	ফেরত p;
}

শূন্য
__wrap_free(শূন্য *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

অক্ষর *
__wrap_strdup(ধ্রুবক অক্ষর *s)
{
	আকার_t len;
	অক্ষর *p;
	যদি (s == ফাঁকা)
		ফেরত ফাঁকা;
	len = strlen(s) + 1;
	p = (অক্ষর *)__real_malloc(len);
	যদি (p == ফাঁকা)
		ফেরত ফাঁকা;
	memcpy(p, s, len);
	arena_track(p);
	ফেরত p;
}

শূন্য
fuzz_arena_begin(শূন্য)
{
	tracking = 1;
}

শূন্য
fuzz_arena_release(শূন্য)
{
	কাঠামো arena_গ্রন্থি *n;
	tracking = 0;
	যখন (arena_শীর্ষ != ফাঁকা) {
		n = arena_শীর্ষ;
		arena_শীর্ষ = n->পরবর্তী;
		__real_free(n);
	}
}

শূন্য
fuzz_arena_cleanup(শূন্য)
{
	কাঠামো arena_গ্রন্থি *n;
	tracking = 0;
	যখন (arena_শীর্ষ != ফাঁকা) {
		n = arena_শীর্ষ;
		arena_শীর্ষ = n->পরবর্তী;
		__real_free(n->ptr);
		__real_free(n);
	}
}
