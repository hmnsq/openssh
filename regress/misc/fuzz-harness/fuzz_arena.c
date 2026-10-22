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

বাহ্য শূন্য *__real_malloc(size_t);
বাহ্য শূন্য *__real_calloc(size_t, size_t);
বাহ্য শূন্য *__real_realloc(শূন্য *, size_t);
বাহ্য শূন্য __real_free(শূন্য *);
বাহ্য বর্ণ *__real_strdup(ধ্রুব বর্ণ *);

সংরচনা arena_গ্রন্থি {
	শূন্য *ptr;
	সংরচনা arena_গ্রন্থি *next;
};

স্থির সংরচনা arena_গ্রন্থি *arena_head;
স্থির পূর্ণাঙ্ক tracking;

স্থির অন্তঃস্থ শূন্য
arena_track(শূন্য *p)
{
	সংরচনা arena_গ্রন্থি *n;
	যদি (!tracking || p == রিক্ত)
		প্রত্যাগম;
	n = (সংরচনা arena_গ্রন্থি *)__real_malloc(পরিমাণ(*n));
	যদি (n == রিক্ত)
		প্রত্যাগম;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

স্থির অন্তঃস্থ শূন্য
arena_untrack(শূন্য *p)
{
	সংরচনা arena_গ্রন্থি **pp;
	যদি (p == রিক্ত)
		প্রত্যাগম;
	প্রতি (pp = &arena_head; *pp != রিক্ত; pp = &(*pp)->next) {
		যদি ((*pp)->ptr == p) {
			সংরচনা arena_গ্রন্থি *n = *pp;
			*pp = n->next;
			__real_free(n);
			প্রত্যাগম;
		}
	}
}

শূন্য *
__wrap_malloc(size_t size)
{
	শূন্য *p = __real_malloc(size);
	arena_track(p);
	প্রত্যাগম p;
}

শূন্য *
__wrap_calloc(size_t nmemb, size_t size)
{
	শূন্য *p = __real_calloc(nmemb, size);
	arena_track(p);
	প্রত্যাগম p;
}

শূন্য *
__wrap_realloc(শূন্য *ptr, size_t size)
{
	arena_untrack(ptr);
	শূন্য *p = __real_realloc(ptr, size);
	arena_track(p);
	প্রত্যাগম p;
}

শূন্য
__wrap_free(শূন্য *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

বর্ণ *
__wrap_strdup(ধ্রুব বর্ণ *s)
{
	size_t len;
	বর্ণ *p;
	যদি (s == রিক্ত)
		প্রত্যাগম রিক্ত;
	len = strlen(s) + 1;
	p = (বর্ণ *)__real_malloc(len);
	যদি (p == রিক্ত)
		প্রত্যাগম রিক্ত;
	memcpy(p, s, len);
	arena_track(p);
	প্রত্যাগম p;
}

শূন্য
fuzz_arena_begin(শূন্য)
{
	tracking = 1;
}

শূন্য
fuzz_arena_release(শূন্য)
{
	সংরচনা arena_গ্রন্থি *n;
	tracking = 0;
	যাবত্ (arena_head != রিক্ত) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

শূন্য
fuzz_arena_cleanup(শূন্য)
{
	সংরচনা arena_গ্রন্থি *n;
	tracking = 0;
	যাবত্ (arena_head != রিক্ত) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
