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

#شامل <stddef.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

بیرونی تهی *__real_malloc(size_t);
بیرونی تهی *__real_calloc(size_t, size_t);
بیرونی تهی *__real_realloc(تهی *, size_t);
بیرونی تهی __real_free(تهی *);
بیرونی نویسه *__real_strdup(ثابت نویسه *);

ساختار arena_گره {
	تهی *ptr;
	ساختار arena_گره *next;
};

ایستا ساختار arena_گره *arena_head;
ایستا صحیح tracking;

ایستا درونخطی تهی
arena_track(تهی *p)
{
	ساختار arena_گره *n;
	اگر (!tracking || p == پوچ)
		بازگشت;
	n = (ساختار arena_گره *)__real_malloc(اندازه(*n));
	اگر (n == پوچ)
		بازگشت;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

ایستا درونخطی تهی
arena_untrack(تهی *p)
{
	ساختار arena_گره **pp;
	اگر (p == پوچ)
		بازگشت;
	برای (pp = &arena_head; *pp != پوچ; pp = &(*pp)->next) {
		اگر ((*pp)->ptr == p) {
			ساختار arena_گره *n = *pp;
			*pp = n->next;
			__real_free(n);
			بازگشت;
		}
	}
}

تهی *
__wrap_malloc(size_t size)
{
	تهی *p = __real_malloc(size);
	arena_track(p);
	بازگشت p;
}

تهی *
__wrap_calloc(size_t nmemb, size_t size)
{
	تهی *p = __real_calloc(nmemb, size);
	arena_track(p);
	بازگشت p;
}

تهی *
__wrap_realloc(تهی *ptr, size_t size)
{
	arena_untrack(ptr);
	تهی *p = __real_realloc(ptr, size);
	arena_track(p);
	بازگشت p;
}

تهی
__wrap_free(تهی *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

نویسه *
__wrap_strdup(ثابت نویسه *s)
{
	size_t len;
	نویسه *p;
	اگر (s == پوچ)
		بازگشت پوچ;
	len = strlen(s) + 1;
	p = (نویسه *)__real_malloc(len);
	اگر (p == پوچ)
		بازگشت پوچ;
	memcpy(p, s, len);
	arena_track(p);
	بازگشت p;
}

تهی
fuzz_arena_begin(تهی)
{
	tracking = 1;
}

تهی
fuzz_arena_release(تهی)
{
	ساختار arena_گره *n;
	tracking = 0;
	وقتی (arena_head != پوچ) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

تهی
fuzz_arena_cleanup(تهی)
{
	ساختار arena_گره *n;
	tracking = 0;
	وقتی (arena_head != پوچ) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
