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

#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

வெளி வெறுமை *__real_malloc(size_t);
வெளி வெறுமை *__real_calloc(size_t, size_t);
வெளி வெறுமை *__real_realloc(வெறுமை *, size_t);
வெளி வெறுமை __real_free(வெறுமை *);
வெளி எழுத்து *__real_strdup(மாறிலி எழுத்து *);

கட்டமைப்பு arena_முனை {
	வெறுமை *ptr;
	கட்டமைப்பு arena_முனை *next;
};

நிலையான கட்டமைப்பு arena_முனை *arena_head;
நிலையான முழு tracking;

நிலையான உள்வரி வெறுமை
arena_track(வெறுமை *p)
{
	கட்டமைப்பு arena_முனை *n;
	எனில் (!tracking || p == வெற்று)
		திரும்பு;
	n = (கட்டமைப்பு arena_முனை *)__real_malloc(அளவு(*n));
	எனில் (n == வெற்று)
		திரும்பு;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

நிலையான உள்வரி வெறுமை
arena_untrack(வெறுமை *p)
{
	கட்டமைப்பு arena_முனை **pp;
	எனில் (p == வெற்று)
		திரும்பு;
	க்கு (pp = &arena_head; *pp != வெற்று; pp = &(*pp)->next) {
		எனில் ((*pp)->ptr == p) {
			கட்டமைப்பு arena_முனை *n = *pp;
			*pp = n->next;
			__real_free(n);
			திரும்பு;
		}
	}
}

வெறுமை *
__wrap_malloc(size_t size)
{
	வெறுமை *p = __real_malloc(size);
	arena_track(p);
	திரும்பு p;
}

வெறுமை *
__wrap_calloc(size_t nmemb, size_t size)
{
	வெறுமை *p = __real_calloc(nmemb, size);
	arena_track(p);
	திரும்பு p;
}

வெறுமை *
__wrap_realloc(வெறுமை *ptr, size_t size)
{
	arena_untrack(ptr);
	வெறுமை *p = __real_realloc(ptr, size);
	arena_track(p);
	திரும்பு p;
}

வெறுமை
__wrap_free(வெறுமை *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

எழுத்து *
__wrap_strdup(மாறிலி எழுத்து *s)
{
	size_t len;
	எழுத்து *p;
	எனில் (s == வெற்று)
		திரும்பு வெற்று;
	len = strlen(s) + 1;
	p = (எழுத்து *)__real_malloc(len);
	எனில் (p == வெற்று)
		திரும்பு வெற்று;
	memcpy(p, s, len);
	arena_track(p);
	திரும்பு p;
}

வெறுமை
fuzz_arena_begin(வெறுமை)
{
	tracking = 1;
}

வெறுமை
fuzz_arena_release(வெறுமை)
{
	கட்டமைப்பு arena_முனை *n;
	tracking = 0;
	போது (arena_head != வெற்று) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

வெறுமை
fuzz_arena_cleanup(வெறுமை)
{
	கட்டமைப்பு arena_முனை *n;
	tracking = 0;
	போது (arena_head != வெற்று) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
