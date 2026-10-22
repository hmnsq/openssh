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

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಬಾಹ್ಯ ಶೂನ್ಯ *__real_malloc(size_t);
ಬಾಹ್ಯ ಶೂನ್ಯ *__real_calloc(size_t, size_t);
ಬಾಹ್ಯ ಶೂನ್ಯ *__real_realloc(ಶೂನ್ಯ *, size_t);
ಬಾಹ್ಯ ಶೂನ್ಯ __real_free(ಶೂನ್ಯ *);
ಬಾಹ್ಯ ವರ್ಣ *__real_strdup(ಧ್ರುವ ವರ್ಣ *);

ಸಂರಚನಾ arena_ಗಂಟು {
	ಶೂನ್ಯ *ptr;
	ಸಂರಚನಾ arena_ಗಂಟು *next;
};

ಸ್ಥಿರ ಸಂರಚನಾ arena_ಗಂಟು *arena_head;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ tracking;

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಶೂನ್ಯ
arena_track(ಶೂನ್ಯ *p)
{
	ಸಂರಚನಾ arena_ಗಂಟು *n;
	ಯದಿ (!tracking || p == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	n = (ಸಂರಚನಾ arena_ಗಂಟು *)__real_malloc(ಪರಿಮಾಣ(*n));
	ಯದಿ (n == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಶೂನ್ಯ
arena_untrack(ಶೂನ್ಯ *p)
{
	ಸಂರಚನಾ arena_ಗಂಟು **pp;
	ಯದಿ (p == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (pp = &arena_head; *pp != ರಿಕ್ತ; pp = &(*pp)->next) {
		ಯದಿ ((*pp)->ptr == p) {
			ಸಂರಚನಾ arena_ಗಂಟು *n = *pp;
			*pp = n->next;
			__real_free(n);
			ಪ್ರತ್ಯಾಗಮ;
		}
	}
}

ಶೂನ್ಯ *
__wrap_malloc(size_t size)
{
	ಶೂನ್ಯ *p = __real_malloc(size);
	arena_track(p);
	ಪ್ರತ್ಯಾಗಮ p;
}

ಶೂನ್ಯ *
__wrap_calloc(size_t nmemb, size_t size)
{
	ಶೂನ್ಯ *p = __real_calloc(nmemb, size);
	arena_track(p);
	ಪ್ರತ್ಯಾಗಮ p;
}

ಶೂನ್ಯ *
__wrap_realloc(ಶೂನ್ಯ *ptr, size_t size)
{
	arena_untrack(ptr);
	ಶೂನ್ಯ *p = __real_realloc(ptr, size);
	arena_track(p);
	ಪ್ರತ್ಯಾಗಮ p;
}

ಶೂನ್ಯ
__wrap_free(ಶೂನ್ಯ *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

ವರ್ಣ *
__wrap_strdup(ಧ್ರುವ ವರ್ಣ *s)
{
	size_t len;
	ವರ್ಣ *p;
	ಯದಿ (s == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	len = strlen(s) + 1;
	p = (ವರ್ಣ *)__real_malloc(len);
	ಯದಿ (p == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	memcpy(p, s, len);
	arena_track(p);
	ಪ್ರತ್ಯಾಗಮ p;
}

ಶೂನ್ಯ
fuzz_arena_begin(ಶೂನ್ಯ)
{
	tracking = 1;
}

ಶೂನ್ಯ
fuzz_arena_release(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ arena_ಗಂಟು *n;
	tracking = 0;
	ಯಾವತ್ (arena_head != ರಿಕ್ತ) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

ಶೂನ್ಯ
fuzz_arena_cleanup(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ arena_ಗಂಟು *n;
	tracking = 0;
	ಯಾವತ್ (arena_head != ರಿಕ್ತ) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
