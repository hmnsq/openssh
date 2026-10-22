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

ಬಾಹ್ಯ ಶೂನ್ಯ *__real_malloc(ಗಾತ್ರ_t);
ಬಾಹ್ಯ ಶೂನ್ಯ *__real_calloc(ಗಾತ್ರ_t, ಗಾತ್ರ_t);
ಬಾಹ್ಯ ಶೂನ್ಯ *__real_realloc(ಶೂನ್ಯ *, ಗಾತ್ರ_t);
ಬಾಹ್ಯ ಶೂನ್ಯ __real_free(ಶೂನ್ಯ *);
ಬಾಹ್ಯ ಅಕ್ಷರ *__real_strdup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ರಚನೆ arena_ಗಂಟು {
	ಶೂನ್ಯ *ptr;
	ರಚನೆ arena_ಗಂಟು *ಮುಂದಿನ;
};

ಸ್ಥಿರ ರಚನೆ arena_ಗಂಟು *arena_ತಲೆ;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ tracking;

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
arena_track(ಶೂನ್ಯ *p)
{
	ರಚನೆ arena_ಗಂಟು *n;
	ಆದರೆ (!tracking || p == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	n = (ರಚನೆ arena_ಗಂಟು *)__real_malloc(ಗಾತ್ರ(*n));
	ಆದರೆ (n == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	n->ptr = p;
	n->ಮುಂದಿನ = arena_ತಲೆ;
	arena_ತಲೆ = n;
}

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
arena_untrack(ಶೂನ್ಯ *p)
{
	ರಚನೆ arena_ಗಂಟು **pp;
	ಆದರೆ (p == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (pp = &arena_ತಲೆ; *pp != ಖಾಲಿ; pp = &(*pp)->ಮುಂದಿನ) {
		ಆದರೆ ((*pp)->ptr == p) {
			ರಚನೆ arena_ಗಂಟು *n = *pp;
			*pp = n->ಮುಂದಿನ;
			__real_free(n);
			ಹಿಂತಿರುಗಿ;
		}
	}
}

ಶೂನ್ಯ *
__wrap_malloc(ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಶೂನ್ಯ *p = __real_malloc(ಗಾತ್ರ_2);
	arena_track(p);
	ಹಿಂತಿರುಗಿ p;
}

ಶೂನ್ಯ *
__wrap_calloc(ಗಾತ್ರ_t nmemb, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಶೂನ್ಯ *p = __real_calloc(nmemb, ಗಾತ್ರ_2);
	arena_track(p);
	ಹಿಂತಿರುಗಿ p;
}

ಶೂನ್ಯ *
__wrap_realloc(ಶೂನ್ಯ *ptr, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	arena_untrack(ptr);
	ಶೂನ್ಯ *p = __real_realloc(ptr, ಗಾತ್ರ_2);
	arena_track(p);
	ಹಿಂತಿರುಗಿ p;
}

ಶೂನ್ಯ
__wrap_free(ಶೂನ್ಯ *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

ಅಕ್ಷರ *
__wrap_strdup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t len;
	ಅಕ್ಷರ *p;
	ಆದರೆ (s == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s) + 1;
	p = (ಅಕ್ಷರ *)__real_malloc(len);
	ಆದರೆ (p == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಸ್ಮರಣೆ_ನಕಲು(p, s, len);
	arena_track(p);
	ಹಿಂತಿರುಗಿ p;
}

ಶೂನ್ಯ
fuzz_arena_begin(ಶೂನ್ಯ)
{
	tracking = 1;
}

ಶೂನ್ಯ
fuzz_arena_release(ಶೂನ್ಯ)
{
	ರಚನೆ arena_ಗಂಟು *n;
	tracking = 0;
	ಆಗ (arena_ತಲೆ != ಖಾಲಿ) {
		n = arena_ತಲೆ;
		arena_ತಲೆ = n->ಮುಂದಿನ;
		__real_free(n);
	}
}

ಶೂನ್ಯ
fuzz_arena_cleanup(ಶೂನ್ಯ)
{
	ರಚನೆ arena_ಗಂಟು *n;
	tracking = 0;
	ಆಗ (arena_ತಲೆ != ಖಾಲಿ) {
		n = arena_ತಲೆ;
		arena_ತಲೆ = n->ಮುಂದಿನ;
		__real_free(n->ptr);
		__real_free(n);
	}
}
