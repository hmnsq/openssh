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

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਬਾਹਰੀ ਖਾਲੀ *__real_malloc(ਮਾਪ_t);
ਬਾਹਰੀ ਖਾਲੀ *__real_calloc(ਮਾਪ_t, ਮਾਪ_t);
ਬਾਹਰੀ ਖਾਲੀ *__real_realloc(ਖਾਲੀ *, ਮਾਪ_t);
ਬਾਹਰੀ ਖਾਲੀ __real_free(ਖਾਲੀ *);
ਬਾਹਰੀ ਅੱਖਰ *__real_strdup(ਅਚਲ ਅੱਖਰ *);

ਬਣਤਰ arena_ਗੰਢ {
	ਖਾਲੀ *ptr;
	ਬਣਤਰ arena_ਗੰਢ *ਅਗਲਾ;
};

ਸਥਿਰ ਬਣਤਰ arena_ਗੰਢ *arena_ਸਿਰ;
ਸਥਿਰ ਪੂਰਨ tracking;

ਸਥਿਰ ਸਤਰਅੰਦਰ ਖਾਲੀ
arena_track(ਖਾਲੀ *p)
{
	ਬਣਤਰ arena_ਗੰਢ *n;
	ਜੇ (!tracking || p == ਨਿਰਾ)
		ਵਾਪਸ;
	n = (ਬਣਤਰ arena_ਗੰਢ *)__real_malloc(ਆਕਾਰ(*n));
	ਜੇ (n == ਨਿਰਾ)
		ਵਾਪਸ;
	n->ptr = p;
	n->ਅਗਲਾ = arena_ਸਿਰ;
	arena_ਸਿਰ = n;
}

ਸਥਿਰ ਸਤਰਅੰਦਰ ਖਾਲੀ
arena_untrack(ਖਾਲੀ *p)
{
	ਬਣਤਰ arena_ਗੰਢ **pp;
	ਜੇ (p == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (pp = &arena_ਸਿਰ; *pp != ਨਿਰਾ; pp = &(*pp)->ਅਗਲਾ) {
		ਜੇ ((*pp)->ptr == p) {
			ਬਣਤਰ arena_ਗੰਢ *n = *pp;
			*pp = n->ਅਗਲਾ;
			__real_free(n);
			ਵਾਪਸ;
		}
	}
}

ਖਾਲੀ *
__wrap_malloc(ਮਾਪ_t ਮਾਪ)
{
	ਖਾਲੀ *p = __real_malloc(ਮਾਪ);
	arena_track(p);
	ਵਾਪਸ p;
}

ਖਾਲੀ *
__wrap_calloc(ਮਾਪ_t nmemb, ਮਾਪ_t ਮਾਪ)
{
	ਖਾਲੀ *p = __real_calloc(nmemb, ਮਾਪ);
	arena_track(p);
	ਵਾਪਸ p;
}

ਖਾਲੀ *
__wrap_realloc(ਖਾਲੀ *ptr, ਮਾਪ_t ਮਾਪ)
{
	arena_untrack(ptr);
	ਖਾਲੀ *p = __real_realloc(ptr, ਮਾਪ);
	arena_track(p);
	ਵਾਪਸ p;
}

ਖਾਲੀ
__wrap_free(ਖਾਲੀ *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

ਅੱਖਰ *
__wrap_strdup(ਅਚਲ ਅੱਖਰ *s)
{
	ਮਾਪ_t len;
	ਅੱਖਰ *p;
	ਜੇ (s == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	len = ਲੜੀ_ਲੰਬਾਈ(s) + 1;
	p = (ਅੱਖਰ *)__real_malloc(len);
	ਜੇ (p == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(p, s, len);
	arena_track(p);
	ਵਾਪਸ p;
}

ਖਾਲੀ
fuzz_arena_begin(ਖਾਲੀ)
{
	tracking = 1;
}

ਖਾਲੀ
fuzz_arena_release(ਖਾਲੀ)
{
	ਬਣਤਰ arena_ਗੰਢ *n;
	tracking = 0;
	ਜਦੋਂ (arena_ਸਿਰ != ਨਿਰਾ) {
		n = arena_ਸਿਰ;
		arena_ਸਿਰ = n->ਅਗਲਾ;
		__real_free(n);
	}
}

ਖਾਲੀ
fuzz_arena_cleanup(ਖਾਲੀ)
{
	ਬਣਤਰ arena_ਗੰਢ *n;
	tracking = 0;
	ਜਦੋਂ (arena_ਸਿਰ != ਨਿਰਾ) {
		n = arena_ਸਿਰ;
		arena_ਸਿਰ = n->ਅਗਲਾ;
		__real_free(n->ptr);
		__real_free(n);
	}
}
