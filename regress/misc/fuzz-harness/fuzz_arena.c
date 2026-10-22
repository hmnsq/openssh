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

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

ബാഹ്യ ശൂന്യം *__real_malloc(size_t);
ബാഹ്യ ശൂന്യം *__real_calloc(size_t, size_t);
ബാഹ്യ ശൂന്യം *__real_realloc(ശൂന്യം *, size_t);
ബാഹ്യ ശൂന്യം __real_free(ശൂന്യം *);
ബാഹ്യ അക്ഷരം *__real_strdup(സ്ഥിരം അക്ഷരം *);

ഘടന arena_കണ്ണി {
	ശൂന്യം *ptr;
	ഘടന arena_കണ്ണി *next;
};

സ്ഥിതം ഘടന arena_കണ്ണി *arena_head;
സ്ഥിതം പൂർണ്ണസംഖ്യ tracking;

സ്ഥിതം വരിയിൽ ശൂന്യം
arena_track(ശൂന്യം *p)
{
	ഘടന arena_കണ്ണി *n;
	എങ്കിൽ (!tracking || p == ശൂന്യ)
		തിരികെ;
	n = (ഘടന arena_കണ്ണി *)__real_malloc(വലുപ്പം(*n));
	എങ്കിൽ (n == ശൂന്യ)
		തിരികെ;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

സ്ഥിതം വരിയിൽ ശൂന്യം
arena_untrack(ശൂന്യം *p)
{
	ഘടന arena_കണ്ണി **pp;
	എങ്കിൽ (p == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (pp = &arena_head; *pp != ശൂന്യ; pp = &(*pp)->next) {
		എങ്കിൽ ((*pp)->ptr == p) {
			ഘടന arena_കണ്ണി *n = *pp;
			*pp = n->next;
			__real_free(n);
			തിരികെ;
		}
	}
}

ശൂന്യം *
__wrap_malloc(size_t size)
{
	ശൂന്യം *p = __real_malloc(size);
	arena_track(p);
	തിരികെ p;
}

ശൂന്യം *
__wrap_calloc(size_t nmemb, size_t size)
{
	ശൂന്യം *p = __real_calloc(nmemb, size);
	arena_track(p);
	തിരികെ p;
}

ശൂന്യം *
__wrap_realloc(ശൂന്യം *ptr, size_t size)
{
	arena_untrack(ptr);
	ശൂന്യം *p = __real_realloc(ptr, size);
	arena_track(p);
	തിരികെ p;
}

ശൂന്യം
__wrap_free(ശൂന്യം *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

അക്ഷരം *
__wrap_strdup(സ്ഥിരം അക്ഷരം *s)
{
	size_t len;
	അക്ഷരം *p;
	എങ്കിൽ (s == ശൂന്യ)
		തിരികെ ശൂന്യ;
	len = strlen(s) + 1;
	p = (അക്ഷരം *)__real_malloc(len);
	എങ്കിൽ (p == ശൂന്യ)
		തിരികെ ശൂന്യ;
	memcpy(p, s, len);
	arena_track(p);
	തിരികെ p;
}

ശൂന്യം
fuzz_arena_begin(ശൂന്യം)
{
	tracking = 1;
}

ശൂന്യം
fuzz_arena_release(ശൂന്യം)
{
	ഘടന arena_കണ്ണി *n;
	tracking = 0;
	ആകുമ്പോൾ (arena_head != ശൂന്യ) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

ശൂന്യം
fuzz_arena_cleanup(ശൂന്യം)
{
	ഘടന arena_കണ്ണി *n;
	tracking = 0;
	ആകുമ്പോൾ (arena_head != ശൂന്യ) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
