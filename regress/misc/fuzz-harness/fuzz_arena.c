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

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

બાહ્ય શૂન્ય *__real_malloc(size_t);
બાહ્ય શૂન્ય *__real_calloc(size_t, size_t);
બાહ્ય શૂન્ય *__real_realloc(શૂન્ય *, size_t);
બાહ્ય શૂન્ય __real_free(શૂન્ય *);
બાહ્ય અક્ષર *__real_strdup(અચલ અક્ષર *);

સંરચના arena_ગાંઠ {
	શૂન્ય *ptr;
	સંરચના arena_ગાંઠ *next;
};

સ્થિર સંરચના arena_ગાંઠ *arena_head;
સ્થિર પૂર્ણાંક tracking;

સ્થિર અંતઃરેખ શૂન્ય
arena_track(શૂન્ય *p)
{
	સંરચના arena_ગાંઠ *n;
	જો (!tracking || p == ખાલી)
		પાછા;
	n = (સંરચના arena_ગાંઠ *)__real_malloc(કદ(*n));
	જો (n == ખાલી)
		પાછા;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

સ્થિર અંતઃરેખ શૂન્ય
arena_untrack(શૂન્ય *p)
{
	સંરચના arena_ગાંઠ **pp;
	જો (p == ખાલી)
		પાછા;
	માટે (pp = &arena_head; *pp != ખાલી; pp = &(*pp)->next) {
		જો ((*pp)->ptr == p) {
			સંરચના arena_ગાંઠ *n = *pp;
			*pp = n->next;
			__real_free(n);
			પાછા;
		}
	}
}

શૂન્ય *
__wrap_malloc(size_t size)
{
	શૂન્ય *p = __real_malloc(size);
	arena_track(p);
	પાછા p;
}

શૂન્ય *
__wrap_calloc(size_t nmemb, size_t size)
{
	શૂન્ય *p = __real_calloc(nmemb, size);
	arena_track(p);
	પાછા p;
}

શૂન્ય *
__wrap_realloc(શૂન્ય *ptr, size_t size)
{
	arena_untrack(ptr);
	શૂન્ય *p = __real_realloc(ptr, size);
	arena_track(p);
	પાછા p;
}

શૂન્ય
__wrap_free(શૂન્ય *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

અક્ષર *
__wrap_strdup(અચલ અક્ષર *s)
{
	size_t len;
	અક્ષર *p;
	જો (s == ખાલી)
		પાછા ખાલી;
	len = strlen(s) + 1;
	p = (અક્ષર *)__real_malloc(len);
	જો (p == ખાલી)
		પાછા ખાલી;
	memcpy(p, s, len);
	arena_track(p);
	પાછા p;
}

શૂન્ય
fuzz_arena_begin(શૂન્ય)
{
	tracking = 1;
}

શૂન્ય
fuzz_arena_release(શૂન્ય)
{
	સંરચના arena_ગાંઠ *n;
	tracking = 0;
	જ્યારે (arena_head != ખાલી) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

શૂન્ય
fuzz_arena_cleanup(શૂન્ય)
{
	સંરચના arena_ગાંઠ *n;
	tracking = 0;
	જ્યારે (arena_head != ખાલી) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
