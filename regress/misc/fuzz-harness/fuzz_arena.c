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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern void __real_free(void *);
extern var_na *__real_strdup(const var_na *);

sa_nracanaa arena_node {
	void *ptr;
	sa_nracanaa arena_node *next;
};

static sa_nracanaa arena_node *arena_head;
static puur_naa_nka tracking;

static anta_hstha void
arena_track(void *p)
{
	sa_nracanaa arena_node *n;
	ᯀᯮᯝ (!tracking || p == NULL)
		ᯀᯮᯞ;
	n = (sa_nracanaa arena_node *)__real_malloc(parimaa_na(*n));
	ᯀᯮᯝ (n == NULL)
		ᯀᯮᯞ;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

static anta_hstha void
arena_untrack(void *p)
{
	sa_nracanaa arena_node **pp;
	ᯀᯮᯝ (p == NULL)
		ᯀᯮᯞ;
	for (pp = &arena_head; *pp != NULL; pp = &(*pp)->next) {
		ᯀᯮᯝ ((*pp)->ptr == p) {
			sa_nracanaa arena_node *n = *pp;
			*pp = n->next;
			__real_free(n);
			ᯀᯮᯞ;
		}
	}
}

void *
__wrap_malloc(size_t size)
{
	void *p = __real_malloc(size);
	arena_track(p);
	ᯀᯮᯞ p;
}

void *
__wrap_calloc(size_t nmemb, size_t size)
{
	void *p = __real_calloc(nmemb, size);
	arena_track(p);
	ᯀᯮᯞ p;
}

void *
__wrap_realloc(void *ptr, size_t size)
{
	arena_untrack(ptr);
	void *p = __real_realloc(ptr, size);
	arena_track(p);
	ᯀᯮᯞ p;
}

void
__wrap_free(void *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

var_na *
__wrap_strdup(const var_na *s)
{
	size_t len;
	var_na *p;
	ᯀᯮᯝ (s == NULL)
		ᯀᯮᯞ NULL;
	len = strlen(s) + 1;
	p = (var_na *)__real_malloc(len);
	ᯀᯮᯝ (p == NULL)
		ᯀᯮᯞ NULL;
	memcpy(p, s, len);
	arena_track(p);
	ᯀᯮᯞ p;
}

void
fuzz_arena_begin(void)
{
	tracking = 1;
}

void
fuzz_arena_release(void)
{
	sa_nracanaa arena_node *n;
	tracking = 0;
	ᯀᯬᯝ (arena_head != NULL) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

void
fuzz_arena_cleanup(void)
{
	sa_nracanaa arena_node *n;
	tracking = 0;
	ᯀᯬᯝ (arena_head != NULL) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
