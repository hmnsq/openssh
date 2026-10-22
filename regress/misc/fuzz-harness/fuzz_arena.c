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

#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ବାହ୍ୟ ଶୂନ୍ୟ *__real_malloc(size_t);
ବାହ୍ୟ ଶୂନ୍ୟ *__real_calloc(size_t, size_t);
ବାହ୍ୟ ଶୂନ୍ୟ *__real_realloc(ଶୂନ୍ୟ *, size_t);
ବାହ୍ୟ ଶୂନ୍ୟ __real_free(ଶୂନ୍ୟ *);
ବାହ୍ୟ ଅକ୍ଷର *__real_strdup(ଅଚଳ ଅକ୍ଷର *);

ସଂରଚନା arena_ଗଣ୍ଠି {
	ଶୂନ୍ୟ *ptr;
	ସଂରଚନା arena_ଗଣ୍ଠି *next;
};

ସ୍ଥିର ସଂରଚନା arena_ଗଣ୍ଠି *arena_head;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା tracking;

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
arena_track(ଶୂନ୍ୟ *p)
{
	ସଂରଚନା arena_ଗଣ୍ଠି *n;
	ଯଦି (!tracking || p == ଖାଲି)
		ଫେରନ୍ତୁ;
	n = (ସଂରଚନା arena_ଗଣ୍ଠି *)__real_malloc(ଆକାର(*n));
	ଯଦି (n == ଖାଲି)
		ଫେରନ୍ତୁ;
	n->ptr = p;
	n->next = arena_head;
	arena_head = n;
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
arena_untrack(ଶୂନ୍ୟ *p)
{
	ସଂରଚନା arena_ଗଣ୍ଠି **pp;
	ଯଦି (p == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (pp = &arena_head; *pp != ଖାଲି; pp = &(*pp)->next) {
		ଯଦି ((*pp)->ptr == p) {
			ସଂରଚନା arena_ଗଣ୍ଠି *n = *pp;
			*pp = n->next;
			__real_free(n);
			ଫେରନ୍ତୁ;
		}
	}
}

ଶୂନ୍ୟ *
__wrap_malloc(size_t size)
{
	ଶୂନ୍ୟ *p = __real_malloc(size);
	arena_track(p);
	ଫେରନ୍ତୁ p;
}

ଶୂନ୍ୟ *
__wrap_calloc(size_t nmemb, size_t size)
{
	ଶୂନ୍ୟ *p = __real_calloc(nmemb, size);
	arena_track(p);
	ଫେରନ୍ତୁ p;
}

ଶୂନ୍ୟ *
__wrap_realloc(ଶୂନ୍ୟ *ptr, size_t size)
{
	arena_untrack(ptr);
	ଶୂନ୍ୟ *p = __real_realloc(ptr, size);
	arena_track(p);
	ଫେରନ୍ତୁ p;
}

ଶୂନ୍ୟ
__wrap_free(ଶୂନ୍ୟ *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

ଅକ୍ଷର *
__wrap_strdup(ଅଚଳ ଅକ୍ଷର *s)
{
	size_t len;
	ଅକ୍ଷର *p;
	ଯଦି (s == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	len = strlen(s) + 1;
	p = (ଅକ୍ଷର *)__real_malloc(len);
	ଯଦି (p == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	memcpy(p, s, len);
	arena_track(p);
	ଫେରନ୍ତୁ p;
}

ଶୂନ୍ୟ
fuzz_arena_begin(ଶୂନ୍ୟ)
{
	tracking = 1;
}

ଶୂନ୍ୟ
fuzz_arena_release(ଶୂନ୍ୟ)
{
	ସଂରଚନା arena_ଗଣ୍ଠି *n;
	tracking = 0;
	ଯେତେବେଳେ (arena_head != ଖାଲି) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n);
	}
}

ଶୂନ୍ୟ
fuzz_arena_cleanup(ଶୂନ୍ୟ)
{
	ସଂରଚନା arena_ଗଣ୍ଠି *n;
	tracking = 0;
	ଯେତେବେଳେ (arena_head != ଖାଲି) {
		n = arena_head;
		arena_head = n->next;
		__real_free(n->ptr);
		__real_free(n);
	}
}
