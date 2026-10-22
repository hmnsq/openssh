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

#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

خارجي فراغ *__real_malloc(اندازه_t);
خارجي فراغ *__real_calloc(اندازه_t, اندازه_t);
خارجي فراغ *__real_realloc(فراغ *, اندازه_t);
خارجي فراغ __real_free(فراغ *);
خارجي حرف *__real_strdup(ثابت حرف *);

بنية arena_غوټه {
	فراغ *ptr;
	بنية arena_غوټه *بل;
};

ساكن بنية arena_غوټه *arena_سر;
ساكن صحيح tracking;

ساكن مضمن فراغ
arena_track(فراغ *p)
{
	بنية arena_غوټه *n;
	إذا (!tracking || p == عدم)
		أرجع;
	n = (بنية arena_غوټه *)__real_malloc(حجم(*n));
	إذا (n == عدم)
		أرجع;
	n->ptr = p;
	n->بل = arena_سر;
	arena_سر = n;
}

ساكن مضمن فراغ
arena_untrack(فراغ *p)
{
	بنية arena_غوټه **pp;
	إذا (p == عدم)
		أرجع;
	لكل (pp = &arena_سر; *pp != عدم; pp = &(*pp)->بل) {
		إذا ((*pp)->ptr == p) {
			بنية arena_غوټه *n = *pp;
			*pp = n->بل;
			__real_free(n);
			أرجع;
		}
	}
}

فراغ *
__wrap_malloc(اندازه_t اندازه)
{
	فراغ *p = __real_malloc(اندازه);
	arena_track(p);
	أرجع p;
}

فراغ *
__wrap_calloc(اندازه_t nmemb, اندازه_t اندازه)
{
	فراغ *p = __real_calloc(nmemb, اندازه);
	arena_track(p);
	أرجع p;
}

فراغ *
__wrap_realloc(فراغ *ptr, اندازه_t اندازه)
{
	arena_untrack(ptr);
	فراغ *p = __real_realloc(ptr, اندازه);
	arena_track(p);
	أرجع p;
}

فراغ
__wrap_free(فراغ *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

حرف *
__wrap_strdup(ثابت حرف *s)
{
	اندازه_t len;
	حرف *p;
	إذا (s == عدم)
		أرجع عدم;
	len = مزي_اوږدوالی(s) + 1;
	p = (حرف *)__real_malloc(len);
	إذا (p == عدم)
		أرجع عدم;
	حافظه_نقل(p, s, len);
	arena_track(p);
	أرجع p;
}

فراغ
fuzz_arena_begin(فراغ)
{
	tracking = 1;
}

فراغ
fuzz_arena_release(فراغ)
{
	بنية arena_غوټه *n;
	tracking = 0;
	طالما (arena_سر != عدم) {
		n = arena_سر;
		arena_سر = n->بل;
		__real_free(n);
	}
}

فراغ
fuzz_arena_cleanup(فراغ)
{
	بنية arena_غوټه *n;
	tracking = 0;
	طالما (arena_سر != عدم) {
		n = arena_سر;
		arena_سر = n->بل;
		__real_free(n->ptr);
		__real_free(n);
	}
}
