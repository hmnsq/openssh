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

خارجی خالی *__real_malloc(سائز_t);
خارجی خالی *__real_calloc(سائز_t, سائز_t);
خارجی خالی *__real_realloc(خالی *, سائز_t);
خارجی خالی __real_free(خالی *);
خارجی حرف *__real_strdup(ثابت حرف *);

ساخت arena_گرہ {
	خالی *ptr;
	ساخت arena_گرہ *اگلا;
};

ساکن ساخت arena_گرہ *arena_سر;
ساکن صحیح tracking;

ساکن اندرونی خالی
arena_track(خالی *p)
{
	ساخت arena_گرہ *n;
	اگر (!tracking || p == تہی)
		واپس;
	n = (ساخت arena_گرہ *)__real_malloc(حجم(*n));
	اگر (n == تہی)
		واپس;
	n->ptr = p;
	n->اگلا = arena_سر;
	arena_سر = n;
}

ساکن اندرونی خالی
arena_untrack(خالی *p)
{
	ساخت arena_گرہ **pp;
	اگر (p == تہی)
		واپس;
	برائے (pp = &arena_سر; *pp != تہی; pp = &(*pp)->اگلا) {
		اگر ((*pp)->ptr == p) {
			ساخت arena_گرہ *n = *pp;
			*pp = n->اگلا;
			__real_free(n);
			واپس;
		}
	}
}

خالی *
__wrap_malloc(سائز_t سائز)
{
	خالی *p = __real_malloc(سائز);
	arena_track(p);
	واپس p;
}

خالی *
__wrap_calloc(سائز_t nmemb, سائز_t سائز)
{
	خالی *p = __real_calloc(nmemb, سائز);
	arena_track(p);
	واپس p;
}

خالی *
__wrap_realloc(خالی *ptr, سائز_t سائز)
{
	arena_untrack(ptr);
	خالی *p = __real_realloc(ptr, سائز);
	arena_track(p);
	واپس p;
}

خالی
__wrap_free(خالی *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

حرف *
__wrap_strdup(ثابت حرف *s)
{
	سائز_t len;
	حرف *p;
	اگر (s == تہی)
		واپس تہی;
	len = لڑی_لمبائی(s) + 1;
	p = (حرف *)__real_malloc(len);
	اگر (p == تہی)
		واپس تہی;
	حافظہ_نقل(p, s, len);
	arena_track(p);
	واپس p;
}

خالی
fuzz_arena_begin(خالی)
{
	tracking = 1;
}

خالی
fuzz_arena_release(خالی)
{
	ساخت arena_گرہ *n;
	tracking = 0;
	جب (arena_سر != تہی) {
		n = arena_سر;
		arena_سر = n->اگلا;
		__real_free(n);
	}
}

خالی
fuzz_arena_cleanup(خالی)
{
	ساخت arena_گرہ *n;
	tracking = 0;
	جب (arena_سر != تہی) {
		n = arena_سر;
		arena_سر = n->اگلا;
		__real_free(n->ptr);
		__real_free(n);
	}
}
