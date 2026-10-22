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

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

బాహ్య శూన్య *__real_malloc(కొలత_t);
బాహ్య శూన్య *__real_calloc(కొలత_t, కొలత_t);
బాహ్య శూన్య *__real_realloc(శూన్య *, కొలత_t);
బాహ్య శూన్య __real_free(శూన్య *);
బాహ్య అక్షరం *__real_strdup(స్థిరరాశి అక్షరం *);

నిర్మాణం arena_కణుపు {
	శూన్య *ptr;
	నిర్మాణం arena_కణుపు *తదుపరి;
};

స్థిర నిర్మాణం arena_కణుపు *arena_తల;
స్థిర పూర్ణాంకం tracking;

స్థిర అంతఃవరుస శూన్య
arena_track(శూన్య *p)
{
	నిర్మాణం arena_కణుపు *n;
	ఒకవేళ (!tracking || p == ఖాళీ)
		తిరిగి;
	n = (నిర్మాణం arena_కణుపు *)__real_malloc(పరిమాణం(*n));
	ఒకవేళ (n == ఖాళీ)
		తిరిగి;
	n->ptr = p;
	n->తదుపరి = arena_తల;
	arena_తల = n;
}

స్థిర అంతఃవరుస శూన్య
arena_untrack(శూన్య *p)
{
	నిర్మాణం arena_కణుపు **pp;
	ఒకవేళ (p == ఖాళీ)
		తిరిగి;
	కొరకు (pp = &arena_తల; *pp != ఖాళీ; pp = &(*pp)->తదుపరి) {
		ఒకవేళ ((*pp)->ptr == p) {
			నిర్మాణం arena_కణుపు *n = *pp;
			*pp = n->తదుపరి;
			__real_free(n);
			తిరిగి;
		}
	}
}

శూన్య *
__wrap_malloc(కొలత_t కొలత)
{
	శూన్య *p = __real_malloc(కొలత);
	arena_track(p);
	తిరిగి p;
}

శూన్య *
__wrap_calloc(కొలత_t nmemb, కొలత_t కొలత)
{
	శూన్య *p = __real_calloc(nmemb, కొలత);
	arena_track(p);
	తిరిగి p;
}

శూన్య *
__wrap_realloc(శూన్య *ptr, కొలత_t కొలత)
{
	arena_untrack(ptr);
	శూన్య *p = __real_realloc(ptr, కొలత);
	arena_track(p);
	తిరిగి p;
}

శూన్య
__wrap_free(శూన్య *ptr)
{
	arena_untrack(ptr);
	__real_free(ptr);
}

అక్షరం *
__wrap_strdup(స్థిరరాశి అక్షరం *s)
{
	కొలత_t len;
	అక్షరం *p;
	ఒకవేళ (s == ఖాళీ)
		తిరిగి ఖాళీ;
	len = అక్షరశ్రేణి_పొడవు(s) + 1;
	p = (అక్షరం *)__real_malloc(len);
	ఒకవేళ (p == ఖాళీ)
		తిరిగి ఖాళీ;
	జ్ఞాపకం_నకలు(p, s, len);
	arena_track(p);
	తిరిగి p;
}

శూన్య
fuzz_arena_begin(శూన్య)
{
	tracking = 1;
}

శూన్య
fuzz_arena_release(శూన్య)
{
	నిర్మాణం arena_కణుపు *n;
	tracking = 0;
	అయితే (arena_తల != ఖాళీ) {
		n = arena_తల;
		arena_తల = n->తదుపరి;
		__real_free(n);
	}
}

శూన్య
fuzz_arena_cleanup(శూన్య)
{
	నిర్మాణం arena_కణుపు *n;
	tracking = 0;
	అయితే (arena_తల != ఖాళీ) {
		n = arena_తల;
		arena_తల = n->తదుపరి;
		__real_free(n->ptr);
		__real_free(n);
	}
}
