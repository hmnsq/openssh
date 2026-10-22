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

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਸਥਿਰ ਪੂਰਨ log_initialized = 0;

ਸਥਿਰ ਪੂਰਨ
noop_cb(ਬਣਤਰ hostkey_foreach_ਸਤਰ *l, ਖਾਲੀ *ctx)
{
	(ਖਾਲੀ)l; (ਖਾਲੀ)ctx;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	ਸਥਿਰ ਅਚਲ u_int flag_combos[] = {
		0,
		HKF_WANT_ਮੇਲ,
		HKF_WANT_PARSE_ਕੁੰਜੀ,
		HKF_WANT_ਮੇਲ | HKF_WANT_PARSE_ਕੁੰਜੀ,
	};
	ਲਈ (ਮਾਪ_t i = 0; i < ਆਕਾਰ(flag_combos)/ਆਕਾਰ(flag_combos[0]); i++) {
		FILE *f = fmemopen((ਖਾਲੀ *)ਅੰਕੜੇ, ਮਾਪ, "r");
		ਜੇ (f == ਨਿਰਾ)
			ਜਾਰੀ;
		ਅਚਲ ਅੱਖਰ *host = (flag_combos[i] & HKF_WANT_ਮੇਲ) ?
		    "example.com" : ਨਿਰਾ;
		(ਖਾਲੀ)hostkeys_foreach_file("/fuzz", f, noop_cb, ਨਿਰਾ,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((ਖਾਲੀ *)ਅੰਕੜੇ, ਮਾਪ, "r");
		ਜੇ (f != ਨਿਰਾ) {
			ਬਣਤਰ hostkeys *hk = init_hostkeys();
			ਜੇ (hk != ਨਿਰਾ) {
				ਲੱਦੋ_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	ਜੇ (ਮਾਪ > 0) {
		ਮਾਪ_t n = ਮਾਪ < 256 ? ਮਾਪ : 256;
		ਅੱਖਰ *hb = (ਅੱਖਰ *)ਸਮ੍ਰਿਤੀ_ਦਿਓ(n + 1);
		ਜੇ (hb != ਨਿਰਾ) {
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(hb, ਅੰਕੜੇ, n);
			hb[n] = '\0';
			ਅੱਖਰ *h = host_hash("example.com", hb, 0);
			ਮੁਕਤ(h);
			ਮੁਕਤ(hb);
		}
	}

	ਵਾਪਸ 0;
}

} // extern "C"
