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

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "log.h"

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ log_initialized = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
noop_cb(ಸಂರಚನಾ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)l; (ಶೂನ್ಯ)ctx;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	ಸ್ಥಿರ ಧ್ರುವ u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_ಕೀಲಿ,
		HKF_WANT_MATCH | HKF_WANT_PARSE_ಕೀಲಿ,
	};
	ಪ್ರತಿ (size_t i = 0; i < ಪರಿಮಾಣ(flag_combos)/ಪರಿಮಾಣ(flag_combos[0]); i++) {
		FILE *f = fmemopen((ಶೂನ್ಯ *)data, size, "r");
		ಯದಿ (f == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಧ್ರುವ ವರ್ಣ *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : ರಿಕ್ತ;
		(ಶೂನ್ಯ)hostkeys_foreach_file("/fuzz", f, noop_cb, ರಿಕ್ತ,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((ಶೂನ್ಯ *)data, size, "r");
		ಯದಿ (f != ರಿಕ್ತ) {
			ಸಂರಚನಾ hostkeys *hk = init_hostkeys();
			ಯದಿ (hk != ರಿಕ್ತ) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	ಯದಿ (size > 0) {
		size_t n = size < 256 ? size : 256;
		ವರ್ಣ *hb = (ವರ್ಣ *)malloc(n + 1);
		ಯದಿ (hb != ರಿಕ್ತ) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			ವರ್ಣ *h = host_hash("example.com", hb, 0);
			ಮುಕ್ತ(h);
			ಮುಕ್ತ(hb);
		}
	}

	ಪ್ರತ್ಯಾಗಮ 0;
}

} // extern "C"
