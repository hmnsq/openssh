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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ log_initialized = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
noop_cb(ರಚನೆ hostkey_foreach_ಸಾಲು *l, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)l; (ಶೂನ್ಯ)ctx;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ u_int flag_combos[] = {
		0,
		HKF_WANT_ಹೊಂದಿಕೆ,
		HKF_WANT_PARSE_ಕೀಲಿ,
		HKF_WANT_ಹೊಂದಿಕೆ | HKF_WANT_PARSE_ಕೀಲಿ,
	};
	ಗಾಗಿ (ಗಾತ್ರ_t i = 0; i < ಗಾತ್ರ(flag_combos)/ಗಾತ್ರ(flag_combos[0]); i++) {
		FILE *f = fmemopen((ಶೂನ್ಯ *)ದತ್ತಾಂಶ, ಗಾತ್ರ_2, "r");
		ಆದರೆ (f == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host = (flag_combos[i] & HKF_WANT_ಹೊಂದಿಕೆ) ?
		    "example.com" : ಖಾಲಿ;
		(ಶೂನ್ಯ)hostkeys_foreach_file("/fuzz", f, noop_cb, ಖಾಲಿ,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((ಶೂನ್ಯ *)ದತ್ತಾಂಶ, ಗಾತ್ರ_2, "r");
		ಆದರೆ (f != ಖಾಲಿ) {
			ರಚನೆ hostkeys *hk = init_hostkeys();
			ಆದರೆ (hk != ಖಾಲಿ) {
				ತುಂಬು_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	ಆದರೆ (ಗಾತ್ರ_2 > 0) {
		ಗಾತ್ರ_t n = ಗಾತ್ರ_2 < 256 ? ಗಾತ್ರ_2 : 256;
		ಅಕ್ಷರ *hb = (ಅಕ್ಷರ *)ಸ್ಮರಣೆ_ಕೊಡು(n + 1);
		ಆದರೆ (hb != ಖಾಲಿ) {
			ಸ್ಮರಣೆ_ನಕಲು(hb, ದತ್ತಾಂಶ, n);
			hb[n] = '\0';
			ಅಕ್ಷರ *h = host_hash("example.com", hb, 0);
			ಬಿಡುಗಡೆ(h);
			ಬಿಡುಗಡೆ(hb);
		}
	}

	ಹಿಂತಿರುಗಿ 0;
}

} // extern "C"
