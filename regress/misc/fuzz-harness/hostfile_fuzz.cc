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

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

বাহ্যিক "C" {

#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "log.h"

স্থির পূর্ণসংখ্যা log_initialized = 0;

স্থির পূর্ণসংখ্যা
noop_cb(কাঠামো hostkey_foreach_সারি *l, শূন্য *ctx)
{
	(শূন্য)l; (শূন্য)ctx;
	ফেরত 0;
}

পূর্ণসংখ্যা
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	স্থির ধ্রুবক u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_চাবি,
		HKF_WANT_MATCH | HKF_WANT_PARSE_চাবি,
	};
	জন্য (আকার_t i = 0; i < আকার(flag_combos)/আকার(flag_combos[0]); i++) {
		FILE *f = fmemopen((শূন্য *)তথ্য, আকার_2, "r");
		যদি (f == ফাঁকা)
			চালু;
		ধ্রুবক অক্ষর *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : ফাঁকা;
		(শূন্য)hostkeys_foreach_file("/fuzz", f, noop_cb, ফাঁকা,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((শূন্য *)তথ্য, আকার_2, "r");
		যদি (f != ফাঁকা) {
			কাঠামো hostkeys *hk = init_hostkeys();
			যদি (hk != ফাঁকা) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	যদি (আকার_2 > 0) {
		আকার_t n = আকার_2 < 256 ? আকার_2 : 256;
		অক্ষর *hb = (অক্ষর *)malloc(n + 1);
		যদি (hb != ফাঁকা) {
			memcpy(hb, তথ্য, n);
			hb[n] = '\0';
			অক্ষর *h = host_hash("example.com", hb, 0);
			মুক্ত(h);
			মুক্ত(hb);
		}
	}

	ফেরত 0;
}

} // extern "C"
