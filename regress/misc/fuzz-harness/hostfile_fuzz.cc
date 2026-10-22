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

বাহ্য "C" {

#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "log.h"

স্থির পূর্ণাঙ্ক log_initialized = 0;

স্থির পূর্ণাঙ্ক
noop_cb(সংরচনা hostkey_foreach_সারি *l, শূন্য *ctx)
{
	(শূন্য)l; (শূন্য)ctx;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t *data, size_t size)
{
	যদি (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	স্থির ধ্রুব u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_চাবি,
		HKF_WANT_MATCH | HKF_WANT_PARSE_চাবি,
	};
	প্রতি (size_t i = 0; i < পরিমাণ(flag_combos)/পরিমাণ(flag_combos[0]); i++) {
		FILE *f = fmemopen((শূন্য *)data, size, "r");
		যদি (f == রিক্ত)
			অনুবর্ত;
		ধ্রুব বর্ণ *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : রিক্ত;
		(শূন্য)hostkeys_foreach_file("/fuzz", f, noop_cb, রিক্ত,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((শূন্য *)data, size, "r");
		যদি (f != রিক্ত) {
			সংরচনা hostkeys *hk = init_hostkeys();
			যদি (hk != রিক্ত) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	যদি (size > 0) {
		size_t n = size < 256 ? size : 256;
		বর্ণ *hb = (বর্ণ *)malloc(n + 1);
		যদি (hb != রিক্ত) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			বর্ণ *h = host_hash("example.com", hb, 0);
			মুক্ত(h);
			মুক্ত(hb);
		}
	}

	প্রত্যাগম 0;
}

} // extern "C"
