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

#شامل <stdio.h>
#شامل <stddef.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

بیرونی "C" {

#شامل "hostfile.h"
#شامل "sshkey.h"
#شامل "log.h"

ایستا صحیح log_initialized = 0;

ایستا صحیح
noop_cb(ساختار hostkey_foreach_سطر *l, تهی *ctx)
{
	(تهی)l; (تهی)ctx;
	بازگشت 0;
}

صحیح
LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t *data, size_t size)
{
	اگر (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	ایستا ثابت u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_کلید,
		HKF_WANT_MATCH | HKF_WANT_PARSE_کلید,
	};
	برای (size_t i = 0; i < اندازه(flag_combos)/اندازه(flag_combos[0]); i++) {
		FILE *f = fmemopen((تهی *)data, size, "r");
		اگر (f == پوچ)
			ادامه;
		ثابت نویسه *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : پوچ;
		(تهی)hostkeys_foreach_file("/fuzz", f, noop_cb, پوچ,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((تهی *)data, size, "r");
		اگر (f != پوچ) {
			ساختار hostkeys *hk = init_hostkeys();
			اگر (hk != پوچ) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	اگر (size > 0) {
		size_t n = size < 256 ? size : 256;
		نویسه *hb = (نویسه *)malloc(n + 1);
		اگر (hb != پوچ) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			نویسه *h = host_hash("example.com", hb, 0);
			آزاد(h);
			آزاد(hb);
		}
	}

	بازگشت 0;
}

} // extern "C"
