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

خارجی "C" {

#شامل "hostfile.h"
#شامل "sshkey.h"
#شامل "log.h"

ساکن صحیح log_initialized = 0;

ساکن صحیح
noop_cb(ساخت hostkey_foreach_سطر *l, خالی *ctx)
{
	(خالی)l; (خالی)ctx;
	واپس 0;
}

صحیح
LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	ساکن ثابت u_int flag_combos[] = {
		0,
		HKF_WANT_مطابقت,
		HKF_WANT_PARSE_کلید,
		HKF_WANT_مطابقت | HKF_WANT_PARSE_کلید,
	};
	برائے (سائز_t i = 0; i < حجم(flag_combos)/حجم(flag_combos[0]); i++) {
		FILE *f = fmemopen((خالی *)ڈیٹا, سائز, "r");
		اگر (f == تہی)
			جاری;
		ثابت حرف *host = (flag_combos[i] & HKF_WANT_مطابقت) ?
		    "example.com" : تہی;
		(خالی)hostkeys_foreach_file("/fuzz", f, noop_cb, تہی,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((خالی *)ڈیٹا, سائز, "r");
		اگر (f != تہی) {
			ساخت hostkeys *hk = init_hostkeys();
			اگر (hk != تہی) {
				بھرو_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	اگر (سائز > 0) {
		سائز_t n = سائز < 256 ? سائز : 256;
		حرف *hb = (حرف *)حافظہ_دو(n + 1);
		اگر (hb != تہی) {
			حافظہ_نقل(hb, ڈیٹا, n);
			hb[n] = '\0';
			حرف *h = host_hash("example.com", hb, 0);
			آزاد(h);
			آزاد(hb);
		}
	}

	واپس 0;
}

} // extern "C"
