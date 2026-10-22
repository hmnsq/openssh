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

#ضمن <stdio.h>
#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

خارجي "C" {

#ضمن "hostfile.h"
#ضمن "sshkey.h"
#ضمن "log.h"

ساكن صحيح log_initialized = 0;

ساكن صحيح
noop_cb(بنية hostkey_foreach_سٽ *l, فراغ *ctx)
{
	(فراغ)l; (فراغ)ctx;
	أرجع 0;
}

صحيح
LLVMFuzzer_Test_One_داخلا(ثابت uint8_t *معلومات, سائيز_t سائيز)
{
	إذا (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	ساكن ثابت u_int flag_combos[] = {
		0,
		HKF_WANT_ميلاپ,
		HKF_WANT_PARSE_ڪنجي,
		HKF_WANT_ميلاپ | HKF_WANT_PARSE_ڪنجي,
	};
	لكل (سائيز_t i = 0; i < حجم(flag_combos)/حجم(flag_combos[0]); i++) {
		FILE *f = fmemopen((فراغ *)معلومات, سائيز, "r");
		إذا (f == عدم)
			استمر;
		ثابت حرف *host = (flag_combos[i] & HKF_WANT_ميلاپ) ?
		    "example.com" : عدم;
		(فراغ)hostkeys_foreach_file("/fuzz", f, noop_cb, عدم,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((فراغ *)معلومات, سائيز, "r");
		إذا (f != عدم) {
			بنية hostkeys *hk = init_hostkeys();
			إذا (hk != عدم) {
				ڀريو_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	إذا (سائيز > 0) {
		سائيز_t n = سائيز < 256 ? سائيز : 256;
		حرف *hb = (حرف *)يادگيري_ڏيو(n + 1);
		إذا (hb != عدم) {
			يادگيري_نقل(hb, معلومات, n);
			hb[n] = '\0';
			حرف *h = host_hash("example.com", hb, 0);
			حرر(h);
			حرر(hb);
		}
	}

	أرجع 0;
}

} // extern "C"
