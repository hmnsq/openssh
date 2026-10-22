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

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

ବାହ୍ୟ "C" {

#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା log_initialized = 0;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
noop_cb(ସଂରଚନା hostkey_foreach_ଧାଡ଼ି *l, ଶୂନ୍ୟ *ctx)
{
	(ଶୂନ୍ୟ)l; (ଶୂନ୍ୟ)ctx;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	ସ୍ଥିର ଅଚଳ u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_ଚାବି,
		HKF_WANT_MATCH | HKF_WANT_PARSE_ଚାବି,
	};
	ପାଇଁ (size_t i = 0; i < ଆକାର(flag_combos)/ଆକାର(flag_combos[0]); i++) {
		FILE *f = fmemopen((ଶୂନ୍ୟ *)data, size, "r");
		ଯଦି (f == ଖାଲି)
			ଜାରି;
		ଅଚଳ ଅକ୍ଷର *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : ଖାଲି;
		(ଶୂନ୍ୟ)hostkeys_foreach_file("/fuzz", f, noop_cb, ଖାଲି,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((ଶୂନ୍ୟ *)data, size, "r");
		ଯଦି (f != ଖାଲି) {
			ସଂରଚନା hostkeys *hk = init_hostkeys();
			ଯଦି (hk != ଖାଲି) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	ଯଦି (size > 0) {
		size_t n = size < 256 ? size : 256;
		ଅକ୍ଷର *hb = (ଅକ୍ଷର *)malloc(n + 1);
		ଯଦି (hb != ଖାଲି) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			ଅକ୍ଷର *h = host_hash("example.com", hb, 0);
			ମୁକ୍ତ(h);
			ମୁକ୍ତ(hb);
		}
	}

	ଫେରନ୍ତୁ 0;
}

} // extern "C"
