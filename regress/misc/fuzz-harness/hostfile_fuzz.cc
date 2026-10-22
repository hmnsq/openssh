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

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

बाह्य "C" {

#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "log.h"

स्थिर पूर्णाङ्क log_initialized = 0;

स्थिर पूर्णाङ्क
noop_cb(संरचना hostkey_foreach_पङ्क्तिः *l, शून्य *ctx)
{
	(शून्य)l; (शून्य)ctx;
	प्रत्यागम 0;
}

पूर्णाङ्क
LLVMFuzzer_Test_One_निवेशः(ध्रुव uint8_t *data, size_t size)
{
	जइ (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	स्थिर ध्रुव u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_कुञ्चिका,
		HKF_WANT_MATCH | HKF_WANT_PARSE_कुञ्चिका,
	};
	प्रति (size_t i = 0; i < परिमाण(flag_combos)/परिमाण(flag_combos[0]); i++) {
		FILE *f = fmemopen((शून्य *)data, size, "r");
		जइ (f == रिक्त)
			अनुवर्त;
		ध्रुव वर्ण *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : रिक्त;
		(शून्य)hostkeys_foreach_file("/fuzz", f, noop_cb, रिक्त,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((शून्य *)data, size, "r");
		जइ (f != रिक्त) {
			संरचना hostkeys *hk = init_hostkeys();
			जइ (hk != रिक्त) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	जइ (size > 0) {
		size_t n = size < 256 ? size : 256;
		वर्ण *hb = (वर्ण *)malloc(n + 1);
		जइ (hb != रिक्त) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			वर्ण *h = host_hash("example.com", hb, 0);
			मुक्त(h);
			मुक्त(hb);
		}
	}

	प्रत्यागम 0;
}

} // extern "C"
