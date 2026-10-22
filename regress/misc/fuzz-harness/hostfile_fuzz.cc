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

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

வெளி "C" {

#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "log.h"

நிலையான முழு log_initialized = 0;

நிலையான முழு
noop_cb(கட்டமைப்பு hostkey_foreach_வரி *l, வெறுமை *ctx)
{
	(வெறுமை)l; (வெறுமை)ctx;
	திரும்பு 0;
}

முழு
LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size)
{
	எனில் (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	நிலையான மாறிலி u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_சாவி,
		HKF_WANT_MATCH | HKF_WANT_PARSE_சாவி,
	};
	க்கு (size_t i = 0; i < அளவு(flag_combos)/அளவு(flag_combos[0]); i++) {
		FILE *f = fmemopen((வெறுமை *)data, size, "r");
		எனில் (f == வெற்று)
			தொடர்;
		மாறிலி எழுத்து *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : வெற்று;
		(வெறுமை)hostkeys_foreach_file("/fuzz", f, noop_cb, வெற்று,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((வெறுமை *)data, size, "r");
		எனில் (f != வெற்று) {
			கட்டமைப்பு hostkeys *hk = init_hostkeys();
			எனில் (hk != வெற்று) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	எனில் (size > 0) {
		size_t n = size < 256 ? size : 256;
		எழுத்து *hb = (எழுத்து *)malloc(n + 1);
		எனில் (hb != வெற்று) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			எழுத்து *h = host_hash("example.com", hb, 0);
			விடுவி(h);
			விடுவி(hb);
		}
	}

	திரும்பு 0;
}

} // extern "C"
