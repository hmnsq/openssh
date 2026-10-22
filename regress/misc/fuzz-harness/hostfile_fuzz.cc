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

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

બાહ્ય "C" {

#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "log.h"

સ્થિર પૂર્ણાંક log_initialized = 0;

સ્થિર પૂર્ણાંક
noop_cb(સંરચના hostkey_foreach_લીટી *l, શૂન્ય *ctx)
{
	(શૂન્ય)l; (શૂન્ય)ctx;
	પાછા 0;
}

પૂર્ણાંક
LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size)
{
	જો (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	સ્થિર અચલ u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_ચાવી,
		HKF_WANT_MATCH | HKF_WANT_PARSE_ચાવી,
	};
	માટે (size_t i = 0; i < કદ(flag_combos)/કદ(flag_combos[0]); i++) {
		FILE *f = fmemopen((શૂન્ય *)data, size, "r");
		જો (f == ખાલી)
			ચાલુ;
		અચલ અક્ષર *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : ખાલી;
		(શૂન્ય)hostkeys_foreach_file("/fuzz", f, noop_cb, ખાલી,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((શૂન્ય *)data, size, "r");
		જો (f != ખાલી) {
			સંરચના hostkeys *hk = init_hostkeys();
			જો (hk != ખાલી) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	જો (size > 0) {
		size_t n = size < 256 ? size : 256;
		અક્ષર *hb = (અક્ષર *)malloc(n + 1);
		જો (hb != ખાલી) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			અક્ષર *h = host_hash("example.com", hb, 0);
			મુક્ત(h);
			મુક્ત(hb);
		}
	}

	પાછા 0;
}

} // extern "C"
