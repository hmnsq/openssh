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

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "log.h"

സ്ഥിതം പൂർണ്ണസംഖ്യ log_initialized = 0;

സ്ഥിതം പൂർണ്ണസംഖ്യ
noop_cb(ഘടന hostkey_foreach_വരി *l, ശൂന്യം *ctx)
{
	(ശൂന്യം)l; (ശൂന്യം)ctx;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	സ്ഥിതം സ്ഥിരം u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_താക്കോൽ,
		HKF_WANT_MATCH | HKF_WANT_PARSE_താക്കോൽ,
	};
	വേണ്ടി (size_t i = 0; i < വലുപ്പം(flag_combos)/വലുപ്പം(flag_combos[0]); i++) {
		FILE *f = fmemopen((ശൂന്യം *)data, size, "r");
		എങ്കിൽ (f == ശൂന്യ)
			തുടരുക;
		സ്ഥിരം അക്ഷരം *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : ശൂന്യ;
		(ശൂന്യം)hostkeys_foreach_file("/fuzz", f, noop_cb, ശൂന്യ,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((ശൂന്യം *)data, size, "r");
		എങ്കിൽ (f != ശൂന്യ) {
			ഘടന hostkeys *hk = init_hostkeys();
			എങ്കിൽ (hk != ശൂന്യ) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	എങ്കിൽ (size > 0) {
		size_t n = size < 256 ? size : 256;
		അക്ഷരം *hb = (അക്ഷരം *)malloc(n + 1);
		എങ്കിൽ (hb != ശൂന്യ) {
			memcpy(hb, data, n);
			hb[n] = '\0';
			അക്ഷരം *h = host_hash("example.com", hb, 0);
			സ്വതന്ത്രം(h);
			സ്വതന്ത്രം(hb);
		}
	}

	തിരികെ 0;
}

} // extern "C"
