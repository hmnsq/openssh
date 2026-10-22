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

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

బాహ్య "C" {

#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "log.h"

స్థిర పూర్ణాంకం log_initialized = 0;

స్థిర పూర్ణాంకం
noop_cb(నిర్మాణం hostkey_foreach_పంక్తి *l, శూన్య *ctx)
{
	(శూన్య)l; (శూన్య)ctx;
	తిరిగి 0;
}

పూర్ణాంకం
LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	స్థిర స్థిరరాశి u_int flag_combos[] = {
		0,
		HKF_WANT_సరిపోలిక,
		HKF_WANT_PARSE_కీలకం,
		HKF_WANT_సరిపోలిక | HKF_WANT_PARSE_కీలకం,
	};
	కొరకు (కొలత_t i = 0; i < పరిమాణం(flag_combos)/పరిమాణం(flag_combos[0]); i++) {
		FILE *f = fmemopen((శూన్య *)దత్తాంశం, కొలత, "r");
		ఒకవేళ (f == ఖాళీ)
			కొనసాగు;
		స్థిరరాశి అక్షరం *host = (flag_combos[i] & HKF_WANT_సరిపోలిక) ?
		    "example.com" : ఖాళీ;
		(శూన్య)hostkeys_foreach_file("/fuzz", f, noop_cb, ఖాళీ,
		    host, "127.0.0.1", flag_combos[i], 0);
		fclose(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		FILE *f = fmemopen((శూన్య *)దత్తాంశం, కొలత, "r");
		ఒకవేళ (f != ఖాళీ) {
			నిర్మాణం hostkeys *hk = init_hostkeys();
			ఒకవేళ (hk != ఖాళీ) {
				ఎక్కించు_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			fclose(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	ఒకవేళ (కొలత > 0) {
		కొలత_t n = కొలత < 256 ? కొలత : 256;
		అక్షరం *hb = (అక్షరం *)జ్ఞాపకం_ఇవ్వు(n + 1);
		ఒకవేళ (hb != ఖాళీ) {
			జ్ఞాపకం_నకలు(hb, దత్తాంశం, n);
			hb[n] = '\0';
			అక్షరం *h = host_hash("example.com", hb, 0);
			విడుదల(h);
			విడుదల(hb);
		}
	}

	తిరిగి 0;
}

} // extern "C"
