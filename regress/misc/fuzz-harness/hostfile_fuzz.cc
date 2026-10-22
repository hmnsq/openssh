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

#समावेश <stdio.h>
#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

बाह्य "C" {

#समावेश "hostfile.h"
#समावेश "sshkey.h"
#समावेश "log.h"

अटल पूर्णांक log_initialized = 0;

अटल पूर्णांक
noop_cb(काष्ठा hostkey_foreach_पंक्ति *l, व्योम *ctx)
{
	(व्योम)l; (व्योम)ctx;
	वापस 0;
}

पूर्णांक
LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (!log_initialized) {
		log_init("hostfile_fuzz", SYSLOG_LEVEL_QUIET,
		    SYSLOG_FACILITY_AUTH, 0);
		log_initialized = 1;
	}

	/* Drive every HKF_WANT_* combination on each input. */
	अटल स्थिर u_int flag_combos[] = {
		0,
		HKF_WANT_MATCH,
		HKF_WANT_PARSE_कुंजी,
		HKF_WANT_MATCH | HKF_WANT_PARSE_कुंजी,
	};
	क्रम (माप_प्रकार i = 0; i < माप(flag_combos)/माप(flag_combos[0]); i++) {
		खाता *f = fmemopen((व्योम *)तथ्य, आकार, "r");
		अगर (f == शून्य)
			जारी;
		स्थिर अक्षर *host = (flag_combos[i] & HKF_WANT_MATCH) ?
		    "example.com" : शून्य;
		(व्योम)hostkeys_foreach_file("/fuzz", f, noop_cb, शून्य,
		    host, "127.0.0.1", flag_combos[i], 0);
		ख_बंद(f);
	}

	/* Higher-level wrapper that adds record_hostkey on top of foreach. */
	{
		खाता *f = fmemopen((व्योम *)तथ्य, आकार, "r");
		अगर (f != शून्य) {
			काष्ठा hostkeys *hk = init_hostkeys();
			अगर (hk != शून्य) {
				load_hostkeys_file(hk, "example.com",
				    "/fuzz", f, 0);
				free_hostkeys(hk);
			}
			ख_बंद(f);
		}
	}

	/* Drive host_hash + extract_salt on a bounded hostname-shaped slice. */
	अगर (आकार > 0) {
		माप_प्रकार n = आकार < 256 ? आकार : 256;
		अक्षर *hb = (अक्षर *)दो_स्मृति(n + 1);
		अगर (hb != शून्य) {
			स_नकल(hb, तथ्य, n);
			hb[n] = '\0';
			अक्षर *h = host_hash("example.com", hb, 0);
			मुक्त(h);
			मुक्त(hb);
		}
	}

	वापस 0;
}

} // extern "C"
