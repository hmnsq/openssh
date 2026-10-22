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

/*
 * Fuzzer for OpenSSH agent client reply parser (authfd.c)
 *
 * Target: authfd.c
 *
 * Drives every public agent client API on a socketpair using the
 * fuzzer input as the reply payload. A helper opens a fresh
 * socketpair, frames the body as a length-prefixed agent reply,
 * invokes one API, and resets state via fuzz_arena_cleanup before
 * the next call. Each iteration runs all five APIs on the same
 * input so no API is starved by a selector byte.
 *
 * Primary functions exercised:
 * - ssh_fetch_identitylist
 * - ssh_agent_sign
 * - ssh_agent_has_key
 * - ssh_agent_query_extensions
 * - ssh_lock_agent
 *
 * Threat model: a malicious or compromised agent (via ForwardAgent
 * to a hostile host) returning crafted replies. The client must
 * parse them safely.
 *
 * fuzz_arena (linker --wrap'd malloc family) provides per-call heap
 * cleanup so allocations not released by the code under test are
 * reclaimed before the next call.
 */

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/types.h>

बाह्य "C" {
#अन्तर्भाव "includes.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfd.h"
#अन्तर्भाव "log.h"

शून्य fuzz_arena_begin(शून्य);
शून्य fuzz_arena_cleanup(शून्य);
}

#अन्तर्भाव "fixed-keys.h"

स्थिर संरचना sshkey *test_किल्ल्या[3] = { रिक्त, रिक्त, रिक्त };
स्थिर पूर्णांक initialized = 0;

स्थिर संरचना sshkey *
load_pubkey_or_die(स्थिरांक अक्षर *txt)
{
	अक्षर *tmp, *cp;
	संरचना sshkey *k;

	जर ((k = sshkey_new(किल्ली_UNSPEC)) == रिक्त)
		पात();
	जर ((tmp = cp = strdup(txt)) == रिक्त)
		पात();
	जर (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	परत k;
}

स्थिर शून्य
setup(शून्य)
{
	जर (initialized)
		परत;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_किल्ल्या[0] = load_pubkey_or_die(PUB_RSA);
	test_किल्ल्या[1] = load_pubkey_or_die(PUB_ECDSA);
	test_किल्ल्या[2] = load_pubkey_or_die(PUB_ED25519);
}

गणना {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_किल्ली,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

स्थिर शून्य
run_one(पूर्णांक api, संरचना sshkey *k, पूर्णांक lock_arg,
    स्थिरांक uint8_t *body, माप_प्रकार bsize)
{
	पूर्णांक sv[2] = { -1, -1 };
	जर (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		परत;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(शून्य)लिख(sv[0], hdr, आकार(hdr));
	जर (bsize > 0)
		(शून्य)लिख(sv[0], body, bsize);

	fuzz_arena_begin();

	निवड (api) {
	स्थिती API_FETCH_IDENTITYLIST: {
		संरचना ssh_identitylist *idl = रिक्त;
		(शून्य)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		थांबा;
	}
	स्थिती API_AGENT_SIGN: {
		स्थिरांक u_char संदेश[16] = { 0 };
		u_char *sig = रिक्त;
		माप_प्रकार siglen = 0;
		(शून्य)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    संदेश, आकार(संदेश), रिक्त, 0);
		मुक्त(sig);
		थांबा;
	}
	स्थिती API_AGENT_HAS_किल्ली:
		(शून्य)ssh_agent_has_किल्ली(sv[1], k);
		थांबा;
	स्थिती API_QUERY_EXTENSIONS: {
		अक्षर **exts = रिक्त;
		पूर्णांक n = ssh_agent_query_extensions(sv[1], &exts);
		जर (n == 0 && exts != रिक्त) {
			साठी (पूर्णांक i = 0; exts[i] != रिक्त; i++)
				मुक्त(exts[i]);
			मुक्त(exts);
		}
		थांबा;
	}
	स्थिती API_LOCK_AGENT:
		(शून्य)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		थांबा;
	}

	fuzz_arena_cleanup();

	बंद(sv[0]);
	बंद(sv[1]);
}

बाह्य "C" पूर्णांक
LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t *data, माप_प्रकार size)
{
	setup();

	जर (size > 65536)
		परत 0;

	run_one(API_FETCH_IDENTITYLIST, रिक्त,           0, data, size);
	run_one(API_AGENT_SIGN,         test_किल्ल्या[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_किल्ल्या[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_किल्ल्या[2],   0, data, size);
	run_one(API_AGENT_HAS_किल्ली,      test_किल्ल्या[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   रिक्त,           0, data, size);
	run_one(API_LOCK_AGENT,         रिक्त,           1, data, size);

	परत 0;
}
