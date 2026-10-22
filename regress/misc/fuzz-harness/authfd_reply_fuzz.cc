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

स्थिर संरचना sshkey *test_साँचोहरू[3] = { रिक्त, रिक्त, रिक्त };
स्थिर पूर्णाङ्क initialized = 0;

स्थिर संरचना sshkey *
load_pubkey_or_die(अचर वर्ण *txt)
{
	वर्ण *tmp, *cp;
	संरचना sshkey *k;

	यदि ((k = sshkey_new(साँचो_UNSPEC)) == रिक्त)
		पात();
	यदि ((tmp = cp = strdup(txt)) == रिक्त)
		पात();
	यदि (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	फर्काऊ k;
}

स्थिर शून्य
setup(शून्य)
{
	यदि (initialized)
		फर्काऊ;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_साँचोहरू[0] = load_pubkey_or_die(PUB_RSA);
	test_साँचोहरू[1] = load_pubkey_or_die(PUB_ECDSA);
	test_साँचोहरू[2] = load_pubkey_or_die(PUB_ED25519);
}

गणना {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_साँचो,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

स्थिर शून्य
run_one(पूर्णाङ्क api, संरचना sshkey *k, पूर्णाङ्क lock_arg,
    अचर uint8_t *body, माप_प्रकार bsize)
{
	पूर्णाङ्क sv[2] = { -1, -1 };
	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		फर्काऊ;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(शून्य)लिख(sv[0], hdr, परिमाण(hdr));
	यदि (bsize > 0)
		(शून्य)लिख(sv[0], body, bsize);

	fuzz_arena_begin();

	विकल्प (api) {
	पक्ष API_FETCH_IDENTITYLIST: {
		संरचना ssh_identitylist *idl = रिक्त;
		(शून्य)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		रोक;
	}
	पक्ष API_AGENT_SIGN: {
		अचर u_char सन्देश[16] = { 0 };
		u_char *sig = रिक्त;
		माप_प्रकार siglen = 0;
		(शून्य)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    सन्देश, परिमाण(सन्देश), रिक्त, 0);
		मुक्त(sig);
		रोक;
	}
	पक्ष API_AGENT_HAS_साँचो:
		(शून्य)ssh_agent_has_साँचो(sv[1], k);
		रोक;
	पक्ष API_QUERY_EXTENSIONS: {
		वर्ण **exts = रिक्त;
		पूर्णाङ्क n = ssh_agent_query_extensions(sv[1], &exts);
		यदि (n == 0 && exts != रिक्त) {
			लागि (पूर्णाङ्क i = 0; exts[i] != रिक्त; i++)
				मुक्त(exts[i]);
			मुक्त(exts);
		}
		रोक;
	}
	पक्ष API_LOCK_AGENT:
		(शून्य)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		रोक;
	}

	fuzz_arena_cleanup();

	बंद(sv[0]);
	बंद(sv[1]);
}

बाह्य "C" पूर्णाङ्क
LLVMFuzzer_Test_One_आगत(अचर uint8_t *data, माप_प्रकार size)
{
	setup();

	यदि (size > 65536)
		फर्काऊ 0;

	run_one(API_FETCH_IDENTITYLIST, रिक्त,           0, data, size);
	run_one(API_AGENT_SIGN,         test_साँचोहरू[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_साँचोहरू[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_साँचोहरू[2],   0, data, size);
	run_one(API_AGENT_HAS_साँचो,      test_साँचोहरू[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   रिक्त,           0, data, size);
	run_one(API_LOCK_AGENT,         रिक्त,           1, data, size);

	फर्काऊ 0;
}
