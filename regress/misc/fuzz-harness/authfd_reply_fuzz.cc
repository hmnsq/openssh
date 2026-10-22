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

#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <sys/socket.h>
#समावेश <sys/types.h>

बाह्य "C" {
#समावेश "includes.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "authfd.h"
#समावेश "log.h"

व्योम fuzz_arena_begin(व्योम);
व्योम fuzz_arena_cleanup(व्योम);
}

#समावेश "fixed-keys.h"

अटल काष्ठा sshkey *test_कुंजियाँ[3] = { शून्य, शून्य, शून्य };
अटल पूर्णांक initialized = 0;

अटल काष्ठा sshkey *
load_pubkey_or_die(स्थिर अक्षर *txt)
{
	अक्षर *tmp, *cp;
	काष्ठा sshkey *k;

	अगर ((k = sshkey_new(कुंजी_UNSPEC)) == शून्य)
		पात();
	अगर ((tmp = cp = strdup(txt)) == शून्य)
		पात();
	अगर (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	वापस k;
}

अटल व्योम
setup(व्योम)
{
	अगर (initialized)
		वापस;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_कुंजियाँ[0] = load_pubkey_or_die(PUB_RSA);
	test_कुंजियाँ[1] = load_pubkey_or_die(PUB_ECDSA);
	test_कुंजियाँ[2] = load_pubkey_or_die(PUB_ED25519);
}

क्रमागत {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_कुंजी,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

अटल व्योम
run_one(पूर्णांक api, काष्ठा sshkey *k, पूर्णांक lock_arg,
    स्थिर uint8_t *body, माप_प्रकार bsize)
{
	पूर्णांक sv[2] = { -1, -1 };
	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		वापस;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(व्योम)ग_लिखो(sv[0], hdr, माप(hdr));
	अगर (bsize > 0)
		(व्योम)ग_लिखो(sv[0], body, bsize);

	fuzz_arena_begin();

	चयन (api) {
	हाल API_FETCH_IDENTITYLIST: {
		काष्ठा ssh_identitylist *idl = शून्य;
		(व्योम)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		अवरोध;
	}
	हाल API_AGENT_SIGN: {
		स्थिर u_char संदेश[16] = { 0 };
		u_char *sig = शून्य;
		माप_प्रकार siglen = 0;
		(व्योम)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    संदेश, माप(संदेश), शून्य, 0);
		मुक्त(sig);
		अवरोध;
	}
	हाल API_AGENT_HAS_कुंजी:
		(व्योम)ssh_agent_has_कुंजी(sv[1], k);
		अवरोध;
	हाल API_QUERY_EXTENSIONS: {
		अक्षर **exts = शून्य;
		पूर्णांक n = ssh_agent_query_extensions(sv[1], &exts);
		अगर (n == 0 && exts != शून्य) {
			क्रम (पूर्णांक i = 0; exts[i] != शून्य; i++)
				मुक्त(exts[i]);
			मुक्त(exts);
		}
		अवरोध;
	}
	हाल API_LOCK_AGENT:
		(व्योम)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		अवरोध;
	}

	fuzz_arena_cleanup();

	बंद(sv[0]);
	बंद(sv[1]);
}

बाह्य "C" पूर्णांक
LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	setup();

	अगर (आकार > 65536)
		वापस 0;

	run_one(API_FETCH_IDENTITYLIST, शून्य,           0, तथ्य, आकार);
	run_one(API_AGENT_SIGN,         test_कुंजियाँ[0],   0, तथ्य, आकार);
	run_one(API_AGENT_SIGN,         test_कुंजियाँ[1],   0, तथ्य, आकार);
	run_one(API_AGENT_SIGN,         test_कुंजियाँ[2],   0, तथ्य, आकार);
	run_one(API_AGENT_HAS_कुंजी,      test_कुंजियाँ[2],   0, तथ्य, आकार);
	run_one(API_QUERY_EXTENSIONS,   शून्य,           0, तथ्य, आकार);
	run_one(API_LOCK_AGENT,         शून्य,           1, तथ्य, आकार);

	वापस 0;
}
