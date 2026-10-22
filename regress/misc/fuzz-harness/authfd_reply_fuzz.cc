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

#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/types.h>

வெளி "C" {
#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "log.h"

வெறுமை fuzz_arena_begin(வெறுமை);
வெறுமை fuzz_arena_cleanup(வெறுமை);
}

#அந்தர்பாவ "fixed-keys.h"

நிலையான கட்டமைப்பு sshkey *test_சாவிகள்[3] = { வெற்று, வெற்று, வெற்று };
நிலையான முழு initialized = 0;

நிலையான கட்டமைப்பு sshkey *
load_pubkey_or_die(மாறிலி எழுத்து *txt)
{
	எழுத்து *tmp, *cp;
	கட்டமைப்பு sshkey *k;

	எனில் ((k = sshkey_new(சாவி_UNSPEC)) == வெற்று)
		abort();
	எனில் ((tmp = cp = strdup(txt)) == வெற்று)
		abort();
	எனில் (sshkey_read(k, &cp) != 0)
		abort();
	விடுவி(tmp);
	திரும்பு k;
}

நிலையான வெறுமை
setup(வெறுமை)
{
	எனில் (initialized)
		திரும்பு;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_சாவிகள்[0] = load_pubkey_or_die(PUB_RSA);
	test_சாவிகள்[1] = load_pubkey_or_die(PUB_ECDSA);
	test_சாவிகள்[2] = load_pubkey_or_die(PUB_ED25519);
}

எண்ணிக்கை {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_சாவி,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

நிலையான வெறுமை
run_one(முழு api, கட்டமைப்பு sshkey *k, முழு lock_arg,
    மாறிலி uint8_t *body, size_t bsize)
{
	முழு sv[2] = { -1, -1 };
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		திரும்பு;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(வெறுமை)லிக(sv[0], hdr, அளவு(hdr));
	எனில் (bsize > 0)
		(வெறுமை)லிக(sv[0], body, bsize);

	fuzz_arena_begin();

	தேர்வு (api) {
	நிலை API_FETCH_IDENTITYLIST: {
		கட்டமைப்பு ssh_identitylist *idl = வெற்று;
		(வெறுமை)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		நிறுத்து;
	}
	நிலை API_AGENT_SIGN: {
		மாறிலி u_char செய்தி[16] = { 0 };
		u_char *sig = வெற்று;
		size_t siglen = 0;
		(வெறுமை)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    செய்தி, அளவு(செய்தி), வெற்று, 0);
		விடுவி(sig);
		நிறுத்து;
	}
	நிலை API_AGENT_HAS_சாவி:
		(வெறுமை)ssh_agent_has_சாவி(sv[1], k);
		நிறுத்து;
	நிலை API_QUERY_EXTENSIONS: {
		எழுத்து **exts = வெற்று;
		முழு n = ssh_agent_query_extensions(sv[1], &exts);
		எனில் (n == 0 && exts != வெற்று) {
			க்கு (முழு i = 0; exts[i] != வெற்று; i++)
				விடுவி(exts[i]);
			விடுவி(exts);
		}
		நிறுத்து;
	}
	நிலை API_LOCK_AGENT:
		(வெறுமை)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		நிறுத்து;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

வெளி "C" முழு
LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size)
{
	setup();

	எனில் (size > 65536)
		திரும்பு 0;

	run_one(API_FETCH_IDENTITYLIST, வெற்று,           0, data, size);
	run_one(API_AGENT_SIGN,         test_சாவிகள்[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_சாவிகள்[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_சாவிகள்[2],   0, data, size);
	run_one(API_AGENT_HAS_சாவி,      test_சாவிகள்[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   வெற்று,           0, data, size);
	run_one(API_LOCK_AGENT,         வெற்று,           1, data, size);

	திரும்பு 0;
}
