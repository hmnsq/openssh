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

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

ಬಾಹ್ಯ "C" {
#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "log.h"

ಶೂನ್ಯ fuzz_arena_begin(ಶೂನ್ಯ);
ಶೂನ್ಯ fuzz_arena_cleanup(ಶೂನ್ಯ);
}

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *test_ಕೀಲಿಗಳು[3] = { ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ };
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ initialized = 0;

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_pubkey_or_die(ಧ್ರುವ ವರ್ಣ *txt)
{
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *k;

	ಯದಿ ((k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
		abort();
	ಯದಿ ((tmp = cp = strdup(txt)) == ರಿಕ್ತ)
		abort();
	ಯದಿ (sshkey_read(k, &cp) != 0)
		abort();
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಶೂನ್ಯ
setup(ಶೂನ್ಯ)
{
	ಯದಿ (initialized)
		ಪ್ರತ್ಯಾಗಮ;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_ಕೀಲಿಗಳು[0] = load_pubkey_or_die(PUB_RSA);
	test_ಕೀಲಿಗಳು[1] = load_pubkey_or_die(PUB_ECDSA);
	test_ಕೀಲಿಗಳು[2] = load_pubkey_or_die(PUB_ED25519);
}

ಗಣನಾ {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_ಕೀಲಿ,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

ಸ್ಥಿರ ಶೂನ್ಯ
run_one(ಪೂರ್ಣಾಙ್ಕ api, ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ lock_arg,
    ಧ್ರುವ uint8_t *body, size_t bsize)
{
	ಪೂರ್ಣಾಙ್ಕ sv[2] = { -1, -1 };
	ಯದಿ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ಪ್ರತ್ಯಾಗಮ;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(ಶೂನ್ಯ)ಲಿಖ(sv[0], hdr, ಪರಿಮಾಣ(hdr));
	ಯದಿ (bsize > 0)
		(ಶೂನ್ಯ)ಲಿಖ(sv[0], body, bsize);

	fuzz_arena_begin();

	ವಿಕಲ್ಪ (api) {
	ಪಕ್ಷ API_FETCH_IDENTITYLIST: {
		ಸಂರಚನಾ ssh_identitylist *idl = ರಿಕ್ತ;
		(ಶೂನ್ಯ)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		ಭಙ್ಗ;
	}
	ಪಕ್ಷ API_AGENT_SIGN: {
		ಧ್ರುವ u_char ಸಂದೇಶ[16] = { 0 };
		u_char *sig = ರಿಕ್ತ;
		size_t siglen = 0;
		(ಶೂನ್ಯ)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    ಸಂದೇಶ, ಪರಿಮಾಣ(ಸಂದೇಶ), ರಿಕ್ತ, 0);
		ಮುಕ್ತ(sig);
		ಭಙ್ಗ;
	}
	ಪಕ್ಷ API_AGENT_HAS_ಕೀಲಿ:
		(ಶೂನ್ಯ)ssh_agent_has_ಕೀಲಿ(sv[1], k);
		ಭಙ್ಗ;
	ಪಕ್ಷ API_QUERY_EXTENSIONS: {
		ವರ್ಣ **exts = ರಿಕ್ತ;
		ಪೂರ್ಣಾಙ್ಕ n = ssh_agent_query_extensions(sv[1], &exts);
		ಯದಿ (n == 0 && exts != ರಿಕ್ತ) {
			ಪ್ರತಿ (ಪೂರ್ಣಾಙ್ಕ i = 0; exts[i] != ರಿಕ್ತ; i++)
				ಮುಕ್ತ(exts[i]);
			ಮುಕ್ತ(exts);
		}
		ಭಙ್ಗ;
	}
	ಪಕ್ಷ API_LOCK_AGENT:
		(ಶೂನ್ಯ)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		ಭಙ್ಗ;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t *data, size_t size)
{
	setup();

	ಯದಿ (size > 65536)
		ಪ್ರತ್ಯಾಗಮ 0;

	run_one(API_FETCH_IDENTITYLIST, ರಿಕ್ತ,           0, data, size);
	run_one(API_AGENT_SIGN,         test_ಕೀಲಿಗಳು[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_ಕೀಲಿಗಳು[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_ಕೀಲಿಗಳು[2],   0, data, size);
	run_one(API_AGENT_HAS_ಕೀಲಿ,      test_ಕೀಲಿಗಳು[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   ರಿಕ್ತ,           0, data, size);
	run_one(API_LOCK_AGENT,         ರಿಕ್ತ,           1, data, size);

	ಪ್ರತ್ಯಾಗಮ 0;
}
