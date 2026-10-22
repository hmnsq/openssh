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

ಸ್ಥಿರ ರಚನೆ sshkey *test_ಕೀಲಿಗಳು[3] = { ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ };
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ initialized = 0;

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_pubkey_or_die(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *txt)
{
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *k;

	ಆದರೆ ((k = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
		abort();
	ಆದರೆ ((tmp = cp = strdup(txt)) == ಖಾಲಿ)
		abort();
	ಆದರೆ (sshkey_read(k, &cp) != 0)
		abort();
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಸಿದ್ಧತೆ(ಶೂನ್ಯ)
{
	ಆದರೆ (initialized)
		ಹಿಂತಿರುಗಿ;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_ಕೀಲಿಗಳು[0] = ತುಂಬು_pubkey_or_die(PUB_RSA);
	test_ಕೀಲಿಗಳು[1] = ತುಂಬು_pubkey_or_die(PUB_ECDSA);
	test_ಕೀಲಿಗಳು[2] = ತುಂಬು_pubkey_or_die(PUB_ED25519);
}

ಎಣಿಕೆ {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_ಕೀಲಿ,
	API_QUERY_EXTENSIONS,
	API_ಬೀಗ_AGENT,
};

ಸ್ಥಿರ ಶೂನ್ಯ
ಸತತ_one(ಪೂರ್ಣಾಂಕ api, ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ ಬೀಗ_arg,
    ಸ್ಥಿರಾಂಕ uint8_t *body, ಗಾತ್ರ_t bsize)
{
	ಪೂರ್ಣಾಂಕ sv[2] = { -1, -1 };
	ಆದರೆ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ಹಿಂತಿರುಗಿ;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(ಶೂನ್ಯ)ಲಿಖ(sv[0], hdr, ಗಾತ್ರ(hdr));
	ಆದರೆ (bsize > 0)
		(ಶೂನ್ಯ)ಲಿಖ(sv[0], body, bsize);

	fuzz_arena_begin();

	ಆಯ್ಕೆ (api) {
	ಸ್ಥಿತಿ API_FETCH_IDENTITYLIST: {
		ರಚನೆ ssh_identitylist *idl = ಖಾಲಿ;
		(ಶೂನ್ಯ)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		ನಿಲ್ಲಿಸು;
	}
	ಸ್ಥಿತಿ API_AGENT_SIGN: {
		ಸ್ಥಿರಾಂಕ u_char ಸಂದೇಶ[16] = { 0 };
		u_char *sig = ಖಾಲಿ;
		ಗಾತ್ರ_t siglen = 0;
		(ಶೂನ್ಯ)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ), ಖಾಲಿ, 0);
		ಬಿಡುಗಡೆ(sig);
		ನಿಲ್ಲಿಸು;
	}
	ಸ್ಥಿತಿ API_AGENT_HAS_ಕೀಲಿ:
		(ಶೂನ್ಯ)ssh_agent_has_ಕೀಲಿ(sv[1], k);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ API_QUERY_EXTENSIONS: {
		ಅಕ್ಷರ **exts = ಖಾಲಿ;
		ಪೂರ್ಣಾಂಕ n = ssh_agent_query_extensions(sv[1], &exts);
		ಆದರೆ (n == 0 && exts != ಖಾಲಿ) {
			ಗಾಗಿ (ಪೂರ್ಣಾಂಕ i = 0; exts[i] != ಖಾಲಿ; i++)
				ಬಿಡುಗಡೆ(exts[i]);
			ಬಿಡುಗಡೆ(exts);
		}
		ನಿಲ್ಲಿಸು;
	}
	ಸ್ಥಿತಿ API_ಬೀಗ_AGENT:
		(ಶೂನ್ಯ)ssh_ಬೀಗ_agent(sv[1], ಬೀಗ_arg, "fuzz");
		ನಿಲ್ಲಿಸು;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಸಿದ್ಧತೆ();

	ಆದರೆ (ಗಾತ್ರ_2 > 65536)
		ಹಿಂತಿರುಗಿ 0;

	ಸತತ_one(API_FETCH_IDENTITYLIST, ಖಾಲಿ,           0, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	ಸತತ_one(API_AGENT_SIGN,         test_ಕೀಲಿಗಳು[0],   0, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	ಸತತ_one(API_AGENT_SIGN,         test_ಕೀಲಿಗಳು[1],   0, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	ಸತತ_one(API_AGENT_SIGN,         test_ಕೀಲಿಗಳು[2],   0, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	ಸತತ_one(API_AGENT_HAS_ಕೀಲಿ,      test_ಕೀಲಿಗಳು[2],   0, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	ಸತತ_one(API_QUERY_EXTENSIONS,   ಖಾಲಿ,           0, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);
	ಸತತ_one(API_ಬೀಗ_AGENT,         ಖಾಲಿ,           1, ದತ್ತಾಂಶ, ಗಾತ್ರ_2);

	ಹಿಂತಿರುಗಿ 0;
}
