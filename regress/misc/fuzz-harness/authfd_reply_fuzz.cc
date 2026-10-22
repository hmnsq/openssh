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

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

ਬਾਹਰੀ "C" {
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਖਾਲੀ fuzz_arena_begin(ਖਾਲੀ);
ਖਾਲੀ fuzz_arena_cleanup(ਖਾਲੀ);
}

#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"

ਸਥਿਰ ਬਣਤਰ sshkey *test_ਕੁੰਜੀਆਂ[3] = { ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ };
ਸਥਿਰ ਪੂਰਨ initialized = 0;

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_pubkey_or_die(ਅਚਲ ਅੱਖਰ *txt)
{
	ਅੱਖਰ *tmp, *cp;
	ਬਣਤਰ sshkey *k;

	ਜੇ ((k = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
		abort();
	ਜੇ ((tmp = cp = strdup(txt)) == ਨਿਰਾ)
		abort();
	ਜੇ (sshkey_read(k, &cp) != 0)
		abort();
	ਮੁਕਤ(tmp);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਖਾਲੀ
ਤਿਆਰੀ(ਖਾਲੀ)
{
	ਜੇ (initialized)
		ਵਾਪਸ;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_ਕੁੰਜੀਆਂ[0] = ਲੱਦੋ_pubkey_or_die(PUB_RSA);
	test_ਕੁੰਜੀਆਂ[1] = ਲੱਦੋ_pubkey_or_die(PUB_ECDSA);
	test_ਕੁੰਜੀਆਂ[2] = ਲੱਦੋ_pubkey_or_die(PUB_ED25519);
}

ਗਿਣਤੀ {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_ਕੁੰਜੀ,
	API_QUERY_EXTENSIONS,
	API_ਤਾਲਾ_AGENT,
};

ਸਥਿਰ ਖਾਲੀ
ਲੜੀਵਾਰ_one(ਪੂਰਨ api, ਬਣਤਰ sshkey *k, ਪੂਰਨ ਤਾਲਾ_arg,
    ਅਚਲ uint8_t *body, ਮਾਪ_t bsize)
{
	ਪੂਰਨ sv[2] = { -1, -1 };
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ਵਾਪਸ;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(ਖਾਲੀ)ਲਿਖ(sv[0], hdr, ਆਕਾਰ(hdr));
	ਜੇ (bsize > 0)
		(ਖਾਲੀ)ਲਿਖ(sv[0], body, bsize);

	fuzz_arena_begin();

	ਚੋਣ (api) {
	ਹਾਲਤ API_FETCH_IDENTITYLIST: {
		ਬਣਤਰ ssh_identitylist *idl = ਨਿਰਾ;
		(ਖਾਲੀ)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		ਰੋਕੋ;
	}
	ਹਾਲਤ API_AGENT_SIGN: {
		ਅਚਲ u_char ਸੁਨੇਹਾ[16] = { 0 };
		u_char *sig = ਨਿਰਾ;
		ਮਾਪ_t siglen = 0;
		(ਖਾਲੀ)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ), ਨਿਰਾ, 0);
		ਮੁਕਤ(sig);
		ਰੋਕੋ;
	}
	ਹਾਲਤ API_AGENT_HAS_ਕੁੰਜੀ:
		(ਖਾਲੀ)ssh_agent_has_ਕੁੰਜੀ(sv[1], k);
		ਰੋਕੋ;
	ਹਾਲਤ API_QUERY_EXTENSIONS: {
		ਅੱਖਰ **exts = ਨਿਰਾ;
		ਪੂਰਨ n = ssh_agent_query_extensions(sv[1], &exts);
		ਜੇ (n == 0 && exts != ਨਿਰਾ) {
			ਲਈ (ਪੂਰਨ i = 0; exts[i] != ਨਿਰਾ; i++)
				ਮੁਕਤ(exts[i]);
			ਮੁਕਤ(exts);
		}
		ਰੋਕੋ;
	}
	ਹਾਲਤ API_ਤਾਲਾ_AGENT:
		(ਖਾਲੀ)ssh_ਤਾਲਾ_agent(sv[1], ਤਾਲਾ_arg, "fuzz");
		ਰੋਕੋ;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ਬਾਹਰੀ "C" ਪੂਰਨ
LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਤਿਆਰੀ();

	ਜੇ (ਮਾਪ > 65536)
		ਵਾਪਸ 0;

	ਲੜੀਵਾਰ_one(API_FETCH_IDENTITYLIST, ਨਿਰਾ,           0, ਅੰਕੜੇ, ਮਾਪ);
	ਲੜੀਵਾਰ_one(API_AGENT_SIGN,         test_ਕੁੰਜੀਆਂ[0],   0, ਅੰਕੜੇ, ਮਾਪ);
	ਲੜੀਵਾਰ_one(API_AGENT_SIGN,         test_ਕੁੰਜੀਆਂ[1],   0, ਅੰਕੜੇ, ਮਾਪ);
	ਲੜੀਵਾਰ_one(API_AGENT_SIGN,         test_ਕੁੰਜੀਆਂ[2],   0, ਅੰਕੜੇ, ਮਾਪ);
	ਲੜੀਵਾਰ_one(API_AGENT_HAS_ਕੁੰਜੀ,      test_ਕੁੰਜੀਆਂ[2],   0, ਅੰਕੜੇ, ਮਾਪ);
	ਲੜੀਵਾਰ_one(API_QUERY_EXTENSIONS,   ਨਿਰਾ,           0, ਅੰਕੜੇ, ਮਾਪ);
	ਲੜੀਵਾਰ_one(API_ਤਾਲਾ_AGENT,         ਨਿਰਾ,           1, ਅੰਕੜੇ, ਮਾਪ);

	ਵਾਪਸ 0;
}
