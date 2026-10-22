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

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/types.h>

ബാഹ്യ "C" {
#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "log.h"

ശൂന്യം fuzz_arena_begin(ശൂന്യം);
ശൂന്യം fuzz_arena_cleanup(ശൂന്യം);
}

#അന്തര്ഭാവ "fixed-keys.h"

സ്ഥിതം ഘടന sshkey *test_താക്കോലുകൾ[3] = { ശൂന്യ, ശൂന്യ, ശൂന്യ };
സ്ഥിതം പൂർണ്ണസംഖ്യ initialized = 0;

സ്ഥിതം ഘടന sshkey *
load_pubkey_or_die(സ്ഥിരം അക്ഷരം *txt)
{
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *k;

	എങ്കിൽ ((k = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
		abort();
	എങ്കിൽ ((tmp = cp = strdup(txt)) == ശൂന്യ)
		abort();
	എങ്കിൽ (sshkey_read(k, &cp) != 0)
		abort();
	സ്വതന്ത്രം(tmp);
	തിരികെ k;
}

സ്ഥിതം ശൂന്യം
setup(ശൂന്യം)
{
	എങ്കിൽ (initialized)
		തിരികെ;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_താക്കോലുകൾ[0] = load_pubkey_or_die(PUB_RSA);
	test_താക്കോലുകൾ[1] = load_pubkey_or_die(PUB_ECDSA);
	test_താക്കോലുകൾ[2] = load_pubkey_or_die(PUB_ED25519);
}

എണ്ണൽ {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_താക്കോൽ,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

സ്ഥിതം ശൂന്യം
run_one(പൂർണ്ണസംഖ്യ api, ഘടന sshkey *k, പൂർണ്ണസംഖ്യ lock_arg,
    സ്ഥിരം uint8_t *body, size_t bsize)
{
	പൂർണ്ണസംഖ്യ sv[2] = { -1, -1 };
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		തിരികെ;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(ശൂന്യം)ലിഖ(sv[0], hdr, വലുപ്പം(hdr));
	എങ്കിൽ (bsize > 0)
		(ശൂന്യം)ലിഖ(sv[0], body, bsize);

	fuzz_arena_begin();

	തിരഞ്ഞെടുപ്പ് (api) {
	അവസ്ഥ API_FETCH_IDENTITYLIST: {
		ഘടന ssh_identitylist *idl = ശൂന്യ;
		(ശൂന്യം)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		നിർത്തുക;
	}
	അവസ്ഥ API_AGENT_SIGN: {
		സ്ഥിരം u_char സന്ദേശം[16] = { 0 };
		u_char *sig = ശൂന്യ;
		size_t siglen = 0;
		(ശൂന്യം)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    സന്ദേശം, വലുപ്പം(സന്ദേശം), ശൂന്യ, 0);
		സ്വതന്ത്രം(sig);
		നിർത്തുക;
	}
	അവസ്ഥ API_AGENT_HAS_താക്കോൽ:
		(ശൂന്യം)ssh_agent_has_താക്കോൽ(sv[1], k);
		നിർത്തുക;
	അവസ്ഥ API_QUERY_EXTENSIONS: {
		അക്ഷരം **exts = ശൂന്യ;
		പൂർണ്ണസംഖ്യ n = ssh_agent_query_extensions(sv[1], &exts);
		എങ്കിൽ (n == 0 && exts != ശൂന്യ) {
			വേണ്ടി (പൂർണ്ണസംഖ്യ i = 0; exts[i] != ശൂന്യ; i++)
				സ്വതന്ത്രം(exts[i]);
			സ്വതന്ത്രം(exts);
		}
		നിർത്തുക;
	}
	അവസ്ഥ API_LOCK_AGENT:
		(ശൂന്യം)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		നിർത്തുക;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ
LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size)
{
	setup();

	എങ്കിൽ (size > 65536)
		തിരികെ 0;

	run_one(API_FETCH_IDENTITYLIST, ശൂന്യ,           0, data, size);
	run_one(API_AGENT_SIGN,         test_താക്കോലുകൾ[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_താക്കോലുകൾ[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_താക്കോലുകൾ[2],   0, data, size);
	run_one(API_AGENT_HAS_താക്കോൽ,      test_താക്കോലുകൾ[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   ശൂന്യ,           0, data, size);
	run_one(API_LOCK_AGENT,         ശൂന്യ,           1, data, size);

	തിരികെ 0;
}
