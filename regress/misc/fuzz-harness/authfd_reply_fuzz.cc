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

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/types.h>

બાહ્ય "C" {
#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "log.h"

શૂન્ય fuzz_arena_begin(શૂન્ય);
શૂન્ય fuzz_arena_cleanup(શૂન્ય);
}

#અન્તર્ભાવ "fixed-keys.h"

સ્થિર સંરચના sshkey *test_ચાવીઓ[3] = { ખાલી, ખાલી, ખાલી };
સ્થિર પૂર્ણાંક initialized = 0;

સ્થિર સંરચના sshkey *
load_pubkey_or_die(અચલ અક્ષર *txt)
{
	અક્ષર *tmp, *cp;
	સંરચના sshkey *k;

	જો ((k = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
		abort();
	જો ((tmp = cp = strdup(txt)) == ખાલી)
		abort();
	જો (sshkey_read(k, &cp) != 0)
		abort();
	મુક્ત(tmp);
	પાછા k;
}

સ્થિર શૂન્ય
setup(શૂન્ય)
{
	જો (initialized)
		પાછા;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_ચાવીઓ[0] = load_pubkey_or_die(PUB_RSA);
	test_ચાવીઓ[1] = load_pubkey_or_die(PUB_ECDSA);
	test_ચાવીઓ[2] = load_pubkey_or_die(PUB_ED25519);
}

ગણના {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_ચાવી,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

સ્થિર શૂન્ય
run_one(પૂર્ણાંક api, સંરચના sshkey *k, પૂર્ણાંક lock_arg,
    અચલ uint8_t *body, size_t bsize)
{
	પૂર્ણાંક sv[2] = { -1, -1 };
	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		પાછા;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(શૂન્ય)લિખ(sv[0], hdr, કદ(hdr));
	જો (bsize > 0)
		(શૂન્ય)લિખ(sv[0], body, bsize);

	fuzz_arena_begin();

	પસંદગી (api) {
	સ્થિતિ API_FETCH_IDENTITYLIST: {
		સંરચના ssh_identitylist *idl = ખાલી;
		(શૂન્ય)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		તોડો;
	}
	સ્થિતિ API_AGENT_SIGN: {
		અચલ u_char સંદેશ[16] = { 0 };
		u_char *sig = ખાલી;
		size_t siglen = 0;
		(શૂન્ય)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    સંદેશ, કદ(સંદેશ), ખાલી, 0);
		મુક્ત(sig);
		તોડો;
	}
	સ્થિતિ API_AGENT_HAS_ચાવી:
		(શૂન્ય)ssh_agent_has_ચાવી(sv[1], k);
		તોડો;
	સ્થિતિ API_QUERY_EXTENSIONS: {
		અક્ષર **exts = ખાલી;
		પૂર્ણાંક n = ssh_agent_query_extensions(sv[1], &exts);
		જો (n == 0 && exts != ખાલી) {
			માટે (પૂર્ણાંક i = 0; exts[i] != ખાલી; i++)
				મુક્ત(exts[i]);
			મુક્ત(exts);
		}
		તોડો;
	}
	સ્થિતિ API_LOCK_AGENT:
		(શૂન્ય)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		તોડો;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

બાહ્ય "C" પૂર્ણાંક
LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size)
{
	setup();

	જો (size > 65536)
		પાછા 0;

	run_one(API_FETCH_IDENTITYLIST, ખાલી,           0, data, size);
	run_one(API_AGENT_SIGN,         test_ચાવીઓ[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_ચાવીઓ[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_ચાવીઓ[2],   0, data, size);
	run_one(API_AGENT_HAS_ચાવી,      test_ચાવીઓ[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   ખાલી,           0, data, size);
	run_one(API_LOCK_AGENT,         ખાલી,           1, data, size);

	પાછા 0;
}
