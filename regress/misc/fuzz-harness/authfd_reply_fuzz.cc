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

#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

ବାହ୍ୟ "C" {
#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

ଶୂନ୍ୟ fuzz_arena_begin(ଶୂନ୍ୟ);
ଶୂନ୍ୟ fuzz_arena_cleanup(ଶୂନ୍ୟ);
}

#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"

ସ୍ଥିର ସଂରଚନା sshkey *test_ଚାବିଗୁଡ଼ିକ[3] = { ଖାଲି, ଖାଲି, ଖାଲି };
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା initialized = 0;

ସ୍ଥିର ସଂରଚନା sshkey *
load_pubkey_or_die(ଅଚଳ ଅକ୍ଷର *txt)
{
	ଅକ୍ଷର *tmp, *cp;
	ସଂରଚନା sshkey *k;

	ଯଦି ((k = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
		abort();
	ଯଦି ((tmp = cp = strdup(txt)) == ଖାଲି)
		abort();
	ଯଦି (sshkey_read(k, &cp) != 0)
		abort();
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ k;
}

ସ୍ଥିର ଶୂନ୍ୟ
setup(ଶୂନ୍ୟ)
{
	ଯଦି (initialized)
		ଫେରନ୍ତୁ;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_ଚାବିଗୁଡ଼ିକ[0] = load_pubkey_or_die(PUB_RSA);
	test_ଚାବିଗୁଡ଼ିକ[1] = load_pubkey_or_die(PUB_ECDSA);
	test_ଚାବିଗୁଡ଼ିକ[2] = load_pubkey_or_die(PUB_ED25519);
}

ଗଣନା {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_ଚାବି,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

ସ୍ଥିର ଶୂନ୍ୟ
run_one(ପୂର୍ଣ୍ଣସଂଖ୍ୟା api, ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା lock_arg,
    ଅଚଳ uint8_t *body, size_t bsize)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sv[2] = { -1, -1 };
	ଯଦି (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ଫେରନ୍ତୁ;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(ଶୂନ୍ୟ)ଲିଖ(sv[0], hdr, ଆକାର(hdr));
	ଯଦି (bsize > 0)
		(ଶୂନ୍ୟ)ଲିଖ(sv[0], body, bsize);

	fuzz_arena_begin();

	ବାଛ (api) {
	ସ୍ଥିତି API_FETCH_IDENTITYLIST: {
		ସଂରଚନା ssh_identitylist *idl = ଖାଲି;
		(ଶୂନ୍ୟ)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		ଭାଙ୍ଗ;
	}
	ସ୍ଥିତି API_AGENT_SIGN: {
		ଅଚଳ u_char ସନ୍ଦେଶ[16] = { 0 };
		u_char *sig = ଖାଲି;
		size_t siglen = 0;
		(ଶୂନ୍ୟ)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ), ଖାଲି, 0);
		ମୁକ୍ତ(sig);
		ଭାଙ୍ଗ;
	}
	ସ୍ଥିତି API_AGENT_HAS_ଚାବି:
		(ଶୂନ୍ୟ)ssh_agent_has_ଚାବି(sv[1], k);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି API_QUERY_EXTENSIONS: {
		ଅକ୍ଷର **exts = ଖାଲି;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା n = ssh_agent_query_extensions(sv[1], &exts);
		ଯଦି (n == 0 && exts != ଖାଲି) {
			ପାଇଁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା i = 0; exts[i] != ଖାଲି; i++)
				ମୁକ୍ତ(exts[i]);
			ମୁକ୍ତ(exts);
		}
		ଭାଙ୍ଗ;
	}
	ସ୍ଥିତି API_LOCK_AGENT:
		(ଶୂନ୍ୟ)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		ଭାଙ୍ଗ;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା
LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size)
{
	setup();

	ଯଦି (size > 65536)
		ଫେରନ୍ତୁ 0;

	run_one(API_FETCH_IDENTITYLIST, ଖାଲି,           0, data, size);
	run_one(API_AGENT_SIGN,         test_ଚାବିଗୁଡ଼ିକ[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_ଚାବିଗୁଡ଼ିକ[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_ଚାବିଗୁଡ଼ିକ[2],   0, data, size);
	run_one(API_AGENT_HAS_ଚାବି,      test_ଚାବିଗୁଡ଼ିକ[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   ଖାଲି,           0, data, size);
	run_one(API_LOCK_AGENT,         ଖାଲି,           1, data, size);

	ଫେରନ୍ତୁ 0;
}
