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

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/types.h>

বাহ্যিক "C" {
#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "log.h"

শূন্য fuzz_arena_begin(শূন্য);
শূন্য fuzz_arena_cleanup(শূন্য);
}

#অন্তর্ভাব "fixed-keys.h"

স্থির কাঠামো sshkey *test_চাবিগুলি[3] = { ফাঁকা, ফাঁকা, ফাঁকা };
স্থির পূর্ণসংখ্যা initialized = 0;

স্থির কাঠামো sshkey *
load_pubkey_or_die(ধ্রুবক অক্ষর *txt)
{
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *k;

	যদি ((k = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
		abort();
	যদি ((tmp = cp = strdup(txt)) == ফাঁকা)
		abort();
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ফেরত k;
}

স্থির শূন্য
setup(শূন্য)
{
	যদি (initialized)
		ফেরত;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_চাবিগুলি[0] = load_pubkey_or_die(PUB_RSA);
	test_চাবিগুলি[1] = load_pubkey_or_die(PUB_ECDSA);
	test_চাবিগুলি[2] = load_pubkey_or_die(PUB_ED25519);
}

গণনা {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_চাবি,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

স্থির শূন্য
run_one(পূর্ণসংখ্যা api, কাঠামো sshkey *k, পূর্ণসংখ্যা lock_arg,
    ধ্রুবক uint8_t *body, আকার_t bsize)
{
	পূর্ণসংখ্যা sv[2] = { -1, -1 };
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ফেরত;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(শূন্য)লিখ(sv[0], hdr, আকার(hdr));
	যদি (bsize > 0)
		(শূন্য)লিখ(sv[0], body, bsize);

	fuzz_arena_begin();

	নির্বাচন (api) {
	ক্ষেত্র API_FETCH_IDENTITYLIST: {
		কাঠামো ssh_identitylist *idl = ফাঁকা;
		(শূন্য)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		বিরতি;
	}
	ক্ষেত্র API_AGENT_SIGN: {
		ধ্রুবক u_char বার্তা[16] = { 0 };
		u_char *sig = ফাঁকা;
		আকার_t siglen = 0;
		(শূন্য)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    বার্তা, আকার(বার্তা), ফাঁকা, 0);
		মুক্ত(sig);
		বিরতি;
	}
	ক্ষেত্র API_AGENT_HAS_চাবি:
		(শূন্য)ssh_agent_has_চাবি(sv[1], k);
		বিরতি;
	ক্ষেত্র API_QUERY_EXTENSIONS: {
		অক্ষর **exts = ফাঁকা;
		পূর্ণসংখ্যা n = ssh_agent_query_extensions(sv[1], &exts);
		যদি (n == 0 && exts != ফাঁকা) {
			জন্য (পূর্ণসংখ্যা i = 0; exts[i] != ফাঁকা; i++)
				মুক্ত(exts[i]);
			মুক্ত(exts);
		}
		বিরতি;
	}
	ক্ষেত্র API_LOCK_AGENT:
		(শূন্য)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		বিরতি;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

বাহ্যিক "C" পূর্ণসংখ্যা
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	setup();

	যদি (আকার_2 > 65536)
		ফেরত 0;

	run_one(API_FETCH_IDENTITYLIST, ফাঁকা,           0, তথ্য, আকার_2);
	run_one(API_AGENT_SIGN,         test_চাবিগুলি[0],   0, তথ্য, আকার_2);
	run_one(API_AGENT_SIGN,         test_চাবিগুলি[1],   0, তথ্য, আকার_2);
	run_one(API_AGENT_SIGN,         test_চাবিগুলি[2],   0, তথ্য, আকার_2);
	run_one(API_AGENT_HAS_চাবি,      test_চাবিগুলি[2],   0, তথ্য, আকার_2);
	run_one(API_QUERY_EXTENSIONS,   ফাঁকা,           0, তথ্য, আকার_2);
	run_one(API_LOCK_AGENT,         ফাঁকা,           1, তথ্য, আকার_2);

	ফেরত 0;
}
