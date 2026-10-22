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

#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/types.h>

বাহ্য "C" {
#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "authfd.h"
#অন্তর্ভাৱ "log.h"

শূন্য fuzz_arena_begin(শূন্য);
শূন্য fuzz_arena_cleanup(শূন্য);
}

#অন্তর্ভাৱ "fixed-keys.h"

স্থির সংরচনা sshkey *test_চাবিগুলি[3] = { রিক্ত, রিক্ত, রিক্ত };
স্থির পূর্ণাঙ্ক initialized = 0;

স্থির সংরচনা sshkey *
load_pubkey_or_die(ধ্রুৱ ৱর্ণ *txt)
{
	ৱর্ণ *tmp, *cp;
	সংরচনা sshkey *k;

	যদি ((k = sshkey_new(চাবি_UNSPEC)) == রিক্ত)
		abort();
	যদি ((tmp = cp = strdup(txt)) == রিক্ত)
		abort();
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ঘূৰাই k;
}

স্থির শূন্য
setup(শূন্য)
{
	যদি (initialized)
		ঘূৰাই;
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
run_one(পূর্ণাঙ্ক api, সংরচনা sshkey *k, পূর্ণাঙ্ক lock_arg,
    ধ্রুৱ uint8_t *body, size_t bsize)
{
	পূর্ণাঙ্ক sv[2] = { -1, -1 };
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ঘূৰাই;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(শূন্য)লিখ(sv[0], hdr, পরিমাণ(hdr));
	যদি (bsize > 0)
		(শূন্য)লিখ(sv[0], body, bsize);

	fuzz_arena_begin();

	ৱিকল্প (api) {
	পক্ষ API_FETCH_IDENTITYLIST: {
		সংরচনা ssh_identitylist *idl = রিক্ত;
		(শূন্য)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		ভঙ্গ;
	}
	পক্ষ API_AGENT_SIGN: {
		ধ্রুৱ u_char বাৰ্তা[16] = { 0 };
		u_char *sig = রিক্ত;
		size_t siglen = 0;
		(শূন্য)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    বাৰ্তা, পরিমাণ(বাৰ্তা), রিক্ত, 0);
		মুক্ত(sig);
		ভঙ্গ;
	}
	পক্ষ API_AGENT_HAS_চাবি:
		(শূন্য)ssh_agent_has_চাবি(sv[1], k);
		ভঙ্গ;
	পক্ষ API_QUERY_EXTENSIONS: {
		ৱর্ণ **exts = রিক্ত;
		পূর্ণাঙ্ক n = ssh_agent_query_extensions(sv[1], &exts);
		যদি (n == 0 && exts != রিক্ত) {
			বাবে (পূর্ণাঙ্ক i = 0; exts[i] != রিক্ত; i++)
				মুক্ত(exts[i]);
			মুক্ত(exts);
		}
		ভঙ্গ;
	}
	পক্ষ API_LOCK_AGENT:
		(শূন্য)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		ভঙ্গ;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

বাহ্য "C" পূর্ণাঙ্ক
LLVMFuzzer_Test_One_প্ৰবেশ(ধ্রুৱ uint8_t *data, size_t size)
{
	setup();

	যদি (size > 65536)
		ঘূৰাই 0;

	run_one(API_FETCH_IDENTITYLIST, রিক্ত,           0, data, size);
	run_one(API_AGENT_SIGN,         test_চাবিগুলি[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_চাবিগুলি[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_চাবিগুলি[2],   0, data, size);
	run_one(API_AGENT_HAS_চাবি,      test_চাবিগুলি[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   রিক্ত,           0, data, size);
	run_one(API_LOCK_AGENT,         রিক্ত,           1, data, size);

	ঘূৰাই 0;
}
