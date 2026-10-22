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

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/types.h>

బాహ్య "C" {
#అన్తర్భావ "includes.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "log.h"

శూన్య fuzz_arena_begin(శూన్య);
శూన్య fuzz_arena_cleanup(శూన్య);
}

#అన్తర్భావ "fixed-keys.h"

స్థిర నిర్మాణం sshkey *test_కీలకాలు[3] = { ఖాళీ, ఖాళీ, ఖాళీ };
స్థిర పూర్ణాంకం initialized = 0;

స్థిర నిర్మాణం sshkey *
ఎక్కించు_pubkey_or_die(స్థిరరాశి అక్షరం *txt)
{
	అక్షరం *tmp, *cp;
	నిర్మాణం sshkey *k;

	ఒకవేళ ((k = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
		abort();
	ఒకవేళ ((tmp = cp = strdup(txt)) == ఖాళీ)
		abort();
	ఒకవేళ (sshkey_read(k, &cp) != 0)
		abort();
	విడుదల(tmp);
	తిరిగి k;
}

స్థిర శూన్య
అమరిక(శూన్య)
{
	ఒకవేళ (initialized)
		తిరిగి;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_కీలకాలు[0] = ఎక్కించు_pubkey_or_die(PUB_RSA);
	test_కీలకాలు[1] = ఎక్కించు_pubkey_or_die(PUB_ECDSA);
	test_కీలకాలు[2] = ఎక్కించు_pubkey_or_die(PUB_ED25519);
}

గణన {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_కీలకం,
	API_QUERY_EXTENSIONS,
	API_తాళం_AGENT,
};

స్థిర శూన్య
నిరంతరం_one(పూర్ణాంకం api, నిర్మాణం sshkey *k, పూర్ణాంకం తాళం_arg,
    స్థిరరాశి uint8_t *body, కొలత_t bsize)
{
	పూర్ణాంకం sv[2] = { -1, -1 };
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		తిరిగి;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(శూన్య)లిఖ(sv[0], hdr, పరిమాణం(hdr));
	ఒకవేళ (bsize > 0)
		(శూన్య)లిఖ(sv[0], body, bsize);

	fuzz_arena_begin();

	ఎంపిక (api) {
	స్థితి API_FETCH_IDENTITYLIST: {
		నిర్మాణం ssh_identitylist *idl = ఖాళీ;
		(శూన్య)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		ఆపు;
	}
	స్థితి API_AGENT_SIGN: {
		స్థిరరాశి u_char సందేశం[16] = { 0 };
		u_char *sig = ఖాళీ;
		కొలత_t siglen = 0;
		(శూన్య)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    సందేశం, పరిమాణం(సందేశం), ఖాళీ, 0);
		విడుదల(sig);
		ఆపు;
	}
	స్థితి API_AGENT_HAS_కీలకం:
		(శూన్య)ssh_agent_has_కీలకం(sv[1], k);
		ఆపు;
	స్థితి API_QUERY_EXTENSIONS: {
		అక్షరం **exts = ఖాళీ;
		పూర్ణాంకం n = ssh_agent_query_extensions(sv[1], &exts);
		ఒకవేళ (n == 0 && exts != ఖాళీ) {
			కొరకు (పూర్ణాంకం i = 0; exts[i] != ఖాళీ; i++)
				విడుదల(exts[i]);
			విడుదల(exts);
		}
		ఆపు;
	}
	స్థితి API_తాళం_AGENT:
		(శూన్య)ssh_తాళం_agent(sv[1], తాళం_arg, "fuzz");
		ఆపు;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

బాహ్య "C" పూర్ణాంకం
LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	అమరిక();

	ఒకవేళ (కొలత > 65536)
		తిరిగి 0;

	నిరంతరం_one(API_FETCH_IDENTITYLIST, ఖాళీ,           0, దత్తాంశం, కొలత);
	నిరంతరం_one(API_AGENT_SIGN,         test_కీలకాలు[0],   0, దత్తాంశం, కొలత);
	నిరంతరం_one(API_AGENT_SIGN,         test_కీలకాలు[1],   0, దత్తాంశం, కొలత);
	నిరంతరం_one(API_AGENT_SIGN,         test_కీలకాలు[2],   0, దత్తాంశం, కొలత);
	నిరంతరం_one(API_AGENT_HAS_కీలకం,      test_కీలకాలు[2],   0, దత్తాంశం, కొలత);
	నిరంతరం_one(API_QUERY_EXTENSIONS,   ఖాళీ,           0, దత్తాంశం, కొలత);
	నిరంతరం_one(API_తాళం_AGENT,         ఖాళీ,           1, దత్తాంశం, కొలత);

	తిరిగి 0;
}
