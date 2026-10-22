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

#شامل <stddef.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <sys/socket.h>
#شامل <sys/types.h>

بیرونی "C" {
#شامل "includes.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "authfd.h"
#شامل "log.h"

تهی fuzz_arena_begin(تهی);
تهی fuzz_arena_cleanup(تهی);
}

#شامل "fixed-keys.h"

ایستا ساختار sshkey *test_کلیدها[3] = { پوچ, پوچ, پوچ };
ایستا صحیح initialized = 0;

ایستا ساختار sshkey *
load_pubkey_or_die(ثابت نویسه *txt)
{
	نویسه *tmp, *cp;
	ساختار sshkey *k;

	اگر ((k = sshkey_new(کلید_UNSPEC)) == پوچ)
		abort();
	اگر ((tmp = cp = strdup(txt)) == پوچ)
		abort();
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	بازگشت k;
}

ایستا تهی
setup(تهی)
{
	اگر (initialized)
		بازگشت;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_کلیدها[0] = load_pubkey_or_die(PUB_RSA);
	test_کلیدها[1] = load_pubkey_or_die(PUB_ECDSA);
	test_کلیدها[2] = load_pubkey_or_die(PUB_ED25519);
}

شمارش {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_کلید,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

ایستا تهی
run_one(صحیح api, ساختار sshkey *k, صحیح lock_arg,
    ثابت uint8_t *body, size_t bsize)
{
	صحیح sv[2] = { -1, -1 };
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		بازگشت;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(تهی)اكتب(sv[0], hdr, اندازه(hdr));
	اگر (bsize > 0)
		(تهی)اكتب(sv[0], body, bsize);

	fuzz_arena_begin();

	انتخاب (api) {
	حالت API_FETCH_IDENTITYLIST: {
		ساختار ssh_identitylist *idl = پوچ;
		(تهی)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		بشکن;
	}
	حالت API_AGENT_SIGN: {
		ثابت u_char پیام[16] = { 0 };
		u_char *sig = پوچ;
		size_t siglen = 0;
		(تهی)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    پیام, اندازه(پیام), پوچ, 0);
		آزاد(sig);
		بشکن;
	}
	حالت API_AGENT_HAS_کلید:
		(تهی)ssh_agent_has_کلید(sv[1], k);
		بشکن;
	حالت API_QUERY_EXTENSIONS: {
		نویسه **exts = پوچ;
		صحیح n = ssh_agent_query_extensions(sv[1], &exts);
		اگر (n == 0 && exts != پوچ) {
			برای (صحیح i = 0; exts[i] != پوچ; i++)
				آزاد(exts[i]);
			آزاد(exts);
		}
		بشکن;
	}
	حالت API_LOCK_AGENT:
		(تهی)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		بشکن;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

بیرونی "C" صحیح
LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t *data, size_t size)
{
	setup();

	اگر (size > 65536)
		بازگشت 0;

	run_one(API_FETCH_IDENTITYLIST, پوچ,           0, data, size);
	run_one(API_AGENT_SIGN,         test_کلیدها[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_کلیدها[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_کلیدها[2],   0, data, size);
	run_one(API_AGENT_HAS_کلید,      test_کلیدها[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   پوچ,           0, data, size);
	run_one(API_LOCK_AGENT,         پوچ,           1, data, size);

	بازگشت 0;
}
