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

خارجی "C" {
#شامل "includes.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "authfd.h"
#شامل "log.h"

خالی fuzz_arena_begin(خالی);
خالی fuzz_arena_cleanup(خالی);
}

#شامل "fixed-keys.h"

ساکن ساخت sshkey *test_کلیدیں[3] = { تہی, تہی, تہی };
ساکن صحیح initialized = 0;

ساکن ساخت sshkey *
بھرو_pubkey_or_die(ثابت حرف *txt)
{
	حرف *tmp, *cp;
	ساخت sshkey *k;

	اگر ((k = sshkey_new(کلید_UNSPEC)) == تہی)
		abort();
	اگر ((tmp = cp = strdup(txt)) == تہی)
		abort();
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	واپس k;
}

ساکن خالی
تیاری(خالی)
{
	اگر (initialized)
		واپس;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_کلیدیں[0] = بھرو_pubkey_or_die(PUB_RSA);
	test_کلیدیں[1] = بھرو_pubkey_or_die(PUB_ECDSA);
	test_کلیدیں[2] = بھرو_pubkey_or_die(PUB_ED25519);
}

شمار {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_کلید,
	API_QUERY_EXTENSIONS,
	API_تالا_AGENT,
};

ساکن خالی
تسلسل_one(صحیح api, ساخت sshkey *k, صحیح تالا_arg,
    ثابت uint8_t *body, سائز_t bsize)
{
	صحیح sv[2] = { -1, -1 };
	اگر (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		واپس;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(خالی)اكتب(sv[0], hdr, حجم(hdr));
	اگر (bsize > 0)
		(خالی)اكتب(sv[0], body, bsize);

	fuzz_arena_begin();

	انتخاب (api) {
	حالت API_FETCH_IDENTITYLIST: {
		ساخت ssh_identitylist *idl = تہی;
		(خالی)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		توڑو;
	}
	حالت API_AGENT_SIGN: {
		ثابت u_char پیغام[16] = { 0 };
		u_char *sig = تہی;
		سائز_t siglen = 0;
		(خالی)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    پیغام, حجم(پیغام), تہی, 0);
		آزاد(sig);
		توڑو;
	}
	حالت API_AGENT_HAS_کلید:
		(خالی)ssh_agent_has_کلید(sv[1], k);
		توڑو;
	حالت API_QUERY_EXTENSIONS: {
		حرف **exts = تہی;
		صحیح n = ssh_agent_query_extensions(sv[1], &exts);
		اگر (n == 0 && exts != تہی) {
			برائے (صحیح i = 0; exts[i] != تہی; i++)
				آزاد(exts[i]);
			آزاد(exts);
		}
		توڑو;
	}
	حالت API_تالا_AGENT:
		(خالی)ssh_تالا_agent(sv[1], تالا_arg, "fuzz");
		توڑو;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

خارجی "C" صحیح
LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	تیاری();

	اگر (سائز > 65536)
		واپس 0;

	تسلسل_one(API_FETCH_IDENTITYLIST, تہی,           0, ڈیٹا, سائز);
	تسلسل_one(API_AGENT_SIGN,         test_کلیدیں[0],   0, ڈیٹا, سائز);
	تسلسل_one(API_AGENT_SIGN,         test_کلیدیں[1],   0, ڈیٹا, سائز);
	تسلسل_one(API_AGENT_SIGN,         test_کلیدیں[2],   0, ڈیٹا, سائز);
	تسلسل_one(API_AGENT_HAS_کلید,      test_کلیدیں[2],   0, ڈیٹا, سائز);
	تسلسل_one(API_QUERY_EXTENSIONS,   تہی,           0, ڈیٹا, سائز);
	تسلسل_one(API_تالا_AGENT,         تہی,           1, ڈیٹا, سائز);

	واپس 0;
}
