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

#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <sys/socket.h>
#ضمن <sys/types.h>

خارجي "C" {
#ضمن "includes.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "authfd.h"
#ضمن "log.h"

فراغ fuzz_arena_begin(فراغ);
فراغ fuzz_arena_cleanup(فراغ);
}

#ضمن "fixed-keys.h"

ساكن بنية sshkey *test_کلیدها[3] = { عدم, عدم, عدم };
ساكن صحيح initialized = 0;

ساكن بنية sshkey *
بارگیری_pubkey_or_die(ثابت حرف *txt)
{
	حرف *tmp, *cp;
	بنية sshkey *k;

	إذا ((k = sshkey_new(کلید_UNSPEC)) == عدم)
		abort();
	إذا ((tmp = cp = strdup(txt)) == عدم)
		abort();
	إذا (sshkey_read(k, &cp) != 0)
		abort();
	حرر(tmp);
	أرجع k;
}

ساكن فراغ
راهاندازی(فراغ)
{
	إذا (initialized)
		أرجع;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_کلیدها[0] = بارگیری_pubkey_or_die(PUB_RSA);
	test_کلیدها[1] = بارگیری_pubkey_or_die(PUB_ECDSA);
	test_کلیدها[2] = بارگیری_pubkey_or_die(PUB_ED25519);
}

تعداد {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_کلید,
	API_QUERY_EXTENSIONS,
	API_قفل_AGENT,
};

ساكن فراغ
پیاپی_one(صحيح api, بنية sshkey *k, صحيح قفل_arg,
    ثابت uint8_t *body, اندازه_t bsize)
{
	صحيح sv[2] = { -1, -1 };
	إذا (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		أرجع;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(فراغ)اكتب(sv[0], hdr, حجم(hdr));
	إذا (bsize > 0)
		(فراغ)اكتب(sv[0], body, bsize);

	fuzz_arena_begin();

	بدل (api) {
	حالة API_FETCH_IDENTITYLIST: {
		بنية ssh_identitylist *idl = عدم;
		(فراغ)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		اكسر;
	}
	حالة API_AGENT_SIGN: {
		ثابت u_char پیام[16] = { 0 };
		u_char *sig = عدم;
		اندازه_t siglen = 0;
		(فراغ)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    پیام, حجم(پیام), عدم, 0);
		حرر(sig);
		اكسر;
	}
	حالة API_AGENT_HAS_کلید:
		(فراغ)ssh_agent_has_کلید(sv[1], k);
		اكسر;
	حالة API_QUERY_EXTENSIONS: {
		حرف **exts = عدم;
		صحيح n = ssh_agent_query_extensions(sv[1], &exts);
		إذا (n == 0 && exts != عدم) {
			لكل (صحيح i = 0; exts[i] != عدم; i++)
				حرر(exts[i]);
			حرر(exts);
		}
		اكسر;
	}
	حالة API_قفل_AGENT:
		(فراغ)ssh_قفل_agent(sv[1], قفل_arg, "fuzz");
		اكسر;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

خارجي "C" صحيح
LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t *داده, اندازه_t اندازه)
{
	راهاندازی();

	إذا (اندازه > 65536)
		أرجع 0;

	پیاپی_one(API_FETCH_IDENTITYLIST, عدم,           0, داده, اندازه);
	پیاپی_one(API_AGENT_SIGN,         test_کلیدها[0],   0, داده, اندازه);
	پیاپی_one(API_AGENT_SIGN,         test_کلیدها[1],   0, داده, اندازه);
	پیاپی_one(API_AGENT_SIGN,         test_کلیدها[2],   0, داده, اندازه);
	پیاپی_one(API_AGENT_HAS_کلید,      test_کلیدها[2],   0, داده, اندازه);
	پیاپی_one(API_QUERY_EXTENSIONS,   عدم,           0, داده, اندازه);
	پیاپی_one(API_قفل_AGENT,         عدم,           1, داده, اندازه);

	أرجع 0;
}
