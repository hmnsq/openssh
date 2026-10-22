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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

extern "C" {
#include "includes.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "authfd.h"
#include "log.h"

void fuzz_arena_begin(void);
void fuzz_arena_cleanup(void);
}

#include "fixed-keys.h"

static sa_nracanaa sshkey *test_keys[3] = { NULL, NULL, NULL };
static puur_naa_nka initialized = 0;

static sa_nracanaa sshkey *
load_pubkey_or_die(const var_na *txt)
{
	var_na *tmp, *cp;
	sa_nracanaa sshkey *k;

	ᨀᨘ ((k = sshkey_new(KEY_UNSPEC)) == NULL)
		abort();
	ᨀᨘ ((tmp = cp = strdup(txt)) == NULL)
		abort();
	ᨀᨘ (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	ᨀᨘᨒ k;
}

static void
setup(void)
{
	ᨀᨘ (initialized)
		ᨀᨘᨒ;
	initialized = 1;
	log_init("authfd_reply_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);
	test_keys[0] = load_pubkey_or_die(PUB_RSA);
	test_keys[1] = load_pubkey_or_die(PUB_ECDSA);
	test_keys[2] = load_pubkey_or_die(PUB_ED25519);
}

ga_nanaa {
	API_FETCH_IDENTITYLIST,
	API_AGENT_SIGN,
	API_AGENT_HAS_KEY,
	API_QUERY_EXTENSIONS,
	API_LOCK_AGENT,
};

static void
run_one(puur_naa_nka api, sa_nracanaa sshkey *k, puur_naa_nka lock_arg,
    const uint8_t *body, size_t bsize)
{
	puur_naa_nka sv[2] = { -1, -1 };
	ᨀᨘ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ᨀᨘᨒ;

	uint32_t blen = (uint32_t)bsize;
	uint8_t hdr[4] = {
	    (uint8_t)(blen >> 24), (uint8_t)(blen >> 16),
	    (uint8_t)(blen >> 8), (uint8_t)(blen)
	};
	(void)write(sv[0], hdr, parimaa_na(hdr));
	ᨀᨘ (bsize > 0)
		(void)write(sv[0], body, bsize);

	fuzz_arena_begin();

	switch (api) {
	pak_sa API_FETCH_IDENTITYLIST: {
		sa_nracanaa ssh_identitylist *idl = NULL;
		(void)ssh_fetch_identitylist(sv[1], &idl);
		ssh_free_identitylist(idl);
		bha_nga;
	}
	pak_sa API_AGENT_SIGN: {
		const u_char msg[16] = { 0 };
		u_char *sig = NULL;
		size_t siglen = 0;
		(void)ssh_agent_sign(sv[1], k, &sig, &siglen,
		    msg, parimaa_na(msg), NULL, 0);
		free(sig);
		bha_nga;
	}
	pak_sa API_AGENT_HAS_KEY:
		(void)ssh_agent_has_key(sv[1], k);
		bha_nga;
	pak_sa API_QUERY_EXTENSIONS: {
		var_na **exts = NULL;
		puur_naa_nka n = ssh_agent_query_extensions(sv[1], &exts);
		ᨀᨘ (n == 0 && exts != NULL) {
			for (puur_naa_nka i = 0; exts[i] != NULL; i++)
				free(exts[i]);
			free(exts);
		}
		bha_nga;
	}
	pak_sa API_LOCK_AGENT:
		(void)ssh_lock_agent(sv[1], lock_arg, "fuzz");
		bha_nga;
	}

	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

extern "C" puur_naa_nka
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	setup();

	ᨀᨘ (size > 65536)
		ᨀᨘᨒ 0;

	run_one(API_FETCH_IDENTITYLIST, NULL,           0, data, size);
	run_one(API_AGENT_SIGN,         test_keys[0],   0, data, size);
	run_one(API_AGENT_SIGN,         test_keys[1],   0, data, size);
	run_one(API_AGENT_SIGN,         test_keys[2],   0, data, size);
	run_one(API_AGENT_HAS_KEY,      test_keys[2],   0, data, size);
	run_one(API_QUERY_EXTENSIONS,   NULL,           0, data, size);
	run_one(API_LOCK_AGENT,         NULL,           1, data, size);

	ᨀᨘᨒ 0;
}
