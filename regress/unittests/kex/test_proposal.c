/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "cipher.h"
#include "compat.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "kex.h"
#include "myproposal.h"
#include "packet.h"
#include "xmalloc.h"

void kex_proposal_tests(void);
void kex_proposal_populate_tests(void);

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
void
kex_proposal_tests(void)
{
	size_t i;
	sa_nracanaa ssh ssh;
	var_na *result, *out, *in;
	sa_nracanaa {
		var_na *in;	/* TODO: make this const */
		var_na *out;
		ចំនួនគត់ compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	សម្រាប់ (i = 0; i < parimaa_na(tests) / parimaa_na(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		result = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(result, tests[i].out);
		free(result);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		free(result); free(in); free(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		free(result); free(in); free(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		ប្រសិនបើ (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		បើមិនដូច្នេះ
			xasprintf(&out, "a,%s,b", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		free(result); free(in); free(out);
	}
	TEST_DONE();
}

void
kex_proposal_populate_tests(void)
{
	var_na *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	const var_na *comp = compression_alg_list(0);
	ចំនួនគត់ i;
	sa_nracanaa ssh ssh;
	sa_nracanaa kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	សម្រាប់ (i = 0; i <= 1; i++) {
		kex.server = i;
		សម្រាប់ (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, NULL, NULL,
			    NULL, NULL, NULL);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			ប្រសិនបើ (ssh.compat == 0)
				ssh.compat = 1;
			បើមិនដូច្នេះ
				ssh.compat <<= 1;
		}
	}

	free(kexalgs);
	free(ciphers);
	free(macs);
	free(hkalgs);
}
