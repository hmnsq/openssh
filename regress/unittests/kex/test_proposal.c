/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

ಶೂನ್ಯ kex_proposal_tests(ಶೂನ್ಯ);
ಶೂನ್ಯ kex_proposal_populate_tests(ಶೂನ್ಯ);

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
ಶೂನ್ಯ
kex_proposal_tests(ಶೂನ್ಯ)
{
	size_t i;
	ಸಂರಚನಾ ssh ssh;
	ವರ್ಣ *result, *out, *in;
	ಸಂರಚನಾ {
		ವರ್ಣ *in;	/* TODO: make this const */
		ವರ್ಣ *out;
		ಪೂರ್ಣಾಙ್ಕ compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	ಪ್ರತಿ (i = 0; i < ಪರಿಮಾಣ(tests) / ಪರಿಮಾಣ(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		result = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(result, tests[i].out);
		ಮುಕ್ತ(result);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		ಮುಕ್ತ(result); ಮುಕ್ತ(in); ಮುಕ್ತ(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		ಮುಕ್ತ(result); ಮುಕ್ತ(in); ಮುಕ್ತ(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		ಯದಿ (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		ಅನ್ಯಥಾ
			xasprintf(&out, "a,%s,b", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		ಮುಕ್ತ(result); ಮುಕ್ತ(in); ಮುಕ್ತ(out);
	}
	TEST_DONE();
}

ಶೂನ್ಯ
kex_proposal_populate_tests(ಶೂನ್ಯ)
{
	ವರ್ಣ *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ಧ್ರುವ ವರ್ಣ *comp = compression_alg_list(0);
	ಪೂರ್ಣಾಙ್ಕ i;
	ಸಂರಚನಾ ssh ssh;
	ಸಂರಚನಾ kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	ಪ್ರತಿ (i = 0; i <= 1; i++) {
		kex.server = i;
		ಪ್ರತಿ (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ರಿಕ್ತ, ರಿಕ್ತ,
			    ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			ಯದಿ (ssh.compat == 0)
				ssh.compat = 1;
			ಅನ್ಯಥಾ
				ssh.compat <<= 1;
		}
	}

	ಮುಕ್ತ(kexalgs);
	ಮುಕ್ತ(ciphers);
	ಮುಕ್ತ(macs);
	ಮುಕ್ತ(hkalgs);
}
