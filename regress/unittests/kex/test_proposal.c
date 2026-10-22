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

#ವ್ಯಾಖ್ಯಾನಿಸು CURVE25519 "curve25519-sha256@libssh.org"
#ವ್ಯಾಖ್ಯಾನಿಸು DHGEX1 "diffie-hellman-group-exchange-sha1"
#ವ್ಯಾಖ್ಯಾನಿಸು DHGEX256 "diffie-hellman-group-exchange-sha256"
#ವ್ಯಾಖ್ಯಾನಿಸು KEXALGOS CURVE25519","DHGEX256","DHGEX1
ಶೂನ್ಯ
kex_proposal_tests(ಶೂನ್ಯ)
{
	ಗಾತ್ರ_t i;
	ರಚನೆ ssh ssh;
	ಅಕ್ಷರ *ಫಲಿತಾಂಶ, *ಹೊರಹೋಗು, *ಒಳ;
	ರಚನೆ {
		ಅಕ್ಷರ *ಒಳ;	/* TODO: make this const */
		ಅಕ್ಷರ *ಹೊರಹೋಗು;
		ಪೂರ್ಣಾಂಕ compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_ಆರಂಭ("compat_kex_proposal");
	ಗಾಗಿ (i = 0; i < ಗಾತ್ರ(tests) / ಗಾತ್ರ(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		ಫಲಿತಾಂಶ = compat_kex_proposal(&ssh, tests[i].ಒಳ);
		ASSERT_STRING_EQ(ಫಲಿತಾಂಶ, tests[i].ಹೊರಹೋಗು);
		ಬಿಡುಗಡೆ(ಫಲಿತಾಂಶ);
		/* match at end */
		ಒಳ = kex_ಹೆಸರುಗಳು_cat("a", tests[i].ಒಳ);
		ಹೊರಹೋಗು = kex_ಹೆಸರುಗಳು_cat("a", tests[i].ಹೊರಹೋಗು);
		ಫಲಿತಾಂಶ = compat_kex_proposal(&ssh, ಒಳ);
		ASSERT_STRING_EQ(ಫಲಿತಾಂಶ, ಹೊರಹೋಗು);
		ಬಿಡುಗಡೆ(ಫಲಿತಾಂಶ); ಬಿಡುಗಡೆ(ಒಳ); ಬಿಡುಗಡೆ(ಹೊರಹೋಗು);
		/* match at start */
		ಒಳ = kex_ಹೆಸರುಗಳು_cat(tests[i].ಒಳ, "a");
		ಹೊರಹೋಗು = kex_ಹೆಸರುಗಳು_cat(tests[i].ಹೊರಹೋಗು, "a");
		ಫಲಿತಾಂಶ = compat_kex_proposal(&ssh, ಒಳ);
		ASSERT_STRING_EQ(ಫಲಿತಾಂಶ, ಹೊರಹೋಗು);
		ಬಿಡುಗಡೆ(ಫಲಿತಾಂಶ); ಬಿಡುಗಡೆ(ಒಳ); ಬಿಡುಗಡೆ(ಹೊರಹೋಗು);
		/* match in middle */
		xasprintf(&ಒಳ, "a,%s,b", tests[i].ಒಳ);
		ಆದರೆ (*(tests[i].ಹೊರಹೋಗು) == '\0')
			ಹೊರಹೋಗು = xstrdup("a,b");
		ಇಲ್ಲದಿದ್ದರೆ
			xasprintf(&ಹೊರಹೋಗು, "a,%s,b", tests[i].ಹೊರಹೋಗು);
		ಫಲಿತಾಂಶ = compat_kex_proposal(&ssh, ಒಳ);
		ASSERT_STRING_EQ(ಫಲಿತಾಂಶ, ಹೊರಹೋಗು);
		ಬಿಡುಗಡೆ(ಫಲಿತಾಂಶ); ಬಿಡುಗಡೆ(ಒಳ); ಬಿಡುಗಡೆ(ಹೊರಹೋಗು);
	}
	TEST_ಮುಗಿದ();
}

ಶೂನ್ಯ
kex_proposal_populate_tests(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comp = compression_alg_list(0);
	ಪೂರ್ಣಾಂಕ i;
	ರಚನೆ ssh ssh;
	ರಚನೆ kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_ಆರಂಭ("compat_kex_proposal_populate");
	ಗಾಗಿ (i = 0; i <= 1; i++) {
		kex.server = i;
		ಗಾಗಿ (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ಖಾಲಿ, ಖಾಲಿ,
			    ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			ಆದರೆ (ssh.compat == 0)
				ssh.compat = 1;
			ಇಲ್ಲದಿದ್ದರೆ
				ssh.compat <<= 1;
		}
	}

	ಬಿಡುಗಡೆ(kexalgs);
	ಬಿಡುಗಡೆ(ciphers);
	ಬಿಡುಗಡೆ(macs);
	ಬಿಡುಗಡೆ(hkalgs);
}
