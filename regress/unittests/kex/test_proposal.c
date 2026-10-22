/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <signal.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "cipher.h"
#ضمن "compat.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "kex.h"
#ضمن "myproposal.h"
#ضمن "packet.h"
#ضمن "xmalloc.h"

فراغ kex_proposal_tests(فراغ);
فراغ kex_proposal_populate_tests(فراغ);

#تعریف_کرو CURVE25519 "curve25519-sha256@libssh.org"
#تعریف_کرو DHGEX1 "diffie-hellman-group-exchange-sha1"
#تعریف_کرو DHGEX256 "diffie-hellman-group-exchange-sha256"
#تعریف_کرو KEXALGOS CURVE25519","DHGEX256","DHGEX1
فراغ
kex_proposal_tests(فراغ)
{
	ناپ_t i;
	بنية ssh ssh;
	حرف *نتیجہ, *باہرلا, *وچ;
	بنية {
		حرف *وچ;	/* TODO: make this const */
		حرف *باہرلا;
		صحيح compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_شروع("compat_kex_proposal");
	لكل (i = 0; i < حجم(tests) / حجم(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		نتیجہ = compat_kex_proposal(&ssh, tests[i].وچ);
		ASSERT_STRING_EQ(نتیجہ, tests[i].باہرلا);
		حرر(نتیجہ);
		/* match at end */
		وچ = kex_ناں_cat("a", tests[i].وچ);
		باہرلا = kex_ناں_cat("a", tests[i].باہرلا);
		نتیجہ = compat_kex_proposal(&ssh, وچ);
		ASSERT_STRING_EQ(نتیجہ, باہرلا);
		حرر(نتیجہ); حرر(وچ); حرر(باہرلا);
		/* match at start */
		وچ = kex_ناں_cat(tests[i].وچ, "a");
		باہرلا = kex_ناں_cat(tests[i].باہرلا, "a");
		نتیجہ = compat_kex_proposal(&ssh, وچ);
		ASSERT_STRING_EQ(نتیجہ, باہرلا);
		حرر(نتیجہ); حرر(وچ); حرر(باہرلا);
		/* match in middle */
		xasprintf(&وچ, "a,%s,b", tests[i].وچ);
		إذا (*(tests[i].باہرلا) == '\0')
			باہرلا = xstrdup("a,b");
		وإلا
			xasprintf(&باہرلا, "a,%s,b", tests[i].باہرلا);
		نتیجہ = compat_kex_proposal(&ssh, وچ);
		ASSERT_STRING_EQ(نتیجہ, باہرلا);
		حرر(نتیجہ); حرر(وچ); حرر(باہرلا);
	}
	TEST_پورا();
}

فراغ
kex_proposal_populate_tests(فراغ)
{
	حرف *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ثابت حرف *comp = compression_alg_list(0);
	صحيح i;
	بنية ssh ssh;
	بنية kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_شروع("compat_kex_proposal_populate");
	لكل (i = 0; i <= 1; i++) {
		kex.server = i;
		لكل (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, عدم, عدم,
			    عدم, عدم, عدم);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			إذا (ssh.compat == 0)
				ssh.compat = 1;
			وإلا
				ssh.compat <<= 1;
		}
	}

	حرر(kexalgs);
	حرر(ciphers);
	حرر(macs);
	حرر(hkalgs);
}
