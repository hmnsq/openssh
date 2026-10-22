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

#تعریف_کن CURVE25519 "curve25519-sha256@libssh.org"
#تعریف_کن DHGEX1 "diffie-hellman-group-exchange-sha1"
#تعریف_کن DHGEX256 "diffie-hellman-group-exchange-sha256"
#تعریف_کن KEXALGOS CURVE25519","DHGEX256","DHGEX1
فراغ
kex_proposal_tests(فراغ)
{
	اندازه_t i;
	بنية ssh ssh;
	حرف *نتیجه, *بیرون, *درون;
	بنية {
		حرف *درون;	/* TODO: make this const */
		حرف *بیرون;
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
		نتیجه = compat_kex_proposal(&ssh, tests[i].درون);
		ASSERT_STRING_EQ(نتیجه, tests[i].بیرون);
		حرر(نتیجه);
		/* match at end */
		درون = kex_نامها_cat("a", tests[i].درون);
		بیرون = kex_نامها_cat("a", tests[i].بیرون);
		نتیجه = compat_kex_proposal(&ssh, درون);
		ASSERT_STRING_EQ(نتیجه, بیرون);
		حرر(نتیجه); حرر(درون); حرر(بیرون);
		/* match at start */
		درون = kex_نامها_cat(tests[i].درون, "a");
		بیرون = kex_نامها_cat(tests[i].بیرون, "a");
		نتیجه = compat_kex_proposal(&ssh, درون);
		ASSERT_STRING_EQ(نتیجه, بیرون);
		حرر(نتیجه); حرر(درون); حرر(بیرون);
		/* match in middle */
		xasprintf(&درون, "a,%s,b", tests[i].درون);
		إذا (*(tests[i].بیرون) == '\0')
			بیرون = xstrdup("a,b");
		وإلا
			xasprintf(&بیرون, "a,%s,b", tests[i].بیرون);
		نتیجه = compat_kex_proposal(&ssh, درون);
		ASSERT_STRING_EQ(نتیجه, بیرون);
		حرر(نتیجه); حرر(درون); حرر(بیرون);
	}
	TEST_انجامشده();
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
