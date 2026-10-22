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

#تعریف_کړه CURVE25519 "curve25519-sha256@libssh.org"
#تعریف_کړه DHGEX1 "diffie-hellman-group-exchange-sha1"
#تعریف_کړه DHGEX256 "diffie-hellman-group-exchange-sha256"
#تعریف_کړه KEXALGOS CURVE25519","DHGEX256","DHGEX1
فراغ
kex_proposal_tests(فراغ)
{
	اندازه_t i;
	بنية ssh ssh;
	حرف *پایله, *بهر, *دننه;
	بنية {
		حرف *دننه;	/* TODO: make this const */
		حرف *بهر;
		صحيح compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_پیل("compat_kex_proposal");
	لكل (i = 0; i < حجم(tests) / حجم(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		پایله = compat_kex_proposal(&ssh, tests[i].دننه);
		ASSERT_STRING_EQ(پایله, tests[i].بهر);
		حرر(پایله);
		/* match at end */
		دننه = kex_نومونه_cat("a", tests[i].دننه);
		بهر = kex_نومونه_cat("a", tests[i].بهر);
		پایله = compat_kex_proposal(&ssh, دننه);
		ASSERT_STRING_EQ(پایله, بهر);
		حرر(پایله); حرر(دننه); حرر(بهر);
		/* match at start */
		دننه = kex_نومونه_cat(tests[i].دننه, "a");
		بهر = kex_نومونه_cat(tests[i].بهر, "a");
		پایله = compat_kex_proposal(&ssh, دننه);
		ASSERT_STRING_EQ(پایله, بهر);
		حرر(پایله); حرر(دننه); حرر(بهر);
		/* match in middle */
		xasprintf(&دننه, "a,%s,b", tests[i].دننه);
		إذا (*(tests[i].بهر) == '\0')
			بهر = xstrdup("a,b");
		وإلا
			xasprintf(&بهر, "a,%s,b", tests[i].بهر);
		پایله = compat_kex_proposal(&ssh, دننه);
		ASSERT_STRING_EQ(پایله, بهر);
		حرر(پایله); حرر(دننه); حرر(بهر);
	}
	TEST_بشپړ();
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
	TEST_پیل("compat_kex_proposal_populate");
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
