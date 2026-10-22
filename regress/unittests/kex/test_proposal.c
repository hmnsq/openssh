/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <signal.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "cipher.h"
#شامل "compat.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "kex.h"
#شامل "myproposal.h"
#شامل "packet.h"
#شامل "xmalloc.h"

خالی kex_proposal_tests(خالی);
خالی kex_proposal_populate_tests(خالی);

#تعریف_کرو CURVE25519 "curve25519-sha256@libssh.org"
#تعریف_کرو DHGEX1 "diffie-hellman-group-exchange-sha1"
#تعریف_کرو DHGEX256 "diffie-hellman-group-exchange-sha256"
#تعریف_کرو KEXALGOS CURVE25519","DHGEX256","DHGEX1
خالی
kex_proposal_tests(خالی)
{
	سائز_t i;
	ساخت ssh ssh;
	حرف *نتیجہ, *برآمد, *اندر;
	ساخت {
		حرف *اندر;	/* TODO: make this const */
		حرف *برآمد;
		صحیح compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_آغاز("compat_kex_proposal");
	برائے (i = 0; i < حجم(tests) / حجم(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		نتیجہ = compat_kex_proposal(&ssh, tests[i].اندر);
		ASSERT_STRING_EQ(نتیجہ, tests[i].برآمد);
		آزاد(نتیجہ);
		/* match at end */
		اندر = kex_نام_cat("a", tests[i].اندر);
		برآمد = kex_نام_cat("a", tests[i].برآمد);
		نتیجہ = compat_kex_proposal(&ssh, اندر);
		ASSERT_STRING_EQ(نتیجہ, برآمد);
		آزاد(نتیجہ); آزاد(اندر); آزاد(برآمد);
		/* match at start */
		اندر = kex_نام_cat(tests[i].اندر, "a");
		برآمد = kex_نام_cat(tests[i].برآمد, "a");
		نتیجہ = compat_kex_proposal(&ssh, اندر);
		ASSERT_STRING_EQ(نتیجہ, برآمد);
		آزاد(نتیجہ); آزاد(اندر); آزاد(برآمد);
		/* match in middle */
		xasprintf(&اندر, "a,%s,b", tests[i].اندر);
		اگر (*(tests[i].برآمد) == '\0')
			برآمد = xstrdup("a,b");
		ورنہ
			xasprintf(&برآمد, "a,%s,b", tests[i].برآمد);
		نتیجہ = compat_kex_proposal(&ssh, اندر);
		ASSERT_STRING_EQ(نتیجہ, برآمد);
		آزاد(نتیجہ); آزاد(اندر); آزاد(برآمد);
	}
	TEST_مکمل();
}

خالی
kex_proposal_populate_tests(خالی)
{
	حرف *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ثابت حرف *comp = compression_alg_list(0);
	صحیح i;
	ساخت ssh ssh;
	ساخت kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_آغاز("compat_kex_proposal_populate");
	برائے (i = 0; i <= 1; i++) {
		kex.server = i;
		برائے (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, تہی, تہی,
			    تہی, تہی, تہی);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			اگر (ssh.compat == 0)
				ssh.compat = 1;
			ورنہ
				ssh.compat <<= 1;
		}
	}

	آزاد(kexalgs);
	آزاد(ciphers);
	آزاد(macs);
	آزاد(hkalgs);
}
