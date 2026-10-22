/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "cipher.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "xmalloc.h"

శూన్య kex_proposal_tests(శూన్య);
శూన్య kex_proposal_populate_tests(శూన్య);

#నిర్వచించు CURVE25519 "curve25519-sha256@libssh.org"
#నిర్వచించు DHGEX1 "diffie-hellman-group-exchange-sha1"
#నిర్వచించు DHGEX256 "diffie-hellman-group-exchange-sha256"
#నిర్వచించు KEXALGOS CURVE25519","DHGEX256","DHGEX1
శూన్య
kex_proposal_tests(శూన్య)
{
	కొలత_t i;
	నిర్మాణం ssh ssh;
	అక్షరం *ఫలితం, *బహిర్గతం, *లోపల;
	నిర్మాణం {
		అక్షరం *లోపల;	/* TODO: make this const */
		అక్షరం *బహిర్గతం;
		పూర్ణాంకం compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_ప్రారంభం("compat_kex_proposal");
	కొరకు (i = 0; i < పరిమాణం(tests) / పరిమాణం(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		ఫలితం = compat_kex_proposal(&ssh, tests[i].లోపల);
		ASSERT_STRING_EQ(ఫలితం, tests[i].బహిర్గతం);
		విడుదల(ఫలితం);
		/* match at end */
		లోపల = kex_పేర్లు_cat("a", tests[i].లోపల);
		బహిర్గతం = kex_పేర్లు_cat("a", tests[i].బహిర్గతం);
		ఫలితం = compat_kex_proposal(&ssh, లోపల);
		ASSERT_STRING_EQ(ఫలితం, బహిర్గతం);
		విడుదల(ఫలితం); విడుదల(లోపల); విడుదల(బహిర్గతం);
		/* match at start */
		లోపల = kex_పేర్లు_cat(tests[i].లోపల, "a");
		బహిర్గతం = kex_పేర్లు_cat(tests[i].బహిర్గతం, "a");
		ఫలితం = compat_kex_proposal(&ssh, లోపల);
		ASSERT_STRING_EQ(ఫలితం, బహిర్గతం);
		విడుదల(ఫలితం); విడుదల(లోపల); విడుదల(బహిర్గతం);
		/* match in middle */
		xasprintf(&లోపల, "a,%s,b", tests[i].లోపల);
		ఒకవేళ (*(tests[i].బహిర్గతం) == '\0')
			బహిర్గతం = xstrdup("a,b");
		లేకపోతే
			xasprintf(&బహిర్గతం, "a,%s,b", tests[i].బహిర్గతం);
		ఫలితం = compat_kex_proposal(&ssh, లోపల);
		ASSERT_STRING_EQ(ఫలితం, బహిర్గతం);
		విడుదల(ఫలితం); విడుదల(లోపల); విడుదల(బహిర్గతం);
	}
	TEST_పూర్తి();
}

శూన్య
kex_proposal_populate_tests(శూన్య)
{
	అక్షరం *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	స్థిరరాశి అక్షరం *comp = compression_alg_list(0);
	పూర్ణాంకం i;
	నిర్మాణం ssh ssh;
	నిర్మాణం kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_ప్రారంభం("compat_kex_proposal_populate");
	కొరకు (i = 0; i <= 1; i++) {
		kex.server = i;
		కొరకు (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ఖాళీ, ఖాళీ,
			    ఖాళీ, ఖాళీ, ఖాళీ);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			ఒకవేళ (ssh.compat == 0)
				ssh.compat = 1;
			లేకపోతే
				ssh.compat <<= 1;
		}
	}

	విడుదల(kexalgs);
	విడుదల(ciphers);
	విడుదల(macs);
	విడుదల(hkalgs);
}
