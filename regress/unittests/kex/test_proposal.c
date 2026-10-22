/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "cipher.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "xmalloc.h"

शून्य kex_proposal_tests(शून्य);
शून्य kex_proposal_populate_tests(शून्य);

#परिभाषय CURVE25519 "curve25519-sha256@libssh.org"
#परिभाषय DHGEX1 "diffie-hellman-group-exchange-sha1"
#परिभाषय DHGEX256 "diffie-hellman-group-exchange-sha256"
#परिभाषय KEXALGOS CURVE25519","DHGEX256","DHGEX1
शून्य
kex_proposal_tests(शून्य)
{
	आकार_t i;
	संरचना ssh ssh;
	वर्ण *परिणाम, *बहिर्गमनम्, *अन्तर्;
	संरचना {
		वर्ण *अन्तर्;	/* TODO: make this const */
		वर्ण *बहिर्गमनम्;
		पूर्णाङ्क compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	प्रति (i = 0; i < परिमाण(tests) / परिमाण(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		परिणाम = compat_kex_proposal(&ssh, tests[i].अन्तर्);
		ASSERT_STRING_EQ(परिणाम, tests[i].बहिर्गमनम्);
		मुक्त(परिणाम);
		/* match at end */
		अन्तर् = kex_नामानि_cat("a", tests[i].अन्तर्);
		बहिर्गमनम् = kex_नामानि_cat("a", tests[i].बहिर्गमनम्);
		परिणाम = compat_kex_proposal(&ssh, अन्तर्);
		ASSERT_STRING_EQ(परिणाम, बहिर्गमनम्);
		मुक्त(परिणाम); मुक्त(अन्तर्); मुक्त(बहिर्गमनम्);
		/* match at start */
		अन्तर् = kex_नामानि_cat(tests[i].अन्तर्, "a");
		बहिर्गमनम् = kex_नामानि_cat(tests[i].बहिर्गमनम्, "a");
		परिणाम = compat_kex_proposal(&ssh, अन्तर्);
		ASSERT_STRING_EQ(परिणाम, बहिर्गमनम्);
		मुक्त(परिणाम); मुक्त(अन्तर्); मुक्त(बहिर्गमनम्);
		/* match in middle */
		xasprintf(&अन्तर्, "a,%s,b", tests[i].अन्तर्);
		यदि (*(tests[i].बहिर्गमनम्) == '\0')
			बहिर्गमनम् = xstrdup("a,b");
		अन्यथा
			xasprintf(&बहिर्गमनम्, "a,%s,b", tests[i].बहिर्गमनम्);
		परिणाम = compat_kex_proposal(&ssh, अन्तर्);
		ASSERT_STRING_EQ(परिणाम, बहिर्गमनम्);
		मुक्त(परिणाम); मुक्त(अन्तर्); मुक्त(बहिर्गमनम्);
	}
	TEST_समाप्तम्();
}

शून्य
kex_proposal_populate_tests(शून्य)
{
	वर्ण *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ध्रुव वर्ण *comp = compression_alg_list(0);
	पूर्णाङ्क i;
	संरचना ssh ssh;
	संरचना kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	प्रति (i = 0; i <= 1; i++) {
		kex.server = i;
		प्रति (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, रिक्त, रिक्त,
			    रिक्त, रिक्त, रिक्त);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			यदि (ssh.compat == 0)
				ssh.compat = 1;
			अन्यथा
				ssh.compat <<= 1;
		}
	}

	मुक्त(kexalgs);
	मुक्त(ciphers);
	मुक्त(macs);
	मुक्त(hkalgs);
}
