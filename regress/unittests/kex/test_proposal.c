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

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
शून्य
kex_proposal_tests(शून्य)
{
	size_t i;
	संरचना ssh ssh;
	वर्ण *result, *out, *in;
	संरचना {
		वर्ण *in;	/* TODO: make this const */
		वर्ण *out;
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
		result = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(result, tests[i].out);
		मुक्त(result);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		मुक्त(result); मुक्त(in); मुक्त(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		मुक्त(result); मुक्त(in); मुक्त(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		यदि (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		अन्यथा
			xasprintf(&out, "a,%s,b", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		मुक्त(result); मुक्त(in); मुक्त(out);
	}
	TEST_DONE();
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
