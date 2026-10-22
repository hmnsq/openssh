/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "cipher.h"
#समावेश "compat.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "kex.h"
#समावेश "myproposal.h"
#समावेश "packet.h"
#समावेश "xmalloc.h"

व्योम kex_proposal_tests(व्योम);
व्योम kex_proposal_populate_tests(व्योम);

#घोषणा CURVE25519 "curve25519-sha256@libssh.org"
#घोषणा DHGEX1 "diffie-hellman-group-exchange-sha1"
#घोषणा DHGEX256 "diffie-hellman-group-exchange-sha256"
#घोषणा KEXALGOS CURVE25519","DHGEX256","DHGEX1
व्योम
kex_proposal_tests(व्योम)
{
	माप_प्रकार i;
	काष्ठा ssh ssh;
	अक्षर *परिणाम, *out, *in;
	काष्ठा {
		अक्षर *in;	/* TODO: make this const */
		अक्षर *out;
		पूर्णांक compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	क्रम (i = 0; i < माप(tests) / माप(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		परिणाम = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(परिणाम, tests[i].out);
		मुक्त(परिणाम);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		परिणाम = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(परिणाम, out);
		मुक्त(परिणाम); मुक्त(in); मुक्त(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		परिणाम = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(परिणाम, out);
		मुक्त(परिणाम); मुक्त(in); मुक्त(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		अगर (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		अन्यथा
			xasprintf(&out, "a,%s,b", tests[i].out);
		परिणाम = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(परिणाम, out);
		मुक्त(परिणाम); मुक्त(in); मुक्त(out);
	}
	TEST_DONE();
}

व्योम
kex_proposal_populate_tests(व्योम)
{
	अक्षर *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	स्थिर अक्षर *comp = compression_alg_list(0);
	पूर्णांक i;
	काष्ठा ssh ssh;
	काष्ठा kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	क्रम (i = 0; i <= 1; i++) {
		kex.server = i;
		क्रम (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, शून्य, शून्य,
			    शून्य, शून्य, शून्य);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			अगर (ssh.compat == 0)
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
