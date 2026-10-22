/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "xmalloc.h"

শূন্য kex_proposal_tests(শূন্য);
শূন্য kex_proposal_populate_tests(শূন্য);

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
শূন্য
kex_proposal_tests(শূন্য)
{
	আকার_t i;
	কাঠামো ssh ssh;
	অক্ষর *ফলাফল, *out, *in;
	কাঠামো {
		অক্ষর *in;	/* TODO: make this const */
		অক্ষর *out;
		পূর্ণসংখ্যা compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	জন্য (i = 0; i < আকার(tests) / আকার(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		ফলাফল = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(ফলাফল, tests[i].out);
		মুক্ত(ফলাফল);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		ফলাফল = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(ফলাফল, out);
		মুক্ত(ফলাফল); মুক্ত(in); মুক্ত(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		ফলাফল = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(ফলাফল, out);
		মুক্ত(ফলাফল); মুক্ত(in); মুক্ত(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		যদি (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		অন্যথা
			xasprintf(&out, "a,%s,b", tests[i].out);
		ফলাফল = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(ফলাফল, out);
		মুক্ত(ফলাফল); মুক্ত(in); মুক্ত(out);
	}
	TEST_DONE();
}

শূন্য
kex_proposal_populate_tests(শূন্য)
{
	অক্ষর *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ধ্রুবক অক্ষর *comp = compression_alg_list(0);
	পূর্ণসংখ্যা i;
	কাঠামো ssh ssh;
	কাঠামো kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	জন্য (i = 0; i <= 1; i++) {
		kex.server = i;
		জন্য (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ফাঁকা, ফাঁকা,
			    ফাঁকা, ফাঁকা, ফাঁকা);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			যদি (ssh.compat == 0)
				ssh.compat = 1;
			অন্যথা
				ssh.compat <<= 1;
		}
	}

	মুক্ত(kexalgs);
	মুক্ত(ciphers);
	মুক্ত(macs);
	মুক্ত(hkalgs);
}
