/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

ଶୂନ୍ୟ kex_proposal_tests(ଶୂନ୍ୟ);
ଶୂନ୍ୟ kex_proposal_populate_tests(ଶୂନ୍ୟ);

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
ଶୂନ୍ୟ
kex_proposal_tests(ଶୂନ୍ୟ)
{
	size_t i;
	ସଂରଚନା ssh ssh;
	ଅକ୍ଷର *result, *out, *in;
	ସଂରଚନା {
		ଅକ୍ଷର *in;	/* TODO: make this const */
		ଅକ୍ଷର *out;
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	ପାଇଁ (i = 0; i < ଆକାର(tests) / ଆକାର(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		result = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(result, tests[i].out);
		ମୁକ୍ତ(result);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		ମୁକ୍ତ(result); ମୁକ୍ତ(in); ମୁକ୍ତ(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		ମୁକ୍ତ(result); ମୁକ୍ତ(in); ମୁକ୍ତ(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		ଯଦି (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		ଅନ୍ୟଥା
			xasprintf(&out, "a,%s,b", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		ମୁକ୍ତ(result); ମୁକ୍ତ(in); ମୁକ୍ତ(out);
	}
	TEST_DONE();
}

ଶୂନ୍ୟ
kex_proposal_populate_tests(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ଅଚଳ ଅକ୍ଷର *comp = compression_alg_list(0);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ସଂରଚନା ssh ssh;
	ସଂରଚନା kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	ପାଇଁ (i = 0; i <= 1; i++) {
		kex.server = i;
		ପାଇଁ (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ଖାଲି, ଖାଲି,
			    ଖାଲି, ଖାଲି, ଖାଲି);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			ଯଦି (ssh.compat == 0)
				ssh.compat = 1;
			ଅନ୍ୟଥା
				ssh.compat <<= 1;
		}
	}

	ମୁକ୍ତ(kexalgs);
	ମୁକ୍ତ(ciphers);
	ମୁକ୍ତ(macs);
	ମୁକ୍ତ(hkalgs);
}
