/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "xmalloc.h"

શૂન્ય kex_proposal_tests(શૂન્ય);
શૂન્ય kex_proposal_populate_tests(શૂન્ય);

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
શૂન્ય
kex_proposal_tests(શૂન્ય)
{
	size_t i;
	સંરચના ssh ssh;
	અક્ષર *result, *out, *in;
	સંરચના {
		અક્ષર *in;	/* TODO: make this const */
		અક્ષર *out;
		પૂર્ણાંક compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	માટે (i = 0; i < કદ(tests) / કદ(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		result = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(result, tests[i].out);
		મુક્ત(result);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		મુક્ત(result); મુક્ત(in); મુક્ત(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		મુક્ત(result); મુક્ત(in); મુક્ત(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		જો (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		નહીંતર
			xasprintf(&out, "a,%s,b", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		મુક્ત(result); મુક્ત(in); મુક્ત(out);
	}
	TEST_DONE();
}

શૂન્ય
kex_proposal_populate_tests(શૂન્ય)
{
	અક્ષર *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	અચલ અક્ષર *comp = compression_alg_list(0);
	પૂર્ણાંક i;
	સંરચના ssh ssh;
	સંરચના kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	માટે (i = 0; i <= 1; i++) {
		kex.server = i;
		માટે (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ખાલી, ખાલી,
			    ખાલી, ખાલી, ખાલી);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			જો (ssh.compat == 0)
				ssh.compat = 1;
			નહીંતર
				ssh.compat <<= 1;
		}
	}

	મુક્ત(kexalgs);
	મુક્ત(ciphers);
	મુક્ત(macs);
	મુક્ત(hkalgs);
}
