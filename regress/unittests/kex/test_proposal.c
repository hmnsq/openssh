/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "xmalloc.h"

வெறுமை kex_proposal_tests(வெறுமை);
வெறுமை kex_proposal_populate_tests(வெறுமை);

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
வெறுமை
kex_proposal_tests(வெறுமை)
{
	size_t i;
	கட்டமைப்பு ssh ssh;
	எழுத்து *result, *out, *in;
	கட்டமைப்பு {
		எழுத்து *in;	/* TODO: make this const */
		எழுத்து *out;
		முழு compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	க்கு (i = 0; i < அளவு(tests) / அளவு(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		result = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(result, tests[i].out);
		விடுவி(result);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		விடுவி(result); விடுவி(in); விடுவி(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		விடுவி(result); விடுவி(in); விடுவி(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		எனில் (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		இல்லையெனில்
			xasprintf(&out, "a,%s,b", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		விடுவி(result); விடுவி(in); விடுவி(out);
	}
	TEST_DONE();
}

வெறுமை
kex_proposal_populate_tests(வெறுமை)
{
	எழுத்து *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	மாறிலி எழுத்து *comp = compression_alg_list(0);
	முழு i;
	கட்டமைப்பு ssh ssh;
	கட்டமைப்பு kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	க்கு (i = 0; i <= 1; i++) {
		kex.server = i;
		க்கு (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, வெற்று, வெற்று,
			    வெற்று, வெற்று, வெற்று);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			எனில் (ssh.compat == 0)
				ssh.compat = 1;
			இல்லையெனில்
				ssh.compat <<= 1;
		}
	}

	விடுவி(kexalgs);
	விடுவி(ciphers);
	விடுவி(macs);
	விடுவி(hkalgs);
}
