/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "xmalloc.h"

ശൂന്യം kex_proposal_tests(ശൂന്യം);
ശൂന്യം kex_proposal_populate_tests(ശൂന്യം);

#define CURVE25519 "curve25519-sha256@libssh.org"
#define DHGEX1 "diffie-hellman-group-exchange-sha1"
#define DHGEX256 "diffie-hellman-group-exchange-sha256"
#define KEXALGOS CURVE25519","DHGEX256","DHGEX1
ശൂന്യം
kex_proposal_tests(ശൂന്യം)
{
	size_t i;
	ഘടന ssh ssh;
	അക്ഷരം *result, *out, *in;
	ഘടന {
		അക്ഷരം *in;	/* TODO: make this const */
		അക്ഷരം *out;
		പൂർണ്ണസംഖ്യ compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_START("compat_kex_proposal");
	വേണ്ടി (i = 0; i < വലുപ്പം(tests) / വലുപ്പം(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		result = compat_kex_proposal(&ssh, tests[i].in);
		ASSERT_STRING_EQ(result, tests[i].out);
		സ്വതന്ത്രം(result);
		/* match at end */
		in = kex_names_cat("a", tests[i].in);
		out = kex_names_cat("a", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		സ്വതന്ത്രം(result); സ്വതന്ത്രം(in); സ്വതന്ത്രം(out);
		/* match at start */
		in = kex_names_cat(tests[i].in, "a");
		out = kex_names_cat(tests[i].out, "a");
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		സ്വതന്ത്രം(result); സ്വതന്ത്രം(in); സ്വതന്ത്രം(out);
		/* match in middle */
		xasprintf(&in, "a,%s,b", tests[i].in);
		എങ്കിൽ (*(tests[i].out) == '\0')
			out = xstrdup("a,b");
		അല്ലെങ്കിൽ
			xasprintf(&out, "a,%s,b", tests[i].out);
		result = compat_kex_proposal(&ssh, in);
		ASSERT_STRING_EQ(result, out);
		സ്വതന്ത്രം(result); സ്വതന്ത്രം(in); സ്വതന്ത്രം(out);
	}
	TEST_DONE();
}

ശൂന്യം
kex_proposal_populate_tests(ശൂന്യം)
{
	അക്ഷരം *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	സ്ഥിരം അക്ഷരം *comp = compression_alg_list(0);
	പൂർണ്ണസംഖ്യ i;
	ഘടന ssh ssh;
	ഘടന kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_START("compat_kex_proposal_populate");
	വേണ്ടി (i = 0; i <= 1; i++) {
		kex.server = i;
		വേണ്ടി (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ശൂന്യ, ശൂന്യ,
			    ശൂന്യ, ശൂന്യ, ശൂന്യ);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			എങ്കിൽ (ssh.compat == 0)
				ssh.compat = 1;
			അല്ലെങ്കിൽ
				ssh.compat <<= 1;
		}
	}

	സ്വതന്ത്രം(kexalgs);
	സ്വതന്ത്രം(ciphers);
	സ്വതന്ത്രം(macs);
	സ്വതന്ത്രം(hkalgs);
}
