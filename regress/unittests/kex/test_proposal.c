/* 	$OpenBSD: test_proposal.c,v 1.2 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

ਖਾਲੀ kex_proposal_tests(ਖਾਲੀ);
ਖਾਲੀ kex_proposal_populate_tests(ਖਾਲੀ);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CURVE25519 "curve25519-sha256@libssh.org"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DHGEX1 "diffie-hellman-group-exchange-sha1"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DHGEX256 "diffie-hellman-group-exchange-sha256"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ KEXALGOS CURVE25519","DHGEX256","DHGEX1
ਖਾਲੀ
kex_proposal_tests(ਖਾਲੀ)
{
	ਮਾਪ_t i;
	ਬਣਤਰ ssh ssh;
	ਅੱਖਰ *ਨਤੀਜਾ, *ਬਾਹਰਲਾ, *ਵਿੱਚ;
	ਬਣਤਰ {
		ਅੱਖਰ *ਵਿੱਚ;	/* TODO: make this const */
		ਅੱਖਰ *ਬਾਹਰਲਾ;
		ਪੂਰਨ compat;
	} tests[] = {
		{ KEXALGOS, KEXALGOS, 0},
		{ KEXALGOS, DHGEX256","DHGEX1, SSH_BUG_CURVE25519PAD },
		{ KEXALGOS, CURVE25519, SSH_OLD_DHGEX },
		{ "a,"KEXALGOS, "a", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX },
		/* TODO: enable once compat_kex_proposal doesn't fatal() */
		/* { KEXALGOS, "", SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX }, */
	};

	TEST_ਸ਼ੁਰੂ("compat_kex_proposal");
	ਲਈ (i = 0; i < ਆਕਾਰ(tests) / ਆਕਾਰ(*tests); i++) {
		ssh.compat = tests[i].compat;
		/* match entire string */
		ਨਤੀਜਾ = compat_kex_proposal(&ssh, tests[i].ਵਿੱਚ);
		ASSERT_STRING_EQ(ਨਤੀਜਾ, tests[i].ਬਾਹਰਲਾ);
		ਮੁਕਤ(ਨਤੀਜਾ);
		/* match at end */
		ਵਿੱਚ = kex_ਨਾਂ_cat("a", tests[i].ਵਿੱਚ);
		ਬਾਹਰਲਾ = kex_ਨਾਂ_cat("a", tests[i].ਬਾਹਰਲਾ);
		ਨਤੀਜਾ = compat_kex_proposal(&ssh, ਵਿੱਚ);
		ASSERT_STRING_EQ(ਨਤੀਜਾ, ਬਾਹਰਲਾ);
		ਮੁਕਤ(ਨਤੀਜਾ); ਮੁਕਤ(ਵਿੱਚ); ਮੁਕਤ(ਬਾਹਰਲਾ);
		/* match at start */
		ਵਿੱਚ = kex_ਨਾਂ_cat(tests[i].ਵਿੱਚ, "a");
		ਬਾਹਰਲਾ = kex_ਨਾਂ_cat(tests[i].ਬਾਹਰਲਾ, "a");
		ਨਤੀਜਾ = compat_kex_proposal(&ssh, ਵਿੱਚ);
		ASSERT_STRING_EQ(ਨਤੀਜਾ, ਬਾਹਰਲਾ);
		ਮੁਕਤ(ਨਤੀਜਾ); ਮੁਕਤ(ਵਿੱਚ); ਮੁਕਤ(ਬਾਹਰਲਾ);
		/* match in middle */
		xasprintf(&ਵਿੱਚ, "a,%s,b", tests[i].ਵਿੱਚ);
		ਜੇ (*(tests[i].ਬਾਹਰਲਾ) == '\0')
			ਬਾਹਰਲਾ = xstrdup("a,b");
		ਨਹੀਂਤਾਂ
			xasprintf(&ਬਾਹਰਲਾ, "a,%s,b", tests[i].ਬਾਹਰਲਾ);
		ਨਤੀਜਾ = compat_kex_proposal(&ssh, ਵਿੱਚ);
		ASSERT_STRING_EQ(ਨਤੀਜਾ, ਬਾਹਰਲਾ);
		ਮੁਕਤ(ਨਤੀਜਾ); ਮੁਕਤ(ਵਿੱਚ); ਮੁਕਤ(ਬਾਹਰਲਾ);
	}
	TEST_ਪੂਰਾ();
}

ਖਾਲੀ
kex_proposal_populate_tests(ਖਾਲੀ)
{
	ਅੱਖਰ *prop[PROPOSAL_MAX], *kexalgs, *ciphers, *macs, *hkalgs;
	ਅਚਲ ਅੱਖਰ *comp = compression_alg_list(0);
	ਪੂਰਨ i;
	ਬਣਤਰ ssh ssh;
	ਬਣਤਰ kex kex;

	kexalgs = kex_alg_list(',');
	ciphers = cipher_alg_list(',', 0);
	macs = mac_alg_list(',');
	hkalgs = kex_alg_list(',');

	ssh.kex = &kex;
	TEST_ਸ਼ੁਰੂ("compat_kex_proposal_populate");
	ਲਈ (i = 0; i <= 1; i++) {
		kex.server = i;
		ਲਈ (ssh.compat = 0; ssh.compat < 0x40000000; ) {
			kex_proposal_populate_entries(&ssh, prop, ਨਿਰਾ, ਨਿਰਾ,
			    ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ);
			kex_proposal_free_entries(prop);
			kex_proposal_populate_entries(&ssh, prop, kexalgs,
			    ciphers, macs, hkalgs, comp);
			kex_proposal_free_entries(prop);
			ਜੇ (ssh.compat == 0)
				ssh.compat = 1;
			ਨਹੀਂਤਾਂ
				ssh.compat <<= 1;
		}
	}

	ਮੁਕਤ(kexalgs);
	ਮੁਕਤ(ciphers);
	ਮੁਕਤ(macs);
	ਮੁਕਤ(hkalgs);
}
