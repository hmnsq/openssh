/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "log.h"

ಶೂನ್ಯ kex_tests(ಶೂನ್ಯ);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ do_debug = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
do_send_and_receive(ರಚನೆ ssh *from, ರಚನೆ ssh *ಗಮ್ಯ)
{
	u_char type;
	ಗಾತ್ರ_t len;
	ಸ್ಥಿರಾಂಕ u_char *buf;
	ಪೂರ್ಣಾಂಕ r;

	ಗಾಗಿ (;;) {
		ಆದರೆ ((r = ssh_packet_ಮುಂದಿನ(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			ಹಿಂತಿರುಗಿ r;
		}
		ಆದರೆ (type != 0)
			ಹಿಂತಿರುಗಿ 0;
		buf = ssh_output_ptr(from, &len);
		ಆದರೆ (do_debug)
			ಬರೆ("%zu", len);
		ಆದರೆ (len == 0)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_ಒಳಹರಿವು_append(ಗಮ್ಯ, buf, len)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಸತತ_kex(ರಚನೆ ssh *client, ರಚನೆ ssh *server)
{
	ಪೂರ್ಣಾಂಕ r = 0;

	ಆಗ (!server->kex->ಮುಗಿದ || !client->kex->ಮುಗಿದ) {
		ಆದರೆ (do_debug)
			ಬರೆ(" S:");
		ಆದರೆ ((r = do_send_and_receive(server, client)))
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (do_debug)
			ಬರೆ(" C:");
		ಆದರೆ ((r = do_send_and_receive(client, server)))
			ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (do_debug)
		ಬರೆ("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->ಮುಗಿದ, 1);
	ASSERT_INT_EQ(client->kex->ಮುಗಿದ, 1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_kex_with_ಕೀಲಿ(ಅಕ್ಷರ *kex, ಅಕ್ಷರ *cipher, ಅಕ್ಷರ *mac,
    ರಚನೆ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಂಕ keytype, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	ರಚನೆ ssh *client = ಖಾಲಿ, *server = ಖಾಲಿ, *server2 = ಖಾಲಿ;
	ರಚನೆ sshkey *ಖಾಸಗಿ, *ಸಾರ್ವಜನಿಕ;
	ರಚನೆ sshbuf *state;
	ರಚನೆ kex_params kex_params;
	ಅಕ್ಷರ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *keyname = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ != ಖಾಲಿ) {
		ಖಾಸಗಿ = ಕೀಲಿ;
		keytype = ಕೀಲಿ->type;
	} ಇಲ್ಲದಿದ್ದರೆ {
		TEST_ಆರಂಭ("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, ಬಿಟ್ಟುಗಳು, &ಖಾಸಗಿ), 0);
		TEST_ಮುಗಿದ();
	}

	TEST_ಆರಂಭ("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_ಖಾಸಗಿ(ಖಾಸಗಿ, &ಸಾರ್ವಜನಿಕ), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ssh_init");
	ಸ್ಮರಣೆ_ನಕಲು(kex_params.proposal, myproposal, ಗಾತ್ರ(myproposal));
	ಆದರೆ (kex != ಖಾಲಿ)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	ಆದರೆ (cipher != ಖಾಲಿ) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	ಆದರೆ (mac != ಖಾಲಿ) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(ಖಾಸಗಿ));
	ASSERT_PTR_NE(keyname, ಖಾಲಿ);
	kex_params.proposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, ಖಾಲಿ);
	ASSERT_PTR_NE(server, ಖಾಲಿ);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_ಕೂಡಿಸು_hostkey(server, ಖಾಸಗಿ), 0);
	ASSERT_INT_EQ(ssh_ಕೂಡಿಸು_hostkey(client, ಸಾರ್ವಜನಿಕ), 0);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("kex");
	ಸತತ_kex(client, server);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rekeying client");
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	ಸತತ_kex(client, server);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rekeying server");
	ASSERT_INT_EQ(kex_send_kexinit(server), 0);
	ಸತತ_kex(client, server);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ssh_packet_get_state");
	state = sshbuf_new();
	ASSERT_PTR_NE(state, ಖಾಲಿ);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("ssh_packet_set_state");
	server2 = ಖಾಲಿ;
	ASSERT_INT_EQ(ssh_init(&server2, 1, ಖಾಲಿ), 0);
	ASSERT_PTR_NE(server2, ಖಾಲಿ);
	ASSERT_INT_EQ(ssh_ಕೂಡಿಸು_hostkey(server2, ಖಾಸಗಿ), 0);
	ASSERT_INT_EQ(ssh_packet_ಗಣ_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, ಖಾಲಿ);
	/* XXX we need to set the callbacks */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	server2->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	server2->kex->ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ = server->kex->ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ;
	server2->kex->ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ = server->kex->ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ;
	server2->kex->sign = server->kex->sign;
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	ಸತತ_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	ಸತತ_kex(client, server2);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("cleanup");
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
		sshkey_free(ಖಾಸಗಿ);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	ಬಿಡುಗಡೆ(keyname);
	TEST_ಮುಗಿದ();
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_kex(ಅಕ್ಷರ *kex)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ name[256];

	ಆದರೆ (test_is_benchmark()) {
		snprintf(name, ಗಾತ್ರ(name), "generate %s", kex);
		TEST_ಆರಂಭ(name);
		ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ED25519, 0, &ಕೀಲಿ), 0);
		TEST_ಮುಗಿದ();
		snprintf(name, ಗಾತ್ರ(name), "KEX %s", kex);
		BENCH_ಆರಂಭ(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_ಕೀಲಿ(kex, "aes128-ctr", "hmac-sha2-256", ಕೀಲಿ,
		    ಕೀಲಿ_ED25519, 256);
		BENCH_ಮುಕ್ತಾಯ("kex");
		sshkey_free(ಕೀಲಿ);
		ಹಿಂತಿರುಗಿ;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	do_kex_with_ಕೀಲಿ(kex, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಕೀಲಿ_RSA, 2048);
	do_kex_with_ಕೀಲಿ(kex, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಕೀಲಿ_ECDSA, 256);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	do_kex_with_ಕೀಲಿ(kex, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಕೀಲಿ_ED25519, 256);
}

ಶೂನ್ಯ
kex_tests(ಶೂನ್ಯ)
{
	do_kex("curve25519-sha256");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group1-sha1");
	ಆದರೆ (test_is_benchmark()) {
		do_kex("diffie-hellman-group14-sha256");
		do_kex("diffie-hellman-group16-sha512");
		do_kex("diffie-hellman-group18-sha512");
	}
# ifdef USE_MLKEM768X25519
	do_kex("mlkem768x25519-sha256");
# endif /* USE_MLKEM768X25519 */
# ifdef USE_SNTRUP761X25519
	do_kex("sntrup761x25519-sha512");
# endif /* USE_SNTRUP761X25519 */
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
}
