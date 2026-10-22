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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ do_debug = 0;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
do_send_and_receive(ಸಂರಚನಾ ssh *from, ಸಂರಚನಾ ssh *to)
{
	u_char type;
	size_t len;
	ಧ್ರುವ u_char *buf;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಪ್ರತಿ (;;) {
		ಯದಿ ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			ಪ್ರತ್ಯಾಗಮ r;
		}
		ಯದಿ (type != 0)
			ಪ್ರತ್ಯಾಗಮ 0;
		buf = ssh_output_ptr(from, &len);
		ಯದಿ (do_debug)
			printf("%zu", len);
		ಯದಿ (len == 0)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_ಒಳಹರಿವು_append(to, buf, len)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
run_kex(ಸಂರಚನಾ ssh *client, ಸಂರಚನಾ ssh *server)
{
	ಪೂರ್ಣಾಙ್ಕ r = 0;

	ಯಾವತ್ (!server->kex->done || !client->kex->done) {
		ಯದಿ (do_debug)
			printf(" S:");
		ಯದಿ ((r = do_send_and_receive(server, client)))
			ಭಙ್ಗ;
		ಯದಿ (do_debug)
			printf(" C:");
		ಯದಿ ((r = do_send_and_receive(client, server)))
			ಭಙ್ಗ;
	}
	ಯದಿ (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_kex_with_ಕೀಲಿ(ವರ್ಣ *kex, ವರ್ಣ *cipher, ವರ್ಣ *mac,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಪೂರ್ಣಾಙ್ಕ keytype, ಪೂರ್ಣಾಙ್ಕ bits)
{
	ಸಂರಚನಾ ssh *client = ರಿಕ್ತ, *server = ರಿಕ್ತ, *server2 = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ, *ಸಾರ್ವಜನಿಕ;
	ಸಂರಚನಾ sshbuf *state;
	ಸಂರಚನಾ kex_params kex_params;
	ವರ್ಣ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *keyname = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ != ರಿಕ್ತ) {
		ಗುಪ್ತ = ಕೀಲಿ;
		keytype = ಕೀಲಿ->type;
	} ಅನ್ಯಥಾ {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &ಗುಪ್ತ), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(ಗುಪ್ತ, &ಸಾರ್ವಜನಿಕ), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, ಪರಿಮಾಣ(myproposal));
	ಯದಿ (kex != ರಿಕ್ತ)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	ಯದಿ (cipher != ರಿಕ್ತ) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	ಯದಿ (mac != ರಿಕ್ತ) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(ಗುಪ್ತ));
	ASSERT_PTR_NE(keyname, ರಿಕ್ತ);
	kex_params.proposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, ರಿಕ್ತ);
	ASSERT_PTR_NE(server, ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, ಗುಪ್ತ), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, ಸಾರ್ವಜನಿಕ), 0);
	TEST_DONE();

	TEST_START("kex");
	run_kex(client, server);
	TEST_DONE();

	TEST_START("rekeying client");
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server);
	TEST_DONE();

	TEST_START("rekeying server");
	ASSERT_INT_EQ(kex_send_kexinit(server), 0);
	run_kex(client, server);
	TEST_DONE();

	TEST_START("ssh_packet_get_state");
	state = sshbuf_new();
	ASSERT_PTR_NE(state, ರಿಕ್ತ);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = ರಿಕ್ತ;
	ASSERT_INT_EQ(ssh_init(&server2, 1, ರಿಕ್ತ), 0);
	ASSERT_PTR_NE(server2, ರಿಕ್ತ);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, ಗುಪ್ತ), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, ರಿಕ್ತ);
	/* XXX we need to set the callbacks */
#ifdef WITH_OPENSSL
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#endif /* WITH_OPENSSL */
	server2->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	server2->kex->load_host_public_ಕೀಲಿ = server->kex->load_host_public_ಕೀಲಿ;
	server2->kex->load_host_private_ಕೀಲಿ = server->kex->load_host_private_ಕೀಲಿ;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(ಸಾರ್ವಜನಿಕ);
	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ)
		sshkey_free(ಗುಪ್ತ);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	ಮುಕ್ತ(keyname);
	TEST_DONE();
}

ಸ್ಥಿರ ಶೂನ್ಯ
do_kex(ವರ್ಣ *kex)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ name[256];

	ಯದಿ (test_is_benchmark()) {
		snprintf(name, ಪರಿಮಾಣ(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(ಕೀಲಿ_ED25519, 0, &ಕೀಲಿ), 0);
		TEST_DONE();
		snprintf(name, ಪರಿಮಾಣ(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_ಕೀಲಿ(kex, "aes128-ctr", "hmac-sha2-256", ಕೀಲಿ,
		    ಕೀಲಿ_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(ಕೀಲಿ);
		ಪ್ರತ್ಯಾಗಮ;
	}

#ifdef WITH_OPENSSL
	do_kex_with_ಕೀಲಿ(kex, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ಕೀಲಿ_RSA, 2048);
	do_kex_with_ಕೀಲಿ(kex, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ಕೀಲಿ_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_ಕೀಲಿ(kex, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ಕೀಲಿ_ED25519, 256);
}

ಶೂನ್ಯ
kex_tests(ಶೂನ್ಯ)
{
	do_kex("curve25519-sha256");
#ifdef WITH_OPENSSL
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group1-sha1");
	ಯದಿ (test_is_benchmark()) {
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
#endif /* WITH_OPENSSL */
}
