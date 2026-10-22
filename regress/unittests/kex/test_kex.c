/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "log.h"

शून्य kex_tests(शून्य);
स्थिर पूर्णाङ्क do_debug = 0;

स्थिर पूर्णाङ्क
do_send_and_receive(संरचना ssh *from, संरचना ssh *to)
{
	u_char type;
	size_t len;
	ध्रुव u_char *buf;
	पूर्णाङ्क r;

	प्रति (;;) {
		यदि ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			प्रत्यागम r;
		}
		यदि (type != 0)
			प्रत्यागम 0;
		buf = ssh_output_ptr(from, &len);
		यदि (do_debug)
			printf("%zu", len);
		यदि (len == 0)
			प्रत्यागम 0;
		यदि ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_निवेश_append(to, buf, len)) != 0)
			प्रत्यागम r;
	}
}

स्थिर शून्य
run_kex(संरचना ssh *client, संरचना ssh *server)
{
	पूर्णाङ्क r = 0;

	यावत् (!server->kex->done || !client->kex->done) {
		यदि (do_debug)
			printf(" S:");
		यदि ((r = do_send_and_receive(server, client)))
			भङ्ग;
		यदि (do_debug)
			printf(" C:");
		यदि ((r = do_send_and_receive(client, server)))
			भङ्ग;
	}
	यदि (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

स्थिर शून्य
do_kex_with_कुंजी(वर्ण *kex, वर्ण *cipher, वर्ण *mac,
    संरचना sshkey *कुंजी, पूर्णाङ्क keytype, पूर्णाङ्क bits)
{
	संरचना ssh *client = रिक्त, *server = रिक्त, *server2 = रिक्त;
	संरचना sshkey *गुप्त, *सार्वजनिक;
	संरचना sshbuf *state;
	संरचना kex_params kex_params;
	वर्ण *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	वर्ण *keyname = रिक्त;

	यदि (कुंजी != रिक्त) {
		गुप्त = कुंजी;
		keytype = कुंजी->type;
	} अन्यथा {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &गुप्त), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(गुप्त, &सार्वजनिक), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, परिमाण(myproposal));
	यदि (kex != रिक्त)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	यदि (cipher != रिक्त) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	यदि (mac != रिक्त) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(गुप्त));
	ASSERT_PTR_NE(keyname, रिक्त);
	kex_params.proposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, रिक्त);
	ASSERT_PTR_NE(server, रिक्त);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, गुप्त), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, सार्वजनिक), 0);
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
	ASSERT_PTR_NE(state, रिक्त);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = रिक्त;
	ASSERT_INT_EQ(ssh_init(&server2, 1, रिक्त), 0);
	ASSERT_PTR_NE(server2, रिक्त);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, गुप्त), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, रिक्त);
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
	server2->kex->load_host_public_कुंजी = server->kex->load_host_public_कुंजी;
	server2->kex->load_host_private_कुंजी = server->kex->load_host_private_कुंजी;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(सार्वजनिक);
	यदि (कुंजी == रिक्त)
		sshkey_free(गुप्त);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	मुक्त(keyname);
	TEST_DONE();
}

स्थिर शून्य
do_kex(वर्ण *kex)
{
	संरचना sshkey *कुंजी = रिक्त;
	वर्ण name[256];

	यदि (test_is_benchmark()) {
		snprintf(name, परिमाण(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(कुंजी_ED25519, 0, &कुंजी), 0);
		TEST_DONE();
		snprintf(name, परिमाण(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_कुंजी(kex, "aes128-ctr", "hmac-sha2-256", कुंजी,
		    कुंजी_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(कुंजी);
		प्रत्यागम;
	}

#ifdef WITH_OPENSSL
	do_kex_with_कुंजी(kex, रिक्त, रिक्त, रिक्त, कुंजी_RSA, 2048);
	do_kex_with_कुंजी(kex, रिक्त, रिक्त, रिक्त, कुंजी_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_कुंजी(kex, रिक्त, रिक्त, रिक्त, कुंजी_ED25519, 256);
}

शून्य
kex_tests(शून्य)
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
	यदि (test_is_benchmark()) {
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
