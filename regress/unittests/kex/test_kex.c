/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/time.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "ssherr.h"
#ضمن "ssh_api.h"
#ضمن "sshbuf.h"
#ضمن "packet.h"
#ضمن "myproposal.h"
#ضمن "log.h"

فراغ kex_tests(فراغ);
ساكن صحيح do_debug = 0;

ساكن صحيح
do_send_and_receive(بنية ssh *from, بنية ssh *to)
{
	u_char type;
	size_t len;
	ثابت u_char *buf;
	صحيح r;

	لكل (;;) {
		𐤀𐤌 ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			أرجع r;
		}
		𐤀𐤌 (type != 0)
			أرجع 0;
		buf = ssh_output_ptr(from, &len);
		𐤀𐤌 (do_debug)
			printf("%zu", len);
		𐤀𐤌 (len == 0)
			أرجع 0;
		𐤀𐤌 ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_input_append(to, buf, len)) != 0)
			أرجع r;
	}
}

ساكن فراغ
run_kex(بنية ssh *client, بنية ssh *server)
{
	صحيح r = 0;

	طالما (!server->kex->done || !client->kex->done) {
		𐤀𐤌 (do_debug)
			printf(" S:");
		𐤀𐤌 ((r = do_send_and_receive(server, client)))
			اكسر;
		𐤀𐤌 (do_debug)
			printf(" C:");
		𐤀𐤌 ((r = do_send_and_receive(client, server)))
			اكسر;
	}
	𐤀𐤌 (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

ساكن فراغ
do_kex_with_key(حرف *kex, حرف *cipher, حرف *mac,
    بنية sshkey *key, صحيح keytype, صحيح bits)
{
	بنية ssh *client = عدم, *server = عدم, *server2 = عدم;
	بنية sshkey *خاص, *عام;
	بنية sshbuf *state;
	بنية kex_params kex_params;
	حرف *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *keyname = عدم;

	𐤀𐤌 (key != عدم) {
		خاص = key;
		keytype = key->type;
	} وإلا {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &خاص), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(خاص, &عام), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, حجم(myproposal));
	𐤀𐤌 (kex != عدم)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	𐤀𐤌 (cipher != عدم) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	𐤀𐤌 (mac != عدم) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(خاص));
	ASSERT_PTR_NE(keyname, عدم);
	kex_params.proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, عدم);
	ASSERT_PTR_NE(server, عدم);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, خاص), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, عام), 0);
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
	ASSERT_PTR_NE(state, عدم);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = عدم;
	ASSERT_INT_EQ(ssh_init(&server2, 1, عدم), 0);
	ASSERT_PTR_NE(server2, عدم);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, خاص), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, عدم);
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
	server2->kex->load_host_public_key = server->kex->load_host_public_key;
	server2->kex->load_host_private_key = server->kex->load_host_private_key;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(عام);
	𐤀𐤌 (key == عدم)
		sshkey_free(خاص);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	حرر(keyname);
	TEST_DONE();
}

ساكن فراغ
do_kex(حرف *kex)
{
	بنية sshkey *key = عدم;
	حرف name[256];

	𐤀𐤌 (test_is_benchmark()) {
		snprintf(name, حجم(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(KEY_ED25519, 0, &key), 0);
		TEST_DONE();
		snprintf(name, حجم(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_key(kex, "aes128-ctr", "hmac-sha2-256", key,
		    KEY_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(key);
		أرجع;
	}

#ifdef WITH_OPENSSL
	do_kex_with_key(kex, عدم, عدم, عدم, KEY_RSA, 2048);
	do_kex_with_key(kex, عدم, عدم, عدم, KEY_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_key(kex, عدم, عدم, عدم, KEY_ED25519, 256);
}

فراغ
kex_tests(فراغ)
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
	𐤀𐤌 (test_is_benchmark()) {
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
