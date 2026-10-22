/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/time.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "ssh_api.h"
#شامل "sshbuf.h"
#شامل "packet.h"
#شامل "myproposal.h"
#شامل "log.h"

تهی kex_tests(تهی);
ایستا صحیح do_debug = 0;

ایستا صحیح
do_send_and_receive(ساختار ssh *from, ساختار ssh *to)
{
	u_char type;
	size_t len;
	ثابت u_char *buf;
	صحیح r;

	برای (;;) {
		اگر ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			بازگشت r;
		}
		اگر (type != 0)
			بازگشت 0;
		buf = ssh_output_ptr(from, &len);
		اگر (do_debug)
			printf("%zu", len);
		اگر (len == 0)
			بازگشت 0;
		اگر ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_درون_داد_append(to, buf, len)) != 0)
			بازگشت r;
	}
}

ایستا تهی
run_kex(ساختار ssh *client, ساختار ssh *server)
{
	صحیح r = 0;

	وقتی (!server->kex->done || !client->kex->done) {
		اگر (do_debug)
			printf(" S:");
		اگر ((r = do_send_and_receive(server, client)))
			بشکن;
		اگر (do_debug)
			printf(" C:");
		اگر ((r = do_send_and_receive(client, server)))
			بشکن;
	}
	اگر (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

ایستا تهی
do_kex_with_کلید(نویسه *kex, نویسه *cipher, نویسه *mac,
    ساختار sshkey *کلید, صحیح keytype, صحیح bits)
{
	ساختار ssh *client = پوچ, *server = پوچ, *server2 = پوچ;
	ساختار sshkey *خصوصی, *عمومی;
	ساختار sshbuf *state;
	ساختار kex_params kex_params;
	نویسه *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	نویسه *keyname = پوچ;

	اگر (کلید != پوچ) {
		خصوصی = کلید;
		keytype = کلید->type;
	} وگرنه {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &خصوصی), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(خصوصی, &عمومی), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, اندازه(myproposal));
	اگر (kex != پوچ)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	اگر (cipher != پوچ) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	اگر (mac != پوچ) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(خصوصی));
	ASSERT_PTR_NE(keyname, پوچ);
	kex_params.proposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, پوچ);
	ASSERT_PTR_NE(server, پوچ);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, خصوصی), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, عمومی), 0);
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
	ASSERT_PTR_NE(state, پوچ);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = پوچ;
	ASSERT_INT_EQ(ssh_init(&server2, 1, پوچ), 0);
	ASSERT_PTR_NE(server2, پوچ);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, خصوصی), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, پوچ);
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
	server2->kex->load_host_public_کلید = server->kex->load_host_public_کلید;
	server2->kex->load_host_private_کلید = server->kex->load_host_private_کلید;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(عمومی);
	اگر (کلید == پوچ)
		sshkey_free(خصوصی);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	آزاد(keyname);
	TEST_DONE();
}

ایستا تهی
do_kex(نویسه *kex)
{
	ساختار sshkey *کلید = پوچ;
	نویسه name[256];

	اگر (test_is_benchmark()) {
		snprintf(name, اندازه(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 0, &کلید), 0);
		TEST_DONE();
		snprintf(name, اندازه(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_کلید(kex, "aes128-ctr", "hmac-sha2-256", کلید,
		    کلید_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(کلید);
		بازگشت;
	}

#ifdef WITH_OPENSSL
	do_kex_with_کلید(kex, پوچ, پوچ, پوچ, کلید_RSA, 2048);
	do_kex_with_کلید(kex, پوچ, پوچ, پوچ, کلید_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_کلید(kex, پوچ, پوچ, پوچ, کلید_ED25519, 256);
}

تهی
kex_tests(تهی)
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
	اگر (test_is_benchmark()) {
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
