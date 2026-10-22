/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

ଶୂନ୍ୟ kex_tests(ଶୂନ୍ୟ);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା do_debug = 0;

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
do_send_and_receive(ସଂରଚନା ssh *from, ସଂରଚନା ssh *to)
{
	u_char type;
	size_t len;
	ଅଚଳ u_char *buf;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ପାଇଁ (;;) {
		ଯଦି ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			ଫେରନ୍ତୁ r;
		}
		ଯଦି (type != 0)
			ଫେରନ୍ତୁ 0;
		buf = ssh_output_ptr(from, &len);
		ଯଦି (do_debug)
			printf("%zu", len);
		ଯଦି (len == 0)
			ଫେରନ୍ତୁ 0;
		ଯଦି ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_ନିବେଶ_append(to, buf, len)) != 0)
			ଫେରନ୍ତୁ r;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
run_kex(ସଂରଚନା ssh *client, ସଂରଚନା ssh *server)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = 0;

	ଯେତେବେଳେ (!server->kex->done || !client->kex->done) {
		ଯଦି (do_debug)
			printf(" S:");
		ଯଦି ((r = do_send_and_receive(server, client)))
			ଭାଙ୍ଗ;
		ଯଦି (do_debug)
			printf(" C:");
		ଯଦି ((r = do_send_and_receive(client, server)))
			ଭାଙ୍ଗ;
	}
	ଯଦି (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

ସ୍ଥିର ଶୂନ୍ୟ
do_kex_with_ଚାବି(ଅକ୍ଷର *kex, ଅକ୍ଷର *cipher, ଅକ୍ଷର *mac,
    ସଂରଚନା sshkey *ଚାବି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା keytype, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	ସଂରଚନା ssh *client = ଖାଲି, *server = ଖାଲି, *server2 = ଖାଲି;
	ସଂରଚନା sshkey *ବ୍ୟକ୍ତିଗତ, *ସର୍ବସାଧାରଣ;
	ସଂରଚନା sshbuf *state;
	ସଂରଚନା kex_params kex_params;
	ଅକ୍ଷର *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ଅକ୍ଷର *keyname = ଖାଲି;

	ଯଦି (ଚାବି != ଖାଲି) {
		ବ୍ୟକ୍ତିଗତ = ଚାବି;
		keytype = ଚାବି->type;
	} ଅନ୍ୟଥା {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &ବ୍ୟକ୍ତିଗତ), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(ବ୍ୟକ୍ତିଗତ, &ସର୍ବସାଧାରଣ), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, ଆକାର(myproposal));
	ଯଦି (kex != ଖାଲି)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	ଯଦି (cipher != ଖାଲି) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	ଯଦି (mac != ଖାଲି) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(ବ୍ୟକ୍ତିଗତ));
	ASSERT_PTR_NE(keyname, ଖାଲି);
	kex_params.proposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, ଖାଲି);
	ASSERT_PTR_NE(server, ଖାଲି);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, ବ୍ୟକ୍ତିଗତ), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, ସର୍ବସାଧାରଣ), 0);
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
	ASSERT_PTR_NE(state, ଖାଲି);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = ଖାଲି;
	ASSERT_INT_EQ(ssh_init(&server2, 1, ଖାଲି), 0);
	ASSERT_PTR_NE(server2, ଖାଲି);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, ବ୍ୟକ୍ତିଗତ), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, ଖାଲି);
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
	server2->kex->load_host_public_ଚାବି = server->kex->load_host_public_ଚାବି;
	server2->kex->load_host_private_ଚାବି = server->kex->load_host_private_ଚାବି;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(ସର୍ବସାଧାରଣ);
	ଯଦି (ଚାବି == ଖାଲି)
		sshkey_free(ବ୍ୟକ୍ତିଗତ);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	ମୁକ୍ତ(keyname);
	TEST_DONE();
}

ସ୍ଥିର ଶୂନ୍ୟ
do_kex(ଅକ୍ଷର *kex)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ଅକ୍ଷର name[256];

	ଯଦି (test_is_benchmark()) {
		snprintf(name, ଆକାର(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(ଚାବି_ED25519, 0, &ଚାବି), 0);
		TEST_DONE();
		snprintf(name, ଆକାର(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_ଚାବି(kex, "aes128-ctr", "hmac-sha2-256", ଚାବି,
		    ଚାବି_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(ଚାବି);
		ଫେରନ୍ତୁ;
	}

#ifdef WITH_OPENSSL
	do_kex_with_ଚାବି(kex, ଖାଲି, ଖାଲି, ଖାଲି, ଚାବି_RSA, 2048);
	do_kex_with_ଚାବି(kex, ଖାଲି, ଖାଲି, ଖାଲି, ଚାବି_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_ଚାବି(kex, ଖାଲି, ଖାଲି, ଖାଲି, ଚାବି_ED25519, 256);
}

ଶୂନ୍ୟ
kex_tests(ଶୂନ୍ୟ)
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
	ଯଦି (test_is_benchmark()) {
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
