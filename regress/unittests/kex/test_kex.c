/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/time.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "log.h"

શૂન્ય kex_tests(શૂન્ય);
સ્થિર પૂર્ણાંક do_debug = 0;

સ્થિર પૂર્ણાંક
do_send_and_receive(સંરચના ssh *from, સંરચના ssh *to)
{
	u_char type;
	size_t len;
	અચલ u_char *buf;
	પૂર્ણાંક r;

	માટે (;;) {
		જો ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			પાછા r;
		}
		જો (type != 0)
			પાછા 0;
		buf = ssh_output_ptr(from, &len);
		જો (do_debug)
			printf("%zu", len);
		જો (len == 0)
			પાછા 0;
		જો ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_આગત_append(to, buf, len)) != 0)
			પાછા r;
	}
}

સ્થિર શૂન્ય
run_kex(સંરચના ssh *client, સંરચના ssh *server)
{
	પૂર્ણાંક r = 0;

	જ્યારે (!server->kex->done || !client->kex->done) {
		જો (do_debug)
			printf(" S:");
		જો ((r = do_send_and_receive(server, client)))
			તોડો;
		જો (do_debug)
			printf(" C:");
		જો ((r = do_send_and_receive(client, server)))
			તોડો;
	}
	જો (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

સ્થિર શૂન્ય
do_kex_with_ચાવી(અક્ષર *kex, અક્ષર *cipher, અક્ષર *mac,
    સંરચના sshkey *ચાવી, પૂર્ણાંક keytype, પૂર્ણાંક bits)
{
	સંરચના ssh *client = ખાલી, *server = ખાલી, *server2 = ખાલી;
	સંરચના sshkey *ખાનગી, *જાહેર;
	સંરચના sshbuf *state;
	સંરચના kex_params kex_params;
	અક્ષર *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *keyname = ખાલી;

	જો (ચાવી != ખાલી) {
		ખાનગી = ચાવી;
		keytype = ચાવી->type;
	} નહીંતર {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &ખાનગી), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(ખાનગી, &જાહેર), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, કદ(myproposal));
	જો (kex != ખાલી)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	જો (cipher != ખાલી) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	જો (mac != ખાલી) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(ખાનગી));
	ASSERT_PTR_NE(keyname, ખાલી);
	kex_params.proposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, ખાલી);
	ASSERT_PTR_NE(server, ખાલી);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, ખાનગી), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, જાહેર), 0);
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
	ASSERT_PTR_NE(state, ખાલી);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = ખાલી;
	ASSERT_INT_EQ(ssh_init(&server2, 1, ખાલી), 0);
	ASSERT_PTR_NE(server2, ખાલી);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, ખાનગી), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, ખાલી);
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
	server2->kex->load_host_public_ચાવી = server->kex->load_host_public_ચાવી;
	server2->kex->load_host_private_ચાવી = server->kex->load_host_private_ચાવી;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(જાહેર);
	જો (ચાવી == ખાલી)
		sshkey_free(ખાનગી);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	મુક્ત(keyname);
	TEST_DONE();
}

સ્થિર શૂન્ય
do_kex(અક્ષર *kex)
{
	સંરચના sshkey *ચાવી = ખાલી;
	અક્ષર name[256];

	જો (test_is_benchmark()) {
		snprintf(name, કદ(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(ચાવી_ED25519, 0, &ચાવી), 0);
		TEST_DONE();
		snprintf(name, કદ(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_ચાવી(kex, "aes128-ctr", "hmac-sha2-256", ચાવી,
		    ચાવી_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(ચાવી);
		પાછા;
	}

#ifdef WITH_OPENSSL
	do_kex_with_ચાવી(kex, ખાલી, ખાલી, ખાલી, ચાવી_RSA, 2048);
	do_kex_with_ચાવી(kex, ખાલી, ખાલી, ખાલી, ચાવી_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_ચાવી(kex, ખાલી, ખાલી, ખાલી, ચાવી_ED25519, 256);
}

શૂન્ય
kex_tests(શૂન્ય)
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
	જો (test_is_benchmark()) {
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
