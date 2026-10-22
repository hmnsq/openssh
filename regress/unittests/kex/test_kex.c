/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/time.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "../test_helper/test_helper.h"

#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "ssh_api.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "myproposal.h"
#অন্তর্ভাৱ "log.h"

শূন্য kex_tests(শূন্য);
স্থির পূর্ণাঙ্ক do_debug = 0;

স্থির পূর্ণাঙ্ক
do_send_and_receive(সংরচনা ssh *from, সংরচনা ssh *to)
{
	u_char type;
	size_t len;
	ধ্রুৱ u_char *buf;
	পূর্ণাঙ্ক r;

	বাবে (;;) {
		যদি ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			ঘূৰাই r;
		}
		যদি (type != 0)
			ঘূৰাই 0;
		buf = ssh_output_ptr(from, &len);
		যদি (do_debug)
			printf("%zu", len);
		যদি (len == 0)
			ঘূৰাই 0;
		যদি ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_প্ৰবেশ_append(to, buf, len)) != 0)
			ঘূৰাই r;
	}
}

স্থির শূন্য
run_kex(সংরচনা ssh *client, সংরচনা ssh *server)
{
	পূর্ণাঙ্ক r = 0;

	যেতিয়ালৈ (!server->kex->done || !client->kex->done) {
		যদি (do_debug)
			printf(" S:");
		যদি ((r = do_send_and_receive(server, client)))
			ভঙ্গ;
		যদি (do_debug)
			printf(" C:");
		যদি ((r = do_send_and_receive(client, server)))
			ভঙ্গ;
	}
	যদি (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

স্থির শূন্য
do_kex_with_চাবি(ৱর্ণ *kex, ৱর্ণ *cipher, ৱর্ণ *mac,
    সংরচনা sshkey *চাবি, পূর্ণাঙ্ক keytype, পূর্ণাঙ্ক bits)
{
	সংরচনা ssh *client = রিক্ত, *server = রিক্ত, *server2 = রিক্ত;
	সংরচনা sshkey *গুপ্ত, *সার্ৱজনিক;
	সংরচনা sshbuf *state;
	সংরচনা kex_params kex_params;
	ৱর্ণ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ৱর্ণ *keyname = রিক্ত;

	যদি (চাবি != রিক্ত) {
		গুপ্ত = চাবি;
		keytype = চাবি->type;
	} অন্যথা {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &গুপ্ত), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(গুপ্ত, &সার্ৱজনিক), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, পরিমাণ(myproposal));
	যদি (kex != রিক্ত)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	যদি (cipher != রিক্ত) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	যদি (mac != রিক্ত) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(গুপ্ত));
	ASSERT_PTR_NE(keyname, রিক্ত);
	kex_params.proposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, রিক্ত);
	ASSERT_PTR_NE(server, রিক্ত);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, গুপ্ত), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, সার্ৱজনিক), 0);
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
	ASSERT_PTR_NE(state, রিক্ত);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = রিক্ত;
	ASSERT_INT_EQ(ssh_init(&server2, 1, রিক্ত), 0);
	ASSERT_PTR_NE(server2, রিক্ত);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, গুপ্ত), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, রিক্ত);
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
	server2->kex->load_host_public_চাবি = server->kex->load_host_public_চাবি;
	server2->kex->load_host_private_চাবি = server->kex->load_host_private_চাবি;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(সার্ৱজনিক);
	যদি (চাবি == রিক্ত)
		sshkey_free(গুপ্ত);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	মুক্ত(keyname);
	TEST_DONE();
}

স্থির শূন্য
do_kex(ৱর্ণ *kex)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	ৱর্ণ name[256];

	যদি (test_is_benchmark()) {
		snprintf(name, পরিমাণ(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(চাবি_ED25519, 0, &চাবি), 0);
		TEST_DONE();
		snprintf(name, পরিমাণ(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_চাবি(kex, "aes128-ctr", "hmac-sha2-256", চাবি,
		    চাবি_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(চাবি);
		ঘূৰাই;
	}

#ifdef WITH_OPENSSL
	do_kex_with_চাবি(kex, রিক্ত, রিক্ত, রিক্ত, চাবি_RSA, 2048);
	do_kex_with_চাবি(kex, রিক্ত, রিক্ত, রিক্ত, চাবি_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_চাবি(kex, রিক্ত, রিক্ত, রিক্ত, চাবি_ED25519, 256);
}

শূন্য
kex_tests(শূন্য)
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
	যদি (test_is_benchmark()) {
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
