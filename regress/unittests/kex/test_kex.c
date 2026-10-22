/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "log.h"

శూన్య kex_tests(శూన్య);
స్థిర పూర్ణాంకం do_debug = 0;

స్థిర పూర్ణాంకం
do_send_and_receive(నిర్మాణం ssh *from, నిర్మాణం ssh *గమ్యం)
{
	u_char type;
	కొలత_t len;
	స్థిరరాశి u_char *buf;
	పూర్ణాంకం r;

	కొరకు (;;) {
		ఒకవేళ ((r = ssh_packet_తదుపరి(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			తిరిగి r;
		}
		ఒకవేళ (type != 0)
			తిరిగి 0;
		buf = ssh_output_ptr(from, &len);
		ఒకవేళ (do_debug)
			రాయి("%zu", len);
		ఒకవేళ (len == 0)
			తిరిగి 0;
		ఒకవేళ ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_ఆదానం_append(గమ్యం, buf, len)) != 0)
			తిరిగి r;
	}
}

స్థిర శూన్య
నిరంతరం_kex(నిర్మాణం ssh *client, నిర్మాణం ssh *server)
{
	పూర్ణాంకం r = 0;

	అయితే (!server->kex->పూర్తి || !client->kex->పూర్తి) {
		ఒకవేళ (do_debug)
			రాయి(" S:");
		ఒకవేళ ((r = do_send_and_receive(server, client)))
			ఆపు;
		ఒకవేళ (do_debug)
			రాయి(" C:");
		ఒకవేళ ((r = do_send_and_receive(client, server)))
			ఆపు;
	}
	ఒకవేళ (do_debug)
		రాయి("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->పూర్తి, 1);
	ASSERT_INT_EQ(client->kex->పూర్తి, 1);
}

స్థిర శూన్య
do_kex_with_కీలకం(అక్షరం *kex, అక్షరం *cipher, అక్షరం *mac,
    నిర్మాణం sshkey *కీలకం, పూర్ణాంకం keytype, పూర్ణాంకం బిట్లు)
{
	నిర్మాణం ssh *client = ఖాళీ, *server = ఖాళీ, *server2 = ఖాళీ;
	నిర్మాణం sshkey *అంతరంగ, *బహిరంగ;
	నిర్మాణం sshbuf *state;
	నిర్మాణం kex_params kex_params;
	అక్షరం *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	అక్షరం *keyname = ఖాళీ;

	ఒకవేళ (కీలకం != ఖాళీ) {
		అంతరంగ = కీలకం;
		keytype = కీలకం->type;
	} లేకపోతే {
		TEST_ప్రారంభం("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, బిట్లు, &అంతరంగ), 0);
		TEST_పూర్తి();
	}

	TEST_ప్రారంభం("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_వ్యక్తిగత(అంతరంగ, &బహిరంగ), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ssh_init");
	జ్ఞాపకం_నకలు(kex_params.proposal, myproposal, పరిమాణం(myproposal));
	ఒకవేళ (kex != ఖాళీ)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	ఒకవేళ (cipher != ఖాళీ) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	ఒకవేళ (mac != ఖాళీ) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(అంతరంగ));
	ASSERT_PTR_NE(keyname, ఖాళీ);
	kex_params.proposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, ఖాళీ);
	ASSERT_PTR_NE(server, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_కూడు_hostkey(server, అంతరంగ), 0);
	ASSERT_INT_EQ(ssh_కూడు_hostkey(client, బహిరంగ), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("kex");
	నిరంతరం_kex(client, server);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rekeying client");
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	నిరంతరం_kex(client, server);
	TEST_పూర్తి();

	TEST_ప్రారంభం("rekeying server");
	ASSERT_INT_EQ(kex_send_kexinit(server), 0);
	నిరంతరం_kex(client, server);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ssh_packet_get_state");
	state = sshbuf_new();
	ASSERT_PTR_NE(state, ఖాళీ);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("ssh_packet_set_state");
	server2 = ఖాళీ;
	ASSERT_INT_EQ(ssh_init(&server2, 1, ఖాళీ), 0);
	ASSERT_PTR_NE(server2, ఖాళీ);
	ASSERT_INT_EQ(ssh_కూడు_hostkey(server2, అంతరంగ), 0);
	ASSERT_INT_EQ(ssh_packet_సమితి_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, ఖాళీ);
	/* XXX we need to set the callbacks */
#నిర్వచితమైతే WITH_OPENSSL
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#అయితే_ముగింపు /* WITH_OPENSSL */
	server2->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	server2->kex->ఎక్కించు_host_ప్రజా_కీలకం = server->kex->ఎక్కించు_host_ప్రజా_కీలకం;
	server2->kex->ఎక్కించు_host_వ్యక్తిగత_కీలకం = server->kex->ఎక్కించు_host_వ్యక్తిగత_కీలకం;
	server2->kex->sign = server->kex->sign;
	TEST_పూర్తి();

	TEST_ప్రారంభం("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	నిరంతరం_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	నిరంతరం_kex(client, server2);
	TEST_పూర్తి();

	TEST_ప్రారంభం("cleanup");
	sshkey_free(బహిరంగ);
	ఒకవేళ (కీలకం == ఖాళీ)
		sshkey_free(అంతరంగ);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	విడుదల(keyname);
	TEST_పూర్తి();
}

స్థిర శూన్య
do_kex(అక్షరం *kex)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	అక్షరం name[256];

	ఒకవేళ (test_is_benchmark()) {
		snprintf(name, పరిమాణం(name), "generate %s", kex);
		TEST_ప్రారంభం(name);
		ASSERT_INT_EQ(sshkey_generate(కీలకం_ED25519, 0, &కీలకం), 0);
		TEST_పూర్తి();
		snprintf(name, పరిమాణం(name), "KEX %s", kex);
		BENCH_ప్రారంభం(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_కీలకం(kex, "aes128-ctr", "hmac-sha2-256", కీలకం,
		    కీలకం_ED25519, 256);
		BENCH_ముగింపు("kex");
		sshkey_free(కీలకం);
		తిరిగి;
	}

#నిర్వచితమైతే WITH_OPENSSL
	do_kex_with_కీలకం(kex, ఖాళీ, ఖాళీ, ఖాళీ, కీలకం_RSA, 2048);
	do_kex_with_కీలకం(kex, ఖాళీ, ఖాళీ, ఖాళీ, కీలకం_ECDSA, 256);
#అయితే_ముగింపు /* WITH_OPENSSL */
	do_kex_with_కీలకం(kex, ఖాళీ, ఖాళీ, ఖాళీ, కీలకం_ED25519, 256);
}

శూన్య
kex_tests(శూన్య)
{
	do_kex("curve25519-sha256");
#నిర్వచితమైతే WITH_OPENSSL
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group1-sha1");
	ఒకవేళ (test_is_benchmark()) {
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
#అయితే_ముగింపు /* WITH_OPENSSL */
}
