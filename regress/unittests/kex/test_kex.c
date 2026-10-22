/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/time.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "log.h"

ശൂന്യം kex_tests(ശൂന്യം);
സ്ഥിതം പൂർണ്ണസംഖ്യ do_debug = 0;

സ്ഥിതം പൂർണ്ണസംഖ്യ
do_send_and_receive(ഘടന ssh *from, ഘടന ssh *to)
{
	u_char type;
	size_t len;
	സ്ഥിരം u_char *buf;
	പൂർണ്ണസംഖ്യ r;

	വേണ്ടി (;;) {
		എങ്കിൽ ((r = ssh_packet_next(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			തിരികെ r;
		}
		എങ്കിൽ (type != 0)
			തിരികെ 0;
		buf = ssh_output_ptr(from, &len);
		എങ്കിൽ (do_debug)
			printf("%zu", len);
		എങ്കിൽ (len == 0)
			തിരികെ 0;
		എങ്കിൽ ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_നിവേശം_append(to, buf, len)) != 0)
			തിരികെ r;
	}
}

സ്ഥിതം ശൂന്യം
run_kex(ഘടന ssh *client, ഘടന ssh *server)
{
	പൂർണ്ണസംഖ്യ r = 0;

	ആകുമ്പോൾ (!server->kex->done || !client->kex->done) {
		എങ്കിൽ (do_debug)
			printf(" S:");
		എങ്കിൽ ((r = do_send_and_receive(server, client)))
			നിർത്തുക;
		എങ്കിൽ (do_debug)
			printf(" C:");
		എങ്കിൽ ((r = do_send_and_receive(client, server)))
			നിർത്തുക;
	}
	എങ്കിൽ (do_debug)
		printf("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

സ്ഥിതം ശൂന്യം
do_kex_with_താക്കോൽ(അക്ഷരം *kex, അക്ഷരം *cipher, അക്ഷരം *mac,
    ഘടന sshkey *താക്കോൽ, പൂർണ്ണസംഖ്യ keytype, പൂർണ്ണസംഖ്യ bits)
{
	ഘടന ssh *client = ശൂന്യ, *server = ശൂന്യ, *server2 = ശൂന്യ;
	ഘടന sshkey *സ്വകാര്യ, *പൊതു;
	ഘടന sshbuf *state;
	ഘടന kex_params kex_params;
	അക്ഷരം *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *keyname = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ != ശൂന്യ) {
		സ്വകാര്യ = താക്കോൽ;
		keytype = താക്കോൽ->type;
	} അല്ലെങ്കിൽ {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &സ്വകാര്യ), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(സ്വകാര്യ, &പൊതു), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	memcpy(kex_params.proposal, myproposal, വലുപ്പം(myproposal));
	എങ്കിൽ (kex != ശൂന്യ)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	എങ്കിൽ (cipher != ശൂന്യ) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	എങ്കിൽ (mac != ശൂന്യ) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(സ്വകാര്യ));
	ASSERT_PTR_NE(keyname, ശൂന്യ);
	kex_params.proposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, ശൂന്യ);
	ASSERT_PTR_NE(server, ശൂന്യ);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, സ്വകാര്യ), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, പൊതു), 0);
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
	ASSERT_PTR_NE(state, ശൂന്യ);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = ശൂന്യ;
	ASSERT_INT_EQ(ssh_init(&server2, 1, ശൂന്യ), 0);
	ASSERT_PTR_NE(server2, ശൂന്യ);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, സ്വകാര്യ), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, ശൂന്യ);
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
	server2->kex->load_host_public_താക്കോൽ = server->kex->load_host_public_താക്കോൽ;
	server2->kex->load_host_private_താക്കോൽ = server->kex->load_host_private_താക്കോൽ;
	server2->kex->sign = server->kex->sign;
	TEST_DONE();

	TEST_START("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	run_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	run_kex(client, server2);
	TEST_DONE();

	TEST_START("cleanup");
	sshkey_free(പൊതു);
	എങ്കിൽ (താക്കോൽ == ശൂന്യ)
		sshkey_free(സ്വകാര്യ);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	സ്വതന്ത്രം(keyname);
	TEST_DONE();
}

സ്ഥിതം ശൂന്യം
do_kex(അക്ഷരം *kex)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	അക്ഷരം name[256];

	എങ്കിൽ (test_is_benchmark()) {
		snprintf(name, വലുപ്പം(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(താക്കോൽ_ED25519, 0, &താക്കോൽ), 0);
		TEST_DONE();
		snprintf(name, വലുപ്പം(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_താക്കോൽ(kex, "aes128-ctr", "hmac-sha2-256", താക്കോൽ,
		    താക്കോൽ_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(താക്കോൽ);
		തിരികെ;
	}

#ifdef WITH_OPENSSL
	do_kex_with_താക്കോൽ(kex, ശൂന്യ, ശൂന്യ, ശൂന്യ, താക്കോൽ_RSA, 2048);
	do_kex_with_താക്കോൽ(kex, ശൂന്യ, ശൂന്യ, ശൂന്യ, താക്കോൽ_ECDSA, 256);
#endif /* WITH_OPENSSL */
	do_kex_with_താക്കോൽ(kex, ശൂന്യ, ശൂന്യ, ശൂന്യ, താക്കോൽ_ED25519, 256);
}

ശൂന്യം
kex_tests(ശൂന്യം)
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
	എങ്കിൽ (test_is_benchmark()) {
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
