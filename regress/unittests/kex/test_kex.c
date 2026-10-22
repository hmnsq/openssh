/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਖਾਲੀ kex_tests(ਖਾਲੀ);
ਸਥਿਰ ਪੂਰਨ do_debug = 0;

ਸਥਿਰ ਪੂਰਨ
do_send_and_receive(ਬਣਤਰ ssh *from, ਬਣਤਰ ssh *ਮੰਜ਼ਿਲ)
{
	u_char type;
	ਮਾਪ_t len;
	ਅਚਲ u_char *buf;
	ਪੂਰਨ r;

	ਲਈ (;;) {
		ਜੇ ((r = ssh_packet_ਅਗਲਾ(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			ਵਾਪਸ r;
		}
		ਜੇ (type != 0)
			ਵਾਪਸ 0;
		buf = ssh_output_ptr(from, &len);
		ਜੇ (do_debug)
			ਲਿਖੋ("%zu", len);
		ਜੇ (len == 0)
			ਵਾਪਸ 0;
		ਜੇ ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_ਨਿਵੇਸ਼_append(ਮੰਜ਼ਿਲ, buf, len)) != 0)
			ਵਾਪਸ r;
	}
}

ਸਥਿਰ ਖਾਲੀ
ਲੜੀਵਾਰ_kex(ਬਣਤਰ ssh *client, ਬਣਤਰ ssh *server)
{
	ਪੂਰਨ r = 0;

	ਜਦੋਂ (!server->kex->ਪੂਰਾ || !client->kex->ਪੂਰਾ) {
		ਜੇ (do_debug)
			ਲਿਖੋ(" S:");
		ਜੇ ((r = do_send_and_receive(server, client)))
			ਰੋਕੋ;
		ਜੇ (do_debug)
			ਲਿਖੋ(" C:");
		ਜੇ ((r = do_send_and_receive(client, server)))
			ਰੋਕੋ;
	}
	ਜੇ (do_debug)
		ਲਿਖੋ("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->ਪੂਰਾ, 1);
	ASSERT_INT_EQ(client->kex->ਪੂਰਾ, 1);
}

ਸਥਿਰ ਖਾਲੀ
do_kex_with_ਕੁੰਜੀ(ਅੱਖਰ *kex, ਅੱਖਰ *cipher, ਅੱਖਰ *mac,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਪੂਰਨ keytype, ਪੂਰਨ ਬਿੱਟ)
{
	ਬਣਤਰ ssh *client = ਨਿਰਾ, *server = ਨਿਰਾ, *server2 = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਨਿਜੀ, *ਜਨਤਕ;
	ਬਣਤਰ sshbuf *state;
	ਬਣਤਰ kex_params kex_params;
	ਅੱਖਰ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅੱਖਰ *keyname = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ != ਨਿਰਾ) {
		ਨਿਜੀ = ਕੁੰਜੀ;
		keytype = ਕੁੰਜੀ->type;
	} ਨਹੀਂਤਾਂ {
		TEST_ਸ਼ੁਰੂ("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, ਬਿੱਟ, &ਨਿਜੀ), 0);
		TEST_ਪੂਰਾ();
	}

	TEST_ਸ਼ੁਰੂ("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_ਨਿੱਜੀ(ਨਿਜੀ, &ਜਨਤਕ), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ssh_init");
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(kex_params.proposal, myproposal, ਆਕਾਰ(myproposal));
	ਜੇ (kex != ਨਿਰਾ)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	ਜੇ (cipher != ਨਿਰਾ) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	ਜੇ (mac != ਨਿਰਾ) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(ਨਿਜੀ));
	ASSERT_PTR_NE(keyname, ਨਿਰਾ);
	kex_params.proposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, ਨਿਰਾ);
	ASSERT_PTR_NE(server, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_ਜੋੜੋ_hostkey(server, ਨਿਜੀ), 0);
	ASSERT_INT_EQ(ssh_ਜੋੜੋ_hostkey(client, ਜਨਤਕ), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("kex");
	ਲੜੀਵਾਰ_kex(client, server);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rekeying client");
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	ਲੜੀਵਾਰ_kex(client, server);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rekeying server");
	ASSERT_INT_EQ(kex_send_kexinit(server), 0);
	ਲੜੀਵਾਰ_kex(client, server);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ssh_packet_get_state");
	state = sshbuf_new();
	ASSERT_PTR_NE(state, ਨਿਰਾ);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("ssh_packet_set_state");
	server2 = ਨਿਰਾ;
	ASSERT_INT_EQ(ssh_init(&server2, 1, ਨਿਰਾ), 0);
	ASSERT_PTR_NE(server2, ਨਿਰਾ);
	ASSERT_INT_EQ(ssh_ਜੋੜੋ_hostkey(server2, ਨਿਜੀ), 0);
	ASSERT_INT_EQ(ssh_packet_ਸੈੱਟ_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, ਨਿਰਾ);
	/* XXX we need to set the callbacks */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	server2->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	server2->kex->ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ = server->kex->ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ;
	server2->kex->ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ = server->kex->ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ;
	server2->kex->sign = server->kex->sign;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	ਲੜੀਵਾਰ_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	ਲੜੀਵਾਰ_kex(client, server2);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("cleanup");
	sshkey_free(ਜਨਤਕ);
	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
		sshkey_free(ਨਿਜੀ);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	ਮੁਕਤ(keyname);
	TEST_ਪੂਰਾ();
}

ਸਥਿਰ ਖਾਲੀ
do_kex(ਅੱਖਰ *kex)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ name[256];

	ਜੇ (test_is_benchmark()) {
		snprintf(name, ਆਕਾਰ(name), "generate %s", kex);
		TEST_ਸ਼ੁਰੂ(name);
		ASSERT_INT_EQ(sshkey_generate(ਕੁੰਜੀ_ED25519, 0, &ਕੁੰਜੀ), 0);
		TEST_ਪੂਰਾ();
		snprintf(name, ਆਕਾਰ(name), "KEX %s", kex);
		BENCH_ਸ਼ੁਰੂ(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_ਕੁੰਜੀ(kex, "aes128-ctr", "hmac-sha2-256", ਕੁੰਜੀ,
		    ਕੁੰਜੀ_ED25519, 256);
		BENCH_ਅੰਤ("kex");
		sshkey_free(ਕੁੰਜੀ);
		ਵਾਪਸ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	do_kex_with_ਕੁੰਜੀ(kex, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਕੁੰਜੀ_RSA, 2048);
	do_kex_with_ਕੁੰਜੀ(kex, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਕੁੰਜੀ_ECDSA, 256);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	do_kex_with_ਕੁੰਜੀ(kex, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਕੁੰਜੀ_ED25519, 256);
}

ਖਾਲੀ
kex_tests(ਖਾਲੀ)
{
	do_kex("curve25519-sha256");
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group1-sha1");
	ਜੇ (test_is_benchmark()) {
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
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
}
