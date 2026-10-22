/* 	$OpenBSD: test_kex.c,v 1.12 2025/08/21 05:55:30 djm Exp $ */
/*
 * Regress test KEX
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/time.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "ssherr.h"
#समावेश "ssh_api.h"
#समावेश "sshbuf.h"
#समावेश "packet.h"
#समावेश "myproposal.h"
#समावेश "log.h"

व्योम kex_tests(व्योम);
अटल पूर्णांक do_debug = 0;

अटल पूर्णांक
do_send_and_receive(काष्ठा ssh *from, काष्ठा ssh *to)
{
	u_char type;
	माप_प्रकार len;
	स्थिर u_char *buf;
	पूर्णांक r;

	क्रम (;;) {
		अगर ((r = ssh_packet_अग्र(from, &type)) != 0) {
			ख_लिखो(मानक_त्रुटि, "ssh_packet_next: %s\n", ssh_err(r));
			वापस r;
		}
		अगर (type != 0)
			वापस 0;
		buf = ssh_output_ptr(from, &len);
		अगर (do_debug)
			म_लिखो("%zu", len);
		अगर (len == 0)
			वापस 0;
		अगर ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_निवेश_append(to, buf, len)) != 0)
			वापस r;
	}
}

अटल व्योम
run_kex(काष्ठा ssh *client, काष्ठा ssh *server)
{
	पूर्णांक r = 0;

	जबतक (!server->kex->done || !client->kex->done) {
		अगर (do_debug)
			म_लिखो(" S:");
		अगर ((r = do_send_and_receive(server, client)))
			अवरोध;
		अगर (do_debug)
			म_लिखो(" C:");
		अगर ((r = do_send_and_receive(client, server)))
			अवरोध;
	}
	अगर (do_debug)
		म_लिखो("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->done, 1);
	ASSERT_INT_EQ(client->kex->done, 1);
}

अटल व्योम
do_kex_with_कुंजी(अक्षर *kex, अक्षर *cipher, अक्षर *mac,
    काष्ठा sshkey *कुंजी, पूर्णांक keytype, पूर्णांक bits)
{
	काष्ठा ssh *client = शून्य, *server = शून्य, *server2 = शून्य;
	काष्ठा sshkey *निजी, *खुला;
	काष्ठा sshbuf *state;
	काष्ठा kex_params kex_params;
	अक्षर *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *keyname = शून्य;

	अगर (कुंजी != शून्य) {
		निजी = कुंजी;
		keytype = कुंजी->type;
	} अन्यथा {
		TEST_START("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, bits, &निजी), 0);
		TEST_DONE();
	}

	TEST_START("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_private(निजी, &खुला), 0);
	TEST_DONE();

	TEST_START("ssh_init");
	स_नकल(kex_params.proposal, myproposal, माप(myproposal));
	अगर (kex != शून्य)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	अगर (cipher != शून्य) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	अगर (mac != शून्य) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(निजी));
	ASSERT_PTR_NE(keyname, शून्य);
	kex_params.proposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, शून्य);
	ASSERT_PTR_NE(server, शून्य);
	TEST_DONE();

	TEST_START("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_add_hostkey(server, निजी), 0);
	ASSERT_INT_EQ(ssh_add_hostkey(client, खुला), 0);
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
	ASSERT_PTR_NE(state, शून्य);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_DONE();

	TEST_START("ssh_packet_set_state");
	server2 = शून्य;
	ASSERT_INT_EQ(ssh_init(&server2, 1, शून्य), 0);
	ASSERT_PTR_NE(server2, शून्य);
	ASSERT_INT_EQ(ssh_add_hostkey(server2, निजी), 0);
	ASSERT_INT_EQ(ssh_packet_set_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, शून्य);
	/* XXX we need to set the callbacks */
#अगर_घोषित WITH_OPENSSL
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#पूर्ण_अगर /* WITH_OPENSSL */
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
	sshkey_free(खुला);
	अगर (कुंजी == शून्य)
		sshkey_free(निजी);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	मुक्त(keyname);
	TEST_DONE();
}

अटल व्योम
do_kex(अक्षर *kex)
{
	काष्ठा sshkey *कुंजी = शून्य;
	अक्षर name[256];

	अगर (test_is_benchmark()) {
		snprintf(name, माप(name), "generate %s", kex);
		TEST_START(name);
		ASSERT_INT_EQ(sshkey_generate(कुंजी_ED25519, 0, &कुंजी), 0);
		TEST_DONE();
		snprintf(name, माप(name), "KEX %s", kex);
		BENCH_START(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_कुंजी(kex, "aes128-ctr", "hmac-sha2-256", कुंजी,
		    कुंजी_ED25519, 256);
		BENCH_FINISH("kex");
		sshkey_free(कुंजी);
		वापस;
	}

#अगर_घोषित WITH_OPENSSL
	do_kex_with_कुंजी(kex, शून्य, शून्य, शून्य, कुंजी_RSA, 2048);
	do_kex_with_कुंजी(kex, शून्य, शून्य, शून्य, कुंजी_ECDSA, 256);
#पूर्ण_अगर /* WITH_OPENSSL */
	do_kex_with_कुंजी(kex, शून्य, शून्य, शून्य, कुंजी_ED25519, 256);
}

व्योम
kex_tests(व्योम)
{
	do_kex("curve25519-sha256");
#अगर_घोषित WITH_OPENSSL
	do_kex("ecdh-sha2-nistp256");
	do_kex("ecdh-sha2-nistp384");
	do_kex("ecdh-sha2-nistp521");
	do_kex("diffie-hellman-group-exchange-sha256");
	do_kex("diffie-hellman-group-exchange-sha1");
	do_kex("diffie-hellman-group14-sha1");
	do_kex("diffie-hellman-group1-sha1");
	अगर (test_is_benchmark()) {
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
#पूर्ण_अगर /* WITH_OPENSSL */
}
