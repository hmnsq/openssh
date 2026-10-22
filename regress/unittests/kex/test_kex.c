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

خالی kex_tests(خالی);
ساکن صحیح do_debug = 0;

ساکن صحیح
do_send_and_receive(ساخت ssh *from, ساخت ssh *مقصد)
{
	u_char type;
	سائز_t len;
	ثابت u_char *buf;
	صحیح r;

	برائے (;;) {
		اگر ((r = ssh_packet_اگلا(from, &type)) != 0) {
			fprintf(stderr, "ssh_packet_next: %s\n", ssh_err(r));
			واپس r;
		}
		اگر (type != 0)
			واپس 0;
		buf = ssh_output_ptr(from, &len);
		اگر (do_debug)
			لکھو("%zu", len);
		اگر (len == 0)
			واپس 0;
		اگر ((r = ssh_output_consume(from, len)) != 0 ||
		    (r = ssh_داخلہ_append(مقصد, buf, len)) != 0)
			واپس r;
	}
}

ساکن خالی
تسلسل_kex(ساخت ssh *client, ساخت ssh *server)
{
	صحیح r = 0;

	جب (!server->kex->مکمل || !client->kex->مکمل) {
		اگر (do_debug)
			لکھو(" S:");
		اگر ((r = do_send_and_receive(server, client)))
			توڑو;
		اگر (do_debug)
			لکھو(" C:");
		اگر ((r = do_send_and_receive(client, server)))
			توڑو;
	}
	اگر (do_debug)
		لکھو("done: %s\n", ssh_err(r));
	ASSERT_INT_EQ(r, 0);
	ASSERT_INT_EQ(server->kex->مکمل, 1);
	ASSERT_INT_EQ(client->kex->مکمل, 1);
}

ساکن خالی
do_kex_with_کلید(حرف *kex, حرف *cipher, حرف *mac,
    ساخت sshkey *کلید, صحیح keytype, صحیح بٹ)
{
	ساخت ssh *client = تہی, *server = تہی, *server2 = تہی;
	ساخت sshkey *نجی, *عوامی;
	ساخت sshbuf *state;
	ساخت kex_params kex_params;
	حرف *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *keyname = تہی;

	اگر (کلید != تہی) {
		نجی = کلید;
		keytype = کلید->type;
	} ورنہ {
		TEST_آغاز("sshkey_generate");
		ASSERT_INT_EQ(sshkey_generate(keytype, بٹ, &نجی), 0);
		TEST_مکمل();
	}

	TEST_آغاز("sshkey_from_private");
	ASSERT_INT_EQ(sshkey_from_نجی(نجی, &عوامی), 0);
	TEST_مکمل();

	TEST_آغاز("ssh_init");
	حافظہ_نقل(kex_params.proposal, myproposal, حجم(myproposal));
	اگر (kex != تہی)
		kex_params.proposal[PROPOSAL_KEX_ALGS] = kex;
	اگر (cipher != تہی) {
		kex_params.proposal[PROPOSAL_ENC_ALGS_CTOS] = cipher;
		kex_params.proposal[PROPOSAL_ENC_ALGS_STOC] = cipher;
	}
	اگر (mac != تہی) {
		kex_params.proposal[PROPOSAL_MAC_ALGS_CTOS] = mac;
		kex_params.proposal[PROPOSAL_MAC_ALGS_STOC] = mac;
	}
	keyname = strdup(sshkey_ssh_name(نجی));
	ASSERT_PTR_NE(keyname, تہی);
	kex_params.proposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = keyname;
	ASSERT_INT_EQ(ssh_init(&client, 0, &kex_params), 0);
	ASSERT_INT_EQ(ssh_init(&server, 1, &kex_params), 0);
	ASSERT_PTR_NE(client, تہی);
	ASSERT_PTR_NE(server, تہی);
	TEST_مکمل();

	TEST_آغاز("ssh_add_hostkey");
	ASSERT_INT_EQ(ssh_جوڑو_hostkey(server, نجی), 0);
	ASSERT_INT_EQ(ssh_جوڑو_hostkey(client, عوامی), 0);
	TEST_مکمل();

	TEST_آغاز("kex");
	تسلسل_kex(client, server);
	TEST_مکمل();

	TEST_آغاز("rekeying client");
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	تسلسل_kex(client, server);
	TEST_مکمل();

	TEST_آغاز("rekeying server");
	ASSERT_INT_EQ(kex_send_kexinit(server), 0);
	تسلسل_kex(client, server);
	TEST_مکمل();

	TEST_آغاز("ssh_packet_get_state");
	state = sshbuf_new();
	ASSERT_PTR_NE(state, تہی);
	ASSERT_INT_EQ(ssh_packet_get_state(server, state), 0);
	ASSERT_INT_GE(sshbuf_len(state), 1);
	TEST_مکمل();

	TEST_آغاز("ssh_packet_set_state");
	server2 = تہی;
	ASSERT_INT_EQ(ssh_init(&server2, 1, تہی), 0);
	ASSERT_PTR_NE(server2, تہی);
	ASSERT_INT_EQ(ssh_جوڑو_hostkey(server2, نجی), 0);
	ASSERT_INT_EQ(ssh_packet_سیٹ_state(server2, state), 0);
	ASSERT_INT_EQ(sshbuf_len(state), 0);
	sshbuf_free(state);
	ASSERT_PTR_NE(server2->kex, تہی);
	/* XXX we need to set the callbacks */
#اگر_تعریف_شدہ WITH_OPENSSL
	server2->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	server2->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
	server2->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#اگر_ختم /* WITH_OPENSSL */
	server2->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
	server2->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
	server2->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
	server2->kex->بھرو_host_عوامی_کلید = server->kex->بھرو_host_عوامی_کلید;
	server2->kex->بھرو_host_نجی_کلید = server->kex->بھرو_host_نجی_کلید;
	server2->kex->sign = server->kex->sign;
	TEST_مکمل();

	TEST_آغاز("rekeying server2");
	ASSERT_INT_EQ(kex_send_kexinit(server2), 0);
	تسلسل_kex(client, server2);
	ASSERT_INT_EQ(kex_send_kexinit(client), 0);
	تسلسل_kex(client, server2);
	TEST_مکمل();

	TEST_آغاز("cleanup");
	sshkey_free(عوامی);
	اگر (کلید == تہی)
		sshkey_free(نجی);
	ssh_free(client);
	ssh_free(server);
	ssh_free(server2);
	آزاد(keyname);
	TEST_مکمل();
}

ساکن خالی
do_kex(حرف *kex)
{
	ساخت sshkey *کلید = تہی;
	حرف name[256];

	اگر (test_is_benchmark()) {
		snprintf(name, حجم(name), "generate %s", kex);
		TEST_آغاز(name);
		ASSERT_INT_EQ(sshkey_generate(کلید_ED25519, 0, &کلید), 0);
		TEST_مکمل();
		snprintf(name, حجم(name), "KEX %s", kex);
		BENCH_آغاز(name);
		/*
		 * NB. use a cipher/MAC here that requires minimal bits from
		 * the KEX to avoid DH-GEX taking forever.
		 */
		do_kex_with_کلید(kex, "aes128-ctr", "hmac-sha2-256", کلید,
		    کلید_ED25519, 256);
		BENCH_اختتام("kex");
		sshkey_free(کلید);
		واپس;
	}

#اگر_تعریف_شدہ WITH_OPENSSL
	do_kex_with_کلید(kex, تہی, تہی, تہی, کلید_RSA, 2048);
	do_kex_with_کلید(kex, تہی, تہی, تہی, کلید_ECDSA, 256);
#اگر_ختم /* WITH_OPENSSL */
	do_kex_with_کلید(kex, تہی, تہی, تہی, کلید_ED25519, 256);
}

خالی
kex_tests(خالی)
{
	do_kex("curve25519-sha256");
#اگر_تعریف_شدہ WITH_OPENSSL
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
#اگر_ختم /* WITH_OPENSSL */
}
