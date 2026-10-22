/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for OpenSSH client-side userauth dispatch (sshconnect2.c)
 *
 * Target: sshconnect2.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sshconnect2.c so
 * its static input_userauth_* handlers are reachable from this
 * translation unit. The driver completes an in-process KEX with real
 * cipher and HMAC, then for each iteration injects a fuzzer-controlled
 * SSH2_MSG_* message into the client's input stream and runs the
 * dispatch loop. Non-userauth message types fall through to
 * dispatch_protocol_ignore.
 *
 * Primary functions exercised:
 * - input_userauth_banner / failure / success / info_req / pk_ok /
 *   passwd_changereq / service_accept
 * - sshkey_from_blob (via input_userauth_pk_ok)
 * - downstream sshpkt_get_* and sshbuf_get_* primitives
 *
 * Linker --wrap neutralises two blocking functions:
 * - __wrap_ssh_packet_write_wait (real one ppoll's on fd=-1)
 * - __wrap_read_passphrase (real one reads /dev/tty)
 */

#شامل <setjmp.h>
#شامل <signal.h>
#شامل <stddef.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "digest.h"
#شامل "misc.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "ssh_api.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "packet.h"
#شامل "myproposal.h"
#شامل "kex.h"
#شامل "xmalloc.h"
#شامل "authfile.h"
#شامل "readconf.h"

Options options;
صحیح debug_flag = 0;

ساخت ssh;

صحیح
__wrap_ssh_packet_write_wait(ساخت ssh *ssh)
{
	(خالی)ssh;
	واپس 0;
}

حرف *
__wrap_read_passphrase(ثابت حرف *prompt, صحیح flags)
{
	(خالی)prompt;
	(خالی)flags;
	واپس strdup("fuzz");
}

#شامل "../../../sshconnect2.c"
#شامل "fixed-keys.h"

ساکن jmp_buf fuzz_env;
ساکن متلون صحیح اندر_fuzz = 0;

خالی
cleanup_exit(صحیح رمز)
{
	اگر (اندر_fuzz)
		longjmp(fuzz_env, رمز ? رمز : 1);
	_exit(رمز);
}

ساکن ساخت sshkey *
بھرو_نجی(ثابت حرف *str)
{
	ساخت sshbuf *b = sshbuf_from(str, لڑی_لمبائی(str));
	ساخت sshkey *k = تہی;
	اگر (b == تہی || sshkey_parse_نجی_fileblob(b, "", &k, تہی) != 0)
		abort();
	sshbuf_free(b);
	واپس k;
}

ساکن ساخت sshkey *
بھرو_عوامی(ثابت حرف *str)
{
	حرف *tmp, *cp;
	ساخت sshkey *k = sshkey_new(کلید_UNSPEC);
	اگر (k == تہی)
		abort();
	tmp = cp = strdup(str);
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	واپس k;
}

ساکن صحیح
pump(ساخت ssh *from, ساخت ssh *مقصد, سائز_t *transferred)
{
	ثابت u_char *buf;
	سائز_t len;
	u_char type;
	صحیح r;
	*transferred = 0;
	اگر ((r = ssh_packet_اگلا(from, &type)) != 0)
		واپس r;
	buf = ssh_output_ptr(from, &len);
	اگر (len == 0)
		واپس 0;
	اگر ((r = ssh_داخلہ_append(مقصد, buf, len)) != 0)
		واپس r;
	اگر ((r = ssh_output_consume(from, len)) != 0)
		واپس r;
	*transferred = len;
	واپس 0;
}

ساکن صحیح
تسلسل_kex(ساخت ssh *client, ساخت ssh *server)
{
	صحیح r;
	سائز_t cn, sn;
	برائے (صحیح i = 0; i < 100; i++) {
		اگر ((r = pump(server, client, &sn)) != 0) واپس r;
		اگر ((r = pump(client, server, &cn)) != 0) واپس r;
		اگر (server->kex->مکمل && client->kex->مکمل)
			واپس 0;
		اگر (cn == 0 && sn == 0)
			واپس SSH_ERR_PROTOCOL_ERROR;
	}
	واپس SSH_ERR_PROTOCOL_ERROR;
}

ساکن Sensitive g_sensitive = { تہی, 0 };
ساکن Authctxt g_authctxt;
ساکن ساخت ssh *g_client = تہی;
ساکن ساخت ssh *g_server = تہی;
ساکن صحیح g_init = 0;

ساکن خالی
fuzz_reset_authctxt(ساخت ssh *ssh)
{
	آزاد(g_authctxt.authlist);
	g_authctxt.authlist = تہی;
	اگر (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, حجم(g_authctxt));
	g_authctxt.server_user = (حرف *)"fuzz";
	g_authctxt.local_user = (حرف *)"fuzz";
	g_authctxt.host = (حرف *)"127.0.0.1";
	g_authctxt.service = (حرف *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.طریقہ = authmethod_lookup("none");
	g_authctxt.authlist = تہی;
	g_authctxt.methoddata = تہی;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.فعال_ktype = تہی;
	g_authctxt.oktypes = تہی;
	g_authctxt.ktypes = تہی;
	g_authctxt.info_req_نظر_آیا = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.کلیدیں);
	ssh->authctxt = &g_authctxt;
}

ساکن خالی
fuzz_تیاری(ساخت ssh *ssh)
{
	initialize_options(&options);
	options.batch_منوال = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.نمبر_کا_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(خالی)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_EXT_INFO, kex_داخلہ_ext_info);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_SERVICE_ACCEPT, &داخلہ_userauth_service_accept);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_SUCCESS, &داخلہ_userauth_success);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_FAILURE, &داخلہ_userauth_failure);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_BANNER, &داخلہ_userauth_banner);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_INFO_REQUEST, &داخلہ_userauth_info_req);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PK_OK, &داخلہ_userauth_pk_ok);
	ssh_dispatch_سیٹ(ssh, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ, &داخلہ_userauth_passwd_changereq);
}

ساکن صحیح
init_once(خالی)
{
	اگر (g_init)
		واپس 0;
	اشارہ(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ساخت sshkey *priv = بھرو_نجی(PRIV_ED25519);
	ساخت sshkey *pub = بھرو_عوامی(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحیح i;
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			p = keyname;
		ورنہ اگر (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ورنہ اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ورنہ اگر (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ساخت kex_params kp;
	حافظہ_نقل(kp.proposal, proposal, حجم(proposal));

	اگر (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		واپس -1;
	اگر (ssh_جوڑو_hostkey(g_server, priv) != 0 ||
	    ssh_جوڑو_hostkey(g_client, pub) != 0)
		واپس -1;
	اگر (تسلسل_kex(g_client, g_server) != 0)
		واپس -1;

	fuzz_تیاری(g_client);

	آزاد(keyname);
	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	واپس 0;
}

ساکن ثابت uint8_t k_پیغام_types[] = {
	SSH2_پیغام_DISCONNECT, SSH2_پیغام_IGNORE, SSH2_پیغام_UNIMPLEMENTED,
	SSH2_پیغام_DEBUG, SSH2_پیغام_SERVICE_ACCEPT, SSH2_پیغام_EXT_INFO,
	SSH2_پیغام_USERAUTH_FAILURE, SSH2_پیغام_USERAUTH_SUCCESS,
	SSH2_پیغام_USERAUTH_BANNER, SSH2_پیغام_USERAUTH_INFO_REQUEST,
	SSH2_پیغام_USERAUTH_PK_OK, SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ,
};

خالی
fuzz_one_پیغام(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (init_once() != 0)
		واپس;
	اگر (سائز > 65000)
		واپس;

	uint8_t selector = سائز > 0 ? ڈیٹا[0] : 0;
	ثابت uint8_t *payload = سائز > 0 ? ڈیٹا + 1 : تہی;
	سائز_t plen = سائز > 0 ? سائز - 1 : 0;

	uint8_t پیغام_type = k_پیغام_types[selector %
	    (حجم(k_پیغام_types) / حجم(k_پیغام_types[0]))];

	fuzz_reset_authctxt(g_client);

	اندر_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		سائز_t transferred;
		اگر (ssh_packet_put(g_server, پیغام_type, payload, plen) != 0)
			جاؤ مکمل;
		اگر (pump(g_server, g_client, &transferred) != 0)
			جاؤ مکمل;
		(خالی)ssh_dispatch_تسلسل(g_client, DISPATCH_NONBLOCK, تہی);
	مکمل:
		;
	}
	اندر_fuzz = 0;
}
