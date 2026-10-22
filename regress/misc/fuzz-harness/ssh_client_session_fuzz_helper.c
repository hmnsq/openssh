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

ساختار ssh;

صحیح
__wrap_ssh_packet_write_wait(ساختار ssh *ssh)
{
	(تهی)ssh;
	بازگشت 0;
}

نویسه *
__wrap_read_passphrase(ثابت نویسه *prompt, صحیح flags)
{
	(تهی)prompt;
	(تهی)flags;
	بازگشت strdup("fuzz");
}

#شامل "../../../sshconnect2.c"
#شامل "fixed-keys.h"

ایستا jmp_buf fuzz_env;
ایستا فرار صحیح in_fuzz = 0;

تهی
cleanup_exit(صحیح code)
{
	اگر (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ایستا ساختار sshkey *
load_private(ثابت نویسه *str)
{
	ساختار sshbuf *b = sshbuf_from(str, strlen(str));
	ساختار sshkey *k = پوچ;
	اگر (b == پوچ || sshkey_parse_private_fileblob(b, "", &k, پوچ) != 0)
		abort();
	sshbuf_free(b);
	بازگشت k;
}

ایستا ساختار sshkey *
load_public(ثابت نویسه *str)
{
	نویسه *tmp, *cp;
	ساختار sshkey *k = sshkey_new(کلید_UNSPEC);
	اگر (k == پوچ)
		abort();
	tmp = cp = strdup(str);
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	بازگشت k;
}

ایستا صحیح
pump(ساختار ssh *from, ساختار ssh *to, size_t *transferred)
{
	ثابت u_char *buf;
	size_t len;
	u_char type;
	صحیح r;
	*transferred = 0;
	اگر ((r = ssh_packet_next(from, &type)) != 0)
		بازگشت r;
	buf = ssh_output_ptr(from, &len);
	اگر (len == 0)
		بازگشت 0;
	اگر ((r = ssh_درون_داد_append(to, buf, len)) != 0)
		بازگشت r;
	اگر ((r = ssh_output_consume(from, len)) != 0)
		بازگشت r;
	*transferred = len;
	بازگشت 0;
}

ایستا صحیح
run_kex(ساختار ssh *client, ساختار ssh *server)
{
	صحیح r;
	size_t cn, sn;
	برای (صحیح i = 0; i < 100; i++) {
		اگر ((r = pump(server, client, &sn)) != 0) بازگشت r;
		اگر ((r = pump(client, server, &cn)) != 0) بازگشت r;
		اگر (server->kex->done && client->kex->done)
			بازگشت 0;
		اگر (cn == 0 && sn == 0)
			بازگشت SSH_ERR_PROTOCOL_ERROR;
	}
	بازگشت SSH_ERR_PROTOCOL_ERROR;
}

ایستا Sensitive g_sensitive = { پوچ, 0 };
ایستا Authctxt g_authctxt;
ایستا ساختار ssh *g_client = پوچ;
ایستا ساختار ssh *g_server = پوچ;
ایستا صحیح g_init = 0;

ایستا تهی
fuzz_reset_authctxt(ساختار ssh *ssh)
{
	آزاد(g_authctxt.authlist);
	g_authctxt.authlist = پوچ;
	اگر (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, اندازه(g_authctxt));
	g_authctxt.server_user = (نویسه *)"fuzz";
	g_authctxt.local_user = (نویسه *)"fuzz";
	g_authctxt.host = (نویسه *)"127.0.0.1";
	g_authctxt.service = (نویسه *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = پوچ;
	g_authctxt.methoddata = پوچ;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = پوچ;
	g_authctxt.oktypes = پوچ;
	g_authctxt.ktypes = پوچ;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.کلیدها);
	ssh->authctxt = &g_authctxt;
}

ایستا تهی
fuzz_setup(ساختار ssh *ssh)
{
	initialize_options(&options);
	options.batch_mode = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.عدد_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(تهی)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_پیام_EXT_INFO, kex_درون_داد_ext_info);
	ssh_dispatch_set(ssh, SSH2_پیام_SERVICE_ACCEPT, &درون_داد_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_SUCCESS, &درون_داد_userauth_success);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_FAILURE, &درون_داد_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_BANNER, &درون_داد_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_INFO_REQUEST, &درون_داد_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_PK_OK, &درون_داد_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_پیام_USERAUTH_PASSWD_CHANGEREQ, &درون_داد_userauth_passwd_changereq);
}

ایستا صحیح
init_once(تهی)
{
	اگر (g_init)
		بازگشت 0;
	سیگنال(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ساختار sshkey *priv = load_private(PRIV_ED25519);
	ساختار sshkey *pub = load_public(PUB_ED25519);
	نویسه *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت نویسه *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	نویسه *proposal[PROPOSAL_MAX] = { 0 };
	صحیح i;
	برای (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت نویسه *p = defaults[i];
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			p = keyname;
		وگرنه اگر (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		وگرنه اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		وگرنه اگر (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ساختار kex_params kp;
	memcpy(kp.proposal, proposal, اندازه(proposal));

	اگر (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		بازگشت -1;
	اگر (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		بازگشت -1;
	اگر (run_kex(g_client, g_server) != 0)
		بازگشت -1;

	fuzz_setup(g_client);

	آزاد(keyname);
	برای (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	بازگشت 0;
}

ایستا ثابت uint8_t k_پیام_types[] = {
	SSH2_پیام_DISCONNECT, SSH2_پیام_IGNORE, SSH2_پیام_UNIMPLEMENTED,
	SSH2_پیام_DEBUG, SSH2_پیام_SERVICE_ACCEPT, SSH2_پیام_EXT_INFO,
	SSH2_پیام_USERAUTH_FAILURE, SSH2_پیام_USERAUTH_SUCCESS,
	SSH2_پیام_USERAUTH_BANNER, SSH2_پیام_USERAUTH_INFO_REQUEST,
	SSH2_پیام_USERAUTH_PK_OK, SSH2_پیام_USERAUTH_PASSWD_CHANGEREQ,
};

تهی
fuzz_one_message(ثابت uint8_t *data, size_t size)
{
	اگر (init_once() != 0)
		بازگشت;
	اگر (size > 65000)
		بازگشت;

	uint8_t selector = size > 0 ? data[0] : 0;
	ثابت uint8_t *payload = size > 0 ? data + 1 : پوچ;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t پیام_type = k_پیام_types[selector %
	    (اندازه(k_پیام_types) / اندازه(k_پیام_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		size_t transferred;
		اگر (ssh_packet_put(g_server, پیام_type, payload, plen) != 0)
			برو done;
		اگر (pump(g_server, g_client, &transferred) != 0)
			برو done;
		(تهی)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, پوچ);
	done:
		;
	}
	in_fuzz = 0;
}
