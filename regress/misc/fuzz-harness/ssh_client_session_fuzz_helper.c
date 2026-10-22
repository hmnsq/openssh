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

#ضمن <setjmp.h>
#ضمن <signal.h>
#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "digest.h"
#ضمن "misc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "ssh_api.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "packet.h"
#ضمن "myproposal.h"
#ضمن "kex.h"
#ضمن "xmalloc.h"
#ضمن "authfile.h"
#ضمن "readconf.h"

Options options;
صحيح debug_flag = 0;

بنية ssh;

صحيح
__wrap_ssh_packet_write_wait(بنية ssh *ssh)
{
	(فراغ)ssh;
	إرجاع 0;
}

حرف *
__wrap_read_passphrase(ثابت حرف *prompt, صحيح flags)
{
	(فراغ)prompt;
	(فراغ)flags;
	إرجاع strdup("fuzz");
}

#ضمن "../../../sshconnect2.c"
#ضمن "fixed-keys.h"

ساكن jmp_buf fuzz_env;
ساكن متطاير صحيح in_fuzz = 0;

فراغ
cleanup_exit(صحيح code)
{
	إذا (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ساكن بنية sshkey *
load_private(ثابت حرف *str)
{
	بنية sshbuf *b = sshbuf_from(str, strlen(str));
	بنية sshkey *k = عدم;
	إذا (b == عدم || sshkey_parse_private_fileblob(b, "", &k, عدم) != 0)
		abort();
	sshbuf_free(b);
	إرجاع k;
}

ساكن بنية sshkey *
load_public(ثابت حرف *str)
{
	حرف *tmp, *cp;
	بنية sshkey *k = sshkey_new(مفتاح_UNSPEC);
	إذا (k == عدم)
		abort();
	tmp = cp = strdup(str);
	إذا (sshkey_read(k, &cp) != 0)
		abort();
	حرر(tmp);
	إرجاع k;
}

ساكن صحيح
pump(بنية ssh *from, بنية ssh *to, size_t *transferred)
{
	ثابت u_char *buf;
	size_t len;
	u_char type;
	صحيح r;
	*transferred = 0;
	إذا ((r = ssh_packet_next(from, &type)) != 0)
		إرجاع r;
	buf = ssh_output_ptr(from, &len);
	إذا (len == 0)
		إرجاع 0;
	إذا ((r = ssh_إدخال_append(to, buf, len)) != 0)
		إرجاع r;
	إذا ((r = ssh_output_consume(from, len)) != 0)
		إرجاع r;
	*transferred = len;
	إرجاع 0;
}

ساكن صحيح
run_kex(بنية ssh *client, بنية ssh *server)
{
	صحيح r;
	size_t cn, sn;
	لكل (صحيح i = 0; i < 100; i++) {
		إذا ((r = pump(server, client, &sn)) != 0) إرجاع r;
		إذا ((r = pump(client, server, &cn)) != 0) إرجاع r;
		إذا (server->kex->done && client->kex->done)
			إرجاع 0;
		إذا (cn == 0 && sn == 0)
			إرجاع SSH_ERR_PROTOCOL_ERROR;
	}
	إرجاع SSH_ERR_PROTOCOL_ERROR;
}

ساكن Sensitive g_sensitive = { عدم, 0 };
ساكن Authctxt g_authctxt;
ساكن بنية ssh *g_client = عدم;
ساكن بنية ssh *g_server = عدم;
ساكن صحيح g_init = 0;

ساكن فراغ
fuzz_reset_authctxt(بنية ssh *ssh)
{
	حرر(g_authctxt.authlist);
	g_authctxt.authlist = عدم;
	إذا (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, حجم(g_authctxt));
	g_authctxt.server_user = (حرف *)"fuzz";
	g_authctxt.local_user = (حرف *)"fuzz";
	g_authctxt.host = (حرف *)"127.0.0.1";
	g_authctxt.service = (حرف *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = عدم;
	g_authctxt.methoddata = عدم;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = عدم;
	g_authctxt.oktypes = عدم;
	g_authctxt.ktypes = عدم;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.مفاتيح);
	ssh->authctxt = &g_authctxt;
}

ساكن فراغ
fuzz_setup(بنية ssh *ssh)
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
	options.العدد_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(فراغ)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_رسالة_EXT_INFO, kex_إدخال_ext_info);
	ssh_dispatch_set(ssh, SSH2_رسالة_SERVICE_ACCEPT, &إدخال_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_رسالة_USERAUTH_SUCCESS, &إدخال_userauth_success);
	ssh_dispatch_set(ssh, SSH2_رسالة_USERAUTH_FAILURE, &إدخال_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_رسالة_USERAUTH_BANNER, &إدخال_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_رسالة_USERAUTH_INFO_REQUEST, &إدخال_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_رسالة_USERAUTH_PK_OK, &إدخال_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_رسالة_USERAUTH_PASSWD_CHANGEREQ, &إدخال_userauth_passwd_changereq);
}

ساكن صحيح
init_once(فراغ)
{
	إذا (g_init)
		إرجاع 0;
	إشارة(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	بنية sshkey *priv = load_private(PRIV_ED25519);
	بنية sshkey *pub = load_public(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحيح i;
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		إذا (i == PROPOSAL_SERVER_HOST_مفتاح_ALGS)
			p = keyname;
		وإلا إذا (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		وإلا إذا (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		وإلا إذا (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	بنية kex_params kp;
	memcpy(kp.proposal, proposal, حجم(proposal));

	إذا (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		إرجاع -1;
	إذا (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		إرجاع -1;
	إذا (run_kex(g_client, g_server) != 0)
		إرجاع -1;

	fuzz_setup(g_client);

	حرر(keyname);
	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(proposal[i]);
	g_init = 1;
	إرجاع 0;
}

ساكن ثابت uint8_t k_رسالة_types[] = {
	SSH2_رسالة_DISCONNECT, SSH2_رسالة_IGNORE, SSH2_رسالة_UNIMPLEMENTED,
	SSH2_رسالة_DEBUG, SSH2_رسالة_SERVICE_ACCEPT, SSH2_رسالة_EXT_INFO,
	SSH2_رسالة_USERAUTH_FAILURE, SSH2_رسالة_USERAUTH_SUCCESS,
	SSH2_رسالة_USERAUTH_BANNER, SSH2_رسالة_USERAUTH_INFO_REQUEST,
	SSH2_رسالة_USERAUTH_PK_OK, SSH2_رسالة_USERAUTH_PASSWD_CHANGEREQ,
};

فراغ
fuzz_one_message(ثابت uint8_t *data, size_t size)
{
	إذا (init_once() != 0)
		إرجاع;
	إذا (size > 65000)
		إرجاع;

	uint8_t selector = size > 0 ? data[0] : 0;
	ثابت uint8_t *payload = size > 0 ? data + 1 : عدم;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t رسالة_type = k_رسالة_types[selector %
	    (حجم(k_رسالة_types) / حجم(k_رسالة_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	إذا (setjmp(fuzz_env) == 0) {
		size_t transferred;
		إذا (ssh_packet_put(g_server, رسالة_type, payload, plen) != 0)
			اذهب done;
		إذا (pump(g_server, g_client, &transferred) != 0)
			اذهب done;
		(فراغ)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, عدم);
	done:
		;
	}
	in_fuzz = 0;
}
