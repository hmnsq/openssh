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

#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"

Options options;
ਪੂਰਨ debug_flag = 0;

ਬਣਤਰ ssh;

ਪੂਰਨ
__wrap_ssh_packet_write_wait(ਬਣਤਰ ssh *ssh)
{
	(ਖਾਲੀ)ssh;
	ਵਾਪਸ 0;
}

ਅੱਖਰ *
__wrap_read_passphrase(ਅਚਲ ਅੱਖਰ *prompt, ਪੂਰਨ flags)
{
	(ਖਾਲੀ)prompt;
	(ਖਾਲੀ)flags;
	ਵਾਪਸ strdup("fuzz");
}

#ਅਨ੍ਤਰ੍ਭਾਵ "../../../sshconnect2.c"
#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"

ਸਥਿਰ jmp_buf fuzz_env;
ਸਥਿਰ ਅਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_fuzz = 0;

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *str)
{
	ਬਣਤਰ sshbuf *b = sshbuf_from(str, ਲੜੀ_ਲੰਬਾਈ(str));
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਜੇ (b == ਨਿਰਾ || sshkey_parse_ਨਿੱਜੀ_fileblob(b, "", &k, ਨਿਰਾ) != 0)
		abort();
	sshbuf_free(b);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *str)
{
	ਅੱਖਰ *tmp, *cp;
	ਬਣਤਰ sshkey *k = sshkey_new(ਕੁੰਜੀ_UNSPEC);
	ਜੇ (k == ਨਿਰਾ)
		abort();
	tmp = cp = strdup(str);
	ਜੇ (sshkey_read(k, &cp) != 0)
		abort();
	ਮੁਕਤ(tmp);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਪੂਰਨ
pump(ਬਣਤਰ ssh *from, ਬਣਤਰ ssh *ਮੰਜ਼ਿਲ, ਮਾਪ_t *transferred)
{
	ਅਚਲ u_char *buf;
	ਮਾਪ_t len;
	u_char type;
	ਪੂਰਨ r;
	*transferred = 0;
	ਜੇ ((r = ssh_packet_ਅਗਲਾ(from, &type)) != 0)
		ਵਾਪਸ r;
	buf = ssh_output_ptr(from, &len);
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ ((r = ssh_ਨਿਵੇਸ਼_append(ਮੰਜ਼ਿਲ, buf, len)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = ssh_output_consume(from, len)) != 0)
		ਵਾਪਸ r;
	*transferred = len;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਲੜੀਵਾਰ_kex(ਬਣਤਰ ssh *client, ਬਣਤਰ ssh *server)
{
	ਪੂਰਨ r;
	ਮਾਪ_t cn, sn;
	ਲਈ (ਪੂਰਨ i = 0; i < 100; i++) {
		ਜੇ ((r = pump(server, client, &sn)) != 0) ਵਾਪਸ r;
		ਜੇ ((r = pump(client, server, &cn)) != 0) ਵਾਪਸ r;
		ਜੇ (server->kex->ਪੂਰਾ && client->kex->ਪੂਰਾ)
			ਵਾਪਸ 0;
		ਜੇ (cn == 0 && sn == 0)
			ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
	}
	ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
}

ਸਥਿਰ Sensitive g_sensitive = { ਨਿਰਾ, 0 };
ਸਥਿਰ Authctxt g_authctxt;
ਸਥਿਰ ਬਣਤਰ ssh *g_client = ਨਿਰਾ;
ਸਥਿਰ ਬਣਤਰ ssh *g_server = ਨਿਰਾ;
ਸਥਿਰ ਪੂਰਨ g_init = 0;

ਸਥਿਰ ਖਾਲੀ
fuzz_reset_authctxt(ਬਣਤਰ ssh *ssh)
{
	ਮੁਕਤ(g_authctxt.authlist);
	g_authctxt.authlist = ਨਿਰਾ;
	ਜੇ (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, ਆਕਾਰ(g_authctxt));
	g_authctxt.server_user = (ਅੱਖਰ *)"fuzz";
	g_authctxt.local_user = (ਅੱਖਰ *)"fuzz";
	g_authctxt.host = (ਅੱਖਰ *)"127.0.0.1";
	g_authctxt.service = (ਅੱਖਰ *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.ਵਿਧੀ = authmethod_lookup("none");
	g_authctxt.authlist = ਨਿਰਾ;
	g_authctxt.methoddata = ਨਿਰਾ;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.ਸਰਗਰਮ_ktype = ਨਿਰਾ;
	g_authctxt.oktypes = ਨਿਰਾ;
	g_authctxt.ktypes = ਨਿਰਾ;
	g_authctxt.info_req_ਵੇਖਿਆ = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.ਕੁੰਜੀਆਂ);
	ssh->authctxt = &g_authctxt;
}

ਸਥਿਰ ਖਾਲੀ
fuzz_ਤਿਆਰੀ(ਬਣਤਰ ssh *ssh)
{
	initialize_options(&options);
	options.batch_ਬਹੁਲਕ = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.ਸੰਖਿਆ_ਦਾ_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(ਖਾਲੀ)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_EXT_INFO, kex_ਨਿਵੇਸ਼_ext_info);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_SERVICE_ACCEPT, &ਨਿਵੇਸ਼_userauth_service_accept);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_SUCCESS, &ਨਿਵੇਸ਼_userauth_success);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_FAILURE, &ਨਿਵੇਸ਼_userauth_failure);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_BANNER, &ਨਿਵੇਸ਼_userauth_banner);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_REQUEST, &ਨਿਵੇਸ਼_userauth_info_req);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_PK_OK, &ਨਿਵੇਸ਼_userauth_pk_ok);
	ssh_dispatch_ਸੈੱਟ(ssh, SSH2_ਸੁਨੇਹਾ_USERAUTH_PASSWD_CHANGEREQ, &ਨਿਵੇਸ਼_userauth_passwd_changereq);
}

ਸਥਿਰ ਪੂਰਨ
init_once(ਖਾਲੀ)
{
	ਜੇ (g_init)
		ਵਾਪਸ 0;
	ਸੰਕੇਤ(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ਬਣਤਰ sshkey *priv = ਲੱਦੋ_ਨਿੱਜੀ(PRIV_ED25519);
	ਬਣਤਰ sshkey *pub = ਲੱਦੋ_ਜਨਤਕ(PUB_ED25519);
	ਅੱਖਰ *keyname = xstrdup(sshkey_ssh_name(priv));

	ਅਚਲ ਅੱਖਰ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅੱਖਰ *proposal[PROPOSAL_MAX] = { 0 };
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਅਚਲ ਅੱਖਰ *p = defaults[i];
		ਜੇ (i == PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS)
			p = keyname;
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ਬਣਤਰ kex_params kp;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(kp.proposal, proposal, ਆਕਾਰ(proposal));

	ਜੇ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ssh_ਜੋੜੋ_hostkey(g_server, priv) != 0 ||
	    ssh_ਜੋੜੋ_hostkey(g_client, pub) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ਲੜੀਵਾਰ_kex(g_client, g_server) != 0)
		ਵਾਪਸ -1;

	fuzz_ਤਿਆਰੀ(g_client);

	ਮੁਕਤ(keyname);
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(proposal[i]);
	g_init = 1;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਅਚਲ uint8_t k_ਸੁਨੇਹਾ_types[] = {
	SSH2_ਸੁਨੇਹਾ_DISCONNECT, SSH2_ਸੁਨੇਹਾ_IGNORE, SSH2_ਸੁਨੇਹਾ_UNIMPLEMENTED,
	SSH2_ਸੁਨੇਹਾ_DEBUG, SSH2_ਸੁਨੇਹਾ_SERVICE_ACCEPT, SSH2_ਸੁਨੇਹਾ_EXT_INFO,
	SSH2_ਸੁਨੇਹਾ_USERAUTH_FAILURE, SSH2_ਸੁਨੇਹਾ_USERAUTH_SUCCESS,
	SSH2_ਸੁਨੇਹਾ_USERAUTH_BANNER, SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_REQUEST,
	SSH2_ਸੁਨੇਹਾ_USERAUTH_PK_OK, SSH2_ਸੁਨੇਹਾ_USERAUTH_PASSWD_CHANGEREQ,
};

ਖਾਲੀ
fuzz_one_ਸੁਨੇਹਾ(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (init_once() != 0)
		ਵਾਪਸ;
	ਜੇ (ਮਾਪ > 65000)
		ਵਾਪਸ;

	uint8_t selector = ਮਾਪ > 0 ? ਅੰਕੜੇ[0] : 0;
	ਅਚਲ uint8_t *payload = ਮਾਪ > 0 ? ਅੰਕੜੇ + 1 : ਨਿਰਾ;
	ਮਾਪ_t plen = ਮਾਪ > 0 ? ਮਾਪ - 1 : 0;

	uint8_t ਸੁਨੇਹਾ_type = k_ਸੁਨੇਹਾ_types[selector %
	    (ਆਕਾਰ(k_ਸੁਨੇਹਾ_types) / ਆਕਾਰ(k_ਸੁਨੇਹਾ_types[0]))];

	fuzz_reset_authctxt(g_client);

	ਵਿੱਚ_fuzz = 1;
	ਜੇ (setjmp(fuzz_env) == 0) {
		ਮਾਪ_t transferred;
		ਜੇ (ssh_packet_put(g_server, ਸੁਨੇਹਾ_type, payload, plen) != 0)
			ਜਾਓ ਪੂਰਾ;
		ਜੇ (pump(g_server, g_client, &transferred) != 0)
			ਜਾਓ ਪੂਰਾ;
		(ਖਾਲੀ)ssh_dispatch_ਲੜੀਵਾਰ(g_client, DISPATCH_NONBLOCK, ਨਿਰਾ);
	ਪੂਰਾ:
		;
	}
	ਵਿੱਚ_fuzz = 0;
}
