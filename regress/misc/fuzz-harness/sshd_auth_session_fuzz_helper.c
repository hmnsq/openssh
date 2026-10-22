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
 * Fuzzer for OpenSSH server-side userauth dispatch (auth2.c + auth2-*.c)
 *
 * Target: input_userauth_request and the userauth_* method handlers
 *
 * Threat model: pre-auth attacker sending crafted USERAUTH_REQUEST
 * messages to sshd. Mirror of ssh_client_session_fuzz on the server
 * side. The handlers parse method/user/service/key/sig fields before
 * calling any actual authentication backend.
 *
 * Mock layer: the monitor_wrap mm_* IPC functions are replaced with
 * in-process stubs that return canned data so the dispatch path runs
 * without real privsep IPC or filesystem access. mm_sshkey_verify is
 * the only stub that calls a real backend (sshkey_verify), which
 * harmlessly fails on garbage signatures.
 *
 * KEX is real, mirrored across two in-process ssh structs created via
 * ssh_api. After KEX completes, input_userauth_request is registered
 * on the server's dispatch table and each iteration delivers a
 * fuzzer-controlled USERAUTH_REQUEST.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

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
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "audit.h"

ServerOptions options;
ਬਣਤਰ sshbuf *loginmsg = ਨਿਰਾ;
ਬਣਤਰ include_list includes;
ਬਣਤਰ sshauthopt *auth_opts = ਨਿਰਾ;
ਬਣਤਰ passwd *privsep_pw = ਨਿਰਾ;

ਸਥਿਰ jmp_buf fuzz_env;
ਸਥਿਰ ਅਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_fuzz = 0;

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

ਪੂਰਨ
__wrap_ssh_packet_write_wait(ਬਣਤਰ ssh *ssh)
{
	(ਖਾਲੀ)ssh;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਬਣਤਰ passwd g_fake_pw;

ਪੂਰਨ
mm_is_monitor(ਖਾਲੀ)
{
	ਵਾਪਸ 0;
}

ਬਣਤਰ passwd *
mm_getpwnamallow(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *user)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)user;
	ਵਾਪਸ &g_fake_pw;
}

ਪੂਰਨ
mm_auth_password(ਬਣਤਰ ssh *ssh, ਅੱਖਰ *password)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)password;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
mm_user_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਪੂਰਨ auth_attempt, ਬਣਤਰ sshauthopt **authoptsp)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)pw;
	(ਖਾਲੀ)ਕੁੰਜੀ;
	(ਖਾਲੀ)auth_attempt;
	(ਖਾਲੀ)authoptsp;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
mm_hostbased_ਕੁੰਜੀ_allowed(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *user,
    ਅਚਲ ਅੱਖਰ *host, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)pw;
	(ਖਾਲੀ)user;
	(ਖਾਲੀ)host;
	(ਖਾਲੀ)ਕੁੰਜੀ;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
mm_sshkey_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen, ਅਚਲ ਅੱਖਰ *alg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ਵਾਪਸ sshkey_verify(ਕੁੰਜੀ, sig, siglen, ਅੰਕੜੇ, datalen, alg, compat,
	    detailsp);
}

ਖਾਲੀ
mm_inform_authserv(ਅੱਖਰ *service, ਅੱਖਰ *style)
{
	(ਖਾਲੀ)service;
	(ਖਾਲੀ)style;
}

ਖਾਲੀ
mm_audit_event(ਬਣਤਰ ssh *ssh, ssh_audit_event_t event)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)event;
}

ਖਾਲੀ
mm_ਸ਼ੁਰੂ_pam(ਬਣਤਰ ssh *ssh)
{
	(ਖਾਲੀ)ssh;
}

ਪੂਰਨ
mm_do_pam_account(ਖਾਲੀ)
{
	ਵਾਪਸ 0;
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

#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"

ਬਣਤਰ sshbuf *cfg = ਨਿਰਾ;

ਪੂਰਨ auth_rhosts2(ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *client_user,
    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ipaddr) { (ਖਾਲੀ)pw;
    (ਖਾਲੀ)client_user; (ਖਾਲੀ)hostname; (ਖਾਲੀ)ipaddr; ਵਾਪਸ 0; }
ਪੂਰਨ platform_locked_account(ਬਣਤਰ passwd *pw) { (ਖਾਲੀ)pw; ਵਾਪਸ 0; }
ਖਾਲੀ ਰਿਕਾਰਡ_failed_login(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *user,
    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ttyname) { (ਖਾਲੀ)ssh; (ਖਾਲੀ)user;
    (ਖਾਲੀ)hostname; (ਖਾਲੀ)ttyname; }
ਪੂਰਨ temporarily_use_uid(ਬਣਤਰ passwd *pw) { (ਖਾਲੀ)pw; ਵਾਪਸ 0; }
ਖਾਲੀ restore_uid(ਖਾਲੀ) { }
ਅੱਖਰ *mm_auth2_read_banner(ਖਾਲੀ) { ਵਾਪਸ ਨਿਰਾ; }
ਬਣਤਰ connection_info *
server_get_connection_info(ਬਣਤਰ ssh *ssh, ਪੂਰਨ populate, ਪੂਰਨ use_dns)
    { (ਖਾਲੀ)ssh; (ਖਾਲੀ)populate; (ਖਾਲੀ)use_dns; ਵਾਪਸ ਨਿਰਾ; }
ਖਾਲੀ server_process_permitopen(ਬਣਤਰ ssh *ssh) { (ਖਾਲੀ)ssh; }
ਖਾਲੀ server_process_channel_timeouts(ਬਣਤਰ ssh *ssh) { (ਖਾਲੀ)ssh; }

#ਅਨ੍ਤਰ੍ਭਾਵ "../../../auth2.c"

ਸਥਿਰ ਬਣਤਰ ssh *g_client = ਨਿਰਾ;
ਸਥਿਰ ਬਣਤਰ ssh *g_server = ਨਿਰਾ;
ਸਥਿਰ ਪੂਰਨ g_init = 0;
ਸਥਿਰ Authctxt g_authctxt;

ਸਥਿਰ ਖਾਲੀ
fuzz_reset_authctxt(ਬਣਤਰ ssh *ssh)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ i;

	ਮੁਕਤ(g_authctxt.user);
	ਮੁਕਤ(g_authctxt.service);
	ਮੁਕਤ(g_authctxt.style);
	ਮੁਕਤ(g_authctxt.auth_ਵਿਧੀ_info);
	ਜੇ (g_authctxt.auth_methods != ਨਿਰਾ) {
		ਲਈ (i = 0; i < g_authctxt.ਅੰਕ_auth_methods; i++)
			ਮੁਕਤ(g_authctxt.auth_methods[i]);
		ਮੁਕਤ(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_ਵਿਧੀ_ਕੁੰਜੀ);
	ਲਈ (i = 0; i < g_authctxt.nprev_ਕੁੰਜੀਆਂ; i++)
		sshkey_free(g_authctxt.prev_ਕੁੰਜੀਆਂ[i]);
	ਮੁਕਤ(g_authctxt.prev_ਕੁੰਜੀਆਂ);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, ਆਕਾਰ(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

ਸਥਿਰ ਪੂਰਨ
init_once(ਖਾਲੀ)
{
	ਜੇ (g_init)
		ਵਾਪਸ 0;
	ਸੰਕੇਤ(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ਆਕਾਰ(g_fake_pw));
	g_fake_pw.pw_name = (ਅੱਖਰ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ਅੱਖਰ *)"/tmp";
	g_fake_pw.pw_shell = (ਅੱਖਰ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

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

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_ਸੈੱਟ(g_server, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST,
	    &ਨਿਵੇਸ਼_userauth_request);

	ਮੁਕਤ(keyname);
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(proposal[i]);
	g_init = 1;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
fuzz_userauth_one(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (init_once() != 0)
		ਵਾਪਸ;
	ਜੇ (ਮਾਪ > 65000)
		ਵਾਪਸ;

	fuzz_reset_authctxt(g_server);

	ਵਿੱਚ_fuzz = 1;
	ਜੇ (setjmp(fuzz_env) == 0) {
		ਮਾਪ_t transferred;
		ਜੇ (ssh_packet_put(g_client, SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST,
		    ਅੰਕੜੇ, ਮਾਪ) != 0)
			ਜਾਓ ਪੂਰਾ;
		ਜੇ (pump(g_client, g_server, &transferred) != 0)
			ਜਾਓ ਪੂਰਾ;
		(ਖਾਲੀ)ssh_dispatch_ਲੜੀਵਾਰ(g_server, DISPATCH_NONBLOCK, ਨਿਰਾ);
	ਪੂਰਾ:
		;
	}
	ਵਿੱਚ_fuzz = 0;
}
