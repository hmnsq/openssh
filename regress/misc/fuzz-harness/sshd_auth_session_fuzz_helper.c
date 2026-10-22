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

#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "audit.h"

ServerOptions options;
ರಚನೆ sshbuf *loginmsg = ಖಾಲಿ;
ರಚನೆ include_list includes;
ರಚನೆ sshauthopt *auth_opts = ಖಾಲಿ;
ರಚನೆ passwd *privsep_pw = ಖಾಲಿ;

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಅಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳ_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ ಸಂಕೇತ_2)
{
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, ಸಂಕೇತ_2 ? ಸಂಕೇತ_2 : 1);
	_exit(ಸಂಕೇತ_2);
}

ಪೂರ್ಣಾಂಕ
__wrap_ssh_packet_write_wait(ರಚನೆ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ passwd g_fake_pw;

ಪೂರ್ಣಾಂಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ 0;
}

ರಚನೆ passwd *
mm_getpwnamallow(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)user;
	ಹಿಂತಿರುಗಿ &g_fake_pw;
}

ಪೂರ್ಣಾಂಕ
mm_auth_password(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *password)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)password;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
mm_user_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *pw, ರಚನೆ sshkey *ಕೀಲಿ,
    ಪೂರ್ಣಾಂಕ auth_attempt, ರಚನೆ sshauthopt **authoptsp)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)pw;
	(ಶೂನ್ಯ)ಕೀಲಿ;
	(ಶೂನ್ಯ)auth_attempt;
	(ಶೂನ್ಯ)authoptsp;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
mm_hostbased_ಕೀಲಿ_allowed(ರಚನೆ ssh *ssh, ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ರಚನೆ sshkey *ಕೀಲಿ)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)pw;
	(ಶೂನ್ಯ)user;
	(ಶೂನ್ಯ)host;
	(ಶೂನ್ಯ)ಕೀಲಿ;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
mm_sshkey_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat,
    ರಚನೆ sshkey_sig_details **detailsp)
{
	ಹಿಂತಿರುಗಿ sshkey_verify(ಕೀಲಿ, sig, siglen, ದತ್ತಾಂಶ, datalen, alg, compat,
	    detailsp);
}

ಶೂನ್ಯ
mm_inform_authserv(ಅಕ್ಷರ *service, ಅಕ್ಷರ *style)
{
	(ಶೂನ್ಯ)service;
	(ಶೂನ್ಯ)style;
}

ಶೂನ್ಯ
mm_audit_event(ರಚನೆ ssh *ssh, ssh_audit_event_t event)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)event;
}

ಶೂನ್ಯ
mm_ಆರಂಭ_pam(ರಚನೆ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh;
}

ಪೂರ್ಣಾಂಕ
mm_do_pam_account(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ರಚನೆ sshbuf *b = sshbuf_from(str, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(str));
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಆದರೆ (b == ಖಾಲಿ || sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &k, ಖಾಲಿ) != 0)
		abort();
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಆದರೆ (k == ಖಾಲಿ)
		abort();
	tmp = cp = strdup(str);
	ಆದರೆ (sshkey_read(k, &cp) != 0)
		abort();
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pump(ರಚನೆ ssh *from, ರಚನೆ ssh *ಗಮ್ಯ, ಗಾತ್ರ_t *transferred)
{
	ಸ್ಥಿರಾಂಕ u_char *buf;
	ಗಾತ್ರ_t len;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;
	*transferred = 0;
	ಆದರೆ ((r = ssh_packet_ಮುಂದಿನ(from, &type)) != 0)
		ಹಿಂತಿರುಗಿ r;
	buf = ssh_output_ptr(from, &len);
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = ssh_ಒಳಹರಿವು_append(ಗಮ್ಯ, buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = ssh_output_consume(from, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	*transferred = len;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಸತತ_kex(ರಚನೆ ssh *client, ರಚನೆ ssh *server)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t cn, sn;
	ಗಾಗಿ (ಪೂರ್ಣಾಂಕ i = 0; i < 100; i++) {
		ಆದರೆ ((r = pump(server, client, &sn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((r = pump(client, server, &cn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (server->kex->ಮುಗಿದ && client->kex->ಮುಗಿದ)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (cn == 0 && sn == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
}

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ರಚನೆ sshbuf *cfg = ಖಾಲಿ;

ಪೂರ್ಣಾಂಕ auth_rhosts2(ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *client_user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ipaddr) { (ಶೂನ್ಯ)pw;
    (ಶೂನ್ಯ)client_user; (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ipaddr; ಹಿಂತಿರುಗಿ 0; }
ಪೂರ್ಣಾಂಕ platform_locked_account(ರಚನೆ passwd *pw) { (ಶೂನ್ಯ)pw; ಹಿಂತಿರುಗಿ 0; }
ಶೂನ್ಯ ದಾಖಲೆ_failed_login(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttyname) { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)user;
    (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ttyname; }
ಪೂರ್ಣಾಂಕ temporarily_use_uid(ರಚನೆ passwd *pw) { (ಶೂನ್ಯ)pw; ಹಿಂತಿರುಗಿ 0; }
ಶೂನ್ಯ restore_uid(ಶೂನ್ಯ) { }
ಅಕ್ಷರ *mm_auth2_read_banner(ಶೂನ್ಯ) { ಹಿಂತಿರುಗಿ ಖಾಲಿ; }
ರಚನೆ connection_info *
server_get_connection_info(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ populate, ಪೂರ್ಣಾಂಕ use_dns)
    { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)populate; (ಶೂನ್ಯ)use_dns; ಹಿಂತಿರುಗಿ ಖಾಲಿ; }
ಶೂನ್ಯ server_process_permitopen(ರಚನೆ ssh *ssh) { (ಶೂನ್ಯ)ssh; }
ಶೂನ್ಯ server_process_channel_timeouts(ರಚನೆ ssh *ssh) { (ಶೂನ್ಯ)ssh; }

#ಅನ್ತರ್ಭಾವ "../../../auth2.c"

ಸ್ಥಿರ ರಚನೆ ssh *g_client = ಖಾಲಿ;
ಸ್ಥಿರ ರಚನೆ ssh *g_server = ಖಾಲಿ;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_init = 0;
ಸ್ಥಿರ Authctxt g_authctxt;

ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_reset_authctxt(ರಚನೆ ssh *ssh)
{
	ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ i;

	ಬಿಡುಗಡೆ(g_authctxt.user);
	ಬಿಡುಗಡೆ(g_authctxt.service);
	ಬಿಡುಗಡೆ(g_authctxt.style);
	ಬಿಡುಗಡೆ(g_authctxt.auth_ವಿಧಾನ_info);
	ಆದರೆ (g_authctxt.auth_methods != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; i < g_authctxt.ಅಂಕೆ_auth_methods; i++)
			ಬಿಡುಗಡೆ(g_authctxt.auth_methods[i]);
		ಬಿಡುಗಡೆ(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_ವಿಧಾನ_ಕೀಲಿ);
	ಗಾಗಿ (i = 0; i < g_authctxt.nprev_ಕೀಲಿಗಳು; i++)
		sshkey_free(g_authctxt.prev_ಕೀಲಿಗಳು[i]);
	ಬಿಡುಗಡೆ(g_authctxt.prev_ಕೀಲಿಗಳು);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, ಗಾತ್ರ(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
init_once(ಶೂನ್ಯ)
{
	ಆದರೆ (g_init)
		ಹಿಂತಿರುಗಿ 0;
	ಸಂಕೇತ(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ಗಾತ್ರ(g_fake_pw));
	g_fake_pw.pw_name = (ಅಕ್ಷರ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ಅಕ್ಷರ *)"/tmp";
	g_fake_pw.pw_shell = (ಅಕ್ಷರ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	ರಚನೆ sshkey *priv = ತುಂಬು_ಖಾಸಗಿ(PRIV_ED25519);
	ರಚನೆ sshkey *pub = ತುಂಬು_ಬಹಿರಂಗ(PUB_ED25519);
	ಅಕ್ಷರ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p = defaults[i];
		ಆದರೆ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ರಚನೆ kex_params kp;
	ಸ್ಮರಣೆ_ನಕಲು(kp.proposal, proposal, ಗಾತ್ರ(proposal));

	ಆದರೆ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ssh_ಕೂಡಿಸು_hostkey(g_server, priv) != 0 ||
	    ssh_ಕೂಡಿಸು_hostkey(g_client, pub) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ಸತತ_kex(g_client, g_server) != 0)
		ಹಿಂತಿರುಗಿ -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_ಗಣ(g_server, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
	    &ಒಳಹರಿವು_userauth_request);

	ಬಿಡುಗಡೆ(keyname);
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(proposal[i]);
	g_init = 1;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
fuzz_userauth_one(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (init_once() != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಗಾತ್ರ_2 > 65000)
		ಹಿಂತಿರುಗಿ;

	fuzz_reset_authctxt(g_server);

	ಒಳ_fuzz = 1;
	ಆದರೆ (setjmp(fuzz_env) == 0) {
		ಗಾತ್ರ_t transferred;
		ಆದರೆ (ssh_packet_put(g_client, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
		    ದತ್ತಾಂಶ, ಗಾತ್ರ_2) != 0)
			ಹೋಗು ಮುಗಿದ;
		ಆದರೆ (pump(g_client, g_server, &transferred) != 0)
			ಹೋಗು ಮುಗಿದ;
		(ಶೂನ್ಯ)ssh_dispatch_ಸತತ(g_server, DISPATCH_NONBLOCK, ಖಾಲಿ);
	ಮುಗಿದ:
		;
	}
	ಒಳ_fuzz = 0;
}
