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
ಸಂರಚನಾ sshbuf *loginmsg = ರಿಕ್ತ;
ಸಂರಚನಾ include_list includes;
ಸಂರಚನಾ sshauthopt *auth_opts = ರಿಕ್ತ;
ಸಂರಚನಾ passwd *privsep_pw = ರಿಕ್ತ;

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಚಞ್ಚಲ ಪೂರ್ಣಾಙ್ಕ in_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ code)
{
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_ssh_packet_write_wait(ಸಂರಚನಾ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ passwd g_fake_pw;

ಪೂರ್ಣಾಙ್ಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸಂರಚನಾ passwd *
mm_getpwnamallow(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *user)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)user;
	ಪ್ರತ್ಯಾಗಮ &g_fake_pw;
}

ಪೂರ್ಣಾಙ್ಕ
mm_auth_password(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *password)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)password;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
mm_user_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಪೂರ್ಣಾಙ್ಕ auth_attempt, ಸಂರಚನಾ sshauthopt **authoptsp)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)pw;
	(ಶೂನ್ಯ)ಕೀಲಿ;
	(ಶೂನ್ಯ)auth_attempt;
	(ಶೂನ್ಯ)authoptsp;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
mm_hostbased_ಕೀಲಿ_allowed(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *user,
    ಧ್ರುವ ವರ್ಣ *host, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)pw;
	(ಶೂನ್ಯ)user;
	(ಶೂನ್ಯ)host;
	(ಶೂನ್ಯ)ಕೀಲಿ;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
mm_sshkey_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ u_char *data, size_t datalen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat,
    ಸಂರಚನಾ sshkey_sig_details **detailsp)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_verify(ಕೀಲಿ, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

ಶೂನ್ಯ
mm_inform_authserv(ವರ್ಣ *service, ವರ್ಣ *style)
{
	(ಶೂನ್ಯ)service;
	(ಶೂನ್ಯ)style;
}

ಶೂನ್ಯ
mm_audit_event(ಸಂರಚನಾ ssh *ssh, ssh_audit_event_t event)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)event;
}

ಶೂನ್ಯ
mm_start_pam(ಸಂರಚನಾ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh;
}

ಪೂರ್ಣಾಙ್ಕ
mm_do_pam_account(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_private(ಧ್ರುವ ವರ್ಣ *str)
{
	ಸಂರಚನಾ sshbuf *b = sshbuf_from(str, strlen(str));
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಯದಿ (b == ರಿಕ್ತ || sshkey_parse_private_fileblob(b, "", &k, ರಿಕ್ತ) != 0)
		abort();
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_public(ಧ್ರುವ ವರ್ಣ *str)
{
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಯದಿ (k == ರಿಕ್ತ)
		abort();
	tmp = cp = strdup(str);
	ಯದಿ (sshkey_read(k, &cp) != 0)
		abort();
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pump(ಸಂರಚನಾ ssh *from, ಸಂರಚನಾ ssh *to, size_t *transferred)
{
	ಧ್ರುವ u_char *buf;
	size_t len;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;
	*transferred = 0;
	ಯದಿ ((r = ssh_packet_next(from, &type)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	buf = ssh_output_ptr(from, &len);
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = ssh_ಒಳಹರಿವು_append(to, buf, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = ssh_output_consume(from, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	*transferred = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
run_kex(ಸಂರಚನಾ ssh *client, ಸಂರಚನಾ ssh *server)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t cn, sn;
	ಪ್ರತಿ (ಪೂರ್ಣಾಙ್ಕ i = 0; i < 100; i++) {
		ಯದಿ ((r = pump(server, client, &sn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((r = pump(client, server, &cn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (server->kex->done && client->kex->done)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ (cn == 0 && sn == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
}

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ಸಂರಚನಾ sshbuf *cfg = ರಿಕ್ತ;

ಪೂರ್ಣಾಙ್ಕ auth_rhosts2(ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *client_user,
    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ipaddr) { (ಶೂನ್ಯ)pw;
    (ಶೂನ್ಯ)client_user; (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ipaddr; ಪ್ರತ್ಯಾಗಮ 0; }
ಪೂರ್ಣಾಙ್ಕ platform_locked_account(ಸಂರಚನಾ passwd *pw) { (ಶೂನ್ಯ)pw; ಪ್ರತ್ಯಾಗಮ 0; }
ಶೂನ್ಯ record_failed_login(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *user,
    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ttyname) { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)user;
    (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ttyname; }
ಪೂರ್ಣಾಙ್ಕ temporarily_use_uid(ಸಂರಚನಾ passwd *pw) { (ಶೂನ್ಯ)pw; ಪ್ರತ್ಯಾಗಮ 0; }
ಶೂನ್ಯ restore_uid(ಶೂನ್ಯ) { }
ವರ್ಣ *mm_auth2_read_banner(ಶೂನ್ಯ) { ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; }
ಸಂರಚನಾ connection_info *
server_get_connection_info(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ populate, ಪೂರ್ಣಾಙ್ಕ use_dns)
    { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)populate; (ಶೂನ್ಯ)use_dns; ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; }
ಶೂನ್ಯ server_process_permitopen(ಸಂರಚನಾ ssh *ssh) { (ಶೂನ್ಯ)ssh; }
ಶೂನ್ಯ server_process_channel_timeouts(ಸಂರಚನಾ ssh *ssh) { (ಶೂನ್ಯ)ssh; }

#ಅನ್ತರ್ಭಾವ "../../../auth2.c"

ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_client = ರಿಕ್ತ;
ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_server = ರಿಕ್ತ;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_init = 0;
ಸ್ಥಿರ Authctxt g_authctxt;

ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_reset_authctxt(ಸಂರಚನಾ ssh *ssh)
{
	unsigned ಪೂರ್ಣಾಙ್ಕ i;

	ಮುಕ್ತ(g_authctxt.user);
	ಮುಕ್ತ(g_authctxt.service);
	ಮುಕ್ತ(g_authctxt.style);
	ಮುಕ್ತ(g_authctxt.auth_method_info);
	ಯದಿ (g_authctxt.auth_methods != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; i < g_authctxt.ಅಂಕೆ_auth_methods; i++)
			ಮುಕ್ತ(g_authctxt.auth_methods[i]);
		ಮುಕ್ತ(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_ಕೀಲಿ);
	ಪ್ರತಿ (i = 0; i < g_authctxt.nprev_ಕೀಲಿಗಳು; i++)
		sshkey_free(g_authctxt.prev_ಕೀಲಿಗಳು[i]);
	ಮುಕ್ತ(g_authctxt.prev_ಕೀಲಿಗಳು);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, ಪರಿಮಾಣ(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
init_once(ಶೂನ್ಯ)
{
	ಯದಿ (g_init)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸಙ್ಕೇತ(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ಪರಿಮಾಣ(g_fake_pw));
	g_fake_pw.pw_name = (ವರ್ಣ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ವರ್ಣ *)"/tmp";
	g_fake_pw.pw_shell = (ವರ್ಣ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	ಸಂರಚನಾ sshkey *priv = load_private(PRIV_ED25519);
	ಸಂರಚನಾ sshkey *pub = load_public(PUB_ED25519);
	ವರ್ಣ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಧ್ರುವ ವರ್ಣ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಧ್ರುವ ವರ್ಣ *p = defaults[i];
		ಯದಿ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ಸಂರಚನಾ kex_params kp;
	memcpy(kp.proposal, proposal, ಪರಿಮಾಣ(proposal));

	ಯದಿ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (run_kex(g_client, g_server) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
	    &ಒಳಹರಿವು_userauth_request);

	ಮುಕ್ತ(keyname);
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(proposal[i]);
	g_init = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
fuzz_userauth_one(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (init_once() != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (size > 65000)
		ಪ್ರತ್ಯಾಗಮ;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	ಯದಿ (setjmp(fuzz_env) == 0) {
		size_t transferred;
		ಯದಿ (ssh_packet_put(g_client, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST,
		    data, size) != 0)
			ಗಚ್ಛ done;
		ಯದಿ (pump(g_client, g_server, &transferred) != 0)
			ಗಚ್ಛ done;
		(ಶೂನ್ಯ)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ರಿಕ್ತ);
	done:
		;
	}
	in_fuzz = 0;
}
