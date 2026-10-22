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

#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "audit.h"

ServerOptions options;
સંરચના sshbuf *loginmsg = ખાલી;
સંરચના include_list includes;
સંરચના sshauthopt *auth_opts = ખાલી;
સંરચના passwd *privsep_pw = ખાલી;

સ્થિર jmp_buf fuzz_env;
સ્થિર અસ્થિર પૂર્ણાંક in_fuzz = 0;

શૂન્ય
cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

પૂર્ણાંક
__wrap_ssh_packet_write_wait(સંરચના ssh *ssh)
{
	(શૂન્ય)ssh;
	પાછા 0;
}

સ્થિર સંરચના passwd g_fake_pw;

પૂર્ણાંક
mm_is_monitor(શૂન્ય)
{
	પાછા 0;
}

સંરચના passwd *
mm_getpwnamallow(સંરચના ssh *ssh, અચલ અક્ષર *user)
{
	(શૂન્ય)ssh;
	(શૂન્ય)user;
	પાછા &g_fake_pw;
}

પૂર્ણાંક
mm_auth_password(સંરચના ssh *ssh, અક્ષર *password)
{
	(શૂન્ય)ssh;
	(શૂન્ય)password;
	પાછા 0;
}

પૂર્ણાંક
mm_user_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *pw, સંરચના sshkey *ચાવી,
    પૂર્ણાંક auth_attempt, સંરચના sshauthopt **authoptsp)
{
	(શૂન્ય)ssh;
	(શૂન્ય)pw;
	(શૂન્ય)ચાવી;
	(શૂન્ય)auth_attempt;
	(શૂન્ય)authoptsp;
	પાછા 0;
}

પૂર્ણાંક
mm_hostbased_ચાવી_allowed(સંરચના ssh *ssh, સંરચના passwd *pw, અચલ અક્ષર *user,
    અચલ અક્ષર *host, સંરચના sshkey *ચાવી)
{
	(શૂન્ય)ssh;
	(શૂન્ય)pw;
	(શૂન્ય)user;
	(શૂન્ય)host;
	(શૂન્ય)ચાવી;
	પાછા 0;
}

પૂર્ણાંક
mm_sshkey_verify(અચલ સંરચના sshkey *ચાવી, અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t datalen, અચલ અક્ષર *alg, u_int compat,
    સંરચના sshkey_sig_details **detailsp)
{
	પાછા sshkey_verify(ચાવી, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

શૂન્ય
mm_inform_authserv(અક્ષર *service, અક્ષર *style)
{
	(શૂન્ય)service;
	(શૂન્ય)style;
}

શૂન્ય
mm_audit_event(સંરચના ssh *ssh, ssh_audit_event_t event)
{
	(શૂન્ય)ssh;
	(શૂન્ય)event;
}

શૂન્ય
mm_start_pam(સંરચના ssh *ssh)
{
	(શૂન્ય)ssh;
}

પૂર્ણાંક
mm_do_pam_account(શૂન્ય)
{
	પાછા 0;
}

સ્થિર સંરચના sshkey *
load_private(અચલ અક્ષર *str)
{
	સંરચના sshbuf *b = sshbuf_from(str, strlen(str));
	સંરચના sshkey *k = ખાલી;
	જો (b == ખાલી || sshkey_parse_private_fileblob(b, "", &k, ખાલી) != 0)
		abort();
	sshbuf_free(b);
	પાછા k;
}

સ્થિર સંરચના sshkey *
load_public(અચલ અક્ષર *str)
{
	અક્ષર *tmp, *cp;
	સંરચના sshkey *k = sshkey_new(ચાવી_UNSPEC);
	જો (k == ખાલી)
		abort();
	tmp = cp = strdup(str);
	જો (sshkey_read(k, &cp) != 0)
		abort();
	મુક્ત(tmp);
	પાછા k;
}

સ્થિર પૂર્ણાંક
pump(સંરચના ssh *from, સંરચના ssh *to, size_t *transferred)
{
	અચલ u_char *buf;
	size_t len;
	u_char type;
	પૂર્ણાંક r;
	*transferred = 0;
	જો ((r = ssh_packet_next(from, &type)) != 0)
		પાછા r;
	buf = ssh_output_ptr(from, &len);
	જો (len == 0)
		પાછા 0;
	જો ((r = ssh_આગત_append(to, buf, len)) != 0)
		પાછા r;
	જો ((r = ssh_output_consume(from, len)) != 0)
		પાછા r;
	*transferred = len;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
run_kex(સંરચના ssh *client, સંરચના ssh *server)
{
	પૂર્ણાંક r;
	size_t cn, sn;
	માટે (પૂર્ણાંક i = 0; i < 100; i++) {
		જો ((r = pump(server, client, &sn)) != 0) પાછા r;
		જો ((r = pump(client, server, &cn)) != 0) પાછા r;
		જો (server->kex->done && client->kex->done)
			પાછા 0;
		જો (cn == 0 && sn == 0)
			પાછા SSH_ERR_PROTOCOL_ERROR;
	}
	પાછા SSH_ERR_PROTOCOL_ERROR;
}

#અન્તર્ભાવ "fixed-keys.h"

સંરચના sshbuf *cfg = ખાલી;

પૂર્ણાંક auth_rhosts2(સંરચના passwd *pw, અચલ અક્ષર *client_user,
    અચલ અક્ષર *hostname, અચલ અક્ષર *ipaddr) { (શૂન્ય)pw;
    (શૂન્ય)client_user; (શૂન્ય)hostname; (શૂન્ય)ipaddr; પાછા 0; }
પૂર્ણાંક platform_locked_account(સંરચના passwd *pw) { (શૂન્ય)pw; પાછા 0; }
શૂન્ય record_failed_login(સંરચના ssh *ssh, અચલ અક્ષર *user,
    અચલ અક્ષર *hostname, અચલ અક્ષર *ttyname) { (શૂન્ય)ssh; (શૂન્ય)user;
    (શૂન્ય)hostname; (શૂન્ય)ttyname; }
પૂર્ણાંક temporarily_use_uid(સંરચના passwd *pw) { (શૂન્ય)pw; પાછા 0; }
શૂન્ય restore_uid(શૂન્ય) { }
અક્ષર *mm_auth2_read_banner(શૂન્ય) { પાછા ખાલી; }
સંરચના connection_info *
server_get_connection_info(સંરચના ssh *ssh, પૂર્ણાંક populate, પૂર્ણાંક use_dns)
    { (શૂન્ય)ssh; (શૂન્ય)populate; (શૂન્ય)use_dns; પાછા ખાલી; }
શૂન્ય server_process_permitopen(સંરચના ssh *ssh) { (શૂન્ય)ssh; }
શૂન્ય server_process_channel_timeouts(સંરચના ssh *ssh) { (શૂન્ય)ssh; }

#અન્તર્ભાવ "../../../auth2.c"

સ્થિર સંરચના ssh *g_client = ખાલી;
સ્થિર સંરચના ssh *g_server = ખાલી;
સ્થિર પૂર્ણાંક g_init = 0;
સ્થિર Authctxt g_authctxt;

સ્થિર શૂન્ય
fuzz_reset_authctxt(સંરચના ssh *ssh)
{
	unsigned પૂર્ણાંક i;

	મુક્ત(g_authctxt.user);
	મુક્ત(g_authctxt.service);
	મુક્ત(g_authctxt.style);
	મુક્ત(g_authctxt.auth_method_info);
	જો (g_authctxt.auth_methods != ખાલી) {
		માટે (i = 0; i < g_authctxt.અંક_auth_methods; i++)
			મુક્ત(g_authctxt.auth_methods[i]);
		મુક્ત(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_ચાવી);
	માટે (i = 0; i < g_authctxt.nprev_ચાવીઓ; i++)
		sshkey_free(g_authctxt.prev_ચાવીઓ[i]);
	મુક્ત(g_authctxt.prev_ચાવીઓ);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, કદ(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

સ્થિર પૂર્ણાંક
init_once(શૂન્ય)
{
	જો (g_init)
		પાછા 0;
	સંકેત(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, કદ(g_fake_pw));
	g_fake_pw.pw_name = (અક્ષર *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (અક્ષર *)"/tmp";
	g_fake_pw.pw_shell = (અક્ષર *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	સંરચના sshkey *priv = load_private(PRIV_ED25519);
	સંરચના sshkey *pub = load_public(PUB_ED25519);
	અક્ષર *keyname = xstrdup(sshkey_ssh_name(priv));

	અચલ અક્ષર *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *proposal[PROPOSAL_MAX] = { 0 };
	પૂર્ણાંક i;
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		અચલ અક્ષર *p = defaults[i];
		જો (i == PROPOSAL_SERVER_HOST_ચાવી_ALGS)
			p = keyname;
		નહીંતર જો (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		નહીંતર જો (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		નહીંતર જો (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	સંરચના kex_params kp;
	memcpy(kp.proposal, proposal, કદ(proposal));

	જો (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		પાછા -1;
	જો (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		પાછા -1;
	જો (run_kex(g_client, g_server) != 0)
		પાછા -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_સંદેશ_USERAUTH_REQUEST,
	    &આગત_userauth_request);

	મુક્ત(keyname);
	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(proposal[i]);
	g_init = 1;
	પાછા 0;
}

શૂન્ય
fuzz_userauth_one(અચલ uint8_t *data, size_t size)
{
	જો (init_once() != 0)
		પાછા;
	જો (size > 65000)
		પાછા;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	જો (setjmp(fuzz_env) == 0) {
		size_t transferred;
		જો (ssh_packet_put(g_client, SSH2_સંદેશ_USERAUTH_REQUEST,
		    data, size) != 0)
			જાઓ done;
		જો (pump(g_client, g_server, &transferred) != 0)
			જાઓ done;
		(શૂન્ય)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ખાલી);
	done:
		;
	}
	in_fuzz = 0;
}
