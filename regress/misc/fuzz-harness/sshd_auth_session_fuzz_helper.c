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

#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "audit.h"

ServerOptions options;
ഘടന sshbuf *loginmsg = ശൂന്യ;
ഘടന include_list includes;
ഘടന sshauthopt *auth_opts = ശൂന്യ;
ഘടന passwd *privsep_pw = ശൂന്യ;

സ്ഥിതം jmp_buf fuzz_env;
സ്ഥിതം അസ്ഥിര പൂർണ്ണസംഖ്യ in_fuzz = 0;

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

പൂർണ്ണസംഖ്യ
__wrap_ssh_packet_write_wait(ഘടന ssh *ssh)
{
	(ശൂന്യം)ssh;
	തിരികെ 0;
}

സ്ഥിതം ഘടന passwd g_fake_pw;

പൂർണ്ണസംഖ്യ
mm_is_monitor(ശൂന്യം)
{
	തിരികെ 0;
}

ഘടന passwd *
mm_getpwnamallow(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *user)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)user;
	തിരികെ &g_fake_pw;
}

പൂർണ്ണസംഖ്യ
mm_auth_password(ഘടന ssh *ssh, അക്ഷരം *password)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)password;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
mm_user_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *pw, ഘടന sshkey *താക്കോൽ,
    പൂർണ്ണസംഖ്യ auth_attempt, ഘടന sshauthopt **authoptsp)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)pw;
	(ശൂന്യം)താക്കോൽ;
	(ശൂന്യം)auth_attempt;
	(ശൂന്യം)authoptsp;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
mm_hostbased_താക്കോൽ_allowed(ഘടന ssh *ssh, ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *user,
    സ്ഥിരം അക്ഷരം *host, ഘടന sshkey *താക്കോൽ)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)pw;
	(ശൂന്യം)user;
	(ശൂന്യം)host;
	(ശൂന്യം)താക്കോൽ;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
mm_sshkey_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ, സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t datalen, സ്ഥിരം അക്ഷരം *alg, u_int compat,
    ഘടന sshkey_sig_details **detailsp)
{
	തിരികെ sshkey_verify(താക്കോൽ, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

ശൂന്യം
mm_inform_authserv(അക്ഷരം *service, അക്ഷരം *style)
{
	(ശൂന്യം)service;
	(ശൂന്യം)style;
}

ശൂന്യം
mm_audit_event(ഘടന ssh *ssh, ssh_audit_event_t event)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)event;
}

ശൂന്യം
mm_start_pam(ഘടന ssh *ssh)
{
	(ശൂന്യം)ssh;
}

പൂർണ്ണസംഖ്യ
mm_do_pam_account(ശൂന്യം)
{
	തിരികെ 0;
}

സ്ഥിതം ഘടന sshkey *
load_private(സ്ഥിരം അക്ഷരം *str)
{
	ഘടന sshbuf *b = sshbuf_from(str, strlen(str));
	ഘടന sshkey *k = ശൂന്യ;
	എങ്കിൽ (b == ശൂന്യ || sshkey_parse_private_fileblob(b, "", &k, ശൂന്യ) != 0)
		abort();
	sshbuf_free(b);
	തിരികെ k;
}

സ്ഥിതം ഘടന sshkey *
load_public(സ്ഥിരം അക്ഷരം *str)
{
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *k = sshkey_new(താക്കോൽ_UNSPEC);
	എങ്കിൽ (k == ശൂന്യ)
		abort();
	tmp = cp = strdup(str);
	എങ്കിൽ (sshkey_read(k, &cp) != 0)
		abort();
	സ്വതന്ത്രം(tmp);
	തിരികെ k;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pump(ഘടന ssh *from, ഘടന ssh *to, size_t *transferred)
{
	സ്ഥിരം u_char *buf;
	size_t len;
	u_char type;
	പൂർണ്ണസംഖ്യ r;
	*transferred = 0;
	എങ്കിൽ ((r = ssh_packet_next(from, &type)) != 0)
		തിരികെ r;
	buf = ssh_output_ptr(from, &len);
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ ((r = ssh_നിവേശം_append(to, buf, len)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = ssh_output_consume(from, len)) != 0)
		തിരികെ r;
	*transferred = len;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
run_kex(ഘടന ssh *client, ഘടന ssh *server)
{
	പൂർണ്ണസംഖ്യ r;
	size_t cn, sn;
	വേണ്ടി (പൂർണ്ണസംഖ്യ i = 0; i < 100; i++) {
		എങ്കിൽ ((r = pump(server, client, &sn)) != 0) തിരികെ r;
		എങ്കിൽ ((r = pump(client, server, &cn)) != 0) തിരികെ r;
		എങ്കിൽ (server->kex->done && client->kex->done)
			തിരികെ 0;
		എങ്കിൽ (cn == 0 && sn == 0)
			തിരികെ SSH_ERR_PROTOCOL_ERROR;
	}
	തിരികെ SSH_ERR_PROTOCOL_ERROR;
}

#അന്തര്ഭാവ "fixed-keys.h"

ഘടന sshbuf *cfg = ശൂന്യ;

പൂർണ്ണസംഖ്യ auth_rhosts2(ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *client_user,
    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *ipaddr) { (ശൂന്യം)pw;
    (ശൂന്യം)client_user; (ശൂന്യം)hostname; (ശൂന്യം)ipaddr; തിരികെ 0; }
പൂർണ്ണസംഖ്യ platform_locked_account(ഘടന passwd *pw) { (ശൂന്യം)pw; തിരികെ 0; }
ശൂന്യം record_failed_login(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *user,
    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *ttyname) { (ശൂന്യം)ssh; (ശൂന്യം)user;
    (ശൂന്യം)hostname; (ശൂന്യം)ttyname; }
പൂർണ്ണസംഖ്യ temporarily_use_uid(ഘടന passwd *pw) { (ശൂന്യം)pw; തിരികെ 0; }
ശൂന്യം restore_uid(ശൂന്യം) { }
അക്ഷരം *mm_auth2_read_banner(ശൂന്യം) { തിരികെ ശൂന്യ; }
ഘടന connection_info *
server_get_connection_info(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ populate, പൂർണ്ണസംഖ്യ use_dns)
    { (ശൂന്യം)ssh; (ശൂന്യം)populate; (ശൂന്യം)use_dns; തിരികെ ശൂന്യ; }
ശൂന്യം server_process_permitopen(ഘടന ssh *ssh) { (ശൂന്യം)ssh; }
ശൂന്യം server_process_channel_timeouts(ഘടന ssh *ssh) { (ശൂന്യം)ssh; }

#അന്തര്ഭാവ "../../../auth2.c"

സ്ഥിതം ഘടന ssh *g_client = ശൂന്യ;
സ്ഥിതം ഘടന ssh *g_server = ശൂന്യ;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_init = 0;
സ്ഥിതം Authctxt g_authctxt;

സ്ഥിതം ശൂന്യം
fuzz_reset_authctxt(ഘടന ssh *ssh)
{
	unsigned പൂർണ്ണസംഖ്യ i;

	സ്വതന്ത്രം(g_authctxt.user);
	സ്വതന്ത്രം(g_authctxt.service);
	സ്വതന്ത്രം(g_authctxt.style);
	സ്വതന്ത്രം(g_authctxt.auth_method_info);
	എങ്കിൽ (g_authctxt.auth_methods != ശൂന്യ) {
		വേണ്ടി (i = 0; i < g_authctxt.അക്കം_auth_methods; i++)
			സ്വതന്ത്രം(g_authctxt.auth_methods[i]);
		സ്വതന്ത്രം(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_താക്കോൽ);
	വേണ്ടി (i = 0; i < g_authctxt.nprev_താക്കോലുകൾ; i++)
		sshkey_free(g_authctxt.prev_താക്കോലുകൾ[i]);
	സ്വതന്ത്രം(g_authctxt.prev_താക്കോലുകൾ);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, വലുപ്പം(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
init_once(ശൂന്യം)
{
	എങ്കിൽ (g_init)
		തിരികെ 0;
	സൂചന(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, വലുപ്പം(g_fake_pw));
	g_fake_pw.pw_name = (അക്ഷരം *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (അക്ഷരം *)"/tmp";
	g_fake_pw.pw_shell = (അക്ഷരം *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	ഘടന sshkey *priv = load_private(PRIV_ED25519);
	ഘടന sshkey *pub = load_public(PUB_ED25519);
	അക്ഷരം *keyname = xstrdup(sshkey_ssh_name(priv));

	സ്ഥിരം അക്ഷരം *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *proposal[PROPOSAL_MAX] = { 0 };
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		സ്ഥിരം അക്ഷരം *p = defaults[i];
		എങ്കിൽ (i == PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS)
			p = keyname;
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ഘടന kex_params kp;
	memcpy(kp.proposal, proposal, വലുപ്പം(proposal));

	എങ്കിൽ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		തിരികെ -1;
	എങ്കിൽ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		തിരികെ -1;
	എങ്കിൽ (run_kex(g_client, g_server) != 0)
		തിരികെ -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_സന്ദേശം_USERAUTH_REQUEST,
	    &നിവേശം_userauth_request);

	സ്വതന്ത്രം(keyname);
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(proposal[i]);
	g_init = 1;
	തിരികെ 0;
}

ശൂന്യം
fuzz_userauth_one(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (init_once() != 0)
		തിരികെ;
	എങ്കിൽ (size > 65000)
		തിരികെ;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	എങ്കിൽ (setjmp(fuzz_env) == 0) {
		size_t transferred;
		എങ്കിൽ (ssh_packet_put(g_client, SSH2_സന്ദേശം_USERAUTH_REQUEST,
		    data, size) != 0)
			പോകുക done;
		എങ്കിൽ (pump(g_client, g_server, &transferred) != 0)
			പോകുക done;
		(ശൂന്യം)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ശൂന്യ);
	done:
		;
	}
	in_fuzz = 0;
}
