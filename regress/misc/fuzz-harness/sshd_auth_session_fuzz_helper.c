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

#অন্তর্ভাৱ <setjmp.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "ssh_api.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "myproposal.h"
#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "audit.h"

ServerOptions options;
সংরচনা sshbuf *loginmsg = রিক্ত;
সংরচনা include_list includes;
সংরচনা sshauthopt *auth_opts = রিক্ত;
সংরচনা passwd *privsep_pw = রিক্ত;

স্থির jmp_buf fuzz_env;
স্থির চঞ্চল পূর্ণাঙ্ক in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

পূর্ণাঙ্ক
__wrap_ssh_packet_write_wait(সংরচনা ssh *ssh)
{
	(শূন্য)ssh;
	ঘূৰাই 0;
}

স্থির সংরচনা passwd g_fake_pw;

পূর্ণাঙ্ক
mm_is_monitor(শূন্য)
{
	ঘূৰাই 0;
}

সংরচনা passwd *
mm_getpwnamallow(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *user)
{
	(শূন্য)ssh;
	(শূন্য)user;
	ঘূৰাই &g_fake_pw;
}

পূর্ণাঙ্ক
mm_auth_password(সংরচনা ssh *ssh, ৱর্ণ *password)
{
	(শূন্য)ssh;
	(শূন্য)password;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
mm_user_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *pw, সংরচনা sshkey *চাবি,
    পূর্ণাঙ্ক auth_attempt, সংরচনা sshauthopt **authoptsp)
{
	(শূন্য)ssh;
	(শূন্য)pw;
	(শূন্য)চাবি;
	(শূন্য)auth_attempt;
	(শূন্য)authoptsp;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
mm_hostbased_চাবি_allowed(সংরচনা ssh *ssh, সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *user,
    ধ্রুৱ ৱর্ণ *host, সংরচনা sshkey *চাবি)
{
	(শূন্য)ssh;
	(শূন্য)pw;
	(শূন্য)user;
	(শূন্য)host;
	(শূন্য)চাবি;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
mm_sshkey_verify(ধ্রুৱ সংরচনা sshkey *চাবি, ধ্রুৱ u_char *sig, size_t siglen,
    ধ্রুৱ u_char *data, size_t datalen, ধ্রুৱ ৱর্ণ *alg, u_int compat,
    সংরচনা sshkey_sig_details **detailsp)
{
	ঘূৰাই sshkey_verify(চাবি, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

শূন্য
mm_inform_authserv(ৱর্ণ *service, ৱর্ণ *style)
{
	(শূন্য)service;
	(শূন্য)style;
}

শূন্য
mm_audit_event(সংরচনা ssh *ssh, ssh_audit_event_t event)
{
	(শূন্য)ssh;
	(শূন্য)event;
}

শূন্য
mm_start_pam(সংরচনা ssh *ssh)
{
	(শূন্য)ssh;
}

পূর্ণাঙ্ক
mm_do_pam_account(শূন্য)
{
	ঘূৰাই 0;
}

স্থির সংরচনা sshkey *
load_private(ধ্রুৱ ৱর্ণ *str)
{
	সংরচনা sshbuf *b = sshbuf_from(str, strlen(str));
	সংরচনা sshkey *k = রিক্ত;
	যদি (b == রিক্ত || sshkey_parse_private_fileblob(b, "", &k, রিক্ত) != 0)
		abort();
	sshbuf_free(b);
	ঘূৰাই k;
}

স্থির সংরচনা sshkey *
load_public(ধ্রুৱ ৱর্ণ *str)
{
	ৱর্ণ *tmp, *cp;
	সংরচনা sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == রিক্ত)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ঘূৰাই k;
}

স্থির পূর্ণাঙ্ক
pump(সংরচনা ssh *from, সংরচনা ssh *to, size_t *transferred)
{
	ধ্রুৱ u_char *buf;
	size_t len;
	u_char type;
	পূর্ণাঙ্ক r;
	*transferred = 0;
	যদি ((r = ssh_packet_next(from, &type)) != 0)
		ঘূৰাই r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		ঘূৰাই 0;
	যদি ((r = ssh_প্ৰবেশ_append(to, buf, len)) != 0)
		ঘূৰাই r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		ঘূৰাই r;
	*transferred = len;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
run_kex(সংরচনা ssh *client, সংরচনা ssh *server)
{
	পূর্ণাঙ্ক r;
	size_t cn, sn;
	বাবে (পূর্ণাঙ্ক i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) ঘূৰাই r;
		যদি ((r = pump(client, server, &cn)) != 0) ঘূৰাই r;
		যদি (server->kex->done && client->kex->done)
			ঘূৰাই 0;
		যদি (cn == 0 && sn == 0)
			ঘূৰাই SSH_ERR_PROTOCOL_ERROR;
	}
	ঘূৰাই SSH_ERR_PROTOCOL_ERROR;
}

#অন্তর্ভাৱ "fixed-keys.h"

সংরচনা sshbuf *cfg = রিক্ত;

পূর্ণাঙ্ক auth_rhosts2(সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *client_user,
    ধ্রুৱ ৱর্ণ *hostname, ধ্রুৱ ৱর্ণ *ipaddr) { (শূন্য)pw;
    (শূন্য)client_user; (শূন্য)hostname; (শূন্য)ipaddr; ঘূৰাই 0; }
পূর্ণাঙ্ক platform_locked_account(সংরচনা passwd *pw) { (শূন্য)pw; ঘূৰাই 0; }
শূন্য record_failed_login(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *user,
    ধ্রুৱ ৱর্ণ *hostname, ধ্রুৱ ৱর্ণ *ttyname) { (শূন্য)ssh; (শূন্য)user;
    (শূন্য)hostname; (শূন্য)ttyname; }
পূর্ণাঙ্ক temporarily_use_uid(সংরচনা passwd *pw) { (শূন্য)pw; ঘূৰাই 0; }
শূন্য restore_uid(শূন্য) { }
ৱর্ণ *mm_auth2_read_banner(শূন্য) { ঘূৰাই রিক্ত; }
সংরচনা connection_info *
server_get_connection_info(সংরচনা ssh *ssh, পূর্ণাঙ্ক populate, পূর্ণাঙ্ক use_dns)
    { (শূন্য)ssh; (শূন্য)populate; (শূন্য)use_dns; ঘূৰাই রিক্ত; }
শূন্য server_process_permitopen(সংরচনা ssh *ssh) { (শূন্য)ssh; }
শূন্য server_process_channel_timeouts(সংরচনা ssh *ssh) { (শূন্য)ssh; }

#অন্তর্ভাৱ "../../../auth2.c"

স্থির সংরচনা ssh *g_client = রিক্ত;
স্থির সংরচনা ssh *g_server = রিক্ত;
স্থির পূর্ণাঙ্ক g_init = 0;
স্থির Authctxt g_authctxt;

স্থির শূন্য
fuzz_reset_authctxt(সংরচনা ssh *ssh)
{
	unsigned পূর্ণাঙ্ক i;

	মুক্ত(g_authctxt.user);
	মুক্ত(g_authctxt.service);
	মুক্ত(g_authctxt.style);
	মুক্ত(g_authctxt.auth_method_info);
	যদি (g_authctxt.auth_methods != রিক্ত) {
		বাবে (i = 0; i < g_authctxt.অঙ্ক_auth_methods; i++)
			মুক্ত(g_authctxt.auth_methods[i]);
		মুক্ত(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_চাবি);
	বাবে (i = 0; i < g_authctxt.nprev_চাবিগুলি; i++)
		sshkey_free(g_authctxt.prev_চাবিগুলি[i]);
	মুক্ত(g_authctxt.prev_চাবিগুলি);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, পরিমাণ(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

স্থির পূর্ণাঙ্ক
init_once(শূন্য)
{
	যদি (g_init)
		ঘূৰাই 0;
	সঙ্কেত(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, পরিমাণ(g_fake_pw));
	g_fake_pw.pw_name = (ৱর্ণ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ৱর্ণ *)"/tmp";
	g_fake_pw.pw_shell = (ৱর্ণ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	সংরচনা sshkey *priv = load_private(PRIV_ED25519);
	সংরচনা sshkey *pub = load_public(PUB_ED25519);
	ৱর্ণ *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুৱ ৱর্ণ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ৱর্ণ *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণাঙ্ক i;
	বাবে (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুৱ ৱর্ণ *p = defaults[i];
		যদি (i == PROPOSAL_SERVER_HOST_চাবি_ALGS)
			p = keyname;
		অন্যথা যদি (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		অন্যথা যদি (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		অন্যথা যদি (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	সংরচনা kex_params kp;
	memcpy(kp.proposal, proposal, পরিমাণ(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ঘূৰাই -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ঘূৰাই -1;
	যদি (run_kex(g_client, g_server) != 0)
		ঘূৰাই -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_বাৰ্তা_USERAUTH_REQUEST,
	    &প্ৰবেশ_userauth_request);

	মুক্ত(keyname);
	বাবে (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	ঘূৰাই 0;
}

শূন্য
fuzz_userauth_one(ধ্রুৱ uint8_t *data, size_t size)
{
	যদি (init_once() != 0)
		ঘূৰাই;
	যদি (size > 65000)
		ঘূৰাই;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		size_t transferred;
		যদি (ssh_packet_put(g_client, SSH2_বাৰ্তা_USERAUTH_REQUEST,
		    data, size) != 0)
			গচ্ছ done;
		যদি (pump(g_client, g_server, &transferred) != 0)
			গচ্ছ done;
		(শূন্য)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, রিক্ত);
	done:
		;
	}
	in_fuzz = 0;
}
