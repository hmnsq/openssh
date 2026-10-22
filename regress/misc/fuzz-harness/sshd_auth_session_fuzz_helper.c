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

#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "audit.h"

ServerOptions options;
কাঠামো sshbuf *loginmsg = ফাঁকা;
কাঠামো include_list includes;
কাঠামো sshauthopt *auth_opts = ফাঁকা;
কাঠামো passwd *privsep_pw = ফাঁকা;

স্থির jmp_buf fuzz_env;
স্থির অস্থির পূর্ণসংখ্যা in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

পূর্ণসংখ্যা
__wrap_ssh_packet_write_wait(কাঠামো ssh *ssh)
{
	(শূন্য)ssh;
	ফেরত 0;
}

স্থির কাঠামো passwd g_fake_pw;

পূর্ণসংখ্যা
mm_is_monitor(শূন্য)
{
	ফেরত 0;
}

কাঠামো passwd *
mm_getpwnamallow(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *user)
{
	(শূন্য)ssh;
	(শূন্য)user;
	ফেরত &g_fake_pw;
}

পূর্ণসংখ্যা
mm_auth_password(কাঠামো ssh *ssh, অক্ষর *password)
{
	(শূন্য)ssh;
	(শূন্য)password;
	ফেরত 0;
}

পূর্ণসংখ্যা
mm_user_চাবি_allowed(কাঠামো ssh *ssh, কাঠামো passwd *pw, কাঠামো sshkey *চাবি,
    পূর্ণসংখ্যা auth_attempt, কাঠামো sshauthopt **authoptsp)
{
	(শূন্য)ssh;
	(শূন্য)pw;
	(শূন্য)চাবি;
	(শূন্য)auth_attempt;
	(শূন্য)authoptsp;
	ফেরত 0;
}

পূর্ণসংখ্যা
mm_hostbased_চাবি_allowed(কাঠামো ssh *ssh, কাঠামো passwd *pw, ধ্রুবক অক্ষর *user,
    ধ্রুবক অক্ষর *host, কাঠামো sshkey *চাবি)
{
	(শূন্য)ssh;
	(শূন্য)pw;
	(শূন্য)user;
	(শূন্য)host;
	(শূন্য)চাবি;
	ফেরত 0;
}

পূর্ণসংখ্যা
mm_sshkey_verify(ধ্রুবক কাঠামো sshkey *চাবি, ধ্রুবক u_char *sig, আকার_t siglen,
    ধ্রুবক u_char *তথ্য, আকার_t datalen, ধ্রুবক অক্ষর *alg, u_int compat,
    কাঠামো sshkey_sig_details **detailsp)
{
	ফেরত sshkey_verify(চাবি, sig, siglen, তথ্য, datalen, alg, compat,
	    detailsp);
}

শূন্য
mm_inform_authserv(অক্ষর *service, অক্ষর *style)
{
	(শূন্য)service;
	(শূন্য)style;
}

শূন্য
mm_audit_event(কাঠামো ssh *ssh, ssh_audit_event_t event)
{
	(শূন্য)ssh;
	(শূন্য)event;
}

শূন্য
mm_start_pam(কাঠামো ssh *ssh)
{
	(শূন্য)ssh;
}

পূর্ণসংখ্যা
mm_do_pam_account(শূন্য)
{
	ফেরত 0;
}

স্থির কাঠামো sshkey *
load_private(ধ্রুবক অক্ষর *str)
{
	কাঠামো sshbuf *b = sshbuf_from(str, strlen(str));
	কাঠামো sshkey *k = ফাঁকা;
	যদি (b == ফাঁকা || sshkey_parse_private_fileblob(b, "", &k, ফাঁকা) != 0)
		abort();
	sshbuf_free(b);
	ফেরত k;
}

স্থির কাঠামো sshkey *
load_public(ধ্রুবক অক্ষর *str)
{
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == ফাঁকা)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ফেরত k;
}

স্থির পূর্ণসংখ্যা
pump(কাঠামো ssh *from, কাঠামো ssh *to, আকার_t *transferred)
{
	ধ্রুবক u_char *buf;
	আকার_t len;
	u_char type;
	পূর্ণসংখ্যা r;
	*transferred = 0;
	যদি ((r = ssh_packet_পরবর্তী(from, &type)) != 0)
		ফেরত r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		ফেরত 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		ফেরত r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		ফেরত r;
	*transferred = len;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
run_kex(কাঠামো ssh *client, কাঠামো ssh *server)
{
	পূর্ণসংখ্যা r;
	আকার_t cn, sn;
	জন্য (পূর্ণসংখ্যা i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) ফেরত r;
		যদি ((r = pump(client, server, &cn)) != 0) ফেরত r;
		যদি (server->kex->done && client->kex->done)
			ফেরত 0;
		যদি (cn == 0 && sn == 0)
			ফেরত SSH_ERR_PROTOCOL_ERROR;
	}
	ফেরত SSH_ERR_PROTOCOL_ERROR;
}

#অন্তর্ভাব "fixed-keys.h"

কাঠামো sshbuf *cfg = ফাঁকা;

পূর্ণসংখ্যা auth_rhosts2(কাঠামো passwd *pw, ধ্রুবক অক্ষর *client_user,
    ধ্রুবক অক্ষর *hostname, ধ্রুবক অক্ষর *ipaddr) { (শূন্য)pw;
    (শূন্য)client_user; (শূন্য)hostname; (শূন্য)ipaddr; ফেরত 0; }
পূর্ণসংখ্যা platform_locked_account(কাঠামো passwd *pw) { (শূন্য)pw; ফেরত 0; }
শূন্য record_failed_login(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *user,
    ধ্রুবক অক্ষর *hostname, ধ্রুবক অক্ষর *ttyname) { (শূন্য)ssh; (শূন্য)user;
    (শূন্য)hostname; (শূন্য)ttyname; }
পূর্ণসংখ্যা temporarily_use_uid(কাঠামো passwd *pw) { (শূন্য)pw; ফেরত 0; }
শূন্য restore_uid(শূন্য) { }
অক্ষর *mm_auth2_read_banner(শূন্য) { ফেরত ফাঁকা; }
কাঠামো connection_info *
server_get_connection_info(কাঠামো ssh *ssh, পূর্ণসংখ্যা populate, পূর্ণসংখ্যা use_dns)
    { (শূন্য)ssh; (শূন্য)populate; (শূন্য)use_dns; ফেরত ফাঁকা; }
শূন্য server_process_permitopen(কাঠামো ssh *ssh) { (শূন্য)ssh; }
শূন্য server_process_channel_timeouts(কাঠামো ssh *ssh) { (শূন্য)ssh; }

#অন্তর্ভাব "../../../auth2.c"

স্থির কাঠামো ssh *g_client = ফাঁকা;
স্থির কাঠামো ssh *g_server = ফাঁকা;
স্থির পূর্ণসংখ্যা g_init = 0;
স্থির Authctxt g_authctxt;

স্থির শূন্য
fuzz_reset_authctxt(কাঠামো ssh *ssh)
{
	unsigned পূর্ণসংখ্যা i;

	মুক্ত(g_authctxt.user);
	মুক্ত(g_authctxt.service);
	মুক্ত(g_authctxt.style);
	মুক্ত(g_authctxt.auth_method_info);
	যদি (g_authctxt.auth_methods != ফাঁকা) {
		জন্য (i = 0; i < g_authctxt.অঙ্ক_auth_methods; i++)
			মুক্ত(g_authctxt.auth_methods[i]);
		মুক্ত(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_চাবি);
	জন্য (i = 0; i < g_authctxt.nprev_চাবিগুলি; i++)
		sshkey_free(g_authctxt.পূর্ব_চাবিগুলি[i]);
	মুক্ত(g_authctxt.পূর্ব_চাবিগুলি);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, আকার(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

স্থির পূর্ণসংখ্যা
init_once(শূন্য)
{
	যদি (g_init)
		ফেরত 0;
	সংকেত(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, আকার(g_fake_pw));
	g_fake_pw.pw_name = (অক্ষর *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (অক্ষর *)"/tmp";
	g_fake_pw.pw_shell = (অক্ষর *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	কাঠামো sshkey *priv = load_private(PRIV_ED25519);
	কাঠামো sshkey *pub = load_public(PUB_ED25519);
	অক্ষর *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুবক অক্ষর *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	অক্ষর *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুবক অক্ষর *p = defaults[i];
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
	কাঠামো kex_params kp;
	memcpy(kp.proposal, proposal, আকার(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ফেরত -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ফেরত -1;
	যদি (run_kex(g_client, g_server) != 0)
		ফেরত -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_বার্তা_USERAUTH_REQUEST,
	    &প্রবেশ_userauth_request);

	মুক্ত(keyname);
	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	ফেরত 0;
}

শূন্য
fuzz_userauth_one(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (init_once() != 0)
		ফেরত;
	যদি (আকার_2 > 65000)
		ফেরত;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		আকার_t transferred;
		যদি (ssh_packet_put(g_client, SSH2_বার্তা_USERAUTH_REQUEST,
		    তথ্য, আকার_2) != 0)
			যাও done;
		যদি (pump(g_client, g_server, &transferred) != 0)
			যাও done;
		(শূন্য)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ফাঁকা);
	done:
		;
	}
	in_fuzz = 0;
}
