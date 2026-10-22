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

#شامل <setjmp.h>
#شامل <signal.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <pwd.h>
#شامل <sys/types.h>

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
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "servconf.h"
#شامل "audit.h"

ServerOptions options;
ساختار sshbuf *loginmsg = پوچ;
ساختار include_list includes;
ساختار sshauthopt *auth_opts = پوچ;
ساختار passwd *privsep_pw = پوچ;

ایستا jmp_buf fuzz_env;
ایستا فرار صحیح in_fuzz = 0;

تهی
cleanup_exit(صحیح code)
{
	اگر (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

صحیح
__wrap_ssh_packet_write_wait(ساختار ssh *ssh)
{
	(تهی)ssh;
	بازگشت 0;
}

ایستا ساختار passwd g_fake_pw;

صحیح
mm_is_monitor(تهی)
{
	بازگشت 0;
}

ساختار passwd *
mm_getpwnamallow(ساختار ssh *ssh, ثابت نویسه *user)
{
	(تهی)ssh;
	(تهی)user;
	بازگشت &g_fake_pw;
}

صحیح
mm_auth_password(ساختار ssh *ssh, نویسه *password)
{
	(تهی)ssh;
	(تهی)password;
	بازگشت 0;
}

صحیح
mm_user_کلید_allowed(ساختار ssh *ssh, ساختار passwd *pw, ساختار sshkey *کلید,
    صحیح auth_attempt, ساختار sshauthopt **authoptsp)
{
	(تهی)ssh;
	(تهی)pw;
	(تهی)کلید;
	(تهی)auth_attempt;
	(تهی)authoptsp;
	بازگشت 0;
}

صحیح
mm_hostbased_کلید_allowed(ساختار ssh *ssh, ساختار passwd *pw, ثابت نویسه *user,
    ثابت نویسه *host, ساختار sshkey *کلید)
{
	(تهی)ssh;
	(تهی)pw;
	(تهی)user;
	(تهی)host;
	(تهی)کلید;
	بازگشت 0;
}

صحیح
mm_sshkey_verify(ثابت ساختار sshkey *کلید, ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t datalen, ثابت نویسه *alg, u_int compat,
    ساختار sshkey_sig_details **detailsp)
{
	بازگشت sshkey_verify(کلید, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

تهی
mm_inform_authserv(نویسه *service, نویسه *style)
{
	(تهی)service;
	(تهی)style;
}

تهی
mm_audit_event(ساختار ssh *ssh, ssh_audit_event_t event)
{
	(تهی)ssh;
	(تهی)event;
}

تهی
mm_start_pam(ساختار ssh *ssh)
{
	(تهی)ssh;
}

صحیح
mm_do_pam_account(تهی)
{
	بازگشت 0;
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

#شامل "fixed-keys.h"

ساختار sshbuf *cfg = پوچ;

صحیح auth_rhosts2(ساختار passwd *pw, ثابت نویسه *client_user,
    ثابت نویسه *hostname, ثابت نویسه *ipaddr) { (تهی)pw;
    (تهی)client_user; (تهی)hostname; (تهی)ipaddr; بازگشت 0; }
صحیح platform_locked_account(ساختار passwd *pw) { (تهی)pw; بازگشت 0; }
تهی record_failed_login(ساختار ssh *ssh, ثابت نویسه *user,
    ثابت نویسه *hostname, ثابت نویسه *ttyname) { (تهی)ssh; (تهی)user;
    (تهی)hostname; (تهی)ttyname; }
صحیح temporarily_use_uid(ساختار passwd *pw) { (تهی)pw; بازگشت 0; }
تهی restore_uid(تهی) { }
نویسه *mm_auth2_read_banner(تهی) { بازگشت پوچ; }
ساختار connection_info *
server_get_connection_info(ساختار ssh *ssh, صحیح populate, صحیح use_dns)
    { (تهی)ssh; (تهی)populate; (تهی)use_dns; بازگشت پوچ; }
تهی server_process_permitopen(ساختار ssh *ssh) { (تهی)ssh; }
تهی server_process_channel_timeouts(ساختار ssh *ssh) { (تهی)ssh; }

#شامل "../../../auth2.c"

ایستا ساختار ssh *g_client = پوچ;
ایستا ساختار ssh *g_server = پوچ;
ایستا صحیح g_init = 0;
ایستا Authctxt g_authctxt;

ایستا تهی
fuzz_reset_authctxt(ساختار ssh *ssh)
{
	unsigned صحیح i;

	آزاد(g_authctxt.user);
	آزاد(g_authctxt.service);
	آزاد(g_authctxt.style);
	آزاد(g_authctxt.auth_method_info);
	اگر (g_authctxt.auth_methods != پوچ) {
		برای (i = 0; i < g_authctxt.رقم_auth_methods; i++)
			آزاد(g_authctxt.auth_methods[i]);
		آزاد(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_کلید);
	برای (i = 0; i < g_authctxt.nprev_کلیدها; i++)
		sshkey_free(g_authctxt.prev_کلیدها[i]);
	آزاد(g_authctxt.prev_کلیدها);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, اندازه(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

ایستا صحیح
init_once(تهی)
{
	اگر (g_init)
		بازگشت 0;
	سیگنال(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, اندازه(g_fake_pw));
	g_fake_pw.pw_name = (نویسه *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (نویسه *)"/tmp";
	g_fake_pw.pw_shell = (نویسه *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

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

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_پیام_USERAUTH_REQUEST,
	    &درون_داد_userauth_request);

	آزاد(keyname);
	برای (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	بازگشت 0;
}

تهی
fuzz_userauth_one(ثابت uint8_t *data, size_t size)
{
	اگر (init_once() != 0)
		بازگشت;
	اگر (size > 65000)
		بازگشت;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		size_t transferred;
		اگر (ssh_packet_put(g_client, SSH2_پیام_USERAUTH_REQUEST,
		    data, size) != 0)
			برو done;
		اگر (pump(g_client, g_server, &transferred) != 0)
			برو done;
		(تهی)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, پوچ);
	done:
		;
	}
	in_fuzz = 0;
}
