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
ساخت sshbuf *loginmsg = تہی;
ساخت include_list includes;
ساخت sshauthopt *auth_opts = تہی;
ساخت passwd *privsep_pw = تہی;

ساکن jmp_buf fuzz_env;
ساکن متلون صحیح اندر_fuzz = 0;

خالی
cleanup_exit(صحیح رمز)
{
	اگر (اندر_fuzz)
		longjmp(fuzz_env, رمز ? رمز : 1);
	_exit(رمز);
}

صحیح
__wrap_ssh_packet_write_wait(ساخت ssh *ssh)
{
	(خالی)ssh;
	واپس 0;
}

ساکن ساخت passwd g_fake_pw;

صحیح
mm_is_monitor(خالی)
{
	واپس 0;
}

ساخت passwd *
mm_getpwnamallow(ساخت ssh *ssh, ثابت حرف *user)
{
	(خالی)ssh;
	(خالی)user;
	واپس &g_fake_pw;
}

صحیح
mm_auth_password(ساخت ssh *ssh, حرف *password)
{
	(خالی)ssh;
	(خالی)password;
	واپس 0;
}

صحیح
mm_user_کلید_allowed(ساخت ssh *ssh, ساخت passwd *pw, ساخت sshkey *کلید,
    صحیح auth_attempt, ساخت sshauthopt **authoptsp)
{
	(خالی)ssh;
	(خالی)pw;
	(خالی)کلید;
	(خالی)auth_attempt;
	(خالی)authoptsp;
	واپس 0;
}

صحیح
mm_hostbased_کلید_allowed(ساخت ssh *ssh, ساخت passwd *pw, ثابت حرف *user,
    ثابت حرف *host, ساخت sshkey *کلید)
{
	(خالی)ssh;
	(خالی)pw;
	(خالی)user;
	(خالی)host;
	(خالی)کلید;
	واپس 0;
}

صحیح
mm_sshkey_verify(ثابت ساخت sshkey *کلید, ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t datalen, ثابت حرف *alg, u_int compat,
    ساخت sshkey_sig_details **detailsp)
{
	واپس sshkey_verify(کلید, sig, siglen, ڈیٹا, datalen, alg, compat,
	    detailsp);
}

خالی
mm_inform_authserv(حرف *service, حرف *style)
{
	(خالی)service;
	(خالی)style;
}

خالی
mm_audit_event(ساخت ssh *ssh, ssh_audit_event_t event)
{
	(خالی)ssh;
	(خالی)event;
}

خالی
mm_آغاز_pam(ساخت ssh *ssh)
{
	(خالی)ssh;
}

صحیح
mm_do_pam_account(خالی)
{
	واپس 0;
}

ساکن ساخت sshkey *
بھرو_نجی(ثابت حرف *str)
{
	ساخت sshbuf *b = sshbuf_from(str, لڑی_لمبائی(str));
	ساخت sshkey *k = تہی;
	اگر (b == تہی || sshkey_parse_نجی_fileblob(b, "", &k, تہی) != 0)
		abort();
	sshbuf_free(b);
	واپس k;
}

ساکن ساخت sshkey *
بھرو_عوامی(ثابت حرف *str)
{
	حرف *tmp, *cp;
	ساخت sshkey *k = sshkey_new(کلید_UNSPEC);
	اگر (k == تہی)
		abort();
	tmp = cp = strdup(str);
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	واپس k;
}

ساکن صحیح
pump(ساخت ssh *from, ساخت ssh *مقصد, سائز_t *transferred)
{
	ثابت u_char *buf;
	سائز_t len;
	u_char type;
	صحیح r;
	*transferred = 0;
	اگر ((r = ssh_packet_اگلا(from, &type)) != 0)
		واپس r;
	buf = ssh_output_ptr(from, &len);
	اگر (len == 0)
		واپس 0;
	اگر ((r = ssh_داخلہ_append(مقصد, buf, len)) != 0)
		واپس r;
	اگر ((r = ssh_output_consume(from, len)) != 0)
		واپس r;
	*transferred = len;
	واپس 0;
}

ساکن صحیح
تسلسل_kex(ساخت ssh *client, ساخت ssh *server)
{
	صحیح r;
	سائز_t cn, sn;
	برائے (صحیح i = 0; i < 100; i++) {
		اگر ((r = pump(server, client, &sn)) != 0) واپس r;
		اگر ((r = pump(client, server, &cn)) != 0) واپس r;
		اگر (server->kex->مکمل && client->kex->مکمل)
			واپس 0;
		اگر (cn == 0 && sn == 0)
			واپس SSH_ERR_PROTOCOL_ERROR;
	}
	واپس SSH_ERR_PROTOCOL_ERROR;
}

#شامل "fixed-keys.h"

ساخت sshbuf *cfg = تہی;

صحیح auth_rhosts2(ساخت passwd *pw, ثابت حرف *client_user,
    ثابت حرف *hostname, ثابت حرف *ipaddr) { (خالی)pw;
    (خالی)client_user; (خالی)hostname; (خالی)ipaddr; واپس 0; }
صحیح platform_locked_account(ساخت passwd *pw) { (خالی)pw; واپس 0; }
خالی ریکارڈ_failed_login(ساخت ssh *ssh, ثابت حرف *user,
    ثابت حرف *hostname, ثابت حرف *ttyname) { (خالی)ssh; (خالی)user;
    (خالی)hostname; (خالی)ttyname; }
صحیح temporarily_use_uid(ساخت passwd *pw) { (خالی)pw; واپس 0; }
خالی restore_uid(خالی) { }
حرف *mm_auth2_read_banner(خالی) { واپس تہی; }
ساخت connection_info *
server_get_connection_info(ساخت ssh *ssh, صحیح populate, صحیح use_dns)
    { (خالی)ssh; (خالی)populate; (خالی)use_dns; واپس تہی; }
خالی server_process_permitopen(ساخت ssh *ssh) { (خالی)ssh; }
خالی server_process_channel_timeouts(ساخت ssh *ssh) { (خالی)ssh; }

#شامل "../../../auth2.c"

ساکن ساخت ssh *g_client = تہی;
ساکن ساخت ssh *g_server = تہی;
ساکن صحیح g_init = 0;
ساکن Authctxt g_authctxt;

ساکن خالی
fuzz_reset_authctxt(ساخت ssh *ssh)
{
	غیرعلامتی صحیح i;

	آزاد(g_authctxt.user);
	آزاد(g_authctxt.service);
	آزاد(g_authctxt.style);
	آزاد(g_authctxt.auth_طریقہ_info);
	اگر (g_authctxt.auth_methods != تہی) {
		برائے (i = 0; i < g_authctxt.عدد_auth_methods; i++)
			آزاد(g_authctxt.auth_methods[i]);
		آزاد(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_طریقہ_کلید);
	برائے (i = 0; i < g_authctxt.nprev_کلیدیں; i++)
		sshkey_free(g_authctxt.پچھلا_کلیدیں[i]);
	آزاد(g_authctxt.پچھلا_کلیدیں);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, حجم(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

ساکن صحیح
init_once(خالی)
{
	اگر (g_init)
		واپس 0;
	اشارہ(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, حجم(g_fake_pw));
	g_fake_pw.pw_name = (حرف *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (حرف *)"/tmp";
	g_fake_pw.pw_shell = (حرف *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	ساخت sshkey *priv = بھرو_نجی(PRIV_ED25519);
	ساخت sshkey *pub = بھرو_عوامی(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحیح i;
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			p = keyname;
		ورنہ اگر (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ورنہ اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ورنہ اگر (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ساخت kex_params kp;
	حافظہ_نقل(kp.proposal, proposal, حجم(proposal));

	اگر (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		واپس -1;
	اگر (ssh_جوڑو_hostkey(g_server, priv) != 0 ||
	    ssh_جوڑو_hostkey(g_client, pub) != 0)
		واپس -1;
	اگر (تسلسل_kex(g_client, g_server) != 0)
		واپس -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_سیٹ(g_server, SSH2_پیغام_USERAUTH_REQUEST,
	    &داخلہ_userauth_request);

	آزاد(keyname);
	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	واپس 0;
}

خالی
fuzz_userauth_one(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (init_once() != 0)
		واپس;
	اگر (سائز > 65000)
		واپس;

	fuzz_reset_authctxt(g_server);

	اندر_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		سائز_t transferred;
		اگر (ssh_packet_put(g_client, SSH2_پیغام_USERAUTH_REQUEST,
		    ڈیٹا, سائز) != 0)
			جاؤ مکمل;
		اگر (pump(g_client, g_server, &transferred) != 0)
			جاؤ مکمل;
		(خالی)ssh_dispatch_تسلسل(g_server, DISPATCH_NONBLOCK, تہی);
	مکمل:
		;
	}
	اندر_fuzz = 0;
}
