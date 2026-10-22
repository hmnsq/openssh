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

#ضمن <setjmp.h>
#ضمن <signal.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <pwd.h>
#ضمن <sys/types.h>

#ضمن "log.h"
#ضمن "digest.h"
#ضمن "misc.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "ssh_api.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "packet.h"
#ضمن "myproposal.h"
#ضمن "kex.h"
#ضمن "xmalloc.h"
#ضمن "authfile.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "servconf.h"
#ضمن "audit.h"

ServerOptions options;
بنية sshbuf *loginmsg = عدم;
بنية include_list includes;
بنية sshauthopt *auth_opts = عدم;
بنية passwd *privsep_pw = عدم;

ساكن jmp_buf fuzz_env;
ساكن متطاير صحيح اندريون_fuzz = 0;

فراغ
cleanup_exit(صحيح ڪوڊ)
{
	إذا (اندريون_fuzz)
		longjmp(fuzz_env, ڪوڊ ? ڪوڊ : 1);
	_exit(ڪوڊ);
}

صحيح
__wrap_ssh_packet_write_wait(بنية ssh *ssh)
{
	(فراغ)ssh;
	أرجع 0;
}

ساكن بنية passwd g_fake_pw;

صحيح
mm_is_monitor(فراغ)
{
	أرجع 0;
}

بنية passwd *
mm_getpwnamallow(بنية ssh *ssh, ثابت حرف *user)
{
	(فراغ)ssh;
	(فراغ)user;
	أرجع &g_fake_pw;
}

صحيح
mm_auth_password(بنية ssh *ssh, حرف *password)
{
	(فراغ)ssh;
	(فراغ)password;
	أرجع 0;
}

صحيح
mm_user_ڪنجي_allowed(بنية ssh *ssh, بنية passwd *pw, بنية sshkey *ڪنجي,
    صحيح auth_attempt, بنية sshauthopt **authoptsp)
{
	(فراغ)ssh;
	(فراغ)pw;
	(فراغ)ڪنجي;
	(فراغ)auth_attempt;
	(فراغ)authoptsp;
	أرجع 0;
}

صحيح
mm_hostbased_ڪنجي_allowed(بنية ssh *ssh, بنية passwd *pw, ثابت حرف *user,
    ثابت حرف *host, بنية sshkey *ڪنجي)
{
	(فراغ)ssh;
	(فراغ)pw;
	(فراغ)user;
	(فراغ)host;
	(فراغ)ڪنجي;
	أرجع 0;
}

صحيح
mm_sshkey_verify(ثابت بنية sshkey *ڪنجي, ثابت u_char *sig, سائيز_t siglen,
    ثابت u_char *معلومات, سائيز_t datalen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	أرجع sshkey_verify(ڪنجي, sig, siglen, معلومات, datalen, alg, compat,
	    detailsp);
}

فراغ
mm_inform_authserv(حرف *service, حرف *style)
{
	(فراغ)service;
	(فراغ)style;
}

فراغ
mm_audit_event(بنية ssh *ssh, ssh_audit_event_t event)
{
	(فراغ)ssh;
	(فراغ)event;
}

فراغ
mm_شروعات_pam(بنية ssh *ssh)
{
	(فراغ)ssh;
}

صحيح
mm_do_pam_account(فراغ)
{
	أرجع 0;
}

ساكن بنية sshkey *
ڀريو_ذاتي(ثابت حرف *str)
{
	بنية sshbuf *b = sshbuf_from(str, لڙي_ڊيگهه(str));
	بنية sshkey *k = عدم;
	إذا (b == عدم || sshkey_parse_ذاتي_fileblob(b, "", &k, عدم) != 0)
		abort();
	sshbuf_free(b);
	أرجع k;
}

ساكن بنية sshkey *
ڀريو_عوامي(ثابت حرف *str)
{
	حرف *tmp, *cp;
	بنية sshkey *k = sshkey_new(ڪنجي_UNSPEC);
	إذا (k == عدم)
		abort();
	tmp = cp = strdup(str);
	إذا (sshkey_read(k, &cp) != 0)
		abort();
	حرر(tmp);
	أرجع k;
}

ساكن صحيح
pump(بنية ssh *from, بنية ssh *منزل, سائيز_t *transferred)
{
	ثابت u_char *buf;
	سائيز_t len;
	u_char type;
	صحيح r;
	*transferred = 0;
	إذا ((r = ssh_packet_ايندڙ(from, &type)) != 0)
		أرجع r;
	buf = ssh_output_ptr(from, &len);
	إذا (len == 0)
		أرجع 0;
	إذا ((r = ssh_داخلا_append(منزل, buf, len)) != 0)
		أرجع r;
	إذا ((r = ssh_output_consume(from, len)) != 0)
		أرجع r;
	*transferred = len;
	أرجع 0;
}

ساكن صحيح
لاڳيتو_kex(بنية ssh *client, بنية ssh *server)
{
	صحيح r;
	سائيز_t cn, sn;
	لكل (صحيح i = 0; i < 100; i++) {
		إذا ((r = pump(server, client, &sn)) != 0) أرجع r;
		إذا ((r = pump(client, server, &cn)) != 0) أرجع r;
		إذا (server->kex->پورو && client->kex->پورو)
			أرجع 0;
		إذا (cn == 0 && sn == 0)
			أرجع SSH_ERR_PROTOCOL_ERROR;
	}
	أرجع SSH_ERR_PROTOCOL_ERROR;
}

#ضمن "fixed-keys.h"

بنية sshbuf *cfg = عدم;

صحيح auth_rhosts2(بنية passwd *pw, ثابت حرف *client_user,
    ثابت حرف *hostname, ثابت حرف *ipaddr) { (فراغ)pw;
    (فراغ)client_user; (فراغ)hostname; (فراغ)ipaddr; أرجع 0; }
صحيح platform_locked_account(بنية passwd *pw) { (فراغ)pw; أرجع 0; }
فراغ رڪارڊ_failed_login(بنية ssh *ssh, ثابت حرف *user,
    ثابت حرف *hostname, ثابت حرف *ttyname) { (فراغ)ssh; (فراغ)user;
    (فراغ)hostname; (فراغ)ttyname; }
صحيح temporarily_use_uid(بنية passwd *pw) { (فراغ)pw; أرجع 0; }
فراغ restore_uid(فراغ) { }
حرف *mm_auth2_read_banner(فراغ) { أرجع عدم; }
بنية connection_info *
server_get_connection_info(بنية ssh *ssh, صحيح populate, صحيح use_dns)
    { (فراغ)ssh; (فراغ)populate; (فراغ)use_dns; أرجع عدم; }
فراغ server_process_permitopen(بنية ssh *ssh) { (فراغ)ssh; }
فراغ server_process_channel_timeouts(بنية ssh *ssh) { (فراغ)ssh; }

#ضمن "../../../auth2.c"

ساكن بنية ssh *g_client = عدم;
ساكن بنية ssh *g_server = عدم;
ساكن صحيح g_init = 0;
ساكن Authctxt g_authctxt;

ساكن فراغ
fuzz_reset_authctxt(بنية ssh *ssh)
{
	بنانشان صحيح i;

	حرر(g_authctxt.user);
	حرر(g_authctxt.service);
	حرر(g_authctxt.style);
	حرر(g_authctxt.auth_طريقو_info);
	إذا (g_authctxt.auth_methods != عدم) {
		لكل (i = 0; i < g_authctxt.انگ_auth_methods; i++)
			حرر(g_authctxt.auth_methods[i]);
		حرر(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_طريقو_ڪنجي);
	لكل (i = 0; i < g_authctxt.nprev_ڪنجيون; i++)
		sshkey_free(g_authctxt.prev_ڪنجيون[i]);
	حرر(g_authctxt.prev_ڪنجيون);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, حجم(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

ساكن صحيح
init_once(فراغ)
{
	إذا (g_init)
		أرجع 0;
	إشارة(SIGPIPE, SIG_IGN);
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

	بنية sshkey *priv = ڀريو_ذاتي(PRIV_ED25519);
	بنية sshkey *pub = ڀريو_عوامي(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحيح i;
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		إذا (i == PROPOSAL_SERVER_HOST_ڪنجي_ALGS)
			p = keyname;
		وإلا إذا (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		وإلا إذا (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		وإلا إذا (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	بنية kex_params kp;
	يادگيري_نقل(kp.proposal, proposal, حجم(proposal));

	إذا (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		أرجع -1;
	إذا (ssh_جوڙيو_hostkey(g_server, priv) != 0 ||
	    ssh_جوڙيو_hostkey(g_client, pub) != 0)
		أرجع -1;
	إذا (لاڳيتو_kex(g_client, g_server) != 0)
		أرجع -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_سيٽ(g_server, SSH2_نياپو_USERAUTH_REQUEST,
	    &داخلا_userauth_request);

	حرر(keyname);
	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(proposal[i]);
	g_init = 1;
	أرجع 0;
}

فراغ
fuzz_userauth_one(ثابت uint8_t *معلومات, سائيز_t سائيز)
{
	إذا (init_once() != 0)
		أرجع;
	إذا (سائيز > 65000)
		أرجع;

	fuzz_reset_authctxt(g_server);

	اندريون_fuzz = 1;
	إذا (setjmp(fuzz_env) == 0) {
		سائيز_t transferred;
		إذا (ssh_packet_put(g_client, SSH2_نياپو_USERAUTH_REQUEST,
		    معلومات, سائيز) != 0)
			اذهب پورو;
		إذا (pump(g_client, g_server, &transferred) != 0)
			اذهب پورو;
		(فراغ)ssh_dispatch_لاڳيتو(g_server, DISPATCH_NONBLOCK, عدم);
	پورو:
		;
	}
	اندريون_fuzz = 0;
}
