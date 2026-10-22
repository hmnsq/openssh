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
 * Helper for session_channel_req_fuzz. Drives the server side of
 * session.c CHANNEL_REQUEST processing via the public
 * session_input_channel_req() entry point. See the .cc driver for
 * the threat-model writeup.
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
#شامل "auth-options.h"
#شامل "servconf.h"
#شامل "channels.h"
#شامل "session.h"

ServerOptions options;
ساخت sshbuf *loginmsg = تہی;
ساخت include_list includes;
ساکن ساخت sshauthopt g_auth_opts_storage;
ساخت sshauthopt *auth_opts = &g_auth_opts_storage;
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

خالی
__wrap_ssh_packet_disconnect(ساخت ssh *ssh, ثابت حرف *fmt, ...)
{
	(خالی)ssh;
	(خالی)fmt;
	اگر (اندر_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

صحیح
__wrap_sshpkt_fatal(ساخت ssh *ssh, صحیح r, ثابت حرف *fmt, ...)
{
	(خالی)ssh;
	(خالی)fmt;
	اگر (اندر_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

صحیح
mm_is_monitor(خالی)
{
	واپس 0;
}

خالی
mm_audit_تسلسل_command(ثابت حرف *cmd)
{
	(خالی)cmd;
}

صحیح
mm_pty_allocate(صحیح *ptyfd, صحیح *ttyfd, حرف *namebuf, سائز_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	اگر (namebuf != تہی && namebuflen > 0)
		namebuf[0] = '\0';
	واپس 0;
}

خالی mm_session_pty_cleanup2(Session *s) { (خالی)s; }
صحیح platform_locked_account(ساخت passwd *pw) { (خالی)pw; واپس 0; }
خالی ریکارڈ_failed_login(ساخت ssh *ssh, ثابت حرف *user,
    ثابت حرف *hostname, ثابت حرف *ttyname) { (خالی)ssh; (خالی)user;
    (خالی)hostname; (خالی)ttyname; }
صحیح temporarily_use_uid(ساخت passwd *pw) { (خالی)pw; واپس 0; }
خالی restore_uid(خالی) { }
خالی platform_setusercontext(ساخت passwd *pw) { (خالی)pw; }
خالی platform_setusercontext_post_groups(ساخت passwd *pw) { (خالی)pw; }
ساخت connection_info *
server_get_connection_info(ساخت ssh *ssh, صحیح populate, صحیح use_dns)
    { (خالی)ssh; (خالی)populate; (خالی)use_dns; واپس تہی; }
صحیح auth2_methods_valid(ثابت حرف *list, صحیح allow_unknown)
    { (خالی)list; (خالی)allow_unknown; واپس 0; }
ساخت sshbuf *cfg = تہی;
صحیح auth_sock = -1;
حرف **tun_fwd_ifnames = تہی;

ساخت logininfo *login_get_lastlog(ساخت logininfo *li, ثابت uid_t uid)
    { (خالی)li; (خالی)uid; واپس تہی; }
ساخت logininfo *login_alloc_اندراج(pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *سطر)
    { (خالی)pid; (خالی)username; (خالی)hostname; (خالی)سطر; واپس تہی; }
خالی server_process_permitopen(ساخت ssh *ssh) { (خالی)ssh; }
خالی server_process_channel_timeouts(ساخت ssh *ssh) { (خالی)ssh; }
صحیح server_loop2(ساخت ssh *ssh, Authctxt *authctxt)
    { (خالی)ssh; (خالی)authctxt; واپس 0; }
صحیح platform_privileged_uidswap(خالی) { واپس 0; }
صحیح sftp_server_main(صحیح argc, حرف **argv, ساخت passwd *user_pw)
    { (خالی)argc; (خالی)argv; (خالی)user_pw; واپس 0; }
صحیح debug_flag = 0;
خالی permanently_سیٹ_uid(ساخت passwd *pw) { (خالی)pw; }
صحیح login_login(ساخت logininfo *li) { (خالی)li; واپس 0; }
صحیح login_logout(ساخت logininfo *li) { (خالی)li; واپس 0; }
خالی login_free_اندراج(ساخت logininfo *li) { (خالی)li; }
خالی login_سیٹ_addr(ساخت logininfo *li, ثابت ساخت sockaddr *sa,
    ثابت غیرعلامتی صحیح sa_سائز) { (خالی)li; (خالی)sa; (خالی)sa_سائز; }
صحیح openpty(صحیح *amaster, صحیح *aslave, حرف *name,
    ثابت ساخت termios *termp, ثابت ساخت winsize *winp)
    { (خالی)termp; (خالی)winp; *amaster = -1; *aslave = -1;
    اگر (name) name[0] = '\0'; واپس -1; }

خارجی صحیح __real_do_exec(ساخت ssh *, Session *, ثابت حرف *);
خارجی صحیح __real_do_exec_pty(ساخت ssh *, Session *, ثابت حرف *);
خارجی صحیح __real_do_exec_no_pty(ساخت ssh *, Session *, ثابت حرف *);

صحیح
__wrap_do_exec(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	(خالی)ssh;
	(خالی)s;
	(خالی)command;
	واپس 0;
}

صحیح
__wrap_do_exec_pty(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	(خالی)ssh;
	(خالی)s;
	(خالی)command;
	واپس 0;
}

صحیح
__wrap_do_exec_no_pty(ساخت ssh *ssh, Session *s, ثابت حرف *command)
{
	(خالی)ssh;
	(خالی)s;
	(خالی)command;
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

ساکن ساخت ssh *g_client = تہی;
ساکن ساخت ssh *g_server = تہی;
ساکن صحیح g_init = 0;
ساکن صحیح g_channel_id = -1;
ساکن Authctxt g_authctxt;
ساکن ساخت passwd g_fake_pw;

ساکن حرف *g_pending_rtype = تہی;
ساکن حرف *g_pending_exec_cmd = تہی;
ساکن حرف *g_pending_env_name = تہی;
ساکن حرف *g_pending_env_val = تہی;

ساکن خالی
my_session_exec_req(ساخت ssh *ssh)
{
	صحیح r;
	اگر ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ساکن خالی
my_session_env_req(ساخت ssh *ssh)
{
	صحیح r;
	اگر ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, تہی)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ساکن صحیح
داخلہ_channel_request(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	uint32_t chan_id;
	u_char want_جواب;

	(خالی)type;
	(خالی)seq;
	اگر (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, تہی) != 0 ||
	    sshpkt_get_u8(ssh, &want_جواب) != 0)
		واپس 0;
	اگر (g_channel_id >= 0 && g_pending_rtype != تہی) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		اگر (c != تہی) {
			اگر (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			ورنہ اگر (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			ورنہ
				(خالی)session_داخلہ_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	واپس 0;
}

ساکن خالی
reset_channel(ساخت ssh *ssh)
{
	اگر (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		اگر (c != تہی)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (حرف *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (حرف *)"fuzz", 0);
	اگر (c == تہی)
		واپس;
	g_channel_id = c->self;
	Session *s = session_new();
	اگر (s != تہی) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

ساکن صحیح
init_once(خالی)
{
	اگر (g_init)
		واپس 0;
	اشارہ(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
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

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, حجم(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

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

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_سیٹ(g_server, SSH2_پیغام_CHANNEL_REQUEST,
	    &داخلہ_channel_request);

	آزاد(keyname);
	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	واپس 0;
}

خالی
fuzz_session_one(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (init_once() != 0)
		واپس;
	اگر (سائز > 65000)
		واپس;

	reset_channel(g_server);

	اندر_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		سائز_t transferred;
		اگر (ssh_packet_put(g_client, SSH2_پیغام_CHANNEL_REQUEST,
		    ڈیٹا, سائز) != 0)
			جاؤ مکمل;
		اگر (pump(g_client, g_server, &transferred) != 0)
			جاؤ مکمل;
		(خالی)ssh_dispatch_تسلسل(g_server, DISPATCH_NONBLOCK, تہی);
	مکمل:
		;
	}
	اندر_fuzz = 0;
	آزاد(g_pending_rtype);
	g_pending_rtype = تہی;
	آزاد(g_pending_exec_cmd);
	g_pending_exec_cmd = تہی;
	آزاد(g_pending_env_name);
	g_pending_env_name = تہی;
	آزاد(g_pending_env_val);
	g_pending_env_val = تہی;
}
