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
ساختار sshbuf *loginmsg = پوچ;
ساختار include_list includes;
ایستا ساختار sshauthopt g_auth_opts_storage;
ساختار sshauthopt *auth_opts = &g_auth_opts_storage;
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

تهی
__wrap_ssh_packet_disconnect(ساختار ssh *ssh, ثابت نویسه *fmt, ...)
{
	(تهی)ssh;
	(تهی)fmt;
	اگر (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

صحیح
__wrap_sshpkt_fatal(ساختار ssh *ssh, صحیح r, ثابت نویسه *fmt, ...)
{
	(تهی)ssh;
	(تهی)fmt;
	اگر (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

صحیح
mm_is_monitor(تهی)
{
	بازگشت 0;
}

تهی
mm_audit_run_command(ثابت نویسه *cmd)
{
	(تهی)cmd;
}

صحیح
mm_pty_allocate(صحیح *ptyfd, صحیح *ttyfd, نویسه *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	اگر (namebuf != پوچ && namebuflen > 0)
		namebuf[0] = '\0';
	بازگشت 0;
}

تهی mm_session_pty_cleanup2(Session *s) { (تهی)s; }
صحیح platform_locked_account(ساختار passwd *pw) { (تهی)pw; بازگشت 0; }
تهی record_failed_login(ساختار ssh *ssh, ثابت نویسه *user,
    ثابت نویسه *hostname, ثابت نویسه *ttyname) { (تهی)ssh; (تهی)user;
    (تهی)hostname; (تهی)ttyname; }
صحیح temporarily_use_uid(ساختار passwd *pw) { (تهی)pw; بازگشت 0; }
تهی restore_uid(تهی) { }
تهی platform_setusercontext(ساختار passwd *pw) { (تهی)pw; }
تهی platform_setusercontext_post_groups(ساختار passwd *pw) { (تهی)pw; }
ساختار connection_info *
server_get_connection_info(ساختار ssh *ssh, صحیح populate, صحیح use_dns)
    { (تهی)ssh; (تهی)populate; (تهی)use_dns; بازگشت پوچ; }
صحیح auth2_methods_valid(ثابت نویسه *list, صحیح allow_unknown)
    { (تهی)list; (تهی)allow_unknown; بازگشت 0; }
ساختار sshbuf *cfg = پوچ;
صحیح auth_sock = -1;
نویسه **tun_fwd_ifnames = پوچ;

ساختار logininfo *login_get_lastlog(ساختار logininfo *li, ثابت uid_t uid)
    { (تهی)li; (تهی)uid; بازگشت پوچ; }
ساختار logininfo *login_alloc_entry(pid_t pid, ثابت نویسه *username,
    ثابت نویسه *hostname, ثابت نویسه *سطر)
    { (تهی)pid; (تهی)username; (تهی)hostname; (تهی)سطر; بازگشت پوچ; }
تهی server_process_permitopen(ساختار ssh *ssh) { (تهی)ssh; }
تهی server_process_channel_timeouts(ساختار ssh *ssh) { (تهی)ssh; }
صحیح server_loop2(ساختار ssh *ssh, Authctxt *authctxt)
    { (تهی)ssh; (تهی)authctxt; بازگشت 0; }
صحیح platform_privileged_uidswap(تهی) { بازگشت 0; }
صحیح sftp_server_main(صحیح argc, نویسه **argv, ساختار passwd *user_pw)
    { (تهی)argc; (تهی)argv; (تهی)user_pw; بازگشت 0; }
صحیح debug_flag = 0;
تهی permanently_set_uid(ساختار passwd *pw) { (تهی)pw; }
صحیح login_login(ساختار logininfo *li) { (تهی)li; بازگشت 0; }
صحیح login_logout(ساختار logininfo *li) { (تهی)li; بازگشت 0; }
تهی login_free_entry(ساختار logininfo *li) { (تهی)li; }
تهی login_set_addr(ساختار logininfo *li, ثابت ساختار sockaddr *sa,
    ثابت unsigned صحیح sa_size) { (تهی)li; (تهی)sa; (تهی)sa_size; }
صحیح openpty(صحیح *amaster, صحیح *aslave, نویسه *name,
    ثابت ساختار termios *termp, ثابت ساختار winsize *winp)
    { (تهی)termp; (تهی)winp; *amaster = -1; *aslave = -1;
    اگر (name) name[0] = '\0'; بازگشت -1; }

بیرونی صحیح __real_do_exec(ساختار ssh *, Session *, ثابت نویسه *);
بیرونی صحیح __real_do_exec_pty(ساختار ssh *, Session *, ثابت نویسه *);
بیرونی صحیح __real_do_exec_no_pty(ساختار ssh *, Session *, ثابت نویسه *);

صحیح
__wrap_do_exec(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	(تهی)ssh;
	(تهی)s;
	(تهی)command;
	بازگشت 0;
}

صحیح
__wrap_do_exec_pty(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	(تهی)ssh;
	(تهی)s;
	(تهی)command;
	بازگشت 0;
}

صحیح
__wrap_do_exec_no_pty(ساختار ssh *ssh, Session *s, ثابت نویسه *command)
{
	(تهی)ssh;
	(تهی)s;
	(تهی)command;
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

ایستا ساختار ssh *g_client = پوچ;
ایستا ساختار ssh *g_server = پوچ;
ایستا صحیح g_init = 0;
ایستا صحیح g_channel_id = -1;
ایستا Authctxt g_authctxt;
ایستا ساختار passwd g_fake_pw;

ایستا نویسه *g_pending_rtype = پوچ;
ایستا نویسه *g_pending_exec_cmd = پوچ;
ایستا نویسه *g_pending_env_name = پوچ;
ایستا نویسه *g_pending_env_val = پوچ;

ایستا تهی
my_session_exec_req(ساختار ssh *ssh)
{
	صحیح r;
	اگر ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, پوچ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ایستا تهی
my_session_env_req(ساختار ssh *ssh)
{
	صحیح r;
	اگر ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, پوچ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, پوچ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ایستا صحیح
درون_داد_channel_request(صحیح type, uint32_t seq, ساختار ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(تهی)type;
	(تهی)seq;
	اگر (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, پوچ) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		بازگشت 0;
	اگر (g_channel_id >= 0 && g_pending_rtype != پوچ) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		اگر (c != پوچ) {
			اگر (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			وگرنه اگر (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			وگرنه
				(تهی)session_درون_داد_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	بازگشت 0;
}

ایستا تهی
reset_channel(ساختار ssh *ssh)
{
	اگر (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		اگر (c != پوچ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (نویسه *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (نویسه *)"fuzz", 0);
	اگر (c == پوچ)
		بازگشت;
	g_channel_id = c->self;
	Session *s = session_new();
	اگر (s != پوچ) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

ایستا صحیح
init_once(تهی)
{
	اگر (g_init)
		بازگشت 0;
	سیگنال(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
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

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, اندازه(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

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

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_پیام_CHANNEL_REQUEST,
	    &درون_داد_channel_request);

	آزاد(keyname);
	برای (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	بازگشت 0;
}

تهی
fuzz_session_one(ثابت uint8_t *data, size_t size)
{
	اگر (init_once() != 0)
		بازگشت;
	اگر (size > 65000)
		بازگشت;

	reset_channel(g_server);

	in_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		size_t transferred;
		اگر (ssh_packet_put(g_client, SSH2_پیام_CHANNEL_REQUEST,
		    data, size) != 0)
			برو done;
		اگر (pump(g_client, g_server, &transferred) != 0)
			برو done;
		(تهی)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, پوچ);
	done:
		;
	}
	in_fuzz = 0;
	آزاد(g_pending_rtype);
	g_pending_rtype = پوچ;
	آزاد(g_pending_exec_cmd);
	g_pending_exec_cmd = پوچ;
	آزاد(g_pending_env_name);
	g_pending_env_name = پوچ;
	آزاد(g_pending_env_val);
	g_pending_env_val = پوچ;
}
