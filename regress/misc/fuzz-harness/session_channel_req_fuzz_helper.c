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
#ضمن "auth-options.h"
#ضمن "servconf.h"
#ضمن "channels.h"
#ضمن "session.h"

ServerOptions options;
بنية sshbuf *loginmsg = عدم;
بنية include_list includes;
ساكن بنية sshauthopt g_auth_opts_storage;
بنية sshauthopt *auth_opts = &g_auth_opts_storage;
بنية passwd *privsep_pw = عدم;

ساكن jmp_buf fuzz_env;
ساكن متطاير صحيح in_fuzz = 0;

فراغ
cleanup_exit(صحيح code)
{
	إذا (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

فراغ
__wrap_ssh_packet_disconnect(بنية ssh *ssh, ثابت حرف *fmt, ...)
{
	(فراغ)ssh;
	(فراغ)fmt;
	إذا (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

صحيح
__wrap_sshpkt_fatal(بنية ssh *ssh, صحيح r, ثابت حرف *fmt, ...)
{
	(فراغ)ssh;
	(فراغ)fmt;
	إذا (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

صحيح
mm_is_monitor(فراغ)
{
	أرجع 0;
}

فراغ
mm_audit_run_command(ثابت حرف *cmd)
{
	(فراغ)cmd;
}

صحيح
mm_pty_allocate(صحيح *ptyfd, صحيح *ttyfd, حرف *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	إذا (namebuf != عدم && namebuflen > 0)
		namebuf[0] = '\0';
	أرجع 0;
}

فراغ mm_session_pty_cleanup2(Session *s) { (فراغ)s; }
صحيح platform_locked_account(بنية passwd *pw) { (فراغ)pw; أرجع 0; }
فراغ record_failed_login(بنية ssh *ssh, ثابت حرف *user,
    ثابت حرف *hostname, ثابت حرف *ttyname) { (فراغ)ssh; (فراغ)user;
    (فراغ)hostname; (فراغ)ttyname; }
صحيح temporarily_use_uid(بنية passwd *pw) { (فراغ)pw; أرجع 0; }
فراغ restore_uid(فراغ) { }
فراغ platform_setusercontext(بنية passwd *pw) { (فراغ)pw; }
فراغ platform_setusercontext_post_groups(بنية passwd *pw) { (فراغ)pw; }
بنية connection_info *
server_get_connection_info(بنية ssh *ssh, صحيح populate, صحيح use_dns)
    { (فراغ)ssh; (فراغ)populate; (فراغ)use_dns; أرجع عدم; }
صحيح auth2_methods_valid(ثابت حرف *list, صحيح allow_unknown)
    { (فراغ)list; (فراغ)allow_unknown; أرجع 0; }
بنية sshbuf *cfg = عدم;
صحيح auth_sock = -1;
حرف **tun_fwd_ifnames = عدم;

بنية logininfo *login_get_lastlog(بنية logininfo *li, ثابت uid_t uid)
    { (فراغ)li; (فراغ)uid; أرجع عدم; }
بنية logininfo *login_alloc_entry(pid_t pid, ثابت حرف *username,
    ثابت حرف *hostname, ثابت حرف *باريس)
    { (فراغ)pid; (فراغ)username; (فراغ)hostname; (فراغ)باريس; أرجع عدم; }
فراغ server_process_permitopen(بنية ssh *ssh) { (فراغ)ssh; }
فراغ server_process_channel_timeouts(بنية ssh *ssh) { (فراغ)ssh; }
صحيح server_loop2(بنية ssh *ssh, Authctxt *authctxt)
    { (فراغ)ssh; (فراغ)authctxt; أرجع 0; }
صحيح platform_privileged_uidswap(فراغ) { أرجع 0; }
صحيح sftp_server_main(صحيح argc, حرف **argv, بنية passwd *user_pw)
    { (فراغ)argc; (فراغ)argv; (فراغ)user_pw; أرجع 0; }
صحيح debug_flag = 0;
فراغ permanently_set_uid(بنية passwd *pw) { (فراغ)pw; }
صحيح login_login(بنية logininfo *li) { (فراغ)li; أرجع 0; }
صحيح login_logout(بنية logininfo *li) { (فراغ)li; أرجع 0; }
فراغ login_free_entry(بنية logininfo *li) { (فراغ)li; }
فراغ login_set_addr(بنية logininfo *li, ثابت بنية sockaddr *sa,
    ثابت unsigned صحيح sa_size) { (فراغ)li; (فراغ)sa; (فراغ)sa_size; }
صحيح openpty(صحيح *amaster, صحيح *aslave, حرف *name,
    ثابت بنية termios *termp, ثابت بنية winsize *winp)
    { (فراغ)termp; (فراغ)winp; *amaster = -1; *aslave = -1;
    إذا (name) name[0] = '\0'; أرجع -1; }

خارجي صحيح __real_do_exec(بنية ssh *, Session *, ثابت حرف *);
خارجي صحيح __real_do_exec_pty(بنية ssh *, Session *, ثابت حرف *);
خارجي صحيح __real_do_exec_no_pty(بنية ssh *, Session *, ثابت حرف *);

صحيح
__wrap_do_exec(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	(فراغ)ssh;
	(فراغ)s;
	(فراغ)command;
	أرجع 0;
}

صحيح
__wrap_do_exec_pty(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	(فراغ)ssh;
	(فراغ)s;
	(فراغ)command;
	أرجع 0;
}

صحيح
__wrap_do_exec_no_pty(بنية ssh *ssh, Session *s, ثابت حرف *command)
{
	(فراغ)ssh;
	(فراغ)s;
	(فراغ)command;
	أرجع 0;
}

ساكن بنية sshkey *
load_private(ثابت حرف *str)
{
	بنية sshbuf *b = sshbuf_from(str, strlen(str));
	بنية sshkey *k = عدم;
	إذا (b == عدم || sshkey_parse_private_fileblob(b, "", &k, عدم) != 0)
		abort();
	sshbuf_free(b);
	أرجع k;
}

ساكن بنية sshkey *
load_public(ثابت حرف *str)
{
	حرف *tmp, *cp;
	بنية sshkey *k = sshkey_new(کونچي_UNSPEC);
	إذا (k == عدم)
		abort();
	tmp = cp = strdup(str);
	إذا (sshkey_read(k, &cp) != 0)
		abort();
	حرر(tmp);
	أرجع k;
}

ساكن صحيح
pump(بنية ssh *from, بنية ssh *to, size_t *transferred)
{
	ثابت u_char *buf;
	size_t len;
	u_char type;
	صحيح r;
	*transferred = 0;
	إذا ((r = ssh_packet_next(from, &type)) != 0)
		أرجع r;
	buf = ssh_output_ptr(from, &len);
	إذا (len == 0)
		أرجع 0;
	إذا ((r = ssh_ماسوقن_append(to, buf, len)) != 0)
		أرجع r;
	إذا ((r = ssh_output_consume(from, len)) != 0)
		أرجع r;
	*transferred = len;
	أرجع 0;
}

ساكن صحيح
run_kex(بنية ssh *client, بنية ssh *server)
{
	صحيح r;
	size_t cn, sn;
	لكل (صحيح i = 0; i < 100; i++) {
		إذا ((r = pump(server, client, &sn)) != 0) أرجع r;
		إذا ((r = pump(client, server, &cn)) != 0) أرجع r;
		إذا (server->kex->done && client->kex->done)
			أرجع 0;
		إذا (cn == 0 && sn == 0)
			أرجع SSH_ERR_PROTOCOL_ERROR;
	}
	أرجع SSH_ERR_PROTOCOL_ERROR;
}

#ضمن "fixed-keys.h"

ساكن بنية ssh *g_client = عدم;
ساكن بنية ssh *g_server = عدم;
ساكن صحيح g_init = 0;
ساكن صحيح g_channel_id = -1;
ساكن Authctxt g_authctxt;
ساكن بنية passwd g_fake_pw;

ساكن حرف *g_pending_rtype = عدم;
ساكن حرف *g_pending_exec_cmd = عدم;
ساكن حرف *g_pending_env_name = عدم;
ساكن حرف *g_pending_env_val = عدم;

ساكن فراغ
my_session_exec_req(بنية ssh *ssh)
{
	صحيح r;
	إذا ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, عدم)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ساكن فراغ
my_session_env_req(بنية ssh *ssh)
{
	صحيح r;
	إذا ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, عدم)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, عدم)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ساكن صحيح
ماسوقن_channel_request(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(فراغ)type;
	(فراغ)seq;
	إذا (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, عدم) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		أرجع 0;
	إذا (g_channel_id >= 0 && g_pending_rtype != عدم) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		إذا (c != عدم) {
			إذا (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			وإلا إذا (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			وإلا
				(فراغ)session_ماسوقن_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	أرجع 0;
}

ساكن فراغ
reset_channel(بنية ssh *ssh)
{
	إذا (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		إذا (c != عدم)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (حرف *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (حرف *)"fuzz", 0);
	إذا (c == عدم)
		أرجع;
	g_channel_id = c->self;
	Session *s = session_new();
	إذا (s != عدم) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

ساكن صحيح
init_once(فراغ)
{
	إذا (g_init)
		أرجع 0;
	إشارة(SIGPIPE, SIG_IGN);
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

	بنية sshkey *priv = load_private(PRIV_ED25519);
	بنية sshkey *pub = load_public(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحيح i;
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		إذا (i == PROPOSAL_SERVER_HOST_کونچي_ALGS)
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
	memcpy(kp.proposal, proposal, حجم(proposal));

	إذا (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		أرجع -1;
	إذا (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		أرجع -1;
	إذا (run_kex(g_client, g_server) != 0)
		أرجع -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_ڤسنن_CHANNEL_REQUEST,
	    &ماسوقن_channel_request);

	حرر(keyname);
	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(proposal[i]);
	g_init = 1;
	أرجع 0;
}

فراغ
fuzz_session_one(ثابت uint8_t *data, size_t size)
{
	إذا (init_once() != 0)
		أرجع;
	إذا (size > 65000)
		أرجع;

	reset_channel(g_server);

	in_fuzz = 1;
	إذا (setjmp(fuzz_env) == 0) {
		size_t transferred;
		إذا (ssh_packet_put(g_client, SSH2_ڤسنن_CHANNEL_REQUEST,
		    data, size) != 0)
			اذهب done;
		إذا (pump(g_client, g_server, &transferred) != 0)
			اذهب done;
		(فراغ)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, عدم);
	done:
		;
	}
	in_fuzz = 0;
	حرر(g_pending_rtype);
	g_pending_rtype = عدم;
	حرر(g_pending_exec_cmd);
	g_pending_exec_cmd = عدم;
	حرر(g_pending_env_name);
	g_pending_env_name = عدم;
	حرر(g_pending_env_val);
	g_pending_env_val = عدم;
}
