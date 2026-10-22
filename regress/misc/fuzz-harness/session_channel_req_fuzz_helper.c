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

#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "session.h"

ServerOptions options;
ਬਣਤਰ sshbuf *loginmsg = ਨਿਰਾ;
ਬਣਤਰ include_list includes;
ਸਥਿਰ ਬਣਤਰ sshauthopt g_auth_opts_storage;
ਬਣਤਰ sshauthopt *auth_opts = &g_auth_opts_storage;
ਬਣਤਰ passwd *privsep_pw = ਨਿਰਾ;

ਸਥਿਰ jmp_buf fuzz_env;
ਸਥਿਰ ਅਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_fuzz = 0;

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

ਖਾਲੀ
__wrap_ssh_packet_disconnect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)fmt;
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ਪੂਰਨ
__wrap_sshpkt_fatal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)fmt;
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ਪੂਰਨ
mm_is_monitor(ਖਾਲੀ)
{
	ਵਾਪਸ 0;
}

ਖਾਲੀ
mm_audit_ਲੜੀਵਾਰ_command(ਅਚਲ ਅੱਖਰ *cmd)
{
	(ਖਾਲੀ)cmd;
}

ਪੂਰਨ
mm_pty_allocate(ਪੂਰਨ *ptyfd, ਪੂਰਨ *ttyfd, ਅੱਖਰ *namebuf, ਮਾਪ_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	ਜੇ (namebuf != ਨਿਰਾ && namebuflen > 0)
		namebuf[0] = '\0';
	ਵਾਪਸ 0;
}

ਖਾਲੀ mm_session_pty_cleanup2(Session *s) { (ਖਾਲੀ)s; }
ਪੂਰਨ platform_locked_account(ਬਣਤਰ passwd *pw) { (ਖਾਲੀ)pw; ਵਾਪਸ 0; }
ਖਾਲੀ ਰਿਕਾਰਡ_failed_login(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *user,
    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ttyname) { (ਖਾਲੀ)ssh; (ਖਾਲੀ)user;
    (ਖਾਲੀ)hostname; (ਖਾਲੀ)ttyname; }
ਪੂਰਨ temporarily_use_uid(ਬਣਤਰ passwd *pw) { (ਖਾਲੀ)pw; ਵਾਪਸ 0; }
ਖਾਲੀ restore_uid(ਖਾਲੀ) { }
ਖਾਲੀ platform_setusercontext(ਬਣਤਰ passwd *pw) { (ਖਾਲੀ)pw; }
ਖਾਲੀ platform_setusercontext_post_groups(ਬਣਤਰ passwd *pw) { (ਖਾਲੀ)pw; }
ਬਣਤਰ connection_info *
server_get_connection_info(ਬਣਤਰ ssh *ssh, ਪੂਰਨ populate, ਪੂਰਨ use_dns)
    { (ਖਾਲੀ)ssh; (ਖਾਲੀ)populate; (ਖਾਲੀ)use_dns; ਵਾਪਸ ਨਿਰਾ; }
ਪੂਰਨ auth2_methods_valid(ਅਚਲ ਅੱਖਰ *list, ਪੂਰਨ allow_unknown)
    { (ਖਾਲੀ)list; (ਖਾਲੀ)allow_unknown; ਵਾਪਸ 0; }
ਬਣਤਰ sshbuf *cfg = ਨਿਰਾ;
ਪੂਰਨ auth_sock = -1;
ਅੱਖਰ **tun_fwd_ifnames = ਨਿਰਾ;

ਬਣਤਰ logininfo *login_get_lastlog(ਬਣਤਰ logininfo *li, ਅਚਲ uid_t uid)
    { (ਖਾਲੀ)li; (ਖਾਲੀ)uid; ਵਾਪਸ ਨਿਰਾ; }
ਬਣਤਰ logininfo *login_alloc_ਇੰਦਰਾਜ(pid_t pid, ਅਚਲ ਅੱਖਰ *username,
    ਅਚਲ ਅੱਖਰ *hostname, ਅਚਲ ਅੱਖਰ *ਸਤਰ)
    { (ਖਾਲੀ)pid; (ਖਾਲੀ)username; (ਖਾਲੀ)hostname; (ਖਾਲੀ)ਸਤਰ; ਵਾਪਸ ਨਿਰਾ; }
ਖਾਲੀ server_process_permitopen(ਬਣਤਰ ssh *ssh) { (ਖਾਲੀ)ssh; }
ਖਾਲੀ server_process_channel_timeouts(ਬਣਤਰ ssh *ssh) { (ਖਾਲੀ)ssh; }
ਪੂਰਨ server_loop2(ਬਣਤਰ ssh *ssh, Authctxt *authctxt)
    { (ਖਾਲੀ)ssh; (ਖਾਲੀ)authctxt; ਵਾਪਸ 0; }
ਪੂਰਨ platform_privileged_uidswap(ਖਾਲੀ) { ਵਾਪਸ 0; }
ਪੂਰਨ sftp_server_main(ਪੂਰਨ argc, ਅੱਖਰ **argv, ਬਣਤਰ passwd *user_pw)
    { (ਖਾਲੀ)argc; (ਖਾਲੀ)argv; (ਖਾਲੀ)user_pw; ਵਾਪਸ 0; }
ਪੂਰਨ debug_flag = 0;
ਖਾਲੀ permanently_ਸੈੱਟ_uid(ਬਣਤਰ passwd *pw) { (ਖਾਲੀ)pw; }
ਪੂਰਨ login_login(ਬਣਤਰ logininfo *li) { (ਖਾਲੀ)li; ਵਾਪਸ 0; }
ਪੂਰਨ login_logout(ਬਣਤਰ logininfo *li) { (ਖਾਲੀ)li; ਵਾਪਸ 0; }
ਖਾਲੀ login_free_ਇੰਦਰਾਜ(ਬਣਤਰ logininfo *li) { (ਖਾਲੀ)li; }
ਖਾਲੀ login_ਸੈੱਟ_addr(ਬਣਤਰ logininfo *li, ਅਚਲ ਬਣਤਰ sockaddr *sa,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ sa_ਮਾਪ) { (ਖਾਲੀ)li; (ਖਾਲੀ)sa; (ਖਾਲੀ)sa_ਮਾਪ; }
ਪੂਰਨ openpty(ਪੂਰਨ *amaster, ਪੂਰਨ *aslave, ਅੱਖਰ *name,
    ਅਚਲ ਬਣਤਰ termios *termp, ਅਚਲ ਬਣਤਰ winsize *winp)
    { (ਖਾਲੀ)termp; (ਖਾਲੀ)winp; *amaster = -1; *aslave = -1;
    ਜੇ (name) name[0] = '\0'; ਵਾਪਸ -1; }

ਬਾਹਰੀ ਪੂਰਨ __real_do_exec(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);
ਬਾਹਰੀ ਪੂਰਨ __real_do_exec_pty(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);
ਬਾਹਰੀ ਪੂਰਨ __real_do_exec_no_pty(ਬਣਤਰ ssh *, Session *, ਅਚਲ ਅੱਖਰ *);

ਪੂਰਨ
__wrap_do_exec(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)s;
	(ਖਾਲੀ)command;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
__wrap_do_exec_pty(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)s;
	(ਖਾਲੀ)command;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
__wrap_do_exec_no_pty(ਬਣਤਰ ssh *ssh, Session *s, ਅਚਲ ਅੱਖਰ *command)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)s;
	(ਖਾਲੀ)command;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *str)
{
	ਬਣਤਰ sshbuf *b = sshbuf_from(str, ਲੜੀ_ਲੰਬਾਈ(str));
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਜੇ (b == ਨਿਰਾ || sshkey_parse_ਨਿੱਜੀ_fileblob(b, "", &k, ਨਿਰਾ) != 0)
		abort();
	sshbuf_free(b);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *str)
{
	ਅੱਖਰ *tmp, *cp;
	ਬਣਤਰ sshkey *k = sshkey_new(ਕੁੰਜੀ_UNSPEC);
	ਜੇ (k == ਨਿਰਾ)
		abort();
	tmp = cp = strdup(str);
	ਜੇ (sshkey_read(k, &cp) != 0)
		abort();
	ਮੁਕਤ(tmp);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਪੂਰਨ
pump(ਬਣਤਰ ssh *from, ਬਣਤਰ ssh *ਮੰਜ਼ਿਲ, ਮਾਪ_t *transferred)
{
	ਅਚਲ u_char *buf;
	ਮਾਪ_t len;
	u_char type;
	ਪੂਰਨ r;
	*transferred = 0;
	ਜੇ ((r = ssh_packet_ਅਗਲਾ(from, &type)) != 0)
		ਵਾਪਸ r;
	buf = ssh_output_ptr(from, &len);
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ ((r = ssh_ਨਿਵੇਸ਼_append(ਮੰਜ਼ਿਲ, buf, len)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = ssh_output_consume(from, len)) != 0)
		ਵਾਪਸ r;
	*transferred = len;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਲੜੀਵਾਰ_kex(ਬਣਤਰ ssh *client, ਬਣਤਰ ssh *server)
{
	ਪੂਰਨ r;
	ਮਾਪ_t cn, sn;
	ਲਈ (ਪੂਰਨ i = 0; i < 100; i++) {
		ਜੇ ((r = pump(server, client, &sn)) != 0) ਵਾਪਸ r;
		ਜੇ ((r = pump(client, server, &cn)) != 0) ਵਾਪਸ r;
		ਜੇ (server->kex->ਪੂਰਾ && client->kex->ਪੂਰਾ)
			ਵਾਪਸ 0;
		ਜੇ (cn == 0 && sn == 0)
			ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
	}
	ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
}

#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"

ਸਥਿਰ ਬਣਤਰ ssh *g_client = ਨਿਰਾ;
ਸਥਿਰ ਬਣਤਰ ssh *g_server = ਨਿਰਾ;
ਸਥਿਰ ਪੂਰਨ g_init = 0;
ਸਥਿਰ ਪੂਰਨ g_channel_id = -1;
ਸਥਿਰ Authctxt g_authctxt;
ਸਥਿਰ ਬਣਤਰ passwd g_fake_pw;

ਸਥਿਰ ਅੱਖਰ *g_pending_rtype = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *g_pending_exec_cmd = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *g_pending_env_name = ਨਿਰਾ;
ਸਥਿਰ ਅੱਖਰ *g_pending_env_val = ਨਿਰਾ;

ਸਥਿਰ ਖਾਲੀ
my_session_exec_req(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;
	ਜੇ ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ਸਥਿਰ ਖਾਲੀ
my_session_env_req(ਬਣਤਰ ssh *ssh)
{
	ਪੂਰਨ r;
	ਜੇ ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ਸਥਿਰ ਪੂਰਨ
ਨਿਵੇਸ਼_channel_request(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	uint32_t chan_id;
	u_char want_ਜਵਾਬ;

	(ਖਾਲੀ)type;
	(ਖਾਲੀ)seq;
	ਜੇ (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ਨਿਰਾ) != 0 ||
	    sshpkt_get_u8(ssh, &want_ਜਵਾਬ) != 0)
		ਵਾਪਸ 0;
	ਜੇ (g_channel_id >= 0 && g_pending_rtype != ਨਿਰਾ) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ਜੇ (c != ਨਿਰਾ) {
			ਜੇ (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			ਨਹੀਂਤਾਂ
				(ਖਾਲੀ)session_ਨਿਵੇਸ਼_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
reset_channel(ਬਣਤਰ ssh *ssh)
{
	ਜੇ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ਜੇ (c != ਨਿਰਾ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (ਅੱਖਰ *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (ਅੱਖਰ *)"fuzz", 0);
	ਜੇ (c == ਨਿਰਾ)
		ਵਾਪਸ;
	g_channel_id = c->self;
	Session *s = session_new();
	ਜੇ (s != ਨਿਰਾ) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

ਸਥਿਰ ਪੂਰਨ
init_once(ਖਾਲੀ)
{
	ਜੇ (g_init)
		ਵਾਪਸ 0;
	ਸੰਕੇਤ(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ਆਕਾਰ(g_fake_pw));
	g_fake_pw.pw_name = (ਅੱਖਰ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ਅੱਖਰ *)"/tmp";
	g_fake_pw.pw_shell = (ਅੱਖਰ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, ਆਕਾਰ(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	ਬਣਤਰ sshkey *priv = ਲੱਦੋ_ਨਿੱਜੀ(PRIV_ED25519);
	ਬਣਤਰ sshkey *pub = ਲੱਦੋ_ਜਨਤਕ(PUB_ED25519);
	ਅੱਖਰ *keyname = xstrdup(sshkey_ssh_name(priv));

	ਅਚਲ ਅੱਖਰ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅੱਖਰ *proposal[PROPOSAL_MAX] = { 0 };
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਅਚਲ ਅੱਖਰ *p = defaults[i];
		ਜੇ (i == PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS)
			p = keyname;
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ਬਣਤਰ kex_params kp;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(kp.proposal, proposal, ਆਕਾਰ(proposal));

	ਜੇ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ssh_ਜੋੜੋ_hostkey(g_server, priv) != 0 ||
	    ssh_ਜੋੜੋ_hostkey(g_client, pub) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ਲੜੀਵਾਰ_kex(g_client, g_server) != 0)
		ਵਾਪਸ -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_ਸੈੱਟ(g_server, SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST,
	    &ਨਿਵੇਸ਼_channel_request);

	ਮੁਕਤ(keyname);
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(proposal[i]);
	g_init = 1;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
fuzz_session_one(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (init_once() != 0)
		ਵਾਪਸ;
	ਜੇ (ਮਾਪ > 65000)
		ਵਾਪਸ;

	reset_channel(g_server);

	ਵਿੱਚ_fuzz = 1;
	ਜੇ (setjmp(fuzz_env) == 0) {
		ਮਾਪ_t transferred;
		ਜੇ (ssh_packet_put(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST,
		    ਅੰਕੜੇ, ਮਾਪ) != 0)
			ਜਾਓ ਪੂਰਾ;
		ਜੇ (pump(g_client, g_server, &transferred) != 0)
			ਜਾਓ ਪੂਰਾ;
		(ਖਾਲੀ)ssh_dispatch_ਲੜੀਵਾਰ(g_server, DISPATCH_NONBLOCK, ਨਿਰਾ);
	ਪੂਰਾ:
		;
	}
	ਵਿੱਚ_fuzz = 0;
	ਮੁਕਤ(g_pending_rtype);
	g_pending_rtype = ਨਿਰਾ;
	ਮੁਕਤ(g_pending_exec_cmd);
	g_pending_exec_cmd = ਨਿਰਾ;
	ਮੁਕਤ(g_pending_env_name);
	g_pending_env_name = ਨਿਰਾ;
	ਮੁਕਤ(g_pending_env_val);
	g_pending_env_val = ਨਿਰਾ;
}
