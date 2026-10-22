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

#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "session.h"

ServerOptions options;
સંરચના sshbuf *loginmsg = ખાલી;
સંરચના include_list includes;
સ્થિર સંરચના sshauthopt g_auth_opts_storage;
સંરચના sshauthopt *auth_opts = &g_auth_opts_storage;
સંરચના passwd *privsep_pw = ખાલી;

સ્થિર jmp_buf fuzz_env;
સ્થિર અસ્થિર પૂર્ણાંક in_fuzz = 0;

શૂન્ય
cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

શૂન્ય
__wrap_ssh_packet_disconnect(સંરચના ssh *ssh, અચલ અક્ષર *fmt, ...)
{
	(શૂન્ય)ssh;
	(શૂન્ય)fmt;
	જો (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

પૂર્ણાંક
__wrap_sshpkt_fatal(સંરચના ssh *ssh, પૂર્ણાંક r, અચલ અક્ષર *fmt, ...)
{
	(શૂન્ય)ssh;
	(શૂન્ય)fmt;
	જો (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

પૂર્ણાંક
mm_is_monitor(શૂન્ય)
{
	પાછા 0;
}

શૂન્ય
mm_audit_run_command(અચલ અક્ષર *cmd)
{
	(શૂન્ય)cmd;
}

પૂર્ણાંક
mm_pty_allocate(પૂર્ણાંક *ptyfd, પૂર્ણાંક *ttyfd, અક્ષર *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	જો (namebuf != ખાલી && namebuflen > 0)
		namebuf[0] = '\0';
	પાછા 0;
}

શૂન્ય mm_session_pty_cleanup2(Session *s) { (શૂન્ય)s; }
પૂર્ણાંક platform_locked_account(સંરચના passwd *pw) { (શૂન્ય)pw; પાછા 0; }
શૂન્ય record_failed_login(સંરચના ssh *ssh, અચલ અક્ષર *user,
    અચલ અક્ષર *hostname, અચલ અક્ષર *ttyname) { (શૂન્ય)ssh; (શૂન્ય)user;
    (શૂન્ય)hostname; (શૂન્ય)ttyname; }
પૂર્ણાંક temporarily_use_uid(સંરચના passwd *pw) { (શૂન્ય)pw; પાછા 0; }
શૂન્ય restore_uid(શૂન્ય) { }
શૂન્ય platform_setusercontext(સંરચના passwd *pw) { (શૂન્ય)pw; }
શૂન્ય platform_setusercontext_post_groups(સંરચના passwd *pw) { (શૂન્ય)pw; }
સંરચના connection_info *
server_get_connection_info(સંરચના ssh *ssh, પૂર્ણાંક populate, પૂર્ણાંક use_dns)
    { (શૂન્ય)ssh; (શૂન્ય)populate; (શૂન્ય)use_dns; પાછા ખાલી; }
પૂર્ણાંક auth2_methods_valid(અચલ અક્ષર *list, પૂર્ણાંક allow_unknown)
    { (શૂન્ય)list; (શૂન્ય)allow_unknown; પાછા 0; }
સંરચના sshbuf *cfg = ખાલી;
પૂર્ણાંક auth_sock = -1;
અક્ષર **tun_fwd_ifnames = ખાલી;

સંરચના logininfo *login_get_lastlog(સંરચના logininfo *li, અચલ uid_t uid)
    { (શૂન્ય)li; (શૂન્ય)uid; પાછા ખાલી; }
સંરચના logininfo *login_alloc_entry(pid_t pid, અચલ અક્ષર *username,
    અચલ અક્ષર *hostname, અચલ અક્ષર *લીટી)
    { (શૂન્ય)pid; (શૂન્ય)username; (શૂન્ય)hostname; (શૂન્ય)લીટી; પાછા ખાલી; }
શૂન્ય server_process_permitopen(સંરચના ssh *ssh) { (શૂન્ય)ssh; }
શૂન્ય server_process_channel_timeouts(સંરચના ssh *ssh) { (શૂન્ય)ssh; }
પૂર્ણાંક server_loop2(સંરચના ssh *ssh, Authctxt *authctxt)
    { (શૂન્ય)ssh; (શૂન્ય)authctxt; પાછા 0; }
પૂર્ણાંક platform_privileged_uidswap(શૂન્ય) { પાછા 0; }
પૂર્ણાંક sftp_server_main(પૂર્ણાંક argc, અક્ષર **argv, સંરચના passwd *user_pw)
    { (શૂન્ય)argc; (શૂન્ય)argv; (શૂન્ય)user_pw; પાછા 0; }
પૂર્ણાંક debug_flag = 0;
શૂન્ય permanently_set_uid(સંરચના passwd *pw) { (શૂન્ય)pw; }
પૂર્ણાંક login_login(સંરચના logininfo *li) { (શૂન્ય)li; પાછા 0; }
પૂર્ણાંક login_logout(સંરચના logininfo *li) { (શૂન્ય)li; પાછા 0; }
શૂન્ય login_free_entry(સંરચના logininfo *li) { (શૂન્ય)li; }
શૂન્ય login_set_addr(સંરચના logininfo *li, અચલ સંરચના sockaddr *sa,
    અચલ unsigned પૂર્ણાંક sa_size) { (શૂન્ય)li; (શૂન્ય)sa; (શૂન્ય)sa_size; }
પૂર્ણાંક openpty(પૂર્ણાંક *amaster, પૂર્ણાંક *aslave, અક્ષર *name,
    અચલ સંરચના termios *termp, અચલ સંરચના winsize *winp)
    { (શૂન્ય)termp; (શૂન્ય)winp; *amaster = -1; *aslave = -1;
    જો (name) name[0] = '\0'; પાછા -1; }

બાહ્ય પૂર્ણાંક __real_do_exec(સંરચના ssh *, Session *, અચલ અક્ષર *);
બાહ્ય પૂર્ણાંક __real_do_exec_pty(સંરચના ssh *, Session *, અચલ અક્ષર *);
બાહ્ય પૂર્ણાંક __real_do_exec_no_pty(સંરચના ssh *, Session *, અચલ અક્ષર *);

પૂર્ણાંક
__wrap_do_exec(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	(શૂન્ય)ssh;
	(શૂન્ય)s;
	(શૂન્ય)command;
	પાછા 0;
}

પૂર્ણાંક
__wrap_do_exec_pty(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	(શૂન્ય)ssh;
	(શૂન્ય)s;
	(શૂન્ય)command;
	પાછા 0;
}

પૂર્ણાંક
__wrap_do_exec_no_pty(સંરચના ssh *ssh, Session *s, અચલ અક્ષર *command)
{
	(શૂન્ય)ssh;
	(શૂન્ય)s;
	(શૂન્ય)command;
	પાછા 0;
}

સ્થિર સંરચના sshkey *
load_private(અચલ અક્ષર *str)
{
	સંરચના sshbuf *b = sshbuf_from(str, strlen(str));
	સંરચના sshkey *k = ખાલી;
	જો (b == ખાલી || sshkey_parse_private_fileblob(b, "", &k, ખાલી) != 0)
		abort();
	sshbuf_free(b);
	પાછા k;
}

સ્થિર સંરચના sshkey *
load_public(અચલ અક્ષર *str)
{
	અક્ષર *tmp, *cp;
	સંરચના sshkey *k = sshkey_new(ચાવી_UNSPEC);
	જો (k == ખાલી)
		abort();
	tmp = cp = strdup(str);
	જો (sshkey_read(k, &cp) != 0)
		abort();
	મુક્ત(tmp);
	પાછા k;
}

સ્થિર પૂર્ણાંક
pump(સંરચના ssh *from, સંરચના ssh *to, size_t *transferred)
{
	અચલ u_char *buf;
	size_t len;
	u_char type;
	પૂર્ણાંક r;
	*transferred = 0;
	જો ((r = ssh_packet_next(from, &type)) != 0)
		પાછા r;
	buf = ssh_output_ptr(from, &len);
	જો (len == 0)
		પાછા 0;
	જો ((r = ssh_આગત_append(to, buf, len)) != 0)
		પાછા r;
	જો ((r = ssh_output_consume(from, len)) != 0)
		પાછા r;
	*transferred = len;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
run_kex(સંરચના ssh *client, સંરચના ssh *server)
{
	પૂર્ણાંક r;
	size_t cn, sn;
	માટે (પૂર્ણાંક i = 0; i < 100; i++) {
		જો ((r = pump(server, client, &sn)) != 0) પાછા r;
		જો ((r = pump(client, server, &cn)) != 0) પાછા r;
		જો (server->kex->done && client->kex->done)
			પાછા 0;
		જો (cn == 0 && sn == 0)
			પાછા SSH_ERR_PROTOCOL_ERROR;
	}
	પાછા SSH_ERR_PROTOCOL_ERROR;
}

#અન્તર્ભાવ "fixed-keys.h"

સ્થિર સંરચના ssh *g_client = ખાલી;
સ્થિર સંરચના ssh *g_server = ખાલી;
સ્થિર પૂર્ણાંક g_init = 0;
સ્થિર પૂર્ણાંક g_channel_id = -1;
સ્થિર Authctxt g_authctxt;
સ્થિર સંરચના passwd g_fake_pw;

સ્થિર અક્ષર *g_pending_rtype = ખાલી;
સ્થિર અક્ષર *g_pending_exec_cmd = ખાલી;
સ્થિર અક્ષર *g_pending_env_name = ખાલી;
સ્થિર અક્ષર *g_pending_env_val = ખાલી;

સ્થિર શૂન્ય
my_session_exec_req(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;
	જો ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

સ્થિર શૂન્ય
my_session_env_req(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;
	જો ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ખાલી)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

સ્થિર પૂર્ણાંક
આગત_channel_request(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(શૂન્ય)type;
	(શૂન્ય)seq;
	જો (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ખાલી) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		પાછા 0;
	જો (g_channel_id >= 0 && g_pending_rtype != ખાલી) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		જો (c != ખાલી) {
			જો (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			નહીંતર જો (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			નહીંતર
				(શૂન્ય)session_આગત_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	પાછા 0;
}

સ્થિર શૂન્ય
reset_channel(સંરચના ssh *ssh)
{
	જો (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		જો (c != ખાલી)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (અક્ષર *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (અક્ષર *)"fuzz", 0);
	જો (c == ખાલી)
		પાછા;
	g_channel_id = c->self;
	Session *s = session_new();
	જો (s != ખાલી) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

સ્થિર પૂર્ણાંક
init_once(શૂન્ય)
{
	જો (g_init)
		પાછા 0;
	સંકેત(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, કદ(g_fake_pw));
	g_fake_pw.pw_name = (અક્ષર *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (અક્ષર *)"/tmp";
	g_fake_pw.pw_shell = (અક્ષર *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, કદ(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	સંરચના sshkey *priv = load_private(PRIV_ED25519);
	સંરચના sshkey *pub = load_public(PUB_ED25519);
	અક્ષર *keyname = xstrdup(sshkey_ssh_name(priv));

	અચલ અક્ષર *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *proposal[PROPOSAL_MAX] = { 0 };
	પૂર્ણાંક i;
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		અચલ અક્ષર *p = defaults[i];
		જો (i == PROPOSAL_SERVER_HOST_ચાવી_ALGS)
			p = keyname;
		નહીંતર જો (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		નહીંતર જો (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		નહીંતર જો (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	સંરચના kex_params kp;
	memcpy(kp.proposal, proposal, કદ(proposal));

	જો (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		પાછા -1;
	જો (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		પાછા -1;
	જો (run_kex(g_client, g_server) != 0)
		પાછા -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_સંદેશ_CHANNEL_REQUEST,
	    &આગત_channel_request);

	મુક્ત(keyname);
	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(proposal[i]);
	g_init = 1;
	પાછા 0;
}

શૂન્ય
fuzz_session_one(અચલ uint8_t *data, size_t size)
{
	જો (init_once() != 0)
		પાછા;
	જો (size > 65000)
		પાછા;

	reset_channel(g_server);

	in_fuzz = 1;
	જો (setjmp(fuzz_env) == 0) {
		size_t transferred;
		જો (ssh_packet_put(g_client, SSH2_સંદેશ_CHANNEL_REQUEST,
		    data, size) != 0)
			જાઓ done;
		જો (pump(g_client, g_server, &transferred) != 0)
			જાઓ done;
		(શૂન્ય)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ખાલી);
	done:
		;
	}
	in_fuzz = 0;
	મુક્ત(g_pending_rtype);
	g_pending_rtype = ખાલી;
	મુક્ત(g_pending_exec_cmd);
	g_pending_exec_cmd = ખાલી;
	મુક્ત(g_pending_env_name);
	g_pending_env_name = ખાલી;
	મુક્ત(g_pending_env_val);
	g_pending_env_val = ખાલી;
}
