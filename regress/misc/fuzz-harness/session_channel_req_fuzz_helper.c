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

#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "session.h"

ServerOptions options;
ഘടന sshbuf *loginmsg = ശൂന്യ;
ഘടന include_list includes;
സ്ഥിതം ഘടന sshauthopt g_auth_opts_storage;
ഘടന sshauthopt *auth_opts = &g_auth_opts_storage;
ഘടന passwd *privsep_pw = ശൂന്യ;

സ്ഥിതം jmp_buf fuzz_env;
സ്ഥിതം അസ്ഥിര പൂർണ്ണസംഖ്യ in_fuzz = 0;

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ശൂന്യം
__wrap_ssh_packet_disconnect(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)fmt;
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

പൂർണ്ണസംഖ്യ
__wrap_sshpkt_fatal(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ r, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)fmt;
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

പൂർണ്ണസംഖ്യ
mm_is_monitor(ശൂന്യം)
{
	തിരികെ 0;
}

ശൂന്യം
mm_audit_run_command(സ്ഥിരം അക്ഷരം *cmd)
{
	(ശൂന്യം)cmd;
}

പൂർണ്ണസംഖ്യ
mm_pty_allocate(പൂർണ്ണസംഖ്യ *ptyfd, പൂർണ്ണസംഖ്യ *ttyfd, അക്ഷരം *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	എങ്കിൽ (namebuf != ശൂന്യ && namebuflen > 0)
		namebuf[0] = '\0';
	തിരികെ 0;
}

ശൂന്യം mm_session_pty_cleanup2(Session *s) { (ശൂന്യം)s; }
പൂർണ്ണസംഖ്യ platform_locked_account(ഘടന passwd *pw) { (ശൂന്യം)pw; തിരികെ 0; }
ശൂന്യം record_failed_login(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *user,
    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *ttyname) { (ശൂന്യം)ssh; (ശൂന്യം)user;
    (ശൂന്യം)hostname; (ശൂന്യം)ttyname; }
പൂർണ്ണസംഖ്യ temporarily_use_uid(ഘടന passwd *pw) { (ശൂന്യം)pw; തിരികെ 0; }
ശൂന്യം restore_uid(ശൂന്യം) { }
ശൂന്യം platform_setusercontext(ഘടന passwd *pw) { (ശൂന്യം)pw; }
ശൂന്യം platform_setusercontext_post_groups(ഘടന passwd *pw) { (ശൂന്യം)pw; }
ഘടന connection_info *
server_get_connection_info(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ populate, പൂർണ്ണസംഖ്യ use_dns)
    { (ശൂന്യം)ssh; (ശൂന്യം)populate; (ശൂന്യം)use_dns; തിരികെ ശൂന്യ; }
പൂർണ്ണസംഖ്യ auth2_methods_valid(സ്ഥിരം അക്ഷരം *list, പൂർണ്ണസംഖ്യ allow_unknown)
    { (ശൂന്യം)list; (ശൂന്യം)allow_unknown; തിരികെ 0; }
ഘടന sshbuf *cfg = ശൂന്യ;
പൂർണ്ണസംഖ്യ auth_sock = -1;
അക്ഷരം **tun_fwd_ifnames = ശൂന്യ;

ഘടന logininfo *login_get_lastlog(ഘടന logininfo *li, സ്ഥിരം uid_t uid)
    { (ശൂന്യം)li; (ശൂന്യം)uid; തിരികെ ശൂന്യ; }
ഘടന logininfo *login_alloc_entry(pid_t pid, സ്ഥിരം അക്ഷരം *username,
    സ്ഥിരം അക്ഷരം *hostname, സ്ഥിരം അക്ഷരം *വരി)
    { (ശൂന്യം)pid; (ശൂന്യം)username; (ശൂന്യം)hostname; (ശൂന്യം)വരി; തിരികെ ശൂന്യ; }
ശൂന്യം server_process_permitopen(ഘടന ssh *ssh) { (ശൂന്യം)ssh; }
ശൂന്യം server_process_channel_timeouts(ഘടന ssh *ssh) { (ശൂന്യം)ssh; }
പൂർണ്ണസംഖ്യ server_loop2(ഘടന ssh *ssh, Authctxt *authctxt)
    { (ശൂന്യം)ssh; (ശൂന്യം)authctxt; തിരികെ 0; }
പൂർണ്ണസംഖ്യ platform_privileged_uidswap(ശൂന്യം) { തിരികെ 0; }
പൂർണ്ണസംഖ്യ sftp_server_main(പൂർണ്ണസംഖ്യ argc, അക്ഷരം **argv, ഘടന passwd *user_pw)
    { (ശൂന്യം)argc; (ശൂന്യം)argv; (ശൂന്യം)user_pw; തിരികെ 0; }
പൂർണ്ണസംഖ്യ debug_flag = 0;
ശൂന്യം permanently_set_uid(ഘടന passwd *pw) { (ശൂന്യം)pw; }
പൂർണ്ണസംഖ്യ login_login(ഘടന logininfo *li) { (ശൂന്യം)li; തിരികെ 0; }
പൂർണ്ണസംഖ്യ login_logout(ഘടന logininfo *li) { (ശൂന്യം)li; തിരികെ 0; }
ശൂന്യം login_free_entry(ഘടന logininfo *li) { (ശൂന്യം)li; }
ശൂന്യം login_set_addr(ഘടന logininfo *li, സ്ഥിരം ഘടന sockaddr *sa,
    സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ sa_size) { (ശൂന്യം)li; (ശൂന്യം)sa; (ശൂന്യം)sa_size; }
പൂർണ്ണസംഖ്യ openpty(പൂർണ്ണസംഖ്യ *amaster, പൂർണ്ണസംഖ്യ *aslave, അക്ഷരം *name,
    സ്ഥിരം ഘടന termios *termp, സ്ഥിരം ഘടന winsize *winp)
    { (ശൂന്യം)termp; (ശൂന്യം)winp; *amaster = -1; *aslave = -1;
    എങ്കിൽ (name) name[0] = '\0'; തിരികെ -1; }

ബാഹ്യ പൂർണ്ണസംഖ്യ __real_do_exec(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);
ബാഹ്യ പൂർണ്ണസംഖ്യ __real_do_exec_pty(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);
ബാഹ്യ പൂർണ്ണസംഖ്യ __real_do_exec_no_pty(ഘടന ssh *, Session *, സ്ഥിരം അക്ഷരം *);

പൂർണ്ണസംഖ്യ
__wrap_do_exec(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)s;
	(ശൂന്യം)command;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
__wrap_do_exec_pty(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)s;
	(ശൂന്യം)command;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
__wrap_do_exec_no_pty(ഘടന ssh *ssh, Session *s, സ്ഥിരം അക്ഷരം *command)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)s;
	(ശൂന്യം)command;
	തിരികെ 0;
}

സ്ഥിതം ഘടന sshkey *
load_private(സ്ഥിരം അക്ഷരം *str)
{
	ഘടന sshbuf *b = sshbuf_from(str, strlen(str));
	ഘടന sshkey *k = ശൂന്യ;
	എങ്കിൽ (b == ശൂന്യ || sshkey_parse_private_fileblob(b, "", &k, ശൂന്യ) != 0)
		abort();
	sshbuf_free(b);
	തിരികെ k;
}

സ്ഥിതം ഘടന sshkey *
load_public(സ്ഥിരം അക്ഷരം *str)
{
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *k = sshkey_new(താക്കോൽ_UNSPEC);
	എങ്കിൽ (k == ശൂന്യ)
		abort();
	tmp = cp = strdup(str);
	എങ്കിൽ (sshkey_read(k, &cp) != 0)
		abort();
	സ്വതന്ത്രം(tmp);
	തിരികെ k;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pump(ഘടന ssh *from, ഘടന ssh *to, size_t *transferred)
{
	സ്ഥിരം u_char *buf;
	size_t len;
	u_char type;
	പൂർണ്ണസംഖ്യ r;
	*transferred = 0;
	എങ്കിൽ ((r = ssh_packet_next(from, &type)) != 0)
		തിരികെ r;
	buf = ssh_output_ptr(from, &len);
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ ((r = ssh_നിവേശം_append(to, buf, len)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = ssh_output_consume(from, len)) != 0)
		തിരികെ r;
	*transferred = len;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
run_kex(ഘടന ssh *client, ഘടന ssh *server)
{
	പൂർണ്ണസംഖ്യ r;
	size_t cn, sn;
	വേണ്ടി (പൂർണ്ണസംഖ്യ i = 0; i < 100; i++) {
		എങ്കിൽ ((r = pump(server, client, &sn)) != 0) തിരികെ r;
		എങ്കിൽ ((r = pump(client, server, &cn)) != 0) തിരികെ r;
		എങ്കിൽ (server->kex->done && client->kex->done)
			തിരികെ 0;
		എങ്കിൽ (cn == 0 && sn == 0)
			തിരികെ SSH_ERR_PROTOCOL_ERROR;
	}
	തിരികെ SSH_ERR_PROTOCOL_ERROR;
}

#അന്തര്ഭാവ "fixed-keys.h"

സ്ഥിതം ഘടന ssh *g_client = ശൂന്യ;
സ്ഥിതം ഘടന ssh *g_server = ശൂന്യ;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_init = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_channel_id = -1;
സ്ഥിതം Authctxt g_authctxt;
സ്ഥിതം ഘടന passwd g_fake_pw;

സ്ഥിതം അക്ഷരം *g_pending_rtype = ശൂന്യ;
സ്ഥിതം അക്ഷരം *g_pending_exec_cmd = ശൂന്യ;
സ്ഥിതം അക്ഷരം *g_pending_env_name = ശൂന്യ;
സ്ഥിതം അക്ഷരം *g_pending_env_val = ശൂന്യ;

സ്ഥിതം ശൂന്യം
my_session_exec_req(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

സ്ഥിതം ശൂന്യം
my_session_env_req(ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_channel_request(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(ശൂന്യം)type;
	(ശൂന്യം)seq;
	എങ്കിൽ (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ശൂന്യ) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		തിരികെ 0;
	എങ്കിൽ (g_channel_id >= 0 && g_pending_rtype != ശൂന്യ) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		എങ്കിൽ (c != ശൂന്യ) {
			എങ്കിൽ (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			അല്ലെങ്കിൽ
				(ശൂന്യം)session_നിവേശം_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
reset_channel(ഘടന ssh *ssh)
{
	എങ്കിൽ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		എങ്കിൽ (c != ശൂന്യ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (അക്ഷരം *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (അക്ഷരം *)"fuzz", 0);
	എങ്കിൽ (c == ശൂന്യ)
		തിരികെ;
	g_channel_id = c->self;
	Session *s = session_new();
	എങ്കിൽ (s != ശൂന്യ) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
init_once(ശൂന്യം)
{
	എങ്കിൽ (g_init)
		തിരികെ 0;
	സൂചന(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, വലുപ്പം(g_fake_pw));
	g_fake_pw.pw_name = (അക്ഷരം *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (അക്ഷരം *)"/tmp";
	g_fake_pw.pw_shell = (അക്ഷരം *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, വലുപ്പം(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	ഘടന sshkey *priv = load_private(PRIV_ED25519);
	ഘടന sshkey *pub = load_public(PUB_ED25519);
	അക്ഷരം *keyname = xstrdup(sshkey_ssh_name(priv));

	സ്ഥിരം അക്ഷരം *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *proposal[PROPOSAL_MAX] = { 0 };
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		സ്ഥിരം അക്ഷരം *p = defaults[i];
		എങ്കിൽ (i == PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS)
			p = keyname;
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ഘടന kex_params kp;
	memcpy(kp.proposal, proposal, വലുപ്പം(proposal));

	എങ്കിൽ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		തിരികെ -1;
	എങ്കിൽ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		തിരികെ -1;
	എങ്കിൽ (run_kex(g_client, g_server) != 0)
		തിരികെ -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_സന്ദേശം_CHANNEL_REQUEST,
	    &നിവേശം_channel_request);

	സ്വതന്ത്രം(keyname);
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(proposal[i]);
	g_init = 1;
	തിരികെ 0;
}

ശൂന്യം
fuzz_session_one(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (init_once() != 0)
		തിരികെ;
	എങ്കിൽ (size > 65000)
		തിരികെ;

	reset_channel(g_server);

	in_fuzz = 1;
	എങ്കിൽ (setjmp(fuzz_env) == 0) {
		size_t transferred;
		എങ്കിൽ (ssh_packet_put(g_client, SSH2_സന്ദേശം_CHANNEL_REQUEST,
		    data, size) != 0)
			പോകുക done;
		എങ്കിൽ (pump(g_client, g_server, &transferred) != 0)
			പോകുക done;
		(ശൂന്യം)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ശൂന്യ);
	done:
		;
	}
	in_fuzz = 0;
	സ്വതന്ത്രം(g_pending_rtype);
	g_pending_rtype = ശൂന്യ;
	സ്വതന്ത്രം(g_pending_exec_cmd);
	g_pending_exec_cmd = ശൂന്യ;
	സ്വതന്ത്രം(g_pending_env_name);
	g_pending_env_name = ശൂന്യ;
	സ്വതന്ത്രം(g_pending_env_val);
	g_pending_env_val = ശൂന്യ;
}
