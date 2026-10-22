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

#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "session.h"

ServerOptions options;
கட்டமைப்பு sshbuf *loginmsg = வெற்று;
கட்டமைப்பு include_list includes;
நிலையான கட்டமைப்பு sshauthopt g_auth_opts_storage;
கட்டமைப்பு sshauthopt *auth_opts = &g_auth_opts_storage;
கட்டமைப்பு passwd *privsep_pw = வெற்று;

நிலையான jmp_buf fuzz_env;
நிலையான நிலையற்ற முழு in_fuzz = 0;

வெறுமை
cleanup_exit(முழு code)
{
	எனில் (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

வெறுமை
__wrap_ssh_packet_disconnect(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *fmt, ...)
{
	(வெறுமை)ssh;
	(வெறுமை)fmt;
	எனில் (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

முழு
__wrap_sshpkt_fatal(கட்டமைப்பு ssh *ssh, முழு r, மாறிலி எழுத்து *fmt, ...)
{
	(வெறுமை)ssh;
	(வெறுமை)fmt;
	எனில் (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

முழு
mm_is_monitor(வெறுமை)
{
	திரும்பு 0;
}

வெறுமை
mm_audit_run_command(மாறிலி எழுத்து *cmd)
{
	(வெறுமை)cmd;
}

முழு
mm_pty_allocate(முழு *ptyfd, முழு *ttyfd, எழுத்து *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	எனில் (namebuf != வெற்று && namebuflen > 0)
		namebuf[0] = '\0';
	திரும்பு 0;
}

வெறுமை mm_session_pty_cleanup2(Session *s) { (வெறுமை)s; }
முழு platform_locked_account(கட்டமைப்பு passwd *pw) { (வெறுமை)pw; திரும்பு 0; }
வெறுமை record_failed_login(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *user,
    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *ttyname) { (வெறுமை)ssh; (வெறுமை)user;
    (வெறுமை)hostname; (வெறுமை)ttyname; }
முழு temporarily_use_uid(கட்டமைப்பு passwd *pw) { (வெறுமை)pw; திரும்பு 0; }
வெறுமை restore_uid(வெறுமை) { }
வெறுமை platform_setusercontext(கட்டமைப்பு passwd *pw) { (வெறுமை)pw; }
வெறுமை platform_setusercontext_post_groups(கட்டமைப்பு passwd *pw) { (வெறுமை)pw; }
கட்டமைப்பு connection_info *
server_get_connection_info(கட்டமைப்பு ssh *ssh, முழு populate, முழு use_dns)
    { (வெறுமை)ssh; (வெறுமை)populate; (வெறுமை)use_dns; திரும்பு வெற்று; }
முழு auth2_methods_valid(மாறிலி எழுத்து *list, முழு allow_unknown)
    { (வெறுமை)list; (வெறுமை)allow_unknown; திரும்பு 0; }
கட்டமைப்பு sshbuf *cfg = வெற்று;
முழு auth_sock = -1;
எழுத்து **tun_fwd_ifnames = வெற்று;

கட்டமைப்பு logininfo *login_get_lastlog(கட்டமைப்பு logininfo *li, மாறிலி uid_t uid)
    { (வெறுமை)li; (வெறுமை)uid; திரும்பு வெற்று; }
கட்டமைப்பு logininfo *login_alloc_entry(pid_t pid, மாறிலி எழுத்து *username,
    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *வரி)
    { (வெறுமை)pid; (வெறுமை)username; (வெறுமை)hostname; (வெறுமை)வரி; திரும்பு வெற்று; }
வெறுமை server_process_permitopen(கட்டமைப்பு ssh *ssh) { (வெறுமை)ssh; }
வெறுமை server_process_channel_timeouts(கட்டமைப்பு ssh *ssh) { (வெறுமை)ssh; }
முழு server_loop2(கட்டமைப்பு ssh *ssh, Authctxt *authctxt)
    { (வெறுமை)ssh; (வெறுமை)authctxt; திரும்பு 0; }
முழு platform_privileged_uidswap(வெறுமை) { திரும்பு 0; }
முழு sftp_server_main(முழு argc, எழுத்து **argv, கட்டமைப்பு passwd *user_pw)
    { (வெறுமை)argc; (வெறுமை)argv; (வெறுமை)user_pw; திரும்பு 0; }
முழு debug_flag = 0;
வெறுமை permanently_set_uid(கட்டமைப்பு passwd *pw) { (வெறுமை)pw; }
முழு login_login(கட்டமைப்பு logininfo *li) { (வெறுமை)li; திரும்பு 0; }
முழு login_logout(கட்டமைப்பு logininfo *li) { (வெறுமை)li; திரும்பு 0; }
வெறுமை login_free_entry(கட்டமைப்பு logininfo *li) { (வெறுமை)li; }
வெறுமை login_set_addr(கட்டமைப்பு logininfo *li, மாறிலி கட்டமைப்பு sockaddr *sa,
    மாறிலி unsigned முழு sa_size) { (வெறுமை)li; (வெறுமை)sa; (வெறுமை)sa_size; }
முழு openpty(முழு *amaster, முழு *aslave, எழுத்து *name,
    மாறிலி கட்டமைப்பு termios *termp, மாறிலி கட்டமைப்பு winsize *winp)
    { (வெறுமை)termp; (வெறுமை)winp; *amaster = -1; *aslave = -1;
    எனில் (name) name[0] = '\0'; திரும்பு -1; }

வெளி முழு __real_do_exec(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);
வெளி முழு __real_do_exec_pty(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);
வெளி முழு __real_do_exec_no_pty(கட்டமைப்பு ssh *, Session *, மாறிலி எழுத்து *);

முழு
__wrap_do_exec(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	(வெறுமை)ssh;
	(வெறுமை)s;
	(வெறுமை)command;
	திரும்பு 0;
}

முழு
__wrap_do_exec_pty(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	(வெறுமை)ssh;
	(வெறுமை)s;
	(வெறுமை)command;
	திரும்பு 0;
}

முழு
__wrap_do_exec_no_pty(கட்டமைப்பு ssh *ssh, Session *s, மாறிலி எழுத்து *command)
{
	(வெறுமை)ssh;
	(வெறுமை)s;
	(வெறுமை)command;
	திரும்பு 0;
}

நிலையான கட்டமைப்பு sshkey *
load_private(மாறிலி எழுத்து *str)
{
	கட்டமைப்பு sshbuf *b = sshbuf_from(str, strlen(str));
	கட்டமைப்பு sshkey *k = வெற்று;
	எனில் (b == வெற்று || sshkey_parse_private_fileblob(b, "", &k, வெற்று) != 0)
		abort();
	sshbuf_free(b);
	திரும்பு k;
}

நிலையான கட்டமைப்பு sshkey *
load_public(மாறிலி எழுத்து *str)
{
	எழுத்து *tmp, *cp;
	கட்டமைப்பு sshkey *k = sshkey_new(சாவி_UNSPEC);
	எனில் (k == வெற்று)
		abort();
	tmp = cp = strdup(str);
	எனில் (sshkey_read(k, &cp) != 0)
		abort();
	விடுவி(tmp);
	திரும்பு k;
}

நிலையான முழு
pump(கட்டமைப்பு ssh *from, கட்டமைப்பு ssh *to, size_t *transferred)
{
	மாறிலி u_char *buf;
	size_t len;
	u_char type;
	முழு r;
	*transferred = 0;
	எனில் ((r = ssh_packet_next(from, &type)) != 0)
		திரும்பு r;
	buf = ssh_output_ptr(from, &len);
	எனில் (len == 0)
		திரும்பு 0;
	எனில் ((r = ssh_உள்ளீடு_append(to, buf, len)) != 0)
		திரும்பு r;
	எனில் ((r = ssh_output_consume(from, len)) != 0)
		திரும்பு r;
	*transferred = len;
	திரும்பு 0;
}

நிலையான முழு
run_kex(கட்டமைப்பு ssh *client, கட்டமைப்பு ssh *server)
{
	முழு r;
	size_t cn, sn;
	க்கு (முழு i = 0; i < 100; i++) {
		எனில் ((r = pump(server, client, &sn)) != 0) திரும்பு r;
		எனில் ((r = pump(client, server, &cn)) != 0) திரும்பு r;
		எனில் (server->kex->done && client->kex->done)
			திரும்பு 0;
		எனில் (cn == 0 && sn == 0)
			திரும்பு SSH_ERR_PROTOCOL_ERROR;
	}
	திரும்பு SSH_ERR_PROTOCOL_ERROR;
}

#அந்தர்பாவ "fixed-keys.h"

நிலையான கட்டமைப்பு ssh *g_client = வெற்று;
நிலையான கட்டமைப்பு ssh *g_server = வெற்று;
நிலையான முழு g_init = 0;
நிலையான முழு g_channel_id = -1;
நிலையான Authctxt g_authctxt;
நிலையான கட்டமைப்பு passwd g_fake_pw;

நிலையான எழுத்து *g_pending_rtype = வெற்று;
நிலையான எழுத்து *g_pending_exec_cmd = வெற்று;
நிலையான எழுத்து *g_pending_env_name = வெற்று;
நிலையான எழுத்து *g_pending_env_val = வெற்று;

நிலையான வெறுமை
my_session_exec_req(கட்டமைப்பு ssh *ssh)
{
	முழு r;
	எனில் ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

நிலையான வெறுமை
my_session_env_req(கட்டமைப்பு ssh *ssh)
{
	முழு r;
	எனில் ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, வெற்று)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

நிலையான முழு
உள்ளீடு_channel_request(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(வெறுமை)type;
	(வெறுமை)seq;
	எனில் (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, வெற்று) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		திரும்பு 0;
	எனில் (g_channel_id >= 0 && g_pending_rtype != வெற்று) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		எனில் (c != வெற்று) {
			எனில் (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			இல்லையெனில் எனில் (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			இல்லையெனில்
				(வெறுமை)session_உள்ளீடு_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	திரும்பு 0;
}

நிலையான வெறுமை
reset_channel(கட்டமைப்பு ssh *ssh)
{
	எனில் (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		எனில் (c != வெற்று)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (எழுத்து *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (எழுத்து *)"fuzz", 0);
	எனில் (c == வெற்று)
		திரும்பு;
	g_channel_id = c->self;
	Session *s = session_new();
	எனில் (s != வெற்று) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

நிலையான முழு
init_once(வெறுமை)
{
	எனில் (g_init)
		திரும்பு 0;
	சமிக்ஞை(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, அளவு(g_fake_pw));
	g_fake_pw.pw_name = (எழுத்து *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (எழுத்து *)"/tmp";
	g_fake_pw.pw_shell = (எழுத்து *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, அளவு(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	கட்டமைப்பு sshkey *priv = load_private(PRIV_ED25519);
	கட்டமைப்பு sshkey *pub = load_public(PUB_ED25519);
	எழுத்து *keyname = xstrdup(sshkey_ssh_name(priv));

	மாறிலி எழுத்து *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	எழுத்து *proposal[PROPOSAL_MAX] = { 0 };
	முழு i;
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		மாறிலி எழுத்து *p = defaults[i];
		எனில் (i == PROPOSAL_SERVER_HOST_சாவி_ALGS)
			p = keyname;
		இல்லையெனில் எனில் (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		இல்லையெனில் எனில் (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		இல்லையெனில் எனில் (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	கட்டமைப்பு kex_params kp;
	memcpy(kp.proposal, proposal, அளவு(proposal));

	எனில் (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		திரும்பு -1;
	எனில் (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		திரும்பு -1;
	எனில் (run_kex(g_client, g_server) != 0)
		திரும்பு -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_செய்தி_CHANNEL_REQUEST,
	    &உள்ளீடு_channel_request);

	விடுவி(keyname);
	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(proposal[i]);
	g_init = 1;
	திரும்பு 0;
}

வெறுமை
fuzz_session_one(மாறிலி uint8_t *data, size_t size)
{
	எனில் (init_once() != 0)
		திரும்பு;
	எனில் (size > 65000)
		திரும்பு;

	reset_channel(g_server);

	in_fuzz = 1;
	எனில் (setjmp(fuzz_env) == 0) {
		size_t transferred;
		எனில் (ssh_packet_put(g_client, SSH2_செய்தி_CHANNEL_REQUEST,
		    data, size) != 0)
			செல் done;
		எனில் (pump(g_client, g_server, &transferred) != 0)
			செல் done;
		(வெறுமை)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, வெற்று);
	done:
		;
	}
	in_fuzz = 0;
	விடுவி(g_pending_rtype);
	g_pending_rtype = வெற்று;
	விடுவி(g_pending_exec_cmd);
	g_pending_exec_cmd = வெற்று;
	விடுவி(g_pending_env_name);
	g_pending_env_name = வெற்று;
	விடுவி(g_pending_env_val);
	g_pending_env_val = வெற்று;
}
