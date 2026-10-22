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

#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-options.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "session.h"

ServerOptions options;
সংরচনা sshbuf *loginmsg = রিক্ত;
সংরচনা include_list includes;
স্থির সংরচনা sshauthopt g_auth_opts_storage;
সংরচনা sshauthopt *auth_opts = &g_auth_opts_storage;
সংরচনা passwd *privsep_pw = রিক্ত;

স্থির jmp_buf fuzz_env;
স্থির চঞ্চল পূর্ণাঙ্ক in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

শূন্য
__wrap_ssh_packet_disconnect(সংরচনা ssh *ssh, ধ্রুব বর্ণ *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

পূর্ণাঙ্ক
__wrap_sshpkt_fatal(সংরচনা ssh *ssh, পূর্ণাঙ্ক r, ধ্রুব বর্ণ *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

পূর্ণাঙ্ক
mm_is_monitor(শূন্য)
{
	প্রত্যাগম 0;
}

শূন্য
mm_audit_run_command(ধ্রুব বর্ণ *cmd)
{
	(শূন্য)cmd;
}

পূর্ণাঙ্ক
mm_pty_allocate(পূর্ণাঙ্ক *ptyfd, পূর্ণাঙ্ক *ttyfd, বর্ণ *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	যদি (namebuf != রিক্ত && namebuflen > 0)
		namebuf[0] = '\0';
	প্রত্যাগম 0;
}

শূন্য mm_session_pty_cleanup2(Session *s) { (শূন্য)s; }
পূর্ণাঙ্ক platform_locked_account(সংরচনা passwd *pw) { (শূন্য)pw; প্রত্যাগম 0; }
শূন্য record_failed_login(সংরচনা ssh *ssh, ধ্রুব বর্ণ *user,
    ধ্রুব বর্ণ *hostname, ধ্রুব বর্ণ *ttyname) { (শূন্য)ssh; (শূন্য)user;
    (শূন্য)hostname; (শূন্য)ttyname; }
পূর্ণাঙ্ক temporarily_use_uid(সংরচনা passwd *pw) { (শূন্য)pw; প্রত্যাগম 0; }
শূন্য restore_uid(শূন্য) { }
শূন্য platform_setusercontext(সংরচনা passwd *pw) { (শূন্য)pw; }
শূন্য platform_setusercontext_post_groups(সংরচনা passwd *pw) { (শূন্য)pw; }
সংরচনা connection_info *
server_get_connection_info(সংরচনা ssh *ssh, পূর্ণাঙ্ক populate, পূর্ণাঙ্ক use_dns)
    { (শূন্য)ssh; (শূন্য)populate; (শূন্য)use_dns; প্রত্যাগম রিক্ত; }
পূর্ণাঙ্ক auth2_methods_valid(ধ্রুব বর্ণ *list, পূর্ণাঙ্ক allow_unknown)
    { (শূন্য)list; (শূন্য)allow_unknown; প্রত্যাগম 0; }
সংরচনা sshbuf *cfg = রিক্ত;
পূর্ণাঙ্ক auth_sock = -1;
বর্ণ **tun_fwd_ifnames = রিক্ত;

সংরচনা logininfo *login_get_lastlog(সংরচনা logininfo *li, ধ্রুব uid_t uid)
    { (শূন্য)li; (শূন্য)uid; প্রত্যাগম রিক্ত; }
সংরচনা logininfo *login_alloc_entry(pid_t pid, ধ্রুব বর্ণ *username,
    ধ্রুব বর্ণ *hostname, ধ্রুব বর্ণ *সারি)
    { (শূন্য)pid; (শূন্য)username; (শূন্য)hostname; (শূন্য)সারি; প্রত্যাগম রিক্ত; }
শূন্য server_process_permitopen(সংরচনা ssh *ssh) { (শূন্য)ssh; }
শূন্য server_process_channel_timeouts(সংরচনা ssh *ssh) { (শূন্য)ssh; }
পূর্ণাঙ্ক server_loop2(সংরচনা ssh *ssh, Authctxt *authctxt)
    { (শূন্য)ssh; (শূন্য)authctxt; প্রত্যাগম 0; }
পূর্ণাঙ্ক platform_privileged_uidswap(শূন্য) { প্রত্যাগম 0; }
পূর্ণাঙ্ক sftp_server_main(পূর্ণাঙ্ক argc, বর্ণ **argv, সংরচনা passwd *user_pw)
    { (শূন্য)argc; (শূন্য)argv; (শূন্য)user_pw; প্রত্যাগম 0; }
পূর্ণাঙ্ক debug_flag = 0;
শূন্য permanently_set_uid(সংরচনা passwd *pw) { (শূন্য)pw; }
পূর্ণাঙ্ক login_login(সংরচনা logininfo *li) { (শূন্য)li; প্রত্যাগম 0; }
পূর্ণাঙ্ক login_logout(সংরচনা logininfo *li) { (শূন্য)li; প্রত্যাগম 0; }
শূন্য login_free_entry(সংরচনা logininfo *li) { (শূন্য)li; }
শূন্য login_set_addr(সংরচনা logininfo *li, ধ্রুব সংরচনা sockaddr *sa,
    ধ্রুব unsigned পূর্ণাঙ্ক sa_size) { (শূন্য)li; (শূন্য)sa; (শূন্য)sa_size; }
পূর্ণাঙ্ক openpty(পূর্ণাঙ্ক *amaster, পূর্ণাঙ্ক *aslave, বর্ণ *name,
    ধ্রুব সংরচনা termios *termp, ধ্রুব সংরচনা winsize *winp)
    { (শূন্য)termp; (শূন্য)winp; *amaster = -1; *aslave = -1;
    যদি (name) name[0] = '\0'; প্রত্যাগম -1; }

বাহ্য পূর্ণাঙ্ক __real_do_exec(সংরচনা ssh *, Session *, ধ্রুব বর্ণ *);
বাহ্য পূর্ণাঙ্ক __real_do_exec_pty(সংরচনা ssh *, Session *, ধ্রুব বর্ণ *);
বাহ্য পূর্ণাঙ্ক __real_do_exec_no_pty(সংরচনা ssh *, Session *, ধ্রুব বর্ণ *);

পূর্ণাঙ্ক
__wrap_do_exec(সংরচনা ssh *ssh, Session *s, ধ্রুব বর্ণ *command)
{
	(শূন্য)ssh;
	(শূন্য)s;
	(শূন্য)command;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
__wrap_do_exec_pty(সংরচনা ssh *ssh, Session *s, ধ্রুব বর্ণ *command)
{
	(শূন্য)ssh;
	(শূন্য)s;
	(শূন্য)command;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
__wrap_do_exec_no_pty(সংরচনা ssh *ssh, Session *s, ধ্রুব বর্ণ *command)
{
	(শূন্য)ssh;
	(শূন্য)s;
	(শূন্য)command;
	প্রত্যাগম 0;
}

স্থির সংরচনা sshkey *
load_private(ধ্রুব বর্ণ *str)
{
	সংরচনা sshbuf *b = sshbuf_from(str, strlen(str));
	সংরচনা sshkey *k = রিক্ত;
	যদি (b == রিক্ত || sshkey_parse_private_fileblob(b, "", &k, রিক্ত) != 0)
		abort();
	sshbuf_free(b);
	প্রত্যাগম k;
}

স্থির সংরচনা sshkey *
load_public(ধ্রুব বর্ণ *str)
{
	বর্ণ *tmp, *cp;
	সংরচনা sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == রিক্ত)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	প্রত্যাগম k;
}

স্থির পূর্ণাঙ্ক
pump(সংরচনা ssh *from, সংরচনা ssh *to, size_t *transferred)
{
	ধ্রুব u_char *buf;
	size_t len;
	u_char type;
	পূর্ণাঙ্ক r;
	*transferred = 0;
	যদি ((r = ssh_packet_next(from, &type)) != 0)
		প্রত্যাগম r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		প্রত্যাগম 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		প্রত্যাগম r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		প্রত্যাগম r;
	*transferred = len;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
run_kex(সংরচনা ssh *client, সংরচনা ssh *server)
{
	পূর্ণাঙ্ক r;
	size_t cn, sn;
	প্রতি (পূর্ণাঙ্ক i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) প্রত্যাগম r;
		যদি ((r = pump(client, server, &cn)) != 0) প্রত্যাগম r;
		যদি (server->kex->done && client->kex->done)
			প্রত্যাগম 0;
		যদি (cn == 0 && sn == 0)
			প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
	}
	প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
}

#অন্তর্ভাব "fixed-keys.h"

স্থির সংরচনা ssh *g_client = রিক্ত;
স্থির সংরচনা ssh *g_server = রিক্ত;
স্থির পূর্ণাঙ্ক g_init = 0;
স্থির পূর্ণাঙ্ক g_channel_id = -1;
স্থির Authctxt g_authctxt;
স্থির সংরচনা passwd g_fake_pw;

স্থির বর্ণ *g_pending_rtype = রিক্ত;
স্থির বর্ণ *g_pending_exec_cmd = রিক্ত;
স্থির বর্ণ *g_pending_env_name = রিক্ত;
স্থির বর্ণ *g_pending_env_val = রিক্ত;

স্থির শূন্য
my_session_exec_req(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;
	যদি ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, রিক্ত)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

স্থির শূন্য
my_session_env_req(সংরচনা ssh *ssh)
{
	পূর্ণাঙ্ক r;
	যদি ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, রিক্ত)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, রিক্ত)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

স্থির পূর্ণাঙ্ক
প্রবেশ_channel_request(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(শূন্য)type;
	(শূন্য)seq;
	যদি (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, রিক্ত) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		প্রত্যাগম 0;
	যদি (g_channel_id >= 0 && g_pending_rtype != রিক্ত) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		যদি (c != রিক্ত) {
			যদি (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			অন্যথা যদি (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			অন্যথা
				(শূন্য)session_প্রবেশ_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	প্রত্যাগম 0;
}

স্থির শূন্য
reset_channel(সংরচনা ssh *ssh)
{
	যদি (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		যদি (c != রিক্ত)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (বর্ণ *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (বর্ণ *)"fuzz", 0);
	যদি (c == রিক্ত)
		প্রত্যাগম;
	g_channel_id = c->self;
	Session *s = session_new();
	যদি (s != রিক্ত) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

স্থির পূর্ণাঙ্ক
init_once(শূন্য)
{
	যদি (g_init)
		প্রত্যাগম 0;
	সঙ্কেত(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, পরিমাণ(g_fake_pw));
	g_fake_pw.pw_name = (বর্ণ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (বর্ণ *)"/tmp";
	g_fake_pw.pw_shell = (বর্ণ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, পরিমাণ(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	সংরচনা sshkey *priv = load_private(PRIV_ED25519);
	সংরচনা sshkey *pub = load_public(PUB_ED25519);
	বর্ণ *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুব বর্ণ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	বর্ণ *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণাঙ্ক i;
	প্রতি (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুব বর্ণ *p = defaults[i];
		যদি (i == PROPOSAL_SERVER_HOST_চাবি_ALGS)
			p = keyname;
		অন্যথা যদি (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		অন্যথা যদি (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		অন্যথা যদি (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	সংরচনা kex_params kp;
	memcpy(kp.proposal, proposal, পরিমাণ(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		প্রত্যাগম -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		প্রত্যাগম -1;
	যদি (run_kex(g_client, g_server) != 0)
		প্রত্যাগম -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_বার্তা_CHANNEL_REQUEST,
	    &প্রবেশ_channel_request);

	মুক্ত(keyname);
	প্রতি (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	প্রত্যাগম 0;
}

শূন্য
fuzz_session_one(ধ্রুব uint8_t *data, size_t size)
{
	যদি (init_once() != 0)
		প্রত্যাগম;
	যদি (size > 65000)
		প্রত্যাগম;

	reset_channel(g_server);

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		size_t transferred;
		যদি (ssh_packet_put(g_client, SSH2_বার্তা_CHANNEL_REQUEST,
		    data, size) != 0)
			গচ্ছ done;
		যদি (pump(g_client, g_server, &transferred) != 0)
			গচ্ছ done;
		(শূন্য)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, রিক্ত);
	done:
		;
	}
	in_fuzz = 0;
	মুক্ত(g_pending_rtype);
	g_pending_rtype = রিক্ত;
	মুক্ত(g_pending_exec_cmd);
	g_pending_exec_cmd = রিক্ত;
	মুক্ত(g_pending_env_name);
	g_pending_env_name = রিক্ত;
	মুক্ত(g_pending_env_val);
	g_pending_env_val = রিক্ত;
}
