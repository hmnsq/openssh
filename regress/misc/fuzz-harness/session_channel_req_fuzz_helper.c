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
কাঠামো sshbuf *loginmsg = ফাঁকা;
কাঠামো include_list includes;
স্থির কাঠামো sshauthopt g_auth_opts_storage;
কাঠামো sshauthopt *auth_opts = &g_auth_opts_storage;
কাঠামো passwd *privsep_pw = ফাঁকা;

স্থির jmp_buf fuzz_env;
স্থির অস্থির পূর্ণসংখ্যা in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

শূন্য
__wrap_ssh_packet_disconnect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

পূর্ণসংখ্যা
__wrap_sshpkt_fatal(কাঠামো ssh *ssh, পূর্ণসংখ্যা r, ধ্রুবক অক্ষর *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

পূর্ণসংখ্যা
mm_is_monitor(শূন্য)
{
	ফেরত 0;
}

শূন্য
mm_audit_run_command(ধ্রুবক অক্ষর *cmd)
{
	(শূন্য)cmd;
}

পূর্ণসংখ্যা
mm_pty_allocate(পূর্ণসংখ্যা *ptyfd, পূর্ণসংখ্যা *ttyfd, অক্ষর *namebuf, আকার_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	যদি (namebuf != ফাঁকা && namebuflen > 0)
		namebuf[0] = '\0';
	ফেরত 0;
}

শূন্য mm_session_pty_cleanup2(Session *s) { (শূন্য)s; }
পূর্ণসংখ্যা platform_locked_account(কাঠামো passwd *pw) { (শূন্য)pw; ফেরত 0; }
শূন্য record_failed_login(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *user,
    ধ্রুবক অক্ষর *hostname, ধ্রুবক অক্ষর *ttyname) { (শূন্য)ssh; (শূন্য)user;
    (শূন্য)hostname; (শূন্য)ttyname; }
পূর্ণসংখ্যা temporarily_use_uid(কাঠামো passwd *pw) { (শূন্য)pw; ফেরত 0; }
শূন্য restore_uid(শূন্য) { }
শূন্য platform_setusercontext(কাঠামো passwd *pw) { (শূন্য)pw; }
শূন্য platform_setusercontext_post_groups(কাঠামো passwd *pw) { (শূন্য)pw; }
কাঠামো connection_info *
server_get_connection_info(কাঠামো ssh *ssh, পূর্ণসংখ্যা populate, পূর্ণসংখ্যা use_dns)
    { (শূন্য)ssh; (শূন্য)populate; (শূন্য)use_dns; ফেরত ফাঁকা; }
পূর্ণসংখ্যা auth2_methods_valid(ধ্রুবক অক্ষর *list, পূর্ণসংখ্যা allow_unknown)
    { (শূন্য)list; (শূন্য)allow_unknown; ফেরত 0; }
কাঠামো sshbuf *cfg = ফাঁকা;
পূর্ণসংখ্যা auth_sock = -1;
অক্ষর **tun_fwd_ifnames = ফাঁকা;

কাঠামো logininfo *login_get_lastlog(কাঠামো logininfo *li, ধ্রুবক uid_t uid)
    { (শূন্য)li; (শূন্য)uid; ফেরত ফাঁকা; }
কাঠামো logininfo *login_alloc_entry(pid_t pid, ধ্রুবক অক্ষর *username,
    ধ্রুবক অক্ষর *hostname, ধ্রুবক অক্ষর *সারি)
    { (শূন্য)pid; (শূন্য)username; (শূন্য)hostname; (শূন্য)সারি; ফেরত ফাঁকা; }
শূন্য server_process_permitopen(কাঠামো ssh *ssh) { (শূন্য)ssh; }
শূন্য server_process_channel_timeouts(কাঠামো ssh *ssh) { (শূন্য)ssh; }
পূর্ণসংখ্যা server_loop2(কাঠামো ssh *ssh, Authctxt *authctxt)
    { (শূন্য)ssh; (শূন্য)authctxt; ফেরত 0; }
পূর্ণসংখ্যা platform_privileged_uidswap(শূন্য) { ফেরত 0; }
পূর্ণসংখ্যা sftp_server_main(পূর্ণসংখ্যা argc, অক্ষর **argv, কাঠামো passwd *user_pw)
    { (শূন্য)argc; (শূন্য)argv; (শূন্য)user_pw; ফেরত 0; }
পূর্ণসংখ্যা debug_flag = 0;
শূন্য permanently_set_uid(কাঠামো passwd *pw) { (শূন্য)pw; }
পূর্ণসংখ্যা login_login(কাঠামো logininfo *li) { (শূন্য)li; ফেরত 0; }
পূর্ণসংখ্যা login_logout(কাঠামো logininfo *li) { (শূন্য)li; ফেরত 0; }
শূন্য login_free_entry(কাঠামো logininfo *li) { (শূন্য)li; }
শূন্য login_set_addr(কাঠামো logininfo *li, ধ্রুবক কাঠামো sockaddr *sa,
    ধ্রুবক unsigned পূর্ণসংখ্যা sa_আকার) { (শূন্য)li; (শূন্য)sa; (শূন্য)sa_আকার; }
পূর্ণসংখ্যা openpty(পূর্ণসংখ্যা *amaster, পূর্ণসংখ্যা *aslave, অক্ষর *name,
    ধ্রুবক কাঠামো termios *termp, ধ্রুবক কাঠামো winsize *winp)
    { (শূন্য)termp; (শূন্য)winp; *amaster = -1; *aslave = -1;
    যদি (name) name[0] = '\0'; ফেরত -1; }

বাহ্যিক পূর্ণসংখ্যা __real_do_exec(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);
বাহ্যিক পূর্ণসংখ্যা __real_do_exec_pty(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);
বাহ্যিক পূর্ণসংখ্যা __real_do_exec_no_pty(কাঠামো ssh *, Session *, ধ্রুবক অক্ষর *);

পূর্ণসংখ্যা
__wrap_do_exec(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	(শূন্য)ssh;
	(শূন্য)s;
	(শূন্য)command;
	ফেরত 0;
}

পূর্ণসংখ্যা
__wrap_do_exec_pty(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	(শূন্য)ssh;
	(শূন্য)s;
	(শূন্য)command;
	ফেরত 0;
}

পূর্ণসংখ্যা
__wrap_do_exec_no_pty(কাঠামো ssh *ssh, Session *s, ধ্রুবক অক্ষর *command)
{
	(শূন্য)ssh;
	(শূন্য)s;
	(শূন্য)command;
	ফেরত 0;
}

স্থির কাঠামো sshkey *
load_private(ধ্রুবক অক্ষর *str)
{
	কাঠামো sshbuf *b = sshbuf_from(str, strlen(str));
	কাঠামো sshkey *k = ফাঁকা;
	যদি (b == ফাঁকা || sshkey_parse_private_fileblob(b, "", &k, ফাঁকা) != 0)
		abort();
	sshbuf_free(b);
	ফেরত k;
}

স্থির কাঠামো sshkey *
load_public(ধ্রুবক অক্ষর *str)
{
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == ফাঁকা)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ফেরত k;
}

স্থির পূর্ণসংখ্যা
pump(কাঠামো ssh *from, কাঠামো ssh *to, আকার_t *transferred)
{
	ধ্রুবক u_char *buf;
	আকার_t len;
	u_char type;
	পূর্ণসংখ্যা r;
	*transferred = 0;
	যদি ((r = ssh_packet_পরবর্তী(from, &type)) != 0)
		ফেরত r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		ফেরত 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		ফেরত r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		ফেরত r;
	*transferred = len;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
run_kex(কাঠামো ssh *client, কাঠামো ssh *server)
{
	পূর্ণসংখ্যা r;
	আকার_t cn, sn;
	জন্য (পূর্ণসংখ্যা i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) ফেরত r;
		যদি ((r = pump(client, server, &cn)) != 0) ফেরত r;
		যদি (server->kex->done && client->kex->done)
			ফেরত 0;
		যদি (cn == 0 && sn == 0)
			ফেরত SSH_ERR_PROTOCOL_ERROR;
	}
	ফেরত SSH_ERR_PROTOCOL_ERROR;
}

#অন্তর্ভাব "fixed-keys.h"

স্থির কাঠামো ssh *g_client = ফাঁকা;
স্থির কাঠামো ssh *g_server = ফাঁকা;
স্থির পূর্ণসংখ্যা g_init = 0;
স্থির পূর্ণসংখ্যা g_channel_id = -1;
স্থির Authctxt g_authctxt;
স্থির কাঠামো passwd g_fake_pw;

স্থির অক্ষর *g_pending_rtype = ফাঁকা;
স্থির অক্ষর *g_pending_exec_cmd = ফাঁকা;
স্থির অক্ষর *g_pending_env_name = ফাঁকা;
স্থির অক্ষর *g_pending_env_val = ফাঁকা;

স্থির শূন্য
my_session_exec_req(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;
	যদি ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

স্থির শূন্য
my_session_env_req(কাঠামো ssh *ssh)
{
	পূর্ণসংখ্যা r;
	যদি ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

স্থির পূর্ণসংখ্যা
প্রবেশ_channel_request(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(শূন্য)type;
	(শূন্য)seq;
	যদি (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ফাঁকা) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		ফেরত 0;
	যদি (g_channel_id >= 0 && g_pending_rtype != ফাঁকা) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		যদি (c != ফাঁকা) {
			যদি (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			অন্যথা যদি (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			অন্যথা
				(শূন্য)session_প্রবেশ_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	ফেরত 0;
}

স্থির শূন্য
reset_channel(কাঠামো ssh *ssh)
{
	যদি (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		যদি (c != ফাঁকা)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (অক্ষর *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (অক্ষর *)"fuzz", 0);
	যদি (c == ফাঁকা)
		ফেরত;
	g_channel_id = c->self;
	Session *s = session_new();
	যদি (s != ফাঁকা) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

স্থির পূর্ণসংখ্যা
init_once(শূন্য)
{
	যদি (g_init)
		ফেরত 0;
	সংকেত(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, আকার(g_fake_pw));
	g_fake_pw.pw_name = (অক্ষর *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (অক্ষর *)"/tmp";
	g_fake_pw.pw_shell = (অক্ষর *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, আকার(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	কাঠামো sshkey *priv = load_private(PRIV_ED25519);
	কাঠামো sshkey *pub = load_public(PUB_ED25519);
	অক্ষর *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুবক অক্ষর *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	অক্ষর *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুবক অক্ষর *p = defaults[i];
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
	কাঠামো kex_params kp;
	memcpy(kp.proposal, proposal, আকার(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ফেরত -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ফেরত -1;
	যদি (run_kex(g_client, g_server) != 0)
		ফেরত -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_বার্তা_CHANNEL_REQUEST,
	    &প্রবেশ_channel_request);

	মুক্ত(keyname);
	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	ফেরত 0;
}

শূন্য
fuzz_session_one(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (init_once() != 0)
		ফেরত;
	যদি (আকার_2 > 65000)
		ফেরত;

	reset_channel(g_server);

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		আকার_t transferred;
		যদি (ssh_packet_put(g_client, SSH2_বার্তা_CHANNEL_REQUEST,
		    তথ্য, আকার_2) != 0)
			যাও done;
		যদি (pump(g_client, g_server, &transferred) != 0)
			যাও done;
		(শূন্য)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ফাঁকা);
	done:
		;
	}
	in_fuzz = 0;
	মুক্ত(g_pending_rtype);
	g_pending_rtype = ফাঁকা;
	মুক্ত(g_pending_exec_cmd);
	g_pending_exec_cmd = ফাঁকা;
	মুক্ত(g_pending_env_name);
	g_pending_env_name = ফাঁকা;
	মুক্ত(g_pending_env_val);
	g_pending_env_val = ফাঁকা;
}
