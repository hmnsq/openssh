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

#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <sys/types.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "session.h"

ServerOptions options;
संरचना sshbuf *loginmsg = रिक्त;
संरचना include_list includes;
स्थिर संरचना sshauthopt g_auth_opts_storage;
संरचना sshauthopt *auth_opts = &g_auth_opts_storage;
संरचना passwd *privsep_pw = रिक्त;

स्थिर jmp_buf fuzz_env;
स्थिर चञ्चल पूर्णाङ्क in_fuzz = 0;

शून्य
cleanup_exit(पूर्णाङ्क code)
{
	यदि (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

शून्य
__wrap_ssh_packet_disconnect(संरचना ssh *ssh, ध्रुव वर्ण *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	यदि (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

पूर्णाङ्क
__wrap_sshpkt_fatal(संरचना ssh *ssh, पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	यदि (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

पूर्णाङ्क
mm_is_monitor(शून्य)
{
	प्रत्यागम 0;
}

शून्य
mm_audit_run_command(ध्रुव वर्ण *cmd)
{
	(शून्य)cmd;
}

पूर्णाङ्क
mm_pty_allocate(पूर्णाङ्क *ptyfd, पूर्णाङ्क *ttyfd, वर्ण *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	यदि (namebuf != रिक्त && namebuflen > 0)
		namebuf[0] = '\0';
	प्रत्यागम 0;
}

शून्य mm_session_pty_cleanup2(Session *s) { (शून्य)s; }
पूर्णाङ्क platform_locked_account(संरचना passwd *pw) { (शून्य)pw; प्रत्यागम 0; }
शून्य record_failed_login(संरचना ssh *ssh, ध्रुव वर्ण *user,
    ध्रुव वर्ण *hostname, ध्रुव वर्ण *ttyname) { (शून्य)ssh; (शून्य)user;
    (शून्य)hostname; (शून्य)ttyname; }
पूर्णाङ्क temporarily_use_uid(संरचना passwd *pw) { (शून्य)pw; प्रत्यागम 0; }
शून्य restore_uid(शून्य) { }
शून्य platform_setusercontext(संरचना passwd *pw) { (शून्य)pw; }
शून्य platform_setusercontext_post_groups(संरचना passwd *pw) { (शून्य)pw; }
संरचना connection_info *
server_get_connection_info(संरचना ssh *ssh, पूर्णाङ्क populate, पूर्णाङ्क use_dns)
    { (शून्य)ssh; (शून्य)populate; (शून्य)use_dns; प्रत्यागम रिक्त; }
पूर्णाङ्क auth2_methods_valid(ध्रुव वर्ण *list, पूर्णाङ्क allow_unknown)
    { (शून्य)list; (शून्य)allow_unknown; प्रत्यागम 0; }
संरचना sshbuf *cfg = रिक्त;
पूर्णाङ्क auth_sock = -1;
वर्ण **tun_fwd_ifnames = रिक्त;

संरचना logininfo *login_get_lastlog(संरचना logininfo *li, ध्रुव uid_t uid)
    { (शून्य)li; (शून्य)uid; प्रत्यागम रिक्त; }
संरचना logininfo *login_alloc_entry(pid_t pid, ध्रुव वर्ण *username,
    ध्रुव वर्ण *hostname, ध्रुव वर्ण *ओळ)
    { (शून्य)pid; (शून्य)username; (शून्य)hostname; (शून्य)ओळ; प्रत्यागम रिक्त; }
शून्य server_process_permitopen(संरचना ssh *ssh) { (शून्य)ssh; }
शून्य server_process_channel_timeouts(संरचना ssh *ssh) { (शून्य)ssh; }
पूर्णाङ्क server_loop2(संरचना ssh *ssh, Authctxt *authctxt)
    { (शून्य)ssh; (शून्य)authctxt; प्रत्यागम 0; }
पूर्णाङ्क platform_privileged_uidswap(शून्य) { प्रत्यागम 0; }
पूर्णाङ्क sftp_server_main(पूर्णाङ्क argc, वर्ण **argv, संरचना passwd *user_pw)
    { (शून्य)argc; (शून्य)argv; (शून्य)user_pw; प्रत्यागम 0; }
पूर्णाङ्क debug_flag = 0;
शून्य permanently_set_uid(संरचना passwd *pw) { (शून्य)pw; }
पूर्णाङ्क login_login(संरचना logininfo *li) { (शून्य)li; प्रत्यागम 0; }
पूर्णाङ्क login_logout(संरचना logininfo *li) { (शून्य)li; प्रत्यागम 0; }
शून्य login_free_entry(संरचना logininfo *li) { (शून्य)li; }
शून्य login_set_addr(संरचना logininfo *li, ध्रुव संरचना sockaddr *sa,
    ध्रुव unsigned पूर्णाङ्क sa_size) { (शून्य)li; (शून्य)sa; (शून्य)sa_size; }
पूर्णाङ्क openpty(पूर्णाङ्क *amaster, पूर्णाङ्क *aslave, वर्ण *name,
    ध्रुव संरचना termios *termp, ध्रुव संरचना winsize *winp)
    { (शून्य)termp; (शून्य)winp; *amaster = -1; *aslave = -1;
    यदि (name) name[0] = '\0'; प्रत्यागम -1; }

बाह्य पूर्णाङ्क __real_do_exec(संरचना ssh *, Session *, ध्रुव वर्ण *);
बाह्य पूर्णाङ्क __real_do_exec_pty(संरचना ssh *, Session *, ध्रुव वर्ण *);
बाह्य पूर्णाङ्क __real_do_exec_no_pty(संरचना ssh *, Session *, ध्रुव वर्ण *);

पूर्णाङ्क
__wrap_do_exec(संरचना ssh *ssh, Session *s, ध्रुव वर्ण *command)
{
	(शून्य)ssh;
	(शून्य)s;
	(शून्य)command;
	प्रत्यागम 0;
}

पूर्णाङ्क
__wrap_do_exec_pty(संरचना ssh *ssh, Session *s, ध्रुव वर्ण *command)
{
	(शून्य)ssh;
	(शून्य)s;
	(शून्य)command;
	प्रत्यागम 0;
}

पूर्णाङ्क
__wrap_do_exec_no_pty(संरचना ssh *ssh, Session *s, ध्रुव वर्ण *command)
{
	(शून्य)ssh;
	(शून्य)s;
	(शून्य)command;
	प्रत्यागम 0;
}

स्थिर संरचना sshkey *
load_private(ध्रुव वर्ण *str)
{
	संरचना sshbuf *b = sshbuf_from(str, strlen(str));
	संरचना sshkey *k = रिक्त;
	यदि (b == रिक्त || sshkey_parse_private_fileblob(b, "", &k, रिक्त) != 0)
		abort();
	sshbuf_free(b);
	प्रत्यागम k;
}

स्थिर संरचना sshkey *
load_public(ध्रुव वर्ण *str)
{
	वर्ण *tmp, *cp;
	संरचना sshkey *k = sshkey_new(किल्ली_UNSPEC);
	यदि (k == रिक्त)
		abort();
	tmp = cp = strdup(str);
	यदि (sshkey_read(k, &cp) != 0)
		abort();
	मुक्त(tmp);
	प्रत्यागम k;
}

स्थिर पूर्णाङ्क
pump(संरचना ssh *from, संरचना ssh *to, size_t *transferred)
{
	ध्रुव u_char *buf;
	size_t len;
	u_char type;
	पूर्णाङ्क r;
	*transferred = 0;
	यदि ((r = ssh_packet_next(from, &type)) != 0)
		प्रत्यागम r;
	buf = ssh_output_ptr(from, &len);
	यदि (len == 0)
		प्रत्यागम 0;
	यदि ((r = ssh_आदान_append(to, buf, len)) != 0)
		प्रत्यागम r;
	यदि ((r = ssh_output_consume(from, len)) != 0)
		प्रत्यागम r;
	*transferred = len;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
run_kex(संरचना ssh *client, संरचना ssh *server)
{
	पूर्णाङ्क r;
	size_t cn, sn;
	प्रति (पूर्णाङ्क i = 0; i < 100; i++) {
		यदि ((r = pump(server, client, &sn)) != 0) प्रत्यागम r;
		यदि ((r = pump(client, server, &cn)) != 0) प्रत्यागम r;
		यदि (server->kex->done && client->kex->done)
			प्रत्यागम 0;
		यदि (cn == 0 && sn == 0)
			प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
	}
	प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
}

#अन्तर्भाव "fixed-keys.h"

स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णाङ्क g_init = 0;
स्थिर पूर्णाङ्क g_channel_id = -1;
स्थिर Authctxt g_authctxt;
स्थिर संरचना passwd g_fake_pw;

स्थिर वर्ण *g_pending_rtype = रिक्त;
स्थिर वर्ण *g_pending_exec_cmd = रिक्त;
स्थिर वर्ण *g_pending_env_name = रिक्त;
स्थिर वर्ण *g_pending_env_val = रिक्त;

स्थिर शून्य
my_session_exec_req(संरचना ssh *ssh)
{
	पूर्णाङ्क r;
	यदि ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

स्थिर शून्य
my_session_env_req(संरचना ssh *ssh)
{
	पूर्णाङ्क r;
	यदि ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

स्थिर पूर्णाङ्क
आदान_channel_request(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(शून्य)type;
	(शून्य)seq;
	यदि (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, रिक्त) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		प्रत्यागम 0;
	यदि (g_channel_id >= 0 && g_pending_rtype != रिक्त) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		यदि (c != रिक्त) {
			यदि (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			अन्यथा यदि (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			अन्यथा
				(शून्य)session_आदान_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	प्रत्यागम 0;
}

स्थिर शून्य
reset_channel(संरचना ssh *ssh)
{
	यदि (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		यदि (c != रिक्त)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (वर्ण *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (वर्ण *)"fuzz", 0);
	यदि (c == रिक्त)
		प्रत्यागम;
	g_channel_id = c->self;
	Session *s = session_new();
	यदि (s != रिक्त) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

स्थिर पूर्णाङ्क
init_once(शून्य)
{
	यदि (g_init)
		प्रत्यागम 0;
	सङ्केत(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, परिमाण(g_fake_pw));
	g_fake_pw.pw_name = (वर्ण *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (वर्ण *)"/tmp";
	g_fake_pw.pw_shell = (वर्ण *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, परिमाण(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	संरचना sshkey *priv = load_private(PRIV_ED25519);
	संरचना sshkey *pub = load_public(PUB_ED25519);
	वर्ण *keyname = xstrdup(sshkey_ssh_name(priv));

	ध्रुव वर्ण *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	वर्ण *proposal[PROPOSAL_MAX] = { 0 };
	पूर्णाङ्क i;
	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		ध्रुव वर्ण *p = defaults[i];
		यदि (i == PROPOSAL_SERVER_HOST_किल्ली_ALGS)
			p = keyname;
		अन्यथा यदि (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		अन्यथा यदि (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		अन्यथा यदि (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	संरचना kex_params kp;
	memcpy(kp.proposal, proposal, परिमाण(proposal));

	यदि (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		प्रत्यागम -1;
	यदि (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		प्रत्यागम -1;
	यदि (run_kex(g_client, g_server) != 0)
		प्रत्यागम -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_संदेश_CHANNEL_REQUEST,
	    &आदान_channel_request);

	मुक्त(keyname);
	प्रति (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	प्रत्यागम 0;
}

शून्य
fuzz_session_one(ध्रुव uint8_t *data, size_t size)
{
	यदि (init_once() != 0)
		प्रत्यागम;
	यदि (size > 65000)
		प्रत्यागम;

	reset_channel(g_server);

	in_fuzz = 1;
	यदि (setjmp(fuzz_env) == 0) {
		size_t transferred;
		यदि (ssh_packet_put(g_client, SSH2_संदेश_CHANNEL_REQUEST,
		    data, size) != 0)
			गच्छ done;
		यदि (pump(g_client, g_server, &transferred) != 0)
			गच्छ done;
		(शून्य)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, रिक्त);
	done:
		;
	}
	in_fuzz = 0;
	मुक्त(g_pending_rtype);
	g_pending_rtype = रिक्त;
	मुक्त(g_pending_exec_cmd);
	g_pending_exec_cmd = रिक्त;
	मुक्त(g_pending_env_name);
	g_pending_env_name = रिक्त;
	मुक्त(g_pending_env_val);
	g_pending_env_val = रिक्त;
}
