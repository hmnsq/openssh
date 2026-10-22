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

स्थिर लाँघ_बफ fuzz_env;
स्थिर अस्थिर पूर्णांक in_fuzz = 0;

शून्य
cleanup_exit(पूर्णांक code)
{
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_exit(code);
}

शून्य
__wrap_ssh_packet_disconnect(संरचना ssh *ssh, स्थिरांक अक्षर *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_exit(1);
}

पूर्णांक
__wrap_sshpkt_fatal(संरचना ssh *ssh, पूर्णांक r, स्थिरांक अक्षर *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_exit(r ? r : 1);
}

पूर्णांक
mm_is_monitor(शून्य)
{
	परत 0;
}

शून्य
mm_audit_run_command(स्थिरांक अक्षर *cmd)
{
	(शून्य)cmd;
}

पूर्णांक
mm_pty_allocate(पूर्णांक *ptyfd, पूर्णांक *ttyfd, अक्षर *namebuf, माप_प्रकार namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	जर (namebuf != रिक्त && namebuflen > 0)
		namebuf[0] = '\0';
	परत 0;
}

शून्य mm_session_pty_cleanup2(Session *s) { (शून्य)s; }
पूर्णांक platform_locked_account(संरचना passwd *pw) { (शून्य)pw; परत 0; }
शून्य record_failed_login(संरचना ssh *ssh, स्थिरांक अक्षर *user,
    स्थिरांक अक्षर *hostname, स्थिरांक अक्षर *ttyname) { (शून्य)ssh; (शून्य)user;
    (शून्य)hostname; (शून्य)ttyname; }
पूर्णांक temporarily_use_uid(संरचना passwd *pw) { (शून्य)pw; परत 0; }
शून्य restore_uid(शून्य) { }
शून्य platform_setusercontext(संरचना passwd *pw) { (शून्य)pw; }
शून्य platform_setusercontext_post_groups(संरचना passwd *pw) { (शून्य)pw; }
संरचना connection_info *
server_get_connection_info(संरचना ssh *ssh, पूर्णांक populate, पूर्णांक use_dns)
    { (शून्य)ssh; (शून्य)populate; (शून्य)use_dns; परत रिक्त; }
पूर्णांक auth2_methods_valid(स्थिरांक अक्षर *list, पूर्णांक allow_unknown)
    { (शून्य)list; (शून्य)allow_unknown; परत 0; }
संरचना sshbuf *cfg = रिक्त;
पूर्णांक auth_sock = -1;
अक्षर **tun_fwd_ifnames = रिक्त;

संरचना logininfo *login_get_lastlog(संरचना logininfo *li, स्थिरांक uid_t uid)
    { (शून्य)li; (शून्य)uid; परत रिक्त; }
संरचना logininfo *login_alloc_entry(pid_t pid, स्थिरांक अक्षर *username,
    स्थिरांक अक्षर *hostname, स्थिरांक अक्षर *ओळ)
    { (शून्य)pid; (शून्य)username; (शून्य)hostname; (शून्य)ओळ; परत रिक्त; }
शून्य server_process_permitopen(संरचना ssh *ssh) { (शून्य)ssh; }
शून्य server_process_channel_timeouts(संरचना ssh *ssh) { (शून्य)ssh; }
पूर्णांक server_loop2(संरचना ssh *ssh, Authctxt *authctxt)
    { (शून्य)ssh; (शून्य)authctxt; परत 0; }
पूर्णांक platform_privileged_uidswap(शून्य) { परत 0; }
पूर्णांक sftp_server_main(पूर्णांक argc, अक्षर **argv, संरचना passwd *user_pw)
    { (शून्य)argc; (शून्य)argv; (शून्य)user_pw; परत 0; }
पूर्णांक debug_flag = 0;
शून्य permanently_set_uid(संरचना passwd *pw) { (शून्य)pw; }
पूर्णांक login_login(संरचना logininfo *li) { (शून्य)li; परत 0; }
पूर्णांक login_logout(संरचना logininfo *li) { (शून्य)li; परत 0; }
शून्य login_free_entry(संरचना logininfo *li) { (शून्य)li; }
शून्य login_set_addr(संरचना logininfo *li, स्थिरांक संरचना sockaddr *sa,
    स्थिरांक अचिन्हित पूर्णांक sa_size) { (शून्य)li; (शून्य)sa; (शून्य)sa_size; }
पूर्णांक openpty(पूर्णांक *amaster, पूर्णांक *aslave, अक्षर *name,
    स्थिरांक संरचना termios *termp, स्थिरांक संरचना winsize *winp)
    { (शून्य)termp; (शून्य)winp; *amaster = -1; *aslave = -1;
    जर (name) name[0] = '\0'; परत -1; }

बाह्य पूर्णांक __real_do_exec(संरचना ssh *, Session *, स्थिरांक अक्षर *);
बाह्य पूर्णांक __real_do_exec_pty(संरचना ssh *, Session *, स्थिरांक अक्षर *);
बाह्य पूर्णांक __real_do_exec_no_pty(संरचना ssh *, Session *, स्थिरांक अक्षर *);

पूर्णांक
__wrap_do_exec(संरचना ssh *ssh, Session *s, स्थिरांक अक्षर *command)
{
	(शून्य)ssh;
	(शून्य)s;
	(शून्य)command;
	परत 0;
}

पूर्णांक
__wrap_do_exec_pty(संरचना ssh *ssh, Session *s, स्थिरांक अक्षर *command)
{
	(शून्य)ssh;
	(शून्य)s;
	(शून्य)command;
	परत 0;
}

पूर्णांक
__wrap_do_exec_no_pty(संरचना ssh *ssh, Session *s, स्थिरांक अक्षर *command)
{
	(शून्य)ssh;
	(शून्य)s;
	(शून्य)command;
	परत 0;
}

स्थिर संरचना sshkey *
load_private(स्थिरांक अक्षर *str)
{
	संरचना sshbuf *b = sshbuf_from(str, म_माप(str));
	संरचना sshkey *k = रिक्त;
	जर (b == रिक्त || sshkey_parse_private_fileblob(b, "", &k, रिक्त) != 0)
		पात();
	sshbuf_free(b);
	परत k;
}

स्थिर संरचना sshkey *
load_public(स्थिरांक अक्षर *str)
{
	अक्षर *tmp, *cp;
	संरचना sshkey *k = sshkey_new(किल्ली_UNSPEC);
	जर (k == रिक्त)
		पात();
	tmp = cp = strdup(str);
	जर (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	परत k;
}

स्थिर पूर्णांक
pump(संरचना ssh *from, संरचना ssh *to, माप_प्रकार *transferred)
{
	स्थिरांक u_char *buf;
	माप_प्रकार len;
	u_char type;
	पूर्णांक r;
	*transferred = 0;
	जर ((r = ssh_packet_next(from, &type)) != 0)
		परत r;
	buf = ssh_output_ptr(from, &len);
	जर (len == 0)
		परत 0;
	जर ((r = ssh_आदान_append(to, buf, len)) != 0)
		परत r;
	जर ((r = ssh_output_consume(from, len)) != 0)
		परत r;
	*transferred = len;
	परत 0;
}

स्थिर पूर्णांक
run_kex(संरचना ssh *client, संरचना ssh *server)
{
	पूर्णांक r;
	माप_प्रकार cn, sn;
	साठी (पूर्णांक i = 0; i < 100; i++) {
		जर ((r = pump(server, client, &sn)) != 0) परत r;
		जर ((r = pump(client, server, &cn)) != 0) परत r;
		जर (server->kex->done && client->kex->done)
			परत 0;
		जर (cn == 0 && sn == 0)
			परत SSH_ERR_PROTOCOL_ERROR;
	}
	परत SSH_ERR_PROTOCOL_ERROR;
}

#अन्तर्भाव "fixed-keys.h"

स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णांक g_init = 0;
स्थिर पूर्णांक g_channel_id = -1;
स्थिर Authctxt g_authctxt;
स्थिर संरचना passwd g_fake_pw;

स्थिर अक्षर *g_pending_rtype = रिक्त;
स्थिर अक्षर *g_pending_exec_cmd = रिक्त;
स्थिर अक्षर *g_pending_env_name = रिक्त;
स्थिर अक्षर *g_pending_env_val = रिक्त;

स्थिर शून्य
my_session_exec_req(संरचना ssh *ssh)
{
	पूर्णांक r;
	जर ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

स्थिर शून्य
my_session_env_req(संरचना ssh *ssh)
{
	पूर्णांक r;
	जर ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, रिक्त)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

स्थिर पूर्णांक
आदान_channel_request(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(शून्य)type;
	(शून्य)seq;
	जर (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, रिक्त) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		परत 0;
	जर (g_channel_id >= 0 && g_pending_rtype != रिक्त) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		जर (c != रिक्त) {
			जर (म_भेद(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			अन्यथा जर (म_भेद(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			अन्यथा
				(शून्य)session_आदान_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	परत 0;
}

स्थिर शून्य
reset_channel(संरचना ssh *ssh)
{
	जर (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		जर (c != रिक्त)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (अक्षर *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (अक्षर *)"fuzz", 0);
	जर (c == रिक्त)
		परत;
	g_channel_id = c->self;
	Session *s = session_new();
	जर (s != रिक्त) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

स्थिर पूर्णांक
init_once(शून्य)
{
	जर (g_init)
		परत 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	स_रखो(&g_fake_pw, 0, आकार(g_fake_pw));
	g_fake_pw.pw_name = (अक्षर *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (अक्षर *)"/tmp";
	g_fake_pw.pw_shell = (अक्षर *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	स_रखो(&g_authctxt, 0, आकार(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	संरचना sshkey *priv = load_private(PRIV_ED25519);
	संरचना sshkey *pub = load_public(PUB_ED25519);
	अक्षर *keyname = xstrdup(sshkey_ssh_name(priv));

	स्थिरांक अक्षर *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *proposal[PROPOSAL_MAX] = { 0 };
	पूर्णांक i;
	साठी (i = 0; i < PROPOSAL_MAX; i++) {
		स्थिरांक अक्षर *p = defaults[i];
		जर (i == PROPOSAL_SERVER_HOST_किल्ली_ALGS)
			p = keyname;
		अन्यथा जर (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		अन्यथा जर (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		अन्यथा जर (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	संरचना kex_params kp;
	स_नकल(kp.proposal, proposal, आकार(proposal));

	जर (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		परत -1;
	जर (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		परत -1;
	जर (run_kex(g_client, g_server) != 0)
		परत -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_संदेश_CHANNEL_REQUEST,
	    &आदान_channel_request);

	मुक्त(keyname);
	साठी (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	परत 0;
}

शून्य
fuzz_session_one(स्थिरांक uint8_t *data, माप_प्रकार size)
{
	जर (init_once() != 0)
		परत;
	जर (size > 65000)
		परत;

	reset_channel(g_server);

	in_fuzz = 1;
	जर (बनाओ_लाँघ(fuzz_env) == 0) {
		माप_प्रकार transferred;
		जर (ssh_packet_put(g_client, SSH2_संदेश_CHANNEL_REQUEST,
		    data, size) != 0)
			जा done;
		जर (pump(g_client, g_server, &transferred) != 0)
			जा done;
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
