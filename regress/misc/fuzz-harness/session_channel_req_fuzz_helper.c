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

#समावेश <setjmp.h>
#समावेश <signal.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <pwd.h>
#समावेश <sys/types.h>

#समावेश "log.h"
#समावेश "digest.h"
#समावेश "misc.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "ssh_api.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "packet.h"
#समावेश "myproposal.h"
#समावेश "kex.h"
#समावेश "xmalloc.h"
#समावेश "authfile.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-options.h"
#समावेश "servconf.h"
#समावेश "channels.h"
#समावेश "session.h"

ServerOptions options;
काष्ठा sshbuf *loginmsg = शून्य;
काष्ठा include_list includes;
अटल काष्ठा sshauthopt g_auth_opts_storage;
काष्ठा sshauthopt *auth_opts = &g_auth_opts_storage;
काष्ठा passwd *privsep_pw = शून्य;

अटल लाँघ_बफ fuzz_env;
अटल अस्थिर पूर्णांक in_fuzz = 0;

व्योम
cleanup_exit(पूर्णांक code)
{
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_निकास(code);
}

व्योम
__wrap_ssh_packet_disconnect(काष्ठा ssh *ssh, स्थिर अक्षर *fmt, ...)
{
	(व्योम)ssh;
	(व्योम)fmt;
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_निकास(1);
}

पूर्णांक
__wrap_sshpkt_fatal(काष्ठा ssh *ssh, पूर्णांक r, स्थिर अक्षर *fmt, ...)
{
	(व्योम)ssh;
	(व्योम)fmt;
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_निकास(r ? r : 1);
}

पूर्णांक
mm_is_monitor(व्योम)
{
	वापस 0;
}

व्योम
mm_audit_run_command(स्थिर अक्षर *cmd)
{
	(व्योम)cmd;
}

पूर्णांक
mm_pty_allocate(पूर्णांक *ptyfd, पूर्णांक *ttyfd, अक्षर *namebuf, माप_प्रकार namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	अगर (namebuf != शून्य && namebuflen > 0)
		namebuf[0] = '\0';
	वापस 0;
}

व्योम mm_session_pty_cleanup2(Session *s) { (व्योम)s; }
पूर्णांक platform_locked_account(काष्ठा passwd *pw) { (व्योम)pw; वापस 0; }
व्योम record_failed_login(काष्ठा ssh *ssh, स्थिर अक्षर *user,
    स्थिर अक्षर *hostname, स्थिर अक्षर *ttyname) { (व्योम)ssh; (व्योम)user;
    (व्योम)hostname; (व्योम)ttyname; }
पूर्णांक temporarily_use_uid(काष्ठा passwd *pw) { (व्योम)pw; वापस 0; }
व्योम restore_uid(व्योम) { }
व्योम platform_setusercontext(काष्ठा passwd *pw) { (व्योम)pw; }
व्योम platform_setusercontext_post_groups(काष्ठा passwd *pw) { (व्योम)pw; }
काष्ठा connection_info *
server_get_connection_info(काष्ठा ssh *ssh, पूर्णांक populate, पूर्णांक use_dns)
    { (व्योम)ssh; (व्योम)populate; (व्योम)use_dns; वापस शून्य; }
पूर्णांक auth2_methods_valid(स्थिर अक्षर *list, पूर्णांक allow_unknown)
    { (व्योम)list; (व्योम)allow_unknown; वापस 0; }
काष्ठा sshbuf *cfg = शून्य;
पूर्णांक auth_sock = -1;
अक्षर **tun_fwd_ifnames = शून्य;

काष्ठा logininfo *login_get_lastlog(काष्ठा logininfo *li, स्थिर uid_t uid)
    { (व्योम)li; (व्योम)uid; वापस शून्य; }
काष्ठा logininfo *login_alloc_entry(pid_t pid, स्थिर अक्षर *username,
    स्थिर अक्षर *hostname, स्थिर अक्षर *पंक्ति)
    { (व्योम)pid; (व्योम)username; (व्योम)hostname; (व्योम)पंक्ति; वापस शून्य; }
व्योम server_process_permitopen(काष्ठा ssh *ssh) { (व्योम)ssh; }
व्योम server_process_channel_timeouts(काष्ठा ssh *ssh) { (व्योम)ssh; }
पूर्णांक server_loop2(काष्ठा ssh *ssh, Authctxt *authctxt)
    { (व्योम)ssh; (व्योम)authctxt; वापस 0; }
पूर्णांक platform_privileged_uidswap(व्योम) { वापस 0; }
पूर्णांक sftp_server_main(पूर्णांक argc, अक्षर **argv, काष्ठा passwd *user_pw)
    { (व्योम)argc; (व्योम)argv; (व्योम)user_pw; वापस 0; }
पूर्णांक debug_flag = 0;
व्योम permanently_set_uid(काष्ठा passwd *pw) { (व्योम)pw; }
पूर्णांक login_login(काष्ठा logininfo *li) { (व्योम)li; वापस 0; }
पूर्णांक login_logout(काष्ठा logininfo *li) { (व्योम)li; वापस 0; }
व्योम login_free_entry(काष्ठा logininfo *li) { (व्योम)li; }
व्योम login_set_addr(काष्ठा logininfo *li, स्थिर काष्ठा sockaddr *sa,
    स्थिर अचिन्हित पूर्णांक sa_आकार) { (व्योम)li; (व्योम)sa; (व्योम)sa_आकार; }
पूर्णांक openpty(पूर्णांक *amaster, पूर्णांक *aslave, अक्षर *name,
    स्थिर काष्ठा termios *termp, स्थिर काष्ठा winsize *winp)
    { (व्योम)termp; (व्योम)winp; *amaster = -1; *aslave = -1;
    अगर (name) name[0] = '\0'; वापस -1; }

बाह्य पूर्णांक __real_do_exec(काष्ठा ssh *, Session *, स्थिर अक्षर *);
बाह्य पूर्णांक __real_do_exec_pty(काष्ठा ssh *, Session *, स्थिर अक्षर *);
बाह्य पूर्णांक __real_do_exec_no_pty(काष्ठा ssh *, Session *, स्थिर अक्षर *);

पूर्णांक
__wrap_do_exec(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	(व्योम)ssh;
	(व्योम)s;
	(व्योम)command;
	वापस 0;
}

पूर्णांक
__wrap_do_exec_pty(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	(व्योम)ssh;
	(व्योम)s;
	(व्योम)command;
	वापस 0;
}

पूर्णांक
__wrap_do_exec_no_pty(काष्ठा ssh *ssh, Session *s, स्थिर अक्षर *command)
{
	(व्योम)ssh;
	(व्योम)s;
	(व्योम)command;
	वापस 0;
}

अटल काष्ठा sshkey *
load_private(स्थिर अक्षर *str)
{
	काष्ठा sshbuf *b = sshbuf_from(str, म_माप(str));
	काष्ठा sshkey *k = शून्य;
	अगर (b == शून्य || sshkey_parse_private_fileblob(b, "", &k, शून्य) != 0)
		पात();
	sshbuf_free(b);
	वापस k;
}

अटल काष्ठा sshkey *
load_public(स्थिर अक्षर *str)
{
	अक्षर *tmp, *cp;
	काष्ठा sshkey *k = sshkey_new(कुंजी_UNSPEC);
	अगर (k == शून्य)
		पात();
	tmp = cp = strdup(str);
	अगर (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	वापस k;
}

अटल पूर्णांक
pump(काष्ठा ssh *from, काष्ठा ssh *to, माप_प्रकार *transferred)
{
	स्थिर u_char *buf;
	माप_प्रकार len;
	u_char type;
	पूर्णांक r;
	*transferred = 0;
	अगर ((r = ssh_packet_अग्र(from, &type)) != 0)
		वापस r;
	buf = ssh_output_ptr(from, &len);
	अगर (len == 0)
		वापस 0;
	अगर ((r = ssh_निवेश_append(to, buf, len)) != 0)
		वापस r;
	अगर ((r = ssh_output_consume(from, len)) != 0)
		वापस r;
	*transferred = len;
	वापस 0;
}

अटल पूर्णांक
run_kex(काष्ठा ssh *client, काष्ठा ssh *server)
{
	पूर्णांक r;
	माप_प्रकार cn, sn;
	क्रम (पूर्णांक i = 0; i < 100; i++) {
		अगर ((r = pump(server, client, &sn)) != 0) वापस r;
		अगर ((r = pump(client, server, &cn)) != 0) वापस r;
		अगर (server->kex->done && client->kex->done)
			वापस 0;
		अगर (cn == 0 && sn == 0)
			वापस SSH_ERR_PROTOCOL_ERROR;
	}
	वापस SSH_ERR_PROTOCOL_ERROR;
}

#समावेश "fixed-keys.h"

अटल काष्ठा ssh *g_client = शून्य;
अटल काष्ठा ssh *g_server = शून्य;
अटल पूर्णांक g_init = 0;
अटल पूर्णांक g_channel_id = -1;
अटल Authctxt g_authctxt;
अटल काष्ठा passwd g_fake_pw;

अटल अक्षर *g_pending_rtype = शून्य;
अटल अक्षर *g_pending_exec_cmd = शून्य;
अटल अक्षर *g_pending_env_name = शून्य;
अटल अक्षर *g_pending_env_val = शून्य;

अटल व्योम
my_session_exec_req(काष्ठा ssh *ssh)
{
	पूर्णांक r;
	अगर ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

अटल व्योम
my_session_env_req(काष्ठा ssh *ssh)
{
	पूर्णांक r;
	अगर ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, शून्य)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

अटल पूर्णांक
निवेश_channel_request(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(व्योम)type;
	(व्योम)seq;
	अगर (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, शून्य) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		वापस 0;
	अगर (g_channel_id >= 0 && g_pending_rtype != शून्य) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		अगर (c != शून्य) {
			अगर (म_भेद(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			अन्यथा अगर (म_भेद(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			अन्यथा
				(व्योम)session_निवेश_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	वापस 0;
}

अटल व्योम
reset_channel(काष्ठा ssh *ssh)
{
	अगर (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		अगर (c != शून्य)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (अक्षर *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (अक्षर *)"fuzz", 0);
	अगर (c == शून्य)
		वापस;
	g_channel_id = c->self;
	Session *s = session_new();
	अगर (s != शून्य) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

अटल पूर्णांक
init_once(व्योम)
{
	अगर (g_init)
		वापस 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	स_रखो(&g_fake_pw, 0, माप(g_fake_pw));
	g_fake_pw.pw_name = (अक्षर *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (अक्षर *)"/tmp";
	g_fake_pw.pw_shell = (अक्षर *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	स_रखो(&g_authctxt, 0, माप(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	काष्ठा sshkey *priv = load_private(PRIV_ED25519);
	काष्ठा sshkey *pub = load_public(PUB_ED25519);
	अक्षर *keyname = xstrdup(sshkey_ssh_name(priv));

	स्थिर अक्षर *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *proposal[PROPOSAL_MAX] = { 0 };
	पूर्णांक i;
	क्रम (i = 0; i < PROPOSAL_MAX; i++) {
		स्थिर अक्षर *p = defaults[i];
		अगर (i == PROPOSAL_SERVER_HOST_कुंजी_ALGS)
			p = keyname;
		अन्यथा अगर (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		अन्यथा अगर (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		अन्यथा अगर (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	काष्ठा kex_params kp;
	स_नकल(kp.proposal, proposal, माप(proposal));

	अगर (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		वापस -1;
	अगर (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		वापस -1;
	अगर (run_kex(g_client, g_server) != 0)
		वापस -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_संदेश_CHANNEL_REQUEST,
	    &निवेश_channel_request);

	मुक्त(keyname);
	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	वापस 0;
}

व्योम
fuzz_session_one(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (init_once() != 0)
		वापस;
	अगर (आकार > 65000)
		वापस;

	reset_channel(g_server);

	in_fuzz = 1;
	अगर (बनाओ_लाँघ(fuzz_env) == 0) {
		माप_प्रकार transferred;
		अगर (ssh_packet_put(g_client, SSH2_संदेश_CHANNEL_REQUEST,
		    तथ्य, आकार) != 0)
			जाओ done;
		अगर (pump(g_client, g_server, &transferred) != 0)
			जाओ done;
		(व्योम)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, शून्य);
	done:
		;
	}
	in_fuzz = 0;
	मुक्त(g_pending_rtype);
	g_pending_rtype = शून्य;
	मुक्त(g_pending_exec_cmd);
	g_pending_exec_cmd = शून्य;
	मुक्त(g_pending_env_name);
	g_pending_env_name = शून्य;
	मुक्त(g_pending_env_val);
	g_pending_env_val = शून्य;
}
