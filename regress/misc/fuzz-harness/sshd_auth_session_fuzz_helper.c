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
 * Fuzzer for OpenSSH server-side userauth dispatch (auth2.c + auth2-*.c)
 *
 * Target: input_userauth_request and the userauth_* method handlers
 *
 * Threat model: pre-auth attacker sending crafted USERAUTH_REQUEST
 * messages to sshd. Mirror of ssh_client_session_fuzz on the server
 * side. The handlers parse method/user/service/key/sig fields before
 * calling any actual authentication backend.
 *
 * Mock layer: the monitor_wrap mm_* IPC functions are replaced with
 * in-process stubs that return canned data so the dispatch path runs
 * without real privsep IPC or filesystem access. mm_sshkey_verify is
 * the only stub that calls a real backend (sshkey_verify), which
 * harmlessly fails on garbage signatures.
 *
 * KEX is real, mirrored across two in-process ssh structs created via
 * ssh_api. After KEX completes, input_userauth_request is registered
 * on the server's dispatch table and each iteration delivers a
 * fuzzer-controlled USERAUTH_REQUEST.
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
#समावेश "servconf.h"
#समावेश "audit.h"

ServerOptions options;
काष्ठा sshbuf *loginmsg = शून्य;
काष्ठा include_list includes;
काष्ठा sshauthopt *auth_opts = शून्य;
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

पूर्णांक
__wrap_ssh_packet_write_wait(काष्ठा ssh *ssh)
{
	(व्योम)ssh;
	वापस 0;
}

अटल काष्ठा passwd g_fake_pw;

पूर्णांक
mm_is_monitor(व्योम)
{
	वापस 0;
}

काष्ठा passwd *
mm_getpwnamallow(काष्ठा ssh *ssh, स्थिर अक्षर *user)
{
	(व्योम)ssh;
	(व्योम)user;
	वापस &g_fake_pw;
}

पूर्णांक
mm_auth_password(काष्ठा ssh *ssh, अक्षर *password)
{
	(व्योम)ssh;
	(व्योम)password;
	वापस 0;
}

पूर्णांक
mm_user_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *pw, काष्ठा sshkey *कुंजी,
    पूर्णांक auth_attempt, काष्ठा sshauthopt **authoptsp)
{
	(व्योम)ssh;
	(व्योम)pw;
	(व्योम)कुंजी;
	(व्योम)auth_attempt;
	(व्योम)authoptsp;
	वापस 0;
}

पूर्णांक
mm_hostbased_कुंजी_allowed(काष्ठा ssh *ssh, काष्ठा passwd *pw, स्थिर अक्षर *user,
    स्थिर अक्षर *host, काष्ठा sshkey *कुंजी)
{
	(व्योम)ssh;
	(व्योम)pw;
	(व्योम)user;
	(व्योम)host;
	(व्योम)कुंजी;
	वापस 0;
}

पूर्णांक
mm_sshkey_verify(स्थिर काष्ठा sshkey *कुंजी, स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार datalen, स्थिर अक्षर *alg, u_int compat,
    काष्ठा sshkey_sig_details **detailsp)
{
	वापस sshkey_verify(कुंजी, sig, siglen, तथ्य, datalen, alg, compat,
	    detailsp);
}

व्योम
mm_inform_authserv(अक्षर *service, अक्षर *style)
{
	(व्योम)service;
	(व्योम)style;
}

व्योम
mm_audit_event(काष्ठा ssh *ssh, ssh_audit_event_t event)
{
	(व्योम)ssh;
	(व्योम)event;
}

व्योम
mm_start_pam(काष्ठा ssh *ssh)
{
	(व्योम)ssh;
}

पूर्णांक
mm_do_pam_account(व्योम)
{
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

काष्ठा sshbuf *cfg = शून्य;

पूर्णांक auth_rhosts2(काष्ठा passwd *pw, स्थिर अक्षर *client_user,
    स्थिर अक्षर *hostname, स्थिर अक्षर *ipaddr) { (व्योम)pw;
    (व्योम)client_user; (व्योम)hostname; (व्योम)ipaddr; वापस 0; }
पूर्णांक platform_locked_account(काष्ठा passwd *pw) { (व्योम)pw; वापस 0; }
व्योम record_failed_login(काष्ठा ssh *ssh, स्थिर अक्षर *user,
    स्थिर अक्षर *hostname, स्थिर अक्षर *ttyname) { (व्योम)ssh; (व्योम)user;
    (व्योम)hostname; (व्योम)ttyname; }
पूर्णांक temporarily_use_uid(काष्ठा passwd *pw) { (व्योम)pw; वापस 0; }
व्योम restore_uid(व्योम) { }
अक्षर *mm_auth2_read_banner(व्योम) { वापस शून्य; }
काष्ठा connection_info *
server_get_connection_info(काष्ठा ssh *ssh, पूर्णांक populate, पूर्णांक use_dns)
    { (व्योम)ssh; (व्योम)populate; (व्योम)use_dns; वापस शून्य; }
व्योम server_process_permitopen(काष्ठा ssh *ssh) { (व्योम)ssh; }
व्योम server_process_channel_timeouts(काष्ठा ssh *ssh) { (व्योम)ssh; }

#समावेश "../../../auth2.c"

अटल काष्ठा ssh *g_client = शून्य;
अटल काष्ठा ssh *g_server = शून्य;
अटल पूर्णांक g_init = 0;
अटल Authctxt g_authctxt;

अटल व्योम
fuzz_reset_authctxt(काष्ठा ssh *ssh)
{
	अचिन्हित पूर्णांक i;

	मुक्त(g_authctxt.user);
	मुक्त(g_authctxt.service);
	मुक्त(g_authctxt.style);
	मुक्त(g_authctxt.auth_method_info);
	अगर (g_authctxt.auth_methods != शून्य) {
		क्रम (i = 0; i < g_authctxt.अंक_auth_methods; i++)
			मुक्त(g_authctxt.auth_methods[i]);
		मुक्त(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_कुंजी);
	क्रम (i = 0; i < g_authctxt.nprev_कुंजियाँ; i++)
		sshkey_free(g_authctxt.पूर्व_कुंजियाँ[i]);
	मुक्त(g_authctxt.पूर्व_कुंजियाँ);
	sshbuf_free(g_authctxt.session_info);
	स_रखो(&g_authctxt, 0, माप(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

अटल पूर्णांक
init_once(व्योम)
{
	अगर (g_init)
		वापस 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
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
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

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

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_संदेश_USERAUTH_REQUEST,
	    &निवेश_userauth_request);

	मुक्त(keyname);
	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	वापस 0;
}

व्योम
fuzz_userauth_one(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (init_once() != 0)
		वापस;
	अगर (आकार > 65000)
		वापस;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	अगर (बनाओ_लाँघ(fuzz_env) == 0) {
		माप_प्रकार transferred;
		अगर (ssh_packet_put(g_client, SSH2_संदेश_USERAUTH_REQUEST,
		    तथ्य, आकार) != 0)
			जाओ done;
		अगर (pump(g_client, g_server, &transferred) != 0)
			जाओ done;
		(व्योम)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, शून्य);
	done:
		;
	}
	in_fuzz = 0;
}
