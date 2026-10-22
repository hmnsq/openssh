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
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "audit.h"

ServerOptions options;
संरचना sshbuf *loginmsg = रिक्त;
संरचना include_list includes;
संरचना sshauthopt *auth_opts = रिक्त;
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

पूर्णांक
__wrap_ssh_packet_write_wait(संरचना ssh *ssh)
{
	(शून्य)ssh;
	परत 0;
}

स्थिर संरचना passwd g_fake_pw;

पूर्णांक
mm_is_monitor(शून्य)
{
	परत 0;
}

संरचना passwd *
mm_getpwnamallow(संरचना ssh *ssh, स्थिरांक अक्षर *user)
{
	(शून्य)ssh;
	(शून्य)user;
	परत &g_fake_pw;
}

पूर्णांक
mm_auth_password(संरचना ssh *ssh, अक्षर *password)
{
	(शून्य)ssh;
	(शून्य)password;
	परत 0;
}

पूर्णांक
mm_user_किल्ली_allowed(संरचना ssh *ssh, संरचना passwd *pw, संरचना sshkey *किल्ली,
    पूर्णांक auth_attempt, संरचना sshauthopt **authoptsp)
{
	(शून्य)ssh;
	(शून्य)pw;
	(शून्य)किल्ली;
	(शून्य)auth_attempt;
	(शून्य)authoptsp;
	परत 0;
}

पूर्णांक
mm_hostbased_किल्ली_allowed(संरचना ssh *ssh, संरचना passwd *pw, स्थिरांक अक्षर *user,
    स्थिरांक अक्षर *host, संरचना sshkey *किल्ली)
{
	(शून्य)ssh;
	(शून्य)pw;
	(शून्य)user;
	(शून्य)host;
	(शून्य)किल्ली;
	परत 0;
}

पूर्णांक
mm_sshkey_verify(स्थिरांक संरचना sshkey *किल्ली, स्थिरांक u_char *sig, माप_प्रकार siglen,
    स्थिरांक u_char *data, माप_प्रकार datalen, स्थिरांक अक्षर *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	परत sshkey_verify(किल्ली, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

शून्य
mm_inform_authserv(अक्षर *service, अक्षर *style)
{
	(शून्य)service;
	(शून्य)style;
}

शून्य
mm_audit_event(संरचना ssh *ssh, ssh_audit_event_t event)
{
	(शून्य)ssh;
	(शून्य)event;
}

शून्य
mm_start_pam(संरचना ssh *ssh)
{
	(शून्य)ssh;
}

पूर्णांक
mm_do_pam_account(शून्य)
{
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

संरचना sshbuf *cfg = रिक्त;

पूर्णांक auth_rhosts2(संरचना passwd *pw, स्थिरांक अक्षर *client_user,
    स्थिरांक अक्षर *hostname, स्थिरांक अक्षर *ipaddr) { (शून्य)pw;
    (शून्य)client_user; (शून्य)hostname; (शून्य)ipaddr; परत 0; }
पूर्णांक platform_locked_account(संरचना passwd *pw) { (शून्य)pw; परत 0; }
शून्य record_failed_login(संरचना ssh *ssh, स्थिरांक अक्षर *user,
    स्थिरांक अक्षर *hostname, स्थिरांक अक्षर *ttyname) { (शून्य)ssh; (शून्य)user;
    (शून्य)hostname; (शून्य)ttyname; }
पूर्णांक temporarily_use_uid(संरचना passwd *pw) { (शून्य)pw; परत 0; }
शून्य restore_uid(शून्य) { }
अक्षर *mm_auth2_read_banner(शून्य) { परत रिक्त; }
संरचना connection_info *
server_get_connection_info(संरचना ssh *ssh, पूर्णांक populate, पूर्णांक use_dns)
    { (शून्य)ssh; (शून्य)populate; (शून्य)use_dns; परत रिक्त; }
शून्य server_process_permitopen(संरचना ssh *ssh) { (शून्य)ssh; }
शून्य server_process_channel_timeouts(संरचना ssh *ssh) { (शून्य)ssh; }

#अन्तर्भाव "../../../auth2.c"

स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णांक g_init = 0;
स्थिर Authctxt g_authctxt;

स्थिर शून्य
fuzz_reset_authctxt(संरचना ssh *ssh)
{
	अचिन्हित पूर्णांक i;

	मुक्त(g_authctxt.user);
	मुक्त(g_authctxt.service);
	मुक्त(g_authctxt.style);
	मुक्त(g_authctxt.auth_method_info);
	जर (g_authctxt.auth_methods != रिक्त) {
		साठी (i = 0; i < g_authctxt.अंक_auth_methods; i++)
			मुक्त(g_authctxt.auth_methods[i]);
		मुक्त(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_किल्ली);
	साठी (i = 0; i < g_authctxt.nprev_किल्ल्या; i++)
		sshkey_free(g_authctxt.prev_किल्ल्या[i]);
	मुक्त(g_authctxt.prev_किल्ल्या);
	sshbuf_free(g_authctxt.session_info);
	स_रखो(&g_authctxt, 0, आकार(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

स्थिर पूर्णांक
init_once(शून्य)
{
	जर (g_init)
		परत 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
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
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

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

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_संदेश_USERAUTH_REQUEST,
	    &आदान_userauth_request);

	मुक्त(keyname);
	साठी (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	परत 0;
}

शून्य
fuzz_userauth_one(स्थिरांक uint8_t *data, माप_प्रकार size)
{
	जर (init_once() != 0)
		परत;
	जर (size > 65000)
		परत;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	जर (बनाओ_लाँघ(fuzz_env) == 0) {
		माप_प्रकार transferred;
		जर (ssh_packet_put(g_client, SSH2_संदेश_USERAUTH_REQUEST,
		    data, size) != 0)
			जा done;
		जर (pump(g_client, g_server, &transferred) != 0)
			जा done;
		(शून्य)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, रिक्त);
	done:
		;
	}
	in_fuzz = 0;
}
