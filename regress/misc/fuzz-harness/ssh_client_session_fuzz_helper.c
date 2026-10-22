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
 * Fuzzer for OpenSSH client-side userauth dispatch (sshconnect2.c)
 *
 * Target: sshconnect2.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sshconnect2.c so
 * its static input_userauth_* handlers are reachable from this
 * translation unit. The driver completes an in-process KEX with real
 * cipher and HMAC, then for each iteration injects a fuzzer-controlled
 * SSH2_MSG_* message into the client's input stream and runs the
 * dispatch loop. Non-userauth message types fall through to
 * dispatch_protocol_ignore.
 *
 * Primary functions exercised:
 * - input_userauth_banner / failure / success / info_req / pk_ok /
 *   passwd_changereq / service_accept
 * - sshkey_from_blob (via input_userauth_pk_ok)
 * - downstream sshpkt_get_* and sshbuf_get_* primitives
 *
 * Linker --wrap neutralises two blocking functions:
 * - __wrap_ssh_packet_write_wait (real one ppoll's on fd=-1)
 * - __wrap_read_passphrase (real one reads /dev/tty)
 */

#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

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
#अन्तर्भाव "readconf.h"

Options options;
पूर्णांक debug_flag = 0;

संरचना ssh;

पूर्णांक
__wrap_ssh_packet_write_wait(संरचना ssh *ssh)
{
	(शून्य)ssh;
	परत 0;
}

अक्षर *
__wrap_read_passphrase(स्थिरांक अक्षर *prompt, पूर्णांक flags)
{
	(शून्य)prompt;
	(शून्य)flags;
	परत strdup("fuzz");
}

#अन्तर्भाव "../../../sshconnect2.c"
#अन्तर्भाव "fixed-keys.h"

स्थिर लाँघ_बफ fuzz_env;
स्थिर अस्थिर पूर्णांक in_fuzz = 0;

शून्य
cleanup_exit(पूर्णांक code)
{
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_exit(code);
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

स्थिर Sensitive g_sensitive = { रिक्त, 0 };
स्थिर Authctxt g_authctxt;
स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णांक g_init = 0;

स्थिर शून्य
fuzz_reset_authctxt(संरचना ssh *ssh)
{
	मुक्त(g_authctxt.authlist);
	g_authctxt.authlist = रिक्त;
	जर (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	स_रखो(&g_authctxt, 0, आकार(g_authctxt));
	g_authctxt.server_user = (अक्षर *)"fuzz";
	g_authctxt.local_user = (अक्षर *)"fuzz";
	g_authctxt.host = (अक्षर *)"127.0.0.1";
	g_authctxt.service = (अक्षर *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = रिक्त;
	g_authctxt.methoddata = रिक्त;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = रिक्त;
	g_authctxt.oktypes = रिक्त;
	g_authctxt.ktypes = रिक्त;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.किल्ल्या);
	ssh->authctxt = &g_authctxt;
}

स्थिर शून्य
fuzz_setup(संरचना ssh *ssh)
{
	initialize_options(&options);
	options.batch_mode = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.संख्या_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(शून्य)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, kex_आदान_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_SERVICE_ACCEPT, &आदान_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_SUCCESS, &आदान_userauth_success);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_FAILURE, &आदान_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_BANNER, &आदान_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST, &आदान_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PK_OK, &आदान_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ, &आदान_userauth_passwd_changereq);
}

स्थिर पूर्णांक
init_once(शून्य)
{
	जर (g_init)
		परत 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

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

	fuzz_setup(g_client);

	मुक्त(keyname);
	साठी (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	परत 0;
}

स्थिर स्थिरांक uint8_t k_संदेश_types[] = {
	SSH2_संदेश_DISCONNECT, SSH2_संदेश_IGNORE, SSH2_संदेश_UNIMPLEMENTED,
	SSH2_संदेश_DEBUG, SSH2_संदेश_SERVICE_ACCEPT, SSH2_संदेश_EXT_INFO,
	SSH2_संदेश_USERAUTH_FAILURE, SSH2_संदेश_USERAUTH_SUCCESS,
	SSH2_संदेश_USERAUTH_BANNER, SSH2_संदेश_USERAUTH_INFO_REQUEST,
	SSH2_संदेश_USERAUTH_PK_OK, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ,
};

शून्य
fuzz_one_message(स्थिरांक uint8_t *data, माप_प्रकार size)
{
	जर (init_once() != 0)
		परत;
	जर (size > 65000)
		परत;

	uint8_t selector = size > 0 ? data[0] : 0;
	स्थिरांक uint8_t *payload = size > 0 ? data + 1 : रिक्त;
	माप_प्रकार plen = size > 0 ? size - 1 : 0;

	uint8_t संदेश_type = k_संदेश_types[selector %
	    (आकार(k_संदेश_types) / आकार(k_संदेश_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	जर (बनाओ_लाँघ(fuzz_env) == 0) {
		माप_प्रकार transferred;
		जर (ssh_packet_put(g_server, संदेश_type, payload, plen) != 0)
			जा done;
		जर (pump(g_server, g_client, &transferred) != 0)
			जा done;
		(शून्य)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, रिक्त);
	done:
		;
	}
	in_fuzz = 0;
}
