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

#समावेश <setjmp.h>
#समावेश <signal.h>
#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

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
#समावेश "readconf.h"

Options options;
पूर्णांक debug_flag = 0;

काष्ठा ssh;

पूर्णांक
__wrap_ssh_packet_write_wait(काष्ठा ssh *ssh)
{
	(व्योम)ssh;
	वापस 0;
}

अक्षर *
__wrap_read_passphrase(स्थिर अक्षर *prompt, पूर्णांक flags)
{
	(व्योम)prompt;
	(व्योम)flags;
	वापस strdup("fuzz");
}

#समावेश "../../../sshconnect2.c"
#समावेश "fixed-keys.h"

अटल लाँघ_बफ fuzz_env;
अटल अस्थिर पूर्णांक in_fuzz = 0;

व्योम
cleanup_exit(पूर्णांक code)
{
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_निकास(code);
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

अटल Sensitive g_sensitive = { शून्य, 0 };
अटल Authctxt g_authctxt;
अटल काष्ठा ssh *g_client = शून्य;
अटल काष्ठा ssh *g_server = शून्य;
अटल पूर्णांक g_init = 0;

अटल व्योम
fuzz_reset_authctxt(काष्ठा ssh *ssh)
{
	मुक्त(g_authctxt.authlist);
	g_authctxt.authlist = शून्य;
	अगर (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	स_रखो(&g_authctxt, 0, माप(g_authctxt));
	g_authctxt.server_user = (अक्षर *)"fuzz";
	g_authctxt.local_user = (अक्षर *)"fuzz";
	g_authctxt.host = (अक्षर *)"127.0.0.1";
	g_authctxt.service = (अक्षर *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = शून्य;
	g_authctxt.methoddata = शून्य;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = शून्य;
	g_authctxt.oktypes = शून्य;
	g_authctxt.ktypes = शून्य;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.कुंजियाँ);
	ssh->authctxt = &g_authctxt;
}

अटल व्योम
fuzz_setup(काष्ठा ssh *ssh)
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
	(व्योम)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, kex_निवेश_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_SERVICE_ACCEPT, &निवेश_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_SUCCESS, &निवेश_userauth_success);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_FAILURE, &निवेश_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_BANNER, &निवेश_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_INFO_REQUEST, &निवेश_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PK_OK, &निवेश_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ, &निवेश_userauth_passwd_changereq);
}

अटल पूर्णांक
init_once(व्योम)
{
	अगर (g_init)
		वापस 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

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

	fuzz_setup(g_client);

	मुक्त(keyname);
	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	वापस 0;
}

अटल स्थिर uint8_t k_संदेश_types[] = {
	SSH2_संदेश_DISCONNECT, SSH2_संदेश_IGNORE, SSH2_संदेश_UNIMPLEMENTED,
	SSH2_संदेश_DEBUG, SSH2_संदेश_SERVICE_ACCEPT, SSH2_संदेश_EXT_INFO,
	SSH2_संदेश_USERAUTH_FAILURE, SSH2_संदेश_USERAUTH_SUCCESS,
	SSH2_संदेश_USERAUTH_BANNER, SSH2_संदेश_USERAUTH_INFO_REQUEST,
	SSH2_संदेश_USERAUTH_PK_OK, SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ,
};

व्योम
fuzz_one_message(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (init_once() != 0)
		वापस;
	अगर (आकार > 65000)
		वापस;

	uint8_t selector = आकार > 0 ? तथ्य[0] : 0;
	स्थिर uint8_t *payload = आकार > 0 ? तथ्य + 1 : शून्य;
	माप_प्रकार plen = आकार > 0 ? आकार - 1 : 0;

	uint8_t संदेश_type = k_संदेश_types[selector %
	    (माप(k_संदेश_types) / माप(k_संदेश_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	अगर (बनाओ_लाँघ(fuzz_env) == 0) {
		माप_प्रकार transferred;
		अगर (ssh_packet_put(g_server, संदेश_type, payload, plen) != 0)
			जाओ done;
		अगर (pump(g_server, g_client, &transferred) != 0)
			जाओ done;
		(व्योम)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, शून्य);
	done:
		;
	}
	in_fuzz = 0;
}
