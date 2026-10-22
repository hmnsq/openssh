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
पूर्णाङ्क debug_flag = 0;

संरचना ssh;

पूर्णाङ्क
__wrap_ssh_packet_write_wait(संरचना ssh *ssh)
{
	(शून्य)ssh;
	प्रत्यागम 0;
}

वर्ण *
__wrap_read_passphrase(ध्रुव वर्ण *prompt, पूर्णाङ्क flags)
{
	(शून्य)prompt;
	(शून्य)flags;
	प्रत्यागम strdup("fuzz");
}

#अन्तर्भाव "../../../sshconnect2.c"
#अन्तर्भाव "fixed-keys.h"

स्थिर jmp_buf fuzz_env;
स्थिर चञ्चल पूर्णाङ्क अन्तर्_fuzz = 0;

शून्य
cleanup_exit(पूर्णाङ्क संहिता)
{
	यदि (अन्तर्_fuzz)
		longjmp(fuzz_env, संहिता ? संहिता : 1);
	_exit(संहिता);
}

स्थिर संरचना sshkey *
आरोपय_वैयक्तिकम्(ध्रुव वर्ण *str)
{
	संरचना sshbuf *b = sshbuf_from(str, वाक्यदैर्घ्यम्(str));
	संरचना sshkey *k = रिक्त;
	यदि (b == रिक्त || sshkey_parse_वैयक्तिकम्_fileblob(b, "", &k, रिक्त) != 0)
		abort();
	sshbuf_free(b);
	प्रत्यागम k;
}

स्थिर संरचना sshkey *
आरोपय_लौकिकम्(ध्रुव वर्ण *str)
{
	वर्ण *tmp, *cp;
	संरचना sshkey *k = sshkey_new(कुञ्चिका_UNSPEC);
	यदि (k == रिक्त)
		abort();
	tmp = cp = strdup(str);
	यदि (sshkey_read(k, &cp) != 0)
		abort();
	मुक्त(tmp);
	प्रत्यागम k;
}

स्थिर पूर्णाङ्क
pump(संरचना ssh *from, संरचना ssh *गन्तव्यम्, आकार_t *transferred)
{
	ध्रुव u_char *buf;
	आकार_t len;
	u_char type;
	पूर्णाङ्क r;
	*transferred = 0;
	यदि ((r = ssh_packet_अग्र(from, &type)) != 0)
		प्रत्यागम r;
	buf = ssh_output_ptr(from, &len);
	यदि (len == 0)
		प्रत्यागम 0;
	यदि ((r = ssh_निवेशः_append(गन्तव्यम्, buf, len)) != 0)
		प्रत्यागम r;
	यदि ((r = ssh_output_consume(from, len)) != 0)
		प्रत्यागम r;
	*transferred = len;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
सततम्_kex(संरचना ssh *client, संरचना ssh *server)
{
	पूर्णाङ्क r;
	आकार_t cn, sn;
	प्रति (पूर्णाङ्क i = 0; i < 100; i++) {
		यदि ((r = pump(server, client, &sn)) != 0) प्रत्यागम r;
		यदि ((r = pump(client, server, &cn)) != 0) प्रत्यागम r;
		यदि (server->kex->समाप्तम् && client->kex->समाप्तम्)
			प्रत्यागम 0;
		यदि (cn == 0 && sn == 0)
			प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
	}
	प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
}

स्थिर Sensitive g_sensitive = { रिक्त, 0 };
स्थिर Authctxt g_authctxt;
स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णाङ्क g_init = 0;

स्थिर शून्य
fuzz_reset_authctxt(संरचना ssh *ssh)
{
	मुक्त(g_authctxt.authlist);
	g_authctxt.authlist = रिक्त;
	यदि (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	स्मृतिं_पूरय(&g_authctxt, 0, परिमाण(g_authctxt));
	g_authctxt.server_user = (वर्ण *)"fuzz";
	g_authctxt.local_user = (वर्ण *)"fuzz";
	g_authctxt.host = (वर्ण *)"127.0.0.1";
	g_authctxt.service = (वर्ण *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.विधानम् = authmethod_lookup("none");
	g_authctxt.authlist = रिक्त;
	g_authctxt.methoddata = रिक्त;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.सक्रिय_ktype = रिक्त;
	g_authctxt.oktypes = रिक्त;
	g_authctxt.ktypes = रिक्त;
	g_authctxt.info_req_आलोकितम् = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.कुञ्चिकाः);
	ssh->authctxt = &g_authctxt;
}

स्थिर शून्य
fuzz_सज्जता(संरचना ssh *ssh)
{
	initialize_options(&options);
	options.batch_बहुलकम् = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.सङ्ख्या_सम्बन्धि_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(शून्य)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, kex_निवेशः_ext_info);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_SERVICE_ACCEPT, &निवेशः_userauth_service_accept);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_SUCCESS, &निवेशः_userauth_success);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_FAILURE, &निवेशः_userauth_failure);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_BANNER, &निवेशः_userauth_banner);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_INFO_REQUEST, &निवेशः_userauth_info_req);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_PK_OK, &निवेशः_userauth_pk_ok);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_USERAUTH_PASSWD_CHANGEREQ, &निवेशः_userauth_passwd_changereq);
}

स्थिर पूर्णाङ्क
init_once(शून्य)
{
	यदि (g_init)
		प्रत्यागम 0;
	सङ्केत(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	संरचना sshkey *priv = आरोपय_वैयक्तिकम्(PRIV_ED25519);
	संरचना sshkey *pub = आरोपय_लौकिकम्(PUB_ED25519);
	वर्ण *keyname = xstrdup(sshkey_ssh_name(priv));

	ध्रुव वर्ण *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	वर्ण *proposal[PROPOSAL_MAX] = { 0 };
	पूर्णाङ्क i;
	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		ध्रुव वर्ण *p = defaults[i];
		यदि (i == PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS)
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
	स्मृतिं_प्रतिलिख(kp.proposal, proposal, परिमाण(proposal));

	यदि (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		प्रत्यागम -1;
	यदि (ssh_सङ्कलय_hostkey(g_server, priv) != 0 ||
	    ssh_सङ्कलय_hostkey(g_client, pub) != 0)
		प्रत्यागम -1;
	यदि (सततम्_kex(g_client, g_server) != 0)
		प्रत्यागम -1;

	fuzz_सज्जता(g_client);

	मुक्त(keyname);
	प्रति (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	प्रत्यागम 0;
}

स्थिर ध्रुव uint8_t k_सन्देशः_types[] = {
	SSH2_सन्देशः_DISCONNECT, SSH2_सन्देशः_IGNORE, SSH2_सन्देशः_UNIMPLEMENTED,
	SSH2_सन्देशः_DEBUG, SSH2_सन्देशः_SERVICE_ACCEPT, SSH2_सन्देशः_EXT_INFO,
	SSH2_सन्देशः_USERAUTH_FAILURE, SSH2_सन्देशः_USERAUTH_SUCCESS,
	SSH2_सन्देशः_USERAUTH_BANNER, SSH2_सन्देशः_USERAUTH_INFO_REQUEST,
	SSH2_सन्देशः_USERAUTH_PK_OK, SSH2_सन्देशः_USERAUTH_PASSWD_CHANGEREQ,
};

शून्य
fuzz_one_सन्देशः(ध्रुव uint8_t *दत्त, आकार_t आकार)
{
	यदि (init_once() != 0)
		प्रत्यागम;
	यदि (आकार > 65000)
		प्रत्यागम;

	uint8_t selector = आकार > 0 ? दत्त[0] : 0;
	ध्रुव uint8_t *payload = आकार > 0 ? दत्त + 1 : रिक्त;
	आकार_t plen = आकार > 0 ? आकार - 1 : 0;

	uint8_t सन्देशः_type = k_सन्देशः_types[selector %
	    (परिमाण(k_सन्देशः_types) / परिमाण(k_सन्देशः_types[0]))];

	fuzz_reset_authctxt(g_client);

	अन्तर्_fuzz = 1;
	यदि (setjmp(fuzz_env) == 0) {
		आकार_t transferred;
		यदि (ssh_packet_put(g_server, सन्देशः_type, payload, plen) != 0)
			गच्छ समाप्तम्;
		यदि (pump(g_server, g_client, &transferred) != 0)
			गच्छ समाप्तम्;
		(शून्य)ssh_dispatch_सततम्(g_client, DISPATCH_NONBLOCK, रिक्त);
	समाप्तम्:
		;
	}
	अन्तर्_fuzz = 0;
}
