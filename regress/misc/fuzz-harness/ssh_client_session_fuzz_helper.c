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

#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"

Options options;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag = 0;

ସଂରଚନା ssh;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_ssh_packet_write_wait(ସଂରଚନା ssh *ssh)
{
	(ଶୂନ୍ୟ)ssh;
	ଫେରନ୍ତୁ 0;
}

ଅକ୍ଷର *
__wrap_read_passphrase(ଅଚଳ ଅକ୍ଷର *prompt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	(ଶୂନ୍ୟ)prompt;
	(ଶୂନ୍ୟ)flags;
	ଫେରନ୍ତୁ strdup("fuzz");
}

#ଅନ୍ତର୍ଭାଵ "../../../sshconnect2.c"
#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"

ସ୍ଥିର jmp_buf fuzz_env;
ସ୍ଥିର ଅସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fuzz = 0;

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_private(ଅଚଳ ଅକ୍ଷର *str)
{
	ସଂରଚନା sshbuf *b = sshbuf_from(str, strlen(str));
	ସଂରଚନା sshkey *k = ଖାଲି;
	ଯଦି (b == ଖାଲି || sshkey_parse_private_fileblob(b, "", &k, ଖାଲି) != 0)
		abort();
	sshbuf_free(b);
	ଫେରନ୍ତୁ k;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_public(ଅଚଳ ଅକ୍ଷର *str)
{
	ଅକ୍ଷର *tmp, *cp;
	ସଂରଚନା sshkey *k = sshkey_new(ଚାବି_UNSPEC);
	ଯଦି (k == ଖାଲି)
		abort();
	tmp = cp = strdup(str);
	ଯଦି (sshkey_read(k, &cp) != 0)
		abort();
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ k;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pump(ସଂରଚନା ssh *from, ସଂରଚନା ssh *to, size_t *transferred)
{
	ଅଚଳ u_char *buf;
	size_t len;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	*transferred = 0;
	ଯଦି ((r = ssh_packet_next(from, &type)) != 0)
		ଫେରନ୍ତୁ r;
	buf = ssh_output_ptr(from, &len);
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((r = ssh_ନିବେଶ_append(to, buf, len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = ssh_output_consume(from, len)) != 0)
		ଫେରନ୍ତୁ r;
	*transferred = len;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
run_kex(ସଂରଚନା ssh *client, ସଂରଚନା ssh *server)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t cn, sn;
	ପାଇଁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା i = 0; i < 100; i++) {
		ଯଦି ((r = pump(server, client, &sn)) != 0) ଫେରନ୍ତୁ r;
		ଯଦି ((r = pump(client, server, &cn)) != 0) ଫେରନ୍ତୁ r;
		ଯଦି (server->kex->done && client->kex->done)
			ଫେରନ୍ତୁ 0;
		ଯଦି (cn == 0 && sn == 0)
			ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
	}
	ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
}

ସ୍ଥିର Sensitive g_sensitive = { ଖାଲି, 0 };
ସ୍ଥିର Authctxt g_authctxt;
ସ୍ଥିର ସଂରଚନା ssh *g_client = ଖାଲି;
ସ୍ଥିର ସଂରଚନା ssh *g_server = ଖାଲି;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_init = 0;

ସ୍ଥିର ଶୂନ୍ୟ
fuzz_reset_authctxt(ସଂରଚନା ssh *ssh)
{
	ମୁକ୍ତ(g_authctxt.authlist);
	g_authctxt.authlist = ଖାଲି;
	ଯଦି (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, ଆକାର(g_authctxt));
	g_authctxt.server_user = (ଅକ୍ଷର *)"fuzz";
	g_authctxt.local_user = (ଅକ୍ଷର *)"fuzz";
	g_authctxt.host = (ଅକ୍ଷର *)"127.0.0.1";
	g_authctxt.service = (ଅକ୍ଷର *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = ଖାଲି;
	g_authctxt.methoddata = ଖାଲି;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = ଖାଲି;
	g_authctxt.oktypes = ଖାଲି;
	g_authctxt.ktypes = ଖାଲି;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.ଚାବିଗୁଡ଼ିକ);
	ssh->authctxt = &g_authctxt;
}

ସ୍ଥିର ଶୂନ୍ୟ
fuzz_setup(ସଂରଚନା ssh *ssh)
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
	options.ସଂଖ୍ୟା_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(ଶୂନ୍ୟ)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_EXT_INFO, kex_ନିବେଶ_ext_info);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_SERVICE_ACCEPT, &ନିବେଶ_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_SUCCESS, &ନିବେଶ_userauth_success);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_FAILURE, &ନିବେଶ_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_BANNER, &ନିବେଶ_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_REQUEST, &ନିବେଶ_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_PK_OK, &ନିବେଶ_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_ସନ୍ଦେଶ_USERAUTH_PASSWD_CHANGEREQ, &ନିବେଶ_userauth_passwd_changereq);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
init_once(ଶୂନ୍ୟ)
{
	ଯଦି (g_init)
		ଫେରନ୍ତୁ 0;
	ସଙ୍କେତ(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ସଂରଚନା sshkey *priv = load_private(PRIV_ED25519);
	ସଂରଚନା sshkey *pub = load_public(PUB_ED25519);
	ଅକ୍ଷର *keyname = xstrdup(sshkey_ssh_name(priv));

	ଅଚଳ ଅକ୍ଷର *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ଅକ୍ଷର *proposal[PROPOSAL_MAX] = { 0 };
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ଅଚଳ ଅକ୍ଷର *p = defaults[i];
		ଯଦି (i == PROPOSAL_SERVER_HOST_ଚାବି_ALGS)
			p = keyname;
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ସଂରଚନା kex_params kp;
	memcpy(kp.proposal, proposal, ଆକାର(proposal));

	ଯଦି (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (run_kex(g_client, g_server) != 0)
		ଫେରନ୍ତୁ -1;

	fuzz_setup(g_client);

	ମୁକ୍ତ(keyname);
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(proposal[i]);
	g_init = 1;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଅଚଳ uint8_t k_ସନ୍ଦେଶ_types[] = {
	SSH2_ସନ୍ଦେଶ_DISCONNECT, SSH2_ସନ୍ଦେଶ_IGNORE, SSH2_ସନ୍ଦେଶ_UNIMPLEMENTED,
	SSH2_ସନ୍ଦେଶ_DEBUG, SSH2_ସନ୍ଦେଶ_SERVICE_ACCEPT, SSH2_ସନ୍ଦେଶ_EXT_INFO,
	SSH2_ସନ୍ଦେଶ_USERAUTH_FAILURE, SSH2_ସନ୍ଦେଶ_USERAUTH_SUCCESS,
	SSH2_ସନ୍ଦେଶ_USERAUTH_BANNER, SSH2_ସନ୍ଦେଶ_USERAUTH_INFO_REQUEST,
	SSH2_ସନ୍ଦେଶ_USERAUTH_PK_OK, SSH2_ସନ୍ଦେଶ_USERAUTH_PASSWD_CHANGEREQ,
};

ଶୂନ୍ୟ
fuzz_one_message(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (init_once() != 0)
		ଫେରନ୍ତୁ;
	ଯଦି (size > 65000)
		ଫେରନ୍ତୁ;

	uint8_t selector = size > 0 ? data[0] : 0;
	ଅଚଳ uint8_t *payload = size > 0 ? data + 1 : ଖାଲି;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t ସନ୍ଦେଶ_type = k_ସନ୍ଦେଶ_types[selector %
	    (ଆକାର(k_ସନ୍ଦେଶ_types) / ଆକାର(k_ସନ୍ଦେଶ_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	ଯଦି (setjmp(fuzz_env) == 0) {
		size_t transferred;
		ଯଦି (ssh_packet_put(g_server, ସନ୍ଦେଶ_type, payload, plen) != 0)
			ଯାଅ done;
		ଯଦି (pump(g_server, g_client, &transferred) != 0)
			ଯାଅ done;
		(ଶୂନ୍ୟ)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, ଖାଲି);
	done:
		;
	}
	in_fuzz = 0;
}
