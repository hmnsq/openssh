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

#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "readconf.h"

Options options;
પૂર્ણાંક debug_flag = 0;

સંરચના ssh;

પૂર્ણાંક
__wrap_ssh_packet_write_wait(સંરચના ssh *ssh)
{
	(શૂન્ય)ssh;
	પાછા 0;
}

અક્ષર *
__wrap_read_passphrase(અચલ અક્ષર *prompt, પૂર્ણાંક flags)
{
	(શૂન્ય)prompt;
	(શૂન્ય)flags;
	પાછા strdup("fuzz");
}

#અન્તર્ભાવ "../../../sshconnect2.c"
#અન્તર્ભાવ "fixed-keys.h"

સ્થિર jmp_buf fuzz_env;
સ્થિર અસ્થિર પૂર્ણાંક in_fuzz = 0;

શૂન્ય
cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

સ્થિર સંરચના sshkey *
load_private(અચલ અક્ષર *str)
{
	સંરચના sshbuf *b = sshbuf_from(str, strlen(str));
	સંરચના sshkey *k = ખાલી;
	જો (b == ખાલી || sshkey_parse_private_fileblob(b, "", &k, ખાલી) != 0)
		abort();
	sshbuf_free(b);
	પાછા k;
}

સ્થિર સંરચના sshkey *
load_public(અચલ અક્ષર *str)
{
	અક્ષર *tmp, *cp;
	સંરચના sshkey *k = sshkey_new(ચાવી_UNSPEC);
	જો (k == ખાલી)
		abort();
	tmp = cp = strdup(str);
	જો (sshkey_read(k, &cp) != 0)
		abort();
	મુક્ત(tmp);
	પાછા k;
}

સ્થિર પૂર્ણાંક
pump(સંરચના ssh *from, સંરચના ssh *to, size_t *transferred)
{
	અચલ u_char *buf;
	size_t len;
	u_char type;
	પૂર્ણાંક r;
	*transferred = 0;
	જો ((r = ssh_packet_next(from, &type)) != 0)
		પાછા r;
	buf = ssh_output_ptr(from, &len);
	જો (len == 0)
		પાછા 0;
	જો ((r = ssh_આગત_append(to, buf, len)) != 0)
		પાછા r;
	જો ((r = ssh_output_consume(from, len)) != 0)
		પાછા r;
	*transferred = len;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
run_kex(સંરચના ssh *client, સંરચના ssh *server)
{
	પૂર્ણાંક r;
	size_t cn, sn;
	માટે (પૂર્ણાંક i = 0; i < 100; i++) {
		જો ((r = pump(server, client, &sn)) != 0) પાછા r;
		જો ((r = pump(client, server, &cn)) != 0) પાછા r;
		જો (server->kex->done && client->kex->done)
			પાછા 0;
		જો (cn == 0 && sn == 0)
			પાછા SSH_ERR_PROTOCOL_ERROR;
	}
	પાછા SSH_ERR_PROTOCOL_ERROR;
}

સ્થિર Sensitive g_sensitive = { ખાલી, 0 };
સ્થિર Authctxt g_authctxt;
સ્થિર સંરચના ssh *g_client = ખાલી;
સ્થિર સંરચના ssh *g_server = ખાલી;
સ્થિર પૂર્ણાંક g_init = 0;

સ્થિર શૂન્ય
fuzz_reset_authctxt(સંરચના ssh *ssh)
{
	મુક્ત(g_authctxt.authlist);
	g_authctxt.authlist = ખાલી;
	જો (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, કદ(g_authctxt));
	g_authctxt.server_user = (અક્ષર *)"fuzz";
	g_authctxt.local_user = (અક્ષર *)"fuzz";
	g_authctxt.host = (અક્ષર *)"127.0.0.1";
	g_authctxt.service = (અક્ષર *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = ખાલી;
	g_authctxt.methoddata = ખાલી;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = ખાલી;
	g_authctxt.oktypes = ખાલી;
	g_authctxt.ktypes = ખાલી;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.ચાવીઓ);
	ssh->authctxt = &g_authctxt;
}

સ્થિર શૂન્ય
fuzz_setup(સંરચના ssh *ssh)
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
	options.સંખ્યા_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(શૂન્ય)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, kex_આગત_ext_info);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_SERVICE_ACCEPT, &આગત_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_SUCCESS, &આગત_userauth_success);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_FAILURE, &આગત_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_BANNER, &આગત_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_INFO_REQUEST, &આગત_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_PK_OK, &આગત_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_USERAUTH_PASSWD_CHANGEREQ, &આગત_userauth_passwd_changereq);
}

સ્થિર પૂર્ણાંક
init_once(શૂન્ય)
{
	જો (g_init)
		પાછા 0;
	સંકેત(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	સંરચના sshkey *priv = load_private(PRIV_ED25519);
	સંરચના sshkey *pub = load_public(PUB_ED25519);
	અક્ષર *keyname = xstrdup(sshkey_ssh_name(priv));

	અચલ અક્ષર *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *proposal[PROPOSAL_MAX] = { 0 };
	પૂર્ણાંક i;
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		અચલ અક્ષર *p = defaults[i];
		જો (i == PROPOSAL_SERVER_HOST_ચાવી_ALGS)
			p = keyname;
		નહીંતર જો (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		નહીંતર જો (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		નહીંતર જો (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	સંરચના kex_params kp;
	memcpy(kp.proposal, proposal, કદ(proposal));

	જો (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		પાછા -1;
	જો (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		પાછા -1;
	જો (run_kex(g_client, g_server) != 0)
		પાછા -1;

	fuzz_setup(g_client);

	મુક્ત(keyname);
	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(proposal[i]);
	g_init = 1;
	પાછા 0;
}

સ્થિર અચલ uint8_t k_સંદેશ_types[] = {
	SSH2_સંદેશ_DISCONNECT, SSH2_સંદેશ_IGNORE, SSH2_સંદેશ_UNIMPLEMENTED,
	SSH2_સંદેશ_DEBUG, SSH2_સંદેશ_SERVICE_ACCEPT, SSH2_સંદેશ_EXT_INFO,
	SSH2_સંદેશ_USERAUTH_FAILURE, SSH2_સંદેશ_USERAUTH_SUCCESS,
	SSH2_સંદેશ_USERAUTH_BANNER, SSH2_સંદેશ_USERAUTH_INFO_REQUEST,
	SSH2_સંદેશ_USERAUTH_PK_OK, SSH2_સંદેશ_USERAUTH_PASSWD_CHANGEREQ,
};

શૂન્ય
fuzz_one_message(અચલ uint8_t *data, size_t size)
{
	જો (init_once() != 0)
		પાછા;
	જો (size > 65000)
		પાછા;

	uint8_t selector = size > 0 ? data[0] : 0;
	અચલ uint8_t *payload = size > 0 ? data + 1 : ખાલી;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t સંદેશ_type = k_સંદેશ_types[selector %
	    (કદ(k_સંદેશ_types) / કદ(k_સંદેશ_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	જો (setjmp(fuzz_env) == 0) {
		size_t transferred;
		જો (ssh_packet_put(g_server, સંદેશ_type, payload, plen) != 0)
			જાઓ done;
		જો (pump(g_server, g_client, &transferred) != 0)
			જાઓ done;
		(શૂન્ય)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, ખાલી);
	done:
		;
	}
	in_fuzz = 0;
}
