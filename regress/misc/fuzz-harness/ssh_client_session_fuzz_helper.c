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

#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "readconf.h"

Options options;
முழு debug_flag = 0;

கட்டமைப்பு ssh;

முழு
__wrap_ssh_packet_write_wait(கட்டமைப்பு ssh *ssh)
{
	(வெறுமை)ssh;
	திரும்பு 0;
}

எழுத்து *
__wrap_read_passphrase(மாறிலி எழுத்து *prompt, முழு flags)
{
	(வெறுமை)prompt;
	(வெறுமை)flags;
	திரும்பு strdup("fuzz");
}

#அந்தர்பாவ "../../../sshconnect2.c"
#அந்தர்பாவ "fixed-keys.h"

நிலையான jmp_buf fuzz_env;
நிலையான நிலையற்ற முழு in_fuzz = 0;

வெறுமை
cleanup_exit(முழு code)
{
	எனில் (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

நிலையான கட்டமைப்பு sshkey *
load_private(மாறிலி எழுத்து *str)
{
	கட்டமைப்பு sshbuf *b = sshbuf_from(str, strlen(str));
	கட்டமைப்பு sshkey *k = வெற்று;
	எனில் (b == வெற்று || sshkey_parse_private_fileblob(b, "", &k, வெற்று) != 0)
		abort();
	sshbuf_free(b);
	திரும்பு k;
}

நிலையான கட்டமைப்பு sshkey *
load_public(மாறிலி எழுத்து *str)
{
	எழுத்து *tmp, *cp;
	கட்டமைப்பு sshkey *k = sshkey_new(சாவி_UNSPEC);
	எனில் (k == வெற்று)
		abort();
	tmp = cp = strdup(str);
	எனில் (sshkey_read(k, &cp) != 0)
		abort();
	விடுவி(tmp);
	திரும்பு k;
}

நிலையான முழு
pump(கட்டமைப்பு ssh *from, கட்டமைப்பு ssh *to, size_t *transferred)
{
	மாறிலி u_char *buf;
	size_t len;
	u_char type;
	முழு r;
	*transferred = 0;
	எனில் ((r = ssh_packet_next(from, &type)) != 0)
		திரும்பு r;
	buf = ssh_output_ptr(from, &len);
	எனில் (len == 0)
		திரும்பு 0;
	எனில் ((r = ssh_உள்ளீடு_append(to, buf, len)) != 0)
		திரும்பு r;
	எனில் ((r = ssh_output_consume(from, len)) != 0)
		திரும்பு r;
	*transferred = len;
	திரும்பு 0;
}

நிலையான முழு
run_kex(கட்டமைப்பு ssh *client, கட்டமைப்பு ssh *server)
{
	முழு r;
	size_t cn, sn;
	க்கு (முழு i = 0; i < 100; i++) {
		எனில் ((r = pump(server, client, &sn)) != 0) திரும்பு r;
		எனில் ((r = pump(client, server, &cn)) != 0) திரும்பு r;
		எனில் (server->kex->done && client->kex->done)
			திரும்பு 0;
		எனில் (cn == 0 && sn == 0)
			திரும்பு SSH_ERR_PROTOCOL_ERROR;
	}
	திரும்பு SSH_ERR_PROTOCOL_ERROR;
}

நிலையான Sensitive g_sensitive = { வெற்று, 0 };
நிலையான Authctxt g_authctxt;
நிலையான கட்டமைப்பு ssh *g_client = வெற்று;
நிலையான கட்டமைப்பு ssh *g_server = வெற்று;
நிலையான முழு g_init = 0;

நிலையான வெறுமை
fuzz_reset_authctxt(கட்டமைப்பு ssh *ssh)
{
	விடுவி(g_authctxt.authlist);
	g_authctxt.authlist = வெற்று;
	எனில் (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, அளவு(g_authctxt));
	g_authctxt.server_user = (எழுத்து *)"fuzz";
	g_authctxt.local_user = (எழுத்து *)"fuzz";
	g_authctxt.host = (எழுத்து *)"127.0.0.1";
	g_authctxt.service = (எழுத்து *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = வெற்று;
	g_authctxt.methoddata = வெற்று;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = வெற்று;
	g_authctxt.oktypes = வெற்று;
	g_authctxt.ktypes = வெற்று;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.சாவிகள்);
	ssh->authctxt = &g_authctxt;
}

நிலையான வெறுமை
fuzz_setup(கட்டமைப்பு ssh *ssh)
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
	options.எண்_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(வெறுமை)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_செய்தி_EXT_INFO, kex_உள்ளீடு_ext_info);
	ssh_dispatch_set(ssh, SSH2_செய்தி_SERVICE_ACCEPT, &உள்ளீடு_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_SUCCESS, &உள்ளீடு_userauth_success);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_FAILURE, &உள்ளீடு_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_BANNER, &உள்ளீடு_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_INFO_REQUEST, &உள்ளீடு_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_PK_OK, &உள்ளீடு_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_செய்தி_USERAUTH_PASSWD_CHANGEREQ, &உள்ளீடு_userauth_passwd_changereq);
}

நிலையான முழு
init_once(வெறுமை)
{
	எனில் (g_init)
		திரும்பு 0;
	சமிக்ஞை(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	கட்டமைப்பு sshkey *priv = load_private(PRIV_ED25519);
	கட்டமைப்பு sshkey *pub = load_public(PUB_ED25519);
	எழுத்து *keyname = xstrdup(sshkey_ssh_name(priv));

	மாறிலி எழுத்து *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	எழுத்து *proposal[PROPOSAL_MAX] = { 0 };
	முழு i;
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		மாறிலி எழுத்து *p = defaults[i];
		எனில் (i == PROPOSAL_SERVER_HOST_சாவி_ALGS)
			p = keyname;
		இல்லையெனில் எனில் (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		இல்லையெனில் எனில் (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		இல்லையெனில் எனில் (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	கட்டமைப்பு kex_params kp;
	memcpy(kp.proposal, proposal, அளவு(proposal));

	எனில் (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		திரும்பு -1;
	எனில் (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		திரும்பு -1;
	எனில் (run_kex(g_client, g_server) != 0)
		திரும்பு -1;

	fuzz_setup(g_client);

	விடுவி(keyname);
	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(proposal[i]);
	g_init = 1;
	திரும்பு 0;
}

நிலையான மாறிலி uint8_t k_செய்தி_types[] = {
	SSH2_செய்தி_DISCONNECT, SSH2_செய்தி_IGNORE, SSH2_செய்தி_UNIMPLEMENTED,
	SSH2_செய்தி_DEBUG, SSH2_செய்தி_SERVICE_ACCEPT, SSH2_செய்தி_EXT_INFO,
	SSH2_செய்தி_USERAUTH_FAILURE, SSH2_செய்தி_USERAUTH_SUCCESS,
	SSH2_செய்தி_USERAUTH_BANNER, SSH2_செய்தி_USERAUTH_INFO_REQUEST,
	SSH2_செய்தி_USERAUTH_PK_OK, SSH2_செய்தி_USERAUTH_PASSWD_CHANGEREQ,
};

வெறுமை
fuzz_one_message(மாறிலி uint8_t *data, size_t size)
{
	எனில் (init_once() != 0)
		திரும்பு;
	எனில் (size > 65000)
		திரும்பு;

	uint8_t selector = size > 0 ? data[0] : 0;
	மாறிலி uint8_t *payload = size > 0 ? data + 1 : வெற்று;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t செய்தி_type = k_செய்தி_types[selector %
	    (அளவு(k_செய்தி_types) / அளவு(k_செய்தி_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	எனில் (setjmp(fuzz_env) == 0) {
		size_t transferred;
		எனில் (ssh_packet_put(g_server, செய்தி_type, payload, plen) != 0)
			செல் done;
		எனில் (pump(g_server, g_client, &transferred) != 0)
			செல் done;
		(வெறுமை)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, வெற்று);
	done:
		;
	}
	in_fuzz = 0;
}
