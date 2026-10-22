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

#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"

Options options;
ಪೂರ್ಣಾಙ್ಕ debug_flag = 0;

ಸಂರಚನಾ ssh;

ಪೂರ್ಣಾಙ್ಕ
__wrap_ssh_packet_write_wait(ಸಂರಚನಾ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ವರ್ಣ *
__wrap_read_passphrase(ಧ್ರುವ ವರ್ಣ *prompt, ಪೂರ್ಣಾಙ್ಕ flags)
{
	(ಶೂನ್ಯ)prompt;
	(ಶೂನ್ಯ)flags;
	ಪ್ರತ್ಯಾಗಮ strdup("fuzz");
}

#ಅನ್ತರ್ಭಾವ "../../../sshconnect2.c"
#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಚಞ್ಚಲ ಪೂರ್ಣಾಙ್ಕ in_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ code)
{
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_private(ಧ್ರುವ ವರ್ಣ *str)
{
	ಸಂರಚನಾ sshbuf *b = sshbuf_from(str, strlen(str));
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಯದಿ (b == ರಿಕ್ತ || sshkey_parse_private_fileblob(b, "", &k, ರಿಕ್ತ) != 0)
		abort();
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_public(ಧ್ರುವ ವರ್ಣ *str)
{
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಯದಿ (k == ರಿಕ್ತ)
		abort();
	tmp = cp = strdup(str);
	ಯದಿ (sshkey_read(k, &cp) != 0)
		abort();
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pump(ಸಂರಚನಾ ssh *from, ಸಂರಚನಾ ssh *to, size_t *transferred)
{
	ಧ್ರುವ u_char *buf;
	size_t len;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;
	*transferred = 0;
	ಯದಿ ((r = ssh_packet_next(from, &type)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	buf = ssh_output_ptr(from, &len);
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = ssh_ಒಳಹರಿವು_append(to, buf, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = ssh_output_consume(from, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	*transferred = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
run_kex(ಸಂರಚನಾ ssh *client, ಸಂರಚನಾ ssh *server)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t cn, sn;
	ಪ್ರತಿ (ಪೂರ್ಣಾಙ್ಕ i = 0; i < 100; i++) {
		ಯದಿ ((r = pump(server, client, &sn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((r = pump(client, server, &cn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (server->kex->done && client->kex->done)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ (cn == 0 && sn == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
}

ಸ್ಥಿರ Sensitive g_sensitive = { ರಿಕ್ತ, 0 };
ಸ್ಥಿರ Authctxt g_authctxt;
ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_client = ರಿಕ್ತ;
ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_server = ರಿಕ್ತ;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_init = 0;

ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_reset_authctxt(ಸಂರಚನಾ ssh *ssh)
{
	ಮುಕ್ತ(g_authctxt.authlist);
	g_authctxt.authlist = ರಿಕ್ತ;
	ಯದಿ (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, ಪರಿಮಾಣ(g_authctxt));
	g_authctxt.server_user = (ವರ್ಣ *)"fuzz";
	g_authctxt.local_user = (ವರ್ಣ *)"fuzz";
	g_authctxt.host = (ವರ್ಣ *)"127.0.0.1";
	g_authctxt.service = (ವರ್ಣ *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = ರಿಕ್ತ;
	g_authctxt.methoddata = ರಿಕ್ತ;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = ರಿಕ್ತ;
	g_authctxt.oktypes = ರಿಕ್ತ;
	g_authctxt.ktypes = ರಿಕ್ತ;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.ಕೀಲಿಗಳು);
	ssh->authctxt = &g_authctxt;
}

ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_setup(ಸಂರಚನಾ ssh *ssh)
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
	options.ಸಂಖ್ಯೆ_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(ಶೂನ್ಯ)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT, &ಒಳಹರಿವು_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS, &ಒಳಹರಿವು_userauth_success);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_FAILURE, &ಒಳಹರಿವು_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_BANNER, &ಒಳಹರಿವು_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST, &ಒಳಹರಿವು_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PK_OK, &ಒಳಹರಿವು_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ, &ಒಳಹರಿವು_userauth_passwd_changereq);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
init_once(ಶೂನ್ಯ)
{
	ಯದಿ (g_init)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸಙ್ಕೇತ(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ಸಂರಚನಾ sshkey *priv = load_private(PRIV_ED25519);
	ಸಂರಚನಾ sshkey *pub = load_public(PUB_ED25519);
	ವರ್ಣ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಧ್ರುವ ವರ್ಣ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಧ್ರುವ ವರ್ಣ *p = defaults[i];
		ಯದಿ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ಸಂರಚನಾ kex_params kp;
	memcpy(kp.proposal, proposal, ಪರಿಮಾಣ(proposal));

	ಯದಿ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (run_kex(g_client, g_server) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	fuzz_setup(g_client);

	ಮುಕ್ತ(keyname);
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(proposal[i]);
	g_init = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಧ್ರುವ uint8_t k_ಸಂದೇಶ_types[] = {
	SSH2_ಸಂದೇಶ_DISCONNECT, SSH2_ಸಂದೇಶ_IGNORE, SSH2_ಸಂದೇಶ_UNIMPLEMENTED,
	SSH2_ಸಂದೇಶ_DEBUG, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT, SSH2_ಸಂದೇಶ_EXT_INFO,
	SSH2_ಸಂದೇಶ_USERAUTH_FAILURE, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS,
	SSH2_ಸಂದೇಶ_USERAUTH_BANNER, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST,
	SSH2_ಸಂದೇಶ_USERAUTH_PK_OK, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ,
};

ಶೂನ್ಯ
fuzz_one_message(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (init_once() != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (size > 65000)
		ಪ್ರತ್ಯಾಗಮ;

	uint8_t selector = size > 0 ? data[0] : 0;
	ಧ್ರುವ uint8_t *payload = size > 0 ? data + 1 : ರಿಕ್ತ;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t ಸಂದೇಶ_type = k_ಸಂದೇಶ_types[selector %
	    (ಪರಿಮಾಣ(k_ಸಂದೇಶ_types) / ಪರಿಮಾಣ(k_ಸಂದೇಶ_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	ಯದಿ (setjmp(fuzz_env) == 0) {
		size_t transferred;
		ಯದಿ (ssh_packet_put(g_server, ಸಂದೇಶ_type, payload, plen) != 0)
			ಗಚ್ಛ done;
		ಯದಿ (pump(g_server, g_client, &transferred) != 0)
			ಗಚ್ಛ done;
		(ಶೂನ್ಯ)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, ರಿಕ್ತ);
	done:
		;
	}
	in_fuzz = 0;
}
