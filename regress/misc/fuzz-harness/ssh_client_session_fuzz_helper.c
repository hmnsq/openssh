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
ಪೂರ್ಣಾಂಕ debug_flag = 0;

ರಚನೆ ssh;

ಪೂರ್ಣಾಂಕ
__wrap_ssh_packet_write_wait(ರಚನೆ ssh *ssh)
{
	(ಶೂನ್ಯ)ssh;
	ಹಿಂತಿರುಗಿ 0;
}

ಅಕ್ಷರ *
__wrap_read_passphrase(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt, ಪೂರ್ಣಾಂಕ flags)
{
	(ಶೂನ್ಯ)prompt;
	(ಶೂನ್ಯ)flags;
	ಹಿಂತಿರುಗಿ strdup("fuzz");
}

#ಅನ್ತರ್ಭಾವ "../../../sshconnect2.c"
#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಅಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳ_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ ಸಂಕೇತ_2)
{
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, ಸಂಕೇತ_2 ? ಸಂಕೇತ_2 : 1);
	_exit(ಸಂಕೇತ_2);
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ರಚನೆ sshbuf *b = sshbuf_from(str, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(str));
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಆದರೆ (b == ಖಾಲಿ || sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &k, ಖಾಲಿ) != 0)
		abort();
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಆದರೆ (k == ಖಾಲಿ)
		abort();
	tmp = cp = strdup(str);
	ಆದರೆ (sshkey_read(k, &cp) != 0)
		abort();
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pump(ರಚನೆ ssh *from, ರಚನೆ ssh *ಗಮ್ಯ, ಗಾತ್ರ_t *transferred)
{
	ಸ್ಥಿರಾಂಕ u_char *buf;
	ಗಾತ್ರ_t len;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;
	*transferred = 0;
	ಆದರೆ ((r = ssh_packet_ಮುಂದಿನ(from, &type)) != 0)
		ಹಿಂತಿರುಗಿ r;
	buf = ssh_output_ptr(from, &len);
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = ssh_ಒಳಹರಿವು_append(ಗಮ್ಯ, buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = ssh_output_consume(from, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	*transferred = len;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಸತತ_kex(ರಚನೆ ssh *client, ರಚನೆ ssh *server)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t cn, sn;
	ಗಾಗಿ (ಪೂರ್ಣಾಂಕ i = 0; i < 100; i++) {
		ಆದರೆ ((r = pump(server, client, &sn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((r = pump(client, server, &cn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (server->kex->ಮುಗಿದ && client->kex->ಮುಗಿದ)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (cn == 0 && sn == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
}

ಸ್ಥಿರ Sensitive g_sensitive = { ಖಾಲಿ, 0 };
ಸ್ಥಿರ Authctxt g_authctxt;
ಸ್ಥಿರ ರಚನೆ ssh *g_client = ಖಾಲಿ;
ಸ್ಥಿರ ರಚನೆ ssh *g_server = ಖಾಲಿ;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_init = 0;

ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_reset_authctxt(ರಚನೆ ssh *ssh)
{
	ಬಿಡುಗಡೆ(g_authctxt.authlist);
	g_authctxt.authlist = ಖಾಲಿ;
	ಆದರೆ (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, ಗಾತ್ರ(g_authctxt));
	g_authctxt.server_user = (ಅಕ್ಷರ *)"fuzz";
	g_authctxt.local_user = (ಅಕ್ಷರ *)"fuzz";
	g_authctxt.host = (ಅಕ್ಷರ *)"127.0.0.1";
	g_authctxt.service = (ಅಕ್ಷರ *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.ವಿಧಾನ = authmethod_lookup("none");
	g_authctxt.authlist = ಖಾಲಿ;
	g_authctxt.methoddata = ಖಾಲಿ;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.ಸಕ್ರಿಯ_ktype = ಖಾಲಿ;
	g_authctxt.oktypes = ಖಾಲಿ;
	g_authctxt.ktypes = ಖಾಲಿ;
	g_authctxt.info_req_ನೋಡಿದ = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.ಕೀಲಿಗಳು);
	ssh->authctxt = &g_authctxt;
}

ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_ಸಿದ್ಧತೆ(ರಚನೆ ssh *ssh)
{
	initialize_options(&options);
	options.batch_ಬಹುಲಕ = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.ಸಂಖ್ಯೆ_ದ_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(ಶೂನ್ಯ)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT, &ಒಳಹರಿವು_userauth_service_accept);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS, &ಒಳಹರಿವು_userauth_success);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_FAILURE, &ಒಳಹರಿವು_userauth_failure);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_BANNER, &ಒಳಹರಿವು_userauth_banner);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST, &ಒಳಹರಿವು_userauth_info_req);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PK_OK, &ಒಳಹರಿವು_userauth_pk_ok);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ, &ಒಳಹರಿವು_userauth_passwd_changereq);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
init_once(ಶೂನ್ಯ)
{
	ಆದರೆ (g_init)
		ಹಿಂತಿರುಗಿ 0;
	ಸಂಕೇತ(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ರಚನೆ sshkey *priv = ತುಂಬು_ಖಾಸಗಿ(PRIV_ED25519);
	ರಚನೆ sshkey *pub = ತುಂಬು_ಬಹಿರಂಗ(PUB_ED25519);
	ಅಕ್ಷರ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p = defaults[i];
		ಆದರೆ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ರಚನೆ kex_params kp;
	ಸ್ಮರಣೆ_ನಕಲು(kp.proposal, proposal, ಗಾತ್ರ(proposal));

	ಆದರೆ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ssh_ಕೂಡಿಸು_hostkey(g_server, priv) != 0 ||
	    ssh_ಕೂಡಿಸು_hostkey(g_client, pub) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ಸತತ_kex(g_client, g_server) != 0)
		ಹಿಂತಿರುಗಿ -1;

	fuzz_ಸಿದ್ಧತೆ(g_client);

	ಬಿಡುಗಡೆ(keyname);
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(proposal[i]);
	g_init = 1;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ uint8_t k_ಸಂದೇಶ_types[] = {
	SSH2_ಸಂದೇಶ_DISCONNECT, SSH2_ಸಂದೇಶ_IGNORE, SSH2_ಸಂದೇಶ_UNIMPLEMENTED,
	SSH2_ಸಂದೇಶ_DEBUG, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT, SSH2_ಸಂದೇಶ_EXT_INFO,
	SSH2_ಸಂದೇಶ_USERAUTH_FAILURE, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS,
	SSH2_ಸಂದೇಶ_USERAUTH_BANNER, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST,
	SSH2_ಸಂದೇಶ_USERAUTH_PK_OK, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ,
};

ಶೂನ್ಯ
fuzz_one_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (init_once() != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಗಾತ್ರ_2 > 65000)
		ಹಿಂತಿರುಗಿ;

	uint8_t selector = ಗಾತ್ರ_2 > 0 ? ದತ್ತಾಂಶ[0] : 0;
	ಸ್ಥಿರಾಂಕ uint8_t *payload = ಗಾತ್ರ_2 > 0 ? ದತ್ತಾಂಶ + 1 : ಖಾಲಿ;
	ಗಾತ್ರ_t plen = ಗಾತ್ರ_2 > 0 ? ಗಾತ್ರ_2 - 1 : 0;

	uint8_t ಸಂದೇಶ_type = k_ಸಂದೇಶ_types[selector %
	    (ಗಾತ್ರ(k_ಸಂದೇಶ_types) / ಗಾತ್ರ(k_ಸಂದೇಶ_types[0]))];

	fuzz_reset_authctxt(g_client);

	ಒಳ_fuzz = 1;
	ಆದರೆ (setjmp(fuzz_env) == 0) {
		ಗಾತ್ರ_t transferred;
		ಆದರೆ (ssh_packet_put(g_server, ಸಂದೇಶ_type, payload, plen) != 0)
			ಹೋಗು ಮುಗಿದ;
		ಆದರೆ (pump(g_server, g_client, &transferred) != 0)
			ಹೋಗು ಮುಗಿದ;
		(ಶೂನ್ಯ)ssh_dispatch_ಸತತ(g_client, DISPATCH_NONBLOCK, ಖಾಲಿ);
	ಮುಗಿದ:
		;
	}
	ಒಳ_fuzz = 0;
}
