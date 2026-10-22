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

#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "readconf.h"

Options options;
പൂർണ്ണസംഖ്യ debug_flag = 0;

ഘടന ssh;

പൂർണ്ണസംഖ്യ
__wrap_ssh_packet_write_wait(ഘടന ssh *ssh)
{
	(ശൂന്യം)ssh;
	തിരികെ 0;
}

അക്ഷരം *
__wrap_read_passphrase(സ്ഥിരം അക്ഷരം *prompt, പൂർണ്ണസംഖ്യ flags)
{
	(ശൂന്യം)prompt;
	(ശൂന്യം)flags;
	തിരികെ strdup("fuzz");
}

#അന്തര്ഭാവ "../../../sshconnect2.c"
#അന്തര്ഭാവ "fixed-keys.h"

സ്ഥിതം jmp_buf fuzz_env;
സ്ഥിതം അസ്ഥിര പൂർണ്ണസംഖ്യ in_fuzz = 0;

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

സ്ഥിതം ഘടന sshkey *
load_private(സ്ഥിരം അക്ഷരം *str)
{
	ഘടന sshbuf *b = sshbuf_from(str, strlen(str));
	ഘടന sshkey *k = ശൂന്യ;
	എങ്കിൽ (b == ശൂന്യ || sshkey_parse_private_fileblob(b, "", &k, ശൂന്യ) != 0)
		abort();
	sshbuf_free(b);
	തിരികെ k;
}

സ്ഥിതം ഘടന sshkey *
load_public(സ്ഥിരം അക്ഷരം *str)
{
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *k = sshkey_new(താക്കോൽ_UNSPEC);
	എങ്കിൽ (k == ശൂന്യ)
		abort();
	tmp = cp = strdup(str);
	എങ്കിൽ (sshkey_read(k, &cp) != 0)
		abort();
	സ്വതന്ത്രം(tmp);
	തിരികെ k;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pump(ഘടന ssh *from, ഘടന ssh *to, size_t *transferred)
{
	സ്ഥിരം u_char *buf;
	size_t len;
	u_char type;
	പൂർണ്ണസംഖ്യ r;
	*transferred = 0;
	എങ്കിൽ ((r = ssh_packet_next(from, &type)) != 0)
		തിരികെ r;
	buf = ssh_output_ptr(from, &len);
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ ((r = ssh_നിവേശം_append(to, buf, len)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = ssh_output_consume(from, len)) != 0)
		തിരികെ r;
	*transferred = len;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
run_kex(ഘടന ssh *client, ഘടന ssh *server)
{
	പൂർണ്ണസംഖ്യ r;
	size_t cn, sn;
	വേണ്ടി (പൂർണ്ണസംഖ്യ i = 0; i < 100; i++) {
		എങ്കിൽ ((r = pump(server, client, &sn)) != 0) തിരികെ r;
		എങ്കിൽ ((r = pump(client, server, &cn)) != 0) തിരികെ r;
		എങ്കിൽ (server->kex->done && client->kex->done)
			തിരികെ 0;
		എങ്കിൽ (cn == 0 && sn == 0)
			തിരികെ SSH_ERR_PROTOCOL_ERROR;
	}
	തിരികെ SSH_ERR_PROTOCOL_ERROR;
}

സ്ഥിതം Sensitive g_sensitive = { ശൂന്യ, 0 };
സ്ഥിതം Authctxt g_authctxt;
സ്ഥിതം ഘടന ssh *g_client = ശൂന്യ;
സ്ഥിതം ഘടന ssh *g_server = ശൂന്യ;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_init = 0;

സ്ഥിതം ശൂന്യം
fuzz_reset_authctxt(ഘടന ssh *ssh)
{
	സ്വതന്ത്രം(g_authctxt.authlist);
	g_authctxt.authlist = ശൂന്യ;
	എങ്കിൽ (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, വലുപ്പം(g_authctxt));
	g_authctxt.server_user = (അക്ഷരം *)"fuzz";
	g_authctxt.local_user = (അക്ഷരം *)"fuzz";
	g_authctxt.host = (അക്ഷരം *)"127.0.0.1";
	g_authctxt.service = (അക്ഷരം *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = ശൂന്യ;
	g_authctxt.methoddata = ശൂന്യ;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = ശൂന്യ;
	g_authctxt.oktypes = ശൂന്യ;
	g_authctxt.ktypes = ശൂന്യ;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.താക്കോലുകൾ);
	ssh->authctxt = &g_authctxt;
}

സ്ഥിതം ശൂന്യം
fuzz_setup(ഘടന ssh *ssh)
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
	options.സംഖ്യ_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(ശൂന്യം)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, kex_നിവേശം_ext_info);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_SERVICE_ACCEPT, &നിവേശം_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_SUCCESS, &നിവേശം_userauth_success);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_FAILURE, &നിവേശം_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_BANNER, &നിവേശം_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_INFO_REQUEST, &നിവേശം_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_PK_OK, &നിവേശം_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_PASSWD_CHANGEREQ, &നിവേശം_userauth_passwd_changereq);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
init_once(ശൂന്യം)
{
	എങ്കിൽ (g_init)
		തിരികെ 0;
	സൂചന(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ഘടന sshkey *priv = load_private(PRIV_ED25519);
	ഘടന sshkey *pub = load_public(PUB_ED25519);
	അക്ഷരം *keyname = xstrdup(sshkey_ssh_name(priv));

	സ്ഥിരം അക്ഷരം *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *proposal[PROPOSAL_MAX] = { 0 };
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		സ്ഥിരം അക്ഷരം *p = defaults[i];
		എങ്കിൽ (i == PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS)
			p = keyname;
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ഘടന kex_params kp;
	memcpy(kp.proposal, proposal, വലുപ്പം(proposal));

	എങ്കിൽ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		തിരികെ -1;
	എങ്കിൽ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		തിരികെ -1;
	എങ്കിൽ (run_kex(g_client, g_server) != 0)
		തിരികെ -1;

	fuzz_setup(g_client);

	സ്വതന്ത്രം(keyname);
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(proposal[i]);
	g_init = 1;
	തിരികെ 0;
}

സ്ഥിതം സ്ഥിരം uint8_t k_സന്ദേശം_types[] = {
	SSH2_സന്ദേശം_DISCONNECT, SSH2_സന്ദേശം_IGNORE, SSH2_സന്ദേശം_UNIMPLEMENTED,
	SSH2_സന്ദേശം_DEBUG, SSH2_സന്ദേശം_SERVICE_ACCEPT, SSH2_സന്ദേശം_EXT_INFO,
	SSH2_സന്ദേശം_USERAUTH_FAILURE, SSH2_സന്ദേശം_USERAUTH_SUCCESS,
	SSH2_സന്ദേശം_USERAUTH_BANNER, SSH2_സന്ദേശം_USERAUTH_INFO_REQUEST,
	SSH2_സന്ദേശം_USERAUTH_PK_OK, SSH2_സന്ദേശം_USERAUTH_PASSWD_CHANGEREQ,
};

ശൂന്യം
fuzz_one_message(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (init_once() != 0)
		തിരികെ;
	എങ്കിൽ (size > 65000)
		തിരികെ;

	uint8_t selector = size > 0 ? data[0] : 0;
	സ്ഥിരം uint8_t *payload = size > 0 ? data + 1 : ശൂന്യ;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t സന്ദേശം_type = k_സന്ദേശം_types[selector %
	    (വലുപ്പം(k_സന്ദേശം_types) / വലുപ്പം(k_സന്ദേശം_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	എങ്കിൽ (setjmp(fuzz_env) == 0) {
		size_t transferred;
		എങ്കിൽ (ssh_packet_put(g_server, സന്ദേശം_type, payload, plen) != 0)
			പോകുക done;
		എങ്കിൽ (pump(g_server, g_client, &transferred) != 0)
			പോകുക done;
		(ശൂന്യം)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, ശൂന്യ);
	done:
		;
	}
	in_fuzz = 0;
}
