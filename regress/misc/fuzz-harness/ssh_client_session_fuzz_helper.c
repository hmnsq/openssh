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

#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "readconf.h"

Options options;
পূর্ণাঙ্ক debug_flag = 0;

সংরচনা ssh;

পূর্ণাঙ্ক
__wrap_ssh_packet_write_wait(সংরচনা ssh *ssh)
{
	(শূন্য)ssh;
	প্রত্যাগম 0;
}

বর্ণ *
__wrap_read_passphrase(ধ্রুব বর্ণ *prompt, পূর্ণাঙ্ক flags)
{
	(শূন্য)prompt;
	(শূন্য)flags;
	প্রত্যাগম strdup("fuzz");
}

#অন্তর্ভাব "../../../sshconnect2.c"
#অন্তর্ভাব "fixed-keys.h"

স্থির jmp_buf fuzz_env;
স্থির চঞ্চল পূর্ণাঙ্ক in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

স্থির সংরচনা sshkey *
load_private(ধ্রুব বর্ণ *str)
{
	সংরচনা sshbuf *b = sshbuf_from(str, strlen(str));
	সংরচনা sshkey *k = রিক্ত;
	যদি (b == রিক্ত || sshkey_parse_private_fileblob(b, "", &k, রিক্ত) != 0)
		abort();
	sshbuf_free(b);
	প্রত্যাগম k;
}

স্থির সংরচনা sshkey *
load_public(ধ্রুব বর্ণ *str)
{
	বর্ণ *tmp, *cp;
	সংরচনা sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == রিক্ত)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	প্রত্যাগম k;
}

স্থির পূর্ণাঙ্ক
pump(সংরচনা ssh *from, সংরচনা ssh *to, size_t *transferred)
{
	ধ্রুব u_char *buf;
	size_t len;
	u_char type;
	পূর্ণাঙ্ক r;
	*transferred = 0;
	যদি ((r = ssh_packet_next(from, &type)) != 0)
		প্রত্যাগম r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		প্রত্যাগম 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		প্রত্যাগম r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		প্রত্যাগম r;
	*transferred = len;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
run_kex(সংরচনা ssh *client, সংরচনা ssh *server)
{
	পূর্ণাঙ্ক r;
	size_t cn, sn;
	প্রতি (পূর্ণাঙ্ক i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) প্রত্যাগম r;
		যদি ((r = pump(client, server, &cn)) != 0) প্রত্যাগম r;
		যদি (server->kex->done && client->kex->done)
			প্রত্যাগম 0;
		যদি (cn == 0 && sn == 0)
			প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
	}
	প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
}

স্থির Sensitive g_sensitive = { রিক্ত, 0 };
স্থির Authctxt g_authctxt;
স্থির সংরচনা ssh *g_client = রিক্ত;
স্থির সংরচনা ssh *g_server = রিক্ত;
স্থির পূর্ণাঙ্ক g_init = 0;

স্থির শূন্য
fuzz_reset_authctxt(সংরচনা ssh *ssh)
{
	মুক্ত(g_authctxt.authlist);
	g_authctxt.authlist = রিক্ত;
	যদি (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, পরিমাণ(g_authctxt));
	g_authctxt.server_user = (বর্ণ *)"fuzz";
	g_authctxt.local_user = (বর্ণ *)"fuzz";
	g_authctxt.host = (বর্ণ *)"127.0.0.1";
	g_authctxt.service = (বর্ণ *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = রিক্ত;
	g_authctxt.methoddata = রিক্ত;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = রিক্ত;
	g_authctxt.oktypes = রিক্ত;
	g_authctxt.ktypes = রিক্ত;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.চাবিগুলি);
	ssh->authctxt = &g_authctxt;
}

স্থির শূন্য
fuzz_setup(সংরচনা ssh *ssh)
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
	options.সংখ্যা_of_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(শূন্য)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_set(ssh, SSH2_বার্তা_EXT_INFO, kex_প্রবেশ_ext_info);
	ssh_dispatch_set(ssh, SSH2_বার্তা_SERVICE_ACCEPT, &প্রবেশ_userauth_service_accept);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_SUCCESS, &প্রবেশ_userauth_success);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_FAILURE, &প্রবেশ_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_BANNER, &প্রবেশ_userauth_banner);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_INFO_REQUEST, &প্রবেশ_userauth_info_req);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_PK_OK, &প্রবেশ_userauth_pk_ok);
	ssh_dispatch_set(ssh, SSH2_বার্তা_USERAUTH_PASSWD_CHANGEREQ, &প্রবেশ_userauth_passwd_changereq);
}

স্থির পূর্ণাঙ্ক
init_once(শূন্য)
{
	যদি (g_init)
		প্রত্যাগম 0;
	সঙ্কেত(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	সংরচনা sshkey *priv = load_private(PRIV_ED25519);
	সংরচনা sshkey *pub = load_public(PUB_ED25519);
	বর্ণ *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুব বর্ণ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	বর্ণ *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণাঙ্ক i;
	প্রতি (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুব বর্ণ *p = defaults[i];
		যদি (i == PROPOSAL_SERVER_HOST_চাবি_ALGS)
			p = keyname;
		অন্যথা যদি (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		অন্যথা যদি (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		অন্যথা যদি (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	সংরচনা kex_params kp;
	memcpy(kp.proposal, proposal, পরিমাণ(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		প্রত্যাগম -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		প্রত্যাগম -1;
	যদি (run_kex(g_client, g_server) != 0)
		প্রত্যাগম -1;

	fuzz_setup(g_client);

	মুক্ত(keyname);
	প্রতি (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	প্রত্যাগম 0;
}

স্থির ধ্রুব uint8_t k_বার্তা_types[] = {
	SSH2_বার্তা_DISCONNECT, SSH2_বার্তা_IGNORE, SSH2_বার্তা_UNIMPLEMENTED,
	SSH2_বার্তা_DEBUG, SSH2_বার্তা_SERVICE_ACCEPT, SSH2_বার্তা_EXT_INFO,
	SSH2_বার্তা_USERAUTH_FAILURE, SSH2_বার্তা_USERAUTH_SUCCESS,
	SSH2_বার্তা_USERAUTH_BANNER, SSH2_বার্তা_USERAUTH_INFO_REQUEST,
	SSH2_বার্তা_USERAUTH_PK_OK, SSH2_বার্তা_USERAUTH_PASSWD_CHANGEREQ,
};

শূন্য
fuzz_one_message(ধ্রুব uint8_t *data, size_t size)
{
	যদি (init_once() != 0)
		প্রত্যাগম;
	যদি (size > 65000)
		প্রত্যাগম;

	uint8_t selector = size > 0 ? data[0] : 0;
	ধ্রুব uint8_t *payload = size > 0 ? data + 1 : রিক্ত;
	size_t plen = size > 0 ? size - 1 : 0;

	uint8_t বার্তা_type = k_বার্তা_types[selector %
	    (পরিমাণ(k_বার্তা_types) / পরিমাণ(k_বার্তা_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		size_t transferred;
		যদি (ssh_packet_put(g_server, বার্তা_type, payload, plen) != 0)
			গচ্ছ done;
		যদি (pump(g_server, g_client, &transferred) != 0)
			গচ্ছ done;
		(শূন্য)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, রিক্ত);
	done:
		;
	}
	in_fuzz = 0;
}
