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
পূর্ণসংখ্যা debug_flag = 0;

কাঠামো ssh;

পূর্ণসংখ্যা
__wrap_ssh_packet_write_wait(কাঠামো ssh *ssh)
{
	(শূন্য)ssh;
	ফেরত 0;
}

অক্ষর *
__wrap_read_passphrase(ধ্রুবক অক্ষর *prompt, পূর্ণসংখ্যা flags)
{
	(শূন্য)prompt;
	(শূন্য)flags;
	ফেরত strdup("fuzz");
}

#অন্তর্ভাব "../../../sshconnect2.c"
#অন্তর্ভাব "fixed-keys.h"

স্থির jmp_buf fuzz_env;
স্থির অস্থির পূর্ণসংখ্যা in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

স্থির কাঠামো sshkey *
load_private(ধ্রুবক অক্ষর *str)
{
	কাঠামো sshbuf *b = sshbuf_from(str, strlen(str));
	কাঠামো sshkey *k = ফাঁকা;
	যদি (b == ফাঁকা || sshkey_parse_private_fileblob(b, "", &k, ফাঁকা) != 0)
		abort();
	sshbuf_free(b);
	ফেরত k;
}

স্থির কাঠামো sshkey *
load_public(ধ্রুবক অক্ষর *str)
{
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == ফাঁকা)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ফেরত k;
}

স্থির পূর্ণসংখ্যা
pump(কাঠামো ssh *from, কাঠামো ssh *to, আকার_t *transferred)
{
	ধ্রুবক u_char *buf;
	আকার_t len;
	u_char type;
	পূর্ণসংখ্যা r;
	*transferred = 0;
	যদি ((r = ssh_packet_পরবর্তী(from, &type)) != 0)
		ফেরত r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		ফেরত 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		ফেরত r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		ফেরত r;
	*transferred = len;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
run_kex(কাঠামো ssh *client, কাঠামো ssh *server)
{
	পূর্ণসংখ্যা r;
	আকার_t cn, sn;
	জন্য (পূর্ণসংখ্যা i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) ফেরত r;
		যদি ((r = pump(client, server, &cn)) != 0) ফেরত r;
		যদি (server->kex->done && client->kex->done)
			ফেরত 0;
		যদি (cn == 0 && sn == 0)
			ফেরত SSH_ERR_PROTOCOL_ERROR;
	}
	ফেরত SSH_ERR_PROTOCOL_ERROR;
}

স্থির Sensitive g_sensitive = { ফাঁকা, 0 };
স্থির Authctxt g_authctxt;
স্থির কাঠামো ssh *g_client = ফাঁকা;
স্থির কাঠামো ssh *g_server = ফাঁকা;
স্থির পূর্ণসংখ্যা g_init = 0;

স্থির শূন্য
fuzz_reset_authctxt(কাঠামো ssh *ssh)
{
	মুক্ত(g_authctxt.authlist);
	g_authctxt.authlist = ফাঁকা;
	যদি (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, আকার(g_authctxt));
	g_authctxt.server_user = (অক্ষর *)"fuzz";
	g_authctxt.local_user = (অক্ষর *)"fuzz";
	g_authctxt.host = (অক্ষর *)"127.0.0.1";
	g_authctxt.service = (অক্ষর *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.method = authmethod_lookup("none");
	g_authctxt.authlist = ফাঁকা;
	g_authctxt.methoddata = ফাঁকা;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.active_ktype = ফাঁকা;
	g_authctxt.oktypes = ফাঁকা;
	g_authctxt.ktypes = ফাঁকা;
	g_authctxt.info_req_seen = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.চাবিগুলি);
	ssh->authctxt = &g_authctxt;
}

স্থির শূন্য
fuzz_setup(কাঠামো ssh *ssh)
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

স্থির পূর্ণসংখ্যা
init_once(শূন্য)
{
	যদি (g_init)
		ফেরত 0;
	সংকেত(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	কাঠামো sshkey *priv = load_private(PRIV_ED25519);
	কাঠামো sshkey *pub = load_public(PUB_ED25519);
	অক্ষর *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুবক অক্ষর *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	অক্ষর *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুবক অক্ষর *p = defaults[i];
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
	কাঠামো kex_params kp;
	memcpy(kp.proposal, proposal, আকার(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ফেরত -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ফেরত -1;
	যদি (run_kex(g_client, g_server) != 0)
		ফেরত -1;

	fuzz_setup(g_client);

	মুক্ত(keyname);
	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	ফেরত 0;
}

স্থির ধ্রুবক uint8_t k_বার্তা_types[] = {
	SSH2_বার্তা_DISCONNECT, SSH2_বার্তা_IGNORE, SSH2_বার্তা_UNIMPLEMENTED,
	SSH2_বার্তা_DEBUG, SSH2_বার্তা_SERVICE_ACCEPT, SSH2_বার্তা_EXT_INFO,
	SSH2_বার্তা_USERAUTH_FAILURE, SSH2_বার্তা_USERAUTH_SUCCESS,
	SSH2_বার্তা_USERAUTH_BANNER, SSH2_বার্তা_USERAUTH_INFO_REQUEST,
	SSH2_বার্তা_USERAUTH_PK_OK, SSH2_বার্তা_USERAUTH_PASSWD_CHANGEREQ,
};

শূন্য
fuzz_one_message(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (init_once() != 0)
		ফেরত;
	যদি (আকার_2 > 65000)
		ফেরত;

	uint8_t selector = আকার_2 > 0 ? তথ্য[0] : 0;
	ধ্রুবক uint8_t *payload = আকার_2 > 0 ? তথ্য + 1 : ফাঁকা;
	আকার_t plen = আকার_2 > 0 ? আকার_2 - 1 : 0;

	uint8_t বার্তা_type = k_বার্তা_types[selector %
	    (আকার(k_বার্তা_types) / আকার(k_বার্তা_types[0]))];

	fuzz_reset_authctxt(g_client);

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		আকার_t transferred;
		যদি (ssh_packet_put(g_server, বার্তা_type, payload, plen) != 0)
			যাও done;
		যদি (pump(g_server, g_client, &transferred) != 0)
			যাও done;
		(শূন্য)ssh_dispatch_run(g_client, DISPATCH_NONBLOCK, ফাঁকা);
	done:
		;
	}
	in_fuzz = 0;
}
