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

#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "readconf.h"

Options options;
పూర్ణాంకం debug_flag = 0;

నిర్మాణం ssh;

పూర్ణాంకం
__wrap_ssh_packet_write_wait(నిర్మాణం ssh *ssh)
{
	(శూన్య)ssh;
	తిరిగి 0;
}

అక్షరం *
__wrap_read_passphrase(స్థిరరాశి అక్షరం *prompt, పూర్ణాంకం flags)
{
	(శూన్య)prompt;
	(శూన్య)flags;
	తిరిగి strdup("fuzz");
}

#అన్తర్భావ "../../../sshconnect2.c"
#అన్తర్భావ "fixed-keys.h"

స్థిర jmp_buf fuzz_env;
స్థిర అస్థిర పూర్ణాంకం లోపల_fuzz = 0;

శూన్య
cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_వ్యక్తిగత(స్థిరరాశి అక్షరం *str)
{
	నిర్మాణం sshbuf *b = sshbuf_from(str, అక్షరశ్రేణి_పొడవు(str));
	నిర్మాణం sshkey *k = ఖాళీ;
	ఒకవేళ (b == ఖాళీ || sshkey_parse_వ్యక్తిగత_fileblob(b, "", &k, ఖాళీ) != 0)
		abort();
	sshbuf_free(b);
	తిరిగి k;
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_ప్రజా(స్థిరరాశి అక్షరం *str)
{
	అక్షరం *tmp, *cp;
	నిర్మాణం sshkey *k = sshkey_new(కీలకం_UNSPEC);
	ఒకవేళ (k == ఖాళీ)
		abort();
	tmp = cp = strdup(str);
	ఒకవేళ (sshkey_read(k, &cp) != 0)
		abort();
	విడుదల(tmp);
	తిరిగి k;
}

స్థిర పూర్ణాంకం
pump(నిర్మాణం ssh *from, నిర్మాణం ssh *గమ్యం, కొలత_t *transferred)
{
	స్థిరరాశి u_char *buf;
	కొలత_t len;
	u_char type;
	పూర్ణాంకం r;
	*transferred = 0;
	ఒకవేళ ((r = ssh_packet_తదుపరి(from, &type)) != 0)
		తిరిగి r;
	buf = ssh_output_ptr(from, &len);
	ఒకవేళ (len == 0)
		తిరిగి 0;
	ఒకవేళ ((r = ssh_ఆదానం_append(గమ్యం, buf, len)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = ssh_output_consume(from, len)) != 0)
		తిరిగి r;
	*transferred = len;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
నిరంతరం_kex(నిర్మాణం ssh *client, నిర్మాణం ssh *server)
{
	పూర్ణాంకం r;
	కొలత_t cn, sn;
	కొరకు (పూర్ణాంకం i = 0; i < 100; i++) {
		ఒకవేళ ((r = pump(server, client, &sn)) != 0) తిరిగి r;
		ఒకవేళ ((r = pump(client, server, &cn)) != 0) తిరిగి r;
		ఒకవేళ (server->kex->పూర్తి && client->kex->పూర్తి)
			తిరిగి 0;
		ఒకవేళ (cn == 0 && sn == 0)
			తిరిగి SSH_ERR_PROTOCOL_ERROR;
	}
	తిరిగి SSH_ERR_PROTOCOL_ERROR;
}

స్థిర Sensitive g_sensitive = { ఖాళీ, 0 };
స్థిర Authctxt g_authctxt;
స్థిర నిర్మాణం ssh *g_client = ఖాళీ;
స్థిర నిర్మాణం ssh *g_server = ఖాళీ;
స్థిర పూర్ణాంకం g_init = 0;

స్థిర శూన్య
fuzz_reset_authctxt(నిర్మాణం ssh *ssh)
{
	విడుదల(g_authctxt.authlist);
	g_authctxt.authlist = ఖాళీ;
	ఒకవేళ (ssh->authctxt == &g_authctxt)
		pubkey_cleanup(ssh);

	memset(&g_authctxt, 0, పరిమాణం(g_authctxt));
	g_authctxt.server_user = (అక్షరం *)"fuzz";
	g_authctxt.local_user = (అక్షరం *)"fuzz";
	g_authctxt.host = (అక్షరం *)"127.0.0.1";
	g_authctxt.service = (అక్షరం *)"ssh-connection";
	g_authctxt.success = 0;
	g_authctxt.పద్ధతి = authmethod_lookup("none");
	g_authctxt.authlist = ఖాళీ;
	g_authctxt.methoddata = ఖాళీ;
	g_authctxt.sensitive = &g_sensitive;
	g_authctxt.చురుకైన_ktype = ఖాళీ;
	g_authctxt.oktypes = ఖాళీ;
	g_authctxt.ktypes = ఖాళీ;
	g_authctxt.info_req_చూసిన = 0;
	g_authctxt.attempt_kbdint = 0;
	g_authctxt.attempt_passwd = 0;
	g_authctxt.agent_fd = -1;
	TAILQ_INIT(&g_authctxt.కీలకాలు);
	ssh->authctxt = &g_authctxt;
}

స్థిర శూన్య
fuzz_అమరిక(నిర్మాణం ssh *ssh)
{
	initialize_options(&options);
	options.batch_బహుళకం = 1;
	options.pubkey_authentication = 0;
	options.password_authentication = 0;
	options.kbd_interactive_authentication = 0;
	options.hostbased_authentication = 0;
	options.gss_authentication = 0;
	options.preferred_authentications = strdup("none");
	options.user = strdup("fuzz");
	options.సంఖ్య_యొక్క_password_prompts = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fingerprint_hash = SSH_DIGEST_SHA256;
	(శూన్య)fill_default_options(&options);

	fuzz_reset_authctxt(ssh);

	ssh_dispatch_init(ssh, &dispatch_protocol_ignore);

	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, kex_ఆదానం_ext_info);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_SERVICE_ACCEPT, &ఆదానం_userauth_service_accept);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_SUCCESS, &ఆదానం_userauth_success);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_FAILURE, &ఆదానం_userauth_failure);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_BANNER, &ఆదానం_userauth_banner);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_INFO_REQUEST, &ఆదానం_userauth_info_req);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_PK_OK, &ఆదానం_userauth_pk_ok);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_PASSWD_CHANGEREQ, &ఆదానం_userauth_passwd_changereq);
}

స్థిర పూర్ణాంకం
init_once(శూన్య)
{
	ఒకవేళ (g_init)
		తిరిగి 0;
	సంకేతం(SIGPIPE, SIG_IGN);
	log_init("ssh_client_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	నిర్మాణం sshkey *priv = ఎక్కించు_వ్యక్తిగత(PRIV_ED25519);
	నిర్మాణం sshkey *pub = ఎక్కించు_ప్రజా(PUB_ED25519);
	అక్షరం *keyname = xstrdup(sshkey_ssh_name(priv));

	స్థిరరాశి అక్షరం *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	అక్షరం *proposal[PROPOSAL_MAX] = { 0 };
	పూర్ణాంకం i;
	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		స్థిరరాశి అక్షరం *p = defaults[i];
		ఒకవేళ (i == PROPOSAL_SERVER_HOST_కీలకం_ALGS)
			p = keyname;
		లేకపోతే ఒకవేళ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		లేకపోతే ఒకవేళ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		లేకపోతే ఒకవేళ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	నిర్మాణం kex_params kp;
	జ్ఞాపకం_నకలు(kp.proposal, proposal, పరిమాణం(proposal));

	ఒకవేళ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		తిరిగి -1;
	ఒకవేళ (ssh_కూడు_hostkey(g_server, priv) != 0 ||
	    ssh_కూడు_hostkey(g_client, pub) != 0)
		తిరిగి -1;
	ఒకవేళ (నిరంతరం_kex(g_client, g_server) != 0)
		తిరిగి -1;

	fuzz_అమరిక(g_client);

	విడుదల(keyname);
	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(proposal[i]);
	g_init = 1;
	తిరిగి 0;
}

స్థిర స్థిరరాశి uint8_t k_సందేశం_types[] = {
	SSH2_సందేశం_DISCONNECT, SSH2_సందేశం_IGNORE, SSH2_సందేశం_UNIMPLEMENTED,
	SSH2_సందేశం_DEBUG, SSH2_సందేశం_SERVICE_ACCEPT, SSH2_సందేశం_EXT_INFO,
	SSH2_సందేశం_USERAUTH_FAILURE, SSH2_సందేశం_USERAUTH_SUCCESS,
	SSH2_సందేశం_USERAUTH_BANNER, SSH2_సందేశం_USERAUTH_INFO_REQUEST,
	SSH2_సందేశం_USERAUTH_PK_OK, SSH2_సందేశం_USERAUTH_PASSWD_CHANGEREQ,
};

శూన్య
fuzz_one_సందేశం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (init_once() != 0)
		తిరిగి;
	ఒకవేళ (కొలత > 65000)
		తిరిగి;

	uint8_t selector = కొలత > 0 ? దత్తాంశం[0] : 0;
	స్థిరరాశి uint8_t *payload = కొలత > 0 ? దత్తాంశం + 1 : ఖాళీ;
	కొలత_t plen = కొలత > 0 ? కొలత - 1 : 0;

	uint8_t సందేశం_type = k_సందేశం_types[selector %
	    (పరిమాణం(k_సందేశం_types) / పరిమాణం(k_సందేశం_types[0]))];

	fuzz_reset_authctxt(g_client);

	లోపల_fuzz = 1;
	ఒకవేళ (setjmp(fuzz_env) == 0) {
		కొలత_t transferred;
		ఒకవేళ (ssh_packet_put(g_server, సందేశం_type, payload, plen) != 0)
			వెళ్ళు పూర్తి;
		ఒకవేళ (pump(g_server, g_client, &transferred) != 0)
			వెళ్ళు పూర్తి;
		(శూన్య)ssh_dispatch_నిరంతరం(g_client, DISPATCH_NONBLOCK, ఖాళీ);
	పూర్తి:
		;
	}
	లోపల_fuzz = 0;
}
