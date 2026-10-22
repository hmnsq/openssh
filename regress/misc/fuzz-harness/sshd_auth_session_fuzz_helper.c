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
 * Fuzzer for OpenSSH server-side userauth dispatch (auth2.c + auth2-*.c)
 *
 * Target: input_userauth_request and the userauth_* method handlers
 *
 * Threat model: pre-auth attacker sending crafted USERAUTH_REQUEST
 * messages to sshd. Mirror of ssh_client_session_fuzz on the server
 * side. The handlers parse method/user/service/key/sig fields before
 * calling any actual authentication backend.
 *
 * Mock layer: the monitor_wrap mm_* IPC functions are replaced with
 * in-process stubs that return canned data so the dispatch path runs
 * without real privsep IPC or filesystem access. mm_sshkey_verify is
 * the only stub that calls a real backend (sshkey_verify), which
 * harmlessly fails on garbage signatures.
 *
 * KEX is real, mirrored across two in-process ssh structs created via
 * ssh_api. After KEX completes, input_userauth_request is registered
 * on the server's dispatch table and each iteration delivers a
 * fuzzer-controlled USERAUTH_REQUEST.
 */

#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <sys/types.h>

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
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "audit.h"

ServerOptions options;
నిర్మాణం sshbuf *loginmsg = ఖాళీ;
నిర్మాణం include_list includes;
నిర్మాణం sshauthopt *auth_opts = ఖాళీ;
నిర్మాణం passwd *privsep_pw = ఖాళీ;

స్థిర jmp_buf fuzz_env;
స్థిర అస్థిర పూర్ణాంకం లోపల_fuzz = 0;

శూన్య
cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

పూర్ణాంకం
__wrap_ssh_packet_write_wait(నిర్మాణం ssh *ssh)
{
	(శూన్య)ssh;
	తిరిగి 0;
}

స్థిర నిర్మాణం passwd g_fake_pw;

పూర్ణాంకం
mm_is_monitor(శూన్య)
{
	తిరిగి 0;
}

నిర్మాణం passwd *
mm_getpwnamallow(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *user)
{
	(శూన్య)ssh;
	(శూన్య)user;
	తిరిగి &g_fake_pw;
}

పూర్ణాంకం
mm_auth_password(నిర్మాణం ssh *ssh, అక్షరం *password)
{
	(శూన్య)ssh;
	(శూన్య)password;
	తిరిగి 0;
}

పూర్ణాంకం
mm_user_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *pw, నిర్మాణం sshkey *కీలకం,
    పూర్ణాంకం auth_attempt, నిర్మాణం sshauthopt **authoptsp)
{
	(శూన్య)ssh;
	(శూన్య)pw;
	(శూన్య)కీలకం;
	(శూన్య)auth_attempt;
	(శూన్య)authoptsp;
	తిరిగి 0;
}

పూర్ణాంకం
mm_hostbased_కీలకం_allowed(నిర్మాణం ssh *ssh, నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *user,
    స్థిరరాశి అక్షరం *host, నిర్మాణం sshkey *కీలకం)
{
	(శూన్య)ssh;
	(శూన్య)pw;
	(శూన్య)user;
	(శూన్య)host;
	(శూన్య)కీలకం;
	తిరిగి 0;
}

పూర్ణాంకం
mm_sshkey_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం, స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen, స్థిరరాశి అక్షరం *alg, u_int compat,
    నిర్మాణం sshkey_sig_details **detailsp)
{
	తిరిగి sshkey_verify(కీలకం, sig, siglen, దత్తాంశం, datalen, alg, compat,
	    detailsp);
}

శూన్య
mm_inform_authserv(అక్షరం *service, అక్షరం *style)
{
	(శూన్య)service;
	(శూన్య)style;
}

శూన్య
mm_audit_event(నిర్మాణం ssh *ssh, ssh_audit_event_t event)
{
	(శూన్య)ssh;
	(శూన్య)event;
}

శూన్య
mm_ప్రారంభం_pam(నిర్మాణం ssh *ssh)
{
	(శూన్య)ssh;
}

పూర్ణాంకం
mm_do_pam_account(శూన్య)
{
	తిరిగి 0;
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

#అన్తర్భావ "fixed-keys.h"

నిర్మాణం sshbuf *cfg = ఖాళీ;

పూర్ణాంకం auth_rhosts2(నిర్మాణం passwd *pw, స్థిరరాశి అక్షరం *client_user,
    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *ipaddr) { (శూన్య)pw;
    (శూన్య)client_user; (శూన్య)hostname; (శూన్య)ipaddr; తిరిగి 0; }
పూర్ణాంకం platform_locked_account(నిర్మాణం passwd *pw) { (శూన్య)pw; తిరిగి 0; }
శూన్య రికార్డు_failed_login(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *user,
    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *ttyname) { (శూన్య)ssh; (శూన్య)user;
    (శూన్య)hostname; (శూన్య)ttyname; }
పూర్ణాంకం temporarily_use_uid(నిర్మాణం passwd *pw) { (శూన్య)pw; తిరిగి 0; }
శూన్య restore_uid(శూన్య) { }
అక్షరం *mm_auth2_read_banner(శూన్య) { తిరిగి ఖాళీ; }
నిర్మాణం connection_info *
server_get_connection_info(నిర్మాణం ssh *ssh, పూర్ణాంకం populate, పూర్ణాంకం use_dns)
    { (శూన్య)ssh; (శూన్య)populate; (శూన్య)use_dns; తిరిగి ఖాళీ; }
శూన్య server_process_permitopen(నిర్మాణం ssh *ssh) { (శూన్య)ssh; }
శూన్య server_process_channel_timeouts(నిర్మాణం ssh *ssh) { (శూన్య)ssh; }

#అన్తర్భావ "../../../auth2.c"

స్థిర నిర్మాణం ssh *g_client = ఖాళీ;
స్థిర నిర్మాణం ssh *g_server = ఖాళీ;
స్థిర పూర్ణాంకం g_init = 0;
స్థిర Authctxt g_authctxt;

స్థిర శూన్య
fuzz_reset_authctxt(నిర్మాణం ssh *ssh)
{
	గుర్తులేని పూర్ణాంకం i;

	విడుదల(g_authctxt.user);
	విడుదల(g_authctxt.service);
	విడుదల(g_authctxt.style);
	విడుదల(g_authctxt.auth_పద్ధతి_info);
	ఒకవేళ (g_authctxt.auth_methods != ఖాళీ) {
		కొరకు (i = 0; i < g_authctxt.అంకె_auth_methods; i++)
			విడుదల(g_authctxt.auth_methods[i]);
		విడుదల(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_పద్ధతి_కీలకం);
	కొరకు (i = 0; i < g_authctxt.nprev_కీలకాలు; i++)
		sshkey_free(g_authctxt.prev_కీలకాలు[i]);
	విడుదల(g_authctxt.prev_కీలకాలు);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, పరిమాణం(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

స్థిర పూర్ణాంకం
init_once(శూన్య)
{
	ఒకవేళ (g_init)
		తిరిగి 0;
	సంకేతం(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, పరిమాణం(g_fake_pw));
	g_fake_pw.pw_name = (అక్షరం *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (అక్షరం *)"/tmp";
	g_fake_pw.pw_shell = (అక్షరం *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

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

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_సమితి(g_server, SSH2_సందేశం_USERAUTH_REQUEST,
	    &ఆదానం_userauth_request);

	విడుదల(keyname);
	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(proposal[i]);
	g_init = 1;
	తిరిగి 0;
}

శూన్య
fuzz_userauth_one(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (init_once() != 0)
		తిరిగి;
	ఒకవేళ (కొలత > 65000)
		తిరిగి;

	fuzz_reset_authctxt(g_server);

	లోపల_fuzz = 1;
	ఒకవేళ (setjmp(fuzz_env) == 0) {
		కొలత_t transferred;
		ఒకవేళ (ssh_packet_put(g_client, SSH2_సందేశం_USERAUTH_REQUEST,
		    దత్తాంశం, కొలత) != 0)
			వెళ్ళు పూర్తి;
		ఒకవేళ (pump(g_client, g_server, &transferred) != 0)
			వెళ్ళు పూర్తి;
		(శూన్య)ssh_dispatch_నిరంతరం(g_server, DISPATCH_NONBLOCK, ఖాళీ);
	పూర్తి:
		;
	}
	లోపల_fuzz = 0;
}
