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

#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

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
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "audit.h"

ServerOptions options;
ସଂରଚନା sshbuf *loginmsg = ଖାଲି;
ସଂରଚନା include_list includes;
ସଂରଚନା sshauthopt *auth_opts = ଖାଲି;
ସଂରଚନା passwd *privsep_pw = ଖାଲି;

ସ୍ଥିର jmp_buf fuzz_env;
ସ୍ଥିର ଅସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fuzz = 0;

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_ssh_packet_write_wait(ସଂରଚନା ssh *ssh)
{
	(ଶୂନ୍ୟ)ssh;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ସଂରଚନା passwd g_fake_pw;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_is_monitor(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ 0;
}

ସଂରଚନା passwd *
mm_getpwnamallow(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *user)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)user;
	ଫେରନ୍ତୁ &g_fake_pw;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_auth_password(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *password)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)password;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_user_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *pw, ସଂରଚନା sshkey *ଚାବି,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_attempt, ସଂରଚନା sshauthopt **authoptsp)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)pw;
	(ଶୂନ୍ୟ)ଚାବି;
	(ଶୂନ୍ୟ)auth_attempt;
	(ଶୂନ୍ୟ)authoptsp;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_hostbased_ଚାବି_allowed(ସଂରଚନା ssh *ssh, ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *user,
    ଅଚଳ ଅକ୍ଷର *host, ସଂରଚନା sshkey *ଚାବି)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)pw;
	(ଶୂନ୍ୟ)user;
	(ଶୂନ୍ୟ)host;
	(ଶୂନ୍ୟ)ଚାବି;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_sshkey_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t datalen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat,
    ସଂରଚନା sshkey_sig_details **detailsp)
{
	ଫେରନ୍ତୁ sshkey_verify(ଚାବି, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

ଶୂନ୍ୟ
mm_inform_authserv(ଅକ୍ଷର *service, ଅକ୍ଷର *style)
{
	(ଶୂନ୍ୟ)service;
	(ଶୂନ୍ୟ)style;
}

ଶୂନ୍ୟ
mm_audit_event(ସଂରଚନା ssh *ssh, ssh_audit_event_t event)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)event;
}

ଶୂନ୍ୟ
mm_start_pam(ସଂରଚନା ssh *ssh)
{
	(ଶୂନ୍ୟ)ssh;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_do_pam_account(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ 0;
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

#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"

ସଂରଚନା sshbuf *cfg = ଖାଲି;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_rhosts2(ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *client_user,
    ଅଚଳ ଅକ୍ଷର *hostname, ଅଚଳ ଅକ୍ଷର *ipaddr) { (ଶୂନ୍ୟ)pw;
    (ଶୂନ୍ୟ)client_user; (ଶୂନ୍ୟ)hostname; (ଶୂନ୍ୟ)ipaddr; ଫେରନ୍ତୁ 0; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା platform_locked_account(ସଂରଚନା passwd *pw) { (ଶୂନ୍ୟ)pw; ଫେରନ୍ତୁ 0; }
ଶୂନ୍ୟ record_failed_login(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *user,
    ଅଚଳ ଅକ୍ଷର *hostname, ଅଚଳ ଅକ୍ଷର *ttyname) { (ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)user;
    (ଶୂନ୍ୟ)hostname; (ଶୂନ୍ୟ)ttyname; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା temporarily_use_uid(ସଂରଚନା passwd *pw) { (ଶୂନ୍ୟ)pw; ଫେରନ୍ତୁ 0; }
ଶୂନ୍ୟ restore_uid(ଶୂନ୍ୟ) { }
ଅକ୍ଷର *mm_auth2_read_banner(ଶୂନ୍ୟ) { ଫେରନ୍ତୁ ଖାଲି; }
ସଂରଚନା connection_info *
server_get_connection_info(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା populate, ପୂର୍ଣ୍ଣସଂଖ୍ୟା use_dns)
    { (ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)populate; (ଶୂନ୍ୟ)use_dns; ଫେରନ୍ତୁ ଖାଲି; }
ଶୂନ୍ୟ server_process_permitopen(ସଂରଚନା ssh *ssh) { (ଶୂନ୍ୟ)ssh; }
ଶୂନ୍ୟ server_process_channel_timeouts(ସଂରଚନା ssh *ssh) { (ଶୂନ୍ୟ)ssh; }

#ଅନ୍ତର୍ଭାଵ "../../../auth2.c"

ସ୍ଥିର ସଂରଚନା ssh *g_client = ଖାଲି;
ସ୍ଥିର ସଂରଚନା ssh *g_server = ଖାଲି;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_init = 0;
ସ୍ଥିର Authctxt g_authctxt;

ସ୍ଥିର ଶୂନ୍ୟ
fuzz_reset_authctxt(ସଂରଚନା ssh *ssh)
{
	unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ମୁକ୍ତ(g_authctxt.user);
	ମୁକ୍ତ(g_authctxt.service);
	ମୁକ୍ତ(g_authctxt.style);
	ମୁକ୍ତ(g_authctxt.auth_method_info);
	ଯଦି (g_authctxt.auth_methods != ଖାଲି) {
		ପାଇଁ (i = 0; i < g_authctxt.ଅଙ୍କ_auth_methods; i++)
			ମୁକ୍ତ(g_authctxt.auth_methods[i]);
		ମୁକ୍ତ(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_ଚାବି);
	ପାଇଁ (i = 0; i < g_authctxt.nprev_ଚାବିଗୁଡ଼ିକ; i++)
		sshkey_free(g_authctxt.prev_ଚାବିଗୁଡ଼ିକ[i]);
	ମୁକ୍ତ(g_authctxt.prev_ଚାବିଗୁଡ଼ିକ);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, ଆକାର(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
init_once(ଶୂନ୍ୟ)
{
	ଯଦି (g_init)
		ଫେରନ୍ତୁ 0;
	ସଙ୍କେତ(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ଆକାର(g_fake_pw));
	g_fake_pw.pw_name = (ଅକ୍ଷର *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ଅକ୍ଷର *)"/tmp";
	g_fake_pw.pw_shell = (ଅକ୍ଷର *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

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

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST,
	    &ନିବେଶ_userauth_request);

	ମୁକ୍ତ(keyname);
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(proposal[i]);
	g_init = 1;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
fuzz_userauth_one(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (init_once() != 0)
		ଫେରନ୍ତୁ;
	ଯଦି (size > 65000)
		ଫେରନ୍ତୁ;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	ଯଦି (setjmp(fuzz_env) == 0) {
		size_t transferred;
		ଯଦି (ssh_packet_put(g_client, SSH2_ସନ୍ଦେଶ_USERAUTH_REQUEST,
		    data, size) != 0)
			ଯାଅ done;
		ଯଦି (pump(g_client, g_server, &transferred) != 0)
			ଯାଅ done;
		(ଶୂନ୍ୟ)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ଖାଲି);
	done:
		;
	}
	in_fuzz = 0;
}
