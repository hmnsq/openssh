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

#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <sys/types.h>

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
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "audit.h"

ServerOptions options;
கட்டமைப்பு sshbuf *loginmsg = வெற்று;
கட்டமைப்பு include_list includes;
கட்டமைப்பு sshauthopt *auth_opts = வெற்று;
கட்டமைப்பு passwd *privsep_pw = வெற்று;

நிலையான jmp_buf fuzz_env;
நிலையான நிலையற்ற முழு in_fuzz = 0;

வெறுமை
cleanup_exit(முழு code)
{
	எனில் (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

முழு
__wrap_ssh_packet_write_wait(கட்டமைப்பு ssh *ssh)
{
	(வெறுமை)ssh;
	திரும்பு 0;
}

நிலையான கட்டமைப்பு passwd g_fake_pw;

முழு
mm_is_monitor(வெறுமை)
{
	திரும்பு 0;
}

கட்டமைப்பு passwd *
mm_getpwnamallow(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *user)
{
	(வெறுமை)ssh;
	(வெறுமை)user;
	திரும்பு &g_fake_pw;
}

முழு
mm_auth_password(கட்டமைப்பு ssh *ssh, எழுத்து *password)
{
	(வெறுமை)ssh;
	(வெறுமை)password;
	திரும்பு 0;
}

முழு
mm_user_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *சாவி,
    முழு auth_attempt, கட்டமைப்பு sshauthopt **authoptsp)
{
	(வெறுமை)ssh;
	(வெறுமை)pw;
	(வெறுமை)சாவி;
	(வெறுமை)auth_attempt;
	(வெறுமை)authoptsp;
	திரும்பு 0;
}

முழு
mm_hostbased_சாவி_allowed(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *user,
    மாறிலி எழுத்து *host, கட்டமைப்பு sshkey *சாவி)
{
	(வெறுமை)ssh;
	(வெறுமை)pw;
	(வெறுமை)user;
	(வெறுமை)host;
	(வெறுமை)சாவி;
	திரும்பு 0;
}

முழு
mm_sshkey_verify(மாறிலி கட்டமைப்பு sshkey *சாவி, மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t datalen, மாறிலி எழுத்து *alg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **detailsp)
{
	திரும்பு sshkey_verify(சாவி, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

வெறுமை
mm_inform_authserv(எழுத்து *service, எழுத்து *style)
{
	(வெறுமை)service;
	(வெறுமை)style;
}

வெறுமை
mm_audit_event(கட்டமைப்பு ssh *ssh, ssh_audit_event_t event)
{
	(வெறுமை)ssh;
	(வெறுமை)event;
}

வெறுமை
mm_start_pam(கட்டமைப்பு ssh *ssh)
{
	(வெறுமை)ssh;
}

முழு
mm_do_pam_account(வெறுமை)
{
	திரும்பு 0;
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

#அந்தர்பாவ "fixed-keys.h"

கட்டமைப்பு sshbuf *cfg = வெற்று;

முழு auth_rhosts2(கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *client_user,
    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *ipaddr) { (வெறுமை)pw;
    (வெறுமை)client_user; (வெறுமை)hostname; (வெறுமை)ipaddr; திரும்பு 0; }
முழு platform_locked_account(கட்டமைப்பு passwd *pw) { (வெறுமை)pw; திரும்பு 0; }
வெறுமை record_failed_login(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *user,
    மாறிலி எழுத்து *hostname, மாறிலி எழுத்து *ttyname) { (வெறுமை)ssh; (வெறுமை)user;
    (வெறுமை)hostname; (வெறுமை)ttyname; }
முழு temporarily_use_uid(கட்டமைப்பு passwd *pw) { (வெறுமை)pw; திரும்பு 0; }
வெறுமை restore_uid(வெறுமை) { }
எழுத்து *mm_auth2_read_banner(வெறுமை) { திரும்பு வெற்று; }
கட்டமைப்பு connection_info *
server_get_connection_info(கட்டமைப்பு ssh *ssh, முழு populate, முழு use_dns)
    { (வெறுமை)ssh; (வெறுமை)populate; (வெறுமை)use_dns; திரும்பு வெற்று; }
வெறுமை server_process_permitopen(கட்டமைப்பு ssh *ssh) { (வெறுமை)ssh; }
வெறுமை server_process_channel_timeouts(கட்டமைப்பு ssh *ssh) { (வெறுமை)ssh; }

#அந்தர்பாவ "../../../auth2.c"

நிலையான கட்டமைப்பு ssh *g_client = வெற்று;
நிலையான கட்டமைப்பு ssh *g_server = வெற்று;
நிலையான முழு g_init = 0;
நிலையான Authctxt g_authctxt;

நிலையான வெறுமை
fuzz_reset_authctxt(கட்டமைப்பு ssh *ssh)
{
	unsigned முழு i;

	விடுவி(g_authctxt.user);
	விடுவி(g_authctxt.service);
	விடுவி(g_authctxt.style);
	விடுவி(g_authctxt.auth_method_info);
	எனில் (g_authctxt.auth_methods != வெற்று) {
		க்கு (i = 0; i < g_authctxt.இலக்கம்_auth_methods; i++)
			விடுவி(g_authctxt.auth_methods[i]);
		விடுவி(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_சாவி);
	க்கு (i = 0; i < g_authctxt.nprev_சாவிகள்; i++)
		sshkey_free(g_authctxt.prev_சாவிகள்[i]);
	விடுவி(g_authctxt.prev_சாவிகள்);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, அளவு(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

நிலையான முழு
init_once(வெறுமை)
{
	எனில் (g_init)
		திரும்பு 0;
	சமிக்ஞை(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, அளவு(g_fake_pw));
	g_fake_pw.pw_name = (எழுத்து *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (எழுத்து *)"/tmp";
	g_fake_pw.pw_shell = (எழுத்து *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

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

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_செய்தி_USERAUTH_REQUEST,
	    &உள்ளீடு_userauth_request);

	விடுவி(keyname);
	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(proposal[i]);
	g_init = 1;
	திரும்பு 0;
}

வெறுமை
fuzz_userauth_one(மாறிலி uint8_t *data, size_t size)
{
	எனில் (init_once() != 0)
		திரும்பு;
	எனில் (size > 65000)
		திரும்பு;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	எனில் (setjmp(fuzz_env) == 0) {
		size_t transferred;
		எனில் (ssh_packet_put(g_client, SSH2_செய்தி_USERAUTH_REQUEST,
		    data, size) != 0)
			செல் done;
		எனில் (pump(g_client, g_server, &transferred) != 0)
			செல் done;
		(வெறுமை)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, வெற்று);
	done:
		;
	}
	in_fuzz = 0;
}
