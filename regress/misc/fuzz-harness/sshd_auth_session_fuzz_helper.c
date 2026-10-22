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

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include "log.h"
#include "digest.h"
#include "misc.h"
#include "ssh.h"
#include "ssh2.h"
#include "ssh_api.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "packet.h"
#include "myproposal.h"
#include "kex.h"
#include "xmalloc.h"
#include "authfile.h"
#include "hostfile.h"
#include "auth.h"
#include "servconf.h"
#include "audit.h"

ServerOptions options;
sa_nracanaa sshbuf *loginmsg = NULL;
sa_nracanaa include_list includes;
sa_nracanaa sshauthopt *auth_opts = NULL;
sa_nracanaa passwd *privsep_pw = NULL;

static jmp_buf fuzz_env;
static ca_ncala පූර්ණ_සංඛ්‍යා in_fuzz = 0;

void
cleanup_exit(පූර්ණ_සංඛ්‍යා code)
{
	නම් (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

පූර්ණ_සංඛ්‍යා
__wrap_ssh_packet_write_wait(sa_nracanaa ssh *ssh)
{
	(void)ssh;
	ආපසු 0;
}

static sa_nracanaa passwd g_fake_pw;

පූර්ණ_සංඛ්‍යා
mm_is_monitor(void)
{
	ආපසු 0;
}

sa_nracanaa passwd *
mm_getpwnamallow(sa_nracanaa ssh *ssh, const var_na *user)
{
	(void)ssh;
	(void)user;
	ආපසු &g_fake_pw;
}

පූර්ණ_සංඛ්‍යා
mm_auth_password(sa_nracanaa ssh *ssh, var_na *password)
{
	(void)ssh;
	(void)password;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
mm_user_key_allowed(sa_nracanaa ssh *ssh, sa_nracanaa passwd *pw, sa_nracanaa sshkey *key,
    පූර්ණ_සංඛ්‍යා auth_attempt, sa_nracanaa sshauthopt **authoptsp)
{
	(void)ssh;
	(void)pw;
	(void)key;
	(void)auth_attempt;
	(void)authoptsp;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
mm_hostbased_key_allowed(sa_nracanaa ssh *ssh, sa_nracanaa passwd *pw, const var_na *user,
    const var_na *host, sa_nracanaa sshkey *key)
{
	(void)ssh;
	(void)pw;
	(void)user;
	(void)host;
	(void)key;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
mm_sshkey_verify(const sa_nracanaa sshkey *key, const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen, const var_na *alg, u_int compat,
    sa_nracanaa sshkey_sig_details **detailsp)
{
	ආපසු sshkey_verify(key, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

void
mm_inform_authserv(var_na *service, var_na *style)
{
	(void)service;
	(void)style;
}

void
mm_audit_event(sa_nracanaa ssh *ssh, ssh_audit_event_t event)
{
	(void)ssh;
	(void)event;
}

void
mm_start_pam(sa_nracanaa ssh *ssh)
{
	(void)ssh;
}

පූර්ණ_සංඛ්‍යා
mm_do_pam_account(void)
{
	ආපසු 0;
}

static sa_nracanaa sshkey *
load_private(const var_na *str)
{
	sa_nracanaa sshbuf *b = sshbuf_from(str, strlen(str));
	sa_nracanaa sshkey *k = NULL;
	නම් (b == NULL || sshkey_parse_private_fileblob(b, "", &k, NULL) != 0)
		abort();
	sshbuf_free(b);
	ආපසු k;
}

static sa_nracanaa sshkey *
load_public(const var_na *str)
{
	var_na *tmp, *cp;
	sa_nracanaa sshkey *k = sshkey_new(KEY_UNSPEC);
	නම් (k == NULL)
		abort();
	tmp = cp = strdup(str);
	නම් (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	ආපසු k;
}

static පූර්ණ_සංඛ්‍යා
pump(sa_nracanaa ssh *from, sa_nracanaa ssh *to, size_t *transferred)
{
	const u_char *buf;
	size_t len;
	u_char type;
	පූර්ණ_සංඛ්‍යා r;
	*transferred = 0;
	නම් ((r = ssh_packet_next(from, &type)) != 0)
		ආපසු r;
	buf = ssh_output_ptr(from, &len);
	නම් (len == 0)
		ආපසු 0;
	නම් ((r = ssh_input_append(to, buf, len)) != 0)
		ආපසු r;
	නම් ((r = ssh_output_consume(from, len)) != 0)
		ආපසු r;
	*transferred = len;
	ආපසු 0;
}

static පූර්ණ_සංඛ්‍යා
run_kex(sa_nracanaa ssh *client, sa_nracanaa ssh *server)
{
	පූර්ණ_සංඛ්‍යා r;
	size_t cn, sn;
	සඳහා (පූර්ණ_සංඛ්‍යා i = 0; i < 100; i++) {
		නම් ((r = pump(server, client, &sn)) != 0) ආපසු r;
		නම් ((r = pump(client, server, &cn)) != 0) ආපසු r;
		නම් (server->kex->done && client->kex->done)
			ආපසු 0;
		නම් (cn == 0 && sn == 0)
			ආපසු SSH_ERR_PROTOCOL_ERROR;
	}
	ආපසු SSH_ERR_PROTOCOL_ERROR;
}

#include "fixed-keys.h"

sa_nracanaa sshbuf *cfg = NULL;

පූර්ණ_සංඛ්‍යා auth_rhosts2(sa_nracanaa passwd *pw, const var_na *client_user,
    const var_na *hostname, const var_na *ipaddr) { (void)pw;
    (void)client_user; (void)hostname; (void)ipaddr; ආපසු 0; }
පූර්ණ_සංඛ්‍යා platform_locked_account(sa_nracanaa passwd *pw) { (void)pw; ආපසු 0; }
void record_failed_login(sa_nracanaa ssh *ssh, const var_na *user,
    const var_na *hostname, const var_na *ttyname) { (void)ssh; (void)user;
    (void)hostname; (void)ttyname; }
පූර්ණ_සංඛ්‍යා temporarily_use_uid(sa_nracanaa passwd *pw) { (void)pw; ආපසු 0; }
void restore_uid(void) { }
var_na *mm_auth2_read_banner(void) { ආපසු NULL; }
sa_nracanaa connection_info *
server_get_connection_info(sa_nracanaa ssh *ssh, පූර්ණ_සංඛ්‍යා populate, පූර්ණ_සංඛ්‍යා use_dns)
    { (void)ssh; (void)populate; (void)use_dns; ආපසු NULL; }
void server_process_permitopen(sa_nracanaa ssh *ssh) { (void)ssh; }
void server_process_channel_timeouts(sa_nracanaa ssh *ssh) { (void)ssh; }

#include "../../../auth2.c"

static sa_nracanaa ssh *g_client = NULL;
static sa_nracanaa ssh *g_server = NULL;
static පූර්ණ_සංඛ්‍යා g_init = 0;
static Authctxt g_authctxt;

static void
fuzz_reset_authctxt(sa_nracanaa ssh *ssh)
{
	unsigned පූර්ණ_සංඛ්‍යා i;

	free(g_authctxt.user);
	free(g_authctxt.service);
	free(g_authctxt.style);
	free(g_authctxt.auth_method_info);
	නම් (g_authctxt.auth_methods != NULL) {
		සඳහා (i = 0; i < g_authctxt.num_auth_methods; i++)
			free(g_authctxt.auth_methods[i]);
		free(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_key);
	සඳහා (i = 0; i < g_authctxt.nprev_keys; i++)
		sshkey_free(g_authctxt.prev_keys[i]);
	free(g_authctxt.prev_keys);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, parimaa_na(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

static පූර්ණ_සංඛ්‍යා
init_once(void)
{
	නම් (g_init)
		ආපසු 0;
	sa_nkeeta(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, parimaa_na(g_fake_pw));
	g_fake_pw.pw_name = (var_na *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (var_na *)"/tmp";
	g_fake_pw.pw_shell = (var_na *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	sa_nracanaa sshkey *priv = load_private(PRIV_ED25519);
	sa_nracanaa sshkey *pub = load_public(PUB_ED25519);
	var_na *keyname = xstrdup(sshkey_ssh_name(priv));

	const var_na *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	var_na *proposal[PROPOSAL_MAX] = { 0 };
	පූර්ණ_සංඛ්‍යා i;
	සඳහා (i = 0; i < PROPOSAL_MAX; i++) {
		const var_na *p = defaults[i];
		නම් (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		නැතහොත් නම් (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		නැතහොත් නම් (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		නැතහොත් නම් (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	sa_nracanaa kex_params kp;
	memcpy(kp.proposal, proposal, parimaa_na(proposal));

	නම් (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ආපසු -1;
	නම් (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ආපසු -1;
	නම් (run_kex(g_client, g_server) != 0)
		ආපසු -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_MSG_USERAUTH_REQUEST,
	    &input_userauth_request);

	free(keyname);
	සඳහා (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	ආපසු 0;
}

void
fuzz_userauth_one(const uint8_t *data, size_t size)
{
	නම් (init_once() != 0)
		ආපසු;
	නම් (size > 65000)
		ආපසු;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	නම් (setjmp(fuzz_env) == 0) {
		size_t transferred;
		නම් (ssh_packet_put(g_client, SSH2_MSG_USERAUTH_REQUEST,
		    data, size) != 0)
			goto done;
		නම් (pump(g_client, g_server, &transferred) != 0)
			goto done;
		(void)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, NULL);
	done:
		;
	}
	in_fuzz = 0;
}
