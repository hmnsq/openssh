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
struct sshbuf *loginmsg = NULL;
struct include_list includes;
struct sshauthopt *auth_opts = NULL;
struct passwd *privsep_pw = NULL;

static jmp_buf fuzz_env;
static volatile số_nguyên in_fuzz = 0;

void
cleanup_exit(số_nguyên code)
{
	nếu (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

số_nguyên
__wrap_ssh_packet_write_wait(struct ssh *ssh)
{
	(void)ssh;
	trả_về 0;
}

static struct passwd g_fake_pw;

số_nguyên
mm_is_monitor(void)
{
	trả_về 0;
}

struct passwd *
mm_getpwnamallow(struct ssh *ssh, const char *user)
{
	(void)ssh;
	(void)user;
	trả_về &g_fake_pw;
}

số_nguyên
mm_auth_password(struct ssh *ssh, char *password)
{
	(void)ssh;
	(void)password;
	trả_về 0;
}

số_nguyên
mm_user_key_allowed(struct ssh *ssh, struct passwd *pw, struct sshkey *key,
    số_nguyên auth_attempt, struct sshauthopt **authoptsp)
{
	(void)ssh;
	(void)pw;
	(void)key;
	(void)auth_attempt;
	(void)authoptsp;
	trả_về 0;
}

số_nguyên
mm_hostbased_key_allowed(struct ssh *ssh, struct passwd *pw, const char *user,
    const char *host, struct sshkey *key)
{
	(void)ssh;
	(void)pw;
	(void)user;
	(void)host;
	(void)key;
	trả_về 0;
}

số_nguyên
mm_sshkey_verify(const struct sshkey *key, const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	trả_về sshkey_verify(key, sig, siglen, data, datalen, alg, compat,
	    detailsp);
}

void
mm_inform_authserv(char *service, char *style)
{
	(void)service;
	(void)style;
}

void
mm_audit_event(struct ssh *ssh, ssh_audit_event_t event)
{
	(void)ssh;
	(void)event;
}

void
mm_start_pam(struct ssh *ssh)
{
	(void)ssh;
}

số_nguyên
mm_do_pam_account(void)
{
	trả_về 0;
}

static struct sshkey *
load_private(const char *str)
{
	struct sshbuf *b = sshbuf_from(str, strlen(str));
	struct sshkey *k = NULL;
	nếu (b == NULL || sshkey_parse_private_fileblob(b, "", &k, NULL) != 0)
		abort();
	sshbuf_free(b);
	trả_về k;
}

static struct sshkey *
load_public(const char *str)
{
	char *tmp, *cp;
	struct sshkey *k = sshkey_new(KEY_UNSPEC);
	nếu (k == NULL)
		abort();
	tmp = cp = strdup(str);
	nếu (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	trả_về k;
}

static số_nguyên
pump(struct ssh *from, struct ssh *to, size_t *transferred)
{
	const u_char *buf;
	size_t len;
	u_char type;
	số_nguyên r;
	*transferred = 0;
	nếu ((r = ssh_packet_next(from, &type)) != 0)
		trả_về r;
	buf = ssh_output_ptr(from, &len);
	nếu (len == 0)
		trả_về 0;
	nếu ((r = ssh_input_append(to, buf, len)) != 0)
		trả_về r;
	nếu ((r = ssh_output_consume(from, len)) != 0)
		trả_về r;
	*transferred = len;
	trả_về 0;
}

static số_nguyên
run_kex(struct ssh *client, struct ssh *server)
{
	số_nguyên r;
	size_t cn, sn;
	cho (số_nguyên i = 0; i < 100; i++) {
		nếu ((r = pump(server, client, &sn)) != 0) trả_về r;
		nếu ((r = pump(client, server, &cn)) != 0) trả_về r;
		nếu (server->kex->done && client->kex->done)
			trả_về 0;
		nếu (cn == 0 && sn == 0)
			trả_về SSH_ERR_PROTOCOL_ERROR;
	}
	trả_về SSH_ERR_PROTOCOL_ERROR;
}

#include "fixed-keys.h"

struct sshbuf *cfg = NULL;

số_nguyên auth_rhosts2(struct passwd *pw, const char *client_user,
    const char *hostname, const char *ipaddr) { (void)pw;
    (void)client_user; (void)hostname; (void)ipaddr; trả_về 0; }
số_nguyên platform_locked_account(struct passwd *pw) { (void)pw; trả_về 0; }
void record_failed_login(struct ssh *ssh, const char *user,
    const char *hostname, const char *ttyname) { (void)ssh; (void)user;
    (void)hostname; (void)ttyname; }
số_nguyên temporarily_use_uid(struct passwd *pw) { (void)pw; trả_về 0; }
void restore_uid(void) { }
char *mm_auth2_read_banner(void) { trả_về NULL; }
struct connection_info *
server_get_connection_info(struct ssh *ssh, số_nguyên populate, số_nguyên use_dns)
    { (void)ssh; (void)populate; (void)use_dns; trả_về NULL; }
void server_process_permitopen(struct ssh *ssh) { (void)ssh; }
void server_process_channel_timeouts(struct ssh *ssh) { (void)ssh; }

#include "../../../auth2.c"

static struct ssh *g_client = NULL;
static struct ssh *g_server = NULL;
static số_nguyên g_init = 0;
static Authctxt g_authctxt;

static void
fuzz_reset_authctxt(struct ssh *ssh)
{
	unsigned số_nguyên i;

	free(g_authctxt.user);
	free(g_authctxt.service);
	free(g_authctxt.style);
	free(g_authctxt.auth_method_info);
	nếu (g_authctxt.auth_methods != NULL) {
		cho (i = 0; i < g_authctxt.num_auth_methods; i++)
			free(g_authctxt.auth_methods[i]);
		free(g_authctxt.auth_methods);
	}
	sshkey_free(g_authctxt.auth_method_key);
	cho (i = 0; i < g_authctxt.nprev_keys; i++)
		sshkey_free(g_authctxt.prev_keys[i]);
	free(g_authctxt.prev_keys);
	sshbuf_free(g_authctxt.session_info);
	memset(&g_authctxt, 0, sizeof(g_authctxt));
	ssh->authctxt = &g_authctxt;
}

static số_nguyên
init_once(void)
{
	nếu (g_init)
		trả_về 0;
	signal(SIGPIPE, SIG_IGN);
	log_init("sshd_auth_session_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, sizeof(g_fake_pw));
	g_fake_pw.pw_name = (char *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (char *)"/tmp";
	g_fake_pw.pw_shell = (char *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);
	options.password_authentication = 1;
	options.pubkey_authentication = 1;
	options.kbd_interactive_authentication = 1;
	options.hostbased_authentication = 1;
	options.max_authtries = 1024;

	loginmsg = sshbuf_new();

	struct sshkey *priv = load_private(PRIV_ED25519);
	struct sshkey *pub = load_public(PUB_ED25519);
	char *keyname = xstrdup(sshkey_ssh_name(priv));

	const char *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	char *proposal[PROPOSAL_MAX] = { 0 };
	số_nguyên i;
	cho (i = 0; i < PROPOSAL_MAX; i++) {
		const char *p = defaults[i];
		nếu (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		không_thì nếu (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		không_thì nếu (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		không_thì nếu (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	struct kex_params kp;
	memcpy(kp.proposal, proposal, sizeof(proposal));

	nếu (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		trả_về -1;
	nếu (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		trả_về -1;
	nếu (run_kex(g_client, g_server) != 0)
		trả_về -1;

	fuzz_reset_authctxt(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_MSG_USERAUTH_REQUEST,
	    &input_userauth_request);

	free(keyname);
	cho (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	trả_về 0;
}

void
fuzz_userauth_one(const uint8_t *data, size_t size)
{
	nếu (init_once() != 0)
		trả_về;
	nếu (size > 65000)
		trả_về;

	fuzz_reset_authctxt(g_server);

	in_fuzz = 1;
	nếu (setjmp(fuzz_env) == 0) {
		size_t transferred;
		nếu (ssh_packet_put(g_client, SSH2_MSG_USERAUTH_REQUEST,
		    data, size) != 0)
			goto done;
		nếu (pump(g_client, g_server, &transferred) != 0)
			goto done;
		(void)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, NULL);
	done:
		;
	}
	in_fuzz = 0;
}
