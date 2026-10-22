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
 * Helper for session_channel_req_fuzz. Drives the server side of
 * session.c CHANNEL_REQUEST processing via the public
 * session_input_channel_req() entry point. See the .cc driver for
 * the threat-model writeup.
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
#include "auth-options.h"
#include "servconf.h"
#include "channels.h"
#include "session.h"

ServerOptions options;
struct sshbuf *loginmsg = NULL;
struct include_list includes;
static struct sshauthopt g_auth_opts_storage;
struct sshauthopt *auth_opts = &g_auth_opts_storage;
struct passwd *privsep_pw = NULL;

static jmp_buf fuzz_env;
static volatile ціле in_fuzz = 0;

void
cleanup_exit(ціле code)
{
	якщо (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

void
__wrap_ssh_packet_disconnect(struct ssh *ssh, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	якщо (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ціле
__wrap_sshpkt_fatal(struct ssh *ssh, ціле r, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	якщо (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ціле
mm_is_monitor(void)
{
	повернути 0;
}

void
mm_audit_run_command(const char *cmd)
{
	(void)cmd;
}

ціле
mm_pty_allocate(ціле *ptyfd, ціле *ttyfd, char *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	якщо (namebuf != NULL && namebuflen > 0)
		namebuf[0] = '\0';
	повернути 0;
}

void mm_session_pty_cleanup2(Session *s) { (void)s; }
ціле platform_locked_account(struct passwd *pw) { (void)pw; повернути 0; }
void record_failed_login(struct ssh *ssh, const char *user,
    const char *hostname, const char *ttyname) { (void)ssh; (void)user;
    (void)hostname; (void)ttyname; }
ціле temporarily_use_uid(struct passwd *pw) { (void)pw; повернути 0; }
void restore_uid(void) { }
void platform_setusercontext(struct passwd *pw) { (void)pw; }
void platform_setusercontext_post_groups(struct passwd *pw) { (void)pw; }
struct connection_info *
server_get_connection_info(struct ssh *ssh, ціле populate, ціле use_dns)
    { (void)ssh; (void)populate; (void)use_dns; повернути NULL; }
ціле auth2_methods_valid(const char *list, ціле allow_unknown)
    { (void)list; (void)allow_unknown; повернути 0; }
struct sshbuf *cfg = NULL;
ціле auth_sock = -1;
char **tun_fwd_ifnames = NULL;

struct logininfo *login_get_lastlog(struct logininfo *li, const uid_t uid)
    { (void)li; (void)uid; повернути NULL; }
struct logininfo *login_alloc_entry(pid_t pid, const char *username,
    const char *hostname, const char *line)
    { (void)pid; (void)username; (void)hostname; (void)line; повернути NULL; }
void server_process_permitopen(struct ssh *ssh) { (void)ssh; }
void server_process_channel_timeouts(struct ssh *ssh) { (void)ssh; }
ціле server_loop2(struct ssh *ssh, Authctxt *authctxt)
    { (void)ssh; (void)authctxt; повернути 0; }
ціле platform_privileged_uidswap(void) { повернути 0; }
ціле sftp_server_main(ціле argc, char **argv, struct passwd *user_pw)
    { (void)argc; (void)argv; (void)user_pw; повернути 0; }
ціле debug_flag = 0;
void permanently_set_uid(struct passwd *pw) { (void)pw; }
ціле login_login(struct logininfo *li) { (void)li; повернути 0; }
ціле login_logout(struct logininfo *li) { (void)li; повернути 0; }
void login_free_entry(struct logininfo *li) { (void)li; }
void login_set_addr(struct logininfo *li, const struct sockaddr *sa,
    const unsigned ціле sa_size) { (void)li; (void)sa; (void)sa_size; }
ціле openpty(ціле *amaster, ціле *aslave, char *name,
    const struct termios *termp, const struct winsize *winp)
    { (void)termp; (void)winp; *amaster = -1; *aslave = -1;
    якщо (name) name[0] = '\0'; повернути -1; }

extern ціле __real_do_exec(struct ssh *, Session *, const char *);
extern ціле __real_do_exec_pty(struct ssh *, Session *, const char *);
extern ціле __real_do_exec_no_pty(struct ssh *, Session *, const char *);

ціле
__wrap_do_exec(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	повернути 0;
}

ціле
__wrap_do_exec_pty(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	повернути 0;
}

ціле
__wrap_do_exec_no_pty(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	повернути 0;
}

static struct sshkey *
load_private(const char *str)
{
	struct sshbuf *b = sshbuf_from(str, strlen(str));
	struct sshkey *k = NULL;
	якщо (b == NULL || sshkey_parse_private_fileblob(b, "", &k, NULL) != 0)
		abort();
	sshbuf_free(b);
	повернути k;
}

static struct sshkey *
load_public(const char *str)
{
	char *tmp, *cp;
	struct sshkey *k = sshkey_new(KEY_UNSPEC);
	якщо (k == NULL)
		abort();
	tmp = cp = strdup(str);
	якщо (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	повернути k;
}

static ціле
pump(struct ssh *from, struct ssh *to, size_t *transferred)
{
	const u_char *buf;
	size_t len;
	u_char type;
	ціле r;
	*transferred = 0;
	якщо ((r = ssh_packet_next(from, &type)) != 0)
		повернути r;
	buf = ssh_output_ptr(from, &len);
	якщо (len == 0)
		повернути 0;
	якщо ((r = ssh_input_append(to, buf, len)) != 0)
		повернути r;
	якщо ((r = ssh_output_consume(from, len)) != 0)
		повернути r;
	*transferred = len;
	повернути 0;
}

static ціле
run_kex(struct ssh *client, struct ssh *server)
{
	ціле r;
	size_t cn, sn;
	для (ціле i = 0; i < 100; i++) {
		якщо ((r = pump(server, client, &sn)) != 0) повернути r;
		якщо ((r = pump(client, server, &cn)) != 0) повернути r;
		якщо (server->kex->done && client->kex->done)
			повернути 0;
		якщо (cn == 0 && sn == 0)
			повернути SSH_ERR_PROTOCOL_ERROR;
	}
	повернути SSH_ERR_PROTOCOL_ERROR;
}

#include "fixed-keys.h"

static struct ssh *g_client = NULL;
static struct ssh *g_server = NULL;
static ціле g_init = 0;
static ціле g_channel_id = -1;
static Authctxt g_authctxt;
static struct passwd g_fake_pw;

static char *g_pending_rtype = NULL;
static char *g_pending_exec_cmd = NULL;
static char *g_pending_env_name = NULL;
static char *g_pending_env_val = NULL;

static void
my_session_exec_req(struct ssh *ssh)
{
	ціле r;
	якщо ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static void
my_session_env_req(struct ssh *ssh)
{
	ціле r;
	якщо ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static ціле
input_channel_request(ціле type, uint32_t seq, struct ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(void)type;
	(void)seq;
	якщо (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, NULL) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		повернути 0;
	якщо (g_channel_id >= 0 && g_pending_rtype != NULL) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		якщо (c != NULL) {
			якщо (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			інакше якщо (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			інакше
				(void)session_input_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	повернути 0;
}

static void
reset_channel(struct ssh *ssh)
{
	якщо (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		якщо (c != NULL)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (char *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (char *)"fuzz", 0);
	якщо (c == NULL)
		повернути;
	g_channel_id = c->self;
	Session *s = session_new();
	якщо (s != NULL) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

static ціле
init_once(void)
{
	якщо (g_init)
		повернути 0;
	signal(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
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

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, sizeof(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	struct sshkey *priv = load_private(PRIV_ED25519);
	struct sshkey *pub = load_public(PUB_ED25519);
	char *keyname = xstrdup(sshkey_ssh_name(priv));

	const char *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	char *proposal[PROPOSAL_MAX] = { 0 };
	ціле i;
	для (i = 0; i < PROPOSAL_MAX; i++) {
		const char *p = defaults[i];
		якщо (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		інакше якщо (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		інакше якщо (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		інакше якщо (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	struct kex_params kp;
	memcpy(kp.proposal, proposal, sizeof(proposal));

	якщо (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		повернути -1;
	якщо (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		повернути -1;
	якщо (run_kex(g_client, g_server) != 0)
		повернути -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_MSG_CHANNEL_REQUEST,
	    &input_channel_request);

	free(keyname);
	для (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	повернути 0;
}

void
fuzz_session_one(const uint8_t *data, size_t size)
{
	якщо (init_once() != 0)
		повернути;
	якщо (size > 65000)
		повернути;

	reset_channel(g_server);

	in_fuzz = 1;
	якщо (setjmp(fuzz_env) == 0) {
		size_t transferred;
		якщо (ssh_packet_put(g_client, SSH2_MSG_CHANNEL_REQUEST,
		    data, size) != 0)
			goto done;
		якщо (pump(g_client, g_server, &transferred) != 0)
			goto done;
		(void)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, NULL);
	done:
		;
	}
	in_fuzz = 0;
	free(g_pending_rtype);
	g_pending_rtype = NULL;
	free(g_pending_exec_cmd);
	g_pending_exec_cmd = NULL;
	free(g_pending_env_name);
	g_pending_env_name = NULL;
	free(g_pending_env_val);
	g_pending_env_val = NULL;
}
