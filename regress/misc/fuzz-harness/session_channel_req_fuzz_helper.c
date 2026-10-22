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
static volatile целое in_fuzz = 0;

void
cleanup_exit(целое code)
{
	если (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

void
__wrap_ssh_packet_disconnect(struct ssh *ssh, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	если (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

целое
__wrap_sshpkt_fatal(struct ssh *ssh, целое r, const char *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	если (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

целое
mm_is_monitor(void)
{
	вернуть 0;
}

void
mm_audit_run_command(const char *cmd)
{
	(void)cmd;
}

целое
mm_pty_allocate(целое *ptyfd, целое *ttyfd, char *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	если (namebuf != NULL && namebuflen > 0)
		namebuf[0] = '\0';
	вернуть 0;
}

void mm_session_pty_cleanup2(Session *s) { (void)s; }
целое platform_locked_account(struct passwd *pw) { (void)pw; вернуть 0; }
void record_failed_login(struct ssh *ssh, const char *user,
    const char *hostname, const char *ttyname) { (void)ssh; (void)user;
    (void)hostname; (void)ttyname; }
целое temporarily_use_uid(struct passwd *pw) { (void)pw; вернуть 0; }
void restore_uid(void) { }
void platform_setusercontext(struct passwd *pw) { (void)pw; }
void platform_setusercontext_post_groups(struct passwd *pw) { (void)pw; }
struct connection_info *
server_get_connection_info(struct ssh *ssh, целое populate, целое use_dns)
    { (void)ssh; (void)populate; (void)use_dns; вернуть NULL; }
целое auth2_methods_valid(const char *list, целое allow_unknown)
    { (void)list; (void)allow_unknown; вернуть 0; }
struct sshbuf *cfg = NULL;
целое auth_sock = -1;
char **tun_fwd_ifnames = NULL;

struct logininfo *login_get_lastlog(struct logininfo *li, const uid_t uid)
    { (void)li; (void)uid; вернуть NULL; }
struct logininfo *login_alloc_entry(pid_t pid, const char *username,
    const char *hostname, const char *line)
    { (void)pid; (void)username; (void)hostname; (void)line; вернуть NULL; }
void server_process_permitopen(struct ssh *ssh) { (void)ssh; }
void server_process_channel_timeouts(struct ssh *ssh) { (void)ssh; }
целое server_loop2(struct ssh *ssh, Authctxt *authctxt)
    { (void)ssh; (void)authctxt; вернуть 0; }
целое platform_privileged_uidswap(void) { вернуть 0; }
целое sftp_server_main(целое argc, char **argv, struct passwd *user_pw)
    { (void)argc; (void)argv; (void)user_pw; вернуть 0; }
целое debug_flag = 0;
void permanently_set_uid(struct passwd *pw) { (void)pw; }
целое login_login(struct logininfo *li) { (void)li; вернуть 0; }
целое login_logout(struct logininfo *li) { (void)li; вернуть 0; }
void login_free_entry(struct logininfo *li) { (void)li; }
void login_set_addr(struct logininfo *li, const struct sockaddr *sa,
    const unsigned целое sa_size) { (void)li; (void)sa; (void)sa_size; }
целое openpty(целое *amaster, целое *aslave, char *name,
    const struct termios *termp, const struct winsize *winp)
    { (void)termp; (void)winp; *amaster = -1; *aslave = -1;
    если (name) name[0] = '\0'; вернуть -1; }

extern целое __real_do_exec(struct ssh *, Session *, const char *);
extern целое __real_do_exec_pty(struct ssh *, Session *, const char *);
extern целое __real_do_exec_no_pty(struct ssh *, Session *, const char *);

целое
__wrap_do_exec(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	вернуть 0;
}

целое
__wrap_do_exec_pty(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	вернуть 0;
}

целое
__wrap_do_exec_no_pty(struct ssh *ssh, Session *s, const char *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	вернуть 0;
}

static struct sshkey *
load_private(const char *str)
{
	struct sshbuf *b = sshbuf_from(str, strlen(str));
	struct sshkey *k = NULL;
	если (b == NULL || sshkey_parse_private_fileblob(b, "", &k, NULL) != 0)
		abort();
	sshbuf_free(b);
	вернуть k;
}

static struct sshkey *
load_public(const char *str)
{
	char *tmp, *cp;
	struct sshkey *k = sshkey_new(KEY_UNSPEC);
	если (k == NULL)
		abort();
	tmp = cp = strdup(str);
	если (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	вернуть k;
}

static целое
pump(struct ssh *from, struct ssh *to, size_t *transferred)
{
	const u_char *buf;
	size_t len;
	u_char type;
	целое r;
	*transferred = 0;
	если ((r = ssh_packet_next(from, &type)) != 0)
		вернуть r;
	buf = ssh_output_ptr(from, &len);
	если (len == 0)
		вернуть 0;
	если ((r = ssh_input_append(to, buf, len)) != 0)
		вернуть r;
	если ((r = ssh_output_consume(from, len)) != 0)
		вернуть r;
	*transferred = len;
	вернуть 0;
}

static целое
run_kex(struct ssh *client, struct ssh *server)
{
	целое r;
	size_t cn, sn;
	для (целое i = 0; i < 100; i++) {
		если ((r = pump(server, client, &sn)) != 0) вернуть r;
		если ((r = pump(client, server, &cn)) != 0) вернуть r;
		если (server->kex->done && client->kex->done)
			вернуть 0;
		если (cn == 0 && sn == 0)
			вернуть SSH_ERR_PROTOCOL_ERROR;
	}
	вернуть SSH_ERR_PROTOCOL_ERROR;
}

#include "fixed-keys.h"

static struct ssh *g_client = NULL;
static struct ssh *g_server = NULL;
static целое g_init = 0;
static целое g_channel_id = -1;
static Authctxt g_authctxt;
static struct passwd g_fake_pw;

static char *g_pending_rtype = NULL;
static char *g_pending_exec_cmd = NULL;
static char *g_pending_env_name = NULL;
static char *g_pending_env_val = NULL;

static void
my_session_exec_req(struct ssh *ssh)
{
	целое r;
	если ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static void
my_session_env_req(struct ssh *ssh)
{
	целое r;
	если ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static целое
input_channel_request(целое type, uint32_t seq, struct ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(void)type;
	(void)seq;
	если (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, NULL) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		вернуть 0;
	если (g_channel_id >= 0 && g_pending_rtype != NULL) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		если (c != NULL) {
			если (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			иначе если (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			иначе
				(void)session_input_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	вернуть 0;
}

static void
reset_channel(struct ssh *ssh)
{
	если (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		если (c != NULL)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (char *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (char *)"fuzz", 0);
	если (c == NULL)
		вернуть;
	g_channel_id = c->self;
	Session *s = session_new();
	если (s != NULL) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

static целое
init_once(void)
{
	если (g_init)
		вернуть 0;
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
	целое i;
	для (i = 0; i < PROPOSAL_MAX; i++) {
		const char *p = defaults[i];
		если (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		иначе если (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		иначе если (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		иначе если (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	struct kex_params kp;
	memcpy(kp.proposal, proposal, sizeof(proposal));

	если (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		вернуть -1;
	если (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		вернуть -1;
	если (run_kex(g_client, g_server) != 0)
		вернуть -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_MSG_CHANNEL_REQUEST,
	    &input_channel_request);

	free(keyname);
	для (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	вернуть 0;
}

void
fuzz_session_one(const uint8_t *data, size_t size)
{
	если (init_once() != 0)
		вернуть;
	если (size > 65000)
		вернуть;

	reset_channel(g_server);

	in_fuzz = 1;
	если (setjmp(fuzz_env) == 0) {
		size_t transferred;
		если (ssh_packet_put(g_client, SSH2_MSG_CHANNEL_REQUEST,
		    data, size) != 0)
			goto done;
		если (pump(g_client, g_server, &transferred) != 0)
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
