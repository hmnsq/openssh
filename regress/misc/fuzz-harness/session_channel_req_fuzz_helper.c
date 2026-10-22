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
sa_nracanaa sshbuf *loginmsg = NULL;
sa_nracanaa include_list includes;
static sa_nracanaa sshauthopt g_auth_opts_storage;
sa_nracanaa sshauthopt *auth_opts = &g_auth_opts_storage;
sa_nracanaa passwd *privsep_pw = NULL;

static jmp_buf fuzz_env;
static ca_ncala ཧྲིལ in_fuzz = 0;

void
cleanup_exit(ཧྲིལ code)
{
	གལ་སྲིད (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

void
__wrap_ssh_packet_disconnect(sa_nracanaa ssh *ssh, const var_na *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	གལ་སྲིད (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ཧྲིལ
__wrap_sshpkt_fatal(sa_nracanaa ssh *ssh, ཧྲིལ r, const var_na *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	གལ་སྲིད (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ཧྲིལ
mm_is_monitor(void)
{
	ལོག 0;
}

void
mm_audit_run_command(const var_na *cmd)
{
	(void)cmd;
}

ཧྲིལ
mm_pty_allocate(ཧྲིལ *ptyfd, ཧྲིལ *ttyfd, var_na *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	གལ་སྲིད (namebuf != NULL && namebuflen > 0)
		namebuf[0] = '\0';
	ལོག 0;
}

void mm_session_pty_cleanup2(Session *s) { (void)s; }
ཧྲིལ platform_locked_account(sa_nracanaa passwd *pw) { (void)pw; ལོག 0; }
void record_failed_login(sa_nracanaa ssh *ssh, const var_na *user,
    const var_na *hostname, const var_na *ttyname) { (void)ssh; (void)user;
    (void)hostname; (void)ttyname; }
ཧྲིལ temporarily_use_uid(sa_nracanaa passwd *pw) { (void)pw; ལོག 0; }
void restore_uid(void) { }
void platform_setusercontext(sa_nracanaa passwd *pw) { (void)pw; }
void platform_setusercontext_post_groups(sa_nracanaa passwd *pw) { (void)pw; }
sa_nracanaa connection_info *
server_get_connection_info(sa_nracanaa ssh *ssh, ཧྲིལ populate, ཧྲིལ use_dns)
    { (void)ssh; (void)populate; (void)use_dns; ལོག NULL; }
ཧྲིལ auth2_methods_valid(const var_na *list, ཧྲིལ allow_unknown)
    { (void)list; (void)allow_unknown; ལོག 0; }
sa_nracanaa sshbuf *cfg = NULL;
ཧྲིལ auth_sock = -1;
var_na **tun_fwd_ifnames = NULL;

sa_nracanaa logininfo *login_get_lastlog(sa_nracanaa logininfo *li, const uid_t uid)
    { (void)li; (void)uid; ལོག NULL; }
sa_nracanaa logininfo *login_alloc_entry(pid_t pid, const var_na *username,
    const var_na *hostname, const var_na *line)
    { (void)pid; (void)username; (void)hostname; (void)line; ལོག NULL; }
void server_process_permitopen(sa_nracanaa ssh *ssh) { (void)ssh; }
void server_process_channel_timeouts(sa_nracanaa ssh *ssh) { (void)ssh; }
ཧྲིལ server_loop2(sa_nracanaa ssh *ssh, Authctxt *authctxt)
    { (void)ssh; (void)authctxt; ལོག 0; }
ཧྲིལ platform_privileged_uidswap(void) { ལོག 0; }
ཧྲིལ sftp_server_main(ཧྲིལ argc, var_na **argv, sa_nracanaa passwd *user_pw)
    { (void)argc; (void)argv; (void)user_pw; ལོག 0; }
ཧྲིལ debug_flag = 0;
void permanently_set_uid(sa_nracanaa passwd *pw) { (void)pw; }
ཧྲིལ login_login(sa_nracanaa logininfo *li) { (void)li; ལོག 0; }
ཧྲིལ login_logout(sa_nracanaa logininfo *li) { (void)li; ལོག 0; }
void login_free_entry(sa_nracanaa logininfo *li) { (void)li; }
void login_set_addr(sa_nracanaa logininfo *li, const sa_nracanaa sockaddr *sa,
    const unsigned ཧྲིལ sa_size) { (void)li; (void)sa; (void)sa_size; }
ཧྲིལ openpty(ཧྲིལ *amaster, ཧྲིལ *aslave, var_na *name,
    const sa_nracanaa termios *termp, const sa_nracanaa winsize *winp)
    { (void)termp; (void)winp; *amaster = -1; *aslave = -1;
    གལ་སྲིད (name) name[0] = '\0'; ལོག -1; }

extern ཧྲིལ __real_do_exec(sa_nracanaa ssh *, Session *, const var_na *);
extern ཧྲིལ __real_do_exec_pty(sa_nracanaa ssh *, Session *, const var_na *);
extern ཧྲིལ __real_do_exec_no_pty(sa_nracanaa ssh *, Session *, const var_na *);

ཧྲིལ
__wrap_do_exec(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	ལོག 0;
}

ཧྲིལ
__wrap_do_exec_pty(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	ལོག 0;
}

ཧྲིལ
__wrap_do_exec_no_pty(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	ལོག 0;
}

static sa_nracanaa sshkey *
load_private(const var_na *str)
{
	sa_nracanaa sshbuf *b = sshbuf_from(str, strlen(str));
	sa_nracanaa sshkey *k = NULL;
	གལ་སྲིད (b == NULL || sshkey_parse_private_fileblob(b, "", &k, NULL) != 0)
		abort();
	sshbuf_free(b);
	ལོག k;
}

static sa_nracanaa sshkey *
load_public(const var_na *str)
{
	var_na *tmp, *cp;
	sa_nracanaa sshkey *k = sshkey_new(KEY_UNSPEC);
	གལ་སྲིད (k == NULL)
		abort();
	tmp = cp = strdup(str);
	གལ་སྲིད (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	ལོག k;
}

static ཧྲིལ
pump(sa_nracanaa ssh *from, sa_nracanaa ssh *to, size_t *transferred)
{
	const u_char *buf;
	size_t len;
	u_char type;
	ཧྲིལ r;
	*transferred = 0;
	གལ་སྲིད ((r = ssh_packet_next(from, &type)) != 0)
		ལོག r;
	buf = ssh_output_ptr(from, &len);
	གལ་སྲིད (len == 0)
		ལོག 0;
	གལ་སྲིད ((r = ssh_input_append(to, buf, len)) != 0)
		ལོག r;
	གལ་སྲིད ((r = ssh_output_consume(from, len)) != 0)
		ལོག r;
	*transferred = len;
	ལོག 0;
}

static ཧྲིལ
run_kex(sa_nracanaa ssh *client, sa_nracanaa ssh *server)
{
	ཧྲིལ r;
	size_t cn, sn;
	དོན་ལུ (ཧྲིལ i = 0; i < 100; i++) {
		གལ་སྲིད ((r = pump(server, client, &sn)) != 0) ལོག r;
		གལ་སྲིད ((r = pump(client, server, &cn)) != 0) ལོག r;
		གལ་སྲིད (server->kex->done && client->kex->done)
			ལོག 0;
		གལ་སྲིད (cn == 0 && sn == 0)
			ལོག SSH_ERR_PROTOCOL_ERROR;
	}
	ལོག SSH_ERR_PROTOCOL_ERROR;
}

#include "fixed-keys.h"

static sa_nracanaa ssh *g_client = NULL;
static sa_nracanaa ssh *g_server = NULL;
static ཧྲིལ g_init = 0;
static ཧྲིལ g_channel_id = -1;
static Authctxt g_authctxt;
static sa_nracanaa passwd g_fake_pw;

static var_na *g_pending_rtype = NULL;
static var_na *g_pending_exec_cmd = NULL;
static var_na *g_pending_env_name = NULL;
static var_na *g_pending_env_val = NULL;

static void
my_session_exec_req(sa_nracanaa ssh *ssh)
{
	ཧྲིལ r;
	གལ་སྲིད ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static void
my_session_env_req(sa_nracanaa ssh *ssh)
{
	ཧྲིལ r;
	གལ་སྲིད ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static ཧྲིལ
input_channel_request(ཧྲིལ type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(void)type;
	(void)seq;
	གལ་སྲིད (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, NULL) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		ལོག 0;
	གལ་སྲིད (g_channel_id >= 0 && g_pending_rtype != NULL) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		གལ་སྲིད (c != NULL) {
			གལ་སྲིད (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			དེ་མིན གལ་སྲིད (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			དེ་མིན
				(void)session_input_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	ལོག 0;
}

static void
reset_channel(sa_nracanaa ssh *ssh)
{
	གལ་སྲིད (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		གལ་སྲིད (c != NULL)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (var_na *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (var_na *)"fuzz", 0);
	གལ་སྲིད (c == NULL)
		ལོག;
	g_channel_id = c->self;
	Session *s = session_new();
	གལ་སྲིད (s != NULL) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

static ཧྲིལ
init_once(void)
{
	གལ་སྲིད (g_init)
		ལོག 0;
	sa_nkeeta(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
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

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, parimaa_na(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	sa_nracanaa sshkey *priv = load_private(PRIV_ED25519);
	sa_nracanaa sshkey *pub = load_public(PUB_ED25519);
	var_na *keyname = xstrdup(sshkey_ssh_name(priv));

	const var_na *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	var_na *proposal[PROPOSAL_MAX] = { 0 };
	ཧྲིལ i;
	དོན་ལུ (i = 0; i < PROPOSAL_MAX; i++) {
		const var_na *p = defaults[i];
		གལ་སྲིད (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		དེ་མིན གལ་སྲིད (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		དེ་མིན གལ་སྲིད (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		དེ་མིན གལ་སྲིད (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	sa_nracanaa kex_params kp;
	memcpy(kp.proposal, proposal, parimaa_na(proposal));

	གལ་སྲིད (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ལོག -1;
	གལ་སྲིད (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ལོག -1;
	གལ་སྲིད (run_kex(g_client, g_server) != 0)
		ལོག -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_MSG_CHANNEL_REQUEST,
	    &input_channel_request);

	free(keyname);
	དོན་ལུ (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	ལོག 0;
}

void
fuzz_session_one(const uint8_t *data, size_t size)
{
	གལ་སྲིད (init_once() != 0)
		ལོག;
	གལ་སྲིད (size > 65000)
		ལོག;

	reset_channel(g_server);

	in_fuzz = 1;
	གལ་སྲིད (setjmp(fuzz_env) == 0) {
		size_t transferred;
		གལ་སྲིད (ssh_packet_put(g_client, SSH2_MSG_CHANNEL_REQUEST,
		    data, size) != 0)
			goto done;
		གལ་སྲིད (pump(g_client, g_server, &transferred) != 0)
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
