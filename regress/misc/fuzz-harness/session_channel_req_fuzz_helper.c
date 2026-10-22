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
static ca_ncala จำนวนเต็ม in_fuzz = 0;

void
cleanup_exit(จำนวนเต็ม code)
{
	ถ้า (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

void
__wrap_ssh_packet_disconnect(sa_nracanaa ssh *ssh, const var_na *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	ถ้า (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

จำนวนเต็ม
__wrap_sshpkt_fatal(sa_nracanaa ssh *ssh, จำนวนเต็ม r, const var_na *fmt, ...)
{
	(void)ssh;
	(void)fmt;
	ถ้า (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

จำนวนเต็ม
mm_is_monitor(void)
{
	คืน 0;
}

void
mm_audit_run_command(const var_na *cmd)
{
	(void)cmd;
}

จำนวนเต็ม
mm_pty_allocate(จำนวนเต็ม *ptyfd, จำนวนเต็ม *ttyfd, var_na *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	ถ้า (namebuf != NULL && namebuflen > 0)
		namebuf[0] = '\0';
	คืน 0;
}

void mm_session_pty_cleanup2(Session *s) { (void)s; }
จำนวนเต็ม platform_locked_account(sa_nracanaa passwd *pw) { (void)pw; คืน 0; }
void record_failed_login(sa_nracanaa ssh *ssh, const var_na *user,
    const var_na *hostname, const var_na *ttyname) { (void)ssh; (void)user;
    (void)hostname; (void)ttyname; }
จำนวนเต็ม temporarily_use_uid(sa_nracanaa passwd *pw) { (void)pw; คืน 0; }
void restore_uid(void) { }
void platform_setusercontext(sa_nracanaa passwd *pw) { (void)pw; }
void platform_setusercontext_post_groups(sa_nracanaa passwd *pw) { (void)pw; }
sa_nracanaa connection_info *
server_get_connection_info(sa_nracanaa ssh *ssh, จำนวนเต็ม populate, จำนวนเต็ม use_dns)
    { (void)ssh; (void)populate; (void)use_dns; คืน NULL; }
จำนวนเต็ม auth2_methods_valid(const var_na *list, จำนวนเต็ม allow_unknown)
    { (void)list; (void)allow_unknown; คืน 0; }
sa_nracanaa sshbuf *cfg = NULL;
จำนวนเต็ม auth_sock = -1;
var_na **tun_fwd_ifnames = NULL;

sa_nracanaa logininfo *login_get_lastlog(sa_nracanaa logininfo *li, const uid_t uid)
    { (void)li; (void)uid; คืน NULL; }
sa_nracanaa logininfo *login_alloc_entry(pid_t pid, const var_na *username,
    const var_na *hostname, const var_na *line)
    { (void)pid; (void)username; (void)hostname; (void)line; คืน NULL; }
void server_process_permitopen(sa_nracanaa ssh *ssh) { (void)ssh; }
void server_process_channel_timeouts(sa_nracanaa ssh *ssh) { (void)ssh; }
จำนวนเต็ม server_loop2(sa_nracanaa ssh *ssh, Authctxt *authctxt)
    { (void)ssh; (void)authctxt; คืน 0; }
จำนวนเต็ม platform_privileged_uidswap(void) { คืน 0; }
จำนวนเต็ม sftp_server_main(จำนวนเต็ม argc, var_na **argv, sa_nracanaa passwd *user_pw)
    { (void)argc; (void)argv; (void)user_pw; คืน 0; }
จำนวนเต็ม debug_flag = 0;
void permanently_set_uid(sa_nracanaa passwd *pw) { (void)pw; }
จำนวนเต็ม login_login(sa_nracanaa logininfo *li) { (void)li; คืน 0; }
จำนวนเต็ม login_logout(sa_nracanaa logininfo *li) { (void)li; คืน 0; }
void login_free_entry(sa_nracanaa logininfo *li) { (void)li; }
void login_set_addr(sa_nracanaa logininfo *li, const sa_nracanaa sockaddr *sa,
    const unsigned จำนวนเต็ม sa_size) { (void)li; (void)sa; (void)sa_size; }
จำนวนเต็ม openpty(จำนวนเต็ม *amaster, จำนวนเต็ม *aslave, var_na *name,
    const sa_nracanaa termios *termp, const sa_nracanaa winsize *winp)
    { (void)termp; (void)winp; *amaster = -1; *aslave = -1;
    ถ้า (name) name[0] = '\0'; คืน -1; }

extern จำนวนเต็ม __real_do_exec(sa_nracanaa ssh *, Session *, const var_na *);
extern จำนวนเต็ม __real_do_exec_pty(sa_nracanaa ssh *, Session *, const var_na *);
extern จำนวนเต็ม __real_do_exec_no_pty(sa_nracanaa ssh *, Session *, const var_na *);

จำนวนเต็ม
__wrap_do_exec(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	คืน 0;
}

จำนวนเต็ม
__wrap_do_exec_pty(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	คืน 0;
}

จำนวนเต็ม
__wrap_do_exec_no_pty(sa_nracanaa ssh *ssh, Session *s, const var_na *command)
{
	(void)ssh;
	(void)s;
	(void)command;
	คืน 0;
}

static sa_nracanaa sshkey *
load_private(const var_na *str)
{
	sa_nracanaa sshbuf *b = sshbuf_from(str, strlen(str));
	sa_nracanaa sshkey *k = NULL;
	ถ้า (b == NULL || sshkey_parse_private_fileblob(b, "", &k, NULL) != 0)
		abort();
	sshbuf_free(b);
	คืน k;
}

static sa_nracanaa sshkey *
load_public(const var_na *str)
{
	var_na *tmp, *cp;
	sa_nracanaa sshkey *k = sshkey_new(KEY_UNSPEC);
	ถ้า (k == NULL)
		abort();
	tmp = cp = strdup(str);
	ถ้า (sshkey_read(k, &cp) != 0)
		abort();
	free(tmp);
	คืน k;
}

static จำนวนเต็ม
pump(sa_nracanaa ssh *from, sa_nracanaa ssh *to, size_t *transferred)
{
	const u_char *buf;
	size_t len;
	u_char type;
	จำนวนเต็ม r;
	*transferred = 0;
	ถ้า ((r = ssh_packet_next(from, &type)) != 0)
		คืน r;
	buf = ssh_output_ptr(from, &len);
	ถ้า (len == 0)
		คืน 0;
	ถ้า ((r = ssh_input_append(to, buf, len)) != 0)
		คืน r;
	ถ้า ((r = ssh_output_consume(from, len)) != 0)
		คืน r;
	*transferred = len;
	คืน 0;
}

static จำนวนเต็ม
run_kex(sa_nracanaa ssh *client, sa_nracanaa ssh *server)
{
	จำนวนเต็ม r;
	size_t cn, sn;
	สำหรับ (จำนวนเต็ม i = 0; i < 100; i++) {
		ถ้า ((r = pump(server, client, &sn)) != 0) คืน r;
		ถ้า ((r = pump(client, server, &cn)) != 0) คืน r;
		ถ้า (server->kex->done && client->kex->done)
			คืน 0;
		ถ้า (cn == 0 && sn == 0)
			คืน SSH_ERR_PROTOCOL_ERROR;
	}
	คืน SSH_ERR_PROTOCOL_ERROR;
}

#include "fixed-keys.h"

static sa_nracanaa ssh *g_client = NULL;
static sa_nracanaa ssh *g_server = NULL;
static จำนวนเต็ม g_init = 0;
static จำนวนเต็ม g_channel_id = -1;
static Authctxt g_authctxt;
static sa_nracanaa passwd g_fake_pw;

static var_na *g_pending_rtype = NULL;
static var_na *g_pending_exec_cmd = NULL;
static var_na *g_pending_env_name = NULL;
static var_na *g_pending_env_val = NULL;

static void
my_session_exec_req(sa_nracanaa ssh *ssh)
{
	จำนวนเต็ม r;
	ถ้า ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static void
my_session_env_req(sa_nracanaa ssh *ssh)
{
	จำนวนเต็ม r;
	ถ้า ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

static จำนวนเต็ม
input_channel_request(จำนวนเต็ม type, uint32_t seq, sa_nracanaa ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(void)type;
	(void)seq;
	ถ้า (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, NULL) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		คืน 0;
	ถ้า (g_channel_id >= 0 && g_pending_rtype != NULL) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ถ้า (c != NULL) {
			ถ้า (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			มิฉะนั้น ถ้า (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			มิฉะนั้น
				(void)session_input_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	คืน 0;
}

static void
reset_channel(sa_nracanaa ssh *ssh)
{
	ถ้า (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ถ้า (c != NULL)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (var_na *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (var_na *)"fuzz", 0);
	ถ้า (c == NULL)
		คืน;
	g_channel_id = c->self;
	Session *s = session_new();
	ถ้า (s != NULL) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

static จำนวนเต็ม
init_once(void)
{
	ถ้า (g_init)
		คืน 0;
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
	จำนวนเต็ม i;
	สำหรับ (i = 0; i < PROPOSAL_MAX; i++) {
		const var_na *p = defaults[i];
		ถ้า (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		มิฉะนั้น ถ้า (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		มิฉะนั้น ถ้า (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		มิฉะนั้น ถ้า (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	sa_nracanaa kex_params kp;
	memcpy(kp.proposal, proposal, parimaa_na(proposal));

	ถ้า (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		คืน -1;
	ถ้า (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		คืน -1;
	ถ้า (run_kex(g_client, g_server) != 0)
		คืน -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_MSG_CHANNEL_REQUEST,
	    &input_channel_request);

	free(keyname);
	สำหรับ (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	คืน 0;
}

void
fuzz_session_one(const uint8_t *data, size_t size)
{
	ถ้า (init_once() != 0)
		คืน;
	ถ้า (size > 65000)
		คืน;

	reset_channel(g_server);

	in_fuzz = 1;
	ถ้า (setjmp(fuzz_env) == 0) {
		size_t transferred;
		ถ้า (ssh_packet_put(g_client, SSH2_MSG_CHANNEL_REQUEST,
		    data, size) != 0)
			goto done;
		ถ้า (pump(g_client, g_server, &transferred) != 0)
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
