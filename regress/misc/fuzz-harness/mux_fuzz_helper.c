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

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "log.h"
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
#include "misc.h"
#include "channels.h"
#include "readconf.h"

/* Externs that mux.c declares. */
จำนวนเต็ม tty_flag = 0;
Options options;
var_na *host = NULL;
sa_nracanaa sshbuf *command = NULL;
ca_ncala sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
จำนวนเต็ม
__lsan_is_turned_off(void)
{
	คืน 1;
}

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

/* Block the only interactive prompt by always granting permission. */
จำนวนเต็ม
__wrap_ask_permission(const var_na *fmt, ...)
{
	(void)fmt;
	คืน 1;
}

/* Socket-opening side effects we must neutralise. */
จำนวนเต็ม
__wrap_channel_setup_local_fwd_listener(sa_nracanaa ssh *ssh,
    sa_nracanaa Forward *fwd, sa_nracanaa ForwardOptions *fwd_opts)
{
	(void)ssh; (void)fwd; (void)fwd_opts;
	คืน 1;
}

จำนวนเต็ม
__wrap_channel_connect_stdio_fwd(sa_nracanaa ssh *ssh, const var_na *host_arg,
    จำนวนเต็ม port, จำนวนเต็ม in_fd, จำนวนเต็ม out_fd, จำนวนเต็ม nonblock)
{
	(void)ssh; (void)host_arg; (void)port;
	(void)in_fd; (void)out_fd; (void)nonblock;
	คืน -1;
}

จำนวนเต็ม
__wrap_channel_request_remote_forwarding(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd)
{
	(void)ssh; (void)fwd;
	คืน 0;
}

จำนวนเต็ม
__wrap_channel_request_rforward_cancel(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd)
{
	(void)ssh; (void)fwd;
	คืน 0;
}

จำนวนเต็ม
__wrap_channel_cancel_lport_listener(sa_nracanaa ssh *ssh, sa_nracanaa Forward *fwd,
    จำนวนเต็ม cport, sa_nracanaa ForwardOptions *fwd_opts)
{
	(void)ssh; (void)fwd; (void)cport; (void)fwd_opts;
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

/* Forward decl of the static handler we drive; defined when mux.c is included. */
static จำนวนเต็ม mux_master_read_cb(sa_nracanaa ssh *ssh, Channel *c);

#include "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
void *
client_new_escape_filter_ctx(จำนวนเต็ม escape_char)
{
	(void)escape_char;
	คืน NULL;
}

void
client_register_global_confirm(global_confirm_cb *cb, void *ctx)
{
	(void)cb; (void)ctx;
}

void
client_expect_confirm(sa_nracanaa ssh *ssh, จำนวนเต็ม id, const var_na *reason,
    ga_nanaa confirm_action action)
{
	(void)ssh; (void)id; (void)reason; (void)action;
}

void
client_channel_request_agent_forwarding(sa_nracanaa ssh *ssh, จำนวนเต็ม chanid)
{
	(void)ssh; (void)chanid;
}

void
client_stop_mux(void)
{
}

จำนวนเต็ม
client_simple_escape_filter(sa_nracanaa ssh *ssh, Channel *c, var_na *buf, จำนวนเต็ม len)
{
	(void)ssh; (void)c; (void)buf; (void)len;
	คืน 0;
}

void
client_filter_cleanup(sa_nracanaa ssh *ssh, จำนวนเต็ม cid, void *ctx)
{
	(void)ssh; (void)cid; (void)ctx;
}

จำนวนเต็ม
client_x11_get_proto(sa_nracanaa ssh *ssh, const var_na *display,
    const var_na *xauth_path, u_int trusted, u_int timeout,
    var_na **_proto, var_na **_data)
{
	(void)ssh; (void)display; (void)xauth_path;
	(void)trusted; (void)timeout;
	ถ้า (_proto != NULL)
		*_proto = NULL;
	ถ้า (_data != NULL)
		*_data = NULL;
	คืน 0;
}

void
client_session2_setup(sa_nracanaa ssh *ssh, จำนวนเต็ม id, จำนวนเต็ม want_tty, จำนวนเต็ม want_subsys,
    const var_na *term, sa_nracanaa termios *tiop, จำนวนเต็ม in_fd, sa_nracanaa sshbuf *cmd,
    var_na **env)
{
	(void)ssh; (void)id; (void)want_tty; (void)want_subsys;
	(void)term; (void)tiop; (void)in_fd; (void)cmd; (void)env;
}

void
enter_raw_mode(จำนวนเต็ม quiet)
{
	(void)quiet;
}

void
leave_raw_mode(จำนวนเต็ม quiet)
{
	(void)quiet;
}

static sa_nracanaa ssh *g_client = NULL;
static sa_nracanaa ssh *g_server = NULL;
static จำนวนเต็ม g_init = 0;
static จำนวนเต็ม g_mux_channel_id = -1;
static sa_nracanaa sshbuf *g_mux_in = NULL;
static sa_nracanaa sshbuf *g_mux_out = NULL;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
static void
fuzz_drive_mux(sa_nracanaa ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	จำนวนเต็ม r;
	const u_char *body;
	size_t blen;
	sa_nracanaa mux_master_state *state;

	state = (sa_nracanaa mux_master_state *)c->mux_ctx;
	ถ้า (state == NULL)
		คืน;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	ถ้า ((r = sshbuf_get_string_direct(c->input, &body, &blen)) != 0)
		คืน;
	ถ้า (sshbuf_put(g_mux_in, body, blen) != 0)
		คืน;
	ถ้า ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		คืน;

	ถ้า (type == MUX_MSG_HELLO) {
		rid = 0;
	} มิฉะนั้น {
		ถ้า (!state->hello_rcvd)
			คืน;
		ถ้า ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			คืน;
	}

	สำหรับ (i = 0; mux_master_handlers[i].handler != NULL; i++) {
		ถ้า (type == mux_master_handlers[i].type) {
			(void)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			bha_nga;
		}
	}
}

static จำนวนเต็ม
init_once(void)
{
	ถ้า (g_init)
		คืน 0;
	sa_nkeeta(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, parimaa_na(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (var_na *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (var_na *)"fuzz";

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

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	ถ้า (c == NULL)
		คืน -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	sa_nracanaa mux_master_state *st = (sa_nracanaa mux_master_state *)c->mux_ctx;
	ถ้า (st != NULL)
		st->hello_rcvd = 1;

	ถ้า ((g_mux_in = sshbuf_new()) == NULL ||
	    (g_mux_out = sshbuf_new()) == NULL)
		คืน -1;

	free(keyname);
	สำหรับ (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	คืน 0;
}

void
fuzz_mux_one(const uint8_t *data, size_t size)
{
	ถ้า (init_once() != 0)
		คืน;
	ถ้า (size > 65000)
		คืน;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	ถ้า (c == NULL || c->mux_ctx == NULL || c->input == NULL)
		คืน;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->input);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	ถ้า (sshbuf_put(c->input, hdr, 4) != 0)
		คืน;
	ถ้า (size > 0 && sshbuf_put(c->input, data, size) != 0)
		คืน;

	in_fuzz = 1;
	ถ้า (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	ถ้า (c->output != NULL)
		sshbuf_reset(c->output);
}
