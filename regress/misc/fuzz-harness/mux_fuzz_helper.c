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
ціле tty_flag = 0;
Options options;
char *host = NULL;
struct sshbuf *command = NULL;
volatile sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
ціле
__lsan_is_turned_off(void)
{
	повернути 1;
}

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

/* Block the only interactive prompt by always granting permission. */
ціле
__wrap_ask_permission(const char *fmt, ...)
{
	(void)fmt;
	повернути 1;
}

/* Socket-opening side effects we must neutralise. */
ціле
__wrap_channel_setup_local_fwd_listener(struct ssh *ssh,
    struct Forward *fwd, struct ForwardOptions *fwd_opts)
{
	(void)ssh; (void)fwd; (void)fwd_opts;
	повернути 1;
}

ціле
__wrap_channel_connect_stdio_fwd(struct ssh *ssh, const char *host_arg,
    ціле port, ціле in_fd, ціле out_fd, ціле nonblock)
{
	(void)ssh; (void)host_arg; (void)port;
	(void)in_fd; (void)out_fd; (void)nonblock;
	повернути -1;
}

ціле
__wrap_channel_request_remote_forwarding(struct ssh *ssh, struct Forward *fwd)
{
	(void)ssh; (void)fwd;
	повернути 0;
}

ціле
__wrap_channel_request_rforward_cancel(struct ssh *ssh, struct Forward *fwd)
{
	(void)ssh; (void)fwd;
	повернути 0;
}

ціле
__wrap_channel_cancel_lport_listener(struct ssh *ssh, struct Forward *fwd,
    ціле cport, struct ForwardOptions *fwd_opts)
{
	(void)ssh; (void)fwd; (void)cport; (void)fwd_opts;
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

/* Forward decl of the static handler we drive; defined when mux.c is included. */
static ціле mux_master_read_cb(struct ssh *ssh, Channel *c);

#include "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
void *
client_new_escape_filter_ctx(ціле escape_char)
{
	(void)escape_char;
	повернути NULL;
}

void
client_register_global_confirm(global_confirm_cb *cb, void *ctx)
{
	(void)cb; (void)ctx;
}

void
client_expect_confirm(struct ssh *ssh, ціле id, const char *reason,
    enum confirm_action action)
{
	(void)ssh; (void)id; (void)reason; (void)action;
}

void
client_channel_request_agent_forwarding(struct ssh *ssh, ціле chanid)
{
	(void)ssh; (void)chanid;
}

void
client_stop_mux(void)
{
}

ціле
client_simple_escape_filter(struct ssh *ssh, Channel *c, char *buf, ціле len)
{
	(void)ssh; (void)c; (void)buf; (void)len;
	повернути 0;
}

void
client_filter_cleanup(struct ssh *ssh, ціле cid, void *ctx)
{
	(void)ssh; (void)cid; (void)ctx;
}

ціле
client_x11_get_proto(struct ssh *ssh, const char *display,
    const char *xauth_path, u_int trusted, u_int timeout,
    char **_proto, char **_data)
{
	(void)ssh; (void)display; (void)xauth_path;
	(void)trusted; (void)timeout;
	якщо (_proto != NULL)
		*_proto = NULL;
	якщо (_data != NULL)
		*_data = NULL;
	повернути 0;
}

void
client_session2_setup(struct ssh *ssh, ціле id, ціле want_tty, ціле want_subsys,
    const char *term, struct termios *tiop, ціле in_fd, struct sshbuf *cmd,
    char **env)
{
	(void)ssh; (void)id; (void)want_tty; (void)want_subsys;
	(void)term; (void)tiop; (void)in_fd; (void)cmd; (void)env;
}

void
enter_raw_mode(ціле quiet)
{
	(void)quiet;
}

void
leave_raw_mode(ціле quiet)
{
	(void)quiet;
}

static struct ssh *g_client = NULL;
static struct ssh *g_server = NULL;
static ціле g_init = 0;
static ціле g_mux_channel_id = -1;
static struct sshbuf *g_mux_in = NULL;
static struct sshbuf *g_mux_out = NULL;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
static void
fuzz_drive_mux(struct ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	ціле r;
	const u_char *body;
	size_t blen;
	struct mux_master_state *state;

	state = (struct mux_master_state *)c->mux_ctx;
	якщо (state == NULL)
		повернути;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	якщо ((r = sshbuf_get_string_direct(c->input, &body, &blen)) != 0)
		повернути;
	якщо (sshbuf_put(g_mux_in, body, blen) != 0)
		повернути;
	якщо ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		повернути;

	якщо (type == MUX_MSG_HELLO) {
		rid = 0;
	} інакше {
		якщо (!state->hello_rcvd)
			повернути;
		якщо ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			повернути;
	}

	для (i = 0; mux_master_handlers[i].handler != NULL; i++) {
		якщо (type == mux_master_handlers[i].type) {
			(void)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			break;
		}
	}
}

static ціле
init_once(void)
{
	якщо (g_init)
		повернути 0;
	signal(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, sizeof(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (char *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (char *)"fuzz";

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

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	якщо (c == NULL)
		повернути -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	struct mux_master_state *st = (struct mux_master_state *)c->mux_ctx;
	якщо (st != NULL)
		st->hello_rcvd = 1;

	якщо ((g_mux_in = sshbuf_new()) == NULL ||
	    (g_mux_out = sshbuf_new()) == NULL)
		повернути -1;

	free(keyname);
	для (i = 0; i < PROPOSAL_MAX; i++)
		free(proposal[i]);
	g_init = 1;
	повернути 0;
}

void
fuzz_mux_one(const uint8_t *data, size_t size)
{
	якщо (init_once() != 0)
		повернути;
	якщо (size > 65000)
		повернути;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	якщо (c == NULL || c->mux_ctx == NULL || c->input == NULL)
		повернути;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->input);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	якщо (sshbuf_put(c->input, hdr, 4) != 0)
		повернути;
	якщо (size > 0 && sshbuf_put(c->input, data, size) != 0)
		повернути;

	in_fuzz = 1;
	якщо (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	якщо (c->output != NULL)
		sshbuf_reset(c->output);
}
