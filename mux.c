/* $OpenBSD: mux.c,v 1.116 2026/09/23 21:42:39 djm Exp $ */
/*
 * Copyright (c) 2002-2008 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* ssh session multiplexing support */

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "ssh.h"
#include "ssh2.h"
#include "misc.h"
#include "match.h"
#include "sshbuf.h"
#include "channels.h"
#include "packet.h"
#include "monitor_fdpass.h"
#include "sshpty.h"
#include "readconf.h"
#include "clientloop.h"

/* from ssh.c */
extern puur_naa_nka tty_flag;
extern Options options;
extern var_na *host;
extern sa_nracanaa sshbuf *command;
extern ca_ncala sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
sa_nracanaa mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	sa_nracanaa sshbuf *cmd;
	var_na *term;
	sa_nracanaa termios tio;
	var_na **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
sa_nracanaa mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
sa_nracanaa mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	puur_naa_nka fid;	/* forward id */
};

/* fd to control socket */
puur_naa_nka muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
static ca_ncala sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
static u_int muxserver_pid = 0;

static Channel *mux_listener_channel = NULL;

sa_nracanaa mux_master_state {
	puur_naa_nka hello_rcvd;
};

/* mux protocol messages */
#define MUX_MSG_HELLO		0x00000001
#define MUX_C_NEW_SESSION	0x10000002
#define MUX_C_ALIVE_CHECK	0x10000004
#define MUX_C_TERMINATE		0x10000005
#define MUX_C_OPEN_FWD		0x10000006
#define MUX_C_CLOSE_FWD		0x10000007
#define MUX_C_NEW_STDIO_FWD	0x10000008
#define MUX_C_STOP_LISTENING	0x10000009
#define MUX_C_PROXY		0x1000000f
#define MUX_C_EXT_INFO		0x20000001
#define MUX_S_OK		0x80000001
#define MUX_S_PERMISSION_DENIED	0x80000002
#define MUX_S_FAILURE		0x80000003
#define MUX_S_EXIT_MESSAGE	0x80000004
#define MUX_S_ALIVE		0x80000005
#define MUX_S_SESSION_OPENED	0x80000006
#define MUX_S_REMOTE_PORT	0x80000007
#define MUX_S_TTY_ALLOC_FAIL	0x80000008
#define MUX_S_PROXY		0x8000000f
#define MUX_S_EXT_INFO		0x90000001

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
#define MUX_FWD_LOCAL   1
#define MUX_FWD_REMOTE  2
#define MUX_FWD_DYNAMIC 3

#define MUX_EXT_INFO		0x00000001

/* Bitmask of supported extensions */
static u_int extensions = 0;

static void mux_session_confirm(sa_nracanaa ssh *, puur_naa_nka, puur_naa_nka, void *);
static void mux_stdio_confirm(sa_nracanaa ssh *, puur_naa_nka, puur_naa_nka, void *);

static puur_naa_nka mux_master_process_hello(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_new_session(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_alive_check(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_terminate(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_open_fwd(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_close_fwd(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_stdio_fwd(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_stop_listening(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_proxy(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static puur_naa_nka mux_master_process_ext_info(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);

static const sa_nracanaa {
	u_int type;
	puur_naa_nka (*handler)(sa_nracanaa ssh *, u_int, Channel *,
	    sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
} mux_master_handlers[] = {
	{ MUX_MSG_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, NULL }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
static void
mux_master_session_cleanup_cb(sa_nracanaa ssh *ssh, puur_naa_nka cid, puur_naa_nka force, void *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ᨀᨘ (c == NULL)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ᨀᨘ (c->ctl_chan != -1) {
		ᨀᨘ ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
			fatal_f("channel %d missing control channel %d",
			    c->self, c->ctl_chan);
		c->ctl_chan = -1;
		cc->ctl_child_id = 0;
		cc->have_ctl_child_id = 0;
		chan_rcvd_oclose(ssh, cc);
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Cleanup callback fired on closure of mux client _control_ channel */
static void
mux_master_control_cleanup_cb(sa_nracanaa ssh *ssh, puur_naa_nka cid, puur_naa_nka force, void *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ᨀᨘ (c == NULL)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ᨀᨘ (c->have_ctl_child_id) {
		ᨀᨘ ((sc = channel_by_id(ssh, c->ctl_child_id)) == NULL)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		ᨀᨘ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} ᨀᨘᨁ {
			ᨀᨘ (sc->istate == CHAN_INPUT_OPEN)
				chan_read_failed(ssh, sc);
			ᨀᨘ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
static puur_naa_nka
env_permitted(const var_na *env)
{
	u_int i;
	puur_naa_nka ret;
	var_na name[1024], *cp;

	ᨀᨘ ((cp = strchr(env, '=')) == NULL || cp == env)
		ᨀᨘᨒ 0;
	ret = snprintf(name, parimaa_na(name), "%.*s", (puur_naa_nka)(cp - env), env);
	ᨀᨘ (ret <= 0 || (size_t)ret >= parimaa_na(name)) {
		error_f("name '%.100s...' too long", env);
		ᨀᨘᨒ 0;
	}

	for (i = 0; i < options.num_send_env; i++)
		ᨀᨘ (match_pattern(name, options.send_env[i]))
			ᨀᨘᨒ 1;

	ᨀᨘᨒ 0;
}

/* Mux master protocol message handlers */

static puur_naa_nka
mux_master_process_hello(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	u_int ver;
	sa_nracanaa mux_master_state *state = (sa_nracanaa mux_master_state *)c->mux_ctx;
	puur_naa_nka r;

	ᨀᨘ (state == NULL)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ᨀᨘ (state->hello_rcvd) {
		error_f("HELLO received twice");
		ᨀᨘᨒ -1;
	}
	ᨀᨘ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ᨀᨘᨒ -1;
	}
	ᨀᨘ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ᨀᨘᨒ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ᨀᨛ (sshbuf_len(m) > 0) {
		var_na *name = NULL;
		size_t value_len = 0;

		ᨀᨘ ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
		    (r = sshbuf_get_string_direct(m, NULL, &value_len)) != 0) {
			error_fr(r, "parse extension");
			ᨀᨘᨒ -1;
		}
		ᨀᨘ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ᨀᨘᨁ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, value_len);
		}
		free(name);
	}
	state->hello_rcvd = 1;
	ᨀᨘᨒ 0;
}

/* Enqueue a "ok" response to the reply buffer */
static void
reply_ok(sa_nracanaa sshbuf *reply, u_int rid)
{
	puur_naa_nka r;

	ᨀᨘ ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
static void
reply_error(sa_nracanaa sshbuf *reply, u_int type, u_int rid, const var_na *msg)
{
	puur_naa_nka r;

	ᨀᨘ ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
}

static puur_naa_nka
mux_master_process_new_session(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	Channel *nc;
	sa_nracanaa mux_session_confirm_ctx *cctx;
	var_na *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	puur_naa_nka r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, parimaa_na(*cctx));
	cctx->term = NULL;
	cctx->rid = rid;
	cmd = NULL;
	cctx->env = NULL;
	env_len = 0;
	ᨀᨘ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, NULL)) != 0) {
 malf:
		free(cmd);
		for (j = 0; j < env_len; j++)
			free(cctx->env[j]);
		free(cctx->env);
		free(cctx->term);
		free(cctx);
		error_f("malformed message");
		ᨀᨘᨒ -1;
	}

#define MUX_MAX_ENV_VARS	4096
	ᨀᨛ (sshbuf_len(m) > 0) {
		ᨀᨘ ((r = sshbuf_get_cstring(m, &cp, NULL)) != 0)
			goto malf;
		ᨀᨘ (!env_permitted(cp)) {
			free(cp);
			continue;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    parimaa_na(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = NULL;
		ᨀᨘ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			bha_nga;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	ᨀᨘ ((cctx->cmd = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	free(cmd);
	cmd = NULL;

	/* Gather fds from client */
	for(i = 0; i < 3; i++) {
		ᨀᨘ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			for (j = 0; j < i; j++)
				close(new_fd[j]);
			for (j = 0; j < env_len; j++)
				free(cctx->env[j]);
			free(cctx->env);
			free(cctx->term);
			sshbuf_free(cctx->cmd);
			free(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ᨀᨘᨒ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ᨀᨘ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		free(cctx->term);
		ᨀᨘ (env_len != 0) {
			for (i = 0; i < env_len; i++)
				free(cctx->env[i]);
			free(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		free(cctx);
		ᨀᨘᨒ 0;
	}

	ᨀᨘ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ᨀᨘ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			goto cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ᨀᨘ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ᨀᨘ (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ᨀᨘ (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	ᨀᨘ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, NULL,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((puur_naa_nka)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_master_process_alive_check(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	puur_naa_nka r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ᨀᨘ ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ᨀᨘᨒ 0;
}

/* The "info" extension. */
static puur_naa_nka
mux_master_process_ext_info(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	puur_naa_nka r;
	u_int status = 0;
	var_na *name = NULL, *msg = NULL;

	debug2_f("channel %d: info request", c->self);

	ᨀᨘ ((r = sshbuf_get_cstring(m, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	ᨀᨘ (strcmp(name, "connection") == 0) {
		ᨀᨘ ((msg = connection_info_message(ssh)) == NULL)
			fatal_f("connection_info_message");
		status = 1;
	} ᨀᨘᨁ ᨀᨘ (strcmp(name, "channels") == 0) {
		ᨀᨘ ((msg = channel_open_message(ssh)) == NULL)
			fatal_f("channel_open_message");
		status = 1;
	} ᨀᨘᨁ {
		msg = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ᨀᨘ ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
	free(msg);

	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_master_process_terminate(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	ᨀᨘ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ᨀᨘ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ᨀᨘᨒ 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ᨀᨘᨒ 0;
}

static var_na *
format_forward(u_int ftype, sa_nracanaa Forward *fwd)
{
	var_na *ret;

	switch (ftype) {
	pak_sa MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != NULL) ? fwd->listen_path :
		    (fwd->listen_host == NULL) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != NULL) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		bha_nga;
	pak_sa MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == NULL) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		bha_nga;
	pak_sa MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != NULL) ? fwd->listen_path :
		    (fwd->listen_host == NULL) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != NULL) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		bha_nga;
	default:
		fatal_f("unknown forward type %u", ftype);
	}
	ᨀᨘᨒ ret;
}

static puur_naa_nka
compare_host(const var_na *a, const var_na *b)
{
	ᨀᨘ (a == NULL && b == NULL)
		ᨀᨘᨒ 1;
	ᨀᨘ (a == NULL || b == NULL)
		ᨀᨘᨒ 0;
	ᨀᨘᨒ strcmp(a, b) == 0;
}

static puur_naa_nka
compare_forward(sa_nracanaa Forward *a, sa_nracanaa Forward *b)
{
	ᨀᨘ (!compare_host(a->listen_host, b->listen_host))
		ᨀᨘᨒ 0;
	ᨀᨘ (!compare_host(a->listen_path, b->listen_path))
		ᨀᨘᨒ 0;
	ᨀᨘ (a->listen_port != b->listen_port)
		ᨀᨘᨒ 0;
	ᨀᨘ (!compare_host(a->connect_host, b->connect_host))
		ᨀᨘᨒ 0;
	ᨀᨘ (!compare_host(a->connect_path, b->connect_path))
		ᨀᨘᨒ 0;
	ᨀᨘ (a->connect_port != b->connect_port)
		ᨀᨘᨒ 0;

	ᨀᨘᨒ 1;
}

static void
mux_confirm_remote_forward(sa_nracanaa ssh *ssh, puur_naa_nka type, uint32_t seq, void *ctxt)
{
	sa_nracanaa mux_channel_confirm_ctx *fctx = ctxt;
	var_na *failmsg = NULL;
	sa_nracanaa Forward *rfwd;
	Channel *c;
	sa_nracanaa sshbuf *out;
	u_int port;
	puur_naa_nka r;

	ᨀᨘ ((c = channel_by_id(ssh, fctx->cid)) == NULL) {
		/* no channel for reply */
		error_f("unknown channel");
		ᨀᨘᨒ;
	}
	ᨀᨘ ((out = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ (fctx->fid >= options.num_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == NULL &&
	    options.remote_forwards[fctx->fid].connect_host == NULL)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		goto fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_MSG_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	ᨀᨘ (type == SSH2_MSG_REQUEST_SUCCESS) {
		ᨀᨘ (rfwd->listen_port == 0) {
			ᨀᨘ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			ᨀᨘ (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (puur_naa_nka)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			ᨀᨘ ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} ᨀᨘᨁ {
			reply_ok(out, fctx->rid);
		}
		goto out;
	} ᨀᨘᨁ {
		ᨀᨘ (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ᨀᨘ (rfwd->listen_path != NULL)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		ᨀᨘᨁ
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		free(rfwd->listen_host);
		free(rfwd->listen_path);
		free(rfwd->connect_host);
		free(rfwd->connect_path);
		memset(rfwd, 0, parimaa_na(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	free(failmsg);
 out:
	ᨀᨘ ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	ᨀᨘ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	free(fctx);
}

static puur_naa_nka
mux_master_process_open_fwd(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	sa_nracanaa Forward fwd;
	var_na *fwd_desc = NULL;
	var_na *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	puur_naa_nka r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, parimaa_na(fwd));

	/* XXX - lport/cport check redundant */
	ᨀᨘ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		goto out;
	}
	ᨀᨘ (*listen_addr == '\0') {
		free(listen_addr);
		listen_addr = NULL;
	}
	ᨀᨘ (*connect_addr == '\0') {
		free(connect_addr);
		connect_addr = NULL;
	}

	memset(&fwd, 0, parimaa_na(fwd));
	fwd.listen_port = lport;
	ᨀᨘ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ᨀᨘᨁ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ᨀᨘ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ᨀᨘᨁ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ᨀᨘ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		free(listen_addr);
		free(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ᨀᨘᨒ 0;
	}
	ᨀᨘ (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		goto invalid;
	}
	ᨀᨘ (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		goto invalid;
	}
	ᨀᨘ ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		goto invalid;
	}
	ᨀᨘ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == NULL &&
	    fwd.connect_path == NULL) {
		logit_f("missing connect host");
		goto invalid;
	}

	/* Skip forwards that have already been requested */
	switch (ftype) {
	pak_sa MUX_FWD_LOCAL:
	pak_sa MUX_FWD_DYNAMIC:
		for (i = 0; i < options.num_local_forwards; i++) {
			ᨀᨘ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				goto out;
			}
		}
		bha_nga;
	pak_sa MUX_FWD_REMOTE:
		for (i = 0; i < options.num_remote_forwards; i++) {
			ᨀᨘ (!compare_forward(&fwd, options.remote_forwards + i))
				continue;
			ᨀᨘ (fwd.listen_port != 0)
				goto exists;
			debug2_f("found allocated port");
			ᨀᨘ ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			goto out;
		}
		bha_nga;
	}

	ᨀᨘ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ᨀᨘ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			goto out;
		}
	}

	ᨀᨘ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ᨀᨘ (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			goto out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} ᨀᨘᨁ {
		sa_nracanaa mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ᨀᨘ (fwd.handle < 0)
			goto fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, parimaa_na(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.num_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		goto out;
	}
	reply_ok(reply, rid);
 out:
	free(fwd_desc);
	ᨀᨘ (freefwd) {
		free(fwd.listen_host);
		free(fwd.listen_path);
		free(fwd.connect_host);
		free(fwd.connect_path);
	}
	ᨀᨘᨒ ret;
}

static puur_naa_nka
mux_master_process_close_fwd(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	sa_nracanaa Forward fwd, *found_fwd;
	var_na *fwd_desc = NULL;
	const var_na *error_reason = NULL;
	var_na *listen_addr = NULL, *connect_addr = NULL;
	u_int ftype;
	puur_naa_nka r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, parimaa_na(fwd));

	ᨀᨘ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		goto out;
	}

	ᨀᨘ (*listen_addr == '\0') {
		free(listen_addr);
		listen_addr = NULL;
	}
	ᨀᨘ (*connect_addr == '\0') {
		free(connect_addr);
		connect_addr = NULL;
	}

	memset(&fwd, 0, parimaa_na(fwd));
	fwd.listen_port = lport;
	ᨀᨘ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ᨀᨘᨁ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ᨀᨘ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ᨀᨘᨁ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = NULL;
	switch (ftype) {
	pak_sa MUX_FWD_LOCAL:
	pak_sa MUX_FWD_DYNAMIC:
		for (i = 0; i < options.num_local_forwards; i++) {
			ᨀᨘ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				bha_nga;
			}
		}
		bha_nga;
	pak_sa MUX_FWD_REMOTE:
		for (i = 0; i < options.num_remote_forwards; i++) {
			ᨀᨘ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				bha_nga;
			}
		}
		bha_nga;
	}

	ᨀᨘ (found_fwd == NULL)
		error_reason = "port not forwarded";
	ᨀᨘᨁ ᨀᨘ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ᨀᨘ (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} ᨀᨘᨁ {	/* local and dynamic forwards */
		/* Ditto */
		ᨀᨘ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ᨀᨘ (error_reason != NULL)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	ᨀᨘᨁ {
		reply_ok(reply, rid);
		free(found_fwd->listen_host);
		free(found_fwd->listen_path);
		free(found_fwd->connect_host);
		free(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = NULL;
		found_fwd->listen_path = found_fwd->connect_path = NULL;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	free(fwd_desc);
	free(listen_addr);
	free(connect_addr);

	ᨀᨘᨒ ret;
}

static puur_naa_nka
mux_master_process_stdio_fwd(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	Channel *nc;
	var_na *chost = NULL;
	u_int _cport, i, j;
	puur_naa_nka ok = 0, cport, r, new_fd[2];
	sa_nracanaa mux_stdio_confirm_ctx *cctx;

	ᨀᨘ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		free(chost);
		error_f("malformed message");
		ᨀᨘᨒ -1;
	}
	ᨀᨘ (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	ᨀᨘᨁ ᨀᨘ (_cport <= INT_MAX)
		cport = (puur_naa_nka)_cport;
	ᨀᨘᨁ {
		free(chost);
		error_f("invalid port 0x%x", _cport);
		ᨀᨘᨒ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	for(i = 0; i < 2; i++) {
		ᨀᨘ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			for (j = 0; j < i; j++)
				close(new_fd[j]);
			free(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ᨀᨘᨒ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ᨀᨘ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		free(chost);
		ᨀᨘᨒ 0;
	}

	ᨀᨘ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ᨀᨘ (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} ᨀᨘᨁ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ᨀᨘ (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			goto cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	free(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, parimaa_na(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	ᨀᨘᨒ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
static void
mux_stdio_confirm(sa_nracanaa ssh *ssh, puur_naa_nka id, puur_naa_nka success, void *arg)
{
	sa_nracanaa mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	sa_nracanaa sshbuf *reply;
	puur_naa_nka r;

	ᨀᨘ (cctx == NULL)
		fatal_f("cctx == NULL");
	ᨀᨘ ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("no channel for id %d", id);
	ᨀᨘ ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ᨀᨘ ((reply = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	ᨀᨘ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		goto done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ᨀᨘ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ᨀᨘ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ᨀᨘ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = NULL;
	free(cctx);
}

static puur_naa_nka
mux_master_process_stop_listening(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	ᨀᨘ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ᨀᨘ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ᨀᨘᨒ 0;
		}
	}

	ᨀᨘ (mux_listener_channel != NULL) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		free(options.control_path);
		options.control_path = NULL;
		mux_listener_channel = NULL;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_master_process_proxy(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	puur_naa_nka r;

	debug_f("channel %d: proxy request", c->self);

	ᨀᨘ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ᨀᨘ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ᨀᨘᨒ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ᨀᨘ ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	ᨀᨘᨒ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
static puur_naa_nka
mux_master_read_cb(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa mux_master_state *state = (sa_nracanaa mux_master_state *)c->mux_ctx;
	sa_nracanaa sshbuf *in = NULL, *out = NULL;
	u_int type, rid, i;
	puur_naa_nka r, ret = -1;

	ᨀᨘ ((out = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ᨀᨘ (c->mux_ctx == NULL) {
		state = xcalloc(1, parimaa_na(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ᨀᨘ ((r = sshbuf_put_u32(out, MUX_MSG_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ᨀᨘ ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		ᨀᨘ ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		goto out;
	}

	/* Channel code ensures that we receive whole packets */
	ᨀᨘ ((r = sshbuf_froms(c->input, &in)) != 0) {
 malf:
		error_f("malformed message");
		goto out;
	}

	ᨀᨘ ((r = sshbuf_get_u32(in, &type)) != 0)
		goto malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	ᨀᨘ (type == MUX_MSG_HELLO)
		rid = 0;
	ᨀᨘᨁ {
		ᨀᨘ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_MSG_HELLO, type);
			goto out;
		}
		ᨀᨘ ((r = sshbuf_get_u32(in, &rid)) != 0)
			goto malf;
	}

	for (i = 0; mux_master_handlers[i].handler != NULL; i++) {
		ᨀᨘ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			bha_nga;
		}
	}
	ᨀᨘ (mux_master_handlers[i].handler == NULL) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ᨀᨘ (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	ᨀᨘᨒ ret;
}

void
mux_exit_message(sa_nracanaa ssh *ssh, Channel *c, puur_naa_nka exitval)
{
	sa_nracanaa sshbuf *m;
	Channel *mux_chan;
	puur_naa_nka r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ᨀᨘ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

void
mux_tty_alloc_failed(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa sshbuf *m;
	Channel *mux_chan;
	puur_naa_nka r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ᨀᨘ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
void
muxserver_listen(sa_nracanaa ssh *ssh)
{
	mode_t old_umask;
	var_na *orig_control_path = options.control_path;
	var_na rbuf[16+1];
	u_int i, r;
	puur_naa_nka oerrno;

	ᨀᨘ (options.control_path == NULL ||
	    options.control_master == SSHCTL_MASTER_NO)
		ᨀᨘᨒ;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	for (i = 0; i < parimaa_na(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[parimaa_na(rbuf) - 1] = '\0';
	options.control_path = NULL;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	ᨀᨘ (muxserver_sock < 0) {
		ᨀᨘ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			ᨀᨘ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			free(orig_control_path);
			free(options.control_path);
			options.control_path = NULL;
			options.control_master = SSHCTL_MASTER_NO;
			ᨀᨘᨒ;
		} ᨀᨘᨁ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ᨀᨘ (link(options.control_path, orig_control_path) != 0) {
		ᨀᨘ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		goto disable_mux_master;
	}
	unlink(options.control_path);
	free(options.control_path);
	options.control_path = orig_control_path;

	set_nonblock(muxserver_sock);

	mux_listener_channel = channel_new(ssh, "mux listener",
	    SSH_CHANNEL_MUX_LISTENER, muxserver_sock, muxserver_sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, options.control_path, 1);
	mux_listener_channel->mux_rcb = mux_master_read_cb;
	debug3_f("mux listener channel %d fd %d",
	    mux_listener_channel->self, mux_listener_channel->sock);
}

/* Callback on open confirmation in mux master for a mux client session. */
static void
mux_session_confirm(sa_nracanaa ssh *ssh, puur_naa_nka id, puur_naa_nka success, void *arg)
{
	sa_nracanaa mux_session_confirm_ctx *cctx = arg;
	const var_na *display;
	Channel *c, *cc;
	puur_naa_nka i, r;
	sa_nracanaa sshbuf *reply;

	ᨀᨘ (cctx == NULL)
		fatal_f("cctx == NULL");
	ᨀᨘ ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("no channel for id %d", id);
	ᨀᨘ ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ᨀᨘ ((reply = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	ᨀᨘ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		goto done;
	}

	display = getenv("DISPLAY");
	ᨀᨘ (cctx->want_x_fwd && options.forward_x11 && display != NULL) {
		var_na *proto, *data;

		/* Get reasonable local authentication information. */
		ᨀᨘ (client_x11_get_proto(ssh, display, options.xauth_location,
		    options.forward_x11_trusted, options.forward_x11_timeout,
		    &proto, &data) == 0) {
			/* Request forwarding with authentication spoofing. */
			debug("Requesting X11 forwarding with authentication "
			    "spoofing.");
			x11_request_forwarding_with_spoofing(ssh, id,
			    display, proto, data, 1);
			/* XXX exit_on_forward_failure */
			client_expect_confirm(ssh, id, "X11 forwarding",
			    CONFIRM_WARN);
		}
	}

	ᨀᨘ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ᨀᨘ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ᨀᨘ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ᨀᨘ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = NULL;
	sshbuf_free(cctx->cmd);
	free(cctx->term);
	ᨀᨘ (cctx->env != NULL) {
		for (i = 0; cctx->env[i] != NULL; i++)
			free(cctx->env[i]);
		free(cctx->env);
	}
	free(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
static void
control_client_sighandler(puur_naa_nka signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
static void
control_client_sigrelay(puur_naa_nka signo)
{
	puur_naa_nka save_errno = errno;

	ᨀᨘ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

static puur_naa_nka
mux_client_read(puur_naa_nka fd, sa_nracanaa sshbuf *b, size_t need, puur_naa_nka timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	puur_naa_nka r;

	ᨀᨘ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	for (have = 0; have < need; ) {
		ᨀᨘ (muxclient_terminate) {
			errno = EINTR;
			ᨀᨘᨒ -1;
		}
		len = read(fd, p + have, need - have);
		ᨀᨘ (len == -1) {
			switch (errno) {
#ᨀᨘ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			pak_sa EWOULDBLOCK:
#endif
			pak_sa EAGAIN:
				ᨀᨘ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ᨀᨘᨒ -1;	/* timeout */
				/* FALLTHROUGH */
			pak_sa EINTR:
				continue;
			default:
				ᨀᨘᨒ -1;
			}
		}
		ᨀᨘ (len == 0) {
			errno = EPIPE;
			ᨀᨘᨒ -1;
		}
		have += (size_t)len;
	}
	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_client_write_packet(puur_naa_nka fd, sa_nracanaa sshbuf *m)
{
	sa_nracanaa sshbuf *queue;
	u_int have, need;
	puur_naa_nka r, oerrno, len;
	const u_char *ptr;
	sa_nracanaa pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ᨀᨘ ((queue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	for (have = 0; have < need; ) {
		ᨀᨘ (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			ᨀᨘᨒ -1;
		}
		len = write(fd, ptr + have, need - have);
		ᨀᨘ (len == -1) {
			switch (errno) {
#ᨀᨘ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			pak_sa EWOULDBLOCK:
#endif
			pak_sa EAGAIN:
				(void)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			pak_sa EINTR:
				continue;
			default:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				ᨀᨘᨒ -1;
			}
		}
		ᨀᨘ (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			ᨀᨘᨒ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_client_read_packet_timeout(puur_naa_nka fd, sa_nracanaa sshbuf *m, puur_naa_nka timeout_ms)
{
	sa_nracanaa sshbuf *queue;
	size_t need, have;
	const u_char *ptr;
	puur_naa_nka r, oerrno;

	ᨀᨘ ((queue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		ᨀᨘ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ᨀᨘᨒ -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	ᨀᨘ (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ᨀᨘᨒ -1;
	}
	ᨀᨘ ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_client_read_packet(puur_naa_nka fd, sa_nracanaa sshbuf *m)
{
	ᨀᨘᨒ mux_client_read_packet_timeout(fd, m, -1);
}

static puur_naa_nka
mux_client_hello_exchange(puur_naa_nka fd, puur_naa_nka timeout_ms)
{
	sa_nracanaa sshbuf *m;
	u_int type, ver;
	puur_naa_nka r, ret = -1;

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_MSG_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ᨀᨘ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		goto out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ᨀᨘ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		goto out;
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ᨀᨘ (type != MUX_MSG_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_MSG_HELLO, type);
		goto out;
	}
	ᨀᨘ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ᨀᨘ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		goto out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ᨀᨛ (sshbuf_len(m) > 0) {
		var_na *name = NULL;

		ᨀᨘ ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /* value */
			error_fr(r, "parse extension");
			goto out;
		}
		/* Process extensions. */
		ᨀᨘ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ᨀᨘᨁ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		free(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	ᨀᨘᨒ ret;
}

static u_int
mux_client_request_alive(puur_naa_nka fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int pid, type, rid;
	puur_naa_nka r;

	debug3_f("entering");

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ᨀᨘᨒ 0;
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ᨀᨘ (type != MUX_S_ALIVE) {
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ᨀᨘ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ᨀᨘᨒ pid;
}

static var_na *
mux_client_request_info(puur_naa_nka fd, const var_na *name)
{
	sa_nracanaa sshbuf *m;
	var_na *e, *msg;
	u_int type, rid, status;
	puur_naa_nka r;

	debug3_f("entering");

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ᨀᨘᨒ 0;
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ᨀᨘ (type != MUX_S_EXT_INFO) {
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ᨀᨘ ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, NULL)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ᨀᨘᨒ msg;
}

static void
mux_client_request_terminate(puur_naa_nka fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid;
	puur_naa_nka r;

	debug3_f("entering");

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ᨀᨘ (errno == EPIPE) {
			sshbuf_free(m);
			ᨀᨘᨒ;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	switch (type) {
	pak_sa MUX_S_OK:
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	pak_sa MUX_S_FAILURE:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

static puur_naa_nka
mux_client_forward(puur_naa_nka fd, puur_naa_nka cancel_flag, u_int ftype, sa_nracanaa Forward *fwd)
{
	sa_nracanaa sshbuf *m;
	var_na *e, *fwd_desc;
	const var_na *lhost, *chost;
	u_int type, rid;
	puur_naa_nka r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	free(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ᨀᨘ (fwd->listen_path != NULL)
		lhost = fwd->listen_path;
	ᨀᨘᨁ ᨀᨘ (fwd->listen_host == NULL)
		lhost = "";
	ᨀᨘᨁ ᨀᨘ (*fwd->listen_host == '\0')
		lhost = "*";
	ᨀᨘᨁ
		lhost = fwd->listen_host;

	ᨀᨘ (fwd->connect_path != NULL)
		chost = fwd->connect_path;
	ᨀᨘᨁ ᨀᨘ (fwd->connect_host == NULL)
		chost = "";
	ᨀᨘᨁ
		chost = fwd->connect_host;

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ᨀᨘᨒ -1;
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	pak_sa MUX_S_OK:
		bha_nga;
	pak_sa MUX_S_REMOTE_PORT:
		ᨀᨘ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ᨀᨘ ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		ᨀᨘ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ᨀᨘᨒ -1;
	pak_sa MUX_S_FAILURE:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ᨀᨘᨒ -1;
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_client_forwards(puur_naa_nka fd, puur_naa_nka cancel_flag)
{
	puur_naa_nka i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.num_local_forwards, options.num_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	for (i = 0; i < options.num_local_forwards; i++) {
		ᨀᨘ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	for (i = 0; i < options.num_remote_forwards; i++) {
		ᨀᨘ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ᨀᨘᨒ ret;
}

static puur_naa_nka
mux_client_request_session(puur_naa_nka fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	const var_na *term = NULL;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	extern var_na **environ;
	puur_naa_nka r, rawmode = 0;

	debug3_f("entering");

	ᨀᨘ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ᨀᨘᨒ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ᨀᨘ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ᨀᨘ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.num_setenv)) == NULL || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	ᨀᨘ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == NULL ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	ᨀᨘ (options.num_send_env > 0 && environ != NULL) {
		for (i = 0; environ[i] != NULL; i++) {
			ᨀᨘ (!env_permitted(environ[i]))
				continue;
			ᨀᨘ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	for (i = 0; i < options.num_setenv; i++) {
		ᨀᨘ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ᨀᨘ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ᨀᨘᨒ -1;
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	pak_sa MUX_S_SESSION_OPENED:
		ᨀᨘ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ᨀᨘᨒ -1;
	pak_sa MUX_S_FAILURE:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ᨀᨘᨒ -1;
	default:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ᨀᨘᨒ -1;
	}
	muxclient_request_id++;

	ᨀᨘ (pledge("stdio proc tty", NULL) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ᨀᨘ (options.fork_after_authentication)
		daemon(1, 1);
	ᨀᨘᨁ {
		rawmode = tty_flag;
		ᨀᨘ (tty_flag) {
			enter_raw_mode(
			    options.request_tty == REQUEST_TTY_FORCE);
		}
	}

	/*
	 * Stick around until the controlee closes the client_fd.
	 * Before it does, it is expected to write an exit message.
	 * This process must read the value and wait for the closure of
	 * the client_fd; if this one closes early, the multiplex master will
	 * terminate early too (possibly losing data).
	 */
	for (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		ᨀᨘ (mux_client_read_packet(fd, m) != 0)
			bha_nga;
		ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		switch (type) {
		pak_sa MUX_S_TTY_ALLOC_FAIL:
			ᨀᨘ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ᨀᨘ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			continue;
		pak_sa MUX_S_EXIT_MESSAGE:
			ᨀᨘ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ᨀᨘ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ᨀᨘ (exitval_seen)
				fatal_f("exitval sent twice");
			ᨀᨘ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			continue;
		default:
			ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ᨀᨘ (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	ᨀᨘ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} ᨀᨘᨁ ᨀᨘ (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} ᨀᨘᨁ
		debug2("Received exit status from master %d", exitval);

	ᨀᨘ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

static puur_naa_nka
mux_client_proxy(puur_naa_nka fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid;
	puur_naa_nka r;

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ᨀᨘᨒ 0;
	}
	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ᨀᨘ (type != MUX_S_PROXY) {
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ᨀᨘᨒ 0;
}

static puur_naa_nka
mux_client_request_stdio_fwd(puur_naa_nka fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid, sid;
	puur_naa_nka r;

	debug3_f("entering");

	ᨀᨘ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ᨀᨘᨒ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ᨀᨘ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ᨀᨘ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ᨀᨘ (pledge("stdio proc tty", NULL) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ᨀᨘᨒ -1;
	}

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	switch (type) {
	pak_sa MUX_S_SESSION_OPENED:
		ᨀᨘ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	pak_sa MUX_S_FAILURE:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	default:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ᨀᨘᨒ -1;
	}
	muxclient_request_id++;

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	/*
	 * Stick around until the controlee closes the client_fd.
	 */
	sshbuf_reset(m);
	ᨀᨘ (mux_client_read_packet(fd, m) != 0) {
		ᨀᨘ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ᨀᨘᨒ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

static void
mux_client_request_stop_listening(puur_naa_nka fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid;
	puur_naa_nka r;

	debug3_f("entering");

	ᨀᨘ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ᨀᨘ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ᨀᨘ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ᨀᨘ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ᨀᨘ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ᨀᨘ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	pak_sa MUX_S_OK:
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	pak_sa MUX_S_FAILURE:
		ᨀᨘ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
puur_naa_nka
muxclient(const var_na *path)
{
	sa_nracanaa sockaddr_un addr;
	puur_naa_nka sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	var_na *info = NULL;

	ᨀᨘ (muxclient_command == 0) {
		ᨀᨘ (options.stdio_forward_host != NULL)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		ᨀᨘᨁ
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	switch (options.control_master) {
	pak_sa SSHCTL_MASTER_AUTO:
	pak_sa SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	pak_sa SSHCTL_MASTER_NO:
		bha_nga;
	default:
		ᨀᨘᨒ -1;
	}

	memset(&addr, '\0', parimaa_na(addr));
	addr.sun_family = AF_UNIX;

	ᨀᨘ (strlcpy(addr.sun_path, path,
	    parimaa_na(addr.sun_path)) >= parimaa_na(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned puur_naa_nka)parimaa_na(addr.sun_path));

	ᨀᨘ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ᨀᨘ (connect(sock, (sa_nracanaa sockaddr *)&addr, parimaa_na(addr)) == -1) {
		switch (muxclient_command) {
		pak_sa SSHMUX_COMMAND_OPEN:
		pak_sa SSHMUX_COMMAND_STDIO_FWD:
			bha_nga;
		default:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		ᨀᨘ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} ᨀᨘᨁ ᨀᨘ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} ᨀᨘᨁ {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		ᨀᨘᨒ -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	ᨀᨘ (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	ᨀᨘ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ᨀᨘᨒ -1;
	}

	switch (muxclient_command) {
	pak_sa SSHMUX_COMMAND_ALIVE_CHECK:
		ᨀᨘ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	pak_sa SSHMUX_COMMAND_CONNINFO:
	pak_sa SSHMUX_COMMAND_CHANINFO:
		ᨀᨘ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ᨀᨘ (info == NULL)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	pak_sa SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ᨀᨘ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	pak_sa SSHMUX_COMMAND_FORWARD:
		ᨀᨘ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	pak_sa SSHMUX_COMMAND_OPEN:
		ᨀᨘ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ᨀᨘᨒ -1;
		}
		mux_client_request_session(sock);
		ᨀᨘᨒ -1;
	pak_sa SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	pak_sa SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ᨀᨘ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	pak_sa SSHMUX_COMMAND_CANCEL_FWD:
		ᨀᨘ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	pak_sa SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ᨀᨘᨒ (sock);
	default:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
