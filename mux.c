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
extern ចំនួនគត់ tty_flag;
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
	ចំនួនគត់ fid;	/* forward id */
};

/* fd to control socket */
ចំនួនគត់ muxserver_sock = -1;

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
	ចំនួនគត់ hello_rcvd;
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

static void mux_session_confirm(sa_nracanaa ssh *, ចំនួនគត់, ចំនួនគត់, void *);
static void mux_stdio_confirm(sa_nracanaa ssh *, ចំនួនគត់, ចំនួនគត់, void *);

static ចំនួនគត់ mux_master_process_hello(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_new_session(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_alive_check(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_terminate(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_open_fwd(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_close_fwd(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_stdio_fwd(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_stop_listening(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_proxy(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);
static ចំនួនគត់ mux_master_process_ext_info(sa_nracanaa ssh *, u_int,
	    Channel *, sa_nracanaa sshbuf *, sa_nracanaa sshbuf *);

static const sa_nracanaa {
	u_int type;
	ចំនួនគត់ (*handler)(sa_nracanaa ssh *, u_int, Channel *,
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
mux_master_session_cleanup_cb(sa_nracanaa ssh *ssh, ចំនួនគត់ cid, ចំនួនគត់ force, void *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ប្រសិនបើ (c == NULL)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ប្រសិនបើ (c->ctl_chan != -1) {
		ប្រសិនបើ ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
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
mux_master_control_cleanup_cb(sa_nracanaa ssh *ssh, ចំនួនគត់ cid, ចំនួនគត់ force, void *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ប្រសិនបើ (c == NULL)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ប្រសិនបើ (c->have_ctl_child_id) {
		ប្រសិនបើ ((sc = channel_by_id(ssh, c->ctl_child_id)) == NULL)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		ប្រសិនបើ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} បើមិនដូច្នេះ {
			ប្រសិនបើ (sc->istate == CHAN_INPUT_OPEN)
				chan_read_failed(ssh, sc);
			ប្រសិនបើ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
static ចំនួនគត់
env_permitted(const var_na *env)
{
	u_int i;
	ចំនួនគត់ ret;
	var_na name[1024], *cp;

	ប្រសិនបើ ((cp = strchr(env, '=')) == NULL || cp == env)
		ត្រឡប់ 0;
	ret = snprintf(name, parimaa_na(name), "%.*s", (ចំនួនគត់)(cp - env), env);
	ប្រសិនបើ (ret <= 0 || (size_t)ret >= parimaa_na(name)) {
		error_f("name '%.100s...' too long", env);
		ត្រឡប់ 0;
	}

	សម្រាប់ (i = 0; i < options.num_send_env; i++)
		ប្រសិនបើ (match_pattern(name, options.send_env[i]))
			ត្រឡប់ 1;

	ត្រឡប់ 0;
}

/* Mux master protocol message handlers */

static ចំនួនគត់
mux_master_process_hello(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	u_int ver;
	sa_nracanaa mux_master_state *state = (sa_nracanaa mux_master_state *)c->mux_ctx;
	ចំនួនគត់ r;

	ប្រសិនបើ (state == NULL)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ប្រសិនបើ (state->hello_rcvd) {
		error_f("HELLO received twice");
		ត្រឡប់ -1;
	}
	ប្រសិនបើ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ត្រឡប់ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ខណៈពេល (sshbuf_len(m) > 0) {
		var_na *name = NULL;
		size_t value_len = 0;

		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
		    (r = sshbuf_get_string_direct(m, NULL, &value_len)) != 0) {
			error_fr(r, "parse extension");
			ត្រឡប់ -1;
		}
		ប្រសិនបើ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} បើមិនដូច្នេះ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, value_len);
		}
		free(name);
	}
	state->hello_rcvd = 1;
	ត្រឡប់ 0;
}

/* Enqueue a "ok" response to the reply buffer */
static void
reply_ok(sa_nracanaa sshbuf *reply, u_int rid)
{
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
static void
reply_error(sa_nracanaa sshbuf *reply, u_int type, u_int rid, const var_na *msg)
{
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
}

static ចំនួនគត់
mux_master_process_new_session(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	Channel *nc;
	sa_nracanaa mux_session_confirm_ctx *cctx;
	var_na *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	ចំនួនគត់ r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, parimaa_na(*cctx));
	cctx->term = NULL;
	cctx->rid = rid;
	cmd = NULL;
	cctx->env = NULL;
	env_len = 0;
	ប្រសិនបើ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, NULL)) != 0) {
 malf:
		free(cmd);
		សម្រាប់ (j = 0; j < env_len; j++)
			free(cctx->env[j]);
		free(cctx->env);
		free(cctx->term);
		free(cctx);
		error_f("malformed message");
		ត្រឡប់ -1;
	}

#define MUX_MAX_ENV_VARS	4096
	ខណៈពេល (sshbuf_len(m) > 0) {
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &cp, NULL)) != 0)
			goto malf;
		ប្រសិនបើ (!env_permitted(cp)) {
			free(cp);
			continue;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    parimaa_na(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = NULL;
		ប្រសិនបើ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			bha_nga;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	ប្រសិនបើ ((cctx->cmd = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	free(cmd);
	cmd = NULL;

	/* Gather fds from client */
	សម្រាប់(i = 0; i < 3; i++) {
		ប្រសិនបើ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			សម្រាប់ (j = 0; j < i; j++)
				close(new_fd[j]);
			សម្រាប់ (j = 0; j < env_len; j++)
				free(cctx->env[j]);
			free(cctx->env);
			free(cctx->term);
			sshbuf_free(cctx->cmd);
			free(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ត្រឡប់ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ប្រសិនបើ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		free(cctx->term);
		ប្រសិនបើ (env_len != 0) {
			សម្រាប់ (i = 0; i < env_len; i++)
				free(cctx->env[i]);
			free(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		free(cctx);
		ត្រឡប់ 0;
	}

	ប្រសិនបើ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ប្រសិនបើ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			goto cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ប្រសិនបើ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ប្រសិនបើ (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ប្រសិនបើ (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	ប្រសិនបើ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, NULL,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((ចំនួនគត់)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_master_process_alive_check(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	ចំនួនគត់ r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ប្រសិនបើ ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ត្រឡប់ 0;
}

/* The "info" extension. */
static ចំនួនគត់
mux_master_process_ext_info(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	ចំនួនគត់ r;
	u_int status = 0;
	var_na *name = NULL, *msg = NULL;

	debug2_f("channel %d: info request", c->self);

	ប្រសិនបើ ((r = sshbuf_get_cstring(m, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	ប្រសិនបើ (strcmp(name, "connection") == 0) {
		ប្រសិនបើ ((msg = connection_info_message(ssh)) == NULL)
			fatal_f("connection_info_message");
		status = 1;
	} បើមិនដូច្នេះ ប្រសិនបើ (strcmp(name, "channels") == 0) {
		ប្រសិនបើ ((msg = channel_open_message(ssh)) == NULL)
			fatal_f("channel_open_message");
		status = 1;
	} បើមិនដូច្នេះ {
		msg = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ប្រសិនបើ ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
	free(msg);

	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_master_process_terminate(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	ប្រសិនបើ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ប្រសិនបើ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ត្រឡប់ 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ត្រឡប់ 0;
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
	ត្រឡប់ ret;
}

static ចំនួនគត់
compare_host(const var_na *a, const var_na *b)
{
	ប្រសិនបើ (a == NULL && b == NULL)
		ត្រឡប់ 1;
	ប្រសិនបើ (a == NULL || b == NULL)
		ត្រឡប់ 0;
	ត្រឡប់ strcmp(a, b) == 0;
}

static ចំនួនគត់
compare_forward(sa_nracanaa Forward *a, sa_nracanaa Forward *b)
{
	ប្រសិនបើ (!compare_host(a->listen_host, b->listen_host))
		ត្រឡប់ 0;
	ប្រសិនបើ (!compare_host(a->listen_path, b->listen_path))
		ត្រឡប់ 0;
	ប្រសិនបើ (a->listen_port != b->listen_port)
		ត្រឡប់ 0;
	ប្រសិនបើ (!compare_host(a->connect_host, b->connect_host))
		ត្រឡប់ 0;
	ប្រសិនបើ (!compare_host(a->connect_path, b->connect_path))
		ត្រឡប់ 0;
	ប្រសិនបើ (a->connect_port != b->connect_port)
		ត្រឡប់ 0;

	ត្រឡប់ 1;
}

static void
mux_confirm_remote_forward(sa_nracanaa ssh *ssh, ចំនួនគត់ type, uint32_t seq, void *ctxt)
{
	sa_nracanaa mux_channel_confirm_ctx *fctx = ctxt;
	var_na *failmsg = NULL;
	sa_nracanaa Forward *rfwd;
	Channel *c;
	sa_nracanaa sshbuf *out;
	u_int port;
	ចំនួនគត់ r;

	ប្រសិនបើ ((c = channel_by_id(ssh, fctx->cid)) == NULL) {
		/* no channel for reply */
		error_f("unknown channel");
		ត្រឡប់;
	}
	ប្រសិនបើ ((out = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ (fctx->fid >= options.num_remote_forwards ||
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
	ប្រសិនបើ (type == SSH2_MSG_REQUEST_SUCCESS) {
		ប្រសិនបើ (rfwd->listen_port == 0) {
			ប្រសិនបើ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			ប្រសិនបើ (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (ចំនួនគត់)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			ប្រសិនបើ ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} បើមិនដូច្នេះ {
			reply_ok(out, fctx->rid);
		}
		goto out;
	} បើមិនដូច្នេះ {
		ប្រសិនបើ (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ប្រសិនបើ (rfwd->listen_path != NULL)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		បើមិនដូច្នេះ
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
	ប្រសិនបើ ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	ប្រសិនបើ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	free(fctx);
}

static ចំនួនគត់
mux_master_process_open_fwd(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	sa_nracanaa Forward fwd;
	var_na *fwd_desc = NULL;
	var_na *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	ចំនួនគត់ r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, parimaa_na(fwd));

	/* XXX - lport/cport check redundant */
	ប្រសិនបើ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
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
	ប្រសិនបើ (*listen_addr == '\0') {
		free(listen_addr);
		listen_addr = NULL;
	}
	ប្រសិនបើ (*connect_addr == '\0') {
		free(connect_addr);
		connect_addr = NULL;
	}

	memset(&fwd, 0, parimaa_na(fwd));
	fwd.listen_port = lport;
	ប្រសិនបើ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	បើមិនដូច្នេះ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ប្រសិនបើ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	បើមិនដូច្នេះ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ប្រសិនបើ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		free(listen_addr);
		free(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ត្រឡប់ 0;
	}
	ប្រសិនបើ (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		goto invalid;
	}
	ប្រសិនបើ (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		goto invalid;
	}
	ប្រសិនបើ ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		goto invalid;
	}
	ប្រសិនបើ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == NULL &&
	    fwd.connect_path == NULL) {
		logit_f("missing connect host");
		goto invalid;
	}

	/* Skip forwards that have already been requested */
	switch (ftype) {
	pak_sa MUX_FWD_LOCAL:
	pak_sa MUX_FWD_DYNAMIC:
		សម្រាប់ (i = 0; i < options.num_local_forwards; i++) {
			ប្រសិនបើ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				goto out;
			}
		}
		bha_nga;
	pak_sa MUX_FWD_REMOTE:
		សម្រាប់ (i = 0; i < options.num_remote_forwards; i++) {
			ប្រសិនបើ (!compare_forward(&fwd, options.remote_forwards + i))
				continue;
			ប្រសិនបើ (fwd.listen_port != 0)
				goto exists;
			debug2_f("found allocated port");
			ប្រសិនបើ ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			goto out;
		}
		bha_nga;
	}

	ប្រសិនបើ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ប្រសិនបើ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			goto out;
		}
	}

	ប្រសិនបើ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ប្រសិនបើ (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			goto out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} បើមិនដូច្នេះ {
		sa_nracanaa mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ប្រសិនបើ (fwd.handle < 0)
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
	ប្រសិនបើ (freefwd) {
		free(fwd.listen_host);
		free(fwd.listen_path);
		free(fwd.connect_host);
		free(fwd.connect_path);
	}
	ត្រឡប់ ret;
}

static ចំនួនគត់
mux_master_process_close_fwd(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	sa_nracanaa Forward fwd, *found_fwd;
	var_na *fwd_desc = NULL;
	const var_na *error_reason = NULL;
	var_na *listen_addr = NULL, *connect_addr = NULL;
	u_int ftype;
	ចំនួនគត់ r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, parimaa_na(fwd));

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
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

	ប្រសិនបើ (*listen_addr == '\0') {
		free(listen_addr);
		listen_addr = NULL;
	}
	ប្រសិនបើ (*connect_addr == '\0') {
		free(connect_addr);
		connect_addr = NULL;
	}

	memset(&fwd, 0, parimaa_na(fwd));
	fwd.listen_port = lport;
	ប្រសិនបើ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	បើមិនដូច្នេះ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ប្រសិនបើ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	បើមិនដូច្នេះ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = NULL;
	switch (ftype) {
	pak_sa MUX_FWD_LOCAL:
	pak_sa MUX_FWD_DYNAMIC:
		សម្រាប់ (i = 0; i < options.num_local_forwards; i++) {
			ប្រសិនបើ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				bha_nga;
			}
		}
		bha_nga;
	pak_sa MUX_FWD_REMOTE:
		សម្រាប់ (i = 0; i < options.num_remote_forwards; i++) {
			ប្រសិនបើ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				bha_nga;
			}
		}
		bha_nga;
	}

	ប្រសិនបើ (found_fwd == NULL)
		error_reason = "port not forwarded";
	បើមិនដូច្នេះ ប្រសិនបើ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ប្រសិនបើ (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} បើមិនដូច្នេះ {	/* local and dynamic forwards */
		/* Ditto */
		ប្រសិនបើ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ប្រសិនបើ (error_reason != NULL)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	បើមិនដូច្នេះ {
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

	ត្រឡប់ ret;
}

static ចំនួនគត់
mux_master_process_stdio_fwd(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	Channel *nc;
	var_na *chost = NULL;
	u_int _cport, i, j;
	ចំនួនគត់ ok = 0, cport, r, new_fd[2];
	sa_nracanaa mux_stdio_confirm_ctx *cctx;

	ប្រសិនបើ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		free(chost);
		error_f("malformed message");
		ត្រឡប់ -1;
	}
	ប្រសិនបើ (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	បើមិនដូច្នេះ ប្រសិនបើ (_cport <= INT_MAX)
		cport = (ចំនួនគត់)_cport;
	បើមិនដូច្នេះ {
		free(chost);
		error_f("invalid port 0x%x", _cport);
		ត្រឡប់ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	សម្រាប់(i = 0; i < 2; i++) {
		ប្រសិនបើ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			សម្រាប់ (j = 0; j < i; j++)
				close(new_fd[j]);
			free(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ត្រឡប់ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ប្រសិនបើ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		free(chost);
		ត្រឡប់ 0;
	}

	ប្រសិនបើ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ប្រសិនបើ (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} បើមិនដូច្នេះ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ប្រសិនបើ (!ok) {
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
	ត្រឡប់ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
static void
mux_stdio_confirm(sa_nracanaa ssh *ssh, ចំនួនគត់ id, ចំនួនគត់ success, void *arg)
{
	sa_nracanaa mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	sa_nracanaa sshbuf *reply;
	ចំនួនគត់ r;

	ប្រសិនបើ (cctx == NULL)
		fatal_f("cctx == NULL");
	ប្រសិនបើ ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("no channel for id %d", id);
	ប្រសិនបើ ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ប្រសិនបើ ((reply = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	ប្រសិនបើ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		goto done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ប្រសិនបើ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ប្រសិនបើ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ប្រសិនបើ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = NULL;
	free(cctx);
}

static ចំនួនគត់
mux_master_process_stop_listening(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	ប្រសិនបើ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ប្រសិនបើ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ត្រឡប់ 0;
		}
	}

	ប្រសិនបើ (mux_listener_channel != NULL) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		free(options.control_path);
		options.control_path = NULL;
		mux_listener_channel = NULL;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_master_process_proxy(sa_nracanaa ssh *ssh, u_int rid,
    Channel *c, sa_nracanaa sshbuf *m, sa_nracanaa sshbuf *reply)
{
	ចំនួនគត់ r;

	debug_f("channel %d: proxy request", c->self);

	ប្រសិនបើ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ប្រសិនបើ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ត្រឡប់ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ប្រសិនបើ ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	ត្រឡប់ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
static ចំនួនគត់
mux_master_read_cb(sa_nracanaa ssh *ssh, Channel *c)
{
	sa_nracanaa mux_master_state *state = (sa_nracanaa mux_master_state *)c->mux_ctx;
	sa_nracanaa sshbuf *in = NULL, *out = NULL;
	u_int type, rid, i;
	ចំនួនគត់ r, ret = -1;

	ប្រសិនបើ ((out = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ប្រសិនបើ (c->mux_ctx == NULL) {
		state = xcalloc(1, parimaa_na(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ប្រសិនបើ ((r = sshbuf_put_u32(out, MUX_MSG_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ប្រសិនបើ ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		ប្រសិនបើ ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		goto out;
	}

	/* Channel code ensures that we receive whole packets */
	ប្រសិនបើ ((r = sshbuf_froms(c->input, &in)) != 0) {
 malf:
		error_f("malformed message");
		goto out;
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(in, &type)) != 0)
		goto malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	ប្រសិនបើ (type == MUX_MSG_HELLO)
		rid = 0;
	បើមិនដូច្នេះ {
		ប្រសិនបើ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_MSG_HELLO, type);
			goto out;
		}
		ប្រសិនបើ ((r = sshbuf_get_u32(in, &rid)) != 0)
			goto malf;
	}

	សម្រាប់ (i = 0; mux_master_handlers[i].handler != NULL; i++) {
		ប្រសិនបើ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			bha_nga;
		}
	}
	ប្រសិនបើ (mux_master_handlers[i].handler == NULL) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ប្រសិនបើ (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	ត្រឡប់ ret;
}

void
mux_exit_message(sa_nracanaa ssh *ssh, Channel *c, ចំនួនគត់ exitval)
{
	sa_nracanaa sshbuf *m;
	Channel *mux_chan;
	ចំនួនគត់ r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ប្រសិនបើ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
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
	ចំនួនគត់ r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ប្រសិនបើ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
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
	ចំនួនគត់ oerrno;

	ប្រសិនបើ (options.control_path == NULL ||
	    options.control_master == SSHCTL_MASTER_NO)
		ត្រឡប់;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	សម្រាប់ (i = 0; i < parimaa_na(rbuf) - 1; i++) {
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
	ប្រសិនបើ (muxserver_sock < 0) {
		ប្រសិនបើ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			ប្រសិនបើ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			free(orig_control_path);
			free(options.control_path);
			options.control_path = NULL;
			options.control_master = SSHCTL_MASTER_NO;
			ត្រឡប់;
		} បើមិនដូច្នេះ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ប្រសិនបើ (link(options.control_path, orig_control_path) != 0) {
		ប្រសិនបើ (errno != EEXIST) {
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
mux_session_confirm(sa_nracanaa ssh *ssh, ចំនួនគត់ id, ចំនួនគត់ success, void *arg)
{
	sa_nracanaa mux_session_confirm_ctx *cctx = arg;
	const var_na *display;
	Channel *c, *cc;
	ចំនួនគត់ i, r;
	sa_nracanaa sshbuf *reply;

	ប្រសិនបើ (cctx == NULL)
		fatal_f("cctx == NULL");
	ប្រសិនបើ ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("no channel for id %d", id);
	ប្រសិនបើ ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ប្រសិនបើ ((reply = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	ប្រសិនបើ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		goto done;
	}

	display = getenv("DISPLAY");
	ប្រសិនបើ (cctx->want_x_fwd && options.forward_x11 && display != NULL) {
		var_na *proto, *data;

		/* Get reasonable local authentication information. */
		ប្រសិនបើ (client_x11_get_proto(ssh, display, options.xauth_location,
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

	ប្រសិនបើ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ប្រសិនបើ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ប្រសិនបើ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ប្រសិនបើ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = NULL;
	sshbuf_free(cctx->cmd);
	free(cctx->term);
	ប្រសិនបើ (cctx->env != NULL) {
		សម្រាប់ (i = 0; cctx->env[i] != NULL; i++)
			free(cctx->env[i]);
		free(cctx->env);
	}
	free(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
static void
control_client_sighandler(ចំនួនគត់ signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
static void
control_client_sigrelay(ចំនួនគត់ signo)
{
	ចំនួនគត់ save_errno = errno;

	ប្រសិនបើ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

static ចំនួនគត់
mux_client_read(ចំនួនគត់ fd, sa_nracanaa sshbuf *b, size_t need, ចំនួនគត់ timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	សម្រាប់ (have = 0; have < need; ) {
		ប្រសិនបើ (muxclient_terminate) {
			errno = EINTR;
			ត្រឡប់ -1;
		}
		len = read(fd, p + have, need - have);
		ប្រសិនបើ (len == -1) {
			switch (errno) {
#ប្រសិនបើ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			pak_sa EWOULDBLOCK:
#endif
			pak_sa EAGAIN:
				ប្រសិនបើ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ត្រឡប់ -1;	/* timeout */
				/* FALLTHROUGH */
			pak_sa EINTR:
				continue;
			default:
				ត្រឡប់ -1;
			}
		}
		ប្រសិនបើ (len == 0) {
			errno = EPIPE;
			ត្រឡប់ -1;
		}
		have += (size_t)len;
	}
	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_client_write_packet(ចំនួនគត់ fd, sa_nracanaa sshbuf *m)
{
	sa_nracanaa sshbuf *queue;
	u_int have, need;
	ចំនួនគត់ r, oerrno, len;
	const u_char *ptr;
	sa_nracanaa pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ប្រសិនបើ ((queue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	សម្រាប់ (have = 0; have < need; ) {
		ប្រសិនបើ (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			ត្រឡប់ -1;
		}
		len = write(fd, ptr + have, need - have);
		ប្រសិនបើ (len == -1) {
			switch (errno) {
#ប្រសិនបើ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
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
				ត្រឡប់ -1;
			}
		}
		ប្រសិនបើ (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			ត្រឡប់ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_client_read_packet_timeout(ចំនួនគត់ fd, sa_nracanaa sshbuf *m, ចំនួនគត់ timeout_ms)
{
	sa_nracanaa sshbuf *queue;
	size_t need, have;
	const u_char *ptr;
	ចំនួនគត់ r, oerrno;

	ប្រសិនបើ ((queue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		ប្រសិនបើ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ត្រឡប់ -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	ប្រសិនបើ (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ត្រឡប់ -1;
	}
	ប្រសិនបើ ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_client_read_packet(ចំនួនគត់ fd, sa_nracanaa sshbuf *m)
{
	ត្រឡប់ mux_client_read_packet_timeout(fd, m, -1);
}

static ចំនួនគត់
mux_client_hello_exchange(ចំនួនគត់ fd, ចំនួនគត់ timeout_ms)
{
	sa_nracanaa sshbuf *m;
	u_int type, ver;
	ចំនួនគត់ r, ret = -1;

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_MSG_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		goto out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ប្រសិនបើ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		goto out;
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ប្រសិនបើ (type != MUX_MSG_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_MSG_HELLO, type);
		goto out;
	}
	ប្រសិនបើ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ប្រសិនបើ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		goto out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ខណៈពេល (sshbuf_len(m) > 0) {
		var_na *name = NULL;

		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /* value */
			error_fr(r, "parse extension");
			goto out;
		}
		/* Process extensions. */
		ប្រសិនបើ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} បើមិនដូច្នេះ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		free(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	ត្រឡប់ ret;
}

static u_int
mux_client_request_alive(ចំនួនគត់ fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int pid, type, rid;
	ចំនួនគត់ r;

	debug3_f("entering");

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ត្រឡប់ 0;
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ប្រសិនបើ (type != MUX_S_ALIVE) {
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ប្រសិនបើ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ត្រឡប់ pid;
}

static var_na *
mux_client_request_info(ចំនួនគត់ fd, const var_na *name)
{
	sa_nracanaa sshbuf *m;
	var_na *e, *msg;
	u_int type, rid, status;
	ចំនួនគត់ r;

	debug3_f("entering");

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ត្រឡប់ 0;
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ប្រសិនបើ (type != MUX_S_EXT_INFO) {
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ប្រសិនបើ ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, NULL)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ត្រឡប់ msg;
}

static void
mux_client_request_terminate(ចំនួនគត់ fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid;
	ចំនួនគត់ r;

	debug3_f("entering");

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ប្រសិនបើ (errno == EPIPE) {
			sshbuf_free(m);
			ត្រឡប់;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	switch (type) {
	pak_sa MUX_S_OK:
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	pak_sa MUX_S_FAILURE:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

static ចំនួនគត់
mux_client_forward(ចំនួនគត់ fd, ចំនួនគត់ cancel_flag, u_int ftype, sa_nracanaa Forward *fwd)
{
	sa_nracanaa sshbuf *m;
	var_na *e, *fwd_desc;
	const var_na *lhost, *chost;
	u_int type, rid;
	ចំនួនគត់ r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	free(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ប្រសិនបើ (fwd->listen_path != NULL)
		lhost = fwd->listen_path;
	បើមិនដូច្នេះ ប្រសិនបើ (fwd->listen_host == NULL)
		lhost = "";
	បើមិនដូច្នេះ ប្រសិនបើ (*fwd->listen_host == '\0')
		lhost = "*";
	បើមិនដូច្នេះ
		lhost = fwd->listen_host;

	ប្រសិនបើ (fwd->connect_path != NULL)
		chost = fwd->connect_path;
	បើមិនដូច្នេះ ប្រសិនបើ (fwd->connect_host == NULL)
		chost = "";
	បើមិនដូច្នេះ
		chost = fwd->connect_host;

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ត្រឡប់ -1;
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	pak_sa MUX_S_OK:
		bha_nga;
	pak_sa MUX_S_REMOTE_PORT:
		ប្រសិនបើ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ប្រសិនបើ ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		ប្រសិនបើ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ត្រឡប់ -1;
	pak_sa MUX_S_FAILURE:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ត្រឡប់ -1;
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_client_forwards(ចំនួនគត់ fd, ចំនួនគត់ cancel_flag)
{
	ចំនួនគត់ i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.num_local_forwards, options.num_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	សម្រាប់ (i = 0; i < options.num_local_forwards; i++) {
		ប្រសិនបើ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	សម្រាប់ (i = 0; i < options.num_remote_forwards; i++) {
		ប្រសិនបើ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ត្រឡប់ ret;
}

static ចំនួនគត់
mux_client_request_session(ចំនួនគត់ fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	const var_na *term = NULL;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	extern var_na **environ;
	ចំនួនគត់ r, rawmode = 0;

	debug3_f("entering");

	ប្រសិនបើ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ត្រឡប់ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ប្រសិនបើ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ប្រសិនបើ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.num_setenv)) == NULL || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	ប្រសិនបើ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
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
	ប្រសិនបើ (options.num_send_env > 0 && environ != NULL) {
		សម្រាប់ (i = 0; environ[i] != NULL; i++) {
			ប្រសិនបើ (!env_permitted(environ[i]))
				continue;
			ប្រសិនបើ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	សម្រាប់ (i = 0; i < options.num_setenv; i++) {
		ប្រសិនបើ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ប្រសិនបើ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ត្រឡប់ -1;
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	pak_sa MUX_S_SESSION_OPENED:
		ប្រសិនបើ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ត្រឡប់ -1;
	pak_sa MUX_S_FAILURE:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ត្រឡប់ -1;
	default:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ត្រឡប់ -1;
	}
	muxclient_request_id++;

	ប្រសិនបើ (pledge("stdio proc tty", NULL) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ប្រសិនបើ (options.fork_after_authentication)
		daemon(1, 1);
	បើមិនដូច្នេះ {
		rawmode = tty_flag;
		ប្រសិនបើ (tty_flag) {
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
	សម្រាប់ (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		ប្រសិនបើ (mux_client_read_packet(fd, m) != 0)
			bha_nga;
		ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		switch (type) {
		pak_sa MUX_S_TTY_ALLOC_FAIL:
			ប្រសិនបើ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ប្រសិនបើ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			continue;
		pak_sa MUX_S_EXIT_MESSAGE:
			ប្រសិនបើ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ប្រសិនបើ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ប្រសិនបើ (exitval_seen)
				fatal_f("exitval sent twice");
			ប្រសិនបើ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			continue;
		default:
			ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ប្រសិនបើ (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	ប្រសិនបើ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} បើមិនដូច្នេះ ប្រសិនបើ (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} បើមិនដូច្នេះ
		debug2("Received exit status from master %d", exitval);

	ប្រសិនបើ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

static ចំនួនគត់
mux_client_proxy(ចំនួនគត់ fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid;
	ចំនួនគត់ r;

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ត្រឡប់ 0;
	}
	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ប្រសិនបើ (type != MUX_S_PROXY) {
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ត្រឡប់ 0;
}

static ចំនួនគត់
mux_client_request_stdio_fwd(ចំនួនគត់ fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid, sid;
	ចំនួនគត់ r;

	debug3_f("entering");

	ប្រសិនបើ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ត្រឡប់ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ប្រសិនបើ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ប្រសិនបើ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ប្រសិនបើ (pledge("stdio proc tty", NULL) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ត្រឡប់ -1;
	}

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	switch (type) {
	pak_sa MUX_S_SESSION_OPENED:
		ប្រសិនបើ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	pak_sa MUX_S_FAILURE:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	default:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ត្រឡប់ -1;
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
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0) {
		ប្រសិនបើ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ត្រឡប់ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

static void
mux_client_request_stop_listening(ចំនួនគត់ fd)
{
	sa_nracanaa sshbuf *m;
	var_na *e;
	u_int type, rid;
	ចំនួនគត់ r;

	debug3_f("entering");

	ប្រសិនបើ ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	ប្រសិនបើ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ប្រសិនបើ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ប្រសិនបើ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ប្រសិនបើ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ប្រសិនបើ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	pak_sa MUX_S_OK:
		bha_nga;
	pak_sa MUX_S_PERMISSION_DENIED:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	pak_sa MUX_S_FAILURE:
		ប្រសិនបើ ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
ចំនួនគត់
muxclient(const var_na *path)
{
	sa_nracanaa sockaddr_un addr;
	ចំនួនគត់ sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	var_na *info = NULL;

	ប្រសិនបើ (muxclient_command == 0) {
		ប្រសិនបើ (options.stdio_forward_host != NULL)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		បើមិនដូច្នេះ
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
		ត្រឡប់ -1;
	}

	memset(&addr, '\0', parimaa_na(addr));
	addr.sun_family = AF_UNIX;

	ប្រសិនបើ (strlcpy(addr.sun_path, path,
	    parimaa_na(addr.sun_path)) >= parimaa_na(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned ចំនួនគត់)parimaa_na(addr.sun_path));

	ប្រសិនបើ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ប្រសិនបើ (connect(sock, (sa_nracanaa sockaddr *)&addr, parimaa_na(addr)) == -1) {
		switch (muxclient_command) {
		pak_sa SSHMUX_COMMAND_OPEN:
		pak_sa SSHMUX_COMMAND_STDIO_FWD:
			bha_nga;
		default:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		ប្រសិនបើ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} បើមិនដូច្នេះ ប្រសិនបើ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} បើមិនដូច្នេះ {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		ត្រឡប់ -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	ប្រសិនបើ (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	ប្រសិនបើ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ត្រឡប់ -1;
	}

	switch (muxclient_command) {
	pak_sa SSHMUX_COMMAND_ALIVE_CHECK:
		ប្រសិនបើ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	pak_sa SSHMUX_COMMAND_CONNINFO:
	pak_sa SSHMUX_COMMAND_CHANINFO:
		ប្រសិនបើ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ប្រសិនបើ (info == NULL)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	pak_sa SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ប្រសិនបើ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	pak_sa SSHMUX_COMMAND_FORWARD:
		ប្រសិនបើ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	pak_sa SSHMUX_COMMAND_OPEN:
		ប្រសិនបើ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ត្រឡប់ -1;
		}
		mux_client_request_session(sock);
		ត្រឡប់ -1;
	pak_sa SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	pak_sa SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ប្រសិនបើ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	pak_sa SSHMUX_COMMAND_CANCEL_FWD:
		ប្រសិនបើ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	pak_sa SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ត្រឡប់ (sock);
	default:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
