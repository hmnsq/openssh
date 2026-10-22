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
extern 整数 tty_flag;
extern Options options;
extern char *host;
extern struct sshbuf *command;
extern volatile sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
struct mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	struct sshbuf *cmd;
	char *term;
	struct termios tio;
	char **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
struct mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
struct mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	整数 fid;	/* forward id */
};

/* fd to control socket */
整数 muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
static volatile sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
static u_int muxserver_pid = 0;

static Channel *mux_listener_channel = NULL;

struct mux_master_state {
	整数 hello_rcvd;
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

static void mux_session_confirm(struct ssh *, 整数, 整数, void *);
static void mux_stdio_confirm(struct ssh *, 整数, 整数, void *);

static 整数 mux_master_process_hello(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_new_session(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_alive_check(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_terminate(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_open_fwd(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_close_fwd(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_stdio_fwd(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_stop_listening(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_proxy(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);
static 整数 mux_master_process_ext_info(struct ssh *, u_int,
	    Channel *, struct sshbuf *, struct sshbuf *);

static const struct {
	u_int type;
	整数 (*handler)(struct ssh *, u_int, Channel *,
	    struct sshbuf *, struct sshbuf *);
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
mux_master_session_cleanup_cb(struct ssh *ssh, 整数 cid, 整数 force, void *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	如果 (c == NULL)
		fatal_f("channel_by_id(%i) == NULL", cid);
	如果 (c->ctl_chan != -1) {
		如果 ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
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
mux_master_control_cleanup_cb(struct ssh *ssh, 整数 cid, 整数 force, void *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	如果 (c == NULL)
		fatal_f("channel_by_id(%i) == NULL", cid);
	如果 (c->have_ctl_child_id) {
		如果 ((sc = channel_by_id(ssh, c->ctl_child_id)) == NULL)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		如果 (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} 否则 {
			如果 (sc->istate == CHAN_INPUT_OPEN)
				chan_read_failed(ssh, sc);
			如果 (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
static 整数
env_permitted(const char *env)
{
	u_int i;
	整数 ret;
	char name[1024], *cp;

	如果 ((cp = strchr(env, '=')) == NULL || cp == env)
		返回 0;
	ret = snprintf(name, sizeof(name), "%.*s", (整数)(cp - env), env);
	如果 (ret <= 0 || (size_t)ret >= sizeof(name)) {
		error_f("name '%.100s...' too long", env);
		返回 0;
	}

	为 (i = 0; i < options.num_send_env; i++)
		如果 (match_pattern(name, options.send_env[i]))
			返回 1;

	返回 0;
}

/* Mux master protocol message handlers */

static 整数
mux_master_process_hello(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	u_int ver;
	struct mux_master_state *state = (struct mux_master_state *)c->mux_ctx;
	整数 r;

	如果 (state == NULL)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	如果 (state->hello_rcvd) {
		error_f("HELLO received twice");
		返回 -1;
	}
	如果 ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		返回 -1;
	}
	如果 (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		返回 -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	当 (sshbuf_len(m) > 0) {
		char *name = NULL;
		size_t value_len = 0;

		如果 ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
		    (r = sshbuf_get_string_direct(m, NULL, &value_len)) != 0) {
			error_fr(r, "parse extension");
			返回 -1;
		}
		如果 (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} 否则 {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, value_len);
		}
		free(name);
	}
	state->hello_rcvd = 1;
	返回 0;
}

/* Enqueue a "ok" response to the reply buffer */
static void
reply_ok(struct sshbuf *reply, u_int rid)
{
	整数 r;

	如果 ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
static void
reply_error(struct sshbuf *reply, u_int type, u_int rid, const char *msg)
{
	整数 r;

	如果 ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
}

static 整数
mux_master_process_new_session(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	Channel *nc;
	struct mux_session_confirm_ctx *cctx;
	char *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	整数 r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, sizeof(*cctx));
	cctx->term = NULL;
	cctx->rid = rid;
	cmd = NULL;
	cctx->env = NULL;
	env_len = 0;
	如果 ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, NULL)) != 0) {
 malf:
		free(cmd);
		为 (j = 0; j < env_len; j++)
			free(cctx->env[j]);
		free(cctx->env);
		free(cctx->term);
		free(cctx);
		error_f("malformed message");
		返回 -1;
	}

#define MUX_MAX_ENV_VARS	4096
	当 (sshbuf_len(m) > 0) {
		如果 ((r = sshbuf_get_cstring(m, &cp, NULL)) != 0)
			goto malf;
		如果 (!env_permitted(cp)) {
			free(cp);
			continue;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    sizeof(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = NULL;
		如果 (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			break;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	如果 ((cctx->cmd = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	free(cmd);
	cmd = NULL;

	/* Gather fds from client */
	为(i = 0; i < 3; i++) {
		如果 ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			为 (j = 0; j < i; j++)
				close(new_fd[j]);
			为 (j = 0; j < env_len; j++)
				free(cctx->env[j]);
			free(cctx->env);
			free(cctx->term);
			sshbuf_free(cctx->cmd);
			free(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			返回 -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	如果 (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		free(cctx->term);
		如果 (env_len != 0) {
			为 (i = 0; i < env_len; i++)
				free(cctx->env[i]);
			free(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		free(cctx);
		返回 0;
	}

	如果 (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		如果 (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			goto cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	如果 (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	如果 (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	如果 (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	如果 (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, NULL,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((整数)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	返回 0;
}

static 整数
mux_master_process_alive_check(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	整数 r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	如果 ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	返回 0;
}

/* The "info" extension. */
static 整数
mux_master_process_ext_info(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	整数 r;
	u_int status = 0;
	char *name = NULL, *msg = NULL;

	debug2_f("channel %d: info request", c->self);

	如果 ((r = sshbuf_get_cstring(m, &name, NULL)) != 0)
		fatal_fr(r, "parse");

	如果 (strcmp(name, "connection") == 0) {
		如果 ((msg = connection_info_message(ssh)) == NULL)
			fatal_f("connection_info_message");
		status = 1;
	} 否则 如果 (strcmp(name, "channels") == 0) {
		如果 ((msg = channel_open_message(ssh)) == NULL)
			fatal_f("channel_open_message");
		status = 1;
	} 否则 {
		msg = xstrdup("info request type not supported");
	}

	/* prepare reply */
	如果 ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
	free(msg);

	返回 0;
}

static 整数
mux_master_process_terminate(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	如果 (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		如果 (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			返回 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	返回 0;
}

static char *
format_forward(u_int ftype, struct Forward *fwd)
{
	char *ret;

	switch (ftype) {
	case MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != NULL) ? fwd->listen_path :
		    (fwd->listen_host == NULL) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != NULL) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		break;
	case MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == NULL) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		break;
	case MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != NULL) ? fwd->listen_path :
		    (fwd->listen_host == NULL) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != NULL) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		break;
	default:
		fatal_f("unknown forward type %u", ftype);
	}
	返回 ret;
}

static 整数
compare_host(const char *a, const char *b)
{
	如果 (a == NULL && b == NULL)
		返回 1;
	如果 (a == NULL || b == NULL)
		返回 0;
	返回 strcmp(a, b) == 0;
}

static 整数
compare_forward(struct Forward *a, struct Forward *b)
{
	如果 (!compare_host(a->listen_host, b->listen_host))
		返回 0;
	如果 (!compare_host(a->listen_path, b->listen_path))
		返回 0;
	如果 (a->listen_port != b->listen_port)
		返回 0;
	如果 (!compare_host(a->connect_host, b->connect_host))
		返回 0;
	如果 (!compare_host(a->connect_path, b->connect_path))
		返回 0;
	如果 (a->connect_port != b->connect_port)
		返回 0;

	返回 1;
}

static void
mux_confirm_remote_forward(struct ssh *ssh, 整数 type, uint32_t seq, void *ctxt)
{
	struct mux_channel_confirm_ctx *fctx = ctxt;
	char *failmsg = NULL;
	struct Forward *rfwd;
	Channel *c;
	struct sshbuf *out;
	u_int port;
	整数 r;

	如果 ((c = channel_by_id(ssh, fctx->cid)) == NULL) {
		/* no channel for reply */
		error_f("unknown channel");
		返回;
	}
	如果 ((out = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 (fctx->fid >= options.num_remote_forwards ||
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
	如果 (type == SSH2_MSG_REQUEST_SUCCESS) {
		如果 (rfwd->listen_port == 0) {
			如果 ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			如果 (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (整数)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			如果 ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} 否则 {
			reply_ok(out, fctx->rid);
		}
		goto out;
	} 否则 {
		如果 (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		如果 (rfwd->listen_path != NULL)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		否则
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
		memset(rfwd, 0, sizeof(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	free(failmsg);
 out:
	如果 ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	如果 (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	free(fctx);
}

static 整数
mux_master_process_open_fwd(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	struct Forward fwd;
	char *fwd_desc = NULL;
	char *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	整数 r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, sizeof(fwd));

	/* XXX - lport/cport check redundant */
	如果 ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
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
	如果 (*listen_addr == '\0') {
		free(listen_addr);
		listen_addr = NULL;
	}
	如果 (*connect_addr == '\0') {
		free(connect_addr);
		connect_addr = NULL;
	}

	memset(&fwd, 0, sizeof(fwd));
	fwd.listen_port = lport;
	如果 (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	否则
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	如果 (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	否则
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	如果 (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		free(listen_addr);
		free(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		返回 0;
	}
	如果 (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		goto invalid;
	}
	如果 (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		goto invalid;
	}
	如果 ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		goto invalid;
	}
	如果 (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == NULL &&
	    fwd.connect_path == NULL) {
		logit_f("missing connect host");
		goto invalid;
	}

	/* Skip forwards that have already been requested */
	switch (ftype) {
	case MUX_FWD_LOCAL:
	case MUX_FWD_DYNAMIC:
		为 (i = 0; i < options.num_local_forwards; i++) {
			如果 (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				goto out;
			}
		}
		break;
	case MUX_FWD_REMOTE:
		为 (i = 0; i < options.num_remote_forwards; i++) {
			如果 (!compare_forward(&fwd, options.remote_forwards + i))
				continue;
			如果 (fwd.listen_port != 0)
				goto exists;
			debug2_f("found allocated port");
			如果 ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			goto out;
		}
		break;
	}

	如果 (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		如果 (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			goto out;
		}
	}

	如果 (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		如果 (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			goto out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} 否则 {
		struct mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		如果 (fwd.handle < 0)
			goto fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, sizeof(*fctx));
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
	如果 (freefwd) {
		free(fwd.listen_host);
		free(fwd.listen_path);
		free(fwd.connect_host);
		free(fwd.connect_path);
	}
	返回 ret;
}

static 整数
mux_master_process_close_fwd(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	struct Forward fwd, *found_fwd;
	char *fwd_desc = NULL;
	const char *error_reason = NULL;
	char *listen_addr = NULL, *connect_addr = NULL;
	u_int ftype;
	整数 r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, sizeof(fwd));

	如果 ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
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

	如果 (*listen_addr == '\0') {
		free(listen_addr);
		listen_addr = NULL;
	}
	如果 (*connect_addr == '\0') {
		free(connect_addr);
		connect_addr = NULL;
	}

	memset(&fwd, 0, sizeof(fwd));
	fwd.listen_port = lport;
	如果 (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	否则
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	如果 (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	否则
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = NULL;
	switch (ftype) {
	case MUX_FWD_LOCAL:
	case MUX_FWD_DYNAMIC:
		为 (i = 0; i < options.num_local_forwards; i++) {
			如果 (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				break;
			}
		}
		break;
	case MUX_FWD_REMOTE:
		为 (i = 0; i < options.num_remote_forwards; i++) {
			如果 (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				break;
			}
		}
		break;
	}

	如果 (found_fwd == NULL)
		error_reason = "port not forwarded";
	否则 如果 (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		如果 (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} 否则 {	/* local and dynamic forwards */
		/* Ditto */
		如果 (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	如果 (error_reason != NULL)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	否则 {
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

	返回 ret;
}

static 整数
mux_master_process_stdio_fwd(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	Channel *nc;
	char *chost = NULL;
	u_int _cport, i, j;
	整数 ok = 0, cport, r, new_fd[2];
	struct mux_stdio_confirm_ctx *cctx;

	如果 ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, NULL)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		free(chost);
		error_f("malformed message");
		返回 -1;
	}
	如果 (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	否则 如果 (_cport <= INT_MAX)
		cport = (整数)_cport;
	否则 {
		free(chost);
		error_f("invalid port 0x%x", _cport);
		返回 -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	为(i = 0; i < 2; i++) {
		如果 ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			为 (j = 0; j < i; j++)
				close(new_fd[j]);
			free(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			返回 -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	如果 (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		free(chost);
		返回 0;
	}

	如果 (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		如果 (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} 否则 {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		如果 (!ok) {
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

	cctx = xcalloc(1, sizeof(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	返回 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
static void
mux_stdio_confirm(struct ssh *ssh, 整数 id, 整数 success, void *arg)
{
	struct mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	struct sshbuf *reply;
	整数 r;

	如果 (cctx == NULL)
		fatal_f("cctx == NULL");
	如果 ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("no channel for id %d", id);
	如果 ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	如果 ((reply = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	如果 (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		goto done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	如果 ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	如果 ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	如果 (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = NULL;
	free(cctx);
}

static 整数
mux_master_process_stop_listening(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	如果 (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		如果 (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			返回 0;
		}
	}

	如果 (mux_listener_channel != NULL) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		free(options.control_path);
		options.control_path = NULL;
		mux_listener_channel = NULL;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	返回 0;
}

static 整数
mux_master_process_proxy(struct ssh *ssh, u_int rid,
    Channel *c, struct sshbuf *m, struct sshbuf *reply)
{
	整数 r;

	debug_f("channel %d: proxy request", c->self);

	如果 (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		如果 (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			返回 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	如果 ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	返回 0;
}

/* Channel callbacks fired on read/write from mux client fd */
static 整数
mux_master_read_cb(struct ssh *ssh, Channel *c)
{
	struct mux_master_state *state = (struct mux_master_state *)c->mux_ctx;
	struct sshbuf *in = NULL, *out = NULL;
	u_int type, rid, i;
	整数 r, ret = -1;

	如果 ((out = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	如果 (c->mux_ctx == NULL) {
		state = xcalloc(1, sizeof(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		如果 ((r = sshbuf_put_u32(out, MUX_MSG_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		如果 ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		如果 ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		goto out;
	}

	/* Channel code ensures that we receive whole packets */
	如果 ((r = sshbuf_froms(c->input, &in)) != 0) {
 malf:
		error_f("malformed message");
		goto out;
	}

	如果 ((r = sshbuf_get_u32(in, &type)) != 0)
		goto malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	如果 (type == MUX_MSG_HELLO)
		rid = 0;
	否则 {
		如果 (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_MSG_HELLO, type);
			goto out;
		}
		如果 ((r = sshbuf_get_u32(in, &rid)) != 0)
			goto malf;
	}

	为 (i = 0; mux_master_handlers[i].handler != NULL; i++) {
		如果 (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			break;
		}
	}
	如果 (mux_master_handlers[i].handler == NULL) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	如果 (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	返回 ret;
}

void
mux_exit_message(struct ssh *ssh, Channel *c, 整数 exitval)
{
	struct sshbuf *m;
	Channel *mux_chan;
	整数 r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	如果 ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

void
mux_tty_alloc_failed(struct ssh *ssh, Channel *c)
{
	struct sshbuf *m;
	Channel *mux_chan;
	整数 r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	如果 ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
void
muxserver_listen(struct ssh *ssh)
{
	mode_t old_umask;
	char *orig_control_path = options.control_path;
	char rbuf[16+1];
	u_int i, r;
	整数 oerrno;

	如果 (options.control_path == NULL ||
	    options.control_master == SSHCTL_MASTER_NO)
		返回;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	为 (i = 0; i < sizeof(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[sizeof(rbuf) - 1] = '\0';
	options.control_path = NULL;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	如果 (muxserver_sock < 0) {
		如果 (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			如果 (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			free(orig_control_path);
			free(options.control_path);
			options.control_path = NULL;
			options.control_master = SSHCTL_MASTER_NO;
			返回;
		} 否则 {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	如果 (link(options.control_path, orig_control_path) != 0) {
		如果 (errno != EEXIST) {
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
mux_session_confirm(struct ssh *ssh, 整数 id, 整数 success, void *arg)
{
	struct mux_session_confirm_ctx *cctx = arg;
	const char *display;
	Channel *c, *cc;
	整数 i, r;
	struct sshbuf *reply;

	如果 (cctx == NULL)
		fatal_f("cctx == NULL");
	如果 ((c = channel_by_id(ssh, id)) == NULL)
		fatal_f("no channel for id %d", id);
	如果 ((cc = channel_by_id(ssh, c->ctl_chan)) == NULL)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	如果 ((reply = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	如果 (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		goto done;
	}

	display = getenv("DISPLAY");
	如果 (cctx->want_x_fwd && options.forward_x11 && display != NULL) {
		char *proto, *data;

		/* Get reasonable local authentication information. */
		如果 (client_x11_get_proto(ssh, display, options.xauth_location,
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

	如果 (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	如果 ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	如果 ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	如果 (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = NULL;
	sshbuf_free(cctx->cmd);
	free(cctx->term);
	如果 (cctx->env != NULL) {
		为 (i = 0; cctx->env[i] != NULL; i++)
			free(cctx->env[i]);
		free(cctx->env);
	}
	free(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
static void
control_client_sighandler(整数 signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
static void
control_client_sigrelay(整数 signo)
{
	整数 save_errno = errno;

	如果 (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

static 整数
mux_client_read(整数 fd, struct sshbuf *b, size_t need, 整数 timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	整数 r;

	如果 ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	为 (have = 0; have < need; ) {
		如果 (muxclient_terminate) {
			errno = EINTR;
			返回 -1;
		}
		len = read(fd, p + have, need - have);
		如果 (len == -1) {
			switch (errno) {
#如果 defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			case EWOULDBLOCK:
#endif
			case EAGAIN:
				如果 (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					返回 -1;	/* timeout */
				/* FALLTHROUGH */
			case EINTR:
				continue;
			default:
				返回 -1;
			}
		}
		如果 (len == 0) {
			errno = EPIPE;
			返回 -1;
		}
		have += (size_t)len;
	}
	返回 0;
}

static 整数
mux_client_write_packet(整数 fd, struct sshbuf *m)
{
	struct sshbuf *queue;
	u_int have, need;
	整数 r, oerrno, len;
	const u_char *ptr;
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	如果 ((queue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	为 (have = 0; have < need; ) {
		如果 (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			返回 -1;
		}
		len = write(fd, ptr + have, need - have);
		如果 (len == -1) {
			switch (errno) {
#如果 defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			case EWOULDBLOCK:
#endif
			case EAGAIN:
				(void)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			case EINTR:
				continue;
			default:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				返回 -1;
			}
		}
		如果 (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			返回 -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	返回 0;
}

static 整数
mux_client_read_packet_timeout(整数 fd, struct sshbuf *m, 整数 timeout_ms)
{
	struct sshbuf *queue;
	size_t need, have;
	const u_char *ptr;
	整数 r, oerrno;

	如果 ((queue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		如果 ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		返回 -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	如果 (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		返回 -1;
	}
	如果 ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	返回 0;
}

static 整数
mux_client_read_packet(整数 fd, struct sshbuf *m)
{
	返回 mux_client_read_packet_timeout(fd, m, -1);
}

static 整数
mux_client_hello_exchange(整数 fd, 整数 timeout_ms)
{
	struct sshbuf *m;
	u_int type, ver;
	整数 r, ret = -1;

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_MSG_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	如果 (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		goto out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	如果 (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		goto out;
	}

	如果 ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	如果 (type != MUX_MSG_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_MSG_HELLO, type);
		goto out;
	}
	如果 ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	如果 (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		goto out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	当 (sshbuf_len(m) > 0) {
		char *name = NULL;

		如果 ((r = sshbuf_get_cstring(m, &name, NULL)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /* value */
			error_fr(r, "parse extension");
			goto out;
		}
		/* Process extensions. */
		如果 (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} 否则 {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		free(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	返回 ret;
}

static u_int
mux_client_request_alive(整数 fd)
{
	struct sshbuf *m;
	char *e;
	u_int pid, type, rid;
	整数 r;

	debug3_f("entering");

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	如果 (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		返回 0;
	}

	如果 ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	如果 (type != MUX_S_ALIVE) {
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	如果 ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	如果 ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	返回 pid;
}

static char *
mux_client_request_info(整数 fd, const char *name)
{
	struct sshbuf *m;
	char *e, *msg;
	u_int type, rid, status;
	整数 r;

	debug3_f("entering");

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	如果 (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		返回 0;
	}

	如果 ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	如果 (type != MUX_S_EXT_INFO) {
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	如果 ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	如果 ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, NULL)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	返回 msg;
}

static void
mux_client_request_terminate(整数 fd)
{
	struct sshbuf *m;
	char *e;
	u_int type, rid;
	整数 r;

	debug3_f("entering");

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	如果 (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		如果 (errno == EPIPE) {
			sshbuf_free(m);
			返回;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	如果 ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	switch (type) {
	case MUX_S_OK:
		break;
	case MUX_S_PERMISSION_DENIED:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	case MUX_S_FAILURE:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

static 整数
mux_client_forward(整数 fd, 整数 cancel_flag, u_int ftype, struct Forward *fwd)
{
	struct sshbuf *m;
	char *e, *fwd_desc;
	const char *lhost, *chost;
	u_int type, rid;
	整数 r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	free(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	如果 (fwd->listen_path != NULL)
		lhost = fwd->listen_path;
	否则 如果 (fwd->listen_host == NULL)
		lhost = "";
	否则 如果 (*fwd->listen_host == '\0')
		lhost = "*";
	否则
		lhost = fwd->listen_host;

	如果 (fwd->connect_path != NULL)
		chost = fwd->connect_path;
	否则 如果 (fwd->connect_host == NULL)
		chost = "";
	否则
		chost = fwd->connect_host;

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	如果 (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		返回 -1;
	}

	如果 ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	case MUX_S_OK:
		break;
	case MUX_S_REMOTE_PORT:
		如果 (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		如果 ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		如果 (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		break;
	case MUX_S_PERMISSION_DENIED:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		返回 -1;
	case MUX_S_FAILURE:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		返回 -1;
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	返回 0;
}

static 整数
mux_client_forwards(整数 fd, 整数 cancel_flag)
{
	整数 i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.num_local_forwards, options.num_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	为 (i = 0; i < options.num_local_forwards; i++) {
		如果 (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	为 (i = 0; i < options.num_remote_forwards; i++) {
		如果 (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	返回 ret;
}

static 整数
mux_client_request_session(整数 fd)
{
	struct sshbuf *m;
	char *e;
	const char *term = NULL;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	extern char **environ;
	整数 r, rawmode = 0;

	debug3_f("entering");

	如果 ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		返回 -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	如果 (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	如果 ((term = lookup_env_in_list("TERM", options.setenv,
	    options.num_setenv)) == NULL || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	如果 (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
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
	如果 (options.num_send_env > 0 && environ != NULL) {
		为 (i = 0; environ[i] != NULL; i++) {
			如果 (!env_permitted(environ[i]))
				continue;
			如果 ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	为 (i = 0; i < options.num_setenv; i++) {
		如果 ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	如果 (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	如果 (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		返回 -1;
	}

	如果 ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	case MUX_S_SESSION_OPENED:
		如果 ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		break;
	case MUX_S_PERMISSION_DENIED:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		返回 -1;
	case MUX_S_FAILURE:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		返回 -1;
	default:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		返回 -1;
	}
	muxclient_request_id++;

	如果 (pledge("stdio proc tty", NULL) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	如果 (options.fork_after_authentication)
		daemon(1, 1);
	否则 {
		rawmode = tty_flag;
		如果 (tty_flag) {
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
	为 (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		如果 (mux_client_read_packet(fd, m) != 0)
			break;
		如果 ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		switch (type) {
		case MUX_S_TTY_ALLOC_FAIL:
			如果 ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			如果 (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			continue;
		case MUX_S_EXIT_MESSAGE:
			如果 ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			如果 (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			如果 (exitval_seen)
				fatal_f("exitval sent twice");
			如果 ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			continue;
		default:
			如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	如果 (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	如果 (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} 否则 如果 (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} 否则
		debug2("Received exit status from master %d", exitval);

	如果 (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

static 整数
mux_client_proxy(整数 fd)
{
	struct sshbuf *m;
	char *e;
	u_int type, rid;
	整数 r;

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	如果 (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		返回 0;
	}
	如果 ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	如果 (type != MUX_S_PROXY) {
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	返回 0;
}

static 整数
mux_client_request_stdio_fwd(整数 fd)
{
	struct sshbuf *m;
	char *e;
	u_int type, rid, sid;
	整数 r;

	debug3_f("entering");

	如果 ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		返回 -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	如果 (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	如果 (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	如果 (pledge("stdio proc tty", NULL) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	如果 (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		返回 -1;
	}

	如果 ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	switch (type) {
	case MUX_S_SESSION_OPENED:
		如果 ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		break;
	case MUX_S_PERMISSION_DENIED:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	case MUX_S_FAILURE:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	default:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		返回 -1;
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
	如果 (mux_client_read_packet(fd, m) != 0) {
		如果 (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			返回 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

static void
mux_client_request_stop_listening(整数 fd)
{
	struct sshbuf *m;
	char *e;
	u_int type, rid;
	整数 r;

	debug3_f("entering");

	如果 ((m = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	如果 ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	如果 (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	如果 (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	如果 ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	如果 (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	switch (type) {
	case MUX_S_OK:
		break;
	case MUX_S_PERMISSION_DENIED:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	case MUX_S_FAILURE:
		如果 ((r = sshbuf_get_cstring(m, &e, NULL)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	default:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
整数
muxclient(const char *path)
{
	struct sockaddr_un addr;
	整数 sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	char *info = NULL;

	如果 (muxclient_command == 0) {
		如果 (options.stdio_forward_host != NULL)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		否则
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	switch (options.control_master) {
	case SSHCTL_MASTER_AUTO:
	case SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	case SSHCTL_MASTER_NO:
		break;
	default:
		返回 -1;
	}

	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;

	如果 (strlcpy(addr.sun_path, path,
	    sizeof(addr.sun_path)) >= sizeof(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned 整数)sizeof(addr.sun_path));

	如果 ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	如果 (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		switch (muxclient_command) {
		case SSHMUX_COMMAND_OPEN:
		case SSHMUX_COMMAND_STDIO_FWD:
			break;
		default:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		如果 (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} 否则 如果 (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} 否则 {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		返回 -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	如果 (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	如果 (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		返回 -1;
	}

	switch (muxclient_command) {
	case SSHMUX_COMMAND_ALIVE_CHECK:
		如果 ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	case SSHMUX_COMMAND_CONNINFO:
	case SSHMUX_COMMAND_CHANINFO:
		如果 (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		如果 (info == NULL)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	case SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		如果 (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	case SSHMUX_COMMAND_FORWARD:
		如果 (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	case SSHMUX_COMMAND_OPEN:
		如果 (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			返回 -1;
		}
		mux_client_request_session(sock);
		返回 -1;
	case SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	case SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		如果 (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	case SSHMUX_COMMAND_CANCEL_FWD:
		如果 (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	case SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		返回 (sock);
	default:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
