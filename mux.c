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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/queue.h>
#ضمن <sys/stat.h>
#ضمن <sys/socket.h>
#ضمن <sys/un.h>

#ضمن <errno.h>
#ضمن <poll.h>
#ضمن <limits.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stddef.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "log.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "misc.h"
#ضمن "match.h"
#ضمن "sshbuf.h"
#ضمن "channels.h"
#ضمن "packet.h"
#ضمن "monitor_fdpass.h"
#ضمن "sshpty.h"
#ضمن "readconf.h"
#ضمن "clientloop.h"

/* from ssh.c */
خارجي صحيح tty_flag;
خارجي Options options;
خارجي حرف *host;
خارجي بنية sshbuf *command;
خارجي متطاير sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
بنية mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	بنية sshbuf *cmd;
	حرف *term;
	بنية termios tio;
	حرف **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
بنية mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
بنية mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	صحيح fid;	/* forward id */
};

/* fd to control socket */
صحيح muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
ساكن متطاير sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
ساكن u_int muxserver_pid = 0;

ساكن Channel *mux_listener_channel = عدم;

بنية mux_master_state {
	صحيح hello_rcvd;
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
ساكن u_int extensions = 0;

ساكن فراغ mux_session_confirm(بنية ssh *, صحيح, صحيح, فراغ *);
ساكن فراغ mux_stdio_confirm(بنية ssh *, صحيح, صحيح, فراغ *);

ساكن صحيح mux_master_process_hello(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_new_session(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_alive_check(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_terminate(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_open_fwd(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_close_fwd(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_stdio_fwd(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_stop_listening(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_proxy(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);
ساكن صحيح mux_master_process_ext_info(بنية ssh *, u_int,
	    Channel *, بنية sshbuf *, بنية sshbuf *);

ساكن ثابت بنية {
	u_int type;
	صحيح (*handler)(بنية ssh *, u_int, Channel *,
	    بنية sshbuf *, بنية sshbuf *);
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
	{ 0, عدم }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
ساكن فراغ
mux_master_session_cleanup_cb(بنية ssh *ssh, صحيح cid, صحيح force, فراغ *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ܐܢ (c == عدم)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ܐܢ (c->ctl_chan != -1) {
		ܐܢ ((cc = channel_by_id(ssh, c->ctl_chan)) == عدم)
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
ساكن فراغ
mux_master_control_cleanup_cb(بنية ssh *ssh, صحيح cid, صحيح force, فراغ *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ܐܢ (c == عدم)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ܐܢ (c->have_ctl_child_id) {
		ܐܢ ((sc = channel_by_id(ssh, c->ctl_child_id)) == عدم)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		ܐܢ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} ܐܚܪܢܐ {
			ܐܢ (sc->istate == CHAN_INPUT_OPEN)
				chan_read_failed(ssh, sc);
			ܐܢ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
ساكن صحيح
env_permitted(ثابت حرف *env)
{
	u_int i;
	صحيح ret;
	حرف name[1024], *cp;

	ܐܢ ((cp = strchr(env, '=')) == عدم || cp == env)
		ܦܢܐ 0;
	ret = snprintf(name, حجم(name), "%.*s", (صحيح)(cp - env), env);
	ܐܢ (ret <= 0 || (size_t)ret >= حجم(name)) {
		error_f("name '%.100s...' too long", env);
		ܦܢܐ 0;
	}

	لكل (i = 0; i < options.num_send_env; i++)
		ܐܢ (match_pattern(name, options.send_env[i]))
			ܦܢܐ 1;

	ܦܢܐ 0;
}

/* Mux master protocol message handlers */

ساكن صحيح
mux_master_process_hello(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	u_int ver;
	بنية mux_master_state *state = (بنية mux_master_state *)c->mux_ctx;
	صحيح r;

	ܐܢ (state == عدم)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ܐܢ (state->hello_rcvd) {
		error_f("HELLO received twice");
		ܦܢܐ -1;
	}
	ܐܢ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ܦܢܐ -1;
	}
	ܐܢ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ܦܢܐ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ܟܡܐ (sshbuf_len(m) > 0) {
		حرف *name = عدم;
		size_t value_len = 0;

		ܐܢ ((r = sshbuf_get_cstring(m, &name, عدم)) != 0 ||
		    (r = sshbuf_get_string_direct(m, عدم, &value_len)) != 0) {
			error_fr(r, "parse extension");
			ܦܢܐ -1;
		}
		ܐܢ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ܐܚܪܢܐ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, value_len);
		}
		حرر(name);
	}
	state->hello_rcvd = 1;
	ܦܢܐ 0;
}

/* Enqueue a "ok" response to the reply buffer */
ساكن فراغ
reply_ok(بنية sshbuf *reply, u_int rid)
{
	صحيح r;

	ܐܢ ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ساكن فراغ
reply_error(بنية sshbuf *reply, u_int type, u_int rid, ثابت حرف *msg)
{
	صحيح r;

	ܐܢ ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
}

ساكن صحيح
mux_master_process_new_session(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	Channel *nc;
	بنية mux_session_confirm_ctx *cctx;
	حرف *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	صحيح r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, حجم(*cctx));
	cctx->term = عدم;
	cctx->rid = rid;
	cmd = عدم;
	cctx->env = عدم;
	env_len = 0;
	ܐܢ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, عدم)) != 0) {
 malf:
		حرر(cmd);
		لكل (j = 0; j < env_len; j++)
			حرر(cctx->env[j]);
		حرر(cctx->env);
		حرر(cctx->term);
		حرر(cctx);
		error_f("malformed message");
		ܦܢܐ -1;
	}

#define MUX_MAX_ENV_VARS	4096
	ܟܡܐ (sshbuf_len(m) > 0) {
		ܐܢ ((r = sshbuf_get_cstring(m, &cp, عدم)) != 0)
			اذهب malf;
		ܐܢ (!env_permitted(cp)) {
			حرر(cp);
			استمر;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    حجم(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = عدم;
		ܐܢ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			اكسر;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	ܐܢ ((cctx->cmd = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	حرر(cmd);
	cmd = عدم;

	/* Gather fds from client */
	لكل(i = 0; i < 3; i++) {
		ܐܢ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			لكل (j = 0; j < i; j++)
				close(new_fd[j]);
			لكل (j = 0; j < env_len; j++)
				حرر(cctx->env[j]);
			حرر(cctx->env);
			حرر(cctx->term);
			sshbuf_free(cctx->cmd);
			حرر(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ܦܢܐ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ܐܢ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		حرر(cctx->term);
		ܐܢ (env_len != 0) {
			لكل (i = 0; i < env_len; i++)
				حرر(cctx->env[i]);
			حرر(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		حرر(cctx);
		ܦܢܐ 0;
	}

	ܐܢ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ܐܢ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			اذهب cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ܐܢ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ܐܢ (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ܐܢ (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	ܐܢ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, عدم,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((صحيح)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ܦܢܐ 0;
}

ساكن صحيح
mux_master_process_alive_check(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	صحيح r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ܐܢ ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ܦܢܐ 0;
}

/* The "info" extension. */
ساكن صحيح
mux_master_process_ext_info(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	صحيح r;
	u_int status = 0;
	حرف *name = عدم, *msg = عدم;

	debug2_f("channel %d: info request", c->self);

	ܐܢ ((r = sshbuf_get_cstring(m, &name, عدم)) != 0)
		fatal_fr(r, "parse");

	ܐܢ (strcmp(name, "connection") == 0) {
		ܐܢ ((msg = connection_info_message(ssh)) == عدم)
			fatal_f("connection_info_message");
		status = 1;
	} ܐܚܪܢܐ ܐܢ (strcmp(name, "channels") == 0) {
		ܐܢ ((msg = channel_open_message(ssh)) == عدم)
			fatal_f("channel_open_message");
		status = 1;
	} ܐܚܪܢܐ {
		msg = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ܐܢ ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, msg)) != 0)
		fatal_fr(r, "reply");
	حرر(msg);

	ܦܢܐ 0;
}

ساكن صحيح
mux_master_process_terminate(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	ܐܢ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ܐܢ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ܦܢܐ 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ܦܢܐ 0;
}

ساكن حرف *
format_forward(u_int ftype, بنية Forward *fwd)
{
	حرف *ret;

	بدل (ftype) {
	حالة MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != عدم) ? fwd->listen_path :
		    (fwd->listen_host == عدم) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != عدم) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		اكسر;
	حالة MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == عدم) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		اكسر;
	حالة MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != عدم) ? fwd->listen_path :
		    (fwd->listen_host == عدم) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != عدم) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		اكسر;
	افتراضي:
		fatal_f("unknown forward type %u", ftype);
	}
	ܦܢܐ ret;
}

ساكن صحيح
compare_host(ثابت حرف *a, ثابت حرف *b)
{
	ܐܢ (a == عدم && b == عدم)
		ܦܢܐ 1;
	ܐܢ (a == عدم || b == عدم)
		ܦܢܐ 0;
	ܦܢܐ strcmp(a, b) == 0;
}

ساكن صحيح
compare_forward(بنية Forward *a, بنية Forward *b)
{
	ܐܢ (!compare_host(a->listen_host, b->listen_host))
		ܦܢܐ 0;
	ܐܢ (!compare_host(a->listen_path, b->listen_path))
		ܦܢܐ 0;
	ܐܢ (a->listen_port != b->listen_port)
		ܦܢܐ 0;
	ܐܢ (!compare_host(a->connect_host, b->connect_host))
		ܦܢܐ 0;
	ܐܢ (!compare_host(a->connect_path, b->connect_path))
		ܦܢܐ 0;
	ܐܢ (a->connect_port != b->connect_port)
		ܦܢܐ 0;

	ܦܢܐ 1;
}

ساكن فراغ
mux_confirm_remote_forward(بنية ssh *ssh, صحيح type, uint32_t seq, فراغ *ctxt)
{
	بنية mux_channel_confirm_ctx *fctx = ctxt;
	حرف *failmsg = عدم;
	بنية Forward *rfwd;
	Channel *c;
	بنية sshbuf *out;
	u_int port;
	صحيح r;

	ܐܢ ((c = channel_by_id(ssh, fctx->cid)) == عدم) {
		/* no channel for reply */
		error_f("unknown channel");
		ܦܢܐ;
	}
	ܐܢ ((out = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ (fctx->fid >= options.num_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == عدم &&
	    options.remote_forwards[fctx->fid].connect_host == عدم)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		اذهب fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_MSG_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	ܐܢ (type == SSH2_MSG_REQUEST_SUCCESS) {
		ܐܢ (rfwd->listen_port == 0) {
			ܐܢ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			ܐܢ (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (صحيح)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			ܐܢ ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} ܐܚܪܢܐ {
			reply_ok(out, fctx->rid);
		}
		اذهب out;
	} ܐܚܪܢܐ {
		ܐܢ (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ܐܢ (rfwd->listen_path != عدم)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		ܐܚܪܢܐ
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		حرر(rfwd->listen_host);
		حرر(rfwd->listen_path);
		حرر(rfwd->connect_host);
		حرر(rfwd->connect_path);
		memset(rfwd, 0, حجم(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	حرر(failmsg);
 out:
	ܐܢ ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	ܐܢ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	حرر(fctx);
}

ساكن صحيح
mux_master_process_open_fwd(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	بنية Forward fwd;
	حرف *fwd_desc = عدم;
	حرف *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	صحيح r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, حجم(fwd));

	/* XXX - lport/cport check redundant */
	ܐܢ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		اذهب out;
	}
	ܐܢ (*listen_addr == '\0') {
		حرر(listen_addr);
		listen_addr = عدم;
	}
	ܐܢ (*connect_addr == '\0') {
		حرر(connect_addr);
		connect_addr = عدم;
	}

	memset(&fwd, 0, حجم(fwd));
	fwd.listen_port = lport;
	ܐܢ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ܐܚܪܢܐ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ܐܢ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ܐܚܪܢܐ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ܐܢ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		حرر(listen_addr);
		حرر(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ܦܢܐ 0;
	}
	ܐܢ (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		اذهب invalid;
	}
	ܐܢ (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		اذهب invalid;
	}
	ܐܢ ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		اذهب invalid;
	}
	ܐܢ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == عدم &&
	    fwd.connect_path == عدم) {
		logit_f("missing connect host");
		اذهب invalid;
	}

	/* Skip forwards that have already been requested */
	بدل (ftype) {
	حالة MUX_FWD_LOCAL:
	حالة MUX_FWD_DYNAMIC:
		لكل (i = 0; i < options.num_local_forwards; i++) {
			ܐܢ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				اذهب out;
			}
		}
		اكسر;
	حالة MUX_FWD_REMOTE:
		لكل (i = 0; i < options.num_remote_forwards; i++) {
			ܐܢ (!compare_forward(&fwd, options.remote_forwards + i))
				استمر;
			ܐܢ (fwd.listen_port != 0)
				اذهب exists;
			debug2_f("found allocated port");
			ܐܢ ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			اذهب out;
		}
		اكسر;
	}

	ܐܢ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ܐܢ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			اذهب out;
		}
	}

	ܐܢ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ܐܢ (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			اذهب out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} ܐܚܪܢܐ {
		بنية mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ܐܢ (fwd.handle < 0)
			اذهب fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, حجم(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.num_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		اذهب out;
	}
	reply_ok(reply, rid);
 out:
	حرر(fwd_desc);
	ܐܢ (freefwd) {
		حرر(fwd.listen_host);
		حرر(fwd.listen_path);
		حرر(fwd.connect_host);
		حرر(fwd.connect_path);
	}
	ܦܢܐ ret;
}

ساكن صحيح
mux_master_process_close_fwd(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	بنية Forward fwd, *found_fwd;
	حرف *fwd_desc = عدم;
	ثابت حرف *error_reason = عدم;
	حرف *listen_addr = عدم, *connect_addr = عدم;
	u_int ftype;
	صحيح r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, حجم(fwd));

	ܐܢ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		اذهب out;
	}

	ܐܢ (*listen_addr == '\0') {
		حرر(listen_addr);
		listen_addr = عدم;
	}
	ܐܢ (*connect_addr == '\0') {
		حرر(connect_addr);
		connect_addr = عدم;
	}

	memset(&fwd, 0, حجم(fwd));
	fwd.listen_port = lport;
	ܐܢ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ܐܚܪܢܐ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ܐܢ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ܐܚܪܢܐ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = عدم;
	بدل (ftype) {
	حالة MUX_FWD_LOCAL:
	حالة MUX_FWD_DYNAMIC:
		لكل (i = 0; i < options.num_local_forwards; i++) {
			ܐܢ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				اكسر;
			}
		}
		اكسر;
	حالة MUX_FWD_REMOTE:
		لكل (i = 0; i < options.num_remote_forwards; i++) {
			ܐܢ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				اكسر;
			}
		}
		اكسر;
	}

	ܐܢ (found_fwd == عدم)
		error_reason = "port not forwarded";
	ܐܚܪܢܐ ܐܢ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ܐܢ (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} ܐܚܪܢܐ {	/* local and dynamic forwards */
		/* Ditto */
		ܐܢ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ܐܢ (error_reason != عدم)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	ܐܚܪܢܐ {
		reply_ok(reply, rid);
		حرر(found_fwd->listen_host);
		حرر(found_fwd->listen_path);
		حرر(found_fwd->connect_host);
		حرر(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = عدم;
		found_fwd->listen_path = found_fwd->connect_path = عدم;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	حرر(fwd_desc);
	حرر(listen_addr);
	حرر(connect_addr);

	ܦܢܐ ret;
}

ساكن صحيح
mux_master_process_stdio_fwd(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	Channel *nc;
	حرف *chost = عدم;
	u_int _cport, i, j;
	صحيح ok = 0, cport, r, new_fd[2];
	بنية mux_stdio_confirm_ctx *cctx;

	ܐܢ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		حرر(chost);
		error_f("malformed message");
		ܦܢܐ -1;
	}
	ܐܢ (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	ܐܚܪܢܐ ܐܢ (_cport <= INT_MAX)
		cport = (صحيح)_cport;
	ܐܚܪܢܐ {
		حرر(chost);
		error_f("invalid port 0x%x", _cport);
		ܦܢܐ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	لكل(i = 0; i < 2; i++) {
		ܐܢ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			لكل (j = 0; j < i; j++)
				close(new_fd[j]);
			حرر(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ܦܢܐ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ܐܢ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		حرر(chost);
		ܦܢܐ 0;
	}

	ܐܢ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ܐܢ (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} ܐܚܪܢܐ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ܐܢ (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			اذهب cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	حرر(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, حجم(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	ܦܢܐ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ساكن فراغ
mux_stdio_confirm(بنية ssh *ssh, صحيح id, صحيح success, فراغ *arg)
{
	بنية mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	بنية sshbuf *reply;
	صحيح r;

	ܐܢ (cctx == عدم)
		fatal_f("cctx == NULL");
	ܐܢ ((c = channel_by_id(ssh, id)) == عدم)
		fatal_f("no channel for id %d", id);
	ܐܢ ((cc = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ܐܢ ((reply = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	ܐܢ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		اذهب done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ܐܢ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ܐܢ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ܐܢ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = عدم;
	حرر(cctx);
}

ساكن صحيح
mux_master_process_stop_listening(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	ܐܢ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ܐܢ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ܦܢܐ 0;
		}
	}

	ܐܢ (mux_listener_channel != عدم) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		حرر(options.control_path);
		options.control_path = عدم;
		mux_listener_channel = عدم;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	ܦܢܐ 0;
}

ساكن صحيح
mux_master_process_proxy(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	صحيح r;

	debug_f("channel %d: proxy request", c->self);

	ܐܢ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ܐܢ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ܦܢܐ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ܐܢ ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	ܦܢܐ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ساكن صحيح
mux_master_read_cb(بنية ssh *ssh, Channel *c)
{
	بنية mux_master_state *state = (بنية mux_master_state *)c->mux_ctx;
	بنية sshbuf *in = عدم, *out = عدم;
	u_int type, rid, i;
	صحيح r, ret = -1;

	ܐܢ ((out = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ܐܢ (c->mux_ctx == عدم) {
		state = xcalloc(1, حجم(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ܐܢ ((r = sshbuf_put_u32(out, MUX_MSG_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ܐܢ ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		ܐܢ ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		اذهب out;
	}

	/* Channel code ensures that we receive whole packets */
	ܐܢ ((r = sshbuf_froms(c->input, &in)) != 0) {
 malf:
		error_f("malformed message");
		اذهب out;
	}

	ܐܢ ((r = sshbuf_get_u32(in, &type)) != 0)
		اذهب malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	ܐܢ (type == MUX_MSG_HELLO)
		rid = 0;
	ܐܚܪܢܐ {
		ܐܢ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_MSG_HELLO, type);
			اذهب out;
		}
		ܐܢ ((r = sshbuf_get_u32(in, &rid)) != 0)
			اذهب malf;
	}

	لكل (i = 0; mux_master_handlers[i].handler != عدم; i++) {
		ܐܢ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			اكسر;
		}
	}
	ܐܢ (mux_master_handlers[i].handler == عدم) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ܐܢ (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	ܦܢܐ ret;
}

فراغ
mux_exit_message(بنية ssh *ssh, Channel *c, صحيح exitval)
{
	بنية sshbuf *m;
	Channel *mux_chan;
	صحيح r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ܐܢ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

فراغ
mux_tty_alloc_failed(بنية ssh *ssh, Channel *c)
{
	بنية sshbuf *m;
	Channel *mux_chan;
	صحيح r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ܐܢ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
فراغ
muxserver_listen(بنية ssh *ssh)
{
	mode_t old_umask;
	حرف *orig_control_path = options.control_path;
	حرف rbuf[16+1];
	u_int i, r;
	صحيح oerrno;

	ܐܢ (options.control_path == عدم ||
	    options.control_master == SSHCTL_MASTER_NO)
		ܦܢܐ;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	لكل (i = 0; i < حجم(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[حجم(rbuf) - 1] = '\0';
	options.control_path = عدم;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	ܐܢ (muxserver_sock < 0) {
		ܐܢ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			ܐܢ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			حرر(orig_control_path);
			حرر(options.control_path);
			options.control_path = عدم;
			options.control_master = SSHCTL_MASTER_NO;
			ܦܢܐ;
		} ܐܚܪܢܐ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ܐܢ (link(options.control_path, orig_control_path) != 0) {
		ܐܢ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		اذهب disable_mux_master;
	}
	unlink(options.control_path);
	حرر(options.control_path);
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
ساكن فراغ
mux_session_confirm(بنية ssh *ssh, صحيح id, صحيح success, فراغ *arg)
{
	بنية mux_session_confirm_ctx *cctx = arg;
	ثابت حرف *display;
	Channel *c, *cc;
	صحيح i, r;
	بنية sshbuf *reply;

	ܐܢ (cctx == عدم)
		fatal_f("cctx == NULL");
	ܐܢ ((c = channel_by_id(ssh, id)) == عدم)
		fatal_f("no channel for id %d", id);
	ܐܢ ((cc = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ܐܢ ((reply = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	ܐܢ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		اذهب done;
	}

	display = getenv("DISPLAY");
	ܐܢ (cctx->want_x_fwd && options.forward_x11 && display != عدم) {
		حرف *proto, *data;

		/* Get reasonable local authentication information. */
		ܐܢ (client_x11_get_proto(ssh, display, options.xauth_location,
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

	ܐܢ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ܐܢ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ܐܢ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ܐܢ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = عدم;
	sshbuf_free(cctx->cmd);
	حرر(cctx->term);
	ܐܢ (cctx->env != عدم) {
		لكل (i = 0; cctx->env[i] != عدم; i++)
			حرر(cctx->env[i]);
		حرر(cctx->env);
	}
	حرر(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
ساكن فراغ
control_client_sighandler(صحيح signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
ساكن فراغ
control_client_sigrelay(صحيح signo)
{
	صحيح save_errno = errno;

	ܐܢ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

ساكن صحيح
mux_client_read(صحيح fd, بنية sshbuf *b, size_t need, صحيح timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	صحيح r;

	ܐܢ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	لكل (have = 0; have < need; ) {
		ܐܢ (muxclient_terminate) {
			errno = EINTR;
			ܦܢܐ -1;
		}
		len = اقرأ(fd, p + have, need - have);
		ܐܢ (len == -1) {
			بدل (errno) {
#ܐܢ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			حالة EWOULDBLOCK:
#endif
			حالة EAGAIN:
				ܐܢ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ܦܢܐ -1;	/* timeout */
				/* FALLTHROUGH */
			حالة EINTR:
				استمر;
			افتراضي:
				ܦܢܐ -1;
			}
		}
		ܐܢ (len == 0) {
			errno = EPIPE;
			ܦܢܐ -1;
		}
		have += (size_t)len;
	}
	ܦܢܐ 0;
}

ساكن صحيح
mux_client_write_packet(صحيح fd, بنية sshbuf *m)
{
	بنية sshbuf *queue;
	u_int have, need;
	صحيح r, oerrno, len;
	ثابت u_char *ptr;
	بنية pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ܐܢ ((queue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	لكل (have = 0; have < need; ) {
		ܐܢ (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			ܦܢܐ -1;
		}
		len = اكتب(fd, ptr + have, need - have);
		ܐܢ (len == -1) {
			بدل (errno) {
#ܐܢ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			حالة EWOULDBLOCK:
#endif
			حالة EAGAIN:
				(فراغ)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			حالة EINTR:
				استمر;
			افتراضي:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				ܦܢܐ -1;
			}
		}
		ܐܢ (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			ܦܢܐ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	ܦܢܐ 0;
}

ساكن صحيح
mux_client_read_packet_timeout(صحيح fd, بنية sshbuf *m, صحيح timeout_ms)
{
	بنية sshbuf *queue;
	size_t need, have;
	ثابت u_char *ptr;
	صحيح r, oerrno;

	ܐܢ ((queue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		ܐܢ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ܦܢܐ -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	ܐܢ (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ܦܢܐ -1;
	}
	ܐܢ ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	ܦܢܐ 0;
}

ساكن صحيح
mux_client_read_packet(صحيح fd, بنية sshbuf *m)
{
	ܦܢܐ mux_client_read_packet_timeout(fd, m, -1);
}

ساكن صحيح
mux_client_hello_exchange(صحيح fd, صحيح timeout_ms)
{
	بنية sshbuf *m;
	u_int type, ver;
	صحيح r, ret = -1;

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_MSG_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ܐܢ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		اذهب out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ܐܢ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		اذهب out;
	}

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ܐܢ (type != MUX_MSG_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_MSG_HELLO, type);
		اذهب out;
	}
	ܐܢ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ܐܢ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		اذهب out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ܟܡܐ (sshbuf_len(m) > 0) {
		حرف *name = عدم;

		ܐܢ ((r = sshbuf_get_cstring(m, &name, عدم)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /* value */
			error_fr(r, "parse extension");
			اذهب out;
		}
		/* Process extensions. */
		ܐܢ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ܐܚܪܢܐ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		حرر(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	ܦܢܐ ret;
}

ساكن u_int
mux_client_request_alive(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int pid, type, rid;
	صحيح r;

	debug3_f("entering");

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ܦܢܐ 0;
	}

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ܐܢ (type != MUX_S_ALIVE) {
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ܐܢ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ܐܢ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ܦܢܐ pid;
}

ساكن حرف *
mux_client_request_info(صحيح fd, ثابت حرف *name)
{
	بنية sshbuf *m;
	حرف *e, *msg;
	u_int type, rid, status;
	صحيح r;

	debug3_f("entering");

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ܦܢܐ 0;
	}

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ܐܢ (type != MUX_S_EXT_INFO) {
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ܐܢ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ܐܢ ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &msg, عدم)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ܦܢܐ msg;
}

ساكن فراغ
mux_client_request_terminate(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int type, rid;
	صحيح r;

	debug3_f("entering");

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ܐܢ (errno == EPIPE) {
			sshbuf_free(m);
			ܦܢܐ;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	بدل (type) {
	حالة MUX_S_OK:
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	حالة MUX_S_FAILURE:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	افتراضي:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

ساكن صحيح
mux_client_forward(صحيح fd, صحيح cancel_flag, u_int ftype, بنية Forward *fwd)
{
	بنية sshbuf *m;
	حرف *e, *fwd_desc;
	ثابت حرف *lhost, *chost;
	u_int type, rid;
	صحيح r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	حرر(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ܐܢ (fwd->listen_path != عدم)
		lhost = fwd->listen_path;
	ܐܚܪܢܐ ܐܢ (fwd->listen_host == عدم)
		lhost = "";
	ܐܚܪܢܐ ܐܢ (*fwd->listen_host == '\0')
		lhost = "*";
	ܐܚܪܢܐ
		lhost = fwd->listen_host;

	ܐܢ (fwd->connect_path != عدم)
		chost = fwd->connect_path;
	ܐܚܪܢܐ ܐܢ (fwd->connect_host == عدم)
		chost = "";
	ܐܚܪܢܐ
		chost = fwd->connect_host;

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ܦܢܐ -1;
	}

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	بدل (type) {
	حالة MUX_S_OK:
		اكسر;
	حالة MUX_S_REMOTE_PORT:
		ܐܢ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ܐܢ ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		ܐܢ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ܦܢܐ -1;
	حالة MUX_S_FAILURE:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ܦܢܐ -1;
	افتراضي:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ܦܢܐ 0;
}

ساكن صحيح
mux_client_forwards(صحيح fd, صحيح cancel_flag)
{
	صحيح i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.num_local_forwards, options.num_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	لكل (i = 0; i < options.num_local_forwards; i++) {
		ܐܢ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	لكل (i = 0; i < options.num_remote_forwards; i++) {
		ܐܢ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ܦܢܐ ret;
}

ساكن صحيح
mux_client_request_session(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	ثابت حرف *term = عدم;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	خارجي حرف **environ;
	صحيح r, rawmode = 0;

	debug3_f("entering");

	ܐܢ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ܦܢܐ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ܐܢ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ܐܢ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.num_setenv)) == عدم || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	ܐܢ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == عدم ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	ܐܢ (options.num_send_env > 0 && environ != عدم) {
		لكل (i = 0; environ[i] != عدم; i++) {
			ܐܢ (!env_permitted(environ[i]))
				استمر;
			ܐܢ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	لكل (i = 0; i < options.num_setenv; i++) {
		ܐܢ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ܐܢ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ܦܢܐ -1;
	}

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	بدل (type) {
	حالة MUX_S_SESSION_OPENED:
		ܐܢ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ܦܢܐ -1;
	حالة MUX_S_FAILURE:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ܦܢܐ -1;
	افتراضي:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ܦܢܐ -1;
	}
	muxclient_request_id++;

	ܐܢ (pledge("stdio proc tty", عدم) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ܐܢ (options.fork_after_authentication)
		daemon(1, 1);
	ܐܚܪܢܐ {
		rawmode = tty_flag;
		ܐܢ (tty_flag) {
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
	لكل (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		ܐܢ (mux_client_read_packet(fd, m) != 0)
			اكسر;
		ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		بدل (type) {
		حالة MUX_S_TTY_ALLOC_FAIL:
			ܐܢ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ܐܢ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			استمر;
		حالة MUX_S_EXIT_MESSAGE:
			ܐܢ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ܐܢ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ܐܢ (exitval_seen)
				fatal_f("exitval sent twice");
			ܐܢ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			استمر;
		افتراضي:
			ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ܐܢ (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	ܐܢ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} ܐܚܪܢܐ ܐܢ (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} ܐܚܪܢܐ
		debug2("Received exit status from master %d", exitval);

	ܐܢ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

ساكن صحيح
mux_client_proxy(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int type, rid;
	صحيح r;

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ܦܢܐ 0;
	}
	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ܐܢ (type != MUX_S_PROXY) {
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ܦܢܐ 0;
}

ساكن صحيح
mux_client_request_stdio_fwd(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int type, rid, sid;
	صحيح r;

	debug3_f("entering");

	ܐܢ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ܦܢܐ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ܐܢ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ܐܢ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ܐܢ (pledge("stdio proc tty", عدم) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ܦܢܐ -1;
	}

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	بدل (type) {
	حالة MUX_S_SESSION_OPENED:
		ܐܢ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	حالة MUX_S_FAILURE:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	افتراضي:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ܦܢܐ -1;
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
	ܐܢ (mux_client_read_packet(fd, m) != 0) {
		ܐܢ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ܦܢܐ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

ساكن فراغ
mux_client_request_stop_listening(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int type, rid;
	صحيح r;

	debug3_f("entering");

	ܐܢ ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	ܐܢ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ܐܢ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ܐܢ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ܐܢ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ܐܢ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	بدل (type) {
	حالة MUX_S_OK:
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	حالة MUX_S_FAILURE:
		ܐܢ ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	افتراضي:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
صحيح
muxclient(ثابت حرف *path)
{
	بنية sockaddr_un addr;
	صحيح sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	حرف *info = عدم;

	ܐܢ (muxclient_command == 0) {
		ܐܢ (options.stdio_forward_host != عدم)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		ܐܚܪܢܐ
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	بدل (options.control_master) {
	حالة SSHCTL_MASTER_AUTO:
	حالة SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	حالة SSHCTL_MASTER_NO:
		اكسر;
	افتراضي:
		ܦܢܐ -1;
	}

	memset(&addr, '\0', حجم(addr));
	addr.sun_family = AF_UNIX;

	ܐܢ (strlcpy(addr.sun_path, path,
	    حجم(addr.sun_path)) >= حجم(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned صحيح)حجم(addr.sun_path));

	ܐܢ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ܐܢ (connect(sock, (بنية sockaddr *)&addr, حجم(addr)) == -1) {
		بدل (muxclient_command) {
		حالة SSHMUX_COMMAND_OPEN:
		حالة SSHMUX_COMMAND_STDIO_FWD:
			اكسر;
		افتراضي:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		ܐܢ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} ܐܚܪܢܐ ܐܢ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} ܐܚܪܢܐ {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		ܦܢܐ -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	ܐܢ (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	ܐܢ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ܦܢܐ -1;
	}

	بدل (muxclient_command) {
	حالة SSHMUX_COMMAND_ALIVE_CHECK:
		ܐܢ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	حالة SSHMUX_COMMAND_CONNINFO:
	حالة SSHMUX_COMMAND_CHANINFO:
		ܐܢ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ܐܢ (info == عدم)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	حالة SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ܐܢ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	حالة SSHMUX_COMMAND_FORWARD:
		ܐܢ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	حالة SSHMUX_COMMAND_OPEN:
		ܐܢ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ܦܢܐ -1;
		}
		mux_client_request_session(sock);
		ܦܢܐ -1;
	حالة SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	حالة SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ܐܢ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	حالة SSHMUX_COMMAND_CANCEL_FWD:
		ܐܢ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	حالة SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ܦܢܐ (sock);
	افتراضي:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
