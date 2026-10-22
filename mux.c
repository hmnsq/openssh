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
#define MUX_پەیام_HELLO		0x00000001
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
	{ MUX_پەیام_HELLO, mux_master_process_hello },
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
	إذا (c == عدم)
		fatal_f("channel_by_id(%i) == NULL", cid);
	إذا (c->ctl_chan != -1) {
		إذا ((cc = channel_by_id(ssh, c->ctl_chan)) == عدم)
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
	إذا (c == عدم)
		fatal_f("channel_by_id(%i) == NULL", cid);
	إذا (c->have_ctl_child_id) {
		إذا ((sc = channel_by_id(ssh, c->ctl_child_id)) == عدم)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		إذا (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} وإلا {
			إذا (sc->istate == CHAN_تێخستن_OPEN)
				chan_read_failed(ssh, sc);
			إذا (sc->ostate == CHAN_OUTPUT_OPEN)
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

	إذا ((cp = strchr(env, '=')) == عدم || cp == env)
		أرجع 0;
	ret = snprintf(name, حجم(name), "%.*s", (صحيح)(cp - env), env);
	إذا (ret <= 0 || (size_t)ret >= حجم(name)) {
		error_f("name '%.100s...' too long", env);
		أرجع 0;
	}

	لكل (i = 0; i < options.ژمارە_send_env; i++)
		إذا (match_pattern(name, options.send_env[i]))
			أرجع 1;

	أرجع 0;
}

/* Mux master protocol message handlers */

ساكن صحيح
mux_master_process_hello(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	u_int ver;
	بنية mux_master_state *state = (بنية mux_master_state *)c->mux_ctx;
	صحيح r;

	إذا (state == عدم)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	إذا (state->hello_rcvd) {
		error_f("HELLO received twice");
		أرجع -1;
	}
	إذا ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		أرجع -1;
	}
	إذا (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		أرجع -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	طالما (sshbuf_len(m) > 0) {
		حرف *name = عدم;
		size_t بەها_len = 0;

		إذا ((r = sshbuf_get_cstring(m, &name, عدم)) != 0 ||
		    (r = sshbuf_get_string_direct(m, عدم, &بەها_len)) != 0) {
			error_fr(r, "parse extension");
			أرجع -1;
		}
		إذا (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} وإلا {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, بەها_len);
		}
		حرر(name);
	}
	state->hello_rcvd = 1;
	أرجع 0;
}

/* Enqueue a "ok" response to the reply buffer */
ساكن فراغ
reply_ok(بنية sshbuf *reply, u_int rid)
{
	صحيح r;

	إذا ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ساكن فراغ
reply_error(بنية sshbuf *reply, u_int type, u_int rid, ثابت حرف *پەیام)
{
	صحيح r;

	إذا ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, پەیام)) != 0)
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
	إذا ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
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
		أرجع -1;
	}

#define MUX_MAX_ENV_VARS	4096
	طالما (sshbuf_len(m) > 0) {
		إذا ((r = sshbuf_get_cstring(m, &cp, عدم)) != 0)
			اذهب malf;
		إذا (!env_permitted(cp)) {
			حرر(cp);
			استمر;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    حجم(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = عدم;
		إذا (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			اكسر;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	إذا ((cctx->cmd = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	حرر(cmd);
	cmd = عدم;

	/* Gather fds from client */
	لكل(i = 0; i < 3; i++) {
		إذا ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
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
			أرجع -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	إذا (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		حرر(cctx->term);
		إذا (env_len != 0) {
			لكل (i = 0; i < env_len; i++)
				حرر(cctx->env[i]);
			حرر(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		حرر(cctx);
		أرجع 0;
	}

	إذا (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		إذا (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			اذهب cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	إذا (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	إذا (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	إذا (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	إذا (cctx->want_tty && escape_char != 0xffffffff) {
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
	أرجع 0;
}

ساكن صحيح
mux_master_process_alive_check(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	صحيح r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	إذا ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	أرجع 0;
}

/* The "info" extension. */
ساكن صحيح
mux_master_process_ext_info(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	صحيح r;
	u_int status = 0;
	حرف *name = عدم, *پەیام = عدم;

	debug2_f("channel %d: info request", c->self);

	إذا ((r = sshbuf_get_cstring(m, &name, عدم)) != 0)
		fatal_fr(r, "parse");

	إذا (strcmp(name, "connection") == 0) {
		إذا ((پەیام = connection_info_message(ssh)) == عدم)
			fatal_f("connection_info_message");
		status = 1;
	} وإلا إذا (strcmp(name, "channels") == 0) {
		إذا ((پەیام = channel_open_message(ssh)) == عدم)
			fatal_f("channel_open_message");
		status = 1;
	} وإلا {
		پەیام = xstrdup("info request type not supported");
	}

	/* prepare reply */
	إذا ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, پەیام)) != 0)
		fatal_fr(r, "reply");
	حرر(پەیام);

	أرجع 0;
}

ساكن صحيح
mux_master_process_terminate(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	إذا (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		إذا (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			أرجع 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	أرجع 0;
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
	أرجع ret;
}

ساكن صحيح
compare_host(ثابت حرف *a, ثابت حرف *b)
{
	إذا (a == عدم && b == عدم)
		أرجع 1;
	إذا (a == عدم || b == عدم)
		أرجع 0;
	أرجع strcmp(a, b) == 0;
}

ساكن صحيح
compare_forward(بنية Forward *a, بنية Forward *b)
{
	إذا (!compare_host(a->listen_host, b->listen_host))
		أرجع 0;
	إذا (!compare_host(a->listen_path, b->listen_path))
		أرجع 0;
	إذا (a->listen_port != b->listen_port)
		أرجع 0;
	إذا (!compare_host(a->connect_host, b->connect_host))
		أرجع 0;
	إذا (!compare_host(a->connect_path, b->connect_path))
		أرجع 0;
	إذا (a->connect_port != b->connect_port)
		أرجع 0;

	أرجع 1;
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

	إذا ((c = channel_by_id(ssh, fctx->cid)) == عدم) {
		/* no channel for reply */
		error_f("unknown channel");
		أرجع;
	}
	إذا ((out = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا (fctx->fid >= options.ژمارە_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == عدم &&
	    options.remote_forwards[fctx->fid].connect_host == عدم)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		اذهب fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_پەیام_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	إذا (type == SSH2_پەیام_REQUEST_SUCCESS) {
		إذا (rfwd->listen_port == 0) {
			إذا ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			إذا (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (صحيح)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			إذا ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} وإلا {
			reply_ok(out, fctx->rid);
		}
		اذهب out;
	} وإلا {
		إذا (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		إذا (rfwd->listen_path != عدم)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		وإلا
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
	إذا ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	إذا (c->mux_pause <= 0)
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
	إذا ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
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
	إذا (*listen_addr == '\0') {
		حرر(listen_addr);
		listen_addr = عدم;
	}
	إذا (*connect_addr == '\0') {
		حرر(connect_addr);
		connect_addr = عدم;
	}

	memset(&fwd, 0, حجم(fwd));
	fwd.listen_port = lport;
	إذا (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	وإلا
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	إذا (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	وإلا
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	إذا (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		حرر(listen_addr);
		حرر(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		أرجع 0;
	}
	إذا (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		اذهب invalid;
	}
	إذا (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		اذهب invalid;
	}
	إذا ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		اذهب invalid;
	}
	إذا (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == عدم &&
	    fwd.connect_path == عدم) {
		logit_f("missing connect host");
		اذهب invalid;
	}

	/* Skip forwards that have already been requested */
	بدل (ftype) {
	حالة MUX_FWD_LOCAL:
	حالة MUX_FWD_DYNAMIC:
		لكل (i = 0; i < options.ژمارە_local_forwards; i++) {
			إذا (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				اذهب out;
			}
		}
		اكسر;
	حالة MUX_FWD_REMOTE:
		لكل (i = 0; i < options.ژمارە_remote_forwards; i++) {
			إذا (!compare_forward(&fwd, options.remote_forwards + i))
				استمر;
			إذا (fwd.listen_port != 0)
				اذهب exists;
			debug2_f("found allocated port");
			إذا ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			اذهب out;
		}
		اكسر;
	}

	إذا (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		إذا (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			اذهب out;
		}
	}

	إذا (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		إذا (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			اذهب out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} وإلا {
		بنية mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		إذا (fwd.handle < 0)
			اذهب fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, حجم(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.ژمارە_remote_forwards - 1;
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
	إذا (freefwd) {
		حرر(fwd.listen_host);
		حرر(fwd.listen_path);
		حرر(fwd.connect_host);
		حرر(fwd.connect_path);
	}
	أرجع ret;
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

	إذا ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
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

	إذا (*listen_addr == '\0') {
		حرر(listen_addr);
		listen_addr = عدم;
	}
	إذا (*connect_addr == '\0') {
		حرر(connect_addr);
		connect_addr = عدم;
	}

	memset(&fwd, 0, حجم(fwd));
	fwd.listen_port = lport;
	إذا (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	وإلا
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	إذا (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	وإلا
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = عدم;
	بدل (ftype) {
	حالة MUX_FWD_LOCAL:
	حالة MUX_FWD_DYNAMIC:
		لكل (i = 0; i < options.ژمارە_local_forwards; i++) {
			إذا (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				اكسر;
			}
		}
		اكسر;
	حالة MUX_FWD_REMOTE:
		لكل (i = 0; i < options.ژمارە_remote_forwards; i++) {
			إذا (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				اكسر;
			}
		}
		اكسر;
	}

	إذا (found_fwd == عدم)
		error_reason = "port not forwarded";
	وإلا إذا (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		إذا (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} وإلا {	/* local and dynamic forwards */
		/* Ditto */
		إذا (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	إذا (error_reason != عدم)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	وإلا {
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

	أرجع ret;
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

	إذا ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, عدم)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		حرر(chost);
		error_f("malformed message");
		أرجع -1;
	}
	إذا (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	وإلا إذا (_cport <= INT_MAX)
		cport = (صحيح)_cport;
	وإلا {
		حرر(chost);
		error_f("invalid port 0x%x", _cport);
		أرجع -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	لكل(i = 0; i < 2; i++) {
		إذا ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			لكل (j = 0; j < i; j++)
				close(new_fd[j]);
			حرر(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			أرجع -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	إذا (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		حرر(chost);
		أرجع 0;
	}

	إذا (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		إذا (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} وإلا {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		إذا (!ok) {
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
	أرجع 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ساكن فراغ
mux_stdio_confirm(بنية ssh *ssh, صحيح id, صحيح success, فراغ *arg)
{
	بنية mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	بنية sshbuf *reply;
	صحيح r;

	إذا (cctx == عدم)
		fatal_f("cctx == NULL");
	إذا ((c = channel_by_id(ssh, id)) == عدم)
		fatal_f("no channel for id %d", id);
	إذا ((cc = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	إذا ((reply = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	إذا (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		اذهب done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	إذا ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	إذا ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	إذا (cc->mux_pause <= 0)
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

	إذا (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		إذا (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			أرجع 0;
		}
	}

	إذا (mux_listener_channel != عدم) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		حرر(options.control_path);
		options.control_path = عدم;
		mux_listener_channel = عدم;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	أرجع 0;
}

ساكن صحيح
mux_master_process_proxy(بنية ssh *ssh, u_int rid,
    Channel *c, بنية sshbuf *m, بنية sshbuf *reply)
{
	صحيح r;

	debug_f("channel %d: proxy request", c->self);

	إذا (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		إذا (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			أرجع 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	إذا ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	أرجع 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ساكن صحيح
mux_master_read_cb(بنية ssh *ssh, Channel *c)
{
	بنية mux_master_state *state = (بنية mux_master_state *)c->mux_ctx;
	بنية sshbuf *in = عدم, *out = عدم;
	u_int type, rid, i;
	صحيح r, ret = -1;

	إذا ((out = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	إذا (c->mux_ctx == عدم) {
		state = xcalloc(1, حجم(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		إذا ((r = sshbuf_put_u32(out, MUX_پەیام_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		إذا ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		إذا ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		اذهب out;
	}

	/* Channel code ensures that we receive whole packets */
	إذا ((r = sshbuf_froms(c->تێخستن, &in)) != 0) {
 malf:
		error_f("malformed message");
		اذهب out;
	}

	إذا ((r = sshbuf_get_u32(in, &type)) != 0)
		اذهب malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	إذا (type == MUX_پەیام_HELLO)
		rid = 0;
	وإلا {
		إذا (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_پەیام_HELLO, type);
			اذهب out;
		}
		إذا ((r = sshbuf_get_u32(in, &rid)) != 0)
			اذهب malf;
	}

	لكل (i = 0; mux_master_handlers[i].handler != عدم; i++) {
		إذا (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			اكسر;
		}
	}
	إذا (mux_master_handlers[i].handler == عدم) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	إذا (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	أرجع ret;
}

فراغ
mux_exit_message(بنية ssh *ssh, Channel *c, صحيح exitval)
{
	بنية sshbuf *m;
	Channel *mux_chan;
	صحيح r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	إذا ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
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

	إذا ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
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

	إذا (options.control_path == عدم ||
	    options.control_master == SSHCTL_MASTER_NO)
		أرجع;

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
	إذا (muxserver_sock < 0) {
		إذا (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			إذا (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			حرر(orig_control_path);
			حرر(options.control_path);
			options.control_path = عدم;
			options.control_master = SSHCTL_MASTER_NO;
			أرجع;
		} وإلا {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	إذا (link(options.control_path, orig_control_path) != 0) {
		إذا (errno != EEXIST) {
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

	إذا (cctx == عدم)
		fatal_f("cctx == NULL");
	إذا ((c = channel_by_id(ssh, id)) == عدم)
		fatal_f("no channel for id %d", id);
	إذا ((cc = channel_by_id(ssh, c->ctl_chan)) == عدم)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	إذا ((reply = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");

	إذا (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		اذهب done;
	}

	display = getenv("DISPLAY");
	إذا (cctx->want_x_fwd && options.forward_x11 && display != عدم) {
		حرف *proto, *data;

		/* Get reasonable local authentication information. */
		إذا (client_x11_get_proto(ssh, display, options.xauth_location,
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

	إذا (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	إذا ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	إذا ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	إذا (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = عدم;
	sshbuf_free(cctx->cmd);
	حرر(cctx->term);
	إذا (cctx->env != عدم) {
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

	إذا (muxserver_pid > 1)
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

	إذا ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	لكل (have = 0; have < need; ) {
		إذا (muxclient_terminate) {
			errno = EINTR;
			أرجع -1;
		}
		len = اقرأ(fd, p + have, need - have);
		إذا (len == -1) {
			بدل (errno) {
#إذا defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			حالة EWOULDBLOCK:
#endif
			حالة EAGAIN:
				إذا (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					أرجع -1;	/* timeout */
				/* FALLTHROUGH */
			حالة EINTR:
				استمر;
			افتراضي:
				أرجع -1;
			}
		}
		إذا (len == 0) {
			errno = EPIPE;
			أرجع -1;
		}
		have += (size_t)len;
	}
	أرجع 0;
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
	إذا ((queue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	لكل (have = 0; have < need; ) {
		إذا (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			أرجع -1;
		}
		len = اكتب(fd, ptr + have, need - have);
		إذا (len == -1) {
			بدل (errno) {
#إذا defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
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
				أرجع -1;
			}
		}
		إذا (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			أرجع -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	أرجع 0;
}

ساكن صحيح
mux_client_read_packet_timeout(صحيح fd, بنية sshbuf *m, صحيح timeout_ms)
{
	بنية sshbuf *queue;
	size_t need, have;
	ثابت u_char *ptr;
	صحيح r, oerrno;

	إذا ((queue = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		إذا ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		أرجع -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	إذا (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		أرجع -1;
	}
	إذا ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	أرجع 0;
}

ساكن صحيح
mux_client_read_packet(صحيح fd, بنية sshbuf *m)
{
	أرجع mux_client_read_packet_timeout(fd, m, -1);
}

ساكن صحيح
mux_client_hello_exchange(صحيح fd, صحيح timeout_ms)
{
	بنية sshbuf *m;
	u_int type, ver;
	صحيح r, ret = -1;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_پەیام_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	إذا (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		اذهب out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	إذا (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		اذهب out;
	}

	إذا ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != MUX_پەیام_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_پەیام_HELLO, type);
		اذهب out;
	}
	إذا ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	إذا (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		اذهب out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	طالما (sshbuf_len(m) > 0) {
		حرف *name = عدم;

		إذا ((r = sshbuf_get_cstring(m, &name, عدم)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*بەها*/
			error_fr(r, "parse extension");
			اذهب out;
		}
		/* Process extensions. */
		إذا (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} وإلا {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		حرر(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	أرجع ret;
}

ساكن u_int
mux_client_request_alive(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int pid, type, rid;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	إذا (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		أرجع 0;
	}

	إذا ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != MUX_S_ALIVE) {
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	إذا ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	إذا ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	أرجع pid;
}

ساكن حرف *
mux_client_request_info(صحيح fd, ثابت حرف *name)
{
	بنية sshbuf *m;
	حرف *e, *پەیام;
	u_int type, rid, status;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	إذا (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		أرجع 0;
	}

	إذا ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	إذا (type != MUX_S_EXT_INFO) {
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	إذا ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	إذا ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &پەیام, عدم)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	أرجع پەیام;
}

ساكن فراغ
mux_client_request_terminate(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int type, rid;
	صحيح r;

	debug3_f("entering");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	إذا (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		إذا (errno == EPIPE) {
			sshbuf_free(m);
			أرجع;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	إذا ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	بدل (type) {
	حالة MUX_S_OK:
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	حالة MUX_S_FAILURE:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
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
	إذا (fwd->listen_path != عدم)
		lhost = fwd->listen_path;
	وإلا إذا (fwd->listen_host == عدم)
		lhost = "";
	وإلا إذا (*fwd->listen_host == '\0')
		lhost = "*";
	وإلا
		lhost = fwd->listen_host;

	إذا (fwd->connect_path != عدم)
		chost = fwd->connect_path;
	وإلا إذا (fwd->connect_host == عدم)
		chost = "";
	وإلا
		chost = fwd->connect_host;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	إذا (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		أرجع -1;
	}

	إذا ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	بدل (type) {
	حالة MUX_S_OK:
		اكسر;
	حالة MUX_S_REMOTE_PORT:
		إذا (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		إذا ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		إذا (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		أرجع -1;
	حالة MUX_S_FAILURE:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		أرجع -1;
	افتراضي:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	أرجع 0;
}

ساكن صحيح
mux_client_forwards(صحيح fd, صحيح cancel_flag)
{
	صحيح i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.ژمارە_local_forwards, options.ژمارە_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	لكل (i = 0; i < options.ژمارە_local_forwards; i++) {
		إذا (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	لكل (i = 0; i < options.ژمارە_remote_forwards; i++) {
		إذا (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	أرجع ret;
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

	إذا ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		أرجع -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	إذا (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	إذا ((term = lookup_env_in_list("TERM", options.setenv,
	    options.ژمارە_setenv)) == عدم || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	إذا (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
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
	إذا (options.ژمارە_send_env > 0 && environ != عدم) {
		لكل (i = 0; environ[i] != عدم; i++) {
			إذا (!env_permitted(environ[i]))
				استمر;
			إذا ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	لكل (i = 0; i < options.ژمارە_setenv; i++) {
		إذا ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	إذا (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	إذا (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		أرجع -1;
	}

	إذا ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	بدل (type) {
	حالة MUX_S_SESSION_OPENED:
		إذا ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		أرجع -1;
	حالة MUX_S_FAILURE:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		أرجع -1;
	افتراضي:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		أرجع -1;
	}
	muxclient_request_id++;

	إذا (pledge("stdio proc tty", عدم) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	إذا (options.fork_after_authentication)
		daemon(1, 1);
	وإلا {
		rawmode = tty_flag;
		إذا (tty_flag) {
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
		إذا (mux_client_read_packet(fd, m) != 0)
			اكسر;
		إذا ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		بدل (type) {
		حالة MUX_S_TTY_ALLOC_FAIL:
			إذا ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			إذا (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			استمر;
		حالة MUX_S_EXIT_MESSAGE:
			إذا ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			إذا (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			إذا (exitval_seen)
				fatal_f("exitval sent twice");
			إذا ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			استمر;
		افتراضي:
			إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	إذا (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	إذا (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} وإلا إذا (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} وإلا
		debug2("Received exit status from master %d", exitval);

	إذا (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
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

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	إذا (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		أرجع 0;
	}
	إذا ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	إذا (type != MUX_S_PROXY) {
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	أرجع 0;
}

ساكن صحيح
mux_client_request_stdio_fwd(صحيح fd)
{
	بنية sshbuf *m;
	حرف *e;
	u_int type, rid, sid;
	صحيح r;

	debug3_f("entering");

	إذا ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		أرجع -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	إذا (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	إذا (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	إذا (pledge("stdio proc tty", عدم) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	إذا (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		أرجع -1;
	}

	إذا ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	بدل (type) {
	حالة MUX_S_SESSION_OPENED:
		إذا ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	حالة MUX_S_FAILURE:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	افتراضي:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		أرجع -1;
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
	إذا (mux_client_read_packet(fd, m) != 0) {
		إذا (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			أرجع 0;
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

	إذا ((m = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new");
	إذا ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	إذا (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	إذا (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	إذا ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	إذا (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	بدل (type) {
	حالة MUX_S_OK:
		اكسر;
	حالة MUX_S_PERMISSION_DENIED:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	حالة MUX_S_FAILURE:
		إذا ((r = sshbuf_get_cstring(m, &e, عدم)) != 0)
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

	إذا (muxclient_command == 0) {
		إذا (options.stdio_forward_host != عدم)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		وإلا
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
		أرجع -1;
	}

	memset(&addr, '\0', حجم(addr));
	addr.sun_family = AF_UNIX;

	إذا (strlcpy(addr.sun_path, path,
	    حجم(addr.sun_path)) >= حجم(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned صحيح)حجم(addr.sun_path));

	إذا ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	إذا (connect(sock, (بنية sockaddr *)&addr, حجم(addr)) == -1) {
		بدل (muxclient_command) {
		حالة SSHMUX_COMMAND_OPEN:
		حالة SSHMUX_COMMAND_STDIO_FWD:
			اكسر;
		افتراضي:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		إذا (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} وإلا إذا (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} وإلا {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		أرجع -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	إذا (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	إذا (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		أرجع -1;
	}

	بدل (muxclient_command) {
	حالة SSHMUX_COMMAND_ALIVE_CHECK:
		إذا ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	حالة SSHMUX_COMMAND_CONNINFO:
	حالة SSHMUX_COMMAND_CHANINFO:
		إذا (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		إذا (info == عدم)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	حالة SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		إذا (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	حالة SSHMUX_COMMAND_FORWARD:
		إذا (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	حالة SSHMUX_COMMAND_OPEN:
		إذا (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			أرجع -1;
		}
		mux_client_request_session(sock);
		أرجع -1;
	حالة SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	حالة SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		إذا (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	حالة SSHMUX_COMMAND_CANCEL_FWD:
		إذا (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	حالة SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		أرجع (sock);
	افتراضي:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
