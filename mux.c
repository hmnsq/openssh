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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/queue.h>
#شامل <sys/stat.h>
#شامل <sys/socket.h>
#شامل <sys/un.h>

#شامل <errno.h>
#شامل <poll.h>
#شامل <limits.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stddef.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "log.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "misc.h"
#شامل "match.h"
#شامل "sshbuf.h"
#شامل "channels.h"
#شامل "packet.h"
#شامل "monitor_fdpass.h"
#شامل "sshpty.h"
#شامل "readconf.h"
#شامل "clientloop.h"

/* from ssh.c */
خارجی صحیح tty_flag;
خارجی Options options;
خارجی حرف *host;
خارجی ساخت sshbuf *command;
خارجی متلون sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
ساخت mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	ساخت sshbuf *cmd;
	حرف *رکن;
	ساخت termios tio;
	حرف **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
ساخت mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
ساخت mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	صحیح fid;	/* forward id */
};

/* fd to control socket */
صحیح muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
ساکن متلون sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
ساکن u_int muxserver_pid = 0;

ساکن Channel *mux_listener_channel = تہی;

ساخت mux_master_state {
	صحیح hello_rcvd;
};

/* mux protocol messages */
#تعریف_کرو MUX_پیغام_HELLO		0x00000001
#تعریف_کرو MUX_C_NEW_SESSION	0x10000002
#تعریف_کرو MUX_C_ALIVE_CHECK	0x10000004
#تعریف_کرو MUX_C_TERMINATE		0x10000005
#تعریف_کرو MUX_C_OPEN_FWD		0x10000006
#تعریف_کرو MUX_C_CLOSE_FWD		0x10000007
#تعریف_کرو MUX_C_NEW_STDIO_FWD	0x10000008
#تعریف_کرو MUX_C_STOP_LISTENING	0x10000009
#تعریف_کرو MUX_C_PROXY		0x1000000f
#تعریف_کرو MUX_C_EXT_INFO		0x20000001
#تعریف_کرو MUX_S_OK		0x80000001
#تعریف_کرو MUX_S_PERMISSION_DENIED	0x80000002
#تعریف_کرو MUX_S_FAILURE		0x80000003
#تعریف_کرو MUX_S_EXIT_پیغام	0x80000004
#تعریف_کرو MUX_S_ALIVE		0x80000005
#تعریف_کرو MUX_S_SESSION_OPENED	0x80000006
#تعریف_کرو MUX_S_REMOTE_پورٹ	0x80000007
#تعریف_کرو MUX_S_TTY_ALLOC_FAIL	0x80000008
#تعریف_کرو MUX_S_PROXY		0x8000000f
#تعریف_کرو MUX_S_EXT_INFO		0x90000001

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
#تعریف_کرو MUX_FWD_LOCAL   1
#تعریف_کرو MUX_FWD_REMOTE  2
#تعریف_کرو MUX_FWD_DYNAMIC 3

#تعریف_کرو MUX_EXT_INFO		0x00000001

/* Bitmask of supported extensions */
ساکن u_int extensions = 0;

ساکن خالی mux_session_confirm(ساخت ssh *, صحیح, صحیح, خالی *);
ساکن خالی mux_stdio_confirm(ساخت ssh *, صحیح, صحیح, خالی *);

ساکن صحیح mux_master_process_hello(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_new_session(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_alive_check(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_terminate(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_open_fwd(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_close_fwd(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_stdio_fwd(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_stop_listening(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_proxy(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);
ساکن صحیح mux_master_process_ext_info(ساخت ssh *, u_int,
	    Channel *, ساخت sshbuf *, ساخت sshbuf *);

ساکن ثابت ساخت {
	u_int type;
	صحیح (*handler)(ساخت ssh *, u_int, Channel *,
	    ساخت sshbuf *, ساخت sshbuf *);
} mux_master_handlers[] = {
	{ MUX_پیغام_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, تہی }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
ساکن خالی
mux_master_session_cleanup_cb(ساخت ssh *ssh, صحیح cid, صحیح force, خالی *غیر_مستعمل)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	اگر (c == تہی)
		fatal_f("channel_by_id(%i) == NULL", cid);
	اگر (c->ctl_chan != -1) {
		اگر ((cc = channel_by_id(ssh, c->ctl_chan)) == تہی)
			fatal_f("channel %d missing control channel %d",
			    c->self, c->ctl_chan);
		c->ctl_chan = -1;
		cc->ctl_بچہ_id = 0;
		cc->have_ctl_بچہ_id = 0;
		chan_rcvd_oclose(ssh, cc);
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Cleanup callback fired on closure of mux client _control_ channel */
ساکن خالی
mux_master_control_cleanup_cb(ساخت ssh *ssh, صحیح cid, صحیح force, خالی *غیر_مستعمل)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	اگر (c == تہی)
		fatal_f("channel_by_id(%i) == NULL", cid);
	اگر (c->have_ctl_بچہ_id) {
		اگر ((sc = channel_by_id(ssh, c->ctl_بچہ_id)) == تہی)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_بچہ_id);
		c->ctl_بچہ_id = 0;
		c->have_ctl_بچہ_id = 0;
		sc->ctl_chan = -1;
		اگر (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} ورنہ {
			اگر (sc->istate == CHAN_داخلہ_OPEN)
				chan_read_failed(ssh, sc);
			اگر (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
ساکن صحیح
env_permitted(ثابت حرف *env)
{
	u_int i;
	صحیح ret;
	حرف name[1024], *cp;

	اگر ((cp = strchr(env, '=')) == تہی || cp == env)
		واپس 0;
	ret = snprintf(name, حجم(name), "%.*s", (صحیح)(cp - env), env);
	اگر (ret <= 0 || (سائز_t)ret >= حجم(name)) {
		error_f("name '%.100s...' too long", env);
		واپس 0;
	}

	برائے (i = 0; i < options.عدد_send_env; i++)
		اگر (مطابقت_نمونہ(name, options.send_env[i]))
			واپس 1;

	واپس 0;
}

/* Mux master protocol message handlers */

ساکن صحیح
mux_master_process_hello(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	u_int ver;
	ساخت mux_master_state *state = (ساخت mux_master_state *)c->mux_ctx;
	صحیح r;

	اگر (state == تہی)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	اگر (state->hello_rcvd) {
		error_f("HELLO received twice");
		واپس -1;
	}
	اگر ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		واپس -1;
	}
	اگر (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		واپس -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	جب (sshbuf_len(m) > 0) {
		حرف *name = تہی;
		سائز_t قدر_len = 0;

		اگر ((r = sshbuf_get_cstring(m, &name, تہی)) != 0 ||
		    (r = sshbuf_get_string_براہ_راست(m, تہی, &قدر_len)) != 0) {
			error_fr(r, "parse extension");
			واپس -1;
		}
		اگر (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ورنہ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, قدر_len);
		}
		آزاد(name);
	}
	state->hello_rcvd = 1;
	واپس 0;
}

/* Enqueue a "ok" response to the reply buffer */
ساکن خالی
جواب_ok(ساخت sshbuf *جواب, u_int rid)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(جواب, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(جواب, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ساکن خالی
جواب_error(ساخت sshbuf *جواب, u_int type, u_int rid, ثابت حرف *پیغام)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(جواب, type)) != 0 ||
	    (r = sshbuf_put_u32(جواب, rid)) != 0 ||
	    (r = sshbuf_put_cstring(جواب, پیغام)) != 0)
		fatal_fr(r, "reply");
}

ساکن صحیح
mux_master_process_new_session(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	Channel *nc;
	ساخت mux_session_confirm_ctx *cctx;
	حرف *cmd, *cp;
	u_int i, j, env_len, escape_char, کھڑکی, packetmax;
	صحیح r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, حجم(*cctx));
	cctx->رکن = تہی;
	cctx->rid = rid;
	cmd = تہی;
	cctx->env = تہی;
	env_len = 0;
	اگر ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->رکن, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, تہی)) != 0) {
 malf:
		آزاد(cmd);
		برائے (j = 0; j < env_len; j++)
			آزاد(cctx->env[j]);
		آزاد(cctx->env);
		آزاد(cctx->رکن);
		آزاد(cctx);
		error_f("malformed message");
		واپس -1;
	}

#تعریف_کرو MUX_MAX_ENV_VARS	4096
	جب (sshbuf_len(m) > 0) {
		اگر ((r = sshbuf_get_cstring(m, &cp, تہی)) != 0)
			جاؤ malf;
		اگر (!env_permitted(cp)) {
			آزاد(cp);
			جاری;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    حجم(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = تہی;
		اگر (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			توڑو;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->رکن, cmd, env_len);

	اگر ((cctx->cmd = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put(cctx->cmd, cmd, لڑی_لمبائی(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	آزاد(cmd);
	cmd = تہی;

	/* Gather fds from client */
	برائے(i = 0; i < 3; i++) {
		اگر ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			برائے (j = 0; j < i; j++)
				close(new_fd[j]);
			برائے (j = 0; j < env_len; j++)
				آزاد(cctx->env[j]);
			آزاد(cctx->env);
			آزاد(cctx->رکن);
			sshbuf_free(cctx->cmd);
			آزاد(cctx);
			جواب_error(جواب, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			واپس -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	اگر (c->have_ctl_بچہ_id) {
		debug2_f("session already open");
		جواب_error(جواب, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		آزاد(cctx->رکن);
		اگر (env_len != 0) {
			برائے (i = 0; i < env_len; i++)
				آزاد(cctx->env[i]);
			آزاد(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		آزاد(cctx);
		واپس 0;
	}

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			جواب_error(جواب, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			جاؤ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	اگر (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	کھڑکی = CHAN_SES_کھڑکی_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	اگر (cctx->want_tty) {
		کھڑکی >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], کھڑکی, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	اگر (cctx->want_tty)
		channel_سیٹ_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_بچہ_id = nc->self;	/* link control -> session channel */
	c->have_ctl_بچہ_id = 1;

	اگر (cctx->want_tty && escape_char != 0xffffffff) {
		channel_رجسٹر_filter(ssh, nc->self,
		    client_simple_escape_filter, تہی,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((صحیح)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_رجسٹر_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_رجسٹر_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	واپس 0;
}

ساکن صحیح
mux_master_process_alive_check(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	صحیح r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	اگر ((r = sshbuf_put_u32(جواب, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(جواب, rid)) != 0 ||
	    (r = sshbuf_put_u32(جواب, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	واپس 0;
}

/* The "info" extension. */
ساکن صحیح
mux_master_process_ext_info(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	صحیح r;
	u_int حالت_2 = 0;
	حرف *name = تہی, *پیغام = تہی;

	debug2_f("channel %d: info request", c->self);

	اگر ((r = sshbuf_get_cstring(m, &name, تہی)) != 0)
		fatal_fr(r, "parse");

	اگر (strcmp(name, "connection") == 0) {
		اگر ((پیغام = connection_info_پیغام(ssh)) == تہی)
			fatal_f("connection_info_message");
		حالت_2 = 1;
	} ورنہ اگر (strcmp(name, "channels") == 0) {
		اگر ((پیغام = channel_open_پیغام(ssh)) == تہی)
			fatal_f("channel_open_message");
		حالت_2 = 1;
	} ورنہ {
		پیغام = xstrdup("info request type not supported");
	}

	/* prepare reply */
	اگر ((r = sshbuf_put_u32(جواب, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(جواب, rid)) != 0 ||
	    (r = sshbuf_put_u32(جواب, حالت_2)) != 0 ||
	    (r = sshbuf_put_cstring(جواب, پیغام)) != 0)
		fatal_fr(r, "reply");
	آزاد(پیغام);

	واپس 0;
}

ساکن صحیح
mux_master_process_terminate(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	debug2_f("channel %d: terminate request", c->self);

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			جواب_error(جواب, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			واپس 0;
		}
	}

	quit_pending = 1;
	جواب_ok(جواب, rid);
	/* XXX exit happens too soon - message never makes it to client */
	واپس 0;
}

ساکن حرف *
format_forward(u_int ftype, ساخت Forward *fwd)
{
	حرف *ret;

	انتخاب (ftype) {
	حالت MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_راستہ != تہی) ? fwd->listen_راستہ :
		    (fwd->listen_host == تہی) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_پورٹ,
		    (fwd->connect_راستہ != تہی) ? fwd->connect_راستہ :
		    fwd->connect_host, fwd->connect_پورٹ);
		توڑو;
	حالت MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == تہی) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_پورٹ);
		توڑو;
	حالت MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_راستہ != تہی) ? fwd->listen_راستہ :
		    (fwd->listen_host == تہی) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_پورٹ,
		    (fwd->connect_راستہ != تہی) ? fwd->connect_راستہ :
		    fwd->connect_host, fwd->connect_پورٹ);
		توڑو;
	طےشدہ:
		fatal_f("unknown forward type %u", ftype);
	}
	واپس ret;
}

ساکن صحیح
compare_host(ثابت حرف *a, ثابت حرف *b)
{
	اگر (a == تہی && b == تہی)
		واپس 1;
	اگر (a == تہی || b == تہی)
		واپس 0;
	واپس strcmp(a, b) == 0;
}

ساکن صحیح
compare_forward(ساخت Forward *a, ساخت Forward *b)
{
	اگر (!compare_host(a->listen_host, b->listen_host))
		واپس 0;
	اگر (!compare_host(a->listen_راستہ, b->listen_راستہ))
		واپس 0;
	اگر (a->listen_پورٹ != b->listen_پورٹ)
		واپس 0;
	اگر (!compare_host(a->connect_host, b->connect_host))
		واپس 0;
	اگر (!compare_host(a->connect_راستہ, b->connect_راستہ))
		واپس 0;
	اگر (a->connect_پورٹ != b->connect_پورٹ)
		واپس 0;

	واپس 1;
}

ساکن خالی
mux_confirm_remote_forward(ساخت ssh *ssh, صحیح type, uint32_t seq, خالی *ctxt)
{
	ساخت mux_channel_confirm_ctx *fctx = ctxt;
	حرف *failmsg = تہی;
	ساخت Forward *rfwd;
	Channel *c;
	ساخت sshbuf *برآمد;
	u_int پورٹ;
	صحیح r;

	اگر ((c = channel_by_id(ssh, fctx->cid)) == تہی) {
		/* no channel for reply */
		error_f("unknown channel");
		واپس;
	}
	اگر ((برآمد = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر (fctx->fid >= options.عدد_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_راستہ == تہی &&
	    options.remote_forwards[fctx->fid].connect_host == تہی)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		جاؤ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_پیغام_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_پورٹ, rfwd->connect_راستہ ? rfwd->connect_راستہ :
	    rfwd->connect_host, rfwd->connect_پورٹ);
	اگر (type == SSH2_پیغام_REQUEST_SUCCESS) {
		اگر (rfwd->listen_پورٹ == 0) {
			اگر ((r = sshpkt_get_u32(ssh, &پورٹ)) != 0)
				fatal_fr(r, "parse port");
			اگر (پورٹ > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", پورٹ,
				    rfwd->connect_host, rfwd->connect_پورٹ);
			}
			rfwd->allocated_پورٹ = (صحیح)پورٹ;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_پورٹ,
			    rfwd->connect_host, rfwd->connect_پورٹ);
			اگر ((r = sshbuf_put_u32(برآمد,
			    MUX_S_REMOTE_پورٹ)) != 0 ||
			    (r = sshbuf_put_u32(برآمد, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(برآمد,
			    rfwd->allocated_پورٹ)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_پورٹ);
		} ورنہ {
			جواب_ok(برآمد, fctx->rid);
		}
		جاؤ برآمد;
	} ورنہ {
		اگر (rfwd->listen_پورٹ == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		اگر (rfwd->listen_راستہ != تہی)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_راستہ);
		ورنہ
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_پورٹ);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_پورٹ,
		    rfwd->connect_راستہ ? rfwd->connect_راستہ :
		    rfwd->connect_host, rfwd->connect_پورٹ);

		آزاد(rfwd->listen_host);
		آزاد(rfwd->listen_راستہ);
		آزاد(rfwd->connect_host);
		آزاد(rfwd->connect_راستہ);
		memset(rfwd, 0, حجم(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	جواب_error(برآمد, MUX_S_FAILURE, fctx->rid, failmsg);
	آزاد(failmsg);
 برآمد:
	اگر ((r = sshbuf_put_stringb(c->output, برآمد)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(برآمد);
	اگر (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	آزاد(fctx);
}

ساکن صحیح
mux_master_process_open_fwd(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	ساخت Forward fwd;
	حرف *fwd_desc = تہی;
	حرف *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	صحیح r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, حجم(fwd));

	/* XXX - lport/cport check redundant */
	اگر ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)پورٹ_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)پورٹ_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		جاؤ برآمد;
	}
	اگر (*listen_addr == '\0') {
		آزاد(listen_addr);
		listen_addr = تہی;
	}
	اگر (*connect_addr == '\0') {
		آزاد(connect_addr);
		connect_addr = تہی;
	}

	memset(&fwd, 0, حجم(fwd));
	fwd.listen_پورٹ = lport;
	اگر (fwd.listen_پورٹ == پورٹ_STREAMLOCAL)
		fwd.listen_راستہ = listen_addr;
	ورنہ
		fwd.listen_host = listen_addr;
	fwd.connect_پورٹ = cport;
	اگر (fwd.connect_پورٹ == پورٹ_STREAMLOCAL)
		fwd.connect_راستہ = connect_addr;
	ورنہ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	اگر (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		آزاد(listen_addr);
		آزاد(connect_addr);
		جواب_error(جواب, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		واپس 0;
	}
	اگر (ftype == MUX_FWD_DYNAMIC && fwd.listen_راستہ) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		جاؤ invalid;
	}
	اگر (fwd.listen_پورٹ != پورٹ_STREAMLOCAL && fwd.listen_پورٹ >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_پورٹ);
		جاؤ invalid;
	}
	اگر ((fwd.connect_پورٹ != پورٹ_STREAMLOCAL &&
	    fwd.connect_پورٹ >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_پورٹ == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_پورٹ);
		جاؤ invalid;
	}
	اگر (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == تہی &&
	    fwd.connect_راستہ == تہی) {
		logit_f("missing connect host");
		جاؤ invalid;
	}

	/* Skip forwards that have already been requested */
	انتخاب (ftype) {
	حالت MUX_FWD_LOCAL:
	حالت MUX_FWD_DYNAMIC:
		برائے (i = 0; i < options.عدد_local_forwards; i++) {
			اگر (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				جواب_ok(جواب, rid);
				جاؤ برآمد;
			}
		}
		توڑو;
	حالت MUX_FWD_REMOTE:
		برائے (i = 0; i < options.عدد_remote_forwards; i++) {
			اگر (!compare_forward(&fwd, options.remote_forwards + i))
				جاری;
			اگر (fwd.listen_پورٹ != 0)
				جاؤ exists;
			debug2_f("found allocated port");
			اگر ((r = sshbuf_put_u32(جواب,
			    MUX_S_REMOTE_پورٹ)) != 0 ||
			    (r = sshbuf_put_u32(جواب, rid)) != 0 ||
			    (r = sshbuf_put_u32(جواب,
			    options.remote_forwards[i].allocated_پورٹ)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			جاؤ برآمد;
		}
		توڑو;
	}

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			جواب_error(جواب, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			جاؤ برآمد;
		}
	}

	اگر (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		اگر (!channel_تیاری_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			جواب_error(جواب, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			جاؤ برآمد;
		}
		جوڑو_local_forward(&options, &fwd);
		freefwd = 0;
	} ورنہ {
		ساخت mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		اگر (fwd.handle < 0)
			جاؤ fail;
		جوڑو_remote_forward(&options, &fwd);
		fctx = xcalloc(1, حجم(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.عدد_remote_forwards - 1;
		client_رجسٹر_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		جاؤ برآمد;
	}
	جواب_ok(جواب, rid);
 برآمد:
	آزاد(fwd_desc);
	اگر (freefwd) {
		آزاد(fwd.listen_host);
		آزاد(fwd.listen_راستہ);
		آزاد(fwd.connect_host);
		آزاد(fwd.connect_راستہ);
	}
	واپس ret;
}

ساکن صحیح
mux_master_process_close_fwd(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	ساخت Forward fwd, *ملا_fwd;
	حرف *fwd_desc = تہی;
	ثابت حرف *error_reason = تہی;
	حرف *listen_addr = تہی, *connect_addr = تہی;
	u_int ftype;
	صحیح r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, حجم(fwd));

	اگر ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)پورٹ_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)پورٹ_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		جاؤ برآمد;
	}

	اگر (*listen_addr == '\0') {
		آزاد(listen_addr);
		listen_addr = تہی;
	}
	اگر (*connect_addr == '\0') {
		آزاد(connect_addr);
		connect_addr = تہی;
	}

	memset(&fwd, 0, حجم(fwd));
	fwd.listen_پورٹ = lport;
	اگر (fwd.listen_پورٹ == پورٹ_STREAMLOCAL)
		fwd.listen_راستہ = listen_addr;
	ورنہ
		fwd.listen_host = listen_addr;
	fwd.connect_پورٹ = cport;
	اگر (fwd.connect_پورٹ == پورٹ_STREAMLOCAL)
		fwd.connect_راستہ = connect_addr;
	ورنہ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	ملا_fwd = تہی;
	انتخاب (ftype) {
	حالت MUX_FWD_LOCAL:
	حالت MUX_FWD_DYNAMIC:
		برائے (i = 0; i < options.عدد_local_forwards; i++) {
			اگر (compare_forward(&fwd,
			    options.local_forwards + i)) {
				ملا_fwd = options.local_forwards + i;
				توڑو;
			}
		}
		توڑو;
	حالت MUX_FWD_REMOTE:
		برائے (i = 0; i < options.عدد_remote_forwards; i++) {
			اگر (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				ملا_fwd = options.remote_forwards + i;
				توڑو;
			}
		}
		توڑو;
	}

	اگر (ملا_fwd == تہی)
		error_reason = "port not forwarded";
	ورنہ اگر (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		اگر (channel_request_rforward_cancel(ssh, ملا_fwd) == -1)
			error_reason = "port not in permitted opens";
	} ورنہ {	/* local and dynamic forwards */
		/* Ditto */
		اگر (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_پورٹ,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	اگر (error_reason != تہی)
		جواب_error(جواب, MUX_S_FAILURE, rid, error_reason);
	ورنہ {
		جواب_ok(جواب, rid);
		آزاد(ملا_fwd->listen_host);
		آزاد(ملا_fwd->listen_راستہ);
		آزاد(ملا_fwd->connect_host);
		آزاد(ملا_fwd->connect_راستہ);
		ملا_fwd->listen_host = ملا_fwd->connect_host = تہی;
		ملا_fwd->listen_راستہ = ملا_fwd->connect_راستہ = تہی;
		ملا_fwd->listen_پورٹ = ملا_fwd->connect_پورٹ = 0;
	}
 برآمد:
	آزاد(fwd_desc);
	آزاد(listen_addr);
	آزاد(connect_addr);

	واپس ret;
}

ساکن صحیح
mux_master_process_stdio_fwd(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	Channel *nc;
	حرف *chost = تہی;
	u_int _cport, i, j;
	صحیح ok = 0, cport, r, new_fd[2];
	ساخت mux_stdio_confirm_ctx *cctx;

	اگر ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, تہی)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		آزاد(chost);
		error_f("malformed message");
		واپس -1;
	}
	اگر (_cport == (u_int)پورٹ_STREAMLOCAL)
		cport = پورٹ_STREAMLOCAL;
	ورنہ اگر (_cport <= زیادہ_سے_زیادہ_عدد)
		cport = (صحیح)_cport;
	ورنہ {
		آزاد(chost);
		error_f("invalid port 0x%x", _cport);
		واپس -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	برائے(i = 0; i < 2; i++) {
		اگر ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			برائے (j = 0; j < i; j++)
				close(new_fd[j]);
			آزاد(chost);

			/* prepare reply */
			جواب_error(جواب, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			واپس -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	اگر (c->have_ctl_بچہ_id) {
		debug2_f("session already open");
		جواب_error(جواب, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		آزاد(chost);
		واپس 0;
	}

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (cport == پورٹ_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} ورنہ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		اگر (!ok) {
			debug2_f("stdio fwd refused by user");
			جواب_error(جواب, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			جاؤ cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	آزاد(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_بچہ_id = nc->self;	/* link control -> session channel */
	c->have_ctl_بچہ_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_رجسٹر_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, حجم(*cctx));
	cctx->rid = rid;
	channel_رجسٹر_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	واپس 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ساکن خالی
mux_stdio_confirm(ساخت ssh *ssh, صحیح id, صحیح success, خالی *arg)
{
	ساخت mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	ساخت sshbuf *جواب;
	صحیح r;

	اگر (cctx == تہی)
		fatal_f("cctx == NULL");
	اگر ((c = channel_by_id(ssh, id)) == تہی)
		fatal_f("no channel for id %d", id);
	اگر ((cc = channel_by_id(ssh, c->ctl_chan)) == تہی)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	اگر ((جواب = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");

	اگر (!success) {
		debug3_f("sending failure reply");
		جواب_error(جواب, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		جاؤ مکمل;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	اگر ((r = sshbuf_put_u32(جواب, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(جواب, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(جواب, c->self)) != 0)
		fatal_fr(r, "reply");

 مکمل:
	/* Send reply */
	اگر ((r = sshbuf_put_stringb(cc->output, جواب)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(جواب);

	اگر (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = تہی;
	آزاد(cctx);
}

ساکن صحیح
mux_master_process_stop_listening(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	debug_f("channel %d: stop listening", c->self);

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			جواب_error(جواب, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			واپس 0;
		}
	}

	اگر (mux_listener_channel != تہی) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		آزاد(options.control_راستہ);
		options.control_راستہ = تہی;
		mux_listener_channel = تہی;
		muxserver_sock = -1;
	}

	جواب_ok(جواب, rid);
	واپس 0;
}

ساکن صحیح
mux_master_process_proxy(ساخت ssh *ssh, u_int rid,
    Channel *c, ساخت sshbuf *m, ساخت sshbuf *جواب)
{
	صحیح r;

	debug_f("channel %d: proxy request", c->self);

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			جواب_error(جواب, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			واپس 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	اگر ((r = sshbuf_put_u32(جواب, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(جواب, rid)) != 0)
		fatal_fr(r, "reply");

	واپس 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ساکن صحیح
mux_master_read_cb(ساخت ssh *ssh, Channel *c)
{
	ساخت mux_master_state *state = (ساخت mux_master_state *)c->mux_ctx;
	ساخت sshbuf *اندر = تہی, *برآمد = تہی;
	u_int type, rid, i;
	صحیح r, ret = -1;

	اگر ((برآمد = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	اگر (c->mux_ctx == تہی) {
		state = xcalloc(1, حجم(*state));
		c->mux_ctx = state;
		channel_رجسٹر_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		اگر ((r = sshbuf_put_u32(برآمد, MUX_پیغام_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(برآمد, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		اگر ((r = sshbuf_put_cstring(برآمد, "info")) != 0 ||
		    (r = sshbuf_put_cstring(برآمد, "0")) != 0)
			fatal_fr(r, "put info extension");
		اگر ((r = sshbuf_put_stringb(c->output, برآمد)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		جاؤ برآمد;
	}

	/* Channel code ensures that we receive whole packets */
	اگر ((r = sshbuf_froms(c->داخلہ, &اندر)) != 0) {
 malf:
		error_f("malformed message");
		جاؤ برآمد;
	}

	اگر ((r = sshbuf_get_u32(اندر, &type)) != 0)
		جاؤ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(اندر));

	اگر (type == MUX_پیغام_HELLO)
		rid = 0;
	ورنہ {
		اگر (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_پیغام_HELLO, type);
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_get_u32(اندر, &rid)) != 0)
			جاؤ malf;
	}

	برائے (i = 0; mux_master_handlers[i].handler != تہی; i++) {
		اگر (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, اندر, برآمد);
			توڑو;
		}
	}
	اگر (mux_master_handlers[i].handler == تہی) {
		error_f("unsupported mux message 0x%08x", type);
		جواب_error(برآمد, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	اگر (sshbuf_len(برآمد) != 0 &&
	    (r = sshbuf_put_stringb(c->output, برآمد)) != 0)
		fatal_fr(r, "enqueue");
 برآمد:
	sshbuf_free(اندر);
	sshbuf_free(برآمد);
	واپس ret;
}

خالی
mux_exit_پیغام(ساخت ssh *ssh, Channel *c, صحیح exitval)
{
	ساخت sshbuf *m;
	Channel *mux_chan;
	صحیح r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	اگر ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == تہی)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_S_EXIT_پیغام)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

خالی
mux_tty_alloc_failed(ساخت ssh *ssh, Channel *c)
{
	ساخت sshbuf *m;
	Channel *mux_chan;
	صحیح r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	اگر ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == تہی)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
خالی
muxserver_listen(ساخت ssh *ssh)
{
	منوال_t old_umask;
	حرف *orig_control_راستہ = options.control_راستہ;
	حرف rbuf[16+1];
	u_int i, r;
	صحیح oerrno;

	اگر (options.control_راستہ == تہی ||
	    options.control_master == SSHCTL_MASTER_NO)
		واپس;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	برائے (i = 0; i < حجم(rbuf) - 1; i++) {
		r = arc4random_یکساں(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[حجم(rbuf) - 1] = '\0';
	options.control_راستہ = تہی;
	xasprintf(&options.control_راستہ, "%s.%s", orig_control_راستہ, rbuf);
	debug3_f("temporary control path %s", options.control_راستہ);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_راستہ, 64, 0);
	oerrno = errno;
	umask(old_umask);
	اگر (muxserver_sock < 0) {
		اگر (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_راستہ);
 disable_mux_master:
			اگر (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			آزاد(orig_control_راستہ);
			آزاد(options.control_راستہ);
			options.control_راستہ = تہی;
			options.control_master = SSHCTL_MASTER_NO;
			واپس;
		} ورنہ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	اگر (link(options.control_راستہ, orig_control_راستہ) != 0) {
		اگر (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_راستہ, orig_control_راستہ,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_راستہ);
		unlink(options.control_راستہ);
		جاؤ disable_mux_master;
	}
	unlink(options.control_راستہ);
	آزاد(options.control_راستہ);
	options.control_راستہ = orig_control_راستہ;

	سیٹ_nonblock(muxserver_sock);

	mux_listener_channel = channel_new(ssh, "mux listener",
	    SSH_CHANNEL_MUX_LISTENER, muxserver_sock, muxserver_sock, -1,
	    CHAN_TCP_کھڑکی_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, options.control_راستہ, 1);
	mux_listener_channel->mux_rcb = mux_master_read_cb;
	debug3_f("mux listener channel %d fd %d",
	    mux_listener_channel->self, mux_listener_channel->sock);
}

/* Callback on open confirmation in mux master for a mux client session. */
ساکن خالی
mux_session_confirm(ساخت ssh *ssh, صحیح id, صحیح success, خالی *arg)
{
	ساخت mux_session_confirm_ctx *cctx = arg;
	ثابت حرف *display;
	Channel *c, *cc;
	صحیح i, r;
	ساخت sshbuf *جواب;

	اگر (cctx == تہی)
		fatal_f("cctx == NULL");
	اگر ((c = channel_by_id(ssh, id)) == تہی)
		fatal_f("no channel for id %d", id);
	اگر ((cc = channel_by_id(ssh, c->ctl_chan)) == تہی)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	اگر ((جواب = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");

	اگر (!success) {
		debug3_f("sending failure reply");
		جواب_error(جواب, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		جاؤ مکمل;
	}

	display = getenv("DISPLAY");
	اگر (cctx->want_x_fwd && options.forward_x11 && display != تہی) {
		حرف *proto, *ڈیٹا;

		/* Get reasonable local authentication information. */
		اگر (client_x11_get_proto(ssh, display, options.xauth_location,
		    options.forward_x11_trusted, options.forward_x11_timeout,
		    &proto, &ڈیٹا) == 0) {
			/* Request forwarding with authentication spoofing. */
			debug("Requesting X11 forwarding with authentication "
			    "spoofing.");
			x11_request_forwarding_with_spoofing(ssh, id,
			    display, proto, ڈیٹا, 1);
			/* XXX exit_on_forward_failure */
			client_expect_confirm(ssh, id, "X11 forwarding",
			    CONFIRM_WARN);
		}
	}

	اگر (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_تیاری(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->رکن, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	اگر ((r = sshbuf_put_u32(جواب, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(جواب, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(جواب, c->self)) != 0)
		fatal_fr(r, "reply");

 مکمل:
	/* Send reply */
	اگر ((r = sshbuf_put_stringb(cc->output, جواب)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(جواب);

	اگر (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = تہی;
	sshbuf_free(cctx->cmd);
	آزاد(cctx->رکن);
	اگر (cctx->env != تہی) {
		برائے (i = 0; cctx->env[i] != تہی; i++)
			آزاد(cctx->env[i]);
		آزاد(cctx->env);
	}
	آزاد(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
ساکن خالی
control_client_sighandler(صحیح signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
ساکن خالی
control_client_sigrelay(صحیح signo)
{
	صحیح save_errno = errno;

	اگر (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

ساکن صحیح
mux_client_read(صحیح fd, ساخت sshbuf *b, سائز_t need, صحیح timeout_ms)
{
	سائز_t have;
	ssize_t len;
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	برائے (have = 0; have < need; ) {
		اگر (muxclient_terminate) {
			errno = EINTR;
			واپس -1;
		}
		len = اقرأ(fd, p + have, need - have);
		اگر (len == -1) {
			انتخاب (errno) {
#اگر defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			حالت EWOULDBLOCK:
#اگر_ختم
			حالت EAGAIN:
				اگر (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					واپس -1;	/* timeout */
				/* FALLTHROUGH */
			حالت EINTR:
				جاری;
			طےشدہ:
				واپس -1;
			}
		}
		اگر (len == 0) {
			errno = EPIPE;
			واپس -1;
		}
		have += (سائز_t)len;
	}
	واپس 0;
}

ساکن صحیح
mux_client_write_packet(صحیح fd, ساخت sshbuf *m)
{
	ساخت sshbuf *قطار;
	u_int have, need;
	صحیح r, oerrno, len;
	ثابت u_char *ptr;
	ساخت pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	اگر ((قطار = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_stringb(قطار, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(قطار);
	ptr = sshbuf_ptr(قطار);

	برائے (have = 0; have < need; ) {
		اگر (muxclient_terminate) {
			sshbuf_free(قطار);
			errno = EINTR;
			واپس -1;
		}
		len = اكتب(fd, ptr + have, need - have);
		اگر (len == -1) {
			انتخاب (errno) {
#اگر defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			حالت EWOULDBLOCK:
#اگر_ختم
			حالت EAGAIN:
				(خالی)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			حالت EINTR:
				جاری;
			طےشدہ:
				oerrno = errno;
				sshbuf_free(قطار);
				errno = oerrno;
				واپس -1;
			}
		}
		اگر (len == 0) {
			sshbuf_free(قطار);
			errno = EPIPE;
			واپس -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(قطار);
	واپس 0;
}

ساکن صحیح
mux_client_read_packet_timeout(صحیح fd, ساخت sshbuf *m, صحیح timeout_ms)
{
	ساخت sshbuf *قطار;
	سائز_t need, have;
	ثابت u_char *ptr;
	صحیح r, oerrno;

	اگر ((قطار = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر (mux_client_read(fd, قطار, 4, timeout_ms) != 0) {
		اگر ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(قطار);
		errno = oerrno;
		واپس -1;
	}
	need = PEEK_U32(sshbuf_ptr(قطار));
	اگر (mux_client_read(fd, قطار, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(قطار);
		errno = oerrno;
		واپس -1;
	}
	اگر ((r = sshbuf_get_string_براہ_راست(قطار, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(قطار);
	واپس 0;
}

ساکن صحیح
mux_client_read_packet(صحیح fd, ساخت sshbuf *m)
{
	واپس mux_client_read_packet_timeout(fd, m, -1);
}

ساکن صحیح
mux_client_hello_exchange(صحیح fd, صحیح timeout_ms)
{
	ساخت sshbuf *m;
	u_int type, ver;
	صحیح r, ret = -1;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_پیغام_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	اگر (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		جاؤ برآمد;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	اگر (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		جاؤ برآمد;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != MUX_پیغام_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_پیغام_HELLO, type);
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	اگر (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		جاؤ برآمد;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	جب (sshbuf_len(m) > 0) {
		حرف *name = تہی;

		اگر ((r = sshbuf_get_cstring(m, &name, تہی)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*قدر*/
			error_fr(r, "parse extension");
			جاؤ برآمد;
		}
		/* Process extensions. */
		اگر (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ورنہ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		آزاد(name);
	}
	/* success */
	ret = 0;
 برآمد:
	sshbuf_free(m);
	واپس ret;
}

ساکن u_int
mux_client_request_alive(صحیح fd)
{
	ساخت sshbuf *m;
	حرف *e;
	u_int pid, type, rid;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	اگر (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		واپس 0;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != MUX_S_ALIVE) {
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	اگر ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	اگر ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	واپس pid;
}

ساکن حرف *
mux_client_request_info(صحیح fd, ثابت حرف *name)
{
	ساخت sshbuf *m;
	حرف *e, *پیغام;
	u_int type, rid, حالت_2;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	اگر (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		واپس 0;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != MUX_S_EXT_INFO) {
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	اگر ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	اگر ((r = sshbuf_get_u32(m, &حالت_2)) != 0 ||
	    (r = sshbuf_get_cstring(m, &پیغام, تہی)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	واپس پیغام;
}

ساکن خالی
mux_client_request_terminate(صحیح fd)
{
	ساخت sshbuf *m;
	حرف *e;
	u_int type, rid;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	اگر (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		اگر (errno == EPIPE) {
			sshbuf_free(m);
			واپس;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	انتخاب (type) {
	حالت MUX_S_OK:
		توڑو;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	طےشدہ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

ساکن صحیح
mux_client_forward(صحیح fd, صحیح cancel_flag, u_int ftype, ساخت Forward *fwd)
{
	ساخت sshbuf *m;
	حرف *e, *fwd_desc;
	ثابت حرف *lhost, *chost;
	u_int type, rid;
	صحیح r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	آزاد(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	اگر (fwd->listen_راستہ != تہی)
		lhost = fwd->listen_راستہ;
	ورنہ اگر (fwd->listen_host == تہی)
		lhost = "";
	ورنہ اگر (*fwd->listen_host == '\0')
		lhost = "*";
	ورنہ
		lhost = fwd->listen_host;

	اگر (fwd->connect_راستہ != تہی)
		chost = fwd->connect_راستہ;
	ورنہ اگر (fwd->connect_host == تہی)
		chost = "";
	ورنہ
		chost = fwd->connect_host;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_پورٹ)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_پورٹ)) != 0)
		fatal_fr(r, "request");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	اگر (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		واپس -1;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	انتخاب (type) {
	حالت MUX_S_OK:
		توڑو;
	حالت MUX_S_REMOTE_پورٹ:
		اگر (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		اگر ((r = sshbuf_get_u32(m, &fwd->allocated_پورٹ)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_پورٹ,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_پورٹ);
		اگر (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_پورٹ);
		توڑو;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		واپس -1;
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		واپس -1;
	طےشدہ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	واپس 0;
}

ساکن صحیح
mux_client_forwards(صحیح fd, صحیح cancel_flag)
{
	صحیح i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.عدد_local_forwards, options.عدد_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	برائے (i = 0; i < options.عدد_local_forwards; i++) {
		اگر (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_پورٹ == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	برائے (i = 0; i < options.عدد_remote_forwards; i++) {
		اگر (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	واپس ret;
}

ساکن صحیح
mux_client_request_session(صحیح fd)
{
	ساخت sshbuf *m;
	حرف *e;
	ثابت حرف *رکن = تہی;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_نظر_آیا;
	خارجی حرف **environ;
	صحیح r, rawmode = 0;

	debug3_f("entering");

	اگر ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		واپس -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	اگر (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	اگر ((رکن = lookup_env_اندر_list("TERM", options.setenv,
	    options.عدد_setenv)) == تہی || *رکن == '\0')
		رکن = getenv("TERM");

	echar = 0xffffffff;
	اگر (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, تہی, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, رکن == تہی ? "" : رکن)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	اگر (options.عدد_send_env > 0 && environ != تہی) {
		برائے (i = 0; environ[i] != تہی; i++) {
			اگر (!env_permitted(environ[i]))
				جاری;
			اگر ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	برائے (i = 0; i < options.عدد_setenv; i++) {
		اگر ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	اگر (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	اگر (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		واپس -1;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	انتخاب (type) {
	حالت MUX_S_SESSION_OPENED:
		اگر ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		توڑو;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		واپس -1;
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		واپس -1;
	طےشدہ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		واپس -1;
	}
	muxclient_request_id++;

	اگر (pledge("stdio proc tty", تہی) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	اگر (options.fork_after_authentication)
		daemon(1, 1);
	ورنہ {
		rawmode = tty_flag;
		اگر (tty_flag) {
			enter_raw_منوال(
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
	برائے (exitval = 255, exitval_نظر_آیا = 0;;) {
		sshbuf_reset(m);
		اگر (mux_client_read_packet(fd, m) != 0)
			توڑو;
		اگر ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		انتخاب (type) {
		حالت MUX_S_TTY_ALLOC_FAIL:
			اگر ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			اگر (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_منوال(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			جاری;
		حالت MUX_S_EXIT_پیغام:
			اگر ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			اگر (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			اگر (exitval_نظر_آیا)
				fatal_f("exitval sent twice");
			اگر ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_نظر_آیا = 1;
			جاری;
		طےشدہ:
			اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	اگر (rawmode)
		leave_raw_منوال(options.request_tty == REQUEST_TTY_FORCE);

	اگر (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} ورنہ اگر (!exitval_نظر_آیا) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} ورنہ
		debug2("Received exit status from master %d", exitval);

	اگر (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	باہر_نکلو(exitval);
}

ساکن صحیح
mux_client_proxy(صحیح fd)
{
	ساخت sshbuf *m;
	حرف *e;
	u_int type, rid;
	صحیح r;

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	اگر (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		واپس 0;
	}
	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	اگر (type != MUX_S_PROXY) {
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	واپس 0;
}

ساکن صحیح
mux_client_request_stdio_fwd(صحیح fd)
{
	ساخت sshbuf *m;
	حرف *e;
	u_int type, rid, sid;
	صحیح r;

	debug3_f("entering");

	اگر ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		واپس -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	اگر (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, تہی, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_پورٹ)) != 0)
		fatal_fr(r, "request");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	اگر (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	اگر (pledge("stdio proc tty", تہی) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	اگر (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		واپس -1;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	انتخاب (type) {
	حالت MUX_S_SESSION_OPENED:
		اگر ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		توڑو;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	طےشدہ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		واپس -1;
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
	اگر (mux_client_read_packet(fd, m) != 0) {
		اگر (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			واپس 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

ساکن خالی
mux_client_request_stop_listening(صحیح fd)
{
	ساخت sshbuf *m;
	حرف *e;
	u_int type, rid;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	اگر (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	انتخاب (type) {
	حالت MUX_S_OK:
		توڑو;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, تہی)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	طےشدہ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
صحیح
muxclient(ثابت حرف *راستہ)
{
	ساخت sockaddr_un addr;
	صحیح sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	حرف *info = تہی;

	اگر (muxclient_command == 0) {
		اگر (options.stdio_forward_host != تہی)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		ورنہ
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	انتخاب (options.control_master) {
	حالت SSHCTL_MASTER_AUTO:
	حالت SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", راستہ);
		/* FALLTHROUGH */
	حالت SSHCTL_MASTER_NO:
		توڑو;
	طےشدہ:
		واپس -1;
	}

	memset(&addr, '\0', حجم(addr));
	addr.sun_family = AF_UNIX;

	اگر (strlcpy(addr.sun_راستہ, راستہ,
	    حجم(addr.sun_راستہ)) >= حجم(addr.sun_راستہ))
		fatal("ControlPath too long ('%s' >= %u bytes)", راستہ,
		    (غیرعلامتی صحیح)حجم(addr.sun_راستہ));

	اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	اگر (connect(sock, (ساخت sockaddr *)&addr, حجم(addr)) == -1) {
		انتخاب (muxclient_command) {
		حالت SSHMUX_COMMAND_OPEN:
		حالت SSHMUX_COMMAND_STDIO_FWD:
			توڑو;
		طےشدہ:
			fatal("Control socket connect(%.100s): %s", راستہ,
			    strerror(errno));
		}
		اگر (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", راستہ);
			unlink(راستہ);
		} ورنہ اگر (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", راستہ);
		} ورنہ {
			error("Control socket connect(%.100s): %s", راستہ,
			    strerror(errno));
		}
		close(sock);
		واپس -1;
	}
	سیٹ_nonblock(sock);

	/* Timeout on initial connection only. */
	اگر (timeout > 0 && timeout < زیادہ_سے_زیادہ_عدد / 1000)
		timeout_ms = timeout * 1000;

	اگر (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		واپس -1;
	}

	انتخاب (muxclient_command) {
	حالت SSHMUX_COMMAND_ALIVE_CHECK:
		اگر ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		باہر_نکلو(0);
	حالت SSHMUX_COMMAND_CONNINFO:
	حالت SSHMUX_COMMAND_CHANINFO:
		اگر (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		اگر (info == تہی)
			fatal_f("info request failed");
		لکھو("%s", info);
		باہر_نکلو(0);
	حالت SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		اگر (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		باہر_نکلو(0);
	حالت SSHMUX_COMMAND_FORWARD:
		اگر (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		باہر_نکلو(0);
	حالت SSHMUX_COMMAND_OPEN:
		اگر (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			واپس -1;
		}
		mux_client_request_session(sock);
		واپس -1;
	حالت SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		باہر_نکلو(0);
	حالت SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		اگر (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		باہر_نکلو(0);
	حالت SSHMUX_COMMAND_CANCEL_FWD:
		اگر (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		باہر_نکلو(0);
	حالت SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		واپس (sock);
	طےشدہ:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
