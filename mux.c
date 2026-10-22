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
بیرونی صحیح tty_flag;
بیرونی Options options;
بیرونی نویسه *host;
بیرونی ساختار sshbuf *command;
بیرونی فرار sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
ساختار mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	ساختار sshbuf *cmd;
	نویسه *term;
	ساختار termios tio;
	نویسه **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
ساختار mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
ساختار mux_channel_confirm_ctx {
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
ایستا فرار sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
ایستا u_int muxserver_pid = 0;

ایستا Channel *mux_listener_channel = پوچ;

ساختار mux_master_state {
	صحیح hello_rcvd;
};

/* mux protocol messages */
#define MUX_پیام_HELLO		0x00000001
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
ایستا u_int extensions = 0;

ایستا تهی mux_session_confirm(ساختار ssh *, صحیح, صحیح, تهی *);
ایستا تهی mux_stdio_confirm(ساختار ssh *, صحیح, صحیح, تهی *);

ایستا صحیح mux_master_process_hello(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_new_session(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_alive_check(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_terminate(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_open_fwd(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_close_fwd(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_stdio_fwd(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_stop_listening(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_proxy(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);
ایستا صحیح mux_master_process_ext_info(ساختار ssh *, u_int,
	    Channel *, ساختار sshbuf *, ساختار sshbuf *);

ایستا ثابت ساختار {
	u_int type;
	صحیح (*handler)(ساختار ssh *, u_int, Channel *,
	    ساختار sshbuf *, ساختار sshbuf *);
} mux_master_handlers[] = {
	{ MUX_پیام_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, پوچ }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
ایستا تهی
mux_master_session_cleanup_cb(ساختار ssh *ssh, صحیح cid, صحیح force, تهی *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	اگر (c == پوچ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	اگر (c->ctl_chan != -1) {
		اگر ((cc = channel_by_id(ssh, c->ctl_chan)) == پوچ)
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
ایستا تهی
mux_master_control_cleanup_cb(ساختار ssh *ssh, صحیح cid, صحیح force, تهی *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	اگر (c == پوچ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	اگر (c->have_ctl_child_id) {
		اگر ((sc = channel_by_id(ssh, c->ctl_child_id)) == پوچ)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		اگر (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} وگرنه {
			اگر (sc->istate == CHAN_درون_داد_OPEN)
				chan_read_failed(ssh, sc);
			اگر (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
ایستا صحیح
env_permitted(ثابت نویسه *env)
{
	u_int i;
	صحیح ret;
	نویسه name[1024], *cp;

	اگر ((cp = strchr(env, '=')) == پوچ || cp == env)
		بازگشت 0;
	ret = snprintf(name, اندازه(name), "%.*s", (صحیح)(cp - env), env);
	اگر (ret <= 0 || (size_t)ret >= اندازه(name)) {
		error_f("name '%.100s...' too long", env);
		بازگشت 0;
	}

	برای (i = 0; i < options.رقم_send_env; i++)
		اگر (match_pattern(name, options.send_env[i]))
			بازگشت 1;

	بازگشت 0;
}

/* Mux master protocol message handlers */

ایستا صحیح
mux_master_process_hello(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	u_int ver;
	ساختار mux_master_state *state = (ساختار mux_master_state *)c->mux_ctx;
	صحیح r;

	اگر (state == پوچ)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	اگر (state->hello_rcvd) {
		error_f("HELLO received twice");
		بازگشت -1;
	}
	اگر ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		بازگشت -1;
	}
	اگر (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		بازگشت -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	وقتی (sshbuf_len(m) > 0) {
		نویسه *name = پوچ;
		size_t مقدار_len = 0;

		اگر ((r = sshbuf_get_cstring(m, &name, پوچ)) != 0 ||
		    (r = sshbuf_get_string_direct(m, پوچ, &مقدار_len)) != 0) {
			error_fr(r, "parse extension");
			بازگشت -1;
		}
		اگر (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} وگرنه {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, مقدار_len);
		}
		آزاد(name);
	}
	state->hello_rcvd = 1;
	بازگشت 0;
}

/* Enqueue a "ok" response to the reply buffer */
ایستا تهی
reply_ok(ساختار sshbuf *reply, u_int rid)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ایستا تهی
reply_error(ساختار sshbuf *reply, u_int type, u_int rid, ثابت نویسه *پیام)
{
	صحیح r;

	اگر ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, پیام)) != 0)
		fatal_fr(r, "reply");
}

ایستا صحیح
mux_master_process_new_session(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	Channel *nc;
	ساختار mux_session_confirm_ctx *cctx;
	نویسه *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	صحیح r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, اندازه(*cctx));
	cctx->term = پوچ;
	cctx->rid = rid;
	cmd = پوچ;
	cctx->env = پوچ;
	env_len = 0;
	اگر ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, پوچ)) != 0) {
 malf:
		آزاد(cmd);
		برای (j = 0; j < env_len; j++)
			آزاد(cctx->env[j]);
		آزاد(cctx->env);
		آزاد(cctx->term);
		آزاد(cctx);
		error_f("malformed message");
		بازگشت -1;
	}

#define MUX_MAX_ENV_VARS	4096
	وقتی (sshbuf_len(m) > 0) {
		اگر ((r = sshbuf_get_cstring(m, &cp, پوچ)) != 0)
			برو malf;
		اگر (!env_permitted(cp)) {
			آزاد(cp);
			ادامه;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    اندازه(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = پوچ;
		اگر (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			بشکن;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	اگر ((cctx->cmd = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	آزاد(cmd);
	cmd = پوچ;

	/* Gather fds from client */
	برای(i = 0; i < 3; i++) {
		اگر ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			برای (j = 0; j < i; j++)
				close(new_fd[j]);
			برای (j = 0; j < env_len; j++)
				آزاد(cctx->env[j]);
			آزاد(cctx->env);
			آزاد(cctx->term);
			sshbuf_free(cctx->cmd);
			آزاد(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			بازگشت -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	اگر (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		آزاد(cctx->term);
		اگر (env_len != 0) {
			برای (i = 0; i < env_len; i++)
				آزاد(cctx->env[i]);
			آزاد(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		آزاد(cctx);
		بازگشت 0;
	}

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			برو cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	اگر (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	اگر (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	اگر (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	اگر (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, پوچ,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((صحیح)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	بازگشت 0;
}

ایستا صحیح
mux_master_process_alive_check(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	صحیح r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	اگر ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	بازگشت 0;
}

/* The "info" extension. */
ایستا صحیح
mux_master_process_ext_info(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	صحیح r;
	u_int status = 0;
	نویسه *name = پوچ, *پیام = پوچ;

	debug2_f("channel %d: info request", c->self);

	اگر ((r = sshbuf_get_cstring(m, &name, پوچ)) != 0)
		fatal_fr(r, "parse");

	اگر (strcmp(name, "connection") == 0) {
		اگر ((پیام = connection_info_message(ssh)) == پوچ)
			fatal_f("connection_info_message");
		status = 1;
	} وگرنه اگر (strcmp(name, "channels") == 0) {
		اگر ((پیام = channel_open_message(ssh)) == پوچ)
			fatal_f("channel_open_message");
		status = 1;
	} وگرنه {
		پیام = xstrdup("info request type not supported");
	}

	/* prepare reply */
	اگر ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, پیام)) != 0)
		fatal_fr(r, "reply");
	آزاد(پیام);

	بازگشت 0;
}

ایستا صحیح
mux_master_process_terminate(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			بازگشت 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	بازگشت 0;
}

ایستا نویسه *
format_forward(u_int ftype, ساختار Forward *fwd)
{
	نویسه *ret;

	انتخاب (ftype) {
	حالت MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != پوچ) ? fwd->listen_path :
		    (fwd->listen_host == پوچ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != پوچ) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		بشکن;
	حالت MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == پوچ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		بشکن;
	حالت MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != پوچ) ? fwd->listen_path :
		    (fwd->listen_host == پوچ) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != پوچ) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		بشکن;
	پیشفرض:
		fatal_f("unknown forward type %u", ftype);
	}
	بازگشت ret;
}

ایستا صحیح
compare_host(ثابت نویسه *a, ثابت نویسه *b)
{
	اگر (a == پوچ && b == پوچ)
		بازگشت 1;
	اگر (a == پوچ || b == پوچ)
		بازگشت 0;
	بازگشت strcmp(a, b) == 0;
}

ایستا صحیح
compare_forward(ساختار Forward *a, ساختار Forward *b)
{
	اگر (!compare_host(a->listen_host, b->listen_host))
		بازگشت 0;
	اگر (!compare_host(a->listen_path, b->listen_path))
		بازگشت 0;
	اگر (a->listen_port != b->listen_port)
		بازگشت 0;
	اگر (!compare_host(a->connect_host, b->connect_host))
		بازگشت 0;
	اگر (!compare_host(a->connect_path, b->connect_path))
		بازگشت 0;
	اگر (a->connect_port != b->connect_port)
		بازگشت 0;

	بازگشت 1;
}

ایستا تهی
mux_confirm_remote_forward(ساختار ssh *ssh, صحیح type, uint32_t seq, تهی *ctxt)
{
	ساختار mux_channel_confirm_ctx *fctx = ctxt;
	نویسه *failmsg = پوچ;
	ساختار Forward *rfwd;
	Channel *c;
	ساختار sshbuf *out;
	u_int port;
	صحیح r;

	اگر ((c = channel_by_id(ssh, fctx->cid)) == پوچ) {
		/* no channel for reply */
		error_f("unknown channel");
		بازگشت;
	}
	اگر ((out = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر (fctx->fid >= options.رقم_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == پوچ &&
	    options.remote_forwards[fctx->fid].connect_host == پوچ)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		برو fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_پیام_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	اگر (type == SSH2_پیام_REQUEST_SUCCESS) {
		اگر (rfwd->listen_port == 0) {
			اگر ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			اگر (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (صحیح)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			اگر ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} وگرنه {
			reply_ok(out, fctx->rid);
		}
		برو out;
	} وگرنه {
		اگر (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		اگر (rfwd->listen_path != پوچ)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		وگرنه
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		آزاد(rfwd->listen_host);
		آزاد(rfwd->listen_path);
		آزاد(rfwd->connect_host);
		آزاد(rfwd->connect_path);
		memset(rfwd, 0, اندازه(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	آزاد(failmsg);
 out:
	اگر ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	اگر (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	آزاد(fctx);
}

ایستا صحیح
mux_master_process_open_fwd(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	ساختار Forward fwd;
	نویسه *fwd_desc = پوچ;
	نویسه *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	صحیح r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, اندازه(fwd));

	/* XXX - lport/cport check redundant */
	اگر ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		برو out;
	}
	اگر (*listen_addr == '\0') {
		آزاد(listen_addr);
		listen_addr = پوچ;
	}
	اگر (*connect_addr == '\0') {
		آزاد(connect_addr);
		connect_addr = پوچ;
	}

	memset(&fwd, 0, اندازه(fwd));
	fwd.listen_port = lport;
	اگر (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	وگرنه
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	اگر (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	وگرنه
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	اگر (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		آزاد(listen_addr);
		آزاد(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		بازگشت 0;
	}
	اگر (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		برو invalid;
	}
	اگر (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		برو invalid;
	}
	اگر ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		برو invalid;
	}
	اگر (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == پوچ &&
	    fwd.connect_path == پوچ) {
		logit_f("missing connect host");
		برو invalid;
	}

	/* Skip forwards that have already been requested */
	انتخاب (ftype) {
	حالت MUX_FWD_LOCAL:
	حالت MUX_FWD_DYNAMIC:
		برای (i = 0; i < options.رقم_local_forwards; i++) {
			اگر (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				برو out;
			}
		}
		بشکن;
	حالت MUX_FWD_REMOTE:
		برای (i = 0; i < options.رقم_remote_forwards; i++) {
			اگر (!compare_forward(&fwd, options.remote_forwards + i))
				ادامه;
			اگر (fwd.listen_port != 0)
				برو exists;
			debug2_f("found allocated port");
			اگر ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			برو out;
		}
		بشکن;
	}

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			برو out;
		}
	}

	اگر (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		اگر (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			برو out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} وگرنه {
		ساختار mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		اگر (fwd.handle < 0)
			برو fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, اندازه(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.رقم_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		برو out;
	}
	reply_ok(reply, rid);
 out:
	آزاد(fwd_desc);
	اگر (freefwd) {
		آزاد(fwd.listen_host);
		آزاد(fwd.listen_path);
		آزاد(fwd.connect_host);
		آزاد(fwd.connect_path);
	}
	بازگشت ret;
}

ایستا صحیح
mux_master_process_close_fwd(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	ساختار Forward fwd, *found_fwd;
	نویسه *fwd_desc = پوچ;
	ثابت نویسه *error_reason = پوچ;
	نویسه *listen_addr = پوچ, *connect_addr = پوچ;
	u_int ftype;
	صحیح r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, اندازه(fwd));

	اگر ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		برو out;
	}

	اگر (*listen_addr == '\0') {
		آزاد(listen_addr);
		listen_addr = پوچ;
	}
	اگر (*connect_addr == '\0') {
		آزاد(connect_addr);
		connect_addr = پوچ;
	}

	memset(&fwd, 0, اندازه(fwd));
	fwd.listen_port = lport;
	اگر (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	وگرنه
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	اگر (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	وگرنه
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = پوچ;
	انتخاب (ftype) {
	حالت MUX_FWD_LOCAL:
	حالت MUX_FWD_DYNAMIC:
		برای (i = 0; i < options.رقم_local_forwards; i++) {
			اگر (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				بشکن;
			}
		}
		بشکن;
	حالت MUX_FWD_REMOTE:
		برای (i = 0; i < options.رقم_remote_forwards; i++) {
			اگر (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				بشکن;
			}
		}
		بشکن;
	}

	اگر (found_fwd == پوچ)
		error_reason = "port not forwarded";
	وگرنه اگر (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		اگر (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} وگرنه {	/* local and dynamic forwards */
		/* Ditto */
		اگر (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	اگر (error_reason != پوچ)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	وگرنه {
		reply_ok(reply, rid);
		آزاد(found_fwd->listen_host);
		آزاد(found_fwd->listen_path);
		آزاد(found_fwd->connect_host);
		آزاد(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = پوچ;
		found_fwd->listen_path = found_fwd->connect_path = پوچ;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	آزاد(fwd_desc);
	آزاد(listen_addr);
	آزاد(connect_addr);

	بازگشت ret;
}

ایستا صحیح
mux_master_process_stdio_fwd(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	Channel *nc;
	نویسه *chost = پوچ;
	u_int _cport, i, j;
	صحیح ok = 0, cport, r, new_fd[2];
	ساختار mux_stdio_confirm_ctx *cctx;

	اگر ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		آزاد(chost);
		error_f("malformed message");
		بازگشت -1;
	}
	اگر (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	وگرنه اگر (_cport <= INT_MAX)
		cport = (صحیح)_cport;
	وگرنه {
		آزاد(chost);
		error_f("invalid port 0x%x", _cport);
		بازگشت -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	برای(i = 0; i < 2; i++) {
		اگر ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			برای (j = 0; j < i; j++)
				close(new_fd[j]);
			آزاد(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			بازگشت -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	اگر (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		آزاد(chost);
		بازگشت 0;
	}

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} وگرنه {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		اگر (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			برو cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	آزاد(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, اندازه(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	بازگشت 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ایستا تهی
mux_stdio_confirm(ساختار ssh *ssh, صحیح id, صحیح success, تهی *arg)
{
	ساختار mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	ساختار sshbuf *reply;
	صحیح r;

	اگر (cctx == پوچ)
		fatal_f("cctx == NULL");
	اگر ((c = channel_by_id(ssh, id)) == پوچ)
		fatal_f("no channel for id %d", id);
	اگر ((cc = channel_by_id(ssh, c->ctl_chan)) == پوچ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	اگر ((reply = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");

	اگر (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		برو done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	اگر ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	اگر ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	اگر (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = پوچ;
	آزاد(cctx);
}

ایستا صحیح
mux_master_process_stop_listening(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			بازگشت 0;
		}
	}

	اگر (mux_listener_channel != پوچ) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		آزاد(options.control_path);
		options.control_path = پوچ;
		mux_listener_channel = پوچ;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	بازگشت 0;
}

ایستا صحیح
mux_master_process_proxy(ساختار ssh *ssh, u_int rid,
    Channel *c, ساختار sshbuf *m, ساختار sshbuf *reply)
{
	صحیح r;

	debug_f("channel %d: proxy request", c->self);

	اگر (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		اگر (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			بازگشت 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	اگر ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	بازگشت 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ایستا صحیح
mux_master_read_cb(ساختار ssh *ssh, Channel *c)
{
	ساختار mux_master_state *state = (ساختار mux_master_state *)c->mux_ctx;
	ساختار sshbuf *in = پوچ, *out = پوچ;
	u_int type, rid, i;
	صحیح r, ret = -1;

	اگر ((out = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	اگر (c->mux_ctx == پوچ) {
		state = xcalloc(1, اندازه(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		اگر ((r = sshbuf_put_u32(out, MUX_پیام_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		اگر ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		اگر ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		برو out;
	}

	/* Channel code ensures that we receive whole packets */
	اگر ((r = sshbuf_froms(c->درون_داد, &in)) != 0) {
 malf:
		error_f("malformed message");
		برو out;
	}

	اگر ((r = sshbuf_get_u32(in, &type)) != 0)
		برو malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	اگر (type == MUX_پیام_HELLO)
		rid = 0;
	وگرنه {
		اگر (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_پیام_HELLO, type);
			برو out;
		}
		اگر ((r = sshbuf_get_u32(in, &rid)) != 0)
			برو malf;
	}

	برای (i = 0; mux_master_handlers[i].handler != پوچ; i++) {
		اگر (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			بشکن;
		}
	}
	اگر (mux_master_handlers[i].handler == پوچ) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	اگر (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	بازگشت ret;
}

تهی
mux_exit_message(ساختار ssh *ssh, Channel *c, صحیح exitval)
{
	ساختار sshbuf *m;
	Channel *mux_chan;
	صحیح r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	اگر ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == پوچ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

تهی
mux_tty_alloc_failed(ساختار ssh *ssh, Channel *c)
{
	ساختار sshbuf *m;
	Channel *mux_chan;
	صحیح r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	اگر ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == پوچ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
تهی
muxserver_listen(ساختار ssh *ssh)
{
	mode_t old_umask;
	نویسه *orig_control_path = options.control_path;
	نویسه rbuf[16+1];
	u_int i, r;
	صحیح oerrno;

	اگر (options.control_path == پوچ ||
	    options.control_master == SSHCTL_MASTER_NO)
		بازگشت;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	برای (i = 0; i < اندازه(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[اندازه(rbuf) - 1] = '\0';
	options.control_path = پوچ;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	اگر (muxserver_sock < 0) {
		اگر (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			اگر (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			آزاد(orig_control_path);
			آزاد(options.control_path);
			options.control_path = پوچ;
			options.control_master = SSHCTL_MASTER_NO;
			بازگشت;
		} وگرنه {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	اگر (link(options.control_path, orig_control_path) != 0) {
		اگر (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		برو disable_mux_master;
	}
	unlink(options.control_path);
	آزاد(options.control_path);
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
ایستا تهی
mux_session_confirm(ساختار ssh *ssh, صحیح id, صحیح success, تهی *arg)
{
	ساختار mux_session_confirm_ctx *cctx = arg;
	ثابت نویسه *display;
	Channel *c, *cc;
	صحیح i, r;
	ساختار sshbuf *reply;

	اگر (cctx == پوچ)
		fatal_f("cctx == NULL");
	اگر ((c = channel_by_id(ssh, id)) == پوچ)
		fatal_f("no channel for id %d", id);
	اگر ((cc = channel_by_id(ssh, c->ctl_chan)) == پوچ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	اگر ((reply = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");

	اگر (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		برو done;
	}

	display = getenv("DISPLAY");
	اگر (cctx->want_x_fwd && options.forward_x11 && display != پوچ) {
		نویسه *proto, *data;

		/* Get reasonable local authentication information. */
		اگر (client_x11_get_proto(ssh, display, options.xauth_location,
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

	اگر (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	اگر ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	اگر ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	اگر (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = پوچ;
	sshbuf_free(cctx->cmd);
	آزاد(cctx->term);
	اگر (cctx->env != پوچ) {
		برای (i = 0; cctx->env[i] != پوچ; i++)
			آزاد(cctx->env[i]);
		آزاد(cctx->env);
	}
	آزاد(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
ایستا تهی
control_client_sighandler(صحیح signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
ایستا تهی
control_client_sigrelay(صحیح signo)
{
	صحیح save_errno = errno;

	اگر (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

ایستا صحیح
mux_client_read(صحیح fd, ساختار sshbuf *b, size_t need, صحیح timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	برای (have = 0; have < need; ) {
		اگر (muxclient_terminate) {
			errno = EINTR;
			بازگشت -1;
		}
		len = اقرأ(fd, p + have, need - have);
		اگر (len == -1) {
			انتخاب (errno) {
#اگر defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			حالت EWOULDBLOCK:
#endif
			حالت EAGAIN:
				اگر (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					بازگشت -1;	/* timeout */
				/* FALLTHROUGH */
			حالت EINTR:
				ادامه;
			پیشفرض:
				بازگشت -1;
			}
		}
		اگر (len == 0) {
			errno = EPIPE;
			بازگشت -1;
		}
		have += (size_t)len;
	}
	بازگشت 0;
}

ایستا صحیح
mux_client_write_packet(صحیح fd, ساختار sshbuf *m)
{
	ساختار sshbuf *queue;
	u_int have, need;
	صحیح r, oerrno, len;
	ثابت u_char *ptr;
	ساختار pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	اگر ((queue = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	برای (have = 0; have < need; ) {
		اگر (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			بازگشت -1;
		}
		len = اكتب(fd, ptr + have, need - have);
		اگر (len == -1) {
			انتخاب (errno) {
#اگر defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			حالت EWOULDBLOCK:
#endif
			حالت EAGAIN:
				(تهی)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			حالت EINTR:
				ادامه;
			پیشفرض:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				بازگشت -1;
			}
		}
		اگر (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			بازگشت -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	بازگشت 0;
}

ایستا صحیح
mux_client_read_packet_timeout(صحیح fd, ساختار sshbuf *m, صحیح timeout_ms)
{
	ساختار sshbuf *queue;
	size_t need, have;
	ثابت u_char *ptr;
	صحیح r, oerrno;

	اگر ((queue = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		اگر ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		بازگشت -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	اگر (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		بازگشت -1;
	}
	اگر ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	بازگشت 0;
}

ایستا صحیح
mux_client_read_packet(صحیح fd, ساختار sshbuf *m)
{
	بازگشت mux_client_read_packet_timeout(fd, m, -1);
}

ایستا صحیح
mux_client_hello_exchange(صحیح fd, صحیح timeout_ms)
{
	ساختار sshbuf *m;
	u_int type, ver;
	صحیح r, ret = -1;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_پیام_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	اگر (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		برو out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	اگر (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		برو out;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != MUX_پیام_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_پیام_HELLO, type);
		برو out;
	}
	اگر ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	اگر (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		برو out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	وقتی (sshbuf_len(m) > 0) {
		نویسه *name = پوچ;

		اگر ((r = sshbuf_get_cstring(m, &name, پوچ)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*مقدار*/
			error_fr(r, "parse extension");
			برو out;
		}
		/* Process extensions. */
		اگر (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} وگرنه {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		آزاد(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	بازگشت ret;
}

ایستا u_int
mux_client_request_alive(صحیح fd)
{
	ساختار sshbuf *m;
	نویسه *e;
	u_int pid, type, rid;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
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
		بازگشت 0;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != MUX_S_ALIVE) {
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
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

	بازگشت pid;
}

ایستا نویسه *
mux_client_request_info(صحیح fd, ثابت نویسه *name)
{
	ساختار sshbuf *m;
	نویسه *e, *پیام;
	u_int type, rid, status;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
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
		بازگشت 0;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	اگر (type != MUX_S_EXT_INFO) {
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	اگر ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	اگر ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &پیام, پوچ)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	بازگشت پیام;
}

ایستا تهی
mux_client_request_terminate(صحیح fd)
{
	ساختار sshbuf *m;
	نویسه *e;
	u_int type, rid;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
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
			بازگشت;
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
		بشکن;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	پیشفرض:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

ایستا صحیح
mux_client_forward(صحیح fd, صحیح cancel_flag, u_int ftype, ساختار Forward *fwd)
{
	ساختار sshbuf *m;
	نویسه *e, *fwd_desc;
	ثابت نویسه *lhost, *chost;
	u_int type, rid;
	صحیح r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	آزاد(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	اگر (fwd->listen_path != پوچ)
		lhost = fwd->listen_path;
	وگرنه اگر (fwd->listen_host == پوچ)
		lhost = "";
	وگرنه اگر (*fwd->listen_host == '\0')
		lhost = "*";
	وگرنه
		lhost = fwd->listen_host;

	اگر (fwd->connect_path != پوچ)
		chost = fwd->connect_path;
	وگرنه اگر (fwd->connect_host == پوچ)
		chost = "";
	وگرنه
		chost = fwd->connect_host;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	اگر (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		بازگشت -1;
	}

	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	انتخاب (type) {
	حالت MUX_S_OK:
		بشکن;
	حالت MUX_S_REMOTE_PORT:
		اگر (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		اگر ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		اگر (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		بشکن;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		بازگشت -1;
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		بازگشت -1;
	پیشفرض:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	بازگشت 0;
}

ایستا صحیح
mux_client_forwards(صحیح fd, صحیح cancel_flag)
{
	صحیح i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.رقم_local_forwards, options.رقم_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	برای (i = 0; i < options.رقم_local_forwards; i++) {
		اگر (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	برای (i = 0; i < options.رقم_remote_forwards; i++) {
		اگر (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	بازگشت ret;
}

ایستا صحیح
mux_client_request_session(صحیح fd)
{
	ساختار sshbuf *m;
	نویسه *e;
	ثابت نویسه *term = پوچ;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	بیرونی نویسه **environ;
	صحیح r, rawmode = 0;

	debug3_f("entering");

	اگر ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		بازگشت -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	اگر (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	اگر ((term = lookup_env_in_list("TERM", options.setenv,
	    options.رقم_setenv)) == پوچ || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	اگر (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, پوچ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == پوچ ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	اگر (options.رقم_send_env > 0 && environ != پوچ) {
		برای (i = 0; environ[i] != پوچ; i++) {
			اگر (!env_permitted(environ[i]))
				ادامه;
			اگر ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	برای (i = 0; i < options.رقم_setenv; i++) {
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
		بازگشت -1;
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
		بشکن;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		بازگشت -1;
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		بازگشت -1;
	پیشفرض:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		بازگشت -1;
	}
	muxclient_request_id++;

	اگر (pledge("stdio proc tty", پوچ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	اگر (options.fork_after_authentication)
		daemon(1, 1);
	وگرنه {
		rawmode = tty_flag;
		اگر (tty_flag) {
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
	برای (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		اگر (mux_client_read_packet(fd, m) != 0)
			بشکن;
		اگر ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		انتخاب (type) {
		حالت MUX_S_TTY_ALLOC_FAIL:
			اگر ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			اگر (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			ادامه;
		حالت MUX_S_EXIT_MESSAGE:
			اگر ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			اگر (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			اگر (exitval_seen)
				fatal_f("exitval sent twice");
			اگر ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			ادامه;
		پیشفرض:
			اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	اگر (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	اگر (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} وگرنه اگر (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} وگرنه
		debug2("Received exit status from master %d", exitval);

	اگر (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

ایستا صحیح
mux_client_proxy(صحیح fd)
{
	ساختار sshbuf *m;
	نویسه *e;
	u_int type, rid;
	صحیح r;

	اگر ((m = sshbuf_new()) == پوچ)
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
		بازگشت 0;
	}
	اگر ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	اگر (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	اگر (type != MUX_S_PROXY) {
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	بازگشت 0;
}

ایستا صحیح
mux_client_request_stdio_fwd(صحیح fd)
{
	ساختار sshbuf *m;
	نویسه *e;
	u_int type, rid, sid;
	صحیح r;

	debug3_f("entering");

	اگر ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		بازگشت -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	اگر (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	اگر ((m = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new");
	اگر ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, پوچ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	اگر (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	اگر (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	اگر (pledge("stdio proc tty", پوچ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	اگر (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		بازگشت -1;
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
		بشکن;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	پیشفرض:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		بازگشت -1;
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
			بازگشت 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

ایستا تهی
mux_client_request_stop_listening(صحیح fd)
{
	ساختار sshbuf *m;
	نویسه *e;
	u_int type, rid;
	صحیح r;

	debug3_f("entering");

	اگر ((m = sshbuf_new()) == پوچ)
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
		بشکن;
	حالت MUX_S_PERMISSION_DENIED:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	حالت MUX_S_FAILURE:
		اگر ((r = sshbuf_get_cstring(m, &e, پوچ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	پیشفرض:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
صحیح
muxclient(ثابت نویسه *path)
{
	ساختار sockaddr_un addr;
	صحیح sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	نویسه *info = پوچ;

	اگر (muxclient_command == 0) {
		اگر (options.stdio_forward_host != پوچ)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		وگرنه
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	انتخاب (options.control_master) {
	حالت SSHCTL_MASTER_AUTO:
	حالت SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	حالت SSHCTL_MASTER_NO:
		بشکن;
	پیشفرض:
		بازگشت -1;
	}

	memset(&addr, '\0', اندازه(addr));
	addr.sun_family = AF_UNIX;

	اگر (strlcpy(addr.sun_path, path,
	    اندازه(addr.sun_path)) >= اندازه(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned صحیح)اندازه(addr.sun_path));

	اگر ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	اگر (connect(sock, (ساختار sockaddr *)&addr, اندازه(addr)) == -1) {
		انتخاب (muxclient_command) {
		حالت SSHMUX_COMMAND_OPEN:
		حالت SSHMUX_COMMAND_STDIO_FWD:
			بشکن;
		پیشفرض:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		اگر (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} وگرنه اگر (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} وگرنه {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		بازگشت -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	اگر (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	اگر (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		بازگشت -1;
	}

	انتخاب (muxclient_command) {
	حالت SSHMUX_COMMAND_ALIVE_CHECK:
		اگر ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	حالت SSHMUX_COMMAND_CONNINFO:
	حالت SSHMUX_COMMAND_CHANINFO:
		اگر (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		اگر (info == پوچ)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	حالت SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		اگر (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	حالت SSHMUX_COMMAND_FORWARD:
		اگر (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	حالت SSHMUX_COMMAND_OPEN:
		اگر (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			بازگشت -1;
		}
		mux_client_request_session(sock);
		بازگشت -1;
	حالت SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	حالت SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		اگر (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	حالت SSHMUX_COMMAND_CANCEL_FWD:
		اگر (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	حالت SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		بازگشت (sock);
	پیشفرض:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
