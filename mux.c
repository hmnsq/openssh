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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <poll.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "monitor_fdpass.h"
#அந்தர்பாவ "sshpty.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "clientloop.h"

/* from ssh.c */
வெளி முழு tty_flag;
வெளி Options options;
வெளி எழுத்து *host;
வெளி கட்டமைப்பு sshbuf *command;
வெளி நிலையற்ற sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
கட்டமைப்பு mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	கட்டமைப்பு sshbuf *cmd;
	எழுத்து *term;
	கட்டமைப்பு termios tio;
	எழுத்து **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
கட்டமைப்பு mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
கட்டமைப்பு mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	முழு fid;	/* forward id */
};

/* fd to control socket */
முழு muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
நிலையான நிலையற்ற sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
நிலையான u_int muxserver_pid = 0;

நிலையான Channel *mux_listener_channel = வெற்று;

கட்டமைப்பு mux_master_state {
	முழு hello_rcvd;
};

/* mux protocol messages */
#define MUX_செய்தி_HELLO		0x00000001
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
நிலையான u_int extensions = 0;

நிலையான வெறுமை mux_session_confirm(கட்டமைப்பு ssh *, முழு, முழு, வெறுமை *);
நிலையான வெறுமை mux_stdio_confirm(கட்டமைப்பு ssh *, முழு, முழு, வெறுமை *);

நிலையான முழு mux_master_process_hello(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_new_session(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_alive_check(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_terminate(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_open_fwd(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_close_fwd(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_stdio_fwd(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_stop_listening(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_proxy(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
நிலையான முழு mux_master_process_ext_info(கட்டமைப்பு ssh *, u_int,
	    Channel *, கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);

நிலையான மாறிலி கட்டமைப்பு {
	u_int type;
	முழு (*handler)(கட்டமைப்பு ssh *, u_int, Channel *,
	    கட்டமைப்பு sshbuf *, கட்டமைப்பு sshbuf *);
} mux_master_handlers[] = {
	{ MUX_செய்தி_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, வெற்று }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
நிலையான வெறுமை
mux_master_session_cleanup_cb(கட்டமைப்பு ssh *ssh, முழு cid, முழு force, வெறுமை *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	எனில் (c == வெற்று)
		fatal_f("channel_by_id(%i) == NULL", cid);
	எனில் (c->ctl_chan != -1) {
		எனில் ((cc = channel_by_id(ssh, c->ctl_chan)) == வெற்று)
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
நிலையான வெறுமை
mux_master_control_cleanup_cb(கட்டமைப்பு ssh *ssh, முழு cid, முழு force, வெறுமை *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	எனில் (c == வெற்று)
		fatal_f("channel_by_id(%i) == NULL", cid);
	எனில் (c->have_ctl_child_id) {
		எனில் ((sc = channel_by_id(ssh, c->ctl_child_id)) == வெற்று)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		எனில் (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} இல்லையெனில் {
			எனில் (sc->istate == CHAN_உள்ளீடு_OPEN)
				chan_read_failed(ssh, sc);
			எனில் (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
நிலையான முழு
env_permitted(மாறிலி எழுத்து *env)
{
	u_int i;
	முழு ret;
	எழுத்து name[1024], *cp;

	எனில் ((cp = strchr(env, '=')) == வெற்று || cp == env)
		திரும்பு 0;
	ret = snprintf(name, அளவு(name), "%.*s", (முழு)(cp - env), env);
	எனில் (ret <= 0 || (size_t)ret >= அளவு(name)) {
		error_f("name '%.100s...' too long", env);
		திரும்பு 0;
	}

	க்கு (i = 0; i < options.இலக்கம்_send_env; i++)
		எனில் (match_pattern(name, options.send_env[i]))
			திரும்பு 1;

	திரும்பு 0;
}

/* Mux master protocol message handlers */

நிலையான முழு
mux_master_process_hello(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	u_int ver;
	கட்டமைப்பு mux_master_state *state = (கட்டமைப்பு mux_master_state *)c->mux_ctx;
	முழு r;

	எனில் (state == வெற்று)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	எனில் (state->hello_rcvd) {
		error_f("HELLO received twice");
		திரும்பு -1;
	}
	எனில் ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		திரும்பு -1;
	}
	எனில் (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		திரும்பு -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	போது (sshbuf_len(m) > 0) {
		எழுத்து *name = வெற்று;
		size_t மதிப்பு_len = 0;

		எனில் ((r = sshbuf_get_cstring(m, &name, வெற்று)) != 0 ||
		    (r = sshbuf_get_string_direct(m, வெற்று, &மதிப்பு_len)) != 0) {
			error_fr(r, "parse extension");
			திரும்பு -1;
		}
		எனில் (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} இல்லையெனில் {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, மதிப்பு_len);
		}
		விடுவி(name);
	}
	state->hello_rcvd = 1;
	திரும்பு 0;
}

/* Enqueue a "ok" response to the reply buffer */
நிலையான வெறுமை
reply_ok(கட்டமைப்பு sshbuf *reply, u_int rid)
{
	முழு r;

	எனில் ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
நிலையான வெறுமை
reply_error(கட்டமைப்பு sshbuf *reply, u_int type, u_int rid, மாறிலி எழுத்து *செய்தி)
{
	முழு r;

	எனில் ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, செய்தி)) != 0)
		fatal_fr(r, "reply");
}

நிலையான முழு
mux_master_process_new_session(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	Channel *nc;
	கட்டமைப்பு mux_session_confirm_ctx *cctx;
	எழுத்து *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	முழு r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, அளவு(*cctx));
	cctx->term = வெற்று;
	cctx->rid = rid;
	cmd = வெற்று;
	cctx->env = வெற்று;
	env_len = 0;
	எனில் ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, வெற்று)) != 0) {
 malf:
		விடுவி(cmd);
		க்கு (j = 0; j < env_len; j++)
			விடுவி(cctx->env[j]);
		விடுவி(cctx->env);
		விடுவி(cctx->term);
		விடுவி(cctx);
		error_f("malformed message");
		திரும்பு -1;
	}

#define MUX_MAX_ENV_VARS	4096
	போது (sshbuf_len(m) > 0) {
		எனில் ((r = sshbuf_get_cstring(m, &cp, வெற்று)) != 0)
			செல் malf;
		எனில் (!env_permitted(cp)) {
			விடுவி(cp);
			தொடர்;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    அளவு(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = வெற்று;
		எனில் (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			நிறுத்து;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	எனில் ((cctx->cmd = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	விடுவி(cmd);
	cmd = வெற்று;

	/* Gather fds from client */
	க்கு(i = 0; i < 3; i++) {
		எனில் ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			க்கு (j = 0; j < i; j++)
				close(new_fd[j]);
			க்கு (j = 0; j < env_len; j++)
				விடுவி(cctx->env[j]);
			விடுவி(cctx->env);
			விடுவி(cctx->term);
			sshbuf_free(cctx->cmd);
			விடுவி(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			திரும்பு -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	எனில் (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		விடுவி(cctx->term);
		எனில் (env_len != 0) {
			க்கு (i = 0; i < env_len; i++)
				விடுவி(cctx->env[i]);
			விடுவி(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		விடுவி(cctx);
		திரும்பு 0;
	}

	எனில் (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		எனில் (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			செல் cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	எனில் (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	எனில் (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	எனில் (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	எனில் (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, வெற்று,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((முழு)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	திரும்பு 0;
}

நிலையான முழு
mux_master_process_alive_check(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	முழு r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	எனில் ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	திரும்பு 0;
}

/* The "info" extension. */
நிலையான முழு
mux_master_process_ext_info(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	முழு r;
	u_int status = 0;
	எழுத்து *name = வெற்று, *செய்தி = வெற்று;

	debug2_f("channel %d: info request", c->self);

	எனில் ((r = sshbuf_get_cstring(m, &name, வெற்று)) != 0)
		fatal_fr(r, "parse");

	எனில் (strcmp(name, "connection") == 0) {
		எனில் ((செய்தி = connection_info_message(ssh)) == வெற்று)
			fatal_f("connection_info_message");
		status = 1;
	} இல்லையெனில் எனில் (strcmp(name, "channels") == 0) {
		எனில் ((செய்தி = channel_open_message(ssh)) == வெற்று)
			fatal_f("channel_open_message");
		status = 1;
	} இல்லையெனில் {
		செய்தி = xstrdup("info request type not supported");
	}

	/* prepare reply */
	எனில் ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, செய்தி)) != 0)
		fatal_fr(r, "reply");
	விடுவி(செய்தி);

	திரும்பு 0;
}

நிலையான முழு
mux_master_process_terminate(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	எனில் (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		எனில் (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			திரும்பு 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	திரும்பு 0;
}

நிலையான எழுத்து *
format_forward(u_int ftype, கட்டமைப்பு Forward *fwd)
{
	எழுத்து *ret;

	தேர்வு (ftype) {
	நிலை MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != வெற்று) ? fwd->listen_path :
		    (fwd->listen_host == வெற்று) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != வெற்று) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		நிறுத்து;
	நிலை MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == வெற்று) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		நிறுத்து;
	நிலை MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != வெற்று) ? fwd->listen_path :
		    (fwd->listen_host == வெற்று) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != வெற்று) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		நிறுத்து;
	இயல்பு:
		fatal_f("unknown forward type %u", ftype);
	}
	திரும்பு ret;
}

நிலையான முழு
compare_host(மாறிலி எழுத்து *a, மாறிலி எழுத்து *b)
{
	எனில் (a == வெற்று && b == வெற்று)
		திரும்பு 1;
	எனில் (a == வெற்று || b == வெற்று)
		திரும்பு 0;
	திரும்பு strcmp(a, b) == 0;
}

நிலையான முழு
compare_forward(கட்டமைப்பு Forward *a, கட்டமைப்பு Forward *b)
{
	எனில் (!compare_host(a->listen_host, b->listen_host))
		திரும்பு 0;
	எனில் (!compare_host(a->listen_path, b->listen_path))
		திரும்பு 0;
	எனில் (a->listen_port != b->listen_port)
		திரும்பு 0;
	எனில் (!compare_host(a->connect_host, b->connect_host))
		திரும்பு 0;
	எனில் (!compare_host(a->connect_path, b->connect_path))
		திரும்பு 0;
	எனில் (a->connect_port != b->connect_port)
		திரும்பு 0;

	திரும்பு 1;
}

நிலையான வெறுமை
mux_confirm_remote_forward(கட்டமைப்பு ssh *ssh, முழு type, uint32_t seq, வெறுமை *ctxt)
{
	கட்டமைப்பு mux_channel_confirm_ctx *fctx = ctxt;
	எழுத்து *failmsg = வெற்று;
	கட்டமைப்பு Forward *rfwd;
	Channel *c;
	கட்டமைப்பு sshbuf *out;
	u_int port;
	முழு r;

	எனில் ((c = channel_by_id(ssh, fctx->cid)) == வெற்று) {
		/* no channel for reply */
		error_f("unknown channel");
		திரும்பு;
	}
	எனில் ((out = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் (fctx->fid >= options.இலக்கம்_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == வெற்று &&
	    options.remote_forwards[fctx->fid].connect_host == வெற்று)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		செல் fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_செய்தி_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	எனில் (type == SSH2_செய்தி_REQUEST_SUCCESS) {
		எனில் (rfwd->listen_port == 0) {
			எனில் ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			எனில் (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (முழு)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			எனில் ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} இல்லையெனில் {
			reply_ok(out, fctx->rid);
		}
		செல் out;
	} இல்லையெனில் {
		எனில் (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		எனில் (rfwd->listen_path != வெற்று)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		இல்லையெனில்
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		விடுவி(rfwd->listen_host);
		விடுவி(rfwd->listen_path);
		விடுவி(rfwd->connect_host);
		விடுவி(rfwd->connect_path);
		memset(rfwd, 0, அளவு(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	விடுவி(failmsg);
 out:
	எனில் ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	எனில் (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	விடுவி(fctx);
}

நிலையான முழு
mux_master_process_open_fwd(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	கட்டமைப்பு Forward fwd;
	எழுத்து *fwd_desc = வெற்று;
	எழுத்து *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	முழு r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, அளவு(fwd));

	/* XXX - lport/cport check redundant */
	எனில் ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		செல் out;
	}
	எனில் (*listen_addr == '\0') {
		விடுவி(listen_addr);
		listen_addr = வெற்று;
	}
	எனில் (*connect_addr == '\0') {
		விடுவி(connect_addr);
		connect_addr = வெற்று;
	}

	memset(&fwd, 0, அளவு(fwd));
	fwd.listen_port = lport;
	எனில் (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	இல்லையெனில்
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	எனில் (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	இல்லையெனில்
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	எனில் (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		விடுவி(listen_addr);
		விடுவி(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		திரும்பு 0;
	}
	எனில் (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		செல் invalid;
	}
	எனில் (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		செல் invalid;
	}
	எனில் ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		செல் invalid;
	}
	எனில் (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == வெற்று &&
	    fwd.connect_path == வெற்று) {
		logit_f("missing connect host");
		செல் invalid;
	}

	/* Skip forwards that have already been requested */
	தேர்வு (ftype) {
	நிலை MUX_FWD_LOCAL:
	நிலை MUX_FWD_DYNAMIC:
		க்கு (i = 0; i < options.இலக்கம்_local_forwards; i++) {
			எனில் (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				செல் out;
			}
		}
		நிறுத்து;
	நிலை MUX_FWD_REMOTE:
		க்கு (i = 0; i < options.இலக்கம்_remote_forwards; i++) {
			எனில் (!compare_forward(&fwd, options.remote_forwards + i))
				தொடர்;
			எனில் (fwd.listen_port != 0)
				செல் exists;
			debug2_f("found allocated port");
			எனில் ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			செல் out;
		}
		நிறுத்து;
	}

	எனில் (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		எனில் (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			செல் out;
		}
	}

	எனில் (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		எனில் (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			செல் out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} இல்லையெனில் {
		கட்டமைப்பு mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		எனில் (fwd.handle < 0)
			செல் fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, அளவு(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.இலக்கம்_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		செல் out;
	}
	reply_ok(reply, rid);
 out:
	விடுவி(fwd_desc);
	எனில் (freefwd) {
		விடுவி(fwd.listen_host);
		விடுவி(fwd.listen_path);
		விடுவி(fwd.connect_host);
		விடுவி(fwd.connect_path);
	}
	திரும்பு ret;
}

நிலையான முழு
mux_master_process_close_fwd(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	கட்டமைப்பு Forward fwd, *found_fwd;
	எழுத்து *fwd_desc = வெற்று;
	மாறிலி எழுத்து *error_reason = வெற்று;
	எழுத்து *listen_addr = வெற்று, *connect_addr = வெற்று;
	u_int ftype;
	முழு r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, அளவு(fwd));

	எனில் ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		செல் out;
	}

	எனில் (*listen_addr == '\0') {
		விடுவி(listen_addr);
		listen_addr = வெற்று;
	}
	எனில் (*connect_addr == '\0') {
		விடுவி(connect_addr);
		connect_addr = வெற்று;
	}

	memset(&fwd, 0, அளவு(fwd));
	fwd.listen_port = lport;
	எனில் (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	இல்லையெனில்
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	எனில் (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	இல்லையெனில்
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = வெற்று;
	தேர்வு (ftype) {
	நிலை MUX_FWD_LOCAL:
	நிலை MUX_FWD_DYNAMIC:
		க்கு (i = 0; i < options.இலக்கம்_local_forwards; i++) {
			எனில் (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				நிறுத்து;
			}
		}
		நிறுத்து;
	நிலை MUX_FWD_REMOTE:
		க்கு (i = 0; i < options.இலக்கம்_remote_forwards; i++) {
			எனில் (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				நிறுத்து;
			}
		}
		நிறுத்து;
	}

	எனில் (found_fwd == வெற்று)
		error_reason = "port not forwarded";
	இல்லையெனில் எனில் (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		எனில் (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} இல்லையெனில் {	/* local and dynamic forwards */
		/* Ditto */
		எனில் (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	எனில் (error_reason != வெற்று)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	இல்லையெனில் {
		reply_ok(reply, rid);
		விடுவி(found_fwd->listen_host);
		விடுவி(found_fwd->listen_path);
		விடுவி(found_fwd->connect_host);
		விடுவி(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = வெற்று;
		found_fwd->listen_path = found_fwd->connect_path = வெற்று;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	விடுவி(fwd_desc);
	விடுவி(listen_addr);
	விடுவி(connect_addr);

	திரும்பு ret;
}

நிலையான முழு
mux_master_process_stdio_fwd(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	Channel *nc;
	எழுத்து *chost = வெற்று;
	u_int _cport, i, j;
	முழு ok = 0, cport, r, new_fd[2];
	கட்டமைப்பு mux_stdio_confirm_ctx *cctx;

	எனில் ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		விடுவி(chost);
		error_f("malformed message");
		திரும்பு -1;
	}
	எனில் (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	இல்லையெனில் எனில் (_cport <= INT_MAX)
		cport = (முழு)_cport;
	இல்லையெனில் {
		விடுவி(chost);
		error_f("invalid port 0x%x", _cport);
		திரும்பு -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	க்கு(i = 0; i < 2; i++) {
		எனில் ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			க்கு (j = 0; j < i; j++)
				close(new_fd[j]);
			விடுவி(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			திரும்பு -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	எனில் (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		விடுவி(chost);
		திரும்பு 0;
	}

	எனில் (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		எனில் (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} இல்லையெனில் {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		எனில் (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			செல் cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	விடுவி(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, அளவு(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	திரும்பு 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
நிலையான வெறுமை
mux_stdio_confirm(கட்டமைப்பு ssh *ssh, முழு id, முழு success, வெறுமை *arg)
{
	கட்டமைப்பு mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	கட்டமைப்பு sshbuf *reply;
	முழு r;

	எனில் (cctx == வெற்று)
		fatal_f("cctx == NULL");
	எனில் ((c = channel_by_id(ssh, id)) == வெற்று)
		fatal_f("no channel for id %d", id);
	எனில் ((cc = channel_by_id(ssh, c->ctl_chan)) == வெற்று)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	எனில் ((reply = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");

	எனில் (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		செல் done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	எனில் ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	எனில் ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	எனில் (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = வெற்று;
	விடுவி(cctx);
}

நிலையான முழு
mux_master_process_stop_listening(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	எனில் (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		எனில் (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			திரும்பு 0;
		}
	}

	எனில் (mux_listener_channel != வெற்று) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		விடுவி(options.control_path);
		options.control_path = வெற்று;
		mux_listener_channel = வெற்று;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	திரும்பு 0;
}

நிலையான முழு
mux_master_process_proxy(கட்டமைப்பு ssh *ssh, u_int rid,
    Channel *c, கட்டமைப்பு sshbuf *m, கட்டமைப்பு sshbuf *reply)
{
	முழு r;

	debug_f("channel %d: proxy request", c->self);

	எனில் (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		எனில் (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			திரும்பு 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	எனில் ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	திரும்பு 0;
}

/* Channel callbacks fired on read/write from mux client fd */
நிலையான முழு
mux_master_read_cb(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு mux_master_state *state = (கட்டமைப்பு mux_master_state *)c->mux_ctx;
	கட்டமைப்பு sshbuf *in = வெற்று, *out = வெற்று;
	u_int type, rid, i;
	முழு r, ret = -1;

	எனில் ((out = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	எனில் (c->mux_ctx == வெற்று) {
		state = xcalloc(1, அளவு(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		எனில் ((r = sshbuf_put_u32(out, MUX_செய்தி_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		எனில் ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		எனில் ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		செல் out;
	}

	/* Channel code ensures that we receive whole packets */
	எனில் ((r = sshbuf_froms(c->உள்ளீடு, &in)) != 0) {
 malf:
		error_f("malformed message");
		செல் out;
	}

	எனில் ((r = sshbuf_get_u32(in, &type)) != 0)
		செல் malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	எனில் (type == MUX_செய்தி_HELLO)
		rid = 0;
	இல்லையெனில் {
		எனில் (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_செய்தி_HELLO, type);
			செல் out;
		}
		எனில் ((r = sshbuf_get_u32(in, &rid)) != 0)
			செல் malf;
	}

	க்கு (i = 0; mux_master_handlers[i].handler != வெற்று; i++) {
		எனில் (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			நிறுத்து;
		}
	}
	எனில் (mux_master_handlers[i].handler == வெற்று) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	எனில் (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	திரும்பு ret;
}

வெறுமை
mux_exit_message(கட்டமைப்பு ssh *ssh, Channel *c, முழு exitval)
{
	கட்டமைப்பு sshbuf *m;
	Channel *mux_chan;
	முழு r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	எனில் ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == வெற்று)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

வெறுமை
mux_tty_alloc_failed(கட்டமைப்பு ssh *ssh, Channel *c)
{
	கட்டமைப்பு sshbuf *m;
	Channel *mux_chan;
	முழு r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	எனில் ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == வெற்று)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
வெறுமை
muxserver_listen(கட்டமைப்பு ssh *ssh)
{
	mode_t old_umask;
	எழுத்து *orig_control_path = options.control_path;
	எழுத்து rbuf[16+1];
	u_int i, r;
	முழு oerrno;

	எனில் (options.control_path == வெற்று ||
	    options.control_master == SSHCTL_MASTER_NO)
		திரும்பு;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	க்கு (i = 0; i < அளவு(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[அளவு(rbuf) - 1] = '\0';
	options.control_path = வெற்று;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	எனில் (muxserver_sock < 0) {
		எனில் (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			எனில் (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			விடுவி(orig_control_path);
			விடுவி(options.control_path);
			options.control_path = வெற்று;
			options.control_master = SSHCTL_MASTER_NO;
			திரும்பு;
		} இல்லையெனில் {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	எனில் (link(options.control_path, orig_control_path) != 0) {
		எனில் (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		செல் disable_mux_master;
	}
	unlink(options.control_path);
	விடுவி(options.control_path);
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
நிலையான வெறுமை
mux_session_confirm(கட்டமைப்பு ssh *ssh, முழு id, முழு success, வெறுமை *arg)
{
	கட்டமைப்பு mux_session_confirm_ctx *cctx = arg;
	மாறிலி எழுத்து *display;
	Channel *c, *cc;
	முழு i, r;
	கட்டமைப்பு sshbuf *reply;

	எனில் (cctx == வெற்று)
		fatal_f("cctx == NULL");
	எனில் ((c = channel_by_id(ssh, id)) == வெற்று)
		fatal_f("no channel for id %d", id);
	எனில் ((cc = channel_by_id(ssh, c->ctl_chan)) == வெற்று)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	எனில் ((reply = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");

	எனில் (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		செல் done;
	}

	display = getenv("DISPLAY");
	எனில் (cctx->want_x_fwd && options.forward_x11 && display != வெற்று) {
		எழுத்து *proto, *data;

		/* Get reasonable local authentication information. */
		எனில் (client_x11_get_proto(ssh, display, options.xauth_location,
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

	எனில் (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	எனில் ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	எனில் ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	எனில் (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = வெற்று;
	sshbuf_free(cctx->cmd);
	விடுவி(cctx->term);
	எனில் (cctx->env != வெற்று) {
		க்கு (i = 0; cctx->env[i] != வெற்று; i++)
			விடுவி(cctx->env[i]);
		விடுவி(cctx->env);
	}
	விடுவி(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
நிலையான வெறுமை
control_client_sighandler(முழு signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
நிலையான வெறுமை
control_client_sigrelay(முழு signo)
{
	முழு save_errno = errno;

	எனில் (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

நிலையான முழு
mux_client_read(முழு fd, கட்டமைப்பு sshbuf *b, size_t need, முழு timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	முழு r;

	எனில் ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	க்கு (have = 0; have < need; ) {
		எனில் (muxclient_terminate) {
			errno = EINTR;
			திரும்பு -1;
		}
		len = பட(fd, p + have, need - have);
		எனில் (len == -1) {
			தேர்வு (errno) {
#எனில் defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			நிலை EWOULDBLOCK:
#endif
			நிலை EAGAIN:
				எனில் (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					திரும்பு -1;	/* timeout */
				/* FALLTHROUGH */
			நிலை EINTR:
				தொடர்;
			இயல்பு:
				திரும்பு -1;
			}
		}
		எனில் (len == 0) {
			errno = EPIPE;
			திரும்பு -1;
		}
		have += (size_t)len;
	}
	திரும்பு 0;
}

நிலையான முழு
mux_client_write_packet(முழு fd, கட்டமைப்பு sshbuf *m)
{
	கட்டமைப்பு sshbuf *queue;
	u_int have, need;
	முழு r, oerrno, len;
	மாறிலி u_char *ptr;
	கட்டமைப்பு pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	எனில் ((queue = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	க்கு (have = 0; have < need; ) {
		எனில் (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			திரும்பு -1;
		}
		len = லிக(fd, ptr + have, need - have);
		எனில் (len == -1) {
			தேர்வு (errno) {
#எனில் defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			நிலை EWOULDBLOCK:
#endif
			நிலை EAGAIN:
				(வெறுமை)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			நிலை EINTR:
				தொடர்;
			இயல்பு:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				திரும்பு -1;
			}
		}
		எனில் (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			திரும்பு -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	திரும்பு 0;
}

நிலையான முழு
mux_client_read_packet_timeout(முழு fd, கட்டமைப்பு sshbuf *m, முழு timeout_ms)
{
	கட்டமைப்பு sshbuf *queue;
	size_t need, have;
	மாறிலி u_char *ptr;
	முழு r, oerrno;

	எனில் ((queue = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		எனில் ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		திரும்பு -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	எனில் (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		திரும்பு -1;
	}
	எனில் ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	திரும்பு 0;
}

நிலையான முழு
mux_client_read_packet(முழு fd, கட்டமைப்பு sshbuf *m)
{
	திரும்பு mux_client_read_packet_timeout(fd, m, -1);
}

நிலையான முழு
mux_client_hello_exchange(முழு fd, முழு timeout_ms)
{
	கட்டமைப்பு sshbuf *m;
	u_int type, ver;
	முழு r, ret = -1;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_செய்தி_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	எனில் (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		செல் out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	எனில் (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		செல் out;
	}

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	எனில் (type != MUX_செய்தி_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_செய்தி_HELLO, type);
		செல் out;
	}
	எனில் ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	எனில் (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		செல் out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	போது (sshbuf_len(m) > 0) {
		எழுத்து *name = வெற்று;

		எனில் ((r = sshbuf_get_cstring(m, &name, வெற்று)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*மதிப்பு*/
			error_fr(r, "parse extension");
			செல் out;
		}
		/* Process extensions. */
		எனில் (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} இல்லையெனில் {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		விடுவி(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	திரும்பு ret;
}

நிலையான u_int
mux_client_request_alive(முழு fd)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e;
	u_int pid, type, rid;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	எனில் (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		திரும்பு 0;
	}

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	எனில் (type != MUX_S_ALIVE) {
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	எனில் ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	எனில் ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	திரும்பு pid;
}

நிலையான எழுத்து *
mux_client_request_info(முழு fd, மாறிலி எழுத்து *name)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e, *செய்தி;
	u_int type, rid, status;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	எனில் (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		திரும்பு 0;
	}

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	எனில் (type != MUX_S_EXT_INFO) {
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	எனில் ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	எனில் ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &செய்தி, வெற்று)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	திரும்பு செய்தி;
}

நிலையான வெறுமை
mux_client_request_terminate(முழு fd)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e;
	u_int type, rid;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	எனில் (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		எனில் (errno == EPIPE) {
			sshbuf_free(m);
			திரும்பு;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	தேர்வு (type) {
	நிலை MUX_S_OK:
		நிறுத்து;
	நிலை MUX_S_PERMISSION_DENIED:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	நிலை MUX_S_FAILURE:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	இயல்பு:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

நிலையான முழு
mux_client_forward(முழு fd, முழு cancel_flag, u_int ftype, கட்டமைப்பு Forward *fwd)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e, *fwd_desc;
	மாறிலி எழுத்து *lhost, *chost;
	u_int type, rid;
	முழு r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	விடுவி(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	எனில் (fwd->listen_path != வெற்று)
		lhost = fwd->listen_path;
	இல்லையெனில் எனில் (fwd->listen_host == வெற்று)
		lhost = "";
	இல்லையெனில் எனில் (*fwd->listen_host == '\0')
		lhost = "*";
	இல்லையெனில்
		lhost = fwd->listen_host;

	எனில் (fwd->connect_path != வெற்று)
		chost = fwd->connect_path;
	இல்லையெனில் எனில் (fwd->connect_host == வெற்று)
		chost = "";
	இல்லையெனில்
		chost = fwd->connect_host;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	எனில் (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		திரும்பு -1;
	}

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	தேர்வு (type) {
	நிலை MUX_S_OK:
		நிறுத்து;
	நிலை MUX_S_REMOTE_PORT:
		எனில் (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		எனில் ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		எனில் (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		நிறுத்து;
	நிலை MUX_S_PERMISSION_DENIED:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		திரும்பு -1;
	நிலை MUX_S_FAILURE:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		திரும்பு -1;
	இயல்பு:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	திரும்பு 0;
}

நிலையான முழு
mux_client_forwards(முழு fd, முழு cancel_flag)
{
	முழு i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.இலக்கம்_local_forwards, options.இலக்கம்_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	க்கு (i = 0; i < options.இலக்கம்_local_forwards; i++) {
		எனில் (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	க்கு (i = 0; i < options.இலக்கம்_remote_forwards; i++) {
		எனில் (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	திரும்பு ret;
}

நிலையான முழு
mux_client_request_session(முழு fd)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e;
	மாறிலி எழுத்து *term = வெற்று;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	வெளி எழுத்து **environ;
	முழு r, rawmode = 0;

	debug3_f("entering");

	எனில் ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		திரும்பு -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	எனில் (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	எனில் ((term = lookup_env_in_list("TERM", options.setenv,
	    options.இலக்கம்_setenv)) == வெற்று || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	எனில் (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, வெற்று, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == வெற்று ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	எனில் (options.இலக்கம்_send_env > 0 && environ != வெற்று) {
		க்கு (i = 0; environ[i] != வெற்று; i++) {
			எனில் (!env_permitted(environ[i]))
				தொடர்;
			எனில் ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	க்கு (i = 0; i < options.இலக்கம்_setenv; i++) {
		எனில் ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	எனில் (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	எனில் (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		திரும்பு -1;
	}

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	தேர்வு (type) {
	நிலை MUX_S_SESSION_OPENED:
		எனில் ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		நிறுத்து;
	நிலை MUX_S_PERMISSION_DENIED:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		திரும்பு -1;
	நிலை MUX_S_FAILURE:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		திரும்பு -1;
	இயல்பு:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		திரும்பு -1;
	}
	muxclient_request_id++;

	எனில் (pledge("stdio proc tty", வெற்று) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	எனில் (options.fork_after_authentication)
		daemon(1, 1);
	இல்லையெனில் {
		rawmode = tty_flag;
		எனில் (tty_flag) {
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
	க்கு (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		எனில் (mux_client_read_packet(fd, m) != 0)
			நிறுத்து;
		எனில் ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		தேர்வு (type) {
		நிலை MUX_S_TTY_ALLOC_FAIL:
			எனில் ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			எனில் (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			தொடர்;
		நிலை MUX_S_EXIT_MESSAGE:
			எனில் ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			எனில் (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			எனில் (exitval_seen)
				fatal_f("exitval sent twice");
			எனில் ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			தொடர்;
		இயல்பு:
			எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	எனில் (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	எனில் (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} இல்லையெனில் எனில் (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} இல்லையெனில்
		debug2("Received exit status from master %d", exitval);

	எனில் (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

நிலையான முழு
mux_client_proxy(முழு fd)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e;
	u_int type, rid;
	முழு r;

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	எனில் (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		திரும்பு 0;
	}
	எனில் ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	எனில் (type != MUX_S_PROXY) {
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	திரும்பு 0;
}

நிலையான முழு
mux_client_request_stdio_fwd(முழு fd)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e;
	u_int type, rid, sid;
	முழு r;

	debug3_f("entering");

	எனில் ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		திரும்பு -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	எனில் (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, வெற்று, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	எனில் (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	எனில் (pledge("stdio proc tty", வெற்று) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	எனில் (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		திரும்பு -1;
	}

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	தேர்வு (type) {
	நிலை MUX_S_SESSION_OPENED:
		எனில் ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		நிறுத்து;
	நிலை MUX_S_PERMISSION_DENIED:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	நிலை MUX_S_FAILURE:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	இயல்பு:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		திரும்பு -1;
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
	எனில் (mux_client_read_packet(fd, m) != 0) {
		எனில் (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			திரும்பு 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

நிலையான வெறுமை
mux_client_request_stop_listening(முழு fd)
{
	கட்டமைப்பு sshbuf *m;
	எழுத்து *e;
	u_int type, rid;
	முழு r;

	debug3_f("entering");

	எனில் ((m = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new");
	எனில் ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	எனில் (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	எனில் (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	எனில் ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	எனில் (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	தேர்வு (type) {
	நிலை MUX_S_OK:
		நிறுத்து;
	நிலை MUX_S_PERMISSION_DENIED:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	நிலை MUX_S_FAILURE:
		எனில் ((r = sshbuf_get_cstring(m, &e, வெற்று)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	இயல்பு:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
முழு
muxclient(மாறிலி எழுத்து *path)
{
	கட்டமைப்பு sockaddr_un addr;
	முழு sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	எழுத்து *info = வெற்று;

	எனில் (muxclient_command == 0) {
		எனில் (options.stdio_forward_host != வெற்று)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		இல்லையெனில்
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	தேர்வு (options.control_master) {
	நிலை SSHCTL_MASTER_AUTO:
	நிலை SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	நிலை SSHCTL_MASTER_NO:
		நிறுத்து;
	இயல்பு:
		திரும்பு -1;
	}

	memset(&addr, '\0', அளவு(addr));
	addr.sun_family = AF_UNIX;

	எனில் (strlcpy(addr.sun_path, path,
	    அளவு(addr.sun_path)) >= அளவு(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned முழு)அளவு(addr.sun_path));

	எனில் ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	எனில் (connect(sock, (கட்டமைப்பு sockaddr *)&addr, அளவு(addr)) == -1) {
		தேர்வு (muxclient_command) {
		நிலை SSHMUX_COMMAND_OPEN:
		நிலை SSHMUX_COMMAND_STDIO_FWD:
			நிறுத்து;
		இயல்பு:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		எனில் (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} இல்லையெனில் எனில் (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} இல்லையெனில் {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		திரும்பு -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	எனில் (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	எனில் (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		திரும்பு -1;
	}

	தேர்வு (muxclient_command) {
	நிலை SSHMUX_COMMAND_ALIVE_CHECK:
		எனில் ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	நிலை SSHMUX_COMMAND_CONNINFO:
	நிலை SSHMUX_COMMAND_CHANINFO:
		எனில் (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		எனில் (info == வெற்று)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	நிலை SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		எனில் (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	நிலை SSHMUX_COMMAND_FORWARD:
		எனில் (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	நிலை SSHMUX_COMMAND_OPEN:
		எனில் (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			திரும்பு -1;
		}
		mux_client_request_session(sock);
		திரும்பு -1;
	நிலை SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	நிலை SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		எனில் (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	நிலை SSHMUX_COMMAND_CANCEL_FWD:
		எனில் (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	நிலை SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		திரும்பு (sock);
	இயல்பு:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
