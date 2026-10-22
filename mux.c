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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <poll.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "monitor_fdpass.h"
#അന്തര്ഭാവ "sshpty.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "clientloop.h"

/* from ssh.c */
ബാഹ്യ പൂർണ്ണസംഖ്യ tty_flag;
ബാഹ്യ Options options;
ബാഹ്യ അക്ഷരം *host;
ബാഹ്യ ഘടന sshbuf *command;
ബാഹ്യ അസ്ഥിര sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
ഘടന mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	ഘടന sshbuf *cmd;
	അക്ഷരം *term;
	ഘടന termios tio;
	അക്ഷരം **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
ഘടന mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
ഘടന mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	പൂർണ്ണസംഖ്യ fid;	/* forward id */
};

/* fd to control socket */
പൂർണ്ണസംഖ്യ muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
സ്ഥിതം അസ്ഥിര sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
സ്ഥിതം u_int muxserver_pid = 0;

സ്ഥിതം Channel *mux_listener_channel = ശൂന്യ;

ഘടന mux_master_state {
	പൂർണ്ണസംഖ്യ hello_rcvd;
};

/* mux protocol messages */
#define MUX_സന്ദേശം_HELLO		0x00000001
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
സ്ഥിതം u_int extensions = 0;

സ്ഥിതം ശൂന്യം mux_session_confirm(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ശൂന്യം *);
സ്ഥിതം ശൂന്യം mux_stdio_confirm(ഘടന ssh *, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ശൂന്യം *);

സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_hello(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_new_session(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_alive_check(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_terminate(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_open_fwd(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_close_fwd(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_stdio_fwd(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_stop_listening(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_proxy(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_process_ext_info(ഘടന ssh *, u_int,
	    Channel *, ഘടന sshbuf *, ഘടന sshbuf *);

സ്ഥിതം സ്ഥിരം ഘടന {
	u_int type;
	പൂർണ്ണസംഖ്യ (*handler)(ഘടന ssh *, u_int, Channel *,
	    ഘടന sshbuf *, ഘടന sshbuf *);
} mux_master_handlers[] = {
	{ MUX_സന്ദേശം_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, ശൂന്യ }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
സ്ഥിതം ശൂന്യം
mux_master_session_cleanup_cb(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ cid, പൂർണ്ണസംഖ്യ force, ശൂന്യം *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	എങ്കിൽ (c == ശൂന്യ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	എങ്കിൽ (c->ctl_chan != -1) {
		എങ്കിൽ ((cc = channel_by_id(ssh, c->ctl_chan)) == ശൂന്യ)
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
സ്ഥിതം ശൂന്യം
mux_master_control_cleanup_cb(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ cid, പൂർണ്ണസംഖ്യ force, ശൂന്യം *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	എങ്കിൽ (c == ശൂന്യ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	എങ്കിൽ (c->have_ctl_child_id) {
		എങ്കിൽ ((sc = channel_by_id(ssh, c->ctl_child_id)) == ശൂന്യ)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		എങ്കിൽ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (sc->istate == CHAN_നിവേശം_OPEN)
				chan_read_failed(ssh, sc);
			എങ്കിൽ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
സ്ഥിതം പൂർണ്ണസംഖ്യ
env_permitted(സ്ഥിരം അക്ഷരം *env)
{
	u_int i;
	പൂർണ്ണസംഖ്യ ret;
	അക്ഷരം name[1024], *cp;

	എങ്കിൽ ((cp = strchr(env, '=')) == ശൂന്യ || cp == env)
		തിരികെ 0;
	ret = snprintf(name, വലുപ്പം(name), "%.*s", (പൂർണ്ണസംഖ്യ)(cp - env), env);
	എങ്കിൽ (ret <= 0 || (size_t)ret >= വലുപ്പം(name)) {
		error_f("name '%.100s...' too long", env);
		തിരികെ 0;
	}

	വേണ്ടി (i = 0; i < options.അക്കം_send_env; i++)
		എങ്കിൽ (match_pattern(name, options.send_env[i]))
			തിരികെ 1;

	തിരികെ 0;
}

/* Mux master protocol message handlers */

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_hello(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	u_int ver;
	ഘടന mux_master_state *state = (ഘടന mux_master_state *)c->mux_ctx;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (state == ശൂന്യ)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	എങ്കിൽ (state->hello_rcvd) {
		error_f("HELLO received twice");
		തിരികെ -1;
	}
	എങ്കിൽ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		തിരികെ -1;
	}
	എങ്കിൽ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		തിരികെ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ആകുമ്പോൾ (sshbuf_len(m) > 0) {
		അക്ഷരം *name = ശൂന്യ;
		size_t മൂല്യം_len = 0;

		എങ്കിൽ ((r = sshbuf_get_cstring(m, &name, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_string_direct(m, ശൂന്യ, &മൂല്യം_len)) != 0) {
			error_fr(r, "parse extension");
			തിരികെ -1;
		}
		എങ്കിൽ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} അല്ലെങ്കിൽ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, മൂല്യം_len);
		}
		സ്വതന്ത്രം(name);
	}
	state->hello_rcvd = 1;
	തിരികെ 0;
}

/* Enqueue a "ok" response to the reply buffer */
സ്ഥിതം ശൂന്യം
reply_ok(ഘടന sshbuf *reply, u_int rid)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
സ്ഥിതം ശൂന്യം
reply_error(ഘടന sshbuf *reply, u_int type, u_int rid, സ്ഥിരം അക്ഷരം *സന്ദേശം)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, സന്ദേശം)) != 0)
		fatal_fr(r, "reply");
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_new_session(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	Channel *nc;
	ഘടന mux_session_confirm_ctx *cctx;
	അക്ഷരം *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	പൂർണ്ണസംഖ്യ r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, വലുപ്പം(*cctx));
	cctx->term = ശൂന്യ;
	cctx->rid = rid;
	cmd = ശൂന്യ;
	cctx->env = ശൂന്യ;
	env_len = 0;
	എങ്കിൽ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, ശൂന്യ)) != 0) {
 malf:
		സ്വതന്ത്രം(cmd);
		വേണ്ടി (j = 0; j < env_len; j++)
			സ്വതന്ത്രം(cctx->env[j]);
		സ്വതന്ത്രം(cctx->env);
		സ്വതന്ത്രം(cctx->term);
		സ്വതന്ത്രം(cctx);
		error_f("malformed message");
		തിരികെ -1;
	}

#define MUX_MAX_ENV_VARS	4096
	ആകുമ്പോൾ (sshbuf_len(m) > 0) {
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &cp, ശൂന്യ)) != 0)
			പോകുക malf;
		എങ്കിൽ (!env_permitted(cp)) {
			സ്വതന്ത്രം(cp);
			തുടരുക;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    വലുപ്പം(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = ശൂന്യ;
		എങ്കിൽ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			നിർത്തുക;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	എങ്കിൽ ((cctx->cmd = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	സ്വതന്ത്രം(cmd);
	cmd = ശൂന്യ;

	/* Gather fds from client */
	വേണ്ടി(i = 0; i < 3; i++) {
		എങ്കിൽ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			വേണ്ടി (j = 0; j < i; j++)
				close(new_fd[j]);
			വേണ്ടി (j = 0; j < env_len; j++)
				സ്വതന്ത്രം(cctx->env[j]);
			സ്വതന്ത്രം(cctx->env);
			സ്വതന്ത്രം(cctx->term);
			sshbuf_free(cctx->cmd);
			സ്വതന്ത്രം(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			തിരികെ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	എങ്കിൽ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		സ്വതന്ത്രം(cctx->term);
		എങ്കിൽ (env_len != 0) {
			വേണ്ടി (i = 0; i < env_len; i++)
				സ്വതന്ത്രം(cctx->env[i]);
			സ്വതന്ത്രം(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		സ്വതന്ത്രം(cctx);
		തിരികെ 0;
	}

	എങ്കിൽ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		എങ്കിൽ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			പോകുക cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	എങ്കിൽ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	എങ്കിൽ (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	എങ്കിൽ (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	എങ്കിൽ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, ശൂന്യ,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((പൂർണ്ണസംഖ്യ)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_alive_check(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	പൂർണ്ണസംഖ്യ r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	എങ്കിൽ ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	തിരികെ 0;
}

/* The "info" extension. */
സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_ext_info(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	പൂർണ്ണസംഖ്യ r;
	u_int status = 0;
	അക്ഷരം *name = ശൂന്യ, *സന്ദേശം = ശൂന്യ;

	debug2_f("channel %d: info request", c->self);

	എങ്കിൽ ((r = sshbuf_get_cstring(m, &name, ശൂന്യ)) != 0)
		fatal_fr(r, "parse");

	എങ്കിൽ (strcmp(name, "connection") == 0) {
		എങ്കിൽ ((സന്ദേശം = connection_info_message(ssh)) == ശൂന്യ)
			fatal_f("connection_info_message");
		status = 1;
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(name, "channels") == 0) {
		എങ്കിൽ ((സന്ദേശം = channel_open_message(ssh)) == ശൂന്യ)
			fatal_f("channel_open_message");
		status = 1;
	} അല്ലെങ്കിൽ {
		സന്ദേശം = xstrdup("info request type not supported");
	}

	/* prepare reply */
	എങ്കിൽ ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, സന്ദേശം)) != 0)
		fatal_fr(r, "reply");
	സ്വതന്ത്രം(സന്ദേശം);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_terminate(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	എങ്കിൽ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		എങ്കിൽ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			തിരികെ 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	തിരികെ 0;
}

സ്ഥിതം അക്ഷരം *
format_forward(u_int ftype, ഘടന Forward *fwd)
{
	അക്ഷരം *ret;

	തിരഞ്ഞെടുപ്പ് (ftype) {
	അവസ്ഥ MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ശൂന്യ) ? fwd->listen_path :
		    (fwd->listen_host == ശൂന്യ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != ശൂന്യ) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		നിർത്തുക;
	അവസ്ഥ MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == ശൂന്യ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		നിർത്തുക;
	അവസ്ഥ MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ശൂന്യ) ? fwd->listen_path :
		    (fwd->listen_host == ശൂന്യ) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != ശൂന്യ) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		fatal_f("unknown forward type %u", ftype);
	}
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
compare_host(സ്ഥിരം അക്ഷരം *a, സ്ഥിരം അക്ഷരം *b)
{
	എങ്കിൽ (a == ശൂന്യ && b == ശൂന്യ)
		തിരികെ 1;
	എങ്കിൽ (a == ശൂന്യ || b == ശൂന്യ)
		തിരികെ 0;
	തിരികെ strcmp(a, b) == 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
compare_forward(ഘടന Forward *a, ഘടന Forward *b)
{
	എങ്കിൽ (!compare_host(a->listen_host, b->listen_host))
		തിരികെ 0;
	എങ്കിൽ (!compare_host(a->listen_path, b->listen_path))
		തിരികെ 0;
	എങ്കിൽ (a->listen_port != b->listen_port)
		തിരികെ 0;
	എങ്കിൽ (!compare_host(a->connect_host, b->connect_host))
		തിരികെ 0;
	എങ്കിൽ (!compare_host(a->connect_path, b->connect_path))
		തിരികെ 0;
	എങ്കിൽ (a->connect_port != b->connect_port)
		തിരികെ 0;

	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
mux_confirm_remote_forward(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type, uint32_t seq, ശൂന്യം *ctxt)
{
	ഘടന mux_channel_confirm_ctx *fctx = ctxt;
	അക്ഷരം *failmsg = ശൂന്യ;
	ഘടന Forward *rfwd;
	Channel *c;
	ഘടന sshbuf *out;
	u_int port;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((c = channel_by_id(ssh, fctx->cid)) == ശൂന്യ) {
		/* no channel for reply */
		error_f("unknown channel");
		തിരികെ;
	}
	എങ്കിൽ ((out = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ (fctx->fid >= options.അക്കം_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == ശൂന്യ &&
	    options.remote_forwards[fctx->fid].connect_host == ശൂന്യ)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		പോകുക fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_സന്ദേശം_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	എങ്കിൽ (type == SSH2_സന്ദേശം_REQUEST_SUCCESS) {
		എങ്കിൽ (rfwd->listen_port == 0) {
			എങ്കിൽ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			എങ്കിൽ (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (പൂർണ്ണസംഖ്യ)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			എങ്കിൽ ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} അല്ലെങ്കിൽ {
			reply_ok(out, fctx->rid);
		}
		പോകുക out;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		എങ്കിൽ (rfwd->listen_path != ശൂന്യ)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		അല്ലെങ്കിൽ
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		സ്വതന്ത്രം(rfwd->listen_host);
		സ്വതന്ത്രം(rfwd->listen_path);
		സ്വതന്ത്രം(rfwd->connect_host);
		സ്വതന്ത്രം(rfwd->connect_path);
		memset(rfwd, 0, വലുപ്പം(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	സ്വതന്ത്രം(failmsg);
 out:
	എങ്കിൽ ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	എങ്കിൽ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	സ്വതന്ത്രം(fctx);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_open_fwd(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	ഘടന Forward fwd;
	അക്ഷരം *fwd_desc = ശൂന്യ;
	അക്ഷരം *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	പൂർണ്ണസംഖ്യ r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, വലുപ്പം(fwd));

	/* XXX - lport/cport check redundant */
	എങ്കിൽ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		പോകുക out;
	}
	എങ്കിൽ (*listen_addr == '\0') {
		സ്വതന്ത്രം(listen_addr);
		listen_addr = ശൂന്യ;
	}
	എങ്കിൽ (*connect_addr == '\0') {
		സ്വതന്ത്രം(connect_addr);
		connect_addr = ശൂന്യ;
	}

	memset(&fwd, 0, വലുപ്പം(fwd));
	fwd.listen_port = lport;
	എങ്കിൽ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	അല്ലെങ്കിൽ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	എങ്കിൽ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	അല്ലെങ്കിൽ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	എങ്കിൽ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		സ്വതന്ത്രം(listen_addr);
		സ്വതന്ത്രം(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		തിരികെ 0;
	}
	എങ്കിൽ (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		പോകുക invalid;
	}
	എങ്കിൽ (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		പോകുക invalid;
	}
	എങ്കിൽ ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		പോകുക invalid;
	}
	എങ്കിൽ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == ശൂന്യ &&
	    fwd.connect_path == ശൂന്യ) {
		logit_f("missing connect host");
		പോകുക invalid;
	}

	/* Skip forwards that have already been requested */
	തിരഞ്ഞെടുപ്പ് (ftype) {
	അവസ്ഥ MUX_FWD_LOCAL:
	അവസ്ഥ MUX_FWD_DYNAMIC:
		വേണ്ടി (i = 0; i < options.അക്കം_local_forwards; i++) {
			എങ്കിൽ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				പോകുക out;
			}
		}
		നിർത്തുക;
	അവസ്ഥ MUX_FWD_REMOTE:
		വേണ്ടി (i = 0; i < options.അക്കം_remote_forwards; i++) {
			എങ്കിൽ (!compare_forward(&fwd, options.remote_forwards + i))
				തുടരുക;
			എങ്കിൽ (fwd.listen_port != 0)
				പോകുക exists;
			debug2_f("found allocated port");
			എങ്കിൽ ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			പോകുക out;
		}
		നിർത്തുക;
	}

	എങ്കിൽ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		എങ്കിൽ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			പോകുക out;
		}
	}

	എങ്കിൽ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		എങ്കിൽ (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			പോകുക out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} അല്ലെങ്കിൽ {
		ഘടന mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		എങ്കിൽ (fwd.handle < 0)
			പോകുക fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, വലുപ്പം(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.അക്കം_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		പോകുക out;
	}
	reply_ok(reply, rid);
 out:
	സ്വതന്ത്രം(fwd_desc);
	എങ്കിൽ (freefwd) {
		സ്വതന്ത്രം(fwd.listen_host);
		സ്വതന്ത്രം(fwd.listen_path);
		സ്വതന്ത്രം(fwd.connect_host);
		സ്വതന്ത്രം(fwd.connect_path);
	}
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_close_fwd(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	ഘടന Forward fwd, *found_fwd;
	അക്ഷരം *fwd_desc = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *error_reason = ശൂന്യ;
	അക്ഷരം *listen_addr = ശൂന്യ, *connect_addr = ശൂന്യ;
	u_int ftype;
	പൂർണ്ണസംഖ്യ r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, വലുപ്പം(fwd));

	എങ്കിൽ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		പോകുക out;
	}

	എങ്കിൽ (*listen_addr == '\0') {
		സ്വതന്ത്രം(listen_addr);
		listen_addr = ശൂന്യ;
	}
	എങ്കിൽ (*connect_addr == '\0') {
		സ്വതന്ത്രം(connect_addr);
		connect_addr = ശൂന്യ;
	}

	memset(&fwd, 0, വലുപ്പം(fwd));
	fwd.listen_port = lport;
	എങ്കിൽ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	അല്ലെങ്കിൽ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	എങ്കിൽ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	അല്ലെങ്കിൽ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = ശൂന്യ;
	തിരഞ്ഞെടുപ്പ് (ftype) {
	അവസ്ഥ MUX_FWD_LOCAL:
	അവസ്ഥ MUX_FWD_DYNAMIC:
		വേണ്ടി (i = 0; i < options.അക്കം_local_forwards; i++) {
			എങ്കിൽ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				നിർത്തുക;
			}
		}
		നിർത്തുക;
	അവസ്ഥ MUX_FWD_REMOTE:
		വേണ്ടി (i = 0; i < options.അക്കം_remote_forwards; i++) {
			എങ്കിൽ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				നിർത്തുക;
			}
		}
		നിർത്തുക;
	}

	എങ്കിൽ (found_fwd == ശൂന്യ)
		error_reason = "port not forwarded";
	അല്ലെങ്കിൽ എങ്കിൽ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		എങ്കിൽ (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} അല്ലെങ്കിൽ {	/* local and dynamic forwards */
		/* Ditto */
		എങ്കിൽ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	എങ്കിൽ (error_reason != ശൂന്യ)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	അല്ലെങ്കിൽ {
		reply_ok(reply, rid);
		സ്വതന്ത്രം(found_fwd->listen_host);
		സ്വതന്ത്രം(found_fwd->listen_path);
		സ്വതന്ത്രം(found_fwd->connect_host);
		സ്വതന്ത്രം(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = ശൂന്യ;
		found_fwd->listen_path = found_fwd->connect_path = ശൂന്യ;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	സ്വതന്ത്രം(fwd_desc);
	സ്വതന്ത്രം(listen_addr);
	സ്വതന്ത്രം(connect_addr);

	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_stdio_fwd(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	Channel *nc;
	അക്ഷരം *chost = ശൂന്യ;
	u_int _cport, i, j;
	പൂർണ്ണസംഖ്യ ok = 0, cport, r, new_fd[2];
	ഘടന mux_stdio_confirm_ctx *cctx;

	എങ്കിൽ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		സ്വതന്ത്രം(chost);
		error_f("malformed message");
		തിരികെ -1;
	}
	എങ്കിൽ (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	അല്ലെങ്കിൽ എങ്കിൽ (_cport <= INT_MAX)
		cport = (പൂർണ്ണസംഖ്യ)_cport;
	അല്ലെങ്കിൽ {
		സ്വതന്ത്രം(chost);
		error_f("invalid port 0x%x", _cport);
		തിരികെ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	വേണ്ടി(i = 0; i < 2; i++) {
		എങ്കിൽ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			വേണ്ടി (j = 0; j < i; j++)
				close(new_fd[j]);
			സ്വതന്ത്രം(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			തിരികെ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	എങ്കിൽ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		സ്വതന്ത്രം(chost);
		തിരികെ 0;
	}

	എങ്കിൽ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		എങ്കിൽ (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} അല്ലെങ്കിൽ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		എങ്കിൽ (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			പോകുക cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	സ്വതന്ത്രം(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, വലുപ്പം(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	തിരികെ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
സ്ഥിതം ശൂന്യം
mux_stdio_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ success, ശൂന്യം *arg)
{
	ഘടന mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	ഘടന sshbuf *reply;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (cctx == ശൂന്യ)
		fatal_f("cctx == NULL");
	എങ്കിൽ ((c = channel_by_id(ssh, id)) == ശൂന്യ)
		fatal_f("no channel for id %d", id);
	എങ്കിൽ ((cc = channel_by_id(ssh, c->ctl_chan)) == ശൂന്യ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	എങ്കിൽ ((reply = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");

	എങ്കിൽ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		പോകുക done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	എങ്കിൽ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	എങ്കിൽ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	എങ്കിൽ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ശൂന്യ;
	സ്വതന്ത്രം(cctx);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_stop_listening(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	എങ്കിൽ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		എങ്കിൽ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			തിരികെ 0;
		}
	}

	എങ്കിൽ (mux_listener_channel != ശൂന്യ) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		സ്വതന്ത്രം(options.control_path);
		options.control_path = ശൂന്യ;
		mux_listener_channel = ശൂന്യ;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_process_proxy(ഘടന ssh *ssh, u_int rid,
    Channel *c, ഘടന sshbuf *m, ഘടന sshbuf *reply)
{
	പൂർണ്ണസംഖ്യ r;

	debug_f("channel %d: proxy request", c->self);

	എങ്കിൽ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		എങ്കിൽ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			തിരികെ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	എങ്കിൽ ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	തിരികെ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_master_read_cb(ഘടന ssh *ssh, Channel *c)
{
	ഘടന mux_master_state *state = (ഘടന mux_master_state *)c->mux_ctx;
	ഘടന sshbuf *in = ശൂന്യ, *out = ശൂന്യ;
	u_int type, rid, i;
	പൂർണ്ണസംഖ്യ r, ret = -1;

	എങ്കിൽ ((out = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	എങ്കിൽ (c->mux_ctx == ശൂന്യ) {
		state = xcalloc(1, വലുപ്പം(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		എങ്കിൽ ((r = sshbuf_put_u32(out, MUX_സന്ദേശം_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		എങ്കിൽ ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		എങ്കിൽ ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		പോകുക out;
	}

	/* Channel code ensures that we receive whole packets */
	എങ്കിൽ ((r = sshbuf_froms(c->നിവേശം, &in)) != 0) {
 malf:
		error_f("malformed message");
		പോകുക out;
	}

	എങ്കിൽ ((r = sshbuf_get_u32(in, &type)) != 0)
		പോകുക malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	എങ്കിൽ (type == MUX_സന്ദേശം_HELLO)
		rid = 0;
	അല്ലെങ്കിൽ {
		എങ്കിൽ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_സന്ദേശം_HELLO, type);
			പോകുക out;
		}
		എങ്കിൽ ((r = sshbuf_get_u32(in, &rid)) != 0)
			പോകുക malf;
	}

	വേണ്ടി (i = 0; mux_master_handlers[i].handler != ശൂന്യ; i++) {
		എങ്കിൽ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			നിർത്തുക;
		}
	}
	എങ്കിൽ (mux_master_handlers[i].handler == ശൂന്യ) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	എങ്കിൽ (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	തിരികെ ret;
}

ശൂന്യം
mux_exit_message(ഘടന ssh *ssh, Channel *c, പൂർണ്ണസംഖ്യ exitval)
{
	ഘടന sshbuf *m;
	Channel *mux_chan;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	എങ്കിൽ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ശൂന്യ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

ശൂന്യം
mux_tty_alloc_failed(ഘടന ssh *ssh, Channel *c)
{
	ഘടന sshbuf *m;
	Channel *mux_chan;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	എങ്കിൽ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ശൂന്യ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
ശൂന്യം
muxserver_listen(ഘടന ssh *ssh)
{
	mode_t old_umask;
	അക്ഷരം *orig_control_path = options.control_path;
	അക്ഷരം rbuf[16+1];
	u_int i, r;
	പൂർണ്ണസംഖ്യ oerrno;

	എങ്കിൽ (options.control_path == ശൂന്യ ||
	    options.control_master == SSHCTL_MASTER_NO)
		തിരികെ;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	വേണ്ടി (i = 0; i < വലുപ്പം(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[വലുപ്പം(rbuf) - 1] = '\0';
	options.control_path = ശൂന്യ;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	എങ്കിൽ (muxserver_sock < 0) {
		എങ്കിൽ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			എങ്കിൽ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			സ്വതന്ത്രം(orig_control_path);
			സ്വതന്ത്രം(options.control_path);
			options.control_path = ശൂന്യ;
			options.control_master = SSHCTL_MASTER_NO;
			തിരികെ;
		} അല്ലെങ്കിൽ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	എങ്കിൽ (link(options.control_path, orig_control_path) != 0) {
		എങ്കിൽ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		പോകുക disable_mux_master;
	}
	unlink(options.control_path);
	സ്വതന്ത്രം(options.control_path);
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
സ്ഥിതം ശൂന്യം
mux_session_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ success, ശൂന്യം *arg)
{
	ഘടന mux_session_confirm_ctx *cctx = arg;
	സ്ഥിരം അക്ഷരം *display;
	Channel *c, *cc;
	പൂർണ്ണസംഖ്യ i, r;
	ഘടന sshbuf *reply;

	എങ്കിൽ (cctx == ശൂന്യ)
		fatal_f("cctx == NULL");
	എങ്കിൽ ((c = channel_by_id(ssh, id)) == ശൂന്യ)
		fatal_f("no channel for id %d", id);
	എങ്കിൽ ((cc = channel_by_id(ssh, c->ctl_chan)) == ശൂന്യ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	എങ്കിൽ ((reply = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");

	എങ്കിൽ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		പോകുക done;
	}

	display = getenv("DISPLAY");
	എങ്കിൽ (cctx->want_x_fwd && options.forward_x11 && display != ശൂന്യ) {
		അക്ഷരം *proto, *data;

		/* Get reasonable local authentication information. */
		എങ്കിൽ (client_x11_get_proto(ssh, display, options.xauth_location,
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

	എങ്കിൽ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	എങ്കിൽ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	എങ്കിൽ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	എങ്കിൽ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ശൂന്യ;
	sshbuf_free(cctx->cmd);
	സ്വതന്ത്രം(cctx->term);
	എങ്കിൽ (cctx->env != ശൂന്യ) {
		വേണ്ടി (i = 0; cctx->env[i] != ശൂന്യ; i++)
			സ്വതന്ത്രം(cctx->env[i]);
		സ്വതന്ത്രം(cctx->env);
	}
	സ്വതന്ത്രം(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
സ്ഥിതം ശൂന്യം
control_client_sighandler(പൂർണ്ണസംഖ്യ signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
സ്ഥിതം ശൂന്യം
control_client_sigrelay(പൂർണ്ണസംഖ്യ signo)
{
	പൂർണ്ണസംഖ്യ save_errno = errno;

	എങ്കിൽ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_read(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *b, size_t need, പൂർണ്ണസംഖ്യ timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	വേണ്ടി (have = 0; have < need; ) {
		എങ്കിൽ (muxclient_terminate) {
			errno = EINTR;
			തിരികെ -1;
		}
		len = പഠ(fd, p + have, need - have);
		എങ്കിൽ (len == -1) {
			തിരഞ്ഞെടുപ്പ് (errno) {
#എങ്കിൽ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			അവസ്ഥ EWOULDBLOCK:
#endif
			അവസ്ഥ EAGAIN:
				എങ്കിൽ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					തിരികെ -1;	/* timeout */
				/* FALLTHROUGH */
			അവസ്ഥ EINTR:
				തുടരുക;
			സ്ഥിരസ്ഥിതി:
				തിരികെ -1;
			}
		}
		എങ്കിൽ (len == 0) {
			errno = EPIPE;
			തിരികെ -1;
		}
		have += (size_t)len;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_write_packet(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *m)
{
	ഘടന sshbuf *queue;
	u_int have, need;
	പൂർണ്ണസംഖ്യ r, oerrno, len;
	സ്ഥിരം u_char *ptr;
	ഘടന pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	എങ്കിൽ ((queue = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	വേണ്ടി (have = 0; have < need; ) {
		എങ്കിൽ (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			തിരികെ -1;
		}
		len = ലിഖ(fd, ptr + have, need - have);
		എങ്കിൽ (len == -1) {
			തിരഞ്ഞെടുപ്പ് (errno) {
#എങ്കിൽ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			അവസ്ഥ EWOULDBLOCK:
#endif
			അവസ്ഥ EAGAIN:
				(ശൂന്യം)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			അവസ്ഥ EINTR:
				തുടരുക;
			സ്ഥിരസ്ഥിതി:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				തിരികെ -1;
			}
		}
		എങ്കിൽ (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			തിരികെ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_read_packet_timeout(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *m, പൂർണ്ണസംഖ്യ timeout_ms)
{
	ഘടന sshbuf *queue;
	size_t need, have;
	സ്ഥിരം u_char *ptr;
	പൂർണ്ണസംഖ്യ r, oerrno;

	എങ്കിൽ ((queue = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		എങ്കിൽ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		തിരികെ -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	എങ്കിൽ (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		തിരികെ -1;
	}
	എങ്കിൽ ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_read_packet(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *m)
{
	തിരികെ mux_client_read_packet_timeout(fd, m, -1);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_hello_exchange(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ timeout_ms)
{
	ഘടന sshbuf *m;
	u_int type, ver;
	പൂർണ്ണസംഖ്യ r, ret = -1;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_സന്ദേശം_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		പോകുക out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	എങ്കിൽ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		പോകുക out;
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	എങ്കിൽ (type != MUX_സന്ദേശം_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_സന്ദേശം_HELLO, type);
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	എങ്കിൽ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		പോകുക out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ആകുമ്പോൾ (sshbuf_len(m) > 0) {
		അക്ഷരം *name = ശൂന്യ;

		എങ്കിൽ ((r = sshbuf_get_cstring(m, &name, ശൂന്യ)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*മൂല്യം*/
			error_fr(r, "parse extension");
			പോകുക out;
		}
		/* Process extensions. */
		എങ്കിൽ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} അല്ലെങ്കിൽ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		സ്വതന്ത്രം(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	തിരികെ ret;
}

സ്ഥിതം u_int
mux_client_request_alive(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e;
	u_int pid, type, rid;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		തിരികെ 0;
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	എങ്കിൽ (type != MUX_S_ALIVE) {
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	എങ്കിൽ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	തിരികെ pid;
}

സ്ഥിതം അക്ഷരം *
mux_client_request_info(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *name)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e, *സന്ദേശം;
	u_int type, rid, status;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		തിരികെ 0;
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	എങ്കിൽ (type != MUX_S_EXT_INFO) {
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	എങ്കിൽ ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &സന്ദേശം, ശൂന്യ)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	തിരികെ സന്ദേശം;
}

സ്ഥിതം ശൂന്യം
mux_client_request_terminate(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e;
	u_int type, rid;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		എങ്കിൽ (errno == EPIPE) {
			sshbuf_free(m);
			തിരികെ;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ MUX_S_OK:
		നിർത്തുക;
	അവസ്ഥ MUX_S_PERMISSION_DENIED:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	അവസ്ഥ MUX_S_FAILURE:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	സ്ഥിരസ്ഥിതി:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_forward(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ cancel_flag, u_int ftype, ഘടന Forward *fwd)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e, *fwd_desc;
	സ്ഥിരം അക്ഷരം *lhost, *chost;
	u_int type, rid;
	പൂർണ്ണസംഖ്യ r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	സ്വതന്ത്രം(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	എങ്കിൽ (fwd->listen_path != ശൂന്യ)
		lhost = fwd->listen_path;
	അല്ലെങ്കിൽ എങ്കിൽ (fwd->listen_host == ശൂന്യ)
		lhost = "";
	അല്ലെങ്കിൽ എങ്കിൽ (*fwd->listen_host == '\0')
		lhost = "*";
	അല്ലെങ്കിൽ
		lhost = fwd->listen_host;

	എങ്കിൽ (fwd->connect_path != ശൂന്യ)
		chost = fwd->connect_path;
	അല്ലെങ്കിൽ എങ്കിൽ (fwd->connect_host == ശൂന്യ)
		chost = "";
	അല്ലെങ്കിൽ
		chost = fwd->connect_host;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		തിരികെ -1;
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ MUX_S_OK:
		നിർത്തുക;
	അവസ്ഥ MUX_S_REMOTE_PORT:
		എങ്കിൽ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		എങ്കിൽ ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		എങ്കിൽ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		നിർത്തുക;
	അവസ്ഥ MUX_S_PERMISSION_DENIED:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		തിരികെ -1;
	അവസ്ഥ MUX_S_FAILURE:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		തിരികെ -1;
	സ്ഥിരസ്ഥിതി:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_forwards(പൂർണ്ണസംഖ്യ fd, പൂർണ്ണസംഖ്യ cancel_flag)
{
	പൂർണ്ണസംഖ്യ i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.അക്കം_local_forwards, options.അക്കം_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	വേണ്ടി (i = 0; i < options.അക്കം_local_forwards; i++) {
		എങ്കിൽ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	വേണ്ടി (i = 0; i < options.അക്കം_remote_forwards; i++) {
		എങ്കിൽ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_request_session(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e;
	സ്ഥിരം അക്ഷരം *term = ശൂന്യ;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	ബാഹ്യ അക്ഷരം **environ;
	പൂർണ്ണസംഖ്യ r, rawmode = 0;

	debug3_f("entering");

	എങ്കിൽ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		തിരികെ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	എങ്കിൽ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	എങ്കിൽ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.അക്കം_setenv)) == ശൂന്യ || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	എങ്കിൽ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ശൂന്യ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == ശൂന്യ ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	എങ്കിൽ (options.അക്കം_send_env > 0 && environ != ശൂന്യ) {
		വേണ്ടി (i = 0; environ[i] != ശൂന്യ; i++) {
			എങ്കിൽ (!env_permitted(environ[i]))
				തുടരുക;
			എങ്കിൽ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	വേണ്ടി (i = 0; i < options.അക്കം_setenv; i++) {
		എങ്കിൽ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	എങ്കിൽ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		തിരികെ -1;
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ MUX_S_SESSION_OPENED:
		എങ്കിൽ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		നിർത്തുക;
	അവസ്ഥ MUX_S_PERMISSION_DENIED:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		തിരികെ -1;
	അവസ്ഥ MUX_S_FAILURE:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		തിരികെ -1;
	സ്ഥിരസ്ഥിതി:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		തിരികെ -1;
	}
	muxclient_request_id++;

	എങ്കിൽ (pledge("stdio proc tty", ശൂന്യ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	എങ്കിൽ (options.fork_after_authentication)
		daemon(1, 1);
	അല്ലെങ്കിൽ {
		rawmode = tty_flag;
		എങ്കിൽ (tty_flag) {
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
	വേണ്ടി (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		എങ്കിൽ (mux_client_read_packet(fd, m) != 0)
			നിർത്തുക;
		എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ MUX_S_TTY_ALLOC_FAIL:
			എങ്കിൽ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			എങ്കിൽ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			തുടരുക;
		അവസ്ഥ MUX_S_EXIT_MESSAGE:
			എങ്കിൽ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			എങ്കിൽ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			എങ്കിൽ (exitval_seen)
				fatal_f("exitval sent twice");
			എങ്കിൽ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			തുടരുക;
		സ്ഥിരസ്ഥിതി:
			എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	എങ്കിൽ (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	എങ്കിൽ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} അല്ലെങ്കിൽ എങ്കിൽ (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} അല്ലെങ്കിൽ
		debug2("Received exit status from master %d", exitval);

	എങ്കിൽ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_proxy(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e;
	u_int type, rid;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		തിരികെ 0;
	}
	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	എങ്കിൽ (type != MUX_S_PROXY) {
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mux_client_request_stdio_fwd(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e;
	u_int type, rid, sid;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		തിരികെ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	എങ്കിൽ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ശൂന്യ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	എങ്കിൽ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	എങ്കിൽ (pledge("stdio proc tty", ശൂന്യ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		തിരികെ -1;
	}

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ MUX_S_SESSION_OPENED:
		എങ്കിൽ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		നിർത്തുക;
	അവസ്ഥ MUX_S_PERMISSION_DENIED:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	അവസ്ഥ MUX_S_FAILURE:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	സ്ഥിരസ്ഥിതി:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		തിരികെ -1;
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
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0) {
		എങ്കിൽ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			തിരികെ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

സ്ഥിതം ശൂന്യം
mux_client_request_stop_listening(പൂർണ്ണസംഖ്യ fd)
{
	ഘടന sshbuf *m;
	അക്ഷരം *e;
	u_int type, rid;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new");
	എങ്കിൽ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	എങ്കിൽ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	എങ്കിൽ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	എങ്കിൽ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	എങ്കിൽ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ MUX_S_OK:
		നിർത്തുക;
	അവസ്ഥ MUX_S_PERMISSION_DENIED:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	അവസ്ഥ MUX_S_FAILURE:
		എങ്കിൽ ((r = sshbuf_get_cstring(m, &e, ശൂന്യ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	സ്ഥിരസ്ഥിതി:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
പൂർണ്ണസംഖ്യ
muxclient(സ്ഥിരം അക്ഷരം *path)
{
	ഘടന sockaddr_un addr;
	പൂർണ്ണസംഖ്യ sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	അക്ഷരം *info = ശൂന്യ;

	എങ്കിൽ (muxclient_command == 0) {
		എങ്കിൽ (options.stdio_forward_host != ശൂന്യ)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		അല്ലെങ്കിൽ
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	തിരഞ്ഞെടുപ്പ് (options.control_master) {
	അവസ്ഥ SSHCTL_MASTER_AUTO:
	അവസ്ഥ SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	അവസ്ഥ SSHCTL_MASTER_NO:
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}

	memset(&addr, '\0', വലുപ്പം(addr));
	addr.sun_family = AF_UNIX;

	എങ്കിൽ (strlcpy(addr.sun_path, path,
	    വലുപ്പം(addr.sun_path)) >= വലുപ്പം(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned പൂർണ്ണസംഖ്യ)വലുപ്പം(addr.sun_path));

	എങ്കിൽ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	എങ്കിൽ (connect(sock, (ഘടന sockaddr *)&addr, വലുപ്പം(addr)) == -1) {
		തിരഞ്ഞെടുപ്പ് (muxclient_command) {
		അവസ്ഥ SSHMUX_COMMAND_OPEN:
		അവസ്ഥ SSHMUX_COMMAND_STDIO_FWD:
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		എങ്കിൽ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} അല്ലെങ്കിൽ എങ്കിൽ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} അല്ലെങ്കിൽ {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		തിരികെ -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	എങ്കിൽ (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	എങ്കിൽ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		തിരികെ -1;
	}

	തിരഞ്ഞെടുപ്പ് (muxclient_command) {
	അവസ്ഥ SSHMUX_COMMAND_ALIVE_CHECK:
		എങ്കിൽ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	അവസ്ഥ SSHMUX_COMMAND_CONNINFO:
	അവസ്ഥ SSHMUX_COMMAND_CHANINFO:
		എങ്കിൽ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		എങ്കിൽ (info == ശൂന്യ)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	അവസ്ഥ SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		എങ്കിൽ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	അവസ്ഥ SSHMUX_COMMAND_FORWARD:
		എങ്കിൽ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	അവസ്ഥ SSHMUX_COMMAND_OPEN:
		എങ്കിൽ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			തിരികെ -1;
		}
		mux_client_request_session(sock);
		തിരികെ -1;
	അവസ്ഥ SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	അവസ്ഥ SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		എങ്കിൽ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	അവസ്ഥ SSHMUX_COMMAND_CANCEL_FWD:
		എങ്കിൽ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	അവസ്ഥ SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		തിരികെ (sock);
	സ്ഥിരസ്ഥിതി:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
