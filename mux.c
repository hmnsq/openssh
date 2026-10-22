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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <poll.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_fdpass.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshpty.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "clientloop.h"

/* from ssh.c */
ਬਾਹਰੀ ਪੂਰਨ tty_flag;
ਬਾਹਰੀ Options options;
ਬਾਹਰੀ ਅੱਖਰ *host;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *command;
ਬਾਹਰੀ ਅਸਥਿਰ sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
ਬਣਤਰ mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	ਬਣਤਰ sshbuf *cmd;
	ਅੱਖਰ *ਪਦ;
	ਬਣਤਰ termios tio;
	ਅੱਖਰ **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
ਬਣਤਰ mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
ਬਣਤਰ mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	ਪੂਰਨ fid;	/* forward id */
};

/* fd to control socket */
ਪੂਰਨ muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
ਸਥਿਰ ਅਸਥਿਰ sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
ਸਥਿਰ u_int muxserver_pid = 0;

ਸਥਿਰ Channel *mux_listener_channel = ਨਿਰਾ;

ਬਣਤਰ mux_master_state {
	ਪੂਰਨ hello_rcvd;
};

/* mux protocol messages */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_ਸੁਨੇਹਾ_HELLO		0x00000001
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_NEW_SESSION	0x10000002
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_ALIVE_CHECK	0x10000004
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_TERMINATE		0x10000005
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_OPEN_FWD		0x10000006
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_CLOSE_FWD		0x10000007
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_NEW_STDIO_FWD	0x10000008
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_STOP_LISTENING	0x10000009
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_PROXY		0x1000000f
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_C_EXT_INFO		0x20000001
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_OK		0x80000001
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_PERMISSION_DENIED	0x80000002
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_FAILURE		0x80000003
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_EXIT_ਸੁਨੇਹਾ	0x80000004
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_ALIVE		0x80000005
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_SESSION_OPENED	0x80000006
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_REMOTE_ਪੋਰਟ	0x80000007
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_TTY_ALLOC_FAIL	0x80000008
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_PROXY		0x8000000f
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_S_EXT_INFO		0x90000001

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_FWD_LOCAL   1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_FWD_REMOTE  2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_FWD_DYNAMIC 3

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_EXT_INFO		0x00000001

/* Bitmask of supported extensions */
ਸਥਿਰ u_int extensions = 0;

ਸਥਿਰ ਖਾਲੀ mux_session_confirm(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਖਾਲੀ *);
ਸਥਿਰ ਖਾਲੀ mux_stdio_confirm(ਬਣਤਰ ssh *, ਪੂਰਨ, ਪੂਰਨ, ਖਾਲੀ *);

ਸਥਿਰ ਪੂਰਨ mux_master_process_hello(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_new_session(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_alive_check(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_terminate(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_open_fwd(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_close_fwd(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_stdio_fwd(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_stop_listening(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_proxy(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
ਸਥਿਰ ਪੂਰਨ mux_master_process_ext_info(ਬਣਤਰ ssh *, u_int,
	    Channel *, ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);

ਸਥਿਰ ਅਚਲ ਬਣਤਰ {
	u_int type;
	ਪੂਰਨ (*handler)(ਬਣਤਰ ssh *, u_int, Channel *,
	    ਬਣਤਰ sshbuf *, ਬਣਤਰ sshbuf *);
} mux_master_handlers[] = {
	{ MUX_ਸੁਨੇਹਾ_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, ਨਿਰਾ }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
ਸਥਿਰ ਖਾਲੀ
mux_master_session_cleanup_cb(ਬਣਤਰ ssh *ssh, ਪੂਰਨ cid, ਪੂਰਨ force, ਖਾਲੀ *ਅਣਵਰਤਿਆ)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ਜੇ (c == ਨਿਰਾ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ਜੇ (c->ctl_chan != -1) {
		ਜੇ ((cc = channel_by_id(ssh, c->ctl_chan)) == ਨਿਰਾ)
			fatal_f("channel %d missing control channel %d",
			    c->self, c->ctl_chan);
		c->ctl_chan = -1;
		cc->ctl_ਬੱਚਾ_id = 0;
		cc->have_ctl_ਬੱਚਾ_id = 0;
		chan_rcvd_oclose(ssh, cc);
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Cleanup callback fired on closure of mux client _control_ channel */
ਸਥਿਰ ਖਾਲੀ
mux_master_control_cleanup_cb(ਬਣਤਰ ssh *ssh, ਪੂਰਨ cid, ਪੂਰਨ force, ਖਾਲੀ *ਅਣਵਰਤਿਆ)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ਜੇ (c == ਨਿਰਾ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ਜੇ (c->have_ctl_ਬੱਚਾ_id) {
		ਜੇ ((sc = channel_by_id(ssh, c->ctl_ਬੱਚਾ_id)) == ਨਿਰਾ)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_ਬੱਚਾ_id);
		c->ctl_ਬੱਚਾ_id = 0;
		c->have_ctl_ਬੱਚਾ_id = 0;
		sc->ctl_chan = -1;
		ਜੇ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} ਨਹੀਂਤਾਂ {
			ਜੇ (sc->istate == CHAN_ਨਿਵੇਸ਼_OPEN)
				chan_read_failed(ssh, sc);
			ਜੇ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
ਸਥਿਰ ਪੂਰਨ
env_permitted(ਅਚਲ ਅੱਖਰ *env)
{
	u_int i;
	ਪੂਰਨ ret;
	ਅੱਖਰ name[1024], *cp;

	ਜੇ ((cp = strchr(env, '=')) == ਨਿਰਾ || cp == env)
		ਵਾਪਸ 0;
	ret = snprintf(name, ਆਕਾਰ(name), "%.*s", (ਪੂਰਨ)(cp - env), env);
	ਜੇ (ret <= 0 || (ਮਾਪ_t)ret >= ਆਕਾਰ(name)) {
		error_f("name '%.100s...' too long", env);
		ਵਾਪਸ 0;
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_send_env; i++)
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ(name, options.send_env[i]))
			ਵਾਪਸ 1;

	ਵਾਪਸ 0;
}

/* Mux master protocol message handlers */

ਸਥਿਰ ਪੂਰਨ
mux_master_process_hello(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	u_int ver;
	ਬਣਤਰ mux_master_state *state = (ਬਣਤਰ mux_master_state *)c->mux_ctx;
	ਪੂਰਨ r;

	ਜੇ (state == ਨਿਰਾ)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ਜੇ (state->hello_rcvd) {
		error_f("HELLO received twice");
		ਵਾਪਸ -1;
	}
	ਜੇ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ਵਾਪਸ -1;
	}
	ਜੇ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ਵਾਪਸ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ਜਦੋਂ (sshbuf_len(m) > 0) {
		ਅੱਖਰ *name = ਨਿਰਾ;
		ਮਾਪ_t ਮੁੱਲ_len = 0;

		ਜੇ ((r = sshbuf_get_cstring(m, &name, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_get_string_ਸਿੱਧਾ(m, ਨਿਰਾ, &ਮੁੱਲ_len)) != 0) {
			error_fr(r, "parse extension");
			ਵਾਪਸ -1;
		}
		ਜੇ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ਨਹੀਂਤਾਂ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, ਮੁੱਲ_len);
		}
		ਮੁਕਤ(name);
	}
	state->hello_rcvd = 1;
	ਵਾਪਸ 0;
}

/* Enqueue a "ok" response to the reply buffer */
ਸਥਿਰ ਖਾਲੀ
ਜਵਾਬ_ok(ਬਣਤਰ sshbuf *ਜਵਾਬ, u_int rid)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ਸਥਿਰ ਖਾਲੀ
ਜਵਾਬ_error(ਬਣਤਰ sshbuf *ਜਵਾਬ, u_int type, u_int rid, ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ, type)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, rid)) != 0 ||
	    (r = sshbuf_put_cstring(ਜਵਾਬ, ਸੁਨੇਹਾ)) != 0)
		fatal_fr(r, "reply");
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_new_session(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	Channel *nc;
	ਬਣਤਰ mux_session_confirm_ctx *cctx;
	ਅੱਖਰ *cmd, *cp;
	u_int i, j, env_len, escape_char, ਖਿੜਕੀ, packetmax;
	ਪੂਰਨ r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, ਆਕਾਰ(*cctx));
	cctx->ਪਦ = ਨਿਰਾ;
	cctx->rid = rid;
	cmd = ਨਿਰਾ;
	cctx->env = ਨਿਰਾ;
	env_len = 0;
	ਜੇ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->ਪਦ, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, ਨਿਰਾ)) != 0) {
 malf:
		ਮੁਕਤ(cmd);
		ਲਈ (j = 0; j < env_len; j++)
			ਮੁਕਤ(cctx->env[j]);
		ਮੁਕਤ(cctx->env);
		ਮੁਕਤ(cctx->ਪਦ);
		ਮੁਕਤ(cctx);
		error_f("malformed message");
		ਵਾਪਸ -1;
	}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MUX_MAX_ENV_VARS	4096
	ਜਦੋਂ (sshbuf_len(m) > 0) {
		ਜੇ ((r = sshbuf_get_cstring(m, &cp, ਨਿਰਾ)) != 0)
			ਜਾਓ malf;
		ਜੇ (!env_permitted(cp)) {
			ਮੁਕਤ(cp);
			ਜਾਰੀ;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    ਆਕਾਰ(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = ਨਿਰਾ;
		ਜੇ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			ਰੋਕੋ;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->ਪਦ, cmd, env_len);

	ਜੇ ((cctx->cmd = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put(cctx->cmd, cmd, ਲੜੀ_ਲੰਬਾਈ(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	ਮੁਕਤ(cmd);
	cmd = ਨਿਰਾ;

	/* Gather fds from client */
	ਲਈ(i = 0; i < 3; i++) {
		ਜੇ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ਲਈ (j = 0; j < i; j++)
				close(new_fd[j]);
			ਲਈ (j = 0; j < env_len; j++)
				ਮੁਕਤ(cctx->env[j]);
			ਮੁਕਤ(cctx->env);
			ਮੁਕਤ(cctx->ਪਦ);
			sshbuf_free(cctx->cmd);
			ਮੁਕਤ(cctx);
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ਵਾਪਸ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ਜੇ (c->have_ctl_ਬੱਚਾ_id) {
		debug2_f("session already open");
		ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		ਮੁਕਤ(cctx->ਪਦ);
		ਜੇ (env_len != 0) {
			ਲਈ (i = 0; i < env_len; i++)
				ਮੁਕਤ(cctx->env[i]);
			ਮੁਕਤ(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		ਮੁਕਤ(cctx);
		ਵਾਪਸ 0;
	}

	ਜੇ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ਜੇ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ਜਾਓ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ਜੇ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	ਖਿੜਕੀ = CHAN_SES_ਖਿੜਕੀ_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ਜੇ (cctx->want_tty) {
		ਖਿੜਕੀ >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], ਖਿੜਕੀ, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ਜੇ (cctx->want_tty)
		channel_ਸੈੱਟ_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_ਬੱਚਾ_id = nc->self;	/* link control -> session channel */
	c->have_ctl_ਬੱਚਾ_id = 1;

	ਜੇ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_ਰਜਿਸਟਰ_filter(ssh, nc->self,
		    client_simple_escape_filter, ਨਿਰਾ,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((ਪੂਰਨ)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_ਰਜਿਸਟਰ_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_ਰਜਿਸਟਰ_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_alive_check(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	ਪੂਰਨ r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, rid)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ਵਾਪਸ 0;
}

/* The "info" extension. */
ਸਥਿਰ ਪੂਰਨ
mux_master_process_ext_info(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	ਪੂਰਨ r;
	u_int ਸਥਿਤੀ = 0;
	ਅੱਖਰ *name = ਨਿਰਾ, *ਸੁਨੇਹਾ = ਨਿਰਾ;

	debug2_f("channel %d: info request", c->self);

	ਜੇ ((r = sshbuf_get_cstring(m, &name, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse");

	ਜੇ (strcmp(name, "connection") == 0) {
		ਜੇ ((ਸੁਨੇਹਾ = connection_info_ਸੁਨੇਹਾ(ssh)) == ਨਿਰਾ)
			fatal_f("connection_info_message");
		ਸਥਿਤੀ = 1;
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(name, "channels") == 0) {
		ਜੇ ((ਸੁਨੇਹਾ = channel_open_ਸੁਨੇਹਾ(ssh)) == ਨਿਰਾ)
			fatal_f("channel_open_message");
		ਸਥਿਤੀ = 1;
	} ਨਹੀਂਤਾਂ {
		ਸੁਨੇਹਾ = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, rid)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, ਸਥਿਤੀ)) != 0 ||
	    (r = sshbuf_put_cstring(ਜਵਾਬ, ਸੁਨੇਹਾ)) != 0)
		fatal_fr(r, "reply");
	ਮੁਕਤ(ਸੁਨੇਹਾ);

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_terminate(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	debug2_f("channel %d: terminate request", c->self);

	ਜੇ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ਜੇ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ਵਾਪਸ 0;
		}
	}

	quit_pending = 1;
	ਜਵਾਬ_ok(ਜਵਾਬ, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਅੱਖਰ *
format_forward(u_int ftype, ਬਣਤਰ Forward *fwd)
{
	ਅੱਖਰ *ret;

	ਚੋਣ (ftype) {
	ਹਾਲਤ MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) ? fwd->listen_ਰਸਤਾ :
		    (fwd->listen_host == ਨਿਰਾ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_ਪੋਰਟ,
		    (fwd->connect_ਰਸਤਾ != ਨਿਰਾ) ? fwd->connect_ਰਸਤਾ :
		    fwd->connect_host, fwd->connect_ਪੋਰਟ);
		ਰੋਕੋ;
	ਹਾਲਤ MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == ਨਿਰਾ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_ਪੋਰਟ);
		ਰੋਕੋ;
	ਹਾਲਤ MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_ਰਸਤਾ != ਨਿਰਾ) ? fwd->listen_ਰਸਤਾ :
		    (fwd->listen_host == ਨਿਰਾ) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_ਪੋਰਟ,
		    (fwd->connect_ਰਸਤਾ != ਨਿਰਾ) ? fwd->connect_ਰਸਤਾ :
		    fwd->connect_host, fwd->connect_ਪੋਰਟ);
		ਰੋਕੋ;
	ਮੂਲ:
		fatal_f("unknown forward type %u", ftype);
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
compare_host(ਅਚਲ ਅੱਖਰ *a, ਅਚਲ ਅੱਖਰ *b)
{
	ਜੇ (a == ਨਿਰਾ && b == ਨਿਰਾ)
		ਵਾਪਸ 1;
	ਜੇ (a == ਨਿਰਾ || b == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ strcmp(a, b) == 0;
}

ਸਥਿਰ ਪੂਰਨ
compare_forward(ਬਣਤਰ Forward *a, ਬਣਤਰ Forward *b)
{
	ਜੇ (!compare_host(a->listen_host, b->listen_host))
		ਵਾਪਸ 0;
	ਜੇ (!compare_host(a->listen_ਰਸਤਾ, b->listen_ਰਸਤਾ))
		ਵਾਪਸ 0;
	ਜੇ (a->listen_ਪੋਰਟ != b->listen_ਪੋਰਟ)
		ਵਾਪਸ 0;
	ਜੇ (!compare_host(a->connect_host, b->connect_host))
		ਵਾਪਸ 0;
	ਜੇ (!compare_host(a->connect_ਰਸਤਾ, b->connect_ਰਸਤਾ))
		ਵਾਪਸ 0;
	ਜੇ (a->connect_ਪੋਰਟ != b->connect_ਪੋਰਟ)
		ਵਾਪਸ 0;

	ਵਾਪਸ 1;
}

ਸਥਿਰ ਖਾਲੀ
mux_confirm_remote_forward(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type, uint32_t seq, ਖਾਲੀ *ctxt)
{
	ਬਣਤਰ mux_channel_confirm_ctx *fctx = ctxt;
	ਅੱਖਰ *failmsg = ਨਿਰਾ;
	ਬਣਤਰ Forward *rfwd;
	Channel *c;
	ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ;
	u_int ਪੋਰਟ;
	ਪੂਰਨ r;

	ਜੇ ((c = channel_by_id(ssh, fctx->cid)) == ਨਿਰਾ) {
		/* no channel for reply */
		error_f("unknown channel");
		ਵਾਪਸ;
	}
	ਜੇ ((ਬਾਹਰਲਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ (fctx->fid >= options.ਅੰਕ_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_ਰਸਤਾ == ਨਿਰਾ &&
	    options.remote_forwards[fctx->fid].connect_host == ਨਿਰਾ)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		ਜਾਓ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_ਪੋਰਟ, rfwd->connect_ਰਸਤਾ ? rfwd->connect_ਰਸਤਾ :
	    rfwd->connect_host, rfwd->connect_ਪੋਰਟ);
	ਜੇ (type == SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS) {
		ਜੇ (rfwd->listen_ਪੋਰਟ == 0) {
			ਜੇ ((r = sshpkt_get_u32(ssh, &ਪੋਰਟ)) != 0)
				fatal_fr(r, "parse port");
			ਜੇ (ਪੋਰਟ > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", ਪੋਰਟ,
				    rfwd->connect_host, rfwd->connect_ਪੋਰਟ);
			}
			rfwd->allocated_ਪੋਰਟ = (ਪੂਰਨ)ਪੋਰਟ;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_ਪੋਰਟ,
			    rfwd->connect_host, rfwd->connect_ਪੋਰਟ);
			ਜੇ ((r = sshbuf_put_u32(ਬਾਹਰਲਾ,
			    MUX_S_REMOTE_ਪੋਰਟ)) != 0 ||
			    (r = sshbuf_put_u32(ਬਾਹਰਲਾ, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(ਬਾਹਰਲਾ,
			    rfwd->allocated_ਪੋਰਟ)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_ਪੋਰਟ);
		} ਨਹੀਂਤਾਂ {
			ਜਵਾਬ_ok(ਬਾਹਰਲਾ, fctx->rid);
		}
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (rfwd->listen_ਪੋਰਟ == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ਜੇ (rfwd->listen_ਰਸਤਾ != ਨਿਰਾ)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_ਰਸਤਾ);
		ਨਹੀਂਤਾਂ
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_ਪੋਰਟ);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_ਪੋਰਟ,
		    rfwd->connect_ਰਸਤਾ ? rfwd->connect_ਰਸਤਾ :
		    rfwd->connect_host, rfwd->connect_ਪੋਰਟ);

		ਮੁਕਤ(rfwd->listen_host);
		ਮੁਕਤ(rfwd->listen_ਰਸਤਾ);
		ਮੁਕਤ(rfwd->connect_host);
		ਮੁਕਤ(rfwd->connect_ਰਸਤਾ);
		memset(rfwd, 0, ਆਕਾਰ(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	ਜਵਾਬ_error(ਬਾਹਰਲਾ, MUX_S_FAILURE, fctx->rid, failmsg);
	ਮੁਕਤ(failmsg);
 ਬਾਹਰਲਾ:
	ਜੇ ((r = sshbuf_put_stringb(c->output, ਬਾਹਰਲਾ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ਬਾਹਰਲਾ);
	ਜੇ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	ਮੁਕਤ(fctx);
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_open_fwd(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	ਬਣਤਰ Forward fwd;
	ਅੱਖਰ *fwd_desc = ਨਿਰਾ;
	ਅੱਖਰ *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	ਪੂਰਨ r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, ਆਕਾਰ(fwd));

	/* XXX - lport/cport check redundant */
	ਜੇ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)ਪੋਰਟ_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)ਪੋਰਟ_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (*listen_addr == '\0') {
		ਮੁਕਤ(listen_addr);
		listen_addr = ਨਿਰਾ;
	}
	ਜੇ (*connect_addr == '\0') {
		ਮੁਕਤ(connect_addr);
		connect_addr = ਨਿਰਾ;
	}

	memset(&fwd, 0, ਆਕਾਰ(fwd));
	fwd.listen_ਪੋਰਟ = lport;
	ਜੇ (fwd.listen_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL)
		fwd.listen_ਰਸਤਾ = listen_addr;
	ਨਹੀਂਤਾਂ
		fwd.listen_host = listen_addr;
	fwd.connect_ਪੋਰਟ = cport;
	ਜੇ (fwd.connect_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL)
		fwd.connect_ਰਸਤਾ = connect_addr;
	ਨਹੀਂਤਾਂ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ਜੇ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		ਮੁਕਤ(listen_addr);
		ਮੁਕਤ(connect_addr);
		ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ਵਾਪਸ 0;
	}
	ਜੇ (ftype == MUX_FWD_DYNAMIC && fwd.listen_ਰਸਤਾ) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		ਜਾਓ invalid;
	}
	ਜੇ (fwd.listen_ਪੋਰਟ != ਪੋਰਟ_STREAMLOCAL && fwd.listen_ਪੋਰਟ >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_ਪੋਰਟ);
		ਜਾਓ invalid;
	}
	ਜੇ ((fwd.connect_ਪੋਰਟ != ਪੋਰਟ_STREAMLOCAL &&
	    fwd.connect_ਪੋਰਟ >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_ਪੋਰਟ == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_ਪੋਰਟ);
		ਜਾਓ invalid;
	}
	ਜੇ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == ਨਿਰਾ &&
	    fwd.connect_ਰਸਤਾ == ਨਿਰਾ) {
		logit_f("missing connect host");
		ਜਾਓ invalid;
	}

	/* Skip forwards that have already been requested */
	ਚੋਣ (ftype) {
	ਹਾਲਤ MUX_FWD_LOCAL:
	ਹਾਲਤ MUX_FWD_DYNAMIC:
		ਲਈ (i = 0; i < options.ਅੰਕ_local_forwards; i++) {
			ਜੇ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				ਜਵਾਬ_ok(ਜਵਾਬ, rid);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
		ਰੋਕੋ;
	ਹਾਲਤ MUX_FWD_REMOTE:
		ਲਈ (i = 0; i < options.ਅੰਕ_remote_forwards; i++) {
			ਜੇ (!compare_forward(&fwd, options.remote_forwards + i))
				ਜਾਰੀ;
			ਜੇ (fwd.listen_ਪੋਰਟ != 0)
				ਜਾਓ exists;
			debug2_f("found allocated port");
			ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ,
			    MUX_S_REMOTE_ਪੋਰਟ)) != 0 ||
			    (r = sshbuf_put_u32(ਜਵਾਬ, rid)) != 0 ||
			    (r = sshbuf_put_u32(ਜਵਾਬ,
			    options.remote_forwards[i].allocated_ਪੋਰਟ)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਰੋਕੋ;
	}

	ਜੇ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ਜੇ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	ਜੇ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ਜੇ (!channel_ਤਿਆਰੀ_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੋੜੋ_local_forward(&options, &fwd);
		freefwd = 0;
	} ਨਹੀਂਤਾਂ {
		ਬਣਤਰ mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ਜੇ (fwd.handle < 0)
			ਜਾਓ fail;
		ਜੋੜੋ_remote_forward(&options, &fwd);
		fctx = xcalloc(1, ਆਕਾਰ(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.ਅੰਕ_remote_forwards - 1;
		client_ਰਜਿਸਟਰ_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜਵਾਬ_ok(ਜਵਾਬ, rid);
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(fwd_desc);
	ਜੇ (freefwd) {
		ਮੁਕਤ(fwd.listen_host);
		ਮੁਕਤ(fwd.listen_ਰਸਤਾ);
		ਮੁਕਤ(fwd.connect_host);
		ਮੁਕਤ(fwd.connect_ਰਸਤਾ);
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_close_fwd(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	ਬਣਤਰ Forward fwd, *ਮਿਲਿਆ_fwd;
	ਅੱਖਰ *fwd_desc = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *error_reason = ਨਿਰਾ;
	ਅੱਖਰ *listen_addr = ਨਿਰਾ, *connect_addr = ਨਿਰਾ;
	u_int ftype;
	ਪੂਰਨ r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, ਆਕਾਰ(fwd));

	ਜੇ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)ਪੋਰਟ_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)ਪੋਰਟ_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (*listen_addr == '\0') {
		ਮੁਕਤ(listen_addr);
		listen_addr = ਨਿਰਾ;
	}
	ਜੇ (*connect_addr == '\0') {
		ਮੁਕਤ(connect_addr);
		connect_addr = ਨਿਰਾ;
	}

	memset(&fwd, 0, ਆਕਾਰ(fwd));
	fwd.listen_ਪੋਰਟ = lport;
	ਜੇ (fwd.listen_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL)
		fwd.listen_ਰਸਤਾ = listen_addr;
	ਨਹੀਂਤਾਂ
		fwd.listen_host = listen_addr;
	fwd.connect_ਪੋਰਟ = cport;
	ਜੇ (fwd.connect_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL)
		fwd.connect_ਰਸਤਾ = connect_addr;
	ਨਹੀਂਤਾਂ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	ਮਿਲਿਆ_fwd = ਨਿਰਾ;
	ਚੋਣ (ftype) {
	ਹਾਲਤ MUX_FWD_LOCAL:
	ਹਾਲਤ MUX_FWD_DYNAMIC:
		ਲਈ (i = 0; i < options.ਅੰਕ_local_forwards; i++) {
			ਜੇ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				ਮਿਲਿਆ_fwd = options.local_forwards + i;
				ਰੋਕੋ;
			}
		}
		ਰੋਕੋ;
	ਹਾਲਤ MUX_FWD_REMOTE:
		ਲਈ (i = 0; i < options.ਅੰਕ_remote_forwards; i++) {
			ਜੇ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				ਮਿਲਿਆ_fwd = options.remote_forwards + i;
				ਰੋਕੋ;
			}
		}
		ਰੋਕੋ;
	}

	ਜੇ (ਮਿਲਿਆ_fwd == ਨਿਰਾ)
		error_reason = "port not forwarded";
	ਨਹੀਂਤਾਂ ਜੇ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ਜੇ (channel_request_rforward_cancel(ssh, ਮਿਲਿਆ_fwd) == -1)
			error_reason = "port not in permitted opens";
	} ਨਹੀਂਤਾਂ {	/* local and dynamic forwards */
		/* Ditto */
		ਜੇ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_ਪੋਰਟ,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ਜੇ (error_reason != ਨਿਰਾ)
		ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, rid, error_reason);
	ਨਹੀਂਤਾਂ {
		ਜਵਾਬ_ok(ਜਵਾਬ, rid);
		ਮੁਕਤ(ਮਿਲਿਆ_fwd->listen_host);
		ਮੁਕਤ(ਮਿਲਿਆ_fwd->listen_ਰਸਤਾ);
		ਮੁਕਤ(ਮਿਲਿਆ_fwd->connect_host);
		ਮੁਕਤ(ਮਿਲਿਆ_fwd->connect_ਰਸਤਾ);
		ਮਿਲਿਆ_fwd->listen_host = ਮਿਲਿਆ_fwd->connect_host = ਨਿਰਾ;
		ਮਿਲਿਆ_fwd->listen_ਰਸਤਾ = ਮਿਲਿਆ_fwd->connect_ਰਸਤਾ = ਨਿਰਾ;
		ਮਿਲਿਆ_fwd->listen_ਪੋਰਟ = ਮਿਲਿਆ_fwd->connect_ਪੋਰਟ = 0;
	}
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(fwd_desc);
	ਮੁਕਤ(listen_addr);
	ਮੁਕਤ(connect_addr);

	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_stdio_fwd(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	Channel *nc;
	ਅੱਖਰ *chost = ਨਿਰਾ;
	u_int _cport, i, j;
	ਪੂਰਨ ok = 0, cport, r, new_fd[2];
	ਬਣਤਰ mux_stdio_confirm_ctx *cctx;

	ਜੇ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		ਮੁਕਤ(chost);
		error_f("malformed message");
		ਵਾਪਸ -1;
	}
	ਜੇ (_cport == (u_int)ਪੋਰਟ_STREAMLOCAL)
		cport = ਪੋਰਟ_STREAMLOCAL;
	ਨਹੀਂਤਾਂ ਜੇ (_cport <= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ)
		cport = (ਪੂਰਨ)_cport;
	ਨਹੀਂਤਾਂ {
		ਮੁਕਤ(chost);
		error_f("invalid port 0x%x", _cport);
		ਵਾਪਸ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	ਲਈ(i = 0; i < 2; i++) {
		ਜੇ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ਲਈ (j = 0; j < i; j++)
				close(new_fd[j]);
			ਮੁਕਤ(chost);

			/* prepare reply */
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ਵਾਪਸ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ਜੇ (c->have_ctl_ਬੱਚਾ_id) {
		debug2_f("session already open");
		ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		ਮੁਕਤ(chost);
		ਵਾਪਸ 0;
	}

	ਜੇ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ਜੇ (cport == ਪੋਰਟ_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} ਨਹੀਂਤਾਂ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ਜੇ (!ok) {
			debug2_f("stdio fwd refused by user");
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ਜਾਓ cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	ਮੁਕਤ(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_ਬੱਚਾ_id = nc->self;	/* link control -> session channel */
	c->have_ctl_ਬੱਚਾ_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_ਰਜਿਸਟਰ_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, ਆਕਾਰ(*cctx));
	cctx->rid = rid;
	channel_ਰਜਿਸਟਰ_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	ਵਾਪਸ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ਸਥਿਰ ਖਾਲੀ
mux_stdio_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ success, ਖਾਲੀ *arg)
{
	ਬਣਤਰ mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	ਬਣਤਰ sshbuf *ਜਵਾਬ;
	ਪੂਰਨ r;

	ਜੇ (cctx == ਨਿਰਾ)
		fatal_f("cctx == NULL");
	ਜੇ ((c = channel_by_id(ssh, id)) == ਨਿਰਾ)
		fatal_f("no channel for id %d", id);
	ਜੇ ((cc = channel_by_id(ssh, c->ctl_chan)) == ਨਿਰਾ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ਜੇ ((ਜਵਾਬ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");

	ਜੇ (!success) {
		debug3_f("sending failure reply");
		ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		ਜਾਓ ਪੂਰਾ;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, c->self)) != 0)
		fatal_fr(r, "reply");

 ਪੂਰਾ:
	/* Send reply */
	ਜੇ ((r = sshbuf_put_stringb(cc->output, ਜਵਾਬ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ਜਵਾਬ);

	ਜੇ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ਨਿਰਾ;
	ਮੁਕਤ(cctx);
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_stop_listening(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	debug_f("channel %d: stop listening", c->self);

	ਜੇ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ਜੇ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ਵਾਪਸ 0;
		}
	}

	ਜੇ (mux_listener_channel != ਨਿਰਾ) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		ਮੁਕਤ(options.control_ਰਸਤਾ);
		options.control_ਰਸਤਾ = ਨਿਰਾ;
		mux_listener_channel = ਨਿਰਾ;
		muxserver_sock = -1;
	}

	ਜਵਾਬ_ok(ਜਵਾਬ, rid);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_master_process_proxy(ਬਣਤਰ ssh *ssh, u_int rid,
    Channel *c, ਬਣਤਰ sshbuf *m, ਬਣਤਰ sshbuf *ਜਵਾਬ)
{
	ਪੂਰਨ r;

	debug_f("channel %d: proxy request", c->self);

	ਜੇ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ਜੇ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ਵਾਪਸ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, rid)) != 0)
		fatal_fr(r, "reply");

	ਵਾਪਸ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ਸਥਿਰ ਪੂਰਨ
mux_master_read_cb(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ mux_master_state *state = (ਬਣਤਰ mux_master_state *)c->mux_ctx;
	ਬਣਤਰ sshbuf *ਵਿੱਚ = ਨਿਰਾ, *ਬਾਹਰਲਾ = ਨਿਰਾ;
	u_int type, rid, i;
	ਪੂਰਨ r, ret = -1;

	ਜੇ ((ਬਾਹਰਲਾ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ਜੇ (c->mux_ctx == ਨਿਰਾ) {
		state = xcalloc(1, ਆਕਾਰ(*state));
		c->mux_ctx = state;
		channel_ਰਜਿਸਟਰ_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ਜੇ ((r = sshbuf_put_u32(ਬਾਹਰਲਾ, MUX_ਸੁਨੇਹਾ_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(ਬਾਹਰਲਾ, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ਜੇ ((r = sshbuf_put_cstring(ਬਾਹਰਲਾ, "info")) != 0 ||
		    (r = sshbuf_put_cstring(ਬਾਹਰਲਾ, "0")) != 0)
			fatal_fr(r, "put info extension");
		ਜੇ ((r = sshbuf_put_stringb(c->output, ਬਾਹਰਲਾ)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Channel code ensures that we receive whole packets */
	ਜੇ ((r = sshbuf_froms(c->ਨਿਵੇਸ਼, &ਵਿੱਚ)) != 0) {
 malf:
		error_f("malformed message");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshbuf_get_u32(ਵਿੱਚ, &type)) != 0)
		ਜਾਓ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(ਵਿੱਚ));

	ਜੇ (type == MUX_ਸੁਨੇਹਾ_HELLO)
		rid = 0;
	ਨਹੀਂਤਾਂ {
		ਜੇ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_ਸੁਨੇਹਾ_HELLO, type);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshbuf_get_u32(ਵਿੱਚ, &rid)) != 0)
			ਜਾਓ malf;
	}

	ਲਈ (i = 0; mux_master_handlers[i].handler != ਨਿਰਾ; i++) {
		ਜੇ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, ਵਿੱਚ, ਬਾਹਰਲਾ);
			ਰੋਕੋ;
		}
	}
	ਜੇ (mux_master_handlers[i].handler == ਨਿਰਾ) {
		error_f("unsupported mux message 0x%08x", type);
		ਜਵਾਬ_error(ਬਾਹਰਲਾ, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ਜੇ (sshbuf_len(ਬਾਹਰਲਾ) != 0 &&
	    (r = sshbuf_put_stringb(c->output, ਬਾਹਰਲਾ)) != 0)
		fatal_fr(r, "enqueue");
 ਬਾਹਰਲਾ:
	sshbuf_free(ਵਿੱਚ);
	sshbuf_free(ਬਾਹਰਲਾ);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
mux_exit_ਸੁਨੇਹਾ(ਬਣਤਰ ssh *ssh, Channel *c, ਪੂਰਨ exitval)
{
	ਬਣਤਰ sshbuf *m;
	Channel *mux_chan;
	ਪੂਰਨ r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ਜੇ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ਨਿਰਾ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_S_EXIT_ਸੁਨੇਹਾ)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

ਖਾਲੀ
mux_tty_alloc_failed(ਬਣਤਰ ssh *ssh, Channel *c)
{
	ਬਣਤਰ sshbuf *m;
	Channel *mux_chan;
	ਪੂਰਨ r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ਜੇ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ਨਿਰਾ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
ਖਾਲੀ
muxserver_listen(ਬਣਤਰ ssh *ssh)
{
	ਬਹੁਲਕ_t old_umask;
	ਅੱਖਰ *orig_control_ਰਸਤਾ = options.control_ਰਸਤਾ;
	ਅੱਖਰ rbuf[16+1];
	u_int i, r;
	ਪੂਰਨ oerrno;

	ਜੇ (options.control_ਰਸਤਾ == ਨਿਰਾ ||
	    options.control_master == SSHCTL_MASTER_NO)
		ਵਾਪਸ;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	ਲਈ (i = 0; i < ਆਕਾਰ(rbuf) - 1; i++) {
		r = arc4random_ਇਕਸਾਰ(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[ਆਕਾਰ(rbuf) - 1] = '\0';
	options.control_ਰਸਤਾ = ਨਿਰਾ;
	xasprintf(&options.control_ਰਸਤਾ, "%s.%s", orig_control_ਰਸਤਾ, rbuf);
	debug3_f("temporary control path %s", options.control_ਰਸਤਾ);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_ਰਸਤਾ, 64, 0);
	oerrno = errno;
	umask(old_umask);
	ਜੇ (muxserver_sock < 0) {
		ਜੇ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_ਰਸਤਾ);
 disable_mux_master:
			ਜੇ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			ਮੁਕਤ(orig_control_ਰਸਤਾ);
			ਮੁਕਤ(options.control_ਰਸਤਾ);
			options.control_ਰਸਤਾ = ਨਿਰਾ;
			options.control_master = SSHCTL_MASTER_NO;
			ਵਾਪਸ;
		} ਨਹੀਂਤਾਂ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ਜੇ (link(options.control_ਰਸਤਾ, orig_control_ਰਸਤਾ) != 0) {
		ਜੇ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_ਰਸਤਾ, orig_control_ਰਸਤਾ,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_ਰਸਤਾ);
		unlink(options.control_ਰਸਤਾ);
		ਜਾਓ disable_mux_master;
	}
	unlink(options.control_ਰਸਤਾ);
	ਮੁਕਤ(options.control_ਰਸਤਾ);
	options.control_ਰਸਤਾ = orig_control_ਰਸਤਾ;

	ਸੈੱਟ_nonblock(muxserver_sock);

	mux_listener_channel = channel_new(ssh, "mux listener",
	    SSH_CHANNEL_MUX_LISTENER, muxserver_sock, muxserver_sock, -1,
	    CHAN_TCP_ਖਿੜਕੀ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, options.control_ਰਸਤਾ, 1);
	mux_listener_channel->mux_rcb = mux_master_read_cb;
	debug3_f("mux listener channel %d fd %d",
	    mux_listener_channel->self, mux_listener_channel->sock);
}

/* Callback on open confirmation in mux master for a mux client session. */
ਸਥਿਰ ਖਾਲੀ
mux_session_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ success, ਖਾਲੀ *arg)
{
	ਬਣਤਰ mux_session_confirm_ctx *cctx = arg;
	ਅਚਲ ਅੱਖਰ *display;
	Channel *c, *cc;
	ਪੂਰਨ i, r;
	ਬਣਤਰ sshbuf *ਜਵਾਬ;

	ਜੇ (cctx == ਨਿਰਾ)
		fatal_f("cctx == NULL");
	ਜੇ ((c = channel_by_id(ssh, id)) == ਨਿਰਾ)
		fatal_f("no channel for id %d", id);
	ਜੇ ((cc = channel_by_id(ssh, c->ctl_chan)) == ਨਿਰਾ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ਜੇ ((ਜਵਾਬ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");

	ਜੇ (!success) {
		debug3_f("sending failure reply");
		ਜਵਾਬ_error(ਜਵਾਬ, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		ਜਾਓ ਪੂਰਾ;
	}

	display = getenv("DISPLAY");
	ਜੇ (cctx->want_x_fwd && options.forward_x11 && display != ਨਿਰਾ) {
		ਅੱਖਰ *proto, *ਅੰਕੜੇ;

		/* Get reasonable local authentication information. */
		ਜੇ (client_x11_get_proto(ssh, display, options.xauth_location,
		    options.forward_x11_trusted, options.forward_x11_timeout,
		    &proto, &ਅੰਕੜੇ) == 0) {
			/* Request forwarding with authentication spoofing. */
			debug("Requesting X11 forwarding with authentication "
			    "spoofing.");
			x11_request_forwarding_with_spoofing(ssh, id,
			    display, proto, ਅੰਕੜੇ, 1);
			/* XXX exit_on_forward_failure */
			client_expect_confirm(ssh, id, "X11 forwarding",
			    CONFIRM_WARN);
		}
	}

	ਜੇ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_ਤਿਆਰੀ(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->ਪਦ, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ਜੇ ((r = sshbuf_put_u32(ਜਵਾਬ, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(ਜਵਾਬ, c->self)) != 0)
		fatal_fr(r, "reply");

 ਪੂਰਾ:
	/* Send reply */
	ਜੇ ((r = sshbuf_put_stringb(cc->output, ਜਵਾਬ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ਜਵਾਬ);

	ਜੇ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ਨਿਰਾ;
	sshbuf_free(cctx->cmd);
	ਮੁਕਤ(cctx->ਪਦ);
	ਜੇ (cctx->env != ਨਿਰਾ) {
		ਲਈ (i = 0; cctx->env[i] != ਨਿਰਾ; i++)
			ਮੁਕਤ(cctx->env[i]);
		ਮੁਕਤ(cctx->env);
	}
	ਮੁਕਤ(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
ਸਥਿਰ ਖਾਲੀ
control_client_sighandler(ਪੂਰਨ signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
ਸਥਿਰ ਖਾਲੀ
control_client_sigrelay(ਪੂਰਨ signo)
{
	ਪੂਰਨ save_errno = errno;

	ਜੇ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_read(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *b, ਮਾਪ_t need, ਪੂਰਨ timeout_ms)
{
	ਮਾਪ_t have;
	ssize_t len;
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	ਲਈ (have = 0; have < need; ) {
		ਜੇ (muxclient_terminate) {
			errno = EINTR;
			ਵਾਪਸ -1;
		}
		len = ਪਠ(fd, p + have, need - have);
		ਜੇ (len == -1) {
			ਚੋਣ (errno) {
#ਜੇ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ਹਾਲਤ EWOULDBLOCK:
#ਜੇ_ਅੰਤ
			ਹਾਲਤ EAGAIN:
				ਜੇ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ਵਾਪਸ -1;	/* timeout */
				/* FALLTHROUGH */
			ਹਾਲਤ EINTR:
				ਜਾਰੀ;
			ਮੂਲ:
				ਵਾਪਸ -1;
			}
		}
		ਜੇ (len == 0) {
			errno = EPIPE;
			ਵਾਪਸ -1;
		}
		have += (ਮਾਪ_t)len;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_write_packet(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *m)
{
	ਬਣਤਰ sshbuf *ਕਤਾਰ;
	u_int have, need;
	ਪੂਰਨ r, oerrno, len;
	ਅਚਲ u_char *ptr;
	ਬਣਤਰ pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ਜੇ ((ਕਤਾਰ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_stringb(ਕਤਾਰ, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(ਕਤਾਰ);
	ptr = sshbuf_ptr(ਕਤਾਰ);

	ਲਈ (have = 0; have < need; ) {
		ਜੇ (muxclient_terminate) {
			sshbuf_free(ਕਤਾਰ);
			errno = EINTR;
			ਵਾਪਸ -1;
		}
		len = ਲਿਖ(fd, ptr + have, need - have);
		ਜੇ (len == -1) {
			ਚੋਣ (errno) {
#ਜੇ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ਹਾਲਤ EWOULDBLOCK:
#ਜੇ_ਅੰਤ
			ਹਾਲਤ EAGAIN:
				(ਖਾਲੀ)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			ਹਾਲਤ EINTR:
				ਜਾਰੀ;
			ਮੂਲ:
				oerrno = errno;
				sshbuf_free(ਕਤਾਰ);
				errno = oerrno;
				ਵਾਪਸ -1;
			}
		}
		ਜੇ (len == 0) {
			sshbuf_free(ਕਤਾਰ);
			errno = EPIPE;
			ਵਾਪਸ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(ਕਤਾਰ);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_read_packet_timeout(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *m, ਪੂਰਨ timeout_ms)
{
	ਬਣਤਰ sshbuf *ਕਤਾਰ;
	ਮਾਪ_t need, have;
	ਅਚਲ u_char *ptr;
	ਪੂਰਨ r, oerrno;

	ਜੇ ((ਕਤਾਰ = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ (mux_client_read(fd, ਕਤਾਰ, 4, timeout_ms) != 0) {
		ਜੇ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(ਕਤਾਰ);
		errno = oerrno;
		ਵਾਪਸ -1;
	}
	need = PEEK_U32(sshbuf_ptr(ਕਤਾਰ));
	ਜੇ (mux_client_read(fd, ਕਤਾਰ, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(ਕਤਾਰ);
		errno = oerrno;
		ਵਾਪਸ -1;
	}
	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(ਕਤਾਰ, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(ਕਤਾਰ);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_read_packet(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *m)
{
	ਵਾਪਸ mux_client_read_packet_timeout(fd, m, -1);
}

ਸਥਿਰ ਪੂਰਨ
mux_client_hello_exchange(ਪੂਰਨ fd, ਪੂਰਨ timeout_ms)
{
	ਬਣਤਰ sshbuf *m;
	u_int type, ver;
	ਪੂਰਨ r, ret = -1;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_ਸੁਨੇਹਾ_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ਜੇ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ਜੇ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ਜੇ (type != MUX_ਸੁਨੇਹਾ_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_ਸੁਨੇਹਾ_HELLO, type);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ਜੇ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ਜਦੋਂ (sshbuf_len(m) > 0) {
		ਅੱਖਰ *name = ਨਿਰਾ;

		ਜੇ ((r = sshbuf_get_cstring(m, &name, ਨਿਰਾ)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*ਮੁੱਲ*/
			error_fr(r, "parse extension");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Process extensions. */
		ਜੇ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ਨਹੀਂਤਾਂ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		ਮੁਕਤ(name);
	}
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(m);
	ਵਾਪਸ ret;
}

ਸਥਿਰ u_int
mux_client_request_alive(ਪੂਰਨ fd)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e;
	u_int pid, type, rid;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ਵਾਪਸ 0;
	}

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ਜੇ (type != MUX_S_ALIVE) {
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ਜੇ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ਜੇ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ਵਾਪਸ pid;
}

ਸਥਿਰ ਅੱਖਰ *
mux_client_request_info(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e, *ਸੁਨੇਹਾ;
	u_int type, rid, ਸਥਿਤੀ;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ਵਾਪਸ 0;
	}

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ਜੇ (type != MUX_S_EXT_INFO) {
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ਜੇ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ਜੇ ((r = sshbuf_get_u32(m, &ਸਥਿਤੀ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ਵਾਪਸ ਸੁਨੇਹਾ;
}

ਸਥਿਰ ਖਾਲੀ
mux_client_request_terminate(ਪੂਰਨ fd)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e;
	u_int type, rid;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ਜੇ (errno == EPIPE) {
			sshbuf_free(m);
			ਵਾਪਸ;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ਚੋਣ (type) {
	ਹਾਲਤ MUX_S_OK:
		ਰੋਕੋ;
	ਹਾਲਤ MUX_S_PERMISSION_DENIED:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	ਹਾਲਤ MUX_S_FAILURE:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	ਮੂਲ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_forward(ਪੂਰਨ fd, ਪੂਰਨ cancel_flag, u_int ftype, ਬਣਤਰ Forward *fwd)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e, *fwd_desc;
	ਅਚਲ ਅੱਖਰ *lhost, *chost;
	u_int type, rid;
	ਪੂਰਨ r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	ਮੁਕਤ(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ)
		lhost = fwd->listen_ਰਸਤਾ;
	ਨਹੀਂਤਾਂ ਜੇ (fwd->listen_host == ਨਿਰਾ)
		lhost = "";
	ਨਹੀਂਤਾਂ ਜੇ (*fwd->listen_host == '\0')
		lhost = "*";
	ਨਹੀਂਤਾਂ
		lhost = fwd->listen_host;

	ਜੇ (fwd->connect_ਰਸਤਾ != ਨਿਰਾ)
		chost = fwd->connect_ਰਸਤਾ;
	ਨਹੀਂਤਾਂ ਜੇ (fwd->connect_host == ਨਿਰਾ)
		chost = "";
	ਨਹੀਂਤਾਂ
		chost = fwd->connect_host;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_ਪੋਰਟ)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_ਪੋਰਟ)) != 0)
		fatal_fr(r, "request");

	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ਵਾਪਸ -1;
	}

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ਚੋਣ (type) {
	ਹਾਲਤ MUX_S_OK:
		ਰੋਕੋ;
	ਹਾਲਤ MUX_S_REMOTE_ਪੋਰਟ:
		ਜੇ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ਜੇ ((r = sshbuf_get_u32(m, &fwd->allocated_ਪੋਰਟ)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_ਪੋਰਟ,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_ਪੋਰਟ);
		ਜੇ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_ਪੋਰਟ);
		ਰੋਕੋ;
	ਹਾਲਤ MUX_S_PERMISSION_DENIED:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ਵਾਪਸ -1;
	ਹਾਲਤ MUX_S_FAILURE:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ਵਾਪਸ -1;
	ਮੂਲ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_forwards(ਪੂਰਨ fd, ਪੂਰਨ cancel_flag)
{
	ਪੂਰਨ i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.ਅੰਕ_local_forwards, options.ਅੰਕ_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	ਲਈ (i = 0; i < options.ਅੰਕ_local_forwards; i++) {
		ਜੇ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_ਪੋਰਟ == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	ਲਈ (i = 0; i < options.ਅੰਕ_remote_forwards; i++) {
		ਜੇ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_request_session(ਪੂਰਨ fd)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e;
	ਅਚਲ ਅੱਖਰ *ਪਦ = ਨਿਰਾ;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_ਵੇਖਿਆ;
	ਬਾਹਰੀ ਅੱਖਰ **environ;
	ਪੂਰਨ r, rawmode = 0;

	debug3_f("entering");

	ਜੇ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ਵਾਪਸ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ਜੇ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ਜੇ ((ਪਦ = lookup_env_ਵਿੱਚ_list("TERM", options.setenv,
	    options.ਅੰਕ_setenv)) == ਨਿਰਾ || *ਪਦ == '\0')
		ਪਦ = getenv("TERM");

	echar = 0xffffffff;
	ਜੇ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ਨਿਰਾ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, ਪਦ == ਨਿਰਾ ? "" : ਪਦ)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	ਜੇ (options.ਅੰਕ_send_env > 0 && environ != ਨਿਰਾ) {
		ਲਈ (i = 0; environ[i] != ਨਿਰਾ; i++) {
			ਜੇ (!env_permitted(environ[i]))
				ਜਾਰੀ;
			ਜੇ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	ਲਈ (i = 0; i < options.ਅੰਕ_setenv; i++) {
		ਜੇ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ਜੇ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ਵਾਪਸ -1;
	}

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ਚੋਣ (type) {
	ਹਾਲਤ MUX_S_SESSION_OPENED:
		ਜੇ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ਰੋਕੋ;
	ਹਾਲਤ MUX_S_PERMISSION_DENIED:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ਵਾਪਸ -1;
	ਹਾਲਤ MUX_S_FAILURE:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ਵਾਪਸ -1;
	ਮੂਲ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ਵਾਪਸ -1;
	}
	muxclient_request_id++;

	ਜੇ (pledge("stdio proc tty", ਨਿਰਾ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ਜੇ (options.fork_after_authentication)
		daemon(1, 1);
	ਨਹੀਂਤਾਂ {
		rawmode = tty_flag;
		ਜੇ (tty_flag) {
			enter_raw_ਬਹੁਲਕ(
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
	ਲਈ (exitval = 255, exitval_ਵੇਖਿਆ = 0;;) {
		sshbuf_reset(m);
		ਜੇ (mux_client_read_packet(fd, m) != 0)
			ਰੋਕੋ;
		ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		ਚੋਣ (type) {
		ਹਾਲਤ MUX_S_TTY_ALLOC_FAIL:
			ਜੇ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ਜੇ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_ਬਹੁਲਕ(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			ਜਾਰੀ;
		ਹਾਲਤ MUX_S_EXIT_ਸੁਨੇਹਾ:
			ਜੇ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ਜੇ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ਜੇ (exitval_ਵੇਖਿਆ)
				fatal_f("exitval sent twice");
			ਜੇ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_ਵੇਖਿਆ = 1;
			ਜਾਰੀ;
		ਮੂਲ:
			ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ਜੇ (rawmode)
		leave_raw_ਬਹੁਲਕ(options.request_tty == REQUEST_TTY_FORCE);

	ਜੇ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} ਨਹੀਂਤਾਂ ਜੇ (!exitval_ਵੇਖਿਆ) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} ਨਹੀਂਤਾਂ
		debug2("Received exit status from master %d", exitval);

	ਜੇ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	ਬਾਹਰ_ਨਿਕਲੋ(exitval);
}

ਸਥਿਰ ਪੂਰਨ
mux_client_proxy(ਪੂਰਨ fd)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e;
	u_int type, rid;
	ਪੂਰਨ r;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ਵਾਪਸ 0;
	}
	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ਜੇ (type != MUX_S_PROXY) {
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
mux_client_request_stdio_fwd(ਪੂਰਨ fd)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e;
	u_int type, rid, sid;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ਵਾਪਸ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ਜੇ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ਨਿਰਾ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_ਪੋਰਟ)) != 0)
		fatal_fr(r, "request");

	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ਜੇ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ਜੇ (pledge("stdio proc tty", ਨਿਰਾ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ਵਾਪਸ -1;
	}

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ਚੋਣ (type) {
	ਹਾਲਤ MUX_S_SESSION_OPENED:
		ਜੇ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ਰੋਕੋ;
	ਹਾਲਤ MUX_S_PERMISSION_DENIED:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	ਹਾਲਤ MUX_S_FAILURE:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	ਮੂਲ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ਵਾਪਸ -1;
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
	ਜੇ (mux_client_read_packet(fd, m) != 0) {
		ਜੇ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ਵਾਪਸ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

ਸਥਿਰ ਖਾਲੀ
mux_client_request_stop_listening(ਪੂਰਨ fd)
{
	ਬਣਤਰ sshbuf *m;
	ਅੱਖਰ *e;
	u_int type, rid;
	ਪੂਰਨ r;

	debug3_f("entering");

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new");
	ਜੇ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ਜੇ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ਜੇ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ਜੇ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ਜੇ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ਚੋਣ (type) {
	ਹਾਲਤ MUX_S_OK:
		ਰੋਕੋ;
	ਹਾਲਤ MUX_S_PERMISSION_DENIED:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	ਹਾਲਤ MUX_S_FAILURE:
		ਜੇ ((r = sshbuf_get_cstring(m, &e, ਨਿਰਾ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	ਮੂਲ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
ਪੂਰਨ
muxclient(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ sockaddr_un addr;
	ਪੂਰਨ sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	ਅੱਖਰ *info = ਨਿਰਾ;

	ਜੇ (muxclient_command == 0) {
		ਜੇ (options.stdio_forward_host != ਨਿਰਾ)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		ਨਹੀਂਤਾਂ
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	ਚੋਣ (options.control_master) {
	ਹਾਲਤ SSHCTL_MASTER_AUTO:
	ਹਾਲਤ SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", ਰਸਤਾ);
		/* FALLTHROUGH */
	ਹਾਲਤ SSHCTL_MASTER_NO:
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}

	memset(&addr, '\0', ਆਕਾਰ(addr));
	addr.sun_family = AF_UNIX;

	ਜੇ (strlcpy(addr.sun_ਰਸਤਾ, ਰਸਤਾ,
	    ਆਕਾਰ(addr.sun_ਰਸਤਾ)) >= ਆਕਾਰ(addr.sun_ਰਸਤਾ))
		fatal("ControlPath too long ('%s' >= %u bytes)", ਰਸਤਾ,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ)ਆਕਾਰ(addr.sun_ਰਸਤਾ));

	ਜੇ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ਜੇ (connect(sock, (ਬਣਤਰ sockaddr *)&addr, ਆਕਾਰ(addr)) == -1) {
		ਚੋਣ (muxclient_command) {
		ਹਾਲਤ SSHMUX_COMMAND_OPEN:
		ਹਾਲਤ SSHMUX_COMMAND_STDIO_FWD:
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("Control socket connect(%.100s): %s", ਰਸਤਾ,
			    strerror(errno));
		}
		ਜੇ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", ਰਸਤਾ);
			unlink(ਰਸਤਾ);
		} ਨਹੀਂਤਾਂ ਜੇ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", ਰਸਤਾ);
		} ਨਹੀਂਤਾਂ {
			error("Control socket connect(%.100s): %s", ਰਸਤਾ,
			    strerror(errno));
		}
		close(sock);
		ਵਾਪਸ -1;
	}
	ਸੈੱਟ_nonblock(sock);

	/* Timeout on initial connection only. */
	ਜੇ (timeout > 0 && timeout < ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ / 1000)
		timeout_ms = timeout * 1000;

	ਜੇ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ਵਾਪਸ -1;
	}

	ਚੋਣ (muxclient_command) {
	ਹਾਲਤ SSHMUX_COMMAND_ALIVE_CHECK:
		ਜੇ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	ਹਾਲਤ SSHMUX_COMMAND_CONNINFO:
	ਹਾਲਤ SSHMUX_COMMAND_CHANINFO:
		ਜੇ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ਜੇ (info == ਨਿਰਾ)
			fatal_f("info request failed");
		ਲਿਖੋ("%s", info);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	ਹਾਲਤ SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ਜੇ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	ਹਾਲਤ SSHMUX_COMMAND_FORWARD:
		ਜੇ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	ਹਾਲਤ SSHMUX_COMMAND_OPEN:
		ਜੇ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ਵਾਪਸ -1;
		}
		mux_client_request_session(sock);
		ਵਾਪਸ -1;
	ਹਾਲਤ SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	ਹਾਲਤ SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ਜੇ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	ਹਾਲਤ SSHMUX_COMMAND_CANCEL_FWD:
		ਜੇ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		ਬਾਹਰ_ਨਿਕਲੋ(0);
	ਹਾਲਤ SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ਵਾਪਸ (sock);
	ਮੂਲ:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
