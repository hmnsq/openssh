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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <poll.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "monitor_fdpass.h"
#ಅನ್ತರ್ಭಾವ "sshpty.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "clientloop.h"

/* from ssh.c */
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ tty_flag;
ಬಾಹ್ಯ Options options;
ಬಾಹ್ಯ ಅಕ್ಷರ *host;
ಬಾಹ್ಯ ರಚನೆ sshbuf *command;
ಬಾಹ್ಯ ಅಸ್ಥಿರ sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
ರಚನೆ mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	ರಚನೆ sshbuf *cmd;
	ಅಕ್ಷರ *ಪದ;
	ರಚನೆ termios tio;
	ಅಕ್ಷರ **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
ರಚನೆ mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
ರಚನೆ mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	ಪೂರ್ಣಾಂಕ fid;	/* forward id */
};

/* fd to control socket */
ಪೂರ್ಣಾಂಕ muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
ಸ್ಥಿರ u_int muxserver_pid = 0;

ಸ್ಥಿರ Channel *mux_listener_channel = ಖಾಲಿ;

ರಚನೆ mux_master_state {
	ಪೂರ್ಣಾಂಕ hello_rcvd;
};

/* mux protocol messages */
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_ಸಂದೇಶ_HELLO		0x00000001
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_NEW_SESSION	0x10000002
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_ALIVE_CHECK	0x10000004
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_TERMINATE		0x10000005
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_OPEN_FWD		0x10000006
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_CLOSE_FWD		0x10000007
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_NEW_STDIO_FWD	0x10000008
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_STOP_LISTENING	0x10000009
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_PROXY		0x1000000f
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_C_EXT_INFO		0x20000001
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_OK		0x80000001
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_PERMISSION_DENIED	0x80000002
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_FAILURE		0x80000003
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_EXIT_ಸಂದೇಶ	0x80000004
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_ALIVE		0x80000005
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_SESSION_OPENED	0x80000006
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_REMOTE_ಪೋರ್ಟ್	0x80000007
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_TTY_ALLOC_FAIL	0x80000008
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_PROXY		0x8000000f
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_S_EXT_INFO		0x90000001

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_FWD_LOCAL   1
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_FWD_REMOTE  2
#ವ್ಯಾಖ್ಯಾನಿಸು MUX_FWD_DYNAMIC 3

#ವ್ಯಾಖ್ಯಾನಿಸು MUX_EXT_INFO		0x00000001

/* Bitmask of supported extensions */
ಸ್ಥಿರ u_int extensions = 0;

ಸ್ಥಿರ ಶೂನ್ಯ mux_session_confirm(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *);
ಸ್ಥಿರ ಶೂನ್ಯ mux_stdio_confirm(ರಚನೆ ssh *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಶೂನ್ಯ *);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_hello(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_new_session(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_alive_check(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_terminate(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_open_fwd(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_close_fwd(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_stdio_fwd(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_stop_listening(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_proxy(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_process_ext_info(ರಚನೆ ssh *, u_int,
	    Channel *, ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ {
	u_int type;
	ಪೂರ್ಣಾಂಕ (*handler)(ರಚನೆ ssh *, u_int, Channel *,
	    ರಚನೆ sshbuf *, ರಚನೆ sshbuf *);
} mux_master_handlers[] = {
	{ MUX_ಸಂದೇಶ_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, ಖಾಲಿ }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
ಸ್ಥಿರ ಶೂನ್ಯ
mux_master_session_cleanup_cb(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ cid, ಪೂರ್ಣಾಂಕ force, ಶೂನ್ಯ *ಬಳಸದ)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ಆದರೆ (c == ಖಾಲಿ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ಆದರೆ (c->ctl_chan != -1) {
		ಆದರೆ ((cc = channel_by_id(ssh, c->ctl_chan)) == ಖಾಲಿ)
			fatal_f("channel %d missing control channel %d",
			    c->self, c->ctl_chan);
		c->ctl_chan = -1;
		cc->ctl_ಮಗು_id = 0;
		cc->have_ctl_ಮಗು_id = 0;
		chan_rcvd_oclose(ssh, cc);
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Cleanup callback fired on closure of mux client _control_ channel */
ಸ್ಥಿರ ಶೂನ್ಯ
mux_master_control_cleanup_cb(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ cid, ಪೂರ್ಣಾಂಕ force, ಶೂನ್ಯ *ಬಳಸದ)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ಆದರೆ (c == ಖಾಲಿ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ಆದರೆ (c->have_ctl_ಮಗು_id) {
		ಆದರೆ ((sc = channel_by_id(ssh, c->ctl_ಮಗು_id)) == ಖಾಲಿ)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_ಮಗು_id);
		c->ctl_ಮಗು_id = 0;
		c->have_ctl_ಮಗು_id = 0;
		sc->ctl_chan = -1;
		ಆದರೆ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (sc->istate == CHAN_ಒಳಹರಿವು_OPEN)
				chan_read_failed(ssh, sc);
			ಆದರೆ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
env_permitted(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *env)
{
	u_int i;
	ಪೂರ್ಣಾಂಕ ret;
	ಅಕ್ಷರ name[1024], *cp;

	ಆದರೆ ((cp = strchr(env, '=')) == ಖಾಲಿ || cp == env)
		ಹಿಂತಿರುಗಿ 0;
	ret = snprintf(name, ಗಾತ್ರ(name), "%.*s", (ಪೂರ್ಣಾಂಕ)(cp - env), env);
	ಆದರೆ (ret <= 0 || (ಗಾತ್ರ_t)ret >= ಗಾತ್ರ(name)) {
		error_f("name '%.100s...' too long", env);
		ಹಿಂತಿರುಗಿ 0;
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_send_env; i++)
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(name, options.send_env[i]))
			ಹಿಂತಿರುಗಿ 1;

	ಹಿಂತಿರುಗಿ 0;
}

/* Mux master protocol message handlers */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_hello(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	u_int ver;
	ರಚನೆ mux_master_state *state = (ರಚನೆ mux_master_state *)c->mux_ctx;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (state == ಖಾಲಿ)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ಆದರೆ (state->hello_rcvd) {
		error_f("HELLO received twice");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ಹಿಂತಿರುಗಿ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ಆಗ (sshbuf_len(m) > 0) {
		ಅಕ್ಷರ *name = ಖಾಲಿ;
		ಗಾತ್ರ_t ಮೌಲ್ಯ_len = 0;

		ಆದರೆ ((r = sshbuf_get_cstring(m, &name, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_get_string_ನೇರ(m, ಖಾಲಿ, &ಮೌಲ್ಯ_len)) != 0) {
			error_fr(r, "parse extension");
			ಹಿಂತಿರುಗಿ -1;
		}
		ಆದರೆ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, ಮೌಲ್ಯ_len);
		}
		ಬಿಡುಗಡೆ(name);
	}
	state->hello_rcvd = 1;
	ಹಿಂತಿರುಗಿ 0;
}

/* Enqueue a "ok" response to the reply buffer */
ಸ್ಥಿರ ಶೂನ್ಯ
ಉತ್ತರ_ok(ರಚನೆ sshbuf *ಉತ್ತರ, u_int rid)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ಸ್ಥಿರ ಶೂನ್ಯ
ಉತ್ತರ_error(ರಚನೆ sshbuf *ಉತ್ತರ, u_int type, u_int rid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ, type)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, rid)) != 0 ||
	    (r = sshbuf_put_cstring(ಉತ್ತರ, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "reply");
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_new_session(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	Channel *nc;
	ರಚನೆ mux_session_confirm_ctx *cctx;
	ಅಕ್ಷರ *cmd, *cp;
	u_int i, j, env_len, escape_char, ಕಿಟಕಿ, packetmax;
	ಪೂರ್ಣಾಂಕ r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, ಗಾತ್ರ(*cctx));
	cctx->ಪದ = ಖಾಲಿ;
	cctx->rid = rid;
	cmd = ಖಾಲಿ;
	cctx->env = ಖಾಲಿ;
	env_len = 0;
	ಆದರೆ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->ಪದ, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, ಖಾಲಿ)) != 0) {
 malf:
		ಬಿಡುಗಡೆ(cmd);
		ಗಾಗಿ (j = 0; j < env_len; j++)
			ಬಿಡುಗಡೆ(cctx->env[j]);
		ಬಿಡುಗಡೆ(cctx->env);
		ಬಿಡುಗಡೆ(cctx->ಪದ);
		ಬಿಡುಗಡೆ(cctx);
		error_f("malformed message");
		ಹಿಂತಿರುಗಿ -1;
	}

#ವ್ಯಾಖ್ಯಾನಿಸು MUX_MAX_ENV_VARS	4096
	ಆಗ (sshbuf_len(m) > 0) {
		ಆದರೆ ((r = sshbuf_get_cstring(m, &cp, ಖಾಲಿ)) != 0)
			ಹೋಗು malf;
		ಆದರೆ (!env_permitted(cp)) {
			ಬಿಡುಗಡೆ(cp);
			ಮುಂದುವರಿ;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    ಗಾತ್ರ(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = ಖಾಲಿ;
		ಆದರೆ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			ನಿಲ್ಲಿಸು;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->ಪದ, cmd, env_len);

	ಆದರೆ ((cctx->cmd = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put(cctx->cmd, cmd, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	ಬಿಡುಗಡೆ(cmd);
	cmd = ಖಾಲಿ;

	/* Gather fds from client */
	ಗಾಗಿ(i = 0; i < 3; i++) {
		ಆದರೆ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ಗಾಗಿ (j = 0; j < i; j++)
				close(new_fd[j]);
			ಗಾಗಿ (j = 0; j < env_len; j++)
				ಬಿಡುಗಡೆ(cctx->env[j]);
			ಬಿಡುಗಡೆ(cctx->env);
			ಬಿಡುಗಡೆ(cctx->ಪದ);
			sshbuf_free(cctx->cmd);
			ಬಿಡುಗಡೆ(cctx);
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ಆದರೆ (c->have_ctl_ಮಗು_id) {
		debug2_f("session already open");
		ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		ಬಿಡುಗಡೆ(cctx->ಪದ);
		ಆದರೆ (env_len != 0) {
			ಗಾಗಿ (i = 0; i < env_len; i++)
				ಬಿಡುಗಡೆ(cctx->env[i]);
			ಬಿಡುಗಡೆ(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		ಬಿಡುಗಡೆ(cctx);
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಆದರೆ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಹೋಗು cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ಆದರೆ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	ಕಿಟಕಿ = CHAN_SES_ಕಿಟಕಿ_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ಆದರೆ (cctx->want_tty) {
		ಕಿಟಕಿ >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], ಕಿಟಕಿ, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ಆದರೆ (cctx->want_tty)
		channel_ಗಣ_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_ಮಗು_id = nc->self;	/* link control -> session channel */
	c->have_ctl_ಮಗು_id = 1;

	ಆದರೆ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_ರಿಜಿಸ್ಟರ್_filter(ssh, nc->self,
		    client_simple_escape_filter, ಖಾಲಿ,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((ಪೂರ್ಣಾಂಕ)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_ರಿಜಿಸ್ಟರ್_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_alive_check(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	ಪೂರ್ಣಾಂಕ r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, rid)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ಹಿಂತಿರುಗಿ 0;
}

/* The "info" extension. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_ext_info(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	ಪೂರ್ಣಾಂಕ r;
	u_int ಸ್ಥಿತಿ_2 = 0;
	ಅಕ್ಷರ *name = ಖಾಲಿ, *ಸಂದೇಶ = ಖಾಲಿ;

	debug2_f("channel %d: info request", c->self);

	ಆದರೆ ((r = sshbuf_get_cstring(m, &name, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse");

	ಆದರೆ (strcmp(name, "connection") == 0) {
		ಆದರೆ ((ಸಂದೇಶ = connection_info_ಸಂದೇಶ(ssh)) == ಖಾಲಿ)
			fatal_f("connection_info_message");
		ಸ್ಥಿತಿ_2 = 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(name, "channels") == 0) {
		ಆದರೆ ((ಸಂದೇಶ = channel_open_ಸಂದೇಶ(ssh)) == ಖಾಲಿ)
			fatal_f("channel_open_message");
		ಸ್ಥಿತಿ_2 = 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಸಂದೇಶ = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, rid)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, ಸ್ಥಿತಿ_2)) != 0 ||
	    (r = sshbuf_put_cstring(ಉತ್ತರ, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "reply");
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_terminate(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	debug2_f("channel %d: terminate request", c->self);

	ಆದರೆ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಆದರೆ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಹಿಂತಿರುಗಿ 0;
		}
	}

	quit_pending = 1;
	ಉತ್ತರ_ok(ಉತ್ತರ, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
format_forward(u_int ftype, ರಚನೆ Forward *fwd)
{
	ಅಕ್ಷರ *ret;

	ಆಯ್ಕೆ (ftype) {
	ಸ್ಥಿತಿ MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) ? fwd->listen_ಮಾರ್ಗ :
		    (fwd->listen_host == ಖಾಲಿ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_ಪೋರ್ಟ್,
		    (fwd->connect_ಮಾರ್ಗ != ಖಾಲಿ) ? fwd->connect_ಮಾರ್ಗ :
		    fwd->connect_host, fwd->connect_ಪೋರ್ಟ್);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == ಖಾಲಿ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_ಪೋರ್ಟ್);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ) ? fwd->listen_ಮಾರ್ಗ :
		    (fwd->listen_host == ಖಾಲಿ) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_ಪೋರ್ಟ್,
		    (fwd->connect_ಮಾರ್ಗ != ಖಾಲಿ) ? fwd->connect_ಮಾರ್ಗ :
		    fwd->connect_host, fwd->connect_ಪೋರ್ಟ್);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unknown forward type %u", ftype);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
compare_host(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *b)
{
	ಆದರೆ (a == ಖಾಲಿ && b == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 1;
	ಆದರೆ (a == ಖಾಲಿ || b == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ strcmp(a, b) == 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
compare_forward(ರಚನೆ Forward *a, ರಚನೆ Forward *b)
{
	ಆದರೆ (!compare_host(a->listen_host, b->listen_host))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!compare_host(a->listen_ಮಾರ್ಗ, b->listen_ಮಾರ್ಗ))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (a->listen_ಪೋರ್ಟ್ != b->listen_ಪೋರ್ಟ್)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!compare_host(a->connect_host, b->connect_host))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!compare_host(a->connect_ಮಾರ್ಗ, b->connect_ಮಾರ್ಗ))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (a->connect_ಪೋರ್ಟ್ != b->connect_ಪೋರ್ಟ್)
		ಹಿಂತಿರುಗಿ 0;

	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_confirm_remote_forward(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type, uint32_t seq, ಶೂನ್ಯ *ctxt)
{
	ರಚನೆ mux_channel_confirm_ctx *fctx = ctxt;
	ಅಕ್ಷರ *failmsg = ಖಾಲಿ;
	ರಚನೆ Forward *rfwd;
	Channel *c;
	ರಚನೆ sshbuf *ಹೊರಹೋಗು;
	u_int ಪೋರ್ಟ್;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((c = channel_by_id(ssh, fctx->cid)) == ಖಾಲಿ) {
		/* no channel for reply */
		error_f("unknown channel");
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((ಹೊರಹೋಗು = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ (fctx->fid >= options.ಅಂಕೆ_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_ಮಾರ್ಗ == ಖಾಲಿ &&
	    options.remote_forwards[fctx->fid].connect_host == ಖಾಲಿ)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		ಹೋಗು fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_ಪೋರ್ಟ್, rfwd->connect_ಮಾರ್ಗ ? rfwd->connect_ಮಾರ್ಗ :
	    rfwd->connect_host, rfwd->connect_ಪೋರ್ಟ್);
	ಆದರೆ (type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS) {
		ಆದರೆ (rfwd->listen_ಪೋರ್ಟ್ == 0) {
			ಆದರೆ ((r = sshpkt_get_u32(ssh, &ಪೋರ್ಟ್)) != 0)
				fatal_fr(r, "parse port");
			ಆದರೆ (ಪೋರ್ಟ್ > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", ಪೋರ್ಟ್,
				    rfwd->connect_host, rfwd->connect_ಪೋರ್ಟ್);
			}
			rfwd->allocated_ಪೋರ್ಟ್ = (ಪೂರ್ಣಾಂಕ)ಪೋರ್ಟ್;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_ಪೋರ್ಟ್,
			    rfwd->connect_host, rfwd->connect_ಪೋರ್ಟ್);
			ಆದರೆ ((r = sshbuf_put_u32(ಹೊರಹೋಗು,
			    MUX_S_REMOTE_ಪೋರ್ಟ್)) != 0 ||
			    (r = sshbuf_put_u32(ಹೊರಹೋಗು, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(ಹೊರಹೋಗು,
			    rfwd->allocated_ಪೋರ್ಟ್)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_ಪೋರ್ಟ್);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಉತ್ತರ_ok(ಹೊರಹೋಗು, fctx->rid);
		}
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (rfwd->listen_ಪೋರ್ಟ್ == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ಆದರೆ (rfwd->listen_ಮಾರ್ಗ != ಖಾಲಿ)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_ಮಾರ್ಗ);
		ಇಲ್ಲದಿದ್ದರೆ
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_ಪೋರ್ಟ್);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_ಪೋರ್ಟ್,
		    rfwd->connect_ಮಾರ್ಗ ? rfwd->connect_ಮಾರ್ಗ :
		    rfwd->connect_host, rfwd->connect_ಪೋರ್ಟ್);

		ಬಿಡುಗಡೆ(rfwd->listen_host);
		ಬಿಡುಗಡೆ(rfwd->listen_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(rfwd->connect_host);
		ಬಿಡುಗಡೆ(rfwd->connect_ಮಾರ್ಗ);
		memset(rfwd, 0, ಗಾತ್ರ(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	ಉತ್ತರ_error(ಹೊರಹೋಗು, MUX_S_FAILURE, fctx->rid, failmsg);
	ಬಿಡುಗಡೆ(failmsg);
 ಹೊರಹೋಗು:
	ಆದರೆ ((r = sshbuf_put_stringb(c->output, ಹೊರಹೋಗು)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ಹೊರಹೋಗು);
	ಆದರೆ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	ಬಿಡುಗಡೆ(fctx);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_open_fwd(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	ರಚನೆ Forward fwd;
	ಅಕ್ಷರ *fwd_desc = ಖಾಲಿ;
	ಅಕ್ಷರ *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	ಪೂರ್ಣಾಂಕ r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, ಗಾತ್ರ(fwd));

	/* XXX - lport/cport check redundant */
	ಆದರೆ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)ಪೋರ್ಟ್_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)ಪೋರ್ಟ್_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (*listen_addr == '\0') {
		ಬಿಡುಗಡೆ(listen_addr);
		listen_addr = ಖಾಲಿ;
	}
	ಆದರೆ (*connect_addr == '\0') {
		ಬಿಡುಗಡೆ(connect_addr);
		connect_addr = ಖಾಲಿ;
	}

	memset(&fwd, 0, ಗಾತ್ರ(fwd));
	fwd.listen_ಪೋರ್ಟ್ = lport;
	ಆದರೆ (fwd.listen_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL)
		fwd.listen_ಮಾರ್ಗ = listen_addr;
	ಇಲ್ಲದಿದ್ದರೆ
		fwd.listen_host = listen_addr;
	fwd.connect_ಪೋರ್ಟ್ = cport;
	ಆದರೆ (fwd.connect_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL)
		fwd.connect_ಮಾರ್ಗ = connect_addr;
	ಇಲ್ಲದಿದ್ದರೆ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ಆದರೆ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		ಬಿಡುಗಡೆ(listen_addr);
		ಬಿಡುಗಡೆ(connect_addr);
		ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ (ftype == MUX_FWD_DYNAMIC && fwd.listen_ಮಾರ್ಗ) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		ಹೋಗು invalid;
	}
	ಆದರೆ (fwd.listen_ಪೋರ್ಟ್ != ಪೋರ್ಟ್_STREAMLOCAL && fwd.listen_ಪೋರ್ಟ್ >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_ಪೋರ್ಟ್);
		ಹೋಗು invalid;
	}
	ಆದರೆ ((fwd.connect_ಪೋರ್ಟ್ != ಪೋರ್ಟ್_STREAMLOCAL &&
	    fwd.connect_ಪೋರ್ಟ್ >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_ಪೋರ್ಟ್ == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_ಪೋರ್ಟ್);
		ಹೋಗು invalid;
	}
	ಆದರೆ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == ಖಾಲಿ &&
	    fwd.connect_ಮಾರ್ಗ == ಖಾಲಿ) {
		logit_f("missing connect host");
		ಹೋಗು invalid;
	}

	/* Skip forwards that have already been requested */
	ಆಯ್ಕೆ (ftype) {
	ಸ್ಥಿತಿ MUX_FWD_LOCAL:
	ಸ್ಥಿತಿ MUX_FWD_DYNAMIC:
		ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
			ಆದರೆ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				ಉತ್ತರ_ok(ಉತ್ತರ, rid);
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_FWD_REMOTE:
		ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
			ಆದರೆ (!compare_forward(&fwd, options.remote_forwards + i))
				ಮುಂದುವರಿ;
			ಆದರೆ (fwd.listen_ಪೋರ್ಟ್ != 0)
				ಹೋಗು exists;
			debug2_f("found allocated port");
			ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ,
			    MUX_S_REMOTE_ಪೋರ್ಟ್)) != 0 ||
			    (r = sshbuf_put_u32(ಉತ್ತರ, rid)) != 0 ||
			    (r = sshbuf_put_u32(ಉತ್ತರ,
			    options.remote_forwards[i].allocated_ಪೋರ್ಟ್)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ನಿಲ್ಲಿಸು;
	}

	ಆದರೆ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಆದರೆ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	ಆದರೆ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ಆದರೆ (!channel_ಸಿದ್ಧತೆ_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಕೂಡಿಸು_local_forward(&options, &fwd);
		freefwd = 0;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ರಚನೆ mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ಆದರೆ (fwd.handle < 0)
			ಹೋಗು fail;
		ಕೂಡಿಸು_remote_forward(&options, &fwd);
		fctx = xcalloc(1, ಗಾತ್ರ(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.ಅಂಕೆ_remote_forwards - 1;
		client_ರಿಜಿಸ್ಟರ್_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಉತ್ತರ_ok(ಉತ್ತರ, rid);
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(fwd_desc);
	ಆದರೆ (freefwd) {
		ಬಿಡುಗಡೆ(fwd.listen_host);
		ಬಿಡುಗಡೆ(fwd.listen_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(fwd.connect_host);
		ಬಿಡುಗಡೆ(fwd.connect_ಮಾರ್ಗ);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_close_fwd(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	ರಚನೆ Forward fwd, *ಸಿಕ್ಕಿತು_fwd;
	ಅಕ್ಷರ *fwd_desc = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *error_reason = ಖಾಲಿ;
	ಅಕ್ಷರ *listen_addr = ಖಾಲಿ, *connect_addr = ಖಾಲಿ;
	u_int ftype;
	ಪೂರ್ಣಾಂಕ r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, ಗಾತ್ರ(fwd));

	ಆದರೆ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)ಪೋರ್ಟ್_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)ಪೋರ್ಟ್_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (*listen_addr == '\0') {
		ಬಿಡುಗಡೆ(listen_addr);
		listen_addr = ಖಾಲಿ;
	}
	ಆದರೆ (*connect_addr == '\0') {
		ಬಿಡುಗಡೆ(connect_addr);
		connect_addr = ಖಾಲಿ;
	}

	memset(&fwd, 0, ಗಾತ್ರ(fwd));
	fwd.listen_ಪೋರ್ಟ್ = lport;
	ಆದರೆ (fwd.listen_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL)
		fwd.listen_ಮಾರ್ಗ = listen_addr;
	ಇಲ್ಲದಿದ್ದರೆ
		fwd.listen_host = listen_addr;
	fwd.connect_ಪೋರ್ಟ್ = cport;
	ಆದರೆ (fwd.connect_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL)
		fwd.connect_ಮಾರ್ಗ = connect_addr;
	ಇಲ್ಲದಿದ್ದರೆ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	ಸಿಕ್ಕಿತು_fwd = ಖಾಲಿ;
	ಆಯ್ಕೆ (ftype) {
	ಸ್ಥಿತಿ MUX_FWD_LOCAL:
	ಸ್ಥಿತಿ MUX_FWD_DYNAMIC:
		ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
			ಆದರೆ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				ಸಿಕ್ಕಿತು_fwd = options.local_forwards + i;
				ನಿಲ್ಲಿಸು;
			}
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_FWD_REMOTE:
		ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
			ಆದರೆ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				ಸಿಕ್ಕಿತು_fwd = options.remote_forwards + i;
				ನಿಲ್ಲಿಸು;
			}
		}
		ನಿಲ್ಲಿಸು;
	}

	ಆದರೆ (ಸಿಕ್ಕಿತು_fwd == ಖಾಲಿ)
		error_reason = "port not forwarded";
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ಆದರೆ (channel_request_rforward_cancel(ssh, ಸಿಕ್ಕಿತು_fwd) == -1)
			error_reason = "port not in permitted opens";
	} ಇಲ್ಲದಿದ್ದರೆ {	/* local and dynamic forwards */
		/* Ditto */
		ಆದರೆ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_ಪೋರ್ಟ್,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ಆದರೆ (error_reason != ಖಾಲಿ)
		ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, rid, error_reason);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಉತ್ತರ_ok(ಉತ್ತರ, rid);
		ಬಿಡುಗಡೆ(ಸಿಕ್ಕಿತು_fwd->listen_host);
		ಬಿಡುಗಡೆ(ಸಿಕ್ಕಿತು_fwd->listen_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(ಸಿಕ್ಕಿತು_fwd->connect_host);
		ಬಿಡುಗಡೆ(ಸಿಕ್ಕಿತು_fwd->connect_ಮಾರ್ಗ);
		ಸಿಕ್ಕಿತು_fwd->listen_host = ಸಿಕ್ಕಿತು_fwd->connect_host = ಖಾಲಿ;
		ಸಿಕ್ಕಿತು_fwd->listen_ಮಾರ್ಗ = ಸಿಕ್ಕಿತು_fwd->connect_ಮಾರ್ಗ = ಖಾಲಿ;
		ಸಿಕ್ಕಿತು_fwd->listen_ಪೋರ್ಟ್ = ಸಿಕ್ಕಿತು_fwd->connect_ಪೋರ್ಟ್ = 0;
	}
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(fwd_desc);
	ಬಿಡುಗಡೆ(listen_addr);
	ಬಿಡುಗಡೆ(connect_addr);

	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_stdio_fwd(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	Channel *nc;
	ಅಕ್ಷರ *chost = ಖಾಲಿ;
	u_int _cport, i, j;
	ಪೂರ್ಣಾಂಕ ok = 0, cport, r, new_fd[2];
	ರಚನೆ mux_stdio_confirm_ctx *cctx;

	ಆದರೆ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		ಬಿಡುಗಡೆ(chost);
		error_f("malformed message");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (_cport == (u_int)ಪೋರ್ಟ್_STREAMLOCAL)
		cport = ಪೋರ್ಟ್_STREAMLOCAL;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (_cport <= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ)
		cport = (ಪೂರ್ಣಾಂಕ)_cport;
	ಇಲ್ಲದಿದ್ದರೆ {
		ಬಿಡುಗಡೆ(chost);
		error_f("invalid port 0x%x", _cport);
		ಹಿಂತಿರುಗಿ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	ಗಾಗಿ(i = 0; i < 2; i++) {
		ಆದರೆ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ಗಾಗಿ (j = 0; j < i; j++)
				close(new_fd[j]);
			ಬಿಡುಗಡೆ(chost);

			/* prepare reply */
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ಆದರೆ (c->have_ctl_ಮಗು_id) {
		debug2_f("session already open");
		ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		ಬಿಡುಗಡೆ(chost);
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಆದರೆ (cport == ಪೋರ್ಟ್_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ಆದರೆ (!ok) {
			debug2_f("stdio fwd refused by user");
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಹೋಗು cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	ಬಿಡುಗಡೆ(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_ಮಗು_id = nc->self;	/* link control -> session channel */
	c->have_ctl_ಮಗು_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, ಗಾತ್ರ(*cctx));
	cctx->rid = rid;
	channel_ರಿಜಿಸ್ಟರ್_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	ಹಿಂತಿರುಗಿ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ಸ್ಥಿರ ಶೂನ್ಯ
mux_stdio_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ success, ಶೂನ್ಯ *arg)
{
	ರಚನೆ mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	ರಚನೆ sshbuf *ಉತ್ತರ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (cctx == ಖಾಲಿ)
		fatal_f("cctx == NULL");
	ಆದರೆ ((c = channel_by_id(ssh, id)) == ಖಾಲಿ)
		fatal_f("no channel for id %d", id);
	ಆದರೆ ((cc = channel_by_id(ssh, c->ctl_chan)) == ಖಾಲಿ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ಆದರೆ ((ಉತ್ತರ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");

	ಆದರೆ (!success) {
		debug3_f("sending failure reply");
		ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		ಹೋಗು ಮುಗಿದ;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, c->self)) != 0)
		fatal_fr(r, "reply");

 ಮುಗಿದ:
	/* Send reply */
	ಆದರೆ ((r = sshbuf_put_stringb(cc->output, ಉತ್ತರ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ಉತ್ತರ);

	ಆದರೆ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(cctx);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_stop_listening(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	debug_f("channel %d: stop listening", c->self);

	ಆದರೆ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಆದರೆ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಹಿಂತಿರುಗಿ 0;
		}
	}

	ಆದರೆ (mux_listener_channel != ಖಾಲಿ) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		ಬಿಡುಗಡೆ(options.control_ಮಾರ್ಗ);
		options.control_ಮಾರ್ಗ = ಖಾಲಿ;
		mux_listener_channel = ಖಾಲಿ;
		muxserver_sock = -1;
	}

	ಉತ್ತರ_ok(ಉತ್ತರ, rid);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_process_proxy(ರಚನೆ ssh *ssh, u_int rid,
    Channel *c, ರಚನೆ sshbuf *m, ರಚನೆ sshbuf *ಉತ್ತರ)
{
	ಪೂರ್ಣಾಂಕ r;

	debug_f("channel %d: proxy request", c->self);

	ಆದರೆ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಆದರೆ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಹಿಂತಿರುಗಿ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, rid)) != 0)
		fatal_fr(r, "reply");

	ಹಿಂತಿರುಗಿ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_master_read_cb(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ mux_master_state *state = (ರಚನೆ mux_master_state *)c->mux_ctx;
	ರಚನೆ sshbuf *ಒಳ = ಖಾಲಿ, *ಹೊರಹೋಗು = ಖಾಲಿ;
	u_int type, rid, i;
	ಪೂರ್ಣಾಂಕ r, ret = -1;

	ಆದರೆ ((ಹೊರಹೋಗು = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ಆದರೆ (c->mux_ctx == ಖಾಲಿ) {
		state = xcalloc(1, ಗಾತ್ರ(*state));
		c->mux_ctx = state;
		channel_ರಿಜಿಸ್ಟರ್_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ಆದರೆ ((r = sshbuf_put_u32(ಹೊರಹೋಗು, MUX_ಸಂದೇಶ_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(ಹೊರಹೋಗು, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ಆದರೆ ((r = sshbuf_put_cstring(ಹೊರಹೋಗು, "info")) != 0 ||
		    (r = sshbuf_put_cstring(ಹೊರಹೋಗು, "0")) != 0)
			fatal_fr(r, "put info extension");
		ಆದರೆ ((r = sshbuf_put_stringb(c->output, ಹೊರಹೋಗು)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Channel code ensures that we receive whole packets */
	ಆದರೆ ((r = sshbuf_froms(c->ಒಳಹರಿವು, &ಒಳ)) != 0) {
 malf:
		error_f("malformed message");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshbuf_get_u32(ಒಳ, &type)) != 0)
		ಹೋಗು malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(ಒಳ));

	ಆದರೆ (type == MUX_ಸಂದೇಶ_HELLO)
		rid = 0;
	ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_ಸಂದೇಶ_HELLO, type);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_get_u32(ಒಳ, &rid)) != 0)
			ಹೋಗು malf;
	}

	ಗಾಗಿ (i = 0; mux_master_handlers[i].handler != ಖಾಲಿ; i++) {
		ಆದರೆ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, ಒಳ, ಹೊರಹೋಗು);
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (mux_master_handlers[i].handler == ಖಾಲಿ) {
		error_f("unsupported mux message 0x%08x", type);
		ಉತ್ತರ_error(ಹೊರಹೋಗು, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ಆದರೆ (sshbuf_len(ಹೊರಹೋಗು) != 0 &&
	    (r = sshbuf_put_stringb(c->output, ಹೊರಹೋಗು)) != 0)
		fatal_fr(r, "enqueue");
 ಹೊರಹೋಗು:
	sshbuf_free(ಒಳ);
	sshbuf_free(ಹೊರಹೋಗು);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
mux_exit_ಸಂದೇಶ(ರಚನೆ ssh *ssh, Channel *c, ಪೂರ್ಣಾಂಕ exitval)
{
	ರಚನೆ sshbuf *m;
	Channel *mux_chan;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ಆದರೆ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ಖಾಲಿ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_S_EXIT_ಸಂದೇಶ)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

ಶೂನ್ಯ
mux_tty_alloc_failed(ರಚನೆ ssh *ssh, Channel *c)
{
	ರಚನೆ sshbuf *m;
	Channel *mux_chan;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ಆದರೆ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ಖಾಲಿ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
ಶೂನ್ಯ
muxserver_listen(ರಚನೆ ssh *ssh)
{
	ಬಹುಲಕ_t old_umask;
	ಅಕ್ಷರ *orig_control_ಮಾರ್ಗ = options.control_ಮಾರ್ಗ;
	ಅಕ್ಷರ rbuf[16+1];
	u_int i, r;
	ಪೂರ್ಣಾಂಕ oerrno;

	ಆದರೆ (options.control_ಮಾರ್ಗ == ಖಾಲಿ ||
	    options.control_master == SSHCTL_MASTER_NO)
		ಹಿಂತಿರುಗಿ;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	ಗಾಗಿ (i = 0; i < ಗಾತ್ರ(rbuf) - 1; i++) {
		r = arc4random_ಏಕರೂಪ(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[ಗಾತ್ರ(rbuf) - 1] = '\0';
	options.control_ಮಾರ್ಗ = ಖಾಲಿ;
	xasprintf(&options.control_ಮಾರ್ಗ, "%s.%s", orig_control_ಮಾರ್ಗ, rbuf);
	debug3_f("temporary control path %s", options.control_ಮಾರ್ಗ);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_ಮಾರ್ಗ, 64, 0);
	oerrno = errno;
	umask(old_umask);
	ಆದರೆ (muxserver_sock < 0) {
		ಆದರೆ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_ಮಾರ್ಗ);
 disable_mux_master:
			ಆದರೆ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			ಬಿಡುಗಡೆ(orig_control_ಮಾರ್ಗ);
			ಬಿಡುಗಡೆ(options.control_ಮಾರ್ಗ);
			options.control_ಮಾರ್ಗ = ಖಾಲಿ;
			options.control_master = SSHCTL_MASTER_NO;
			ಹಿಂತಿರುಗಿ;
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ಆದರೆ (link(options.control_ಮಾರ್ಗ, orig_control_ಮಾರ್ಗ) != 0) {
		ಆದರೆ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_ಮಾರ್ಗ, orig_control_ಮಾರ್ಗ,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_ಮಾರ್ಗ);
		unlink(options.control_ಮಾರ್ಗ);
		ಹೋಗು disable_mux_master;
	}
	unlink(options.control_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(options.control_ಮಾರ್ಗ);
	options.control_ಮಾರ್ಗ = orig_control_ಮಾರ್ಗ;

	ಗಣ_nonblock(muxserver_sock);

	mux_listener_channel = channel_new(ssh, "mux listener",
	    SSH_CHANNEL_MUX_LISTENER, muxserver_sock, muxserver_sock, -1,
	    CHAN_TCP_ಕಿಟಕಿ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, options.control_ಮಾರ್ಗ, 1);
	mux_listener_channel->mux_rcb = mux_master_read_cb;
	debug3_f("mux listener channel %d fd %d",
	    mux_listener_channel->self, mux_listener_channel->sock);
}

/* Callback on open confirmation in mux master for a mux client session. */
ಸ್ಥಿರ ಶೂನ್ಯ
mux_session_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ success, ಶೂನ್ಯ *arg)
{
	ರಚನೆ mux_session_confirm_ctx *cctx = arg;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *display;
	Channel *c, *cc;
	ಪೂರ್ಣಾಂಕ i, r;
	ರಚನೆ sshbuf *ಉತ್ತರ;

	ಆದರೆ (cctx == ಖಾಲಿ)
		fatal_f("cctx == NULL");
	ಆದರೆ ((c = channel_by_id(ssh, id)) == ಖಾಲಿ)
		fatal_f("no channel for id %d", id);
	ಆದರೆ ((cc = channel_by_id(ssh, c->ctl_chan)) == ಖಾಲಿ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ಆದರೆ ((ಉತ್ತರ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");

	ಆದರೆ (!success) {
		debug3_f("sending failure reply");
		ಉತ್ತರ_error(ಉತ್ತರ, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		ಹೋಗು ಮುಗಿದ;
	}

	display = getenv("DISPLAY");
	ಆದರೆ (cctx->want_x_fwd && options.forward_x11 && display != ಖಾಲಿ) {
		ಅಕ್ಷರ *proto, *ದತ್ತಾಂಶ;

		/* Get reasonable local authentication information. */
		ಆದರೆ (client_x11_get_proto(ssh, display, options.xauth_location,
		    options.forward_x11_trusted, options.forward_x11_timeout,
		    &proto, &ದತ್ತಾಂಶ) == 0) {
			/* Request forwarding with authentication spoofing. */
			debug("Requesting X11 forwarding with authentication "
			    "spoofing.");
			x11_request_forwarding_with_spoofing(ssh, id,
			    display, proto, ದತ್ತಾಂಶ, 1);
			/* XXX exit_on_forward_failure */
			client_expect_confirm(ssh, id, "X11 forwarding",
			    CONFIRM_WARN);
		}
	}

	ಆದರೆ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_ಸಿದ್ಧತೆ(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->ಪದ, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ಆದರೆ ((r = sshbuf_put_u32(ಉತ್ತರ, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(ಉತ್ತರ, c->self)) != 0)
		fatal_fr(r, "reply");

 ಮುಗಿದ:
	/* Send reply */
	ಆದರೆ ((r = sshbuf_put_stringb(cc->output, ಉತ್ತರ)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(ಉತ್ತರ);

	ಆದರೆ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ಖಾಲಿ;
	sshbuf_free(cctx->cmd);
	ಬಿಡುಗಡೆ(cctx->ಪದ);
	ಆದರೆ (cctx->env != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; cctx->env[i] != ಖಾಲಿ; i++)
			ಬಿಡುಗಡೆ(cctx->env[i]);
		ಬಿಡುಗಡೆ(cctx->env);
	}
	ಬಿಡುಗಡೆ(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
ಸ್ಥಿರ ಶೂನ್ಯ
control_client_sighandler(ಪೂರ್ಣಾಂಕ signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
control_client_sigrelay(ಪೂರ್ಣಾಂಕ signo)
{
	ಪೂರ್ಣಾಂಕ save_errno = errno;

	ಆದರೆ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_read(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *b, ಗಾತ್ರ_t need, ಪೂರ್ಣಾಂಕ timeout_ms)
{
	ಗಾತ್ರ_t have;
	ssize_t len;
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	ಗಾಗಿ (have = 0; have < need; ) {
		ಆದರೆ (muxclient_terminate) {
			errno = EINTR;
			ಹಿಂತಿರುಗಿ -1;
		}
		len = ಪಠ(fd, p + have, need - have);
		ಆದರೆ (len == -1) {
			ಆಯ್ಕೆ (errno) {
#ಆದರೆ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ಸ್ಥಿತಿ EWOULDBLOCK:
#ಆದರೆ_ಅಂತ್ಯ
			ಸ್ಥಿತಿ EAGAIN:
				ಆದರೆ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ಹಿಂತಿರುಗಿ -1;	/* timeout */
				/* FALLTHROUGH */
			ಸ್ಥಿತಿ EINTR:
				ಮುಂದುವರಿ;
			ಪೂರ್ವನಿಯೋಜಿತ:
				ಹಿಂತಿರುಗಿ -1;
			}
		}
		ಆದರೆ (len == 0) {
			errno = EPIPE;
			ಹಿಂತಿರುಗಿ -1;
		}
		have += (ಗಾತ್ರ_t)len;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_write_packet(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *m)
{
	ರಚನೆ sshbuf *ಸರತಿ;
	u_int have, need;
	ಪೂರ್ಣಾಂಕ r, oerrno, len;
	ಸ್ಥಿರಾಂಕ u_char *ptr;
	ರಚನೆ pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ಆದರೆ ((ಸರತಿ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_stringb(ಸರತಿ, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(ಸರತಿ);
	ptr = sshbuf_ptr(ಸರತಿ);

	ಗಾಗಿ (have = 0; have < need; ) {
		ಆದರೆ (muxclient_terminate) {
			sshbuf_free(ಸರತಿ);
			errno = EINTR;
			ಹಿಂತಿರುಗಿ -1;
		}
		len = ಲಿಖ(fd, ptr + have, need - have);
		ಆದರೆ (len == -1) {
			ಆಯ್ಕೆ (errno) {
#ಆದರೆ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ಸ್ಥಿತಿ EWOULDBLOCK:
#ಆದರೆ_ಅಂತ್ಯ
			ಸ್ಥಿತಿ EAGAIN:
				(ಶೂನ್ಯ)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			ಸ್ಥಿತಿ EINTR:
				ಮುಂದುವರಿ;
			ಪೂರ್ವನಿಯೋಜಿತ:
				oerrno = errno;
				sshbuf_free(ಸರತಿ);
				errno = oerrno;
				ಹಿಂತಿರುಗಿ -1;
			}
		}
		ಆದರೆ (len == 0) {
			sshbuf_free(ಸರತಿ);
			errno = EPIPE;
			ಹಿಂತಿರುಗಿ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(ಸರತಿ);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_read_packet_timeout(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *m, ಪೂರ್ಣಾಂಕ timeout_ms)
{
	ರಚನೆ sshbuf *ಸರತಿ;
	ಗಾತ್ರ_t need, have;
	ಸ್ಥಿರಾಂಕ u_char *ptr;
	ಪೂರ್ಣಾಂಕ r, oerrno;

	ಆದರೆ ((ಸರತಿ = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ (mux_client_read(fd, ಸರತಿ, 4, timeout_ms) != 0) {
		ಆದರೆ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(ಸರತಿ);
		errno = oerrno;
		ಹಿಂತಿರುಗಿ -1;
	}
	need = PEEK_U32(sshbuf_ptr(ಸರತಿ));
	ಆದರೆ (mux_client_read(fd, ಸರತಿ, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(ಸರತಿ);
		errno = oerrno;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(ಸರತಿ, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(ಸರತಿ);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_read_packet(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *m)
{
	ಹಿಂತಿರುಗಿ mux_client_read_packet_timeout(fd, m, -1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_hello_exchange(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ timeout_ms)
{
	ರಚನೆ sshbuf *m;
	u_int type, ver;
	ಪೂರ್ಣಾಂಕ r, ret = -1;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_ಸಂದೇಶ_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ಆದರೆ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ಆದರೆ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ಆದರೆ (type != MUX_ಸಂದೇಶ_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_ಸಂದೇಶ_HELLO, type);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ಆದರೆ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ಆಗ (sshbuf_len(m) > 0) {
		ಅಕ್ಷರ *name = ಖಾಲಿ;

		ಆದರೆ ((r = sshbuf_get_cstring(m, &name, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*ಮೌಲ್ಯ*/
			error_fr(r, "parse extension");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Process extensions. */
		ಆದರೆ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		ಬಿಡುಗಡೆ(name);
	}
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ u_int
mux_client_request_alive(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e;
	u_int pid, type, rid;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ಆದರೆ (type != MUX_S_ALIVE) {
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಆದರೆ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ಹಿಂತಿರುಗಿ pid;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
mux_client_request_info(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e, *ಸಂದೇಶ;
	u_int type, rid, ಸ್ಥಿತಿ_2;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ 0;
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ಆದರೆ (type != MUX_S_EXT_INFO) {
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಆದರೆ ((r = sshbuf_get_u32(m, &ಸ್ಥಿತಿ_2)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ಸಂದೇಶ, ಖಾಲಿ)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ಹಿಂತಿರುಗಿ ಸಂದೇಶ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_client_request_terminate(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e;
	u_int type, rid;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ಆದರೆ (errno == EPIPE) {
			sshbuf_free(m);
			ಹಿಂತಿರುಗಿ;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ MUX_S_OK:
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_S_PERMISSION_DENIED:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	ಸ್ಥಿತಿ MUX_S_FAILURE:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_forward(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ cancel_flag, u_int ftype, ರಚನೆ Forward *fwd)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e, *fwd_desc;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *lhost, *chost;
	u_int type, rid;
	ಪೂರ್ಣಾಂಕ r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	ಬಿಡುಗಡೆ(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ)
		lhost = fwd->listen_ಮಾರ್ಗ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fwd->listen_host == ಖಾಲಿ)
		lhost = "";
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*fwd->listen_host == '\0')
		lhost = "*";
	ಇಲ್ಲದಿದ್ದರೆ
		lhost = fwd->listen_host;

	ಆದರೆ (fwd->connect_ಮಾರ್ಗ != ಖಾಲಿ)
		chost = fwd->connect_ಮಾರ್ಗ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fwd->connect_host == ಖಾಲಿ)
		chost = "";
	ಇಲ್ಲದಿದ್ದರೆ
		chost = fwd->connect_host;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_ಪೋರ್ಟ್)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_ಪೋರ್ಟ್)) != 0)
		fatal_fr(r, "request");

	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ MUX_S_OK:
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_S_REMOTE_ಪೋರ್ಟ್:
		ಆದರೆ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ಆದರೆ ((r = sshbuf_get_u32(m, &fwd->allocated_ಪೋರ್ಟ್)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_ಪೋರ್ಟ್,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_ಪೋರ್ಟ್);
		ಆದರೆ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_ಪೋರ್ಟ್);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_S_PERMISSION_DENIED:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಥಿತಿ MUX_S_FAILURE:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ಹಿಂತಿರುಗಿ -1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_forwards(ಪೂರ್ಣಾಂಕ fd, ಪೂರ್ಣಾಂಕ cancel_flag)
{
	ಪೂರ್ಣಾಂಕ i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.ಅಂಕೆ_local_forwards, options.ಅಂಕೆ_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
		ಆದರೆ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_ಪೋರ್ಟ್ == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
		ಆದರೆ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_request_session(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪದ = ಖಾಲಿ;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_ನೋಡಿದ;
	ಬಾಹ್ಯ ಅಕ್ಷರ **environ;
	ಪೂರ್ಣಾಂಕ r, rawmode = 0;

	debug3_f("entering");

	ಆದರೆ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ಹಿಂತಿರುಗಿ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ಆದರೆ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ಆದರೆ ((ಪದ = lookup_env_ಒಳ_list("TERM", options.setenv,
	    options.ಅಂಕೆ_setenv)) == ಖಾಲಿ || *ಪದ == '\0')
		ಪದ = getenv("TERM");

	echar = 0xffffffff;
	ಆದರೆ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ಖಾಲಿ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, ಪದ == ಖಾಲಿ ? "" : ಪದ)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	ಆದರೆ (options.ಅಂಕೆ_send_env > 0 && environ != ಖಾಲಿ) {
		ಗಾಗಿ (i = 0; environ[i] != ಖಾಲಿ; i++) {
			ಆದರೆ (!env_permitted(environ[i]))
				ಮುಂದುವರಿ;
			ಆದರೆ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_setenv; i++) {
		ಆದರೆ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ಆದರೆ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ MUX_S_SESSION_OPENED:
		ಆದರೆ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_S_PERMISSION_DENIED:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಥಿತಿ MUX_S_FAILURE:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ -1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ಹಿಂತಿರುಗಿ -1;
	}
	muxclient_request_id++;

	ಆದರೆ (pledge("stdio proc tty", ಖಾಲಿ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ಆದರೆ (options.fork_after_authentication)
		daemon(1, 1);
	ಇಲ್ಲದಿದ್ದರೆ {
		rawmode = tty_flag;
		ಆದರೆ (tty_flag) {
			enter_raw_ಬಹುಲಕ(
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
	ಗಾಗಿ (exitval = 255, exitval_ನೋಡಿದ = 0;;) {
		sshbuf_reset(m);
		ಆದರೆ (mux_client_read_packet(fd, m) != 0)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ MUX_S_TTY_ALLOC_FAIL:
			ಆದರೆ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ಆದರೆ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_ಬಹುಲಕ(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			ಮುಂದುವರಿ;
		ಸ್ಥಿತಿ MUX_S_EXIT_ಸಂದೇಶ:
			ಆದರೆ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ಆದರೆ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ಆದರೆ (exitval_ನೋಡಿದ)
				fatal_f("exitval sent twice");
			ಆದರೆ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_ನೋಡಿದ = 1;
			ಮುಂದುವರಿ;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ಆದರೆ (rawmode)
		leave_raw_ಬಹುಲಕ(options.request_tty == REQUEST_TTY_FORCE);

	ಆದರೆ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (!exitval_ನೋಡಿದ) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} ಇಲ್ಲದಿದ್ದರೆ
		debug2("Received exit status from master %d", exitval);

	ಆದರೆ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	ನಿರ್ಗಮಿಸು(exitval);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_proxy(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e;
	u_int type, rid;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಆದರೆ (type != MUX_S_PROXY) {
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mux_client_request_stdio_fwd(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e;
	u_int type, rid, sid;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ಹಿಂತಿರುಗಿ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ಆದರೆ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ಖಾಲಿ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_ಪೋರ್ಟ್)) != 0)
		fatal_fr(r, "request");

	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ಆದರೆ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ಆದರೆ (pledge("stdio proc tty", ಖಾಲಿ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ MUX_S_SESSION_OPENED:
		ಆದರೆ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_S_PERMISSION_DENIED:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	ಸ್ಥಿತಿ MUX_S_FAILURE:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	ಪೂರ್ವನಿಯೋಜಿತ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ಹಿಂತಿರುಗಿ -1;
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
	ಆದರೆ (mux_client_read_packet(fd, m) != 0) {
		ಆದರೆ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ಹಿಂತಿರುಗಿ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_client_request_stop_listening(ಪೂರ್ಣಾಂಕ fd)
{
	ರಚನೆ sshbuf *m;
	ಅಕ್ಷರ *e;
	u_int type, rid;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new");
	ಆದರೆ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ಆದರೆ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಆದರೆ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ಆದರೆ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಆದರೆ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ MUX_S_OK:
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ MUX_S_PERMISSION_DENIED:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	ಸ್ಥಿತಿ MUX_S_FAILURE:
		ಆದರೆ ((r = sshbuf_get_cstring(m, &e, ಖಾಲಿ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
ಪೂರ್ಣಾಂಕ
muxclient(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ sockaddr_un addr;
	ಪೂರ್ಣಾಂಕ sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	ಅಕ್ಷರ *info = ಖಾಲಿ;

	ಆದರೆ (muxclient_command == 0) {
		ಆದರೆ (options.stdio_forward_host != ಖಾಲಿ)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		ಇಲ್ಲದಿದ್ದರೆ
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	ಆಯ್ಕೆ (options.control_master) {
	ಸ್ಥಿತಿ SSHCTL_MASTER_AUTO:
	ಸ್ಥಿತಿ SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", ಮಾರ್ಗ);
		/* FALLTHROUGH */
	ಸ್ಥಿತಿ SSHCTL_MASTER_NO:
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}

	memset(&addr, '\0', ಗಾತ್ರ(addr));
	addr.sun_family = AF_UNIX;

	ಆದರೆ (strlcpy(addr.sun_ಮಾರ್ಗ, ಮಾರ್ಗ,
	    ಗಾತ್ರ(addr.sun_ಮಾರ್ಗ)) >= ಗಾತ್ರ(addr.sun_ಮಾರ್ಗ))
		fatal("ControlPath too long ('%s' >= %u bytes)", ಮಾರ್ಗ,
		    (ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ)ಗಾತ್ರ(addr.sun_ಮಾರ್ಗ));

	ಆದರೆ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ಆದರೆ (connect(sock, (ರಚನೆ sockaddr *)&addr, ಗಾತ್ರ(addr)) == -1) {
		ಆಯ್ಕೆ (muxclient_command) {
		ಸ್ಥಿತಿ SSHMUX_COMMAND_OPEN:
		ಸ್ಥಿತಿ SSHMUX_COMMAND_STDIO_FWD:
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("Control socket connect(%.100s): %s", ಮಾರ್ಗ,
			    strerror(errno));
		}
		ಆದರೆ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", ಮಾರ್ಗ);
			unlink(ಮಾರ್ಗ);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", ಮಾರ್ಗ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("Control socket connect(%.100s): %s", ಮಾರ್ಗ,
			    strerror(errno));
		}
		close(sock);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಗಣ_nonblock(sock);

	/* Timeout on initial connection only. */
	ಆದರೆ (timeout > 0 && timeout < ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ / 1000)
		timeout_ms = timeout * 1000;

	ಆದರೆ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆಯ್ಕೆ (muxclient_command) {
	ಸ್ಥಿತಿ SSHMUX_COMMAND_ALIVE_CHECK:
		ಆದರೆ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		ನಿರ್ಗಮಿಸು(0);
	ಸ್ಥಿತಿ SSHMUX_COMMAND_CONNINFO:
	ಸ್ಥಿತಿ SSHMUX_COMMAND_CHANINFO:
		ಆದರೆ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ಆದರೆ (info == ಖಾಲಿ)
			fatal_f("info request failed");
		ಬರೆ("%s", info);
		ನಿರ್ಗಮಿಸು(0);
	ಸ್ಥಿತಿ SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ಆದರೆ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		ನಿರ್ಗಮಿಸು(0);
	ಸ್ಥಿತಿ SSHMUX_COMMAND_FORWARD:
		ಆದರೆ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		ನಿರ್ಗಮಿಸು(0);
	ಸ್ಥಿತಿ SSHMUX_COMMAND_OPEN:
		ಆದರೆ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ಹಿಂತಿರುಗಿ -1;
		}
		mux_client_request_session(sock);
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಥಿತಿ SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		ನಿರ್ಗಮಿಸು(0);
	ಸ್ಥಿತಿ SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ಆದರೆ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		ನಿರ್ಗಮಿಸು(0);
	ಸ್ಥಿತಿ SSHMUX_COMMAND_CANCEL_FWD:
		ಆದರೆ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		ನಿರ್ಗಮಿಸು(0);
	ಸ್ಥಿತಿ SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ಹಿಂತಿರುಗಿ (sock);
	ಪೂರ್ವನಿಯೋಜಿತ:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
