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
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ tty_flag;
ಬಾಹ್ಯ Options options;
ಬಾಹ್ಯ ವರ್ಣ *host;
ಬಾಹ್ಯ ಸಂರಚನಾ sshbuf *command;
ಬಾಹ್ಯ ಚಞ್ಚಲ sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
ಸಂರಚನಾ mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	ಸಂರಚನಾ sshbuf *cmd;
	ವರ್ಣ *term;
	ಸಂರಚನಾ termios tio;
	ವರ್ಣ **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
ಸಂರಚನಾ mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
ಸಂರಚನಾ mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	ಪೂರ್ಣಾಙ್ಕ fid;	/* forward id */
};

/* fd to control socket */
ಪೂರ್ಣಾಙ್ಕ muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
ಸ್ಥಿರ u_int muxserver_pid = 0;

ಸ್ಥಿರ Channel *mux_listener_channel = ರಿಕ್ತ;

ಸಂರಚನಾ mux_master_state {
	ಪೂರ್ಣಾಙ್ಕ hello_rcvd;
};

/* mux protocol messages */
#define MUX_ಸಂದೇಶ_HELLO		0x00000001
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
ಸ್ಥಿರ u_int extensions = 0;

ಸ್ಥಿರ ಶೂನ್ಯ mux_session_confirm(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *);
ಸ್ಥಿರ ಶೂನ್ಯ mux_stdio_confirm(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಶೂನ್ಯ *);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_hello(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_new_session(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_alive_check(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_terminate(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_open_fwd(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_close_fwd(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_stdio_fwd(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_stop_listening(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_proxy(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_process_ext_info(ಸಂರಚನಾ ssh *, u_int,
	    Channel *, ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ {
	u_int type;
	ಪೂರ್ಣಾಙ್ಕ (*handler)(ಸಂರಚನಾ ssh *, u_int, Channel *,
	    ಸಂರಚನಾ sshbuf *, ಸಂರಚನಾ sshbuf *);
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
	{ 0, ರಿಕ್ತ }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
ಸ್ಥಿರ ಶೂನ್ಯ
mux_master_session_cleanup_cb(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ cid, ಪೂರ್ಣಾಙ್ಕ force, ಶೂನ್ಯ *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ಯದಿ (c == ರಿಕ್ತ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ಯದಿ (c->ctl_chan != -1) {
		ಯದಿ ((cc = channel_by_id(ssh, c->ctl_chan)) == ರಿಕ್ತ)
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
ಸ್ಥಿರ ಶೂನ್ಯ
mux_master_control_cleanup_cb(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ cid, ಪೂರ್ಣಾಙ್ಕ force, ಶೂನ್ಯ *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ಯದಿ (c == ರಿಕ್ತ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ಯದಿ (c->have_ctl_child_id) {
		ಯದಿ ((sc = channel_by_id(ssh, c->ctl_child_id)) == ರಿಕ್ತ)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		ಯದಿ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} ಅನ್ಯಥಾ {
			ಯದಿ (sc->istate == CHAN_ಒಳಹರಿವು_OPEN)
				chan_read_failed(ssh, sc);
			ಯದಿ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
env_permitted(ಧ್ರುವ ವರ್ಣ *env)
{
	u_int i;
	ಪೂರ್ಣಾಙ್ಕ ret;
	ವರ್ಣ name[1024], *cp;

	ಯದಿ ((cp = strchr(env, '=')) == ರಿಕ್ತ || cp == env)
		ಪ್ರತ್ಯಾಗಮ 0;
	ret = snprintf(name, ಪರಿಮಾಣ(name), "%.*s", (ಪೂರ್ಣಾಙ್ಕ)(cp - env), env);
	ಯದಿ (ret <= 0 || (size_t)ret >= ಪರಿಮಾಣ(name)) {
		error_f("name '%.100s...' too long", env);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_send_env; i++)
		ಯದಿ (match_pattern(name, options.send_env[i]))
			ಪ್ರತ್ಯಾಗಮ 1;

	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Mux master protocol message handlers */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_hello(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	u_int ver;
	ಸಂರಚನಾ mux_master_state *state = (ಸಂರಚನಾ mux_master_state *)c->mux_ctx;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (state == ರಿಕ್ತ)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ಯದಿ (state->hello_rcvd) {
		error_f("HELLO received twice");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ಯಾವತ್ (sshbuf_len(m) > 0) {
		ವರ್ಣ *name = ರಿಕ್ತ;
		size_t ಮೌಲ್ಯ_len = 0;

		ಯದಿ ((r = sshbuf_get_cstring(m, &name, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_get_string_direct(m, ರಿಕ್ತ, &ಮೌಲ್ಯ_len)) != 0) {
			error_fr(r, "parse extension");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		ಯದಿ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ಅನ್ಯಥಾ {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, ಮೌಲ್ಯ_len);
		}
		ಮುಕ್ತ(name);
	}
	state->hello_rcvd = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Enqueue a "ok" response to the reply buffer */
ಸ್ಥಿರ ಶೂನ್ಯ
reply_ok(ಸಂರಚನಾ sshbuf *reply, u_int rid)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ಸ್ಥಿರ ಶೂನ್ಯ
reply_error(ಸಂರಚನಾ sshbuf *reply, u_int type, u_int rid, ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "reply");
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_new_session(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	Channel *nc;
	ಸಂರಚನಾ mux_session_confirm_ctx *cctx;
	ವರ್ಣ *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	ಪೂರ್ಣಾಙ್ಕ r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, ಪರಿಮಾಣ(*cctx));
	cctx->term = ರಿಕ್ತ;
	cctx->rid = rid;
	cmd = ರಿಕ್ತ;
	cctx->env = ರಿಕ್ತ;
	env_len = 0;
	ಯದಿ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, ರಿಕ್ತ)) != 0) {
 malf:
		ಮುಕ್ತ(cmd);
		ಪ್ರತಿ (j = 0; j < env_len; j++)
			ಮುಕ್ತ(cctx->env[j]);
		ಮುಕ್ತ(cctx->env);
		ಮುಕ್ತ(cctx->term);
		ಮುಕ್ತ(cctx);
		error_f("malformed message");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

#define MUX_MAX_ENV_VARS	4096
	ಯಾವತ್ (sshbuf_len(m) > 0) {
		ಯದಿ ((r = sshbuf_get_cstring(m, &cp, ರಿಕ್ತ)) != 0)
			ಗಚ್ಛ malf;
		ಯದಿ (!env_permitted(cp)) {
			ಮುಕ್ತ(cp);
			ಅನುವರ್ತ;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    ಪರಿಮಾಣ(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = ರಿಕ್ತ;
		ಯದಿ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			ಭಙ್ಗ;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	ಯದಿ ((cctx->cmd = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	ಮುಕ್ತ(cmd);
	cmd = ರಿಕ್ತ;

	/* Gather fds from client */
	ಪ್ರತಿ(i = 0; i < 3; i++) {
		ಯದಿ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ಪ್ರತಿ (j = 0; j < i; j++)
				close(new_fd[j]);
			ಪ್ರತಿ (j = 0; j < env_len; j++)
				ಮುಕ್ತ(cctx->env[j]);
			ಮುಕ್ತ(cctx->env);
			ಮುಕ್ತ(cctx->term);
			sshbuf_free(cctx->cmd);
			ಮುಕ್ತ(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ಯದಿ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		ಮುಕ್ತ(cctx->term);
		ಯದಿ (env_len != 0) {
			ಪ್ರತಿ (i = 0; i < env_len; i++)
				ಮುಕ್ತ(cctx->env[i]);
			ಮುಕ್ತ(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		ಮುಕ್ತ(cctx);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಯದಿ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಗಚ್ಛ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ಯದಿ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ಯದಿ (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ಯದಿ (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	ಯದಿ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, ರಿಕ್ತ,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((ಪೂರ್ಣಾಙ್ಕ)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_alive_check(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ಯದಿ ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ಪ್ರತ್ಯಾಗಮ 0;
}

/* The "info" extension. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_ext_info(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	u_int status = 0;
	ವರ್ಣ *name = ರಿಕ್ತ, *ಸಂದೇಶ = ರಿಕ್ತ;

	debug2_f("channel %d: info request", c->self);

	ಯದಿ ((r = sshbuf_get_cstring(m, &name, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse");

	ಯದಿ (strcmp(name, "connection") == 0) {
		ಯದಿ ((ಸಂದೇಶ = connection_info_message(ssh)) == ರಿಕ್ತ)
			fatal_f("connection_info_message");
		status = 1;
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(name, "channels") == 0) {
		ಯದಿ ((ಸಂದೇಶ = channel_open_message(ssh)) == ರಿಕ್ತ)
			fatal_f("channel_open_message");
		status = 1;
	} ಅನ್ಯಥಾ {
		ಸಂದೇಶ = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ಯದಿ ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, ಸಂದೇಶ)) != 0)
		fatal_fr(r, "reply");
	ಮುಕ್ತ(ಸಂದೇಶ);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_terminate(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	ಯದಿ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಯದಿ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ವರ್ಣ *
format_forward(u_int ftype, ಸಂರಚನಾ Forward *fwd)
{
	ವರ್ಣ *ret;

	ವಿಕಲ್ಪ (ftype) {
	ಪಕ್ಷ MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ರಿಕ್ತ) ? fwd->listen_path :
		    (fwd->listen_host == ರಿಕ್ತ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != ರಿಕ್ತ) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == ರಿಕ್ತ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ರಿಕ್ತ) ? fwd->listen_path :
		    (fwd->listen_host == ರಿಕ್ತ) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != ರಿಕ್ತ) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		fatal_f("unknown forward type %u", ftype);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
compare_host(ಧ್ರುವ ವರ್ಣ *a, ಧ್ರುವ ವರ್ಣ *b)
{
	ಯದಿ (a == ರಿಕ್ತ && b == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಯದಿ (a == ರಿಕ್ತ || b == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ strcmp(a, b) == 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
compare_forward(ಸಂರಚನಾ Forward *a, ಸಂರಚನಾ Forward *b)
{
	ಯದಿ (!compare_host(a->listen_host, b->listen_host))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (!compare_host(a->listen_path, b->listen_path))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (a->listen_port != b->listen_port)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (!compare_host(a->connect_host, b->connect_host))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (!compare_host(a->connect_path, b->connect_path))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (a->connect_port != b->connect_port)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_confirm_remote_forward(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಶೂನ್ಯ *ctxt)
{
	ಸಂರಚನಾ mux_channel_confirm_ctx *fctx = ctxt;
	ವರ್ಣ *failmsg = ರಿಕ್ತ;
	ಸಂರಚನಾ Forward *rfwd;
	Channel *c;
	ಸಂರಚನಾ sshbuf *out;
	u_int port;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((c = channel_by_id(ssh, fctx->cid)) == ರಿಕ್ತ) {
		/* no channel for reply */
		error_f("unknown channel");
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((out = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ (fctx->fid >= options.ಅಂಕೆ_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == ರಿಕ್ತ &&
	    options.remote_forwards[fctx->fid].connect_host == ರಿಕ್ತ)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		ಗಚ್ಛ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	ಯದಿ (type == SSH2_ಸಂದೇಶ_REQUEST_SUCCESS) {
		ಯದಿ (rfwd->listen_port == 0) {
			ಯದಿ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			ಯದಿ (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (ಪೂರ್ಣಾಙ್ಕ)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			ಯದಿ ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} ಅನ್ಯಥಾ {
			reply_ok(out, fctx->rid);
		}
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ {
		ಯದಿ (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ಯದಿ (rfwd->listen_path != ರಿಕ್ತ)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		ಅನ್ಯಥಾ
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		ಮುಕ್ತ(rfwd->listen_host);
		ಮುಕ್ತ(rfwd->listen_path);
		ಮುಕ್ತ(rfwd->connect_host);
		ಮುಕ್ತ(rfwd->connect_path);
		memset(rfwd, 0, ಪರಿಮಾಣ(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	ಮುಕ್ತ(failmsg);
 out:
	ಯದಿ ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	ಯದಿ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	ಮುಕ್ತ(fctx);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_open_fwd(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	ಸಂರಚನಾ Forward fwd;
	ವರ್ಣ *fwd_desc = ರಿಕ್ತ;
	ವರ್ಣ *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	ಪೂರ್ಣಾಙ್ಕ r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, ಪರಿಮಾಣ(fwd));

	/* XXX - lport/cport check redundant */
	ಯದಿ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ಗಚ್ಛ out;
	}
	ಯದಿ (*listen_addr == '\0') {
		ಮುಕ್ತ(listen_addr);
		listen_addr = ರಿಕ್ತ;
	}
	ಯದಿ (*connect_addr == '\0') {
		ಮುಕ್ತ(connect_addr);
		connect_addr = ರಿಕ್ತ;
	}

	memset(&fwd, 0, ಪರಿಮಾಣ(fwd));
	fwd.listen_port = lport;
	ಯದಿ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ಅನ್ಯಥಾ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ಯದಿ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ಅನ್ಯಥಾ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ಯದಿ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		ಮುಕ್ತ(listen_addr);
		ಮುಕ್ತ(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		ಗಚ್ಛ invalid;
	}
	ಯದಿ (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		ಗಚ್ಛ invalid;
	}
	ಯದಿ ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		ಗಚ್ಛ invalid;
	}
	ಯದಿ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == ರಿಕ್ತ &&
	    fwd.connect_path == ರಿಕ್ತ) {
		logit_f("missing connect host");
		ಗಚ್ಛ invalid;
	}

	/* Skip forwards that have already been requested */
	ವಿಕಲ್ಪ (ftype) {
	ಪಕ್ಷ MUX_FWD_LOCAL:
	ಪಕ್ಷ MUX_FWD_DYNAMIC:
		ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
			ಯದಿ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				ಗಚ್ಛ out;
			}
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_FWD_REMOTE:
		ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
			ಯದಿ (!compare_forward(&fwd, options.remote_forwards + i))
				ಅನುವರ್ತ;
			ಯದಿ (fwd.listen_port != 0)
				ಗಚ್ಛ exists;
			debug2_f("found allocated port");
			ಯದಿ ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			ಗಚ್ಛ out;
		}
		ಭಙ್ಗ;
	}

	ಯದಿ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಯದಿ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಗಚ್ಛ out;
		}
	}

	ಯದಿ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ಯದಿ (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			ಗಚ್ಛ out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} ಅನ್ಯಥಾ {
		ಸಂರಚನಾ mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ಯದಿ (fwd.handle < 0)
			ಗಚ್ಛ fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, ಪರಿಮಾಣ(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.ಅಂಕೆ_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		ಗಚ್ಛ out;
	}
	reply_ok(reply, rid);
 out:
	ಮುಕ್ತ(fwd_desc);
	ಯದಿ (freefwd) {
		ಮುಕ್ತ(fwd.listen_host);
		ಮುಕ್ತ(fwd.listen_path);
		ಮುಕ್ತ(fwd.connect_host);
		ಮುಕ್ತ(fwd.connect_path);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_close_fwd(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	ಸಂರಚನಾ Forward fwd, *found_fwd;
	ವರ್ಣ *fwd_desc = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *error_reason = ರಿಕ್ತ;
	ವರ್ಣ *listen_addr = ರಿಕ್ತ, *connect_addr = ರಿಕ್ತ;
	u_int ftype;
	ಪೂರ್ಣಾಙ್ಕ r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, ಪರಿಮಾಣ(fwd));

	ಯದಿ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ಗಚ್ಛ out;
	}

	ಯದಿ (*listen_addr == '\0') {
		ಮುಕ್ತ(listen_addr);
		listen_addr = ರಿಕ್ತ;
	}
	ಯದಿ (*connect_addr == '\0') {
		ಮುಕ್ತ(connect_addr);
		connect_addr = ರಿಕ್ತ;
	}

	memset(&fwd, 0, ಪರಿಮಾಣ(fwd));
	fwd.listen_port = lport;
	ಯದಿ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ಅನ್ಯಥಾ
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ಯದಿ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ಅನ್ಯಥಾ
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = ರಿಕ್ತ;
	ವಿಕಲ್ಪ (ftype) {
	ಪಕ್ಷ MUX_FWD_LOCAL:
	ಪಕ್ಷ MUX_FWD_DYNAMIC:
		ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
			ಯದಿ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				ಭಙ್ಗ;
			}
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_FWD_REMOTE:
		ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
			ಯದಿ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				ಭಙ್ಗ;
			}
		}
		ಭಙ್ಗ;
	}

	ಯದಿ (found_fwd == ರಿಕ್ತ)
		error_reason = "port not forwarded";
	ಅನ್ಯಥಾ ಯದಿ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ಯದಿ (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} ಅನ್ಯಥಾ {	/* local and dynamic forwards */
		/* Ditto */
		ಯದಿ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ಯದಿ (error_reason != ರಿಕ್ತ)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	ಅನ್ಯಥಾ {
		reply_ok(reply, rid);
		ಮುಕ್ತ(found_fwd->listen_host);
		ಮುಕ್ತ(found_fwd->listen_path);
		ಮುಕ್ತ(found_fwd->connect_host);
		ಮುಕ್ತ(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = ರಿಕ್ತ;
		found_fwd->listen_path = found_fwd->connect_path = ರಿಕ್ತ;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	ಮುಕ್ತ(fwd_desc);
	ಮುಕ್ತ(listen_addr);
	ಮುಕ್ತ(connect_addr);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_stdio_fwd(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	Channel *nc;
	ವರ್ಣ *chost = ರಿಕ್ತ;
	u_int _cport, i, j;
	ಪೂರ್ಣಾಙ್ಕ ok = 0, cport, r, new_fd[2];
	ಸಂರಚನಾ mux_stdio_confirm_ctx *cctx;

	ಯದಿ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		ಮುಕ್ತ(chost);
		error_f("malformed message");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	ಅನ್ಯಥಾ ಯದಿ (_cport <= INT_MAX)
		cport = (ಪೂರ್ಣಾಙ್ಕ)_cport;
	ಅನ್ಯಥಾ {
		ಮುಕ್ತ(chost);
		error_f("invalid port 0x%x", _cport);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	ಪ್ರತಿ(i = 0; i < 2; i++) {
		ಯದಿ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ಪ್ರತಿ (j = 0; j < i; j++)
				close(new_fd[j]);
			ಮುಕ್ತ(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ಯದಿ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		ಮುಕ್ತ(chost);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಯದಿ (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} ಅನ್ಯಥಾ {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ಯದಿ (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಗಚ್ಛ cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	ಮುಕ್ತ(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, ಪರಿಮಾಣ(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ಸ್ಥಿರ ಶೂನ್ಯ
mux_stdio_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ success, ಶೂನ್ಯ *arg)
{
	ಸಂರಚನಾ mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	ಸಂರಚನಾ sshbuf *reply;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (cctx == ರಿಕ್ತ)
		fatal_f("cctx == NULL");
	ಯದಿ ((c = channel_by_id(ssh, id)) == ರಿಕ್ತ)
		fatal_f("no channel for id %d", id);
	ಯದಿ ((cc = channel_by_id(ssh, c->ctl_chan)) == ರಿಕ್ತ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ಯದಿ ((reply = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");

	ಯದಿ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		ಗಚ್ಛ done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ಯದಿ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ಯದಿ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ಯದಿ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ರಿಕ್ತ;
	ಮುಕ್ತ(cctx);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_stop_listening(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	ಯದಿ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಯದಿ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}

	ಯದಿ (mux_listener_channel != ರಿಕ್ತ) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		ಮುಕ್ತ(options.control_path);
		options.control_path = ರಿಕ್ತ;
		mux_listener_channel = ರಿಕ್ತ;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_process_proxy(ಸಂರಚನಾ ssh *ssh, u_int rid,
    Channel *c, ಸಂರಚನಾ sshbuf *m, ಸಂರಚನಾ sshbuf *reply)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	debug_f("channel %d: proxy request", c->self);

	ಯದಿ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ಯದಿ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ಯದಿ ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_master_read_cb(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ mux_master_state *state = (ಸಂರಚನಾ mux_master_state *)c->mux_ctx;
	ಸಂರಚನಾ sshbuf *in = ರಿಕ್ತ, *out = ರಿಕ್ತ;
	u_int type, rid, i;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;

	ಯದಿ ((out = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ಯದಿ (c->mux_ctx == ರಿಕ್ತ) {
		state = xcalloc(1, ಪರಿಮಾಣ(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ಯದಿ ((r = sshbuf_put_u32(out, MUX_ಸಂದೇಶ_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ಯದಿ ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		ಯದಿ ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		ಗಚ್ಛ out;
	}

	/* Channel code ensures that we receive whole packets */
	ಯದಿ ((r = sshbuf_froms(c->ಒಳಹರಿವು, &in)) != 0) {
 malf:
		error_f("malformed message");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshbuf_get_u32(in, &type)) != 0)
		ಗಚ್ಛ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	ಯದಿ (type == MUX_ಸಂದೇಶ_HELLO)
		rid = 0;
	ಅನ್ಯಥಾ {
		ಯದಿ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_ಸಂದೇಶ_HELLO, type);
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_get_u32(in, &rid)) != 0)
			ಗಚ್ಛ malf;
	}

	ಪ್ರತಿ (i = 0; mux_master_handlers[i].handler != ರಿಕ್ತ; i++) {
		ಯದಿ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (mux_master_handlers[i].handler == ರಿಕ್ತ) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ಯದಿ (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
mux_exit_message(ಸಂರಚನಾ ssh *ssh, Channel *c, ಪೂರ್ಣಾಙ್ಕ exitval)
{
	ಸಂರಚನಾ sshbuf *m;
	Channel *mux_chan;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ಯದಿ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ರಿಕ್ತ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

ಶೂನ್ಯ
mux_tty_alloc_failed(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	ಸಂರಚನಾ sshbuf *m;
	Channel *mux_chan;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ಯದಿ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ರಿಕ್ತ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
ಶೂನ್ಯ
muxserver_listen(ಸಂರಚನಾ ssh *ssh)
{
	mode_t old_umask;
	ವರ್ಣ *orig_control_path = options.control_path;
	ವರ್ಣ rbuf[16+1];
	u_int i, r;
	ಪೂರ್ಣಾಙ್ಕ oerrno;

	ಯದಿ (options.control_path == ರಿಕ್ತ ||
	    options.control_master == SSHCTL_MASTER_NO)
		ಪ್ರತ್ಯಾಗಮ;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	ಪ್ರತಿ (i = 0; i < ಪರಿಮಾಣ(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[ಪರಿಮಾಣ(rbuf) - 1] = '\0';
	options.control_path = ರಿಕ್ತ;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	ಯದಿ (muxserver_sock < 0) {
		ಯದಿ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			ಯದಿ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			ಮುಕ್ತ(orig_control_path);
			ಮುಕ್ತ(options.control_path);
			options.control_path = ರಿಕ್ತ;
			options.control_master = SSHCTL_MASTER_NO;
			ಪ್ರತ್ಯಾಗಮ;
		} ಅನ್ಯಥಾ {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ಯದಿ (link(options.control_path, orig_control_path) != 0) {
		ಯದಿ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		ಗಚ್ಛ disable_mux_master;
	}
	unlink(options.control_path);
	ಮುಕ್ತ(options.control_path);
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
ಸ್ಥಿರ ಶೂನ್ಯ
mux_session_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ success, ಶೂನ್ಯ *arg)
{
	ಸಂರಚನಾ mux_session_confirm_ctx *cctx = arg;
	ಧ್ರುವ ವರ್ಣ *display;
	Channel *c, *cc;
	ಪೂರ್ಣಾಙ್ಕ i, r;
	ಸಂರಚನಾ sshbuf *reply;

	ಯದಿ (cctx == ರಿಕ್ತ)
		fatal_f("cctx == NULL");
	ಯದಿ ((c = channel_by_id(ssh, id)) == ರಿಕ್ತ)
		fatal_f("no channel for id %d", id);
	ಯದಿ ((cc = channel_by_id(ssh, c->ctl_chan)) == ರಿಕ್ತ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ಯದಿ ((reply = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");

	ಯದಿ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		ಗಚ್ಛ done;
	}

	display = getenv("DISPLAY");
	ಯದಿ (cctx->want_x_fwd && options.forward_x11 && display != ರಿಕ್ತ) {
		ವರ್ಣ *proto, *data;

		/* Get reasonable local authentication information. */
		ಯದಿ (client_x11_get_proto(ssh, display, options.xauth_location,
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

	ಯದಿ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ಯದಿ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ಯದಿ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ಯದಿ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ರಿಕ್ತ;
	sshbuf_free(cctx->cmd);
	ಮುಕ್ತ(cctx->term);
	ಯದಿ (cctx->env != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; cctx->env[i] != ರಿಕ್ತ; i++)
			ಮುಕ್ತ(cctx->env[i]);
		ಮುಕ್ತ(cctx->env);
	}
	ಮುಕ್ತ(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
ಸ್ಥಿರ ಶೂನ್ಯ
control_client_sighandler(ಪೂರ್ಣಾಙ್ಕ signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
control_client_sigrelay(ಪೂರ್ಣಾಙ್ಕ signo)
{
	ಪೂರ್ಣಾಙ್ಕ save_errno = errno;

	ಯದಿ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_read(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *b, size_t need, ಪೂರ್ಣಾಙ್ಕ timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	ಪ್ರತಿ (have = 0; have < need; ) {
		ಯದಿ (muxclient_terminate) {
			errno = EINTR;
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		len = ಪಠ(fd, p + have, need - have);
		ಯದಿ (len == -1) {
			ವಿಕಲ್ಪ (errno) {
#ಯದಿ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ಪಕ್ಷ EWOULDBLOCK:
#endif
			ಪಕ್ಷ EAGAIN:
				ಯದಿ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ಪ್ರತ್ಯಾಗಮ -1;	/* timeout */
				/* FALLTHROUGH */
			ಪಕ್ಷ EINTR:
				ಅನುವರ್ತ;
			ಸ್ವಭಾವ:
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		}
		ಯದಿ (len == 0) {
			errno = EPIPE;
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		have += (size_t)len;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_write_packet(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *m)
{
	ಸಂರಚನಾ sshbuf *queue;
	u_int have, need;
	ಪೂರ್ಣಾಙ್ಕ r, oerrno, len;
	ಧ್ರುವ u_char *ptr;
	ಸಂರಚನಾ pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ಯದಿ ((queue = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	ಪ್ರತಿ (have = 0; have < need; ) {
		ಯದಿ (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		len = ಲಿಖ(fd, ptr + have, need - have);
		ಯದಿ (len == -1) {
			ವಿಕಲ್ಪ (errno) {
#ಯದಿ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ಪಕ್ಷ EWOULDBLOCK:
#endif
			ಪಕ್ಷ EAGAIN:
				(ಶೂನ್ಯ)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			ಪಕ್ಷ EINTR:
				ಅನುವರ್ತ;
			ಸ್ವಭಾವ:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		}
		ಯದಿ (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_read_packet_timeout(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *m, ಪೂರ್ಣಾಙ್ಕ timeout_ms)
{
	ಸಂರಚನಾ sshbuf *queue;
	size_t need, have;
	ಧ್ರುವ u_char *ptr;
	ಪೂರ್ಣಾಙ್ಕ r, oerrno;

	ಯದಿ ((queue = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		ಯದಿ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	ಯದಿ (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_read_packet(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *m)
{
	ಪ್ರತ್ಯಾಗಮ mux_client_read_packet_timeout(fd, m, -1);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_hello_exchange(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ timeout_ms)
{
	ಸಂರಚನಾ sshbuf *m;
	u_int type, ver;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_ಸಂದೇಶ_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ಯದಿ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		ಗಚ್ಛ out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ಯದಿ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ಯದಿ (type != MUX_ಸಂದೇಶ_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_ಸಂದೇಶ_HELLO, type);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ಯದಿ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		ಗಚ್ಛ out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ಯಾವತ್ (sshbuf_len(m) > 0) {
		ವರ್ಣ *name = ರಿಕ್ತ;

		ಯದಿ ((r = sshbuf_get_cstring(m, &name, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*ಮೌಲ್ಯ*/
			error_fr(r, "parse extension");
			ಗಚ್ಛ out;
		}
		/* Process extensions. */
		ಯದಿ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ಅನ್ಯಥಾ {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		ಮುಕ್ತ(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ u_int
mux_client_request_alive(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e;
	u_int pid, type, rid;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ಯದಿ (type != MUX_S_ALIVE) {
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಯದಿ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ಪ್ರತ್ಯಾಗಮ pid;
}

ಸ್ಥಿರ ವರ್ಣ *
mux_client_request_info(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e, *ಸಂದೇಶ;
	u_int type, rid, status;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ಯದಿ (type != MUX_S_EXT_INFO) {
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಯದಿ ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ಸಂದೇಶ, ರಿಕ್ತ)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ಪ್ರತ್ಯಾಗಮ ಸಂದೇಶ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_client_request_terminate(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e;
	u_int type, rid;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ಯದಿ (errno == EPIPE) {
			sshbuf_free(m);
			ಪ್ರತ್ಯಾಗಮ;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ MUX_S_OK:
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_S_PERMISSION_DENIED:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	ಪಕ್ಷ MUX_S_FAILURE:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	ಸ್ವಭಾವ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_forward(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ cancel_flag, u_int ftype, ಸಂರಚನಾ Forward *fwd)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e, *fwd_desc;
	ಧ್ರುವ ವರ್ಣ *lhost, *chost;
	u_int type, rid;
	ಪೂರ್ಣಾಙ್ಕ r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	ಮುಕ್ತ(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ)
		lhost = fwd->listen_path;
	ಅನ್ಯಥಾ ಯದಿ (fwd->listen_host == ರಿಕ್ತ)
		lhost = "";
	ಅನ್ಯಥಾ ಯದಿ (*fwd->listen_host == '\0')
		lhost = "*";
	ಅನ್ಯಥಾ
		lhost = fwd->listen_host;

	ಯದಿ (fwd->connect_path != ರಿಕ್ತ)
		chost = fwd->connect_path;
	ಅನ್ಯಥಾ ಯದಿ (fwd->connect_host == ರಿಕ್ತ)
		chost = "";
	ಅನ್ಯಥಾ
		chost = fwd->connect_host;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ MUX_S_OK:
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_S_REMOTE_PORT:
		ಯದಿ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ಯದಿ ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		ಯದಿ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_S_PERMISSION_DENIED:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪಕ್ಷ MUX_S_FAILURE:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ಪ್ರತ್ಯಾಗಮ -1;
	ಸ್ವಭಾವ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_forwards(ಪೂರ್ಣಾಙ್ಕ fd, ಪೂರ್ಣಾಙ್ಕ cancel_flag)
{
	ಪೂರ್ಣಾಙ್ಕ i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.ಅಂಕೆ_local_forwards, options.ಅಂಕೆ_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_local_forwards; i++) {
		ಯದಿ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_remote_forwards; i++) {
		ಯದಿ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_request_session(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e;
	ಧ್ರುವ ವರ್ಣ *term = ರಿಕ್ತ;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	ಬಾಹ್ಯ ವರ್ಣ **environ;
	ಪೂರ್ಣಾಙ್ಕ r, rawmode = 0;

	debug3_f("entering");

	ಯದಿ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ಯದಿ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ಯದಿ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.ಅಂಕೆ_setenv)) == ರಿಕ್ತ || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	ಯದಿ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ರಿಕ್ತ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == ರಿಕ್ತ ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	ಯದಿ (options.ಅಂಕೆ_send_env > 0 && environ != ರಿಕ್ತ) {
		ಪ್ರತಿ (i = 0; environ[i] != ರಿಕ್ತ; i++) {
			ಯದಿ (!env_permitted(environ[i]))
				ಅನುವರ್ತ;
			ಯದಿ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_setenv; i++) {
		ಯದಿ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ಯದಿ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ MUX_S_SESSION_OPENED:
		ಯದಿ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_S_PERMISSION_DENIED:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪಕ್ಷ MUX_S_FAILURE:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ -1;
	ಸ್ವಭಾವ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	muxclient_request_id++;

	ಯದಿ (pledge("stdio proc tty", ರಿಕ್ತ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ಯದಿ (options.fork_after_authentication)
		daemon(1, 1);
	ಅನ್ಯಥಾ {
		rawmode = tty_flag;
		ಯದಿ (tty_flag) {
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
	ಪ್ರತಿ (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		ಯದಿ (mux_client_read_packet(fd, m) != 0)
			ಭಙ್ಗ;
		ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ MUX_S_TTY_ALLOC_FAIL:
			ಯದಿ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ಯದಿ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			ಅನುವರ್ತ;
		ಪಕ್ಷ MUX_S_EXIT_MESSAGE:
			ಯದಿ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ಯದಿ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ಯದಿ (exitval_seen)
				fatal_f("exitval sent twice");
			ಯದಿ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			ಅನುವರ್ತ;
		ಸ್ವಭಾವ:
			ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ಯದಿ (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	ಯದಿ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} ಅನ್ಯಥಾ ಯದಿ (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} ಅನ್ಯಥಾ
		debug2("Received exit status from master %d", exitval);

	ಯದಿ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_proxy(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e;
	u_int type, rid;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ಯದಿ (type != MUX_S_PROXY) {
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mux_client_request_stdio_fwd(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e;
	u_int type, rid, sid;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ಯದಿ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ರಿಕ್ತ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ಯದಿ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ಯದಿ (pledge("stdio proc tty", ರಿಕ್ತ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ MUX_S_SESSION_OPENED:
		ಯದಿ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_S_PERMISSION_DENIED:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	ಪಕ್ಷ MUX_S_FAILURE:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	ಸ್ವಭಾವ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ಪ್ರತ್ಯಾಗಮ -1;
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
	ಯದಿ (mux_client_read_packet(fd, m) != 0) {
		ಯದಿ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

ಸ್ಥಿರ ಶೂನ್ಯ
mux_client_request_stop_listening(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಸಂರಚನಾ sshbuf *m;
	ವರ್ಣ *e;
	u_int type, rid;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");

	ಯದಿ ((m = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new");
	ಯದಿ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ಯದಿ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ಯದಿ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ಯದಿ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ಯದಿ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ MUX_S_OK:
		ಭಙ್ಗ;
	ಪಕ್ಷ MUX_S_PERMISSION_DENIED:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	ಪಕ್ಷ MUX_S_FAILURE:
		ಯದಿ ((r = sshbuf_get_cstring(m, &e, ರಿಕ್ತ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	ಸ್ವಭಾವ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
ಪೂರ್ಣಾಙ್ಕ
muxclient(ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ sockaddr_un addr;
	ಪೂರ್ಣಾಙ್ಕ sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	ವರ್ಣ *info = ರಿಕ್ತ;

	ಯದಿ (muxclient_command == 0) {
		ಯದಿ (options.stdio_forward_host != ರಿಕ್ತ)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		ಅನ್ಯಥಾ
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	ವಿಕಲ್ಪ (options.control_master) {
	ಪಕ್ಷ SSHCTL_MASTER_AUTO:
	ಪಕ್ಷ SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	ಪಕ್ಷ SSHCTL_MASTER_NO:
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	memset(&addr, '\0', ಪರಿಮಾಣ(addr));
	addr.sun_family = AF_UNIX;

	ಯದಿ (strlcpy(addr.sun_path, path,
	    ಪರಿಮಾಣ(addr.sun_path)) >= ಪರಿಮಾಣ(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned ಪೂರ್ಣಾಙ್ಕ)ಪರಿಮಾಣ(addr.sun_path));

	ಯದಿ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ಯದಿ (connect(sock, (ಸಂರಚನಾ sockaddr *)&addr, ಪರಿಮಾಣ(addr)) == -1) {
		ವಿಕಲ್ಪ (muxclient_command) {
		ಪಕ್ಷ SSHMUX_COMMAND_OPEN:
		ಪಕ್ಷ SSHMUX_COMMAND_STDIO_FWD:
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		ಯದಿ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} ಅನ್ಯಥಾ ಯದಿ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} ಅನ್ಯಥಾ {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	ಯದಿ (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	ಯದಿ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ವಿಕಲ್ಪ (muxclient_command) {
	ಪಕ್ಷ SSHMUX_COMMAND_ALIVE_CHECK:
		ಯದಿ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	ಪಕ್ಷ SSHMUX_COMMAND_CONNINFO:
	ಪಕ್ಷ SSHMUX_COMMAND_CHANINFO:
		ಯದಿ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ಯದಿ (info == ರಿಕ್ತ)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	ಪಕ್ಷ SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ಯದಿ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	ಪಕ್ಷ SSHMUX_COMMAND_FORWARD:
		ಯದಿ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	ಪಕ್ಷ SSHMUX_COMMAND_OPEN:
		ಯದಿ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		mux_client_request_session(sock);
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪಕ್ಷ SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	ಪಕ್ಷ SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ಯದಿ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	ಪಕ್ಷ SSHMUX_COMMAND_CANCEL_FWD:
		ಯದಿ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	ಪಕ್ಷ SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ಪ್ರತ್ಯಾಗಮ (sock);
	ಸ್ವಭಾವ:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
