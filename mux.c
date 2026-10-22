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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <poll.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "monitor_fdpass.h"
#అన్తర్భావ "sshpty.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "clientloop.h"

/* from ssh.c */
బాహ్య పూర్ణాంకం tty_flag;
బాహ్య Options options;
బాహ్య అక్షరం *host;
బాహ్య నిర్మాణం sshbuf *command;
బాహ్య అస్థిర sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
నిర్మాణం mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	నిర్మాణం sshbuf *cmd;
	అక్షరం *పదం;
	నిర్మాణం termios tio;
	అక్షరం **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
నిర్మాణం mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
నిర్మాణం mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	పూర్ణాంకం fid;	/* forward id */
};

/* fd to control socket */
పూర్ణాంకం muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
స్థిర అస్థిర sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
స్థిర u_int muxserver_pid = 0;

స్థిర Channel *mux_listener_channel = ఖాళీ;

నిర్మాణం mux_master_state {
	పూర్ణాంకం hello_rcvd;
};

/* mux protocol messages */
#నిర్వచించు MUX_సందేశం_HELLO		0x00000001
#నిర్వచించు MUX_C_NEW_SESSION	0x10000002
#నిర్వచించు MUX_C_ALIVE_CHECK	0x10000004
#నిర్వచించు MUX_C_TERMINATE		0x10000005
#నిర్వచించు MUX_C_OPEN_FWD		0x10000006
#నిర్వచించు MUX_C_CLOSE_FWD		0x10000007
#నిర్వచించు MUX_C_NEW_STDIO_FWD	0x10000008
#నిర్వచించు MUX_C_STOP_LISTENING	0x10000009
#నిర్వచించు MUX_C_PROXY		0x1000000f
#నిర్వచించు MUX_C_EXT_INFO		0x20000001
#నిర్వచించు MUX_S_OK		0x80000001
#నిర్వచించు MUX_S_PERMISSION_DENIED	0x80000002
#నిర్వచించు MUX_S_FAILURE		0x80000003
#నిర్వచించు MUX_S_EXIT_సందేశం	0x80000004
#నిర్వచించు MUX_S_ALIVE		0x80000005
#నిర్వచించు MUX_S_SESSION_OPENED	0x80000006
#నిర్వచించు MUX_S_REMOTE_పోర్టు	0x80000007
#నిర్వచించు MUX_S_TTY_ALLOC_FAIL	0x80000008
#నిర్వచించు MUX_S_PROXY		0x8000000f
#నిర్వచించు MUX_S_EXT_INFO		0x90000001

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
#నిర్వచించు MUX_FWD_LOCAL   1
#నిర్వచించు MUX_FWD_REMOTE  2
#నిర్వచించు MUX_FWD_DYNAMIC 3

#నిర్వచించు MUX_EXT_INFO		0x00000001

/* Bitmask of supported extensions */
స్థిర u_int extensions = 0;

స్థిర శూన్య mux_session_confirm(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, శూన్య *);
స్థిర శూన్య mux_stdio_confirm(నిర్మాణం ssh *, పూర్ణాంకం, పూర్ణాంకం, శూన్య *);

స్థిర పూర్ణాంకం mux_master_process_hello(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_new_session(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_alive_check(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_terminate(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_open_fwd(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_close_fwd(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_stdio_fwd(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_stop_listening(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_proxy(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
స్థిర పూర్ణాంకం mux_master_process_ext_info(నిర్మాణం ssh *, u_int,
	    Channel *, నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);

స్థిర స్థిరరాశి నిర్మాణం {
	u_int type;
	పూర్ణాంకం (*handler)(నిర్మాణం ssh *, u_int, Channel *,
	    నిర్మాణం sshbuf *, నిర్మాణం sshbuf *);
} mux_master_handlers[] = {
	{ MUX_సందేశం_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, ఖాళీ }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
స్థిర శూన్య
mux_master_session_cleanup_cb(నిర్మాణం ssh *ssh, పూర్ణాంకం cid, పూర్ణాంకం force, శూన్య *వాడని)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ఒకవేళ (c == ఖాళీ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ఒకవేళ (c->ctl_chan != -1) {
		ఒకవేళ ((cc = channel_by_id(ssh, c->ctl_chan)) == ఖాళీ)
			fatal_f("channel %d missing control channel %d",
			    c->self, c->ctl_chan);
		c->ctl_chan = -1;
		cc->ctl_బిడ్డ_id = 0;
		cc->have_ctl_బిడ్డ_id = 0;
		chan_rcvd_oclose(ssh, cc);
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Cleanup callback fired on closure of mux client _control_ channel */
స్థిర శూన్య
mux_master_control_cleanup_cb(నిర్మాణం ssh *ssh, పూర్ణాంకం cid, పూర్ణాంకం force, శూన్య *వాడని)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ఒకవేళ (c == ఖాళీ)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ఒకవేళ (c->have_ctl_బిడ్డ_id) {
		ఒకవేళ ((sc = channel_by_id(ssh, c->ctl_బిడ్డ_id)) == ఖాళీ)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_బిడ్డ_id);
		c->ctl_బిడ్డ_id = 0;
		c->have_ctl_బిడ్డ_id = 0;
		sc->ctl_chan = -1;
		ఒకవేళ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} లేకపోతే {
			ఒకవేళ (sc->istate == CHAN_ఆదానం_OPEN)
				chan_read_failed(ssh, sc);
			ఒకవేళ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
స్థిర పూర్ణాంకం
env_permitted(స్థిరరాశి అక్షరం *env)
{
	u_int i;
	పూర్ణాంకం ret;
	అక్షరం name[1024], *cp;

	ఒకవేళ ((cp = strchr(env, '=')) == ఖాళీ || cp == env)
		తిరిగి 0;
	ret = snprintf(name, పరిమాణం(name), "%.*s", (పూర్ణాంకం)(cp - env), env);
	ఒకవేళ (ret <= 0 || (కొలత_t)ret >= పరిమాణం(name)) {
		error_f("name '%.100s...' too long", env);
		తిరిగి 0;
	}

	కొరకు (i = 0; i < options.అంకె_send_env; i++)
		ఒకవేళ (సరిపోలిక_నమూనా(name, options.send_env[i]))
			తిరిగి 1;

	తిరిగి 0;
}

/* Mux master protocol message handlers */

స్థిర పూర్ణాంకం
mux_master_process_hello(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	u_int ver;
	నిర్మాణం mux_master_state *state = (నిర్మాణం mux_master_state *)c->mux_ctx;
	పూర్ణాంకం r;

	ఒకవేళ (state == ఖాళీ)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ఒకవేళ (state->hello_rcvd) {
		error_f("HELLO received twice");
		తిరిగి -1;
	}
	ఒకవేళ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		తిరిగి -1;
	}
	ఒకవేళ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		తిరిగి -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	అయితే (sshbuf_len(m) > 0) {
		అక్షరం *name = ఖాళీ;
		కొలత_t విలువ_len = 0;

		ఒకవేళ ((r = sshbuf_get_cstring(m, &name, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_string_ప్రత్యక్ష(m, ఖాళీ, &విలువ_len)) != 0) {
			error_fr(r, "parse extension");
			తిరిగి -1;
		}
		ఒకవేళ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} లేకపోతే {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, విలువ_len);
		}
		విడుదల(name);
	}
	state->hello_rcvd = 1;
	తిరిగి 0;
}

/* Enqueue a "ok" response to the reply buffer */
స్థిర శూన్య
జవాబు_ok(నిర్మాణం sshbuf *జవాబు, u_int rid)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u32(జవాబు, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
స్థిర శూన్య
జవాబు_error(నిర్మాణం sshbuf *జవాబు, u_int type, u_int rid, స్థిరరాశి అక్షరం *సందేశం)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u32(జవాబు, type)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, rid)) != 0 ||
	    (r = sshbuf_put_cstring(జవాబు, సందేశం)) != 0)
		fatal_fr(r, "reply");
}

స్థిర పూర్ణాంకం
mux_master_process_new_session(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	Channel *nc;
	నిర్మాణం mux_session_confirm_ctx *cctx;
	అక్షరం *cmd, *cp;
	u_int i, j, env_len, escape_char, కిటికీ, packetmax;
	పూర్ణాంకం r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, పరిమాణం(*cctx));
	cctx->పదం = ఖాళీ;
	cctx->rid = rid;
	cmd = ఖాళీ;
	cctx->env = ఖాళీ;
	env_len = 0;
	ఒకవేళ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->పదం, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, ఖాళీ)) != 0) {
 malf:
		విడుదల(cmd);
		కొరకు (j = 0; j < env_len; j++)
			విడుదల(cctx->env[j]);
		విడుదల(cctx->env);
		విడుదల(cctx->పదం);
		విడుదల(cctx);
		error_f("malformed message");
		తిరిగి -1;
	}

#నిర్వచించు MUX_MAX_ENV_VARS	4096
	అయితే (sshbuf_len(m) > 0) {
		ఒకవేళ ((r = sshbuf_get_cstring(m, &cp, ఖాళీ)) != 0)
			వెళ్ళు malf;
		ఒకవేళ (!env_permitted(cp)) {
			విడుదల(cp);
			కొనసాగు;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    పరిమాణం(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = ఖాళీ;
		ఒకవేళ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			ఆపు;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->పదం, cmd, env_len);

	ఒకవేళ ((cctx->cmd = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put(cctx->cmd, cmd, అక్షరశ్రేణి_పొడవు(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	విడుదల(cmd);
	cmd = ఖాళీ;

	/* Gather fds from client */
	కొరకు(i = 0; i < 3; i++) {
		ఒకవేళ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			కొరకు (j = 0; j < i; j++)
				close(new_fd[j]);
			కొరకు (j = 0; j < env_len; j++)
				విడుదల(cctx->env[j]);
			విడుదల(cctx->env);
			విడుదల(cctx->పదం);
			sshbuf_free(cctx->cmd);
			విడుదల(cctx);
			జవాబు_error(జవాబు, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			తిరిగి -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ఒకవేళ (c->have_ctl_బిడ్డ_id) {
		debug2_f("session already open");
		జవాబు_error(జవాబు, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		విడుదల(cctx->పదం);
		ఒకవేళ (env_len != 0) {
			కొరకు (i = 0; i < env_len; i++)
				విడుదల(cctx->env[i]);
			విడుదల(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		విడుదల(cctx);
		తిరిగి 0;
	}

	ఒకవేళ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ఒకవేళ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			జవాబు_error(జవాబు, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			వెళ్ళు cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ఒకవేళ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	కిటికీ = CHAN_SES_కిటికీ_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ఒకవేళ (cctx->want_tty) {
		కిటికీ >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], కిటికీ, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ఒకవేళ (cctx->want_tty)
		channel_సమితి_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_బిడ్డ_id = nc->self;	/* link control -> session channel */
	c->have_ctl_బిడ్డ_id = 1;

	ఒకవేళ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_రిజిస్టరు_filter(ssh, nc->self,
		    client_simple_escape_filter, ఖాళీ,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((పూర్ణాంకం)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_రిజిస్టరు_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_రిజిస్టరు_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_master_process_alive_check(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	పూర్ణాంకం r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ఒకవేళ ((r = sshbuf_put_u32(జవాబు, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, rid)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	తిరిగి 0;
}

/* The "info" extension. */
స్థిర పూర్ణాంకం
mux_master_process_ext_info(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	పూర్ణాంకం r;
	u_int స్థితి_2 = 0;
	అక్షరం *name = ఖాళీ, *సందేశం = ఖాళీ;

	debug2_f("channel %d: info request", c->self);

	ఒకవేళ ((r = sshbuf_get_cstring(m, &name, ఖాళీ)) != 0)
		fatal_fr(r, "parse");

	ఒకవేళ (strcmp(name, "connection") == 0) {
		ఒకవేళ ((సందేశం = connection_info_సందేశం(ssh)) == ఖాళీ)
			fatal_f("connection_info_message");
		స్థితి_2 = 1;
	} లేకపోతే ఒకవేళ (strcmp(name, "channels") == 0) {
		ఒకవేళ ((సందేశం = channel_open_సందేశం(ssh)) == ఖాళీ)
			fatal_f("channel_open_message");
		స్థితి_2 = 1;
	} లేకపోతే {
		సందేశం = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ఒకవేళ ((r = sshbuf_put_u32(జవాబు, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, rid)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, స్థితి_2)) != 0 ||
	    (r = sshbuf_put_cstring(జవాబు, సందేశం)) != 0)
		fatal_fr(r, "reply");
	విడుదల(సందేశం);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_master_process_terminate(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	debug2_f("channel %d: terminate request", c->self);

	ఒకవేళ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ఒకవేళ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			జవాబు_error(జవాబు, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			తిరిగి 0;
		}
	}

	quit_pending = 1;
	జవాబు_ok(జవాబు, rid);
	/* XXX exit happens too soon - message never makes it to client */
	తిరిగి 0;
}

స్థిర అక్షరం *
format_forward(u_int ftype, నిర్మాణం Forward *fwd)
{
	అక్షరం *ret;

	ఎంపిక (ftype) {
	స్థితి MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_మార్గం != ఖాళీ) ? fwd->listen_మార్గం :
		    (fwd->listen_host == ఖాళీ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_పోర్టు,
		    (fwd->connect_మార్గం != ఖాళీ) ? fwd->connect_మార్గం :
		    fwd->connect_host, fwd->connect_పోర్టు);
		ఆపు;
	స్థితి MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == ఖాళీ) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_పోర్టు);
		ఆపు;
	స్థితి MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_మార్గం != ఖాళీ) ? fwd->listen_మార్గం :
		    (fwd->listen_host == ఖాళీ) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_పోర్టు,
		    (fwd->connect_మార్గం != ఖాళీ) ? fwd->connect_మార్గం :
		    fwd->connect_host, fwd->connect_పోర్టు);
		ఆపు;
	అప్రమేయ:
		fatal_f("unknown forward type %u", ftype);
	}
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
compare_host(స్థిరరాశి అక్షరం *a, స్థిరరాశి అక్షరం *b)
{
	ఒకవేళ (a == ఖాళీ && b == ఖాళీ)
		తిరిగి 1;
	ఒకవేళ (a == ఖాళీ || b == ఖాళీ)
		తిరిగి 0;
	తిరిగి strcmp(a, b) == 0;
}

స్థిర పూర్ణాంకం
compare_forward(నిర్మాణం Forward *a, నిర్మాణం Forward *b)
{
	ఒకవేళ (!compare_host(a->listen_host, b->listen_host))
		తిరిగి 0;
	ఒకవేళ (!compare_host(a->listen_మార్గం, b->listen_మార్గం))
		తిరిగి 0;
	ఒకవేళ (a->listen_పోర్టు != b->listen_పోర్టు)
		తిరిగి 0;
	ఒకవేళ (!compare_host(a->connect_host, b->connect_host))
		తిరిగి 0;
	ఒకవేళ (!compare_host(a->connect_మార్గం, b->connect_మార్గం))
		తిరిగి 0;
	ఒకవేళ (a->connect_పోర్టు != b->connect_పోర్టు)
		తిరిగి 0;

	తిరిగి 1;
}

స్థిర శూన్య
mux_confirm_remote_forward(నిర్మాణం ssh *ssh, పూర్ణాంకం type, uint32_t seq, శూన్య *ctxt)
{
	నిర్మాణం mux_channel_confirm_ctx *fctx = ctxt;
	అక్షరం *failmsg = ఖాళీ;
	నిర్మాణం Forward *rfwd;
	Channel *c;
	నిర్మాణం sshbuf *బహిర్గతం;
	u_int పోర్టు;
	పూర్ణాంకం r;

	ఒకవేళ ((c = channel_by_id(ssh, fctx->cid)) == ఖాళీ) {
		/* no channel for reply */
		error_f("unknown channel");
		తిరిగి;
	}
	ఒకవేళ ((బహిర్గతం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ (fctx->fid >= options.అంకె_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_మార్గం == ఖాళీ &&
	    options.remote_forwards[fctx->fid].connect_host == ఖాళీ)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		వెళ్ళు fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_సందేశం_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_పోర్టు, rfwd->connect_మార్గం ? rfwd->connect_మార్గం :
	    rfwd->connect_host, rfwd->connect_పోర్టు);
	ఒకవేళ (type == SSH2_సందేశం_REQUEST_SUCCESS) {
		ఒకవేళ (rfwd->listen_పోర్టు == 0) {
			ఒకవేళ ((r = sshpkt_get_u32(ssh, &పోర్టు)) != 0)
				fatal_fr(r, "parse port");
			ఒకవేళ (పోర్టు > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", పోర్టు,
				    rfwd->connect_host, rfwd->connect_పోర్టు);
			}
			rfwd->allocated_పోర్టు = (పూర్ణాంకం)పోర్టు;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_పోర్టు,
			    rfwd->connect_host, rfwd->connect_పోర్టు);
			ఒకవేళ ((r = sshbuf_put_u32(బహిర్గతం,
			    MUX_S_REMOTE_పోర్టు)) != 0 ||
			    (r = sshbuf_put_u32(బహిర్గతం, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(బహిర్గతం,
			    rfwd->allocated_పోర్టు)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_పోర్టు);
		} లేకపోతే {
			జవాబు_ok(బహిర్గతం, fctx->rid);
		}
		వెళ్ళు బహిర్గతం;
	} లేకపోతే {
		ఒకవేళ (rfwd->listen_పోర్టు == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ఒకవేళ (rfwd->listen_మార్గం != ఖాళీ)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_మార్గం);
		లేకపోతే
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_పోర్టు);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_పోర్టు,
		    rfwd->connect_మార్గం ? rfwd->connect_మార్గం :
		    rfwd->connect_host, rfwd->connect_పోర్టు);

		విడుదల(rfwd->listen_host);
		విడుదల(rfwd->listen_మార్గం);
		విడుదల(rfwd->connect_host);
		విడుదల(rfwd->connect_మార్గం);
		memset(rfwd, 0, పరిమాణం(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	జవాబు_error(బహిర్గతం, MUX_S_FAILURE, fctx->rid, failmsg);
	విడుదల(failmsg);
 బహిర్గతం:
	ఒకవేళ ((r = sshbuf_put_stringb(c->output, బహిర్గతం)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(బహిర్గతం);
	ఒకవేళ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	విడుదల(fctx);
}

స్థిర పూర్ణాంకం
mux_master_process_open_fwd(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	నిర్మాణం Forward fwd;
	అక్షరం *fwd_desc = ఖాళీ;
	అక్షరం *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	పూర్ణాంకం r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, పరిమాణం(fwd));

	/* XXX - lport/cport check redundant */
	ఒకవేళ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)పోర్టు_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)పోర్టు_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (*listen_addr == '\0') {
		విడుదల(listen_addr);
		listen_addr = ఖాళీ;
	}
	ఒకవేళ (*connect_addr == '\0') {
		విడుదల(connect_addr);
		connect_addr = ఖాళీ;
	}

	memset(&fwd, 0, పరిమాణం(fwd));
	fwd.listen_పోర్టు = lport;
	ఒకవేళ (fwd.listen_పోర్టు == పోర్టు_STREAMLOCAL)
		fwd.listen_మార్గం = listen_addr;
	లేకపోతే
		fwd.listen_host = listen_addr;
	fwd.connect_పోర్టు = cport;
	ఒకవేళ (fwd.connect_పోర్టు == పోర్టు_STREAMLOCAL)
		fwd.connect_మార్గం = connect_addr;
	లేకపోతే
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ఒకవేళ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		విడుదల(listen_addr);
		విడుదల(connect_addr);
		జవాబు_error(జవాబు, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		తిరిగి 0;
	}
	ఒకవేళ (ftype == MUX_FWD_DYNAMIC && fwd.listen_మార్గం) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		వెళ్ళు invalid;
	}
	ఒకవేళ (fwd.listen_పోర్టు != పోర్టు_STREAMLOCAL && fwd.listen_పోర్టు >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_పోర్టు);
		వెళ్ళు invalid;
	}
	ఒకవేళ ((fwd.connect_పోర్టు != పోర్టు_STREAMLOCAL &&
	    fwd.connect_పోర్టు >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_పోర్టు == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_పోర్టు);
		వెళ్ళు invalid;
	}
	ఒకవేళ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == ఖాళీ &&
	    fwd.connect_మార్గం == ఖాళీ) {
		logit_f("missing connect host");
		వెళ్ళు invalid;
	}

	/* Skip forwards that have already been requested */
	ఎంపిక (ftype) {
	స్థితి MUX_FWD_LOCAL:
	స్థితి MUX_FWD_DYNAMIC:
		కొరకు (i = 0; i < options.అంకె_local_forwards; i++) {
			ఒకవేళ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				జవాబు_ok(జవాబు, rid);
				వెళ్ళు బహిర్గతం;
			}
		}
		ఆపు;
	స్థితి MUX_FWD_REMOTE:
		కొరకు (i = 0; i < options.అంకె_remote_forwards; i++) {
			ఒకవేళ (!compare_forward(&fwd, options.remote_forwards + i))
				కొనసాగు;
			ఒకవేళ (fwd.listen_పోర్టు != 0)
				వెళ్ళు exists;
			debug2_f("found allocated port");
			ఒకవేళ ((r = sshbuf_put_u32(జవాబు,
			    MUX_S_REMOTE_పోర్టు)) != 0 ||
			    (r = sshbuf_put_u32(జవాబు, rid)) != 0 ||
			    (r = sshbuf_put_u32(జవాబు,
			    options.remote_forwards[i].allocated_పోర్టు)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			వెళ్ళు బహిర్గతం;
		}
		ఆపు;
	}

	ఒకవేళ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ఒకవేళ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			జవాబు_error(జవాబు, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			వెళ్ళు బహిర్గతం;
		}
	}

	ఒకవేళ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ఒకవేళ (!channel_అమరిక_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			జవాబు_error(జవాబు, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			వెళ్ళు బహిర్గతం;
		}
		కూడు_local_forward(&options, &fwd);
		freefwd = 0;
	} లేకపోతే {
		నిర్మాణం mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ఒకవేళ (fwd.handle < 0)
			వెళ్ళు fail;
		కూడు_remote_forward(&options, &fwd);
		fctx = xcalloc(1, పరిమాణం(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.అంకె_remote_forwards - 1;
		client_రిజిస్టరు_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		వెళ్ళు బహిర్గతం;
	}
	జవాబు_ok(జవాబు, rid);
 బహిర్గతం:
	విడుదల(fwd_desc);
	ఒకవేళ (freefwd) {
		విడుదల(fwd.listen_host);
		విడుదల(fwd.listen_మార్గం);
		విడుదల(fwd.connect_host);
		విడుదల(fwd.connect_మార్గం);
	}
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
mux_master_process_close_fwd(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	నిర్మాణం Forward fwd, *దొరికింది_fwd;
	అక్షరం *fwd_desc = ఖాళీ;
	స్థిరరాశి అక్షరం *error_reason = ఖాళీ;
	అక్షరం *listen_addr = ఖాళీ, *connect_addr = ఖాళీ;
	u_int ftype;
	పూర్ణాంకం r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, పరిమాణం(fwd));

	ఒకవేళ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)పోర్టు_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)పోర్టు_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (*listen_addr == '\0') {
		విడుదల(listen_addr);
		listen_addr = ఖాళీ;
	}
	ఒకవేళ (*connect_addr == '\0') {
		విడుదల(connect_addr);
		connect_addr = ఖాళీ;
	}

	memset(&fwd, 0, పరిమాణం(fwd));
	fwd.listen_పోర్టు = lport;
	ఒకవేళ (fwd.listen_పోర్టు == పోర్టు_STREAMLOCAL)
		fwd.listen_మార్గం = listen_addr;
	లేకపోతే
		fwd.listen_host = listen_addr;
	fwd.connect_పోర్టు = cport;
	ఒకవేళ (fwd.connect_పోర్టు == పోర్టు_STREAMLOCAL)
		fwd.connect_మార్గం = connect_addr;
	లేకపోతే
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	దొరికింది_fwd = ఖాళీ;
	ఎంపిక (ftype) {
	స్థితి MUX_FWD_LOCAL:
	స్థితి MUX_FWD_DYNAMIC:
		కొరకు (i = 0; i < options.అంకె_local_forwards; i++) {
			ఒకవేళ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				దొరికింది_fwd = options.local_forwards + i;
				ఆపు;
			}
		}
		ఆపు;
	స్థితి MUX_FWD_REMOTE:
		కొరకు (i = 0; i < options.అంకె_remote_forwards; i++) {
			ఒకవేళ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				దొరికింది_fwd = options.remote_forwards + i;
				ఆపు;
			}
		}
		ఆపు;
	}

	ఒకవేళ (దొరికింది_fwd == ఖాళీ)
		error_reason = "port not forwarded";
	లేకపోతే ఒకవేళ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ఒకవేళ (channel_request_rforward_cancel(ssh, దొరికింది_fwd) == -1)
			error_reason = "port not in permitted opens";
	} లేకపోతే {	/* local and dynamic forwards */
		/* Ditto */
		ఒకవేళ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_పోర్టు,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ఒకవేళ (error_reason != ఖాళీ)
		జవాబు_error(జవాబు, MUX_S_FAILURE, rid, error_reason);
	లేకపోతే {
		జవాబు_ok(జవాబు, rid);
		విడుదల(దొరికింది_fwd->listen_host);
		విడుదల(దొరికింది_fwd->listen_మార్గం);
		విడుదల(దొరికింది_fwd->connect_host);
		విడుదల(దొరికింది_fwd->connect_మార్గం);
		దొరికింది_fwd->listen_host = దొరికింది_fwd->connect_host = ఖాళీ;
		దొరికింది_fwd->listen_మార్గం = దొరికింది_fwd->connect_మార్గం = ఖాళీ;
		దొరికింది_fwd->listen_పోర్టు = దొరికింది_fwd->connect_పోర్టు = 0;
	}
 బహిర్గతం:
	విడుదల(fwd_desc);
	విడుదల(listen_addr);
	విడుదల(connect_addr);

	తిరిగి ret;
}

స్థిర పూర్ణాంకం
mux_master_process_stdio_fwd(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	Channel *nc;
	అక్షరం *chost = ఖాళీ;
	u_int _cport, i, j;
	పూర్ణాంకం ok = 0, cport, r, new_fd[2];
	నిర్మాణం mux_stdio_confirm_ctx *cctx;

	ఒకవేళ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		విడుదల(chost);
		error_f("malformed message");
		తిరిగి -1;
	}
	ఒకవేళ (_cport == (u_int)పోర్టు_STREAMLOCAL)
		cport = పోర్టు_STREAMLOCAL;
	లేకపోతే ఒకవేళ (_cport <= గరిష్ఠ_పూర్ణాంకం)
		cport = (పూర్ణాంకం)_cport;
	లేకపోతే {
		విడుదల(chost);
		error_f("invalid port 0x%x", _cport);
		తిరిగి -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	కొరకు(i = 0; i < 2; i++) {
		ఒకవేళ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			కొరకు (j = 0; j < i; j++)
				close(new_fd[j]);
			విడుదల(chost);

			/* prepare reply */
			జవాబు_error(జవాబు, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			తిరిగి -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ఒకవేళ (c->have_ctl_బిడ్డ_id) {
		debug2_f("session already open");
		జవాబు_error(జవాబు, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		విడుదల(chost);
		తిరిగి 0;
	}

	ఒకవేళ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ఒకవేళ (cport == పోర్టు_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} లేకపోతే {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ఒకవేళ (!ok) {
			debug2_f("stdio fwd refused by user");
			జవాబు_error(జవాబు, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			వెళ్ళు cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	విడుదల(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_బిడ్డ_id = nc->self;	/* link control -> session channel */
	c->have_ctl_బిడ్డ_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_రిజిస్టరు_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, పరిమాణం(*cctx));
	cctx->rid = rid;
	channel_రిజిస్టరు_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	తిరిగి 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
స్థిర శూన్య
mux_stdio_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం success, శూన్య *arg)
{
	నిర్మాణం mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	నిర్మాణం sshbuf *జవాబు;
	పూర్ణాంకం r;

	ఒకవేళ (cctx == ఖాళీ)
		fatal_f("cctx == NULL");
	ఒకవేళ ((c = channel_by_id(ssh, id)) == ఖాళీ)
		fatal_f("no channel for id %d", id);
	ఒకవేళ ((cc = channel_by_id(ssh, c->ctl_chan)) == ఖాళీ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ఒకవేళ ((జవాబు = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");

	ఒకవేళ (!success) {
		debug3_f("sending failure reply");
		జవాబు_error(జవాబు, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		వెళ్ళు పూర్తి;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ఒకవేళ ((r = sshbuf_put_u32(జవాబు, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, c->self)) != 0)
		fatal_fr(r, "reply");

 పూర్తి:
	/* Send reply */
	ఒకవేళ ((r = sshbuf_put_stringb(cc->output, జవాబు)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(జవాబు);

	ఒకవేళ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ఖాళీ;
	విడుదల(cctx);
}

స్థిర పూర్ణాంకం
mux_master_process_stop_listening(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	debug_f("channel %d: stop listening", c->self);

	ఒకవేళ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ఒకవేళ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			జవాబు_error(జవాబు, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			తిరిగి 0;
		}
	}

	ఒకవేళ (mux_listener_channel != ఖాళీ) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		విడుదల(options.control_మార్గం);
		options.control_మార్గం = ఖాళీ;
		mux_listener_channel = ఖాళీ;
		muxserver_sock = -1;
	}

	జవాబు_ok(జవాబు, rid);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_master_process_proxy(నిర్మాణం ssh *ssh, u_int rid,
    Channel *c, నిర్మాణం sshbuf *m, నిర్మాణం sshbuf *జవాబు)
{
	పూర్ణాంకం r;

	debug_f("channel %d: proxy request", c->self);

	ఒకవేళ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ఒకవేళ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			జవాబు_error(జవాబు, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			తిరిగి 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ఒకవేళ ((r = sshbuf_put_u32(జవాబు, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, rid)) != 0)
		fatal_fr(r, "reply");

	తిరిగి 0;
}

/* Channel callbacks fired on read/write from mux client fd */
స్థిర పూర్ణాంకం
mux_master_read_cb(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం mux_master_state *state = (నిర్మాణం mux_master_state *)c->mux_ctx;
	నిర్మాణం sshbuf *లోపల = ఖాళీ, *బహిర్గతం = ఖాళీ;
	u_int type, rid, i;
	పూర్ణాంకం r, ret = -1;

	ఒకవేళ ((బహిర్గతం = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ఒకవేళ (c->mux_ctx == ఖాళీ) {
		state = xcalloc(1, పరిమాణం(*state));
		c->mux_ctx = state;
		channel_రిజిస్టరు_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ఒకవేళ ((r = sshbuf_put_u32(బహిర్గతం, MUX_సందేశం_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(బహిర్గతం, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ఒకవేళ ((r = sshbuf_put_cstring(బహిర్గతం, "info")) != 0 ||
		    (r = sshbuf_put_cstring(బహిర్గతం, "0")) != 0)
			fatal_fr(r, "put info extension");
		ఒకవేళ ((r = sshbuf_put_stringb(c->output, బహిర్గతం)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		వెళ్ళు బహిర్గతం;
	}

	/* Channel code ensures that we receive whole packets */
	ఒకవేళ ((r = sshbuf_froms(c->ఆదానం, &లోపల)) != 0) {
 malf:
		error_f("malformed message");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshbuf_get_u32(లోపల, &type)) != 0)
		వెళ్ళు malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(లోపల));

	ఒకవేళ (type == MUX_సందేశం_HELLO)
		rid = 0;
	లేకపోతే {
		ఒకవేళ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_సందేశం_HELLO, type);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_get_u32(లోపల, &rid)) != 0)
			వెళ్ళు malf;
	}

	కొరకు (i = 0; mux_master_handlers[i].handler != ఖాళీ; i++) {
		ఒకవేళ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, లోపల, బహిర్గతం);
			ఆపు;
		}
	}
	ఒకవేళ (mux_master_handlers[i].handler == ఖాళీ) {
		error_f("unsupported mux message 0x%08x", type);
		జవాబు_error(బహిర్గతం, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ఒకవేళ (sshbuf_len(బహిర్గతం) != 0 &&
	    (r = sshbuf_put_stringb(c->output, బహిర్గతం)) != 0)
		fatal_fr(r, "enqueue");
 బహిర్గతం:
	sshbuf_free(లోపల);
	sshbuf_free(బహిర్గతం);
	తిరిగి ret;
}

శూన్య
mux_exit_సందేశం(నిర్మాణం ssh *ssh, Channel *c, పూర్ణాంకం exitval)
{
	నిర్మాణం sshbuf *m;
	Channel *mux_chan;
	పూర్ణాంకం r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ఒకవేళ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ఖాళీ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_S_EXIT_సందేశం)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

శూన్య
mux_tty_alloc_failed(నిర్మాణం ssh *ssh, Channel *c)
{
	నిర్మాణం sshbuf *m;
	Channel *mux_chan;
	పూర్ణాంకం r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ఒకవేళ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ఖాళీ)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
శూన్య
muxserver_listen(నిర్మాణం ssh *ssh)
{
	బహుళకం_t old_umask;
	అక్షరం *orig_control_మార్గం = options.control_మార్గం;
	అక్షరం rbuf[16+1];
	u_int i, r;
	పూర్ణాంకం oerrno;

	ఒకవేళ (options.control_మార్గం == ఖాళీ ||
	    options.control_master == SSHCTL_MASTER_NO)
		తిరిగి;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	కొరకు (i = 0; i < పరిమాణం(rbuf) - 1; i++) {
		r = arc4random_ఏకరీతి(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[పరిమాణం(rbuf) - 1] = '\0';
	options.control_మార్గం = ఖాళీ;
	xasprintf(&options.control_మార్గం, "%s.%s", orig_control_మార్గం, rbuf);
	debug3_f("temporary control path %s", options.control_మార్గం);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_మార్గం, 64, 0);
	oerrno = errno;
	umask(old_umask);
	ఒకవేళ (muxserver_sock < 0) {
		ఒకవేళ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_మార్గం);
 disable_mux_master:
			ఒకవేళ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			విడుదల(orig_control_మార్గం);
			విడుదల(options.control_మార్గం);
			options.control_మార్గం = ఖాళీ;
			options.control_master = SSHCTL_MASTER_NO;
			తిరిగి;
		} లేకపోతే {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ఒకవేళ (link(options.control_మార్గం, orig_control_మార్గం) != 0) {
		ఒకవేళ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_మార్గం, orig_control_మార్గం,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_మార్గం);
		unlink(options.control_మార్గం);
		వెళ్ళు disable_mux_master;
	}
	unlink(options.control_మార్గం);
	విడుదల(options.control_మార్గం);
	options.control_మార్గం = orig_control_మార్గం;

	సమితి_nonblock(muxserver_sock);

	mux_listener_channel = channel_new(ssh, "mux listener",
	    SSH_CHANNEL_MUX_LISTENER, muxserver_sock, muxserver_sock, -1,
	    CHAN_TCP_కిటికీ_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, options.control_మార్గం, 1);
	mux_listener_channel->mux_rcb = mux_master_read_cb;
	debug3_f("mux listener channel %d fd %d",
	    mux_listener_channel->self, mux_listener_channel->sock);
}

/* Callback on open confirmation in mux master for a mux client session. */
స్థిర శూన్య
mux_session_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం success, శూన్య *arg)
{
	నిర్మాణం mux_session_confirm_ctx *cctx = arg;
	స్థిరరాశి అక్షరం *display;
	Channel *c, *cc;
	పూర్ణాంకం i, r;
	నిర్మాణం sshbuf *జవాబు;

	ఒకవేళ (cctx == ఖాళీ)
		fatal_f("cctx == NULL");
	ఒకవేళ ((c = channel_by_id(ssh, id)) == ఖాళీ)
		fatal_f("no channel for id %d", id);
	ఒకవేళ ((cc = channel_by_id(ssh, c->ctl_chan)) == ఖాళీ)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ఒకవేళ ((జవాబు = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");

	ఒకవేళ (!success) {
		debug3_f("sending failure reply");
		జవాబు_error(జవాబు, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		వెళ్ళు పూర్తి;
	}

	display = getenv("DISPLAY");
	ఒకవేళ (cctx->want_x_fwd && options.forward_x11 && display != ఖాళీ) {
		అక్షరం *proto, *దత్తాంశం;

		/* Get reasonable local authentication information. */
		ఒకవేళ (client_x11_get_proto(ssh, display, options.xauth_location,
		    options.forward_x11_trusted, options.forward_x11_timeout,
		    &proto, &దత్తాంశం) == 0) {
			/* Request forwarding with authentication spoofing. */
			debug("Requesting X11 forwarding with authentication "
			    "spoofing.");
			x11_request_forwarding_with_spoofing(ssh, id,
			    display, proto, దత్తాంశం, 1);
			/* XXX exit_on_forward_failure */
			client_expect_confirm(ssh, id, "X11 forwarding",
			    CONFIRM_WARN);
		}
	}

	ఒకవేళ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_అమరిక(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->పదం, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ఒకవేళ ((r = sshbuf_put_u32(జవాబు, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(జవాబు, c->self)) != 0)
		fatal_fr(r, "reply");

 పూర్తి:
	/* Send reply */
	ఒకవేళ ((r = sshbuf_put_stringb(cc->output, జవాబు)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(జవాబు);

	ఒకవేళ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ఖాళీ;
	sshbuf_free(cctx->cmd);
	విడుదల(cctx->పదం);
	ఒకవేళ (cctx->env != ఖాళీ) {
		కొరకు (i = 0; cctx->env[i] != ఖాళీ; i++)
			విడుదల(cctx->env[i]);
		విడుదల(cctx->env);
	}
	విడుదల(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
స్థిర శూన్య
control_client_sighandler(పూర్ణాంకం signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
స్థిర శూన్య
control_client_sigrelay(పూర్ణాంకం signo)
{
	పూర్ణాంకం save_errno = errno;

	ఒకవేళ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

స్థిర పూర్ణాంకం
mux_client_read(పూర్ణాంకం fd, నిర్మాణం sshbuf *b, కొలత_t need, పూర్ణాంకం timeout_ms)
{
	కొలత_t have;
	ssize_t len;
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	కొరకు (have = 0; have < need; ) {
		ఒకవేళ (muxclient_terminate) {
			errno = EINTR;
			తిరిగి -1;
		}
		len = పఠ(fd, p + have, need - have);
		ఒకవేళ (len == -1) {
			ఎంపిక (errno) {
#ఒకవేళ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			స్థితి EWOULDBLOCK:
#అయితే_ముగింపు
			స్థితి EAGAIN:
				ఒకవేళ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					తిరిగి -1;	/* timeout */
				/* FALLTHROUGH */
			స్థితి EINTR:
				కొనసాగు;
			అప్రమేయ:
				తిరిగి -1;
			}
		}
		ఒకవేళ (len == 0) {
			errno = EPIPE;
			తిరిగి -1;
		}
		have += (కొలత_t)len;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_client_write_packet(పూర్ణాంకం fd, నిర్మాణం sshbuf *m)
{
	నిర్మాణం sshbuf *వరుస;
	u_int have, need;
	పూర్ణాంకం r, oerrno, len;
	స్థిరరాశి u_char *ptr;
	నిర్మాణం pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ఒకవేళ ((వరుస = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_stringb(వరుస, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(వరుస);
	ptr = sshbuf_ptr(వరుస);

	కొరకు (have = 0; have < need; ) {
		ఒకవేళ (muxclient_terminate) {
			sshbuf_free(వరుస);
			errno = EINTR;
			తిరిగి -1;
		}
		len = లిఖ(fd, ptr + have, need - have);
		ఒకవేళ (len == -1) {
			ఎంపిక (errno) {
#ఒకవేళ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			స్థితి EWOULDBLOCK:
#అయితే_ముగింపు
			స్థితి EAGAIN:
				(శూన్య)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			స్థితి EINTR:
				కొనసాగు;
			అప్రమేయ:
				oerrno = errno;
				sshbuf_free(వరుస);
				errno = oerrno;
				తిరిగి -1;
			}
		}
		ఒకవేళ (len == 0) {
			sshbuf_free(వరుస);
			errno = EPIPE;
			తిరిగి -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(వరుస);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_client_read_packet_timeout(పూర్ణాంకం fd, నిర్మాణం sshbuf *m, పూర్ణాంకం timeout_ms)
{
	నిర్మాణం sshbuf *వరుస;
	కొలత_t need, have;
	స్థిరరాశి u_char *ptr;
	పూర్ణాంకం r, oerrno;

	ఒకవేళ ((వరుస = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ (mux_client_read(fd, వరుస, 4, timeout_ms) != 0) {
		ఒకవేళ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(వరుస);
		errno = oerrno;
		తిరిగి -1;
	}
	need = PEEK_U32(sshbuf_ptr(వరుస));
	ఒకవేళ (mux_client_read(fd, వరుస, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(వరుస);
		errno = oerrno;
		తిరిగి -1;
	}
	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(వరుస, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(వరుస);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_client_read_packet(పూర్ణాంకం fd, నిర్మాణం sshbuf *m)
{
	తిరిగి mux_client_read_packet_timeout(fd, m, -1);
}

స్థిర పూర్ణాంకం
mux_client_hello_exchange(పూర్ణాంకం fd, పూర్ణాంకం timeout_ms)
{
	నిర్మాణం sshbuf *m;
	u_int type, ver;
	పూర్ణాంకం r, ret = -1;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_సందేశం_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ఒకవేళ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ఒకవేళ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ఒకవేళ (type != MUX_సందేశం_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_సందేశం_HELLO, type);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ఒకవేళ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		వెళ్ళు బహిర్గతం;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	అయితే (sshbuf_len(m) > 0) {
		అక్షరం *name = ఖాళీ;

		ఒకవేళ ((r = sshbuf_get_cstring(m, &name, ఖాళీ)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*విలువ*/
			error_fr(r, "parse extension");
			వెళ్ళు బహిర్గతం;
		}
		/* Process extensions. */
		ఒకవేళ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} లేకపోతే {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		విడుదల(name);
	}
	/* success */
	ret = 0;
 బహిర్గతం:
	sshbuf_free(m);
	తిరిగి ret;
}

స్థిర u_int
mux_client_request_alive(పూర్ణాంకం fd)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e;
	u_int pid, type, rid;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		తిరిగి 0;
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ఒకవేళ (type != MUX_S_ALIVE) {
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ఒకవేళ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	తిరిగి pid;
}

స్థిర అక్షరం *
mux_client_request_info(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e, *సందేశం;
	u_int type, rid, స్థితి_2;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		తిరిగి 0;
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ఒకవేళ (type != MUX_S_EXT_INFO) {
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ఒకవేళ ((r = sshbuf_get_u32(m, &స్థితి_2)) != 0 ||
	    (r = sshbuf_get_cstring(m, &సందేశం, ఖాళీ)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	తిరిగి సందేశం;
}

స్థిర శూన్య
mux_client_request_terminate(పూర్ణాంకం fd)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e;
	u_int type, rid;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ఒకవేళ (errno == EPIPE) {
			sshbuf_free(m);
			తిరిగి;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ఎంపిక (type) {
	స్థితి MUX_S_OK:
		ఆపు;
	స్థితి MUX_S_PERMISSION_DENIED:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	స్థితి MUX_S_FAILURE:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	అప్రమేయ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

స్థిర పూర్ణాంకం
mux_client_forward(పూర్ణాంకం fd, పూర్ణాంకం cancel_flag, u_int ftype, నిర్మాణం Forward *fwd)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e, *fwd_desc;
	స్థిరరాశి అక్షరం *lhost, *chost;
	u_int type, rid;
	పూర్ణాంకం r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	విడుదల(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ఒకవేళ (fwd->listen_మార్గం != ఖాళీ)
		lhost = fwd->listen_మార్గం;
	లేకపోతే ఒకవేళ (fwd->listen_host == ఖాళీ)
		lhost = "";
	లేకపోతే ఒకవేళ (*fwd->listen_host == '\0')
		lhost = "*";
	లేకపోతే
		lhost = fwd->listen_host;

	ఒకవేళ (fwd->connect_మార్గం != ఖాళీ)
		chost = fwd->connect_మార్గం;
	లేకపోతే ఒకవేళ (fwd->connect_host == ఖాళీ)
		chost = "";
	లేకపోతే
		chost = fwd->connect_host;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_పోర్టు)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_పోర్టు)) != 0)
		fatal_fr(r, "request");

	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		తిరిగి -1;
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ఎంపిక (type) {
	స్థితి MUX_S_OK:
		ఆపు;
	స్థితి MUX_S_REMOTE_పోర్టు:
		ఒకవేళ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ఒకవేళ ((r = sshbuf_get_u32(m, &fwd->allocated_పోర్టు)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_పోర్టు,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_పోర్టు);
		ఒకవేళ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_పోర్టు);
		ఆపు;
	స్థితి MUX_S_PERMISSION_DENIED:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		తిరిగి -1;
	స్థితి MUX_S_FAILURE:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		తిరిగి -1;
	అప్రమేయ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_client_forwards(పూర్ణాంకం fd, పూర్ణాంకం cancel_flag)
{
	పూర్ణాంకం i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.అంకె_local_forwards, options.అంకె_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	కొరకు (i = 0; i < options.అంకె_local_forwards; i++) {
		ఒకవేళ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_పోర్టు == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	కొరకు (i = 0; i < options.అంకె_remote_forwards; i++) {
		ఒకవేళ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
mux_client_request_session(పూర్ణాంకం fd)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e;
	స్థిరరాశి అక్షరం *పదం = ఖాళీ;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_చూసిన;
	బాహ్య అక్షరం **environ;
	పూర్ణాంకం r, rawmode = 0;

	debug3_f("entering");

	ఒకవేళ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		తిరిగి -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ఒకవేళ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ఒకవేళ ((పదం = lookup_env_లోపల_list("TERM", options.setenv,
	    options.అంకె_setenv)) == ఖాళీ || *పదం == '\0')
		పదం = getenv("TERM");

	echar = 0xffffffff;
	ఒకవేళ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ఖాళీ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, పదం == ఖాళీ ? "" : పదం)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	ఒకవేళ (options.అంకె_send_env > 0 && environ != ఖాళీ) {
		కొరకు (i = 0; environ[i] != ఖాళీ; i++) {
			ఒకవేళ (!env_permitted(environ[i]))
				కొనసాగు;
			ఒకవేళ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	కొరకు (i = 0; i < options.అంకె_setenv; i++) {
		ఒకవేళ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ఒకవేళ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		తిరిగి -1;
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ఎంపిక (type) {
	స్థితి MUX_S_SESSION_OPENED:
		ఒకవేళ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ఆపు;
	స్థితి MUX_S_PERMISSION_DENIED:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		తిరిగి -1;
	స్థితి MUX_S_FAILURE:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		తిరిగి -1;
	అప్రమేయ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		తిరిగి -1;
	}
	muxclient_request_id++;

	ఒకవేళ (pledge("stdio proc tty", ఖాళీ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ఒకవేళ (options.fork_after_authentication)
		daemon(1, 1);
	లేకపోతే {
		rawmode = tty_flag;
		ఒకవేళ (tty_flag) {
			enter_raw_బహుళకం(
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
	కొరకు (exitval = 255, exitval_చూసిన = 0;;) {
		sshbuf_reset(m);
		ఒకవేళ (mux_client_read_packet(fd, m) != 0)
			ఆపు;
		ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		ఎంపిక (type) {
		స్థితి MUX_S_TTY_ALLOC_FAIL:
			ఒకవేళ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ఒకవేళ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_బహుళకం(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			కొనసాగు;
		స్థితి MUX_S_EXIT_సందేశం:
			ఒకవేళ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ఒకవేళ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ఒకవేళ (exitval_చూసిన)
				fatal_f("exitval sent twice");
			ఒకవేళ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_చూసిన = 1;
			కొనసాగు;
		అప్రమేయ:
			ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ఒకవేళ (rawmode)
		leave_raw_బహుళకం(options.request_tty == REQUEST_TTY_FORCE);

	ఒకవేళ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} లేకపోతే ఒకవేళ (!exitval_చూసిన) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} లేకపోతే
		debug2("Received exit status from master %d", exitval);

	ఒకవేళ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	నిష్క్రమించు(exitval);
}

స్థిర పూర్ణాంకం
mux_client_proxy(పూర్ణాంకం fd)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e;
	u_int type, rid;
	పూర్ణాంకం r;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		తిరిగి 0;
	}
	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ఒకవేళ (type != MUX_S_PROXY) {
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
mux_client_request_stdio_fwd(పూర్ణాంకం fd)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e;
	u_int type, rid, sid;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		తిరిగి -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ఒకవేళ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ఖాళీ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_పోర్టు)) != 0)
		fatal_fr(r, "request");

	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ఒకవేళ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ఒకవేళ (pledge("stdio proc tty", ఖాళీ) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		తిరిగి -1;
	}

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ఎంపిక (type) {
	స్థితి MUX_S_SESSION_OPENED:
		ఒకవేళ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ఆపు;
	స్థితి MUX_S_PERMISSION_DENIED:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	స్థితి MUX_S_FAILURE:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	అప్రమేయ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		తిరిగి -1;
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
	ఒకవేళ (mux_client_read_packet(fd, m) != 0) {
		ఒకవేళ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			తిరిగి 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

స్థిర శూన్య
mux_client_request_stop_listening(పూర్ణాంకం fd)
{
	నిర్మాణం sshbuf *m;
	అక్షరం *e;
	u_int type, rid;
	పూర్ణాంకం r;

	debug3_f("entering");

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new");
	ఒకవేళ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ఒకవేళ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ఒకవేళ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ఒకవేళ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ఒకవేళ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ఎంపిక (type) {
	స్థితి MUX_S_OK:
		ఆపు;
	స్థితి MUX_S_PERMISSION_DENIED:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	స్థితి MUX_S_FAILURE:
		ఒకవేళ ((r = sshbuf_get_cstring(m, &e, ఖాళీ)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	అప్రమేయ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
పూర్ణాంకం
muxclient(స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం sockaddr_un addr;
	పూర్ణాంకం sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	అక్షరం *info = ఖాళీ;

	ఒకవేళ (muxclient_command == 0) {
		ఒకవేళ (options.stdio_forward_host != ఖాళీ)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		లేకపోతే
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	ఎంపిక (options.control_master) {
	స్థితి SSHCTL_MASTER_AUTO:
	స్థితి SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", మార్గం);
		/* FALLTHROUGH */
	స్థితి SSHCTL_MASTER_NO:
		ఆపు;
	అప్రమేయ:
		తిరిగి -1;
	}

	memset(&addr, '\0', పరిమాణం(addr));
	addr.sun_family = AF_UNIX;

	ఒకవేళ (strlcpy(addr.sun_మార్గం, మార్గం,
	    పరిమాణం(addr.sun_మార్గం)) >= పరిమాణం(addr.sun_మార్గం))
		fatal("ControlPath too long ('%s' >= %u bytes)", మార్గం,
		    (గుర్తులేని పూర్ణాంకం)పరిమాణం(addr.sun_మార్గం));

	ఒకవేళ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ఒకవేళ (connect(sock, (నిర్మాణం sockaddr *)&addr, పరిమాణం(addr)) == -1) {
		ఎంపిక (muxclient_command) {
		స్థితి SSHMUX_COMMAND_OPEN:
		స్థితి SSHMUX_COMMAND_STDIO_FWD:
			ఆపు;
		అప్రమేయ:
			fatal("Control socket connect(%.100s): %s", మార్గం,
			    strerror(errno));
		}
		ఒకవేళ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", మార్గం);
			unlink(మార్గం);
		} లేకపోతే ఒకవేళ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", మార్గం);
		} లేకపోతే {
			error("Control socket connect(%.100s): %s", మార్గం,
			    strerror(errno));
		}
		close(sock);
		తిరిగి -1;
	}
	సమితి_nonblock(sock);

	/* Timeout on initial connection only. */
	ఒకవేళ (timeout > 0 && timeout < గరిష్ఠ_పూర్ణాంకం / 1000)
		timeout_ms = timeout * 1000;

	ఒకవేళ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		తిరిగి -1;
	}

	ఎంపిక (muxclient_command) {
	స్థితి SSHMUX_COMMAND_ALIVE_CHECK:
		ఒకవేళ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		నిష్క్రమించు(0);
	స్థితి SSHMUX_COMMAND_CONNINFO:
	స్థితి SSHMUX_COMMAND_CHANINFO:
		ఒకవేళ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ఒకవేళ (info == ఖాళీ)
			fatal_f("info request failed");
		రాయి("%s", info);
		నిష్క్రమించు(0);
	స్థితి SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ఒకవేళ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		నిష్క్రమించు(0);
	స్థితి SSHMUX_COMMAND_FORWARD:
		ఒకవేళ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		నిష్క్రమించు(0);
	స్థితి SSHMUX_COMMAND_OPEN:
		ఒకవేళ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			తిరిగి -1;
		}
		mux_client_request_session(sock);
		తిరిగి -1;
	స్థితి SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		నిష్క్రమించు(0);
	స్థితి SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ఒకవేళ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		నిష్క్రమించు(0);
	స్థితి SSHMUX_COMMAND_CANCEL_FWD:
		ఒకవేళ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		నిష్క్రమించు(0);
	స్థితి SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		తిరిగి (sock);
	అప్రమేయ:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
