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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <poll.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "monitor_fdpass.h"
#અન્તર્ભાવ "sshpty.h"
#અન્તર્ભાવ "readconf.h"
#અન્તર્ભાવ "clientloop.h"

/* from ssh.c */
બાહ્ય પૂર્ણાંક tty_flag;
બાહ્ય Options options;
બાહ્ય અક્ષર *host;
બાહ્ય સંરચના sshbuf *command;
બાહ્ય અસ્થિર sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
સંરચના mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	સંરચના sshbuf *cmd;
	અક્ષર *term;
	સંરચના termios tio;
	અક્ષર **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
સંરચના mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
સંરચના mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	પૂર્ણાંક fid;	/* forward id */
};

/* fd to control socket */
પૂર્ણાંક muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
સ્થિર અસ્થિર sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
સ્થિર u_int muxserver_pid = 0;

સ્થિર Channel *mux_listener_channel = ખાલી;

સંરચના mux_master_state {
	પૂર્ણાંક hello_rcvd;
};

/* mux protocol messages */
#define MUX_સંદેશ_HELLO		0x00000001
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
સ્થિર u_int extensions = 0;

સ્થિર શૂન્ય mux_session_confirm(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, શૂન્ય *);
સ્થિર શૂન્ય mux_stdio_confirm(સંરચના ssh *, પૂર્ણાંક, પૂર્ણાંક, શૂન્ય *);

સ્થિર પૂર્ણાંક mux_master_process_hello(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_new_session(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_alive_check(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_terminate(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_open_fwd(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_close_fwd(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_stdio_fwd(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_stop_listening(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_proxy(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);
સ્થિર પૂર્ણાંક mux_master_process_ext_info(સંરચના ssh *, u_int,
	    Channel *, સંરચના sshbuf *, સંરચના sshbuf *);

સ્થિર અચલ સંરચના {
	u_int type;
	પૂર્ણાંક (*handler)(સંરચના ssh *, u_int, Channel *,
	    સંરચના sshbuf *, સંરચના sshbuf *);
} mux_master_handlers[] = {
	{ MUX_સંદેશ_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, ખાલી }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
સ્થિર શૂન્ય
mux_master_session_cleanup_cb(સંરચના ssh *ssh, પૂર્ણાંક cid, પૂર્ણાંક force, શૂન્ય *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	જો (c == ખાલી)
		fatal_f("channel_by_id(%i) == NULL", cid);
	જો (c->ctl_chan != -1) {
		જો ((cc = channel_by_id(ssh, c->ctl_chan)) == ખાલી)
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
સ્થિર શૂન્ય
mux_master_control_cleanup_cb(સંરચના ssh *ssh, પૂર્ણાંક cid, પૂર્ણાંક force, શૂન્ય *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	જો (c == ખાલી)
		fatal_f("channel_by_id(%i) == NULL", cid);
	જો (c->have_ctl_child_id) {
		જો ((sc = channel_by_id(ssh, c->ctl_child_id)) == ખાલી)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		જો (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} નહીંતર {
			જો (sc->istate == CHAN_આગત_OPEN)
				chan_read_failed(ssh, sc);
			જો (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
સ્થિર પૂર્ણાંક
env_permitted(અચલ અક્ષર *env)
{
	u_int i;
	પૂર્ણાંક ret;
	અક્ષર name[1024], *cp;

	જો ((cp = strchr(env, '=')) == ખાલી || cp == env)
		પાછા 0;
	ret = snprintf(name, કદ(name), "%.*s", (પૂર્ણાંક)(cp - env), env);
	જો (ret <= 0 || (size_t)ret >= કદ(name)) {
		error_f("name '%.100s...' too long", env);
		પાછા 0;
	}

	માટે (i = 0; i < options.અંક_send_env; i++)
		જો (match_pattern(name, options.send_env[i]))
			પાછા 1;

	પાછા 0;
}

/* Mux master protocol message handlers */

સ્થિર પૂર્ણાંક
mux_master_process_hello(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	u_int ver;
	સંરચના mux_master_state *state = (સંરચના mux_master_state *)c->mux_ctx;
	પૂર્ણાંક r;

	જો (state == ખાલી)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	જો (state->hello_rcvd) {
		error_f("HELLO received twice");
		પાછા -1;
	}
	જો ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		પાછા -1;
	}
	જો (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		પાછા -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	જ્યારે (sshbuf_len(m) > 0) {
		અક્ષર *name = ખાલી;
		size_t કિંમત_len = 0;

		જો ((r = sshbuf_get_cstring(m, &name, ખાલી)) != 0 ||
		    (r = sshbuf_get_string_direct(m, ખાલી, &કિંમત_len)) != 0) {
			error_fr(r, "parse extension");
			પાછા -1;
		}
		જો (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} નહીંતર {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, કિંમત_len);
		}
		મુક્ત(name);
	}
	state->hello_rcvd = 1;
	પાછા 0;
}

/* Enqueue a "ok" response to the reply buffer */
સ્થિર શૂન્ય
reply_ok(સંરચના sshbuf *reply, u_int rid)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
સ્થિર શૂન્ય
reply_error(સંરચના sshbuf *reply, u_int type, u_int rid, અચલ અક્ષર *સંદેશ)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, સંદેશ)) != 0)
		fatal_fr(r, "reply");
}

સ્થિર પૂર્ણાંક
mux_master_process_new_session(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	Channel *nc;
	સંરચના mux_session_confirm_ctx *cctx;
	અક્ષર *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	પૂર્ણાંક r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, કદ(*cctx));
	cctx->term = ખાલી;
	cctx->rid = rid;
	cmd = ખાલી;
	cctx->env = ખાલી;
	env_len = 0;
	જો ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, ખાલી)) != 0) {
 malf:
		મુક્ત(cmd);
		માટે (j = 0; j < env_len; j++)
			મુક્ત(cctx->env[j]);
		મુક્ત(cctx->env);
		મુક્ત(cctx->term);
		મુક્ત(cctx);
		error_f("malformed message");
		પાછા -1;
	}

#define MUX_MAX_ENV_VARS	4096
	જ્યારે (sshbuf_len(m) > 0) {
		જો ((r = sshbuf_get_cstring(m, &cp, ખાલી)) != 0)
			જાઓ malf;
		જો (!env_permitted(cp)) {
			મુક્ત(cp);
			ચાલુ;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    કદ(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = ખાલી;
		જો (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			તોડો;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	જો ((cctx->cmd = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	મુક્ત(cmd);
	cmd = ખાલી;

	/* Gather fds from client */
	માટે(i = 0; i < 3; i++) {
		જો ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			માટે (j = 0; j < i; j++)
				close(new_fd[j]);
			માટે (j = 0; j < env_len; j++)
				મુક્ત(cctx->env[j]);
			મુક્ત(cctx->env);
			મુક્ત(cctx->term);
			sshbuf_free(cctx->cmd);
			મુક્ત(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			પાછા -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	જો (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		મુક્ત(cctx->term);
		જો (env_len != 0) {
			માટે (i = 0; i < env_len; i++)
				મુક્ત(cctx->env[i]);
			મુક્ત(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		મુક્ત(cctx);
		પાછા 0;
	}

	જો (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		જો (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			જાઓ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	જો (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	જો (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	જો (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	જો (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, ખાલી,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((પૂર્ણાંક)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_master_process_alive_check(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	પૂર્ણાંક r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	જો ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	પાછા 0;
}

/* The "info" extension. */
સ્થિર પૂર્ણાંક
mux_master_process_ext_info(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	પૂર્ણાંક r;
	u_int status = 0;
	અક્ષર *name = ખાલી, *સંદેશ = ખાલી;

	debug2_f("channel %d: info request", c->self);

	જો ((r = sshbuf_get_cstring(m, &name, ખાલી)) != 0)
		fatal_fr(r, "parse");

	જો (strcmp(name, "connection") == 0) {
		જો ((સંદેશ = connection_info_message(ssh)) == ખાલી)
			fatal_f("connection_info_message");
		status = 1;
	} નહીંતર જો (strcmp(name, "channels") == 0) {
		જો ((સંદેશ = channel_open_message(ssh)) == ખાલી)
			fatal_f("channel_open_message");
		status = 1;
	} નહીંતર {
		સંદેશ = xstrdup("info request type not supported");
	}

	/* prepare reply */
	જો ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, સંદેશ)) != 0)
		fatal_fr(r, "reply");
	મુક્ત(સંદેશ);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_master_process_terminate(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	જો (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		જો (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			પાછા 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	પાછા 0;
}

સ્થિર અક્ષર *
format_forward(u_int ftype, સંરચના Forward *fwd)
{
	અક્ષર *ret;

	પસંદગી (ftype) {
	સ્થિતિ MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ખાલી) ? fwd->listen_path :
		    (fwd->listen_host == ખાલી) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != ખાલી) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		તોડો;
	સ્થિતિ MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == ખાલી) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		તોડો;
	સ્થિતિ MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ખાલી) ? fwd->listen_path :
		    (fwd->listen_host == ખાલી) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != ખાલી) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		તોડો;
	મૂળભૂત:
		fatal_f("unknown forward type %u", ftype);
	}
	પાછા ret;
}

સ્થિર પૂર્ણાંક
compare_host(અચલ અક્ષર *a, અચલ અક્ષર *b)
{
	જો (a == ખાલી && b == ખાલી)
		પાછા 1;
	જો (a == ખાલી || b == ખાલી)
		પાછા 0;
	પાછા strcmp(a, b) == 0;
}

સ્થિર પૂર્ણાંક
compare_forward(સંરચના Forward *a, સંરચના Forward *b)
{
	જો (!compare_host(a->listen_host, b->listen_host))
		પાછા 0;
	જો (!compare_host(a->listen_path, b->listen_path))
		પાછા 0;
	જો (a->listen_port != b->listen_port)
		પાછા 0;
	જો (!compare_host(a->connect_host, b->connect_host))
		પાછા 0;
	જો (!compare_host(a->connect_path, b->connect_path))
		પાછા 0;
	જો (a->connect_port != b->connect_port)
		પાછા 0;

	પાછા 1;
}

સ્થિર શૂન્ય
mux_confirm_remote_forward(સંરચના ssh *ssh, પૂર્ણાંક type, uint32_t seq, શૂન્ય *ctxt)
{
	સંરચના mux_channel_confirm_ctx *fctx = ctxt;
	અક્ષર *failmsg = ખાલી;
	સંરચના Forward *rfwd;
	Channel *c;
	સંરચના sshbuf *out;
	u_int port;
	પૂર્ણાંક r;

	જો ((c = channel_by_id(ssh, fctx->cid)) == ખાલી) {
		/* no channel for reply */
		error_f("unknown channel");
		પાછા;
	}
	જો ((out = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો (fctx->fid >= options.અંક_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == ખાલી &&
	    options.remote_forwards[fctx->fid].connect_host == ખાલી)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		જાઓ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_સંદેશ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	જો (type == SSH2_સંદેશ_REQUEST_SUCCESS) {
		જો (rfwd->listen_port == 0) {
			જો ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			જો (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (પૂર્ણાંક)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			જો ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} નહીંતર {
			reply_ok(out, fctx->rid);
		}
		જાઓ out;
	} નહીંતર {
		જો (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		જો (rfwd->listen_path != ખાલી)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		નહીંતર
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		મુક્ત(rfwd->listen_host);
		મુક્ત(rfwd->listen_path);
		મુક્ત(rfwd->connect_host);
		મુક્ત(rfwd->connect_path);
		memset(rfwd, 0, કદ(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	મુક્ત(failmsg);
 out:
	જો ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	જો (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	મુક્ત(fctx);
}

સ્થિર પૂર્ણાંક
mux_master_process_open_fwd(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	સંરચના Forward fwd;
	અક્ષર *fwd_desc = ખાલી;
	અક્ષર *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	પૂર્ણાંક r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, કદ(fwd));

	/* XXX - lport/cport check redundant */
	જો ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		જાઓ out;
	}
	જો (*listen_addr == '\0') {
		મુક્ત(listen_addr);
		listen_addr = ખાલી;
	}
	જો (*connect_addr == '\0') {
		મુક્ત(connect_addr);
		connect_addr = ખાલી;
	}

	memset(&fwd, 0, કદ(fwd));
	fwd.listen_port = lport;
	જો (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	નહીંતર
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	જો (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	નહીંતર
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	જો (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		મુક્ત(listen_addr);
		મુક્ત(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		પાછા 0;
	}
	જો (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		જાઓ invalid;
	}
	જો (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		જાઓ invalid;
	}
	જો ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		જાઓ invalid;
	}
	જો (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == ખાલી &&
	    fwd.connect_path == ખાલી) {
		logit_f("missing connect host");
		જાઓ invalid;
	}

	/* Skip forwards that have already been requested */
	પસંદગી (ftype) {
	સ્થિતિ MUX_FWD_LOCAL:
	સ્થિતિ MUX_FWD_DYNAMIC:
		માટે (i = 0; i < options.અંક_local_forwards; i++) {
			જો (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				જાઓ out;
			}
		}
		તોડો;
	સ્થિતિ MUX_FWD_REMOTE:
		માટે (i = 0; i < options.અંક_remote_forwards; i++) {
			જો (!compare_forward(&fwd, options.remote_forwards + i))
				ચાલુ;
			જો (fwd.listen_port != 0)
				જાઓ exists;
			debug2_f("found allocated port");
			જો ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			જાઓ out;
		}
		તોડો;
	}

	જો (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		જો (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			જાઓ out;
		}
	}

	જો (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		જો (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			જાઓ out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} નહીંતર {
		સંરચના mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		જો (fwd.handle < 0)
			જાઓ fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, કદ(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.અંક_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		જાઓ out;
	}
	reply_ok(reply, rid);
 out:
	મુક્ત(fwd_desc);
	જો (freefwd) {
		મુક્ત(fwd.listen_host);
		મુક્ત(fwd.listen_path);
		મુક્ત(fwd.connect_host);
		મુક્ત(fwd.connect_path);
	}
	પાછા ret;
}

સ્થિર પૂર્ણાંક
mux_master_process_close_fwd(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	સંરચના Forward fwd, *found_fwd;
	અક્ષર *fwd_desc = ખાલી;
	અચલ અક્ષર *error_reason = ખાલી;
	અક્ષર *listen_addr = ખાલી, *connect_addr = ખાલી;
	u_int ftype;
	પૂર્ણાંક r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, કદ(fwd));

	જો ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		જાઓ out;
	}

	જો (*listen_addr == '\0') {
		મુક્ત(listen_addr);
		listen_addr = ખાલી;
	}
	જો (*connect_addr == '\0') {
		મુક્ત(connect_addr);
		connect_addr = ખાલી;
	}

	memset(&fwd, 0, કદ(fwd));
	fwd.listen_port = lport;
	જો (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	નહીંતર
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	જો (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	નહીંતર
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = ખાલી;
	પસંદગી (ftype) {
	સ્થિતિ MUX_FWD_LOCAL:
	સ્થિતિ MUX_FWD_DYNAMIC:
		માટે (i = 0; i < options.અંક_local_forwards; i++) {
			જો (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				તોડો;
			}
		}
		તોડો;
	સ્થિતિ MUX_FWD_REMOTE:
		માટે (i = 0; i < options.અંક_remote_forwards; i++) {
			જો (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				તોડો;
			}
		}
		તોડો;
	}

	જો (found_fwd == ખાલી)
		error_reason = "port not forwarded";
	નહીંતર જો (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		જો (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} નહીંતર {	/* local and dynamic forwards */
		/* Ditto */
		જો (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	જો (error_reason != ખાલી)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	નહીંતર {
		reply_ok(reply, rid);
		મુક્ત(found_fwd->listen_host);
		મુક્ત(found_fwd->listen_path);
		મુક્ત(found_fwd->connect_host);
		મુક્ત(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = ખાલી;
		found_fwd->listen_path = found_fwd->connect_path = ખાલી;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	મુક્ત(fwd_desc);
	મુક્ત(listen_addr);
	મુક્ત(connect_addr);

	પાછા ret;
}

સ્થિર પૂર્ણાંક
mux_master_process_stdio_fwd(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	Channel *nc;
	અક્ષર *chost = ખાલી;
	u_int _cport, i, j;
	પૂર્ણાંક ok = 0, cport, r, new_fd[2];
	સંરચના mux_stdio_confirm_ctx *cctx;

	જો ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		મુક્ત(chost);
		error_f("malformed message");
		પાછા -1;
	}
	જો (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	નહીંતર જો (_cport <= INT_MAX)
		cport = (પૂર્ણાંક)_cport;
	નહીંતર {
		મુક્ત(chost);
		error_f("invalid port 0x%x", _cport);
		પાછા -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	માટે(i = 0; i < 2; i++) {
		જો ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			માટે (j = 0; j < i; j++)
				close(new_fd[j]);
			મુક્ત(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			પાછા -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	જો (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		મુક્ત(chost);
		પાછા 0;
	}

	જો (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		જો (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} નહીંતર {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		જો (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			જાઓ cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	મુક્ત(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, કદ(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	પાછા 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
સ્થિર શૂન્ય
mux_stdio_confirm(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક success, શૂન્ય *arg)
{
	સંરચના mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	સંરચના sshbuf *reply;
	પૂર્ણાંક r;

	જો (cctx == ખાલી)
		fatal_f("cctx == NULL");
	જો ((c = channel_by_id(ssh, id)) == ખાલી)
		fatal_f("no channel for id %d", id);
	જો ((cc = channel_by_id(ssh, c->ctl_chan)) == ખાલી)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	જો ((reply = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");

	જો (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		જાઓ done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	જો ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	જો ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	જો (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ખાલી;
	મુક્ત(cctx);
}

સ્થિર પૂર્ણાંક
mux_master_process_stop_listening(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	જો (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		જો (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			પાછા 0;
		}
	}

	જો (mux_listener_channel != ખાલી) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		મુક્ત(options.control_path);
		options.control_path = ખાલી;
		mux_listener_channel = ખાલી;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_master_process_proxy(સંરચના ssh *ssh, u_int rid,
    Channel *c, સંરચના sshbuf *m, સંરચના sshbuf *reply)
{
	પૂર્ણાંક r;

	debug_f("channel %d: proxy request", c->self);

	જો (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		જો (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			પાછા 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	જો ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	પાછા 0;
}

/* Channel callbacks fired on read/write from mux client fd */
સ્થિર પૂર્ણાંક
mux_master_read_cb(સંરચના ssh *ssh, Channel *c)
{
	સંરચના mux_master_state *state = (સંરચના mux_master_state *)c->mux_ctx;
	સંરચના sshbuf *in = ખાલી, *out = ખાલી;
	u_int type, rid, i;
	પૂર્ણાંક r, ret = -1;

	જો ((out = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	જો (c->mux_ctx == ખાલી) {
		state = xcalloc(1, કદ(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		જો ((r = sshbuf_put_u32(out, MUX_સંદેશ_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		જો ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		જો ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		જાઓ out;
	}

	/* Channel code ensures that we receive whole packets */
	જો ((r = sshbuf_froms(c->આગત, &in)) != 0) {
 malf:
		error_f("malformed message");
		જાઓ out;
	}

	જો ((r = sshbuf_get_u32(in, &type)) != 0)
		જાઓ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	જો (type == MUX_સંદેશ_HELLO)
		rid = 0;
	નહીંતર {
		જો (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_સંદેશ_HELLO, type);
			જાઓ out;
		}
		જો ((r = sshbuf_get_u32(in, &rid)) != 0)
			જાઓ malf;
	}

	માટે (i = 0; mux_master_handlers[i].handler != ખાલી; i++) {
		જો (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			તોડો;
		}
	}
	જો (mux_master_handlers[i].handler == ખાલી) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	જો (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	પાછા ret;
}

શૂન્ય
mux_exit_message(સંરચના ssh *ssh, Channel *c, પૂર્ણાંક exitval)
{
	સંરચના sshbuf *m;
	Channel *mux_chan;
	પૂર્ણાંક r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	જો ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ખાલી)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

શૂન્ય
mux_tty_alloc_failed(સંરચના ssh *ssh, Channel *c)
{
	સંરચના sshbuf *m;
	Channel *mux_chan;
	પૂર્ણાંક r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	જો ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ખાલી)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
શૂન્ય
muxserver_listen(સંરચના ssh *ssh)
{
	mode_t old_umask;
	અક્ષર *orig_control_path = options.control_path;
	અક્ષર rbuf[16+1];
	u_int i, r;
	પૂર્ણાંક oerrno;

	જો (options.control_path == ખાલી ||
	    options.control_master == SSHCTL_MASTER_NO)
		પાછા;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	માટે (i = 0; i < કદ(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[કદ(rbuf) - 1] = '\0';
	options.control_path = ખાલી;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	જો (muxserver_sock < 0) {
		જો (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			જો (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			મુક્ત(orig_control_path);
			મુક્ત(options.control_path);
			options.control_path = ખાલી;
			options.control_master = SSHCTL_MASTER_NO;
			પાછા;
		} નહીંતર {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	જો (link(options.control_path, orig_control_path) != 0) {
		જો (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		જાઓ disable_mux_master;
	}
	unlink(options.control_path);
	મુક્ત(options.control_path);
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
સ્થિર શૂન્ય
mux_session_confirm(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક success, શૂન્ય *arg)
{
	સંરચના mux_session_confirm_ctx *cctx = arg;
	અચલ અક્ષર *display;
	Channel *c, *cc;
	પૂર્ણાંક i, r;
	સંરચના sshbuf *reply;

	જો (cctx == ખાલી)
		fatal_f("cctx == NULL");
	જો ((c = channel_by_id(ssh, id)) == ખાલી)
		fatal_f("no channel for id %d", id);
	જો ((cc = channel_by_id(ssh, c->ctl_chan)) == ખાલી)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	જો ((reply = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");

	જો (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		જાઓ done;
	}

	display = getenv("DISPLAY");
	જો (cctx->want_x_fwd && options.forward_x11 && display != ખાલી) {
		અક્ષર *proto, *data;

		/* Get reasonable local authentication information. */
		જો (client_x11_get_proto(ssh, display, options.xauth_location,
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

	જો (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	જો ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	જો ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	જો (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ખાલી;
	sshbuf_free(cctx->cmd);
	મુક્ત(cctx->term);
	જો (cctx->env != ખાલી) {
		માટે (i = 0; cctx->env[i] != ખાલી; i++)
			મુક્ત(cctx->env[i]);
		મુક્ત(cctx->env);
	}
	મુક્ત(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
સ્થિર શૂન્ય
control_client_sighandler(પૂર્ણાંક signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
સ્થિર શૂન્ય
control_client_sigrelay(પૂર્ણાંક signo)
{
	પૂર્ણાંક save_errno = errno;

	જો (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

સ્થિર પૂર્ણાંક
mux_client_read(પૂર્ણાંક fd, સંરચના sshbuf *b, size_t need, પૂર્ણાંક timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	પૂર્ણાંક r;

	જો ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	માટે (have = 0; have < need; ) {
		જો (muxclient_terminate) {
			errno = EINTR;
			પાછા -1;
		}
		len = પઠ(fd, p + have, need - have);
		જો (len == -1) {
			પસંદગી (errno) {
#જો defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			સ્થિતિ EWOULDBLOCK:
#endif
			સ્થિતિ EAGAIN:
				જો (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					પાછા -1;	/* timeout */
				/* FALLTHROUGH */
			સ્થિતિ EINTR:
				ચાલુ;
			મૂળભૂત:
				પાછા -1;
			}
		}
		જો (len == 0) {
			errno = EPIPE;
			પાછા -1;
		}
		have += (size_t)len;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_client_write_packet(પૂર્ણાંક fd, સંરચના sshbuf *m)
{
	સંરચના sshbuf *queue;
	u_int have, need;
	પૂર્ણાંક r, oerrno, len;
	અચલ u_char *ptr;
	સંરચના pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	જો ((queue = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	માટે (have = 0; have < need; ) {
		જો (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			પાછા -1;
		}
		len = લિખ(fd, ptr + have, need - have);
		જો (len == -1) {
			પસંદગી (errno) {
#જો defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			સ્થિતિ EWOULDBLOCK:
#endif
			સ્થિતિ EAGAIN:
				(શૂન્ય)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			સ્થિતિ EINTR:
				ચાલુ;
			મૂળભૂત:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				પાછા -1;
			}
		}
		જો (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			પાછા -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_client_read_packet_timeout(પૂર્ણાંક fd, સંરચના sshbuf *m, પૂર્ણાંક timeout_ms)
{
	સંરચના sshbuf *queue;
	size_t need, have;
	અચલ u_char *ptr;
	પૂર્ણાંક r, oerrno;

	જો ((queue = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		જો ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		પાછા -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	જો (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		પાછા -1;
	}
	જો ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_client_read_packet(પૂર્ણાંક fd, સંરચના sshbuf *m)
{
	પાછા mux_client_read_packet_timeout(fd, m, -1);
}

સ્થિર પૂર્ણાંક
mux_client_hello_exchange(પૂર્ણાંક fd, પૂર્ણાંક timeout_ms)
{
	સંરચના sshbuf *m;
	u_int type, ver;
	પૂર્ણાંક r, ret = -1;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_સંદેશ_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	જો (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		જાઓ out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	જો (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		જાઓ out;
	}

	જો ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	જો (type != MUX_સંદેશ_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_સંદેશ_HELLO, type);
		જાઓ out;
	}
	જો ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	જો (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		જાઓ out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	જ્યારે (sshbuf_len(m) > 0) {
		અક્ષર *name = ખાલી;

		જો ((r = sshbuf_get_cstring(m, &name, ખાલી)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*કિંમત*/
			error_fr(r, "parse extension");
			જાઓ out;
		}
		/* Process extensions. */
		જો (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} નહીંતર {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		મુક્ત(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	પાછા ret;
}

સ્થિર u_int
mux_client_request_alive(પૂર્ણાંક fd)
{
	સંરચના sshbuf *m;
	અક્ષર *e;
	u_int pid, type, rid;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	જો (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		પાછા 0;
	}

	જો ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	જો (type != MUX_S_ALIVE) {
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	જો ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	જો ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	પાછા pid;
}

સ્થિર અક્ષર *
mux_client_request_info(પૂર્ણાંક fd, અચલ અક્ષર *name)
{
	સંરચના sshbuf *m;
	અક્ષર *e, *સંદેશ;
	u_int type, rid, status;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	જો (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		પાછા 0;
	}

	જો ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	જો (type != MUX_S_EXT_INFO) {
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	જો ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	જો ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &સંદેશ, ખાલી)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	પાછા સંદેશ;
}

સ્થિર શૂન્ય
mux_client_request_terminate(પૂર્ણાંક fd)
{
	સંરચના sshbuf *m;
	અક્ષર *e;
	u_int type, rid;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	જો (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		જો (errno == EPIPE) {
			sshbuf_free(m);
			પાછા;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	જો ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	પસંદગી (type) {
	સ્થિતિ MUX_S_OK:
		તોડો;
	સ્થિતિ MUX_S_PERMISSION_DENIED:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	સ્થિતિ MUX_S_FAILURE:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	મૂળભૂત:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

સ્થિર પૂર્ણાંક
mux_client_forward(પૂર્ણાંક fd, પૂર્ણાંક cancel_flag, u_int ftype, સંરચના Forward *fwd)
{
	સંરચના sshbuf *m;
	અક્ષર *e, *fwd_desc;
	અચલ અક્ષર *lhost, *chost;
	u_int type, rid;
	પૂર્ણાંક r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	મુક્ત(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	જો (fwd->listen_path != ખાલી)
		lhost = fwd->listen_path;
	નહીંતર જો (fwd->listen_host == ખાલી)
		lhost = "";
	નહીંતર જો (*fwd->listen_host == '\0')
		lhost = "*";
	નહીંતર
		lhost = fwd->listen_host;

	જો (fwd->connect_path != ખાલી)
		chost = fwd->connect_path;
	નહીંતર જો (fwd->connect_host == ખાલી)
		chost = "";
	નહીંતર
		chost = fwd->connect_host;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	જો (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		પાછા -1;
	}

	જો ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	પસંદગી (type) {
	સ્થિતિ MUX_S_OK:
		તોડો;
	સ્થિતિ MUX_S_REMOTE_PORT:
		જો (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		જો ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		જો (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		તોડો;
	સ્થિતિ MUX_S_PERMISSION_DENIED:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		પાછા -1;
	સ્થિતિ MUX_S_FAILURE:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		પાછા -1;
	મૂળભૂત:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_client_forwards(પૂર્ણાંક fd, પૂર્ણાંક cancel_flag)
{
	પૂર્ણાંક i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.અંક_local_forwards, options.અંક_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	માટે (i = 0; i < options.અંક_local_forwards; i++) {
		જો (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	માટે (i = 0; i < options.અંક_remote_forwards; i++) {
		જો (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	પાછા ret;
}

સ્થિર પૂર્ણાંક
mux_client_request_session(પૂર્ણાંક fd)
{
	સંરચના sshbuf *m;
	અક્ષર *e;
	અચલ અક્ષર *term = ખાલી;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	બાહ્ય અક્ષર **environ;
	પૂર્ણાંક r, rawmode = 0;

	debug3_f("entering");

	જો ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		પાછા -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	જો (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	જો ((term = lookup_env_in_list("TERM", options.setenv,
	    options.અંક_setenv)) == ખાલી || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	જો (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ખાલી, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == ખાલી ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	જો (options.અંક_send_env > 0 && environ != ખાલી) {
		માટે (i = 0; environ[i] != ખાલી; i++) {
			જો (!env_permitted(environ[i]))
				ચાલુ;
			જો ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	માટે (i = 0; i < options.અંક_setenv; i++) {
		જો ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	જો (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	જો (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		પાછા -1;
	}

	જો ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	પસંદગી (type) {
	સ્થિતિ MUX_S_SESSION_OPENED:
		જો ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		તોડો;
	સ્થિતિ MUX_S_PERMISSION_DENIED:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		પાછા -1;
	સ્થિતિ MUX_S_FAILURE:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		પાછા -1;
	મૂળભૂત:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		પાછા -1;
	}
	muxclient_request_id++;

	જો (pledge("stdio proc tty", ખાલી) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	જો (options.fork_after_authentication)
		daemon(1, 1);
	નહીંતર {
		rawmode = tty_flag;
		જો (tty_flag) {
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
	માટે (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		જો (mux_client_read_packet(fd, m) != 0)
			તોડો;
		જો ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		પસંદગી (type) {
		સ્થિતિ MUX_S_TTY_ALLOC_FAIL:
			જો ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			જો (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			ચાલુ;
		સ્થિતિ MUX_S_EXIT_MESSAGE:
			જો ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			જો (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			જો (exitval_seen)
				fatal_f("exitval sent twice");
			જો ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			ચાલુ;
		મૂળભૂત:
			જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	જો (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	જો (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} નહીંતર જો (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} નહીંતર
		debug2("Received exit status from master %d", exitval);

	જો (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

સ્થિર પૂર્ણાંક
mux_client_proxy(પૂર્ણાંક fd)
{
	સંરચના sshbuf *m;
	અક્ષર *e;
	u_int type, rid;
	પૂર્ણાંક r;

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	જો (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		પાછા 0;
	}
	જો ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	જો (type != MUX_S_PROXY) {
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
mux_client_request_stdio_fwd(પૂર્ણાંક fd)
{
	સંરચના sshbuf *m;
	અક્ષર *e;
	u_int type, rid, sid;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		પાછા -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	જો (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ખાલી, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	જો (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	જો (pledge("stdio proc tty", ખાલી) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	જો (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		પાછા -1;
	}

	જો ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	પસંદગી (type) {
	સ્થિતિ MUX_S_SESSION_OPENED:
		જો ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		તોડો;
	સ્થિતિ MUX_S_PERMISSION_DENIED:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	સ્થિતિ MUX_S_FAILURE:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	મૂળભૂત:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		પાછા -1;
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
	જો (mux_client_read_packet(fd, m) != 0) {
		જો (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			પાછા 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

સ્થિર શૂન્ય
mux_client_request_stop_listening(પૂર્ણાંક fd)
{
	સંરચના sshbuf *m;
	અક્ષર *e;
	u_int type, rid;
	પૂર્ણાંક r;

	debug3_f("entering");

	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new");
	જો ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	જો (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	જો (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	જો ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	જો (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	પસંદગી (type) {
	સ્થિતિ MUX_S_OK:
		તોડો;
	સ્થિતિ MUX_S_PERMISSION_DENIED:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	સ્થિતિ MUX_S_FAILURE:
		જો ((r = sshbuf_get_cstring(m, &e, ખાલી)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	મૂળભૂત:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
પૂર્ણાંક
muxclient(અચલ અક્ષર *path)
{
	સંરચના sockaddr_un addr;
	પૂર્ણાંક sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	અક્ષર *info = ખાલી;

	જો (muxclient_command == 0) {
		જો (options.stdio_forward_host != ખાલી)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		નહીંતર
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	પસંદગી (options.control_master) {
	સ્થિતિ SSHCTL_MASTER_AUTO:
	સ્થિતિ SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	સ્થિતિ SSHCTL_MASTER_NO:
		તોડો;
	મૂળભૂત:
		પાછા -1;
	}

	memset(&addr, '\0', કદ(addr));
	addr.sun_family = AF_UNIX;

	જો (strlcpy(addr.sun_path, path,
	    કદ(addr.sun_path)) >= કદ(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned પૂર્ણાંક)કદ(addr.sun_path));

	જો ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	જો (connect(sock, (સંરચના sockaddr *)&addr, કદ(addr)) == -1) {
		પસંદગી (muxclient_command) {
		સ્થિતિ SSHMUX_COMMAND_OPEN:
		સ્થિતિ SSHMUX_COMMAND_STDIO_FWD:
			તોડો;
		મૂળભૂત:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		જો (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} નહીંતર જો (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} નહીંતર {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		પાછા -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	જો (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	જો (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		પાછા -1;
	}

	પસંદગી (muxclient_command) {
	સ્થિતિ SSHMUX_COMMAND_ALIVE_CHECK:
		જો ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	સ્થિતિ SSHMUX_COMMAND_CONNINFO:
	સ્થિતિ SSHMUX_COMMAND_CHANINFO:
		જો (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		જો (info == ખાલી)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	સ્થિતિ SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		જો (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	સ્થિતિ SSHMUX_COMMAND_FORWARD:
		જો (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	સ્થિતિ SSHMUX_COMMAND_OPEN:
		જો (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			પાછા -1;
		}
		mux_client_request_session(sock);
		પાછા -1;
	સ્થિતિ SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	સ્થિતિ SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		જો (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	સ્થિતિ SSHMUX_COMMAND_CANCEL_FWD:
		જો (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	સ્થિતિ SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		પાછા (sock);
	મૂળભૂત:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
