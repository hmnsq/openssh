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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/queue.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/un.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <poll.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "ssh2.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "channels.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "monitor_fdpass.h"
#অন্তর্ভাৱ "sshpty.h"
#অন্তর্ভাৱ "readconf.h"
#অন্তর্ভাৱ "clientloop.h"

/* from ssh.c */
বাহ্য পূর্ণাঙ্ক tty_flag;
বাহ্য Options options;
বাহ্য ৱর্ণ *host;
বাহ্য সংরচনা sshbuf *command;
বাহ্য চঞ্চল sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
সংরচনা mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	সংরচনা sshbuf *cmd;
	ৱর্ণ *term;
	সংরচনা termios tio;
	ৱর্ণ **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
সংরচনা mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
সংরচনা mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	পূর্ণাঙ্ক fid;	/* forward id */
};

/* fd to control socket */
পূর্ণাঙ্ক muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
স্থির চঞ্চল sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
স্থির u_int muxserver_pid = 0;

স্থির Channel *mux_listener_channel = রিক্ত;

সংরচনা mux_master_state {
	পূর্ণাঙ্ক hello_rcvd;
};

/* mux protocol messages */
#define MUX_বাৰ্তা_HELLO		0x00000001
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
স্থির u_int extensions = 0;

স্থির শূন্য mux_session_confirm(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক, শূন্য *);
স্থির শূন্য mux_stdio_confirm(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক, শূন্য *);

স্থির পূর্ণাঙ্ক mux_master_process_hello(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_new_session(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_alive_check(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_terminate(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_open_fwd(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_close_fwd(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_stdio_fwd(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_stop_listening(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_proxy(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);
স্থির পূর্ণাঙ্ক mux_master_process_ext_info(সংরচনা ssh *, u_int,
	    Channel *, সংরচনা sshbuf *, সংরচনা sshbuf *);

স্থির ধ্রুৱ সংরচনা {
	u_int type;
	পূর্ণাঙ্ক (*handler)(সংরচনা ssh *, u_int, Channel *,
	    সংরচনা sshbuf *, সংরচনা sshbuf *);
} mux_master_handlers[] = {
	{ MUX_বাৰ্তা_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, রিক্ত }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
স্থির শূন্য
mux_master_session_cleanup_cb(সংরচনা ssh *ssh, পূর্ণাঙ্ক cid, পূর্ণাঙ্ক force, শূন্য *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	যদি (c == রিক্ত)
		fatal_f("channel_by_id(%i) == NULL", cid);
	যদি (c->ctl_chan != -1) {
		যদি ((cc = channel_by_id(ssh, c->ctl_chan)) == রিক্ত)
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
স্থির শূন্য
mux_master_control_cleanup_cb(সংরচনা ssh *ssh, পূর্ণাঙ্ক cid, পূর্ণাঙ্ক force, শূন্য *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	যদি (c == রিক্ত)
		fatal_f("channel_by_id(%i) == NULL", cid);
	যদি (c->have_ctl_child_id) {
		যদি ((sc = channel_by_id(ssh, c->ctl_child_id)) == রিক্ত)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		যদি (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} অন্যথা {
			যদি (sc->istate == CHAN_প্ৰবেশ_OPEN)
				chan_read_failed(ssh, sc);
			যদি (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
স্থির পূর্ণাঙ্ক
env_permitted(ধ্রুৱ ৱর্ণ *env)
{
	u_int i;
	পূর্ণাঙ্ক ret;
	ৱর্ণ name[1024], *cp;

	যদি ((cp = strchr(env, '=')) == রিক্ত || cp == env)
		ঘূৰাই 0;
	ret = snprintf(name, পরিমাণ(name), "%.*s", (পূর্ণাঙ্ক)(cp - env), env);
	যদি (ret <= 0 || (size_t)ret >= পরিমাণ(name)) {
		error_f("name '%.100s...' too long", env);
		ঘূৰাই 0;
	}

	বাবে (i = 0; i < options.অঙ্ক_send_env; i++)
		যদি (match_pattern(name, options.send_env[i]))
			ঘূৰাই 1;

	ঘূৰাই 0;
}

/* Mux master protocol message handlers */

স্থির পূর্ণাঙ্ক
mux_master_process_hello(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	u_int ver;
	সংরচনা mux_master_state *state = (সংরচনা mux_master_state *)c->mux_ctx;
	পূর্ণাঙ্ক r;

	যদি (state == রিক্ত)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	যদি (state->hello_rcvd) {
		error_f("HELLO received twice");
		ঘূৰাই -1;
	}
	যদি ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ঘূৰাই -1;
	}
	যদি (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ঘূৰাই -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	যেতিয়ালৈ (sshbuf_len(m) > 0) {
		ৱর্ণ *name = রিক্ত;
		size_t মান_len = 0;

		যদি ((r = sshbuf_get_cstring(m, &name, রিক্ত)) != 0 ||
		    (r = sshbuf_get_string_direct(m, রিক্ত, &মান_len)) != 0) {
			error_fr(r, "parse extension");
			ঘূৰাই -1;
		}
		যদি (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} অন্যথা {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, মান_len);
		}
		মুক্ত(name);
	}
	state->hello_rcvd = 1;
	ঘূৰাই 0;
}

/* Enqueue a "ok" response to the reply buffer */
স্থির শূন্য
reply_ok(সংরচনা sshbuf *reply, u_int rid)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
স্থির শূন্য
reply_error(সংরচনা sshbuf *reply, u_int type, u_int rid, ধ্রুৱ ৱর্ণ *বাৰ্তা)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, বাৰ্তা)) != 0)
		fatal_fr(r, "reply");
}

স্থির পূর্ণাঙ্ক
mux_master_process_new_session(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	Channel *nc;
	সংরচনা mux_session_confirm_ctx *cctx;
	ৱর্ণ *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	পূর্ণাঙ্ক r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, পরিমাণ(*cctx));
	cctx->term = রিক্ত;
	cctx->rid = rid;
	cmd = রিক্ত;
	cctx->env = রিক্ত;
	env_len = 0;
	যদি ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, রিক্ত)) != 0) {
 malf:
		মুক্ত(cmd);
		বাবে (j = 0; j < env_len; j++)
			মুক্ত(cctx->env[j]);
		মুক্ত(cctx->env);
		মুক্ত(cctx->term);
		মুক্ত(cctx);
		error_f("malformed message");
		ঘূৰাই -1;
	}

#define MUX_MAX_ENV_VARS	4096
	যেতিয়ালৈ (sshbuf_len(m) > 0) {
		যদি ((r = sshbuf_get_cstring(m, &cp, রিক্ত)) != 0)
			গচ্ছ malf;
		যদি (!env_permitted(cp)) {
			মুক্ত(cp);
			অনুৱর্ত;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    পরিমাণ(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = রিক্ত;
		যদি (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			ভঙ্গ;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	যদি ((cctx->cmd = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	মুক্ত(cmd);
	cmd = রিক্ত;

	/* Gather fds from client */
	বাবে(i = 0; i < 3; i++) {
		যদি ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			বাবে (j = 0; j < i; j++)
				close(new_fd[j]);
			বাবে (j = 0; j < env_len; j++)
				মুক্ত(cctx->env[j]);
			মুক্ত(cctx->env);
			মুক্ত(cctx->term);
			sshbuf_free(cctx->cmd);
			মুক্ত(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ঘূৰাই -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	যদি (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		মুক্ত(cctx->term);
		যদি (env_len != 0) {
			বাবে (i = 0; i < env_len; i++)
				মুক্ত(cctx->env[i]);
			মুক্ত(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		মুক্ত(cctx);
		ঘূৰাই 0;
	}

	যদি (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		যদি (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			গচ্ছ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	যদি (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	যদি (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	যদি (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	যদি (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, রিক্ত,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((পূর্ণাঙ্ক)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_master_process_alive_check(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	পূর্ণাঙ্ক r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	যদি ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ঘূৰাই 0;
}

/* The "info" extension. */
স্থির পূর্ণাঙ্ক
mux_master_process_ext_info(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	পূর্ণাঙ্ক r;
	u_int status = 0;
	ৱর্ণ *name = রিক্ত, *বাৰ্তা = রিক্ত;

	debug2_f("channel %d: info request", c->self);

	যদি ((r = sshbuf_get_cstring(m, &name, রিক্ত)) != 0)
		fatal_fr(r, "parse");

	যদি (strcmp(name, "connection") == 0) {
		যদি ((বাৰ্তা = connection_info_message(ssh)) == রিক্ত)
			fatal_f("connection_info_message");
		status = 1;
	} অন্যথা যদি (strcmp(name, "channels") == 0) {
		যদি ((বাৰ্তা = channel_open_message(ssh)) == রিক্ত)
			fatal_f("channel_open_message");
		status = 1;
	} অন্যথা {
		বাৰ্তা = xstrdup("info request type not supported");
	}

	/* prepare reply */
	যদি ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, বাৰ্তা)) != 0)
		fatal_fr(r, "reply");
	মুক্ত(বাৰ্তা);

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_master_process_terminate(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	যদি (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		যদি (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ঘূৰাই 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ঘূৰাই 0;
}

স্থির ৱর্ণ *
format_forward(u_int ftype, সংরচনা Forward *fwd)
{
	ৱর্ণ *ret;

	ৱিকল্প (ftype) {
	পক্ষ MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != রিক্ত) ? fwd->listen_path :
		    (fwd->listen_host == রিক্ত) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != রিক্ত) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		ভঙ্গ;
	পক্ষ MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == রিক্ত) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		ভঙ্গ;
	পক্ষ MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != রিক্ত) ? fwd->listen_path :
		    (fwd->listen_host == রিক্ত) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != রিক্ত) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		ভঙ্গ;
	স্ৱভাৱ:
		fatal_f("unknown forward type %u", ftype);
	}
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
compare_host(ধ্রুৱ ৱর্ণ *a, ধ্রুৱ ৱর্ণ *b)
{
	যদি (a == রিক্ত && b == রিক্ত)
		ঘূৰাই 1;
	যদি (a == রিক্ত || b == রিক্ত)
		ঘূৰাই 0;
	ঘূৰাই strcmp(a, b) == 0;
}

স্থির পূর্ণাঙ্ক
compare_forward(সংরচনা Forward *a, সংরচনা Forward *b)
{
	যদি (!compare_host(a->listen_host, b->listen_host))
		ঘূৰাই 0;
	যদি (!compare_host(a->listen_path, b->listen_path))
		ঘূৰাই 0;
	যদি (a->listen_port != b->listen_port)
		ঘূৰাই 0;
	যদি (!compare_host(a->connect_host, b->connect_host))
		ঘূৰাই 0;
	যদি (!compare_host(a->connect_path, b->connect_path))
		ঘূৰাই 0;
	যদি (a->connect_port != b->connect_port)
		ঘূৰাই 0;

	ঘূৰাই 1;
}

স্থির শূন্য
mux_confirm_remote_forward(সংরচনা ssh *ssh, পূর্ণাঙ্ক type, uint32_t seq, শূন্য *ctxt)
{
	সংরচনা mux_channel_confirm_ctx *fctx = ctxt;
	ৱর্ণ *failmsg = রিক্ত;
	সংরচনা Forward *rfwd;
	Channel *c;
	সংরচনা sshbuf *out;
	u_int port;
	পূর্ণাঙ্ক r;

	যদি ((c = channel_by_id(ssh, fctx->cid)) == রিক্ত) {
		/* no channel for reply */
		error_f("unknown channel");
		ঘূৰাই;
	}
	যদি ((out = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি (fctx->fid >= options.অঙ্ক_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == রিক্ত &&
	    options.remote_forwards[fctx->fid].connect_host == রিক্ত)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		গচ্ছ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_বাৰ্তা_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	যদি (type == SSH2_বাৰ্তা_REQUEST_SUCCESS) {
		যদি (rfwd->listen_port == 0) {
			যদি ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			যদি (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (পূর্ণাঙ্ক)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			যদি ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} অন্যথা {
			reply_ok(out, fctx->rid);
		}
		গচ্ছ out;
	} অন্যথা {
		যদি (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		যদি (rfwd->listen_path != রিক্ত)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		অন্যথা
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		মুক্ত(rfwd->listen_host);
		মুক্ত(rfwd->listen_path);
		মুক্ত(rfwd->connect_host);
		মুক্ত(rfwd->connect_path);
		memset(rfwd, 0, পরিমাণ(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	মুক্ত(failmsg);
 out:
	যদি ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	যদি (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	মুক্ত(fctx);
}

স্থির পূর্ণাঙ্ক
mux_master_process_open_fwd(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	সংরচনা Forward fwd;
	ৱর্ণ *fwd_desc = রিক্ত;
	ৱর্ণ *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	পূর্ণাঙ্ক r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, পরিমাণ(fwd));

	/* XXX - lport/cport check redundant */
	যদি ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		গচ্ছ out;
	}
	যদি (*listen_addr == '\0') {
		মুক্ত(listen_addr);
		listen_addr = রিক্ত;
	}
	যদি (*connect_addr == '\0') {
		মুক্ত(connect_addr);
		connect_addr = রিক্ত;
	}

	memset(&fwd, 0, পরিমাণ(fwd));
	fwd.listen_port = lport;
	যদি (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	অন্যথা
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	যদি (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	অন্যথা
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	যদি (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		মুক্ত(listen_addr);
		মুক্ত(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ঘূৰাই 0;
	}
	যদি (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		গচ্ছ invalid;
	}
	যদি (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		গচ্ছ invalid;
	}
	যদি ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		গচ্ছ invalid;
	}
	যদি (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == রিক্ত &&
	    fwd.connect_path == রিক্ত) {
		logit_f("missing connect host");
		গচ্ছ invalid;
	}

	/* Skip forwards that have already been requested */
	ৱিকল্প (ftype) {
	পক্ষ MUX_FWD_LOCAL:
	পক্ষ MUX_FWD_DYNAMIC:
		বাবে (i = 0; i < options.অঙ্ক_local_forwards; i++) {
			যদি (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				গচ্ছ out;
			}
		}
		ভঙ্গ;
	পক্ষ MUX_FWD_REMOTE:
		বাবে (i = 0; i < options.অঙ্ক_remote_forwards; i++) {
			যদি (!compare_forward(&fwd, options.remote_forwards + i))
				অনুৱর্ত;
			যদি (fwd.listen_port != 0)
				গচ্ছ exists;
			debug2_f("found allocated port");
			যদি ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			গচ্ছ out;
		}
		ভঙ্গ;
	}

	যদি (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		যদি (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			গচ্ছ out;
		}
	}

	যদি (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		যদি (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			গচ্ছ out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} অন্যথা {
		সংরচনা mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		যদি (fwd.handle < 0)
			গচ্ছ fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, পরিমাণ(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.অঙ্ক_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		গচ্ছ out;
	}
	reply_ok(reply, rid);
 out:
	মুক্ত(fwd_desc);
	যদি (freefwd) {
		মুক্ত(fwd.listen_host);
		মুক্ত(fwd.listen_path);
		মুক্ত(fwd.connect_host);
		মুক্ত(fwd.connect_path);
	}
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
mux_master_process_close_fwd(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	সংরচনা Forward fwd, *found_fwd;
	ৱর্ণ *fwd_desc = রিক্ত;
	ধ্রুৱ ৱর্ণ *error_reason = রিক্ত;
	ৱর্ণ *listen_addr = রিক্ত, *connect_addr = রিক্ত;
	u_int ftype;
	পূর্ণাঙ্ক r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, পরিমাণ(fwd));

	যদি ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		গচ্ছ out;
	}

	যদি (*listen_addr == '\0') {
		মুক্ত(listen_addr);
		listen_addr = রিক্ত;
	}
	যদি (*connect_addr == '\0') {
		মুক্ত(connect_addr);
		connect_addr = রিক্ত;
	}

	memset(&fwd, 0, পরিমাণ(fwd));
	fwd.listen_port = lport;
	যদি (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	অন্যথা
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	যদি (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	অন্যথা
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = রিক্ত;
	ৱিকল্প (ftype) {
	পক্ষ MUX_FWD_LOCAL:
	পক্ষ MUX_FWD_DYNAMIC:
		বাবে (i = 0; i < options.অঙ্ক_local_forwards; i++) {
			যদি (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				ভঙ্গ;
			}
		}
		ভঙ্গ;
	পক্ষ MUX_FWD_REMOTE:
		বাবে (i = 0; i < options.অঙ্ক_remote_forwards; i++) {
			যদি (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				ভঙ্গ;
			}
		}
		ভঙ্গ;
	}

	যদি (found_fwd == রিক্ত)
		error_reason = "port not forwarded";
	অন্যথা যদি (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		যদি (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} অন্যথা {	/* local and dynamic forwards */
		/* Ditto */
		যদি (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	যদি (error_reason != রিক্ত)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	অন্যথা {
		reply_ok(reply, rid);
		মুক্ত(found_fwd->listen_host);
		মুক্ত(found_fwd->listen_path);
		মুক্ত(found_fwd->connect_host);
		মুক্ত(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = রিক্ত;
		found_fwd->listen_path = found_fwd->connect_path = রিক্ত;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	মুক্ত(fwd_desc);
	মুক্ত(listen_addr);
	মুক্ত(connect_addr);

	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
mux_master_process_stdio_fwd(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	Channel *nc;
	ৱর্ণ *chost = রিক্ত;
	u_int _cport, i, j;
	পূর্ণাঙ্ক ok = 0, cport, r, new_fd[2];
	সংরচনা mux_stdio_confirm_ctx *cctx;

	যদি ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		মুক্ত(chost);
		error_f("malformed message");
		ঘূৰাই -1;
	}
	যদি (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	অন্যথা যদি (_cport <= INT_MAX)
		cport = (পূর্ণাঙ্ক)_cport;
	অন্যথা {
		মুক্ত(chost);
		error_f("invalid port 0x%x", _cport);
		ঘূৰাই -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	বাবে(i = 0; i < 2; i++) {
		যদি ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			বাবে (j = 0; j < i; j++)
				close(new_fd[j]);
			মুক্ত(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ঘূৰাই -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	যদি (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		মুক্ত(chost);
		ঘূৰাই 0;
	}

	যদি (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		যদি (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} অন্যথা {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		যদি (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			গচ্ছ cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	মুক্ত(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, পরিমাণ(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	ঘূৰাই 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
স্থির শূন্য
mux_stdio_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, পূর্ণাঙ্ক success, শূন্য *arg)
{
	সংরচনা mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	সংরচনা sshbuf *reply;
	পূর্ণাঙ্ক r;

	যদি (cctx == রিক্ত)
		fatal_f("cctx == NULL");
	যদি ((c = channel_by_id(ssh, id)) == রিক্ত)
		fatal_f("no channel for id %d", id);
	যদি ((cc = channel_by_id(ssh, c->ctl_chan)) == রিক্ত)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	যদি ((reply = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");

	যদি (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		গচ্ছ done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	যদি ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	যদি ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	যদি (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = রিক্ত;
	মুক্ত(cctx);
}

স্থির পূর্ণাঙ্ক
mux_master_process_stop_listening(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	যদি (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		যদি (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ঘূৰাই 0;
		}
	}

	যদি (mux_listener_channel != রিক্ত) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		মুক্ত(options.control_path);
		options.control_path = রিক্ত;
		mux_listener_channel = রিক্ত;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_master_process_proxy(সংরচনা ssh *ssh, u_int rid,
    Channel *c, সংরচনা sshbuf *m, সংরচনা sshbuf *reply)
{
	পূর্ণাঙ্ক r;

	debug_f("channel %d: proxy request", c->self);

	যদি (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		যদি (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ঘূৰাই 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	যদি ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	ঘূৰাই 0;
}

/* Channel callbacks fired on read/write from mux client fd */
স্থির পূর্ণাঙ্ক
mux_master_read_cb(সংরচনা ssh *ssh, Channel *c)
{
	সংরচনা mux_master_state *state = (সংরচনা mux_master_state *)c->mux_ctx;
	সংরচনা sshbuf *in = রিক্ত, *out = রিক্ত;
	u_int type, rid, i;
	পূর্ণাঙ্ক r, ret = -1;

	যদি ((out = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	যদি (c->mux_ctx == রিক্ত) {
		state = xcalloc(1, পরিমাণ(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		যদি ((r = sshbuf_put_u32(out, MUX_বাৰ্তা_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		যদি ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		যদি ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		গচ্ছ out;
	}

	/* Channel code ensures that we receive whole packets */
	যদি ((r = sshbuf_froms(c->প্ৰবেশ, &in)) != 0) {
 malf:
		error_f("malformed message");
		গচ্ছ out;
	}

	যদি ((r = sshbuf_get_u32(in, &type)) != 0)
		গচ্ছ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	যদি (type == MUX_বাৰ্তা_HELLO)
		rid = 0;
	অন্যথা {
		যদি (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_বাৰ্তা_HELLO, type);
			গচ্ছ out;
		}
		যদি ((r = sshbuf_get_u32(in, &rid)) != 0)
			গচ্ছ malf;
	}

	বাবে (i = 0; mux_master_handlers[i].handler != রিক্ত; i++) {
		যদি (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			ভঙ্গ;
		}
	}
	যদি (mux_master_handlers[i].handler == রিক্ত) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	যদি (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	ঘূৰাই ret;
}

শূন্য
mux_exit_message(সংরচনা ssh *ssh, Channel *c, পূর্ণাঙ্ক exitval)
{
	সংরচনা sshbuf *m;
	Channel *mux_chan;
	পূর্ণাঙ্ক r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	যদি ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == রিক্ত)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

শূন্য
mux_tty_alloc_failed(সংরচনা ssh *ssh, Channel *c)
{
	সংরচনা sshbuf *m;
	Channel *mux_chan;
	পূর্ণাঙ্ক r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	যদি ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == রিক্ত)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
শূন্য
muxserver_listen(সংরচনা ssh *ssh)
{
	mode_t old_umask;
	ৱর্ণ *orig_control_path = options.control_path;
	ৱর্ণ rbuf[16+1];
	u_int i, r;
	পূর্ণাঙ্ক oerrno;

	যদি (options.control_path == রিক্ত ||
	    options.control_master == SSHCTL_MASTER_NO)
		ঘূৰাই;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	বাবে (i = 0; i < পরিমাণ(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[পরিমাণ(rbuf) - 1] = '\0';
	options.control_path = রিক্ত;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	যদি (muxserver_sock < 0) {
		যদি (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			যদি (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			মুক্ত(orig_control_path);
			মুক্ত(options.control_path);
			options.control_path = রিক্ত;
			options.control_master = SSHCTL_MASTER_NO;
			ঘূৰাই;
		} অন্যথা {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	যদি (link(options.control_path, orig_control_path) != 0) {
		যদি (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		গচ্ছ disable_mux_master;
	}
	unlink(options.control_path);
	মুক্ত(options.control_path);
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
স্থির শূন্য
mux_session_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, পূর্ণাঙ্ক success, শূন্য *arg)
{
	সংরচনা mux_session_confirm_ctx *cctx = arg;
	ধ্রুৱ ৱর্ণ *display;
	Channel *c, *cc;
	পূর্ণাঙ্ক i, r;
	সংরচনা sshbuf *reply;

	যদি (cctx == রিক্ত)
		fatal_f("cctx == NULL");
	যদি ((c = channel_by_id(ssh, id)) == রিক্ত)
		fatal_f("no channel for id %d", id);
	যদি ((cc = channel_by_id(ssh, c->ctl_chan)) == রিক্ত)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	যদি ((reply = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");

	যদি (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		গচ্ছ done;
	}

	display = getenv("DISPLAY");
	যদি (cctx->want_x_fwd && options.forward_x11 && display != রিক্ত) {
		ৱর্ণ *proto, *data;

		/* Get reasonable local authentication information. */
		যদি (client_x11_get_proto(ssh, display, options.xauth_location,
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

	যদি (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	যদি ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	যদি ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	যদি (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = রিক্ত;
	sshbuf_free(cctx->cmd);
	মুক্ত(cctx->term);
	যদি (cctx->env != রিক্ত) {
		বাবে (i = 0; cctx->env[i] != রিক্ত; i++)
			মুক্ত(cctx->env[i]);
		মুক্ত(cctx->env);
	}
	মুক্ত(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
স্থির শূন্য
control_client_sighandler(পূর্ণাঙ্ক signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
স্থির শূন্য
control_client_sigrelay(পূর্ণাঙ্ক signo)
{
	পূর্ণাঙ্ক save_errno = errno;

	যদি (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

স্থির পূর্ণাঙ্ক
mux_client_read(পূর্ণাঙ্ক fd, সংরচনা sshbuf *b, size_t need, পূর্ণাঙ্ক timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	বাবে (have = 0; have < need; ) {
		যদি (muxclient_terminate) {
			errno = EINTR;
			ঘূৰাই -1;
		}
		len = পঠ(fd, p + have, need - have);
		যদি (len == -1) {
			ৱিকল্প (errno) {
#যদি defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			পক্ষ EWOULDBLOCK:
#endif
			পক্ষ EAGAIN:
				যদি (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ঘূৰাই -1;	/* timeout */
				/* FALLTHROUGH */
			পক্ষ EINTR:
				অনুৱর্ত;
			স্ৱভাৱ:
				ঘূৰাই -1;
			}
		}
		যদি (len == 0) {
			errno = EPIPE;
			ঘূৰাই -1;
		}
		have += (size_t)len;
	}
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_client_write_packet(পূর্ণাঙ্ক fd, সংরচনা sshbuf *m)
{
	সংরচনা sshbuf *queue;
	u_int have, need;
	পূর্ণাঙ্ক r, oerrno, len;
	ধ্রুৱ u_char *ptr;
	সংরচনা pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	যদি ((queue = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	বাবে (have = 0; have < need; ) {
		যদি (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			ঘূৰাই -1;
		}
		len = লিখ(fd, ptr + have, need - have);
		যদি (len == -1) {
			ৱিকল্প (errno) {
#যদি defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			পক্ষ EWOULDBLOCK:
#endif
			পক্ষ EAGAIN:
				(শূন্য)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			পক্ষ EINTR:
				অনুৱর্ত;
			স্ৱভাৱ:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				ঘূৰাই -1;
			}
		}
		যদি (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			ঘূৰাই -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_client_read_packet_timeout(পূর্ণাঙ্ক fd, সংরচনা sshbuf *m, পূর্ণাঙ্ক timeout_ms)
{
	সংরচনা sshbuf *queue;
	size_t need, have;
	ধ্রুৱ u_char *ptr;
	পূর্ণাঙ্ক r, oerrno;

	যদি ((queue = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		যদি ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ঘূৰাই -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	যদি (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ঘূৰাই -1;
	}
	যদি ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_client_read_packet(পূর্ণাঙ্ক fd, সংরচনা sshbuf *m)
{
	ঘূৰাই mux_client_read_packet_timeout(fd, m, -1);
}

স্থির পূর্ণাঙ্ক
mux_client_hello_exchange(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক timeout_ms)
{
	সংরচনা sshbuf *m;
	u_int type, ver;
	পূর্ণাঙ্ক r, ret = -1;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_বাৰ্তা_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	যদি (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		গচ্ছ out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	যদি (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		গচ্ছ out;
	}

	যদি ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != MUX_বাৰ্তা_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_বাৰ্তা_HELLO, type);
		গচ্ছ out;
	}
	যদি ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	যদি (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		গচ্ছ out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	যেতিয়ালৈ (sshbuf_len(m) > 0) {
		ৱর্ণ *name = রিক্ত;

		যদি ((r = sshbuf_get_cstring(m, &name, রিক্ত)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*মান*/
			error_fr(r, "parse extension");
			গচ্ছ out;
		}
		/* Process extensions. */
		যদি (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} অন্যথা {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		মুক্ত(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	ঘূৰাই ret;
}

স্থির u_int
mux_client_request_alive(পূর্ণাঙ্ক fd)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e;
	u_int pid, type, rid;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	যদি (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ঘূৰাই 0;
	}

	যদি ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != MUX_S_ALIVE) {
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	যদি ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	যদি ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ঘূৰাই pid;
}

স্থির ৱর্ণ *
mux_client_request_info(পূর্ণাঙ্ক fd, ধ্রুৱ ৱর্ণ *name)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e, *বাৰ্তা;
	u_int type, rid, status;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	যদি (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ঘূৰাই 0;
	}

	যদি ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	যদি (type != MUX_S_EXT_INFO) {
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	যদি ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	যদি ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &বাৰ্তা, রিক্ত)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ঘূৰাই বাৰ্তা;
}

স্থির শূন্য
mux_client_request_terminate(পূর্ণাঙ্ক fd)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e;
	u_int type, rid;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	যদি (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		যদি (errno == EPIPE) {
			sshbuf_free(m);
			ঘূৰাই;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ৱিকল্প (type) {
	পক্ষ MUX_S_OK:
		ভঙ্গ;
	পক্ষ MUX_S_PERMISSION_DENIED:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	পক্ষ MUX_S_FAILURE:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	স্ৱভাৱ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

স্থির পূর্ণাঙ্ক
mux_client_forward(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক cancel_flag, u_int ftype, সংরচনা Forward *fwd)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e, *fwd_desc;
	ধ্রুৱ ৱর্ণ *lhost, *chost;
	u_int type, rid;
	পূর্ণাঙ্ক r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	মুক্ত(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	যদি (fwd->listen_path != রিক্ত)
		lhost = fwd->listen_path;
	অন্যথা যদি (fwd->listen_host == রিক্ত)
		lhost = "";
	অন্যথা যদি (*fwd->listen_host == '\0')
		lhost = "*";
	অন্যথা
		lhost = fwd->listen_host;

	যদি (fwd->connect_path != রিক্ত)
		chost = fwd->connect_path;
	অন্যথা যদি (fwd->connect_host == রিক্ত)
		chost = "";
	অন্যথা
		chost = fwd->connect_host;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	যদি (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ঘূৰাই -1;
	}

	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ৱিকল্প (type) {
	পক্ষ MUX_S_OK:
		ভঙ্গ;
	পক্ষ MUX_S_REMOTE_PORT:
		যদি (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		যদি ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		যদি (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		ভঙ্গ;
	পক্ষ MUX_S_PERMISSION_DENIED:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ঘূৰাই -1;
	পক্ষ MUX_S_FAILURE:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ঘূৰাই -1;
	স্ৱভাৱ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_client_forwards(পূর্ণাঙ্ক fd, পূর্ণাঙ্ক cancel_flag)
{
	পূর্ণাঙ্ক i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.অঙ্ক_local_forwards, options.অঙ্ক_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	বাবে (i = 0; i < options.অঙ্ক_local_forwards; i++) {
		যদি (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	বাবে (i = 0; i < options.অঙ্ক_remote_forwards; i++) {
		যদি (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
mux_client_request_session(পূর্ণাঙ্ক fd)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e;
	ধ্রুৱ ৱর্ণ *term = রিক্ত;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	বাহ্য ৱর্ণ **environ;
	পূর্ণাঙ্ক r, rawmode = 0;

	debug3_f("entering");

	যদি ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ঘূৰাই -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	যদি (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	যদি ((term = lookup_env_in_list("TERM", options.setenv,
	    options.অঙ্ক_setenv)) == রিক্ত || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	যদি (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, রিক্ত, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == রিক্ত ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	যদি (options.অঙ্ক_send_env > 0 && environ != রিক্ত) {
		বাবে (i = 0; environ[i] != রিক্ত; i++) {
			যদি (!env_permitted(environ[i]))
				অনুৱর্ত;
			যদি ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	বাবে (i = 0; i < options.অঙ্ক_setenv; i++) {
		যদি ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	যদি (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	যদি (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ঘূৰাই -1;
	}

	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ৱিকল্প (type) {
	পক্ষ MUX_S_SESSION_OPENED:
		যদি ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ভঙ্গ;
	পক্ষ MUX_S_PERMISSION_DENIED:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ঘূৰাই -1;
	পক্ষ MUX_S_FAILURE:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ঘূৰাই -1;
	স্ৱভাৱ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ঘূৰাই -1;
	}
	muxclient_request_id++;

	যদি (pledge("stdio proc tty", রিক্ত) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	যদি (options.fork_after_authentication)
		daemon(1, 1);
	অন্যথা {
		rawmode = tty_flag;
		যদি (tty_flag) {
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
	বাবে (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		যদি (mux_client_read_packet(fd, m) != 0)
			ভঙ্গ;
		যদি ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		ৱিকল্প (type) {
		পক্ষ MUX_S_TTY_ALLOC_FAIL:
			যদি ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			যদি (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			অনুৱর্ত;
		পক্ষ MUX_S_EXIT_MESSAGE:
			যদি ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			যদি (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			যদি (exitval_seen)
				fatal_f("exitval sent twice");
			যদি ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			অনুৱর্ত;
		স্ৱভাৱ:
			যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	যদি (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	যদি (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} অন্যথা যদি (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} অন্যথা
		debug2("Received exit status from master %d", exitval);

	যদি (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

স্থির পূর্ণাঙ্ক
mux_client_proxy(পূর্ণাঙ্ক fd)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e;
	u_int type, rid;
	পূর্ণাঙ্ক r;

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	যদি (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ঘূৰাই 0;
	}
	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	যদি (type != MUX_S_PROXY) {
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
mux_client_request_stdio_fwd(পূর্ণাঙ্ক fd)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e;
	u_int type, rid, sid;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ঘূৰাই -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	যদি (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, রিক্ত, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	যদি (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	যদি (pledge("stdio proc tty", রিক্ত) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	যদি (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ঘূৰাই -1;
	}

	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ৱিকল্প (type) {
	পক্ষ MUX_S_SESSION_OPENED:
		যদি ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ভঙ্গ;
	পক্ষ MUX_S_PERMISSION_DENIED:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	পক্ষ MUX_S_FAILURE:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	স্ৱভাৱ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ঘূৰাই -1;
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
	যদি (mux_client_read_packet(fd, m) != 0) {
		যদি (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ঘূৰাই 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

স্থির শূন্য
mux_client_request_stop_listening(পূর্ণাঙ্ক fd)
{
	সংরচনা sshbuf *m;
	ৱর্ণ *e;
	u_int type, rid;
	পূর্ণাঙ্ক r;

	debug3_f("entering");

	যদি ((m = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new");
	যদি ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	যদি (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	যদি (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	যদি ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	যদি (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ৱিকল্প (type) {
	পক্ষ MUX_S_OK:
		ভঙ্গ;
	পক্ষ MUX_S_PERMISSION_DENIED:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	পক্ষ MUX_S_FAILURE:
		যদি ((r = sshbuf_get_cstring(m, &e, রিক্ত)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	স্ৱভাৱ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
পূর্ণাঙ্ক
muxclient(ধ্রুৱ ৱর্ণ *path)
{
	সংরচনা sockaddr_un addr;
	পূর্ণাঙ্ক sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	ৱর্ণ *info = রিক্ত;

	যদি (muxclient_command == 0) {
		যদি (options.stdio_forward_host != রিক্ত)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		অন্যথা
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	ৱিকল্প (options.control_master) {
	পক্ষ SSHCTL_MASTER_AUTO:
	পক্ষ SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	পক্ষ SSHCTL_MASTER_NO:
		ভঙ্গ;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}

	memset(&addr, '\0', পরিমাণ(addr));
	addr.sun_family = AF_UNIX;

	যদি (strlcpy(addr.sun_path, path,
	    পরিমাণ(addr.sun_path)) >= পরিমাণ(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned পূর্ণাঙ্ক)পরিমাণ(addr.sun_path));

	যদি ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	যদি (connect(sock, (সংরচনা sockaddr *)&addr, পরিমাণ(addr)) == -1) {
		ৱিকল্প (muxclient_command) {
		পক্ষ SSHMUX_COMMAND_OPEN:
		পক্ষ SSHMUX_COMMAND_STDIO_FWD:
			ভঙ্গ;
		স্ৱভাৱ:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		যদি (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} অন্যথা যদি (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} অন্যথা {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		ঘূৰাই -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	যদি (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	যদি (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ঘূৰাই -1;
	}

	ৱিকল্প (muxclient_command) {
	পক্ষ SSHMUX_COMMAND_ALIVE_CHECK:
		যদি ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	পক্ষ SSHMUX_COMMAND_CONNINFO:
	পক্ষ SSHMUX_COMMAND_CHANINFO:
		যদি (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		যদি (info == রিক্ত)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	পক্ষ SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		যদি (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	পক্ষ SSHMUX_COMMAND_FORWARD:
		যদি (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	পক্ষ SSHMUX_COMMAND_OPEN:
		যদি (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ঘূৰাই -1;
		}
		mux_client_request_session(sock);
		ঘূৰাই -1;
	পক্ষ SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	পক্ষ SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		যদি (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	পক্ষ SSHMUX_COMMAND_CANCEL_FWD:
		যদি (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	পক্ষ SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ঘূৰাই (sock);
	স্ৱভাৱ:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
