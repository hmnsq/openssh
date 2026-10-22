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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <poll.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "monitor_fdpass.h"
#अन्तर्भाव "sshpty.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "clientloop.h"

/* from ssh.c */
बाह्य पूर्णाङ्क tty_flag;
बाह्य Options options;
बाह्य वर्ण *host;
बाह्य संरचना sshbuf *command;
बाह्य चञ्चल sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
संरचना mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	संरचना sshbuf *cmd;
	वर्ण *term;
	संरचना termios tio;
	वर्ण **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
संरचना mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
संरचना mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	पूर्णाङ्क fid;	/* forward id */
};

/* fd to control socket */
पूर्णाङ्क muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
स्थिर चञ्चल sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
स्थिर u_int muxserver_pid = 0;

स्थिर Channel *mux_listener_channel = रिक्त;

संरचना mux_master_state {
	पूर्णाङ्क hello_rcvd;
};

/* mux protocol messages */
#define MUX_सन्देशः_HELLO		0x00000001
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
स्थिर u_int extensions = 0;

स्थिर शून्य mux_session_confirm(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, शून्य *);
स्थिर शून्य mux_stdio_confirm(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क, शून्य *);

स्थिर पूर्णाङ्क mux_master_process_hello(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_new_session(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_alive_check(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_terminate(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_open_fwd(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_close_fwd(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_stdio_fwd(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_stop_listening(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_proxy(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);
स्थिर पूर्णाङ्क mux_master_process_ext_info(संरचना ssh *, u_int,
	    Channel *, संरचना sshbuf *, संरचना sshbuf *);

स्थिर ध्रुव संरचना {
	u_int type;
	पूर्णाङ्क (*handler)(संरचना ssh *, u_int, Channel *,
	    संरचना sshbuf *, संरचना sshbuf *);
} mux_master_handlers[] = {
	{ MUX_सन्देशः_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, रिक्त }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
स्थिर शून्य
mux_master_session_cleanup_cb(संरचना ssh *ssh, पूर्णाङ्क cid, पूर्णाङ्क force, शून्य *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	जइ (c == रिक्त)
		fatal_f("channel_by_id(%i) == NULL", cid);
	जइ (c->ctl_chan != -1) {
		जइ ((cc = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
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
स्थिर शून्य
mux_master_control_cleanup_cb(संरचना ssh *ssh, पूर्णाङ्क cid, पूर्णाङ्क force, शून्य *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	जइ (c == रिक्त)
		fatal_f("channel_by_id(%i) == NULL", cid);
	जइ (c->have_ctl_child_id) {
		जइ ((sc = channel_by_id(ssh, c->ctl_child_id)) == रिक्त)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		जइ (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} अण्णहा {
			जइ (sc->istate == CHAN_निवेशः_OPEN)
				chan_read_failed(ssh, sc);
			जइ (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
स्थिर पूर्णाङ्क
env_permitted(ध्रुव वर्ण *env)
{
	u_int i;
	पूर्णाङ्क ret;
	वर्ण name[1024], *cp;

	जइ ((cp = strchr(env, '=')) == रिक्त || cp == env)
		प्रत्यागम 0;
	ret = snprintf(name, परिमाण(name), "%.*s", (पूर्णाङ्क)(cp - env), env);
	जइ (ret <= 0 || (size_t)ret >= परिमाण(name)) {
		error_f("name '%.100s...' too long", env);
		प्रत्यागम 0;
	}

	प्रति (i = 0; i < options.अङ्कः_send_env; i++)
		जइ (match_pattern(name, options.send_env[i]))
			प्रत्यागम 1;

	प्रत्यागम 0;
}

/* Mux master protocol message handlers */

स्थिर पूर्णाङ्क
mux_master_process_hello(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	u_int ver;
	संरचना mux_master_state *state = (संरचना mux_master_state *)c->mux_ctx;
	पूर्णाङ्क r;

	जइ (state == रिक्त)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	जइ (state->hello_rcvd) {
		error_f("HELLO received twice");
		प्रत्यागम -1;
	}
	जइ ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		प्रत्यागम -1;
	}
	जइ (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		प्रत्यागम -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	जाव (sshbuf_len(m) > 0) {
		वर्ण *name = रिक्त;
		size_t मानम्_len = 0;

		जइ ((r = sshbuf_get_cstring(m, &name, रिक्त)) != 0 ||
		    (r = sshbuf_get_string_direct(m, रिक्त, &मानम्_len)) != 0) {
			error_fr(r, "parse extension");
			प्रत्यागम -1;
		}
		जइ (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} अण्णहा {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, मानम्_len);
		}
		मुक्त(name);
	}
	state->hello_rcvd = 1;
	प्रत्यागम 0;
}

/* Enqueue a "ok" response to the reply buffer */
स्थिर शून्य
reply_ok(संरचना sshbuf *reply, u_int rid)
{
	पूर्णाङ्क r;

	जइ ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
स्थिर शून्य
reply_error(संरचना sshbuf *reply, u_int type, u_int rid, ध्रुव वर्ण *सन्देशः)
{
	पूर्णाङ्क r;

	जइ ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, सन्देशः)) != 0)
		fatal_fr(r, "reply");
}

स्थिर पूर्णाङ्क
mux_master_process_new_session(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	Channel *nc;
	संरचना mux_session_confirm_ctx *cctx;
	वर्ण *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	पूर्णाङ्क r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, परिमाण(*cctx));
	cctx->term = रिक्त;
	cctx->rid = rid;
	cmd = रिक्त;
	cctx->env = रिक्त;
	env_len = 0;
	जइ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, रिक्त)) != 0) {
 malf:
		मुक्त(cmd);
		प्रति (j = 0; j < env_len; j++)
			मुक्त(cctx->env[j]);
		मुक्त(cctx->env);
		मुक्त(cctx->term);
		मुक्त(cctx);
		error_f("malformed message");
		प्रत्यागम -1;
	}

#define MUX_MAX_ENV_VARS	4096
	जाव (sshbuf_len(m) > 0) {
		जइ ((r = sshbuf_get_cstring(m, &cp, रिक्त)) != 0)
			गच्छ malf;
		जइ (!env_permitted(cp)) {
			मुक्त(cp);
			अनुवर्त;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    परिमाण(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = रिक्त;
		जइ (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			भङ्ग;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	जइ ((cctx->cmd = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	मुक्त(cmd);
	cmd = रिक्त;

	/* Gather fds from client */
	प्रति(i = 0; i < 3; i++) {
		जइ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			प्रति (j = 0; j < i; j++)
				close(new_fd[j]);
			प्रति (j = 0; j < env_len; j++)
				मुक्त(cctx->env[j]);
			मुक्त(cctx->env);
			मुक्त(cctx->term);
			sshbuf_free(cctx->cmd);
			मुक्त(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			प्रत्यागम -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	जइ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		मुक्त(cctx->term);
		जइ (env_len != 0) {
			प्रति (i = 0; i < env_len; i++)
				मुक्त(cctx->env[i]);
			मुक्त(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		मुक्त(cctx);
		प्रत्यागम 0;
	}

	जइ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		जइ (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			गच्छ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	जइ (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	जइ (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	जइ (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	जइ (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, रिक्त,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((पूर्णाङ्क)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_master_process_alive_check(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	पूर्णाङ्क r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	जइ ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	प्रत्यागम 0;
}

/* The "info" extension. */
स्थिर पूर्णाङ्क
mux_master_process_ext_info(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	पूर्णाङ्क r;
	u_int status = 0;
	वर्ण *name = रिक्त, *सन्देशः = रिक्त;

	debug2_f("channel %d: info request", c->self);

	जइ ((r = sshbuf_get_cstring(m, &name, रिक्त)) != 0)
		fatal_fr(r, "parse");

	जइ (strcmp(name, "connection") == 0) {
		जइ ((सन्देशः = connection_info_message(ssh)) == रिक्त)
			fatal_f("connection_info_message");
		status = 1;
	} अण्णहा जइ (strcmp(name, "channels") == 0) {
		जइ ((सन्देशः = channel_open_message(ssh)) == रिक्त)
			fatal_f("channel_open_message");
		status = 1;
	} अण्णहा {
		सन्देशः = xstrdup("info request type not supported");
	}

	/* prepare reply */
	जइ ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, सन्देशः)) != 0)
		fatal_fr(r, "reply");
	मुक्त(सन्देशः);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_master_process_terminate(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	जइ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		जइ (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			प्रत्यागम 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	प्रत्यागम 0;
}

स्थिर वर्ण *
format_forward(u_int ftype, संरचना Forward *fwd)
{
	वर्ण *ret;

	विकल्प (ftype) {
	पक्ष MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != रिक्त) ? fwd->listen_path :
		    (fwd->listen_host == रिक्त) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != रिक्त) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		भङ्ग;
	पक्ष MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == रिक्त) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		भङ्ग;
	पक्ष MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != रिक्त) ? fwd->listen_path :
		    (fwd->listen_host == रिक्त) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != रिक्त) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		भङ्ग;
	स्वभाव:
		fatal_f("unknown forward type %u", ftype);
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
compare_host(ध्रुव वर्ण *a, ध्रुव वर्ण *b)
{
	जइ (a == रिक्त && b == रिक्त)
		प्रत्यागम 1;
	जइ (a == रिक्त || b == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम strcmp(a, b) == 0;
}

स्थिर पूर्णाङ्क
compare_forward(संरचना Forward *a, संरचना Forward *b)
{
	जइ (!compare_host(a->listen_host, b->listen_host))
		प्रत्यागम 0;
	जइ (!compare_host(a->listen_path, b->listen_path))
		प्रत्यागम 0;
	जइ (a->listen_port != b->listen_port)
		प्रत्यागम 0;
	जइ (!compare_host(a->connect_host, b->connect_host))
		प्रत्यागम 0;
	जइ (!compare_host(a->connect_path, b->connect_path))
		प्रत्यागम 0;
	जइ (a->connect_port != b->connect_port)
		प्रत्यागम 0;

	प्रत्यागम 1;
}

स्थिर शून्य
mux_confirm_remote_forward(संरचना ssh *ssh, पूर्णाङ्क type, uint32_t seq, शून्य *ctxt)
{
	संरचना mux_channel_confirm_ctx *fctx = ctxt;
	वर्ण *failmsg = रिक्त;
	संरचना Forward *rfwd;
	Channel *c;
	संरचना sshbuf *out;
	u_int port;
	पूर्णाङ्क r;

	जइ ((c = channel_by_id(ssh, fctx->cid)) == रिक्त) {
		/* no channel for reply */
		error_f("unknown channel");
		प्रत्यागम;
	}
	जइ ((out = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ (fctx->fid >= options.अङ्कः_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == रिक्त &&
	    options.remote_forwards[fctx->fid].connect_host == रिक्त)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		गच्छ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_सन्देशः_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	जइ (type == SSH2_सन्देशः_REQUEST_SUCCESS) {
		जइ (rfwd->listen_port == 0) {
			जइ ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			जइ (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (पूर्णाङ्क)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			जइ ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} अण्णहा {
			reply_ok(out, fctx->rid);
		}
		गच्छ out;
	} अण्णहा {
		जइ (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		जइ (rfwd->listen_path != रिक्त)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		अण्णहा
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		मुक्त(rfwd->listen_host);
		मुक्त(rfwd->listen_path);
		मुक्त(rfwd->connect_host);
		मुक्त(rfwd->connect_path);
		memset(rfwd, 0, परिमाण(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	मुक्त(failmsg);
 out:
	जइ ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	जइ (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	मुक्त(fctx);
}

स्थिर पूर्णाङ्क
mux_master_process_open_fwd(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	संरचना Forward fwd;
	वर्ण *fwd_desc = रिक्त;
	वर्ण *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	पूर्णाङ्क r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, परिमाण(fwd));

	/* XXX - lport/cport check redundant */
	जइ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		गच्छ out;
	}
	जइ (*listen_addr == '\0') {
		मुक्त(listen_addr);
		listen_addr = रिक्त;
	}
	जइ (*connect_addr == '\0') {
		मुक्त(connect_addr);
		connect_addr = रिक्त;
	}

	memset(&fwd, 0, परिमाण(fwd));
	fwd.listen_port = lport;
	जइ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	अण्णहा
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	जइ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	अण्णहा
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	जइ (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		मुक्त(listen_addr);
		मुक्त(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		प्रत्यागम 0;
	}
	जइ (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		गच्छ invalid;
	}
	जइ (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		गच्छ invalid;
	}
	जइ ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		गच्छ invalid;
	}
	जइ (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == रिक्त &&
	    fwd.connect_path == रिक्त) {
		logit_f("missing connect host");
		गच्छ invalid;
	}

	/* Skip forwards that have already been requested */
	विकल्प (ftype) {
	पक्ष MUX_FWD_LOCAL:
	पक्ष MUX_FWD_DYNAMIC:
		प्रति (i = 0; i < options.अङ्कः_local_forwards; i++) {
			जइ (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				गच्छ out;
			}
		}
		भङ्ग;
	पक्ष MUX_FWD_REMOTE:
		प्रति (i = 0; i < options.अङ्कः_remote_forwards; i++) {
			जइ (!compare_forward(&fwd, options.remote_forwards + i))
				अनुवर्त;
			जइ (fwd.listen_port != 0)
				गच्छ exists;
			debug2_f("found allocated port");
			जइ ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			गच्छ out;
		}
		भङ्ग;
	}

	जइ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		जइ (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			गच्छ out;
		}
	}

	जइ (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		जइ (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			गच्छ out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} अण्णहा {
		संरचना mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		जइ (fwd.handle < 0)
			गच्छ fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, परिमाण(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.अङ्कः_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		गच्छ out;
	}
	reply_ok(reply, rid);
 out:
	मुक्त(fwd_desc);
	जइ (freefwd) {
		मुक्त(fwd.listen_host);
		मुक्त(fwd.listen_path);
		मुक्त(fwd.connect_host);
		मुक्त(fwd.connect_path);
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
mux_master_process_close_fwd(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	संरचना Forward fwd, *found_fwd;
	वर्ण *fwd_desc = रिक्त;
	ध्रुव वर्ण *error_reason = रिक्त;
	वर्ण *listen_addr = रिक्त, *connect_addr = रिक्त;
	u_int ftype;
	पूर्णाङ्क r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, परिमाण(fwd));

	जइ ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		गच्छ out;
	}

	जइ (*listen_addr == '\0') {
		मुक्त(listen_addr);
		listen_addr = रिक्त;
	}
	जइ (*connect_addr == '\0') {
		मुक्त(connect_addr);
		connect_addr = रिक्त;
	}

	memset(&fwd, 0, परिमाण(fwd));
	fwd.listen_port = lport;
	जइ (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	अण्णहा
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	जइ (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	अण्णहा
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = रिक्त;
	विकल्प (ftype) {
	पक्ष MUX_FWD_LOCAL:
	पक्ष MUX_FWD_DYNAMIC:
		प्रति (i = 0; i < options.अङ्कः_local_forwards; i++) {
			जइ (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				भङ्ग;
			}
		}
		भङ्ग;
	पक्ष MUX_FWD_REMOTE:
		प्रति (i = 0; i < options.अङ्कः_remote_forwards; i++) {
			जइ (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				भङ्ग;
			}
		}
		भङ्ग;
	}

	जइ (found_fwd == रिक्त)
		error_reason = "port not forwarded";
	अण्णहा जइ (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		जइ (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} अण्णहा {	/* local and dynamic forwards */
		/* Ditto */
		जइ (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	जइ (error_reason != रिक्त)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	अण्णहा {
		reply_ok(reply, rid);
		मुक्त(found_fwd->listen_host);
		मुक्त(found_fwd->listen_path);
		मुक्त(found_fwd->connect_host);
		मुक्त(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = रिक्त;
		found_fwd->listen_path = found_fwd->connect_path = रिक्त;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	मुक्त(fwd_desc);
	मुक्त(listen_addr);
	मुक्त(connect_addr);

	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
mux_master_process_stdio_fwd(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	Channel *nc;
	वर्ण *chost = रिक्त;
	u_int _cport, i, j;
	पूर्णाङ्क ok = 0, cport, r, new_fd[2];
	संरचना mux_stdio_confirm_ctx *cctx;

	जइ ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		मुक्त(chost);
		error_f("malformed message");
		प्रत्यागम -1;
	}
	जइ (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	अण्णहा जइ (_cport <= INT_MAX)
		cport = (पूर्णाङ्क)_cport;
	अण्णहा {
		मुक्त(chost);
		error_f("invalid port 0x%x", _cport);
		प्रत्यागम -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	प्रति(i = 0; i < 2; i++) {
		जइ ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			प्रति (j = 0; j < i; j++)
				close(new_fd[j]);
			मुक्त(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			प्रत्यागम -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	जइ (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		मुक्त(chost);
		प्रत्यागम 0;
	}

	जइ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		जइ (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} अण्णहा {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		जइ (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			गच्छ cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	मुक्त(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, परिमाण(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	प्रत्यागम 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
स्थिर शून्य
mux_stdio_confirm(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क success, शून्य *arg)
{
	संरचना mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	संरचना sshbuf *reply;
	पूर्णाङ्क r;

	जइ (cctx == रिक्त)
		fatal_f("cctx == NULL");
	जइ ((c = channel_by_id(ssh, id)) == रिक्त)
		fatal_f("no channel for id %d", id);
	जइ ((cc = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	जइ ((reply = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	जइ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		गच्छ done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	जइ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	जइ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	जइ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = रिक्त;
	मुक्त(cctx);
}

स्थिर पूर्णाङ्क
mux_master_process_stop_listening(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	जइ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		जइ (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			प्रत्यागम 0;
		}
	}

	जइ (mux_listener_channel != रिक्त) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		मुक्त(options.control_path);
		options.control_path = रिक्त;
		mux_listener_channel = रिक्त;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_master_process_proxy(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *reply)
{
	पूर्णाङ्क r;

	debug_f("channel %d: proxy request", c->self);

	जइ (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		जइ (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			प्रत्यागम 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	जइ ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	प्रत्यागम 0;
}

/* Channel callbacks fired on read/write from mux client fd */
स्थिर पूर्णाङ्क
mux_master_read_cb(संरचना ssh *ssh, Channel *c)
{
	संरचना mux_master_state *state = (संरचना mux_master_state *)c->mux_ctx;
	संरचना sshbuf *in = रिक्त, *out = रिक्त;
	u_int type, rid, i;
	पूर्णाङ्क r, ret = -1;

	जइ ((out = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	जइ (c->mux_ctx == रिक्त) {
		state = xcalloc(1, परिमाण(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		जइ ((r = sshbuf_put_u32(out, MUX_सन्देशः_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		जइ ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		जइ ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		गच्छ out;
	}

	/* Channel code ensures that we receive whole packets */
	जइ ((r = sshbuf_froms(c->निवेशः, &in)) != 0) {
 malf:
		error_f("malformed message");
		गच्छ out;
	}

	जइ ((r = sshbuf_get_u32(in, &type)) != 0)
		गच्छ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	जइ (type == MUX_सन्देशः_HELLO)
		rid = 0;
	अण्णहा {
		जइ (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_सन्देशः_HELLO, type);
			गच्छ out;
		}
		जइ ((r = sshbuf_get_u32(in, &rid)) != 0)
			गच्छ malf;
	}

	प्रति (i = 0; mux_master_handlers[i].handler != रिक्त; i++) {
		जइ (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			भङ्ग;
		}
	}
	जइ (mux_master_handlers[i].handler == रिक्त) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	जइ (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	प्रत्यागम ret;
}

शून्य
mux_exit_message(संरचना ssh *ssh, Channel *c, पूर्णाङ्क exitval)
{
	संरचना sshbuf *m;
	Channel *mux_chan;
	पूर्णाङ्क r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	जइ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

शून्य
mux_tty_alloc_failed(संरचना ssh *ssh, Channel *c)
{
	संरचना sshbuf *m;
	Channel *mux_chan;
	पूर्णाङ्क r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	जइ ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
शून्य
muxserver_listen(संरचना ssh *ssh)
{
	mode_t old_umask;
	वर्ण *orig_control_path = options.control_path;
	वर्ण rbuf[16+1];
	u_int i, r;
	पूर्णाङ्क oerrno;

	जइ (options.control_path == रिक्त ||
	    options.control_master == SSHCTL_MASTER_NO)
		प्रत्यागम;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	प्रति (i = 0; i < परिमाण(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[परिमाण(rbuf) - 1] = '\0';
	options.control_path = रिक्त;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	जइ (muxserver_sock < 0) {
		जइ (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			जइ (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			मुक्त(orig_control_path);
			मुक्त(options.control_path);
			options.control_path = रिक्त;
			options.control_master = SSHCTL_MASTER_NO;
			प्रत्यागम;
		} अण्णहा {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	जइ (link(options.control_path, orig_control_path) != 0) {
		जइ (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		गच्छ disable_mux_master;
	}
	unlink(options.control_path);
	मुक्त(options.control_path);
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
स्थिर शून्य
mux_session_confirm(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क success, शून्य *arg)
{
	संरचना mux_session_confirm_ctx *cctx = arg;
	ध्रुव वर्ण *display;
	Channel *c, *cc;
	पूर्णाङ्क i, r;
	संरचना sshbuf *reply;

	जइ (cctx == रिक्त)
		fatal_f("cctx == NULL");
	जइ ((c = channel_by_id(ssh, id)) == रिक्त)
		fatal_f("no channel for id %d", id);
	जइ ((cc = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	जइ ((reply = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	जइ (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		गच्छ done;
	}

	display = getenv("DISPLAY");
	जइ (cctx->want_x_fwd && options.forward_x11 && display != रिक्त) {
		वर्ण *proto, *data;

		/* Get reasonable local authentication information. */
		जइ (client_x11_get_proto(ssh, display, options.xauth_location,
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

	जइ (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	जइ ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	जइ ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	जइ (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = रिक्त;
	sshbuf_free(cctx->cmd);
	मुक्त(cctx->term);
	जइ (cctx->env != रिक्त) {
		प्रति (i = 0; cctx->env[i] != रिक्त; i++)
			मुक्त(cctx->env[i]);
		मुक्त(cctx->env);
	}
	मुक्त(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
स्थिर शून्य
control_client_sighandler(पूर्णाङ्क signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
स्थिर शून्य
control_client_sigrelay(पूर्णाङ्क signo)
{
	पूर्णाङ्क save_errno = errno;

	जइ (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

स्थिर पूर्णाङ्क
mux_client_read(पूर्णाङ्क fd, संरचना sshbuf *b, size_t need, पूर्णाङ्क timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	पूर्णाङ्क r;

	जइ ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	प्रति (have = 0; have < need; ) {
		जइ (muxclient_terminate) {
			errno = EINTR;
			प्रत्यागम -1;
		}
		len = पठ(fd, p + have, need - have);
		जइ (len == -1) {
			विकल्प (errno) {
#जइ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			पक्ष EWOULDBLOCK:
#endif
			पक्ष EAGAIN:
				जइ (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					प्रत्यागम -1;	/* timeout */
				/* FALLTHROUGH */
			पक्ष EINTR:
				अनुवर्त;
			स्वभाव:
				प्रत्यागम -1;
			}
		}
		जइ (len == 0) {
			errno = EPIPE;
			प्रत्यागम -1;
		}
		have += (size_t)len;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_client_write_packet(पूर्णाङ्क fd, संरचना sshbuf *m)
{
	संरचना sshbuf *queue;
	u_int have, need;
	पूर्णाङ्क r, oerrno, len;
	ध्रुव u_char *ptr;
	संरचना pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	जइ ((queue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	प्रति (have = 0; have < need; ) {
		जइ (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			प्रत्यागम -1;
		}
		len = लिख(fd, ptr + have, need - have);
		जइ (len == -1) {
			विकल्प (errno) {
#जइ defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			पक्ष EWOULDBLOCK:
#endif
			पक्ष EAGAIN:
				(शून्य)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			पक्ष EINTR:
				अनुवर्त;
			स्वभाव:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				प्रत्यागम -1;
			}
		}
		जइ (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			प्रत्यागम -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_client_read_packet_timeout(पूर्णाङ्क fd, संरचना sshbuf *m, पूर्णाङ्क timeout_ms)
{
	संरचना sshbuf *queue;
	size_t need, have;
	ध्रुव u_char *ptr;
	पूर्णाङ्क r, oerrno;

	जइ ((queue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		जइ ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		प्रत्यागम -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	जइ (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		प्रत्यागम -1;
	}
	जइ ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_client_read_packet(पूर्णाङ्क fd, संरचना sshbuf *m)
{
	प्रत्यागम mux_client_read_packet_timeout(fd, m, -1);
}

स्थिर पूर्णाङ्क
mux_client_hello_exchange(पूर्णाङ्क fd, पूर्णाङ्क timeout_ms)
{
	संरचना sshbuf *m;
	u_int type, ver;
	पूर्णाङ्क r, ret = -1;

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_सन्देशः_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	जइ (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		गच्छ out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	जइ (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		गच्छ out;
	}

	जइ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	जइ (type != MUX_सन्देशः_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_सन्देशः_HELLO, type);
		गच्छ out;
	}
	जइ ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	जइ (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		गच्छ out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	जाव (sshbuf_len(m) > 0) {
		वर्ण *name = रिक्त;

		जइ ((r = sshbuf_get_cstring(m, &name, रिक्त)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*मानम्*/
			error_fr(r, "parse extension");
			गच्छ out;
		}
		/* Process extensions. */
		जइ (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} अण्णहा {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		मुक्त(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	प्रत्यागम ret;
}

स्थिर u_int
mux_client_request_alive(पूर्णाङ्क fd)
{
	संरचना sshbuf *m;
	वर्ण *e;
	u_int pid, type, rid;
	पूर्णाङ्क r;

	debug3_f("entering");

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	जइ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम 0;
	}

	जइ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	जइ (type != MUX_S_ALIVE) {
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	जइ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	जइ ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	प्रत्यागम pid;
}

स्थिर वर्ण *
mux_client_request_info(पूर्णाङ्क fd, ध्रुव वर्ण *name)
{
	संरचना sshbuf *m;
	वर्ण *e, *सन्देशः;
	u_int type, rid, status;
	पूर्णाङ्क r;

	debug3_f("entering");

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	जइ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम 0;
	}

	जइ ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	जइ (type != MUX_S_EXT_INFO) {
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	जइ ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	जइ ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &सन्देशः, रिक्त)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	प्रत्यागम सन्देशः;
}

स्थिर शून्य
mux_client_request_terminate(पूर्णाङ्क fd)
{
	संरचना sshbuf *m;
	वर्ण *e;
	u_int type, rid;
	पूर्णाङ्क r;

	debug3_f("entering");

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	जइ (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		जइ (errno == EPIPE) {
			sshbuf_free(m);
			प्रत्यागम;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	जइ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	विकल्प (type) {
	पक्ष MUX_S_OK:
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	पक्ष MUX_S_FAILURE:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	स्वभाव:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

स्थिर पूर्णाङ्क
mux_client_forward(पूर्णाङ्क fd, पूर्णाङ्क cancel_flag, u_int ftype, संरचना Forward *fwd)
{
	संरचना sshbuf *m;
	वर्ण *e, *fwd_desc;
	ध्रुव वर्ण *lhost, *chost;
	u_int type, rid;
	पूर्णाङ्क r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	मुक्त(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	जइ (fwd->listen_path != रिक्त)
		lhost = fwd->listen_path;
	अण्णहा जइ (fwd->listen_host == रिक्त)
		lhost = "";
	अण्णहा जइ (*fwd->listen_host == '\0')
		lhost = "*";
	अण्णहा
		lhost = fwd->listen_host;

	जइ (fwd->connect_path != रिक्त)
		chost = fwd->connect_path;
	अण्णहा जइ (fwd->connect_host == रिक्त)
		chost = "";
	अण्णहा
		chost = fwd->connect_host;

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	जइ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम -1;
	}

	जइ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	विकल्प (type) {
	पक्ष MUX_S_OK:
		भङ्ग;
	पक्ष MUX_S_REMOTE_PORT:
		जइ (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		जइ ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		जइ (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		प्रत्यागम -1;
	पक्ष MUX_S_FAILURE:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		प्रत्यागम -1;
	स्वभाव:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_client_forwards(पूर्णाङ्क fd, पूर्णाङ्क cancel_flag)
{
	पूर्णाङ्क i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.अङ्कः_local_forwards, options.अङ्कः_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	प्रति (i = 0; i < options.अङ्कः_local_forwards; i++) {
		जइ (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	प्रति (i = 0; i < options.अङ्कः_remote_forwards; i++) {
		जइ (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
mux_client_request_session(पूर्णाङ्क fd)
{
	संरचना sshbuf *m;
	वर्ण *e;
	ध्रुव वर्ण *term = रिक्त;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	बाह्य वर्ण **environ;
	पूर्णाङ्क r, rawmode = 0;

	debug3_f("entering");

	जइ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		प्रत्यागम -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	जइ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	जइ ((term = lookup_env_in_list("TERM", options.setenv,
	    options.अङ्कः_setenv)) == रिक्त || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	जइ (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == रिक्त ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	जइ (options.अङ्कः_send_env > 0 && environ != रिक्त) {
		प्रति (i = 0; environ[i] != रिक्त; i++) {
			जइ (!env_permitted(environ[i]))
				अनुवर्त;
			जइ ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	प्रति (i = 0; i < options.अङ्कः_setenv; i++) {
		जइ ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	जइ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	जइ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		प्रत्यागम -1;
	}

	जइ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	विकल्प (type) {
	पक्ष MUX_S_SESSION_OPENED:
		जइ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		प्रत्यागम -1;
	पक्ष MUX_S_FAILURE:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		प्रत्यागम -1;
	स्वभाव:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		प्रत्यागम -1;
	}
	muxclient_request_id++;

	जइ (pledge("stdio proc tty", रिक्त) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	जइ (options.fork_after_authentication)
		daemon(1, 1);
	अण्णहा {
		rawmode = tty_flag;
		जइ (tty_flag) {
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
	प्रति (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		जइ (mux_client_read_packet(fd, m) != 0)
			भङ्ग;
		जइ ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		विकल्प (type) {
		पक्ष MUX_S_TTY_ALLOC_FAIL:
			जइ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			जइ (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			अनुवर्त;
		पक्ष MUX_S_EXIT_MESSAGE:
			जइ ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			जइ (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			जइ (exitval_seen)
				fatal_f("exitval sent twice");
			जइ ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			अनुवर्त;
		स्वभाव:
			जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	जइ (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	जइ (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} अण्णहा जइ (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} अण्णहा
		debug2("Received exit status from master %d", exitval);

	जइ (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

स्थिर पूर्णाङ्क
mux_client_proxy(पूर्णाङ्क fd)
{
	संरचना sshbuf *m;
	वर्ण *e;
	u_int type, rid;
	पूर्णाङ्क r;

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	जइ (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम 0;
	}
	जइ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	जइ (type != MUX_S_PROXY) {
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_client_request_stdio_fwd(पूर्णाङ्क fd)
{
	संरचना sshbuf *m;
	वर्ण *e;
	u_int type, rid, sid;
	पूर्णाङ्क r;

	debug3_f("entering");

	जइ ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		प्रत्यागम -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	जइ (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	जइ (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	जइ (pledge("stdio proc tty", रिक्त) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	जइ (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		प्रत्यागम -1;
	}

	जइ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	विकल्प (type) {
	पक्ष MUX_S_SESSION_OPENED:
		जइ ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	पक्ष MUX_S_FAILURE:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	स्वभाव:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		प्रत्यागम -1;
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
	जइ (mux_client_read_packet(fd, m) != 0) {
		जइ (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			प्रत्यागम 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

स्थिर शून्य
mux_client_request_stop_listening(पूर्णाङ्क fd)
{
	संरचना sshbuf *m;
	वर्ण *e;
	u_int type, rid;
	पूर्णाङ्क r;

	debug3_f("entering");

	जइ ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	जइ ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	जइ (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	जइ (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	जइ ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	जइ (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	विकल्प (type) {
	पक्ष MUX_S_OK:
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	पक्ष MUX_S_FAILURE:
		जइ ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	स्वभाव:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
पूर्णाङ्क
muxclient(ध्रुव वर्ण *path)
{
	संरचना sockaddr_un addr;
	पूर्णाङ्क sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	वर्ण *info = रिक्त;

	जइ (muxclient_command == 0) {
		जइ (options.stdio_forward_host != रिक्त)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		अण्णहा
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	विकल्प (options.control_master) {
	पक्ष SSHCTL_MASTER_AUTO:
	पक्ष SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	पक्ष SSHCTL_MASTER_NO:
		भङ्ग;
	स्वभाव:
		प्रत्यागम -1;
	}

	memset(&addr, '\0', परिमाण(addr));
	addr.sun_family = AF_UNIX;

	जइ (strlcpy(addr.sun_path, path,
	    परिमाण(addr.sun_path)) >= परिमाण(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned पूर्णाङ्क)परिमाण(addr.sun_path));

	जइ ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	जइ (connect(sock, (संरचना sockaddr *)&addr, परिमाण(addr)) == -1) {
		विकल्प (muxclient_command) {
		पक्ष SSHMUX_COMMAND_OPEN:
		पक्ष SSHMUX_COMMAND_STDIO_FWD:
			भङ्ग;
		स्वभाव:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		जइ (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} अण्णहा जइ (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} अण्णहा {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		प्रत्यागम -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	जइ (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	जइ (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		प्रत्यागम -1;
	}

	विकल्प (muxclient_command) {
	पक्ष SSHMUX_COMMAND_ALIVE_CHECK:
		जइ ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	पक्ष SSHMUX_COMMAND_CONNINFO:
	पक्ष SSHMUX_COMMAND_CHANINFO:
		जइ (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		जइ (info == रिक्त)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	पक्ष SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		जइ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	पक्ष SSHMUX_COMMAND_FORWARD:
		जइ (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	पक्ष SSHMUX_COMMAND_OPEN:
		जइ (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			प्रत्यागम -1;
		}
		mux_client_request_session(sock);
		प्रत्यागम -1;
	पक्ष SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	पक्ष SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		जइ (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	पक्ष SSHMUX_COMMAND_CANCEL_FWD:
		जइ (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	पक्ष SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		प्रत्यागम (sock);
	स्वभाव:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
