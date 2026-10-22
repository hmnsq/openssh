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
	वर्ण *पदांशः;
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
#परिभाषय MUX_सन्देशः_HELLO		0x00000001
#परिभाषय MUX_C_NEW_SESSION	0x10000002
#परिभाषय MUX_C_ALIVE_CHECK	0x10000004
#परिभाषय MUX_C_TERMINATE		0x10000005
#परिभाषय MUX_C_OPEN_FWD		0x10000006
#परिभाषय MUX_C_CLOSE_FWD		0x10000007
#परिभाषय MUX_C_NEW_STDIO_FWD	0x10000008
#परिभाषय MUX_C_STOP_LISTENING	0x10000009
#परिभाषय MUX_C_PROXY		0x1000000f
#परिभाषय MUX_C_EXT_INFO		0x20000001
#परिभाषय MUX_S_OK		0x80000001
#परिभाषय MUX_S_PERMISSION_DENIED	0x80000002
#परिभाषय MUX_S_FAILURE		0x80000003
#परिभाषय MUX_S_EXIT_सन्देशः	0x80000004
#परिभाषय MUX_S_ALIVE		0x80000005
#परिभाषय MUX_S_SESSION_OPENED	0x80000006
#परिभाषय MUX_S_REMOTE_पत्तनम्	0x80000007
#परिभाषय MUX_S_TTY_ALLOC_FAIL	0x80000008
#परिभाषय MUX_S_PROXY		0x8000000f
#परिभाषय MUX_S_EXT_INFO		0x90000001

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
#परिभाषय MUX_FWD_LOCAL   1
#परिभाषय MUX_FWD_REMOTE  2
#परिभाषय MUX_FWD_DYNAMIC 3

#परिभाषय MUX_EXT_INFO		0x00000001

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
mux_master_session_cleanup_cb(संरचना ssh *ssh, पूर्णाङ्क cid, पूर्णाङ्क force, शून्य *अप्रयुक्तम्)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	यदि (c == रिक्त)
		fatal_f("channel_by_id(%i) == NULL", cid);
	यदि (c->ctl_chan != -1) {
		यदि ((cc = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
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
mux_master_control_cleanup_cb(संरचना ssh *ssh, पूर्णाङ्क cid, पूर्णाङ्क force, शून्य *अप्रयुक्तम्)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	यदि (c == रिक्त)
		fatal_f("channel_by_id(%i) == NULL", cid);
	यदि (c->have_ctl_child_id) {
		यदि ((sc = channel_by_id(ssh, c->ctl_child_id)) == रिक्त)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		यदि (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} अन्यथा {
			यदि (sc->istate == CHAN_निवेशः_OPEN)
				chan_read_failed(ssh, sc);
			यदि (sc->ostate == CHAN_OUTPUT_OPEN)
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

	यदि ((cp = strchr(env, '=')) == रिक्त || cp == env)
		प्रत्यागम 0;
	ret = snprintf(name, परिमाण(name), "%.*s", (पूर्णाङ्क)(cp - env), env);
	यदि (ret <= 0 || (आकार_t)ret >= परिमाण(name)) {
		error_f("name '%.100s...' too long", env);
		प्रत्यागम 0;
	}

	प्रति (i = 0; i < options.अङ्कः_send_env; i++)
		यदि (मेलनम्_आदर्शः(name, options.send_env[i]))
			प्रत्यागम 1;

	प्रत्यागम 0;
}

/* Mux master protocol message handlers */

स्थिर पूर्णाङ्क
mux_master_process_hello(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	u_int ver;
	संरचना mux_master_state *state = (संरचना mux_master_state *)c->mux_ctx;
	पूर्णाङ्क r;

	यदि (state == रिक्त)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	यदि (state->hello_rcvd) {
		error_f("HELLO received twice");
		प्रत्यागम -1;
	}
	यदि ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		प्रत्यागम -1;
	}
	यदि (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		प्रत्यागम -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	यावत् (sshbuf_len(m) > 0) {
		वर्ण *name = रिक्त;
		आकार_t मानम्_len = 0;

		यदि ((r = sshbuf_get_cstring(m, &name, रिक्त)) != 0 ||
		    (r = sshbuf_get_string_प्रत्यक्षम्(m, रिक्त, &मानम्_len)) != 0) {
			error_fr(r, "parse extension");
			प्रत्यागम -1;
		}
		यदि (वाक्यं_तुलय(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} अन्यथा {
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
प्रत्युत्तरम्_ok(संरचना sshbuf *प्रत्युत्तरम्, u_int rid)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
स्थिर शून्य
प्रत्युत्तरम्_error(संरचना sshbuf *प्रत्युत्तरम्, u_int type, u_int rid, ध्रुव वर्ण *सन्देशः)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्, type)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, rid)) != 0 ||
	    (r = sshbuf_put_cstring(प्रत्युत्तरम्, सन्देशः)) != 0)
		fatal_fr(r, "reply");
}

स्थिर पूर्णाङ्क
mux_master_process_new_session(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	Channel *nc;
	संरचना mux_session_confirm_ctx *cctx;
	वर्ण *cmd, *cp;
	u_int i, j, env_len, escape_char, गवाक्षः, packetmax;
	पूर्णाङ्क r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, परिमाण(*cctx));
	cctx->पदांशः = रिक्त;
	cctx->rid = rid;
	cmd = रिक्त;
	cctx->env = रिक्त;
	env_len = 0;
	यदि ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->पदांशः, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, रिक्त)) != 0) {
 malf:
		मुक्त(cmd);
		प्रति (j = 0; j < env_len; j++)
			मुक्त(cctx->env[j]);
		मुक्त(cctx->env);
		मुक्त(cctx->पदांशः);
		मुक्त(cctx);
		error_f("malformed message");
		प्रत्यागम -1;
	}

#परिभाषय MUX_MAX_ENV_VARS	4096
	यावत् (sshbuf_len(m) > 0) {
		यदि ((r = sshbuf_get_cstring(m, &cp, रिक्त)) != 0)
			गच्छ malf;
		यदि (!env_permitted(cp)) {
			मुक्त(cp);
			अनुवर्त;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    परिमाण(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = रिक्त;
		यदि (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			भङ्ग;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->पदांशः, cmd, env_len);

	यदि ((cctx->cmd = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put(cctx->cmd, cmd, वाक्यदैर्घ्यम्(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	मुक्त(cmd);
	cmd = रिक्त;

	/* Gather fds from client */
	प्रति(i = 0; i < 3; i++) {
		यदि ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			प्रति (j = 0; j < i; j++)
				close(new_fd[j]);
			प्रति (j = 0; j < env_len; j++)
				मुक्त(cctx->env[j]);
			मुक्त(cctx->env);
			मुक्त(cctx->पदांशः);
			sshbuf_free(cctx->cmd);
			मुक्त(cctx);
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			प्रत्यागम -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	यदि (c->have_ctl_child_id) {
		debug2_f("session already open");
		प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		मुक्त(cctx->पदांशः);
		यदि (env_len != 0) {
			प्रति (i = 0; i < env_len; i++)
				मुक्त(cctx->env[i]);
			मुक्त(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		मुक्त(cctx);
		प्रत्यागम 0;
	}

	यदि (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		यदि (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			गच्छ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	यदि (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	गवाक्षः = CHAN_SES_गवाक्षः_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	यदि (cctx->want_tty) {
		गवाक्षः >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], गवाक्षः, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	यदि (cctx->want_tty)
		channel_समुच्चयः_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	यदि (cctx->want_tty && escape_char != 0xffffffff) {
		channel_पञ्जिकाकोशः_filter(ssh, nc->self,
		    client_simple_escape_filter, रिक्त,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((पूर्णाङ्क)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_पञ्जिकाकोशः_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_पञ्जिकाकोशः_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_master_process_alive_check(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	पूर्णाङ्क r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, rid)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	प्रत्यागम 0;
}

/* The "info" extension. */
स्थिर पूर्णाङ्क
mux_master_process_ext_info(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	पूर्णाङ्क r;
	u_int स्थितिः = 0;
	वर्ण *name = रिक्त, *सन्देशः = रिक्त;

	debug2_f("channel %d: info request", c->self);

	यदि ((r = sshbuf_get_cstring(m, &name, रिक्त)) != 0)
		fatal_fr(r, "parse");

	यदि (वाक्यं_तुलय(name, "connection") == 0) {
		यदि ((सन्देशः = connection_info_सन्देशः(ssh)) == रिक्त)
			fatal_f("connection_info_message");
		स्थितिः = 1;
	} अन्यथा यदि (वाक्यं_तुलय(name, "channels") == 0) {
		यदि ((सन्देशः = channel_open_सन्देशः(ssh)) == रिक्त)
			fatal_f("channel_open_message");
		स्थितिः = 1;
	} अन्यथा {
		सन्देशः = xstrdup("info request type not supported");
	}

	/* prepare reply */
	यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, rid)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, स्थितिः)) != 0 ||
	    (r = sshbuf_put_cstring(प्रत्युत्तरम्, सन्देशः)) != 0)
		fatal_fr(r, "reply");
	मुक्त(सन्देशः);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_master_process_terminate(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	debug2_f("channel %d: terminate request", c->self);

	यदि (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		यदि (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			प्रत्यागम 0;
		}
	}

	quit_pending = 1;
	प्रत्युत्तरम्_ok(प्रत्युत्तरम्, rid);
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
		    (fwd->listen_मार्गः != रिक्त) ? fwd->listen_मार्गः :
		    (fwd->listen_host == रिक्त) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_पत्तनम्,
		    (fwd->connect_मार्गः != रिक्त) ? fwd->connect_मार्गः :
		    fwd->connect_host, fwd->connect_पत्तनम्);
		भङ्ग;
	पक्ष MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == रिक्त) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_पत्तनम्);
		भङ्ग;
	पक्ष MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_मार्गः != रिक्त) ? fwd->listen_मार्गः :
		    (fwd->listen_host == रिक्त) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_पत्तनम्,
		    (fwd->connect_मार्गः != रिक्त) ? fwd->connect_मार्गः :
		    fwd->connect_host, fwd->connect_पत्तनम्);
		भङ्ग;
	स्वभाव:
		fatal_f("unknown forward type %u", ftype);
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
compare_host(ध्रुव वर्ण *a, ध्रुव वर्ण *b)
{
	यदि (a == रिक्त && b == रिक्त)
		प्रत्यागम 1;
	यदि (a == रिक्त || b == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम वाक्यं_तुलय(a, b) == 0;
}

स्थिर पूर्णाङ्क
compare_forward(संरचना Forward *a, संरचना Forward *b)
{
	यदि (!compare_host(a->listen_host, b->listen_host))
		प्रत्यागम 0;
	यदि (!compare_host(a->listen_मार्गः, b->listen_मार्गः))
		प्रत्यागम 0;
	यदि (a->listen_पत्तनम् != b->listen_पत्तनम्)
		प्रत्यागम 0;
	यदि (!compare_host(a->connect_host, b->connect_host))
		प्रत्यागम 0;
	यदि (!compare_host(a->connect_मार्गः, b->connect_मार्गः))
		प्रत्यागम 0;
	यदि (a->connect_पत्तनम् != b->connect_पत्तनम्)
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
	संरचना sshbuf *बहिर्गमनम्;
	u_int पत्तनम्;
	पूर्णाङ्क r;

	यदि ((c = channel_by_id(ssh, fctx->cid)) == रिक्त) {
		/* no channel for reply */
		error_f("unknown channel");
		प्रत्यागम;
	}
	यदि ((बहिर्गमनम् = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि (fctx->fid >= options.अङ्कः_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_मार्गः == रिक्त &&
	    options.remote_forwards[fctx->fid].connect_host == रिक्त)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		गच्छ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_सन्देशः_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_पत्तनम्, rfwd->connect_मार्गः ? rfwd->connect_मार्गः :
	    rfwd->connect_host, rfwd->connect_पत्तनम्);
	यदि (type == SSH2_सन्देशः_REQUEST_SUCCESS) {
		यदि (rfwd->listen_पत्तनम् == 0) {
			यदि ((r = sshpkt_get_u32(ssh, &पत्तनम्)) != 0)
				fatal_fr(r, "parse port");
			यदि (पत्तनम् > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", पत्तनम्,
				    rfwd->connect_host, rfwd->connect_पत्तनम्);
			}
			rfwd->allocated_पत्तनम् = (पूर्णाङ्क)पत्तनम्;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_पत्तनम्,
			    rfwd->connect_host, rfwd->connect_पत्तनम्);
			यदि ((r = sshbuf_put_u32(बहिर्गमनम्,
			    MUX_S_REMOTE_पत्तनम्)) != 0 ||
			    (r = sshbuf_put_u32(बहिर्गमनम्, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(बहिर्गमनम्,
			    rfwd->allocated_पत्तनम्)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_पत्तनम्);
		} अन्यथा {
			प्रत्युत्तरम्_ok(बहिर्गमनम्, fctx->rid);
		}
		गच्छ बहिर्गमनम्;
	} अन्यथा {
		यदि (rfwd->listen_पत्तनम् == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		यदि (rfwd->listen_मार्गः != रिक्त)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_मार्गः);
		अन्यथा
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_पत्तनम्);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_पत्तनम्,
		    rfwd->connect_मार्गः ? rfwd->connect_मार्गः :
		    rfwd->connect_host, rfwd->connect_पत्तनम्);

		मुक्त(rfwd->listen_host);
		मुक्त(rfwd->listen_मार्गः);
		मुक्त(rfwd->connect_host);
		मुक्त(rfwd->connect_मार्गः);
		स्मृतिं_पूरय(rfwd, 0, परिमाण(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	प्रत्युत्तरम्_error(बहिर्गमनम्, MUX_S_FAILURE, fctx->rid, failmsg);
	मुक्त(failmsg);
 बहिर्गमनम्:
	यदि ((r = sshbuf_put_stringb(c->output, बहिर्गमनम्)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(बहिर्गमनम्);
	यदि (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	मुक्त(fctx);
}

स्थिर पूर्णाङ्क
mux_master_process_open_fwd(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	संरचना Forward fwd;
	वर्ण *fwd_desc = रिक्त;
	वर्ण *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	पूर्णाङ्क r, i, ret = 0, freefwd = 1;

	स्मृतिं_पूरय(&fwd, 0, परिमाण(fwd));

	/* XXX - lport/cport check redundant */
	यदि ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)पत्तनम्_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)पत्तनम्_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		गच्छ बहिर्गमनम्;
	}
	यदि (*listen_addr == '\0') {
		मुक्त(listen_addr);
		listen_addr = रिक्त;
	}
	यदि (*connect_addr == '\0') {
		मुक्त(connect_addr);
		connect_addr = रिक्त;
	}

	स्मृतिं_पूरय(&fwd, 0, परिमाण(fwd));
	fwd.listen_पत्तनम् = lport;
	यदि (fwd.listen_पत्तनम् == पत्तनम्_STREAMLOCAL)
		fwd.listen_मार्गः = listen_addr;
	अन्यथा
		fwd.listen_host = listen_addr;
	fwd.connect_पत्तनम् = cport;
	यदि (fwd.connect_पत्तनम् == पत्तनम्_STREAMLOCAL)
		fwd.connect_मार्गः = connect_addr;
	अन्यथा
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	यदि (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		मुक्त(listen_addr);
		मुक्त(connect_addr);
		प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		प्रत्यागम 0;
	}
	यदि (ftype == MUX_FWD_DYNAMIC && fwd.listen_मार्गः) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		गच्छ invalid;
	}
	यदि (fwd.listen_पत्तनम् != पत्तनम्_STREAMLOCAL && fwd.listen_पत्तनम् >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_पत्तनम्);
		गच्छ invalid;
	}
	यदि ((fwd.connect_पत्तनम् != पत्तनम्_STREAMLOCAL &&
	    fwd.connect_पत्तनम् >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_पत्तनम् == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_पत्तनम्);
		गच्छ invalid;
	}
	यदि (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == रिक्त &&
	    fwd.connect_मार्गः == रिक्त) {
		logit_f("missing connect host");
		गच्छ invalid;
	}

	/* Skip forwards that have already been requested */
	विकल्प (ftype) {
	पक्ष MUX_FWD_LOCAL:
	पक्ष MUX_FWD_DYNAMIC:
		प्रति (i = 0; i < options.अङ्कः_local_forwards; i++) {
			यदि (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				प्रत्युत्तरम्_ok(प्रत्युत्तरम्, rid);
				गच्छ बहिर्गमनम्;
			}
		}
		भङ्ग;
	पक्ष MUX_FWD_REMOTE:
		प्रति (i = 0; i < options.अङ्कः_remote_forwards; i++) {
			यदि (!compare_forward(&fwd, options.remote_forwards + i))
				अनुवर्त;
			यदि (fwd.listen_पत्तनम् != 0)
				गच्छ exists;
			debug2_f("found allocated port");
			यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्,
			    MUX_S_REMOTE_पत्तनम्)) != 0 ||
			    (r = sshbuf_put_u32(प्रत्युत्तरम्, rid)) != 0 ||
			    (r = sshbuf_put_u32(प्रत्युत्तरम्,
			    options.remote_forwards[i].allocated_पत्तनम्)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			गच्छ बहिर्गमनम्;
		}
		भङ्ग;
	}

	यदि (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		यदि (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			गच्छ बहिर्गमनम्;
		}
	}

	यदि (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		यदि (!channel_सज्जता_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			गच्छ बहिर्गमनम्;
		}
		सङ्कलय_local_forward(&options, &fwd);
		freefwd = 0;
	} अन्यथा {
		संरचना mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		यदि (fwd.handle < 0)
			गच्छ fail;
		सङ्कलय_remote_forward(&options, &fwd);
		fctx = xcalloc(1, परिमाण(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.अङ्कः_remote_forwards - 1;
		client_पञ्जिकाकोशः_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		गच्छ बहिर्गमनम्;
	}
	प्रत्युत्तरम्_ok(प्रत्युत्तरम्, rid);
 बहिर्गमनम्:
	मुक्त(fwd_desc);
	यदि (freefwd) {
		मुक्त(fwd.listen_host);
		मुक्त(fwd.listen_मार्गः);
		मुक्त(fwd.connect_host);
		मुक्त(fwd.connect_मार्गः);
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
mux_master_process_close_fwd(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	संरचना Forward fwd, *प्राप्तम्_fwd;
	वर्ण *fwd_desc = रिक्त;
	ध्रुव वर्ण *error_reason = रिक्त;
	वर्ण *listen_addr = रिक्त, *connect_addr = रिक्त;
	u_int ftype;
	पूर्णाङ्क r, i, ret = 0;
	u_int lport, cport;

	स्मृतिं_पूरय(&fwd, 0, परिमाण(fwd));

	यदि ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)पत्तनम्_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)पत्तनम्_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		गच्छ बहिर्गमनम्;
	}

	यदि (*listen_addr == '\0') {
		मुक्त(listen_addr);
		listen_addr = रिक्त;
	}
	यदि (*connect_addr == '\0') {
		मुक्त(connect_addr);
		connect_addr = रिक्त;
	}

	स्मृतिं_पूरय(&fwd, 0, परिमाण(fwd));
	fwd.listen_पत्तनम् = lport;
	यदि (fwd.listen_पत्तनम् == पत्तनम्_STREAMLOCAL)
		fwd.listen_मार्गः = listen_addr;
	अन्यथा
		fwd.listen_host = listen_addr;
	fwd.connect_पत्तनम् = cport;
	यदि (fwd.connect_पत्तनम् == पत्तनम्_STREAMLOCAL)
		fwd.connect_मार्गः = connect_addr;
	अन्यथा
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	प्राप्तम्_fwd = रिक्त;
	विकल्प (ftype) {
	पक्ष MUX_FWD_LOCAL:
	पक्ष MUX_FWD_DYNAMIC:
		प्रति (i = 0; i < options.अङ्कः_local_forwards; i++) {
			यदि (compare_forward(&fwd,
			    options.local_forwards + i)) {
				प्राप्तम्_fwd = options.local_forwards + i;
				भङ्ग;
			}
		}
		भङ्ग;
	पक्ष MUX_FWD_REMOTE:
		प्रति (i = 0; i < options.अङ्कः_remote_forwards; i++) {
			यदि (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				प्राप्तम्_fwd = options.remote_forwards + i;
				भङ्ग;
			}
		}
		भङ्ग;
	}

	यदि (प्राप्तम्_fwd == रिक्त)
		error_reason = "port not forwarded";
	अन्यथा यदि (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		यदि (channel_request_rforward_cancel(ssh, प्राप्तम्_fwd) == -1)
			error_reason = "port not in permitted opens";
	} अन्यथा {	/* local and dynamic forwards */
		/* Ditto */
		यदि (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_पत्तनम्,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	यदि (error_reason != रिक्त)
		प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, rid, error_reason);
	अन्यथा {
		प्रत्युत्तरम्_ok(प्रत्युत्तरम्, rid);
		मुक्त(प्राप्तम्_fwd->listen_host);
		मुक्त(प्राप्तम्_fwd->listen_मार्गः);
		मुक्त(प्राप्तम्_fwd->connect_host);
		मुक्त(प्राप्तम्_fwd->connect_मार्गः);
		प्राप्तम्_fwd->listen_host = प्राप्तम्_fwd->connect_host = रिक्त;
		प्राप्तम्_fwd->listen_मार्गः = प्राप्तम्_fwd->connect_मार्गः = रिक्त;
		प्राप्तम्_fwd->listen_पत्तनम् = प्राप्तम्_fwd->connect_पत्तनम् = 0;
	}
 बहिर्गमनम्:
	मुक्त(fwd_desc);
	मुक्त(listen_addr);
	मुक्त(connect_addr);

	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
mux_master_process_stdio_fwd(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	Channel *nc;
	वर्ण *chost = रिक्त;
	u_int _cport, i, j;
	पूर्णाङ्क ok = 0, cport, r, new_fd[2];
	संरचना mux_stdio_confirm_ctx *cctx;

	यदि ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		मुक्त(chost);
		error_f("malformed message");
		प्रत्यागम -1;
	}
	यदि (_cport == (u_int)पत्तनम्_STREAMLOCAL)
		cport = पत्तनम्_STREAMLOCAL;
	अन्यथा यदि (_cport <= अधिकतम_पूर्णाङ्कः)
		cport = (पूर्णाङ्क)_cport;
	अन्यथा {
		मुक्त(chost);
		error_f("invalid port 0x%x", _cport);
		प्रत्यागम -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	प्रति(i = 0; i < 2; i++) {
		यदि ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			प्रति (j = 0; j < i; j++)
				close(new_fd[j]);
			मुक्त(chost);

			/* prepare reply */
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			प्रत्यागम -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	यदि (c->have_ctl_child_id) {
		debug2_f("session already open");
		प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		मुक्त(chost);
		प्रत्यागम 0;
	}

	यदि (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		यदि (cport == पत्तनम्_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} अन्यथा {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		यदि (!ok) {
			debug2_f("stdio fwd refused by user");
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_PERMISSION_DENIED, rid,
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

	channel_पञ्जिकाकोशः_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, परिमाण(*cctx));
	cctx->rid = rid;
	channel_पञ्जिकाकोशः_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
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
	संरचना sshbuf *प्रत्युत्तरम्;
	पूर्णाङ्क r;

	यदि (cctx == रिक्त)
		fatal_f("cctx == NULL");
	यदि ((c = channel_by_id(ssh, id)) == रिक्त)
		fatal_f("no channel for id %d", id);
	यदि ((cc = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	यदि ((प्रत्युत्तरम् = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	यदि (!success) {
		debug3_f("sending failure reply");
		प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		गच्छ समाप्तम्;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, c->self)) != 0)
		fatal_fr(r, "reply");

 समाप्तम्:
	/* Send reply */
	यदि ((r = sshbuf_put_stringb(cc->output, प्रत्युत्तरम्)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(प्रत्युत्तरम्);

	यदि (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = रिक्त;
	मुक्त(cctx);
}

स्थिर पूर्णाङ्क
mux_master_process_stop_listening(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	debug_f("channel %d: stop listening", c->self);

	यदि (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		यदि (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			प्रत्यागम 0;
		}
	}

	यदि (mux_listener_channel != रिक्त) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		मुक्त(options.control_मार्गः);
		options.control_मार्गः = रिक्त;
		mux_listener_channel = रिक्त;
		muxserver_sock = -1;
	}

	प्रत्युत्तरम्_ok(प्रत्युत्तरम्, rid);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
mux_master_process_proxy(संरचना ssh *ssh, u_int rid,
    Channel *c, संरचना sshbuf *m, संरचना sshbuf *प्रत्युत्तरम्)
{
	पूर्णाङ्क r;

	debug_f("channel %d: proxy request", c->self);

	यदि (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		यदि (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			प्रत्यागम 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, rid)) != 0)
		fatal_fr(r, "reply");

	प्रत्यागम 0;
}

/* Channel callbacks fired on read/write from mux client fd */
स्थिर पूर्णाङ्क
mux_master_read_cb(संरचना ssh *ssh, Channel *c)
{
	संरचना mux_master_state *state = (संरचना mux_master_state *)c->mux_ctx;
	संरचना sshbuf *अन्तर् = रिक्त, *बहिर्गमनम् = रिक्त;
	u_int type, rid, i;
	पूर्णाङ्क r, ret = -1;

	यदि ((बहिर्गमनम् = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	यदि (c->mux_ctx == रिक्त) {
		state = xcalloc(1, परिमाण(*state));
		c->mux_ctx = state;
		channel_पञ्जिकाकोशः_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		यदि ((r = sshbuf_put_u32(बहिर्गमनम्, MUX_सन्देशः_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(बहिर्गमनम्, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		यदि ((r = sshbuf_put_cstring(बहिर्गमनम्, "info")) != 0 ||
		    (r = sshbuf_put_cstring(बहिर्गमनम्, "0")) != 0)
			fatal_fr(r, "put info extension");
		यदि ((r = sshbuf_put_stringb(c->output, बहिर्गमनम्)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		गच्छ बहिर्गमनम्;
	}

	/* Channel code ensures that we receive whole packets */
	यदि ((r = sshbuf_froms(c->निवेशः, &अन्तर्)) != 0) {
 malf:
		error_f("malformed message");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshbuf_get_u32(अन्तर्, &type)) != 0)
		गच्छ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(अन्तर्));

	यदि (type == MUX_सन्देशः_HELLO)
		rid = 0;
	अन्यथा {
		यदि (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_सन्देशः_HELLO, type);
			गच्छ बहिर्गमनम्;
		}
		यदि ((r = sshbuf_get_u32(अन्तर्, &rid)) != 0)
			गच्छ malf;
	}

	प्रति (i = 0; mux_master_handlers[i].handler != रिक्त; i++) {
		यदि (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, अन्तर्, बहिर्गमनम्);
			भङ्ग;
		}
	}
	यदि (mux_master_handlers[i].handler == रिक्त) {
		error_f("unsupported mux message 0x%08x", type);
		प्रत्युत्तरम्_error(बहिर्गमनम्, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	यदि (sshbuf_len(बहिर्गमनम्) != 0 &&
	    (r = sshbuf_put_stringb(c->output, बहिर्गमनम्)) != 0)
		fatal_fr(r, "enqueue");
 बहिर्गमनम्:
	sshbuf_free(अन्तर्);
	sshbuf_free(बहिर्गमनम्);
	प्रत्यागम ret;
}

शून्य
mux_exit_सन्देशः(संरचना ssh *ssh, Channel *c, पूर्णाङ्क exitval)
{
	संरचना sshbuf *m;
	Channel *mux_chan;
	पूर्णाङ्क r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	यदि ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_S_EXIT_सन्देशः)) != 0 ||
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

	यदि ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
शून्य
muxserver_listen(संरचना ssh *ssh)
{
	बहुलकम्_t old_umask;
	वर्ण *orig_control_मार्गः = options.control_मार्गः;
	वर्ण rbuf[16+1];
	u_int i, r;
	पूर्णाङ्क oerrno;

	यदि (options.control_मार्गः == रिक्त ||
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
		r = arc4random_एकरूपम्(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[परिमाण(rbuf) - 1] = '\0';
	options.control_मार्गः = रिक्त;
	xasprintf(&options.control_मार्गः, "%s.%s", orig_control_मार्गः, rbuf);
	debug3_f("temporary control path %s", options.control_मार्गः);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_मार्गः, 64, 0);
	oerrno = errno;
	umask(old_umask);
	यदि (muxserver_sock < 0) {
		यदि (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_मार्गः);
 disable_mux_master:
			यदि (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			मुक्त(orig_control_मार्गः);
			मुक्त(options.control_मार्गः);
			options.control_मार्गः = रिक्त;
			options.control_master = SSHCTL_MASTER_NO;
			प्रत्यागम;
		} अन्यथा {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	यदि (link(options.control_मार्गः, orig_control_मार्गः) != 0) {
		यदि (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_मार्गः, orig_control_मार्गः,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_मार्गः);
		unlink(options.control_मार्गः);
		गच्छ disable_mux_master;
	}
	unlink(options.control_मार्गः);
	मुक्त(options.control_मार्गः);
	options.control_मार्गः = orig_control_मार्गः;

	समुच्चयः_nonblock(muxserver_sock);

	mux_listener_channel = channel_new(ssh, "mux listener",
	    SSH_CHANNEL_MUX_LISTENER, muxserver_sock, muxserver_sock, -1,
	    CHAN_TCP_गवाक्षः_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
	    0, options.control_मार्गः, 1);
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
	संरचना sshbuf *प्रत्युत्तरम्;

	यदि (cctx == रिक्त)
		fatal_f("cctx == NULL");
	यदि ((c = channel_by_id(ssh, id)) == रिक्त)
		fatal_f("no channel for id %d", id);
	यदि ((cc = channel_by_id(ssh, c->ctl_chan)) == रिक्त)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	यदि ((प्रत्युत्तरम् = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");

	यदि (!success) {
		debug3_f("sending failure reply");
		प्रत्युत्तरम्_error(प्रत्युत्तरम्, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		गच्छ समाप्तम्;
	}

	display = getenv("DISPLAY");
	यदि (cctx->want_x_fwd && options.forward_x11 && display != रिक्त) {
		वर्ण *proto, *दत्त;

		/* Get reasonable local authentication information. */
		यदि (client_x11_get_proto(ssh, display, options.xauth_location,
		    options.forward_x11_trusted, options.forward_x11_timeout,
		    &proto, &दत्त) == 0) {
			/* Request forwarding with authentication spoofing. */
			debug("Requesting X11 forwarding with authentication "
			    "spoofing.");
			x11_request_forwarding_with_spoofing(ssh, id,
			    display, proto, दत्त, 1);
			/* XXX exit_on_forward_failure */
			client_expect_confirm(ssh, id, "X11 forwarding",
			    CONFIRM_WARN);
		}
	}

	यदि (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_सज्जता(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->पदांशः, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	यदि ((r = sshbuf_put_u32(प्रत्युत्तरम्, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(प्रत्युत्तरम्, c->self)) != 0)
		fatal_fr(r, "reply");

 समाप्तम्:
	/* Send reply */
	यदि ((r = sshbuf_put_stringb(cc->output, प्रत्युत्तरम्)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(प्रत्युत्तरम्);

	यदि (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = रिक्त;
	sshbuf_free(cctx->cmd);
	मुक्त(cctx->पदांशः);
	यदि (cctx->env != रिक्त) {
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

	यदि (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

स्थिर पूर्णाङ्क
mux_client_read(पूर्णाङ्क fd, संरचना sshbuf *b, आकार_t need, पूर्णाङ्क timeout_ms)
{
	आकार_t have;
	ssize_t len;
	u_char *p;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	प्रति (have = 0; have < need; ) {
		यदि (muxclient_terminate) {
			errno = EINTR;
			प्रत्यागम -1;
		}
		len = पठ(fd, p + have, need - have);
		यदि (len == -1) {
			विकल्प (errno) {
#यदि defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			पक्ष EWOULDBLOCK:
#यदि_अन्तः
			पक्ष EAGAIN:
				यदि (waitrfd(fd, &timeout_ms,
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
		यदि (len == 0) {
			errno = EPIPE;
			प्रत्यागम -1;
		}
		have += (आकार_t)len;
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
	यदि ((queue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	प्रति (have = 0; have < need; ) {
		यदि (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			प्रत्यागम -1;
		}
		len = लिख(fd, ptr + have, need - have);
		यदि (len == -1) {
			विकल्प (errno) {
#यदि defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			पक्ष EWOULDBLOCK:
#यदि_अन्तः
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
		यदि (len == 0) {
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
	आकार_t need, have;
	ध्रुव u_char *ptr;
	पूर्णाङ्क r, oerrno;

	यदि ((queue = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		यदि ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		प्रत्यागम -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	यदि (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		प्रत्यागम -1;
	}
	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(queue, &ptr, &have)) != 0 ||
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

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_सन्देशः_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	यदि (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		गच्छ बहिर्गमनम्;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	यदि (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	यदि (type != MUX_सन्देशः_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_सन्देशः_HELLO, type);
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	यदि (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		गच्छ बहिर्गमनम्;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	यावत् (sshbuf_len(m) > 0) {
		वर्ण *name = रिक्त;

		यदि ((r = sshbuf_get_cstring(m, &name, रिक्त)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*मानम्*/
			error_fr(r, "parse extension");
			गच्छ बहिर्गमनम्;
		}
		/* Process extensions. */
		यदि (वाक्यं_तुलय(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} अन्यथा {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		मुक्त(name);
	}
	/* success */
	ret = 0;
 बहिर्गमनम्:
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

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	यदि (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम 0;
	}

	यदि ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	यदि (type != MUX_S_ALIVE) {
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	यदि ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	यदि ((r = sshbuf_get_u32(m, &pid)) != 0)
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
	u_int type, rid, स्थितिः;
	पूर्णाङ्क r;

	debug3_f("entering");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	यदि (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम 0;
	}

	यदि ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	यदि (type != MUX_S_EXT_INFO) {
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	यदि ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	यदि ((r = sshbuf_get_u32(m, &स्थितिः)) != 0 ||
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

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	यदि (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		यदि (errno == EPIPE) {
			sshbuf_free(m);
			प्रत्यागम;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	यदि ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	विकल्प (type) {
	पक्ष MUX_S_OK:
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	पक्ष MUX_S_FAILURE:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
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
	यदि (fwd->listen_मार्गः != रिक्त)
		lhost = fwd->listen_मार्गः;
	अन्यथा यदि (fwd->listen_host == रिक्त)
		lhost = "";
	अन्यथा यदि (*fwd->listen_host == '\0')
		lhost = "*";
	अन्यथा
		lhost = fwd->listen_host;

	यदि (fwd->connect_मार्गः != रिक्त)
		chost = fwd->connect_मार्गः;
	अन्यथा यदि (fwd->connect_host == रिक्त)
		chost = "";
	अन्यथा
		chost = fwd->connect_host;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_पत्तनम्)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_पत्तनम्)) != 0)
		fatal_fr(r, "request");

	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	यदि (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम -1;
	}

	यदि ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	विकल्प (type) {
	पक्ष MUX_S_OK:
		भङ्ग;
	पक्ष MUX_S_REMOTE_पत्तनम्:
		यदि (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		यदि ((r = sshbuf_get_u32(m, &fwd->allocated_पत्तनम्)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_पत्तनम्,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_पत्तनम्);
		यदि (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_पत्तनम्);
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		प्रत्यागम -1;
	पक्ष MUX_S_FAILURE:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
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
		यदि (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_पत्तनम् == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	प्रति (i = 0; i < options.अङ्कः_remote_forwards; i++) {
		यदि (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
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
	ध्रुव वर्ण *पदांशः = रिक्त;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_आलोकितम्;
	बाह्य वर्ण **environ;
	पूर्णाङ्क r, rawmode = 0;

	debug3_f("entering");

	यदि ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		प्रत्यागम -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	यदि (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	यदि ((पदांशः = lookup_env_अन्तर्_list("TERM", options.setenv,
	    options.अङ्कः_setenv)) == रिक्त || *पदांशः == '\0')
		पदांशः = getenv("TERM");

	echar = 0xffffffff;
	यदि (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, पदांशः == रिक्त ? "" : पदांशः)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	यदि (options.अङ्कः_send_env > 0 && environ != रिक्त) {
		प्रति (i = 0; environ[i] != रिक्त; i++) {
			यदि (!env_permitted(environ[i]))
				अनुवर्त;
			यदि ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	प्रति (i = 0; i < options.अङ्कः_setenv; i++) {
		यदि ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	यदि (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	यदि (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		प्रत्यागम -1;
	}

	यदि ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	विकल्प (type) {
	पक्ष MUX_S_SESSION_OPENED:
		यदि ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		प्रत्यागम -1;
	पक्ष MUX_S_FAILURE:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
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

	यदि (pledge("stdio proc tty", रिक्त) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	यदि (options.fork_after_authentication)
		daemon(1, 1);
	अन्यथा {
		rawmode = tty_flag;
		यदि (tty_flag) {
			enter_raw_बहुलकम्(
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
	प्रति (exitval = 255, exitval_आलोकितम् = 0;;) {
		sshbuf_reset(m);
		यदि (mux_client_read_packet(fd, m) != 0)
			भङ्ग;
		यदि ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		विकल्प (type) {
		पक्ष MUX_S_TTY_ALLOC_FAIL:
			यदि ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			यदि (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_बहुलकम्(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			अनुवर्त;
		पक्ष MUX_S_EXIT_सन्देशः:
			यदि ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			यदि (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			यदि (exitval_आलोकितम्)
				fatal_f("exitval sent twice");
			यदि ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_आलोकितम् = 1;
			अनुवर्त;
		स्वभाव:
			यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	यदि (rawmode)
		leave_raw_बहुलकम्(options.request_tty == REQUEST_TTY_FORCE);

	यदि (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} अन्यथा यदि (!exitval_आलोकितम्) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} अन्यथा
		debug2("Received exit status from master %d", exitval);

	यदि (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	निर्गच्छ(exitval);
}

स्थिर पूर्णाङ्क
mux_client_proxy(पूर्णाङ्क fd)
{
	संरचना sshbuf *m;
	वर्ण *e;
	u_int type, rid;
	पूर्णाङ्क r;

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	यदि (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		प्रत्यागम 0;
	}
	यदि ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	यदि (type != MUX_S_PROXY) {
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
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

	यदि ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		प्रत्यागम -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	यदि (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_पत्तनम्)) != 0)
		fatal_fr(r, "request");

	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	यदि (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	यदि (pledge("stdio proc tty", रिक्त) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	यदि (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		प्रत्यागम -1;
	}

	यदि ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	विकल्प (type) {
	पक्ष MUX_S_SESSION_OPENED:
		यदि ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	पक्ष MUX_S_FAILURE:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
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
	यदि (mux_client_read_packet(fd, m) != 0) {
		यदि (errno == EPIPE ||
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

	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new");
	यदि ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	यदि (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	यदि (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	यदि ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	यदि (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	विकल्प (type) {
	पक्ष MUX_S_OK:
		भङ्ग;
	पक्ष MUX_S_PERMISSION_DENIED:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	पक्ष MUX_S_FAILURE:
		यदि ((r = sshbuf_get_cstring(m, &e, रिक्त)) != 0)
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
muxclient(ध्रुव वर्ण *मार्गः)
{
	संरचना sockaddr_un addr;
	पूर्णाङ्क sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	वर्ण *info = रिक्त;

	यदि (muxclient_command == 0) {
		यदि (options.stdio_forward_host != रिक्त)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		अन्यथा
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	विकल्प (options.control_master) {
	पक्ष SSHCTL_MASTER_AUTO:
	पक्ष SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", मार्गः);
		/* FALLTHROUGH */
	पक्ष SSHCTL_MASTER_NO:
		भङ्ग;
	स्वभाव:
		प्रत्यागम -1;
	}

	स्मृतिं_पूरय(&addr, '\0', परिमाण(addr));
	addr.sun_family = AF_UNIX;

	यदि (strlcpy(addr.sun_मार्गः, मार्गः,
	    परिमाण(addr.sun_मार्गः)) >= परिमाण(addr.sun_मार्गः))
		fatal("ControlPath too long ('%s' >= %u bytes)", मार्गः,
		    (अचिह्नित पूर्णाङ्क)परिमाण(addr.sun_मार्गः));

	यदि ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	यदि (connect(sock, (संरचना sockaddr *)&addr, परिमाण(addr)) == -1) {
		विकल्प (muxclient_command) {
		पक्ष SSHMUX_COMMAND_OPEN:
		पक्ष SSHMUX_COMMAND_STDIO_FWD:
			भङ्ग;
		स्वभाव:
			fatal("Control socket connect(%.100s): %s", मार्गः,
			    strerror(errno));
		}
		यदि (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", मार्गः);
			unlink(मार्गः);
		} अन्यथा यदि (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", मार्गः);
		} अन्यथा {
			error("Control socket connect(%.100s): %s", मार्गः,
			    strerror(errno));
		}
		close(sock);
		प्रत्यागम -1;
	}
	समुच्चयः_nonblock(sock);

	/* Timeout on initial connection only. */
	यदि (timeout > 0 && timeout < अधिकतम_पूर्णाङ्कः / 1000)
		timeout_ms = timeout * 1000;

	यदि (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		प्रत्यागम -1;
	}

	विकल्प (muxclient_command) {
	पक्ष SSHMUX_COMMAND_ALIVE_CHECK:
		यदि ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		निर्गच्छ(0);
	पक्ष SSHMUX_COMMAND_CONNINFO:
	पक्ष SSHMUX_COMMAND_CHANINFO:
		यदि (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		यदि (info == रिक्त)
			fatal_f("info request failed");
		प्रारूप_लिख("%s", info);
		निर्गच्छ(0);
	पक्ष SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		यदि (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		निर्गच्छ(0);
	पक्ष SSHMUX_COMMAND_FORWARD:
		यदि (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		निर्गच्छ(0);
	पक्ष SSHMUX_COMMAND_OPEN:
		यदि (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			प्रत्यागम -1;
		}
		mux_client_request_session(sock);
		प्रत्यागम -1;
	पक्ष SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		निर्गच्छ(0);
	पक्ष SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		यदि (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		निर्गच्छ(0);
	पक्ष SSHMUX_COMMAND_CANCEL_FWD:
		यदि (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		निर्गच्छ(0);
	पक्ष SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		प्रत्यागम (sock);
	स्वभाव:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
