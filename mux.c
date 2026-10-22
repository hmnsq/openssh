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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/queue.h>
#समावेश <sys/stat.h>
#समावेश <sys/socket.h>
#समावेश <sys/un.h>

#समावेश <errno.h>
#समावेश <poll.h>
#समावेश <limits.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stddef.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "log.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "misc.h"
#समावेश "match.h"
#समावेश "sshbuf.h"
#समावेश "channels.h"
#समावेश "packet.h"
#समावेश "monitor_fdpass.h"
#समावेश "sshpty.h"
#समावेश "readconf.h"
#समावेश "clientloop.h"

/* from ssh.c */
बाह्य पूर्णांक tty_flag;
बाह्य Options options;
बाह्य अक्षर *host;
बाह्य काष्ठा sshbuf *command;
बाह्य अस्थिर संक_पूर्ण_प्रकार quit_pending;

/* Context for session open confirmation callback */
काष्ठा mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	काष्ठा sshbuf *cmd;
	अक्षर *term;
	काष्ठा termios tio;
	अक्षर **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
काष्ठा mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
काष्ठा mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	पूर्णांक fid;	/* forward id */
};

/* fd to control socket */
पूर्णांक muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
अटल अस्थिर संक_पूर्ण_प्रकार muxclient_terminate = 0;

/* PID of multiplex server */
अटल u_int muxserver_pid = 0;

अटल Channel *mux_listener_channel = शून्य;

काष्ठा mux_master_state {
	पूर्णांक hello_rcvd;
};

/* mux protocol messages */
#घोषणा MUX_संदेश_HELLO		0x00000001
#घोषणा MUX_C_NEW_SESSION	0x10000002
#घोषणा MUX_C_ALIVE_CHECK	0x10000004
#घोषणा MUX_C_TERMINATE		0x10000005
#घोषणा MUX_C_OPEN_FWD		0x10000006
#घोषणा MUX_C_CLOSE_FWD		0x10000007
#घोषणा MUX_C_NEW_STDIO_FWD	0x10000008
#घोषणा MUX_C_STOP_LISTENING	0x10000009
#घोषणा MUX_C_PROXY		0x1000000f
#घोषणा MUX_C_EXT_INFO		0x20000001
#घोषणा MUX_S_OK		0x80000001
#घोषणा MUX_S_PERMISSION_DENIED	0x80000002
#घोषणा MUX_S_FAILURE		0x80000003
#घोषणा MUX_S_EXIT_MESSAGE	0x80000004
#घोषणा MUX_S_ALIVE		0x80000005
#घोषणा MUX_S_SESSION_OPENED	0x80000006
#घोषणा MUX_S_REMOTE_PORT	0x80000007
#घोषणा MUX_S_TTY_ALLOC_FAIL	0x80000008
#घोषणा MUX_S_PROXY		0x8000000f
#घोषणा MUX_S_EXT_INFO		0x90000001

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
#घोषणा MUX_FWD_LOCAL   1
#घोषणा MUX_FWD_REMOTE  2
#घोषणा MUX_FWD_DYNAMIC 3

#घोषणा MUX_EXT_INFO		0x00000001

/* Bitmask of supported extensions */
अटल u_int extensions = 0;

अटल व्योम mux_session_confirm(काष्ठा ssh *, पूर्णांक, पूर्णांक, व्योम *);
अटल व्योम mux_stdio_confirm(काष्ठा ssh *, पूर्णांक, पूर्णांक, व्योम *);

अटल पूर्णांक mux_master_process_hello(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_new_session(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_alive_check(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_terminate(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_open_fwd(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_close_fwd(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_stdio_fwd(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_stop_listening(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_proxy(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);
अटल पूर्णांक mux_master_process_ext_info(काष्ठा ssh *, u_int,
	    Channel *, काष्ठा sshbuf *, काष्ठा sshbuf *);

अटल स्थिर काष्ठा {
	u_int type;
	पूर्णांक (*handler)(काष्ठा ssh *, u_int, Channel *,
	    काष्ठा sshbuf *, काष्ठा sshbuf *);
} mux_master_handlers[] = {
	{ MUX_संदेश_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, शून्य }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
अटल व्योम
mux_master_session_cleanup_cb(काष्ठा ssh *ssh, पूर्णांक cid, पूर्णांक force, व्योम *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	अगर (c == शून्य)
		fatal_f("channel_by_id(%i) == NULL", cid);
	अगर (c->ctl_chan != -1) {
		अगर ((cc = channel_by_id(ssh, c->ctl_chan)) == शून्य)
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
अटल व्योम
mux_master_control_cleanup_cb(काष्ठा ssh *ssh, पूर्णांक cid, पूर्णांक force, व्योम *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	अगर (c == शून्य)
		fatal_f("channel_by_id(%i) == NULL", cid);
	अगर (c->have_ctl_child_id) {
		अगर ((sc = channel_by_id(ssh, c->ctl_child_id)) == शून्य)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		अगर (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} अन्यथा {
			अगर (sc->istate == CHAN_निवेश_OPEN)
				chan_read_failed(ssh, sc);
			अगर (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
अटल पूर्णांक
env_permitted(स्थिर अक्षर *env)
{
	u_int i;
	पूर्णांक ret;
	अक्षर name[1024], *cp;

	अगर ((cp = म_अक्षर(env, '=')) == शून्य || cp == env)
		वापस 0;
	ret = snprintf(name, माप(name), "%.*s", (पूर्णांक)(cp - env), env);
	अगर (ret <= 0 || (माप_प्रकार)ret >= माप(name)) {
		error_f("name '%.100s...' too long", env);
		वापस 0;
	}

	क्रम (i = 0; i < options.अंक_send_env; i++)
		अगर (match_pattern(name, options.send_env[i]))
			वापस 1;

	वापस 0;
}

/* Mux master protocol message handlers */

अटल पूर्णांक
mux_master_process_hello(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	u_int ver;
	काष्ठा mux_master_state *state = (काष्ठा mux_master_state *)c->mux_ctx;
	पूर्णांक r;

	अगर (state == शून्य)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	अगर (state->hello_rcvd) {
		error_f("HELLO received twice");
		वापस -1;
	}
	अगर ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		वापस -1;
	}
	अगर (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		वापस -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	जबतक (sshbuf_len(m) > 0) {
		अक्षर *name = शून्य;
		माप_प्रकार मूल्य_len = 0;

		अगर ((r = sshbuf_get_cstring(m, &name, शून्य)) != 0 ||
		    (r = sshbuf_get_string_direct(m, शून्य, &मूल्य_len)) != 0) {
			error_fr(r, "parse extension");
			वापस -1;
		}
		अगर (म_भेद(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} अन्यथा {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, मूल्य_len);
		}
		मुक्त(name);
	}
	state->hello_rcvd = 1;
	वापस 0;
}

/* Enqueue a "ok" response to the reply buffer */
अटल व्योम
reply_ok(काष्ठा sshbuf *reply, u_int rid)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
अटल व्योम
reply_error(काष्ठा sshbuf *reply, u_int type, u_int rid, स्थिर अक्षर *संदेश)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, संदेश)) != 0)
		fatal_fr(r, "reply");
}

अटल पूर्णांक
mux_master_process_new_session(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	Channel *nc;
	काष्ठा mux_session_confirm_ctx *cctx;
	अक्षर *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	पूर्णांक r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, माप(*cctx));
	cctx->term = शून्य;
	cctx->rid = rid;
	cmd = शून्य;
	cctx->env = शून्य;
	env_len = 0;
	अगर ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, शून्य)) != 0) {
 malf:
		मुक्त(cmd);
		क्रम (j = 0; j < env_len; j++)
			मुक्त(cctx->env[j]);
		मुक्त(cctx->env);
		मुक्त(cctx->term);
		मुक्त(cctx);
		error_f("malformed message");
		वापस -1;
	}

#घोषणा MUX_MAX_ENV_VARS	4096
	जबतक (sshbuf_len(m) > 0) {
		अगर ((r = sshbuf_get_cstring(m, &cp, शून्य)) != 0)
			जाओ malf;
		अगर (!env_permitted(cp)) {
			मुक्त(cp);
			जारी;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    माप(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = शून्य;
		अगर (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			अवरोध;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	अगर ((cctx->cmd = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put(cctx->cmd, cmd, म_माप(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	मुक्त(cmd);
	cmd = शून्य;

	/* Gather fds from client */
	क्रम(i = 0; i < 3; i++) {
		अगर ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			क्रम (j = 0; j < i; j++)
				बंद(new_fd[j]);
			क्रम (j = 0; j < env_len; j++)
				मुक्त(cctx->env[j]);
			मुक्त(cctx->env);
			मुक्त(cctx->term);
			sshbuf_free(cctx->cmd);
			मुक्त(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			वापस -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	अगर (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		बंद(new_fd[0]);
		बंद(new_fd[1]);
		बंद(new_fd[2]);
		मुक्त(cctx->term);
		अगर (env_len != 0) {
			क्रम (i = 0; i < env_len; i++)
				मुक्त(cctx->env[i]);
			मुक्त(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		मुक्त(cctx);
		वापस 0;
	}

	अगर (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		अगर (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			जाओ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	अगर (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", म_त्रुटि(त्रुटि_सं));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	अगर (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	अगर (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	अगर (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, शून्य,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((पूर्णांक)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	वापस 0;
}

अटल पूर्णांक
mux_master_process_alive_check(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	पूर्णांक r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	अगर ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	वापस 0;
}

/* The "info" extension. */
अटल पूर्णांक
mux_master_process_ext_info(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	पूर्णांक r;
	u_int status = 0;
	अक्षर *name = शून्य, *संदेश = शून्य;

	debug2_f("channel %d: info request", c->self);

	अगर ((r = sshbuf_get_cstring(m, &name, शून्य)) != 0)
		fatal_fr(r, "parse");

	अगर (म_भेद(name, "connection") == 0) {
		अगर ((संदेश = connection_info_message(ssh)) == शून्य)
			fatal_f("connection_info_message");
		status = 1;
	} अन्यथा अगर (म_भेद(name, "channels") == 0) {
		अगर ((संदेश = channel_open_message(ssh)) == शून्य)
			fatal_f("channel_open_message");
		status = 1;
	} अन्यथा {
		संदेश = xstrdup("info request type not supported");
	}

	/* prepare reply */
	अगर ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, संदेश)) != 0)
		fatal_fr(r, "reply");
	मुक्त(संदेश);

	वापस 0;
}

अटल पूर्णांक
mux_master_process_terminate(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	अगर (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		अगर (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			वापस 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	वापस 0;
}

अटल अक्षर *
format_forward(u_int ftype, काष्ठा Forward *fwd)
{
	अक्षर *ret;

	चयन (ftype) {
	हाल MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != शून्य) ? fwd->listen_path :
		    (fwd->listen_host == शून्य) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != शून्य) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		अवरोध;
	हाल MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == शून्य) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		अवरोध;
	हाल MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != शून्य) ? fwd->listen_path :
		    (fwd->listen_host == शून्य) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != शून्य) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		अवरोध;
	शेष:
		fatal_f("unknown forward type %u", ftype);
	}
	वापस ret;
}

अटल पूर्णांक
compare_host(स्थिर अक्षर *a, स्थिर अक्षर *b)
{
	अगर (a == शून्य && b == शून्य)
		वापस 1;
	अगर (a == शून्य || b == शून्य)
		वापस 0;
	वापस म_भेद(a, b) == 0;
}

अटल पूर्णांक
compare_forward(काष्ठा Forward *a, काष्ठा Forward *b)
{
	अगर (!compare_host(a->listen_host, b->listen_host))
		वापस 0;
	अगर (!compare_host(a->listen_path, b->listen_path))
		वापस 0;
	अगर (a->listen_port != b->listen_port)
		वापस 0;
	अगर (!compare_host(a->connect_host, b->connect_host))
		वापस 0;
	अगर (!compare_host(a->connect_path, b->connect_path))
		वापस 0;
	अगर (a->connect_port != b->connect_port)
		वापस 0;

	वापस 1;
}

अटल व्योम
mux_confirm_remote_forward(काष्ठा ssh *ssh, पूर्णांक type, uint32_t seq, व्योम *ctxt)
{
	काष्ठा mux_channel_confirm_ctx *fctx = ctxt;
	अक्षर *failmsg = शून्य;
	काष्ठा Forward *rfwd;
	Channel *c;
	काष्ठा sshbuf *out;
	u_int port;
	पूर्णांक r;

	अगर ((c = channel_by_id(ssh, fctx->cid)) == शून्य) {
		/* no channel for reply */
		error_f("unknown channel");
		वापस;
	}
	अगर ((out = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर (fctx->fid >= options.अंक_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == शून्य &&
	    options.remote_forwards[fctx->fid].connect_host == शून्य)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		जाओ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_संदेश_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	अगर (type == SSH2_संदेश_REQUEST_SUCCESS) {
		अगर (rfwd->listen_port == 0) {
			अगर ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			अगर (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (पूर्णांक)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			अगर ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} अन्यथा {
			reply_ok(out, fctx->rid);
		}
		जाओ out;
	} अन्यथा {
		अगर (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		अगर (rfwd->listen_path != शून्य)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		अन्यथा
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
		स_रखो(rfwd, 0, माप(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	मुक्त(failmsg);
 out:
	अगर ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	अगर (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	मुक्त(fctx);
}

अटल पूर्णांक
mux_master_process_open_fwd(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	काष्ठा Forward fwd;
	अक्षर *fwd_desc = शून्य;
	अक्षर *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	पूर्णांक r, i, ret = 0, freefwd = 1;

	स_रखो(&fwd, 0, माप(fwd));

	/* XXX - lport/cport check redundant */
	अगर ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		जाओ out;
	}
	अगर (*listen_addr == '\0') {
		मुक्त(listen_addr);
		listen_addr = शून्य;
	}
	अगर (*connect_addr == '\0') {
		मुक्त(connect_addr);
		connect_addr = शून्य;
	}

	स_रखो(&fwd, 0, माप(fwd));
	fwd.listen_port = lport;
	अगर (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	अन्यथा
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	अगर (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	अन्यथा
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	अगर (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		मुक्त(listen_addr);
		मुक्त(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		वापस 0;
	}
	अगर (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		जाओ invalid;
	}
	अगर (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		जाओ invalid;
	}
	अगर ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		जाओ invalid;
	}
	अगर (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == शून्य &&
	    fwd.connect_path == शून्य) {
		logit_f("missing connect host");
		जाओ invalid;
	}

	/* Skip forwards that have already been requested */
	चयन (ftype) {
	हाल MUX_FWD_LOCAL:
	हाल MUX_FWD_DYNAMIC:
		क्रम (i = 0; i < options.अंक_local_forwards; i++) {
			अगर (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				जाओ out;
			}
		}
		अवरोध;
	हाल MUX_FWD_REMOTE:
		क्रम (i = 0; i < options.अंक_remote_forwards; i++) {
			अगर (!compare_forward(&fwd, options.remote_forwards + i))
				जारी;
			अगर (fwd.listen_port != 0)
				जाओ exists;
			debug2_f("found allocated port");
			अगर ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			जाओ out;
		}
		अवरोध;
	}

	अगर (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		अगर (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			जाओ out;
		}
	}

	अगर (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		अगर (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			जाओ out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} अन्यथा {
		काष्ठा mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		अगर (fwd.handle < 0)
			जाओ fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, माप(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.अंक_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		जाओ out;
	}
	reply_ok(reply, rid);
 out:
	मुक्त(fwd_desc);
	अगर (freefwd) {
		मुक्त(fwd.listen_host);
		मुक्त(fwd.listen_path);
		मुक्त(fwd.connect_host);
		मुक्त(fwd.connect_path);
	}
	वापस ret;
}

अटल पूर्णांक
mux_master_process_close_fwd(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	काष्ठा Forward fwd, *found_fwd;
	अक्षर *fwd_desc = शून्य;
	स्थिर अक्षर *error_reason = शून्य;
	अक्षर *listen_addr = शून्य, *connect_addr = शून्य;
	u_int ftype;
	पूर्णांक r, i, ret = 0;
	u_int lport, cport;

	स_रखो(&fwd, 0, माप(fwd));

	अगर ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		जाओ out;
	}

	अगर (*listen_addr == '\0') {
		मुक्त(listen_addr);
		listen_addr = शून्य;
	}
	अगर (*connect_addr == '\0') {
		मुक्त(connect_addr);
		connect_addr = शून्य;
	}

	स_रखो(&fwd, 0, माप(fwd));
	fwd.listen_port = lport;
	अगर (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	अन्यथा
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	अगर (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	अन्यथा
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = शून्य;
	चयन (ftype) {
	हाल MUX_FWD_LOCAL:
	हाल MUX_FWD_DYNAMIC:
		क्रम (i = 0; i < options.अंक_local_forwards; i++) {
			अगर (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				अवरोध;
			}
		}
		अवरोध;
	हाल MUX_FWD_REMOTE:
		क्रम (i = 0; i < options.अंक_remote_forwards; i++) {
			अगर (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				अवरोध;
			}
		}
		अवरोध;
	}

	अगर (found_fwd == शून्य)
		error_reason = "port not forwarded";
	अन्यथा अगर (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		अगर (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} अन्यथा {	/* local and dynamic forwards */
		/* Ditto */
		अगर (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	अगर (error_reason != शून्य)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	अन्यथा {
		reply_ok(reply, rid);
		मुक्त(found_fwd->listen_host);
		मुक्त(found_fwd->listen_path);
		मुक्त(found_fwd->connect_host);
		मुक्त(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = शून्य;
		found_fwd->listen_path = found_fwd->connect_path = शून्य;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	मुक्त(fwd_desc);
	मुक्त(listen_addr);
	मुक्त(connect_addr);

	वापस ret;
}

अटल पूर्णांक
mux_master_process_stdio_fwd(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	Channel *nc;
	अक्षर *chost = शून्य;
	u_int _cport, i, j;
	पूर्णांक ok = 0, cport, r, new_fd[2];
	काष्ठा mux_stdio_confirm_ctx *cctx;

	अगर ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		मुक्त(chost);
		error_f("malformed message");
		वापस -1;
	}
	अगर (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	अन्यथा अगर (_cport <= पूर्णांक_उच्च)
		cport = (पूर्णांक)_cport;
	अन्यथा {
		मुक्त(chost);
		error_f("invalid port 0x%x", _cport);
		वापस -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	क्रम(i = 0; i < 2; i++) {
		अगर ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			क्रम (j = 0; j < i; j++)
				बंद(new_fd[j]);
			मुक्त(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			वापस -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	अगर (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		बंद(new_fd[0]);
		बंद(new_fd[1]);
		मुक्त(chost);
		वापस 0;
	}

	अगर (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		अगर (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} अन्यथा {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		अगर (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			जाओ cleanup;
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

	cctx = xcalloc(1, माप(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	वापस 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
अटल व्योम
mux_stdio_confirm(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक success, व्योम *arg)
{
	काष्ठा mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	काष्ठा sshbuf *reply;
	पूर्णांक r;

	अगर (cctx == शून्य)
		fatal_f("cctx == NULL");
	अगर ((c = channel_by_id(ssh, id)) == शून्य)
		fatal_f("no channel for id %d", id);
	अगर ((cc = channel_by_id(ssh, c->ctl_chan)) == शून्य)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	अगर ((reply = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");

	अगर (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		जाओ done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	अगर ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	अगर ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	अगर (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = शून्य;
	मुक्त(cctx);
}

अटल पूर्णांक
mux_master_process_stop_listening(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	अगर (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		अगर (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			वापस 0;
		}
	}

	अगर (mux_listener_channel != शून्य) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		मुक्त(options.control_path);
		options.control_path = शून्य;
		mux_listener_channel = शून्य;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	वापस 0;
}

अटल पूर्णांक
mux_master_process_proxy(काष्ठा ssh *ssh, u_int rid,
    Channel *c, काष्ठा sshbuf *m, काष्ठा sshbuf *reply)
{
	पूर्णांक r;

	debug_f("channel %d: proxy request", c->self);

	अगर (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		अगर (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			वापस 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	अगर ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	वापस 0;
}

/* Channel callbacks fired on read/write from mux client fd */
अटल पूर्णांक
mux_master_read_cb(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा mux_master_state *state = (काष्ठा mux_master_state *)c->mux_ctx;
	काष्ठा sshbuf *in = शून्य, *out = शून्य;
	u_int type, rid, i;
	पूर्णांक r, ret = -1;

	अगर ((out = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	अगर (c->mux_ctx == शून्य) {
		state = xcalloc(1, माप(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		अगर ((r = sshbuf_put_u32(out, MUX_संदेश_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		अगर ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		अगर ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		जाओ out;
	}

	/* Channel code ensures that we receive whole packets */
	अगर ((r = sshbuf_froms(c->निवेश, &in)) != 0) {
 malf:
		error_f("malformed message");
		जाओ out;
	}

	अगर ((r = sshbuf_get_u32(in, &type)) != 0)
		जाओ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	अगर (type == MUX_संदेश_HELLO)
		rid = 0;
	अन्यथा {
		अगर (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_संदेश_HELLO, type);
			जाओ out;
		}
		अगर ((r = sshbuf_get_u32(in, &rid)) != 0)
			जाओ malf;
	}

	क्रम (i = 0; mux_master_handlers[i].handler != शून्य; i++) {
		अगर (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			अवरोध;
		}
	}
	अगर (mux_master_handlers[i].handler == शून्य) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	अगर (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	वापस ret;
}

व्योम
mux_exit_message(काष्ठा ssh *ssh, Channel *c, पूर्णांक exitval)
{
	काष्ठा sshbuf *m;
	Channel *mux_chan;
	पूर्णांक r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	अगर ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == शून्य)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

व्योम
mux_tty_alloc_failed(काष्ठा ssh *ssh, Channel *c)
{
	काष्ठा sshbuf *m;
	Channel *mux_chan;
	पूर्णांक r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	अगर ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == शून्य)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
व्योम
muxserver_listen(काष्ठा ssh *ssh)
{
	mode_t old_umask;
	अक्षर *orig_control_path = options.control_path;
	अक्षर rbuf[16+1];
	u_int i, r;
	पूर्णांक oerrno;

	अगर (options.control_path == शून्य ||
	    options.control_master == SSHCTL_MASTER_NO)
		वापस;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	क्रम (i = 0; i < माप(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[माप(rbuf) - 1] = '\0';
	options.control_path = शून्य;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = त्रुटि_सं;
	umask(old_umask);
	अगर (muxserver_sock < 0) {
		अगर (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			अगर (muxserver_sock != -1) {
				बंद(muxserver_sock);
				muxserver_sock = -1;
			}
			मुक्त(orig_control_path);
			मुक्त(options.control_path);
			options.control_path = शून्य;
			options.control_master = SSHCTL_MASTER_NO;
			वापस;
		} अन्यथा {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	अगर (link(options.control_path, orig_control_path) != 0) {
		अगर (त्रुटि_सं != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    म_त्रुटि(त्रुटि_सं));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		जाओ disable_mux_master;
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
अटल व्योम
mux_session_confirm(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक success, व्योम *arg)
{
	काष्ठा mux_session_confirm_ctx *cctx = arg;
	स्थिर अक्षर *display;
	Channel *c, *cc;
	पूर्णांक i, r;
	काष्ठा sshbuf *reply;

	अगर (cctx == शून्य)
		fatal_f("cctx == NULL");
	अगर ((c = channel_by_id(ssh, id)) == शून्य)
		fatal_f("no channel for id %d", id);
	अगर ((cc = channel_by_id(ssh, c->ctl_chan)) == शून्य)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	अगर ((reply = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");

	अगर (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		जाओ done;
	}

	display = दो_पर्या("DISPLAY");
	अगर (cctx->want_x_fwd && options.forward_x11 && display != शून्य) {
		अक्षर *proto, *तथ्य;

		/* Get reasonable local authentication information. */
		अगर (client_x11_get_proto(ssh, display, options.xauth_location,
		    options.forward_x11_trusted, options.forward_x11_timeout,
		    &proto, &तथ्य) == 0) {
			/* Request forwarding with authentication spoofing. */
			debug("Requesting X11 forwarding with authentication "
			    "spoofing.");
			x11_request_forwarding_with_spoofing(ssh, id,
			    display, proto, तथ्य, 1);
			/* XXX exit_on_forward_failure */
			client_expect_confirm(ssh, id, "X11 forwarding",
			    CONFIRM_WARN);
		}
	}

	अगर (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	अगर ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	अगर ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	अगर (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = शून्य;
	sshbuf_free(cctx->cmd);
	मुक्त(cctx->term);
	अगर (cctx->env != शून्य) {
		क्रम (i = 0; cctx->env[i] != शून्य; i++)
			मुक्त(cctx->env[i]);
		मुक्त(cctx->env);
	}
	मुक्त(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
अटल व्योम
control_client_sighandler(पूर्णांक signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
अटल व्योम
control_client_sigrelay(पूर्णांक signo)
{
	पूर्णांक save_errno = त्रुटि_सं;

	अगर (muxserver_pid > 1)
		समाप्त(muxserver_pid, signo);

	त्रुटि_सं = save_errno;
}

अटल पूर्णांक
mux_client_read(पूर्णांक fd, काष्ठा sshbuf *b, माप_प्रकार need, पूर्णांक timeout_ms)
{
	माप_प्रकार have;
	ssize_t len;
	u_char *p;
	पूर्णांक r;

	अगर ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	क्रम (have = 0; have < need; ) {
		अगर (muxclient_terminate) {
			त्रुटि_सं = EINTR;
			वापस -1;
		}
		len = पढ़ो(fd, p + have, need - have);
		अगर (len == -1) {
			चयन (त्रुटि_सं) {
#अगर defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			हाल EWOULDBLOCK:
#पूर्ण_अगर
			हाल EAGAIN:
				अगर (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    त्रुटि_सं != EINTR)
					वापस -1;	/* timeout */
				/* FALLTHROUGH */
			हाल EINTR:
				जारी;
			शेष:
				वापस -1;
			}
		}
		अगर (len == 0) {
			त्रुटि_सं = EPIPE;
			वापस -1;
		}
		have += (माप_प्रकार)len;
	}
	वापस 0;
}

अटल पूर्णांक
mux_client_write_packet(पूर्णांक fd, काष्ठा sshbuf *m)
{
	काष्ठा sshbuf *queue;
	u_int have, need;
	पूर्णांक r, oerrno, len;
	स्थिर u_char *ptr;
	काष्ठा pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	अगर ((queue = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	क्रम (have = 0; have < need; ) {
		अगर (muxclient_terminate) {
			sshbuf_free(queue);
			त्रुटि_सं = EINTR;
			वापस -1;
		}
		len = ग_लिखो(fd, ptr + have, need - have);
		अगर (len == -1) {
			चयन (त्रुटि_सं) {
#अगर defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			हाल EWOULDBLOCK:
#पूर्ण_अगर
			हाल EAGAIN:
				(व्योम)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			हाल EINTR:
				जारी;
			शेष:
				oerrno = त्रुटि_सं;
				sshbuf_free(queue);
				त्रुटि_सं = oerrno;
				वापस -1;
			}
		}
		अगर (len == 0) {
			sshbuf_free(queue);
			त्रुटि_सं = EPIPE;
			वापस -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	वापस 0;
}

अटल पूर्णांक
mux_client_read_packet_timeout(पूर्णांक fd, काष्ठा sshbuf *m, पूर्णांक timeout_ms)
{
	काष्ठा sshbuf *queue;
	माप_प्रकार need, have;
	स्थिर u_char *ptr;
	पूर्णांक r, oerrno;

	अगर ((queue = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		अगर ((oerrno = त्रुटि_सं) == EPIPE)
			debug3_f("read header failed: %s",
			    म_त्रुटि(त्रुटि_सं));
		sshbuf_free(queue);
		त्रुटि_सं = oerrno;
		वापस -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	अगर (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = त्रुटि_सं;
		debug3_f("read body failed: %s", म_त्रुटि(त्रुटि_सं));
		sshbuf_free(queue);
		त्रुटि_सं = oerrno;
		वापस -1;
	}
	अगर ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	वापस 0;
}

अटल पूर्णांक
mux_client_read_packet(पूर्णांक fd, काष्ठा sshbuf *m)
{
	वापस mux_client_read_packet_timeout(fd, m, -1);
}

अटल पूर्णांक
mux_client_hello_exchange(पूर्णांक fd, पूर्णांक timeout_ms)
{
	काष्ठा sshbuf *m;
	u_int type, ver;
	पूर्णांक r, ret = -1;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_संदेश_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	अगर (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	अगर (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		जाओ out;
	}

	अगर ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	अगर (type != MUX_संदेश_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_संदेश_HELLO, type);
		जाओ out;
	}
	अगर ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	अगर (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		जाओ out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	जबतक (sshbuf_len(m) > 0) {
		अक्षर *name = शून्य;

		अगर ((r = sshbuf_get_cstring(m, &name, शून्य)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*मूल्य*/
			error_fr(r, "parse extension");
			जाओ out;
		}
		/* Process extensions. */
		अगर (म_भेद(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} अन्यथा {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		मुक्त(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	वापस ret;
}

अटल u_int
mux_client_request_alive(पूर्णांक fd)
{
	काष्ठा sshbuf *m;
	अक्षर *e;
	u_int pid, type, rid;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);

	/* Read their reply */
	अगर (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		वापस 0;
	}

	अगर ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	अगर (type != MUX_S_ALIVE) {
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	अगर ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	अगर ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	वापस pid;
}

अटल अक्षर *
mux_client_request_info(पूर्णांक fd, स्थिर अक्षर *name)
{
	काष्ठा sshbuf *m;
	अक्षर *e, *संदेश;
	u_int type, rid, status;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);

	/* Read their reply */
	अगर (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		वापस 0;
	}

	अगर ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	अगर (type != MUX_S_EXT_INFO) {
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	अगर ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	अगर ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &संदेश, शून्य)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	वापस संदेश;
}

अटल व्योम
mux_client_request_terminate(पूर्णांक fd)
{
	काष्ठा sshbuf *m;
	अक्षर *e;
	u_int type, rid;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);

	/* Read their reply */
	अगर (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		अगर (त्रुटि_सं == EPIPE) {
			sshbuf_free(m);
			वापस;
		}
		fatal_f("read from master failed: %s", म_त्रुटि(त्रुटि_सं));
	}

	अगर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	चयन (type) {
	हाल MUX_S_OK:
		अवरोध;
	हाल MUX_S_PERMISSION_DENIED:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	हाल MUX_S_FAILURE:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	शेष:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

अटल पूर्णांक
mux_client_forward(पूर्णांक fd, पूर्णांक cancel_flag, u_int ftype, काष्ठा Forward *fwd)
{
	काष्ठा sshbuf *m;
	अक्षर *e, *fwd_desc;
	स्थिर अक्षर *lhost, *chost;
	u_int type, rid;
	पूर्णांक r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	मुक्त(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	अगर (fwd->listen_path != शून्य)
		lhost = fwd->listen_path;
	अन्यथा अगर (fwd->listen_host == शून्य)
		lhost = "";
	अन्यथा अगर (*fwd->listen_host == '\0')
		lhost = "*";
	अन्यथा
		lhost = fwd->listen_host;

	अगर (fwd->connect_path != शून्य)
		chost = fwd->connect_path;
	अन्यथा अगर (fwd->connect_host == शून्य)
		chost = "";
	अन्यथा
		chost = fwd->connect_host;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);

	/* Read their reply */
	अगर (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		वापस -1;
	}

	अगर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	चयन (type) {
	हाल MUX_S_OK:
		अवरोध;
	हाल MUX_S_REMOTE_PORT:
		अगर (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		अगर ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		अगर (muxclient_command == SSHMUX_COMMAND_FORWARD)
			ख_लिखो(मानक_निकास, "%i\n", fwd->allocated_port);
		अवरोध;
	हाल MUX_S_PERMISSION_DENIED:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		वापस -1;
	हाल MUX_S_FAILURE:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		वापस -1;
	शेष:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	वापस 0;
}

अटल पूर्णांक
mux_client_forwards(पूर्णांक fd, पूर्णांक cancel_flag)
{
	पूर्णांक i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.अंक_local_forwards, options.अंक_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	क्रम (i = 0; i < options.अंक_local_forwards; i++) {
		अगर (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	क्रम (i = 0; i < options.अंक_remote_forwards; i++) {
		अगर (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	वापस ret;
}

अटल पूर्णांक
mux_client_request_session(पूर्णांक fd)
{
	काष्ठा sshbuf *m;
	अक्षर *e;
	स्थिर अक्षर *term = शून्य;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	बाह्य अक्षर **environ;
	पूर्णांक r, rawmode = 0;

	debug3_f("entering");

	अगर ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		वापस -1;
	}

	ssh_signal(SIGPIPE, संक_छोड़ो);

	अगर (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	अगर ((term = lookup_env_in_list("TERM", options.setenv,
	    options.अंक_setenv)) == शून्य || *term == '\0')
		term = दो_पर्या("TERM");

	echar = 0xffffffff;
	अगर (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, शून्य, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == शून्य ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	अगर (options.अंक_send_env > 0 && environ != शून्य) {
		क्रम (i = 0; environ[i] != शून्य; i++) {
			अगर (!env_permitted(environ[i]))
				जारी;
			अगर ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	क्रम (i = 0; i < options.अंक_setenv; i++) {
		अगर ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	/* Send the stdio file descriptors */
	अगर (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	अगर (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", म_त्रुटि(त्रुटि_सं));
		sshbuf_free(m);
		वापस -1;
	}

	अगर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	चयन (type) {
	हाल MUX_S_SESSION_OPENED:
		अगर ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		अवरोध;
	हाल MUX_S_PERMISSION_DENIED:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		वापस -1;
	हाल MUX_S_FAILURE:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		वापस -1;
	शेष:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		वापस -1;
	}
	muxclient_request_id++;

	अगर (pledge("stdio proc tty", शून्य) == -1)
		fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(संक_विघ्न, control_client_sighandler);
	ssh_signal(संक_इति, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	अगर (options.fork_after_authentication)
		daemon(1, 1);
	अन्यथा {
		rawmode = tty_flag;
		अगर (tty_flag) {
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
	क्रम (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		अगर (mux_client_read_packet(fd, m) != 0)
			अवरोध;
		अगर ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		चयन (type) {
		हाल MUX_S_TTY_ALLOC_FAIL:
			अगर ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			अगर (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			जारी;
		हाल MUX_S_EXIT_MESSAGE:
			अगर ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			अगर (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			अगर (exitval_seen)
				fatal_f("exitval sent twice");
			अगर ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			जारी;
		शेष:
			अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	बंद(fd);
	अगर (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	अगर (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} अन्यथा अगर (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} अन्यथा
		debug2("Received exit status from master %d", exitval);

	अगर (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		ख_लिखो(मानक_त्रुटि, "Shared connection to %s closed.\r\n", host);

	निकास(exitval);
}

अटल पूर्णांक
mux_client_proxy(पूर्णांक fd)
{
	काष्ठा sshbuf *m;
	अक्षर *e;
	u_int type, rid;
	पूर्णांक r;

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);

	/* Read their reply */
	अगर (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		वापस 0;
	}
	अगर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	अगर (type != MUX_S_PROXY) {
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	वापस 0;
}

अटल पूर्णांक
mux_client_request_stdio_fwd(पूर्णांक fd)
{
	काष्ठा sshbuf *m;
	अक्षर *e;
	u_int type, rid, sid;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		वापस -1;
	}

	ssh_signal(SIGPIPE, संक_छोड़ो);

	अगर (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, शून्य, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	/* Send the stdio file descriptors */
	अगर (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	अगर (pledge("stdio proc tty", शून्य) == -1)
		fatal_f("pledge(): %s", म_त्रुटि(त्रुटि_सं));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	अगर (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", म_त्रुटि(त्रुटि_सं));
		sshbuf_free(m);
		वापस -1;
	}

	अगर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	चयन (type) {
	हाल MUX_S_SESSION_OPENED:
		अगर ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		अवरोध;
	हाल MUX_S_PERMISSION_DENIED:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	हाल MUX_S_FAILURE:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	शेष:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		वापस -1;
	}
	muxclient_request_id++;

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(संक_विघ्न, control_client_sighandler);
	ssh_signal(संक_इति, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	/*
	 * Stick around until the controlee closes the client_fd.
	 */
	sshbuf_reset(m);
	अगर (mux_client_read_packet(fd, m) != 0) {
		अगर (त्रुटि_सं == EPIPE ||
		    (त्रुटि_सं == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			वापस 0;
		}
		fatal_f("mux_client_read_packet: %s", म_त्रुटि(त्रुटि_सं));
	}
	fatal_f("master returned unexpected message %u", type);
}

अटल व्योम
mux_client_request_stop_listening(पूर्णांक fd)
{
	काष्ठा sshbuf *m;
	अक्षर *e;
	u_int type, rid;
	पूर्णांक r;

	debug3_f("entering");

	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new");
	अगर ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	अगर (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", म_त्रुटि(त्रुटि_सं));

	sshbuf_reset(m);

	/* Read their reply */
	अगर (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", म_त्रुटि(त्रुटि_सं));

	अगर ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	अगर (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	चयन (type) {
	हाल MUX_S_OK:
		अवरोध;
	हाल MUX_S_PERMISSION_DENIED:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	हाल MUX_S_FAILURE:
		अगर ((r = sshbuf_get_cstring(m, &e, शून्य)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	शेष:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
पूर्णांक
muxclient(स्थिर अक्षर *path)
{
	काष्ठा sockaddr_un addr;
	पूर्णांक sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	अक्षर *info = शून्य;

	अगर (muxclient_command == 0) {
		अगर (options.stdio_forward_host != शून्य)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		अन्यथा
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	चयन (options.control_master) {
	हाल SSHCTL_MASTER_AUTO:
	हाल SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	हाल SSHCTL_MASTER_NO:
		अवरोध;
	शेष:
		वापस -1;
	}

	स_रखो(&addr, '\0', माप(addr));
	addr.sun_family = AF_UNIX;

	अगर (strlcpy(addr.sun_path, path,
	    माप(addr.sun_path)) >= माप(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (अचिन्हित पूर्णांक)माप(addr.sun_path));

	अगर ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", म_त्रुटि(त्रुटि_सं));

	अगर (connect(sock, (काष्ठा sockaddr *)&addr, माप(addr)) == -1) {
		चयन (muxclient_command) {
		हाल SSHMUX_COMMAND_OPEN:
		हाल SSHMUX_COMMAND_STDIO_FWD:
			अवरोध;
		शेष:
			fatal("Control socket connect(%.100s): %s", path,
			    म_त्रुटि(त्रुटि_सं));
		}
		अगर (त्रुटि_सं == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} अन्यथा अगर (त्रुटि_सं == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} अन्यथा {
			error("Control socket connect(%.100s): %s", path,
			    म_त्रुटि(त्रुटि_सं));
		}
		बंद(sock);
		वापस -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	अगर (timeout > 0 && timeout < पूर्णांक_उच्च / 1000)
		timeout_ms = timeout * 1000;

	अगर (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		बंद(sock);
		वापस -1;
	}

	चयन (muxclient_command) {
	हाल SSHMUX_COMMAND_ALIVE_CHECK:
		अगर ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		ख_लिखो(मानक_त्रुटि, "Master running (pid=%u)\r\n", pid);
		निकास(0);
	हाल SSHMUX_COMMAND_CONNINFO:
	हाल SSHMUX_COMMAND_CHANINFO:
		अगर (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		अगर (info == शून्य)
			fatal_f("info request failed");
		म_लिखो("%s", info);
		निकास(0);
	हाल SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		अगर (options.log_level != SYSLOG_LEVEL_QUIET)
			ख_लिखो(मानक_त्रुटि, "Exit request sent.\r\n");
		निकास(0);
	हाल SSHMUX_COMMAND_FORWARD:
		अगर (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		निकास(0);
	हाल SSHMUX_COMMAND_OPEN:
		अगर (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			वापस -1;
		}
		mux_client_request_session(sock);
		वापस -1;
	हाल SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		निकास(0);
	हाल SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		अगर (options.log_level != SYSLOG_LEVEL_QUIET)
			ख_लिखो(मानक_त्रुटि, "Stop listening request sent.\r\n");
		निकास(0);
	हाल SSHMUX_COMMAND_CANCEL_FWD:
		अगर (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		निकास(0);
	हाल SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		वापस (sock);
	शेष:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
