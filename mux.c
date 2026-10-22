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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <poll.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "monitor_fdpass.h"
#ଅନ୍ତର୍ଭାଵ "sshpty.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"
#ଅନ୍ତର୍ଭାଵ "clientloop.h"

/* from ssh.c */
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା tty_flag;
ବାହ୍ୟ Options options;
ବାହ୍ୟ ଅକ୍ଷର *host;
ବାହ୍ୟ ସଂରଚନା sshbuf *command;
ବାହ୍ୟ ଅସ୍ଥିର sig_atomic_t quit_pending;

/* Context for session open confirmation callback */
ସଂରଚନା mux_session_confirm_ctx {
	u_int want_tty;
	u_int want_subsys;
	u_int want_x_fwd;
	u_int want_agent_fwd;
	ସଂରଚନା sshbuf *cmd;
	ଅକ୍ଷର *term;
	ସଂରଚନା termios tio;
	ଅକ୍ଷର **env;
	u_int rid;
};

/* Context for stdio fwd open confirmation callback */
ସଂରଚନା mux_stdio_confirm_ctx {
	u_int rid;
};

/* Context for global channel callback */
ସଂରଚନା mux_channel_confirm_ctx {
	u_int cid;	/* channel id */
	u_int rid;	/* request id */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fid;	/* forward id */
};

/* fd to control socket */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା muxserver_sock = -1;

/* client request id */
u_int muxclient_request_id = 0;

/* Multiplexing control command */
u_int muxclient_command = 0;

/* Set when signalled. */
ସ୍ଥିର ଅସ୍ଥିର sig_atomic_t muxclient_terminate = 0;

/* PID of multiplex server */
ସ୍ଥିର u_int muxserver_pid = 0;

ସ୍ଥିର Channel *mux_listener_channel = ଖାଲି;

ସଂରଚନା mux_master_state {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hello_rcvd;
};

/* mux protocol messages */
#define MUX_ସନ୍ଦେଶ_HELLO		0x00000001
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
ସ୍ଥିର u_int extensions = 0;

ସ୍ଥିର ଶୂନ୍ୟ mux_session_confirm(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *);
ସ୍ଥିର ଶୂନ୍ୟ mux_stdio_confirm(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ଶୂନ୍ୟ *);

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_hello(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_new_session(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_alive_check(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_terminate(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_open_fwd(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_close_fwd(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_stdio_fwd(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_stop_listening(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_proxy(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_process_ext_info(ସଂରଚନା ssh *, u_int,
	    Channel *, ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);

ସ୍ଥିର ଅଚଳ ସଂରଚନା {
	u_int type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*handler)(ସଂରଚନା ssh *, u_int, Channel *,
	    ସଂରଚନା sshbuf *, ସଂରଚନା sshbuf *);
} mux_master_handlers[] = {
	{ MUX_ସନ୍ଦେଶ_HELLO, mux_master_process_hello },
	{ MUX_C_NEW_SESSION, mux_master_process_new_session },
	{ MUX_C_ALIVE_CHECK, mux_master_process_alive_check },
	{ MUX_C_TERMINATE, mux_master_process_terminate },
	{ MUX_C_OPEN_FWD, mux_master_process_open_fwd },
	{ MUX_C_CLOSE_FWD, mux_master_process_close_fwd },
	{ MUX_C_NEW_STDIO_FWD, mux_master_process_stdio_fwd },
	{ MUX_C_STOP_LISTENING, mux_master_process_stop_listening },
	{ MUX_C_PROXY, mux_master_process_proxy },
	{ MUX_C_EXT_INFO, mux_master_process_ext_info },
	{ 0, ଖାଲି }
};

/* Cleanup callback fired on closure of mux client _session_ channel */
ସ୍ଥିର ଶୂନ୍ୟ
mux_master_session_cleanup_cb(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force, ଶୂନ୍ୟ *unused)
{
	Channel *cc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ଯଦି (c == ଖାଲି)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ଯଦି (c->ctl_chan != -1) {
		ଯଦି ((cc = channel_by_id(ssh, c->ctl_chan)) == ଖାଲି)
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
ସ୍ଥିର ଶୂନ୍ୟ
mux_master_control_cleanup_cb(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cid, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force, ଶୂନ୍ୟ *unused)
{
	Channel *sc, *c = channel_by_id(ssh, cid);

	debug3_f("entering for channel %d", cid);
	ଯଦି (c == ଖାଲି)
		fatal_f("channel_by_id(%i) == NULL", cid);
	ଯଦି (c->have_ctl_child_id) {
		ଯଦି ((sc = channel_by_id(ssh, c->ctl_child_id)) == ଖାଲି)
			fatal_f("channel %d missing session channel %u",
			    c->self, c->ctl_child_id);
		c->ctl_child_id = 0;
		c->have_ctl_child_id = 0;
		sc->ctl_chan = -1;
		ଯଦି (sc->type != SSH_CHANNEL_OPEN &&
		    sc->type != SSH_CHANNEL_OPENING) {
			debug2_f("channel %d: not open", sc->self);
			chan_mark_dead(ssh, sc);
		} ଅନ୍ୟଥା {
			ଯଦି (sc->istate == CHAN_ନିବେଶ_OPEN)
				chan_read_failed(ssh, sc);
			ଯଦି (sc->ostate == CHAN_OUTPUT_OPEN)
				chan_write_failed(ssh, sc);
		}
	}
	channel_cancel_cleanup(ssh, c->self);
}

/* Check mux client environment variables before passing them to mux master. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
env_permitted(ଅଚଳ ଅକ୍ଷର *env)
{
	u_int i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	ଅକ୍ଷର name[1024], *cp;

	ଯଦି ((cp = strchr(env, '=')) == ଖାଲି || cp == env)
		ଫେରନ୍ତୁ 0;
	ret = snprintf(name, ଆକାର(name), "%.*s", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(cp - env), env);
	ଯଦି (ret <= 0 || (size_t)ret >= ଆକାର(name)) {
		error_f("name '%.100s...' too long", env);
		ଫେରନ୍ତୁ 0;
	}

	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_send_env; i++)
		ଯଦି (match_pattern(name, options.send_env[i]))
			ଫେରନ୍ତୁ 1;

	ଫେରନ୍ତୁ 0;
}

/* Mux master protocol message handlers */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_hello(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	u_int ver;
	ସଂରଚନା mux_master_state *state = (ସଂରଚନା mux_master_state *)c->mux_ctx;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (state == ଖାଲି)
		fatal_f("channel %d: c->mux_ctx == NULL", c->self);
	ଯଦି (state->hello_rcvd) {
		error_f("HELLO received twice");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((r = sshbuf_get_u32(m, &ver)) != 0) {
		error_fr(r, "parse");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (ver != SSHMUX_VER) {
		error_f("unsupported multiplexing protocol version %u "
		    "(expected %u)", ver, SSHMUX_VER);
		ଫେରନ୍ତୁ -1;
	}
	debug2_f("channel %d client version %u", c->self, ver);

	/* No extensions are presently defined */
	ଯେତେବେଳେ (sshbuf_len(m) > 0) {
		ଅକ୍ଷର *name = ଖାଲି;
		size_t ମୂଲ୍ୟ_len = 0;

		ଯଦି ((r = sshbuf_get_cstring(m, &name, ଖାଲି)) != 0 ||
		    (r = sshbuf_get_string_direct(m, ଖାଲି, &ମୂଲ୍ୟ_len)) != 0) {
			error_fr(r, "parse extension");
			ଫେରନ୍ତୁ -1;
		}
		ଯଦି (strcmp(name, "info") == 0) {
			debug_f("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ଅନ୍ୟଥା {
			debug2_f("Unrecognised extension \"%s\" length %zu",
			    name, ମୂଲ୍ୟ_len);
		}
		ମୁକ୍ତ(name);
	}
	state->hello_rcvd = 1;
	ଫେରନ୍ତୁ 0;
}

/* Enqueue a "ok" response to the reply buffer */
ସ୍ଥିର ଶୂନ୍ୟ
reply_ok(ସଂରଚନା sshbuf *reply, u_int rid)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u32(reply, MUX_S_OK)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");
}

/* Enqueue an error response to the reply buffer */
ସ୍ଥିର ଶୂନ୍ୟ
reply_error(ସଂରଚନା sshbuf *reply, u_int type, u_int rid, ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_u32(reply, type)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_cstring(reply, ସନ୍ଦେଶ)) != 0)
		fatal_fr(r, "reply");
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_new_session(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	Channel *nc;
	ସଂରଚନା mux_session_confirm_ctx *cctx;
	ଅକ୍ଷର *cmd, *cp;
	u_int i, j, env_len, escape_char, window, packetmax;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, new_fd[3];

	/* Reply for SSHMUX_COMMAND_OPEN */
	cctx = xcalloc(1, ଆକାର(*cctx));
	cctx->term = ଖାଲି;
	cctx->rid = rid;
	cmd = ଖାଲି;
	cctx->env = ଖାଲି;
	env_len = 0;
	ଯଦି ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_u32(m, &cctx->want_tty)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_x_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_agent_fwd)) != 0 ||
	    (r = sshbuf_get_u32(m, &cctx->want_subsys)) != 0 ||
	    (r = sshbuf_get_u32(m, &escape_char)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cctx->term, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(m, &cmd, ଖାଲି)) != 0) {
 malf:
		ମୁକ୍ତ(cmd);
		ପାଇଁ (j = 0; j < env_len; j++)
			ମୁକ୍ତ(cctx->env[j]);
		ମୁକ୍ତ(cctx->env);
		ମୁକ୍ତ(cctx->term);
		ମୁକ୍ତ(cctx);
		error_f("malformed message");
		ଫେରନ୍ତୁ -1;
	}

#define MUX_MAX_ENV_VARS	4096
	ଯେତେବେଳେ (sshbuf_len(m) > 0) {
		ଯଦି ((r = sshbuf_get_cstring(m, &cp, ଖାଲି)) != 0)
			ଯାଅ malf;
		ଯଦି (!env_permitted(cp)) {
			ମୁକ୍ତ(cp);
			ଜାରି;
		}
		cctx->env = xreallocarray(cctx->env, env_len + 2,
		    ଆକାର(*cctx->env));
		cctx->env[env_len++] = cp;
		cctx->env[env_len] = ଖାଲି;
		ଯଦି (env_len > MUX_MAX_ENV_VARS) {
			error_f(">%d environment variables received, "
			    "ignoring additional", MUX_MAX_ENV_VARS);
			ଭାଙ୍ଗ;
		}
	}

	debug2_f("channel %d: request tty %d, X %d, agent %d, subsys %d, "
	    "term \"%s\", cmd \"%s\", env %u", c->self,
	    cctx->want_tty, cctx->want_x_fwd, cctx->want_agent_fwd,
	    cctx->want_subsys, cctx->term, cmd, env_len);

	ଯଦି ((cctx->cmd = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put(cctx->cmd, cmd, strlen(cmd))) != 0)
		fatal_fr(r, "sshbuf_put");
	ମୁକ୍ତ(cmd);
	cmd = ଖାଲି;

	/* Gather fds from client */
	ପାଇଁ(i = 0; i < 3; i++) {
		ଯଦି ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ପାଇଁ (j = 0; j < i; j++)
				close(new_fd[j]);
			ପାଇଁ (j = 0; j < env_len; j++)
				ମୁକ୍ତ(cctx->env[j]);
			ମୁକ୍ତ(cctx->env);
			ମୁକ୍ତ(cctx->term);
			sshbuf_free(cctx->cmd);
			ମୁକ୍ତ(cctx);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ଫେରନ୍ତୁ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d, stderr %d",
	    new_fd[0], new_fd[1], new_fd[2]);

	/* XXX support multiple child sessions in future */
	ଯଦି (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		close(new_fd[2]);
		ମୁକ୍ତ(cctx->term);
		ଯଦି (env_len != 0) {
			ପାଇଁ (i = 0; i < env_len; i++)
				ମୁକ୍ତ(cctx->env[i]);
			ମୁକ୍ତ(cctx->env);
		}
		sshbuf_free(cctx->cmd);
		ମୁକ୍ତ(cctx);
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ଯଦି (!ask_permission("Allow shared connection to %s? ", host)) {
			debug2_f("session refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ଯାଅ cleanup;
		}
	}

	/* Try to pick up ttymodes from client before it goes raw */
	ଯଦି (cctx->want_tty && tcgetattr(new_fd[0], &cctx->tio) == -1)
		error_f("tcgetattr: %s", strerror(errno));

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	ଯଦି (cctx->want_tty) {
		window >>= 1;
		packetmax >>= 1;
	}

	nc = channel_new(ssh, "session", SSH_CHANNEL_OPENING,
	    new_fd[0], new_fd[1], new_fd[2], window, packetmax,
	    CHAN_EXTENDED_WRITE, "client-session", CHANNEL_NONBLOCK_STDIO);
	ଯଦି (cctx->want_tty)
		channel_set_tty(ssh, nc);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	ଯଦି (cctx->want_tty && escape_char != 0xffffffff) {
		channel_register_filter(ssh, nc->self,
		    client_simple_escape_filter, ଖାଲି,
		    client_filter_cleanup,
		    client_new_escape_filter_ctx((ପୂର୍ଣ୍ଣସଂଖ୍ୟା)escape_char));
	}

	debug2_f("channel_new: %d linked to control channel %d",
	    nc->self, nc->ctl_chan);

	channel_send_open(ssh, nc->self);
	channel_register_open_confirm(ssh, nc->self, mux_session_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */
	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	/* reply is deferred, sent by mux_session_confirm */
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_alive_check(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug2_f("channel %d: alive check", c->self);

	/* prepare reply */
	ଯଦି ((r = sshbuf_put_u32(reply, MUX_S_ALIVE)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, (u_int)getpid())) != 0)
		fatal_fr(r, "reply");

	ଫେରନ୍ତୁ 0;
}

/* The "info" extension. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_ext_info(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	u_int status = 0;
	ଅକ୍ଷର *name = ଖାଲି, *ସନ୍ଦେଶ = ଖାଲି;

	debug2_f("channel %d: info request", c->self);

	ଯଦି ((r = sshbuf_get_cstring(m, &name, ଖାଲି)) != 0)
		fatal_fr(r, "parse");

	ଯଦି (strcmp(name, "connection") == 0) {
		ଯଦି ((ସନ୍ଦେଶ = connection_info_message(ssh)) == ଖାଲି)
			fatal_f("connection_info_message");
		status = 1;
	} ଅନ୍ୟଥା ଯଦି (strcmp(name, "channels") == 0) {
		ଯଦି ((ସନ୍ଦେଶ = channel_open_message(ssh)) == ଖାଲି)
			fatal_f("channel_open_message");
		status = 1;
	} ଅନ୍ୟଥା {
		ସନ୍ଦେଶ = xstrdup("info request type not supported");
	}

	/* prepare reply */
	ଯଦି ((r = sshbuf_put_u32(reply, MUX_S_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, status)) != 0 ||
	    (r = sshbuf_put_cstring(reply, ସନ୍ଦେଶ)) != 0)
		fatal_fr(r, "reply");
	ମୁକ୍ତ(ସନ୍ଦେଶ);

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_terminate(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	debug2_f("channel %d: terminate request", c->self);

	ଯଦି (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ଯଦି (!ask_permission("Terminate shared connection to %s? ",
		    host)) {
			debug2_f("termination refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ଫେରନ୍ତୁ 0;
		}
	}

	quit_pending = 1;
	reply_ok(reply, rid);
	/* XXX exit happens too soon - message never makes it to client */
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଅକ୍ଷର *
format_forward(u_int ftype, ସଂରଚନା Forward *fwd)
{
	ଅକ୍ଷର *ret;

	ବାଛ (ftype) {
	ସ୍ଥିତି MUX_FWD_LOCAL:
		xasprintf(&ret, "local forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ଖାଲି) ? fwd->listen_path :
		    (fwd->listen_host == ଖାଲି) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port,
		    (fwd->connect_path != ଖାଲି) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_FWD_DYNAMIC:
		xasprintf(&ret, "dynamic forward %.200s:%d -> *",
		    (fwd->listen_host == ଖାଲି) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    fwd->listen_host, fwd->listen_port);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_FWD_REMOTE:
		xasprintf(&ret, "remote forward %.200s:%d -> %.200s:%d",
		    (fwd->listen_path != ଖାଲି) ? fwd->listen_path :
		    (fwd->listen_host == ଖାଲି) ?
		    "LOCALHOST" : fwd->listen_host,
		    fwd->listen_port,
		    (fwd->connect_path != ଖାଲି) ? fwd->connect_path :
		    fwd->connect_host, fwd->connect_port);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unknown forward type %u", ftype);
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
compare_host(ଅଚଳ ଅକ୍ଷର *a, ଅଚଳ ଅକ୍ଷର *b)
{
	ଯଦି (a == ଖାଲି && b == ଖାଲି)
		ଫେରନ୍ତୁ 1;
	ଯଦି (a == ଖାଲି || b == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ strcmp(a, b) == 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
compare_forward(ସଂରଚନା Forward *a, ସଂରଚନା Forward *b)
{
	ଯଦି (!compare_host(a->listen_host, b->listen_host))
		ଫେରନ୍ତୁ 0;
	ଯଦି (!compare_host(a->listen_path, b->listen_path))
		ଫେରନ୍ତୁ 0;
	ଯଦି (a->listen_port != b->listen_port)
		ଫେରନ୍ତୁ 0;
	ଯଦି (!compare_host(a->connect_host, b->connect_host))
		ଫେରନ୍ତୁ 0;
	ଯଦି (!compare_host(a->connect_path, b->connect_path))
		ଫେରନ୍ତୁ 0;
	ଯଦି (a->connect_port != b->connect_port)
		ଫେରନ୍ତୁ 0;

	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ଶୂନ୍ୟ
mux_confirm_remote_forward(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ଶୂନ୍ୟ *ctxt)
{
	ସଂରଚନା mux_channel_confirm_ctx *fctx = ctxt;
	ଅକ୍ଷର *failmsg = ଖାଲି;
	ସଂରଚନା Forward *rfwd;
	Channel *c;
	ସଂରଚନା sshbuf *out;
	u_int port;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((c = channel_by_id(ssh, fctx->cid)) == ଖାଲି) {
		/* no channel for reply */
		error_f("unknown channel");
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((out = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି (fctx->fid >= options.ଅଙ୍କ_remote_forwards ||
	    (options.remote_forwards[fctx->fid].connect_path == ଖାଲି &&
	    options.remote_forwards[fctx->fid].connect_host == ଖାଲି)) {
		xasprintf(&failmsg, "unknown forwarding id %d", fctx->fid);
		ଯାଅ fail;
	}
	rfwd = &options.remote_forwards[fctx->fid];
	debug_f("%s for: listen %d, connect %s:%d",
	    type == SSH2_ସନ୍ଦେଶ_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	ଯଦି (type == SSH2_ସନ୍ଦେଶ_REQUEST_SUCCESS) {
		ଯଦି (rfwd->listen_port == 0) {
			ଯଦି ((r = sshpkt_get_u32(ssh, &port)) != 0)
				fatal_fr(r, "parse port");
			ଯଦି (port > 65535) {
				fatal("Invalid allocated port %u for "
				    "mux remote forward to %s:%d", port,
				    rfwd->connect_host, rfwd->connect_port);
			}
			rfwd->allocated_port = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)port;
			debug("Allocated port %u for mux remote forward"
			    " to %s:%d", rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			ଯଦି ((r = sshbuf_put_u32(out,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(out, fctx->rid)) != 0 ||
			    (r = sshbuf_put_u32(out,
			    rfwd->allocated_port)) != 0)
				fatal_fr(r, "reply");
			channel_update_permission(ssh, rfwd->handle,
			    rfwd->allocated_port);
		} ଅନ୍ୟଥା {
			reply_ok(out, fctx->rid);
		}
		ଯାଅ out;
	} ଅନ୍ୟଥା {
		ଯଦି (rfwd->listen_port == 0)
			channel_update_permission(ssh, rfwd->handle, -1);
		ଯଦି (rfwd->listen_path != ଖାଲି)
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen path %s", rfwd->listen_path);
		ଅନ୍ୟଥା
			xasprintf(&failmsg, "remote port forwarding failed for "
			    "listen port %d", rfwd->listen_port);

		debug2_f("clearing registered forwarding for listen %d, "
		    "connect %s:%d", rfwd->listen_port,
		    rfwd->connect_path ? rfwd->connect_path :
		    rfwd->connect_host, rfwd->connect_port);

		ମୁକ୍ତ(rfwd->listen_host);
		ମୁକ୍ତ(rfwd->listen_path);
		ମୁକ୍ତ(rfwd->connect_host);
		ମୁକ୍ତ(rfwd->connect_path);
		memset(rfwd, 0, ଆକାର(*rfwd));
	}
 fail:
	error_f("%s", failmsg);
	reply_error(out, MUX_S_FAILURE, fctx->rid, failmsg);
	ମୁକ୍ତ(failmsg);
 out:
	ଯଦି ((r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(out);
	ଯଦି (c->mux_pause <= 0)
		fatal_f("mux_pause %d", c->mux_pause);
	c->mux_pause = 0; /* start processing messages again */
	ମୁକ୍ତ(fctx);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_open_fwd(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	ସଂରଚନା Forward fwd;
	ଅକ୍ଷର *fwd_desc = ଖାଲି;
	ଅକ୍ଷର *listen_addr, *connect_addr;
	u_int ftype;
	u_int lport, cport;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, ret = 0, freefwd = 1;

	memset(&fwd, 0, ଆକାର(fwd));

	/* XXX - lport/cport check redundant */
	ଯଦି ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ଯାଅ out;
	}
	ଯଦି (*listen_addr == '\0') {
		ମୁକ୍ତ(listen_addr);
		listen_addr = ଖାଲି;
	}
	ଯଦି (*connect_addr == '\0') {
		ମୁକ୍ତ(connect_addr);
		connect_addr = ଖାଲି;
	}

	memset(&fwd, 0, ଆକାର(fwd));
	fwd.listen_port = lport;
	ଯଦି (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ଅନ୍ୟଥା
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ଯଦି (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ଅନ୍ୟଥା
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	ଯଦି (ftype != MUX_FWD_LOCAL && ftype != MUX_FWD_REMOTE &&
	    ftype != MUX_FWD_DYNAMIC) {
		logit_f("invalid forwarding type %u", ftype);
 invalid:
		ମୁକ୍ତ(listen_addr);
		ମୁକ୍ତ(connect_addr);
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Invalid forwarding request");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି (ftype == MUX_FWD_DYNAMIC && fwd.listen_path) {
		logit_f("streamlocal and dynamic forwards "
		    "are mutually exclusive");
		ଯାଅ invalid;
	}
	ଯଦି (fwd.listen_port != PORT_STREAMLOCAL && fwd.listen_port >= 65536) {
		logit_f("invalid listen port %u", fwd.listen_port);
		ଯାଅ invalid;
	}
	ଯଦି ((fwd.connect_port != PORT_STREAMLOCAL &&
	    fwd.connect_port >= 65536) ||
	    (ftype != MUX_FWD_DYNAMIC && ftype != MUX_FWD_REMOTE &&
	    fwd.connect_port == 0)) {
		logit_f("invalid connect port %u",
		    fwd.connect_port);
		ଯାଅ invalid;
	}
	ଯଦି (ftype != MUX_FWD_DYNAMIC && fwd.connect_host == ଖାଲି &&
	    fwd.connect_path == ଖାଲି) {
		logit_f("missing connect host");
		ଯାଅ invalid;
	}

	/* Skip forwards that have already been requested */
	ବାଛ (ftype) {
	ସ୍ଥିତି MUX_FWD_LOCAL:
	ସ୍ଥିତି MUX_FWD_DYNAMIC:
		ପାଇଁ (i = 0; i < options.ଅଙ୍କ_local_forwards; i++) {
			ଯଦି (compare_forward(&fwd,
			    options.local_forwards + i)) {
 exists:
				debug2_f("found existing forwarding");
				reply_ok(reply, rid);
				ଯାଅ out;
			}
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_FWD_REMOTE:
		ପାଇଁ (i = 0; i < options.ଅଙ୍କ_remote_forwards; i++) {
			ଯଦି (!compare_forward(&fwd, options.remote_forwards + i))
				ଜାରି;
			ଯଦି (fwd.listen_port != 0)
				ଯାଅ exists;
			debug2_f("found allocated port");
			ଯଦି ((r = sshbuf_put_u32(reply,
			    MUX_S_REMOTE_PORT)) != 0 ||
			    (r = sshbuf_put_u32(reply, rid)) != 0 ||
			    (r = sshbuf_put_u32(reply,
			    options.remote_forwards[i].allocated_port)) != 0)
				fatal_fr(r, "reply FWD_REMOTE");
			ଯାଅ out;
		}
		ଭାଙ୍ଗ;
	}

	ଯଦି (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ଯଦି (!ask_permission("Open %s on %s?", fwd_desc, host)) {
			debug2_f("forwarding refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ଯାଅ out;
		}
	}

	ଯଦି (ftype == MUX_FWD_LOCAL || ftype == MUX_FWD_DYNAMIC) {
		ଯଦି (!channel_setup_local_fwd_listener(ssh, &fwd,
		    &options.fwd_opts)) {
 fail:
			logit_f("requested %s failed", fwd_desc);
			reply_error(reply, MUX_S_FAILURE, rid,
			    "Port forwarding failed");
			ଯାଅ out;
		}
		add_local_forward(&options, &fwd);
		freefwd = 0;
	} ଅନ୍ୟଥା {
		ସଂରଚନା mux_channel_confirm_ctx *fctx;

		fwd.handle = channel_request_remote_forwarding(ssh, &fwd);
		ଯଦି (fwd.handle < 0)
			ଯାଅ fail;
		add_remote_forward(&options, &fwd);
		fctx = xcalloc(1, ଆକାର(*fctx));
		fctx->cid = c->self;
		fctx->rid = rid;
		fctx->fid = options.ଅଙ୍କ_remote_forwards - 1;
		client_register_global_confirm(mux_confirm_remote_forward,
		    fctx);
		freefwd = 0;
		c->mux_pause = 1; /* wait for mux_confirm_remote_forward */
		/* delayed reply in mux_confirm_remote_forward */
		ଯାଅ out;
	}
	reply_ok(reply, rid);
 out:
	ମୁକ୍ତ(fwd_desc);
	ଯଦି (freefwd) {
		ମୁକ୍ତ(fwd.listen_host);
		ମୁକ୍ତ(fwd.listen_path);
		ମୁକ୍ତ(fwd.connect_host);
		ମୁକ୍ତ(fwd.connect_path);
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_close_fwd(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	ସଂରଚନା Forward fwd, *found_fwd;
	ଅକ୍ଷର *fwd_desc = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *error_reason = ଖାଲି;
	ଅକ୍ଷର *listen_addr = ଖାଲି, *connect_addr = ଖାଲି;
	u_int ftype;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, i, ret = 0;
	u_int lport, cport;

	memset(&fwd, 0, ଆକାର(fwd));

	ଯଦି ((r = sshbuf_get_u32(m, &ftype)) != 0 ||
	    (r = sshbuf_get_cstring(m, &listen_addr, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, &lport)) != 0 ||
	    (r = sshbuf_get_cstring(m, &connect_addr, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, &cport)) != 0 ||
	    (lport != (u_int)PORT_STREAMLOCAL && lport > 65535) ||
	    (cport != (u_int)PORT_STREAMLOCAL && cport > 65535)) {
		error_f("malformed message");
		ret = -1;
		ଯାଅ out;
	}

	ଯଦି (*listen_addr == '\0') {
		ମୁକ୍ତ(listen_addr);
		listen_addr = ଖାଲି;
	}
	ଯଦି (*connect_addr == '\0') {
		ମୁକ୍ତ(connect_addr);
		connect_addr = ଖାଲି;
	}

	memset(&fwd, 0, ଆକାର(fwd));
	fwd.listen_port = lport;
	ଯଦି (fwd.listen_port == PORT_STREAMLOCAL)
		fwd.listen_path = listen_addr;
	ଅନ୍ୟଥା
		fwd.listen_host = listen_addr;
	fwd.connect_port = cport;
	ଯଦି (fwd.connect_port == PORT_STREAMLOCAL)
		fwd.connect_path = connect_addr;
	ଅନ୍ୟଥା
		fwd.connect_host = connect_addr;

	debug2_f("channel %d: request cancel %s", c->self,
	    (fwd_desc = format_forward(ftype, &fwd)));

	/* make sure this has been requested */
	found_fwd = ଖାଲି;
	ବାଛ (ftype) {
	ସ୍ଥିତି MUX_FWD_LOCAL:
	ସ୍ଥିତି MUX_FWD_DYNAMIC:
		ପାଇଁ (i = 0; i < options.ଅଙ୍କ_local_forwards; i++) {
			ଯଦି (compare_forward(&fwd,
			    options.local_forwards + i)) {
				found_fwd = options.local_forwards + i;
				ଭାଙ୍ଗ;
			}
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_FWD_REMOTE:
		ପାଇଁ (i = 0; i < options.ଅଙ୍କ_remote_forwards; i++) {
			ଯଦି (compare_forward(&fwd,
			    options.remote_forwards + i)) {
				found_fwd = options.remote_forwards + i;
				ଭାଙ୍ଗ;
			}
		}
		ଭାଙ୍ଗ;
	}

	ଯଦି (found_fwd == ଖାଲି)
		error_reason = "port not forwarded";
	ଅନ୍ୟଥା ଯଦି (ftype == MUX_FWD_REMOTE) {
		/*
		 * This shouldn't fail unless we confused the host/port
		 * between options.remote_forwards and permitted_opens.
		 * However, for dynamic allocated listen ports we need
		 * to use the actual listen port.
		 */
		ଯଦି (channel_request_rforward_cancel(ssh, found_fwd) == -1)
			error_reason = "port not in permitted opens";
	} ଅନ୍ୟଥା {	/* local and dynamic forwards */
		/* Ditto */
		ଯଦି (channel_cancel_lport_listener(ssh, &fwd, fwd.connect_port,
		    &options.fwd_opts) != 1)
			error_reason = "port not found";
	}

	ଯଦି (error_reason != ଖାଲି)
		reply_error(reply, MUX_S_FAILURE, rid, error_reason);
	ଅନ୍ୟଥା {
		reply_ok(reply, rid);
		ମୁକ୍ତ(found_fwd->listen_host);
		ମୁକ୍ତ(found_fwd->listen_path);
		ମୁକ୍ତ(found_fwd->connect_host);
		ମୁକ୍ତ(found_fwd->connect_path);
		found_fwd->listen_host = found_fwd->connect_host = ଖାଲି;
		found_fwd->listen_path = found_fwd->connect_path = ଖାଲି;
		found_fwd->listen_port = found_fwd->connect_port = 0;
	}
 out:
	ମୁକ୍ତ(fwd_desc);
	ମୁକ୍ତ(listen_addr);
	ମୁକ୍ତ(connect_addr);

	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_stdio_fwd(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	Channel *nc;
	ଅକ୍ଷର *chost = ଖାଲି;
	u_int _cport, i, j;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ok = 0, cport, r, new_fd[2];
	ସଂରଚନା mux_stdio_confirm_ctx *cctx;

	ଯଦି ((r = sshbuf_skip_string(m)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(m, &chost, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(m, &_cport)) != 0) {
		ମୁକ୍ତ(chost);
		error_f("malformed message");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି (_cport == (u_int)PORT_STREAMLOCAL)
		cport = PORT_STREAMLOCAL;
	ଅନ୍ୟଥା ଯଦି (_cport <= INT_MAX)
		cport = (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)_cport;
	ଅନ୍ୟଥା {
		ମୁକ୍ତ(chost);
		error_f("invalid port 0x%x", _cport);
		ଫେରନ୍ତୁ -1;
	}

	debug2_f("channel %d: stdio fwd to %s:%d", c->self, chost, cport);

	/* Gather fds from client */
	ପାଇଁ(i = 0; i < 2; i++) {
		ଯଦି ((new_fd[i] = mm_receive_fd(c->sock)) == -1) {
			error_f("failed to receive fd %d from client", i);
			ପାଇଁ (j = 0; j < i; j++)
				close(new_fd[j]);
			ମୁକ୍ତ(chost);

			/* prepare reply */
			reply_error(reply, MUX_S_FAILURE, rid,
			    "did not receive file descriptors");
			ଫେରନ୍ତୁ -1;
		}
	}

	debug3_f("got fds stdin %d, stdout %d", new_fd[0], new_fd[1]);

	/* XXX support multiple child sessions in future */
	ଯଦି (c->have_ctl_child_id) {
		debug2_f("session already open");
		reply_error(reply, MUX_S_FAILURE, rid,
		    "Multiple sessions not supported");
 cleanup:
		close(new_fd[0]);
		close(new_fd[1]);
		ମୁକ୍ତ(chost);
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ଯଦି (cport == PORT_STREAMLOCAL) {
			ok = ask_permission("Allow forward to path %s", chost);
		} ଅନ୍ୟଥା {
			ok = ask_permission("Allow forward to [%s]:%d? ",
			    chost, cport);
		}
		ଯଦି (!ok) {
			debug2_f("stdio fwd refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ଯାଅ cleanup;
		}
	}

	nc = channel_connect_stdio_fwd(ssh, chost, cport, new_fd[0], new_fd[1],
	    CHANNEL_NONBLOCK_STDIO);
	ମୁକ୍ତ(chost);

	nc->ctl_chan = c->self;		/* link session -> control channel */
	c->ctl_child_id = nc->self;	/* link control -> session channel */
	c->have_ctl_child_id = 1;

	debug2_f("channel_new: %d control %d", nc->self, nc->ctl_chan);

	channel_register_cleanup(ssh, nc->self,
	    mux_master_session_cleanup_cb, 1);

	cctx = xcalloc(1, ଆକାର(*cctx));
	cctx->rid = rid;
	channel_register_open_confirm(ssh, nc->self, mux_stdio_confirm, cctx);
	c->mux_pause = 1; /* stop handling messages until open_confirm done */

	/* reply is deferred, sent by mux_session_confirm */
	ଫେରନ୍ତୁ 0;
}

/* Callback on open confirmation in mux master for a mux stdio fwd session. */
ସ୍ଥିର ଶୂନ୍ୟ
mux_stdio_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, ଶୂନ୍ୟ *arg)
{
	ସଂରଚନା mux_stdio_confirm_ctx *cctx = arg;
	Channel *c, *cc;
	ସଂରଚନା sshbuf *reply;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (cctx == ଖାଲି)
		fatal_f("cctx == NULL");
	ଯଦି ((c = channel_by_id(ssh, id)) == ଖାଲି)
		fatal_f("no channel for id %d", id);
	ଯଦି ((cc = channel_by_id(ssh, c->ctl_chan)) == ଖାଲି)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ଯଦି ((reply = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");

	ଯଦି (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		/* prepare reply */
		ଯାଅ done;
	}

	debug3_f("sending success reply");
	/* prepare reply */
	ଯଦି ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ଯଦି ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ଯଦି (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ଖାଲି;
	ମୁକ୍ତ(cctx);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_stop_listening(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	debug_f("channel %d: stop listening", c->self);

	ଯଦି (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ଯଦି (!ask_permission("Disable further multiplexing on shared "
		    "connection to %s? ", host)) {
			debug2_f("stop listen refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ଫେରନ୍ତୁ 0;
		}
	}

	ଯଦି (mux_listener_channel != ଖାଲି) {
		channel_free(ssh, mux_listener_channel);
		client_stop_mux();
		ମୁକ୍ତ(options.control_path);
		options.control_path = ଖାଲି;
		mux_listener_channel = ଖାଲି;
		muxserver_sock = -1;
	}

	reply_ok(reply, rid);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_process_proxy(ସଂରଚନା ssh *ssh, u_int rid,
    Channel *c, ସଂରଚନା sshbuf *m, ସଂରଚନା sshbuf *reply)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug_f("channel %d: proxy request", c->self);

	ଯଦି (options.control_master == SSHCTL_MASTER_ASK ||
	    options.control_master == SSHCTL_MASTER_AUTO_ASK) {
		ଯଦି (!ask_permission("Allow multiplex proxy connection?")) {
			debug2_f("proxy refused by user");
			reply_error(reply, MUX_S_PERMISSION_DENIED, rid,
			    "Permission denied");
			ଫେରନ୍ତୁ 0;
		}
	}

	c->mux_rcb = channel_proxy_downstream;
	ଯଦି ((r = sshbuf_put_u32(reply, MUX_S_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(reply, rid)) != 0)
		fatal_fr(r, "reply");

	ଫେରନ୍ତୁ 0;
}

/* Channel callbacks fired on read/write from mux client fd */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_master_read_cb(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା mux_master_state *state = (ସଂରଚନା mux_master_state *)c->mux_ctx;
	ସଂରଚନା sshbuf *in = ଖାଲି, *out = ଖାଲି;
	u_int type, rid, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;

	ଯଦି ((out = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");

	/* Setup ctx and  */
	ଯଦି (c->mux_ctx == ଖାଲି) {
		state = xcalloc(1, ଆକାର(*state));
		c->mux_ctx = state;
		channel_register_cleanup(ssh, c->self,
		    mux_master_control_cleanup_cb, 0);

		/* Send hello */
		ଯଦି ((r = sshbuf_put_u32(out, MUX_ସନ୍ଦେଶ_HELLO)) != 0 ||
		    (r = sshbuf_put_u32(out, SSHMUX_VER)) != 0)
			fatal_fr(r, "reply");
		/* "info" extension */
		ଯଦି ((r = sshbuf_put_cstring(out, "info")) != 0 ||
		    (r = sshbuf_put_cstring(out, "0")) != 0)
			fatal_fr(r, "put info extension");
		ଯଦି ((r = sshbuf_put_stringb(c->output, out)) != 0)
			fatal_fr(r, "enqueue");
		debug3_f("channel %d: hello sent", c->self);
		ret = 0;
		ଯାଅ out;
	}

	/* Channel code ensures that we receive whole packets */
	ଯଦି ((r = sshbuf_froms(c->ନିବେଶ, &in)) != 0) {
 malf:
		error_f("malformed message");
		ଯାଅ out;
	}

	ଯଦି ((r = sshbuf_get_u32(in, &type)) != 0)
		ଯାଅ malf;
	debug3_f("channel %d packet type 0x%08x len %zu", c->self,
	    type, sshbuf_len(in));

	ଯଦି (type == MUX_ସନ୍ଦେଶ_HELLO)
		rid = 0;
	ଅନ୍ୟଥା {
		ଯଦି (!state->hello_rcvd) {
			error_f("expected MUX_MSG_HELLO(0x%08x), "
			    "received 0x%08x", MUX_ସନ୍ଦେଶ_HELLO, type);
			ଯାଅ out;
		}
		ଯଦି ((r = sshbuf_get_u32(in, &rid)) != 0)
			ଯାଅ malf;
	}

	ପାଇଁ (i = 0; mux_master_handlers[i].handler != ଖାଲି; i++) {
		ଯଦି (type == mux_master_handlers[i].type) {
			ret = mux_master_handlers[i].handler(ssh, rid,
			    c, in, out);
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (mux_master_handlers[i].handler == ଖାଲି) {
		error_f("unsupported mux message 0x%08x", type);
		reply_error(out, MUX_S_FAILURE, rid, "unsupported request");
		ret = 0;
	}
	/* Enqueue reply packet */
	ଯଦି (sshbuf_len(out) != 0 &&
	    (r = sshbuf_put_stringb(c->output, out)) != 0)
		fatal_fr(r, "enqueue");
 out:
	sshbuf_free(in);
	sshbuf_free(out);
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
mux_exit_message(ସଂରଚନା ssh *ssh, Channel *c, ପୂର୍ଣ୍ଣସଂଖ୍ୟା exitval)
{
	ସଂରଚନା sshbuf *m;
	Channel *mux_chan;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("channel %d: exit message, exitval %d", c->self, exitval);

	ଯଦି ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ଖାଲି)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_S_EXIT_MESSAGE)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_u32(m, exitval)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

ଶୂନ୍ୟ
mux_tty_alloc_failed(ସଂରଚନା ssh *ssh, Channel *c)
{
	ସଂରଚନା sshbuf *m;
	Channel *mux_chan;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("channel %d: TTY alloc failed", c->self);

	ଯଦି ((mux_chan = channel_by_id(ssh, c->ctl_chan)) == ଖାଲି)
		fatal_f("channel %d missing mux %d", c->self, c->ctl_chan);

	/* Append exit message packet to control socket output queue */
	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_S_TTY_ALLOC_FAIL)) != 0 ||
	    (r = sshbuf_put_u32(m, c->self)) != 0 ||
	    (r = sshbuf_put_stringb(mux_chan->output, m)) != 0)
		fatal_fr(r, "reply");
	sshbuf_free(m);
}

/* Prepare a mux master to listen on a Unix domain socket. */
ଶୂନ୍ୟ
muxserver_listen(ସଂରଚନା ssh *ssh)
{
	mode_t old_umask;
	ଅକ୍ଷର *orig_control_path = options.control_path;
	ଅକ୍ଷର rbuf[16+1];
	u_int i, r;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno;

	ଯଦି (options.control_path == ଖାଲି ||
	    options.control_master == SSHCTL_MASTER_NO)
		ଫେରନ୍ତୁ;

	debug("setting up multiplex master socket");

	/*
	 * Use a temporary path before listen so we can pseudo-atomically
	 * establish the listening socket in its final location to avoid
	 * other processes racing in between bind() and listen() and hitting
	 * an unready socket.
	 */
	ପାଇଁ (i = 0; i < ଆକାର(rbuf) - 1; i++) {
		r = arc4random_uniform(26+26+10);
		rbuf[i] = (r < 26) ? 'a' + r :
		    (r < 26*2) ? 'A' + r - 26 :
		    '0' + r - 26 - 26;
	}
	rbuf[ଆକାର(rbuf) - 1] = '\0';
	options.control_path = ଖାଲି;
	xasprintf(&options.control_path, "%s.%s", orig_control_path, rbuf);
	debug3_f("temporary control path %s", options.control_path);

	old_umask = umask(0177);
	muxserver_sock = unix_listener(options.control_path, 64, 0);
	oerrno = errno;
	umask(old_umask);
	ଯଦି (muxserver_sock < 0) {
		ଯଦି (oerrno == EINVAL || oerrno == EADDRINUSE) {
			error("ControlSocket %s already exists, "
			    "disabling multiplexing", options.control_path);
 disable_mux_master:
			ଯଦି (muxserver_sock != -1) {
				close(muxserver_sock);
				muxserver_sock = -1;
			}
			ମୁକ୍ତ(orig_control_path);
			ମୁକ୍ତ(options.control_path);
			options.control_path = ଖାଲି;
			options.control_master = SSHCTL_MASTER_NO;
			ଫେରନ୍ତୁ;
		} ଅନ୍ୟଥା {
			/* unix_listener() logs the error */
			cleanup_exit(255);
		}
	}

	/* Now atomically "move" the mux socket into position */
	ଯଦି (link(options.control_path, orig_control_path) != 0) {
		ଯଦି (errno != EEXIST) {
			fatal_f("link mux listener %s => %s: %s",
			    options.control_path, orig_control_path,
			    strerror(errno));
		}
		error("ControlSocket %s already exists, disabling multiplexing",
		    orig_control_path);
		unlink(options.control_path);
		ଯାଅ disable_mux_master;
	}
	unlink(options.control_path);
	ମୁକ୍ତ(options.control_path);
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
ସ୍ଥିର ଶୂନ୍ୟ
mux_session_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, ଶୂନ୍ୟ *arg)
{
	ସଂରଚନା mux_session_confirm_ctx *cctx = arg;
	ଅଚଳ ଅକ୍ଷର *display;
	Channel *c, *cc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r;
	ସଂରଚନା sshbuf *reply;

	ଯଦି (cctx == ଖାଲି)
		fatal_f("cctx == NULL");
	ଯଦି ((c = channel_by_id(ssh, id)) == ଖାଲି)
		fatal_f("no channel for id %d", id);
	ଯଦି ((cc = channel_by_id(ssh, c->ctl_chan)) == ଖାଲି)
		fatal_f("channel %d lacks control channel %d",
		    id, c->ctl_chan);
	ଯଦି ((reply = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");

	ଯଦି (!success) {
		debug3_f("sending failure reply");
		reply_error(reply, MUX_S_FAILURE, cctx->rid,
		    "Session open refused by peer");
		ଯାଅ done;
	}

	display = getenv("DISPLAY");
	ଯଦି (cctx->want_x_fwd && options.forward_x11 && display != ଖାଲି) {
		ଅକ୍ଷର *proto, *data;

		/* Get reasonable local authentication information. */
		ଯଦି (client_x11_get_proto(ssh, display, options.xauth_location,
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

	ଯଦି (cctx->want_agent_fwd && options.forward_agent)
		client_channel_request_agent_forwarding(ssh, id);

	client_session2_setup(ssh, id, cctx->want_tty, cctx->want_subsys,
	    cctx->term, &cctx->tio, c->rfd, cctx->cmd, cctx->env);

	debug3_f("sending success reply");
	/* prepare reply */
	ଯଦି ((r = sshbuf_put_u32(reply, MUX_S_SESSION_OPENED)) != 0 ||
	    (r = sshbuf_put_u32(reply, cctx->rid)) != 0 ||
	    (r = sshbuf_put_u32(reply, c->self)) != 0)
		fatal_fr(r, "reply");

 done:
	/* Send reply */
	ଯଦି ((r = sshbuf_put_stringb(cc->output, reply)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(reply);

	ଯଦି (cc->mux_pause <= 0)
		fatal_f("mux_pause %d", cc->mux_pause);
	cc->mux_pause = 0; /* start processing messages again */
	c->open_confirm_ctx = ଖାଲି;
	sshbuf_free(cctx->cmd);
	ମୁକ୍ତ(cctx->term);
	ଯଦି (cctx->env != ଖାଲି) {
		ପାଇଁ (i = 0; cctx->env[i] != ଖାଲି; i++)
			ମୁକ୍ତ(cctx->env[i]);
		ମୁକ୍ତ(cctx->env);
	}
	ମୁକ୍ତ(cctx);
}

/* ** Multiplexing client support */

/* Exit signal handler */
ସ୍ଥିର ଶୂନ୍ୟ
control_client_sighandler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	muxclient_terminate = signo;
}

/*
 * Relay signal handler - used to pass some signals from mux client to
 * mux master.
 */
ସ୍ଥିର ଶୂନ୍ୟ
control_client_sigrelay(ପୂର୍ଣ୍ଣସଂଖ୍ୟା signo)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା save_errno = errno;

	ଯଦି (muxserver_pid > 1)
		kill(muxserver_pid, signo);

	errno = save_errno;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_read(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *b, size_t need, ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout_ms)
{
	size_t have;
	ssize_t len;
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_reserve(b, need, &p)) != 0)
		fatal_fr(r, "reserve");
	ପାଇଁ (have = 0; have < need; ) {
		ଯଦି (muxclient_terminate) {
			errno = EINTR;
			ଫେରନ୍ତୁ -1;
		}
		len = ପଠ(fd, p + have, need - have);
		ଯଦି (len == -1) {
			ବାଛ (errno) {
#ଯଦି defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ସ୍ଥିତି EWOULDBLOCK:
#endif
			ସ୍ଥିତି EAGAIN:
				ଯଦି (waitrfd(fd, &timeout_ms,
				    &muxclient_terminate) == -1 &&
				    errno != EINTR)
					ଫେରନ୍ତୁ -1;	/* timeout */
				/* FALLTHROUGH */
			ସ୍ଥିତି EINTR:
				ଜାରି;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				ଫେରନ୍ତୁ -1;
			}
		}
		ଯଦି (len == 0) {
			errno = EPIPE;
			ଫେରନ୍ତୁ -1;
		}
		have += (size_t)len;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_write_packet(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *m)
{
	ସଂରଚନା sshbuf *queue;
	u_int have, need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, oerrno, len;
	ଅଚଳ u_char *ptr;
	ସଂରଚନା pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ଯଦି ((queue = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_stringb(queue, m)) != 0)
		fatal_fr(r, "enqueue");

	need = sshbuf_len(queue);
	ptr = sshbuf_ptr(queue);

	ପାଇଁ (have = 0; have < need; ) {
		ଯଦି (muxclient_terminate) {
			sshbuf_free(queue);
			errno = EINTR;
			ଫେରନ୍ତୁ -1;
		}
		len = ଲିଖ(fd, ptr + have, need - have);
		ଯଦି (len == -1) {
			ବାଛ (errno) {
#ଯଦି defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
			ସ୍ଥିତି EWOULDBLOCK:
#endif
			ସ୍ଥିତି EAGAIN:
				(ଶୂନ୍ୟ)poll(&pfd, 1, -1);
				/* FALLTHROUGH */
			ସ୍ଥିତି EINTR:
				ଜାରି;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				oerrno = errno;
				sshbuf_free(queue);
				errno = oerrno;
				ଫେରନ୍ତୁ -1;
			}
		}
		ଯଦି (len == 0) {
			sshbuf_free(queue);
			errno = EPIPE;
			ଫେରନ୍ତୁ -1;
		}
		have += (u_int)len;
	}
	sshbuf_free(queue);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_read_packet_timeout(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *m, ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout_ms)
{
	ସଂରଚନା sshbuf *queue;
	size_t need, have;
	ଅଚଳ u_char *ptr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, oerrno;

	ଯଦି ((queue = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି (mux_client_read(fd, queue, 4, timeout_ms) != 0) {
		ଯଦି ((oerrno = errno) == EPIPE)
			debug3_f("read header failed: %s",
			    strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ଫେରନ୍ତୁ -1;
	}
	need = PEEK_U32(sshbuf_ptr(queue));
	ଯଦି (mux_client_read(fd, queue, need, timeout_ms) != 0) {
		oerrno = errno;
		debug3_f("read body failed: %s", strerror(errno));
		sshbuf_free(queue);
		errno = oerrno;
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((r = sshbuf_get_string_direct(queue, &ptr, &have)) != 0 ||
	    (r = sshbuf_put(m, ptr, have)) != 0)
		fatal_fr(r, "dequeue");
	sshbuf_free(queue);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_read_packet(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *m)
{
	ଫେରନ୍ତୁ mux_client_read_packet_timeout(fd, m, -1);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_hello_exchange(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout_ms)
{
	ସଂରଚନା sshbuf *m;
	u_int type, ver;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_ସନ୍ଦେଶ_HELLO)) != 0 ||
	    (r = sshbuf_put_u32(m, SSHMUX_VER)) != 0)
		fatal_fr(r, "assemble hello");
	/* no extensions */

	ଯଦି (mux_client_write_packet(fd, m) != 0) {
		debug_f("write packet: %s", strerror(errno));
		ଯାଅ out;
	}

	sshbuf_reset(m);

	/* Read their HELLO */
	ଯଦି (mux_client_read_packet_timeout(fd, m, timeout_ms) != 0) {
		debug_f("read packet failed");
		ଯାଅ out;
	}

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ଯଦି (type != MUX_ସନ୍ଦେଶ_HELLO) {
		error_f("expected HELLO (%u) got %u", MUX_ସନ୍ଦେଶ_HELLO, type);
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_u32(m, &ver)) != 0)
		fatal_fr(r, "parse version");
	ଯଦି (ver != SSHMUX_VER) {
		error("Unsupported multiplexing protocol version %d "
		    "(expected %d)", ver, SSHMUX_VER);
		ଯାଅ out;
	}
	debug2_f("master version %u", ver);
	/* No extensions are presently defined */
	ଯେତେବେଳେ (sshbuf_len(m) > 0) {
		ଅକ୍ଷର *name = ଖାଲି;

		ଯଦି ((r = sshbuf_get_cstring(m, &name, ଖାଲି)) != 0 ||
		    (r = sshbuf_skip_string(m)) != 0) { /*ମୂଲ୍ୟ*/
			error_fr(r, "parse extension");
			ଯାଅ out;
		}
		/* Process extensions. */
		ଯଦି (strcmp(name, "info") == 0) {
			debug("Received 'info' extension");
			extensions |= MUX_EXT_INFO;
		} ଅନ୍ୟଥା {
			debug2("Unrecognised master extension \"%s\"", name);
		}
		ମୁକ୍ତ(name);
	}
	/* success */
	ret = 0;
 out:
	sshbuf_free(m);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର u_int
mux_client_request_alive(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e;
	u_int pid, type, rid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_C_ALIVE_CHECK)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "assemble");

	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ଯଦି (type != MUX_S_ALIVE) {
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ଯଦି ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ଯଦି ((r = sshbuf_get_u32(m, &pid)) != 0)
		fatal_fr(r, "parse PID");
	sshbuf_free(m);

	debug3_f("done pid = %u", pid);

	muxclient_request_id++;

	ଫେରନ୍ତୁ pid;
}

ସ୍ଥିର ଅକ୍ଷର *
mux_client_request_info(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e, *ସନ୍ଦେଶ;
	u_int type, rid, status;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_C_EXT_INFO)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_cstring(m, name)) != 0)
		fatal_fr(r, "assemble");

	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ଫେରନ୍ତୁ 0;
	}

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0)
		fatal_fr(r, "parse type");
	ଯଦି (type != MUX_S_EXT_INFO) {
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}

	ଯଦି ((r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse remote ID");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ଯଦି ((r = sshbuf_get_u32(m, &status)) != 0 ||
	    (r = sshbuf_get_cstring(m, &ସନ୍ଦେଶ, ଖାଲି)) != 0)
		fatal_fr(r, "parse connection info");
	sshbuf_free(m);

	muxclient_request_id++;

	ଫେରନ୍ତୁ ସନ୍ଦେଶ;
}

ସ୍ଥିର ଶୂନ୍ୟ
mux_client_request_terminate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e;
	u_int type, rid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_C_TERMINATE)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		/* Remote end exited already */
		ଯଦି (errno == EPIPE) {
			sshbuf_free(m);
			ଫେରନ୍ତୁ;
		}
		fatal_f("read from master failed: %s", strerror(errno));
	}

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ବାଛ (type) {
	ସ୍ଥିତି MUX_S_OK:
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_S_PERMISSION_DENIED:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused termination request: %s", e);
	ସ୍ଥିତି MUX_S_FAILURE:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("termination request failed: %s", e);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_forward(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cancel_flag, u_int ftype, ସଂରଚନା Forward *fwd)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e, *fwd_desc;
	ଅଚଳ ଅକ୍ଷର *lhost, *chost;
	u_int type, rid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	fwd_desc = format_forward(ftype, fwd);
	debug("Requesting %s %s",
	    cancel_flag ? "cancellation of" : "forwarding of", fwd_desc);
	ମୁକ୍ତ(fwd_desc);

	type = cancel_flag ? MUX_C_CLOSE_FWD : MUX_C_OPEN_FWD;
	ଯଦି (fwd->listen_path != ଖାଲି)
		lhost = fwd->listen_path;
	ଅନ୍ୟଥା ଯଦି (fwd->listen_host == ଖାଲି)
		lhost = "";
	ଅନ୍ୟଥା ଯଦି (*fwd->listen_host == '\0')
		lhost = "*";
	ଅନ୍ୟଥା
		lhost = fwd->listen_host;

	ଯଦି (fwd->connect_path != ଖାଲି)
		chost = fwd->connect_path;
	ଅନ୍ୟଥା ଯଦି (fwd->connect_host == ଖାଲି)
		chost = "";
	ଅନ୍ୟଥା
		chost = fwd->connect_host;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, type)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_u32(m, ftype)) != 0 ||
	    (r = sshbuf_put_cstring(m, lhost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->listen_port)) != 0 ||
	    (r = sshbuf_put_cstring(m, chost)) != 0 ||
	    (r = sshbuf_put_u32(m, fwd->connect_port)) != 0)
		fatal_fr(r, "request");

	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ବାଛ (type) {
	ସ୍ଥିତି MUX_S_OK:
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_S_REMOTE_PORT:
		ଯଦି (cancel_flag)
			fatal_f("got MUX_S_REMOTE_PORT for cancel");
		ଯଦି ((r = sshbuf_get_u32(m, &fwd->allocated_port)) != 0)
			fatal_fr(r, "parse port");
		verbose("Allocated port %u for remote forward to %s:%d",
		    fwd->allocated_port,
		    fwd->connect_host ? fwd->connect_host : "",
		    fwd->connect_port);
		ଯଦି (muxclient_command == SSHMUX_COMMAND_FORWARD)
			fprintf(stdout, "%i\n", fwd->allocated_port);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_S_PERMISSION_DENIED:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error("Master refused forwarding request: %s", e);
		ଫେରନ୍ତୁ -1;
	ସ୍ଥିତି MUX_S_FAILURE:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		error_f("forwarding request failed: %s", e);
		ଫେରନ୍ତୁ -1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);

	muxclient_request_id++;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_forwards(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cancel_flag)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, ret = 0;

	debug3_f("%s forwardings: %d local, %d remote",
	    cancel_flag ? "cancel" : "request",
	    options.ଅଙ୍କ_local_forwards, options.ଅଙ୍କ_remote_forwards);

	/* XXX ExitOnForwardingFailure */
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_local_forwards; i++) {
		ଯଦି (mux_client_forward(fd, cancel_flag,
		    options.local_forwards[i].connect_port == 0 ?
		    MUX_FWD_DYNAMIC : MUX_FWD_LOCAL,
		    options.local_forwards + i) != 0)
			ret = -1;
	}
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_remote_forwards; i++) {
		ଯଦି (mux_client_forward(fd, cancel_flag, MUX_FWD_REMOTE,
		    options.remote_forwards + i) != 0)
			ret = -1;
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_request_session(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e;
	ଅଚଳ ଅକ୍ଷର *term = ଖାଲି;
	u_int i, echar, rid, sid, esid, exitval, type, exitval_seen;
	ବାହ୍ୟ ଅକ୍ଷର **environ;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, rawmode = 0;

	debug3_f("entering");

	ଯଦି ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ଫେରନ୍ତୁ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ଯଦି (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ଯଦି ((term = lookup_env_in_list("TERM", options.setenv,
	    options.ଅଙ୍କ_setenv)) == ଖାଲି || *term == '\0')
		term = getenv("TERM");

	echar = 0xffffffff;
	ଯଦି (options.escape_char != SSH_ESCAPECHAR_NONE)
	    echar = (u_int)options.escape_char;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_C_NEW_SESSION)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ଖାଲି, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_u32(m, tty_flag)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_x11)) != 0 ||
	    (r = sshbuf_put_u32(m, options.forward_agent)) != 0 ||
	    (r = sshbuf_put_u32(m, options.session_type == SESSION_TYPE_SUBSYSTEM)) != 0 ||
	    (r = sshbuf_put_u32(m, echar)) != 0 ||
	    (r = sshbuf_put_cstring(m, term == ଖାଲି ? "" : term)) != 0 ||
	    (r = sshbuf_put_stringb(m, command)) != 0)
		fatal_fr(r, "request");

	/* Pass environment */
	ଯଦି (options.ଅଙ୍କ_send_env > 0 && environ != ଖାଲି) {
		ପାଇଁ (i = 0; environ[i] != ଖାଲି; i++) {
			ଯଦି (!env_permitted(environ[i]))
				ଜାରି;
			ଯଦି ((r = sshbuf_put_cstring(m, environ[i])) != 0)
				fatal_fr(r, "request sendenv");
		}
	}
	ପାଇଁ (i = 0; i < options.ଅଙ୍କ_setenv; i++) {
		ଯଦି ((r = sshbuf_put_cstring(m, options.setenv[i])) != 0)
			fatal_fr(r, "request setenv");
	}

	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ଯଦି (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1 ||
	    mm_send_fd(fd, STDERR_FILENO) == -1)
		fatal_f("send fds failed");

	debug3_f("session request sent");

	/* Read their reply */
	sshbuf_reset(m);
	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ବାଛ (type) {
	ସ୍ଥିତି MUX_S_SESSION_OPENED:
		ଯଦି ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_S_PERMISSION_DENIED:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		error("Master refused session request: %s", e);
		sshbuf_free(m);
		ଫେରନ୍ତୁ -1;
	ସ୍ଥିତି MUX_S_FAILURE:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		error_f("session request failed: %s", e);
		sshbuf_free(m);
		ଫେରନ୍ତୁ -1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ଫେରନ୍ତୁ -1;
	}
	muxclient_request_id++;

	ଯଦି (pledge("stdio proc tty", ଖାଲି) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	ssh_signal(SIGHUP, control_client_sighandler);
	ssh_signal(SIGINT, control_client_sighandler);
	ssh_signal(SIGTERM, control_client_sighandler);
	ssh_signal(SIGWINCH, control_client_sigrelay);

	ଯଦି (options.fork_after_authentication)
		daemon(1, 1);
	ଅନ୍ୟଥା {
		rawmode = tty_flag;
		ଯଦି (tty_flag) {
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
	ପାଇଁ (exitval = 255, exitval_seen = 0;;) {
		sshbuf_reset(m);
		ଯଦି (mux_client_read_packet(fd, m) != 0)
			ଭାଙ୍ଗ;
		ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0)
			fatal_fr(r, "parse type");
		ବାଛ (type) {
		ସ୍ଥିତି MUX_S_TTY_ALLOC_FAIL:
			ଯଦି ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ଯଦି (esid != sid)
				fatal_f("tty alloc fail on unknown session: "
				    "my id %u theirs %u", sid, esid);
			leave_raw_mode(options.request_tty ==
			    REQUEST_TTY_FORCE);
			rawmode = 0;
			ଜାରି;
		ସ୍ଥିତି MUX_S_EXIT_MESSAGE:
			ଯଦି ((r = sshbuf_get_u32(m, &esid)) != 0)
				fatal_fr(r, "parse session ID");
			ଯଦି (esid != sid)
				fatal_f("exit on unknown session: "
				    "my id %u theirs %u", sid, esid);
			ଯଦି (exitval_seen)
				fatal_f("exitval sent twice");
			ଯଦି ((r = sshbuf_get_u32(m, &exitval)) != 0)
				fatal_fr(r, "parse exitval");
			exitval_seen = 1;
			ଜାରି;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
				fatal_fr(r, "parse error message");
			fatal_f("master returned error: %s", e);
		}
	}

	close(fd);
	ଯଦି (rawmode)
		leave_raw_mode(options.request_tty == REQUEST_TTY_FORCE);

	ଯଦି (muxclient_terminate) {
		debug2("Exiting on signal: %s", strsignal(muxclient_terminate));
		exitval = 255;
	} ଅନ୍ୟଥା ଯଦି (!exitval_seen) {
		debug2("Control master terminated unexpectedly");
		exitval = 255;
	} ଅନ୍ୟଥା
		debug2("Received exit status from master %d", exitval);

	ଯଦି (tty_flag && options.log_level >= SYSLOG_LEVEL_INFO)
		fprintf(stderr, "Shared connection to %s closed.\r\n", host);

	exit(exitval);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_proxy(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e;
	u_int type, rid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_C_PROXY)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");
	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		sshbuf_free(m);
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ଯଦି (type != MUX_S_PROXY) {
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("master returned error: %s", e);
	}
	sshbuf_free(m);

	debug3_f("done");
	muxclient_request_id++;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mux_client_request_stdio_fwd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e;
	u_int type, rid, sid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((muxserver_pid = mux_client_request_alive(fd)) == 0) {
		error_f("master alive request failed");
		ଫେରନ୍ତୁ -1;
	}

	ssh_signal(SIGPIPE, SIG_IGN);

	ଯଦି (options.stdin_null && stdfd_devnull(1, 0, 0) == -1)
		fatal_f("stdfd_devnull failed");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_C_NEW_STDIO_FWD)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0 ||
	    (r = sshbuf_put_string(m, ଖାଲି, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(m, options.stdio_forward_host)) != 0 ||
	    (r = sshbuf_put_u32(m, options.stdio_forward_port)) != 0)
		fatal_fr(r, "request");

	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	/* Send the stdio file descriptors */
	ଯଦି (mm_send_fd(fd, STDIN_FILENO) == -1 ||
	    mm_send_fd(fd, STDOUT_FILENO) == -1)
		fatal_f("send fds failed");

	ଯଦି (pledge("stdio proc tty", ଖାଲି) == -1)
		fatal_f("pledge(): %s", strerror(errno));
	platform_pledge_mux();

	debug3_f("stdio forward request sent");

	/* Read their reply */
	sshbuf_reset(m);

	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		error_f("read from master failed: %s", strerror(errno));
		sshbuf_free(m);
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);
	ବାଛ (type) {
	ସ୍ଥିତି MUX_S_SESSION_OPENED:
		ଯଦି ((r = sshbuf_get_u32(m, &sid)) != 0)
			fatal_fr(r, "parse session ID");
		debug_f("master session id: %u", sid);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_S_PERMISSION_DENIED:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Master refused stdio forwarding request: %s", e);
	ସ୍ଥିତି MUX_S_FAILURE:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		sshbuf_free(m);
		fatal("Stdio forwarding request failed: %s", e);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		sshbuf_free(m);
		error_f("unexpected response from master 0x%08x", type);
		ଫେରନ୍ତୁ -1;
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
	ଯଦି (mux_client_read_packet(fd, m) != 0) {
		ଯଦି (errno == EPIPE ||
		    (errno == EINTR && muxclient_terminate != 0)) {
			sshbuf_free(m);
			ଫେରନ୍ତୁ 0;
		}
		fatal_f("mux_client_read_packet: %s", strerror(errno));
	}
	fatal_f("master returned unexpected message %u", type);
}

ସ୍ଥିର ଶୂନ୍ୟ
mux_client_request_stop_listening(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ସଂରଚନା sshbuf *m;
	ଅକ୍ଷର *e;
	u_int type, rid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("entering");

	ଯଦି ((m = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new");
	ଯଦି ((r = sshbuf_put_u32(m, MUX_C_STOP_LISTENING)) != 0 ||
	    (r = sshbuf_put_u32(m, muxclient_request_id)) != 0)
		fatal_fr(r, "request");

	ଯଦି (mux_client_write_packet(fd, m) != 0)
		fatal_f("write packet: %s", strerror(errno));

	sshbuf_reset(m);

	/* Read their reply */
	ଯଦି (mux_client_read_packet(fd, m) != 0)
		fatal_f("read from master failed: %s", strerror(errno));

	ଯଦି ((r = sshbuf_get_u32(m, &type)) != 0 ||
	    (r = sshbuf_get_u32(m, &rid)) != 0)
		fatal_fr(r, "parse");
	ଯଦି (rid != muxclient_request_id)
		fatal_f("out of sequence reply: my id %u theirs %u",
		    muxclient_request_id, rid);

	ବାଛ (type) {
	ସ୍ଥିତି MUX_S_OK:
		ଭାଙ୍ଗ;
	ସ୍ଥିତି MUX_S_PERMISSION_DENIED:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		fatal("Master refused stop listening request: %s", e);
	ସ୍ଥିତି MUX_S_FAILURE:
		ଯଦି ((r = sshbuf_get_cstring(m, &e, ଖାଲି)) != 0)
			fatal_fr(r, "parse error message");
		fatal_f("stop listening request failed: %s", e);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal_f("unexpected response from master 0x%08x", type);
	}
	sshbuf_free(m);
	muxclient_request_id++;
}

/* Multiplex client main loop. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
muxclient(ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା sockaddr_un addr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sock, timeout = options.connection_timeout, timeout_ms = -1;
	u_int pid;
	ଅକ୍ଷର *info = ଖାଲି;

	ଯଦି (muxclient_command == 0) {
		ଯଦି (options.stdio_forward_host != ଖାଲି)
			muxclient_command = SSHMUX_COMMAND_STDIO_FWD;
		ଅନ୍ୟଥା
			muxclient_command = SSHMUX_COMMAND_OPEN;
	}

	ବାଛ (options.control_master) {
	ସ୍ଥିତି SSHCTL_MASTER_AUTO:
	ସ୍ଥିତି SSHCTL_MASTER_AUTO_ASK:
		debug("auto-mux: Trying existing master at '%s'", path);
		/* FALLTHROUGH */
	ସ୍ଥିତି SSHCTL_MASTER_NO:
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}

	memset(&addr, '\0', ଆକାର(addr));
	addr.sun_family = AF_UNIX;

	ଯଦି (strlcpy(addr.sun_path, path,
	    ଆକାର(addr.sun_path)) >= ଆକାର(addr.sun_path))
		fatal("ControlPath too long ('%s' >= %u bytes)", path,
		    (unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ଆକାର(addr.sun_path));

	ଯଦି ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
		fatal_f("socket(): %s", strerror(errno));

	ଯଦି (connect(sock, (ସଂରଚନା sockaddr *)&addr, ଆକାର(addr)) == -1) {
		ବାଛ (muxclient_command) {
		ସ୍ଥିତି SSHMUX_COMMAND_OPEN:
		ସ୍ଥିତି SSHMUX_COMMAND_STDIO_FWD:
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		ଯଦି (errno == ECONNREFUSED &&
		    options.control_master != SSHCTL_MASTER_NO) {
			debug("Stale control socket %.100s, unlinking", path);
			unlink(path);
		} ଅନ୍ୟଥା ଯଦି (errno == ENOENT) {
			debug("Control socket \"%.100s\" does not exist", path);
		} ଅନ୍ୟଥା {
			error("Control socket connect(%.100s): %s", path,
			    strerror(errno));
		}
		close(sock);
		ଫେରନ୍ତୁ -1;
	}
	set_nonblock(sock);

	/* Timeout on initial connection only. */
	ଯଦି (timeout > 0 && timeout < INT_MAX / 1000)
		timeout_ms = timeout * 1000;

	ଯଦି (mux_client_hello_exchange(sock, timeout_ms) != 0) {
		error_f("master hello exchange failed");
		close(sock);
		ଫେରନ୍ତୁ -1;
	}

	ବାଛ (muxclient_command) {
	ସ୍ଥିତି SSHMUX_COMMAND_ALIVE_CHECK:
		ଯଦି ((pid = mux_client_request_alive(sock)) == 0)
			fatal_f("master alive check failed");
		fprintf(stderr, "Master running (pid=%u)\r\n", pid);
		exit(0);
	ସ୍ଥିତି SSHMUX_COMMAND_CONNINFO:
	ସ୍ଥିତି SSHMUX_COMMAND_CHANINFO:
		ଯଦି (!(extensions & MUX_EXT_INFO))
			fatal("mux server does not support info request");
		info = mux_client_request_info(sock,
		    muxclient_command == SSHMUX_COMMAND_CONNINFO ?
		    "connection" : "channels");
		ଯଦି (info == ଖାଲି)
			fatal_f("info request failed");
		printf("%s", info);
		exit(0);
	ସ୍ଥିତି SSHMUX_COMMAND_TERMINATE:
		mux_client_request_terminate(sock);
		ଯଦି (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Exit request sent.\r\n");
		exit(0);
	ସ୍ଥିତି SSHMUX_COMMAND_FORWARD:
		ଯଦି (mux_client_forwards(sock, 0) != 0)
			fatal_f("master forward request failed");
		exit(0);
	ସ୍ଥିତି SSHMUX_COMMAND_OPEN:
		ଯଦି (mux_client_forwards(sock, 0) != 0) {
			error_f("master forward request failed");
			ଫେରନ୍ତୁ -1;
		}
		mux_client_request_session(sock);
		ଫେରନ୍ତୁ -1;
	ସ୍ଥିତି SSHMUX_COMMAND_STDIO_FWD:
		mux_client_request_stdio_fwd(sock);
		exit(0);
	ସ୍ଥିତି SSHMUX_COMMAND_STOP:
		mux_client_request_stop_listening(sock);
		ଯଦି (options.log_level != SYSLOG_LEVEL_QUIET)
			fprintf(stderr, "Stop listening request sent.\r\n");
		exit(0);
	ସ୍ଥିତି SSHMUX_COMMAND_CANCEL_FWD:
		ଯଦି (mux_client_forwards(sock, 1) != 0)
			error_f("master cancel forward request failed");
		exit(0);
	ସ୍ଥିତି SSHMUX_COMMAND_PROXY:
		mux_client_proxy(sock);
		ଫେରନ୍ତୁ (sock);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		fatal("unrecognised muxclient_command %d", muxclient_command);
	}
}
