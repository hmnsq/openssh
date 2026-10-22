/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"

/* Externs that mux.c declares. */
ಪೂರ್ಣಾಙ್ಕ tty_flag = 0;
Options options;
ವರ್ಣ *host = ರಿಕ್ತ;
ಸಂರಚನಾ sshbuf *command = ರಿಕ್ತ;
ಚಞ್ಚಲ sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
ಪೂರ್ಣಾಙ್ಕ
__lsan_is_turned_off(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಚಞ್ಚಲ ಪೂರ್ಣಾಙ್ಕ in_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ code)
{
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ಶೂನ್ಯ
__wrap_ssh_packet_disconnect(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_sshpkt_fatal(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ r, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
ಪೂರ್ಣಾಙ್ಕ
__wrap_ask_permission(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	(ಶೂನ್ಯ)fmt;
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* Socket-opening side effects we must neutralise. */
ಪೂರ್ಣಾಙ್ಕ
__wrap_channel_setup_local_fwd_listener(ಸಂರಚನಾ ssh *ssh,
    ಸಂರಚನಾ Forward *fwd, ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd; (ಶೂನ್ಯ)fwd_opts;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_channel_connect_stdio_fwd(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *host_arg,
    ಪೂರ್ಣಾಙ್ಕ port, ಪೂರ್ಣಾಙ್ಕ in_fd, ಪೂರ್ಣಾಙ್ಕ out_fd, ಪೂರ್ಣಾಙ್ಕ nonblock)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)host_arg; (ಶೂನ್ಯ)port;
	(ಶೂನ್ಯ)in_fd; (ಶೂನ್ಯ)out_fd; (ಶೂನ್ಯ)nonblock;
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_channel_request_remote_forwarding(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_channel_request_rforward_cancel(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_channel_cancel_lport_listener(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ Forward *fwd,
    ಪೂರ್ಣಾಙ್ಕ cport, ಸಂರಚನಾ ForwardOptions *fwd_opts)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd; (ಶೂನ್ಯ)cport; (ಶೂನ್ಯ)fwd_opts;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_private(ಧ್ರುವ ವರ್ಣ *str)
{
	ಸಂರಚನಾ sshbuf *b = sshbuf_from(str, strlen(str));
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಯದಿ (b == ರಿಕ್ತ || sshkey_parse_private_fileblob(b, "", &k, ರಿಕ್ತ) != 0)
		abort();
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_public(ಧ್ರುವ ವರ್ಣ *str)
{
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಯದಿ (k == ರಿಕ್ತ)
		abort();
	tmp = cp = strdup(str);
	ಯದಿ (sshkey_read(k, &cp) != 0)
		abort();
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pump(ಸಂರಚನಾ ssh *from, ಸಂರಚನಾ ssh *to, size_t *transferred)
{
	ಧ್ರುವ u_char *buf;
	size_t len;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;
	*transferred = 0;
	ಯದಿ ((r = ssh_packet_next(from, &type)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	buf = ssh_output_ptr(from, &len);
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = ssh_ಒಳಹರಿವು_append(to, buf, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = ssh_output_consume(from, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	*transferred = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
run_kex(ಸಂರಚನಾ ssh *client, ಸಂರಚನಾ ssh *server)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t cn, sn;
	ಪ್ರತಿ (ಪೂರ್ಣಾಙ್ಕ i = 0; i < 100; i++) {
		ಯದಿ ((r = pump(server, client, &sn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((r = pump(client, server, &cn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (server->kex->done && client->kex->done)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ (cn == 0 && sn == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
}

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ mux_master_read_cb(ಸಂರಚನಾ ssh *ssh, Channel *c);

#ಅನ್ತರ್ಭಾವ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
ಶೂನ್ಯ *
client_new_escape_filter_ctx(ಪೂರ್ಣಾಙ್ಕ escape_char)
{
	(ಶೂನ್ಯ)escape_char;
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಶೂನ್ಯ
client_register_global_confirm(global_confirm_cb *cb, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)cb; (ಶೂನ್ಯ)ctx;
}

ಶೂನ್ಯ
client_expect_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಧ್ರುವ ವರ್ಣ *reason,
    ಗಣನಾ confirm_action action)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)id; (ಶೂನ್ಯ)reason; (ಶೂನ್ಯ)action;
}

ಶೂನ್ಯ
client_channel_request_agent_forwarding(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ chanid)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)chanid;
}

ಶೂನ್ಯ
client_stop_mux(ಶೂನ್ಯ)
{
}

ಪೂರ್ಣಾಙ್ಕ
client_simple_escape_filter(ಸಂರಚನಾ ssh *ssh, Channel *c, ವರ್ಣ *buf, ಪೂರ್ಣಾಙ್ಕ len)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)c; (ಶೂನ್ಯ)buf; (ಶೂನ್ಯ)len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
client_filter_cleanup(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ cid, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)cid; (ಶೂನ್ಯ)ctx;
}

ಪೂರ್ಣಾಙ್ಕ
client_x11_get_proto(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *display,
    ಧ್ರುವ ವರ್ಣ *xauth_path, u_int trusted, u_int timeout,
    ವರ್ಣ **_proto, ವರ್ಣ **_data)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)display; (ಶೂನ್ಯ)xauth_path;
	(ಶೂನ್ಯ)trusted; (ಶೂನ್ಯ)timeout;
	ಯದಿ (_proto != ರಿಕ್ತ)
		*_proto = ರಿಕ್ತ;
	ಯದಿ (_data != ರಿಕ್ತ)
		*_data = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
client_session2_setup(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ want_tty, ಪೂರ್ಣಾಙ್ಕ want_subsys,
    ಧ್ರುವ ವರ್ಣ *term, ಸಂರಚನಾ termios *tiop, ಪೂರ್ಣಾಙ್ಕ in_fd, ಸಂರಚನಾ sshbuf *cmd,
    ವರ್ಣ **env)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)id; (ಶೂನ್ಯ)want_tty; (ಶೂನ್ಯ)want_subsys;
	(ಶೂನ್ಯ)term; (ಶೂನ್ಯ)tiop; (ಶೂನ್ಯ)in_fd; (ಶೂನ್ಯ)cmd; (ಶೂನ್ಯ)env;
}

ಶೂನ್ಯ
enter_raw_mode(ಪೂರ್ಣಾಙ್ಕ quiet)
{
	(ಶೂನ್ಯ)quiet;
}

ಶೂನ್ಯ
leave_raw_mode(ಪೂರ್ಣಾಙ್ಕ quiet)
{
	(ಶೂನ್ಯ)quiet;
}

ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_client = ರಿಕ್ತ;
ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_server = ರಿಕ್ತ;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_init = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_mux_channel_id = -1;
ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *g_mux_in = ರಿಕ್ತ;
ಸ್ಥಿರ ಸಂರಚನಾ sshbuf *g_mux_out = ರಿಕ್ತ;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_drive_mux(ಸಂರಚನಾ ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ u_char *body;
	size_t blen;
	ಸಂರಚನಾ mux_master_state *state;

	state = (ಸಂರಚನಾ mux_master_state *)c->mux_ctx;
	ಯದಿ (state == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	ಯದಿ ((r = sshbuf_get_string_direct(c->ಒಳಹರಿವು, &body, &blen)) != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (sshbuf_put(g_mux_in, body, blen) != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ (type == MUX_ಸಂದೇಶ_HELLO) {
		rid = 0;
	} ಅನ್ಯಥಾ {
		ಯದಿ (!state->hello_rcvd)
			ಪ್ರತ್ಯಾಗಮ;
		ಯದಿ ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			ಪ್ರತ್ಯಾಗಮ;
	}

	ಪ್ರತಿ (i = 0; mux_master_handlers[i].handler != ರಿಕ್ತ; i++) {
		ಯದಿ (type == mux_master_handlers[i].type) {
			(ಶೂನ್ಯ)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			ಭಙ್ಗ;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
init_once(ಶೂನ್ಯ)
{
	ಯದಿ (g_init)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸಙ್ಕೇತ(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, ಪರಿಮಾಣ(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (ವರ್ಣ *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (ವರ್ಣ *)"fuzz";

	ಸಂರಚನಾ sshkey *priv = load_private(PRIV_ED25519);
	ಸಂರಚನಾ sshkey *pub = load_public(PUB_ED25519);
	ವರ್ಣ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಧ್ರುವ ವರ್ಣ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಧ್ರುವ ವರ್ಣ *p = defaults[i];
		ಯದಿ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ಸಂರಚನಾ kex_params kp;
	memcpy(kp.proposal, proposal, ಪರಿಮಾಣ(proposal));

	ಯದಿ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (run_kex(g_client, g_server) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	ಯದಿ (c == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	ಸಂರಚನಾ mux_master_state *st = (ಸಂರಚನಾ mux_master_state *)c->mux_ctx;
	ಯದಿ (st != ರಿಕ್ತ)
		st->hello_rcvd = 1;

	ಯದಿ ((g_mux_in = sshbuf_new()) == ರಿಕ್ತ ||
	    (g_mux_out = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	ಮುಕ್ತ(keyname);
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(proposal[i]);
	g_init = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
fuzz_mux_one(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (init_once() != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (size > 65000)
		ಪ್ರತ್ಯಾಗಮ;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	ಯದಿ (c == ರಿಕ್ತ || c->mux_ctx == ರಿಕ್ತ || c->ಒಳಹರಿವು == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->ಒಳಹರಿವು);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	ಯದಿ (sshbuf_put(c->ಒಳಹರಿವು, hdr, 4) != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (size > 0 && sshbuf_put(c->ಒಳಹರಿವು, data, size) != 0)
		ಪ್ರತ್ಯಾಗಮ;

	in_fuzz = 1;
	ಯದಿ (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	ಯದಿ (c->output != ರಿಕ್ತ)
		sshbuf_reset(c->output);
}
