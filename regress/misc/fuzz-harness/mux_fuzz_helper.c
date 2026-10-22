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
ಪೂರ್ಣಾಂಕ tty_flag = 0;
Options options;
ಅಕ್ಷರ *host = ಖಾಲಿ;
ರಚನೆ sshbuf *command = ಖಾಲಿ;
ಅಸ್ಥಿರ sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
ಪೂರ್ಣಾಂಕ
__lsan_is_turned_off(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಅಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳ_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ ಸಂಕೇತ_2)
{
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, ಸಂಕೇತ_2 ? ಸಂಕೇತ_2 : 1);
	_exit(ಸಂಕೇತ_2);
}

ಶೂನ್ಯ
__wrap_ssh_packet_disconnect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ಪೂರ್ಣಾಂಕ
__wrap_sshpkt_fatal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
ಪೂರ್ಣಾಂಕ
__wrap_ask_permission(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	(ಶೂನ್ಯ)fmt;
	ಹಿಂತಿರುಗಿ 1;
}

/* Socket-opening side effects we must neutralise. */
ಪೂರ್ಣಾಂಕ
__wrap_channel_setup_local_fwd_listener(ರಚನೆ ssh *ssh,
    ರಚನೆ Forward *fwd, ರಚನೆ ForwardOptions *fwd_opts)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd; (ಶೂನ್ಯ)fwd_opts;
	ಹಿಂತಿರುಗಿ 1;
}

ಪೂರ್ಣಾಂಕ
__wrap_channel_connect_stdio_fwd(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_arg,
    ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್, ಪೂರ್ಣಾಂಕ ಒಳ_fd, ಪೂರ್ಣಾಂಕ ಹೊರಹೋಗು_fd, ಪೂರ್ಣಾಂಕ nonblock)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)host_arg; (ಶೂನ್ಯ)ಪೋರ್ಟ್;
	(ಶೂನ್ಯ)ಒಳ_fd; (ಶೂನ್ಯ)ಹೊರಹೋಗು_fd; (ಶೂನ್ಯ)nonblock;
	ಹಿಂತಿರುಗಿ -1;
}

ಪೂರ್ಣಾಂಕ
__wrap_channel_request_remote_forwarding(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
__wrap_channel_request_rforward_cancel(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
__wrap_channel_cancel_lport_listener(ರಚನೆ ssh *ssh, ರಚನೆ Forward *fwd,
    ಪೂರ್ಣಾಂಕ cport, ರಚನೆ ForwardOptions *fwd_opts)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)fwd; (ಶೂನ್ಯ)cport; (ಶೂನ್ಯ)fwd_opts;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ರಚನೆ sshbuf *b = sshbuf_from(str, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(str));
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಆದರೆ (b == ಖಾಲಿ || sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &k, ಖಾಲಿ) != 0)
		abort();
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಆದರೆ (k == ಖಾಲಿ)
		abort();
	tmp = cp = strdup(str);
	ಆದರೆ (sshkey_read(k, &cp) != 0)
		abort();
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pump(ರಚನೆ ssh *from, ರಚನೆ ssh *ಗಮ್ಯ, ಗಾತ್ರ_t *transferred)
{
	ಸ್ಥಿರಾಂಕ u_char *buf;
	ಗಾತ್ರ_t len;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;
	*transferred = 0;
	ಆದರೆ ((r = ssh_packet_ಮುಂದಿನ(from, &type)) != 0)
		ಹಿಂತಿರುಗಿ r;
	buf = ssh_output_ptr(from, &len);
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = ssh_ಒಳಹರಿವು_append(ಗಮ್ಯ, buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = ssh_output_consume(from, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	*transferred = len;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಸತತ_kex(ರಚನೆ ssh *client, ರಚನೆ ssh *server)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t cn, sn;
	ಗಾಗಿ (ಪೂರ್ಣಾಂಕ i = 0; i < 100; i++) {
		ಆದರೆ ((r = pump(server, client, &sn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((r = pump(client, server, &cn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (server->kex->ಮುಗಿದ && client->kex->ಮುಗಿದ)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (cn == 0 && sn == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
}

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ mux_master_read_cb(ರಚನೆ ssh *ssh, Channel *c);

#ಅನ್ತರ್ಭಾವ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
ಶೂನ್ಯ *
client_new_escape_filter_ctx(ಪೂರ್ಣಾಂಕ escape_char)
{
	(ಶೂನ್ಯ)escape_char;
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಶೂನ್ಯ
client_ರಿಜಿಸ್ಟರ್_global_confirm(global_confirm_cb *cb, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)cb; (ಶೂನ್ಯ)ctx;
}

ಶೂನ್ಯ
client_expect_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason,
    ಎಣಿಕೆ confirm_action action)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)id; (ಶೂನ್ಯ)reason; (ಶೂನ್ಯ)action;
}

ಶೂನ್ಯ
client_channel_request_agent_forwarding(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ chanid)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)chanid;
}

ಶೂನ್ಯ
client_stop_mux(ಶೂನ್ಯ)
{
}

ಪೂರ್ಣಾಂಕ
client_simple_escape_filter(ರಚನೆ ssh *ssh, Channel *c, ಅಕ್ಷರ *buf, ಪೂರ್ಣಾಂಕ len)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)c; (ಶೂನ್ಯ)buf; (ಶೂನ್ಯ)len;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
client_filter_cleanup(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ cid, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)cid; (ಶೂನ್ಯ)ctx;
}

ಪೂರ್ಣಾಂಕ
client_x11_get_proto(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *display,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *xauth_ಮಾರ್ಗ, u_int trusted, u_int timeout,
    ಅಕ್ಷರ **_proto, ಅಕ್ಷರ **ದತ್ತಾಂಶ_2)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)display; (ಶೂನ್ಯ)xauth_ಮಾರ್ಗ;
	(ಶೂನ್ಯ)trusted; (ಶೂನ್ಯ)timeout;
	ಆದರೆ (_proto != ಖಾಲಿ)
		*_proto = ಖಾಲಿ;
	ಆದರೆ (ದತ್ತಾಂಶ_2 != ಖಾಲಿ)
		*ದತ್ತಾಂಶ_2 = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
client_session2_ಸಿದ್ಧತೆ(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ want_tty, ಪೂರ್ಣಾಂಕ want_subsys,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಪದ, ರಚನೆ termios *tiop, ಪೂರ್ಣಾಂಕ ಒಳ_fd, ರಚನೆ sshbuf *cmd,
    ಅಕ್ಷರ **env)
{
	(ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)id; (ಶೂನ್ಯ)want_tty; (ಶೂನ್ಯ)want_subsys;
	(ಶೂನ್ಯ)ಪದ; (ಶೂನ್ಯ)tiop; (ಶೂನ್ಯ)ಒಳ_fd; (ಶೂನ್ಯ)cmd; (ಶೂನ್ಯ)env;
}

ಶೂನ್ಯ
enter_raw_ಬಹುಲಕ(ಪೂರ್ಣಾಂಕ quiet)
{
	(ಶೂನ್ಯ)quiet;
}

ಶೂನ್ಯ
leave_raw_ಬಹುಲಕ(ಪೂರ್ಣಾಂಕ quiet)
{
	(ಶೂನ್ಯ)quiet;
}

ಸ್ಥಿರ ರಚನೆ ssh *g_client = ಖಾಲಿ;
ಸ್ಥಿರ ರಚನೆ ssh *g_server = ಖಾಲಿ;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_init = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_mux_channel_id = -1;
ಸ್ಥಿರ ರಚನೆ sshbuf *g_mux_ಒಳ = ಖಾಲಿ;
ಸ್ಥಿರ ರಚನೆ sshbuf *g_mux_ಹೊರಹೋಗು = ಖಾಲಿ;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
ಸ್ಥಿರ ಶೂನ್ಯ
fuzz_drive_mux(ರಚನೆ ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ u_char *body;
	ಗಾತ್ರ_t blen;
	ರಚನೆ mux_master_state *state;

	state = (ರಚನೆ mux_master_state *)c->mux_ctx;
	ಆದರೆ (state == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	sshbuf_reset(g_mux_ಒಳ);
	sshbuf_reset(g_mux_ಹೊರಹೋಗು);

	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(c->ಒಳಹರಿವು, &body, &blen)) != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (sshbuf_put(g_mux_ಒಳ, body, blen) != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ ((r = sshbuf_get_u32(g_mux_ಒಳ, &type)) != 0)
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ (type == MUX_ಸಂದೇಶ_HELLO) {
		rid = 0;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (!state->hello_rcvd)
			ಹಿಂತಿರುಗಿ;
		ಆದರೆ ((r = sshbuf_get_u32(g_mux_ಒಳ, &rid)) != 0)
			ಹಿಂತಿರುಗಿ;
	}

	ಗಾಗಿ (i = 0; mux_master_handlers[i].handler != ಖಾಲಿ; i++) {
		ಆದರೆ (type == mux_master_handlers[i].type) {
			(ಶೂನ್ಯ)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_ಒಳ, g_mux_ಹೊರಹೋಗು);
			ನಿಲ್ಲಿಸು;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
init_once(ಶೂನ್ಯ)
{
	ಆದರೆ (g_init)
		ಹಿಂತಿರುಗಿ 0;
	ಸಂಕೇತ(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, ಗಾತ್ರ(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_ಮಾರ್ಗ = (ಅಕ್ಷರ *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_ಮುಖವಾಡ = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (ಅಕ್ಷರ *)"fuzz";

	ರಚನೆ sshkey *priv = ತುಂಬು_ಖಾಸಗಿ(PRIV_ED25519);
	ರಚನೆ sshkey *pub = ತುಂಬು_ಬಹಿರಂಗ(PUB_ED25519);
	ಅಕ್ಷರ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p = defaults[i];
		ಆದರೆ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ರಚನೆ kex_params kp;
	ಸ್ಮರಣೆ_ನಕಲು(kp.proposal, proposal, ಗಾತ್ರ(proposal));

	ಆದರೆ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ssh_ಕೂಡಿಸು_hostkey(g_server, priv) != 0 ||
	    ssh_ಕೂಡಿಸು_hostkey(g_client, pub) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ಸತತ_kex(g_client, g_server) != 0)
		ಹಿಂತಿರುಗಿ -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	ಆದರೆ (c == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	ರಚನೆ mux_master_state *st = (ರಚನೆ mux_master_state *)c->mux_ctx;
	ಆದರೆ (st != ಖಾಲಿ)
		st->hello_rcvd = 1;

	ಆದರೆ ((g_mux_ಒಳ = sshbuf_new()) == ಖಾಲಿ ||
	    (g_mux_ಹೊರಹೋಗು = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	ಬಿಡುಗಡೆ(keyname);
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(proposal[i]);
	g_init = 1;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
fuzz_mux_one(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (init_once() != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಗಾತ್ರ_2 > 65000)
		ಹಿಂತಿರುಗಿ;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	ಆದರೆ (c == ಖಾಲಿ || c->mux_ctx == ಖಾಲಿ || c->ಒಳಹರಿವು == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->ಒಳಹರಿವು);
	u_char hdr[4];
	hdr[0] = (u_char)(ಗಾತ್ರ_2 >> 24);
	hdr[1] = (u_char)(ಗಾತ್ರ_2 >> 16);
	hdr[2] = (u_char)(ಗಾತ್ರ_2 >> 8);
	hdr[3] = (u_char)ಗಾತ್ರ_2;
	ಆದರೆ (sshbuf_put(c->ಒಳಹರಿವು, hdr, 4) != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಗಾತ್ರ_2 > 0 && sshbuf_put(c->ಒಳಹರಿವು, ದತ್ತಾಂಶ, ಗಾತ್ರ_2) != 0)
		ಹಿಂತಿರುಗಿ;

	ಒಳ_fuzz = 1;
	ಆದರೆ (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	ಒಳ_fuzz = 0;

	/* Drain anything the handler enqueued. */
	ಆದರೆ (c->output != ಖಾಲಿ)
		sshbuf_reset(c->output);
}
