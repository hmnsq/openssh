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

#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"

/* Externs that mux.c declares. */
ਪੂਰਨ tty_flag = 0;
Options options;
ਅੱਖਰ *host = ਨਿਰਾ;
ਬਣਤਰ sshbuf *command = ਨਿਰਾ;
ਅਸਥਿਰ sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
ਪੂਰਨ
__lsan_is_turned_off(ਖਾਲੀ)
{
	ਵਾਪਸ 1;
}

ਸਥਿਰ jmp_buf fuzz_env;
ਸਥਿਰ ਅਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_fuzz = 0;

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

ਖਾਲੀ
__wrap_ssh_packet_disconnect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)fmt;
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ਪੂਰਨ
__wrap_sshpkt_fatal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)fmt;
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
ਪੂਰਨ
__wrap_ask_permission(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	(ਖਾਲੀ)fmt;
	ਵਾਪਸ 1;
}

/* Socket-opening side effects we must neutralise. */
ਪੂਰਨ
__wrap_channel_setup_local_fwd_listener(ਬਣਤਰ ssh *ssh,
    ਬਣਤਰ Forward *fwd, ਬਣਤਰ ForwardOptions *fwd_opts)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)fwd; (ਖਾਲੀ)fwd_opts;
	ਵਾਪਸ 1;
}

ਪੂਰਨ
__wrap_channel_connect_stdio_fwd(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *host_arg,
    ਪੂਰਨ ਪੋਰਟ, ਪੂਰਨ ਵਿੱਚ_fd, ਪੂਰਨ ਬਾਹਰਲਾ_fd, ਪੂਰਨ nonblock)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)host_arg; (ਖਾਲੀ)ਪੋਰਟ;
	(ਖਾਲੀ)ਵਿੱਚ_fd; (ਖਾਲੀ)ਬਾਹਰਲਾ_fd; (ਖਾਲੀ)nonblock;
	ਵਾਪਸ -1;
}

ਪੂਰਨ
__wrap_channel_request_remote_forwarding(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)fwd;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
__wrap_channel_request_rforward_cancel(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)fwd;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
__wrap_channel_cancel_lport_listener(ਬਣਤਰ ssh *ssh, ਬਣਤਰ Forward *fwd,
    ਪੂਰਨ cport, ਬਣਤਰ ForwardOptions *fwd_opts)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)fwd; (ਖਾਲੀ)cport; (ਖਾਲੀ)fwd_opts;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *str)
{
	ਬਣਤਰ sshbuf *b = sshbuf_from(str, ਲੜੀ_ਲੰਬਾਈ(str));
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਜੇ (b == ਨਿਰਾ || sshkey_parse_ਨਿੱਜੀ_fileblob(b, "", &k, ਨਿਰਾ) != 0)
		abort();
	sshbuf_free(b);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *str)
{
	ਅੱਖਰ *tmp, *cp;
	ਬਣਤਰ sshkey *k = sshkey_new(ਕੁੰਜੀ_UNSPEC);
	ਜੇ (k == ਨਿਰਾ)
		abort();
	tmp = cp = strdup(str);
	ਜੇ (sshkey_read(k, &cp) != 0)
		abort();
	ਮੁਕਤ(tmp);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਪੂਰਨ
pump(ਬਣਤਰ ssh *from, ਬਣਤਰ ssh *ਮੰਜ਼ਿਲ, ਮਾਪ_t *transferred)
{
	ਅਚਲ u_char *buf;
	ਮਾਪ_t len;
	u_char type;
	ਪੂਰਨ r;
	*transferred = 0;
	ਜੇ ((r = ssh_packet_ਅਗਲਾ(from, &type)) != 0)
		ਵਾਪਸ r;
	buf = ssh_output_ptr(from, &len);
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ ((r = ssh_ਨਿਵੇਸ਼_append(ਮੰਜ਼ਿਲ, buf, len)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = ssh_output_consume(from, len)) != 0)
		ਵਾਪਸ r;
	*transferred = len;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਲੜੀਵਾਰ_kex(ਬਣਤਰ ssh *client, ਬਣਤਰ ssh *server)
{
	ਪੂਰਨ r;
	ਮਾਪ_t cn, sn;
	ਲਈ (ਪੂਰਨ i = 0; i < 100; i++) {
		ਜੇ ((r = pump(server, client, &sn)) != 0) ਵਾਪਸ r;
		ਜੇ ((r = pump(client, server, &cn)) != 0) ਵਾਪਸ r;
		ਜੇ (server->kex->ਪੂਰਾ && client->kex->ਪੂਰਾ)
			ਵਾਪਸ 0;
		ਜੇ (cn == 0 && sn == 0)
			ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
	}
	ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
}

#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
ਸਥਿਰ ਪੂਰਨ mux_master_read_cb(ਬਣਤਰ ssh *ssh, Channel *c);

#ਅਨ੍ਤਰ੍ਭਾਵ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
ਖਾਲੀ *
client_new_escape_filter_ctx(ਪੂਰਨ escape_char)
{
	(ਖਾਲੀ)escape_char;
	ਵਾਪਸ ਨਿਰਾ;
}

ਖਾਲੀ
client_ਰਜਿਸਟਰ_global_confirm(global_confirm_cb *cb, ਖਾਲੀ *ctx)
{
	(ਖਾਲੀ)cb; (ਖਾਲੀ)ctx;
}

ਖਾਲੀ
client_expect_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਅਚਲ ਅੱਖਰ *reason,
    ਗਿਣਤੀ confirm_action action)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)id; (ਖਾਲੀ)reason; (ਖਾਲੀ)action;
}

ਖਾਲੀ
client_channel_request_agent_forwarding(ਬਣਤਰ ssh *ssh, ਪੂਰਨ chanid)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)chanid;
}

ਖਾਲੀ
client_stop_mux(ਖਾਲੀ)
{
}

ਪੂਰਨ
client_simple_escape_filter(ਬਣਤਰ ssh *ssh, Channel *c, ਅੱਖਰ *buf, ਪੂਰਨ len)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)c; (ਖਾਲੀ)buf; (ਖਾਲੀ)len;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
client_filter_cleanup(ਬਣਤਰ ssh *ssh, ਪੂਰਨ cid, ਖਾਲੀ *ctx)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)cid; (ਖਾਲੀ)ctx;
}

ਪੂਰਨ
client_x11_get_proto(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *display,
    ਅਚਲ ਅੱਖਰ *xauth_ਰਸਤਾ, u_int trusted, u_int timeout,
    ਅੱਖਰ **_proto, ਅੱਖਰ **ਅੰਕੜੇ_2)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)display; (ਖਾਲੀ)xauth_ਰਸਤਾ;
	(ਖਾਲੀ)trusted; (ਖਾਲੀ)timeout;
	ਜੇ (_proto != ਨਿਰਾ)
		*_proto = ਨਿਰਾ;
	ਜੇ (ਅੰਕੜੇ_2 != ਨਿਰਾ)
		*ਅੰਕੜੇ_2 = ਨਿਰਾ;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
client_session2_ਤਿਆਰੀ(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ want_tty, ਪੂਰਨ want_subsys,
    ਅਚਲ ਅੱਖਰ *ਪਦ, ਬਣਤਰ termios *tiop, ਪੂਰਨ ਵਿੱਚ_fd, ਬਣਤਰ sshbuf *cmd,
    ਅੱਖਰ **env)
{
	(ਖਾਲੀ)ssh; (ਖਾਲੀ)id; (ਖਾਲੀ)want_tty; (ਖਾਲੀ)want_subsys;
	(ਖਾਲੀ)ਪਦ; (ਖਾਲੀ)tiop; (ਖਾਲੀ)ਵਿੱਚ_fd; (ਖਾਲੀ)cmd; (ਖਾਲੀ)env;
}

ਖਾਲੀ
enter_raw_ਬਹੁਲਕ(ਪੂਰਨ quiet)
{
	(ਖਾਲੀ)quiet;
}

ਖਾਲੀ
leave_raw_ਬਹੁਲਕ(ਪੂਰਨ quiet)
{
	(ਖਾਲੀ)quiet;
}

ਸਥਿਰ ਬਣਤਰ ssh *g_client = ਨਿਰਾ;
ਸਥਿਰ ਬਣਤਰ ssh *g_server = ਨਿਰਾ;
ਸਥਿਰ ਪੂਰਨ g_init = 0;
ਸਥਿਰ ਪੂਰਨ g_mux_channel_id = -1;
ਸਥਿਰ ਬਣਤਰ sshbuf *g_mux_ਵਿੱਚ = ਨਿਰਾ;
ਸਥਿਰ ਬਣਤਰ sshbuf *g_mux_ਬਾਹਰਲਾ = ਨਿਰਾ;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
ਸਥਿਰ ਖਾਲੀ
fuzz_drive_mux(ਬਣਤਰ ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	ਪੂਰਨ r;
	ਅਚਲ u_char *body;
	ਮਾਪ_t blen;
	ਬਣਤਰ mux_master_state *state;

	state = (ਬਣਤਰ mux_master_state *)c->mux_ctx;
	ਜੇ (state == ਨਿਰਾ)
		ਵਾਪਸ;

	sshbuf_reset(g_mux_ਵਿੱਚ);
	sshbuf_reset(g_mux_ਬਾਹਰਲਾ);

	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(c->ਨਿਵੇਸ਼, &body, &blen)) != 0)
		ਵਾਪਸ;
	ਜੇ (sshbuf_put(g_mux_ਵਿੱਚ, body, blen) != 0)
		ਵਾਪਸ;
	ਜੇ ((r = sshbuf_get_u32(g_mux_ਵਿੱਚ, &type)) != 0)
		ਵਾਪਸ;

	ਜੇ (type == MUX_ਸੁਨੇਹਾ_HELLO) {
		rid = 0;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (!state->hello_rcvd)
			ਵਾਪਸ;
		ਜੇ ((r = sshbuf_get_u32(g_mux_ਵਿੱਚ, &rid)) != 0)
			ਵਾਪਸ;
	}

	ਲਈ (i = 0; mux_master_handlers[i].handler != ਨਿਰਾ; i++) {
		ਜੇ (type == mux_master_handlers[i].type) {
			(ਖਾਲੀ)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_ਵਿੱਚ, g_mux_ਬਾਹਰਲਾ);
			ਰੋਕੋ;
		}
	}
}

ਸਥਿਰ ਪੂਰਨ
init_once(ਖਾਲੀ)
{
	ਜੇ (g_init)
		ਵਾਪਸ 0;
	ਸੰਕੇਤ(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, ਆਕਾਰ(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_ਰਸਤਾ = (ਅੱਖਰ *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_ਨਕਾਬ = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (ਅੱਖਰ *)"fuzz";

	ਬਣਤਰ sshkey *priv = ਲੱਦੋ_ਨਿੱਜੀ(PRIV_ED25519);
	ਬਣਤਰ sshkey *pub = ਲੱਦੋ_ਜਨਤਕ(PUB_ED25519);
	ਅੱਖਰ *keyname = xstrdup(sshkey_ssh_name(priv));

	ਅਚਲ ਅੱਖਰ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅੱਖਰ *proposal[PROPOSAL_MAX] = { 0 };
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਅਚਲ ਅੱਖਰ *p = defaults[i];
		ਜੇ (i == PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS)
			p = keyname;
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ਬਣਤਰ kex_params kp;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(kp.proposal, proposal, ਆਕਾਰ(proposal));

	ਜੇ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ssh_ਜੋੜੋ_hostkey(g_server, priv) != 0 ||
	    ssh_ਜੋੜੋ_hostkey(g_client, pub) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ਲੜੀਵਾਰ_kex(g_client, g_server) != 0)
		ਵਾਪਸ -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	ਜੇ (c == ਨਿਰਾ)
		ਵਾਪਸ -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	ਬਣਤਰ mux_master_state *st = (ਬਣਤਰ mux_master_state *)c->mux_ctx;
	ਜੇ (st != ਨਿਰਾ)
		st->hello_rcvd = 1;

	ਜੇ ((g_mux_ਵਿੱਚ = sshbuf_new()) == ਨਿਰਾ ||
	    (g_mux_ਬਾਹਰਲਾ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ -1;

	ਮੁਕਤ(keyname);
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(proposal[i]);
	g_init = 1;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
fuzz_mux_one(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (init_once() != 0)
		ਵਾਪਸ;
	ਜੇ (ਮਾਪ > 65000)
		ਵਾਪਸ;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	ਜੇ (c == ਨਿਰਾ || c->mux_ctx == ਨਿਰਾ || c->ਨਿਵੇਸ਼ == ਨਿਰਾ)
		ਵਾਪਸ;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->ਨਿਵੇਸ਼);
	u_char hdr[4];
	hdr[0] = (u_char)(ਮਾਪ >> 24);
	hdr[1] = (u_char)(ਮਾਪ >> 16);
	hdr[2] = (u_char)(ਮਾਪ >> 8);
	hdr[3] = (u_char)ਮਾਪ;
	ਜੇ (sshbuf_put(c->ਨਿਵੇਸ਼, hdr, 4) != 0)
		ਵਾਪਸ;
	ਜੇ (ਮਾਪ > 0 && sshbuf_put(c->ਨਿਵੇਸ਼, ਅੰਕੜੇ, ਮਾਪ) != 0)
		ਵਾਪਸ;

	ਵਿੱਚ_fuzz = 1;
	ਜੇ (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	ਵਿੱਚ_fuzz = 0;

	/* Drain anything the handler enqueued. */
	ਜੇ (c->output != ਨਿਰਾ)
		sshbuf_reset(c->output);
}
