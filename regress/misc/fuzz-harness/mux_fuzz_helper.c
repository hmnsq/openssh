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

#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "readconf.h"

/* Externs that mux.c declares. */
പൂർണ്ണസംഖ്യ tty_flag = 0;
Options options;
അക്ഷരം *host = ശൂന്യ;
ഘടന sshbuf *command = ശൂന്യ;
അസ്ഥിര sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
പൂർണ്ണസംഖ്യ
__lsan_is_turned_off(ശൂന്യം)
{
	തിരികെ 1;
}

സ്ഥിതം jmp_buf fuzz_env;
സ്ഥിതം അസ്ഥിര പൂർണ്ണസംഖ്യ in_fuzz = 0;

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ശൂന്യം
__wrap_ssh_packet_disconnect(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)fmt;
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

പൂർണ്ണസംഖ്യ
__wrap_sshpkt_fatal(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ r, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)fmt;
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
പൂർണ്ണസംഖ്യ
__wrap_ask_permission(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	(ശൂന്യം)fmt;
	തിരികെ 1;
}

/* Socket-opening side effects we must neutralise. */
പൂർണ്ണസംഖ്യ
__wrap_channel_setup_local_fwd_listener(ഘടന ssh *ssh,
    ഘടന Forward *fwd, ഘടന ForwardOptions *fwd_opts)
{
	(ശൂന്യം)ssh; (ശൂന്യം)fwd; (ശൂന്യം)fwd_opts;
	തിരികെ 1;
}

പൂർണ്ണസംഖ്യ
__wrap_channel_connect_stdio_fwd(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *host_arg,
    പൂർണ്ണസംഖ്യ port, പൂർണ്ണസംഖ്യ in_fd, പൂർണ്ണസംഖ്യ out_fd, പൂർണ്ണസംഖ്യ nonblock)
{
	(ശൂന്യം)ssh; (ശൂന്യം)host_arg; (ശൂന്യം)port;
	(ശൂന്യം)in_fd; (ശൂന്യം)out_fd; (ശൂന്യം)nonblock;
	തിരികെ -1;
}

പൂർണ്ണസംഖ്യ
__wrap_channel_request_remote_forwarding(ഘടന ssh *ssh, ഘടന Forward *fwd)
{
	(ശൂന്യം)ssh; (ശൂന്യം)fwd;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
__wrap_channel_request_rforward_cancel(ഘടന ssh *ssh, ഘടന Forward *fwd)
{
	(ശൂന്യം)ssh; (ശൂന്യം)fwd;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
__wrap_channel_cancel_lport_listener(ഘടന ssh *ssh, ഘടന Forward *fwd,
    പൂർണ്ണസംഖ്യ cport, ഘടന ForwardOptions *fwd_opts)
{
	(ശൂന്യം)ssh; (ശൂന്യം)fwd; (ശൂന്യം)cport; (ശൂന്യം)fwd_opts;
	തിരികെ 0;
}

സ്ഥിതം ഘടന sshkey *
load_private(സ്ഥിരം അക്ഷരം *str)
{
	ഘടന sshbuf *b = sshbuf_from(str, strlen(str));
	ഘടന sshkey *k = ശൂന്യ;
	എങ്കിൽ (b == ശൂന്യ || sshkey_parse_private_fileblob(b, "", &k, ശൂന്യ) != 0)
		abort();
	sshbuf_free(b);
	തിരികെ k;
}

സ്ഥിതം ഘടന sshkey *
load_public(സ്ഥിരം അക്ഷരം *str)
{
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *k = sshkey_new(താക്കോൽ_UNSPEC);
	എങ്കിൽ (k == ശൂന്യ)
		abort();
	tmp = cp = strdup(str);
	എങ്കിൽ (sshkey_read(k, &cp) != 0)
		abort();
	സ്വതന്ത്രം(tmp);
	തിരികെ k;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pump(ഘടന ssh *from, ഘടന ssh *to, size_t *transferred)
{
	സ്ഥിരം u_char *buf;
	size_t len;
	u_char type;
	പൂർണ്ണസംഖ്യ r;
	*transferred = 0;
	എങ്കിൽ ((r = ssh_packet_next(from, &type)) != 0)
		തിരികെ r;
	buf = ssh_output_ptr(from, &len);
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ ((r = ssh_നിവേശം_append(to, buf, len)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = ssh_output_consume(from, len)) != 0)
		തിരികെ r;
	*transferred = len;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
run_kex(ഘടന ssh *client, ഘടന ssh *server)
{
	പൂർണ്ണസംഖ്യ r;
	size_t cn, sn;
	വേണ്ടി (പൂർണ്ണസംഖ്യ i = 0; i < 100; i++) {
		എങ്കിൽ ((r = pump(server, client, &sn)) != 0) തിരികെ r;
		എങ്കിൽ ((r = pump(client, server, &cn)) != 0) തിരികെ r;
		എങ്കിൽ (server->kex->done && client->kex->done)
			തിരികെ 0;
		എങ്കിൽ (cn == 0 && sn == 0)
			തിരികെ SSH_ERR_PROTOCOL_ERROR;
	}
	തിരികെ SSH_ERR_PROTOCOL_ERROR;
}

#അന്തര്ഭാവ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
സ്ഥിതം പൂർണ്ണസംഖ്യ mux_master_read_cb(ഘടന ssh *ssh, Channel *c);

#അന്തര്ഭാവ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
ശൂന്യം *
client_new_escape_filter_ctx(പൂർണ്ണസംഖ്യ escape_char)
{
	(ശൂന്യം)escape_char;
	തിരികെ ശൂന്യ;
}

ശൂന്യം
client_register_global_confirm(global_confirm_cb *cb, ശൂന്യം *ctx)
{
	(ശൂന്യം)cb; (ശൂന്യം)ctx;
}

ശൂന്യം
client_expect_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, സ്ഥിരം അക്ഷരം *reason,
    എണ്ണൽ confirm_action action)
{
	(ശൂന്യം)ssh; (ശൂന്യം)id; (ശൂന്യം)reason; (ശൂന്യം)action;
}

ശൂന്യം
client_channel_request_agent_forwarding(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ chanid)
{
	(ശൂന്യം)ssh; (ശൂന്യം)chanid;
}

ശൂന്യം
client_stop_mux(ശൂന്യം)
{
}

പൂർണ്ണസംഖ്യ
client_simple_escape_filter(ഘടന ssh *ssh, Channel *c, അക്ഷരം *buf, പൂർണ്ണസംഖ്യ len)
{
	(ശൂന്യം)ssh; (ശൂന്യം)c; (ശൂന്യം)buf; (ശൂന്യം)len;
	തിരികെ 0;
}

ശൂന്യം
client_filter_cleanup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ cid, ശൂന്യം *ctx)
{
	(ശൂന്യം)ssh; (ശൂന്യം)cid; (ശൂന്യം)ctx;
}

പൂർണ്ണസംഖ്യ
client_x11_get_proto(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *display,
    സ്ഥിരം അക്ഷരം *xauth_path, u_int trusted, u_int timeout,
    അക്ഷരം **_proto, അക്ഷരം **_data)
{
	(ശൂന്യം)ssh; (ശൂന്യം)display; (ശൂന്യം)xauth_path;
	(ശൂന്യം)trusted; (ശൂന്യം)timeout;
	എങ്കിൽ (_proto != ശൂന്യ)
		*_proto = ശൂന്യ;
	എങ്കിൽ (_data != ശൂന്യ)
		*_data = ശൂന്യ;
	തിരികെ 0;
}

ശൂന്യം
client_session2_setup(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ want_tty, പൂർണ്ണസംഖ്യ want_subsys,
    സ്ഥിരം അക്ഷരം *term, ഘടന termios *tiop, പൂർണ്ണസംഖ്യ in_fd, ഘടന sshbuf *cmd,
    അക്ഷരം **env)
{
	(ശൂന്യം)ssh; (ശൂന്യം)id; (ശൂന്യം)want_tty; (ശൂന്യം)want_subsys;
	(ശൂന്യം)term; (ശൂന്യം)tiop; (ശൂന്യം)in_fd; (ശൂന്യം)cmd; (ശൂന്യം)env;
}

ശൂന്യം
enter_raw_mode(പൂർണ്ണസംഖ്യ quiet)
{
	(ശൂന്യം)quiet;
}

ശൂന്യം
leave_raw_mode(പൂർണ്ണസംഖ്യ quiet)
{
	(ശൂന്യം)quiet;
}

സ്ഥിതം ഘടന ssh *g_client = ശൂന്യ;
സ്ഥിതം ഘടന ssh *g_server = ശൂന്യ;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_init = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_mux_channel_id = -1;
സ്ഥിതം ഘടന sshbuf *g_mux_in = ശൂന്യ;
സ്ഥിതം ഘടന sshbuf *g_mux_out = ശൂന്യ;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
സ്ഥിതം ശൂന്യം
fuzz_drive_mux(ഘടന ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം u_char *body;
	size_t blen;
	ഘടന mux_master_state *state;

	state = (ഘടന mux_master_state *)c->mux_ctx;
	എങ്കിൽ (state == ശൂന്യ)
		തിരികെ;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	എങ്കിൽ ((r = sshbuf_get_string_direct(c->നിവേശം, &body, &blen)) != 0)
		തിരികെ;
	എങ്കിൽ (sshbuf_put(g_mux_in, body, blen) != 0)
		തിരികെ;
	എങ്കിൽ ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		തിരികെ;

	എങ്കിൽ (type == MUX_സന്ദേശം_HELLO) {
		rid = 0;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (!state->hello_rcvd)
			തിരികെ;
		എങ്കിൽ ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			തിരികെ;
	}

	വേണ്ടി (i = 0; mux_master_handlers[i].handler != ശൂന്യ; i++) {
		എങ്കിൽ (type == mux_master_handlers[i].type) {
			(ശൂന്യം)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			നിർത്തുക;
		}
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
init_once(ശൂന്യം)
{
	എങ്കിൽ (g_init)
		തിരികെ 0;
	സൂചന(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, വലുപ്പം(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (അക്ഷരം *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (അക്ഷരം *)"fuzz";

	ഘടന sshkey *priv = load_private(PRIV_ED25519);
	ഘടന sshkey *pub = load_public(PUB_ED25519);
	അക്ഷരം *keyname = xstrdup(sshkey_ssh_name(priv));

	സ്ഥിരം അക്ഷരം *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *proposal[PROPOSAL_MAX] = { 0 };
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		സ്ഥിരം അക്ഷരം *p = defaults[i];
		എങ്കിൽ (i == PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS)
			p = keyname;
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ഘടന kex_params kp;
	memcpy(kp.proposal, proposal, വലുപ്പം(proposal));

	എങ്കിൽ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		തിരികെ -1;
	എങ്കിൽ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		തിരികെ -1;
	എങ്കിൽ (run_kex(g_client, g_server) != 0)
		തിരികെ -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	എങ്കിൽ (c == ശൂന്യ)
		തിരികെ -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	ഘടന mux_master_state *st = (ഘടന mux_master_state *)c->mux_ctx;
	എങ്കിൽ (st != ശൂന്യ)
		st->hello_rcvd = 1;

	എങ്കിൽ ((g_mux_in = sshbuf_new()) == ശൂന്യ ||
	    (g_mux_out = sshbuf_new()) == ശൂന്യ)
		തിരികെ -1;

	സ്വതന്ത്രം(keyname);
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(proposal[i]);
	g_init = 1;
	തിരികെ 0;
}

ശൂന്യം
fuzz_mux_one(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (init_once() != 0)
		തിരികെ;
	എങ്കിൽ (size > 65000)
		തിരികെ;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	എങ്കിൽ (c == ശൂന്യ || c->mux_ctx == ശൂന്യ || c->നിവേശം == ശൂന്യ)
		തിരികെ;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->നിവേശം);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	എങ്കിൽ (sshbuf_put(c->നിവേശം, hdr, 4) != 0)
		തിരികെ;
	എങ്കിൽ (size > 0 && sshbuf_put(c->നിവേശം, data, size) != 0)
		തിരികെ;

	in_fuzz = 1;
	എങ്കിൽ (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	എങ്കിൽ (c->output != ശൂന്യ)
		sshbuf_reset(c->output);
}
