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

#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "channels.h"
#અન્તર્ભાવ "readconf.h"

/* Externs that mux.c declares. */
પૂર્ણાંક tty_flag = 0;
Options options;
અક્ષર *host = ખાલી;
સંરચના sshbuf *command = ખાલી;
અસ્થિર sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
પૂર્ણાંક
__lsan_is_turned_off(શૂન્ય)
{
	પાછા 1;
}

સ્થિર jmp_buf fuzz_env;
સ્થિર અસ્થિર પૂર્ણાંક in_fuzz = 0;

શૂન્ય
cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

શૂન્ય
__wrap_ssh_packet_disconnect(સંરચના ssh *ssh, અચલ અક્ષર *fmt, ...)
{
	(શૂન્ય)ssh;
	(શૂન્ય)fmt;
	જો (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

પૂર્ણાંક
__wrap_sshpkt_fatal(સંરચના ssh *ssh, પૂર્ણાંક r, અચલ અક્ષર *fmt, ...)
{
	(શૂન્ય)ssh;
	(શૂન્ય)fmt;
	જો (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
પૂર્ણાંક
__wrap_ask_permission(અચલ અક્ષર *fmt, ...)
{
	(શૂન્ય)fmt;
	પાછા 1;
}

/* Socket-opening side effects we must neutralise. */
પૂર્ણાંક
__wrap_channel_setup_local_fwd_listener(સંરચના ssh *ssh,
    સંરચના Forward *fwd, સંરચના ForwardOptions *fwd_opts)
{
	(શૂન્ય)ssh; (શૂન્ય)fwd; (શૂન્ય)fwd_opts;
	પાછા 1;
}

પૂર્ણાંક
__wrap_channel_connect_stdio_fwd(સંરચના ssh *ssh, અચલ અક્ષર *host_arg,
    પૂર્ણાંક port, પૂર્ણાંક in_fd, પૂર્ણાંક out_fd, પૂર્ણાંક nonblock)
{
	(શૂન્ય)ssh; (શૂન્ય)host_arg; (શૂન્ય)port;
	(શૂન્ય)in_fd; (શૂન્ય)out_fd; (શૂન્ય)nonblock;
	પાછા -1;
}

પૂર્ણાંક
__wrap_channel_request_remote_forwarding(સંરચના ssh *ssh, સંરચના Forward *fwd)
{
	(શૂન્ય)ssh; (શૂન્ય)fwd;
	પાછા 0;
}

પૂર્ણાંક
__wrap_channel_request_rforward_cancel(સંરચના ssh *ssh, સંરચના Forward *fwd)
{
	(શૂન્ય)ssh; (શૂન્ય)fwd;
	પાછા 0;
}

પૂર્ણાંક
__wrap_channel_cancel_lport_listener(સંરચના ssh *ssh, સંરચના Forward *fwd,
    પૂર્ણાંક cport, સંરચના ForwardOptions *fwd_opts)
{
	(શૂન્ય)ssh; (શૂન્ય)fwd; (શૂન્ય)cport; (શૂન્ય)fwd_opts;
	પાછા 0;
}

સ્થિર સંરચના sshkey *
load_private(અચલ અક્ષર *str)
{
	સંરચના sshbuf *b = sshbuf_from(str, strlen(str));
	સંરચના sshkey *k = ખાલી;
	જો (b == ખાલી || sshkey_parse_private_fileblob(b, "", &k, ખાલી) != 0)
		abort();
	sshbuf_free(b);
	પાછા k;
}

સ્થિર સંરચના sshkey *
load_public(અચલ અક્ષર *str)
{
	અક્ષર *tmp, *cp;
	સંરચના sshkey *k = sshkey_new(ચાવી_UNSPEC);
	જો (k == ખાલી)
		abort();
	tmp = cp = strdup(str);
	જો (sshkey_read(k, &cp) != 0)
		abort();
	મુક્ત(tmp);
	પાછા k;
}

સ્થિર પૂર્ણાંક
pump(સંરચના ssh *from, સંરચના ssh *to, size_t *transferred)
{
	અચલ u_char *buf;
	size_t len;
	u_char type;
	પૂર્ણાંક r;
	*transferred = 0;
	જો ((r = ssh_packet_next(from, &type)) != 0)
		પાછા r;
	buf = ssh_output_ptr(from, &len);
	જો (len == 0)
		પાછા 0;
	જો ((r = ssh_આગત_append(to, buf, len)) != 0)
		પાછા r;
	જો ((r = ssh_output_consume(from, len)) != 0)
		પાછા r;
	*transferred = len;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
run_kex(સંરચના ssh *client, સંરચના ssh *server)
{
	પૂર્ણાંક r;
	size_t cn, sn;
	માટે (પૂર્ણાંક i = 0; i < 100; i++) {
		જો ((r = pump(server, client, &sn)) != 0) પાછા r;
		જો ((r = pump(client, server, &cn)) != 0) પાછા r;
		જો (server->kex->done && client->kex->done)
			પાછા 0;
		જો (cn == 0 && sn == 0)
			પાછા SSH_ERR_PROTOCOL_ERROR;
	}
	પાછા SSH_ERR_PROTOCOL_ERROR;
}

#અન્તર્ભાવ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
સ્થિર પૂર્ણાંક mux_master_read_cb(સંરચના ssh *ssh, Channel *c);

#અન્તર્ભાવ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
શૂન્ય *
client_new_escape_filter_ctx(પૂર્ણાંક escape_char)
{
	(શૂન્ય)escape_char;
	પાછા ખાલી;
}

શૂન્ય
client_register_global_confirm(global_confirm_cb *cb, શૂન્ય *ctx)
{
	(શૂન્ય)cb; (શૂન્ય)ctx;
}

શૂન્ય
client_expect_confirm(સંરચના ssh *ssh, પૂર્ણાંક id, અચલ અક્ષર *reason,
    ગણના confirm_action action)
{
	(શૂન્ય)ssh; (શૂન્ય)id; (શૂન્ય)reason; (શૂન્ય)action;
}

શૂન્ય
client_channel_request_agent_forwarding(સંરચના ssh *ssh, પૂર્ણાંક chanid)
{
	(શૂન્ય)ssh; (શૂન્ય)chanid;
}

શૂન્ય
client_stop_mux(શૂન્ય)
{
}

પૂર્ણાંક
client_simple_escape_filter(સંરચના ssh *ssh, Channel *c, અક્ષર *buf, પૂર્ણાંક len)
{
	(શૂન્ય)ssh; (શૂન્ય)c; (શૂન્ય)buf; (શૂન્ય)len;
	પાછા 0;
}

શૂન્ય
client_filter_cleanup(સંરચના ssh *ssh, પૂર્ણાંક cid, શૂન્ય *ctx)
{
	(શૂન્ય)ssh; (શૂન્ય)cid; (શૂન્ય)ctx;
}

પૂર્ણાંક
client_x11_get_proto(સંરચના ssh *ssh, અચલ અક્ષર *display,
    અચલ અક્ષર *xauth_path, u_int trusted, u_int timeout,
    અક્ષર **_proto, અક્ષર **_data)
{
	(શૂન્ય)ssh; (શૂન્ય)display; (શૂન્ય)xauth_path;
	(શૂન્ય)trusted; (શૂન્ય)timeout;
	જો (_proto != ખાલી)
		*_proto = ખાલી;
	જો (_data != ખાલી)
		*_data = ખાલી;
	પાછા 0;
}

શૂન્ય
client_session2_setup(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક want_tty, પૂર્ણાંક want_subsys,
    અચલ અક્ષર *term, સંરચના termios *tiop, પૂર્ણાંક in_fd, સંરચના sshbuf *cmd,
    અક્ષર **env)
{
	(શૂન્ય)ssh; (શૂન્ય)id; (શૂન્ય)want_tty; (શૂન્ય)want_subsys;
	(શૂન્ય)term; (શૂન્ય)tiop; (શૂન્ય)in_fd; (શૂન્ય)cmd; (શૂન્ય)env;
}

શૂન્ય
enter_raw_mode(પૂર્ણાંક quiet)
{
	(શૂન્ય)quiet;
}

શૂન્ય
leave_raw_mode(પૂર્ણાંક quiet)
{
	(શૂન્ય)quiet;
}

સ્થિર સંરચના ssh *g_client = ખાલી;
સ્થિર સંરચના ssh *g_server = ખાલી;
સ્થિર પૂર્ણાંક g_init = 0;
સ્થિર પૂર્ણાંક g_mux_channel_id = -1;
સ્થિર સંરચના sshbuf *g_mux_in = ખાલી;
સ્થિર સંરચના sshbuf *g_mux_out = ખાલી;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
સ્થિર શૂન્ય
fuzz_drive_mux(સંરચના ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	પૂર્ણાંક r;
	અચલ u_char *body;
	size_t blen;
	સંરચના mux_master_state *state;

	state = (સંરચના mux_master_state *)c->mux_ctx;
	જો (state == ખાલી)
		પાછા;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	જો ((r = sshbuf_get_string_direct(c->આગત, &body, &blen)) != 0)
		પાછા;
	જો (sshbuf_put(g_mux_in, body, blen) != 0)
		પાછા;
	જો ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		પાછા;

	જો (type == MUX_સંદેશ_HELLO) {
		rid = 0;
	} નહીંતર {
		જો (!state->hello_rcvd)
			પાછા;
		જો ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			પાછા;
	}

	માટે (i = 0; mux_master_handlers[i].handler != ખાલી; i++) {
		જો (type == mux_master_handlers[i].type) {
			(શૂન્ય)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			તોડો;
		}
	}
}

સ્થિર પૂર્ણાંક
init_once(શૂન્ય)
{
	જો (g_init)
		પાછા 0;
	સંકેત(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, કદ(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (અક્ષર *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (અક્ષર *)"fuzz";

	સંરચના sshkey *priv = load_private(PRIV_ED25519);
	સંરચના sshkey *pub = load_public(PUB_ED25519);
	અક્ષર *keyname = xstrdup(sshkey_ssh_name(priv));

	અચલ અક્ષર *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *proposal[PROPOSAL_MAX] = { 0 };
	પૂર્ણાંક i;
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		અચલ અક્ષર *p = defaults[i];
		જો (i == PROPOSAL_SERVER_HOST_ચાવી_ALGS)
			p = keyname;
		નહીંતર જો (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		નહીંતર જો (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		નહીંતર જો (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	સંરચના kex_params kp;
	memcpy(kp.proposal, proposal, કદ(proposal));

	જો (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		પાછા -1;
	જો (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		પાછા -1;
	જો (run_kex(g_client, g_server) != 0)
		પાછા -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	જો (c == ખાલી)
		પાછા -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	સંરચના mux_master_state *st = (સંરચના mux_master_state *)c->mux_ctx;
	જો (st != ખાલી)
		st->hello_rcvd = 1;

	જો ((g_mux_in = sshbuf_new()) == ખાલી ||
	    (g_mux_out = sshbuf_new()) == ખાલી)
		પાછા -1;

	મુક્ત(keyname);
	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(proposal[i]);
	g_init = 1;
	પાછા 0;
}

શૂન્ય
fuzz_mux_one(અચલ uint8_t *data, size_t size)
{
	જો (init_once() != 0)
		પાછા;
	જો (size > 65000)
		પાછા;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	જો (c == ખાલી || c->mux_ctx == ખાલી || c->આગત == ખાલી)
		પાછા;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->આગત);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	જો (sshbuf_put(c->આગત, hdr, 4) != 0)
		પાછા;
	જો (size > 0 && sshbuf_put(c->આગત, data, size) != 0)
		પાછા;

	in_fuzz = 1;
	જો (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	જો (c->output != ખાલી)
		sshbuf_reset(c->output);
}
