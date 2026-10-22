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

#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "channels.h"
#அந்தர்பாவ "readconf.h"

/* Externs that mux.c declares. */
முழு tty_flag = 0;
Options options;
எழுத்து *host = வெற்று;
கட்டமைப்பு sshbuf *command = வெற்று;
நிலையற்ற sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
முழு
__lsan_is_turned_off(வெறுமை)
{
	திரும்பு 1;
}

நிலையான jmp_buf fuzz_env;
நிலையான நிலையற்ற முழு in_fuzz = 0;

வெறுமை
cleanup_exit(முழு code)
{
	எனில் (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

வெறுமை
__wrap_ssh_packet_disconnect(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *fmt, ...)
{
	(வெறுமை)ssh;
	(வெறுமை)fmt;
	எனில் (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

முழு
__wrap_sshpkt_fatal(கட்டமைப்பு ssh *ssh, முழு r, மாறிலி எழுத்து *fmt, ...)
{
	(வெறுமை)ssh;
	(வெறுமை)fmt;
	எனில் (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
முழு
__wrap_ask_permission(மாறிலி எழுத்து *fmt, ...)
{
	(வெறுமை)fmt;
	திரும்பு 1;
}

/* Socket-opening side effects we must neutralise. */
முழு
__wrap_channel_setup_local_fwd_listener(கட்டமைப்பு ssh *ssh,
    கட்டமைப்பு Forward *fwd, கட்டமைப்பு ForwardOptions *fwd_opts)
{
	(வெறுமை)ssh; (வெறுமை)fwd; (வெறுமை)fwd_opts;
	திரும்பு 1;
}

முழு
__wrap_channel_connect_stdio_fwd(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *host_arg,
    முழு port, முழு in_fd, முழு out_fd, முழு nonblock)
{
	(வெறுமை)ssh; (வெறுமை)host_arg; (வெறுமை)port;
	(வெறுமை)in_fd; (வெறுமை)out_fd; (வெறுமை)nonblock;
	திரும்பு -1;
}

முழு
__wrap_channel_request_remote_forwarding(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd)
{
	(வெறுமை)ssh; (வெறுமை)fwd;
	திரும்பு 0;
}

முழு
__wrap_channel_request_rforward_cancel(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd)
{
	(வெறுமை)ssh; (வெறுமை)fwd;
	திரும்பு 0;
}

முழு
__wrap_channel_cancel_lport_listener(கட்டமைப்பு ssh *ssh, கட்டமைப்பு Forward *fwd,
    முழு cport, கட்டமைப்பு ForwardOptions *fwd_opts)
{
	(வெறுமை)ssh; (வெறுமை)fwd; (வெறுமை)cport; (வெறுமை)fwd_opts;
	திரும்பு 0;
}

நிலையான கட்டமைப்பு sshkey *
load_private(மாறிலி எழுத்து *str)
{
	கட்டமைப்பு sshbuf *b = sshbuf_from(str, strlen(str));
	கட்டமைப்பு sshkey *k = வெற்று;
	எனில் (b == வெற்று || sshkey_parse_private_fileblob(b, "", &k, வெற்று) != 0)
		abort();
	sshbuf_free(b);
	திரும்பு k;
}

நிலையான கட்டமைப்பு sshkey *
load_public(மாறிலி எழுத்து *str)
{
	எழுத்து *tmp, *cp;
	கட்டமைப்பு sshkey *k = sshkey_new(சாவி_UNSPEC);
	எனில் (k == வெற்று)
		abort();
	tmp = cp = strdup(str);
	எனில் (sshkey_read(k, &cp) != 0)
		abort();
	விடுவி(tmp);
	திரும்பு k;
}

நிலையான முழு
pump(கட்டமைப்பு ssh *from, கட்டமைப்பு ssh *to, size_t *transferred)
{
	மாறிலி u_char *buf;
	size_t len;
	u_char type;
	முழு r;
	*transferred = 0;
	எனில் ((r = ssh_packet_next(from, &type)) != 0)
		திரும்பு r;
	buf = ssh_output_ptr(from, &len);
	எனில் (len == 0)
		திரும்பு 0;
	எனில் ((r = ssh_உள்ளீடு_append(to, buf, len)) != 0)
		திரும்பு r;
	எனில் ((r = ssh_output_consume(from, len)) != 0)
		திரும்பு r;
	*transferred = len;
	திரும்பு 0;
}

நிலையான முழு
run_kex(கட்டமைப்பு ssh *client, கட்டமைப்பு ssh *server)
{
	முழு r;
	size_t cn, sn;
	க்கு (முழு i = 0; i < 100; i++) {
		எனில் ((r = pump(server, client, &sn)) != 0) திரும்பு r;
		எனில் ((r = pump(client, server, &cn)) != 0) திரும்பு r;
		எனில் (server->kex->done && client->kex->done)
			திரும்பு 0;
		எனில் (cn == 0 && sn == 0)
			திரும்பு SSH_ERR_PROTOCOL_ERROR;
	}
	திரும்பு SSH_ERR_PROTOCOL_ERROR;
}

#அந்தர்பாவ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
நிலையான முழு mux_master_read_cb(கட்டமைப்பு ssh *ssh, Channel *c);

#அந்தர்பாவ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
வெறுமை *
client_new_escape_filter_ctx(முழு escape_char)
{
	(வெறுமை)escape_char;
	திரும்பு வெற்று;
}

வெறுமை
client_register_global_confirm(global_confirm_cb *cb, வெறுமை *ctx)
{
	(வெறுமை)cb; (வெறுமை)ctx;
}

வெறுமை
client_expect_confirm(கட்டமைப்பு ssh *ssh, முழு id, மாறிலி எழுத்து *reason,
    எண்ணிக்கை confirm_action action)
{
	(வெறுமை)ssh; (வெறுமை)id; (வெறுமை)reason; (வெறுமை)action;
}

வெறுமை
client_channel_request_agent_forwarding(கட்டமைப்பு ssh *ssh, முழு chanid)
{
	(வெறுமை)ssh; (வெறுமை)chanid;
}

வெறுமை
client_stop_mux(வெறுமை)
{
}

முழு
client_simple_escape_filter(கட்டமைப்பு ssh *ssh, Channel *c, எழுத்து *buf, முழு len)
{
	(வெறுமை)ssh; (வெறுமை)c; (வெறுமை)buf; (வெறுமை)len;
	திரும்பு 0;
}

வெறுமை
client_filter_cleanup(கட்டமைப்பு ssh *ssh, முழு cid, வெறுமை *ctx)
{
	(வெறுமை)ssh; (வெறுமை)cid; (வெறுமை)ctx;
}

முழு
client_x11_get_proto(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *display,
    மாறிலி எழுத்து *xauth_path, u_int trusted, u_int timeout,
    எழுத்து **_proto, எழுத்து **_data)
{
	(வெறுமை)ssh; (வெறுமை)display; (வெறுமை)xauth_path;
	(வெறுமை)trusted; (வெறுமை)timeout;
	எனில் (_proto != வெற்று)
		*_proto = வெற்று;
	எனில் (_data != வெற்று)
		*_data = வெற்று;
	திரும்பு 0;
}

வெறுமை
client_session2_setup(கட்டமைப்பு ssh *ssh, முழு id, முழு want_tty, முழு want_subsys,
    மாறிலி எழுத்து *term, கட்டமைப்பு termios *tiop, முழு in_fd, கட்டமைப்பு sshbuf *cmd,
    எழுத்து **env)
{
	(வெறுமை)ssh; (வெறுமை)id; (வெறுமை)want_tty; (வெறுமை)want_subsys;
	(வெறுமை)term; (வெறுமை)tiop; (வெறுமை)in_fd; (வெறுமை)cmd; (வெறுமை)env;
}

வெறுமை
enter_raw_mode(முழு quiet)
{
	(வெறுமை)quiet;
}

வெறுமை
leave_raw_mode(முழு quiet)
{
	(வெறுமை)quiet;
}

நிலையான கட்டமைப்பு ssh *g_client = வெற்று;
நிலையான கட்டமைப்பு ssh *g_server = வெற்று;
நிலையான முழு g_init = 0;
நிலையான முழு g_mux_channel_id = -1;
நிலையான கட்டமைப்பு sshbuf *g_mux_in = வெற்று;
நிலையான கட்டமைப்பு sshbuf *g_mux_out = வெற்று;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
நிலையான வெறுமை
fuzz_drive_mux(கட்டமைப்பு ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	முழு r;
	மாறிலி u_char *body;
	size_t blen;
	கட்டமைப்பு mux_master_state *state;

	state = (கட்டமைப்பு mux_master_state *)c->mux_ctx;
	எனில் (state == வெற்று)
		திரும்பு;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	எனில் ((r = sshbuf_get_string_direct(c->உள்ளீடு, &body, &blen)) != 0)
		திரும்பு;
	எனில் (sshbuf_put(g_mux_in, body, blen) != 0)
		திரும்பு;
	எனில் ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		திரும்பு;

	எனில் (type == MUX_செய்தி_HELLO) {
		rid = 0;
	} இல்லையெனில் {
		எனில் (!state->hello_rcvd)
			திரும்பு;
		எனில் ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			திரும்பு;
	}

	க்கு (i = 0; mux_master_handlers[i].handler != வெற்று; i++) {
		எனில் (type == mux_master_handlers[i].type) {
			(வெறுமை)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			நிறுத்து;
		}
	}
}

நிலையான முழு
init_once(வெறுமை)
{
	எனில் (g_init)
		திரும்பு 0;
	சமிக்ஞை(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, அளவு(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (எழுத்து *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (எழுத்து *)"fuzz";

	கட்டமைப்பு sshkey *priv = load_private(PRIV_ED25519);
	கட்டமைப்பு sshkey *pub = load_public(PUB_ED25519);
	எழுத்து *keyname = xstrdup(sshkey_ssh_name(priv));

	மாறிலி எழுத்து *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	எழுத்து *proposal[PROPOSAL_MAX] = { 0 };
	முழு i;
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		மாறிலி எழுத்து *p = defaults[i];
		எனில் (i == PROPOSAL_SERVER_HOST_சாவி_ALGS)
			p = keyname;
		இல்லையெனில் எனில் (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		இல்லையெனில் எனில் (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		இல்லையெனில் எனில் (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	கட்டமைப்பு kex_params kp;
	memcpy(kp.proposal, proposal, அளவு(proposal));

	எனில் (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		திரும்பு -1;
	எனில் (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		திரும்பு -1;
	எனில் (run_kex(g_client, g_server) != 0)
		திரும்பு -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	எனில் (c == வெற்று)
		திரும்பு -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	கட்டமைப்பு mux_master_state *st = (கட்டமைப்பு mux_master_state *)c->mux_ctx;
	எனில் (st != வெற்று)
		st->hello_rcvd = 1;

	எனில் ((g_mux_in = sshbuf_new()) == வெற்று ||
	    (g_mux_out = sshbuf_new()) == வெற்று)
		திரும்பு -1;

	விடுவி(keyname);
	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(proposal[i]);
	g_init = 1;
	திரும்பு 0;
}

வெறுமை
fuzz_mux_one(மாறிலி uint8_t *data, size_t size)
{
	எனில் (init_once() != 0)
		திரும்பு;
	எனில் (size > 65000)
		திரும்பு;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	எனில் (c == வெற்று || c->mux_ctx == வெற்று || c->உள்ளீடு == வெற்று)
		திரும்பு;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->உள்ளீடு);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	எனில் (sshbuf_put(c->உள்ளீடு, hdr, 4) != 0)
		திரும்பு;
	எனில் (size > 0 && sshbuf_put(c->உள்ளீடு, data, size) != 0)
		திரும்பு;

	in_fuzz = 1;
	எனில் (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	எனில் (c->output != வெற்று)
		sshbuf_reset(c->output);
}
