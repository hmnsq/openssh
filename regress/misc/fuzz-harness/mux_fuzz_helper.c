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

#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "readconf.h"

/* Externs that mux.c declares. */
পূর্ণাঙ্ক tty_flag = 0;
Options options;
বর্ণ *host = রিক্ত;
সংরচনা sshbuf *command = রিক্ত;
চঞ্চল sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
পূর্ণাঙ্ক
__lsan_is_turned_off(শূন্য)
{
	প্রত্যাগম 1;
}

স্থির jmp_buf fuzz_env;
স্থির চঞ্চল পূর্ণাঙ্ক in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

শূন্য
__wrap_ssh_packet_disconnect(সংরচনা ssh *ssh, ধ্রুব বর্ণ *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

পূর্ণাঙ্ক
__wrap_sshpkt_fatal(সংরচনা ssh *ssh, পূর্ণাঙ্ক r, ধ্রুব বর্ণ *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
পূর্ণাঙ্ক
__wrap_ask_permission(ধ্রুব বর্ণ *fmt, ...)
{
	(শূন্য)fmt;
	প্রত্যাগম 1;
}

/* Socket-opening side effects we must neutralise. */
পূর্ণাঙ্ক
__wrap_channel_setup_local_fwd_listener(সংরচনা ssh *ssh,
    সংরচনা Forward *fwd, সংরচনা ForwardOptions *fwd_opts)
{
	(শূন্য)ssh; (শূন্য)fwd; (শূন্য)fwd_opts;
	প্রত্যাগম 1;
}

পূর্ণাঙ্ক
__wrap_channel_connect_stdio_fwd(সংরচনা ssh *ssh, ধ্রুব বর্ণ *host_arg,
    পূর্ণাঙ্ক port, পূর্ণাঙ্ক in_fd, পূর্ণাঙ্ক out_fd, পূর্ণাঙ্ক nonblock)
{
	(শূন্য)ssh; (শূন্য)host_arg; (শূন্য)port;
	(শূন্য)in_fd; (শূন্য)out_fd; (শূন্য)nonblock;
	প্রত্যাগম -1;
}

পূর্ণাঙ্ক
__wrap_channel_request_remote_forwarding(সংরচনা ssh *ssh, সংরচনা Forward *fwd)
{
	(শূন্য)ssh; (শূন্য)fwd;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
__wrap_channel_request_rforward_cancel(সংরচনা ssh *ssh, সংরচনা Forward *fwd)
{
	(শূন্য)ssh; (শূন্য)fwd;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
__wrap_channel_cancel_lport_listener(সংরচনা ssh *ssh, সংরচনা Forward *fwd,
    পূর্ণাঙ্ক cport, সংরচনা ForwardOptions *fwd_opts)
{
	(শূন্য)ssh; (শূন্য)fwd; (শূন্য)cport; (শূন্য)fwd_opts;
	প্রত্যাগম 0;
}

স্থির সংরচনা sshkey *
load_private(ধ্রুব বর্ণ *str)
{
	সংরচনা sshbuf *b = sshbuf_from(str, strlen(str));
	সংরচনা sshkey *k = রিক্ত;
	যদি (b == রিক্ত || sshkey_parse_private_fileblob(b, "", &k, রিক্ত) != 0)
		abort();
	sshbuf_free(b);
	প্রত্যাগম k;
}

স্থির সংরচনা sshkey *
load_public(ধ্রুব বর্ণ *str)
{
	বর্ণ *tmp, *cp;
	সংরচনা sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == রিক্ত)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	প্রত্যাগম k;
}

স্থির পূর্ণাঙ্ক
pump(সংরচনা ssh *from, সংরচনা ssh *to, size_t *transferred)
{
	ধ্রুব u_char *buf;
	size_t len;
	u_char type;
	পূর্ণাঙ্ক r;
	*transferred = 0;
	যদি ((r = ssh_packet_next(from, &type)) != 0)
		প্রত্যাগম r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		প্রত্যাগম 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		প্রত্যাগম r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		প্রত্যাগম r;
	*transferred = len;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
run_kex(সংরচনা ssh *client, সংরচনা ssh *server)
{
	পূর্ণাঙ্ক r;
	size_t cn, sn;
	প্রতি (পূর্ণাঙ্ক i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) প্রত্যাগম r;
		যদি ((r = pump(client, server, &cn)) != 0) প্রত্যাগম r;
		যদি (server->kex->done && client->kex->done)
			প্রত্যাগম 0;
		যদি (cn == 0 && sn == 0)
			প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
	}
	প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
}

#অন্তর্ভাব "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
স্থির পূর্ণাঙ্ক mux_master_read_cb(সংরচনা ssh *ssh, Channel *c);

#অন্তর্ভাব "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
শূন্য *
client_new_escape_filter_ctx(পূর্ণাঙ্ক escape_char)
{
	(শূন্য)escape_char;
	প্রত্যাগম রিক্ত;
}

শূন্য
client_register_global_confirm(global_confirm_cb *cb, শূন্য *ctx)
{
	(শূন্য)cb; (শূন্য)ctx;
}

শূন্য
client_expect_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, ধ্রুব বর্ণ *reason,
    গণনা confirm_action action)
{
	(শূন্য)ssh; (শূন্য)id; (শূন্য)reason; (শূন্য)action;
}

শূন্য
client_channel_request_agent_forwarding(সংরচনা ssh *ssh, পূর্ণাঙ্ক chanid)
{
	(শূন্য)ssh; (শূন্য)chanid;
}

শূন্য
client_stop_mux(শূন্য)
{
}

পূর্ণাঙ্ক
client_simple_escape_filter(সংরচনা ssh *ssh, Channel *c, বর্ণ *buf, পূর্ণাঙ্ক len)
{
	(শূন্য)ssh; (শূন্য)c; (শূন্য)buf; (শূন্য)len;
	প্রত্যাগম 0;
}

শূন্য
client_filter_cleanup(সংরচনা ssh *ssh, পূর্ণাঙ্ক cid, শূন্য *ctx)
{
	(শূন্য)ssh; (শূন্য)cid; (শূন্য)ctx;
}

পূর্ণাঙ্ক
client_x11_get_proto(সংরচনা ssh *ssh, ধ্রুব বর্ণ *display,
    ধ্রুব বর্ণ *xauth_path, u_int trusted, u_int timeout,
    বর্ণ **_proto, বর্ণ **_data)
{
	(শূন্য)ssh; (শূন্য)display; (শূন্য)xauth_path;
	(শূন্য)trusted; (শূন্য)timeout;
	যদি (_proto != রিক্ত)
		*_proto = রিক্ত;
	যদি (_data != রিক্ত)
		*_data = রিক্ত;
	প্রত্যাগম 0;
}

শূন্য
client_session2_setup(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, পূর্ণাঙ্ক want_tty, পূর্ণাঙ্ক want_subsys,
    ধ্রুব বর্ণ *term, সংরচনা termios *tiop, পূর্ণাঙ্ক in_fd, সংরচনা sshbuf *cmd,
    বর্ণ **env)
{
	(শূন্য)ssh; (শূন্য)id; (শূন্য)want_tty; (শূন্য)want_subsys;
	(শূন্য)term; (শূন্য)tiop; (শূন্য)in_fd; (শূন্য)cmd; (শূন্য)env;
}

শূন্য
enter_raw_mode(পূর্ণাঙ্ক quiet)
{
	(শূন্য)quiet;
}

শূন্য
leave_raw_mode(পূর্ণাঙ্ক quiet)
{
	(শূন্য)quiet;
}

স্থির সংরচনা ssh *g_client = রিক্ত;
স্থির সংরচনা ssh *g_server = রিক্ত;
স্থির পূর্ণাঙ্ক g_init = 0;
স্থির পূর্ণাঙ্ক g_mux_channel_id = -1;
স্থির সংরচনা sshbuf *g_mux_in = রিক্ত;
স্থির সংরচনা sshbuf *g_mux_out = রিক্ত;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
স্থির শূন্য
fuzz_drive_mux(সংরচনা ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	পূর্ণাঙ্ক r;
	ধ্রুব u_char *body;
	size_t blen;
	সংরচনা mux_master_state *state;

	state = (সংরচনা mux_master_state *)c->mux_ctx;
	যদি (state == রিক্ত)
		প্রত্যাগম;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	যদি ((r = sshbuf_get_string_direct(c->প্রবেশ, &body, &blen)) != 0)
		প্রত্যাগম;
	যদি (sshbuf_put(g_mux_in, body, blen) != 0)
		প্রত্যাগম;
	যদি ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		প্রত্যাগম;

	যদি (type == MUX_বার্তা_HELLO) {
		rid = 0;
	} অন্যথা {
		যদি (!state->hello_rcvd)
			প্রত্যাগম;
		যদি ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			প্রত্যাগম;
	}

	প্রতি (i = 0; mux_master_handlers[i].handler != রিক্ত; i++) {
		যদি (type == mux_master_handlers[i].type) {
			(শূন্য)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			ভঙ্গ;
		}
	}
}

স্থির পূর্ণাঙ্ক
init_once(শূন্য)
{
	যদি (g_init)
		প্রত্যাগম 0;
	সঙ্কেত(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, পরিমাণ(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (বর্ণ *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (বর্ণ *)"fuzz";

	সংরচনা sshkey *priv = load_private(PRIV_ED25519);
	সংরচনা sshkey *pub = load_public(PUB_ED25519);
	বর্ণ *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুব বর্ণ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	বর্ণ *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণাঙ্ক i;
	প্রতি (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুব বর্ণ *p = defaults[i];
		যদি (i == PROPOSAL_SERVER_HOST_চাবি_ALGS)
			p = keyname;
		অন্যথা যদি (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		অন্যথা যদি (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		অন্যথা যদি (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	সংরচনা kex_params kp;
	memcpy(kp.proposal, proposal, পরিমাণ(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		প্রত্যাগম -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		প্রত্যাগম -1;
	যদি (run_kex(g_client, g_server) != 0)
		প্রত্যাগম -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	যদি (c == রিক্ত)
		প্রত্যাগম -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	সংরচনা mux_master_state *st = (সংরচনা mux_master_state *)c->mux_ctx;
	যদি (st != রিক্ত)
		st->hello_rcvd = 1;

	যদি ((g_mux_in = sshbuf_new()) == রিক্ত ||
	    (g_mux_out = sshbuf_new()) == রিক্ত)
		প্রত্যাগম -1;

	মুক্ত(keyname);
	প্রতি (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	প্রত্যাগম 0;
}

শূন্য
fuzz_mux_one(ধ্রুব uint8_t *data, size_t size)
{
	যদি (init_once() != 0)
		প্রত্যাগম;
	যদি (size > 65000)
		প্রত্যাগম;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	যদি (c == রিক্ত || c->mux_ctx == রিক্ত || c->প্রবেশ == রিক্ত)
		প্রত্যাগম;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->প্রবেশ);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	যদি (sshbuf_put(c->প্রবেশ, hdr, 4) != 0)
		প্রত্যাগম;
	যদি (size > 0 && sshbuf_put(c->প্রবেশ, data, size) != 0)
		প্রত্যাগম;

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	যদি (c->output != রিক্ত)
		sshbuf_reset(c->output);
}
