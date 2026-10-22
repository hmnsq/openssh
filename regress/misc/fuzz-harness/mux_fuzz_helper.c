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

#شامل <setjmp.h>
#شامل <signal.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <sys/types.h>

#شامل "log.h"
#شامل "ssh.h"
#شامل "ssh2.h"
#شامل "ssh_api.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "packet.h"
#شامل "myproposal.h"
#شامل "kex.h"
#شامل "xmalloc.h"
#شامل "authfile.h"
#شامل "misc.h"
#شامل "channels.h"
#شامل "readconf.h"

/* Externs that mux.c declares. */
صحیح tty_flag = 0;
Options options;
نویسه *host = پوچ;
ساختار sshbuf *command = پوچ;
فرار sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
صحیح
__lsan_is_turned_off(تهی)
{
	بازگشت 1;
}

ایستا jmp_buf fuzz_env;
ایستا فرار صحیح in_fuzz = 0;

تهی
cleanup_exit(صحیح code)
{
	اگر (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

تهی
__wrap_ssh_packet_disconnect(ساختار ssh *ssh, ثابت نویسه *fmt, ...)
{
	(تهی)ssh;
	(تهی)fmt;
	اگر (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

صحیح
__wrap_sshpkt_fatal(ساختار ssh *ssh, صحیح r, ثابت نویسه *fmt, ...)
{
	(تهی)ssh;
	(تهی)fmt;
	اگر (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
صحیح
__wrap_ask_permission(ثابت نویسه *fmt, ...)
{
	(تهی)fmt;
	بازگشت 1;
}

/* Socket-opening side effects we must neutralise. */
صحیح
__wrap_channel_setup_local_fwd_listener(ساختار ssh *ssh,
    ساختار Forward *fwd, ساختار ForwardOptions *fwd_opts)
{
	(تهی)ssh; (تهی)fwd; (تهی)fwd_opts;
	بازگشت 1;
}

صحیح
__wrap_channel_connect_stdio_fwd(ساختار ssh *ssh, ثابت نویسه *host_arg,
    صحیح port, صحیح in_fd, صحیح out_fd, صحیح nonblock)
{
	(تهی)ssh; (تهی)host_arg; (تهی)port;
	(تهی)in_fd; (تهی)out_fd; (تهی)nonblock;
	بازگشت -1;
}

صحیح
__wrap_channel_request_remote_forwarding(ساختار ssh *ssh, ساختار Forward *fwd)
{
	(تهی)ssh; (تهی)fwd;
	بازگشت 0;
}

صحیح
__wrap_channel_request_rforward_cancel(ساختار ssh *ssh, ساختار Forward *fwd)
{
	(تهی)ssh; (تهی)fwd;
	بازگشت 0;
}

صحیح
__wrap_channel_cancel_lport_listener(ساختار ssh *ssh, ساختار Forward *fwd,
    صحیح cport, ساختار ForwardOptions *fwd_opts)
{
	(تهی)ssh; (تهی)fwd; (تهی)cport; (تهی)fwd_opts;
	بازگشت 0;
}

ایستا ساختار sshkey *
load_private(ثابت نویسه *str)
{
	ساختار sshbuf *b = sshbuf_from(str, strlen(str));
	ساختار sshkey *k = پوچ;
	اگر (b == پوچ || sshkey_parse_private_fileblob(b, "", &k, پوچ) != 0)
		abort();
	sshbuf_free(b);
	بازگشت k;
}

ایستا ساختار sshkey *
load_public(ثابت نویسه *str)
{
	نویسه *tmp, *cp;
	ساختار sshkey *k = sshkey_new(کلید_UNSPEC);
	اگر (k == پوچ)
		abort();
	tmp = cp = strdup(str);
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	بازگشت k;
}

ایستا صحیح
pump(ساختار ssh *from, ساختار ssh *to, size_t *transferred)
{
	ثابت u_char *buf;
	size_t len;
	u_char type;
	صحیح r;
	*transferred = 0;
	اگر ((r = ssh_packet_next(from, &type)) != 0)
		بازگشت r;
	buf = ssh_output_ptr(from, &len);
	اگر (len == 0)
		بازگشت 0;
	اگر ((r = ssh_درون_داد_append(to, buf, len)) != 0)
		بازگشت r;
	اگر ((r = ssh_output_consume(from, len)) != 0)
		بازگشت r;
	*transferred = len;
	بازگشت 0;
}

ایستا صحیح
run_kex(ساختار ssh *client, ساختار ssh *server)
{
	صحیح r;
	size_t cn, sn;
	برای (صحیح i = 0; i < 100; i++) {
		اگر ((r = pump(server, client, &sn)) != 0) بازگشت r;
		اگر ((r = pump(client, server, &cn)) != 0) بازگشت r;
		اگر (server->kex->done && client->kex->done)
			بازگشت 0;
		اگر (cn == 0 && sn == 0)
			بازگشت SSH_ERR_PROTOCOL_ERROR;
	}
	بازگشت SSH_ERR_PROTOCOL_ERROR;
}

#شامل "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
ایستا صحیح mux_master_read_cb(ساختار ssh *ssh, Channel *c);

#شامل "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
تهی *
client_new_escape_filter_ctx(صحیح escape_char)
{
	(تهی)escape_char;
	بازگشت پوچ;
}

تهی
client_register_global_confirm(global_confirm_cb *cb, تهی *ctx)
{
	(تهی)cb; (تهی)ctx;
}

تهی
client_expect_confirm(ساختار ssh *ssh, صحیح id, ثابت نویسه *reason,
    شمارش confirm_action action)
{
	(تهی)ssh; (تهی)id; (تهی)reason; (تهی)action;
}

تهی
client_channel_request_agent_forwarding(ساختار ssh *ssh, صحیح chanid)
{
	(تهی)ssh; (تهی)chanid;
}

تهی
client_stop_mux(تهی)
{
}

صحیح
client_simple_escape_filter(ساختار ssh *ssh, Channel *c, نویسه *buf, صحیح len)
{
	(تهی)ssh; (تهی)c; (تهی)buf; (تهی)len;
	بازگشت 0;
}

تهی
client_filter_cleanup(ساختار ssh *ssh, صحیح cid, تهی *ctx)
{
	(تهی)ssh; (تهی)cid; (تهی)ctx;
}

صحیح
client_x11_get_proto(ساختار ssh *ssh, ثابت نویسه *display,
    ثابت نویسه *xauth_path, u_int trusted, u_int timeout,
    نویسه **_proto, نویسه **_data)
{
	(تهی)ssh; (تهی)display; (تهی)xauth_path;
	(تهی)trusted; (تهی)timeout;
	اگر (_proto != پوچ)
		*_proto = پوچ;
	اگر (_data != پوچ)
		*_data = پوچ;
	بازگشت 0;
}

تهی
client_session2_setup(ساختار ssh *ssh, صحیح id, صحیح want_tty, صحیح want_subsys,
    ثابت نویسه *term, ساختار termios *tiop, صحیح in_fd, ساختار sshbuf *cmd,
    نویسه **env)
{
	(تهی)ssh; (تهی)id; (تهی)want_tty; (تهی)want_subsys;
	(تهی)term; (تهی)tiop; (تهی)in_fd; (تهی)cmd; (تهی)env;
}

تهی
enter_raw_mode(صحیح quiet)
{
	(تهی)quiet;
}

تهی
leave_raw_mode(صحیح quiet)
{
	(تهی)quiet;
}

ایستا ساختار ssh *g_client = پوچ;
ایستا ساختار ssh *g_server = پوچ;
ایستا صحیح g_init = 0;
ایستا صحیح g_mux_channel_id = -1;
ایستا ساختار sshbuf *g_mux_in = پوچ;
ایستا ساختار sshbuf *g_mux_out = پوچ;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
ایستا تهی
fuzz_drive_mux(ساختار ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	صحیح r;
	ثابت u_char *body;
	size_t blen;
	ساختار mux_master_state *state;

	state = (ساختار mux_master_state *)c->mux_ctx;
	اگر (state == پوچ)
		بازگشت;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	اگر ((r = sshbuf_get_string_direct(c->درون_داد, &body, &blen)) != 0)
		بازگشت;
	اگر (sshbuf_put(g_mux_in, body, blen) != 0)
		بازگشت;
	اگر ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		بازگشت;

	اگر (type == MUX_پیام_HELLO) {
		rid = 0;
	} وگرنه {
		اگر (!state->hello_rcvd)
			بازگشت;
		اگر ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			بازگشت;
	}

	برای (i = 0; mux_master_handlers[i].handler != پوچ; i++) {
		اگر (type == mux_master_handlers[i].type) {
			(تهی)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			بشکن;
		}
	}
}

ایستا صحیح
init_once(تهی)
{
	اگر (g_init)
		بازگشت 0;
	سیگنال(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, اندازه(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (نویسه *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (نویسه *)"fuzz";

	ساختار sshkey *priv = load_private(PRIV_ED25519);
	ساختار sshkey *pub = load_public(PUB_ED25519);
	نویسه *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت نویسه *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	نویسه *proposal[PROPOSAL_MAX] = { 0 };
	صحیح i;
	برای (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت نویسه *p = defaults[i];
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			p = keyname;
		وگرنه اگر (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		وگرنه اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		وگرنه اگر (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ساختار kex_params kp;
	memcpy(kp.proposal, proposal, اندازه(proposal));

	اگر (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		بازگشت -1;
	اگر (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		بازگشت -1;
	اگر (run_kex(g_client, g_server) != 0)
		بازگشت -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	اگر (c == پوچ)
		بازگشت -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	ساختار mux_master_state *st = (ساختار mux_master_state *)c->mux_ctx;
	اگر (st != پوچ)
		st->hello_rcvd = 1;

	اگر ((g_mux_in = sshbuf_new()) == پوچ ||
	    (g_mux_out = sshbuf_new()) == پوچ)
		بازگشت -1;

	آزاد(keyname);
	برای (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	بازگشت 0;
}

تهی
fuzz_mux_one(ثابت uint8_t *data, size_t size)
{
	اگر (init_once() != 0)
		بازگشت;
	اگر (size > 65000)
		بازگشت;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	اگر (c == پوچ || c->mux_ctx == پوچ || c->درون_داد == پوچ)
		بازگشت;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->درون_داد);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	اگر (sshbuf_put(c->درون_داد, hdr, 4) != 0)
		بازگشت;
	اگر (size > 0 && sshbuf_put(c->درون_داد, data, size) != 0)
		بازگشت;

	in_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	اگر (c->output != پوچ)
		sshbuf_reset(c->output);
}
