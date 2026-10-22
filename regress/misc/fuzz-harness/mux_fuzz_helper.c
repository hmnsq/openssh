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
حرف *host = تہی;
ساخت sshbuf *command = تہی;
متلون sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
صحیح
__lsan_is_turned_off(خالی)
{
	واپس 1;
}

ساکن jmp_buf fuzz_env;
ساکن متلون صحیح اندر_fuzz = 0;

خالی
cleanup_exit(صحیح رمز)
{
	اگر (اندر_fuzz)
		longjmp(fuzz_env, رمز ? رمز : 1);
	_exit(رمز);
}

خالی
__wrap_ssh_packet_disconnect(ساخت ssh *ssh, ثابت حرف *fmt, ...)
{
	(خالی)ssh;
	(خالی)fmt;
	اگر (اندر_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

صحیح
__wrap_sshpkt_fatal(ساخت ssh *ssh, صحیح r, ثابت حرف *fmt, ...)
{
	(خالی)ssh;
	(خالی)fmt;
	اگر (اندر_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
صحیح
__wrap_ask_permission(ثابت حرف *fmt, ...)
{
	(خالی)fmt;
	واپس 1;
}

/* Socket-opening side effects we must neutralise. */
صحیح
__wrap_channel_setup_local_fwd_listener(ساخت ssh *ssh,
    ساخت Forward *fwd, ساخت ForwardOptions *fwd_opts)
{
	(خالی)ssh; (خالی)fwd; (خالی)fwd_opts;
	واپس 1;
}

صحیح
__wrap_channel_connect_stdio_fwd(ساخت ssh *ssh, ثابت حرف *host_arg,
    صحیح پورٹ, صحیح اندر_fd, صحیح برآمد_fd, صحیح nonblock)
{
	(خالی)ssh; (خالی)host_arg; (خالی)پورٹ;
	(خالی)اندر_fd; (خالی)برآمد_fd; (خالی)nonblock;
	واپس -1;
}

صحیح
__wrap_channel_request_remote_forwarding(ساخت ssh *ssh, ساخت Forward *fwd)
{
	(خالی)ssh; (خالی)fwd;
	واپس 0;
}

صحیح
__wrap_channel_request_rforward_cancel(ساخت ssh *ssh, ساخت Forward *fwd)
{
	(خالی)ssh; (خالی)fwd;
	واپس 0;
}

صحیح
__wrap_channel_cancel_lport_listener(ساخت ssh *ssh, ساخت Forward *fwd,
    صحیح cport, ساخت ForwardOptions *fwd_opts)
{
	(خالی)ssh; (خالی)fwd; (خالی)cport; (خالی)fwd_opts;
	واپس 0;
}

ساکن ساخت sshkey *
بھرو_نجی(ثابت حرف *str)
{
	ساخت sshbuf *b = sshbuf_from(str, لڑی_لمبائی(str));
	ساخت sshkey *k = تہی;
	اگر (b == تہی || sshkey_parse_نجی_fileblob(b, "", &k, تہی) != 0)
		abort();
	sshbuf_free(b);
	واپس k;
}

ساکن ساخت sshkey *
بھرو_عوامی(ثابت حرف *str)
{
	حرف *tmp, *cp;
	ساخت sshkey *k = sshkey_new(کلید_UNSPEC);
	اگر (k == تہی)
		abort();
	tmp = cp = strdup(str);
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	واپس k;
}

ساکن صحیح
pump(ساخت ssh *from, ساخت ssh *مقصد, سائز_t *transferred)
{
	ثابت u_char *buf;
	سائز_t len;
	u_char type;
	صحیح r;
	*transferred = 0;
	اگر ((r = ssh_packet_اگلا(from, &type)) != 0)
		واپس r;
	buf = ssh_output_ptr(from, &len);
	اگر (len == 0)
		واپس 0;
	اگر ((r = ssh_داخلہ_append(مقصد, buf, len)) != 0)
		واپس r;
	اگر ((r = ssh_output_consume(from, len)) != 0)
		واپس r;
	*transferred = len;
	واپس 0;
}

ساکن صحیح
تسلسل_kex(ساخت ssh *client, ساخت ssh *server)
{
	صحیح r;
	سائز_t cn, sn;
	برائے (صحیح i = 0; i < 100; i++) {
		اگر ((r = pump(server, client, &sn)) != 0) واپس r;
		اگر ((r = pump(client, server, &cn)) != 0) واپس r;
		اگر (server->kex->مکمل && client->kex->مکمل)
			واپس 0;
		اگر (cn == 0 && sn == 0)
			واپس SSH_ERR_PROTOCOL_ERROR;
	}
	واپس SSH_ERR_PROTOCOL_ERROR;
}

#شامل "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
ساکن صحیح mux_master_read_cb(ساخت ssh *ssh, Channel *c);

#شامل "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
خالی *
client_new_escape_filter_ctx(صحیح escape_char)
{
	(خالی)escape_char;
	واپس تہی;
}

خالی
client_رجسٹر_global_confirm(global_confirm_cb *cb, خالی *ctx)
{
	(خالی)cb; (خالی)ctx;
}

خالی
client_expect_confirm(ساخت ssh *ssh, صحیح id, ثابت حرف *reason,
    شمار confirm_action action)
{
	(خالی)ssh; (خالی)id; (خالی)reason; (خالی)action;
}

خالی
client_channel_request_agent_forwarding(ساخت ssh *ssh, صحیح chanid)
{
	(خالی)ssh; (خالی)chanid;
}

خالی
client_stop_mux(خالی)
{
}

صحیح
client_simple_escape_filter(ساخت ssh *ssh, Channel *c, حرف *buf, صحیح len)
{
	(خالی)ssh; (خالی)c; (خالی)buf; (خالی)len;
	واپس 0;
}

خالی
client_filter_cleanup(ساخت ssh *ssh, صحیح cid, خالی *ctx)
{
	(خالی)ssh; (خالی)cid; (خالی)ctx;
}

صحیح
client_x11_get_proto(ساخت ssh *ssh, ثابت حرف *display,
    ثابت حرف *xauth_راستہ, u_int trusted, u_int timeout,
    حرف **_proto, حرف **ڈیٹا_2)
{
	(خالی)ssh; (خالی)display; (خالی)xauth_راستہ;
	(خالی)trusted; (خالی)timeout;
	اگر (_proto != تہی)
		*_proto = تہی;
	اگر (ڈیٹا_2 != تہی)
		*ڈیٹا_2 = تہی;
	واپس 0;
}

خالی
client_session2_تیاری(ساخت ssh *ssh, صحیح id, صحیح want_tty, صحیح want_subsys,
    ثابت حرف *رکن, ساخت termios *tiop, صحیح اندر_fd, ساخت sshbuf *cmd,
    حرف **env)
{
	(خالی)ssh; (خالی)id; (خالی)want_tty; (خالی)want_subsys;
	(خالی)رکن; (خالی)tiop; (خالی)اندر_fd; (خالی)cmd; (خالی)env;
}

خالی
enter_raw_منوال(صحیح quiet)
{
	(خالی)quiet;
}

خالی
leave_raw_منوال(صحیح quiet)
{
	(خالی)quiet;
}

ساکن ساخت ssh *g_client = تہی;
ساکن ساخت ssh *g_server = تہی;
ساکن صحیح g_init = 0;
ساکن صحیح g_mux_channel_id = -1;
ساکن ساخت sshbuf *g_mux_اندر = تہی;
ساکن ساخت sshbuf *g_mux_برآمد = تہی;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
ساکن خالی
fuzz_drive_mux(ساخت ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	صحیح r;
	ثابت u_char *body;
	سائز_t blen;
	ساخت mux_master_state *state;

	state = (ساخت mux_master_state *)c->mux_ctx;
	اگر (state == تہی)
		واپس;

	sshbuf_reset(g_mux_اندر);
	sshbuf_reset(g_mux_برآمد);

	اگر ((r = sshbuf_get_string_براہ_راست(c->داخلہ, &body, &blen)) != 0)
		واپس;
	اگر (sshbuf_put(g_mux_اندر, body, blen) != 0)
		واپس;
	اگر ((r = sshbuf_get_u32(g_mux_اندر, &type)) != 0)
		واپس;

	اگر (type == MUX_پیغام_HELLO) {
		rid = 0;
	} ورنہ {
		اگر (!state->hello_rcvd)
			واپس;
		اگر ((r = sshbuf_get_u32(g_mux_اندر, &rid)) != 0)
			واپس;
	}

	برائے (i = 0; mux_master_handlers[i].handler != تہی; i++) {
		اگر (type == mux_master_handlers[i].type) {
			(خالی)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_اندر, g_mux_برآمد);
			توڑو;
		}
	}
}

ساکن صحیح
init_once(خالی)
{
	اگر (g_init)
		واپس 0;
	اشارہ(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, حجم(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_راستہ = (حرف *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_نقاب = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (حرف *)"fuzz";

	ساخت sshkey *priv = بھرو_نجی(PRIV_ED25519);
	ساخت sshkey *pub = بھرو_عوامی(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحیح i;
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			p = keyname;
		ورنہ اگر (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ورنہ اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ورنہ اگر (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ساخت kex_params kp;
	حافظہ_نقل(kp.proposal, proposal, حجم(proposal));

	اگر (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		واپس -1;
	اگر (ssh_جوڑو_hostkey(g_server, priv) != 0 ||
	    ssh_جوڑو_hostkey(g_client, pub) != 0)
		واپس -1;
	اگر (تسلسل_kex(g_client, g_server) != 0)
		واپس -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	اگر (c == تہی)
		واپس -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	ساخت mux_master_state *st = (ساخت mux_master_state *)c->mux_ctx;
	اگر (st != تہی)
		st->hello_rcvd = 1;

	اگر ((g_mux_اندر = sshbuf_new()) == تہی ||
	    (g_mux_برآمد = sshbuf_new()) == تہی)
		واپس -1;

	آزاد(keyname);
	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	واپس 0;
}

خالی
fuzz_mux_one(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (init_once() != 0)
		واپس;
	اگر (سائز > 65000)
		واپس;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	اگر (c == تہی || c->mux_ctx == تہی || c->داخلہ == تہی)
		واپس;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->داخلہ);
	u_char hdr[4];
	hdr[0] = (u_char)(سائز >> 24);
	hdr[1] = (u_char)(سائز >> 16);
	hdr[2] = (u_char)(سائز >> 8);
	hdr[3] = (u_char)سائز;
	اگر (sshbuf_put(c->داخلہ, hdr, 4) != 0)
		واپس;
	اگر (سائز > 0 && sshbuf_put(c->داخلہ, ڈیٹا, سائز) != 0)
		واپس;

	اندر_fuzz = 1;
	اگر (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	اندر_fuzz = 0;

	/* Drain anything the handler enqueued. */
	اگر (c->output != تہی)
		sshbuf_reset(c->output);
}
