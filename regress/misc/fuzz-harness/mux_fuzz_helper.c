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

#ضمن <setjmp.h>
#ضمن <signal.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <sys/types.h>

#ضمن "log.h"
#ضمن "ssh.h"
#ضمن "ssh2.h"
#ضمن "ssh_api.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "packet.h"
#ضمن "myproposal.h"
#ضمن "kex.h"
#ضمن "xmalloc.h"
#ضمن "authfile.h"
#ضمن "misc.h"
#ضمن "channels.h"
#ضمن "readconf.h"

/* Externs that mux.c declares. */
صحيح tty_flag = 0;
Options options;
حرف *host = عدم;
بنية sshbuf *command = عدم;
متطاير sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
صحيح
__lsan_is_turned_off(فراغ)
{
	أرجع 1;
}

ساكن jmp_buf fuzz_env;
ساكن متطاير صحيح درون_fuzz = 0;

فراغ
cleanup_exit(صحيح کد)
{
	إذا (درون_fuzz)
		longjmp(fuzz_env, کد ? کد : 1);
	_exit(کد);
}

فراغ
__wrap_ssh_packet_disconnect(بنية ssh *ssh, ثابت حرف *fmt, ...)
{
	(فراغ)ssh;
	(فراغ)fmt;
	إذا (درون_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

صحيح
__wrap_sshpkt_fatal(بنية ssh *ssh, صحيح r, ثابت حرف *fmt, ...)
{
	(فراغ)ssh;
	(فراغ)fmt;
	إذا (درون_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
صحيح
__wrap_ask_permission(ثابت حرف *fmt, ...)
{
	(فراغ)fmt;
	أرجع 1;
}

/* Socket-opening side effects we must neutralise. */
صحيح
__wrap_channel_setup_local_fwd_listener(بنية ssh *ssh,
    بنية Forward *fwd, بنية ForwardOptions *fwd_opts)
{
	(فراغ)ssh; (فراغ)fwd; (فراغ)fwd_opts;
	أرجع 1;
}

صحيح
__wrap_channel_connect_stdio_fwd(بنية ssh *ssh, ثابت حرف *host_arg,
    صحيح پورت, صحيح درون_fd, صحيح بیرون_fd, صحيح nonblock)
{
	(فراغ)ssh; (فراغ)host_arg; (فراغ)پورت;
	(فراغ)درون_fd; (فراغ)بیرون_fd; (فراغ)nonblock;
	أرجع -1;
}

صحيح
__wrap_channel_request_remote_forwarding(بنية ssh *ssh, بنية Forward *fwd)
{
	(فراغ)ssh; (فراغ)fwd;
	أرجع 0;
}

صحيح
__wrap_channel_request_rforward_cancel(بنية ssh *ssh, بنية Forward *fwd)
{
	(فراغ)ssh; (فراغ)fwd;
	أرجع 0;
}

صحيح
__wrap_channel_cancel_lport_listener(بنية ssh *ssh, بنية Forward *fwd,
    صحيح cport, بنية ForwardOptions *fwd_opts)
{
	(فراغ)ssh; (فراغ)fwd; (فراغ)cport; (فراغ)fwd_opts;
	أرجع 0;
}

ساكن بنية sshkey *
بارگیری_خصوصی(ثابت حرف *str)
{
	بنية sshbuf *b = sshbuf_from(str, طول_رشته(str));
	بنية sshkey *k = عدم;
	إذا (b == عدم || sshkey_parse_خصوصی_fileblob(b, "", &k, عدم) != 0)
		abort();
	sshbuf_free(b);
	أرجع k;
}

ساكن بنية sshkey *
بارگیری_عمومی(ثابت حرف *str)
{
	حرف *tmp, *cp;
	بنية sshkey *k = sshkey_new(کلید_UNSPEC);
	إذا (k == عدم)
		abort();
	tmp = cp = strdup(str);
	إذا (sshkey_read(k, &cp) != 0)
		abort();
	حرر(tmp);
	أرجع k;
}

ساكن صحيح
pump(بنية ssh *from, بنية ssh *مقصد, اندازه_t *transferred)
{
	ثابت u_char *buf;
	اندازه_t len;
	u_char type;
	صحيح r;
	*transferred = 0;
	إذا ((r = ssh_packet_بعدی(from, &type)) != 0)
		أرجع r;
	buf = ssh_output_ptr(from, &len);
	إذا (len == 0)
		أرجع 0;
	إذا ((r = ssh_درون_داد_append(مقصد, buf, len)) != 0)
		أرجع r;
	إذا ((r = ssh_output_consume(from, len)) != 0)
		أرجع r;
	*transferred = len;
	أرجع 0;
}

ساكن صحيح
پیاپی_kex(بنية ssh *client, بنية ssh *server)
{
	صحيح r;
	اندازه_t cn, sn;
	لكل (صحيح i = 0; i < 100; i++) {
		إذا ((r = pump(server, client, &sn)) != 0) أرجع r;
		إذا ((r = pump(client, server, &cn)) != 0) أرجع r;
		إذا (server->kex->انجامشده && client->kex->انجامشده)
			أرجع 0;
		إذا (cn == 0 && sn == 0)
			أرجع SSH_ERR_PROTOCOL_ERROR;
	}
	أرجع SSH_ERR_PROTOCOL_ERROR;
}

#ضمن "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
ساكن صحيح mux_master_read_cb(بنية ssh *ssh, Channel *c);

#ضمن "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
فراغ *
client_new_escape_filter_ctx(صحيح escape_char)
{
	(فراغ)escape_char;
	أرجع عدم;
}

فراغ
client_ثبات_global_confirm(global_confirm_cb *cb, فراغ *ctx)
{
	(فراغ)cb; (فراغ)ctx;
}

فراغ
client_expect_confirm(بنية ssh *ssh, صحيح id, ثابت حرف *reason,
    تعداد confirm_action action)
{
	(فراغ)ssh; (فراغ)id; (فراغ)reason; (فراغ)action;
}

فراغ
client_channel_request_agent_forwarding(بنية ssh *ssh, صحيح chanid)
{
	(فراغ)ssh; (فراغ)chanid;
}

فراغ
client_stop_mux(فراغ)
{
}

صحيح
client_simple_escape_filter(بنية ssh *ssh, Channel *c, حرف *buf, صحيح len)
{
	(فراغ)ssh; (فراغ)c; (فراغ)buf; (فراغ)len;
	أرجع 0;
}

فراغ
client_filter_cleanup(بنية ssh *ssh, صحيح cid, فراغ *ctx)
{
	(فراغ)ssh; (فراغ)cid; (فراغ)ctx;
}

صحيح
client_x11_get_proto(بنية ssh *ssh, ثابت حرف *display,
    ثابت حرف *xauth_مسیر, u_int trusted, u_int timeout,
    حرف **_proto, حرف **داده_2)
{
	(فراغ)ssh; (فراغ)display; (فراغ)xauth_مسیر;
	(فراغ)trusted; (فراغ)timeout;
	إذا (_proto != عدم)
		*_proto = عدم;
	إذا (داده_2 != عدم)
		*داده_2 = عدم;
	أرجع 0;
}

فراغ
client_session2_راهاندازی(بنية ssh *ssh, صحيح id, صحيح want_tty, صحيح want_subsys,
    ثابت حرف *جمله, بنية termios *tiop, صحيح درون_fd, بنية sshbuf *cmd,
    حرف **env)
{
	(فراغ)ssh; (فراغ)id; (فراغ)want_tty; (فراغ)want_subsys;
	(فراغ)جمله; (فراغ)tiop; (فراغ)درون_fd; (فراغ)cmd; (فراغ)env;
}

فراغ
enter_raw_نما(صحيح quiet)
{
	(فراغ)quiet;
}

فراغ
leave_raw_نما(صحيح quiet)
{
	(فراغ)quiet;
}

ساكن بنية ssh *g_client = عدم;
ساكن بنية ssh *g_server = عدم;
ساكن صحيح g_init = 0;
ساكن صحيح g_mux_channel_id = -1;
ساكن بنية sshbuf *g_mux_درون = عدم;
ساكن بنية sshbuf *g_mux_بیرون = عدم;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
ساكن فراغ
fuzz_drive_mux(بنية ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	صحيح r;
	ثابت u_char *body;
	اندازه_t blen;
	بنية mux_master_state *state;

	state = (بنية mux_master_state *)c->mux_ctx;
	إذا (state == عدم)
		أرجع;

	sshbuf_reset(g_mux_درون);
	sshbuf_reset(g_mux_بیرون);

	إذا ((r = sshbuf_get_string_مستقیم(c->درون_داد, &body, &blen)) != 0)
		أرجع;
	إذا (sshbuf_put(g_mux_درون, body, blen) != 0)
		أرجع;
	إذا ((r = sshbuf_get_u32(g_mux_درون, &type)) != 0)
		أرجع;

	إذا (type == MUX_پیام_HELLO) {
		rid = 0;
	} وإلا {
		إذا (!state->hello_rcvd)
			أرجع;
		إذا ((r = sshbuf_get_u32(g_mux_درون, &rid)) != 0)
			أرجع;
	}

	لكل (i = 0; mux_master_handlers[i].handler != عدم; i++) {
		إذا (type == mux_master_handlers[i].type) {
			(فراغ)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_درون, g_mux_بیرون);
			اكسر;
		}
	}
}

ساكن صحيح
init_once(فراغ)
{
	إذا (g_init)
		أرجع 0;
	إشارة(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, حجم(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_مسیر = (حرف *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_ماسک = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (حرف *)"fuzz";

	بنية sshkey *priv = بارگیری_خصوصی(PRIV_ED25519);
	بنية sshkey *pub = بارگیری_عمومی(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحيح i;
	لكل (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		إذا (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			p = keyname;
		وإلا إذا (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		وإلا إذا (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		وإلا إذا (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	بنية kex_params kp;
	کپی_حافظه(kp.proposal, proposal, حجم(proposal));

	إذا (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		أرجع -1;
	إذا (ssh_جمع_کن_hostkey(g_server, priv) != 0 ||
	    ssh_جمع_کن_hostkey(g_client, pub) != 0)
		أرجع -1;
	إذا (پیاپی_kex(g_client, g_server) != 0)
		أرجع -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	إذا (c == عدم)
		أرجع -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	بنية mux_master_state *st = (بنية mux_master_state *)c->mux_ctx;
	إذا (st != عدم)
		st->hello_rcvd = 1;

	إذا ((g_mux_درون = sshbuf_new()) == عدم ||
	    (g_mux_بیرون = sshbuf_new()) == عدم)
		أرجع -1;

	حرر(keyname);
	لكل (i = 0; i < PROPOSAL_MAX; i++)
		حرر(proposal[i]);
	g_init = 1;
	أرجع 0;
}

فراغ
fuzz_mux_one(ثابت uint8_t *داده, اندازه_t اندازه)
{
	إذا (init_once() != 0)
		أرجع;
	إذا (اندازه > 65000)
		أرجع;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	إذا (c == عدم || c->mux_ctx == عدم || c->درون_داد == عدم)
		أرجع;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->درون_داد);
	u_char hdr[4];
	hdr[0] = (u_char)(اندازه >> 24);
	hdr[1] = (u_char)(اندازه >> 16);
	hdr[2] = (u_char)(اندازه >> 8);
	hdr[3] = (u_char)اندازه;
	إذا (sshbuf_put(c->درون_داد, hdr, 4) != 0)
		أرجع;
	إذا (اندازه > 0 && sshbuf_put(c->درون_داد, داده, اندازه) != 0)
		أرجع;

	درون_fuzz = 1;
	إذا (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	درون_fuzz = 0;

	/* Drain anything the handler enqueued. */
	إذا (c->output != عدم)
		sshbuf_reset(c->output);
}
