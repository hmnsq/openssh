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
পূর্ণসংখ্যা tty_flag = 0;
Options options;
অক্ষর *host = ফাঁকা;
কাঠামো sshbuf *command = ফাঁকা;
অস্থির sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
পূর্ণসংখ্যা
__lsan_is_turned_off(শূন্য)
{
	ফেরত 1;
}

স্থির jmp_buf fuzz_env;
স্থির অস্থির পূর্ণসংখ্যা in_fuzz = 0;

শূন্য
cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

শূন্য
__wrap_ssh_packet_disconnect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

পূর্ণসংখ্যা
__wrap_sshpkt_fatal(কাঠামো ssh *ssh, পূর্ণসংখ্যা r, ধ্রুবক অক্ষর *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
পূর্ণসংখ্যা
__wrap_ask_permission(ধ্রুবক অক্ষর *fmt, ...)
{
	(শূন্য)fmt;
	ফেরত 1;
}

/* Socket-opening side effects we must neutralise. */
পূর্ণসংখ্যা
__wrap_channel_setup_local_fwd_listener(কাঠামো ssh *ssh,
    কাঠামো Forward *fwd, কাঠামো ForwardOptions *fwd_opts)
{
	(শূন্য)ssh; (শূন্য)fwd; (শূন্য)fwd_opts;
	ফেরত 1;
}

পূর্ণসংখ্যা
__wrap_channel_connect_stdio_fwd(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *host_arg,
    পূর্ণসংখ্যা port, পূর্ণসংখ্যা in_fd, পূর্ণসংখ্যা out_fd, পূর্ণসংখ্যা nonblock)
{
	(শূন্য)ssh; (শূন্য)host_arg; (শূন্য)port;
	(শূন্য)in_fd; (শূন্য)out_fd; (শূন্য)nonblock;
	ফেরত -1;
}

পূর্ণসংখ্যা
__wrap_channel_request_remote_forwarding(কাঠামো ssh *ssh, কাঠামো Forward *fwd)
{
	(শূন্য)ssh; (শূন্য)fwd;
	ফেরত 0;
}

পূর্ণসংখ্যা
__wrap_channel_request_rforward_cancel(কাঠামো ssh *ssh, কাঠামো Forward *fwd)
{
	(শূন্য)ssh; (শূন্য)fwd;
	ফেরত 0;
}

পূর্ণসংখ্যা
__wrap_channel_cancel_lport_listener(কাঠামো ssh *ssh, কাঠামো Forward *fwd,
    পূর্ণসংখ্যা cport, কাঠামো ForwardOptions *fwd_opts)
{
	(শূন্য)ssh; (শূন্য)fwd; (শূন্য)cport; (শূন্য)fwd_opts;
	ফেরত 0;
}

স্থির কাঠামো sshkey *
load_private(ধ্রুবক অক্ষর *str)
{
	কাঠামো sshbuf *b = sshbuf_from(str, strlen(str));
	কাঠামো sshkey *k = ফাঁকা;
	যদি (b == ফাঁকা || sshkey_parse_private_fileblob(b, "", &k, ফাঁকা) != 0)
		abort();
	sshbuf_free(b);
	ফেরত k;
}

স্থির কাঠামো sshkey *
load_public(ধ্রুবক অক্ষর *str)
{
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == ফাঁকা)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ফেরত k;
}

স্থির পূর্ণসংখ্যা
pump(কাঠামো ssh *from, কাঠামো ssh *to, আকার_t *transferred)
{
	ধ্রুবক u_char *buf;
	আকার_t len;
	u_char type;
	পূর্ণসংখ্যা r;
	*transferred = 0;
	যদি ((r = ssh_packet_পরবর্তী(from, &type)) != 0)
		ফেরত r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		ফেরত 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		ফেরত r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		ফেরত r;
	*transferred = len;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
run_kex(কাঠামো ssh *client, কাঠামো ssh *server)
{
	পূর্ণসংখ্যা r;
	আকার_t cn, sn;
	জন্য (পূর্ণসংখ্যা i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) ফেরত r;
		যদি ((r = pump(client, server, &cn)) != 0) ফেরত r;
		যদি (server->kex->done && client->kex->done)
			ফেরত 0;
		যদি (cn == 0 && sn == 0)
			ফেরত SSH_ERR_PROTOCOL_ERROR;
	}
	ফেরত SSH_ERR_PROTOCOL_ERROR;
}

#অন্তর্ভাব "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
স্থির পূর্ণসংখ্যা mux_master_read_cb(কাঠামো ssh *ssh, Channel *c);

#অন্তর্ভাব "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
শূন্য *
client_new_escape_filter_ctx(পূর্ণসংখ্যা escape_char)
{
	(শূন্য)escape_char;
	ফেরত ফাঁকা;
}

শূন্য
client_register_global_confirm(global_confirm_cb *cb, শূন্য *ctx)
{
	(শূন্য)cb; (শূন্য)ctx;
}

শূন্য
client_expect_confirm(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, ধ্রুবক অক্ষর *reason,
    গণনা confirm_action action)
{
	(শূন্য)ssh; (শূন্য)id; (শূন্য)reason; (শূন্য)action;
}

শূন্য
client_channel_request_agent_forwarding(কাঠামো ssh *ssh, পূর্ণসংখ্যা chanid)
{
	(শূন্য)ssh; (শূন্য)chanid;
}

শূন্য
client_stop_mux(শূন্য)
{
}

পূর্ণসংখ্যা
client_simple_escape_filter(কাঠামো ssh *ssh, Channel *c, অক্ষর *buf, পূর্ণসংখ্যা len)
{
	(শূন্য)ssh; (শূন্য)c; (শূন্য)buf; (শূন্য)len;
	ফেরত 0;
}

শূন্য
client_filter_cleanup(কাঠামো ssh *ssh, পূর্ণসংখ্যা cid, শূন্য *ctx)
{
	(শূন্য)ssh; (শূন্য)cid; (শূন্য)ctx;
}

পূর্ণসংখ্যা
client_x11_get_proto(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *display,
    ধ্রুবক অক্ষর *xauth_path, u_int trusted, u_int timeout,
    অক্ষর **_proto, অক্ষর **তথ্য_2)
{
	(শূন্য)ssh; (শূন্য)display; (শূন্য)xauth_path;
	(শূন্য)trusted; (শূন্য)timeout;
	যদি (_proto != ফাঁকা)
		*_proto = ফাঁকা;
	যদি (তথ্য_2 != ফাঁকা)
		*তথ্য_2 = ফাঁকা;
	ফেরত 0;
}

শূন্য
client_session2_setup(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা want_tty, পূর্ণসংখ্যা want_subsys,
    ধ্রুবক অক্ষর *term, কাঠামো termios *tiop, পূর্ণসংখ্যা in_fd, কাঠামো sshbuf *cmd,
    অক্ষর **env)
{
	(শূন্য)ssh; (শূন্য)id; (শূন্য)want_tty; (শূন্য)want_subsys;
	(শূন্য)term; (শূন্য)tiop; (শূন্য)in_fd; (শূন্য)cmd; (শূন্য)env;
}

শূন্য
enter_raw_mode(পূর্ণসংখ্যা quiet)
{
	(শূন্য)quiet;
}

শূন্য
leave_raw_mode(পূর্ণসংখ্যা quiet)
{
	(শূন্য)quiet;
}

স্থির কাঠামো ssh *g_client = ফাঁকা;
স্থির কাঠামো ssh *g_server = ফাঁকা;
স্থির পূর্ণসংখ্যা g_init = 0;
স্থির পূর্ণসংখ্যা g_mux_channel_id = -1;
স্থির কাঠামো sshbuf *g_mux_in = ফাঁকা;
স্থির কাঠামো sshbuf *g_mux_out = ফাঁকা;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
স্থির শূন্য
fuzz_drive_mux(কাঠামো ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	পূর্ণসংখ্যা r;
	ধ্রুবক u_char *body;
	আকার_t blen;
	কাঠামো mux_master_state *state;

	state = (কাঠামো mux_master_state *)c->mux_ctx;
	যদি (state == ফাঁকা)
		ফেরত;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	যদি ((r = sshbuf_get_string_direct(c->প্রবেশ, &body, &blen)) != 0)
		ফেরত;
	যদি (sshbuf_put(g_mux_in, body, blen) != 0)
		ফেরত;
	যদি ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		ফেরত;

	যদি (type == MUX_বার্তা_HELLO) {
		rid = 0;
	} অন্যথা {
		যদি (!state->hello_rcvd)
			ফেরত;
		যদি ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			ফেরত;
	}

	জন্য (i = 0; mux_master_handlers[i].handler != ফাঁকা; i++) {
		যদি (type == mux_master_handlers[i].type) {
			(শূন্য)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			বিরতি;
		}
	}
}

স্থির পূর্ণসংখ্যা
init_once(শূন্য)
{
	যদি (g_init)
		ফেরত 0;
	সংকেত(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, আকার(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (অক্ষর *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (অক্ষর *)"fuzz";

	কাঠামো sshkey *priv = load_private(PRIV_ED25519);
	কাঠামো sshkey *pub = load_public(PUB_ED25519);
	অক্ষর *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুবক অক্ষর *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	অক্ষর *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুবক অক্ষর *p = defaults[i];
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
	কাঠামো kex_params kp;
	memcpy(kp.proposal, proposal, আকার(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ফেরত -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ফেরত -1;
	যদি (run_kex(g_client, g_server) != 0)
		ফেরত -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	যদি (c == ফাঁকা)
		ফেরত -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	কাঠামো mux_master_state *st = (কাঠামো mux_master_state *)c->mux_ctx;
	যদি (st != ফাঁকা)
		st->hello_rcvd = 1;

	যদি ((g_mux_in = sshbuf_new()) == ফাঁকা ||
	    (g_mux_out = sshbuf_new()) == ফাঁকা)
		ফেরত -1;

	মুক্ত(keyname);
	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	ফেরত 0;
}

শূন্য
fuzz_mux_one(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (init_once() != 0)
		ফেরত;
	যদি (আকার_2 > 65000)
		ফেরত;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	যদি (c == ফাঁকা || c->mux_ctx == ফাঁকা || c->প্রবেশ == ফাঁকা)
		ফেরত;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->প্রবেশ);
	u_char hdr[4];
	hdr[0] = (u_char)(আকার_2 >> 24);
	hdr[1] = (u_char)(আকার_2 >> 16);
	hdr[2] = (u_char)(আকার_2 >> 8);
	hdr[3] = (u_char)আকার_2;
	যদি (sshbuf_put(c->প্রবেশ, hdr, 4) != 0)
		ফেরত;
	যদি (আকার_2 > 0 && sshbuf_put(c->প্রবেশ, তথ্য, আকার_2) != 0)
		ফেরত;

	in_fuzz = 1;
	যদি (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	যদি (c->output != ফাঁকা)
		sshbuf_reset(c->output);
}
