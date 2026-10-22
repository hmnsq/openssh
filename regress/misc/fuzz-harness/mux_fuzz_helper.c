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

#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"

/* Externs that mux.c declares. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା tty_flag = 0;
Options options;
ଅକ୍ଷର *host = ଖାଲି;
ସଂରଚନା sshbuf *command = ଖାଲି;
ଅସ୍ଥିର sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__lsan_is_turned_off(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର jmp_buf fuzz_env;
ସ୍ଥିର ଅସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fuzz = 0;

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ଶୂନ୍ୟ
__wrap_ssh_packet_disconnect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)fmt;
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_sshpkt_fatal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)fmt;
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_ask_permission(ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	(ଶୂନ୍ୟ)fmt;
	ଫେରନ୍ତୁ 1;
}

/* Socket-opening side effects we must neutralise. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_channel_setup_local_fwd_listener(ସଂରଚନା ssh *ssh,
    ସଂରଚନା Forward *fwd, ସଂରଚନା ForwardOptions *fwd_opts)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)fwd; (ଶୂନ୍ୟ)fwd_opts;
	ଫେରନ୍ତୁ 1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_channel_connect_stdio_fwd(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *host_arg,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା port, ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା out_fd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nonblock)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)host_arg; (ଶୂନ୍ୟ)port;
	(ଶୂନ୍ୟ)in_fd; (ଶୂନ୍ୟ)out_fd; (ଶୂନ୍ୟ)nonblock;
	ଫେରନ୍ତୁ -1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_channel_request_remote_forwarding(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)fwd;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_channel_request_rforward_cancel(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)fwd;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_channel_cancel_lport_listener(ସଂରଚନା ssh *ssh, ସଂରଚନା Forward *fwd,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା cport, ସଂରଚନା ForwardOptions *fwd_opts)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)fwd; (ଶୂନ୍ୟ)cport; (ଶୂନ୍ୟ)fwd_opts;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_private(ଅଚଳ ଅକ୍ଷର *str)
{
	ସଂରଚନା sshbuf *b = sshbuf_from(str, strlen(str));
	ସଂରଚନା sshkey *k = ଖାଲି;
	ଯଦି (b == ଖାଲି || sshkey_parse_private_fileblob(b, "", &k, ଖାଲି) != 0)
		abort();
	sshbuf_free(b);
	ଫେରନ୍ତୁ k;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_public(ଅଚଳ ଅକ୍ଷର *str)
{
	ଅକ୍ଷର *tmp, *cp;
	ସଂରଚନା sshkey *k = sshkey_new(ଚାବି_UNSPEC);
	ଯଦି (k == ଖାଲି)
		abort();
	tmp = cp = strdup(str);
	ଯଦି (sshkey_read(k, &cp) != 0)
		abort();
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ k;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pump(ସଂରଚନା ssh *from, ସଂରଚନା ssh *to, size_t *transferred)
{
	ଅଚଳ u_char *buf;
	size_t len;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	*transferred = 0;
	ଯଦି ((r = ssh_packet_next(from, &type)) != 0)
		ଫେରନ୍ତୁ r;
	buf = ssh_output_ptr(from, &len);
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((r = ssh_ନିବେଶ_append(to, buf, len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = ssh_output_consume(from, len)) != 0)
		ଫେରନ୍ତୁ r;
	*transferred = len;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
run_kex(ସଂରଚନା ssh *client, ସଂରଚନା ssh *server)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t cn, sn;
	ପାଇଁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା i = 0; i < 100; i++) {
		ଯଦି ((r = pump(server, client, &sn)) != 0) ଫେରନ୍ତୁ r;
		ଯଦି ((r = pump(client, server, &cn)) != 0) ଫେରନ୍ତୁ r;
		ଯଦି (server->kex->done && client->kex->done)
			ଫେରନ୍ତୁ 0;
		ଯଦି (cn == 0 && sn == 0)
			ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
	}
	ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
}

#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା mux_master_read_cb(ସଂରଚନା ssh *ssh, Channel *c);

#ଅନ୍ତର୍ଭାଵ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
ଶୂନ୍ୟ *
client_new_escape_filter_ctx(ପୂର୍ଣ୍ଣସଂଖ୍ୟା escape_char)
{
	(ଶୂନ୍ୟ)escape_char;
	ଫେରନ୍ତୁ ଖାଲି;
}

ଶୂନ୍ୟ
client_register_global_confirm(global_confirm_cb *cb, ଶୂନ୍ୟ *ctx)
{
	(ଶୂନ୍ୟ)cb; (ଶୂନ୍ୟ)ctx;
}

ଶୂନ୍ୟ
client_expect_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ଅଚଳ ଅକ୍ଷର *reason,
    ଗଣନା confirm_action action)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)id; (ଶୂନ୍ୟ)reason; (ଶୂନ୍ୟ)action;
}

ଶୂନ୍ୟ
client_channel_request_agent_forwarding(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା chanid)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)chanid;
}

ଶୂନ୍ୟ
client_stop_mux(ଶୂନ୍ୟ)
{
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
client_simple_escape_filter(ସଂରଚନା ssh *ssh, Channel *c, ଅକ୍ଷର *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା len)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)c; (ଶୂନ୍ୟ)buf; (ଶୂନ୍ୟ)len;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
client_filter_cleanup(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା cid, ଶୂନ୍ୟ *ctx)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)cid; (ଶୂନ୍ୟ)ctx;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
client_x11_get_proto(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *display,
    ଅଚଳ ଅକ୍ଷର *xauth_path, u_int trusted, u_int timeout,
    ଅକ୍ଷର **_proto, ଅକ୍ଷର **_data)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)display; (ଶୂନ୍ୟ)xauth_path;
	(ଶୂନ୍ୟ)trusted; (ଶୂନ୍ୟ)timeout;
	ଯଦି (_proto != ଖାଲି)
		*_proto = ଖାଲି;
	ଯଦି (_data != ଖାଲି)
		*_data = ଖାଲି;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
client_session2_setup(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_tty, ପୂର୍ଣ୍ଣସଂଖ୍ୟା want_subsys,
    ଅଚଳ ଅକ୍ଷର *term, ସଂରଚନା termios *tiop, ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fd, ସଂରଚନା sshbuf *cmd,
    ଅକ୍ଷର **env)
{
	(ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)id; (ଶୂନ୍ୟ)want_tty; (ଶୂନ୍ୟ)want_subsys;
	(ଶୂନ୍ୟ)term; (ଶୂନ୍ୟ)tiop; (ଶୂନ୍ୟ)in_fd; (ଶୂନ୍ୟ)cmd; (ଶୂନ୍ୟ)env;
}

ଶୂନ୍ୟ
enter_raw_mode(ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet)
{
	(ଶୂନ୍ୟ)quiet;
}

ଶୂନ୍ୟ
leave_raw_mode(ପୂର୍ଣ୍ଣସଂଖ୍ୟା quiet)
{
	(ଶୂନ୍ୟ)quiet;
}

ସ୍ଥିର ସଂରଚନା ssh *g_client = ଖାଲି;
ସ୍ଥିର ସଂରଚନା ssh *g_server = ଖାଲି;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_init = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_mux_channel_id = -1;
ସ୍ଥିର ସଂରଚନା sshbuf *g_mux_in = ଖାଲି;
ସ୍ଥିର ସଂରଚନା sshbuf *g_mux_out = ଖାଲି;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
ସ୍ଥିର ଶୂନ୍ୟ
fuzz_drive_mux(ସଂରଚନା ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ u_char *body;
	size_t blen;
	ସଂରଚନା mux_master_state *state;

	state = (ସଂରଚନା mux_master_state *)c->mux_ctx;
	ଯଦି (state == ଖାଲି)
		ଫେରନ୍ତୁ;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	ଯଦି ((r = sshbuf_get_string_direct(c->ନିବେଶ, &body, &blen)) != 0)
		ଫେରନ୍ତୁ;
	ଯଦି (sshbuf_put(g_mux_in, body, blen) != 0)
		ଫେରନ୍ତୁ;
	ଯଦି ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		ଫେରନ୍ତୁ;

	ଯଦି (type == MUX_ସନ୍ଦେଶ_HELLO) {
		rid = 0;
	} ଅନ୍ୟଥା {
		ଯଦି (!state->hello_rcvd)
			ଫେରନ୍ତୁ;
		ଯଦି ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			ଫେରନ୍ତୁ;
	}

	ପାଇଁ (i = 0; mux_master_handlers[i].handler != ଖାଲି; i++) {
		ଯଦି (type == mux_master_handlers[i].type) {
			(ଶୂନ୍ୟ)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			ଭାଙ୍ଗ;
		}
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
init_once(ଶୂନ୍ୟ)
{
	ଯଦି (g_init)
		ଫେରନ୍ତୁ 0;
	ସଙ୍କେତ(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, ଆକାର(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (ଅକ୍ଷର *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (ଅକ୍ଷର *)"fuzz";

	ସଂରଚନା sshkey *priv = load_private(PRIV_ED25519);
	ସଂରଚନା sshkey *pub = load_public(PUB_ED25519);
	ଅକ୍ଷର *keyname = xstrdup(sshkey_ssh_name(priv));

	ଅଚଳ ଅକ୍ଷର *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ଅକ୍ଷର *proposal[PROPOSAL_MAX] = { 0 };
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ଅଚଳ ଅକ୍ଷର *p = defaults[i];
		ଯଦି (i == PROPOSAL_SERVER_HOST_ଚାବି_ALGS)
			p = keyname;
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ସଂରଚନା kex_params kp;
	memcpy(kp.proposal, proposal, ଆକାର(proposal));

	ଯଦି (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (run_kex(g_client, g_server) != 0)
		ଫେରନ୍ତୁ -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	ଯଦି (c == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	ସଂରଚନା mux_master_state *st = (ସଂରଚନା mux_master_state *)c->mux_ctx;
	ଯଦି (st != ଖାଲି)
		st->hello_rcvd = 1;

	ଯଦି ((g_mux_in = sshbuf_new()) == ଖାଲି ||
	    (g_mux_out = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	ମୁକ୍ତ(keyname);
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(proposal[i]);
	g_init = 1;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
fuzz_mux_one(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (init_once() != 0)
		ଫେରନ୍ତୁ;
	ଯଦି (size > 65000)
		ଫେରନ୍ତୁ;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	ଯଦି (c == ଖାଲି || c->mux_ctx == ଖାଲି || c->ନିବେଶ == ଖାଲି)
		ଫେରନ୍ତୁ;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->ନିବେଶ);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	ଯଦି (sshbuf_put(c->ନିବେଶ, hdr, 4) != 0)
		ଫେରନ୍ତୁ;
	ଯଦି (size > 0 && sshbuf_put(c->ନିବେଶ, data, size) != 0)
		ଫେରନ୍ତୁ;

	in_fuzz = 1;
	ଯଦି (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	ଯଦି (c->output != ଖାଲି)
		sshbuf_reset(c->output);
}
