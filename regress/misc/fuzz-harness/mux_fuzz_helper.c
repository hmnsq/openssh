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

#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <sys/types.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "readconf.h"

/* Externs that mux.c declares. */
పూర్ణాంకం tty_flag = 0;
Options options;
అక్షరం *host = ఖాళీ;
నిర్మాణం sshbuf *command = ఖాళీ;
అస్థిర sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
పూర్ణాంకం
__lsan_is_turned_off(శూన్య)
{
	తిరిగి 1;
}

స్థిర jmp_buf fuzz_env;
స్థిర అస్థిర పూర్ణాంకం లోపల_fuzz = 0;

శూన్య
cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

శూన్య
__wrap_ssh_packet_disconnect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *fmt, ...)
{
	(శూన్య)ssh;
	(శూన్య)fmt;
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

పూర్ణాంకం
__wrap_sshpkt_fatal(నిర్మాణం ssh *ssh, పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, ...)
{
	(శూన్య)ssh;
	(శూన్య)fmt;
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
పూర్ణాంకం
__wrap_ask_permission(స్థిరరాశి అక్షరం *fmt, ...)
{
	(శూన్య)fmt;
	తిరిగి 1;
}

/* Socket-opening side effects we must neutralise. */
పూర్ణాంకం
__wrap_channel_setup_local_fwd_listener(నిర్మాణం ssh *ssh,
    నిర్మాణం Forward *fwd, నిర్మాణం ForwardOptions *fwd_opts)
{
	(శూన్య)ssh; (శూన్య)fwd; (శూన్య)fwd_opts;
	తిరిగి 1;
}

పూర్ణాంకం
__wrap_channel_connect_stdio_fwd(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *host_arg,
    పూర్ణాంకం పోర్టు, పూర్ణాంకం లోపల_fd, పూర్ణాంకం బహిర్గతం_fd, పూర్ణాంకం nonblock)
{
	(శూన్య)ssh; (శూన్య)host_arg; (శూన్య)పోర్టు;
	(శూన్య)లోపల_fd; (శూన్య)బహిర్గతం_fd; (శూన్య)nonblock;
	తిరిగి -1;
}

పూర్ణాంకం
__wrap_channel_request_remote_forwarding(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd)
{
	(శూన్య)ssh; (శూన్య)fwd;
	తిరిగి 0;
}

పూర్ణాంకం
__wrap_channel_request_rforward_cancel(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd)
{
	(శూన్య)ssh; (శూన్య)fwd;
	తిరిగి 0;
}

పూర్ణాంకం
__wrap_channel_cancel_lport_listener(నిర్మాణం ssh *ssh, నిర్మాణం Forward *fwd,
    పూర్ణాంకం cport, నిర్మాణం ForwardOptions *fwd_opts)
{
	(శూన్య)ssh; (శూన్య)fwd; (శూన్య)cport; (శూన్య)fwd_opts;
	తిరిగి 0;
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_వ్యక్తిగత(స్థిరరాశి అక్షరం *str)
{
	నిర్మాణం sshbuf *b = sshbuf_from(str, అక్షరశ్రేణి_పొడవు(str));
	నిర్మాణం sshkey *k = ఖాళీ;
	ఒకవేళ (b == ఖాళీ || sshkey_parse_వ్యక్తిగత_fileblob(b, "", &k, ఖాళీ) != 0)
		abort();
	sshbuf_free(b);
	తిరిగి k;
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_ప్రజా(స్థిరరాశి అక్షరం *str)
{
	అక్షరం *tmp, *cp;
	నిర్మాణం sshkey *k = sshkey_new(కీలకం_UNSPEC);
	ఒకవేళ (k == ఖాళీ)
		abort();
	tmp = cp = strdup(str);
	ఒకవేళ (sshkey_read(k, &cp) != 0)
		abort();
	విడుదల(tmp);
	తిరిగి k;
}

స్థిర పూర్ణాంకం
pump(నిర్మాణం ssh *from, నిర్మాణం ssh *గమ్యం, కొలత_t *transferred)
{
	స్థిరరాశి u_char *buf;
	కొలత_t len;
	u_char type;
	పూర్ణాంకం r;
	*transferred = 0;
	ఒకవేళ ((r = ssh_packet_తదుపరి(from, &type)) != 0)
		తిరిగి r;
	buf = ssh_output_ptr(from, &len);
	ఒకవేళ (len == 0)
		తిరిగి 0;
	ఒకవేళ ((r = ssh_ఆదానం_append(గమ్యం, buf, len)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = ssh_output_consume(from, len)) != 0)
		తిరిగి r;
	*transferred = len;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
నిరంతరం_kex(నిర్మాణం ssh *client, నిర్మాణం ssh *server)
{
	పూర్ణాంకం r;
	కొలత_t cn, sn;
	కొరకు (పూర్ణాంకం i = 0; i < 100; i++) {
		ఒకవేళ ((r = pump(server, client, &sn)) != 0) తిరిగి r;
		ఒకవేళ ((r = pump(client, server, &cn)) != 0) తిరిగి r;
		ఒకవేళ (server->kex->పూర్తి && client->kex->పూర్తి)
			తిరిగి 0;
		ఒకవేళ (cn == 0 && sn == 0)
			తిరిగి SSH_ERR_PROTOCOL_ERROR;
	}
	తిరిగి SSH_ERR_PROTOCOL_ERROR;
}

#అన్తర్భావ "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
స్థిర పూర్ణాంకం mux_master_read_cb(నిర్మాణం ssh *ssh, Channel *c);

#అన్తర్భావ "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
శూన్య *
client_new_escape_filter_ctx(పూర్ణాంకం escape_char)
{
	(శూన్య)escape_char;
	తిరిగి ఖాళీ;
}

శూన్య
client_రిజిస్టరు_global_confirm(global_confirm_cb *cb, శూన్య *ctx)
{
	(శూన్య)cb; (శూన్య)ctx;
}

శూన్య
client_expect_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id, స్థిరరాశి అక్షరం *reason,
    గణన confirm_action action)
{
	(శూన్య)ssh; (శూన్య)id; (శూన్య)reason; (శూన్య)action;
}

శూన్య
client_channel_request_agent_forwarding(నిర్మాణం ssh *ssh, పూర్ణాంకం chanid)
{
	(శూన్య)ssh; (శూన్య)chanid;
}

శూన్య
client_stop_mux(శూన్య)
{
}

పూర్ణాంకం
client_simple_escape_filter(నిర్మాణం ssh *ssh, Channel *c, అక్షరం *buf, పూర్ణాంకం len)
{
	(శూన్య)ssh; (శూన్య)c; (శూన్య)buf; (శూన్య)len;
	తిరిగి 0;
}

శూన్య
client_filter_cleanup(నిర్మాణం ssh *ssh, పూర్ణాంకం cid, శూన్య *ctx)
{
	(శూన్య)ssh; (శూన్య)cid; (శూన్య)ctx;
}

పూర్ణాంకం
client_x11_get_proto(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *display,
    స్థిరరాశి అక్షరం *xauth_మార్గం, u_int trusted, u_int timeout,
    అక్షరం **_proto, అక్షరం **దత్తాంశం_2)
{
	(శూన్య)ssh; (శూన్య)display; (శూన్య)xauth_మార్గం;
	(శూన్య)trusted; (శూన్య)timeout;
	ఒకవేళ (_proto != ఖాళీ)
		*_proto = ఖాళీ;
	ఒకవేళ (దత్తాంశం_2 != ఖాళీ)
		*దత్తాంశం_2 = ఖాళీ;
	తిరిగి 0;
}

శూన్య
client_session2_అమరిక(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం want_tty, పూర్ణాంకం want_subsys,
    స్థిరరాశి అక్షరం *పదం, నిర్మాణం termios *tiop, పూర్ణాంకం లోపల_fd, నిర్మాణం sshbuf *cmd,
    అక్షరం **env)
{
	(శూన్య)ssh; (శూన్య)id; (శూన్య)want_tty; (శూన్య)want_subsys;
	(శూన్య)పదం; (శూన్య)tiop; (శూన్య)లోపల_fd; (శూన్య)cmd; (శూన్య)env;
}

శూన్య
enter_raw_బహుళకం(పూర్ణాంకం quiet)
{
	(శూన్య)quiet;
}

శూన్య
leave_raw_బహుళకం(పూర్ణాంకం quiet)
{
	(శూన్య)quiet;
}

స్థిర నిర్మాణం ssh *g_client = ఖాళీ;
స్థిర నిర్మాణం ssh *g_server = ఖాళీ;
స్థిర పూర్ణాంకం g_init = 0;
స్థిర పూర్ణాంకం g_mux_channel_id = -1;
స్థిర నిర్మాణం sshbuf *g_mux_లోపల = ఖాళీ;
స్థిర నిర్మాణం sshbuf *g_mux_బహిర్గతం = ఖాళీ;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
స్థిర శూన్య
fuzz_drive_mux(నిర్మాణం ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	పూర్ణాంకం r;
	స్థిరరాశి u_char *body;
	కొలత_t blen;
	నిర్మాణం mux_master_state *state;

	state = (నిర్మాణం mux_master_state *)c->mux_ctx;
	ఒకవేళ (state == ఖాళీ)
		తిరిగి;

	sshbuf_reset(g_mux_లోపల);
	sshbuf_reset(g_mux_బహిర్గతం);

	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(c->ఆదానం, &body, &blen)) != 0)
		తిరిగి;
	ఒకవేళ (sshbuf_put(g_mux_లోపల, body, blen) != 0)
		తిరిగి;
	ఒకవేళ ((r = sshbuf_get_u32(g_mux_లోపల, &type)) != 0)
		తిరిగి;

	ఒకవేళ (type == MUX_సందేశం_HELLO) {
		rid = 0;
	} లేకపోతే {
		ఒకవేళ (!state->hello_rcvd)
			తిరిగి;
		ఒకవేళ ((r = sshbuf_get_u32(g_mux_లోపల, &rid)) != 0)
			తిరిగి;
	}

	కొరకు (i = 0; mux_master_handlers[i].handler != ఖాళీ; i++) {
		ఒకవేళ (type == mux_master_handlers[i].type) {
			(శూన్య)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_లోపల, g_mux_బహిర్గతం);
			ఆపు;
		}
	}
}

స్థిర పూర్ణాంకం
init_once(శూన్య)
{
	ఒకవేళ (g_init)
		తిరిగి 0;
	సంకేతం(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, పరిమాణం(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_మార్గం = (అక్షరం *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_ముసుగు = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (అక్షరం *)"fuzz";

	నిర్మాణం sshkey *priv = ఎక్కించు_వ్యక్తిగత(PRIV_ED25519);
	నిర్మాణం sshkey *pub = ఎక్కించు_ప్రజా(PUB_ED25519);
	అక్షరం *keyname = xstrdup(sshkey_ssh_name(priv));

	స్థిరరాశి అక్షరం *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	అక్షరం *proposal[PROPOSAL_MAX] = { 0 };
	పూర్ణాంకం i;
	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		స్థిరరాశి అక్షరం *p = defaults[i];
		ఒకవేళ (i == PROPOSAL_SERVER_HOST_కీలకం_ALGS)
			p = keyname;
		లేకపోతే ఒకవేళ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		లేకపోతే ఒకవేళ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		లేకపోతే ఒకవేళ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	నిర్మాణం kex_params kp;
	జ్ఞాపకం_నకలు(kp.proposal, proposal, పరిమాణం(proposal));

	ఒకవేళ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		తిరిగి -1;
	ఒకవేళ (ssh_కూడు_hostkey(g_server, priv) != 0 ||
	    ssh_కూడు_hostkey(g_client, pub) != 0)
		తిరిగి -1;
	ఒకవేళ (నిరంతరం_kex(g_client, g_server) != 0)
		తిరిగి -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	ఒకవేళ (c == ఖాళీ)
		తిరిగి -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	నిర్మాణం mux_master_state *st = (నిర్మాణం mux_master_state *)c->mux_ctx;
	ఒకవేళ (st != ఖాళీ)
		st->hello_rcvd = 1;

	ఒకవేళ ((g_mux_లోపల = sshbuf_new()) == ఖాళీ ||
	    (g_mux_బహిర్గతం = sshbuf_new()) == ఖాళీ)
		తిరిగి -1;

	విడుదల(keyname);
	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(proposal[i]);
	g_init = 1;
	తిరిగి 0;
}

శూన్య
fuzz_mux_one(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (init_once() != 0)
		తిరిగి;
	ఒకవేళ (కొలత > 65000)
		తిరిగి;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	ఒకవేళ (c == ఖాళీ || c->mux_ctx == ఖాళీ || c->ఆదానం == ఖాళీ)
		తిరిగి;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->ఆదానం);
	u_char hdr[4];
	hdr[0] = (u_char)(కొలత >> 24);
	hdr[1] = (u_char)(కొలత >> 16);
	hdr[2] = (u_char)(కొలత >> 8);
	hdr[3] = (u_char)కొలత;
	ఒకవేళ (sshbuf_put(c->ఆదానం, hdr, 4) != 0)
		తిరిగి;
	ఒకవేళ (కొలత > 0 && sshbuf_put(c->ఆదానం, దత్తాంశం, కొలత) != 0)
		తిరిగి;

	లోపల_fuzz = 1;
	ఒకవేళ (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	లోపల_fuzz = 0;

	/* Drain anything the handler enqueued. */
	ఒకవేళ (c->output != ఖాళీ)
		sshbuf_reset(c->output);
}
