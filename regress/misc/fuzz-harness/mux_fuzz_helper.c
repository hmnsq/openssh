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

#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <sys/types.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "readconf.h"

/* Externs that mux.c declares. */
पूर्णाङ्क tty_flag = 0;
Options options;
वर्ण *host = रिक्त;
संरचना sshbuf *command = रिक्त;
चञ्चल sig_atomic_t quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
पूर्णाङ्क
__lsan_is_turned_off(शून्य)
{
	प्रत्यागम 1;
}

स्थिर jmp_buf fuzz_env;
स्थिर चञ्चल पूर्णाङ्क in_fuzz = 0;

शून्य
cleanup_exit(पूर्णाङ्क code)
{
	यदि (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

शून्य
__wrap_ssh_packet_disconnect(संरचना ssh *ssh, ध्रुव वर्ण *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	यदि (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

पूर्णाङ्क
__wrap_sshpkt_fatal(संरचना ssh *ssh, पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	यदि (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
पूर्णाङ्क
__wrap_ask_permission(ध्रुव वर्ण *fmt, ...)
{
	(शून्य)fmt;
	प्रत्यागम 1;
}

/* Socket-opening side effects we must neutralise. */
पूर्णाङ्क
__wrap_channel_setup_local_fwd_listener(संरचना ssh *ssh,
    संरचना Forward *fwd, संरचना ForwardOptions *fwd_opts)
{
	(शून्य)ssh; (शून्य)fwd; (शून्य)fwd_opts;
	प्रत्यागम 1;
}

पूर्णाङ्क
__wrap_channel_connect_stdio_fwd(संरचना ssh *ssh, ध्रुव वर्ण *host_arg,
    पूर्णाङ्क port, पूर्णाङ्क in_fd, पूर्णाङ्क out_fd, पूर्णाङ्क nonblock)
{
	(शून्य)ssh; (शून्य)host_arg; (शून्य)port;
	(शून्य)in_fd; (शून्य)out_fd; (शून्य)nonblock;
	प्रत्यागम -1;
}

पूर्णाङ्क
__wrap_channel_request_remote_forwarding(संरचना ssh *ssh, संरचना Forward *fwd)
{
	(शून्य)ssh; (शून्य)fwd;
	प्रत्यागम 0;
}

पूर्णाङ्क
__wrap_channel_request_rforward_cancel(संरचना ssh *ssh, संरचना Forward *fwd)
{
	(शून्य)ssh; (शून्य)fwd;
	प्रत्यागम 0;
}

पूर्णाङ्क
__wrap_channel_cancel_lport_listener(संरचना ssh *ssh, संरचना Forward *fwd,
    पूर्णाङ्क cport, संरचना ForwardOptions *fwd_opts)
{
	(शून्य)ssh; (शून्य)fwd; (शून्य)cport; (शून्य)fwd_opts;
	प्रत्यागम 0;
}

स्थिर संरचना sshkey *
load_private(ध्रुव वर्ण *str)
{
	संरचना sshbuf *b = sshbuf_from(str, strlen(str));
	संरचना sshkey *k = रिक्त;
	यदि (b == रिक्त || sshkey_parse_private_fileblob(b, "", &k, रिक्त) != 0)
		abort();
	sshbuf_free(b);
	प्रत्यागम k;
}

स्थिर संरचना sshkey *
load_public(ध्रुव वर्ण *str)
{
	वर्ण *tmp, *cp;
	संरचना sshkey *k = sshkey_new(कुंजी_UNSPEC);
	यदि (k == रिक्त)
		abort();
	tmp = cp = strdup(str);
	यदि (sshkey_read(k, &cp) != 0)
		abort();
	मुक्त(tmp);
	प्रत्यागम k;
}

स्थिर पूर्णाङ्क
pump(संरचना ssh *from, संरचना ssh *to, size_t *transferred)
{
	ध्रुव u_char *buf;
	size_t len;
	u_char type;
	पूर्णाङ्क r;
	*transferred = 0;
	यदि ((r = ssh_packet_next(from, &type)) != 0)
		प्रत्यागम r;
	buf = ssh_output_ptr(from, &len);
	यदि (len == 0)
		प्रत्यागम 0;
	यदि ((r = ssh_निवेश_append(to, buf, len)) != 0)
		प्रत्यागम r;
	यदि ((r = ssh_output_consume(from, len)) != 0)
		प्रत्यागम r;
	*transferred = len;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
run_kex(संरचना ssh *client, संरचना ssh *server)
{
	पूर्णाङ्क r;
	size_t cn, sn;
	प्रति (पूर्णाङ्क i = 0; i < 100; i++) {
		यदि ((r = pump(server, client, &sn)) != 0) प्रत्यागम r;
		यदि ((r = pump(client, server, &cn)) != 0) प्रत्यागम r;
		यदि (server->kex->done && client->kex->done)
			प्रत्यागम 0;
		यदि (cn == 0 && sn == 0)
			प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
	}
	प्रत्यागम SSH_ERR_PROTOCOL_ERROR;
}

#अन्तर्भाव "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
स्थिर पूर्णाङ्क mux_master_read_cb(संरचना ssh *ssh, Channel *c);

#अन्तर्भाव "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
शून्य *
client_new_escape_filter_ctx(पूर्णाङ्क escape_char)
{
	(शून्य)escape_char;
	प्रत्यागम रिक्त;
}

शून्य
client_register_global_confirm(global_confirm_cb *cb, शून्य *ctx)
{
	(शून्य)cb; (शून्य)ctx;
}

शून्य
client_expect_confirm(संरचना ssh *ssh, पूर्णाङ्क id, ध्रुव वर्ण *reason,
    गणना confirm_action action)
{
	(शून्य)ssh; (शून्य)id; (शून्य)reason; (शून्य)action;
}

शून्य
client_channel_request_agent_forwarding(संरचना ssh *ssh, पूर्णाङ्क chanid)
{
	(शून्य)ssh; (शून्य)chanid;
}

शून्य
client_stop_mux(शून्य)
{
}

पूर्णाङ्क
client_simple_escape_filter(संरचना ssh *ssh, Channel *c, वर्ण *buf, पूर्णाङ्क len)
{
	(शून्य)ssh; (शून्य)c; (शून्य)buf; (शून्य)len;
	प्रत्यागम 0;
}

शून्य
client_filter_cleanup(संरचना ssh *ssh, पूर्णाङ्क cid, शून्य *ctx)
{
	(शून्य)ssh; (शून्य)cid; (शून्य)ctx;
}

पूर्णाङ्क
client_x11_get_proto(संरचना ssh *ssh, ध्रुव वर्ण *display,
    ध्रुव वर्ण *xauth_path, u_int trusted, u_int timeout,
    वर्ण **_proto, वर्ण **_data)
{
	(शून्य)ssh; (शून्य)display; (शून्य)xauth_path;
	(शून्य)trusted; (शून्य)timeout;
	यदि (_proto != रिक्त)
		*_proto = रिक्त;
	यदि (_data != रिक्त)
		*_data = रिक्त;
	प्रत्यागम 0;
}

शून्य
client_session2_setup(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क want_tty, पूर्णाङ्क want_subsys,
    ध्रुव वर्ण *term, संरचना termios *tiop, पूर्णाङ्क in_fd, संरचना sshbuf *cmd,
    वर्ण **env)
{
	(शून्य)ssh; (शून्य)id; (शून्य)want_tty; (शून्य)want_subsys;
	(शून्य)term; (शून्य)tiop; (शून्य)in_fd; (शून्य)cmd; (शून्य)env;
}

शून्य
enter_raw_mode(पूर्णाङ्क quiet)
{
	(शून्य)quiet;
}

शून्य
leave_raw_mode(पूर्णाङ्क quiet)
{
	(शून्य)quiet;
}

स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णाङ्क g_init = 0;
स्थिर पूर्णाङ्क g_mux_channel_id = -1;
स्थिर संरचना sshbuf *g_mux_in = रिक्त;
स्थिर संरचना sshbuf *g_mux_out = रिक्त;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
स्थिर शून्य
fuzz_drive_mux(संरचना ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	पूर्णाङ्क r;
	ध्रुव u_char *body;
	size_t blen;
	संरचना mux_master_state *state;

	state = (संरचना mux_master_state *)c->mux_ctx;
	यदि (state == रिक्त)
		प्रत्यागम;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	यदि ((r = sshbuf_get_string_direct(c->निवेश, &body, &blen)) != 0)
		प्रत्यागम;
	यदि (sshbuf_put(g_mux_in, body, blen) != 0)
		प्रत्यागम;
	यदि ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		प्रत्यागम;

	यदि (type == MUX_संदेश_HELLO) {
		rid = 0;
	} अन्यथा {
		यदि (!state->hello_rcvd)
			प्रत्यागम;
		यदि ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			प्रत्यागम;
	}

	प्रति (i = 0; mux_master_handlers[i].handler != रिक्त; i++) {
		यदि (type == mux_master_handlers[i].type) {
			(शून्य)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			भङ्ग;
		}
	}
}

स्थिर पूर्णाङ्क
init_once(शून्य)
{
	यदि (g_init)
		प्रत्यागम 0;
	सङ्केत(SIGPIPE, SIG_IGN);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	memset(&options, 0, परिमाण(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (वर्ण *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (वर्ण *)"fuzz";

	संरचना sshkey *priv = load_private(PRIV_ED25519);
	संरचना sshkey *pub = load_public(PUB_ED25519);
	वर्ण *keyname = xstrdup(sshkey_ssh_name(priv));

	ध्रुव वर्ण *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	वर्ण *proposal[PROPOSAL_MAX] = { 0 };
	पूर्णाङ्क i;
	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		ध्रुव वर्ण *p = defaults[i];
		यदि (i == PROPOSAL_SERVER_HOST_कुंजी_ALGS)
			p = keyname;
		अन्यथा यदि (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		अन्यथा यदि (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		अन्यथा यदि (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	संरचना kex_params kp;
	memcpy(kp.proposal, proposal, परिमाण(proposal));

	यदि (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		प्रत्यागम -1;
	यदि (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		प्रत्यागम -1;
	यदि (run_kex(g_client, g_server) != 0)
		प्रत्यागम -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	यदि (c == रिक्त)
		प्रत्यागम -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	संरचना mux_master_state *st = (संरचना mux_master_state *)c->mux_ctx;
	यदि (st != रिक्त)
		st->hello_rcvd = 1;

	यदि ((g_mux_in = sshbuf_new()) == रिक्त ||
	    (g_mux_out = sshbuf_new()) == रिक्त)
		प्रत्यागम -1;

	मुक्त(keyname);
	प्रति (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	प्रत्यागम 0;
}

शून्य
fuzz_mux_one(ध्रुव uint8_t *data, size_t size)
{
	यदि (init_once() != 0)
		प्रत्यागम;
	यदि (size > 65000)
		प्रत्यागम;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	यदि (c == रिक्त || c->mux_ctx == रिक्त || c->निवेश == रिक्त)
		प्रत्यागम;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->निवेश);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	यदि (sshbuf_put(c->निवेश, hdr, 4) != 0)
		प्रत्यागम;
	यदि (size > 0 && sshbuf_put(c->निवेश, data, size) != 0)
		प्रत्यागम;

	in_fuzz = 1;
	यदि (setjmp(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	यदि (c->output != रिक्त)
		sshbuf_reset(c->output);
}
