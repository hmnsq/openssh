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
पूर्णांक tty_flag = 0;
Options options;
अक्षर *host = रिक्त;
संरचना sshbuf *command = रिक्त;
अस्थिर संक_पूर्ण_प्रकार quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
पूर्णांक
__lsan_is_turned_off(शून्य)
{
	परत 1;
}

स्थिर लाँघ_बफ fuzz_env;
स्थिर अस्थिर पूर्णांक in_fuzz = 0;

शून्य
cleanup_exit(पूर्णांक code)
{
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_exit(code);
}

शून्य
__wrap_ssh_packet_disconnect(संरचना ssh *ssh, स्थिरांक अक्षर *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_exit(1);
}

पूर्णांक
__wrap_sshpkt_fatal(संरचना ssh *ssh, पूर्णांक r, स्थिरांक अक्षर *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_exit(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
पूर्णांक
__wrap_ask_permission(स्थिरांक अक्षर *fmt, ...)
{
	(शून्य)fmt;
	परत 1;
}

/* Socket-opening side effects we must neutralise. */
पूर्णांक
__wrap_channel_setup_local_fwd_listener(संरचना ssh *ssh,
    संरचना Forward *fwd, संरचना ForwardOptions *fwd_opts)
{
	(शून्य)ssh; (शून्य)fwd; (शून्य)fwd_opts;
	परत 1;
}

पूर्णांक
__wrap_channel_connect_stdio_fwd(संरचना ssh *ssh, स्थिरांक अक्षर *host_arg,
    पूर्णांक port, पूर्णांक in_fd, पूर्णांक out_fd, पूर्णांक nonblock)
{
	(शून्य)ssh; (शून्य)host_arg; (शून्य)port;
	(शून्य)in_fd; (शून्य)out_fd; (शून्य)nonblock;
	परत -1;
}

पूर्णांक
__wrap_channel_request_remote_forwarding(संरचना ssh *ssh, संरचना Forward *fwd)
{
	(शून्य)ssh; (शून्य)fwd;
	परत 0;
}

पूर्णांक
__wrap_channel_request_rforward_cancel(संरचना ssh *ssh, संरचना Forward *fwd)
{
	(शून्य)ssh; (शून्य)fwd;
	परत 0;
}

पूर्णांक
__wrap_channel_cancel_lport_listener(संरचना ssh *ssh, संरचना Forward *fwd,
    पूर्णांक cport, संरचना ForwardOptions *fwd_opts)
{
	(शून्य)ssh; (शून्य)fwd; (शून्य)cport; (शून्य)fwd_opts;
	परत 0;
}

स्थिर संरचना sshkey *
load_private(स्थिरांक अक्षर *str)
{
	संरचना sshbuf *b = sshbuf_from(str, म_माप(str));
	संरचना sshkey *k = रिक्त;
	जर (b == रिक्त || sshkey_parse_private_fileblob(b, "", &k, रिक्त) != 0)
		पात();
	sshbuf_free(b);
	परत k;
}

स्थिर संरचना sshkey *
load_public(स्थिरांक अक्षर *str)
{
	अक्षर *tmp, *cp;
	संरचना sshkey *k = sshkey_new(किल्ली_UNSPEC);
	जर (k == रिक्त)
		पात();
	tmp = cp = strdup(str);
	जर (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	परत k;
}

स्थिर पूर्णांक
pump(संरचना ssh *from, संरचना ssh *to, माप_प्रकार *transferred)
{
	स्थिरांक u_char *buf;
	माप_प्रकार len;
	u_char type;
	पूर्णांक r;
	*transferred = 0;
	जर ((r = ssh_packet_next(from, &type)) != 0)
		परत r;
	buf = ssh_output_ptr(from, &len);
	जर (len == 0)
		परत 0;
	जर ((r = ssh_आदान_append(to, buf, len)) != 0)
		परत r;
	जर ((r = ssh_output_consume(from, len)) != 0)
		परत r;
	*transferred = len;
	परत 0;
}

स्थिर पूर्णांक
run_kex(संरचना ssh *client, संरचना ssh *server)
{
	पूर्णांक r;
	माप_प्रकार cn, sn;
	साठी (पूर्णांक i = 0; i < 100; i++) {
		जर ((r = pump(server, client, &sn)) != 0) परत r;
		जर ((r = pump(client, server, &cn)) != 0) परत r;
		जर (server->kex->done && client->kex->done)
			परत 0;
		जर (cn == 0 && sn == 0)
			परत SSH_ERR_PROTOCOL_ERROR;
	}
	परत SSH_ERR_PROTOCOL_ERROR;
}

#अन्तर्भाव "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
स्थिर पूर्णांक mux_master_read_cb(संरचना ssh *ssh, Channel *c);

#अन्तर्भाव "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
शून्य *
client_new_escape_filter_ctx(पूर्णांक escape_char)
{
	(शून्य)escape_char;
	परत रिक्त;
}

शून्य
client_register_global_confirm(global_confirm_cb *cb, शून्य *ctx)
{
	(शून्य)cb; (शून्य)ctx;
}

शून्य
client_expect_confirm(संरचना ssh *ssh, पूर्णांक id, स्थिरांक अक्षर *reason,
    गणना confirm_action action)
{
	(शून्य)ssh; (शून्य)id; (शून्य)reason; (शून्य)action;
}

शून्य
client_channel_request_agent_forwarding(संरचना ssh *ssh, पूर्णांक chanid)
{
	(शून्य)ssh; (शून्य)chanid;
}

शून्य
client_stop_mux(शून्य)
{
}

पूर्णांक
client_simple_escape_filter(संरचना ssh *ssh, Channel *c, अक्षर *buf, पूर्णांक len)
{
	(शून्य)ssh; (शून्य)c; (शून्य)buf; (शून्य)len;
	परत 0;
}

शून्य
client_filter_cleanup(संरचना ssh *ssh, पूर्णांक cid, शून्य *ctx)
{
	(शून्य)ssh; (शून्य)cid; (शून्य)ctx;
}

पूर्णांक
client_x11_get_proto(संरचना ssh *ssh, स्थिरांक अक्षर *display,
    स्थिरांक अक्षर *xauth_path, u_int trusted, u_int timeout,
    अक्षर **_proto, अक्षर **_data)
{
	(शून्य)ssh; (शून्य)display; (शून्य)xauth_path;
	(शून्य)trusted; (शून्य)timeout;
	जर (_proto != रिक्त)
		*_proto = रिक्त;
	जर (_data != रिक्त)
		*_data = रिक्त;
	परत 0;
}

शून्य
client_session2_setup(संरचना ssh *ssh, पूर्णांक id, पूर्णांक want_tty, पूर्णांक want_subsys,
    स्थिरांक अक्षर *term, संरचना termios *tiop, पूर्णांक in_fd, संरचना sshbuf *cmd,
    अक्षर **env)
{
	(शून्य)ssh; (शून्य)id; (शून्य)want_tty; (शून्य)want_subsys;
	(शून्य)term; (शून्य)tiop; (शून्य)in_fd; (शून्य)cmd; (शून्य)env;
}

शून्य
enter_raw_mode(पूर्णांक quiet)
{
	(शून्य)quiet;
}

शून्य
leave_raw_mode(पूर्णांक quiet)
{
	(शून्य)quiet;
}

स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णांक g_init = 0;
स्थिर पूर्णांक g_mux_channel_id = -1;
स्थिर संरचना sshbuf *g_mux_in = रिक्त;
स्थिर संरचना sshbuf *g_mux_out = रिक्त;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
स्थिर शून्य
fuzz_drive_mux(संरचना ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	पूर्णांक r;
	स्थिरांक u_char *body;
	माप_प्रकार blen;
	संरचना mux_master_state *state;

	state = (संरचना mux_master_state *)c->mux_ctx;
	जर (state == रिक्त)
		परत;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	जर ((r = sshbuf_get_string_direct(c->आदान, &body, &blen)) != 0)
		परत;
	जर (sshbuf_put(g_mux_in, body, blen) != 0)
		परत;
	जर ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		परत;

	जर (type == MUX_संदेश_HELLO) {
		rid = 0;
	} अन्यथा {
		जर (!state->hello_rcvd)
			परत;
		जर ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			परत;
	}

	साठी (i = 0; mux_master_handlers[i].handler != रिक्त; i++) {
		जर (type == mux_master_handlers[i].type) {
			(शून्य)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			थांबा;
		}
	}
}

स्थिर पूर्णांक
init_once(शून्य)
{
	जर (g_init)
		परत 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	स_रखो(&options, 0, आकार(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (अक्षर *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (अक्षर *)"fuzz";

	संरचना sshkey *priv = load_private(PRIV_ED25519);
	संरचना sshkey *pub = load_public(PUB_ED25519);
	अक्षर *keyname = xstrdup(sshkey_ssh_name(priv));

	स्थिरांक अक्षर *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *proposal[PROPOSAL_MAX] = { 0 };
	पूर्णांक i;
	साठी (i = 0; i < PROPOSAL_MAX; i++) {
		स्थिरांक अक्षर *p = defaults[i];
		जर (i == PROPOSAL_SERVER_HOST_किल्ली_ALGS)
			p = keyname;
		अन्यथा जर (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		अन्यथा जर (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		अन्यथा जर (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	संरचना kex_params kp;
	स_नकल(kp.proposal, proposal, आकार(proposal));

	जर (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		परत -1;
	जर (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		परत -1;
	जर (run_kex(g_client, g_server) != 0)
		परत -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	जर (c == रिक्त)
		परत -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	संरचना mux_master_state *st = (संरचना mux_master_state *)c->mux_ctx;
	जर (st != रिक्त)
		st->hello_rcvd = 1;

	जर ((g_mux_in = sshbuf_new()) == रिक्त ||
	    (g_mux_out = sshbuf_new()) == रिक्त)
		परत -1;

	मुक्त(keyname);
	साठी (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	परत 0;
}

शून्य
fuzz_mux_one(स्थिरांक uint8_t *data, माप_प्रकार size)
{
	जर (init_once() != 0)
		परत;
	जर (size > 65000)
		परत;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	जर (c == रिक्त || c->mux_ctx == रिक्त || c->आदान == रिक्त)
		परत;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->आदान);
	u_char hdr[4];
	hdr[0] = (u_char)(size >> 24);
	hdr[1] = (u_char)(size >> 16);
	hdr[2] = (u_char)(size >> 8);
	hdr[3] = (u_char)size;
	जर (sshbuf_put(c->आदान, hdr, 4) != 0)
		परत;
	जर (size > 0 && sshbuf_put(c->आदान, data, size) != 0)
		परत;

	in_fuzz = 1;
	जर (बनाओ_लाँघ(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	जर (c->output != रिक्त)
		sshbuf_reset(c->output);
}
