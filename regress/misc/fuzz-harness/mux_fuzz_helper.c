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

#समावेश <setjmp.h>
#समावेश <signal.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <sys/types.h>

#समावेश "log.h"
#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "ssh_api.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "packet.h"
#समावेश "myproposal.h"
#समावेश "kex.h"
#समावेश "xmalloc.h"
#समावेश "authfile.h"
#समावेश "misc.h"
#समावेश "channels.h"
#समावेश "readconf.h"

/* Externs that mux.c declares. */
पूर्णांक tty_flag = 0;
Options options;
अक्षर *host = शून्य;
काष्ठा sshbuf *command = शून्य;
अस्थिर संक_पूर्ण_प्रकार quit_pending = 0;

/* Temporary: LSan off while upstream mux.c parse-chain leaks remain. */
पूर्णांक
__lsan_is_turned_off(व्योम)
{
	वापस 1;
}

अटल लाँघ_बफ fuzz_env;
अटल अस्थिर पूर्णांक in_fuzz = 0;

व्योम
cleanup_exit(पूर्णांक code)
{
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_निकास(code);
}

व्योम
__wrap_ssh_packet_disconnect(काष्ठा ssh *ssh, स्थिर अक्षर *fmt, ...)
{
	(व्योम)ssh;
	(व्योम)fmt;
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_निकास(1);
}

पूर्णांक
__wrap_sshpkt_fatal(काष्ठा ssh *ssh, पूर्णांक r, स्थिर अक्षर *fmt, ...)
{
	(व्योम)ssh;
	(व्योम)fmt;
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_निकास(r ? r : 1);
}

/* Block the only interactive prompt by always granting permission. */
पूर्णांक
__wrap_ask_permission(स्थिर अक्षर *fmt, ...)
{
	(व्योम)fmt;
	वापस 1;
}

/* Socket-opening side effects we must neutralise. */
पूर्णांक
__wrap_channel_setup_local_fwd_listener(काष्ठा ssh *ssh,
    काष्ठा Forward *fwd, काष्ठा ForwardOptions *fwd_opts)
{
	(व्योम)ssh; (व्योम)fwd; (व्योम)fwd_opts;
	वापस 1;
}

पूर्णांक
__wrap_channel_connect_stdio_fwd(काष्ठा ssh *ssh, स्थिर अक्षर *host_arg,
    पूर्णांक port, पूर्णांक in_fd, पूर्णांक out_fd, पूर्णांक nonblock)
{
	(व्योम)ssh; (व्योम)host_arg; (व्योम)port;
	(व्योम)in_fd; (व्योम)out_fd; (व्योम)nonblock;
	वापस -1;
}

पूर्णांक
__wrap_channel_request_remote_forwarding(काष्ठा ssh *ssh, काष्ठा Forward *fwd)
{
	(व्योम)ssh; (व्योम)fwd;
	वापस 0;
}

पूर्णांक
__wrap_channel_request_rforward_cancel(काष्ठा ssh *ssh, काष्ठा Forward *fwd)
{
	(व्योम)ssh; (व्योम)fwd;
	वापस 0;
}

पूर्णांक
__wrap_channel_cancel_lport_listener(काष्ठा ssh *ssh, काष्ठा Forward *fwd,
    पूर्णांक cport, काष्ठा ForwardOptions *fwd_opts)
{
	(व्योम)ssh; (व्योम)fwd; (व्योम)cport; (व्योम)fwd_opts;
	वापस 0;
}

अटल काष्ठा sshkey *
load_private(स्थिर अक्षर *str)
{
	काष्ठा sshbuf *b = sshbuf_from(str, म_माप(str));
	काष्ठा sshkey *k = शून्य;
	अगर (b == शून्य || sshkey_parse_private_fileblob(b, "", &k, शून्य) != 0)
		पात();
	sshbuf_free(b);
	वापस k;
}

अटल काष्ठा sshkey *
load_public(स्थिर अक्षर *str)
{
	अक्षर *tmp, *cp;
	काष्ठा sshkey *k = sshkey_new(कुंजी_UNSPEC);
	अगर (k == शून्य)
		पात();
	tmp = cp = strdup(str);
	अगर (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	वापस k;
}

अटल पूर्णांक
pump(काष्ठा ssh *from, काष्ठा ssh *to, माप_प्रकार *transferred)
{
	स्थिर u_char *buf;
	माप_प्रकार len;
	u_char type;
	पूर्णांक r;
	*transferred = 0;
	अगर ((r = ssh_packet_अग्र(from, &type)) != 0)
		वापस r;
	buf = ssh_output_ptr(from, &len);
	अगर (len == 0)
		वापस 0;
	अगर ((r = ssh_निवेश_append(to, buf, len)) != 0)
		वापस r;
	अगर ((r = ssh_output_consume(from, len)) != 0)
		वापस r;
	*transferred = len;
	वापस 0;
}

अटल पूर्णांक
run_kex(काष्ठा ssh *client, काष्ठा ssh *server)
{
	पूर्णांक r;
	माप_प्रकार cn, sn;
	क्रम (पूर्णांक i = 0; i < 100; i++) {
		अगर ((r = pump(server, client, &sn)) != 0) वापस r;
		अगर ((r = pump(client, server, &cn)) != 0) वापस r;
		अगर (server->kex->done && client->kex->done)
			वापस 0;
		अगर (cn == 0 && sn == 0)
			वापस SSH_ERR_PROTOCOL_ERROR;
	}
	वापस SSH_ERR_PROTOCOL_ERROR;
}

#समावेश "fixed-keys.h"

/* Forward decl of the static handler we drive; defined when mux.c is included. */
अटल पूर्णांक mux_master_read_cb(काष्ठा ssh *ssh, Channel *c);

#समावेश "../../../mux.c"

/* Stubs for clientloop.c / channels.h symbols mux.o references but we don't link. */
व्योम *
client_new_escape_filter_ctx(पूर्णांक escape_char)
{
	(व्योम)escape_char;
	वापस शून्य;
}

व्योम
client_register_global_confirm(global_confirm_cb *cb, व्योम *ctx)
{
	(व्योम)cb; (व्योम)ctx;
}

व्योम
client_expect_confirm(काष्ठा ssh *ssh, पूर्णांक id, स्थिर अक्षर *reason,
    क्रमागत confirm_action action)
{
	(व्योम)ssh; (व्योम)id; (व्योम)reason; (व्योम)action;
}

व्योम
client_channel_request_agent_forwarding(काष्ठा ssh *ssh, पूर्णांक chanid)
{
	(व्योम)ssh; (व्योम)chanid;
}

व्योम
client_stop_mux(व्योम)
{
}

पूर्णांक
client_simple_escape_filter(काष्ठा ssh *ssh, Channel *c, अक्षर *buf, पूर्णांक len)
{
	(व्योम)ssh; (व्योम)c; (व्योम)buf; (व्योम)len;
	वापस 0;
}

व्योम
client_filter_cleanup(काष्ठा ssh *ssh, पूर्णांक cid, व्योम *ctx)
{
	(व्योम)ssh; (व्योम)cid; (व्योम)ctx;
}

पूर्णांक
client_x11_get_proto(काष्ठा ssh *ssh, स्थिर अक्षर *display,
    स्थिर अक्षर *xauth_path, u_int trusted, u_int timeout,
    अक्षर **_proto, अक्षर **तथ्य_2)
{
	(व्योम)ssh; (व्योम)display; (व्योम)xauth_path;
	(व्योम)trusted; (व्योम)timeout;
	अगर (_proto != शून्य)
		*_proto = शून्य;
	अगर (तथ्य_2 != शून्य)
		*तथ्य_2 = शून्य;
	वापस 0;
}

व्योम
client_session2_setup(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक want_tty, पूर्णांक want_subsys,
    स्थिर अक्षर *term, काष्ठा termios *tiop, पूर्णांक in_fd, काष्ठा sshbuf *cmd,
    अक्षर **env)
{
	(व्योम)ssh; (व्योम)id; (व्योम)want_tty; (व्योम)want_subsys;
	(व्योम)term; (व्योम)tiop; (व्योम)in_fd; (व्योम)cmd; (व्योम)env;
}

व्योम
enter_raw_mode(पूर्णांक quiet)
{
	(व्योम)quiet;
}

व्योम
leave_raw_mode(पूर्णांक quiet)
{
	(व्योम)quiet;
}

अटल काष्ठा ssh *g_client = शून्य;
अटल काष्ठा ssh *g_server = शून्य;
अटल पूर्णांक g_init = 0;
अटल पूर्णांक g_mux_channel_id = -1;
अटल काष्ठा sshbuf *g_mux_in = शून्य;
अटल काष्ठा sshbuf *g_mux_out = शून्य;

/* Mirror of mux_master_read_cb's dispatch loop using file-static in/out */
अटल व्योम
fuzz_drive_mux(काष्ठा ssh *ssh, Channel *c)
{
	u_int type, rid, i;
	पूर्णांक r;
	स्थिर u_char *body;
	माप_प्रकार blen;
	काष्ठा mux_master_state *state;

	state = (काष्ठा mux_master_state *)c->mux_ctx;
	अगर (state == शून्य)
		वापस;

	sshbuf_reset(g_mux_in);
	sshbuf_reset(g_mux_out);

	अगर ((r = sshbuf_get_string_direct(c->निवेश, &body, &blen)) != 0)
		वापस;
	अगर (sshbuf_put(g_mux_in, body, blen) != 0)
		वापस;
	अगर ((r = sshbuf_get_u32(g_mux_in, &type)) != 0)
		वापस;

	अगर (type == MUX_संदेश_HELLO) {
		rid = 0;
	} अन्यथा {
		अगर (!state->hello_rcvd)
			वापस;
		अगर ((r = sshbuf_get_u32(g_mux_in, &rid)) != 0)
			वापस;
	}

	क्रम (i = 0; mux_master_handlers[i].handler != शून्य; i++) {
		अगर (type == mux_master_handlers[i].type) {
			(व्योम)mux_master_handlers[i].handler(ssh, rid, c,
			    g_mux_in, g_mux_out);
			अवरोध;
		}
	}
}

अटल पूर्णांक
init_once(व्योम)
{
	अगर (g_init)
		वापस 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("mux_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

	/* Minimal Options for control-master flow. SSHCTL_MASTER_AUTO avoids
	 * the interactive ASK paths that would gate on ask_permission. */
	स_रखो(&options, 0, माप(options));
	options.control_master = SSHCTL_MASTER_AUTO;
	options.control_path = (अक्षर *)"/fuzz";
	options.escape_char = 0;
	options.log_level = SYSLOG_LEVEL_ERROR;
	options.fwd_opts.gateway_ports = 0;
	options.fwd_opts.streamlocal_bind_mask = 0177;
	options.fwd_opts.streamlocal_bind_unlink = 0;
	host = (अक्षर *)"fuzz";

	काष्ठा sshkey *priv = load_private(PRIV_ED25519);
	काष्ठा sshkey *pub = load_public(PUB_ED25519);
	अक्षर *keyname = xstrdup(sshkey_ssh_name(priv));

	स्थिर अक्षर *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *proposal[PROPOSAL_MAX] = { 0 };
	पूर्णांक i;
	क्रम (i = 0; i < PROPOSAL_MAX; i++) {
		स्थिर अक्षर *p = defaults[i];
		अगर (i == PROPOSAL_SERVER_HOST_कुंजी_ALGS)
			p = keyname;
		अन्यथा अगर (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		अन्यथा अगर (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		अन्यथा अगर (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	काष्ठा kex_params kp;
	स_नकल(kp.proposal, proposal, माप(proposal));

	अगर (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		वापस -1;
	अगर (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		वापस -1;
	अगर (run_kex(g_client, g_server) != 0)
		वापस -1;

	channel_init_channels(g_client);

	Channel *c = channel_new(g_client, "mux-control",
	    SSH_CHANNEL_MUX_CLIENT, -1, -1, -1, 65536, 65536, 0,
	    "mux-control", 1);
	अगर (c == शून्य)
		वापस -1;
	c->mux_rcb = mux_master_read_cb;
	c->flags |= CHAN_LOCAL;
	g_mux_channel_id = c->self;

	/* Bootstrap mux_master_state via the rcb (NULL-ctx branch). */
	c->mux_rcb(g_client, c);

	/* Skip the hello handshake so every iter goes straight to dispatch. */
	काष्ठा mux_master_state *st = (काष्ठा mux_master_state *)c->mux_ctx;
	अगर (st != शून्य)
		st->hello_rcvd = 1;

	अगर ((g_mux_in = sshbuf_new()) == शून्य ||
	    (g_mux_out = sshbuf_new()) == शून्य)
		वापस -1;

	मुक्त(keyname);
	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	वापस 0;
}

व्योम
fuzz_mux_one(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (init_once() != 0)
		वापस;
	अगर (आकार > 65000)
		वापस;

	Channel *c = channel_by_id(g_client, g_mux_channel_id);
	अगर (c == शून्य || c->mux_ctx == शून्य || c->निवेश == शून्य)
		वापस;

	/* mux protocol: outer length-prefixed string containing the body. */
	sshbuf_reset(c->निवेश);
	u_char hdr[4];
	hdr[0] = (u_char)(आकार >> 24);
	hdr[1] = (u_char)(आकार >> 16);
	hdr[2] = (u_char)(आकार >> 8);
	hdr[3] = (u_char)आकार;
	अगर (sshbuf_put(c->निवेश, hdr, 4) != 0)
		वापस;
	अगर (आकार > 0 && sshbuf_put(c->निवेश, तथ्य, आकार) != 0)
		वापस;

	in_fuzz = 1;
	अगर (बनाओ_लाँघ(fuzz_env) == 0) {
		fuzz_drive_mux(g_client, c);
	}
	in_fuzz = 0;

	/* Drain anything the handler enqueued. */
	अगर (c->output != शून्य)
		sshbuf_reset(c->output);
}
