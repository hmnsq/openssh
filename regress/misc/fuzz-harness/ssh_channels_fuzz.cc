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

/*
 * Fuzzer for OpenSSH channel dispatch (channels.c)
 *
 * Target: channels.c
 *
 * Drives the eight public channel_input_* handlers declared in
 * channels.h through ssh_dispatch. After an in-process KEX, a set of
 * scenarios is iterated for each fuzz input. Each scenario sets up a
 * fresh channel (varying type, starting state, and fd backing) with
 * dummy open_confirm and status_confirm callbacks registered, then
 * sequences the same fuzz body as nine CHANNEL_* message types in
 * realistic order so state machine transitions and callback paths
 * are exercised.
 *
 * Primary functions exercised:
 * - channel_input_data / extended_data / ieof / oclose
 * - channel_input_open_confirmation / open_failure
 * - channel_input_window_adjust / status_confirm
 * - channel state machine in nchan.c via sequenced messages
 *
 * Threat model: a peer SSH endpoint sending crafted CHANNEL_*
 * messages over an established session. Pre-auth attacker bytes
 * after KEX completes.
 *
 * Linker --wrap on ssh_packet_disconnect and sshpkt_fatal:
 * channel_input_* call those on malformed channel ids and similar
 * invariants. The real implementations free packet state before
 * cleanup_exit longjmp gets control; the wrappers longjmp directly
 * so per-iteration state survives.
 */

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

बाह्य "C" {
#अन्तर्भाव "includes.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "channels.h"
}


#अन्तर्भाव "fixed-keys.h"

स्थिर लाँघ_बफ fuzz_env;
स्थिर चञ्चल पूर्णाङ्क in_fuzz = 0;

स्थिर वर्ण *g_open_failure_संदेश = रिक्त;

बाह्य "C" पूर्णाङ्क
my_channel_निवेश_open_failure(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	(शून्य)type;
	(शून्य)seq;
	uint32_t reason;
	पूर्णाङ्क r;
	यदि ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	यदि ((r = sshpkt_get_cstring(ssh, &g_open_failure_संदेश, रिक्त)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, रिक्त, रिक्त)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	प्रत्यागम 0;
}

बाह्य "C" शून्य
cleanup_exit(पूर्णाङ्क code)
{
	यदि (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_exit(code);
}

बाह्य "C" शून्य
__wrap_ssh_packet_disconnect(संरचना ssh *ssh, ध्रुव वर्ण *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	यदि (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_exit(1);
}

बाह्य "C" पूर्णाङ्क
__wrap_sshpkt_fatal(संरचना ssh *ssh, पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
{
	(शून्य)ssh;
	(शून्य)fmt;
	यदि (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_exit(r ? r : 1);
}

स्थिर संरचना sshkey *
load_private(ध्रुव वर्ण *str)
{
	संरचना sshbuf *b = sshbuf_from(str, म_माप(str));
	संरचना sshkey *k = रिक्त;
	यदि (b == रिक्त || sshkey_parse_private_fileblob(b, "", &k, रिक्त) != 0)
		पात();
	sshbuf_free(b);
	प्रत्यागम k;
}

स्थिर संरचना sshkey *
load_public(ध्रुव वर्ण *str)
{
	वर्ण *tmp, *cp;
	संरचना sshkey *k = sshkey_new(कुंजी_UNSPEC);
	यदि (k == रिक्त)
		पात();
	tmp = cp = strdup(str);
	यदि (sshkey_read(k, &cp) != 0)
		पात();
	मुक्त(tmp);
	प्रत्यागम k;
}

स्थिर पूर्णाङ्क
pump(संरचना ssh *from, संरचना ssh *to, माप_प्रकार *transferred)
{
	ध्रुव u_char *buf;
	माप_प्रकार len;
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
	माप_प्रकार cn, sn;
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

स्थिर संरचना ssh *g_client = रिक्त;
स्थिर संरचना ssh *g_server = रिक्त;
स्थिर पूर्णाङ्क g_init = 0;
स्थिर पूर्णाङ्क g_pipe[2] = { -1, -1 };

स्थिर शून्य
dummy_open_confirm(संरचना ssh *ssh, पूर्णाङ्क id, पूर्णाङ्क success, शून्य *ctx)
{
	(शून्य)ssh;
	(शून्य)id;
	(शून्य)success;
	(शून्य)ctx;
}

स्थिर शून्य
dummy_status_confirm(संरचना ssh *ssh, पूर्णाङ्क type, Channel *c, शून्य *ctx)
{
	(शून्य)ssh;
	(शून्य)type;
	(शून्य)c;
	(शून्य)ctx;
}

स्थिर शून्य
dummy_status_abandon(संरचना ssh *ssh, Channel *c, शून्य *ctx)
{
	(शून्य)ssh;
	(शून्य)c;
	(शून्य)ctx;
}

स्थिर पूर्णाङ्क
init_once(शून्य)
{
	यदि (g_init)
		प्रत्यागम 0;
	सङ्केत(SIGPIPE, संक_छोड़ो);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	पूर्णाङ्क pfd[2];
	यदि (प्रणाल(pfd) != 0)
		प्रत्यागम -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	बंद(pfd[0]);
	बंद(pfd[1]);
	यदि (g_pipe[0] < 0 || g_pipe[1] < 0)
		प्रत्यागम -1;
	पूर्णाङ्क fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	पूर्णाङ्क fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(शून्य)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(शून्य)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

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
	स_नकल(kp.proposal, proposal, परिमाण(proposal));

	यदि (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		प्रत्यागम -1;
	यदि (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		प्रत्यागम -1;
	यदि (run_kex(g_client, g_server) != 0)
		प्रत्यागम -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_DATA,
	    &channel_निवेश_data);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_EXTENDED_DATA,
	    &channel_निवेश_extended_data);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_EOF,
	    &channel_निवेश_ieof);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_CLOSE,
	    &channel_निवेश_oclose);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION,
	    &channel_निवेश_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_OPEN_FAILURE,
	    &my_channel_निवेश_open_failure);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_WINDOW_ADJUST,
	    &channel_निवेश_window_adjust);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_SUCCESS,
	    &channel_निवेश_status_confirm);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_FAILURE,
	    &channel_निवेश_status_confirm);

	मुक्त(keyname);
	प्रति (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	प्रत्यागम 0;
}

संरचना chan_scenario {
	ध्रुव वर्ण *ctype;
	पूर्णाङ्क state;
	पूर्णाङ्क use_pipe;
};

स्थिर ध्रुव संरचना chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

स्थिर पूर्णाङ्क g_channel_id = -1;

स्थिर शून्य
drain_pipe(शून्य)
{
	वर्ण buf[4096];
	यदि (g_pipe[0] < 0)
		प्रत्यागम;
	यावत् (पठ(g_pipe[0], buf, परिमाण(buf)) > 0) { }
}

स्थिर शून्य
reset_channel(संरचना ssh *ssh, ध्रुव संरचना chan_scenario *s)
{
	यदि (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		यदि (c != रिक्त)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	पूर्णाङ्क rfd = s->use_pipe ? g_pipe[1] : -1;
	पूर्णाङ्क wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (वर्ण *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (वर्ण *)"fuzz", 0);
	यदि (c == रिक्त)
		प्रत्यागम;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, रिक्त);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, रिक्त);
}

स्थिर ध्रुव uint8_t k_संदेश_types[] = {
	SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION,
	SSH2_संदेश_CHANNEL_OPEN_FAILURE,
	SSH2_संदेश_CHANNEL_WINDOW_ADJUST,
	SSH2_संदेश_CHANNEL_DATA,
	SSH2_संदेश_CHANNEL_EXTENDED_DATA,
	SSH2_संदेश_CHANNEL_SUCCESS,
	SSH2_संदेश_CHANNEL_FAILURE,
	SSH2_संदेश_CHANNEL_EOF,
	SSH2_संदेश_CHANNEL_CLOSE,
};

बाह्य "C" पूर्णाङ्क
LLVMFuzzer_Test_One_निवेश(ध्रुव uint8_t *data, माप_प्रकार size)
{
	यदि (init_once() != 0)
		प्रत्यागम 0;
	यदि (size > 65000)
		प्रत्यागम 0;

	ध्रुव माप_प्रकार n_scen = परिमाण(k_scenarios) / परिमाण(k_scenarios[0]);
	ध्रुव माप_प्रकार n_संदेश = परिमाण(k_संदेश_types) / परिमाण(k_संदेश_types[0]);

	प्रति (माप_प्रकार s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		प्रति (माप_प्रकार t = 0; t < n_संदेश; t++) {
			in_fuzz = 1;
			यदि (बनाओ_लाँघ(fuzz_env) == 0) {
				माप_प्रकार transferred;
				यदि (ssh_packet_put(g_server, k_संदेश_types[t],
				    data, size) != 0)
					गच्छ done;
				यदि (pump(g_server, g_client,
				    &transferred) != 0)
					गच्छ done;
				(शून्य)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, रिक्त);
			done:
				;
			}
			in_fuzz = 0;
			मुक्त(g_open_failure_संदेश);
			g_open_failure_संदेश = रिक्त;
		}
	}
	प्रत्यागम 0;
}
