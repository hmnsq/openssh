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

#समावेश <fcntl.h>
#समावेश <setjmp.h>
#समावेश <signal.h>
#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

बाह्य "C" {
#समावेश "includes.h"
#समावेश "ssherr.h"
#समावेश "ssh_api.h"
#समावेश "sshbuf.h"
#समावेश "packet.h"
#समावेश "myproposal.h"
#समावेश "kex.h"
#समावेश "xmalloc.h"
#समावेश "authfile.h"
#समावेश "sshkey.h"
#समावेश "log.h"
#समावेश "ssh2.h"
#समावेश "channels.h"
}


#समावेश "fixed-keys.h"

अटल लाँघ_बफ fuzz_env;
अटल अस्थिर पूर्णांक in_fuzz = 0;

अटल अक्षर *g_open_failure_संदेश = शून्य;

बाह्य "C" पूर्णांक
my_channel_निवेश_open_failure(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	(व्योम)type;
	(व्योम)seq;
	uint32_t reason;
	पूर्णांक r;
	अगर ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	अगर ((r = sshpkt_get_cstring(ssh, &g_open_failure_संदेश, शून्य)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, शून्य, शून्य)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	वापस 0;
}

बाह्य "C" व्योम
cleanup_exit(पूर्णांक code)
{
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_निकास(code);
}

बाह्य "C" व्योम
__wrap_ssh_packet_disconnect(काष्ठा ssh *ssh, स्थिर अक्षर *fmt, ...)
{
	(व्योम)ssh;
	(व्योम)fmt;
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_निकास(1);
}

बाह्य "C" पूर्णांक
__wrap_sshpkt_fatal(काष्ठा ssh *ssh, पूर्णांक r, स्थिर अक्षर *fmt, ...)
{
	(व्योम)ssh;
	(व्योम)fmt;
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, 1);
	_निकास(r ? r : 1);
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

अटल काष्ठा ssh *g_client = शून्य;
अटल काष्ठा ssh *g_server = शून्य;
अटल पूर्णांक g_init = 0;
अटल पूर्णांक g_pipe[2] = { -1, -1 };

अटल व्योम
dummy_open_confirm(काष्ठा ssh *ssh, पूर्णांक id, पूर्णांक success, व्योम *ctx)
{
	(व्योम)ssh;
	(व्योम)id;
	(व्योम)success;
	(व्योम)ctx;
}

अटल व्योम
dummy_status_confirm(काष्ठा ssh *ssh, पूर्णांक type, Channel *c, व्योम *ctx)
{
	(व्योम)ssh;
	(व्योम)type;
	(व्योम)c;
	(व्योम)ctx;
}

अटल व्योम
dummy_status_abandon(काष्ठा ssh *ssh, Channel *c, व्योम *ctx)
{
	(व्योम)ssh;
	(व्योम)c;
	(व्योम)ctx;
}

अटल पूर्णांक
init_once(व्योम)
{
	अगर (g_init)
		वापस 0;
	संकेत(SIGPIPE, संक_छोड़ो);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	पूर्णांक pfd[2];
	अगर (pipe(pfd) != 0)
		वापस -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	बंद(pfd[0]);
	बंद(pfd[1]);
	अगर (g_pipe[0] < 0 || g_pipe[1] < 0)
		वापस -1;
	पूर्णांक fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	पूर्णांक fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(व्योम)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(व्योम)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

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

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_तथ्य,
	    &channel_निवेश_तथ्य);
	ssh_dispatch_set(g_client, SSH2_संदेश_CHANNEL_EXTENDED_तथ्य,
	    &channel_निवेश_extended_तथ्य);
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
	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	g_init = 1;
	वापस 0;
}

काष्ठा chan_scenario {
	स्थिर अक्षर *ctype;
	पूर्णांक state;
	पूर्णांक use_pipe;
};

अटल स्थिर काष्ठा chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

अटल पूर्णांक g_channel_id = -1;

अटल व्योम
drain_pipe(व्योम)
{
	अक्षर buf[4096];
	अगर (g_pipe[0] < 0)
		वापस;
	जबतक (पढ़ो(g_pipe[0], buf, माप(buf)) > 0) { }
}

अटल व्योम
reset_channel(काष्ठा ssh *ssh, स्थिर काष्ठा chan_scenario *s)
{
	अगर (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		अगर (c != शून्य)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	पूर्णांक rfd = s->use_pipe ? g_pipe[1] : -1;
	पूर्णांक wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (अक्षर *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (अक्षर *)"fuzz", 0);
	अगर (c == शून्य)
		वापस;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, शून्य);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, शून्य);
}

अटल स्थिर uint8_t k_संदेश_types[] = {
	SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION,
	SSH2_संदेश_CHANNEL_OPEN_FAILURE,
	SSH2_संदेश_CHANNEL_WINDOW_ADJUST,
	SSH2_संदेश_CHANNEL_तथ्य,
	SSH2_संदेश_CHANNEL_EXTENDED_तथ्य,
	SSH2_संदेश_CHANNEL_SUCCESS,
	SSH2_संदेश_CHANNEL_FAILURE,
	SSH2_संदेश_CHANNEL_EOF,
	SSH2_संदेश_CHANNEL_CLOSE,
};

बाह्य "C" पूर्णांक
LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (init_once() != 0)
		वापस 0;
	अगर (आकार > 65000)
		वापस 0;

	स्थिर माप_प्रकार n_scen = माप(k_scenarios) / माप(k_scenarios[0]);
	स्थिर माप_प्रकार n_संदेश = माप(k_संदेश_types) / माप(k_संदेश_types[0]);

	क्रम (माप_प्रकार s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		क्रम (माप_प्रकार t = 0; t < n_संदेश; t++) {
			in_fuzz = 1;
			अगर (बनाओ_लाँघ(fuzz_env) == 0) {
				माप_प्रकार transferred;
				अगर (ssh_packet_put(g_server, k_संदेश_types[t],
				    तथ्य, आकार) != 0)
					जाओ done;
				अगर (pump(g_server, g_client,
				    &transferred) != 0)
					जाओ done;
				(व्योम)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, शून्य);
			done:
				;
			}
			in_fuzz = 0;
			मुक्त(g_open_failure_संदेश);
			g_open_failure_संदेश = शून्य;
		}
	}
	वापस 0;
}
