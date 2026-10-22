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

#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

ବାହ୍ୟ "C" {
#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
}


#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"

ସ୍ଥିର jmp_buf fuzz_env;
ସ୍ଥିର ଅସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fuzz = 0;

ସ୍ଥିର ଅକ୍ଷର *g_open_failure_ସନ୍ଦେଶ = ଖାଲି;

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା
my_channel_ନିବେଶ_open_failure(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	(ଶୂନ୍ୟ)type;
	(ଶୂନ୍ୟ)seq;
	uint32_t reason;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଯଦି ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ଯଦି ((r = sshpkt_get_cstring(ssh, &g_open_failure_ସନ୍ଦେଶ, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ଖାଲି, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ଫେରନ୍ତୁ 0;
}

ବାହ୍ୟ "C" ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ବାହ୍ୟ "C" ଶୂନ୍ୟ
__wrap_ssh_packet_disconnect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)fmt;
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_sshpkt_fatal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)fmt;
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
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

ସ୍ଥିର ସଂରଚନା ssh *g_client = ଖାଲି;
ସ୍ଥିର ସଂରଚନା ssh *g_server = ଖାଲି;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_init = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_pipe[2] = { -1, -1 };

ସ୍ଥିର ଶୂନ୍ୟ
dummy_open_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା id, ପୂର୍ଣ୍ଣସଂଖ୍ୟା success, ଶୂନ୍ୟ *ctx)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)id;
	(ଶୂନ୍ୟ)success;
	(ଶୂନ୍ୟ)ctx;
}

ସ୍ଥିର ଶୂନ୍ୟ
dummy_status_confirm(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, Channel *c, ଶୂନ୍ୟ *ctx)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)type;
	(ଶୂନ୍ୟ)c;
	(ଶୂନ୍ୟ)ctx;
}

ସ୍ଥିର ଶୂନ୍ୟ
dummy_status_abandon(ସଂରଚନା ssh *ssh, Channel *c, ଶୂନ୍ୟ *ctx)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)c;
	(ଶୂନ୍ୟ)ctx;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
init_once(ଶୂନ୍ୟ)
{
	ଯଦି (g_init)
		ଫେରନ୍ତୁ 0;
	ସଙ୍କେତ(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pfd[2];
	ଯଦି (ପ୍ରଣାଲ(pfd) != 0)
		ଫେରନ୍ତୁ -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	ଯଦି (g_pipe[0] < 0 || g_pipe[1] < 0)
		ଫେରନ୍ତୁ -1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(ଶୂନ୍ୟ)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(ଶୂନ୍ୟ)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

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

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_DATA,
	    &channel_ନିବେଶ_data);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_EXTENDED_DATA,
	    &channel_ନିବେଶ_extended_data);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_EOF,
	    &channel_ନିବେଶ_ieof);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_CLOSE,
	    &channel_ନିବେଶ_oclose);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_CONFIRMATION,
	    &channel_ନିବେଶ_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_FAILURE,
	    &my_channel_ନିବେଶ_open_failure);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_WINDOW_ADJUST,
	    &channel_ନିବେଶ_window_adjust);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_SUCCESS,
	    &channel_ନିବେଶ_status_confirm);
	ssh_dispatch_set(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_FAILURE,
	    &channel_ନିବେଶ_status_confirm);

	ମୁକ୍ତ(keyname);
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(proposal[i]);
	g_init = 1;
	ଫେରନ୍ତୁ 0;
}

ସଂରଚନା chan_scenario {
	ଅଚଳ ଅକ୍ଷର *ctype;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା state;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା use_pipe;
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_channel_id = -1;

ସ୍ଥିର ଶୂନ୍ୟ
drain_pipe(ଶୂନ୍ୟ)
{
	ଅକ୍ଷର buf[4096];
	ଯଦି (g_pipe[0] < 0)
		ଫେରନ୍ତୁ;
	ଯେତେବେଳେ (ପଠ(g_pipe[0], buf, ଆକାର(buf)) > 0) { }
}

ସ୍ଥିର ଶୂନ୍ୟ
reset_channel(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା chan_scenario *s)
{
	ଯଦି (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ଯଦି (c != ଖାଲି)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rfd = s->use_pipe ? g_pipe[1] : -1;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (ଅକ୍ଷର *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (ଅକ୍ଷର *)"fuzz", 0);
	ଯଦି (c == ଖାଲି)
		ଫେରନ୍ତୁ;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ଖାଲି);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, ଖାଲି);
}

ସ୍ଥିର ଅଚଳ uint8_t k_ସନ୍ଦେଶ_types[] = {
	SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_CONFIRMATION,
	SSH2_ସନ୍ଦେଶ_CHANNEL_OPEN_FAILURE,
	SSH2_ସନ୍ଦେଶ_CHANNEL_WINDOW_ADJUST,
	SSH2_ସନ୍ଦେଶ_CHANNEL_DATA,
	SSH2_ସନ୍ଦେଶ_CHANNEL_EXTENDED_DATA,
	SSH2_ସନ୍ଦେଶ_CHANNEL_SUCCESS,
	SSH2_ସନ୍ଦେଶ_CHANNEL_FAILURE,
	SSH2_ସନ୍ଦେଶ_CHANNEL_EOF,
	SSH2_ସନ୍ଦେଶ_CHANNEL_CLOSE,
};

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା
LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (init_once() != 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (size > 65000)
		ଫେରନ୍ତୁ 0;

	ଅଚଳ size_t n_scen = ଆକାର(k_scenarios) / ଆକାର(k_scenarios[0]);
	ଅଚଳ size_t n_ସନ୍ଦେଶ = ଆକାର(k_ସନ୍ଦେଶ_types) / ଆକାର(k_ସନ୍ଦେଶ_types[0]);

	ପାଇଁ (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		ପାଇଁ (size_t t = 0; t < n_ସନ୍ଦେଶ; t++) {
			in_fuzz = 1;
			ଯଦି (setjmp(fuzz_env) == 0) {
				size_t transferred;
				ଯଦି (ssh_packet_put(g_server, k_ସନ୍ଦେଶ_types[t],
				    data, size) != 0)
					ଯାଅ done;
				ଯଦି (pump(g_server, g_client,
				    &transferred) != 0)
					ଯାଅ done;
				(ଶୂନ୍ୟ)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, ଖାଲି);
			done:
				;
			}
			in_fuzz = 0;
			ମୁକ୍ତ(g_open_failure_ସନ୍ଦେଶ);
			g_open_failure_ସନ୍ଦେଶ = ଖାଲି;
		}
	}
	ଫେରନ୍ତୁ 0;
}
