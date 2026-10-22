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

#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

બાહ્ય "C" {
#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "channels.h"
}


#અન્તર્ભાવ "fixed-keys.h"

સ્થિર jmp_buf fuzz_env;
સ્થિર અસ્થિર પૂર્ણાંક in_fuzz = 0;

સ્થિર અક્ષર *g_open_failure_સંદેશ = ખાલી;

બાહ્ય "C" પૂર્ણાંક
my_channel_આગત_open_failure(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	(શૂન્ય)type;
	(શૂન્ય)seq;
	uint32_t reason;
	પૂર્ણાંક r;
	જો ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	જો ((r = sshpkt_get_cstring(ssh, &g_open_failure_સંદેશ, ખાલી)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ખાલી, ખાલી)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	પાછા 0;
}

બાહ્ય "C" શૂન્ય
cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

બાહ્ય "C" શૂન્ય
__wrap_ssh_packet_disconnect(સંરચના ssh *ssh, અચલ અક્ષર *fmt, ...)
{
	(શૂન્ય)ssh;
	(શૂન્ય)fmt;
	જો (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

બાહ્ય "C" પૂર્ણાંક
__wrap_sshpkt_fatal(સંરચના ssh *ssh, પૂર્ણાંક r, અચલ અક્ષર *fmt, ...)
{
	(શૂન્ય)ssh;
	(શૂન્ય)fmt;
	જો (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

સ્થિર સંરચના sshkey *
load_private(અચલ અક્ષર *str)
{
	સંરચના sshbuf *b = sshbuf_from(str, strlen(str));
	સંરચના sshkey *k = ખાલી;
	જો (b == ખાલી || sshkey_parse_private_fileblob(b, "", &k, ખાલી) != 0)
		abort();
	sshbuf_free(b);
	પાછા k;
}

સ્થિર સંરચના sshkey *
load_public(અચલ અક્ષર *str)
{
	અક્ષર *tmp, *cp;
	સંરચના sshkey *k = sshkey_new(ચાવી_UNSPEC);
	જો (k == ખાલી)
		abort();
	tmp = cp = strdup(str);
	જો (sshkey_read(k, &cp) != 0)
		abort();
	મુક્ત(tmp);
	પાછા k;
}

સ્થિર પૂર્ણાંક
pump(સંરચના ssh *from, સંરચના ssh *to, size_t *transferred)
{
	અચલ u_char *buf;
	size_t len;
	u_char type;
	પૂર્ણાંક r;
	*transferred = 0;
	જો ((r = ssh_packet_next(from, &type)) != 0)
		પાછા r;
	buf = ssh_output_ptr(from, &len);
	જો (len == 0)
		પાછા 0;
	જો ((r = ssh_આગત_append(to, buf, len)) != 0)
		પાછા r;
	જો ((r = ssh_output_consume(from, len)) != 0)
		પાછા r;
	*transferred = len;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
run_kex(સંરચના ssh *client, સંરચના ssh *server)
{
	પૂર્ણાંક r;
	size_t cn, sn;
	માટે (પૂર્ણાંક i = 0; i < 100; i++) {
		જો ((r = pump(server, client, &sn)) != 0) પાછા r;
		જો ((r = pump(client, server, &cn)) != 0) પાછા r;
		જો (server->kex->done && client->kex->done)
			પાછા 0;
		જો (cn == 0 && sn == 0)
			પાછા SSH_ERR_PROTOCOL_ERROR;
	}
	પાછા SSH_ERR_PROTOCOL_ERROR;
}

સ્થિર સંરચના ssh *g_client = ખાલી;
સ્થિર સંરચના ssh *g_server = ખાલી;
સ્થિર પૂર્ણાંક g_init = 0;
સ્થિર પૂર્ણાંક g_pipe[2] = { -1, -1 };

સ્થિર શૂન્ય
dummy_open_confirm(સંરચના ssh *ssh, પૂર્ણાંક id, પૂર્ણાંક success, શૂન્ય *ctx)
{
	(શૂન્ય)ssh;
	(શૂન્ય)id;
	(શૂન્ય)success;
	(શૂન્ય)ctx;
}

સ્થિર શૂન્ય
dummy_status_confirm(સંરચના ssh *ssh, પૂર્ણાંક type, Channel *c, શૂન્ય *ctx)
{
	(શૂન્ય)ssh;
	(શૂન્ય)type;
	(શૂન્ય)c;
	(શૂન્ય)ctx;
}

સ્થિર શૂન્ય
dummy_status_abandon(સંરચના ssh *ssh, Channel *c, શૂન્ય *ctx)
{
	(શૂન્ય)ssh;
	(શૂન્ય)c;
	(શૂન્ય)ctx;
}

સ્થિર પૂર્ણાંક
init_once(શૂન્ય)
{
	જો (g_init)
		પાછા 0;
	સંકેત(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	પૂર્ણાંક pfd[2];
	જો (પ્રણાલ(pfd) != 0)
		પાછા -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	જો (g_pipe[0] < 0 || g_pipe[1] < 0)
		પાછા -1;
	પૂર્ણાંક fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	પૂર્ણાંક fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(શૂન્ય)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(શૂન્ય)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	સંરચના sshkey *priv = load_private(PRIV_ED25519);
	સંરચના sshkey *pub = load_public(PUB_ED25519);
	અક્ષર *keyname = xstrdup(sshkey_ssh_name(priv));

	અચલ અક્ષર *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *proposal[PROPOSAL_MAX] = { 0 };
	પૂર્ણાંક i;
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		અચલ અક્ષર *p = defaults[i];
		જો (i == PROPOSAL_SERVER_HOST_ચાવી_ALGS)
			p = keyname;
		નહીંતર જો (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		નહીંતર જો (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		નહીંતર જો (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	સંરચના kex_params kp;
	memcpy(kp.proposal, proposal, કદ(proposal));

	જો (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		પાછા -1;
	જો (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		પાછા -1;
	જો (run_kex(g_client, g_server) != 0)
		પાછા -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_DATA,
	    &channel_આગત_data);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_EXTENDED_DATA,
	    &channel_આગત_extended_data);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_EOF,
	    &channel_આગત_ieof);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_CLOSE,
	    &channel_આગત_oclose);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION,
	    &channel_આગત_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_OPEN_FAILURE,
	    &my_channel_આગત_open_failure);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST,
	    &channel_આગત_window_adjust);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_SUCCESS,
	    &channel_આગત_status_confirm);
	ssh_dispatch_set(g_client, SSH2_સંદેશ_CHANNEL_FAILURE,
	    &channel_આગત_status_confirm);

	મુક્ત(keyname);
	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(proposal[i]);
	g_init = 1;
	પાછા 0;
}

સંરચના chan_scenario {
	અચલ અક્ષર *ctype;
	પૂર્ણાંક state;
	પૂર્ણાંક use_pipe;
};

સ્થિર અચલ સંરચના chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

સ્થિર પૂર્ણાંક g_channel_id = -1;

સ્થિર શૂન્ય
drain_pipe(શૂન્ય)
{
	અક્ષર buf[4096];
	જો (g_pipe[0] < 0)
		પાછા;
	જ્યારે (પઠ(g_pipe[0], buf, કદ(buf)) > 0) { }
}

સ્થિર શૂન્ય
reset_channel(સંરચના ssh *ssh, અચલ સંરચના chan_scenario *s)
{
	જો (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		જો (c != ખાલી)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	પૂર્ણાંક rfd = s->use_pipe ? g_pipe[1] : -1;
	પૂર્ણાંક wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (અક્ષર *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (અક્ષર *)"fuzz", 0);
	જો (c == ખાલી)
		પાછા;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ખાલી);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, ખાલી);
}

સ્થિર અચલ uint8_t k_સંદેશ_types[] = {
	SSH2_સંદેશ_CHANNEL_OPEN_CONFIRMATION,
	SSH2_સંદેશ_CHANNEL_OPEN_FAILURE,
	SSH2_સંદેશ_CHANNEL_WINDOW_ADJUST,
	SSH2_સંદેશ_CHANNEL_DATA,
	SSH2_સંદેશ_CHANNEL_EXTENDED_DATA,
	SSH2_સંદેશ_CHANNEL_SUCCESS,
	SSH2_સંદેશ_CHANNEL_FAILURE,
	SSH2_સંદેશ_CHANNEL_EOF,
	SSH2_સંદેશ_CHANNEL_CLOSE,
};

બાહ્ય "C" પૂર્ણાંક
LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size)
{
	જો (init_once() != 0)
		પાછા 0;
	જો (size > 65000)
		પાછા 0;

	અચલ size_t n_scen = કદ(k_scenarios) / કદ(k_scenarios[0]);
	અચલ size_t n_સંદેશ = કદ(k_સંદેશ_types) / કદ(k_સંદેશ_types[0]);

	માટે (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		માટે (size_t t = 0; t < n_સંદેશ; t++) {
			in_fuzz = 1;
			જો (setjmp(fuzz_env) == 0) {
				size_t transferred;
				જો (ssh_packet_put(g_server, k_સંદેશ_types[t],
				    data, size) != 0)
					જાઓ done;
				જો (pump(g_server, g_client,
				    &transferred) != 0)
					જાઓ done;
				(શૂન્ય)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, ખાલી);
			done:
				;
			}
			in_fuzz = 0;
			મુક્ત(g_open_failure_સંદેશ);
			g_open_failure_સંદેશ = ખાલી;
		}
	}
	પાછા 0;
}
