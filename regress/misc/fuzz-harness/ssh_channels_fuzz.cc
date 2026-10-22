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

#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

ಬಾಹ್ಯ "C" {
#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
}


#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಚಞ್ಚಲ ಪೂರ್ಣಾಙ್ಕ in_fuzz = 0;

ಸ್ಥಿರ ವರ್ಣ *g_open_failure_ಸಂದೇಶ = ರಿಕ್ತ;

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ
my_channel_ಒಳಹರಿವು_open_failure(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	(ಶೂನ್ಯ)type;
	(ಶೂನ್ಯ)seq;
	uint32_t reason;
	ಪೂರ್ಣಾಙ್ಕ r;
	ಯದಿ ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ಯದಿ ((r = sshpkt_get_cstring(ssh, &g_open_failure_ಸಂದೇಶ, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಬಾಹ್ಯ "C" ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ code)
{
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ಬಾಹ್ಯ "C" ಶೂನ್ಯ
__wrap_ssh_packet_disconnect(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ
__wrap_sshpkt_fatal(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ r, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_private(ಧ್ರುವ ವರ್ಣ *str)
{
	ಸಂರಚನಾ sshbuf *b = sshbuf_from(str, strlen(str));
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಯದಿ (b == ರಿಕ್ತ || sshkey_parse_private_fileblob(b, "", &k, ರಿಕ್ತ) != 0)
		abort();
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_public(ಧ್ರುವ ವರ್ಣ *str)
{
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಯದಿ (k == ರಿಕ್ತ)
		abort();
	tmp = cp = strdup(str);
	ಯದಿ (sshkey_read(k, &cp) != 0)
		abort();
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pump(ಸಂರಚನಾ ssh *from, ಸಂರಚನಾ ssh *to, size_t *transferred)
{
	ಧ್ರುವ u_char *buf;
	size_t len;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;
	*transferred = 0;
	ಯದಿ ((r = ssh_packet_next(from, &type)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	buf = ssh_output_ptr(from, &len);
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = ssh_ಒಳಹರಿವು_append(to, buf, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = ssh_output_consume(from, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	*transferred = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
run_kex(ಸಂರಚನಾ ssh *client, ಸಂರಚನಾ ssh *server)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t cn, sn;
	ಪ್ರತಿ (ಪೂರ್ಣಾಙ್ಕ i = 0; i < 100; i++) {
		ಯದಿ ((r = pump(server, client, &sn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((r = pump(client, server, &cn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (server->kex->done && client->kex->done)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ (cn == 0 && sn == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
}

ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_client = ರಿಕ್ತ;
ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_server = ರಿಕ್ತ;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_init = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_pipe[2] = { -1, -1 };

ಸ್ಥಿರ ಶೂನ್ಯ
dummy_open_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ id, ಪೂರ್ಣಾಙ್ಕ success, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)id;
	(ಶೂನ್ಯ)success;
	(ಶೂನ್ಯ)ctx;
}

ಸ್ಥಿರ ಶೂನ್ಯ
dummy_status_confirm(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ type, Channel *c, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)type;
	(ಶೂನ್ಯ)c;
	(ಶೂನ್ಯ)ctx;
}

ಸ್ಥಿರ ಶೂನ್ಯ
dummy_status_abandon(ಸಂರಚನಾ ssh *ssh, Channel *c, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)c;
	(ಶೂನ್ಯ)ctx;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
init_once(ಶೂನ್ಯ)
{
	ಯದಿ (g_init)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸಙ್ಕೇತ(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ಪೂರ್ಣಾಙ್ಕ pfd[2];
	ಯದಿ (ಪ್ರಣಾಲ(pfd) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	ಯದಿ (g_pipe[0] < 0 || g_pipe[1] < 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪೂರ್ಣಾಙ್ಕ fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	ಪೂರ್ಣಾಙ್ಕ fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(ಶೂನ್ಯ)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(ಶೂನ್ಯ)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	ಸಂರಚನಾ sshkey *priv = load_private(PRIV_ED25519);
	ಸಂರಚನಾ sshkey *pub = load_public(PUB_ED25519);
	ವರ್ಣ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಧ್ರುವ ವರ್ಣ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಧ್ರುವ ವರ್ಣ *p = defaults[i];
		ಯದಿ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ಸಂರಚನಾ kex_params kp;
	memcpy(kp.proposal, proposal, ಪರಿಮಾಣ(proposal));

	ಯದಿ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (run_kex(g_client, g_server) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_DATA,
	    &channel_ಒಳಹರಿವು_data);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_DATA,
	    &channel_ಒಳಹರಿವು_extended_data);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_EOF,
	    &channel_ಒಳಹರಿವು_ieof);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_CLOSE,
	    &channel_ಒಳಹರಿವು_oclose);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION,
	    &channel_ಒಳಹರಿವು_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE,
	    &my_channel_ಒಳಹರಿವು_open_failure);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_WINDOW_ADJUST,
	    &channel_ಒಳಹರಿವು_window_adjust);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS,
	    &channel_ಒಳಹರಿವು_status_confirm);
	ssh_dispatch_set(g_client, SSH2_ಸಂದೇಶ_CHANNEL_FAILURE,
	    &channel_ಒಳಹರಿವು_status_confirm);

	ಮುಕ್ತ(keyname);
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(proposal[i]);
	g_init = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸಂರಚನಾ chan_scenario {
	ಧ್ರುವ ವರ್ಣ *ctype;
	ಪೂರ್ಣಾಙ್ಕ state;
	ಪೂರ್ಣಾಙ್ಕ use_pipe;
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_channel_id = -1;

ಸ್ಥಿರ ಶೂನ್ಯ
drain_pipe(ಶೂನ್ಯ)
{
	ವರ್ಣ buf[4096];
	ಯದಿ (g_pipe[0] < 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯಾವತ್ (ಪಠ(g_pipe[0], buf, ಪರಿಮಾಣ(buf)) > 0) { }
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_channel(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಸಂರಚನಾ chan_scenario *s)
{
	ಯದಿ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ಯದಿ (c != ರಿಕ್ತ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	ಪೂರ್ಣಾಙ್ಕ rfd = s->use_pipe ? g_pipe[1] : -1;
	ಪೂರ್ಣಾಙ್ಕ wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (ವರ್ಣ *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (ವರ್ಣ *)"fuzz", 0);
	ಯದಿ (c == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ರಿಕ್ತ);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, ರಿಕ್ತ);
}

ಸ್ಥಿರ ಧ್ರುವ uint8_t k_ಸಂದೇಶ_types[] = {
	SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION,
	SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE,
	SSH2_ಸಂದೇಶ_CHANNEL_WINDOW_ADJUST,
	SSH2_ಸಂದೇಶ_CHANNEL_DATA,
	SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_DATA,
	SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS,
	SSH2_ಸಂದೇಶ_CHANNEL_FAILURE,
	SSH2_ಸಂದೇಶ_CHANNEL_EOF,
	SSH2_ಸಂದೇಶ_CHANNEL_CLOSE,
};

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (init_once() != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (size > 65000)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಧ್ರುವ size_t n_scen = ಪರಿಮಾಣ(k_scenarios) / ಪರಿಮಾಣ(k_scenarios[0]);
	ಧ್ರುವ size_t n_ಸಂದೇಶ = ಪರಿಮಾಣ(k_ಸಂದೇಶ_types) / ಪರಿಮಾಣ(k_ಸಂದೇಶ_types[0]);

	ಪ್ರತಿ (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		ಪ್ರತಿ (size_t t = 0; t < n_ಸಂದೇಶ; t++) {
			in_fuzz = 1;
			ಯದಿ (setjmp(fuzz_env) == 0) {
				size_t transferred;
				ಯದಿ (ssh_packet_put(g_server, k_ಸಂದೇಶ_types[t],
				    data, size) != 0)
					ಗಚ್ಛ done;
				ಯದಿ (pump(g_server, g_client,
				    &transferred) != 0)
					ಗಚ್ಛ done;
				(ಶೂನ್ಯ)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, ರಿಕ್ತ);
			done:
				;
			}
			in_fuzz = 0;
			ಮುಕ್ತ(g_open_failure_ಸಂದೇಶ);
			g_open_failure_ಸಂದೇಶ = ರಿಕ್ತ;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}
