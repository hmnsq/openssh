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
ಸ್ಥಿರ ಅಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳ_fuzz = 0;

ಸ್ಥಿರ ಅಕ್ಷರ *g_open_failure_ಸಂದೇಶ = ಖಾಲಿ;

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ
my_channel_ಒಳಹರಿವು_open_failure(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	(ಶೂನ್ಯ)type;
	(ಶೂನ್ಯ)seq;
	uint32_t reason;
	ಪೂರ್ಣಾಂಕ r;
	ಆದರೆ ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &g_open_failure_ಸಂದೇಶ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_string_ನೇರ(ssh, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ಹಿಂತಿರುಗಿ 0;
}

ಬಾಹ್ಯ "C" ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ ಸಂಕೇತ_2)
{
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, ಸಂಕೇತ_2 ? ಸಂಕೇತ_2 : 1);
	_exit(ಸಂಕೇತ_2);
}

ಬಾಹ್ಯ "C" ಶೂನ್ಯ
__wrap_ssh_packet_disconnect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ
__wrap_sshpkt_fatal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ರಚನೆ sshbuf *b = sshbuf_from(str, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(str));
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಆದರೆ (b == ಖಾಲಿ || sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &k, ಖಾಲಿ) != 0)
		abort();
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಆದರೆ (k == ಖಾಲಿ)
		abort();
	tmp = cp = strdup(str);
	ಆದರೆ (sshkey_read(k, &cp) != 0)
		abort();
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pump(ರಚನೆ ssh *from, ರಚನೆ ssh *ಗಮ್ಯ, ಗಾತ್ರ_t *transferred)
{
	ಸ್ಥಿರಾಂಕ u_char *buf;
	ಗಾತ್ರ_t len;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;
	*transferred = 0;
	ಆದರೆ ((r = ssh_packet_ಮುಂದಿನ(from, &type)) != 0)
		ಹಿಂತಿರುಗಿ r;
	buf = ssh_output_ptr(from, &len);
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = ssh_ಒಳಹರಿವು_append(ಗಮ್ಯ, buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = ssh_output_consume(from, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	*transferred = len;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಸತತ_kex(ರಚನೆ ssh *client, ರಚನೆ ssh *server)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t cn, sn;
	ಗಾಗಿ (ಪೂರ್ಣಾಂಕ i = 0; i < 100; i++) {
		ಆದರೆ ((r = pump(server, client, &sn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((r = pump(client, server, &cn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (server->kex->ಮುಗಿದ && client->kex->ಮುಗಿದ)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (cn == 0 && sn == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
}

ಸ್ಥಿರ ರಚನೆ ssh *g_client = ಖಾಲಿ;
ಸ್ಥಿರ ರಚನೆ ssh *g_server = ಖಾಲಿ;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_init = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_pipe[2] = { -1, -1 };

ಸ್ಥಿರ ಶೂನ್ಯ
dummy_open_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ id, ಪೂರ್ಣಾಂಕ success, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)id;
	(ಶೂನ್ಯ)success;
	(ಶೂನ್ಯ)ctx;
}

ಸ್ಥಿರ ಶೂನ್ಯ
dummy_ಸ್ಥಿತಿ_confirm(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type, Channel *c, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)type;
	(ಶೂನ್ಯ)c;
	(ಶೂನ್ಯ)ctx;
}

ಸ್ಥಿರ ಶೂನ್ಯ
dummy_ಸ್ಥಿತಿ_abandon(ರಚನೆ ssh *ssh, Channel *c, ಶೂನ್ಯ *ctx)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)c;
	(ಶೂನ್ಯ)ctx;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
init_once(ಶೂನ್ಯ)
{
	ಆದರೆ (g_init)
		ಹಿಂತಿರುಗಿ 0;
	ಸಂಕೇತ(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ಪೂರ್ಣಾಂಕ pfd[2];
	ಆದರೆ (ಪ್ರಣಾಲ(pfd) != 0)
		ಹಿಂತಿರುಗಿ -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	ಆದರೆ (g_pipe[0] < 0 || g_pipe[1] < 0)
		ಹಿಂತಿರುಗಿ -1;
	ಪೂರ್ಣಾಂಕ fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	ಪೂರ್ಣಾಂಕ fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(ಶೂನ್ಯ)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(ಶೂನ್ಯ)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	ರಚನೆ sshkey *priv = ತುಂಬು_ಖಾಸಗಿ(PRIV_ED25519);
	ರಚನೆ sshkey *pub = ತುಂಬು_ಬಹಿರಂಗ(PUB_ED25519);
	ಅಕ್ಷರ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p = defaults[i];
		ಆದರೆ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ರಚನೆ kex_params kp;
	ಸ್ಮರಣೆ_ನಕಲು(kp.proposal, proposal, ಗಾತ್ರ(proposal));

	ಆದರೆ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ssh_ಕೂಡಿಸು_hostkey(g_server, priv) != 0 ||
	    ssh_ಕೂಡಿಸು_hostkey(g_client, pub) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ಸತತ_kex(g_client, g_server) != 0)
		ಹಿಂತಿರುಗಿ -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ,
	    &channel_ಒಳಹರಿವು_ದತ್ತಾಂಶ);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ,
	    &channel_ಒಳಹರಿವು_extended_ದತ್ತಾಂಶ);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_EOF,
	    &channel_ಒಳಹರಿವು_ieof);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_CLOSE,
	    &channel_ಒಳಹರಿವು_oclose);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION,
	    &channel_ಒಳಹರಿವು_open_confirmation);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE,
	    &my_channel_ಒಳಹರಿವು_open_failure);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST,
	    &channel_ಒಳಹರಿವು_ಕಿಟಕಿ_adjust);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS,
	    &channel_ಒಳಹರಿವು_ಸ್ಥಿತಿ_confirm);
	ssh_dispatch_ಗಣ(g_client, SSH2_ಸಂದೇಶ_CHANNEL_FAILURE,
	    &channel_ಒಳಹರಿವು_ಸ್ಥಿತಿ_confirm);

	ಬಿಡುಗಡೆ(keyname);
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(proposal[i]);
	g_init = 1;
	ಹಿಂತಿರುಗಿ 0;
}

ರಚನೆ chan_scenario {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ctype;
	ಪೂರ್ಣಾಂಕ state;
	ಪೂರ್ಣಾಂಕ use_pipe;
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_channel_id = -1;

ಸ್ಥಿರ ಶೂನ್ಯ
drain_pipe(ಶೂನ್ಯ)
{
	ಅಕ್ಷರ buf[4096];
	ಆದರೆ (g_pipe[0] < 0)
		ಹಿಂತಿರುಗಿ;
	ಆಗ (ಪಠ(g_pipe[0], buf, ಗಾತ್ರ(buf)) > 0) { }
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_channel(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ chan_scenario *s)
{
	ಆದರೆ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ಆದರೆ (c != ಖಾಲಿ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	ಪೂರ್ಣಾಂಕ rfd = s->use_pipe ? g_pipe[1] : -1;
	ಪೂರ್ಣಾಂಕ wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (ಅಕ್ಷರ *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (ಅಕ್ಷರ *)"fuzz", 0);
	ಆದರೆ (c == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	g_channel_id = c->self;
	channel_ರಿಜಿಸ್ಟರ್_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ಖಾಲಿ);
	channel_ರಿಜಿಸ್ಟರ್_ಸ್ಥಿತಿ_confirm(ssh, g_channel_id,
	    &dummy_ಸ್ಥಿತಿ_confirm, &dummy_ಸ್ಥಿತಿ_abandon, ಖಾಲಿ);
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ uint8_t k_ಸಂದೇಶ_types[] = {
	SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION,
	SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE,
	SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST,
	SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ,
	SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ,
	SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS,
	SSH2_ಸಂದೇಶ_CHANNEL_FAILURE,
	SSH2_ಸಂದೇಶ_CHANNEL_EOF,
	SSH2_ಸಂದೇಶ_CHANNEL_CLOSE,
};

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಂಕ
LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (init_once() != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (ಗಾತ್ರ_2 > 65000)
		ಹಿಂತಿರುಗಿ 0;

	ಸ್ಥಿರಾಂಕ ಗಾತ್ರ_t n_scen = ಗಾತ್ರ(k_scenarios) / ಗಾತ್ರ(k_scenarios[0]);
	ಸ್ಥಿರಾಂಕ ಗಾತ್ರ_t n_ಸಂದೇಶ = ಗಾತ್ರ(k_ಸಂದೇಶ_types) / ಗಾತ್ರ(k_ಸಂದೇಶ_types[0]);

	ಗಾಗಿ (ಗಾತ್ರ_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		ಗಾಗಿ (ಗಾತ್ರ_t t = 0; t < n_ಸಂದೇಶ; t++) {
			ಒಳ_fuzz = 1;
			ಆದರೆ (setjmp(fuzz_env) == 0) {
				ಗಾತ್ರ_t transferred;
				ಆದರೆ (ssh_packet_put(g_server, k_ಸಂದೇಶ_types[t],
				    ದತ್ತಾಂಶ, ಗಾತ್ರ_2) != 0)
					ಹೋಗು ಮುಗಿದ;
				ಆದರೆ (pump(g_server, g_client,
				    &transferred) != 0)
					ಹೋಗು ಮುಗಿದ;
				(ಶೂನ್ಯ)ssh_dispatch_ಸತತ(g_client,
				    DISPATCH_NONBLOCK, ಖಾಲಿ);
			ಮುಗಿದ:
				;
			}
			ಒಳ_fuzz = 0;
			ಬಿಡುಗಡೆ(g_open_failure_ಸಂದೇಶ);
			g_open_failure_ಸಂದೇಶ = ಖಾಲಿ;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}
