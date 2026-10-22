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

#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

ਬਾਹਰੀ "C" {
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"
}


#ਅਨ੍ਤਰ੍ਭਾਵ "fixed-keys.h"

ਸਥਿਰ jmp_buf fuzz_env;
ਸਥਿਰ ਅਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_fuzz = 0;

ਸਥਿਰ ਅੱਖਰ *g_open_failure_ਸੁਨੇਹਾ = ਨਿਰਾ;

ਬਾਹਰੀ "C" ਪੂਰਨ
my_channel_ਨਿਵੇਸ਼_open_failure(ਪੂਰਨ type, uint32_t seq, ਬਣਤਰ ssh *ssh)
{
	(ਖਾਲੀ)type;
	(ਖਾਲੀ)seq;
	uint32_t reason;
	ਪੂਰਨ r;
	ਜੇ ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ਜੇ ((r = sshpkt_get_cstring(ssh, &g_open_failure_ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_string_ਸਿੱਧਾ(ssh, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshpkt_get_ਸਿਰਾ(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ਵਾਪਸ 0;
}

ਬਾਹਰੀ "C" ਖਾਲੀ
cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

ਬਾਹਰੀ "C" ਖਾਲੀ
__wrap_ssh_packet_disconnect(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)fmt;
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ਬਾਹਰੀ "C" ਪੂਰਨ
__wrap_sshpkt_fatal(ਬਣਤਰ ssh *ssh, ਪੂਰਨ r, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)fmt;
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *str)
{
	ਬਣਤਰ sshbuf *b = sshbuf_from(str, ਲੜੀ_ਲੰਬਾਈ(str));
	ਬਣਤਰ sshkey *k = ਨਿਰਾ;
	ਜੇ (b == ਨਿਰਾ || sshkey_parse_ਨਿੱਜੀ_fileblob(b, "", &k, ਨਿਰਾ) != 0)
		abort();
	sshbuf_free(b);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਬਣਤਰ sshkey *
ਲੱਦੋ_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *str)
{
	ਅੱਖਰ *tmp, *cp;
	ਬਣਤਰ sshkey *k = sshkey_new(ਕੁੰਜੀ_UNSPEC);
	ਜੇ (k == ਨਿਰਾ)
		abort();
	tmp = cp = strdup(str);
	ਜੇ (sshkey_read(k, &cp) != 0)
		abort();
	ਮੁਕਤ(tmp);
	ਵਾਪਸ k;
}

ਸਥਿਰ ਪੂਰਨ
pump(ਬਣਤਰ ssh *from, ਬਣਤਰ ssh *ਮੰਜ਼ਿਲ, ਮਾਪ_t *transferred)
{
	ਅਚਲ u_char *buf;
	ਮਾਪ_t len;
	u_char type;
	ਪੂਰਨ r;
	*transferred = 0;
	ਜੇ ((r = ssh_packet_ਅਗਲਾ(from, &type)) != 0)
		ਵਾਪਸ r;
	buf = ssh_output_ptr(from, &len);
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ ((r = ssh_ਨਿਵੇਸ਼_append(ਮੰਜ਼ਿਲ, buf, len)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = ssh_output_consume(from, len)) != 0)
		ਵਾਪਸ r;
	*transferred = len;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਲੜੀਵਾਰ_kex(ਬਣਤਰ ssh *client, ਬਣਤਰ ssh *server)
{
	ਪੂਰਨ r;
	ਮਾਪ_t cn, sn;
	ਲਈ (ਪੂਰਨ i = 0; i < 100; i++) {
		ਜੇ ((r = pump(server, client, &sn)) != 0) ਵਾਪਸ r;
		ਜੇ ((r = pump(client, server, &cn)) != 0) ਵਾਪਸ r;
		ਜੇ (server->kex->ਪੂਰਾ && client->kex->ਪੂਰਾ)
			ਵਾਪਸ 0;
		ਜੇ (cn == 0 && sn == 0)
			ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
	}
	ਵਾਪਸ SSH_ERR_PROTOCOL_ERROR;
}

ਸਥਿਰ ਬਣਤਰ ssh *g_client = ਨਿਰਾ;
ਸਥਿਰ ਬਣਤਰ ssh *g_server = ਨਿਰਾ;
ਸਥਿਰ ਪੂਰਨ g_init = 0;
ਸਥਿਰ ਪੂਰਨ g_pipe[2] = { -1, -1 };

ਸਥਿਰ ਖਾਲੀ
dummy_open_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ id, ਪੂਰਨ success, ਖਾਲੀ *ctx)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)id;
	(ਖਾਲੀ)success;
	(ਖਾਲੀ)ctx;
}

ਸਥਿਰ ਖਾਲੀ
dummy_ਸਥਿਤੀ_confirm(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type, Channel *c, ਖਾਲੀ *ctx)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)type;
	(ਖਾਲੀ)c;
	(ਖਾਲੀ)ctx;
}

ਸਥਿਰ ਖਾਲੀ
dummy_ਸਥਿਤੀ_abandon(ਬਣਤਰ ssh *ssh, Channel *c, ਖਾਲੀ *ctx)
{
	(ਖਾਲੀ)ssh;
	(ਖਾਲੀ)c;
	(ਖਾਲੀ)ctx;
}

ਸਥਿਰ ਪੂਰਨ
init_once(ਖਾਲੀ)
{
	ਜੇ (g_init)
		ਵਾਪਸ 0;
	ਸੰਕੇਤ(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	ਪੂਰਨ pfd[2];
	ਜੇ (ਪ੍ਰਣਾਲ(pfd) != 0)
		ਵਾਪਸ -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	ਜੇ (g_pipe[0] < 0 || g_pipe[1] < 0)
		ਵਾਪਸ -1;
	ਪੂਰਨ fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	ਪੂਰਨ fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(ਖਾਲੀ)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(ਖਾਲੀ)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	ਬਣਤਰ sshkey *priv = ਲੱਦੋ_ਨਿੱਜੀ(PRIV_ED25519);
	ਬਣਤਰ sshkey *pub = ਲੱਦੋ_ਜਨਤਕ(PUB_ED25519);
	ਅੱਖਰ *keyname = xstrdup(sshkey_ssh_name(priv));

	ਅਚਲ ਅੱਖਰ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅੱਖਰ *proposal[PROPOSAL_MAX] = { 0 };
	ਪੂਰਨ i;
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++) {
		ਅਚਲ ਅੱਖਰ *p = defaults[i];
		ਜੇ (i == PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS)
			p = keyname;
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ਨਹੀਂਤਾਂ ਜੇ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ਬਣਤਰ kex_params kp;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(kp.proposal, proposal, ਆਕਾਰ(proposal));

	ਜੇ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ssh_ਜੋੜੋ_hostkey(g_server, priv) != 0 ||
	    ssh_ਜੋੜੋ_hostkey(g_client, pub) != 0)
		ਵਾਪਸ -1;
	ਜੇ (ਲੜੀਵਾਰ_kex(g_client, g_server) != 0)
		ਵਾਪਸ -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ,
	    &channel_ਨਿਵੇਸ਼_ਅੰਕੜੇ);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ,
	    &channel_ਨਿਵੇਸ਼_extended_ਅੰਕੜੇ);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_EOF,
	    &channel_ਨਿਵੇਸ਼_ieof);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE,
	    &channel_ਨਿਵੇਸ਼_oclose);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION,
	    &channel_ਨਿਵੇਸ਼_open_confirmation);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE,
	    &my_channel_ਨਿਵੇਸ਼_open_failure);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST,
	    &channel_ਨਿਵੇਸ਼_ਖਿੜਕੀ_adjust);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS,
	    &channel_ਨਿਵੇਸ਼_ਸਥਿਤੀ_confirm);
	ssh_dispatch_ਸੈੱਟ(g_client, SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE,
	    &channel_ਨਿਵੇਸ਼_ਸਥਿਤੀ_confirm);

	ਮੁਕਤ(keyname);
	ਲਈ (i = 0; i < PROPOSAL_MAX; i++)
		ਮੁਕਤ(proposal[i]);
	g_init = 1;
	ਵਾਪਸ 0;
}

ਬਣਤਰ chan_scenario {
	ਅਚਲ ਅੱਖਰ *ctype;
	ਪੂਰਨ state;
	ਪੂਰਨ use_pipe;
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

ਸਥਿਰ ਪੂਰਨ g_channel_id = -1;

ਸਥਿਰ ਖਾਲੀ
drain_pipe(ਖਾਲੀ)
{
	ਅੱਖਰ buf[4096];
	ਜੇ (g_pipe[0] < 0)
		ਵਾਪਸ;
	ਜਦੋਂ (ਪਠ(g_pipe[0], buf, ਆਕਾਰ(buf)) > 0) { }
}

ਸਥਿਰ ਖਾਲੀ
reset_channel(ਬਣਤਰ ssh *ssh, ਅਚਲ ਬਣਤਰ chan_scenario *s)
{
	ਜੇ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ਜੇ (c != ਨਿਰਾ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	ਪੂਰਨ rfd = s->use_pipe ? g_pipe[1] : -1;
	ਪੂਰਨ wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (ਅੱਖਰ *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (ਅੱਖਰ *)"fuzz", 0);
	ਜੇ (c == ਨਿਰਾ)
		ਵਾਪਸ;
	g_channel_id = c->self;
	channel_ਰਜਿਸਟਰ_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ਨਿਰਾ);
	channel_ਰਜਿਸਟਰ_ਸਥਿਤੀ_confirm(ssh, g_channel_id,
	    &dummy_ਸਥਿਤੀ_confirm, &dummy_ਸਥਿਤੀ_abandon, ਨਿਰਾ);
}

ਸਥਿਰ ਅਚਲ uint8_t k_ਸੁਨੇਹਾ_types[] = {
	SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_EOF,
	SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE,
};

ਬਾਹਰੀ "C" ਪੂਰਨ
LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (init_once() != 0)
		ਵਾਪਸ 0;
	ਜੇ (ਮਾਪ > 65000)
		ਵਾਪਸ 0;

	ਅਚਲ ਮਾਪ_t n_scen = ਆਕਾਰ(k_scenarios) / ਆਕਾਰ(k_scenarios[0]);
	ਅਚਲ ਮਾਪ_t n_ਸੁਨੇਹਾ = ਆਕਾਰ(k_ਸੁਨੇਹਾ_types) / ਆਕਾਰ(k_ਸੁਨੇਹਾ_types[0]);

	ਲਈ (ਮਾਪ_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		ਲਈ (ਮਾਪ_t t = 0; t < n_ਸੁਨੇਹਾ; t++) {
			ਵਿੱਚ_fuzz = 1;
			ਜੇ (setjmp(fuzz_env) == 0) {
				ਮਾਪ_t transferred;
				ਜੇ (ssh_packet_put(g_server, k_ਸੁਨੇਹਾ_types[t],
				    ਅੰਕੜੇ, ਮਾਪ) != 0)
					ਜਾਓ ਪੂਰਾ;
				ਜੇ (pump(g_server, g_client,
				    &transferred) != 0)
					ਜਾਓ ਪੂਰਾ;
				(ਖਾਲੀ)ssh_dispatch_ਲੜੀਵਾਰ(g_client,
				    DISPATCH_NONBLOCK, ਨਿਰਾ);
			ਪੂਰਾ:
				;
			}
			ਵਿੱਚ_fuzz = 0;
			ਮੁਕਤ(g_open_failure_ਸੁਨੇਹਾ);
			g_open_failure_ਸੁਨੇਹਾ = ਨਿਰਾ;
		}
	}
	ਵਾਪਸ 0;
}
