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

#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

বাহ্য "C" {
#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "channels.h"
}


#অন্তর্ভাব "fixed-keys.h"

স্থির jmp_buf fuzz_env;
স্থির চঞ্চল পূর্ণাঙ্ক in_fuzz = 0;

স্থির বর্ণ *g_open_failure_বার্তা = রিক্ত;

বাহ্য "C" পূর্ণাঙ্ক
my_channel_প্রবেশ_open_failure(পূর্ণাঙ্ক type, uint32_t seq, সংরচনা ssh *ssh)
{
	(শূন্য)type;
	(শূন্য)seq;
	uint32_t reason;
	পূর্ণাঙ্ক r;
	যদি ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	যদি ((r = sshpkt_get_cstring(ssh, &g_open_failure_বার্তা, রিক্ত)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, রিক্ত, রিক্ত)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	প্রত্যাগম 0;
}

বাহ্য "C" শূন্য
cleanup_exit(পূর্ণাঙ্ক code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

বাহ্য "C" শূন্য
__wrap_ssh_packet_disconnect(সংরচনা ssh *ssh, ধ্রুব বর্ণ *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

বাহ্য "C" পূর্ণাঙ্ক
__wrap_sshpkt_fatal(সংরচনা ssh *ssh, পূর্ণাঙ্ক r, ধ্রুব বর্ণ *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

স্থির সংরচনা sshkey *
load_private(ধ্রুব বর্ণ *str)
{
	সংরচনা sshbuf *b = sshbuf_from(str, strlen(str));
	সংরচনা sshkey *k = রিক্ত;
	যদি (b == রিক্ত || sshkey_parse_private_fileblob(b, "", &k, রিক্ত) != 0)
		abort();
	sshbuf_free(b);
	প্রত্যাগম k;
}

স্থির সংরচনা sshkey *
load_public(ধ্রুব বর্ণ *str)
{
	বর্ণ *tmp, *cp;
	সংরচনা sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == রিক্ত)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	প্রত্যাগম k;
}

স্থির পূর্ণাঙ্ক
pump(সংরচনা ssh *from, সংরচনা ssh *to, size_t *transferred)
{
	ধ্রুব u_char *buf;
	size_t len;
	u_char type;
	পূর্ণাঙ্ক r;
	*transferred = 0;
	যদি ((r = ssh_packet_next(from, &type)) != 0)
		প্রত্যাগম r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		প্রত্যাগম 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		প্রত্যাগম r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		প্রত্যাগম r;
	*transferred = len;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
run_kex(সংরচনা ssh *client, সংরচনা ssh *server)
{
	পূর্ণাঙ্ক r;
	size_t cn, sn;
	প্রতি (পূর্ণাঙ্ক i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) প্রত্যাগম r;
		যদি ((r = pump(client, server, &cn)) != 0) প্রত্যাগম r;
		যদি (server->kex->done && client->kex->done)
			প্রত্যাগম 0;
		যদি (cn == 0 && sn == 0)
			প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
	}
	প্রত্যাগম SSH_ERR_PROTOCOL_ERROR;
}

স্থির সংরচনা ssh *g_client = রিক্ত;
স্থির সংরচনা ssh *g_server = রিক্ত;
স্থির পূর্ণাঙ্ক g_init = 0;
স্থির পূর্ণাঙ্ক g_pipe[2] = { -1, -1 };

স্থির শূন্য
dummy_open_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক id, পূর্ণাঙ্ক success, শূন্য *ctx)
{
	(শূন্য)ssh;
	(শূন্য)id;
	(শূন্য)success;
	(শূন্য)ctx;
}

স্থির শূন্য
dummy_status_confirm(সংরচনা ssh *ssh, পূর্ণাঙ্ক type, Channel *c, শূন্য *ctx)
{
	(শূন্য)ssh;
	(শূন্য)type;
	(শূন্য)c;
	(শূন্য)ctx;
}

স্থির শূন্য
dummy_status_abandon(সংরচনা ssh *ssh, Channel *c, শূন্য *ctx)
{
	(শূন্য)ssh;
	(শূন্য)c;
	(শূন্য)ctx;
}

স্থির পূর্ণাঙ্ক
init_once(শূন্য)
{
	যদি (g_init)
		প্রত্যাগম 0;
	সঙ্কেত(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	পূর্ণাঙ্ক pfd[2];
	যদি (প্রণাল(pfd) != 0)
		প্রত্যাগম -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	যদি (g_pipe[0] < 0 || g_pipe[1] < 0)
		প্রত্যাগম -1;
	পূর্ণাঙ্ক fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	পূর্ণাঙ্ক fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(শূন্য)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(শূন্য)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	সংরচনা sshkey *priv = load_private(PRIV_ED25519);
	সংরচনা sshkey *pub = load_public(PUB_ED25519);
	বর্ণ *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুব বর্ণ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	বর্ণ *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণাঙ্ক i;
	প্রতি (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুব বর্ণ *p = defaults[i];
		যদি (i == PROPOSAL_SERVER_HOST_চাবি_ALGS)
			p = keyname;
		অন্যথা যদি (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		অন্যথা যদি (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		অন্যথা যদি (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	সংরচনা kex_params kp;
	memcpy(kp.proposal, proposal, পরিমাণ(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		প্রত্যাগম -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		প্রত্যাগম -1;
	যদি (run_kex(g_client, g_server) != 0)
		প্রত্যাগম -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_DATA,
	    &channel_প্রবেশ_data);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_EXTENDED_DATA,
	    &channel_প্রবেশ_extended_data);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_EOF,
	    &channel_প্রবেশ_ieof);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_CLOSE,
	    &channel_প্রবেশ_oclose);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION,
	    &channel_প্রবেশ_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_OPEN_FAILURE,
	    &my_channel_প্রবেশ_open_failure);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_WINDOW_ADJUST,
	    &channel_প্রবেশ_window_adjust);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_SUCCESS,
	    &channel_প্রবেশ_status_confirm);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_FAILURE,
	    &channel_প্রবেশ_status_confirm);

	মুক্ত(keyname);
	প্রতি (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	প্রত্যাগম 0;
}

সংরচনা chan_scenario {
	ধ্রুব বর্ণ *ctype;
	পূর্ণাঙ্ক state;
	পূর্ণাঙ্ক use_pipe;
};

স্থির ধ্রুব সংরচনা chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

স্থির পূর্ণাঙ্ক g_channel_id = -1;

স্থির শূন্য
drain_pipe(শূন্য)
{
	বর্ণ buf[4096];
	যদি (g_pipe[0] < 0)
		প্রত্যাগম;
	যাবত্ (পঠ(g_pipe[0], buf, পরিমাণ(buf)) > 0) { }
}

স্থির শূন্য
reset_channel(সংরচনা ssh *ssh, ধ্রুব সংরচনা chan_scenario *s)
{
	যদি (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		যদি (c != রিক্ত)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	পূর্ণাঙ্ক rfd = s->use_pipe ? g_pipe[1] : -1;
	পূর্ণাঙ্ক wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (বর্ণ *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (বর্ণ *)"fuzz", 0);
	যদি (c == রিক্ত)
		প্রত্যাগম;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, রিক্ত);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, রিক্ত);
}

স্থির ধ্রুব uint8_t k_বার্তা_types[] = {
	SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION,
	SSH2_বার্তা_CHANNEL_OPEN_FAILURE,
	SSH2_বার্তা_CHANNEL_WINDOW_ADJUST,
	SSH2_বার্তা_CHANNEL_DATA,
	SSH2_বার্তা_CHANNEL_EXTENDED_DATA,
	SSH2_বার্তা_CHANNEL_SUCCESS,
	SSH2_বার্তা_CHANNEL_FAILURE,
	SSH2_বার্তা_CHANNEL_EOF,
	SSH2_বার্তা_CHANNEL_CLOSE,
};

বাহ্য "C" পূর্ণাঙ্ক
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুব uint8_t *data, size_t size)
{
	যদি (init_once() != 0)
		প্রত্যাগম 0;
	যদি (size > 65000)
		প্রত্যাগম 0;

	ধ্রুব size_t n_scen = পরিমাণ(k_scenarios) / পরিমাণ(k_scenarios[0]);
	ধ্রুব size_t n_বার্তা = পরিমাণ(k_বার্তা_types) / পরিমাণ(k_বার্তা_types[0]);

	প্রতি (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		প্রতি (size_t t = 0; t < n_বার্তা; t++) {
			in_fuzz = 1;
			যদি (setjmp(fuzz_env) == 0) {
				size_t transferred;
				যদি (ssh_packet_put(g_server, k_বার্তা_types[t],
				    data, size) != 0)
					গচ্ছ done;
				যদি (pump(g_server, g_client,
				    &transferred) != 0)
					গচ্ছ done;
				(শূন্য)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, রিক্ত);
			done:
				;
			}
			in_fuzz = 0;
			মুক্ত(g_open_failure_বার্তা);
			g_open_failure_বার্তা = রিক্ত;
		}
	}
	প্রত্যাগম 0;
}
