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

বাহ্যিক "C" {
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
স্থির অস্থির পূর্ণসংখ্যা in_fuzz = 0;

স্থির অক্ষর *g_open_failure_বার্তা = ফাঁকা;

বাহ্যিক "C" পূর্ণসংখ্যা
my_channel_প্রবেশ_open_failure(পূর্ণসংখ্যা type, uint32_t seq, কাঠামো ssh *ssh)
{
	(শূন্য)type;
	(শূন্য)seq;
	uint32_t reason;
	পূর্ণসংখ্যা r;
	যদি ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	যদি ((r = sshpkt_get_cstring(ssh, &g_open_failure_বার্তা, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ফাঁকা, ফাঁকা)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ফেরত 0;
}

বাহ্যিক "C" শূন্য
cleanup_exit(পূর্ণসংখ্যা code)
{
	যদি (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

বাহ্যিক "C" শূন্য
__wrap_ssh_packet_disconnect(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

বাহ্যিক "C" পূর্ণসংখ্যা
__wrap_sshpkt_fatal(কাঠামো ssh *ssh, পূর্ণসংখ্যা r, ধ্রুবক অক্ষর *fmt, ...)
{
	(শূন্য)ssh;
	(শূন্য)fmt;
	যদি (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

স্থির কাঠামো sshkey *
load_private(ধ্রুবক অক্ষর *str)
{
	কাঠামো sshbuf *b = sshbuf_from(str, strlen(str));
	কাঠামো sshkey *k = ফাঁকা;
	যদি (b == ফাঁকা || sshkey_parse_private_fileblob(b, "", &k, ফাঁকা) != 0)
		abort();
	sshbuf_free(b);
	ফেরত k;
}

স্থির কাঠামো sshkey *
load_public(ধ্রুবক অক্ষর *str)
{
	অক্ষর *tmp, *cp;
	কাঠামো sshkey *k = sshkey_new(চাবি_UNSPEC);
	যদি (k == ফাঁকা)
		abort();
	tmp = cp = strdup(str);
	যদি (sshkey_read(k, &cp) != 0)
		abort();
	মুক্ত(tmp);
	ফেরত k;
}

স্থির পূর্ণসংখ্যা
pump(কাঠামো ssh *from, কাঠামো ssh *to, আকার_t *transferred)
{
	ধ্রুবক u_char *buf;
	আকার_t len;
	u_char type;
	পূর্ণসংখ্যা r;
	*transferred = 0;
	যদি ((r = ssh_packet_পরবর্তী(from, &type)) != 0)
		ফেরত r;
	buf = ssh_output_ptr(from, &len);
	যদি (len == 0)
		ফেরত 0;
	যদি ((r = ssh_প্রবেশ_append(to, buf, len)) != 0)
		ফেরত r;
	যদি ((r = ssh_output_consume(from, len)) != 0)
		ফেরত r;
	*transferred = len;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
run_kex(কাঠামো ssh *client, কাঠামো ssh *server)
{
	পূর্ণসংখ্যা r;
	আকার_t cn, sn;
	জন্য (পূর্ণসংখ্যা i = 0; i < 100; i++) {
		যদি ((r = pump(server, client, &sn)) != 0) ফেরত r;
		যদি ((r = pump(client, server, &cn)) != 0) ফেরত r;
		যদি (server->kex->done && client->kex->done)
			ফেরত 0;
		যদি (cn == 0 && sn == 0)
			ফেরত SSH_ERR_PROTOCOL_ERROR;
	}
	ফেরত SSH_ERR_PROTOCOL_ERROR;
}

স্থির কাঠামো ssh *g_client = ফাঁকা;
স্থির কাঠামো ssh *g_server = ফাঁকা;
স্থির পূর্ণসংখ্যা g_init = 0;
স্থির পূর্ণসংখ্যা g_pipe[2] = { -1, -1 };

স্থির শূন্য
dummy_open_confirm(কাঠামো ssh *ssh, পূর্ণসংখ্যা id, পূর্ণসংখ্যা success, শূন্য *ctx)
{
	(শূন্য)ssh;
	(শূন্য)id;
	(শূন্য)success;
	(শূন্য)ctx;
}

স্থির শূন্য
dummy_status_confirm(কাঠামো ssh *ssh, পূর্ণসংখ্যা type, Channel *c, শূন্য *ctx)
{
	(শূন্য)ssh;
	(শূন্য)type;
	(শূন্য)c;
	(শূন্য)ctx;
}

স্থির শূন্য
dummy_status_abandon(কাঠামো ssh *ssh, Channel *c, শূন্য *ctx)
{
	(শূন্য)ssh;
	(শূন্য)c;
	(শূন্য)ctx;
}

স্থির পূর্ণসংখ্যা
init_once(শূন্য)
{
	যদি (g_init)
		ফেরত 0;
	সংকেত(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	পূর্ণসংখ্যা pfd[2];
	যদি (প্রণাল(pfd) != 0)
		ফেরত -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	যদি (g_pipe[0] < 0 || g_pipe[1] < 0)
		ফেরত -1;
	পূর্ণসংখ্যা fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	পূর্ণসংখ্যা fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(শূন্য)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(শূন্য)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	কাঠামো sshkey *priv = load_private(PRIV_ED25519);
	কাঠামো sshkey *pub = load_public(PUB_ED25519);
	অক্ষর *keyname = xstrdup(sshkey_ssh_name(priv));

	ধ্রুবক অক্ষর *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	অক্ষর *proposal[PROPOSAL_MAX] = { 0 };
	পূর্ণসংখ্যা i;
	জন্য (i = 0; i < PROPOSAL_MAX; i++) {
		ধ্রুবক অক্ষর *p = defaults[i];
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
	কাঠামো kex_params kp;
	memcpy(kp.proposal, proposal, আকার(proposal));

	যদি (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ফেরত -1;
	যদি (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ফেরত -1;
	যদি (run_kex(g_client, g_server) != 0)
		ফেরত -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_তথ্য,
	    &channel_প্রবেশ_তথ্য);
	ssh_dispatch_set(g_client, SSH2_বার্তা_CHANNEL_EXTENDED_তথ্য,
	    &channel_প্রবেশ_extended_তথ্য);
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
	জন্য (i = 0; i < PROPOSAL_MAX; i++)
		মুক্ত(proposal[i]);
	g_init = 1;
	ফেরত 0;
}

কাঠামো chan_scenario {
	ধ্রুবক অক্ষর *ctype;
	পূর্ণসংখ্যা state;
	পূর্ণসংখ্যা use_pipe;
};

স্থির ধ্রুবক কাঠামো chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

স্থির পূর্ণসংখ্যা g_channel_id = -1;

স্থির শূন্য
drain_pipe(শূন্য)
{
	অক্ষর buf[4096];
	যদি (g_pipe[0] < 0)
		ফেরত;
	যখন (পঠ(g_pipe[0], buf, আকার(buf)) > 0) { }
}

স্থির শূন্য
reset_channel(কাঠামো ssh *ssh, ধ্রুবক কাঠামো chan_scenario *s)
{
	যদি (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		যদি (c != ফাঁকা)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	পূর্ণসংখ্যা rfd = s->use_pipe ? g_pipe[1] : -1;
	পূর্ণসংখ্যা wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (অক্ষর *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (অক্ষর *)"fuzz", 0);
	যদি (c == ফাঁকা)
		ফেরত;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ফাঁকা);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, ফাঁকা);
}

স্থির ধ্রুবক uint8_t k_বার্তা_types[] = {
	SSH2_বার্তা_CHANNEL_OPEN_CONFIRMATION,
	SSH2_বার্তা_CHANNEL_OPEN_FAILURE,
	SSH2_বার্তা_CHANNEL_WINDOW_ADJUST,
	SSH2_বার্তা_CHANNEL_তথ্য,
	SSH2_বার্তা_CHANNEL_EXTENDED_তথ্য,
	SSH2_বার্তা_CHANNEL_SUCCESS,
	SSH2_বার্তা_CHANNEL_FAILURE,
	SSH2_বার্তা_CHANNEL_EOF,
	SSH2_বার্তা_CHANNEL_CLOSE,
};

বাহ্যিক "C" পূর্ণসংখ্যা
LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2)
{
	যদি (init_once() != 0)
		ফেরত 0;
	যদি (আকার_2 > 65000)
		ফেরত 0;

	ধ্রুবক আকার_t n_scen = আকার(k_scenarios) / আকার(k_scenarios[0]);
	ধ্রুবক আকার_t n_বার্তা = আকার(k_বার্তা_types) / আকার(k_বার্তা_types[0]);

	জন্য (আকার_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		জন্য (আকার_t t = 0; t < n_বার্তা; t++) {
			in_fuzz = 1;
			যদি (setjmp(fuzz_env) == 0) {
				আকার_t transferred;
				যদি (ssh_packet_put(g_server, k_বার্তা_types[t],
				    তথ্য, আকার_2) != 0)
					যাও done;
				যদি (pump(g_server, g_client,
				    &transferred) != 0)
					যাও done;
				(শূন্য)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, ফাঁকা);
			done:
				;
			}
			in_fuzz = 0;
			মুক্ত(g_open_failure_বার্তা);
			g_open_failure_বার্তা = ফাঁকা;
		}
	}
	ফেরত 0;
}
