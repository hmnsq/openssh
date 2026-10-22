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

#ضمن <fcntl.h>
#ضمن <setjmp.h>
#ضمن <signal.h>
#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

خارجي "C" {
#ضمن "includes.h"
#ضمن "ssherr.h"
#ضمن "ssh_api.h"
#ضمن "sshbuf.h"
#ضمن "packet.h"
#ضمن "myproposal.h"
#ضمن "kex.h"
#ضمن "xmalloc.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "log.h"
#ضمن "ssh2.h"
#ضمن "channels.h"
}


#ضمن "fixed-keys.h"

ساكن jmp_buf fuzz_env;
ساكن متطاير صحيح in_fuzz = 0;

ساكن حرف *g_open_failure_msg = عدم;

خارجي "C" صحيح
my_channel_input_open_failure(صحيح type, uint32_t seq, بنية ssh *ssh)
{
	(فراغ)type;
	(فراغ)seq;
	uint32_t reason;
	صحيح r;
	אם ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	אם ((r = sshpkt_get_cstring(ssh, &g_open_failure_msg, عدم)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, عدم, عدم)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	החזר 0;
}

خارجي "C" فراغ
cleanup_exit(صحيح code)
{
	אם (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

خارجي "C" فراغ
__wrap_ssh_packet_disconnect(بنية ssh *ssh, ثابت حرف *fmt, ...)
{
	(فراغ)ssh;
	(فراغ)fmt;
	אם (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

خارجي "C" صحيح
__wrap_sshpkt_fatal(بنية ssh *ssh, صحيح r, ثابت حرف *fmt, ...)
{
	(فراغ)ssh;
	(فراغ)fmt;
	אם (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ساكن بنية sshkey *
load_private(ثابت حرف *str)
{
	بنية sshbuf *b = sshbuf_from(str, strlen(str));
	بنية sshkey *k = عدم;
	אם (b == عدم || sshkey_parse_private_fileblob(b, "", &k, عدم) != 0)
		abort();
	sshbuf_free(b);
	החזר k;
}

ساكن بنية sshkey *
load_public(ثابت حرف *str)
{
	حرف *tmp, *cp;
	بنية sshkey *k = sshkey_new(KEY_UNSPEC);
	אם (k == عدم)
		abort();
	tmp = cp = strdup(str);
	אם (sshkey_read(k, &cp) != 0)
		abort();
	حرر(tmp);
	החזר k;
}

ساكن صحيح
pump(بنية ssh *from, بنية ssh *to, size_t *transferred)
{
	ثابت u_char *buf;
	size_t len;
	u_char type;
	صحيح r;
	*transferred = 0;
	אם ((r = ssh_packet_next(from, &type)) != 0)
		החזר r;
	buf = ssh_output_ptr(from, &len);
	אם (len == 0)
		החזר 0;
	אם ((r = ssh_input_append(to, buf, len)) != 0)
		החזר r;
	אם ((r = ssh_output_consume(from, len)) != 0)
		החזר r;
	*transferred = len;
	החזר 0;
}

ساكن صحيح
run_kex(بنية ssh *client, بنية ssh *server)
{
	صحيح r;
	size_t cn, sn;
	עבור (صحيح i = 0; i < 100; i++) {
		אם ((r = pump(server, client, &sn)) != 0) החזר r;
		אם ((r = pump(client, server, &cn)) != 0) החזר r;
		אם (server->kex->done && client->kex->done)
			החזר 0;
		אם (cn == 0 && sn == 0)
			החזר SSH_ERR_PROTOCOL_ERROR;
	}
	החזר SSH_ERR_PROTOCOL_ERROR;
}

ساكن بنية ssh *g_client = عدم;
ساكن بنية ssh *g_server = عدم;
ساكن صحيح g_init = 0;
ساكن صحيح g_pipe[2] = { -1, -1 };

ساكن فراغ
dummy_open_confirm(بنية ssh *ssh, صحيح id, صحيح success, فراغ *ctx)
{
	(فراغ)ssh;
	(فراغ)id;
	(فراغ)success;
	(فراغ)ctx;
}

ساكن فراغ
dummy_status_confirm(بنية ssh *ssh, صحيح type, Channel *c, فراغ *ctx)
{
	(فراغ)ssh;
	(فراغ)type;
	(فراغ)c;
	(فراغ)ctx;
}

ساكن فراغ
dummy_status_abandon(بنية ssh *ssh, Channel *c, فراغ *ctx)
{
	(فراغ)ssh;
	(فراغ)c;
	(فراغ)ctx;
}

ساكن صحيح
init_once(فراغ)
{
	אם (g_init)
		החזר 0;
	إشارة(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	صحيح pfd[2];
	אם (أنبوب(pfd) != 0)
		החזר -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	אם (g_pipe[0] < 0 || g_pipe[1] < 0)
		החזר -1;
	صحيح fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	صحيح fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(فراغ)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(فراغ)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	بنية sshkey *priv = load_private(PRIV_ED25519);
	بنية sshkey *pub = load_public(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحيح i;
	עבור (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		אם (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			p = keyname;
		אחרת אם (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		אחרת אם (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		אחרת אם (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	بنية kex_params kp;
	memcpy(kp.proposal, proposal, حجم(proposal));

	אם (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		החזר -1;
	אם (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		החזר -1;
	אם (run_kex(g_client, g_server) != 0)
		החזר -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_DATA,
	    &channel_input_data);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_EXTENDED_DATA,
	    &channel_input_extended_data);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_EOF,
	    &channel_input_ieof);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_CLOSE,
	    &channel_input_oclose);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,
	    &channel_input_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_OPEN_FAILURE,
	    &my_channel_input_open_failure);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_WINDOW_ADJUST,
	    &channel_input_window_adjust);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_SUCCESS,
	    &channel_input_status_confirm);
	ssh_dispatch_set(g_client, SSH2_MSG_CHANNEL_FAILURE,
	    &channel_input_status_confirm);

	حرر(keyname);
	עבור (i = 0; i < PROPOSAL_MAX; i++)
		حرر(proposal[i]);
	g_init = 1;
	החזר 0;
}

بنية chan_scenario {
	ثابت حرف *ctype;
	صحيح state;
	صحيح use_pipe;
};

ساكن ثابت بنية chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

ساكن صحيح g_channel_id = -1;

ساكن فراغ
drain_pipe(فراغ)
{
	حرف buf[4096];
	אם (g_pipe[0] < 0)
		החזר;
	כלעוד (اقرأ(g_pipe[0], buf, حجم(buf)) > 0) { }
}

ساكن فراغ
reset_channel(بنية ssh *ssh, ثابت بنية chan_scenario *s)
{
	אם (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		אם (c != عدم)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	صحيح rfd = s->use_pipe ? g_pipe[1] : -1;
	صحيح wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (حرف *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (حرف *)"fuzz", 0);
	אם (c == عدم)
		החזר;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, عدم);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, عدم);
}

ساكن ثابت uint8_t k_msg_types[] = {
	SSH2_MSG_CHANNEL_OPEN_CONFIRMATION,
	SSH2_MSG_CHANNEL_OPEN_FAILURE,
	SSH2_MSG_CHANNEL_WINDOW_ADJUST,
	SSH2_MSG_CHANNEL_DATA,
	SSH2_MSG_CHANNEL_EXTENDED_DATA,
	SSH2_MSG_CHANNEL_SUCCESS,
	SSH2_MSG_CHANNEL_FAILURE,
	SSH2_MSG_CHANNEL_EOF,
	SSH2_MSG_CHANNEL_CLOSE,
};

خارجي "C" صحيح
LLVMFuzzerTestOneInput(ثابت uint8_t *data, size_t size)
{
	אם (init_once() != 0)
		החזר 0;
	אם (size > 65000)
		החזר 0;

	ثابت size_t n_scen = حجم(k_scenarios) / حجم(k_scenarios[0]);
	ثابت size_t n_msg = حجم(k_msg_types) / حجم(k_msg_types[0]);

	עבור (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		עבור (size_t t = 0; t < n_msg; t++) {
			in_fuzz = 1;
			אם (setjmp(fuzz_env) == 0) {
				size_t transferred;
				אם (ssh_packet_put(g_server, k_msg_types[t],
				    data, size) != 0)
					اذهب done;
				אם (pump(g_server, g_client,
				    &transferred) != 0)
					اذهب done;
				(فراغ)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, عدم);
			done:
				;
			}
			in_fuzz = 0;
			حرر(g_open_failure_msg);
			g_open_failure_msg = عدم;
		}
	}
	החזר 0;
}
