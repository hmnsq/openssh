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

#شامل <fcntl.h>
#شامل <setjmp.h>
#شامل <signal.h>
#شامل <stddef.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

خارجی "C" {
#شامل "includes.h"
#شامل "ssherr.h"
#شامل "ssh_api.h"
#شامل "sshbuf.h"
#شامل "packet.h"
#شامل "myproposal.h"
#شامل "kex.h"
#شامل "xmalloc.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "log.h"
#شامل "ssh2.h"
#شامل "channels.h"
}


#شامل "fixed-keys.h"

ساکن jmp_buf fuzz_env;
ساکن متلون صحیح اندر_fuzz = 0;

ساکن حرف *g_open_failure_پیغام = تہی;

خارجی "C" صحیح
my_channel_داخلہ_open_failure(صحیح type, uint32_t seq, ساخت ssh *ssh)
{
	(خالی)type;
	(خالی)seq;
	uint32_t reason;
	صحیح r;
	اگر ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	اگر ((r = sshpkt_get_cstring(ssh, &g_open_failure_پیغام, تہی)) != 0 ||
	    (r = sshpkt_get_string_براہ_راست(ssh, تہی, تہی)) != 0 ||
	    (r = sshpkt_get_انتہا(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	واپس 0;
}

خارجی "C" خالی
cleanup_exit(صحیح رمز)
{
	اگر (اندر_fuzz)
		longjmp(fuzz_env, رمز ? رمز : 1);
	_exit(رمز);
}

خارجی "C" خالی
__wrap_ssh_packet_disconnect(ساخت ssh *ssh, ثابت حرف *fmt, ...)
{
	(خالی)ssh;
	(خالی)fmt;
	اگر (اندر_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

خارجی "C" صحیح
__wrap_sshpkt_fatal(ساخت ssh *ssh, صحیح r, ثابت حرف *fmt, ...)
{
	(خالی)ssh;
	(خالی)fmt;
	اگر (اندر_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ساکن ساخت sshkey *
بھرو_نجی(ثابت حرف *str)
{
	ساخت sshbuf *b = sshbuf_from(str, لڑی_لمبائی(str));
	ساخت sshkey *k = تہی;
	اگر (b == تہی || sshkey_parse_نجی_fileblob(b, "", &k, تہی) != 0)
		abort();
	sshbuf_free(b);
	واپس k;
}

ساکن ساخت sshkey *
بھرو_عوامی(ثابت حرف *str)
{
	حرف *tmp, *cp;
	ساخت sshkey *k = sshkey_new(کلید_UNSPEC);
	اگر (k == تہی)
		abort();
	tmp = cp = strdup(str);
	اگر (sshkey_read(k, &cp) != 0)
		abort();
	آزاد(tmp);
	واپس k;
}

ساکن صحیح
pump(ساخت ssh *from, ساخت ssh *مقصد, سائز_t *transferred)
{
	ثابت u_char *buf;
	سائز_t len;
	u_char type;
	صحیح r;
	*transferred = 0;
	اگر ((r = ssh_packet_اگلا(from, &type)) != 0)
		واپس r;
	buf = ssh_output_ptr(from, &len);
	اگر (len == 0)
		واپس 0;
	اگر ((r = ssh_داخلہ_append(مقصد, buf, len)) != 0)
		واپس r;
	اگر ((r = ssh_output_consume(from, len)) != 0)
		واپس r;
	*transferred = len;
	واپس 0;
}

ساکن صحیح
تسلسل_kex(ساخت ssh *client, ساخت ssh *server)
{
	صحیح r;
	سائز_t cn, sn;
	برائے (صحیح i = 0; i < 100; i++) {
		اگر ((r = pump(server, client, &sn)) != 0) واپس r;
		اگر ((r = pump(client, server, &cn)) != 0) واپس r;
		اگر (server->kex->مکمل && client->kex->مکمل)
			واپس 0;
		اگر (cn == 0 && sn == 0)
			واپس SSH_ERR_PROTOCOL_ERROR;
	}
	واپس SSH_ERR_PROTOCOL_ERROR;
}

ساکن ساخت ssh *g_client = تہی;
ساکن ساخت ssh *g_server = تہی;
ساکن صحیح g_init = 0;
ساکن صحیح g_pipe[2] = { -1, -1 };

ساکن خالی
dummy_open_confirm(ساخت ssh *ssh, صحیح id, صحیح success, خالی *ctx)
{
	(خالی)ssh;
	(خالی)id;
	(خالی)success;
	(خالی)ctx;
}

ساکن خالی
dummy_حالت_confirm(ساخت ssh *ssh, صحیح type, Channel *c, خالی *ctx)
{
	(خالی)ssh;
	(خالی)type;
	(خالی)c;
	(خالی)ctx;
}

ساکن خالی
dummy_حالت_abandon(ساخت ssh *ssh, Channel *c, خالی *ctx)
{
	(خالی)ssh;
	(خالی)c;
	(خالی)ctx;
}

ساکن صحیح
init_once(خالی)
{
	اگر (g_init)
		واپس 0;
	اشارہ(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	صحیح pfd[2];
	اگر (أنبوب(pfd) != 0)
		واپس -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	اگر (g_pipe[0] < 0 || g_pipe[1] < 0)
		واپس -1;
	صحیح fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	صحیح fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(خالی)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(خالی)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	ساخت sshkey *priv = بھرو_نجی(PRIV_ED25519);
	ساخت sshkey *pub = بھرو_عوامی(PUB_ED25519);
	حرف *keyname = xstrdup(sshkey_ssh_name(priv));

	ثابت حرف *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *proposal[PROPOSAL_MAX] = { 0 };
	صحیح i;
	برائے (i = 0; i < PROPOSAL_MAX; i++) {
		ثابت حرف *p = defaults[i];
		اگر (i == PROPOSAL_SERVER_HOST_کلید_ALGS)
			p = keyname;
		ورنہ اگر (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ورنہ اگر (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ورنہ اگر (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ساخت kex_params kp;
	حافظہ_نقل(kp.proposal, proposal, حجم(proposal));

	اگر (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		واپس -1;
	اگر (ssh_جوڑو_hostkey(g_server, priv) != 0 ||
	    ssh_جوڑو_hostkey(g_client, pub) != 0)
		واپس -1;
	اگر (تسلسل_kex(g_client, g_server) != 0)
		واپس -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_ڈیٹا,
	    &channel_داخلہ_ڈیٹا);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_EXTENDED_ڈیٹا,
	    &channel_داخلہ_extended_ڈیٹا);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_EOF,
	    &channel_داخلہ_ieof);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_CLOSE,
	    &channel_داخلہ_oclose);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION,
	    &channel_داخلہ_open_confirmation);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_OPEN_FAILURE,
	    &my_channel_داخلہ_open_failure);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_کھڑکی_ADJUST,
	    &channel_داخلہ_کھڑکی_adjust);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_SUCCESS,
	    &channel_داخلہ_حالت_confirm);
	ssh_dispatch_سیٹ(g_client, SSH2_پیغام_CHANNEL_FAILURE,
	    &channel_داخلہ_حالت_confirm);

	آزاد(keyname);
	برائے (i = 0; i < PROPOSAL_MAX; i++)
		آزاد(proposal[i]);
	g_init = 1;
	واپس 0;
}

ساخت chan_scenario {
	ثابت حرف *ctype;
	صحیح state;
	صحیح use_pipe;
};

ساکن ثابت ساخت chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

ساکن صحیح g_channel_id = -1;

ساکن خالی
drain_pipe(خالی)
{
	حرف buf[4096];
	اگر (g_pipe[0] < 0)
		واپس;
	جب (اقرأ(g_pipe[0], buf, حجم(buf)) > 0) { }
}

ساکن خالی
reset_channel(ساخت ssh *ssh, ثابت ساخت chan_scenario *s)
{
	اگر (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		اگر (c != تہی)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	صحیح rfd = s->use_pipe ? g_pipe[1] : -1;
	صحیح wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (حرف *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (حرف *)"fuzz", 0);
	اگر (c == تہی)
		واپس;
	g_channel_id = c->self;
	channel_رجسٹر_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, تہی);
	channel_رجسٹر_حالت_confirm(ssh, g_channel_id,
	    &dummy_حالت_confirm, &dummy_حالت_abandon, تہی);
}

ساکن ثابت uint8_t k_پیغام_types[] = {
	SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION,
	SSH2_پیغام_CHANNEL_OPEN_FAILURE,
	SSH2_پیغام_CHANNEL_کھڑکی_ADJUST,
	SSH2_پیغام_CHANNEL_ڈیٹا,
	SSH2_پیغام_CHANNEL_EXTENDED_ڈیٹا,
	SSH2_پیغام_CHANNEL_SUCCESS,
	SSH2_پیغام_CHANNEL_FAILURE,
	SSH2_پیغام_CHANNEL_EOF,
	SSH2_پیغام_CHANNEL_CLOSE,
};

خارجی "C" صحیح
LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز)
{
	اگر (init_once() != 0)
		واپس 0;
	اگر (سائز > 65000)
		واپس 0;

	ثابت سائز_t n_scen = حجم(k_scenarios) / حجم(k_scenarios[0]);
	ثابت سائز_t n_پیغام = حجم(k_پیغام_types) / حجم(k_پیغام_types[0]);

	برائے (سائز_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		برائے (سائز_t t = 0; t < n_پیغام; t++) {
			اندر_fuzz = 1;
			اگر (setjmp(fuzz_env) == 0) {
				سائز_t transferred;
				اگر (ssh_packet_put(g_server, k_پیغام_types[t],
				    ڈیٹا, سائز) != 0)
					جاؤ مکمل;
				اگر (pump(g_server, g_client,
				    &transferred) != 0)
					جاؤ مکمل;
				(خالی)ssh_dispatch_تسلسل(g_client,
				    DISPATCH_NONBLOCK, تہی);
			مکمل:
				;
			}
			اندر_fuzz = 0;
			آزاد(g_open_failure_پیغام);
			g_open_failure_پیغام = تہی;
		}
	}
	واپس 0;
}
