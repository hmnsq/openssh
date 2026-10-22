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

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

வெளி "C" {
#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "channels.h"
}


#அந்தர்பாவ "fixed-keys.h"

நிலையான jmp_buf fuzz_env;
நிலையான நிலையற்ற முழு in_fuzz = 0;

நிலையான எழுத்து *g_open_failure_செய்தி = வெற்று;

வெளி "C" முழு
my_channel_உள்ளீடு_open_failure(முழு type, uint32_t seq, கட்டமைப்பு ssh *ssh)
{
	(வெறுமை)type;
	(வெறுமை)seq;
	uint32_t reason;
	முழு r;
	எனில் ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	எனில் ((r = sshpkt_get_cstring(ssh, &g_open_failure_செய்தி, வெற்று)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, வெற்று, வெற்று)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	திரும்பு 0;
}

வெளி "C" வெறுமை
cleanup_exit(முழு code)
{
	எனில் (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

வெளி "C" வெறுமை
__wrap_ssh_packet_disconnect(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *fmt, ...)
{
	(வெறுமை)ssh;
	(வெறுமை)fmt;
	எனில் (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

வெளி "C" முழு
__wrap_sshpkt_fatal(கட்டமைப்பு ssh *ssh, முழு r, மாறிலி எழுத்து *fmt, ...)
{
	(வெறுமை)ssh;
	(வெறுமை)fmt;
	எனில் (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

நிலையான கட்டமைப்பு sshkey *
load_private(மாறிலி எழுத்து *str)
{
	கட்டமைப்பு sshbuf *b = sshbuf_from(str, strlen(str));
	கட்டமைப்பு sshkey *k = வெற்று;
	எனில் (b == வெற்று || sshkey_parse_private_fileblob(b, "", &k, வெற்று) != 0)
		abort();
	sshbuf_free(b);
	திரும்பு k;
}

நிலையான கட்டமைப்பு sshkey *
load_public(மாறிலி எழுத்து *str)
{
	எழுத்து *tmp, *cp;
	கட்டமைப்பு sshkey *k = sshkey_new(சாவி_UNSPEC);
	எனில் (k == வெற்று)
		abort();
	tmp = cp = strdup(str);
	எனில் (sshkey_read(k, &cp) != 0)
		abort();
	விடுவி(tmp);
	திரும்பு k;
}

நிலையான முழு
pump(கட்டமைப்பு ssh *from, கட்டமைப்பு ssh *to, size_t *transferred)
{
	மாறிலி u_char *buf;
	size_t len;
	u_char type;
	முழு r;
	*transferred = 0;
	எனில் ((r = ssh_packet_next(from, &type)) != 0)
		திரும்பு r;
	buf = ssh_output_ptr(from, &len);
	எனில் (len == 0)
		திரும்பு 0;
	எனில் ((r = ssh_உள்ளீடு_append(to, buf, len)) != 0)
		திரும்பு r;
	எனில் ((r = ssh_output_consume(from, len)) != 0)
		திரும்பு r;
	*transferred = len;
	திரும்பு 0;
}

நிலையான முழு
run_kex(கட்டமைப்பு ssh *client, கட்டமைப்பு ssh *server)
{
	முழு r;
	size_t cn, sn;
	க்கு (முழு i = 0; i < 100; i++) {
		எனில் ((r = pump(server, client, &sn)) != 0) திரும்பு r;
		எனில் ((r = pump(client, server, &cn)) != 0) திரும்பு r;
		எனில் (server->kex->done && client->kex->done)
			திரும்பு 0;
		எனில் (cn == 0 && sn == 0)
			திரும்பு SSH_ERR_PROTOCOL_ERROR;
	}
	திரும்பு SSH_ERR_PROTOCOL_ERROR;
}

நிலையான கட்டமைப்பு ssh *g_client = வெற்று;
நிலையான கட்டமைப்பு ssh *g_server = வெற்று;
நிலையான முழு g_init = 0;
நிலையான முழு g_pipe[2] = { -1, -1 };

நிலையான வெறுமை
dummy_open_confirm(கட்டமைப்பு ssh *ssh, முழு id, முழு success, வெறுமை *ctx)
{
	(வெறுமை)ssh;
	(வெறுமை)id;
	(வெறுமை)success;
	(வெறுமை)ctx;
}

நிலையான வெறுமை
dummy_status_confirm(கட்டமைப்பு ssh *ssh, முழு type, Channel *c, வெறுமை *ctx)
{
	(வெறுமை)ssh;
	(வெறுமை)type;
	(வெறுமை)c;
	(வெறுமை)ctx;
}

நிலையான வெறுமை
dummy_status_abandon(கட்டமைப்பு ssh *ssh, Channel *c, வெறுமை *ctx)
{
	(வெறுமை)ssh;
	(வெறுமை)c;
	(வெறுமை)ctx;
}

நிலையான முழு
init_once(வெறுமை)
{
	எனில் (g_init)
		திரும்பு 0;
	சமிக்ஞை(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	முழு pfd[2];
	எனில் (ப்ரணால(pfd) != 0)
		திரும்பு -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	எனில் (g_pipe[0] < 0 || g_pipe[1] < 0)
		திரும்பு -1;
	முழு fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	முழு fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(வெறுமை)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(வெறுமை)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	கட்டமைப்பு sshkey *priv = load_private(PRIV_ED25519);
	கட்டமைப்பு sshkey *pub = load_public(PUB_ED25519);
	எழுத்து *keyname = xstrdup(sshkey_ssh_name(priv));

	மாறிலி எழுத்து *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	எழுத்து *proposal[PROPOSAL_MAX] = { 0 };
	முழு i;
	க்கு (i = 0; i < PROPOSAL_MAX; i++) {
		மாறிலி எழுத்து *p = defaults[i];
		எனில் (i == PROPOSAL_SERVER_HOST_சாவி_ALGS)
			p = keyname;
		இல்லையெனில் எனில் (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		இல்லையெனில் எனில் (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		இல்லையெனில் எனில் (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	கட்டமைப்பு kex_params kp;
	memcpy(kp.proposal, proposal, அளவு(proposal));

	எனில் (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		திரும்பு -1;
	எனில் (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		திரும்பு -1;
	எனில் (run_kex(g_client, g_server) != 0)
		திரும்பு -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_DATA,
	    &channel_உள்ளீடு_data);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_EXTENDED_DATA,
	    &channel_உள்ளீடு_extended_data);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_EOF,
	    &channel_உள்ளீடு_ieof);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_CLOSE,
	    &channel_உள்ளீடு_oclose);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION,
	    &channel_உள்ளீடு_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_OPEN_FAILURE,
	    &my_channel_உள்ளீடு_open_failure);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_WINDOW_ADJUST,
	    &channel_உள்ளீடு_window_adjust);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_SUCCESS,
	    &channel_உள்ளீடு_status_confirm);
	ssh_dispatch_set(g_client, SSH2_செய்தி_CHANNEL_FAILURE,
	    &channel_உள்ளீடு_status_confirm);

	விடுவி(keyname);
	க்கு (i = 0; i < PROPOSAL_MAX; i++)
		விடுவி(proposal[i]);
	g_init = 1;
	திரும்பு 0;
}

கட்டமைப்பு chan_scenario {
	மாறிலி எழுத்து *ctype;
	முழு state;
	முழு use_pipe;
};

நிலையான மாறிலி கட்டமைப்பு chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

நிலையான முழு g_channel_id = -1;

நிலையான வெறுமை
drain_pipe(வெறுமை)
{
	எழுத்து buf[4096];
	எனில் (g_pipe[0] < 0)
		திரும்பு;
	போது (பட(g_pipe[0], buf, அளவு(buf)) > 0) { }
}

நிலையான வெறுமை
reset_channel(கட்டமைப்பு ssh *ssh, மாறிலி கட்டமைப்பு chan_scenario *s)
{
	எனில் (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		எனில் (c != வெற்று)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	முழு rfd = s->use_pipe ? g_pipe[1] : -1;
	முழு wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (எழுத்து *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (எழுத்து *)"fuzz", 0);
	எனில் (c == வெற்று)
		திரும்பு;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, வெற்று);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, வெற்று);
}

நிலையான மாறிலி uint8_t k_செய்தி_types[] = {
	SSH2_செய்தி_CHANNEL_OPEN_CONFIRMATION,
	SSH2_செய்தி_CHANNEL_OPEN_FAILURE,
	SSH2_செய்தி_CHANNEL_WINDOW_ADJUST,
	SSH2_செய்தி_CHANNEL_DATA,
	SSH2_செய்தி_CHANNEL_EXTENDED_DATA,
	SSH2_செய்தி_CHANNEL_SUCCESS,
	SSH2_செய்தி_CHANNEL_FAILURE,
	SSH2_செய்தி_CHANNEL_EOF,
	SSH2_செய்தி_CHANNEL_CLOSE,
};

வெளி "C" முழு
LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size)
{
	எனில் (init_once() != 0)
		திரும்பு 0;
	எனில் (size > 65000)
		திரும்பு 0;

	மாறிலி size_t n_scen = அளவு(k_scenarios) / அளவு(k_scenarios[0]);
	மாறிலி size_t n_செய்தி = அளவு(k_செய்தி_types) / அளவு(k_செய்தி_types[0]);

	க்கு (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		க்கு (size_t t = 0; t < n_செய்தி; t++) {
			in_fuzz = 1;
			எனில் (setjmp(fuzz_env) == 0) {
				size_t transferred;
				எனில் (ssh_packet_put(g_server, k_செய்தி_types[t],
				    data, size) != 0)
					செல் done;
				எனில் (pump(g_server, g_client,
				    &transferred) != 0)
					செல் done;
				(வெறுமை)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, வெற்று);
			done:
				;
			}
			in_fuzz = 0;
			விடுவி(g_open_failure_செய்தி);
			g_open_failure_செய்தி = வெற்று;
		}
	}
	திரும்பு 0;
}
