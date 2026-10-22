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

#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

ബാഹ്യ "C" {
#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "channels.h"
}


#അന്തര്ഭാവ "fixed-keys.h"

സ്ഥിതം jmp_buf fuzz_env;
സ്ഥിതം അസ്ഥിര പൂർണ്ണസംഖ്യ in_fuzz = 0;

സ്ഥിതം അക്ഷരം *g_open_failure_സന്ദേശം = ശൂന്യ;

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ
my_channel_നിവേശം_open_failure(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	(ശൂന്യം)type;
	(ശൂന്യം)seq;
	uint32_t reason;
	പൂർണ്ണസംഖ്യ r;
	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &g_open_failure_സന്ദേശം, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_string_direct(ssh, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	തിരികെ 0;
}

ബാഹ്യ "C" ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ബാഹ്യ "C" ശൂന്യം
__wrap_ssh_packet_disconnect(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)fmt;
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ
__wrap_sshpkt_fatal(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ r, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)fmt;
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

സ്ഥിതം ഘടന sshkey *
load_private(സ്ഥിരം അക്ഷരം *str)
{
	ഘടന sshbuf *b = sshbuf_from(str, strlen(str));
	ഘടന sshkey *k = ശൂന്യ;
	എങ്കിൽ (b == ശൂന്യ || sshkey_parse_private_fileblob(b, "", &k, ശൂന്യ) != 0)
		abort();
	sshbuf_free(b);
	തിരികെ k;
}

സ്ഥിതം ഘടന sshkey *
load_public(സ്ഥിരം അക്ഷരം *str)
{
	അക്ഷരം *tmp, *cp;
	ഘടന sshkey *k = sshkey_new(താക്കോൽ_UNSPEC);
	എങ്കിൽ (k == ശൂന്യ)
		abort();
	tmp = cp = strdup(str);
	എങ്കിൽ (sshkey_read(k, &cp) != 0)
		abort();
	സ്വതന്ത്രം(tmp);
	തിരികെ k;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pump(ഘടന ssh *from, ഘടന ssh *to, size_t *transferred)
{
	സ്ഥിരം u_char *buf;
	size_t len;
	u_char type;
	പൂർണ്ണസംഖ്യ r;
	*transferred = 0;
	എങ്കിൽ ((r = ssh_packet_next(from, &type)) != 0)
		തിരികെ r;
	buf = ssh_output_ptr(from, &len);
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ ((r = ssh_നിവേശം_append(to, buf, len)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = ssh_output_consume(from, len)) != 0)
		തിരികെ r;
	*transferred = len;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
run_kex(ഘടന ssh *client, ഘടന ssh *server)
{
	പൂർണ്ണസംഖ്യ r;
	size_t cn, sn;
	വേണ്ടി (പൂർണ്ണസംഖ്യ i = 0; i < 100; i++) {
		എങ്കിൽ ((r = pump(server, client, &sn)) != 0) തിരികെ r;
		എങ്കിൽ ((r = pump(client, server, &cn)) != 0) തിരികെ r;
		എങ്കിൽ (server->kex->done && client->kex->done)
			തിരികെ 0;
		എങ്കിൽ (cn == 0 && sn == 0)
			തിരികെ SSH_ERR_PROTOCOL_ERROR;
	}
	തിരികെ SSH_ERR_PROTOCOL_ERROR;
}

സ്ഥിതം ഘടന ssh *g_client = ശൂന്യ;
സ്ഥിതം ഘടന ssh *g_server = ശൂന്യ;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_init = 0;
സ്ഥിതം പൂർണ്ണസംഖ്യ g_pipe[2] = { -1, -1 };

സ്ഥിതം ശൂന്യം
dummy_open_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ id, പൂർണ്ണസംഖ്യ success, ശൂന്യം *ctx)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)id;
	(ശൂന്യം)success;
	(ശൂന്യം)ctx;
}

സ്ഥിതം ശൂന്യം
dummy_status_confirm(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type, Channel *c, ശൂന്യം *ctx)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)type;
	(ശൂന്യം)c;
	(ശൂന്യം)ctx;
}

സ്ഥിതം ശൂന്യം
dummy_status_abandon(ഘടന ssh *ssh, Channel *c, ശൂന്യം *ctx)
{
	(ശൂന്യം)ssh;
	(ശൂന്യം)c;
	(ശൂന്യം)ctx;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
init_once(ശൂന്യം)
{
	എങ്കിൽ (g_init)
		തിരികെ 0;
	സൂചന(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	പൂർണ്ണസംഖ്യ pfd[2];
	എങ്കിൽ (പ്രണാല(pfd) != 0)
		തിരികെ -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	എങ്കിൽ (g_pipe[0] < 0 || g_pipe[1] < 0)
		തിരികെ -1;
	പൂർണ്ണസംഖ്യ fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	പൂർണ്ണസംഖ്യ fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(ശൂന്യം)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(ശൂന്യം)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	ഘടന sshkey *priv = load_private(PRIV_ED25519);
	ഘടന sshkey *pub = load_public(PUB_ED25519);
	അക്ഷരം *keyname = xstrdup(sshkey_ssh_name(priv));

	സ്ഥിരം അക്ഷരം *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *proposal[PROPOSAL_MAX] = { 0 };
	പൂർണ്ണസംഖ്യ i;
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++) {
		സ്ഥിരം അക്ഷരം *p = defaults[i];
		എങ്കിൽ (i == PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS)
			p = keyname;
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		അല്ലെങ്കിൽ എങ്കിൽ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ഘടന kex_params kp;
	memcpy(kp.proposal, proposal, വലുപ്പം(proposal));

	എങ്കിൽ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		തിരികെ -1;
	എങ്കിൽ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		തിരികെ -1;
	എങ്കിൽ (run_kex(g_client, g_server) != 0)
		തിരികെ -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_DATA,
	    &channel_നിവേശം_data);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_EXTENDED_DATA,
	    &channel_നിവേശം_extended_data);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_EOF,
	    &channel_നിവേശം_ieof);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_CLOSE,
	    &channel_നിവേശം_oclose);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION,
	    &channel_നിവേശം_open_confirmation);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE,
	    &my_channel_നിവേശം_open_failure);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_WINDOW_ADJUST,
	    &channel_നിവേശം_window_adjust);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_SUCCESS,
	    &channel_നിവേശം_status_confirm);
	ssh_dispatch_set(g_client, SSH2_സന്ദേശം_CHANNEL_FAILURE,
	    &channel_നിവേശം_status_confirm);

	സ്വതന്ത്രം(keyname);
	വേണ്ടി (i = 0; i < PROPOSAL_MAX; i++)
		സ്വതന്ത്രം(proposal[i]);
	g_init = 1;
	തിരികെ 0;
}

ഘടന chan_scenario {
	സ്ഥിരം അക്ഷരം *ctype;
	പൂർണ്ണസംഖ്യ state;
	പൂർണ്ണസംഖ്യ use_pipe;
};

സ്ഥിതം സ്ഥിരം ഘടന chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

സ്ഥിതം പൂർണ്ണസംഖ്യ g_channel_id = -1;

സ്ഥിതം ശൂന്യം
drain_pipe(ശൂന്യം)
{
	അക്ഷരം buf[4096];
	എങ്കിൽ (g_pipe[0] < 0)
		തിരികെ;
	ആകുമ്പോൾ (പഠ(g_pipe[0], buf, വലുപ്പം(buf)) > 0) { }
}

സ്ഥിതം ശൂന്യം
reset_channel(ഘടന ssh *ssh, സ്ഥിരം ഘടന chan_scenario *s)
{
	എങ്കിൽ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		എങ്കിൽ (c != ശൂന്യ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	പൂർണ്ണസംഖ്യ rfd = s->use_pipe ? g_pipe[1] : -1;
	പൂർണ്ണസംഖ്യ wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (അക്ഷരം *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (അക്ഷരം *)"fuzz", 0);
	എങ്കിൽ (c == ശൂന്യ)
		തിരികെ;
	g_channel_id = c->self;
	channel_register_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ശൂന്യ);
	channel_register_status_confirm(ssh, g_channel_id,
	    &dummy_status_confirm, &dummy_status_abandon, ശൂന്യ);
}

സ്ഥിതം സ്ഥിരം uint8_t k_സന്ദേശം_types[] = {
	SSH2_സന്ദേശം_CHANNEL_OPEN_CONFIRMATION,
	SSH2_സന്ദേശം_CHANNEL_OPEN_FAILURE,
	SSH2_സന്ദേശം_CHANNEL_WINDOW_ADJUST,
	SSH2_സന്ദേശം_CHANNEL_DATA,
	SSH2_സന്ദേശം_CHANNEL_EXTENDED_DATA,
	SSH2_സന്ദേശം_CHANNEL_SUCCESS,
	SSH2_സന്ദേശം_CHANNEL_FAILURE,
	SSH2_സന്ദേശം_CHANNEL_EOF,
	SSH2_സന്ദേശം_CHANNEL_CLOSE,
};

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ
LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (init_once() != 0)
		തിരികെ 0;
	എങ്കിൽ (size > 65000)
		തിരികെ 0;

	സ്ഥിരം size_t n_scen = വലുപ്പം(k_scenarios) / വലുപ്പം(k_scenarios[0]);
	സ്ഥിരം size_t n_സന്ദേശം = വലുപ്പം(k_സന്ദേശം_types) / വലുപ്പം(k_സന്ദേശം_types[0]);

	വേണ്ടി (size_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		വേണ്ടി (size_t t = 0; t < n_സന്ദേശം; t++) {
			in_fuzz = 1;
			എങ്കിൽ (setjmp(fuzz_env) == 0) {
				size_t transferred;
				എങ്കിൽ (ssh_packet_put(g_server, k_സന്ദേശം_types[t],
				    data, size) != 0)
					പോകുക done;
				എങ്കിൽ (pump(g_server, g_client,
				    &transferred) != 0)
					പോകുക done;
				(ശൂന്യം)ssh_dispatch_run(g_client,
				    DISPATCH_NONBLOCK, ശൂന്യ);
			done:
				;
			}
			in_fuzz = 0;
			സ്വതന്ത്രം(g_open_failure_സന്ദേശം);
			g_open_failure_സന്ദേശം = ശൂന്യ;
		}
	}
	തിരികെ 0;
}
