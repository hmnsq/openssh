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

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

బాహ్య "C" {
#అన్తర్భావ "includes.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "channels.h"
}


#అన్తర్భావ "fixed-keys.h"

స్థిర jmp_buf fuzz_env;
స్థిర అస్థిర పూర్ణాంకం లోపల_fuzz = 0;

స్థిర అక్షరం *g_open_failure_సందేశం = ఖాళీ;

బాహ్య "C" పూర్ణాంకం
my_channel_ఆదానం_open_failure(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	(శూన్య)type;
	(శూన్య)seq;
	uint32_t reason;
	పూర్ణాంకం r;
	ఒకవేళ ((r = sshpkt_get_u32(ssh, &reason)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &g_open_failure_సందేశం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_string_ప్రత్యక్ష(ssh, ఖాళీ, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		ssh_packet_disconnect(ssh, "Invalid open failure message");
	తిరిగి 0;
}

బాహ్య "C" శూన్య
cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

బాహ్య "C" శూన్య
__wrap_ssh_packet_disconnect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *fmt, ...)
{
	(శూన్య)ssh;
	(శూన్య)fmt;
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

బాహ్య "C" పూర్ణాంకం
__wrap_sshpkt_fatal(నిర్మాణం ssh *ssh, పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, ...)
{
	(శూన్య)ssh;
	(శూన్య)fmt;
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_వ్యక్తిగత(స్థిరరాశి అక్షరం *str)
{
	నిర్మాణం sshbuf *b = sshbuf_from(str, అక్షరశ్రేణి_పొడవు(str));
	నిర్మాణం sshkey *k = ఖాళీ;
	ఒకవేళ (b == ఖాళీ || sshkey_parse_వ్యక్తిగత_fileblob(b, "", &k, ఖాళీ) != 0)
		abort();
	sshbuf_free(b);
	తిరిగి k;
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_ప్రజా(స్థిరరాశి అక్షరం *str)
{
	అక్షరం *tmp, *cp;
	నిర్మాణం sshkey *k = sshkey_new(కీలకం_UNSPEC);
	ఒకవేళ (k == ఖాళీ)
		abort();
	tmp = cp = strdup(str);
	ఒకవేళ (sshkey_read(k, &cp) != 0)
		abort();
	విడుదల(tmp);
	తిరిగి k;
}

స్థిర పూర్ణాంకం
pump(నిర్మాణం ssh *from, నిర్మాణం ssh *గమ్యం, కొలత_t *transferred)
{
	స్థిరరాశి u_char *buf;
	కొలత_t len;
	u_char type;
	పూర్ణాంకం r;
	*transferred = 0;
	ఒకవేళ ((r = ssh_packet_తదుపరి(from, &type)) != 0)
		తిరిగి r;
	buf = ssh_output_ptr(from, &len);
	ఒకవేళ (len == 0)
		తిరిగి 0;
	ఒకవేళ ((r = ssh_ఆదానం_append(గమ్యం, buf, len)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = ssh_output_consume(from, len)) != 0)
		తిరిగి r;
	*transferred = len;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
నిరంతరం_kex(నిర్మాణం ssh *client, నిర్మాణం ssh *server)
{
	పూర్ణాంకం r;
	కొలత_t cn, sn;
	కొరకు (పూర్ణాంకం i = 0; i < 100; i++) {
		ఒకవేళ ((r = pump(server, client, &sn)) != 0) తిరిగి r;
		ఒకవేళ ((r = pump(client, server, &cn)) != 0) తిరిగి r;
		ఒకవేళ (server->kex->పూర్తి && client->kex->పూర్తి)
			తిరిగి 0;
		ఒకవేళ (cn == 0 && sn == 0)
			తిరిగి SSH_ERR_PROTOCOL_ERROR;
	}
	తిరిగి SSH_ERR_PROTOCOL_ERROR;
}

స్థిర నిర్మాణం ssh *g_client = ఖాళీ;
స్థిర నిర్మాణం ssh *g_server = ఖాళీ;
స్థిర పూర్ణాంకం g_init = 0;
స్థిర పూర్ణాంకం g_pipe[2] = { -1, -1 };

స్థిర శూన్య
dummy_open_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం id, పూర్ణాంకం success, శూన్య *ctx)
{
	(శూన్య)ssh;
	(శూన్య)id;
	(శూన్య)success;
	(శూన్య)ctx;
}

స్థిర శూన్య
dummy_స్థితి_confirm(నిర్మాణం ssh *ssh, పూర్ణాంకం type, Channel *c, శూన్య *ctx)
{
	(శూన్య)ssh;
	(శూన్య)type;
	(శూన్య)c;
	(శూన్య)ctx;
}

స్థిర శూన్య
dummy_స్థితి_abandon(నిర్మాణం ssh *ssh, Channel *c, శూన్య *ctx)
{
	(శూన్య)ssh;
	(శూన్య)c;
	(శూన్య)ctx;
}

స్థిర పూర్ణాంకం
init_once(శూన్య)
{
	ఒకవేళ (g_init)
		తిరిగి 0;
	సంకేతం(SIGPIPE, SIG_IGN);
	log_init("ssh_channels_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	పూర్ణాంకం pfd[2];
	ఒకవేళ (ప్రణాల(pfd) != 0)
		తిరిగి -1;
	g_pipe[0] = fcntl(pfd[0], F_DUPFD_CLOEXEC, 100);
	g_pipe[1] = fcntl(pfd[1], F_DUPFD_CLOEXEC, 100);
	close(pfd[0]);
	close(pfd[1]);
	ఒకవేళ (g_pipe[0] < 0 || g_pipe[1] < 0)
		తిరిగి -1;
	పూర్ణాంకం fl0 = fcntl(g_pipe[0], F_GETFL, 0);
	పూర్ణాంకం fl1 = fcntl(g_pipe[1], F_GETFL, 0);
	(శూన్య)fcntl(g_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
	(శూన్య)fcntl(g_pipe[1], F_SETFL, fl1 | O_NONBLOCK);

	నిర్మాణం sshkey *priv = ఎక్కించు_వ్యక్తిగత(PRIV_ED25519);
	నిర్మాణం sshkey *pub = ఎక్కించు_ప్రజా(PUB_ED25519);
	అక్షరం *keyname = xstrdup(sshkey_ssh_name(priv));

	స్థిరరాశి అక్షరం *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	అక్షరం *proposal[PROPOSAL_MAX] = { 0 };
	పూర్ణాంకం i;
	కొరకు (i = 0; i < PROPOSAL_MAX; i++) {
		స్థిరరాశి అక్షరం *p = defaults[i];
		ఒకవేళ (i == PROPOSAL_SERVER_HOST_కీలకం_ALGS)
			p = keyname;
		లేకపోతే ఒకవేళ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		లేకపోతే ఒకవేళ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		లేకపోతే ఒకవేళ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	నిర్మాణం kex_params kp;
	జ్ఞాపకం_నకలు(kp.proposal, proposal, పరిమాణం(proposal));

	ఒకవేళ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		తిరిగి -1;
	ఒకవేళ (ssh_కూడు_hostkey(g_server, priv) != 0 ||
	    ssh_కూడు_hostkey(g_client, pub) != 0)
		తిరిగి -1;
	ఒకవేళ (నిరంతరం_kex(g_client, g_server) != 0)
		తిరిగి -1;

	channel_init_channels(g_client);

	ssh_dispatch_init(g_client, &dispatch_protocol_ignore);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_దత్తాంశం,
	    &channel_ఆదానం_దత్తాంశం);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం,
	    &channel_ఆదానం_extended_దత్తాంశం);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_EOF,
	    &channel_ఆదానం_ieof);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_CLOSE,
	    &channel_ఆదానం_oclose);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION,
	    &channel_ఆదానం_open_confirmation);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_OPEN_FAILURE,
	    &my_channel_ఆదానం_open_failure);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST,
	    &channel_ఆదానం_కిటికీ_adjust);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_SUCCESS,
	    &channel_ఆదానం_స్థితి_confirm);
	ssh_dispatch_సమితి(g_client, SSH2_సందేశం_CHANNEL_FAILURE,
	    &channel_ఆదానం_స్థితి_confirm);

	విడుదల(keyname);
	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(proposal[i]);
	g_init = 1;
	తిరిగి 0;
}

నిర్మాణం chan_scenario {
	స్థిరరాశి అక్షరం *ctype;
	పూర్ణాంకం state;
	పూర్ణాంకం use_pipe;
};

స్థిర స్థిరరాశి నిర్మాణం chan_scenario k_scenarios[] = {
	{ "session",         SSH_CHANNEL_OPEN,     0 },
	{ "session",         SSH_CHANNEL_OPENING,  1 },
	{ "x11",             SSH_CHANNEL_OPEN,     1 },
	{ "forwarded-tcpip", SSH_CHANNEL_OPEN,     0 },
	{ "direct-tcpip",    SSH_CHANNEL_OPENING,  1 },
};

స్థిర పూర్ణాంకం g_channel_id = -1;

స్థిర శూన్య
drain_pipe(శూన్య)
{
	అక్షరం buf[4096];
	ఒకవేళ (g_pipe[0] < 0)
		తిరిగి;
	అయితే (పఠ(g_pipe[0], buf, పరిమాణం(buf)) > 0) { }
}

స్థిర శూన్య
reset_channel(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం chan_scenario *s)
{
	ఒకవేళ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ఒకవేళ (c != ఖాళీ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	drain_pipe();

	పూర్ణాంకం rfd = s->use_pipe ? g_pipe[1] : -1;
	పూర్ణాంకం wfd = s->use_pipe ? g_pipe[1] : -1;
	Channel *c = channel_new(ssh, (అక్షరం *)s->ctype, s->state,
	    rfd, wfd, -1, 32768, 32768, 0, (అక్షరం *)"fuzz", 0);
	ఒకవేళ (c == ఖాళీ)
		తిరిగి;
	g_channel_id = c->self;
	channel_రిజిస్టరు_open_confirm(ssh, g_channel_id,
	    &dummy_open_confirm, ఖాళీ);
	channel_రిజిస్టరు_స్థితి_confirm(ssh, g_channel_id,
	    &dummy_స్థితి_confirm, &dummy_స్థితి_abandon, ఖాళీ);
}

స్థిర స్థిరరాశి uint8_t k_సందేశం_types[] = {
	SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION,
	SSH2_సందేశం_CHANNEL_OPEN_FAILURE,
	SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST,
	SSH2_సందేశం_CHANNEL_దత్తాంశం,
	SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం,
	SSH2_సందేశం_CHANNEL_SUCCESS,
	SSH2_సందేశం_CHANNEL_FAILURE,
	SSH2_సందేశం_CHANNEL_EOF,
	SSH2_సందేశం_CHANNEL_CLOSE,
};

బాహ్య "C" పూర్ణాంకం
LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (init_once() != 0)
		తిరిగి 0;
	ఒకవేళ (కొలత > 65000)
		తిరిగి 0;

	స్థిరరాశి కొలత_t n_scen = పరిమాణం(k_scenarios) / పరిమాణం(k_scenarios[0]);
	స్థిరరాశి కొలత_t n_సందేశం = పరిమాణం(k_సందేశం_types) / పరిమాణం(k_సందేశం_types[0]);

	కొరకు (కొలత_t s = 0; s < n_scen; s++) {
		reset_channel(g_client, &k_scenarios[s]);
		కొరకు (కొలత_t t = 0; t < n_సందేశం; t++) {
			లోపల_fuzz = 1;
			ఒకవేళ (setjmp(fuzz_env) == 0) {
				కొలత_t transferred;
				ఒకవేళ (ssh_packet_put(g_server, k_సందేశం_types[t],
				    దత్తాంశం, కొలత) != 0)
					వెళ్ళు పూర్తి;
				ఒకవేళ (pump(g_server, g_client,
				    &transferred) != 0)
					వెళ్ళు పూర్తి;
				(శూన్య)ssh_dispatch_నిరంతరం(g_client,
				    DISPATCH_NONBLOCK, ఖాళీ);
			పూర్తి:
				;
			}
			లోపల_fuzz = 0;
			విడుదల(g_open_failure_సందేశం);
			g_open_failure_సందేశం = ఖాళీ;
		}
	}
	తిరిగి 0;
}
