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
 * Helper for session_channel_req_fuzz. Drives the server side of
 * session.c CHANNEL_REQUEST processing via the public
 * session_input_channel_req() entry point. See the .cc driver for
 * the threat-model writeup.
 */

#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <sys/types.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "session.h"

ServerOptions options;
నిర్మాణం sshbuf *loginmsg = ఖాళీ;
నిర్మాణం include_list includes;
స్థిర నిర్మాణం sshauthopt g_auth_opts_storage;
నిర్మాణం sshauthopt *auth_opts = &g_auth_opts_storage;
నిర్మాణం passwd *privsep_pw = ఖాళీ;

స్థిర jmp_buf fuzz_env;
స్థిర అస్థిర పూర్ణాంకం లోపల_fuzz = 0;

శూన్య
cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

శూన్య
__wrap_ssh_packet_disconnect(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *fmt, ...)
{
	(శూన్య)ssh;
	(శూన్య)fmt;
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

పూర్ణాంకం
__wrap_sshpkt_fatal(నిర్మాణం ssh *ssh, పూర్ణాంకం r, స్థిరరాశి అక్షరం *fmt, ...)
{
	(శూన్య)ssh;
	(శూన్య)fmt;
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

పూర్ణాంకం
mm_is_monitor(శూన్య)
{
	తిరిగి 0;
}

శూన్య
mm_audit_నిరంతరం_command(స్థిరరాశి అక్షరం *cmd)
{
	(శూన్య)cmd;
}

పూర్ణాంకం
mm_pty_allocate(పూర్ణాంకం *ptyfd, పూర్ణాంకం *ttyfd, అక్షరం *namebuf, కొలత_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	ఒకవేళ (namebuf != ఖాళీ && namebuflen > 0)
		namebuf[0] = '\0';
	తిరిగి 0;
}

శూన్య mm_session_pty_cleanup2(Session *s) { (శూన్య)s; }
పూర్ణాంకం platform_locked_account(నిర్మాణం passwd *pw) { (శూన్య)pw; తిరిగి 0; }
శూన్య రికార్డు_failed_login(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *user,
    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *ttyname) { (శూన్య)ssh; (శూన్య)user;
    (శూన్య)hostname; (శూన్య)ttyname; }
పూర్ణాంకం temporarily_use_uid(నిర్మాణం passwd *pw) { (శూన్య)pw; తిరిగి 0; }
శూన్య restore_uid(శూన్య) { }
శూన్య platform_setusercontext(నిర్మాణం passwd *pw) { (శూన్య)pw; }
శూన్య platform_setusercontext_post_groups(నిర్మాణం passwd *pw) { (శూన్య)pw; }
నిర్మాణం connection_info *
server_get_connection_info(నిర్మాణం ssh *ssh, పూర్ణాంకం populate, పూర్ణాంకం use_dns)
    { (శూన్య)ssh; (శూన్య)populate; (శూన్య)use_dns; తిరిగి ఖాళీ; }
పూర్ణాంకం auth2_methods_valid(స్థిరరాశి అక్షరం *list, పూర్ణాంకం allow_unknown)
    { (శూన్య)list; (శూన్య)allow_unknown; తిరిగి 0; }
నిర్మాణం sshbuf *cfg = ఖాళీ;
పూర్ణాంకం auth_sock = -1;
అక్షరం **tun_fwd_ifnames = ఖాళీ;

నిర్మాణం logininfo *login_get_lastlog(నిర్మాణం logininfo *li, స్థిరరాశి uid_t uid)
    { (శూన్య)li; (శూన్య)uid; తిరిగి ఖాళీ; }
నిర్మాణం logininfo *login_alloc_నమోదు(pid_t pid, స్థిరరాశి అక్షరం *username,
    స్థిరరాశి అక్షరం *hostname, స్థిరరాశి అక్షరం *పంక్తి)
    { (శూన్య)pid; (శూన్య)username; (శూన్య)hostname; (శూన్య)పంక్తి; తిరిగి ఖాళీ; }
శూన్య server_process_permitopen(నిర్మాణం ssh *ssh) { (శూన్య)ssh; }
శూన్య server_process_channel_timeouts(నిర్మాణం ssh *ssh) { (శూన్య)ssh; }
పూర్ణాంకం server_loop2(నిర్మాణం ssh *ssh, Authctxt *authctxt)
    { (శూన్య)ssh; (శూన్య)authctxt; తిరిగి 0; }
పూర్ణాంకం platform_privileged_uidswap(శూన్య) { తిరిగి 0; }
పూర్ణాంకం sftp_server_main(పూర్ణాంకం argc, అక్షరం **argv, నిర్మాణం passwd *user_pw)
    { (శూన్య)argc; (శూన్య)argv; (శూన్య)user_pw; తిరిగి 0; }
పూర్ణాంకం debug_flag = 0;
శూన్య permanently_సమితి_uid(నిర్మాణం passwd *pw) { (శూన్య)pw; }
పూర్ణాంకం login_login(నిర్మాణం logininfo *li) { (శూన్య)li; తిరిగి 0; }
పూర్ణాంకం login_logout(నిర్మాణం logininfo *li) { (శూన్య)li; తిరిగి 0; }
శూన్య login_free_నమోదు(నిర్మాణం logininfo *li) { (శూన్య)li; }
శూన్య login_సమితి_addr(నిర్మాణం logininfo *li, స్థిరరాశి నిర్మాణం sockaddr *sa,
    స్థిరరాశి గుర్తులేని పూర్ణాంకం sa_కొలత) { (శూన్య)li; (శూన్య)sa; (శూన్య)sa_కొలత; }
పూర్ణాంకం openpty(పూర్ణాంకం *amaster, పూర్ణాంకం *aslave, అక్షరం *name,
    స్థిరరాశి నిర్మాణం termios *termp, స్థిరరాశి నిర్మాణం winsize *winp)
    { (శూన్య)termp; (శూన్య)winp; *amaster = -1; *aslave = -1;
    ఒకవేళ (name) name[0] = '\0'; తిరిగి -1; }

బాహ్య పూర్ణాంకం __real_do_exec(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);
బాహ్య పూర్ణాంకం __real_do_exec_pty(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);
బాహ్య పూర్ణాంకం __real_do_exec_no_pty(నిర్మాణం ssh *, Session *, స్థిరరాశి అక్షరం *);

పూర్ణాంకం
__wrap_do_exec(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	(శూన్య)ssh;
	(శూన్య)s;
	(శూన్య)command;
	తిరిగి 0;
}

పూర్ణాంకం
__wrap_do_exec_pty(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	(శూన్య)ssh;
	(శూన్య)s;
	(శూన్య)command;
	తిరిగి 0;
}

పూర్ణాంకం
__wrap_do_exec_no_pty(నిర్మాణం ssh *ssh, Session *s, స్థిరరాశి అక్షరం *command)
{
	(శూన్య)ssh;
	(శూన్య)s;
	(శూన్య)command;
	తిరిగి 0;
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

#అన్తర్భావ "fixed-keys.h"

స్థిర నిర్మాణం ssh *g_client = ఖాళీ;
స్థిర నిర్మాణం ssh *g_server = ఖాళీ;
స్థిర పూర్ణాంకం g_init = 0;
స్థిర పూర్ణాంకం g_channel_id = -1;
స్థిర Authctxt g_authctxt;
స్థిర నిర్మాణం passwd g_fake_pw;

స్థిర అక్షరం *g_pending_rtype = ఖాళీ;
స్థిర అక్షరం *g_pending_exec_cmd = ఖాళీ;
స్థిర అక్షరం *g_pending_env_name = ఖాళీ;
స్థిర అక్షరం *g_pending_env_val = ఖాళీ;

స్థిర శూన్య
my_session_exec_req(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

స్థిర శూన్య
my_session_env_req(నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

స్థిర పూర్ణాంకం
ఆదానం_channel_request(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	uint32_t chan_id;
	u_char want_జవాబు;

	(శూన్య)type;
	(శూన్య)seq;
	ఒకవేళ (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ఖాళీ) != 0 ||
	    sshpkt_get_u8(ssh, &want_జవాబు) != 0)
		తిరిగి 0;
	ఒకవేళ (g_channel_id >= 0 && g_pending_rtype != ఖాళీ) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ఒకవేళ (c != ఖాళీ) {
			ఒకవేళ (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			లేకపోతే ఒకవేళ (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			లేకపోతే
				(శూన్య)session_ఆదానం_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	తిరిగి 0;
}

స్థిర శూన్య
reset_channel(నిర్మాణం ssh *ssh)
{
	ఒకవేళ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ఒకవేళ (c != ఖాళీ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (అక్షరం *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (అక్షరం *)"fuzz", 0);
	ఒకవేళ (c == ఖాళీ)
		తిరిగి;
	g_channel_id = c->self;
	Session *s = session_new();
	ఒకవేళ (s != ఖాళీ) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

స్థిర పూర్ణాంకం
init_once(శూన్య)
{
	ఒకవేళ (g_init)
		తిరిగి 0;
	సంకేతం(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, పరిమాణం(g_fake_pw));
	g_fake_pw.pw_name = (అక్షరం *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (అక్షరం *)"/tmp";
	g_fake_pw.pw_shell = (అక్షరం *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, పరిమాణం(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

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

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_సమితి(g_server, SSH2_సందేశం_CHANNEL_REQUEST,
	    &ఆదానం_channel_request);

	విడుదల(keyname);
	కొరకు (i = 0; i < PROPOSAL_MAX; i++)
		విడుదల(proposal[i]);
	g_init = 1;
	తిరిగి 0;
}

శూన్య
fuzz_session_one(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (init_once() != 0)
		తిరిగి;
	ఒకవేళ (కొలత > 65000)
		తిరిగి;

	reset_channel(g_server);

	లోపల_fuzz = 1;
	ఒకవేళ (setjmp(fuzz_env) == 0) {
		కొలత_t transferred;
		ఒకవేళ (ssh_packet_put(g_client, SSH2_సందేశం_CHANNEL_REQUEST,
		    దత్తాంశం, కొలత) != 0)
			వెళ్ళు పూర్తి;
		ఒకవేళ (pump(g_client, g_server, &transferred) != 0)
			వెళ్ళు పూర్తి;
		(శూన్య)ssh_dispatch_నిరంతరం(g_server, DISPATCH_NONBLOCK, ఖాళీ);
	పూర్తి:
		;
	}
	లోపల_fuzz = 0;
	విడుదల(g_pending_rtype);
	g_pending_rtype = ఖాళీ;
	విడుదల(g_pending_exec_cmd);
	g_pending_exec_cmd = ఖాళీ;
	విడుదల(g_pending_env_name);
	g_pending_env_name = ఖాళీ;
	విడుదల(g_pending_env_val);
	g_pending_env_val = ఖాళీ;
}
