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

#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "channels.h"
#ଅନ୍ତର୍ଭାଵ "session.h"

ServerOptions options;
ସଂରଚନା sshbuf *loginmsg = ଖାଲି;
ସଂରଚନା include_list includes;
ସ୍ଥିର ସଂରଚନା sshauthopt g_auth_opts_storage;
ସଂରଚନା sshauthopt *auth_opts = &g_auth_opts_storage;
ସଂରଚନା passwd *privsep_pw = ଖାଲି;

ସ୍ଥିର jmp_buf fuzz_env;
ସ୍ଥିର ଅସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା in_fuzz = 0;

ଶୂନ୍ୟ
cleanup_exit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା code)
{
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ଶୂନ୍ୟ
__wrap_ssh_packet_disconnect(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)fmt;
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_sshpkt_fatal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)fmt;
	ଯଦି (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_is_monitor(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
mm_audit_run_command(ଅଚଳ ଅକ୍ଷର *cmd)
{
	(ଶୂନ୍ୟ)cmd;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_pty_allocate(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ptyfd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ttyfd, ଅକ୍ଷର *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	ଯଦି (namebuf != ଖାଲି && namebuflen > 0)
		namebuf[0] = '\0';
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ mm_session_pty_cleanup2(Session *s) { (ଶୂନ୍ୟ)s; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା platform_locked_account(ସଂରଚନା passwd *pw) { (ଶୂନ୍ୟ)pw; ଫେରନ୍ତୁ 0; }
ଶୂନ୍ୟ record_failed_login(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *user,
    ଅଚଳ ଅକ୍ଷର *hostname, ଅଚଳ ଅକ୍ଷର *ttyname) { (ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)user;
    (ଶୂନ୍ୟ)hostname; (ଶୂନ୍ୟ)ttyname; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା temporarily_use_uid(ସଂରଚନା passwd *pw) { (ଶୂନ୍ୟ)pw; ଫେରନ୍ତୁ 0; }
ଶୂନ୍ୟ restore_uid(ଶୂନ୍ୟ) { }
ଶୂନ୍ୟ platform_setusercontext(ସଂରଚନା passwd *pw) { (ଶୂନ୍ୟ)pw; }
ଶୂନ୍ୟ platform_setusercontext_post_groups(ସଂରଚନା passwd *pw) { (ଶୂନ୍ୟ)pw; }
ସଂରଚନା connection_info *
server_get_connection_info(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା populate, ପୂର୍ଣ୍ଣସଂଖ୍ୟା use_dns)
    { (ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)populate; (ଶୂନ୍ୟ)use_dns; ଫେରନ୍ତୁ ଖାଲି; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth2_methods_valid(ଅଚଳ ଅକ୍ଷର *list, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_unknown)
    { (ଶୂନ୍ୟ)list; (ଶୂନ୍ୟ)allow_unknown; ଫେରନ୍ତୁ 0; }
ସଂରଚନା sshbuf *cfg = ଖାଲି;
ପୂର୍ଣ୍ଣସଂଖ୍ୟା auth_sock = -1;
ଅକ୍ଷର **tun_fwd_ifnames = ଖାଲି;

ସଂରଚନା logininfo *login_get_lastlog(ସଂରଚନା logininfo *li, ଅଚଳ uid_t uid)
    { (ଶୂନ୍ୟ)li; (ଶୂନ୍ୟ)uid; ଫେରନ୍ତୁ ଖାଲି; }
ସଂରଚନା logininfo *login_alloc_entry(pid_t pid, ଅଚଳ ଅକ୍ଷର *username,
    ଅଚଳ ଅକ୍ଷର *hostname, ଅଚଳ ଅକ୍ଷର *ଧାଡ଼ି)
    { (ଶୂନ୍ୟ)pid; (ଶୂନ୍ୟ)username; (ଶୂନ୍ୟ)hostname; (ଶୂନ୍ୟ)ଧାଡ଼ି; ଫେରନ୍ତୁ ଖାଲି; }
ଶୂନ୍ୟ server_process_permitopen(ସଂରଚନା ssh *ssh) { (ଶୂନ୍ୟ)ssh; }
ଶୂନ୍ୟ server_process_channel_timeouts(ସଂରଚନା ssh *ssh) { (ଶୂନ୍ୟ)ssh; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା server_loop2(ସଂରଚନା ssh *ssh, Authctxt *authctxt)
    { (ଶୂନ୍ୟ)ssh; (ଶୂନ୍ୟ)authctxt; ଫେରନ୍ତୁ 0; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା platform_privileged_uidswap(ଶୂନ୍ୟ) { ଫେରନ୍ତୁ 0; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sftp_server_main(ପୂର୍ଣ୍ଣସଂଖ୍ୟା argc, ଅକ୍ଷର **argv, ସଂରଚନା passwd *user_pw)
    { (ଶୂନ୍ୟ)argc; (ଶୂନ୍ୟ)argv; (ଶୂନ୍ୟ)user_pw; ଫେରନ୍ତୁ 0; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା debug_flag = 0;
ଶୂନ୍ୟ permanently_set_uid(ସଂରଚନା passwd *pw) { (ଶୂନ୍ୟ)pw; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_login(ସଂରଚନା logininfo *li) { (ଶୂନ୍ୟ)li; ଫେରନ୍ତୁ 0; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା login_logout(ସଂରଚନା logininfo *li) { (ଶୂନ୍ୟ)li; ଫେରନ୍ତୁ 0; }
ଶୂନ୍ୟ login_free_entry(ସଂରଚନା logininfo *li) { (ଶୂନ୍ୟ)li; }
ଶୂନ୍ୟ login_set_addr(ସଂରଚନା logininfo *li, ଅଚଳ ସଂରଚନା sockaddr *sa,
    ଅଚଳ unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା sa_size) { (ଶୂନ୍ୟ)li; (ଶୂନ୍ୟ)sa; (ଶୂନ୍ୟ)sa_size; }
ପୂର୍ଣ୍ଣସଂଖ୍ୟା openpty(ପୂର୍ଣ୍ଣସଂଖ୍ୟା *amaster, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *aslave, ଅକ୍ଷର *name,
    ଅଚଳ ସଂରଚନା termios *termp, ଅଚଳ ସଂରଚନା winsize *winp)
    { (ଶୂନ୍ୟ)termp; (ଶୂନ୍ୟ)winp; *amaster = -1; *aslave = -1;
    ଯଦି (name) name[0] = '\0'; ଫେରନ୍ତୁ -1; }

ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା __real_do_exec(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା __real_do_exec_pty(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା __real_do_exec_no_pty(ସଂରଚନା ssh *, Session *, ଅଚଳ ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_do_exec(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)s;
	(ଶୂନ୍ୟ)command;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_do_exec_pty(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)s;
	(ଶୂନ୍ୟ)command;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
__wrap_do_exec_no_pty(ସଂରଚନା ssh *ssh, Session *s, ଅଚଳ ଅକ୍ଷର *command)
{
	(ଶୂନ୍ୟ)ssh;
	(ଶୂନ୍ୟ)s;
	(ଶୂନ୍ୟ)command;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_private(ଅଚଳ ଅକ୍ଷର *str)
{
	ସଂରଚନା sshbuf *b = sshbuf_from(str, strlen(str));
	ସଂରଚନା sshkey *k = ଖାଲି;
	ଯଦି (b == ଖାଲି || sshkey_parse_private_fileblob(b, "", &k, ଖାଲି) != 0)
		abort();
	sshbuf_free(b);
	ଫେରନ୍ତୁ k;
}

ସ୍ଥିର ସଂରଚନା sshkey *
load_public(ଅଚଳ ଅକ୍ଷର *str)
{
	ଅକ୍ଷର *tmp, *cp;
	ସଂରଚନା sshkey *k = sshkey_new(ଚାବି_UNSPEC);
	ଯଦି (k == ଖାଲି)
		abort();
	tmp = cp = strdup(str);
	ଯଦି (sshkey_read(k, &cp) != 0)
		abort();
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ k;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pump(ସଂରଚନା ssh *from, ସଂରଚନା ssh *to, size_t *transferred)
{
	ଅଚଳ u_char *buf;
	size_t len;
	u_char type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	*transferred = 0;
	ଯଦି ((r = ssh_packet_next(from, &type)) != 0)
		ଫେରନ୍ତୁ r;
	buf = ssh_output_ptr(from, &len);
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((r = ssh_ନିବେଶ_append(to, buf, len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = ssh_output_consume(from, len)) != 0)
		ଫେରନ୍ତୁ r;
	*transferred = len;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
run_kex(ସଂରଚନା ssh *client, ସଂରଚନା ssh *server)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t cn, sn;
	ପାଇଁ (ପୂର୍ଣ୍ଣସଂଖ୍ୟା i = 0; i < 100; i++) {
		ଯଦି ((r = pump(server, client, &sn)) != 0) ଫେରନ୍ତୁ r;
		ଯଦି ((r = pump(client, server, &cn)) != 0) ଫେରନ୍ତୁ r;
		ଯଦି (server->kex->done && client->kex->done)
			ଫେରନ୍ତୁ 0;
		ଯଦି (cn == 0 && sn == 0)
			ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
	}
	ଫେରନ୍ତୁ SSH_ERR_PROTOCOL_ERROR;
}

#ଅନ୍ତର୍ଭାଵ "fixed-keys.h"

ସ୍ଥିର ସଂରଚନା ssh *g_client = ଖାଲି;
ସ୍ଥିର ସଂରଚନା ssh *g_server = ଖାଲି;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_init = 0;
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା g_channel_id = -1;
ସ୍ଥିର Authctxt g_authctxt;
ସ୍ଥିର ସଂରଚନା passwd g_fake_pw;

ସ୍ଥିର ଅକ୍ଷର *g_pending_rtype = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *g_pending_exec_cmd = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *g_pending_env_name = ଖାଲି;
ସ୍ଥିର ଅକ୍ଷର *g_pending_env_val = ଖାଲି;

ସ୍ଥିର ଶୂନ୍ୟ
my_session_exec_req(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଯଦି ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ସ୍ଥିର ଶୂନ୍ୟ
my_session_env_req(ସଂରଚନା ssh *ssh)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଯଦି ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ଖାଲି)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ନିବେଶ_channel_request(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, uint32_t seq, ସଂରଚନା ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(ଶୂନ୍ୟ)type;
	(ଶୂନ୍ୟ)seq;
	ଯଦି (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ଖାଲି) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (g_channel_id >= 0 && g_pending_rtype != ଖାଲି) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ଯଦି (c != ଖାଲି) {
			ଯଦି (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			ଅନ୍ୟଥା ଯଦି (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			ଅନ୍ୟଥା
				(ଶୂନ୍ୟ)session_ନିବେଶ_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
reset_channel(ସଂରଚନା ssh *ssh)
{
	ଯଦି (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ଯଦି (c != ଖାଲି)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (ଅକ୍ଷର *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (ଅକ୍ଷର *)"fuzz", 0);
	ଯଦି (c == ଖାଲି)
		ଫେରନ୍ତୁ;
	g_channel_id = c->self;
	Session *s = session_new();
	ଯଦି (s != ଖାଲି) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
init_once(ଶୂନ୍ୟ)
{
	ଯଦି (g_init)
		ଫେରନ୍ତୁ 0;
	ସଙ୍କେତ(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ଆକାର(g_fake_pw));
	g_fake_pw.pw_name = (ଅକ୍ଷର *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ଅକ୍ଷର *)"/tmp";
	g_fake_pw.pw_shell = (ଅକ୍ଷର *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, ଆକାର(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	ସଂରଚନା sshkey *priv = load_private(PRIV_ED25519);
	ସଂରଚନା sshkey *pub = load_public(PUB_ED25519);
	ଅକ୍ଷର *keyname = xstrdup(sshkey_ssh_name(priv));

	ଅଚଳ ଅକ୍ଷର *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ଅକ୍ଷର *proposal[PROPOSAL_MAX] = { 0 };
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++) {
		ଅଚଳ ଅକ୍ଷର *p = defaults[i];
		ଯଦି (i == PROPOSAL_SERVER_HOST_ଚାବି_ALGS)
			p = keyname;
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ଅନ୍ୟଥା ଯଦି (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ସଂରଚନା kex_params kp;
	memcpy(kp.proposal, proposal, ଆକାର(proposal));

	ଯଦି (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (run_kex(g_client, g_server) != 0)
		ଫେରନ୍ତୁ -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_ସନ୍ଦେଶ_CHANNEL_REQUEST,
	    &ନିବେଶ_channel_request);

	ମୁକ୍ତ(keyname);
	ପାଇଁ (i = 0; i < PROPOSAL_MAX; i++)
		ମୁକ୍ତ(proposal[i]);
	g_init = 1;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
fuzz_session_one(ଅଚଳ uint8_t *data, size_t size)
{
	ଯଦି (init_once() != 0)
		ଫେରନ୍ତୁ;
	ଯଦି (size > 65000)
		ଫେରନ୍ତୁ;

	reset_channel(g_server);

	in_fuzz = 1;
	ଯଦି (setjmp(fuzz_env) == 0) {
		size_t transferred;
		ଯଦି (ssh_packet_put(g_client, SSH2_ସନ୍ଦେଶ_CHANNEL_REQUEST,
		    data, size) != 0)
			ଯାଅ done;
		ଯଦି (pump(g_client, g_server, &transferred) != 0)
			ଯାଅ done;
		(ଶୂନ୍ୟ)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ଖାଲି);
	done:
		;
	}
	in_fuzz = 0;
	ମୁକ୍ତ(g_pending_rtype);
	g_pending_rtype = ଖାଲି;
	ମୁକ୍ତ(g_pending_exec_cmd);
	g_pending_exec_cmd = ଖାଲି;
	ମୁକ୍ତ(g_pending_env_name);
	g_pending_env_name = ଖାଲି;
	ମୁକ୍ତ(g_pending_env_val);
	g_pending_env_val = ଖାଲି;
}
