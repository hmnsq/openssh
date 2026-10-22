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

#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "channels.h"
#ಅನ್ತರ್ಭಾವ "session.h"

ServerOptions options;
ಸಂರಚನಾ sshbuf *loginmsg = ರಿಕ್ತ;
ಸಂರಚನಾ include_list includes;
ಸ್ಥಿರ ಸಂರಚನಾ sshauthopt g_auth_opts_storage;
ಸಂರಚನಾ sshauthopt *auth_opts = &g_auth_opts_storage;
ಸಂರಚನಾ passwd *privsep_pw = ರಿಕ್ತ;

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಚಞ್ಚಲ ಪೂರ್ಣಾಙ್ಕ in_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ code)
{
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

ಶೂನ್ಯ
__wrap_ssh_packet_disconnect(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_sshpkt_fatal(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ r, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಯದಿ (in_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ಪೂರ್ಣಾಙ್ಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
mm_audit_run_command(ಧ್ರುವ ವರ್ಣ *cmd)
{
	(ಶೂನ್ಯ)cmd;
}

ಪೂರ್ಣಾಙ್ಕ
mm_pty_allocate(ಪೂರ್ಣಾಙ್ಕ *ptyfd, ಪೂರ್ಣಾಙ್ಕ *ttyfd, ವರ್ಣ *namebuf, size_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	ಯದಿ (namebuf != ರಿಕ್ತ && namebuflen > 0)
		namebuf[0] = '\0';
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ mm_session_pty_cleanup2(Session *s) { (ಶೂನ್ಯ)s; }
ಪೂರ್ಣಾಙ್ಕ platform_locked_account(ಸಂರಚನಾ passwd *pw) { (ಶೂನ್ಯ)pw; ಪ್ರತ್ಯಾಗಮ 0; }
ಶೂನ್ಯ record_failed_login(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *user,
    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ttyname) { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)user;
    (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ttyname; }
ಪೂರ್ಣಾಙ್ಕ temporarily_use_uid(ಸಂರಚನಾ passwd *pw) { (ಶೂನ್ಯ)pw; ಪ್ರತ್ಯಾಗಮ 0; }
ಶೂನ್ಯ restore_uid(ಶೂನ್ಯ) { }
ಶೂನ್ಯ platform_setusercontext(ಸಂರಚನಾ passwd *pw) { (ಶೂನ್ಯ)pw; }
ಶೂನ್ಯ platform_setusercontext_post_groups(ಸಂರಚನಾ passwd *pw) { (ಶೂನ್ಯ)pw; }
ಸಂರಚನಾ connection_info *
server_get_connection_info(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ populate, ಪೂರ್ಣಾಙ್ಕ use_dns)
    { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)populate; (ಶೂನ್ಯ)use_dns; ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; }
ಪೂರ್ಣಾಙ್ಕ auth2_methods_valid(ಧ್ರುವ ವರ್ಣ *list, ಪೂರ್ಣಾಙ್ಕ allow_unknown)
    { (ಶೂನ್ಯ)list; (ಶೂನ್ಯ)allow_unknown; ಪ್ರತ್ಯಾಗಮ 0; }
ಸಂರಚನಾ sshbuf *cfg = ರಿಕ್ತ;
ಪೂರ್ಣಾಙ್ಕ auth_sock = -1;
ವರ್ಣ **tun_fwd_ifnames = ರಿಕ್ತ;

ಸಂರಚನಾ logininfo *login_get_lastlog(ಸಂರಚನಾ logininfo *li, ಧ್ರುವ uid_t uid)
    { (ಶೂನ್ಯ)li; (ಶೂನ್ಯ)uid; ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; }
ಸಂರಚನಾ logininfo *login_alloc_entry(pid_t pid, ಧ್ರುವ ವರ್ಣ *username,
    ಧ್ರುವ ವರ್ಣ *hostname, ಧ್ರುವ ವರ್ಣ *ಸಾಲು)
    { (ಶೂನ್ಯ)pid; (ಶೂನ್ಯ)username; (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ಸಾಲು; ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; }
ಶೂನ್ಯ server_process_permitopen(ಸಂರಚನಾ ssh *ssh) { (ಶೂನ್ಯ)ssh; }
ಶೂನ್ಯ server_process_channel_timeouts(ಸಂರಚನಾ ssh *ssh) { (ಶೂನ್ಯ)ssh; }
ಪೂರ್ಣಾಙ್ಕ server_loop2(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
    { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)authctxt; ಪ್ರತ್ಯಾಗಮ 0; }
ಪೂರ್ಣಾಙ್ಕ platform_privileged_uidswap(ಶೂನ್ಯ) { ಪ್ರತ್ಯಾಗಮ 0; }
ಪೂರ್ಣಾಙ್ಕ sftp_server_main(ಪೂರ್ಣಾಙ್ಕ argc, ವರ್ಣ **argv, ಸಂರಚನಾ passwd *user_pw)
    { (ಶೂನ್ಯ)argc; (ಶೂನ್ಯ)argv; (ಶೂನ್ಯ)user_pw; ಪ್ರತ್ಯಾಗಮ 0; }
ಪೂರ್ಣಾಙ್ಕ debug_flag = 0;
ಶೂನ್ಯ permanently_set_uid(ಸಂರಚನಾ passwd *pw) { (ಶೂನ್ಯ)pw; }
ಪೂರ್ಣಾಙ್ಕ login_login(ಸಂರಚನಾ logininfo *li) { (ಶೂನ್ಯ)li; ಪ್ರತ್ಯಾಗಮ 0; }
ಪೂರ್ಣಾಙ್ಕ login_logout(ಸಂರಚನಾ logininfo *li) { (ಶೂನ್ಯ)li; ಪ್ರತ್ಯಾಗಮ 0; }
ಶೂನ್ಯ login_free_entry(ಸಂರಚನಾ logininfo *li) { (ಶೂನ್ಯ)li; }
ಶೂನ್ಯ login_set_addr(ಸಂರಚನಾ logininfo *li, ಧ್ರುವ ಸಂರಚನಾ sockaddr *sa,
    ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ sa_size) { (ಶೂನ್ಯ)li; (ಶೂನ್ಯ)sa; (ಶೂನ್ಯ)sa_size; }
ಪೂರ್ಣಾಙ್ಕ openpty(ಪೂರ್ಣಾಙ್ಕ *amaster, ಪೂರ್ಣಾಙ್ಕ *aslave, ವರ್ಣ *name,
    ಧ್ರುವ ಸಂರಚನಾ termios *termp, ಧ್ರುವ ಸಂರಚನಾ winsize *winp)
    { (ಶೂನ್ಯ)termp; (ಶೂನ್ಯ)winp; *amaster = -1; *aslave = -1;
    ಯದಿ (name) name[0] = '\0'; ಪ್ರತ್ಯಾಗಮ -1; }

ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ __real_do_exec(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ __real_do_exec_pty(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ __real_do_exec_no_pty(ಸಂರಚನಾ ssh *, Session *, ಧ್ರುವ ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ
__wrap_do_exec(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)s;
	(ಶೂನ್ಯ)command;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_do_exec_pty(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)s;
	(ಶೂನ್ಯ)command;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
__wrap_do_exec_no_pty(ಸಂರಚನಾ ssh *ssh, Session *s, ಧ್ರುವ ವರ್ಣ *command)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)s;
	(ಶೂನ್ಯ)command;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_private(ಧ್ರುವ ವರ್ಣ *str)
{
	ಸಂರಚನಾ sshbuf *b = sshbuf_from(str, strlen(str));
	ಸಂರಚನಾ sshkey *k = ರಿಕ್ತ;
	ಯದಿ (b == ರಿಕ್ತ || sshkey_parse_private_fileblob(b, "", &k, ರಿಕ್ತ) != 0)
		abort();
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_public(ಧ್ರುವ ವರ್ಣ *str)
{
	ವರ್ಣ *tmp, *cp;
	ಸಂರಚನಾ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಯದಿ (k == ರಿಕ್ತ)
		abort();
	tmp = cp = strdup(str);
	ಯದಿ (sshkey_read(k, &cp) != 0)
		abort();
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pump(ಸಂರಚನಾ ssh *from, ಸಂರಚನಾ ssh *to, size_t *transferred)
{
	ಧ್ರುವ u_char *buf;
	size_t len;
	u_char type;
	ಪೂರ್ಣಾಙ್ಕ r;
	*transferred = 0;
	ಯದಿ ((r = ssh_packet_next(from, &type)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	buf = ssh_output_ptr(from, &len);
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = ssh_ಒಳಹರಿವು_append(to, buf, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = ssh_output_consume(from, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	*transferred = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
run_kex(ಸಂರಚನಾ ssh *client, ಸಂರಚನಾ ssh *server)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t cn, sn;
	ಪ್ರತಿ (ಪೂರ್ಣಾಙ್ಕ i = 0; i < 100; i++) {
		ಯದಿ ((r = pump(server, client, &sn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((r = pump(client, server, &cn)) != 0) ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (server->kex->done && client->kex->done)
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ (cn == 0 && sn == 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_PROTOCOL_ERROR;
}

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_client = ರಿಕ್ತ;
ಸ್ಥಿರ ಸಂರಚನಾ ssh *g_server = ರಿಕ್ತ;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_init = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ g_channel_id = -1;
ಸ್ಥಿರ Authctxt g_authctxt;
ಸ್ಥಿರ ಸಂರಚನಾ passwd g_fake_pw;

ಸ್ಥಿರ ವರ್ಣ *g_pending_rtype = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *g_pending_exec_cmd = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *g_pending_env_name = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *g_pending_env_val = ರಿಕ್ತ;

ಸ್ಥಿರ ಶೂನ್ಯ
my_session_exec_req(ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಯದಿ ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ಸ್ಥಿರ ಶೂನ್ಯ
my_session_env_req(ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	ಯದಿ ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_channel_request(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	uint32_t chan_id;
	u_char want_reply;

	(ಶೂನ್ಯ)type;
	(ಶೂನ್ಯ)seq;
	ಯದಿ (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ರಿಕ್ತ) != 0 ||
	    sshpkt_get_u8(ssh, &want_reply) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (g_channel_id >= 0 && g_pending_rtype != ರಿಕ್ತ) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ಯದಿ (c != ರಿಕ್ತ) {
			ಯದಿ (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			ಅನ್ಯಥಾ ಯದಿ (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			ಅನ್ಯಥಾ
				(ಶೂನ್ಯ)session_ಒಳಹರಿವು_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_channel(ಸಂರಚನಾ ssh *ssh)
{
	ಯದಿ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ಯದಿ (c != ರಿಕ್ತ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (ವರ್ಣ *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (ವರ್ಣ *)"fuzz", 0);
	ಯದಿ (c == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	g_channel_id = c->self;
	Session *s = session_new();
	ಯದಿ (s != ರಿಕ್ತ) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
init_once(ಶೂನ್ಯ)
{
	ಯದಿ (g_init)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸಙ್ಕೇತ(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ಪರಿಮಾಣ(g_fake_pw));
	g_fake_pw.pw_name = (ವರ್ಣ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ವರ್ಣ *)"/tmp";
	g_fake_pw.pw_shell = (ವರ್ಣ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, ಪರಿಮಾಣ(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	ಸಂರಚನಾ sshkey *priv = load_private(PRIV_ED25519);
	ಸಂರಚನಾ sshkey *pub = load_public(PUB_ED25519);
	ವರ್ಣ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಧ್ರುವ ವರ್ಣ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಙ್ಕ i;
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಧ್ರುವ ವರ್ಣ *p = defaults[i];
		ಯದಿ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಅನ್ಯಥಾ ಯದಿ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ಸಂರಚನಾ kex_params kp;
	memcpy(kp.proposal, proposal, ಪರಿಮಾಣ(proposal));

	ಯದಿ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (ssh_add_hostkey(g_server, priv) != 0 ||
	    ssh_add_hostkey(g_client, pub) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (run_kex(g_client, g_server) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_set(g_server, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST,
	    &ಒಳಹರಿವು_channel_request);

	ಮುಕ್ತ(keyname);
	ಪ್ರತಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಮುಕ್ತ(proposal[i]);
	g_init = 1;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
fuzz_session_one(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (init_once() != 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (size > 65000)
		ಪ್ರತ್ಯಾಗಮ;

	reset_channel(g_server);

	in_fuzz = 1;
	ಯದಿ (setjmp(fuzz_env) == 0) {
		size_t transferred;
		ಯದಿ (ssh_packet_put(g_client, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST,
		    data, size) != 0)
			ಗಚ್ಛ done;
		ಯದಿ (pump(g_client, g_server, &transferred) != 0)
			ಗಚ್ಛ done;
		(ಶೂನ್ಯ)ssh_dispatch_run(g_server, DISPATCH_NONBLOCK, ರಿಕ್ತ);
	done:
		;
	}
	in_fuzz = 0;
	ಮುಕ್ತ(g_pending_rtype);
	g_pending_rtype = ರಿಕ್ತ;
	ಮುಕ್ತ(g_pending_exec_cmd);
	g_pending_exec_cmd = ರಿಕ್ತ;
	ಮುಕ್ತ(g_pending_env_name);
	g_pending_env_name = ರಿಕ್ತ;
	ಮುಕ್ತ(g_pending_env_val);
	g_pending_env_val = ರಿಕ್ತ;
}
