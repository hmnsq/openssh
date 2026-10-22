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
ರಚನೆ sshbuf *loginmsg = ಖಾಲಿ;
ರಚನೆ include_list includes;
ಸ್ಥಿರ ರಚನೆ sshauthopt g_auth_opts_storage;
ರಚನೆ sshauthopt *auth_opts = &g_auth_opts_storage;
ರಚನೆ passwd *privsep_pw = ಖಾಲಿ;

ಸ್ಥಿರ jmp_buf fuzz_env;
ಸ್ಥಿರ ಅಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳ_fuzz = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಂಕ ಸಂಕೇತ_2)
{
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, ಸಂಕೇತ_2 ? ಸಂಕೇತ_2 : 1);
	_exit(ಸಂಕೇತ_2);
}

ಶೂನ್ಯ
__wrap_ssh_packet_disconnect(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(1);
}

ಪೂರ್ಣಾಂಕ
__wrap_sshpkt_fatal(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ r, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)fmt;
	ಆದರೆ (ಒಳ_fuzz)
		longjmp(fuzz_env, 1);
	_exit(r ? r : 1);
}

ಪೂರ್ಣಾಂಕ
mm_is_monitor(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
mm_audit_ಸತತ_command(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd)
{
	(ಶೂನ್ಯ)cmd;
}

ಪೂರ್ಣಾಂಕ
mm_pty_allocate(ಪೂರ್ಣಾಂಕ *ptyfd, ಪೂರ್ಣಾಂಕ *ttyfd, ಅಕ್ಷರ *namebuf, ಗಾತ್ರ_t namebuflen)
{
	*ptyfd = -1;
	*ttyfd = -1;
	ಆದರೆ (namebuf != ಖಾಲಿ && namebuflen > 0)
		namebuf[0] = '\0';
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ mm_session_pty_cleanup2(Session *s) { (ಶೂನ್ಯ)s; }
ಪೂರ್ಣಾಂಕ platform_locked_account(ರಚನೆ passwd *pw) { (ಶೂನ್ಯ)pw; ಹಿಂತಿರುಗಿ 0; }
ಶೂನ್ಯ ದಾಖಲೆ_failed_login(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttyname) { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)user;
    (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ttyname; }
ಪೂರ್ಣಾಂಕ temporarily_use_uid(ರಚನೆ passwd *pw) { (ಶೂನ್ಯ)pw; ಹಿಂತಿರುಗಿ 0; }
ಶೂನ್ಯ restore_uid(ಶೂನ್ಯ) { }
ಶೂನ್ಯ platform_setusercontext(ರಚನೆ passwd *pw) { (ಶೂನ್ಯ)pw; }
ಶೂನ್ಯ platform_setusercontext_post_groups(ರಚನೆ passwd *pw) { (ಶೂನ್ಯ)pw; }
ರಚನೆ connection_info *
server_get_connection_info(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ populate, ಪೂರ್ಣಾಂಕ use_dns)
    { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)populate; (ಶೂನ್ಯ)use_dns; ಹಿಂತಿರುಗಿ ಖಾಲಿ; }
ಪೂರ್ಣಾಂಕ auth2_methods_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *list, ಪೂರ್ಣಾಂಕ allow_unknown)
    { (ಶೂನ್ಯ)list; (ಶೂನ್ಯ)allow_unknown; ಹಿಂತಿರುಗಿ 0; }
ರಚನೆ sshbuf *cfg = ಖಾಲಿ;
ಪೂರ್ಣಾಂಕ auth_sock = -1;
ಅಕ್ಷರ **tun_fwd_ifnames = ಖಾಲಿ;

ರಚನೆ logininfo *login_get_lastlog(ರಚನೆ logininfo *li, ಸ್ಥಿರಾಂಕ uid_t uid)
    { (ಶೂನ್ಯ)li; (ಶೂನ್ಯ)uid; ಹಿಂತಿರುಗಿ ಖಾಲಿ; }
ರಚನೆ logininfo *login_alloc_ನಮೂದು(pid_t pid, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *username,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಾಲು)
    { (ಶೂನ್ಯ)pid; (ಶೂನ್ಯ)username; (ಶೂನ್ಯ)hostname; (ಶೂನ್ಯ)ಸಾಲು; ಹಿಂತಿರುಗಿ ಖಾಲಿ; }
ಶೂನ್ಯ server_process_permitopen(ರಚನೆ ssh *ssh) { (ಶೂನ್ಯ)ssh; }
ಶೂನ್ಯ server_process_channel_timeouts(ರಚನೆ ssh *ssh) { (ಶೂನ್ಯ)ssh; }
ಪೂರ್ಣಾಂಕ server_loop2(ರಚನೆ ssh *ssh, Authctxt *authctxt)
    { (ಶೂನ್ಯ)ssh; (ಶೂನ್ಯ)authctxt; ಹಿಂತಿರುಗಿ 0; }
ಪೂರ್ಣಾಂಕ platform_privileged_uidswap(ಶೂನ್ಯ) { ಹಿಂತಿರುಗಿ 0; }
ಪೂರ್ಣಾಂಕ sftp_server_main(ಪೂರ್ಣಾಂಕ argc, ಅಕ್ಷರ **argv, ರಚನೆ passwd *user_pw)
    { (ಶೂನ್ಯ)argc; (ಶೂನ್ಯ)argv; (ಶೂನ್ಯ)user_pw; ಹಿಂತಿರುಗಿ 0; }
ಪೂರ್ಣಾಂಕ debug_flag = 0;
ಶೂನ್ಯ permanently_ಗಣ_uid(ರಚನೆ passwd *pw) { (ಶೂನ್ಯ)pw; }
ಪೂರ್ಣಾಂಕ login_login(ರಚನೆ logininfo *li) { (ಶೂನ್ಯ)li; ಹಿಂತಿರುಗಿ 0; }
ಪೂರ್ಣಾಂಕ login_logout(ರಚನೆ logininfo *li) { (ಶೂನ್ಯ)li; ಹಿಂತಿರುಗಿ 0; }
ಶೂನ್ಯ login_free_ನಮೂದು(ರಚನೆ logininfo *li) { (ಶೂನ್ಯ)li; }
ಶೂನ್ಯ login_ಗಣ_addr(ರಚನೆ logininfo *li, ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *sa,
    ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ sa_ಗಾತ್ರ) { (ಶೂನ್ಯ)li; (ಶೂನ್ಯ)sa; (ಶೂನ್ಯ)sa_ಗಾತ್ರ; }
ಪೂರ್ಣಾಂಕ openpty(ಪೂರ್ಣಾಂಕ *amaster, ಪೂರ್ಣಾಂಕ *aslave, ಅಕ್ಷರ *name,
    ಸ್ಥಿರಾಂಕ ರಚನೆ termios *termp, ಸ್ಥಿರಾಂಕ ರಚನೆ winsize *winp)
    { (ಶೂನ್ಯ)termp; (ಶೂನ್ಯ)winp; *amaster = -1; *aslave = -1;
    ಆದರೆ (name) name[0] = '\0'; ಹಿಂತಿರುಗಿ -1; }

ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ __real_do_exec(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ __real_do_exec_pty(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ __real_do_exec_no_pty(ರಚನೆ ssh *, Session *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ
__wrap_do_exec(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)s;
	(ಶೂನ್ಯ)command;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
__wrap_do_exec_pty(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)s;
	(ಶೂನ್ಯ)command;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
__wrap_do_exec_no_pty(ರಚನೆ ssh *ssh, Session *s, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	(ಶೂನ್ಯ)ssh;
	(ಶೂನ್ಯ)s;
	(ಶೂನ್ಯ)command;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ರಚನೆ sshbuf *b = sshbuf_from(str, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(str));
	ರಚನೆ sshkey *k = ಖಾಲಿ;
	ಆದರೆ (b == ಖಾಲಿ || sshkey_parse_ಖಾಸಗಿ_fileblob(b, "", &k, ಖಾಲಿ) != 0)
		abort();
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *str)
{
	ಅಕ್ಷರ *tmp, *cp;
	ರಚನೆ sshkey *k = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಆದರೆ (k == ಖಾಲಿ)
		abort();
	tmp = cp = strdup(str);
	ಆದರೆ (sshkey_read(k, &cp) != 0)
		abort();
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ k;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pump(ರಚನೆ ssh *from, ರಚನೆ ssh *ಗಮ್ಯ, ಗಾತ್ರ_t *transferred)
{
	ಸ್ಥಿರಾಂಕ u_char *buf;
	ಗಾತ್ರ_t len;
	u_char type;
	ಪೂರ್ಣಾಂಕ r;
	*transferred = 0;
	ಆದರೆ ((r = ssh_packet_ಮುಂದಿನ(from, &type)) != 0)
		ಹಿಂತಿರುಗಿ r;
	buf = ssh_output_ptr(from, &len);
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = ssh_ಒಳಹರಿವು_append(ಗಮ್ಯ, buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = ssh_output_consume(from, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	*transferred = len;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಸತತ_kex(ರಚನೆ ssh *client, ರಚನೆ ssh *server)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t cn, sn;
	ಗಾಗಿ (ಪೂರ್ಣಾಂಕ i = 0; i < 100; i++) {
		ಆದರೆ ((r = pump(server, client, &sn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((r = pump(client, server, &cn)) != 0) ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (server->kex->ಮುಗಿದ && client->kex->ಮುಗಿದ)
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (cn == 0 && sn == 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_PROTOCOL_ERROR;
}

#ಅನ್ತರ್ಭಾವ "fixed-keys.h"

ಸ್ಥಿರ ರಚನೆ ssh *g_client = ಖಾಲಿ;
ಸ್ಥಿರ ರಚನೆ ssh *g_server = ಖಾಲಿ;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_init = 0;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ g_channel_id = -1;
ಸ್ಥಿರ Authctxt g_authctxt;
ಸ್ಥಿರ ರಚನೆ passwd g_fake_pw;

ಸ್ಥಿರ ಅಕ್ಷರ *g_pending_rtype = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *g_pending_exec_cmd = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *g_pending_env_name = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *g_pending_env_val = ಖಾಲಿ;

ಸ್ಥಿರ ಶೂನ್ಯ
my_session_exec_req(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &g_pending_exec_cmd, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ಸ್ಥಿರ ಶೂನ್ಯ
my_session_env_req(ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &g_pending_env_name, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &g_pending_env_val, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_channel_request(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	uint32_t chan_id;
	u_char want_ಉತ್ತರ;

	(ಶೂನ್ಯ)type;
	(ಶೂನ್ಯ)seq;
	ಆದರೆ (sshpkt_get_u32(ssh, &chan_id) != 0 ||
	    sshpkt_get_cstring(ssh, &g_pending_rtype, ಖಾಲಿ) != 0 ||
	    sshpkt_get_u8(ssh, &want_ಉತ್ತರ) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (g_channel_id >= 0 && g_pending_rtype != ಖಾಲಿ) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ಆದರೆ (c != ಖಾಲಿ) {
			ಆದರೆ (strcmp(g_pending_rtype, "exec") == 0)
				my_session_exec_req(ssh);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(g_pending_rtype, "env") == 0)
				my_session_env_req(ssh);
			ಇಲ್ಲದಿದ್ದರೆ
				(ಶೂನ್ಯ)session_ಒಳಹರಿವು_channel_req(ssh, c,
				    g_pending_rtype);
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_channel(ರಚನೆ ssh *ssh)
{
	ಆದರೆ (g_channel_id >= 0) {
		Channel *c = channel_lookup(ssh, g_channel_id);
		ಆದರೆ (c != ಖಾಲಿ)
			channel_free(ssh, c);
		g_channel_id = -1;
	}
	Channel *c = channel_new(ssh, (ಅಕ್ಷರ *)"session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, 32768, 32768, 0, (ಅಕ್ಷರ *)"fuzz", 0);
	ಆದರೆ (c == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	g_channel_id = c->self;
	Session *s = session_new();
	ಆದರೆ (s != ಖಾಲಿ) {
		s->chanid = c->self;
		s->pw = &g_fake_pw;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
init_once(ಶೂನ್ಯ)
{
	ಆದರೆ (g_init)
		ಹಿಂತಿರುಗಿ 0;
	ಸಂಕೇತ(SIGPIPE, SIG_IGN);
	log_init("session_channel_req_fuzz", SYSLOG_LEVEL_ERROR,
	    SYSLOG_FACILITY_AUTH, 0);

	memset(&g_fake_pw, 0, ಗಾತ್ರ(g_fake_pw));
	g_fake_pw.pw_name = (ಅಕ್ಷರ *)"fuzz";
	g_fake_pw.pw_uid = 1000;
	g_fake_pw.pw_gid = 1000;
	g_fake_pw.pw_dir = (ಅಕ್ಷರ *)"/tmp";
	g_fake_pw.pw_shell = (ಅಕ್ಷರ *)"/bin/sh";
	privsep_pw = &g_fake_pw;

	initialize_server_options(&options);
	fill_default_server_options(&options);

	loginmsg = sshbuf_new();

	memset(&g_authctxt, 0, ಗಾತ್ರ(g_authctxt));
	g_authctxt.pw = &g_fake_pw;
	g_authctxt.valid = 1;

	ರಚನೆ sshkey *priv = ತುಂಬು_ಖಾಸಗಿ(PRIV_ED25519);
	ರಚನೆ sshkey *pub = ತುಂಬು_ಬಹಿರಂಗ(PUB_ED25519);
	ಅಕ್ಷರ *keyname = xstrdup(sshkey_ssh_name(priv));

	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *defaults[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *proposal[PROPOSAL_MAX] = { 0 };
	ಪೂರ್ಣಾಂಕ i;
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++) {
		ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *p = defaults[i];
		ಆದರೆ (i == PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS)
			p = keyname;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_KEX_ALGS)
			p = "curve25519-sha256";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_ENC_ALGS_CTOS ||
		    i == PROPOSAL_ENC_ALGS_STOC)
			p = "aes128-ctr";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (i == PROPOSAL_MAC_ALGS_CTOS ||
		    i == PROPOSAL_MAC_ALGS_STOC)
			p = "hmac-sha2-256";
		proposal[i] = strdup(p);
	}
	ರಚನೆ kex_params kp;
	ಸ್ಮರಣೆ_ನಕಲು(kp.proposal, proposal, ಗಾತ್ರ(proposal));

	ಆದರೆ (ssh_init(&g_client, 0, &kp) != 0 ||
	    ssh_init(&g_server, 1, &kp) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ssh_ಕೂಡಿಸು_hostkey(g_server, priv) != 0 ||
	    ssh_ಕೂಡಿಸು_hostkey(g_client, pub) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (ಸತತ_kex(g_client, g_server) != 0)
		ಹಿಂತಿರುಗಿ -1;

	g_server->authctxt = &g_authctxt;

	channel_init_channels(g_server);

	ssh_dispatch_init(g_server, &dispatch_protocol_ignore);
	ssh_dispatch_ಗಣ(g_server, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST,
	    &ಒಳಹರಿವು_channel_request);

	ಬಿಡುಗಡೆ(keyname);
	ಗಾಗಿ (i = 0; i < PROPOSAL_MAX; i++)
		ಬಿಡುಗಡೆ(proposal[i]);
	g_init = 1;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
fuzz_session_one(ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಆದರೆ (init_once() != 0)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಗಾತ್ರ_2 > 65000)
		ಹಿಂತಿರುಗಿ;

	reset_channel(g_server);

	ಒಳ_fuzz = 1;
	ಆದರೆ (setjmp(fuzz_env) == 0) {
		ಗಾತ್ರ_t transferred;
		ಆದರೆ (ssh_packet_put(g_client, SSH2_ಸಂದೇಶ_CHANNEL_REQUEST,
		    ದತ್ತಾಂಶ, ಗಾತ್ರ_2) != 0)
			ಹೋಗು ಮುಗಿದ;
		ಆದರೆ (pump(g_client, g_server, &transferred) != 0)
			ಹೋಗು ಮುಗಿದ;
		(ಶೂನ್ಯ)ssh_dispatch_ಸತತ(g_server, DISPATCH_NONBLOCK, ಖಾಲಿ);
	ಮುಗಿದ:
		;
	}
	ಒಳ_fuzz = 0;
	ಬಿಡುಗಡೆ(g_pending_rtype);
	g_pending_rtype = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(g_pending_exec_cmd);
	g_pending_exec_cmd = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(g_pending_env_name);
	g_pending_env_name = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(g_pending_env_val);
	g_pending_env_val = ಖಾಲಿ;
}
