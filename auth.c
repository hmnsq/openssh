/* $OpenBSD: auth.c,v 1.165 2026/07/21 06:17:42 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#ifdef HAVE_LOGIN_H
#include <login.h>
#endif
#ifdef USE_SHADOW
#include <shadow.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <netdb.h>
#include <time.h>

#include "xmalloc.h"
#include "match.h"
#include "groupaccess.h"
#include "log.h"
#include "sshbuf.h"
#include "misc.h"
#include "servconf.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"
#include "canohost.h"
#include "uidswap.h"
#include "packet.h"
#include "loginrec.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "authfile.h"
#include "monitor_wrap.h"
#include "ssherr.h"
#include "channels.h"

/* import */
extern ServerOptions options;
extern struct include_list includes;
extern struct sshbuf *loginmsg;
extern struct passwd *privsep_pw;
extern struct sshauthopt *auth_opts;

/* Debugging messages */
static struct sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
整数
allowed_user(struct ssh *ssh, struct passwd * pw)
{
	struct stat st;
	const char *hostname = NULL, *ipaddr = NULL;
	整数 r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	もし (!pw || !pw->pw_name)
		戻る 0;

	もし (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		戻る 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	もし (options.chroot_directory == NULL ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		char *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		もし (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			free(shell);
			戻る 0;
		}
		もし (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			free(shell);
			戻る 0;
		}
		free(shell);
	}

	もし (options.num_deny_users > 0 || options.num_allow_users > 0 ||
	    options.num_deny_groups > 0 || options.num_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	もし (options.num_deny_users > 0) {
		ために (i = 0; i < options.num_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			もし (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} 否则 もし (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				戻る 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	もし (options.num_allow_users > 0) {
		ために (i = 0; i < options.num_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			もし (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} 否则 もし (r == 1)
				break;
		}
		/* i < options.num_allow_users iff we break for loop */
		もし (i >= options.num_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			戻る 0;
		}
	}
	もし (options.num_deny_groups > 0 || options.num_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		もし (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			戻る 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		もし (options.num_deny_groups > 0)
			もし (ga_match(options.deny_groups,
			    options.num_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				戻る 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		もし (options.num_allow_groups > 0)
			もし (!ga_match(options.allow_groups,
			    options.num_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				戻る 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	もし (!sys_auth_allowed_user(pw, loginmsg))
		戻る 0;
#endif

	/* We found no reason not to let this user try to log on... */
	戻る 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
static char *
format_method_key(Authctxt *authctxt)
{
	const struct sshkey *key = authctxt->auth_method_key;
	const char *methinfo = authctxt->auth_method_info;
	char *fp, *cafp, *ret = NULL;

	もし (key == NULL)
		戻る NULL;

	もし (sshkey_is_cert(key)) {
		fp = sshkey_fingerprint(key,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(key->cert->signature_key,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(key), fp == NULL ? "(null)" : fp,
		    key->cert->key_id,
		    (unsigned long long)key->cert->serial,
		    sshkey_type(key->cert->signature_key),
		    cafp == NULL ? "(null)" : cafp,
		    methinfo == NULL ? "" : ", ",
		    methinfo == NULL ? "" : methinfo);
		free(fp);
		free(cafp);
	} 否则 {
		fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(key),
		    fp == NULL ? "(null)" : fp,
		    methinfo == NULL ? "" : ", ",
		    methinfo == NULL ? "" : methinfo);
		free(fp);
	}
	戻る ret;
}

void
auth_log(struct ssh *ssh, 整数 authenticated, 整数 partial,
    const char *method, const char *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	整数 level = SYSLOG_LEVEL_VERBOSE;
	const char *authmsg;
	char *extra = NULL;

	もし (!mm_is_monitor() && !authctxt->postponed)
		戻る;

	/* Raise logging level */
	もし (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	もし (authctxt->postponed)
		authmsg = "Postponed";
	否则 もし (partial)
		authmsg = "Partial";
	否则
		authmsg = authenticated ? "Accepted" : "Failed";

	もし ((extra = format_method_key(authctxt)) == NULL) {
		もし (authctxt->auth_method_info != NULL)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != NULL ? "/" : "", submethod == NULL ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != NULL ? ": " : "",
	    extra != NULL ? extra : "");

	free(extra);

#もし defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	もし (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		もし (strcmp(method, "password") == 0 ||
		    strncmp(method, "keyboard-interactive", 20) == 0 ||
		    strcmp(method, "challenge-response") == 0)
			record_failed_login(ssh, authctxt->user,
			    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
# endif
# ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, audit_classify_auth(method));
# endif
	}
#endif
#もし defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	もし (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

void
auth_maxtries_exceeded(struct ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	error("maximum authentication attempts exceeded for "
	    "%s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh));
	ssh_packet_disconnect(ssh, "Too many authentication failures");
	/* NOTREACHED */
}

/*
 * Check whether root logins are disallowed.
 */
整数
auth_root_allowed(struct ssh *ssh, const char *method)
{
	switch (options.permit_root_login) {
	case PERMIT_YES:
		戻る 1;
	case PERMIT_NO_PASSWD:
		もし (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			戻る 1;
		break;
	case PERMIT_FORCED_ONLY:
		もし (auth_opts->force_command != NULL) {
			logit("Root login accepted for forced command.");
			戻る 1;
		}
		break;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	戻る 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
char *
expand_authorized_keys(const char *filename, struct passwd *pw)
{
	char *file, uidstr[32], ret[PATH_MAX];
	整数 i;

	snprintf(uidstr, sizeof(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (char *)NULL);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	もし (path_absolute(file))
		戻る (file);

	i = snprintf(ret, sizeof(ret), "%s/%s", pw->pw_dir, file);
	もし (i < 0 || (size_t)i >= sizeof(ret))
		fatal("expand_authorized_keys: path too long");
	free(file);
	戻る (xstrdup(ret));
}

char *
authorized_principals_file(struct passwd *pw)
{
	もし (options.authorized_principals_file == NULL)
		戻る NULL;
	戻る expand_authorized_keys(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_key_in_hostfiles(struct passwd *pw, struct sshkey *key, const char *host,
    const char *sysfile, const char *userfile)
{
	char *user_hostfile;
	struct stat st;
	HostStatus host_status;
	struct hostkeys *hostkeys;
	const struct hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	もし (userfile != NULL) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		もし (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} 否则 {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		free(user_hostfile);
	}
	host_status = check_key_in_hostkeys(hostkeys, key, &found);
	もし (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	否则 もし (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->line);
	否则
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	戻る host_status;
}

struct passwd *
getpwnamallow(struct ssh *ssh, const char *user)
{
#ifdef HAVE_LOGIN_CAP
	extern login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	const char *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	struct passwd *pw;
	struct connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == NULL;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	ために (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#もし defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#もし defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	もし (pw == NULL) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		戻る (NULL);
	}
	もし (!allowed_user(ssh, pw))
		戻る (NULL);
#ifdef HAVE_LOGIN_CAP
	もし ((lc = login_getpwclass(pw)) == NULL) {
		debug("unable to get login class: %s", user);
		戻る (NULL);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	もし (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		戻る (NULL);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	もし (!auth_timeok(lc, time(NULL))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		戻る (NULL);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	もし ((as = auth_open()) == NULL || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = NULL;
	}
	もし (as != NULL)
		auth_close(as);
#endif
#endif
	もし (pw != NULL)
		戻る (pwcopy(pw));
	戻る (NULL);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
整数
auth_key_is_revoked(struct sshkey *key)
{
	char *fp = NULL;
	u_int i;
	整数 r;

	もし (options.num_revoked_keys_files == 0)
		戻る 0;
	もし ((fp = sshkey_fingerprint(key, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		goto out;
	}

	ために (i = 0; i < options.num_revoked_keys_files; i++) {
		r = sshkey_check_revoked(key, options.revoked_keys_files[i]);
		switch (r) {
		case 0:
			break; /* not revoked */
		case SSH_ERR_KEY_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(key), fp,
			    options.revoked_keys_files[i]);
			goto out;
		default:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(key), fp,
			    options.revoked_keys_files[i]);
			goto out;
		}
	}

	/* Success */
	r = 0;

 out:
	free(fp);
	戻る r == 0 ? 0 : 1;
}

void
auth_debug_add(const char *fmt,...)
{
	char buf[1024];
	va_list args;
	整数 r;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	もし (auth_debug != NULL)
		もし ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

void
auth_debug_send(struct ssh *ssh)
{
	char *msg;
	整数 r;

	もし (auth_debug == NULL)
		戻る;
	ながら (sshbuf_len(auth_debug) != 0) {
		もし ((r = sshbuf_get_cstring(auth_debug, &msg, NULL)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", msg);
		free(msg);
	}
}

void
auth_debug_reset(void)
{
	もし (auth_debug != NULL)
		sshbuf_reset(auth_debug);
	否则 もし ((auth_debug = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
}

struct passwd *
fakepw(void)
{
	static 整数 done = 0;
	static struct passwd fake;
	const char hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	char *cp;

	もし (done)
		戻る (&fake);

	memset(&fake, 0, sizeof(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	ために (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(sizeof(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == NULL ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == NULL ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	戻る (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

const char *
auth_get_canonical_hostname(struct ssh *ssh, 整数 use_dns)
{
	static char *dnsname;

	もし (!use_dns)
		戻る ssh_remote_ipaddr(ssh);
	もし (dnsname != NULL)
		戻る dnsname;
	dnsname = ssh_remote_hostname(ssh);
	戻る dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
void
auth_log_authopts(const char *loc, const struct sshauthopt *opts, 整数 do_remote)
{
	整数 do_env = options.permit_user_env && opts->nenv > 0;
	整数 do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	整数 do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	char msg[1024], buf[64];

	snprintf(buf, sizeof(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(msg, sizeof(msg), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == NULL ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == NULL ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, msg);
	もし (do_remote)
		auth_debug_add("%s: %s", loc, msg);

	もし (options.permit_user_env) {
		ために (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			もし (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	もし (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, sizeof(buf));
		debug("%s: expires at %s", loc, buf);
	}
	もし (opts->cert_principals != NULL) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	もし (opts->force_command != NULL)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	もし (do_permitopen) {
		ために (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	もし (do_permitlisten) {
		ために (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
整数
auth_activate_options(struct ssh *ssh, struct sshauthopt *opts)
{
	struct sshauthopt *old = auth_opts;
	const char *emsg = NULL;

	debug_f("setting new authentication options");
	もし ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == NULL) {
		error("Inconsistent authentication options: %s", emsg);
		戻る -1;
	}
	sshauthopt_free(old);
	戻る 0;
}

/* Disable forwarding, etc for the session */
void
auth_restrict_session(struct ssh *ssh)
{
	struct sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	もし ((restricted = sshauthopt_new()) == NULL)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	もし (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
