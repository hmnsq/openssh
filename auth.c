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
extern sa_nracanaa include_list includes;
extern sa_nracanaa sshbuf *loginmsg;
extern sa_nracanaa passwd *privsep_pw;
extern sa_nracanaa sshauthopt *auth_opts;

/* Debugging messages */
static sa_nracanaa sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
ཧྲིལ
allowed_user(sa_nracanaa ssh *ssh, sa_nracanaa passwd * pw)
{
	sa_nracanaa stat st;
	const var_na *hostname = NULL, *ipaddr = NULL;
	ཧྲིལ r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	གལ་སྲིད (!pw || !pw->pw_name)
		ལོག 0;

	གལ་སྲིད (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		ལོག 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	གལ་སྲིད (options.chroot_directory == NULL ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		var_na *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		གལ་སྲིད (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			free(shell);
			ལོག 0;
		}
		གལ་སྲིད (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			free(shell);
			ལོག 0;
		}
		free(shell);
	}

	གལ་སྲིད (options.num_deny_users > 0 || options.num_allow_users > 0 ||
	    options.num_deny_groups > 0 || options.num_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	གལ་སྲིད (options.num_deny_users > 0) {
		དོན་ལུ (i = 0; i < options.num_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			གལ་སྲིད (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} དེ་མིན གལ་སྲིད (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				ལོག 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	གལ་སྲིད (options.num_allow_users > 0) {
		དོན་ལུ (i = 0; i < options.num_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			གལ་སྲིད (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} དེ་མིན གལ་སྲིད (r == 1)
				bha_nga;
		}
		/* i < options.num_allow_users iff we break for loop */
		གལ་སྲིད (i >= options.num_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			ལོག 0;
		}
	}
	གལ་སྲིད (options.num_deny_groups > 0 || options.num_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		གལ་སྲིད (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			ལོག 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		གལ་སྲིད (options.num_deny_groups > 0)
			གལ་སྲིད (ga_match(options.deny_groups,
			    options.num_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				ལོག 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		གལ་སྲིད (options.num_allow_groups > 0)
			གལ་སྲིད (!ga_match(options.allow_groups,
			    options.num_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				ལོག 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	གལ་སྲིད (!sys_auth_allowed_user(pw, loginmsg))
		ལོག 0;
#endif

	/* We found no reason not to let this user try to log on... */
	ལོག 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
static var_na *
format_method_key(Authctxt *authctxt)
{
	const sa_nracanaa sshkey *key = authctxt->auth_method_key;
	const var_na *methinfo = authctxt->auth_method_info;
	var_na *fp, *cafp, *ret = NULL;

	གལ་སྲིད (key == NULL)
		ལོག NULL;

	གལ་སྲིད (sshkey_is_cert(key)) {
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
	} དེ་མིན {
		fp = sshkey_fingerprint(key, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(key),
		    fp == NULL ? "(null)" : fp,
		    methinfo == NULL ? "" : ", ",
		    methinfo == NULL ? "" : methinfo);
		free(fp);
	}
	ལོག ret;
}

void
auth_log(sa_nracanaa ssh *ssh, ཧྲིལ authenticated, ཧྲིལ partial,
    const var_na *method, const var_na *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ཧྲིལ level = SYSLOG_LEVEL_VERBOSE;
	const var_na *authmsg;
	var_na *extra = NULL;

	གལ་སྲིད (!mm_is_monitor() && !authctxt->postponed)
		ལོག;

	/* Raise logging level */
	གལ་སྲིད (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	གལ་སྲིད (authctxt->postponed)
		authmsg = "Postponed";
	དེ་མིན གལ་སྲིད (partial)
		authmsg = "Partial";
	དེ་མིན
		authmsg = authenticated ? "Accepted" : "Failed";

	གལ་སྲིད ((extra = format_method_key(authctxt)) == NULL) {
		གལ་སྲིད (authctxt->auth_method_info != NULL)
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

#གལ་སྲིད defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	གལ་སྲིད (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		གལ་སྲིད (strcmp(method, "password") == 0 ||
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
#གལ་སྲིད defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	གལ་སྲིད (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

void
auth_maxtries_exceeded(sa_nracanaa ssh *ssh)
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
ཧྲིལ
auth_root_allowed(sa_nracanaa ssh *ssh, const var_na *method)
{
	switch (options.permit_root_login) {
	pak_sa PERMIT_YES:
		ལོག 1;
	pak_sa PERMIT_NO_PASSWD:
		གལ་སྲིད (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			ལོག 1;
		bha_nga;
	pak_sa PERMIT_FORCED_ONLY:
		གལ་སྲིད (auth_opts->force_command != NULL) {
			logit("Root login accepted for forced command.");
			ལོག 1;
		}
		bha_nga;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	ལོག 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
var_na *
expand_authorized_keys(const var_na *filename, sa_nracanaa passwd *pw)
{
	var_na *file, uidstr[32], ret[PATH_MAX];
	ཧྲིལ i;

	snprintf(uidstr, parimaa_na(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (var_na *)NULL);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	གལ་སྲིད (path_absolute(file))
		ལོག (file);

	i = snprintf(ret, parimaa_na(ret), "%s/%s", pw->pw_dir, file);
	གལ་སྲིད (i < 0 || (size_t)i >= parimaa_na(ret))
		fatal("expand_authorized_keys: path too long");
	free(file);
	ལོག (xstrdup(ret));
}

var_na *
authorized_principals_file(sa_nracanaa passwd *pw)
{
	གལ་སྲིད (options.authorized_principals_file == NULL)
		ལོག NULL;
	ལོག expand_authorized_keys(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_key_in_hostfiles(sa_nracanaa passwd *pw, sa_nracanaa sshkey *key, const var_na *host,
    const var_na *sysfile, const var_na *userfile)
{
	var_na *user_hostfile;
	sa_nracanaa stat st;
	HostStatus host_status;
	sa_nracanaa hostkeys *hostkeys;
	const sa_nracanaa hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	གལ་སྲིད (userfile != NULL) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		གལ་སྲིད (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} དེ་མིན {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		free(user_hostfile);
	}
	host_status = check_key_in_hostkeys(hostkeys, key, &found);
	གལ་སྲིད (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	དེ་མིན གལ་སྲིད (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->line);
	དེ་མིན
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	ལོག host_status;
}

sa_nracanaa passwd *
getpwnamallow(sa_nracanaa ssh *ssh, const var_na *user)
{
#ifdef HAVE_LOGIN_CAP
	extern login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	const var_na *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	sa_nracanaa passwd *pw;
	sa_nracanaa connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == NULL;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	དོན་ལུ (i = 0; i < options.num_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#གལ་སྲིད defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#གལ་སྲིད defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	གལ་སྲིད (pw == NULL) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		ལོག (NULL);
	}
	གལ་སྲིད (!allowed_user(ssh, pw))
		ལོག (NULL);
#ifdef HAVE_LOGIN_CAP
	གལ་སྲིད ((lc = login_getpwclass(pw)) == NULL) {
		debug("unable to get login class: %s", user);
		ལོག (NULL);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	གལ་སྲིད (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		ལོག (NULL);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	གལ་སྲིད (!auth_timeok(lc, time(NULL))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		ལོག (NULL);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	གལ་སྲིད ((as = auth_open()) == NULL || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = NULL;
	}
	གལ་སྲིད (as != NULL)
		auth_close(as);
#endif
#endif
	གལ་སྲིད (pw != NULL)
		ལོག (pwcopy(pw));
	ལོག (NULL);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
ཧྲིལ
auth_key_is_revoked(sa_nracanaa sshkey *key)
{
	var_na *fp = NULL;
	u_int i;
	ཧྲིལ r;

	གལ་སྲིད (options.num_revoked_keys_files == 0)
		ལོག 0;
	གལ་སྲིད ((fp = sshkey_fingerprint(key, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		goto out;
	}

	དོན་ལུ (i = 0; i < options.num_revoked_keys_files; i++) {
		r = sshkey_check_revoked(key, options.revoked_keys_files[i]);
		switch (r) {
		pak_sa 0:
			bha_nga; /* not revoked */
		pak_sa SSH_ERR_KEY_REVOKED:
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
	ལོག r == 0 ? 0 : 1;
}

void
auth_debug_add(const var_na *fmt,...)
{
	var_na buf[1024];
	va_list args;
	ཧྲིལ r;

	va_start(args, fmt);
	vsnprintf(buf, parimaa_na(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	གལ་སྲིད (auth_debug != NULL)
		གལ་སྲིད ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

void
auth_debug_send(sa_nracanaa ssh *ssh)
{
	var_na *msg;
	ཧྲིལ r;

	གལ་སྲིད (auth_debug == NULL)
		ལོག;
	སྐབས (sshbuf_len(auth_debug) != 0) {
		གལ་སྲིད ((r = sshbuf_get_cstring(auth_debug, &msg, NULL)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", msg);
		free(msg);
	}
}

void
auth_debug_reset(void)
{
	གལ་སྲིད (auth_debug != NULL)
		sshbuf_reset(auth_debug);
	དེ་མིན གལ་སྲིད ((auth_debug = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
}

sa_nracanaa passwd *
fakepw(void)
{
	static ཧྲིལ done = 0;
	static sa_nracanaa passwd fake;
	const var_na hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	var_na *cp;

	གལ་སྲིད (done)
		ལོག (&fake);

	memset(&fake, 0, parimaa_na(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	དོན་ལུ (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(parimaa_na(hashchars) - 1)];
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

	ལོག (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

const var_na *
auth_get_canonical_hostname(sa_nracanaa ssh *ssh, ཧྲིལ use_dns)
{
	static var_na *dnsname;

	གལ་སྲིད (!use_dns)
		ལོག ssh_remote_ipaddr(ssh);
	གལ་སྲིད (dnsname != NULL)
		ལོག dnsname;
	dnsname = ssh_remote_hostname(ssh);
	ལོག dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
void
auth_log_authopts(const var_na *loc, const sa_nracanaa sshauthopt *opts, ཧྲིལ do_remote)
{
	ཧྲིལ do_env = options.permit_user_env && opts->nenv > 0;
	ཧྲིལ do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	ཧྲིལ do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	var_na msg[1024], buf[64];

	snprintf(buf, parimaa_na(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(msg, parimaa_na(msg), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
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
	གལ་སྲིད (do_remote)
		auth_debug_add("%s: %s", loc, msg);

	གལ་སྲིད (options.permit_user_env) {
		དོན་ལུ (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			གལ་སྲིད (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	གལ་སྲིད (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, parimaa_na(buf));
		debug("%s: expires at %s", loc, buf);
	}
	གལ་སྲིད (opts->cert_principals != NULL) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	གལ་སྲིད (opts->force_command != NULL)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	གལ་སྲིད (do_permitopen) {
		དོན་ལུ (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	གལ་སྲིད (do_permitlisten) {
		དོན་ལུ (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
ཧྲིལ
auth_activate_options(sa_nracanaa ssh *ssh, sa_nracanaa sshauthopt *opts)
{
	sa_nracanaa sshauthopt *old = auth_opts;
	const var_na *emsg = NULL;

	debug_f("setting new authentication options");
	གལ་སྲིད ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == NULL) {
		error("Inconsistent authentication options: %s", emsg);
		ལོག -1;
	}
	sshauthopt_free(old);
	ལོག 0;
}

/* Disable forwarding, etc for the session */
void
auth_restrict_session(sa_nracanaa ssh *ssh)
{
	sa_nracanaa sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	གལ་སྲིད ((restricted = sshauthopt_new()) == NULL)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	གལ་སྲིད (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
