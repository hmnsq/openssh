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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_H
#ਅਨ੍ਤਰ੍ਭਾਵ <login.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SHADOW
#ਅਨ੍ਤਰ੍ਭਾਵ <shadow.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "groupaccess.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "loginrec.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-gss.h"
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "monitor_wrap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "channels.h"

/* import */
ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਬਣਤਰ include_list includes;
ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;
ਬਾਹਰੀ ਬਣਤਰ passwd *privsep_pw;
ਬਾਹਰੀ ਬਣਤਰ sshauthopt *auth_opts;

/* Debugging messages */
ਸਥਿਰ ਬਣਤਰ sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
ਪੂਰਨ
allowed_user(ਬਣਤਰ ssh *ssh, ਬਣਤਰ passwd * pw)
{
	ਬਣਤਰ stat st;
	ਅਚਲ ਅੱਖਰ *hostname = ਨਿਰਾ, *ipaddr = ਨਿਰਾ;
	ਪੂਰਨ r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	ਜੇ (!pw || !pw->pw_name)
		ਵਾਪਸ 0;

	ਜੇ (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		ਵਾਪਸ 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	ਜੇ (options.chroot_directory == ਨਿਰਾ ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		ਅੱਖਰ *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		ਜੇ (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			ਮੁਕਤ(shell);
			ਵਾਪਸ 0;
		}
		ਜੇ (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			ਮੁਕਤ(shell);
			ਵਾਪਸ 0;
		}
		ਮੁਕਤ(shell);
	}

	ਜੇ (options.ਅੰਕ_deny_users > 0 || options.ਅੰਕ_allow_users > 0 ||
	    options.ਅੰਕ_deny_groups > 0 || options.ਅੰਕ_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	ਜੇ (options.ਅੰਕ_deny_users > 0) {
		ਲਈ (i = 0; i < options.ਅੰਕ_deny_users; i++) {
			r = ਮੇਲ_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			ਜੇ (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} ਨਹੀਂਤਾਂ ਜੇ (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				ਵਾਪਸ 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	ਜੇ (options.ਅੰਕ_allow_users > 0) {
		ਲਈ (i = 0; i < options.ਅੰਕ_allow_users; i++) {
			r = ਮੇਲ_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			ਜੇ (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} ਨਹੀਂਤਾਂ ਜੇ (r == 1)
				ਰੋਕੋ;
		}
		/* i < options.num_allow_users iff we break for loop */
		ਜੇ (i >= options.ਅੰਕ_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			ਵਾਪਸ 0;
		}
	}
	ਜੇ (options.ਅੰਕ_deny_groups > 0 || options.ਅੰਕ_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		ਜੇ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			ਵਾਪਸ 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		ਜੇ (options.ਅੰਕ_deny_groups > 0)
			ਜੇ (ga_ਮੇਲ(options.deny_groups,
			    options.ਅੰਕ_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				ਵਾਪਸ 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		ਜੇ (options.ਅੰਕ_allow_groups > 0)
			ਜੇ (!ga_ਮੇਲ(options.allow_groups,
			    options.ਅੰਕ_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				ਵਾਪਸ 0;
			}
		ga_free();
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CUSTOM_SYS_AUTH_ALLOWED_USER
	ਜੇ (!sys_auth_allowed_user(pw, loginmsg))
		ਵਾਪਸ 0;
#ਜੇ_ਅੰਤ

	/* We found no reason not to let this user try to log on... */
	ਵਾਪਸ 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
ਸਥਿਰ ਅੱਖਰ *
format_ਵਿਧੀ_ਕੁੰਜੀ(Authctxt *authctxt)
{
	ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ = authctxt->auth_ਵਿਧੀ_ਕੁੰਜੀ;
	ਅਚਲ ਅੱਖਰ *methinfo = authctxt->auth_ਵਿਧੀ_info;
	ਅੱਖਰ *fp, *cafp, *ret = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;

	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
		fp = sshkey_fingerprint(ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(ਕੁੰਜੀ), fp == ਨਿਰਾ ? "(null)" : fp,
		    ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
		    sshkey_type(ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ),
		    cafp == ਨਿਰਾ ? "(null)" : cafp,
		    methinfo == ਨਿਰਾ ? "" : ", ",
		    methinfo == ਨਿਰਾ ? "" : methinfo);
		ਮੁਕਤ(fp);
		ਮੁਕਤ(cafp);
	} ਨਹੀਂਤਾਂ {
		fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(ਕੁੰਜੀ),
		    fp == ਨਿਰਾ ? "(null)" : fp,
		    methinfo == ਨਿਰਾ ? "" : ", ",
		    methinfo == ਨਿਰਾ ? "" : methinfo);
		ਮੁਕਤ(fp);
	}
	ਵਾਪਸ ret;
}

ਖਾਲੀ
auth_log(ਬਣਤਰ ssh *ssh, ਪੂਰਨ authenticated, ਪੂਰਨ partial,
    ਅਚਲ ਅੱਖਰ *ਵਿਧੀ, ਅਚਲ ਅੱਖਰ *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ਪੂਰਨ level = SYSLOG_LEVEL_VERBOSE;
	ਅਚਲ ਅੱਖਰ *authmsg;
	ਅੱਖਰ *extra = ਨਿਰਾ;

	ਜੇ (!mm_is_monitor() && !authctxt->postponed)
		ਵਾਪਸ;

	/* Raise logging level */
	ਜੇ (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(ਵਿਧੀ, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	ਜੇ (authctxt->postponed)
		authmsg = "Postponed";
	ਨਹੀਂਤਾਂ ਜੇ (partial)
		authmsg = "Partial";
	ਨਹੀਂਤਾਂ
		authmsg = authenticated ? "Accepted" : "Failed";

	ਜੇ ((extra = format_ਵਿਧੀ_ਕੁੰਜੀ(authctxt)) == ਨਿਰਾ) {
		ਜੇ (authctxt->auth_ਵਿਧੀ_info != ਨਿਰਾ)
			extra = xstrdup(authctxt->auth_ਵਿਧੀ_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    ਵਿਧੀ,
	    submethod != ਨਿਰਾ ? "/" : "", submethod == ਨਿਰਾ ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ਪੋਰਟ(ssh),
	    extra != ਨਿਰਾ ? ": " : "",
	    extra != ਨਿਰਾ ? extra : "");

	ਮੁਕਤ(extra);

#ਜੇ defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	ਜੇ (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		ਜੇ (strcmp(ਵਿਧੀ, "password") == 0 ||
		    ਲੜੀ_ਤੁਲਨਾ(ਵਿਧੀ, "keyboard-interactive", 20) == 0 ||
		    strcmp(ਵਿਧੀ, "challenge-response") == 0)
			ਰਿਕਾਰਡ_failed_login(ssh, authctxt->user,
			    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
# endif
# ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, audit_classify_auth(ਵਿਧੀ));
# endif
	}
#ਜੇ_ਅੰਤ
#ਜੇ defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	ਜੇ (authenticated)
		sys_auth_ਰਿਕਾਰਡ_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
auth_maxtries_exceeded(ਬਣਤਰ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	error("maximum authentication attempts exceeded for "
	    "%s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ਪੋਰਟ(ssh));
	ssh_packet_disconnect(ssh, "Too many authentication failures");
	/* NOTREACHED */
}

/*
 * Check whether root logins are disallowed.
 */
ਪੂਰਨ
auth_ਜੜ੍ਹ_allowed(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *ਵਿਧੀ)
{
	ਚੋਣ (options.permit_ਜੜ੍ਹ_login) {
	ਹਾਲਤ PERMIT_YES:
		ਵਾਪਸ 1;
	ਹਾਲਤ PERMIT_NO_PASSWD:
		ਜੇ (strcmp(ਵਿਧੀ, "publickey") == 0 ||
		    strcmp(ਵਿਧੀ, "hostbased") == 0 ||
		    strcmp(ਵਿਧੀ, "gssapi-with-mic") == 0)
			ਵਾਪਸ 1;
		ਰੋਕੋ;
	ਹਾਲਤ PERMIT_FORCED_ONLY:
		ਜੇ (auth_opts->force_command != ਨਿਰਾ) {
			logit("Root login accepted for forced command.");
			ਵਾਪਸ 1;
		}
		ਰੋਕੋ;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
	ਵਾਪਸ 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
ਅੱਖਰ *
expand_authorized_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ passwd *pw)
{
	ਅੱਖਰ *file, uidstr[32], ret[PATH_MAX];
	ਪੂਰਨ i;

	snprintf(uidstr, ਆਕਾਰ(uidstr), "%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (ਅੱਖਰ *)ਨਿਰਾ);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	ਜੇ (ਰਸਤਾ_absolute(file))
		ਵਾਪਸ (file);

	i = snprintf(ret, ਆਕਾਰ(ret), "%s/%s", pw->pw_dir, file);
	ਜੇ (i < 0 || (ਮਾਪ_t)i >= ਆਕਾਰ(ret))
		fatal("expand_authorized_keys: path too long");
	ਮੁਕਤ(file);
	ਵਾਪਸ (xstrdup(ret));
}

ਅੱਖਰ *
authorized_principals_file(ਬਣਤਰ passwd *pw)
{
	ਜੇ (options.authorized_principals_file == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ expand_authorized_ਕੁੰਜੀਆਂ(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
Host_ਸਥਿਤੀ
check_ਕੁੰਜੀ_ਵਿੱਚ_hostfiles(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *sysfile, ਅਚਲ ਅੱਖਰ *userfile)
{
	ਅੱਖਰ *user_hostfile;
	ਬਣਤਰ stat st;
	Host_ਸਥਿਤੀ host_ਸਥਿਤੀ;
	ਬਣਤਰ hostkeys *hostkeys;
	ਅਚਲ ਬਣਤਰ hostkey_ਇੰਦਰਾਜ *ਮਿਲਿਆ;

	hostkeys = init_hostkeys();
	ਲੱਦੋ_hostkeys(hostkeys, host, sysfile, 0);
	ਜੇ (userfile != ਨਿਰਾ) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		ਜੇ (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_ਜੋੜੋ("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} ਨਹੀਂਤਾਂ {
			temporarily_use_uid(pw);
			ਲੱਦੋ_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		ਮੁਕਤ(user_hostfile);
	}
	host_ਸਥਿਤੀ = check_ਕੁੰਜੀ_ਵਿੱਚ_hostkeys(hostkeys, ਕੁੰਜੀ, &ਮਿਲਿਆ);
	ਜੇ (host_ਸਥਿਤੀ == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	ਨਹੀਂਤਾਂ ਜੇ (host_ਸਥਿਤੀ == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    ਮਿਲਿਆ->host, ਮਿਲਿਆ->file, ਮਿਲਿਆ->ਸਤਰ);
	ਨਹੀਂਤਾਂ
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	ਵਾਪਸ host_ਸਥਿਤੀ;
}

ਬਣਤਰ passwd *
getpwnamallow(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *user)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	ਬਾਹਰੀ login_cap_t *lc;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_AUTH_HOSTOK
	ਅਚਲ ਅੱਖਰ *from_host, *from_ip;
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
	auth_session_t *as;
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ
	ਬਣਤਰ passwd *pw;
	ਬਣਤਰ connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ਨਿਰਾ;
	parse_server_ਮੇਲ_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	ਲਈ (i = 0; i < options.ਅੰਕ_log_verbose; i++)
		log_verbose_ਜੋੜੋ(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_ਸੈੱਟ_rekey_limits(ssh, options.rekey_ਹੱਦਬੰਦੀ,
	    options.rekey_interval);

#ਜੇ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#ਜੇ_ਅੰਤ

	pw = getpwnam(user);

#ਜੇ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#ਜੇ_ਅੰਤ
	ਜੇ (pw == ਨਿਰਾ) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_ਪੋਰਟ(ssh));
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CUSTOM_FAILED_LOGIN
		ਰਿਕਾਰਡ_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#ਜੇ_ਅੰਤ /* SSH_AUDIT_EVENTS */
		ਵਾਪਸ (ਨਿਰਾ);
	}
	ਜੇ (!allowed_user(ssh, pw))
		ਵਾਪਸ (ਨਿਰਾ);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	ਜੇ ((lc = login_getpwclass(pw)) == ਨਿਰਾ) {
		debug("unable to get login class: %s", user);
		ਵਾਪਸ (ਨਿਰਾ);
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	ਜੇ (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		ਵਾਪਸ (ਨਿਰਾ);
	}
#ਜੇ_ਅੰਤ /* HAVE_AUTH_HOSTOK */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_AUTH_TIMEOK
	ਜੇ (!auth_timeok(lc, time(ਨਿਰਾ))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		ਵਾਪਸ (ਨਿਰਾ);
	}
#ਜੇ_ਅੰਤ /* HAVE_AUTH_TIMEOK */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
	ਜੇ ((as = auth_open()) == ਨਿਰਾ || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ਨਿਰਾ;
	}
	ਜੇ (as != ਨਿਰਾ)
		auth_close(as);
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ
	ਜੇ (pw != ਨਿਰਾ)
		ਵਾਪਸ (pwcopy(pw));
	ਵਾਪਸ (ਨਿਰਾ);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
ਪੂਰਨ
auth_ਕੁੰਜੀ_is_revoked(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅੱਖਰ *fp = ਨਿਰਾ;
	u_int i;
	ਪੂਰਨ r;

	ਜੇ (options.ਅੰਕ_revoked_ਕੁੰਜੀਆਂ_files == 0)
		ਵਾਪਸ 0;
	ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਲਈ (i = 0; i < options.ਅੰਕ_revoked_ਕੁੰਜੀਆਂ_files; i++) {
		r = sshkey_check_revoked(ਕੁੰਜੀ, options.revoked_ਕੁੰਜੀਆਂ_files[i]);
		ਚੋਣ (r) {
		ਹਾਲਤ 0:
			ਰੋਕੋ; /* not revoked */
		ਹਾਲਤ SSH_ERR_ਕੁੰਜੀ_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(ਕੁੰਜੀ), fp,
			    options.revoked_ਕੁੰਜੀਆਂ_files[i]);
			ਜਾਓ ਬਾਹਰਲਾ;
		ਮੂਲ:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(ਕੁੰਜੀ), fp,
			    options.revoked_ਕੁੰਜੀਆਂ_files[i]);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Success */
	r = 0;

 ਬਾਹਰਲਾ:
	ਮੁਕਤ(fp);
	ਵਾਪਸ r == 0 ? 0 : 1;
}

ਖਾਲੀ
auth_debug_ਜੋੜੋ(ਅਚਲ ਅੱਖਰ *fmt,...)
{
	ਅੱਖਰ buf[1024];
	va_list ਦਲੀਲਾਂ;
	ਪੂਰਨ r;

	va_start(ਦਲੀਲਾਂ, fmt);
	vsnprintf(buf, ਆਕਾਰ(buf), fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);
	debug3("%s", buf);
	ਜੇ (auth_debug != ਨਿਰਾ)
		ਜੇ ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

ਖਾਲੀ
auth_debug_send(ਬਣਤਰ ssh *ssh)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ;
	ਪੂਰਨ r;

	ਜੇ (auth_debug == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜਦੋਂ (sshbuf_len(auth_debug) != 0) {
		ਜੇ ((r = sshbuf_get_cstring(auth_debug, &ਸੁਨੇਹਾ, ਨਿਰਾ)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", ਸੁਨੇਹਾ);
		ਮੁਕਤ(ਸੁਨੇਹਾ);
	}
}

ਖਾਲੀ
auth_debug_reset(ਖਾਲੀ)
{
	ਜੇ (auth_debug != ਨਿਰਾ)
		sshbuf_reset(auth_debug);
	ਨਹੀਂਤਾਂ ਜੇ ((auth_debug = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
}

ਬਣਤਰ passwd *
fakepw(ਖਾਲੀ)
{
	ਸਥਿਰ ਪੂਰਨ ਪੂਰਾ = 0;
	ਸਥਿਰ ਬਣਤਰ passwd fake;
	ਅਚਲ ਅੱਖਰ hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	ਅੱਖਰ *cp;

	ਜੇ (ਪੂਰਾ)
		ਵਾਪਸ (&fake);

	memset(&fake, 0, ਆਕਾਰ(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	ਲਈ (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_ਇਕਸਾਰ(ਆਕਾਰ(hashchars) - 1)];
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#ਜੇ_ਅੰਤ
	fake.pw_uid = privsep_pw == ਨਿਰਾ ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ਨਿਰਾ ? (gid_t)-1 : privsep_pw->pw_gid;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#ਜੇ_ਅੰਤ
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	ਪੂਰਾ = 1;

	ਵਾਪਸ (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ਅਚਲ ਅੱਖਰ *
auth_get_canonical_hostname(ਬਣਤਰ ssh *ssh, ਪੂਰਨ use_dns)
{
	ਸਥਿਰ ਅੱਖਰ *dnsname;

	ਜੇ (!use_dns)
		ਵਾਪਸ ssh_remote_ipaddr(ssh);
	ਜੇ (dnsname != ਨਿਰਾ)
		ਵਾਪਸ dnsname;
	dnsname = ssh_remote_hostname(ssh);
	ਵਾਪਸ dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
ਖਾਲੀ
auth_log_authopts(ਅਚਲ ਅੱਖਰ *loc, ਅਚਲ ਬਣਤਰ sshauthopt *opts, ਪੂਰਨ do_remote)
{
	ਪੂਰਨ do_env = options.permit_user_env && opts->nenv > 0;
	ਪੂਰਨ do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	ਪੂਰਨ do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	ਮਾਪ_t i;
	ਅੱਖਰ ਸੁਨੇਹਾ[1024], buf[64];

	snprintf(buf, ਆਕਾਰ(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(ਸੁਨੇਹਾ, ਆਕਾਰ(ਸੁਨੇਹਾ), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ਨਿਰਾ ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_ਪੋਰਟ_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ਨਿਰਾ ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, ਸੁਨੇਹਾ);
	ਜੇ (do_remote)
		auth_debug_ਜੋੜੋ("%s: %s", loc, ਸੁਨੇਹਾ);

	ਜੇ (options.permit_user_env) {
		ਲਈ (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			ਜੇ (do_remote) {
				auth_debug_ਜੋੜੋ("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	ਜੇ (opts->valid_before != 0) {
		format_absolute_ਸਮਾਂ(opts->valid_before, buf, ਆਕਾਰ(buf));
		debug("%s: expires at %s", loc, buf);
	}
	ਜੇ (opts->cert_principals != ਨਿਰਾ) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	ਜੇ (opts->force_command != ਨਿਰਾ)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	ਜੇ (do_permitopen) {
		ਲਈ (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	ਜੇ (do_permitlisten) {
		ਲਈ (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
ਪੂਰਨ
auth_activate_options(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshauthopt *opts)
{
	ਬਣਤਰ sshauthopt *old = auth_opts;
	ਅਚਲ ਅੱਖਰ *emsg = ਨਿਰਾ;

	debug_f("setting new authentication options");
	ਜੇ ((auth_opts = sshauthopt_ਮਿਲਾਓ(old, opts, &emsg)) == ਨਿਰਾ) {
		error("Inconsistent authentication options: %s", emsg);
		ਵਾਪਸ -1;
	}
	sshauthopt_free(old);
	ਵਾਪਸ 0;
}

/* Disable forwarding, etc for the session */
ਖਾਲੀ
auth_restrict_session(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	ਜੇ ((restricted = sshauthopt_new()) == ਨਿਰਾ)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	ਜੇ (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
