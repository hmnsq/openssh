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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <netinet/in.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_H
#ಅನ್ತರ್ಭಾವ <login.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SHADOW
#ಅನ್ತರ್ಭಾವ <shadow.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "groupaccess.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "loginrec.h"
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "channels.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ರಚನೆ include_list includes;
ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;
ಬಾಹ್ಯ ರಚನೆ passwd *privsep_pw;
ಬಾಹ್ಯ ರಚನೆ sshauthopt *auth_opts;

/* Debugging messages */
ಸ್ಥಿರ ರಚನೆ sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
ಪೂರ್ಣಾಂಕ
allowed_user(ರಚನೆ ssh *ssh, ರಚನೆ passwd * pw)
{
	ರಚನೆ stat st;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname = ಖಾಲಿ, *ipaddr = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	ಆದರೆ (!pw || !pw->pw_name)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		ಹಿಂತಿರುಗಿ 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	ಆದರೆ (options.chroot_directory == ಖಾಲಿ ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		ಅಕ್ಷರ *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		ಆದರೆ (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			ಬಿಡುಗಡೆ(shell);
			ಹಿಂತಿರುಗಿ 0;
		}
		ಆದರೆ (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			ಬಿಡುಗಡೆ(shell);
			ಹಿಂತಿರುಗಿ 0;
		}
		ಬಿಡುಗಡೆ(shell);
	}

	ಆದರೆ (options.ಅಂಕೆ_deny_users > 0 || options.ಅಂಕೆ_allow_users > 0 ||
	    options.ಅಂಕೆ_deny_groups > 0 || options.ಅಂಕೆ_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	ಆದರೆ (options.ಅಂಕೆ_deny_users > 0) {
		ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_deny_users; i++) {
			r = ಹೊಂದಿಕೆ_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			ಆದರೆ (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				ಹಿಂತಿರುಗಿ 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	ಆದರೆ (options.ಅಂಕೆ_allow_users > 0) {
		ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_allow_users; i++) {
			r = ಹೊಂದಿಕೆ_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			ಆದರೆ (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 1)
				ನಿಲ್ಲಿಸು;
		}
		/* i < options.num_allow_users iff we break for loop */
		ಆದರೆ (i >= options.ಅಂಕೆ_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	ಆದರೆ (options.ಅಂಕೆ_deny_groups > 0 || options.ಅಂಕೆ_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		ಆದರೆ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			ಹಿಂತಿರುಗಿ 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		ಆದರೆ (options.ಅಂಕೆ_deny_groups > 0)
			ಆದರೆ (ga_ಹೊಂದಿಕೆ(options.deny_groups,
			    options.ಅಂಕೆ_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				ಹಿಂತಿರುಗಿ 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		ಆದರೆ (options.ಅಂಕೆ_allow_groups > 0)
			ಆದರೆ (!ga_ಹೊಂದಿಕೆ(options.allow_groups,
			    options.ಅಂಕೆ_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				ಹಿಂತಿರುಗಿ 0;
			}
		ga_free();
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CUSTOM_SYS_AUTH_ALLOWED_USER
	ಆದರೆ (!sys_auth_allowed_user(pw, loginmsg))
		ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ

	/* We found no reason not to let this user try to log on... */
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
format_ವಿಧಾನ_ಕೀಲಿ(Authctxt *authctxt)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ = authctxt->auth_ವಿಧಾನ_ಕೀಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *methinfo = authctxt->auth_ವಿಧಾನ_info;
	ಅಕ್ಷರ *fp, *cafp, *ret = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;

	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
		fp = sshkey_fingerprint(ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(ಕೀಲಿ), fp == ಖಾಲಿ ? "(null)" : fp,
		    ಕೀಲಿ->cert->ಕೀಲಿ_id,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
		    sshkey_type(ಕೀಲಿ->cert->signature_ಕೀಲಿ),
		    cafp == ಖಾಲಿ ? "(null)" : cafp,
		    methinfo == ಖಾಲಿ ? "" : ", ",
		    methinfo == ಖಾಲಿ ? "" : methinfo);
		ಬಿಡುಗಡೆ(fp);
		ಬಿಡುಗಡೆ(cafp);
	} ಇಲ್ಲದಿದ್ದರೆ {
		fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(ಕೀಲಿ),
		    fp == ಖಾಲಿ ? "(null)" : fp,
		    methinfo == ಖಾಲಿ ? "" : ", ",
		    methinfo == ಖಾಲಿ ? "" : methinfo);
		ಬಿಡುಗಡೆ(fp);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
auth_log(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ authenticated, ಪೂರ್ಣಾಂಕ partial,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಪೂರ್ಣಾಂಕ level = SYSLOG_LEVEL_VERBOSE;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *authmsg;
	ಅಕ್ಷರ *extra = ಖಾಲಿ;

	ಆದರೆ (!mm_is_monitor() && !authctxt->postponed)
		ಹಿಂತಿರುಗಿ;

	/* Raise logging level */
	ಆದರೆ (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(ವಿಧಾನ, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	ಆದರೆ (authctxt->postponed)
		authmsg = "Postponed";
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (partial)
		authmsg = "Partial";
	ಇಲ್ಲದಿದ್ದರೆ
		authmsg = authenticated ? "Accepted" : "Failed";

	ಆದರೆ ((extra = format_ವಿಧಾನ_ಕೀಲಿ(authctxt)) == ಖಾಲಿ) {
		ಆದರೆ (authctxt->auth_ವಿಧಾನ_info != ಖಾಲಿ)
			extra = xstrdup(authctxt->auth_ವಿಧಾನ_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    ವಿಧಾನ,
	    submethod != ಖಾಲಿ ? "/" : "", submethod == ಖಾಲಿ ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ಪೋರ್ಟ್(ssh),
	    extra != ಖಾಲಿ ? ": " : "",
	    extra != ಖಾಲಿ ? extra : "");

	ಬಿಡುಗಡೆ(extra);

#ಆದರೆ defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	ಆದರೆ (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		ಆದರೆ (strcmp(ವಿಧಾನ, "password") == 0 ||
		    ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(ವಿಧಾನ, "keyboard-interactive", 20) == 0 ||
		    strcmp(ವಿಧಾನ, "challenge-response") == 0)
			ದಾಖಲೆ_failed_login(ssh, authctxt->user,
			    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
# endif
# ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, audit_classify_auth(ವಿಧಾನ));
# endif
	}
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	ಆದರೆ (authenticated)
		sys_auth_ದಾಖಲೆ_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#ಆದರೆ_ಅಂತ್ಯ
}

ಶೂನ್ಯ
auth_maxtries_exceeded(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	error("maximum authentication attempts exceeded for "
	    "%s%.100s from %.200s port %d ssh2",
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_ಪೋರ್ಟ್(ssh));
	ssh_packet_disconnect(ssh, "Too many authentication failures");
	/* NOTREACHED */
}

/*
 * Check whether root logins are disallowed.
 */
ಪೂರ್ಣಾಂಕ
auth_ಬೇರು_allowed(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ವಿಧಾನ)
{
	ಆಯ್ಕೆ (options.permit_ಬೇರು_login) {
	ಸ್ಥಿತಿ PERMIT_YES:
		ಹಿಂತಿರುಗಿ 1;
	ಸ್ಥಿತಿ PERMIT_NO_PASSWD:
		ಆದರೆ (strcmp(ವಿಧಾನ, "publickey") == 0 ||
		    strcmp(ವಿಧಾನ, "hostbased") == 0 ||
		    strcmp(ವಿಧಾನ, "gssapi-with-mic") == 0)
			ಹಿಂತಿರುಗಿ 1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ PERMIT_FORCED_ONLY:
		ಆದರೆ (auth_opts->force_command != ಖಾಲಿ) {
			logit("Root login accepted for forced command.");
			ಹಿಂತಿರುಗಿ 1;
		}
		ನಿಲ್ಲಿಸು;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
	ಹಿಂತಿರುಗಿ 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
ಅಕ್ಷರ *
expand_authorized_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ passwd *pw)
{
	ಅಕ್ಷರ *file, uidstr[32], ret[PATH_MAX];
	ಪೂರ್ಣಾಂಕ i;

	snprintf(uidstr, ಗಾತ್ರ(uidstr), "%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (ಅಕ್ಷರ *)ಖಾಲಿ);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	ಆದರೆ (ಮಾರ್ಗ_absolute(file))
		ಹಿಂತಿರುಗಿ (file);

	i = snprintf(ret, ಗಾತ್ರ(ret), "%s/%s", pw->pw_dir, file);
	ಆದರೆ (i < 0 || (ಗಾತ್ರ_t)i >= ಗಾತ್ರ(ret))
		fatal("expand_authorized_keys: path too long");
	ಬಿಡುಗಡೆ(file);
	ಹಿಂತಿರುಗಿ (xstrdup(ret));
}

ಅಕ್ಷರ *
authorized_principals_file(ರಚನೆ passwd *pw)
{
	ಆದರೆ (options.authorized_principals_file == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ expand_authorized_ಕೀಲಿಗಳು(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
Host_ಸ್ಥಿತಿ
check_ಕೀಲಿ_ಒಳ_hostfiles(ರಚನೆ passwd *pw, ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sysfile, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *userfile)
{
	ಅಕ್ಷರ *user_hostfile;
	ರಚನೆ stat st;
	Host_ಸ್ಥಿತಿ host_ಸ್ಥಿತಿ;
	ರಚನೆ hostkeys *hostkeys;
	ಸ್ಥಿರಾಂಕ ರಚನೆ hostkey_ನಮೂದು *ಸಿಕ್ಕಿತು;

	hostkeys = init_hostkeys();
	ತುಂಬು_hostkeys(hostkeys, host, sysfile, 0);
	ಆದರೆ (userfile != ಖಾಲಿ) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		ಆದರೆ (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_ಕೂಡಿಸು("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} ಇಲ್ಲದಿದ್ದರೆ {
			temporarily_use_uid(pw);
			ತುಂಬು_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		ಬಿಡುಗಡೆ(user_hostfile);
	}
	host_ಸ್ಥಿತಿ = check_ಕೀಲಿ_ಒಳ_hostkeys(hostkeys, ಕೀಲಿ, &ಸಿಕ್ಕಿತು);
	ಆದರೆ (host_ಸ್ಥಿತಿ == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (host_ಸ್ಥಿತಿ == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    ಸಿಕ್ಕಿತು->host, ಸಿಕ್ಕಿತು->file, ಸಿಕ್ಕಿತು->ಸಾಲು);
	ಇಲ್ಲದಿದ್ದರೆ
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	ಹಿಂತಿರುಗಿ host_ಸ್ಥಿತಿ;
}

ರಚನೆ passwd *
getpwnamallow(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	ಬಾಹ್ಯ login_cap_t *lc;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_AUTH_HOSTOK
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *from_host, *from_ip;
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
	auth_session_t *as;
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ
	ರಚನೆ passwd *pw;
	ರಚನೆ connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ಖಾಲಿ;
	parse_server_ಹೊಂದಿಕೆ_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_log_verbose; i++)
		log_verbose_ಕೂಡಿಸು(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_ಗಣ_rekey_limits(ssh, options.rekey_ಎಲ್ಲೆ,
	    options.rekey_interval);

#ಆದರೆ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#ಆದರೆ_ಅಂತ್ಯ

	pw = getpwnam(user);

#ಆದರೆ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (pw == ಖಾಲಿ) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh));
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ CUSTOM_FAILED_LOGIN
		ದಾಖಲೆ_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#ಆದರೆ_ಅಂತ್ಯ /* SSH_AUDIT_EVENTS */
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	ಆದರೆ (!allowed_user(ssh, pw))
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	ಆದರೆ ((lc = login_getpwclass(pw)) == ಖಾಲಿ) {
		debug("unable to get login class: %s", user);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	ಆದರೆ (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_AUTH_HOSTOK */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_AUTH_TIMEOK
	ಆದರೆ (!auth_timeok(lc, time(ಖಾಲಿ))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_AUTH_TIMEOK */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
	ಆದರೆ ((as = auth_open()) == ಖಾಲಿ || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ಖಾಲಿ;
	}
	ಆದರೆ (as != ಖಾಲಿ)
		auth_close(as);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (pw != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (pwcopy(pw));
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
ಪೂರ್ಣಾಂಕ
auth_ಕೀಲಿ_is_revoked(ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಅಕ್ಷರ *fp = ಖಾಲಿ;
	u_int i;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (options.ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_revoked_ಕೀಲಿಗಳು_files; i++) {
		r = sshkey_check_revoked(ಕೀಲಿ, options.revoked_ಕೀಲಿಗಳು_files[i]);
		ಆಯ್ಕೆ (r) {
		ಸ್ಥಿತಿ 0:
			ನಿಲ್ಲಿಸು; /* not revoked */
		ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(ಕೀಲಿ), fp,
			    options.revoked_ಕೀಲಿಗಳು_files[i]);
			ಹೋಗು ಹೊರಹೋಗು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(ಕೀಲಿ), fp,
			    options.revoked_ಕೀಲಿಗಳು_files[i]);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Success */
	r = 0;

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(fp);
	ಹಿಂತಿರುಗಿ r == 0 ? 0 : 1;
}

ಶೂನ್ಯ
auth_debug_ಕೂಡಿಸು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt,...)
{
	ಅಕ್ಷರ buf[1024];
	va_list ವಾದಗಳು;
	ಪೂರ್ಣಾಂಕ r;

	va_start(ವಾದಗಳು, fmt);
	vsnprintf(buf, ಗಾತ್ರ(buf), fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);
	debug3("%s", buf);
	ಆದರೆ (auth_debug != ಖಾಲಿ)
		ಆದರೆ ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

ಶೂನ್ಯ
auth_debug_send(ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *ಸಂದೇಶ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (auth_debug == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆಗ (sshbuf_len(auth_debug) != 0) {
		ಆದರೆ ((r = sshbuf_get_cstring(auth_debug, &ಸಂದೇಶ, ಖಾಲಿ)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", ಸಂದೇಶ);
		ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	}
}

ಶೂನ್ಯ
auth_debug_reset(ಶೂನ್ಯ)
{
	ಆದರೆ (auth_debug != ಖಾಲಿ)
		sshbuf_reset(auth_debug);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((auth_debug = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
}

ರಚನೆ passwd *
fakepw(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಮುಗಿದ = 0;
	ಸ್ಥಿರ ರಚನೆ passwd fake;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	ಅಕ್ಷರ *cp;

	ಆದರೆ (ಮುಗಿದ)
		ಹಿಂತಿರುಗಿ (&fake);

	memset(&fake, 0, ಗಾತ್ರ(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	ಗಾಗಿ (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_ಏಕರೂಪ(ಗಾತ್ರ(hashchars) - 1)];
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#ಆದರೆ_ಅಂತ್ಯ
	fake.pw_uid = privsep_pw == ಖಾಲಿ ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ಖಾಲಿ ? (gid_t)-1 : privsep_pw->pw_gid;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#ಆದರೆ_ಅಂತ್ಯ
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	ಮುಗಿದ = 1;

	ಹಿಂತಿರುಗಿ (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
auth_get_canonical_hostname(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ use_dns)
{
	ಸ್ಥಿರ ಅಕ್ಷರ *dnsname;

	ಆದರೆ (!use_dns)
		ಹಿಂತಿರುಗಿ ssh_remote_ipaddr(ssh);
	ಆದರೆ (dnsname != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ dnsname;
	dnsname = ssh_remote_hostname(ssh);
	ಹಿಂತಿರುಗಿ dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
ಶೂನ್ಯ
auth_log_authopts(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *loc, ಸ್ಥಿರಾಂಕ ರಚನೆ sshauthopt *opts, ಪೂರ್ಣಾಂಕ do_remote)
{
	ಪೂರ್ಣಾಂಕ do_env = options.permit_user_env && opts->nenv > 0;
	ಪೂರ್ಣಾಂಕ do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	ಪೂರ್ಣಾಂಕ do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	ಗಾತ್ರ_t i;
	ಅಕ್ಷರ ಸಂದೇಶ[1024], buf[64];

	snprintf(buf, ಗಾತ್ರ(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(ಸಂದೇಶ, ಗಾತ್ರ(ಸಂದೇಶ), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ಖಾಲಿ ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_ಪೋರ್ಟ್_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ಖಾಲಿ ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, ಸಂದೇಶ);
	ಆದರೆ (do_remote)
		auth_debug_ಕೂಡಿಸು("%s: %s", loc, ಸಂದೇಶ);

	ಆದರೆ (options.permit_user_env) {
		ಗಾಗಿ (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			ಆದರೆ (do_remote) {
				auth_debug_ಕೂಡಿಸು("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	ಆದರೆ (opts->valid_before != 0) {
		format_absolute_ಸಮಯ(opts->valid_before, buf, ಗಾತ್ರ(buf));
		debug("%s: expires at %s", loc, buf);
	}
	ಆದರೆ (opts->cert_principals != ಖಾಲಿ) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	ಆದರೆ (opts->force_command != ಖಾಲಿ)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	ಆದರೆ (do_permitopen) {
		ಗಾಗಿ (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	ಆದರೆ (do_permitlisten) {
		ಗಾಗಿ (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
ಪೂರ್ಣಾಂಕ
auth_activate_options(ರಚನೆ ssh *ssh, ರಚನೆ sshauthopt *opts)
{
	ರಚನೆ sshauthopt *old = auth_opts;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *emsg = ಖಾಲಿ;

	debug_f("setting new authentication options");
	ಆದರೆ ((auth_opts = sshauthopt_ವಿಲೀನ(old, opts, &emsg)) == ಖಾಲಿ) {
		error("Inconsistent authentication options: %s", emsg);
		ಹಿಂತಿರುಗಿ -1;
	}
	sshauthopt_free(old);
	ಹಿಂತಿರುಗಿ 0;
}

/* Disable forwarding, etc for the session */
ಶೂನ್ಯ
auth_restrict_session(ರಚನೆ ssh *ssh)
{
	ರಚನೆ sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	ಆದರೆ ((restricted = sshauthopt_new()) == ಖಾಲಿ)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	ಆದರೆ (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
