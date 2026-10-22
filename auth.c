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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/wait.h>

#അന്തര്ഭാവ <netinet/in.h>

#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#ifdef HAVE_LOGIN_H
#അന്തര്ഭാവ <login.h>
#endif
#ifdef USE_SHADOW
#അന്തര്ഭാവ <shadow.h>
#endif
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <time.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "groupaccess.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "uidswap.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "loginrec.h"
#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "monitor_wrap.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "channels.h"

/* import */
ബാഹ്യ ServerOptions options;
ബാഹ്യ ഘടന include_list includes;
ബാഹ്യ ഘടന sshbuf *loginmsg;
ബാഹ്യ ഘടന passwd *privsep_pw;
ബാഹ്യ ഘടന sshauthopt *auth_opts;

/* Debugging messages */
സ്ഥിതം ഘടന sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
പൂർണ്ണസംഖ്യ
allowed_user(ഘടന ssh *ssh, ഘടന passwd * pw)
{
	ഘടന stat st;
	സ്ഥിരം അക്ഷരം *hostname = ശൂന്യ, *ipaddr = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	എങ്കിൽ (!pw || !pw->pw_name)
		തിരികെ 0;

	എങ്കിൽ (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		തിരികെ 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	എങ്കിൽ (options.chroot_directory == ശൂന്യ ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		അക്ഷരം *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		എങ്കിൽ (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			സ്വതന്ത്രം(shell);
			തിരികെ 0;
		}
		എങ്കിൽ (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			സ്വതന്ത്രം(shell);
			തിരികെ 0;
		}
		സ്വതന്ത്രം(shell);
	}

	എങ്കിൽ (options.അക്കം_deny_users > 0 || options.അക്കം_allow_users > 0 ||
	    options.അക്കം_deny_groups > 0 || options.അക്കം_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	എങ്കിൽ (options.അക്കം_deny_users > 0) {
		വേണ്ടി (i = 0; i < options.അക്കം_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			എങ്കിൽ (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} അല്ലെങ്കിൽ എങ്കിൽ (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				തിരികെ 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	എങ്കിൽ (options.അക്കം_allow_users > 0) {
		വേണ്ടി (i = 0; i < options.അക്കം_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			എങ്കിൽ (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} അല്ലെങ്കിൽ എങ്കിൽ (r == 1)
				നിർത്തുക;
		}
		/* i < options.num_allow_users iff we break for loop */
		എങ്കിൽ (i >= options.അക്കം_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			തിരികെ 0;
		}
	}
	എങ്കിൽ (options.അക്കം_deny_groups > 0 || options.അക്കം_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		എങ്കിൽ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			തിരികെ 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		എങ്കിൽ (options.അക്കം_deny_groups > 0)
			എങ്കിൽ (ga_match(options.deny_groups,
			    options.അക്കം_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				തിരികെ 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		എങ്കിൽ (options.അക്കം_allow_groups > 0)
			എങ്കിൽ (!ga_match(options.allow_groups,
			    options.അക്കം_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				തിരികെ 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	എങ്കിൽ (!sys_auth_allowed_user(pw, loginmsg))
		തിരികെ 0;
#endif

	/* We found no reason not to let this user try to log on... */
	തിരികെ 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
സ്ഥിതം അക്ഷരം *
format_method_താക്കോൽ(Authctxt *authctxt)
{
	സ്ഥിരം ഘടന sshkey *താക്കോൽ = authctxt->auth_method_താക്കോൽ;
	സ്ഥിരം അക്ഷരം *methinfo = authctxt->auth_method_info;
	അക്ഷരം *fp, *cafp, *ret = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ)
		തിരികെ ശൂന്യ;

	എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
		fp = sshkey_fingerprint(താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(താക്കോൽ->cert->signature_താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(താക്കോൽ), fp == ശൂന്യ ? "(null)" : fp,
		    താക്കോൽ->cert->താക്കോൽ_id,
		    (unsigned long long)താക്കോൽ->cert->serial,
		    sshkey_type(താക്കോൽ->cert->signature_താക്കോൽ),
		    cafp == ശൂന്യ ? "(null)" : cafp,
		    methinfo == ശൂന്യ ? "" : ", ",
		    methinfo == ശൂന്യ ? "" : methinfo);
		സ്വതന്ത്രം(fp);
		സ്വതന്ത്രം(cafp);
	} അല്ലെങ്കിൽ {
		fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(താക്കോൽ),
		    fp == ശൂന്യ ? "(null)" : fp,
		    methinfo == ശൂന്യ ? "" : ", ",
		    methinfo == ശൂന്യ ? "" : methinfo);
		സ്വതന്ത്രം(fp);
	}
	തിരികെ ret;
}

ശൂന്യം
auth_log(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ authenticated, പൂർണ്ണസംഖ്യ partial,
    സ്ഥിരം അക്ഷരം *method, സ്ഥിരം അക്ഷരം *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	പൂർണ്ണസംഖ്യ level = SYSLOG_LEVEL_VERBOSE;
	സ്ഥിരം അക്ഷരം *authmsg;
	അക്ഷരം *extra = ശൂന്യ;

	എങ്കിൽ (!mm_is_monitor() && !authctxt->postponed)
		തിരികെ;

	/* Raise logging level */
	എങ്കിൽ (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	എങ്കിൽ (authctxt->postponed)
		authmsg = "Postponed";
	അല്ലെങ്കിൽ എങ്കിൽ (partial)
		authmsg = "Partial";
	അല്ലെങ്കിൽ
		authmsg = authenticated ? "Accepted" : "Failed";

	എങ്കിൽ ((extra = format_method_താക്കോൽ(authctxt)) == ശൂന്യ) {
		എങ്കിൽ (authctxt->auth_method_info != ശൂന്യ)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != ശൂന്യ ? "/" : "", submethod == ശൂന്യ ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != ശൂന്യ ? ": " : "",
	    extra != ശൂന്യ ? extra : "");

	സ്വതന്ത്രം(extra);

#എങ്കിൽ defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	എങ്കിൽ (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		എങ്കിൽ (strcmp(method, "password") == 0 ||
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
#എങ്കിൽ defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	എങ്കിൽ (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

ശൂന്യം
auth_maxtries_exceeded(ഘടന ssh *ssh)
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
പൂർണ്ണസംഖ്യ
auth_വേര്_allowed(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *method)
{
	തിരഞ്ഞെടുപ്പ് (options.permit_വേര്_login) {
	അവസ്ഥ PERMIT_YES:
		തിരികെ 1;
	അവസ്ഥ PERMIT_NO_PASSWD:
		എങ്കിൽ (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			തിരികെ 1;
		നിർത്തുക;
	അവസ്ഥ PERMIT_FORCED_ONLY:
		എങ്കിൽ (auth_opts->force_command != ശൂന്യ) {
			logit("Root login accepted for forced command.");
			തിരികെ 1;
		}
		നിർത്തുക;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	തിരികെ 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
അക്ഷരം *
expand_authorized_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *filename, ഘടന passwd *pw)
{
	അക്ഷരം *file, uidstr[32], ret[PATH_MAX];
	പൂർണ്ണസംഖ്യ i;

	snprintf(uidstr, വലുപ്പം(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (അക്ഷരം *)ശൂന്യ);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	എങ്കിൽ (path_absolute(file))
		തിരികെ (file);

	i = snprintf(ret, വലുപ്പം(ret), "%s/%s", pw->pw_dir, file);
	എങ്കിൽ (i < 0 || (size_t)i >= വലുപ്പം(ret))
		fatal("expand_authorized_keys: path too long");
	സ്വതന്ത്രം(file);
	തിരികെ (xstrdup(ret));
}

അക്ഷരം *
authorized_principals_file(ഘടന passwd *pw)
{
	എങ്കിൽ (options.authorized_principals_file == ശൂന്യ)
		തിരികെ ശൂന്യ;
	തിരികെ expand_authorized_താക്കോലുകൾ(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_താക്കോൽ_in_hostfiles(ഘടന passwd *pw, ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *sysfile, സ്ഥിരം അക്ഷരം *userfile)
{
	അക്ഷരം *user_hostfile;
	ഘടന stat st;
	HostStatus host_status;
	ഘടന hostkeys *hostkeys;
	സ്ഥിരം ഘടന hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	എങ്കിൽ (userfile != ശൂന്യ) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		എങ്കിൽ (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} അല്ലെങ്കിൽ {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		സ്വതന്ത്രം(user_hostfile);
	}
	host_status = check_താക്കോൽ_in_hostkeys(hostkeys, താക്കോൽ, &found);
	എങ്കിൽ (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	അല്ലെങ്കിൽ എങ്കിൽ (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->വരി);
	അല്ലെങ്കിൽ
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	തിരികെ host_status;
}

ഘടന passwd *
getpwnamallow(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *user)
{
#ifdef HAVE_LOGIN_CAP
	ബാഹ്യ login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	സ്ഥിരം അക്ഷരം *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	ഘടന passwd *pw;
	ഘടന connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ശൂന്യ;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	വേണ്ടി (i = 0; i < options.അക്കം_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#എങ്കിൽ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#എങ്കിൽ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	എങ്കിൽ (pw == ശൂന്യ) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		തിരികെ (ശൂന്യ);
	}
	എങ്കിൽ (!allowed_user(ssh, pw))
		തിരികെ (ശൂന്യ);
#ifdef HAVE_LOGIN_CAP
	എങ്കിൽ ((lc = login_getpwclass(pw)) == ശൂന്യ) {
		debug("unable to get login class: %s", user);
		തിരികെ (ശൂന്യ);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	എങ്കിൽ (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		തിരികെ (ശൂന്യ);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	എങ്കിൽ (!auth_timeok(lc, time(ശൂന്യ))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		തിരികെ (ശൂന്യ);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	എങ്കിൽ ((as = auth_open()) == ശൂന്യ || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ശൂന്യ;
	}
	എങ്കിൽ (as != ശൂന്യ)
		auth_close(as);
#endif
#endif
	എങ്കിൽ (pw != ശൂന്യ)
		തിരികെ (pwcopy(pw));
	തിരികെ (ശൂന്യ);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
പൂർണ്ണസംഖ്യ
auth_താക്കോൽ_is_revoked(ഘടന sshkey *താക്കോൽ)
{
	അക്ഷരം *fp = ശൂന്യ;
	u_int i;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (options.അക്കം_revoked_താക്കോലുകൾ_files == 0)
		തിരികെ 0;
	എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		പോകുക out;
	}

	വേണ്ടി (i = 0; i < options.അക്കം_revoked_താക്കോലുകൾ_files; i++) {
		r = sshkey_check_revoked(താക്കോൽ, options.revoked_താക്കോലുകൾ_files[i]);
		തിരഞ്ഞെടുപ്പ് (r) {
		അവസ്ഥ 0:
			നിർത്തുക; /* not revoked */
		അവസ്ഥ SSH_ERR_താക്കോൽ_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(താക്കോൽ), fp,
			    options.revoked_താക്കോലുകൾ_files[i]);
			പോകുക out;
		സ്ഥിരസ്ഥിതി:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(താക്കോൽ), fp,
			    options.revoked_താക്കോലുകൾ_files[i]);
			പോകുക out;
		}
	}

	/* Success */
	r = 0;

 out:
	സ്വതന്ത്രം(fp);
	തിരികെ r == 0 ? 0 : 1;
}

ശൂന്യം
auth_debug_add(സ്ഥിരം അക്ഷരം *fmt,...)
{
	അക്ഷരം buf[1024];
	va_list args;
	പൂർണ്ണസംഖ്യ r;

	va_start(args, fmt);
	vsnprintf(buf, വലുപ്പം(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	എങ്കിൽ (auth_debug != ശൂന്യ)
		എങ്കിൽ ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

ശൂന്യം
auth_debug_send(ഘടന ssh *ssh)
{
	അക്ഷരം *സന്ദേശം;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (auth_debug == ശൂന്യ)
		തിരികെ;
	ആകുമ്പോൾ (sshbuf_len(auth_debug) != 0) {
		എങ്കിൽ ((r = sshbuf_get_cstring(auth_debug, &സന്ദേശം, ശൂന്യ)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", സന്ദേശം);
		സ്വതന്ത്രം(സന്ദേശം);
	}
}

ശൂന്യം
auth_debug_reset(ശൂന്യം)
{
	എങ്കിൽ (auth_debug != ശൂന്യ)
		sshbuf_reset(auth_debug);
	അല്ലെങ്കിൽ എങ്കിൽ ((auth_debug = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
}

ഘടന passwd *
fakepw(ശൂന്യം)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ done = 0;
	സ്ഥിതം ഘടന passwd fake;
	സ്ഥിരം അക്ഷരം hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	അക്ഷരം *cp;

	എങ്കിൽ (done)
		തിരികെ (&fake);

	memset(&fake, 0, വലുപ്പം(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	വേണ്ടി (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(വലുപ്പം(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == ശൂന്യ ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ശൂന്യ ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	തിരികെ (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

സ്ഥിരം അക്ഷരം *
auth_get_canonical_hostname(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ use_dns)
{
	സ്ഥിതം അക്ഷരം *dnsname;

	എങ്കിൽ (!use_dns)
		തിരികെ ssh_remote_ipaddr(ssh);
	എങ്കിൽ (dnsname != ശൂന്യ)
		തിരികെ dnsname;
	dnsname = ssh_remote_hostname(ssh);
	തിരികെ dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
ശൂന്യം
auth_log_authopts(സ്ഥിരം അക്ഷരം *loc, സ്ഥിരം ഘടന sshauthopt *opts, പൂർണ്ണസംഖ്യ do_remote)
{
	പൂർണ്ണസംഖ്യ do_env = options.permit_user_env && opts->nenv > 0;
	പൂർണ്ണസംഖ്യ do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	പൂർണ്ണസംഖ്യ do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	അക്ഷരം സന്ദേശം[1024], buf[64];

	snprintf(buf, വലുപ്പം(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(സന്ദേശം, വലുപ്പം(സന്ദേശം), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ശൂന്യ ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ശൂന്യ ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, സന്ദേശം);
	എങ്കിൽ (do_remote)
		auth_debug_add("%s: %s", loc, സന്ദേശം);

	എങ്കിൽ (options.permit_user_env) {
		വേണ്ടി (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			എങ്കിൽ (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	എങ്കിൽ (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, വലുപ്പം(buf));
		debug("%s: expires at %s", loc, buf);
	}
	എങ്കിൽ (opts->cert_principals != ശൂന്യ) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	എങ്കിൽ (opts->force_command != ശൂന്യ)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	എങ്കിൽ (do_permitopen) {
		വേണ്ടി (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	എങ്കിൽ (do_permitlisten) {
		വേണ്ടി (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
പൂർണ്ണസംഖ്യ
auth_activate_options(ഘടന ssh *ssh, ഘടന sshauthopt *opts)
{
	ഘടന sshauthopt *old = auth_opts;
	സ്ഥിരം അക്ഷരം *emsg = ശൂന്യ;

	debug_f("setting new authentication options");
	എങ്കിൽ ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == ശൂന്യ) {
		error("Inconsistent authentication options: %s", emsg);
		തിരികെ -1;
	}
	sshauthopt_free(old);
	തിരികെ 0;
}

/* Disable forwarding, etc for the session */
ശൂന്യം
auth_restrict_session(ഘടന ssh *ssh)
{
	ഘടന sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	എങ്കിൽ ((restricted = sshauthopt_new()) == ശൂന്യ)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	എങ്കിൽ (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
