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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/wait.h>

#அந்தர்பாவ <netinet/in.h>

#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#ifdef HAVE_LOGIN_H
#அந்தர்பாவ <login.h>
#endif
#ifdef USE_SHADOW
#அந்தர்பாவ <shadow.h>
#endif
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <time.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "groupaccess.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "canohost.h"
#அந்தர்பாவ "uidswap.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "loginrec.h"
#ifdef GSSAPI
#அந்தர்பாவ "ssh-gss.h"
#endif
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "monitor_wrap.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "channels.h"

/* import */
வெளி ServerOptions options;
வெளி கட்டமைப்பு include_list includes;
வெளி கட்டமைப்பு sshbuf *loginmsg;
வெளி கட்டமைப்பு passwd *privsep_pw;
வெளி கட்டமைப்பு sshauthopt *auth_opts;

/* Debugging messages */
நிலையான கட்டமைப்பு sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
முழு
allowed_user(கட்டமைப்பு ssh *ssh, கட்டமைப்பு passwd * pw)
{
	கட்டமைப்பு stat st;
	மாறிலி எழுத்து *hostname = வெற்று, *ipaddr = வெற்று;
	முழு r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	எனில் (!pw || !pw->pw_name)
		திரும்பு 0;

	எனில் (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		திரும்பு 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	எனில் (options.chroot_directory == வெற்று ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		எழுத்து *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		எனில் (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			விடுவி(shell);
			திரும்பு 0;
		}
		எனில் (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			விடுவி(shell);
			திரும்பு 0;
		}
		விடுவி(shell);
	}

	எனில் (options.இலக்கம்_deny_users > 0 || options.இலக்கம்_allow_users > 0 ||
	    options.இலக்கம்_deny_groups > 0 || options.இலக்கம்_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	எனில் (options.இலக்கம்_deny_users > 0) {
		க்கு (i = 0; i < options.இலக்கம்_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			எனில் (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} இல்லையெனில் எனில் (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				திரும்பு 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	எனில் (options.இலக்கம்_allow_users > 0) {
		க்கு (i = 0; i < options.இலக்கம்_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			எனில் (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} இல்லையெனில் எனில் (r == 1)
				நிறுத்து;
		}
		/* i < options.num_allow_users iff we break for loop */
		எனில் (i >= options.இலக்கம்_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			திரும்பு 0;
		}
	}
	எனில் (options.இலக்கம்_deny_groups > 0 || options.இலக்கம்_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		எனில் (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			திரும்பு 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		எனில் (options.இலக்கம்_deny_groups > 0)
			எனில் (ga_match(options.deny_groups,
			    options.இலக்கம்_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				திரும்பு 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		எனில் (options.இலக்கம்_allow_groups > 0)
			எனில் (!ga_match(options.allow_groups,
			    options.இலக்கம்_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				திரும்பு 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	எனில் (!sys_auth_allowed_user(pw, loginmsg))
		திரும்பு 0;
#endif

	/* We found no reason not to let this user try to log on... */
	திரும்பு 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
நிலையான எழுத்து *
format_method_சாவி(Authctxt *authctxt)
{
	மாறிலி கட்டமைப்பு sshkey *சாவி = authctxt->auth_method_சாவி;
	மாறிலி எழுத்து *methinfo = authctxt->auth_method_info;
	எழுத்து *fp, *cafp, *ret = வெற்று;

	எனில் (சாவி == வெற்று)
		திரும்பு வெற்று;

	எனில் (sshkey_is_cert(சாவி)) {
		fp = sshkey_fingerprint(சாவி,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(சாவி->cert->signature_சாவி,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(சாவி), fp == வெற்று ? "(null)" : fp,
		    சாவி->cert->சாவி_id,
		    (unsigned long long)சாவி->cert->serial,
		    sshkey_type(சாவி->cert->signature_சாவி),
		    cafp == வெற்று ? "(null)" : cafp,
		    methinfo == வெற்று ? "" : ", ",
		    methinfo == வெற்று ? "" : methinfo);
		விடுவி(fp);
		விடுவி(cafp);
	} இல்லையெனில் {
		fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(சாவி),
		    fp == வெற்று ? "(null)" : fp,
		    methinfo == வெற்று ? "" : ", ",
		    methinfo == வெற்று ? "" : methinfo);
		விடுவி(fp);
	}
	திரும்பு ret;
}

வெறுமை
auth_log(கட்டமைப்பு ssh *ssh, முழு authenticated, முழு partial,
    மாறிலி எழுத்து *method, மாறிலி எழுத்து *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	முழு level = SYSLOG_LEVEL_VERBOSE;
	மாறிலி எழுத்து *authmsg;
	எழுத்து *extra = வெற்று;

	எனில் (!mm_is_monitor() && !authctxt->postponed)
		திரும்பு;

	/* Raise logging level */
	எனில் (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	எனில் (authctxt->postponed)
		authmsg = "Postponed";
	இல்லையெனில் எனில் (partial)
		authmsg = "Partial";
	இல்லையெனில்
		authmsg = authenticated ? "Accepted" : "Failed";

	எனில் ((extra = format_method_சாவி(authctxt)) == வெற்று) {
		எனில் (authctxt->auth_method_info != வெற்று)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != வெற்று ? "/" : "", submethod == வெற்று ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != வெற்று ? ": " : "",
	    extra != வெற்று ? extra : "");

	விடுவி(extra);

#எனில் defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	எனில் (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		எனில் (strcmp(method, "password") == 0 ||
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
#எனில் defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	எனில் (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

வெறுமை
auth_maxtries_exceeded(கட்டமைப்பு ssh *ssh)
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
முழு
auth_வேர்_allowed(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *method)
{
	தேர்வு (options.permit_வேர்_login) {
	நிலை PERMIT_YES:
		திரும்பு 1;
	நிலை PERMIT_NO_PASSWD:
		எனில் (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			திரும்பு 1;
		நிறுத்து;
	நிலை PERMIT_FORCED_ONLY:
		எனில் (auth_opts->force_command != வெற்று) {
			logit("Root login accepted for forced command.");
			திரும்பு 1;
		}
		நிறுத்து;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	திரும்பு 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
எழுத்து *
expand_authorized_சாவிகள்(மாறிலி எழுத்து *filename, கட்டமைப்பு passwd *pw)
{
	எழுத்து *file, uidstr[32], ret[PATH_MAX];
	முழு i;

	snprintf(uidstr, அளவு(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (எழுத்து *)வெற்று);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	எனில் (path_absolute(file))
		திரும்பு (file);

	i = snprintf(ret, அளவு(ret), "%s/%s", pw->pw_dir, file);
	எனில் (i < 0 || (size_t)i >= அளவு(ret))
		fatal("expand_authorized_keys: path too long");
	விடுவி(file);
	திரும்பு (xstrdup(ret));
}

எழுத்து *
authorized_principals_file(கட்டமைப்பு passwd *pw)
{
	எனில் (options.authorized_principals_file == வெற்று)
		திரும்பு வெற்று;
	திரும்பு expand_authorized_சாவிகள்(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_சாவி_in_hostfiles(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *host,
    மாறிலி எழுத்து *sysfile, மாறிலி எழுத்து *userfile)
{
	எழுத்து *user_hostfile;
	கட்டமைப்பு stat st;
	HostStatus host_status;
	கட்டமைப்பு hostkeys *hostkeys;
	மாறிலி கட்டமைப்பு hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	எனில் (userfile != வெற்று) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		எனில் (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} இல்லையெனில் {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		விடுவி(user_hostfile);
	}
	host_status = check_சாவி_in_hostkeys(hostkeys, சாவி, &found);
	எனில் (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	இல்லையெனில் எனில் (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->வரி);
	இல்லையெனில்
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	திரும்பு host_status;
}

கட்டமைப்பு passwd *
getpwnamallow(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *user)
{
#ifdef HAVE_LOGIN_CAP
	வெளி login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	மாறிலி எழுத்து *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	கட்டமைப்பு passwd *pw;
	கட்டமைப்பு connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == வெற்று;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	க்கு (i = 0; i < options.இலக்கம்_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#எனில் defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#எனில் defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	எனில் (pw == வெற்று) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		திரும்பு (வெற்று);
	}
	எனில் (!allowed_user(ssh, pw))
		திரும்பு (வெற்று);
#ifdef HAVE_LOGIN_CAP
	எனில் ((lc = login_getpwclass(pw)) == வெற்று) {
		debug("unable to get login class: %s", user);
		திரும்பு (வெற்று);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	எனில் (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		திரும்பு (வெற்று);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	எனில் (!auth_timeok(lc, time(வெற்று))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		திரும்பு (வெற்று);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	எனில் ((as = auth_open()) == வெற்று || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = வெற்று;
	}
	எனில் (as != வெற்று)
		auth_close(as);
#endif
#endif
	எனில் (pw != வெற்று)
		திரும்பு (pwcopy(pw));
	திரும்பு (வெற்று);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
முழு
auth_சாவி_is_revoked(கட்டமைப்பு sshkey *சாவி)
{
	எழுத்து *fp = வெற்று;
	u_int i;
	முழு r;

	எனில் (options.இலக்கம்_revoked_சாவிகள்_files == 0)
		திரும்பு 0;
	எனில் ((fp = sshkey_fingerprint(சாவி, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		செல் out;
	}

	க்கு (i = 0; i < options.இலக்கம்_revoked_சாவிகள்_files; i++) {
		r = sshkey_check_revoked(சாவி, options.revoked_சாவிகள்_files[i]);
		தேர்வு (r) {
		நிலை 0:
			நிறுத்து; /* not revoked */
		நிலை SSH_ERR_சாவி_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(சாவி), fp,
			    options.revoked_சாவிகள்_files[i]);
			செல் out;
		இயல்பு:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(சாவி), fp,
			    options.revoked_சாவிகள்_files[i]);
			செல் out;
		}
	}

	/* Success */
	r = 0;

 out:
	விடுவி(fp);
	திரும்பு r == 0 ? 0 : 1;
}

வெறுமை
auth_debug_add(மாறிலி எழுத்து *fmt,...)
{
	எழுத்து buf[1024];
	va_list args;
	முழு r;

	va_start(args, fmt);
	vsnprintf(buf, அளவு(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	எனில் (auth_debug != வெற்று)
		எனில் ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

வெறுமை
auth_debug_send(கட்டமைப்பு ssh *ssh)
{
	எழுத்து *செய்தி;
	முழு r;

	எனில் (auth_debug == வெற்று)
		திரும்பு;
	போது (sshbuf_len(auth_debug) != 0) {
		எனில் ((r = sshbuf_get_cstring(auth_debug, &செய்தி, வெற்று)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", செய்தி);
		விடுவி(செய்தி);
	}
}

வெறுமை
auth_debug_reset(வெறுமை)
{
	எனில் (auth_debug != வெற்று)
		sshbuf_reset(auth_debug);
	இல்லையெனில் எனில் ((auth_debug = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
}

கட்டமைப்பு passwd *
fakepw(வெறுமை)
{
	நிலையான முழு done = 0;
	நிலையான கட்டமைப்பு passwd fake;
	மாறிலி எழுத்து hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	எழுத்து *cp;

	எனில் (done)
		திரும்பு (&fake);

	memset(&fake, 0, அளவு(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	க்கு (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(அளவு(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == வெற்று ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == வெற்று ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	திரும்பு (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

மாறிலி எழுத்து *
auth_get_canonical_hostname(கட்டமைப்பு ssh *ssh, முழு use_dns)
{
	நிலையான எழுத்து *dnsname;

	எனில் (!use_dns)
		திரும்பு ssh_remote_ipaddr(ssh);
	எனில் (dnsname != வெற்று)
		திரும்பு dnsname;
	dnsname = ssh_remote_hostname(ssh);
	திரும்பு dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
வெறுமை
auth_log_authopts(மாறிலி எழுத்து *loc, மாறிலி கட்டமைப்பு sshauthopt *opts, முழு do_remote)
{
	முழு do_env = options.permit_user_env && opts->nenv > 0;
	முழு do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	முழு do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	எழுத்து செய்தி[1024], buf[64];

	snprintf(buf, அளவு(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(செய்தி, அளவு(செய்தி), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == வெற்று ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == வெற்று ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, செய்தி);
	எனில் (do_remote)
		auth_debug_add("%s: %s", loc, செய்தி);

	எனில் (options.permit_user_env) {
		க்கு (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			எனில் (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	எனில் (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, அளவு(buf));
		debug("%s: expires at %s", loc, buf);
	}
	எனில் (opts->cert_principals != வெற்று) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	எனில் (opts->force_command != வெற்று)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	எனில் (do_permitopen) {
		க்கு (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	எனில் (do_permitlisten) {
		க்கு (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
முழு
auth_activate_options(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshauthopt *opts)
{
	கட்டமைப்பு sshauthopt *old = auth_opts;
	மாறிலி எழுத்து *emsg = வெற்று;

	debug_f("setting new authentication options");
	எனில் ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == வெற்று) {
		error("Inconsistent authentication options: %s", emsg);
		திரும்பு -1;
	}
	sshauthopt_free(old);
	திரும்பு 0;
}

/* Disable forwarding, etc for the session */
வெறுமை
auth_restrict_session(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	எனில் ((restricted = sshauthopt_new()) == வெற்று)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	எனில் (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
