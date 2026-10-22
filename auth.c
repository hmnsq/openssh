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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/wait.h>

#અન્તર્ભાવ <netinet/in.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <pwd.h>
#ifdef HAVE_LOGIN_H
#અન્તર્ભાવ <login.h>
#endif
#ifdef USE_SHADOW
#અન્તર્ભાવ <shadow.h>
#endif
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <netdb.h>
#અન્તર્ભાવ <time.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "groupaccess.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "uidswap.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "loginrec.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "channels.h"

/* import */
બાહ્ય ServerOptions options;
બાહ્ય સંરચના include_list includes;
બાહ્ય સંરચના sshbuf *loginmsg;
બાહ્ય સંરચના passwd *privsep_pw;
બાહ્ય સંરચના sshauthopt *auth_opts;

/* Debugging messages */
સ્થિર સંરચના sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
પૂર્ણાંક
allowed_user(સંરચના ssh *ssh, સંરચના passwd * pw)
{
	સંરચના stat st;
	અચલ અક્ષર *hostname = ખાલી, *ipaddr = ખાલી;
	પૂર્ણાંક r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	જો (!pw || !pw->pw_name)
		પાછા 0;

	જો (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		પાછા 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	જો (options.chroot_directory == ખાલી ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		અક્ષર *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		જો (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			મુક્ત(shell);
			પાછા 0;
		}
		જો (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			મુક્ત(shell);
			પાછા 0;
		}
		મુક્ત(shell);
	}

	જો (options.અંક_deny_users > 0 || options.અંક_allow_users > 0 ||
	    options.અંક_deny_groups > 0 || options.અંક_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	જો (options.અંક_deny_users > 0) {
		માટે (i = 0; i < options.અંક_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			જો (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} નહીંતર જો (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				પાછા 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	જો (options.અંક_allow_users > 0) {
		માટે (i = 0; i < options.અંક_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			જો (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} નહીંતર જો (r == 1)
				તોડો;
		}
		/* i < options.num_allow_users iff we break for loop */
		જો (i >= options.અંક_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			પાછા 0;
		}
	}
	જો (options.અંક_deny_groups > 0 || options.અંક_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		જો (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			પાછા 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		જો (options.અંક_deny_groups > 0)
			જો (ga_match(options.deny_groups,
			    options.અંક_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				પાછા 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		જો (options.અંક_allow_groups > 0)
			જો (!ga_match(options.allow_groups,
			    options.અંક_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				પાછા 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	જો (!sys_auth_allowed_user(pw, loginmsg))
		પાછા 0;
#endif

	/* We found no reason not to let this user try to log on... */
	પાછા 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
સ્થિર અક્ષર *
format_method_ચાવી(Authctxt *authctxt)
{
	અચલ સંરચના sshkey *ચાવી = authctxt->auth_method_ચાવી;
	અચલ અક્ષર *methinfo = authctxt->auth_method_info;
	અક્ષર *fp, *cafp, *ret = ખાલી;

	જો (ચાવી == ખાલી)
		પાછા ખાલી;

	જો (sshkey_is_cert(ચાવી)) {
		fp = sshkey_fingerprint(ચાવી,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(ચાવી->cert->signature_ચાવી,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(ચાવી), fp == ખાલી ? "(null)" : fp,
		    ચાવી->cert->ચાવી_id,
		    (unsigned long long)ચાવી->cert->serial,
		    sshkey_type(ચાવી->cert->signature_ચાવી),
		    cafp == ખાલી ? "(null)" : cafp,
		    methinfo == ખાલી ? "" : ", ",
		    methinfo == ખાલી ? "" : methinfo);
		મુક્ત(fp);
		મુક્ત(cafp);
	} નહીંતર {
		fp = sshkey_fingerprint(ચાવી, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(ચાવી),
		    fp == ખાલી ? "(null)" : fp,
		    methinfo == ખાલી ? "" : ", ",
		    methinfo == ખાલી ? "" : methinfo);
		મુક્ત(fp);
	}
	પાછા ret;
}

શૂન્ય
auth_log(સંરચના ssh *ssh, પૂર્ણાંક authenticated, પૂર્ણાંક partial,
    અચલ અક્ષર *method, અચલ અક્ષર *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	પૂર્ણાંક level = SYSLOG_LEVEL_VERBOSE;
	અચલ અક્ષર *authmsg;
	અક્ષર *extra = ખાલી;

	જો (!mm_is_monitor() && !authctxt->postponed)
		પાછા;

	/* Raise logging level */
	જો (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	જો (authctxt->postponed)
		authmsg = "Postponed";
	નહીંતર જો (partial)
		authmsg = "Partial";
	નહીંતર
		authmsg = authenticated ? "Accepted" : "Failed";

	જો ((extra = format_method_ચાવી(authctxt)) == ખાલી) {
		જો (authctxt->auth_method_info != ખાલી)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != ખાલી ? "/" : "", submethod == ખાલી ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != ખાલી ? ": " : "",
	    extra != ખાલી ? extra : "");

	મુક્ત(extra);

#જો defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	જો (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		જો (strcmp(method, "password") == 0 ||
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
#જો defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	જો (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

શૂન્ય
auth_maxtries_exceeded(સંરચના ssh *ssh)
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
પૂર્ણાંક
auth_મૂળ_allowed(સંરચના ssh *ssh, અચલ અક્ષર *method)
{
	પસંદગી (options.permit_મૂળ_login) {
	સ્થિતિ PERMIT_YES:
		પાછા 1;
	સ્થિતિ PERMIT_NO_PASSWD:
		જો (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			પાછા 1;
		તોડો;
	સ્થિતિ PERMIT_FORCED_ONLY:
		જો (auth_opts->force_command != ખાલી) {
			logit("Root login accepted for forced command.");
			પાછા 1;
		}
		તોડો;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	પાછા 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
અક્ષર *
expand_authorized_ચાવીઓ(અચલ અક્ષર *filename, સંરચના passwd *pw)
{
	અક્ષર *file, uidstr[32], ret[PATH_MAX];
	પૂર્ણાંક i;

	snprintf(uidstr, કદ(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (અક્ષર *)ખાલી);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	જો (path_absolute(file))
		પાછા (file);

	i = snprintf(ret, કદ(ret), "%s/%s", pw->pw_dir, file);
	જો (i < 0 || (size_t)i >= કદ(ret))
		fatal("expand_authorized_keys: path too long");
	મુક્ત(file);
	પાછા (xstrdup(ret));
}

અક્ષર *
authorized_principals_file(સંરચના passwd *pw)
{
	જો (options.authorized_principals_file == ખાલી)
		પાછા ખાલી;
	પાછા expand_authorized_ચાવીઓ(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_ચાવી_in_hostfiles(સંરચના passwd *pw, સંરચના sshkey *ચાવી, અચલ અક્ષર *host,
    અચલ અક્ષર *sysfile, અચલ અક્ષર *userfile)
{
	અક્ષર *user_hostfile;
	સંરચના stat st;
	HostStatus host_status;
	સંરચના hostkeys *hostkeys;
	અચલ સંરચના hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	જો (userfile != ખાલી) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		જો (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} નહીંતર {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		મુક્ત(user_hostfile);
	}
	host_status = check_ચાવી_in_hostkeys(hostkeys, ચાવી, &found);
	જો (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	નહીંતર જો (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->લીટી);
	નહીંતર
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	પાછા host_status;
}

સંરચના passwd *
getpwnamallow(સંરચના ssh *ssh, અચલ અક્ષર *user)
{
#ifdef HAVE_LOGIN_CAP
	બાહ્ય login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	અચલ અક્ષર *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	સંરચના passwd *pw;
	સંરચના connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == ખાલી;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	માટે (i = 0; i < options.અંક_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#જો defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#જો defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	જો (pw == ખાલી) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		પાછા (ખાલી);
	}
	જો (!allowed_user(ssh, pw))
		પાછા (ખાલી);
#ifdef HAVE_LOGIN_CAP
	જો ((lc = login_getpwclass(pw)) == ખાલી) {
		debug("unable to get login class: %s", user);
		પાછા (ખાલી);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	જો (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		પાછા (ખાલી);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	જો (!auth_timeok(lc, time(ખાલી))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		પાછા (ખાલી);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	જો ((as = auth_open()) == ખાલી || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = ખાલી;
	}
	જો (as != ખાલી)
		auth_close(as);
#endif
#endif
	જો (pw != ખાલી)
		પાછા (pwcopy(pw));
	પાછા (ખાલી);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
પૂર્ણાંક
auth_ચાવી_is_revoked(સંરચના sshkey *ચાવી)
{
	અક્ષર *fp = ખાલી;
	u_int i;
	પૂર્ણાંક r;

	જો (options.અંક_revoked_ચાવીઓ_files == 0)
		પાછા 0;
	જો ((fp = sshkey_fingerprint(ચાવી, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		જાઓ out;
	}

	માટે (i = 0; i < options.અંક_revoked_ચાવીઓ_files; i++) {
		r = sshkey_check_revoked(ચાવી, options.revoked_ચાવીઓ_files[i]);
		પસંદગી (r) {
		સ્થિતિ 0:
			તોડો; /* not revoked */
		સ્થિતિ SSH_ERR_ચાવી_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(ચાવી), fp,
			    options.revoked_ચાવીઓ_files[i]);
			જાઓ out;
		મૂળભૂત:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(ચાવી), fp,
			    options.revoked_ચાવીઓ_files[i]);
			જાઓ out;
		}
	}

	/* Success */
	r = 0;

 out:
	મુક્ત(fp);
	પાછા r == 0 ? 0 : 1;
}

શૂન્ય
auth_debug_add(અચલ અક્ષર *fmt,...)
{
	અક્ષર buf[1024];
	va_list args;
	પૂર્ણાંક r;

	va_start(args, fmt);
	vsnprintf(buf, કદ(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	જો (auth_debug != ખાલી)
		જો ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

શૂન્ય
auth_debug_send(સંરચના ssh *ssh)
{
	અક્ષર *સંદેશ;
	પૂર્ણાંક r;

	જો (auth_debug == ખાલી)
		પાછા;
	જ્યારે (sshbuf_len(auth_debug) != 0) {
		જો ((r = sshbuf_get_cstring(auth_debug, &સંદેશ, ખાલી)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", સંદેશ);
		મુક્ત(સંદેશ);
	}
}

શૂન્ય
auth_debug_reset(શૂન્ય)
{
	જો (auth_debug != ખાલી)
		sshbuf_reset(auth_debug);
	નહીંતર જો ((auth_debug = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
}

સંરચના passwd *
fakepw(શૂન્ય)
{
	સ્થિર પૂર્ણાંક done = 0;
	સ્થિર સંરચના passwd fake;
	અચલ અક્ષર hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	અક્ષર *cp;

	જો (done)
		પાછા (&fake);

	memset(&fake, 0, કદ(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	માટે (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(કદ(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == ખાલી ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == ખાલી ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	પાછા (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

અચલ અક્ષર *
auth_get_canonical_hostname(સંરચના ssh *ssh, પૂર્ણાંક use_dns)
{
	સ્થિર અક્ષર *dnsname;

	જો (!use_dns)
		પાછા ssh_remote_ipaddr(ssh);
	જો (dnsname != ખાલી)
		પાછા dnsname;
	dnsname = ssh_remote_hostname(ssh);
	પાછા dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
શૂન્ય
auth_log_authopts(અચલ અક્ષર *loc, અચલ સંરચના sshauthopt *opts, પૂર્ણાંક do_remote)
{
	પૂર્ણાંક do_env = options.permit_user_env && opts->nenv > 0;
	પૂર્ણાંક do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	પૂર્ણાંક do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	અક્ષર સંદેશ[1024], buf[64];

	snprintf(buf, કદ(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(સંદેશ, કદ(સંદેશ), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == ખાલી ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == ખાલી ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, સંદેશ);
	જો (do_remote)
		auth_debug_add("%s: %s", loc, સંદેશ);

	જો (options.permit_user_env) {
		માટે (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			જો (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	જો (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, કદ(buf));
		debug("%s: expires at %s", loc, buf);
	}
	જો (opts->cert_principals != ખાલી) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	જો (opts->force_command != ખાલી)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	જો (do_permitopen) {
		માટે (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	જો (do_permitlisten) {
		માટે (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
પૂર્ણાંક
auth_activate_options(સંરચના ssh *ssh, સંરચના sshauthopt *opts)
{
	સંરચના sshauthopt *old = auth_opts;
	અચલ અક્ષર *emsg = ખાલી;

	debug_f("setting new authentication options");
	જો ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == ખાલી) {
		error("Inconsistent authentication options: %s", emsg);
		પાછા -1;
	}
	sshauthopt_free(old);
	પાછા 0;
}

/* Disable forwarding, etc for the session */
શૂન્ય
auth_restrict_session(સંરચના ssh *ssh)
{
	સંરચના sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	જો ((restricted = sshauthopt_new()) == ખાલી)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	જો (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
