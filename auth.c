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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/wait.h>

#अन्तर्भाव <netinet/in.h>

#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#ifdef HAVE_LOGIN_H
#अन्तर्भाव <login.h>
#endif
#ifdef USE_SHADOW
#अन्तर्भाव <shadow.h>
#endif
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "groupaccess.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "uidswap.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "loginrec.h"
#ifdef GSSAPI
#अन्तर्भाव "ssh-gss.h"
#endif
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "monitor_wrap.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "channels.h"

/* import */
बाह्य ServerOptions options;
बाह्य संरचना include_list includes;
बाह्य संरचना sshbuf *loginmsg;
बाह्य संरचना passwd *privsep_pw;
बाह्य संरचना sshauthopt *auth_opts;

/* Debugging messages */
स्थिर संरचना sshbuf *auth_debug;

/*
 * Check if the user is allowed to log in via ssh. If user is listed
 * in DenyUsers or one of user's groups is listed in DenyGroups, false
 * will be returned. If AllowUsers isn't empty and user isn't listed
 * there, or if AllowGroups isn't empty and one of user's groups isn't
 * listed there, false will be returned.
 * If the user's shell is not executable, false will be returned.
 * Otherwise true is returned.
 */
पूर्णाङ्क
allowed_user(संरचना ssh *ssh, संरचना passwd * pw)
{
	संरचना stat st;
	ध्रुव वर्ण *hostname = रिक्त, *ipaddr = रिक्त;
	पूर्णाङ्क r;
	u_int i;

	/* Shouldn't be called if pw is NULL, but better safe than sorry... */
	जइ (!pw || !pw->pw_name)
		प्रत्यागम 0;

	जइ (!options.use_pam && platform_locked_account(pw)) {
		logit("User %.100s not allowed because account is locked",
		    pw->pw_name);
		प्रत्यागम 0;
	}

	/*
	 * Deny if shell does not exist or is not executable unless we
	 * are chrooting.
	 */
	जइ (options.chroot_directory == रिक्त ||
	    strcasecmp(options.chroot_directory, "none") == 0) {
		वर्ण *shell = xstrdup((pw->pw_shell[0] == '\0') ?
		    _PATH_BSHELL : pw->pw_shell); /* empty = /bin/sh */

		जइ (stat(shell, &st) == -1) {
			logit("User %.100s not allowed because shell %.100s "
			    "does not exist", pw->pw_name, shell);
			मुक्त(shell);
			प्रत्यागम 0;
		}
		जइ (S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & (S_IXOTH|S_IXUSR|S_IXGRP)) == 0) {
			logit("User %.100s not allowed because shell %.100s "
			    "is not executable", pw->pw_name, shell);
			मुक्त(shell);
			प्रत्यागम 0;
		}
		मुक्त(shell);
	}

	जइ (options.अङ्कः_deny_users > 0 || options.अङ्कः_allow_users > 0 ||
	    options.अङ्कः_deny_groups > 0 || options.अङ्कः_allow_groups > 0) {
		hostname = auth_get_canonical_hostname(ssh, options.use_dns);
		ipaddr = ssh_remote_ipaddr(ssh);
	}

	/* Return false if user is listed in DenyUsers */
	जइ (options.अङ्कः_deny_users > 0) {
		प्रति (i = 0; i < options.अङ्कः_deny_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.deny_users[i]);
			जइ (r < 0) {
				fatal("Invalid DenyUsers pattern \"%.100s\"",
				    options.deny_users[i]);
			} अण्णहा जइ (r != 0) {
				logit("User %.100s from %.100s not allowed "
				    "because listed in DenyUsers",
				    pw->pw_name, hostname);
				प्रत्यागम 0;
			}
		}
	}
	/* Return false if AllowUsers isn't empty and user isn't listed there */
	जइ (options.अङ्कः_allow_users > 0) {
		प्रति (i = 0; i < options.अङ्कः_allow_users; i++) {
			r = match_user(pw->pw_name, hostname, ipaddr,
			    options.allow_users[i]);
			जइ (r < 0) {
				fatal("Invalid AllowUsers pattern \"%.100s\"",
				    options.allow_users[i]);
			} अण्णहा जइ (r == 1)
				भङ्ग;
		}
		/* i < options.num_allow_users iff we break for loop */
		जइ (i >= options.अङ्कः_allow_users) {
			logit("User %.100s from %.100s not allowed because "
			    "not listed in AllowUsers", pw->pw_name, hostname);
			प्रत्यागम 0;
		}
	}
	जइ (options.अङ्कः_deny_groups > 0 || options.अङ्कः_allow_groups > 0) {
		/* Get the user's group access list (primary and supplementary) */
		जइ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
			logit("User %.100s from %.100s not allowed because "
			    "not in any group", pw->pw_name, hostname);
			प्रत्यागम 0;
		}

		/* Return false if one of user's groups is listed in DenyGroups */
		जइ (options.अङ्कः_deny_groups > 0)
			जइ (ga_match(options.deny_groups,
			    options.अङ्कः_deny_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because a group is listed in DenyGroups",
				    pw->pw_name, hostname);
				प्रत्यागम 0;
			}
		/*
		 * Return false if AllowGroups isn't empty and one of user's groups
		 * isn't listed there
		 */
		जइ (options.अङ्कः_allow_groups > 0)
			जइ (!ga_match(options.allow_groups,
			    options.अङ्कः_allow_groups)) {
				ga_free();
				logit("User %.100s from %.100s not allowed "
				    "because none of user's groups are listed "
				    "in AllowGroups", pw->pw_name, hostname);
				प्रत्यागम 0;
			}
		ga_free();
	}

#ifdef CUSTOM_SYS_AUTH_ALLOWED_USER
	जइ (!sys_auth_allowed_user(pw, loginmsg))
		प्रत्यागम 0;
#endif

	/* We found no reason not to let this user try to log on... */
	प्रत्यागम 1;
}

/*
 * Formats any key left in authctxt->auth_method_key for inclusion in
 * auth_log()'s message. Also includes authxtct->auth_method_info if present.
 */
स्थिर वर्ण *
format_method_कुञ्चिका(Authctxt *authctxt)
{
	ध्रुव संरचना sshkey *कुञ्चिका = authctxt->auth_method_कुञ्चिका;
	ध्रुव वर्ण *methinfo = authctxt->auth_method_info;
	वर्ण *fp, *cafp, *ret = रिक्त;

	जइ (कुञ्चिका == रिक्त)
		प्रत्यागम रिक्त;

	जइ (sshkey_is_cert(कुञ्चिका)) {
		fp = sshkey_fingerprint(कुञ्चिका,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		cafp = sshkey_fingerprint(कुञ्चिका->cert->signature_कुञ्चिका,
		    options.fingerprint_hash, SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s ID %s (serial %llu) CA %s %s%s%s",
		    sshkey_type(कुञ्चिका), fp == रिक्त ? "(null)" : fp,
		    कुञ्चिका->cert->कुञ्चिका_id,
		    (unsigned long long)कुञ्चिका->cert->serial,
		    sshkey_type(कुञ्चिका->cert->signature_कुञ्चिका),
		    cafp == रिक्त ? "(null)" : cafp,
		    methinfo == रिक्त ? "" : ", ",
		    methinfo == रिक्त ? "" : methinfo);
		मुक्त(fp);
		मुक्त(cafp);
	} अण्णहा {
		fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		xasprintf(&ret, "%s %s%s%s", sshkey_type(कुञ्चिका),
		    fp == रिक्त ? "(null)" : fp,
		    methinfo == रिक्त ? "" : ", ",
		    methinfo == रिक्त ? "" : methinfo);
		मुक्त(fp);
	}
	प्रत्यागम ret;
}

शून्य
auth_log(संरचना ssh *ssh, पूर्णाङ्क authenticated, पूर्णाङ्क partial,
    ध्रुव वर्ण *method, ध्रुव वर्ण *submethod)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	पूर्णाङ्क level = SYSLOG_LEVEL_VERBOSE;
	ध्रुव वर्ण *authmsg;
	वर्ण *extra = रिक्त;

	जइ (!mm_is_monitor() && !authctxt->postponed)
		प्रत्यागम;

	/* Raise logging level */
	जइ (authenticated == 1 ||
	    !authctxt->valid ||
	    authctxt->failures >= options.max_authtries / 2 ||
	    strcmp(method, "password") == 0)
		level = SYSLOG_LEVEL_INFO;

	जइ (authctxt->postponed)
		authmsg = "Postponed";
	अण्णहा जइ (partial)
		authmsg = "Partial";
	अण्णहा
		authmsg = authenticated ? "Accepted" : "Failed";

	जइ ((extra = format_method_कुञ्चिका(authctxt)) == रिक्त) {
		जइ (authctxt->auth_method_info != रिक्त)
			extra = xstrdup(authctxt->auth_method_info);
	}

	do_log2(level, "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s",
	    authmsg,
	    method,
	    submethod != रिक्त ? "/" : "", submethod == रिक्त ? "" : submethod,
	    authctxt->valid ? "" : "invalid user ",
	    authctxt->user,
	    ssh_remote_ipaddr(ssh),
	    ssh_remote_port(ssh),
	    extra != रिक्त ? ": " : "",
	    extra != रिक्त ? extra : "");

	मुक्त(extra);

#जइ defined(CUSTOM_FAILED_LOGIN) || defined(SSH_AUDIT_EVENTS)
	जइ (authenticated == 0 && !(authctxt->postponed || partial)) {
		/* Log failed login attempt */
# ifdef CUSTOM_FAILED_LOGIN
		जइ (strcmp(method, "password") == 0 ||
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
#जइ defined(CUSTOM_FAILED_LOGIN) && defined(WITH_AIXAUTHENTICATE)
	जइ (authenticated)
		sys_auth_record_login(authctxt->user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh",
		    loginmsg);
#endif
}

शून्य
auth_maxtries_exceeded(संरचना ssh *ssh)
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
पूर्णाङ्क
auth_मूलम्_allowed(संरचना ssh *ssh, ध्रुव वर्ण *method)
{
	विकल्प (options.permit_मूलम्_login) {
	पक्ष PERMIT_YES:
		प्रत्यागम 1;
	पक्ष PERMIT_NO_PASSWD:
		जइ (strcmp(method, "publickey") == 0 ||
		    strcmp(method, "hostbased") == 0 ||
		    strcmp(method, "gssapi-with-mic") == 0)
			प्रत्यागम 1;
		भङ्ग;
	पक्ष PERMIT_FORCED_ONLY:
		जइ (auth_opts->force_command != रिक्त) {
			logit("Root login accepted for forced command.");
			प्रत्यागम 1;
		}
		भङ्ग;
	}
	logit("ROOT LOGIN REFUSED FROM %.200s port %d",
	    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
	प्रत्यागम 0;
}


/*
 * Given a template and a passwd structure, build a filename
 * by substituting % tokenised options. Currently, %% becomes '%',
 * %h becomes the home directory and %u the username.
 *
 * This returns a buffer allocated by xmalloc.
 */
वर्ण *
expand_authorized_कुञ्चिकाः(ध्रुव वर्ण *filename, संरचना passwd *pw)
{
	वर्ण *file, uidstr[32], ret[PATH_MAX];
	पूर्णाङ्क i;

	snprintf(uidstr, परिमाण(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	file = percent_expand(filename, "h", pw->pw_dir,
	    "u", pw->pw_name, "U", uidstr, (वर्ण *)रिक्त);

	/*
	 * Ensure that filename starts anchored. If not, be backward
	 * compatible and prepend the '%h/'
	 */
	जइ (path_absolute(file))
		प्रत्यागम (file);

	i = snprintf(ret, परिमाण(ret), "%s/%s", pw->pw_dir, file);
	जइ (i < 0 || (size_t)i >= परिमाण(ret))
		fatal("expand_authorized_keys: path too long");
	मुक्त(file);
	प्रत्यागम (xstrdup(ret));
}

वर्ण *
authorized_principals_file(संरचना passwd *pw)
{
	जइ (options.authorized_principals_file == रिक्त)
		प्रत्यागम रिक्त;
	प्रत्यागम expand_authorized_कुञ्चिकाः(options.authorized_principals_file, pw);
}

/* return ok if key exists in sysfile or userfile */
HostStatus
check_कुञ्चिका_in_hostfiles(संरचना passwd *pw, संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *host,
    ध्रुव वर्ण *sysfile, ध्रुव वर्ण *userfile)
{
	वर्ण *user_hostfile;
	संरचना stat st;
	HostStatus host_status;
	संरचना hostkeys *hostkeys;
	ध्रुव संरचना hostkey_entry *found;

	hostkeys = init_hostkeys();
	load_hostkeys(hostkeys, host, sysfile, 0);
	जइ (userfile != रिक्त) {
		user_hostfile = tilde_expand_filename(userfile, pw->pw_uid);
		जइ (options.strict_modes &&
		    (stat(user_hostfile, &st) == 0) &&
		    ((st.st_uid != 0 && st.st_uid != pw->pw_uid) ||
		    (st.st_mode & 022) != 0)) {
			logit("Authentication refused for %.100s: "
			    "bad owner or modes for %.200s",
			    pw->pw_name, user_hostfile);
			auth_debug_add("Ignored %.200s: bad ownership or modes",
			    user_hostfile);
		} अण्णहा {
			temporarily_use_uid(pw);
			load_hostkeys(hostkeys, host, user_hostfile, 0);
			restore_uid();
		}
		मुक्त(user_hostfile);
	}
	host_status = check_कुञ्चिका_in_hostkeys(hostkeys, कुञ्चिका, &found);
	जइ (host_status == HOST_REVOKED)
		error("WARNING: revoked key for %s attempted authentication",
		    host);
	अण्णहा जइ (host_status == HOST_OK)
		debug_f("key for %s found at %s:%ld",
		    found->host, found->file, found->पङ्क्तिः);
	अण्णहा
		debug_f("key for host %s not found", host);

	free_hostkeys(hostkeys);

	प्रत्यागम host_status;
}

संरचना passwd *
getpwnamallow(संरचना ssh *ssh, ध्रुव वर्ण *user)
{
#ifdef HAVE_LOGIN_CAP
	बाह्य login_cap_t *lc;
#ifdef HAVE_AUTH_HOSTOK
	ध्रुव वर्ण *from_host, *from_ip;
#endif
#ifdef BSD_AUTH
	auth_session_t *as;
#endif
#endif
	संरचना passwd *pw;
	संरचना connection_info *ci;
	u_int i;

	ci = server_get_connection_info(ssh, 1, options.use_dns);
	ci->user = user;
	ci->user_invalid = getpwnam(user) == रिक्त;
	parse_server_match_config(&options, &includes, ci);
	log_change_level(options.log_level);
	log_verbose_reset();
	प्रति (i = 0; i < options.अङ्कः_log_verbose; i++)
		log_verbose_add(options.log_verbose[i]);
	server_process_channel_timeouts(ssh);
	server_process_permitopen(ssh);
	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

#जइ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_setauthdb(user);
#endif

	pw = getpwnam(user);

#जइ defined(_AIX) && defined(HAVE_SETAUTHDB)
	aix_restoreauthdb();
#endif
	जइ (pw == रिक्त) {
		logit("Invalid user %.100s from %.100s port %d",
		    user, ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
#ifdef CUSTOM_FAILED_LOGIN
		record_failed_login(ssh, user,
		    auth_get_canonical_hostname(ssh, options.use_dns), "ssh");
#endif
#ifdef SSH_AUDIT_EVENTS
		audit_event(ssh, SSH_INVALID_USER);
#endif /* SSH_AUDIT_EVENTS */
		प्रत्यागम (रिक्त);
	}
	जइ (!allowed_user(ssh, pw))
		प्रत्यागम (रिक्त);
#ifdef HAVE_LOGIN_CAP
	जइ ((lc = login_getpwclass(pw)) == रिक्त) {
		debug("unable to get login class: %s", user);
		प्रत्यागम (रिक्त);
	}
#ifdef HAVE_AUTH_HOSTOK
	from_host = auth_get_canonical_hostname(ssh, options.use_dns);
	from_ip = ssh_remote_ipaddr(ssh);
	जइ (!auth_hostok(lc, from_host, from_ip)) {
		debug("Denied connection for %.200s from %.200s [%.200s].",
		      pw->pw_name, from_host, from_ip);
		प्रत्यागम (रिक्त);
	}
#endif /* HAVE_AUTH_HOSTOK */
#ifdef HAVE_AUTH_TIMEOK
	जइ (!auth_timeok(lc, time(रिक्त))) {
		debug("LOGIN %.200s REFUSED (TIME)", pw->pw_name);
		प्रत्यागम (रिक्त);
	}
#endif /* HAVE_AUTH_TIMEOK */
#ifdef BSD_AUTH
	जइ ((as = auth_open()) == रिक्त || auth_setpwd(as, pw) != 0 ||
	    auth_approval(as, lc, pw->pw_name, "ssh") <= 0) {
		debug("Approval failure for %s", user);
		pw = रिक्त;
	}
	जइ (as != रिक्त)
		auth_close(as);
#endif
#endif
	जइ (pw != रिक्त)
		प्रत्यागम (pwcopy(pw));
	प्रत्यागम (रिक्त);
}

/* Returns 1 if key is revoked by revoked_keys_file, 0 otherwise */
पूर्णाङ्क
auth_कुञ्चिका_is_revoked(संरचना sshkey *कुञ्चिका)
{
	वर्ण *fp = रिक्त;
	u_int i;
	पूर्णाङ्क r;

	जइ (options.अङ्कः_revoked_कुञ्चिकाः_files == 0)
		प्रत्यागम 0;
	जइ ((fp = sshkey_fingerprint(कुञ्चिका, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		error_fr(r, "fingerprint key");
		गच्छ out;
	}

	प्रति (i = 0; i < options.अङ्कः_revoked_कुञ्चिकाः_files; i++) {
		r = sshkey_check_revoked(कुञ्चिका, options.revoked_कुञ्चिकाः_files[i]);
		विकल्प (r) {
		पक्ष 0:
			भङ्ग; /* not revoked */
		पक्ष SSH_ERR_कुञ्चिका_REVOKED:
			error("Authentication key %s %s revoked by file %s",
			    sshkey_type(कुञ्चिका), fp,
			    options.revoked_कुञ्चिकाः_files[i]);
			गच्छ out;
		स्वभाव:
			error_r(r, "Error checking authentication key %s %s in "
			    "revoked keys file %s", sshkey_type(कुञ्चिका), fp,
			    options.revoked_कुञ्चिकाः_files[i]);
			गच्छ out;
		}
	}

	/* Success */
	r = 0;

 out:
	मुक्त(fp);
	प्रत्यागम r == 0 ? 0 : 1;
}

शून्य
auth_debug_add(ध्रुव वर्ण *fmt,...)
{
	वर्ण buf[1024];
	va_list args;
	पूर्णाङ्क r;

	va_start(args, fmt);
	vsnprintf(buf, परिमाण(buf), fmt, args);
	va_end(args);
	debug3("%s", buf);
	जइ (auth_debug != रिक्त)
		जइ ((r = sshbuf_put_cstring(auth_debug, buf)) != 0)
			fatal_fr(r, "sshbuf_put_cstring");
}

शून्य
auth_debug_send(संरचना ssh *ssh)
{
	वर्ण *सन्देशः;
	पूर्णाङ्क r;

	जइ (auth_debug == रिक्त)
		प्रत्यागम;
	जाव (sshbuf_len(auth_debug) != 0) {
		जइ ((r = sshbuf_get_cstring(auth_debug, &सन्देशः, रिक्त)) != 0)
			fatal_fr(r, "sshbuf_get_cstring");
		ssh_packet_send_debug(ssh, "%s", सन्देशः);
		मुक्त(सन्देशः);
	}
}

शून्य
auth_debug_reset(शून्य)
{
	जइ (auth_debug != रिक्त)
		sshbuf_reset(auth_debug);
	अण्णहा जइ ((auth_debug = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
}

संरचना passwd *
fakepw(शून्य)
{
	स्थिर पूर्णाङ्क done = 0;
	स्थिर संरचना passwd fake;
	ध्रुव वर्ण hashchars[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789"; /* from bcrypt.c */
	वर्ण *cp;

	जइ (done)
		प्रत्यागम (&fake);

	memset(&fake, 0, परिमाण(fake));
	fake.pw_name = "NOUSER";
	fake.pw_passwd = xstrdup("$2a$10$"
	    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
	प्रति (cp = fake.pw_passwd + 7; *cp != '\0'; cp++)
		*cp = hashchars[arc4random_uniform(परिमाण(hashchars) - 1)];
#ifdef HAVE_STRUCT_PASSWD_PW_GECOS
	fake.pw_gecos = "NOUSER";
#endif
	fake.pw_uid = privsep_pw == रिक्त ? (uid_t)-1 : privsep_pw->pw_uid;
	fake.pw_gid = privsep_pw == रिक्त ? (gid_t)-1 : privsep_pw->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	fake.pw_class = "";
#endif
	fake.pw_dir = "/nonexist";
	fake.pw_shell = "/nonexist";
	done = 1;

	प्रत्यागम (&fake);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

ध्रुव वर्ण *
auth_get_canonical_hostname(संरचना ssh *ssh, पूर्णाङ्क use_dns)
{
	स्थिर वर्ण *dnsname;

	जइ (!use_dns)
		प्रत्यागम ssh_remote_ipaddr(ssh);
	जइ (dnsname != रिक्त)
		प्रत्यागम dnsname;
	dnsname = ssh_remote_hostname(ssh);
	प्रत्यागम dnsname;
}

/* These functions link key/cert options to the auth framework */

/* Log sshauthopt options locally and (optionally) for remote transmission */
शून्य
auth_log_authopts(ध्रुव वर्ण *loc, ध्रुव संरचना sshauthopt *opts, पूर्णाङ्क do_remote)
{
	पूर्णाङ्क do_env = options.permit_user_env && opts->nenv > 0;
	पूर्णाङ्क do_permitopen = opts->npermitopen > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_LOCAL) != 0;
	पूर्णाङ्क do_permitlisten = opts->npermitlisten > 0 &&
	    (options.allow_tcp_forwarding & FORWARD_REMOTE) != 0;
	size_t i;
	वर्ण सन्देशः[1024], buf[64];

	snprintf(buf, परिमाण(buf), "%d", opts->force_tun_device);
	/* Try to keep this alphabetically sorted */
	snprintf(सन्देशः, परिमाण(सन्देशः), "key options:%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	    opts->permit_agent_forwarding_flag ? " agent-forwarding" : "",
	    opts->force_command == रिक्त ? "" : " command",
	    do_env ?  " environment" : "",
	    opts->valid_before == 0 ? "" : "expires",
	    opts->no_require_user_presence ? " no-touch-required" : "",
	    do_permitopen ?  " permitopen" : "",
	    do_permitlisten ?  " permitlisten" : "",
	    opts->permit_port_forwarding_flag ? " port-forwarding" : "",
	    opts->cert_principals == रिक्त ? "" : " principals",
	    opts->permit_pty_flag ? " pty" : "",
	    opts->require_verify ? " uv" : "",
	    opts->force_tun_device == -1 ? "" : " tun=",
	    opts->force_tun_device == -1 ? "" : buf,
	    opts->permit_user_rc ? " user-rc" : "",
	    opts->permit_x11_forwarding_flag ? " x11-forwarding" : "");

	debug("%s: %s", loc, सन्देशः);
	जइ (do_remote)
		auth_debug_add("%s: %s", loc, सन्देशः);

	जइ (options.permit_user_env) {
		प्रति (i = 0; i < opts->nenv; i++) {
			debug("%s: environment: %s", loc, opts->env[i]);
			जइ (do_remote) {
				auth_debug_add("%s: environment: %s",
				    loc, opts->env[i]);
			}
		}
	}

	/* Go into a little more details for the local logs. */
	जइ (opts->valid_before != 0) {
		format_absolute_time(opts->valid_before, buf, परिमाण(buf));
		debug("%s: expires at %s", loc, buf);
	}
	जइ (opts->cert_principals != रिक्त) {
		debug("%s: authorized principals: \"%s\"",
		    loc, opts->cert_principals);
	}
	जइ (opts->force_command != रिक्त)
		debug("%s: forced command: \"%s\"", loc, opts->force_command);
	जइ (do_permitopen) {
		प्रति (i = 0; i < opts->npermitopen; i++) {
			debug("%s: permitted open: %s",
			    loc, opts->permitopen[i]);
		}
	}
	जइ (do_permitlisten) {
		प्रति (i = 0; i < opts->npermitlisten; i++) {
			debug("%s: permitted listen: %s",
			    loc, opts->permitlisten[i]);
		}
	}
}

/* Activate a new set of key/cert options; merging with what is there. */
पूर्णाङ्क
auth_activate_options(संरचना ssh *ssh, संरचना sshauthopt *opts)
{
	संरचना sshauthopt *old = auth_opts;
	ध्रुव वर्ण *emsg = रिक्त;

	debug_f("setting new authentication options");
	जइ ((auth_opts = sshauthopt_merge(old, opts, &emsg)) == रिक्त) {
		error("Inconsistent authentication options: %s", emsg);
		प्रत्यागम -1;
	}
	sshauthopt_free(old);
	प्रत्यागम 0;
}

/* Disable forwarding, etc for the session */
शून्य
auth_restrict_session(संरचना ssh *ssh)
{
	संरचना sshauthopt *restricted;

	debug_f("restricting session");

	/* A blank sshauthopt defaults to permitting nothing */
	जइ ((restricted = sshauthopt_new()) == रिक्त)
		fatal_f("sshauthopt_new failed");
	restricted->permit_pty_flag = 1;
	restricted->restricted = 1;

	जइ (auth_activate_options(ssh, restricted) != 0)
		fatal_f("failed to restrict session");
	sshauthopt_free(restricted);
}
