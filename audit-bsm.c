/*
 * TODO
 *
 * - deal with overlap between this and sys_auth_allowed_user
 *   sys_auth_record_login and record_failed_login.
 */

/*
 * Copyright 1988-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 *
 */
/* #pragma ident	"@(#)bsmaudit.c	1.1	01/09/17 SMI" */

#അന്തര്ഭാവ "includes.h"
#എങ്കിൽ defined(USE_BSM_AUDIT)

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef BROKEN_BSM_API
#അന്തര്ഭാവ <libscf.h>
#endif

#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#അന്തര്ഭാവ <bsm/audit.h>
#അന്തര്ഭാവ <bsm/libbsm.h>
#അന്തര്ഭാവ <bsm/audit_uevents.h>
#അന്തര്ഭാവ <bsm/audit_record.h>
#അന്തര്ഭാവ <locale.h>

#എങ്കിൽ defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#അല്ലെങ്കിൽ
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
ബാഹ്യ പൂർണ്ണസംഖ്യ	cannot_audit(പൂർണ്ണസംഖ്യ);
#endif
ബാഹ്യ ശൂന്യം	aug_init(ശൂന്യം);
ബാഹ്യ ശൂന്യം	aug_save_auid(au_id_t);
ബാഹ്യ ശൂന്യം	aug_save_uid(uid_t);
ബാഹ്യ ശൂന്യം	aug_save_euid(uid_t);
ബാഹ്യ ശൂന്യം	aug_save_gid(gid_t);
ബാഹ്യ ശൂന്യം	aug_save_egid(gid_t);
ബാഹ്യ ശൂന്യം	aug_save_pid(pid_t);
ബാഹ്യ ശൂന്യം	aug_save_asid(au_asid_t);
ബാഹ്യ ശൂന്യം	aug_save_tid(dev_t, unsigned പൂർണ്ണസംഖ്യ);
ബാഹ്യ ശൂന്യം	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
ബാഹ്യ പൂർണ്ണസംഖ്യ	aug_save_me(ശൂന്യം);
ബാഹ്യ പൂർണ്ണസംഖ്യ	aug_save_namask(ശൂന്യം);
ബാഹ്യ ശൂന്യം	aug_save_event(au_event_t);
ബാഹ്യ ശൂന്യം	aug_save_sorf(പൂർണ്ണസംഖ്യ);
ബാഹ്യ ശൂന്യം	aug_save_text(അക്ഷരം *);
ബാഹ്യ ശൂന്യം	aug_save_text1(അക്ഷരം *);
ബാഹ്യ ശൂന്യം	aug_save_text2(അക്ഷരം *);
ബാഹ്യ ശൂന്യം	aug_save_na(പൂർണ്ണസംഖ്യ);
ബാഹ്യ ശൂന്യം	aug_save_user(അക്ഷരം *);
ബാഹ്യ ശൂന്യം	aug_save_path(അക്ഷരം *);
ബാഹ്യ പൂർണ്ണസംഖ്യ	aug_save_policy(ശൂന്യം);
ബാഹ്യ ശൂന്യം	aug_save_afunc(പൂർണ്ണസംഖ്യ (*)(പൂർണ്ണസംഖ്യ));
ബാഹ്യ പൂർണ്ണസംഖ്യ	aug_audit(ശൂന്യം);
ബാഹ്യ പൂർണ്ണസംഖ്യ	aug_na_selected(ശൂന്യം);
ബാഹ്യ പൂർണ്ണസംഖ്യ	aug_selected(ശൂന്യം);
ബാഹ്യ പൂർണ്ണസംഖ്യ	aug_daemon_session(ശൂന്യം);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

ബാഹ്യ Authctxt *the_authctxt;
സ്ഥിതം AuditInfoTermID ssh_bsm_tid;

#ifdef BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#define BSM_TEXTBUFSZ 256
#endif

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#എങ്കിൽ defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
ബാഹ്യ പൂർണ്ണസംഖ്യ aug_get_machine(അക്ഷരം *, uint32_t *, uint32_t *);
#അല്ലെങ്കിൽ
സ്ഥിതം പൂർണ്ണസംഖ്യ
aug_get_machine(അക്ഷരം *host, uint32_t *addr, uint32_t *type)
{
	ഘടന addrinfo *ai; 
	ഘടന sockaddr_in *in4;
	ഘടന sockaddr_in6 *in6;
	പൂർണ്ണസംഖ്യ ret = 0, r;

	എങ്കിൽ ((r = getaddrinfo(host, ശൂന്യ, ശൂന്യ, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		തിരികെ -1;
	}
	
	തിരഞ്ഞെടുപ്പ് (ai->ai_family) {
	അവസ്ഥ AF_INET:
		in4 = (ഘടന sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, വലുപ്പം(ഘടന in_addr));
		നിർത്തുക;
#ifdef AU_IPv6
	അവസ്ഥ AF_INET6: 
		in6 = (ഘടന sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, വലുപ്പം(ഘടന in6_addr));
		നിർത്തുക;
#endif
	സ്ഥിരസ്ഥിതി:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	തിരികെ ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
പൂർണ്ണസംഖ്യ
getacna(അക്ഷരം *auditstring, പൂർണ്ണസംഖ്യ len)
{
	scf_handle_t *handle = ശൂന്യ;
	scf_property_t *property = ശൂന്യ;
	scf_മൂല്യം_t *മൂല്യം = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	എങ്കിൽ (handle == ശൂന്യ) 
		തിരികെ -2;

	ret = scf_handle_bind(handle);
	എങ്കിൽ (ret == -1) 
		തിരികെ -2;

	property = scf_property_create(handle);
	എങ്കിൽ (property == ശൂന്യ) 
		തിരികെ -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ശൂന്യ, ശൂന്യ, ശൂന്യ, ശൂന്യ, property, 0);
	എങ്കിൽ (ret == -1) 
		തിരികെ -2;

	മൂല്യം = scf_മൂല്യം_create(handle);
	എങ്കിൽ (മൂല്യം == ശൂന്യ) 
		തിരികെ -2;

	ret = scf_property_get_മൂല്യം(property, മൂല്യം);
	എങ്കിൽ (ret == -1) 
		തിരികെ -2;

	ret = scf_മൂല്യം_get_astring(മൂല്യം, auditstring, len);
	എങ്കിൽ (ret == -1) 
		തിരികെ -2;

	scf_മൂല്യം_destroy(മൂല്യം);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	തിരികെ 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
selected(അക്ഷരം *username, uid_t uid, au_event_t event, പൂർണ്ണസംഖ്യ sf)
{
	പൂർണ്ണസംഖ്യ rc, sorf;
	അക്ഷരം naflags[512];
	ഘടന au_mask mask;

	mask.am_success = mask.am_failure = 0;
	എങ്കിൽ (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, വലുപ്പം(naflags));
		എങ്കിൽ (rc == 0)
			(ശൂന്യം) getauditflagsbin(naflags, &mask);
	} അല്ലെങ്കിൽ
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	തിരികെ(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

സ്ഥിതം ശൂന്യം
bsm_audit_record(പൂർണ്ണസംഖ്യ typ, അക്ഷരം *string, au_event_t event_no)
{
	പൂർണ്ണസംഖ്യ		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	എങ്കിൽ (the_authctxt != ശൂന്യ && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	എങ്കിൽ (!sel)
		തിരികെ;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(ശൂന്യം) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(ശൂന്യം) au_write(ad, au_to_text(string));
	(ശൂന്യം) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#അല്ലെങ്കിൽ
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	എങ്കിൽ (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

സ്ഥിതം ശൂന്യം
bsm_audit_session_setup(ശൂന്യം)
{
	പൂർണ്ണസംഖ്യ rc;
	ഘടന AuditInfoStruct info;
	au_mask_t mask;

	എങ്കിൽ (the_authctxt == ശൂന്യ) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		തിരികെ;
	}

	എങ്കിൽ (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	അല്ലെങ്കിൽ
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(ശൂന്യം) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, വലുപ്പം(info));
	എങ്കിൽ (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

സ്ഥിതം ശൂന്യം
bsm_audit_bad_login(സ്ഥിരം അക്ഷരം *what)
{
	അക്ഷരം textbuf[BSM_TEXTBUFSZ];

	എങ്കിൽ (the_authctxt->valid) {
		(ശൂന്യം) snprintf(textbuf, വലുപ്പം (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} അല്ലെങ്കിൽ {
		(ശൂന്യം) snprintf(textbuf, വലുപ്പം (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

ശൂന്യം
audit_connection_from(സ്ഥിരം അക്ഷരം *host, പൂർണ്ണസംഖ്യ port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	അക്ഷരം buf[1024];

	എങ്കിൽ (cannot_audit(0))
		തിരികെ;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#എങ്കിൽ defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((അക്ഷരം *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, വലുപ്പം(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (പൂർണ്ണസംഖ്യ)tid->at_type, buf);
#അല്ലെങ്കിൽ
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, വലുപ്പം(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

ശൂന്യം
audit_run_command(സ്ഥിരം അക്ഷരം *command)
{
	/* not implemented */
}

ശൂന്യം
audit_session_open(ഘടന logininfo *li)
{
	/* not implemented */
}

ശൂന്യം
audit_session_close(ഘടന logininfo *li)
{
	/* not implemented */
}

ശൂന്യം
audit_event(ഘടന ssh *ssh, ssh_audit_event_t event)
{
	അക്ഷരം    textbuf[BSM_TEXTBUFSZ];
	സ്ഥിതം പൂർണ്ണസംഖ്യ logged_in = 0;
	സ്ഥിരം അക്ഷരം *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	എങ്കിൽ (cannot_audit(0))
		തിരികെ;

	തിരഞ്ഞെടുപ്പ്(event) {
	അവസ്ഥ SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, വലുപ്പം(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		നിർത്തുക;

	അവസ്ഥ SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		എങ്കിൽ (logged_in) {
			snprintf(textbuf, വലുപ്പം(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} അല്ലെങ്കിൽ {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		നിർത്തുക;

	അവസ്ഥ SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		നിർത്തുക;

	അവസ്ഥ SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, വലുപ്പം(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		നിർത്തുക;

	അവസ്ഥ SSH_LOGIN_വേര്_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		നിർത്തുക;

	അവസ്ഥ SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		നിർത്തുക;

	അവസ്ഥ SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		നിർത്തുക;

	സ്ഥിരസ്ഥിതി:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
