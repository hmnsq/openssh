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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಯದಿ defined(USE_BSM_AUDIT)

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef BROKEN_BSM_API
#ಅನ್ತರ್ಭಾವ <libscf.h>
#endif

#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#ಅನ್ತರ್ಭಾವ <bsm/audit.h>
#ಅನ್ತರ್ಭಾವ <bsm/libbsm.h>
#ಅನ್ತರ್ಭಾವ <bsm/audit_uevents.h>
#ಅನ್ತರ್ಭಾವ <bsm/audit_record.h>
#ಅನ್ತರ್ಭಾವ <locale.h>

#ಯದಿ defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#ಅನ್ಯಥಾ
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	cannot_audit(ಪೂರ್ಣಾಙ್ಕ);
#endif
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_init(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_auid(au_id_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_uid(uid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_euid(uid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_gid(gid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_egid(gid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_pid(pid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_asid(au_asid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_tid(dev_t, unsigned ಪೂರ್ಣಾಙ್ಕ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	aug_save_me(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	aug_save_namask(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_event(au_event_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_sorf(ಪೂರ್ಣಾಙ್ಕ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_text(ವರ್ಣ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_text1(ವರ್ಣ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_text2(ವರ್ಣ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_na(ಪೂರ್ಣಾಙ್ಕ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_user(ವರ್ಣ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_path(ವರ್ಣ *);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	aug_save_policy(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_afunc(ಪೂರ್ಣಾಙ್ಕ (*)(ಪೂರ್ಣಾಙ್ಕ));
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	aug_audit(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	aug_na_selected(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	aug_selected(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ	aug_daemon_session(ಶೂನ್ಯ);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

ಬಾಹ್ಯ Authctxt *the_authctxt;
ಸ್ಥಿರ AuditInfoTermID ssh_bsm_tid;

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
#ಯದಿ defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ aug_get_machine(ವರ್ಣ *, uint32_t *, uint32_t *);
#ಅನ್ಯಥಾ
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
aug_get_machine(ವರ್ಣ *host, uint32_t *addr, uint32_t *type)
{
	ಸಂರಚನಾ addrinfo *ai; 
	ಸಂರಚನಾ sockaddr_in *in4;
	ಸಂರಚನಾ sockaddr_in6 *in6;
	ಪೂರ್ಣಾಙ್ಕ ret = 0, r;

	ಯದಿ ((r = getaddrinfo(host, ರಿಕ್ತ, ರಿಕ್ತ, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	
	ವಿಕಲ್ಪ (ai->ai_family) {
	ಪಕ್ಷ AF_INET:
		in4 = (ಸಂರಚನಾ sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, ಪರಿಮಾಣ(ಸಂರಚನಾ in_addr));
		ಭಙ್ಗ;
#ifdef AU_IPv6
	ಪಕ್ಷ AF_INET6: 
		in6 = (ಸಂರಚನಾ sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, ಪರಿಮಾಣ(ಸಂರಚನಾ in6_addr));
		ಭಙ್ಗ;
#endif
	ಸ್ವಭಾವ:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
ಪೂರ್ಣಾಙ್ಕ
getacna(ವರ್ಣ *auditstring, ಪೂರ್ಣಾಙ್ಕ len)
{
	scf_handle_t *handle = ರಿಕ್ತ;
	scf_property_t *property = ರಿಕ್ತ;
	scf_ಮೌಲ್ಯ_t *ಮೌಲ್ಯ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	ಯದಿ (handle == ರಿಕ್ತ) 
		ಪ್ರತ್ಯಾಗಮ -2;

	ret = scf_handle_bind(handle);
	ಯದಿ (ret == -1) 
		ಪ್ರತ್ಯಾಗಮ -2;

	property = scf_property_create(handle);
	ಯದಿ (property == ರಿಕ್ತ) 
		ಪ್ರತ್ಯಾಗಮ -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, property, 0);
	ಯದಿ (ret == -1) 
		ಪ್ರತ್ಯಾಗಮ -2;

	ಮೌಲ್ಯ = scf_ಮೌಲ್ಯ_create(handle);
	ಯದಿ (ಮೌಲ್ಯ == ರಿಕ್ತ) 
		ಪ್ರತ್ಯಾಗಮ -2;

	ret = scf_property_get_ಮೌಲ್ಯ(property, ಮೌಲ್ಯ);
	ಯದಿ (ret == -1) 
		ಪ್ರತ್ಯಾಗಮ -2;

	ret = scf_ಮೌಲ್ಯ_get_astring(ಮೌಲ್ಯ, auditstring, len);
	ಯದಿ (ret == -1) 
		ಪ್ರತ್ಯಾಗಮ -2;

	scf_ಮೌಲ್ಯ_destroy(ಮೌಲ್ಯ);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
selected(ವರ್ಣ *username, uid_t uid, au_event_t event, ಪೂರ್ಣಾಙ್ಕ sf)
{
	ಪೂರ್ಣಾಙ್ಕ rc, sorf;
	ವರ್ಣ naflags[512];
	ಸಂರಚನಾ au_mask mask;

	mask.am_success = mask.am_failure = 0;
	ಯದಿ (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, ಪರಿಮಾಣ(naflags));
		ಯದಿ (rc == 0)
			(ಶೂನ್ಯ) getauditflagsbin(naflags, &mask);
	} ಅನ್ಯಥಾ
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	ಪ್ರತ್ಯಾಗಮ(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsm_audit_record(ಪೂರ್ಣಾಙ್ಕ typ, ವರ್ಣ *string, au_event_t event_no)
{
	ಪೂರ್ಣಾಙ್ಕ		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	ಯದಿ (the_authctxt != ರಿಕ್ತ && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	ಯದಿ (!sel)
		ಪ್ರತ್ಯಾಗಮ;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(ಶೂನ್ಯ) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(ಶೂನ್ಯ) au_write(ad, au_to_text(string));
	(ಶೂನ್ಯ) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#ಅನ್ಯಥಾ
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	ಯದಿ (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsm_audit_session_setup(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಙ್ಕ rc;
	ಸಂರಚನಾ AuditInfoStruct info;
	au_mask_t mask;

	ಯದಿ (the_authctxt == ರಿಕ್ತ) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	ಅನ್ಯಥಾ
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(ಶೂನ್ಯ) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, ಪರಿಮಾಣ(info));
	ಯದಿ (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsm_audit_bad_login(ಧ್ರುವ ವರ್ಣ *what)
{
	ವರ್ಣ textbuf[BSM_TEXTBUFSZ];

	ಯದಿ (the_authctxt->valid) {
		(ಶೂನ್ಯ) snprintf(textbuf, ಪರಿಮಾಣ (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} ಅನ್ಯಥಾ {
		(ಶೂನ್ಯ) snprintf(textbuf, ಪರಿಮಾಣ (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

ಶೂನ್ಯ
audit_connection_from(ಧ್ರುವ ವರ್ಣ *host, ಪೂರ್ಣಾಙ್ಕ port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	ವರ್ಣ buf[1024];

	ಯದಿ (cannot_audit(0))
		ಪ್ರತ್ಯಾಗಮ;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#ಯದಿ defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((ವರ್ಣ *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, ಪರಿಮಾಣ(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (ಪೂರ್ಣಾಙ್ಕ)tid->at_type, buf);
#ಅನ್ಯಥಾ
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, ಪರಿಮಾಣ(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

ಶೂನ್ಯ
audit_run_command(ಧ್ರುವ ವರ್ಣ *command)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_session_open(ಸಂರಚನಾ logininfo *li)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_session_close(ಸಂರಚನಾ logininfo *li)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_event(ಸಂರಚನಾ ssh *ssh, ssh_audit_event_t event)
{
	ವರ್ಣ    textbuf[BSM_TEXTBUFSZ];
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ logged_in = 0;
	ಧ್ರುವ ವರ್ಣ *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	ಯದಿ (cannot_audit(0))
		ಪ್ರತ್ಯಾಗಮ;

	ವಿಕಲ್ಪ(event) {
	ಪಕ್ಷ SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, ಪರಿಮಾಣ(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		ಭಙ್ಗ;

	ಪಕ್ಷ SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		ಯದಿ (logged_in) {
			snprintf(textbuf, ಪರಿಮಾಣ(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} ಅನ್ಯಥಾ {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		ಭಙ್ಗ;

	ಪಕ್ಷ SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, ಪರಿಮಾಣ(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		ಭಙ್ಗ;

	ಪಕ್ಷ SSH_LOGIN_ಬೇರು_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		ಭಙ್ಗ;

	ಪಕ್ಷ SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		ಭಙ್ಗ;

	ಪಕ್ಷ SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		ಭಙ್ಗ;

	ಸ್ವಭಾವ:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
