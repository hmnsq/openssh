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
#ಆದರೆ defined(USE_BSM_AUDIT)

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BROKEN_BSM_API
#ಅನ್ತರ್ಭಾವ <libscf.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ AUE_openssh
# define AUE_openssh     32800
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <bsm/audit.h>
#ಅನ್ತರ್ಭಾವ <bsm/libbsm.h>
#ಅನ್ತರ್ಭಾವ <bsm/audit_uevents.h>
#ಅನ್ತರ್ಭಾವ <bsm/audit_record.h>
#ಅನ್ತರ್ಭಾವ <locale.h>

#ಆದರೆ defined(HAVE_GETAUDIT_ADDR)
#ವ್ಯಾಖ್ಯಾನಿಸು	AuditInfoStruct		auditinfo_addr
#ವ್ಯಾಖ್ಯಾನಿಸು Audit_Info_ಪದ_ID		au_tid_addr_t
#ವ್ಯಾಖ್ಯಾನಿಸು ಗಣ_Audit_Func(a,b)	setaudit_addr((a),(b))
#ವ್ಯಾಖ್ಯಾನಿಸು ಗಣ_Audit_Func_ಪಠ್ಯ	"setaudit_addr"
#ವ್ಯಾಖ್ಯಾನಿಸು AUToSubjectFunc		au_ಗಮ್ಯ_subject_ex
#ವ್ಯಾಖ್ಯಾನಿಸು AUToReturnFunc(a,b)	au_ಗಮ್ಯ_return32((a), (int32_t)(b))
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು	AuditInfoStruct		auditinfo
#ವ್ಯಾಖ್ಯಾನಿಸು Audit_Info_ಪದ_ID		au_tid_t
#ವ್ಯಾಖ್ಯಾನಿಸು ಗಣ_Audit_Func(a,b)	setaudit(a)
#ವ್ಯಾಖ್ಯಾನಿಸು ಗಣ_Audit_Func_ಪಠ್ಯ	"setaudit"
#ವ್ಯಾಖ್ಯಾನಿಸು AUToSubjectFunc		au_ಗಮ್ಯ_subject
#ವ್ಯಾಖ್ಯಾನಿಸು AUToReturnFunc(a,b)	au_ಗಮ್ಯ_return((a), (u_int)(b))
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ cannot_audit
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	cannot_audit(ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_init(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_auid(au_id_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_uid(uid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_euid(uid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_gid(gid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_egid(gid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_pid(pid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_asid(au_asid_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_tid(dev_t, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	aug_save_me(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	aug_save_namask(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_event(au_event_t);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_sorf(ಪೂರ್ಣಾಂಕ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_ಪಠ್ಯ(ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_text1(ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_text2(ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_na(ಪೂರ್ಣಾಂಕ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_user(ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_ಮಾರ್ಗ(ಅಕ್ಷರ *);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	aug_save_policy(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ	aug_save_afunc(ಪೂರ್ಣಾಂಕ (*)(ಪೂರ್ಣಾಂಕ));
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	aug_audit(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	aug_na_selected(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	aug_selected(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ	aug_daemon_session(ಶೂನ್ಯ);

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_GETTEXT
# define gettext(a)	(a)
#ಆದರೆ_ಅಂತ್ಯ

ಬಾಹ್ಯ Authctxt *the_authctxt;
ಸ್ಥಿರ Audit_Info_ಪದ_ID ssh_bsm_tid;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#ವ್ಯಾಖ್ಯಾನಿಸು BSM_TEXTBUFSZ 256
#ಆದರೆ_ಅಂತ್ಯ

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#ಆದರೆ defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
ಬಾಹ್ಯ ಪೂರ್ಣಾಂಕ aug_get_machine(ಅಕ್ಷರ *, uint32_t *, uint32_t *);
#ಇಲ್ಲದಿದ್ದರೆ
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
aug_get_machine(ಅಕ್ಷರ *host, uint32_t *addr, uint32_t *type)
{
	ರಚನೆ addrinfo *ai; 
	ರಚನೆ sockaddr_in *in4;
	ರಚನೆ sockaddr_in6 *in6;
	ಪೂರ್ಣಾಂಕ ret = 0, r;

	ಆದರೆ ((r = getaddrinfo(host, ಖಾಲಿ, ಖಾಲಿ, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		ಹಿಂತಿರುಗಿ -1;
	}
	
	ಆಯ್ಕೆ (ai->ai_family) {
	ಸ್ಥಿತಿ AF_INET:
		in4 = (ರಚನೆ sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		ಸ್ಮರಣೆ_ನಕಲು(addr, &in4->sin_addr, ಗಾತ್ರ(ರಚನೆ in_addr));
		ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ AU_IPv6
	ಸ್ಥಿತಿ AF_INET6: 
		in6 = (ರಚನೆ sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		ಸ್ಮರಣೆ_ನಕಲು(addr, &in6->sin6_addr, ಗಾತ್ರ(ರಚನೆ in6_addr));
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
ಪೂರ್ಣಾಂಕ
getacna(ಅಕ್ಷರ *auditstring, ಪೂರ್ಣಾಂಕ len)
{
	scf_handle_t *handle = ಖಾಲಿ;
	scf_property_t *property = ಖಾಲಿ;
	scf_ಮೌಲ್ಯ_t *ಮೌಲ್ಯ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_ಆವೃತ್ತಿ);
	ಆದರೆ (handle == ಖಾಲಿ) 
		ಹಿಂತಿರುಗಿ -2;

	ret = scf_handle_bind(handle);
	ಆದರೆ (ret == -1) 
		ಹಿಂತಿರುಗಿ -2;

	property = scf_property_create(handle);
	ಆದರೆ (property == ಖಾಲಿ) 
		ಹಿಂತಿರುಗಿ -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, property, 0);
	ಆದರೆ (ret == -1) 
		ಹಿಂತಿರುಗಿ -2;

	ಮೌಲ್ಯ = scf_ಮೌಲ್ಯ_create(handle);
	ಆದರೆ (ಮೌಲ್ಯ == ಖಾಲಿ) 
		ಹಿಂತಿರುಗಿ -2;

	ret = scf_property_get_ಮೌಲ್ಯ(property, ಮೌಲ್ಯ);
	ಆದರೆ (ret == -1) 
		ಹಿಂತಿರುಗಿ -2;

	ret = scf_ಮೌಲ್ಯ_get_astring(ಮೌಲ್ಯ, auditstring, len);
	ಆದರೆ (ret == -1) 
		ಹಿಂತಿರುಗಿ -2;

	scf_ಮೌಲ್ಯ_destroy(ಮೌಲ್ಯ);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
selected(ಅಕ್ಷರ *username, uid_t uid, au_event_t event, ಪೂರ್ಣಾಂಕ sf)
{
	ಪೂರ್ಣಾಂಕ rc, sorf;
	ಅಕ್ಷರ naflags[512];
	ರಚನೆ au_ಮುಖವಾಡ ಮುಖವಾಡ;

	ಮುಖವಾಡ.am_success = ಮುಖವಾಡ.am_failure = 0;
	ಆದರೆ (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, ಗಾತ್ರ(naflags));
		ಆದರೆ (rc == 0)
			(ಶೂನ್ಯ) getauditflagsbin(naflags, &ಮುಖವಾಡ);
	} ಇಲ್ಲದಿದ್ದರೆ
		rc = au_user_ಮುಖವಾಡ(username, &ಮುಖವಾಡ);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	ಹಿಂತಿರುಗಿ(au_preselect(event, &ಮುಖವಾಡ, sorf, AU_PRS_REREAD));
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsm_audit_ದಾಖಲೆ(ಪೂರ್ಣಾಂಕ typ, ಅಕ್ಷರ *string, au_event_t event_no)
{
	ಪೂರ್ಣಾಂಕ		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	Audit_Info_ಪದ_ID	tid = ssh_bsm_tid;

	ಆದರೆ (the_authctxt != ಖಾಲಿ && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	ಆದರೆ (!sel)
		ಹಿಂತಿರುಗಿ;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(ಶೂನ್ಯ) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(ಶೂನ್ಯ) au_write(ad, au_ಗಮ್ಯ_ಪಠ್ಯ(string));
	(ಶೂನ್ಯ) au_write(ad, AUToReturnFunc(typ, rc));

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_ಗಮ್ಯ_WRITE, event_no, 0);
#ಇಲ್ಲದಿದ್ದರೆ
	rc = au_close(ad, AU_ಗಮ್ಯ_WRITE, event_no);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsm_audit_session_ಸಿದ್ಧತೆ(ಶೂನ್ಯ)
{
	ಪೂರ್ಣಾಂಕ rc;
	ರಚನೆ AuditInfoStruct info;
	au_ಮುಖವಾಡ_t ಮುಖವಾಡ;

	ಆದರೆ (the_authctxt == ಖಾಲಿ) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	ಇಲ್ಲದಿದ್ದರೆ
		info.ai_auid = -1;
	info.ai_asid = getpid();
	ಮುಖವಾಡ.am_success = 0;
	ಮುಖವಾಡ.am_failure = 0;

	(ಶೂನ್ಯ) au_user_ಮುಖವಾಡ(the_authctxt->user, &ಮುಖವಾಡ);

	info.ai_ಮುಖವಾಡ.am_success  = ಮುಖವಾಡ.am_success;
	info.ai_ಮುಖವಾಡ.am_failure  = ಮುಖವಾಡ.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = ಗಣ_Audit_Func(&info, ಗಾತ್ರ(info));
	ಆದರೆ (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    ಗಣ_Audit_Func_ಪಠ್ಯ, strerror(errno));
}

ಸ್ಥಿರ ಶೂನ್ಯ
bsm_audit_bad_login(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *what)
{
	ಅಕ್ಷರ textbuf[BSM_TEXTBUFSZ];

	ಆದರೆ (the_authctxt->valid) {
		(ಶೂನ್ಯ) snprintf(textbuf, ಗಾತ್ರ (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_ದಾಖಲೆ(4, textbuf, AUE_openssh);
	} ಇಲ್ಲದಿದ್ದರೆ {
		(ಶೂನ್ಯ) snprintf(textbuf, ಗಾತ್ರ (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_ದಾಖಲೆ(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

ಶೂನ್ಯ
audit_connection_from(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್)
{
	Audit_Info_ಪದ_ID *tid = &ssh_bsm_tid;
	ಅಕ್ಷರ buf[1024];

	ಆದರೆ (cannot_audit(0))
		ಹಿಂತಿರುಗಿ;
	debug3("BSM audit: connection from %.100s port %d", host, ಪೋರ್ಟ್);

	/* populate our terminal id structure */
#ಆದರೆ defined(HAVE_GETAUDIT_ADDR)
	tid->at_ಪೋರ್ಟ್ = (dev_t)ಪೋರ್ಟ್;
	aug_get_machine((ಅಕ್ಷರ *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, ಗಾತ್ರ(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (ಪೂರ್ಣಾಂಕ)tid->at_type, buf);
#ಇಲ್ಲದಿದ್ದರೆ
	/* this is used on IPv4-only machines */
	tid->ಪೋರ್ಟ್ = (dev_t)ಪೋರ್ಟ್;
	tid->machine = inet_addr(host);
	snprintf(buf, ಗಾತ್ರ(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#ಆದರೆ_ಅಂತ್ಯ
}

ಶೂನ್ಯ
audit_ಸತತ_command(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *command)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_session_open(ರಚನೆ logininfo *li)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_session_close(ರಚನೆ logininfo *li)
{
	/* not implemented */
}

ಶೂನ್ಯ
audit_event(ರಚನೆ ssh *ssh, ssh_audit_event_t event)
{
	ಅಕ್ಷರ    textbuf[BSM_TEXTBUFSZ];
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ logged_ಒಳ = 0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	ಆದರೆ (cannot_audit(0))
		ಹಿಂತಿರುಗಿ;

	ಆಯ್ಕೆ(event) {
	ಸ್ಥಿತಿ SSH_AUTH_SUCCESS:
		logged_ಒಳ = 1;
		bsm_audit_session_ಸಿದ್ಧತೆ();
		snprintf(textbuf, ಗಾತ್ರ(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_ದಾಖಲೆ(0, textbuf, AUE_openssh);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		ಆದರೆ (logged_ಒಳ) {
			snprintf(textbuf, ಗಾತ್ರ(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_ದಾಖಲೆ(0, textbuf, AUE_logout);
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ SSH_NOLOGIN:
		bsm_audit_ದಾಖಲೆ(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, ಗಾತ್ರ(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_ದಾಖಲೆ(1, textbuf, AUE_openssh);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ SSH_LOGIN_ಬೇರು_DENIED:
		bsm_audit_ದಾಖಲೆ(2, gettext("not_console"), AUE_openssh);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		ನಿಲ್ಲಿಸು;

	ಪೂರ್ವನಿಯೋಜಿತ:
		debug_f("unhandled event %d", event);
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* BSM */
