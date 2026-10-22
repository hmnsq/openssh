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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ defined(USE_BSM_AUDIT)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BROKEN_BSM_API
#ਅਨ੍ਤਰ੍ਭਾਵ <libscf.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ AUE_openssh
# define AUE_openssh     32800
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <bsm/audit.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <bsm/libbsm.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <bsm/audit_uevents.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <bsm/audit_record.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <locale.h>

#ਜੇ defined(HAVE_GETAUDIT_ADDR)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	AuditInfoStruct		auditinfo_addr
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ Audit_Info_ਪਦ_ID		au_tid_addr_t
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸੈੱਟ_Audit_Func(a,b)	setaudit_addr((a),(b))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸੈੱਟ_Audit_Func_ਪਾਠ	"setaudit_addr"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUToSubjectFunc		au_ਮੰਜ਼ਿਲ_subject_ex
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUToReturnFunc(a,b)	au_ਮੰਜ਼ਿਲ_return32((a), (int32_t)(b))
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	AuditInfoStruct		auditinfo
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ Audit_Info_ਪਦ_ID		au_tid_t
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸੈੱਟ_Audit_Func(a,b)	setaudit(a)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸੈੱਟ_Audit_Func_ਪਾਠ	"setaudit"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUToSubjectFunc		au_ਮੰਜ਼ਿਲ_subject
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AUToReturnFunc(a,b)	au_ਮੰਜ਼ਿਲ_return((a), (u_int)(b))
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ cannot_audit
ਬਾਹਰੀ ਪੂਰਨ	cannot_audit(ਪੂਰਨ);
#ਜੇ_ਅੰਤ
ਬਾਹਰੀ ਖਾਲੀ	aug_init(ਖਾਲੀ);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_auid(au_id_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_uid(uid_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_euid(uid_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_gid(gid_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_egid(gid_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_pid(pid_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_asid(au_asid_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_tid(dev_t, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
ਬਾਹਰੀ ਪੂਰਨ	aug_save_me(ਖਾਲੀ);
ਬਾਹਰੀ ਪੂਰਨ	aug_save_namask(ਖਾਲੀ);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_event(au_event_t);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_sorf(ਪੂਰਨ);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_ਪਾਠ(ਅੱਖਰ *);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_text1(ਅੱਖਰ *);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_text2(ਅੱਖਰ *);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_na(ਪੂਰਨ);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_user(ਅੱਖਰ *);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_ਰਸਤਾ(ਅੱਖਰ *);
ਬਾਹਰੀ ਪੂਰਨ	aug_save_policy(ਖਾਲੀ);
ਬਾਹਰੀ ਖਾਲੀ	aug_save_afunc(ਪੂਰਨ (*)(ਪੂਰਨ));
ਬਾਹਰੀ ਪੂਰਨ	aug_audit(ਖਾਲੀ);
ਬਾਹਰੀ ਪੂਰਨ	aug_na_selected(ਖਾਲੀ);
ਬਾਹਰੀ ਪੂਰਨ	aug_selected(ਖਾਲੀ);
ਬਾਹਰੀ ਪੂਰਨ	aug_daemon_session(ਖਾਲੀ);

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_GETTEXT
# define gettext(a)	(a)
#ਜੇ_ਅੰਤ

ਬਾਹਰੀ Authctxt *the_authctxt;
ਸਥਿਰ Audit_Info_ਪਦ_ID ssh_bsm_tid;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BSM_TEXTBUFSZ 256
#ਜੇ_ਅੰਤ

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#ਜੇ defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
ਬਾਹਰੀ ਪੂਰਨ aug_get_machine(ਅੱਖਰ *, uint32_t *, uint32_t *);
#ਨਹੀਂਤਾਂ
ਸਥਿਰ ਪੂਰਨ
aug_get_machine(ਅੱਖਰ *host, uint32_t *addr, uint32_t *type)
{
	ਬਣਤਰ addrinfo *ai; 
	ਬਣਤਰ sockaddr_in *in4;
	ਬਣਤਰ sockaddr_in6 *in6;
	ਪੂਰਨ ret = 0, r;

	ਜੇ ((r = getaddrinfo(host, ਨਿਰਾ, ਨਿਰਾ, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		ਵਾਪਸ -1;
	}
	
	ਚੋਣ (ai->ai_family) {
	ਹਾਲਤ AF_INET:
		in4 = (ਬਣਤਰ sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(addr, &in4->sin_addr, ਆਕਾਰ(ਬਣਤਰ in_addr));
		ਰੋਕੋ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ AU_IPv6
	ਹਾਲਤ AF_INET6: 
		in6 = (ਬਣਤਰ sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(addr, &in6->sin6_addr, ਆਕਾਰ(ਬਣਤਰ in6_addr));
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ
	ਮੂਲ:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
ਪੂਰਨ
getacna(ਅੱਖਰ *auditstring, ਪੂਰਨ len)
{
	scf_handle_t *handle = ਨਿਰਾ;
	scf_property_t *property = ਨਿਰਾ;
	scf_ਮੁੱਲ_t *ਮੁੱਲ = ਨਿਰਾ;
	ਪੂਰਨ ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_ਸੰਸਕਰਣ);
	ਜੇ (handle == ਨਿਰਾ) 
		ਵਾਪਸ -2;

	ret = scf_handle_bind(handle);
	ਜੇ (ret == -1) 
		ਵਾਪਸ -2;

	property = scf_property_create(handle);
	ਜੇ (property == ਨਿਰਾ) 
		ਵਾਪਸ -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, ਨਿਰਾ, property, 0);
	ਜੇ (ret == -1) 
		ਵਾਪਸ -2;

	ਮੁੱਲ = scf_ਮੁੱਲ_create(handle);
	ਜੇ (ਮੁੱਲ == ਨਿਰਾ) 
		ਵਾਪਸ -2;

	ret = scf_property_get_ਮੁੱਲ(property, ਮੁੱਲ);
	ਜੇ (ret == -1) 
		ਵਾਪਸ -2;

	ret = scf_ਮੁੱਲ_get_astring(ਮੁੱਲ, auditstring, len);
	ਜੇ (ret == -1) 
		ਵਾਪਸ -2;

	scf_ਮੁੱਲ_destroy(ਮੁੱਲ);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ਸਥਿਰ ਪੂਰਨ
selected(ਅੱਖਰ *username, uid_t uid, au_event_t event, ਪੂਰਨ sf)
{
	ਪੂਰਨ rc, sorf;
	ਅੱਖਰ naflags[512];
	ਬਣਤਰ au_ਨਕਾਬ ਨਕਾਬ;

	ਨਕਾਬ.am_success = ਨਕਾਬ.am_failure = 0;
	ਜੇ (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, ਆਕਾਰ(naflags));
		ਜੇ (rc == 0)
			(ਖਾਲੀ) getauditflagsbin(naflags, &ਨਕਾਬ);
	} ਨਹੀਂਤਾਂ
		rc = au_user_ਨਕਾਬ(username, &ਨਕਾਬ);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	ਵਾਪਸ(au_preselect(event, &ਨਕਾਬ, sorf, AU_PRS_REREAD));
}

ਸਥਿਰ ਖਾਲੀ
bsm_audit_ਰਿਕਾਰਡ(ਪੂਰਨ typ, ਅੱਖਰ *string, au_event_t event_no)
{
	ਪੂਰਨ		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	Audit_Info_ਪਦ_ID	tid = ssh_bsm_tid;

	ਜੇ (the_authctxt != ਨਿਰਾ && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	ਜੇ (!sel)
		ਵਾਪਸ;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(ਖਾਲੀ) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(ਖਾਲੀ) au_write(ad, au_ਮੰਜ਼ਿਲ_ਪਾਠ(string));
	(ਖਾਲੀ) au_write(ad, AUToReturnFunc(typ, rc));

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_ਮੰਜ਼ਿਲ_WRITE, event_no, 0);
#ਨਹੀਂਤਾਂ
	rc = au_close(ad, AU_ਮੰਜ਼ਿਲ_WRITE, event_no);
#ਜੇ_ਅੰਤ

	ਜੇ (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ਸਥਿਰ ਖਾਲੀ
bsm_audit_session_ਤਿਆਰੀ(ਖਾਲੀ)
{
	ਪੂਰਨ rc;
	ਬਣਤਰ AuditInfoStruct info;
	au_ਨਕਾਬ_t ਨਕਾਬ;

	ਜੇ (the_authctxt == ਨਿਰਾ) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		ਵਾਪਸ;
	}

	ਜੇ (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	ਨਹੀਂਤਾਂ
		info.ai_auid = -1;
	info.ai_asid = getpid();
	ਨਕਾਬ.am_success = 0;
	ਨਕਾਬ.am_failure = 0;

	(ਖਾਲੀ) au_user_ਨਕਾਬ(the_authctxt->user, &ਨਕਾਬ);

	info.ai_ਨਕਾਬ.am_success  = ਨਕਾਬ.am_success;
	info.ai_ਨਕਾਬ.am_failure  = ਨਕਾਬ.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = ਸੈੱਟ_Audit_Func(&info, ਆਕਾਰ(info));
	ਜੇ (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    ਸੈੱਟ_Audit_Func_ਪਾਠ, strerror(errno));
}

ਸਥਿਰ ਖਾਲੀ
bsm_audit_bad_login(ਅਚਲ ਅੱਖਰ *what)
{
	ਅੱਖਰ textbuf[BSM_TEXTBUFSZ];

	ਜੇ (the_authctxt->valid) {
		(ਖਾਲੀ) snprintf(textbuf, ਆਕਾਰ (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_ਰਿਕਾਰਡ(4, textbuf, AUE_openssh);
	} ਨਹੀਂਤਾਂ {
		(ਖਾਲੀ) snprintf(textbuf, ਆਕਾਰ (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_ਰਿਕਾਰਡ(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

ਖਾਲੀ
audit_connection_from(ਅਚਲ ਅੱਖਰ *host, ਪੂਰਨ ਪੋਰਟ)
{
	Audit_Info_ਪਦ_ID *tid = &ssh_bsm_tid;
	ਅੱਖਰ buf[1024];

	ਜੇ (cannot_audit(0))
		ਵਾਪਸ;
	debug3("BSM audit: connection from %.100s port %d", host, ਪੋਰਟ);

	/* populate our terminal id structure */
#ਜੇ defined(HAVE_GETAUDIT_ADDR)
	tid->at_ਪੋਰਟ = (dev_t)ਪੋਰਟ;
	aug_get_machine((ਅੱਖਰ *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, ਆਕਾਰ(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (ਪੂਰਨ)tid->at_type, buf);
#ਨਹੀਂਤਾਂ
	/* this is used on IPv4-only machines */
	tid->ਪੋਰਟ = (dev_t)ਪੋਰਟ;
	tid->machine = inet_addr(host);
	snprintf(buf, ਆਕਾਰ(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
audit_ਲੜੀਵਾਰ_command(ਅਚਲ ਅੱਖਰ *command)
{
	/* not implemented */
}

ਖਾਲੀ
audit_session_open(ਬਣਤਰ logininfo *li)
{
	/* not implemented */
}

ਖਾਲੀ
audit_session_close(ਬਣਤਰ logininfo *li)
{
	/* not implemented */
}

ਖਾਲੀ
audit_event(ਬਣਤਰ ssh *ssh, ssh_audit_event_t event)
{
	ਅੱਖਰ    textbuf[BSM_TEXTBUFSZ];
	ਸਥਿਰ ਪੂਰਨ logged_ਵਿੱਚ = 0;
	ਅਚਲ ਅੱਖਰ *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	ਜੇ (cannot_audit(0))
		ਵਾਪਸ;

	ਚੋਣ(event) {
	ਹਾਲਤ SSH_AUTH_SUCCESS:
		logged_ਵਿੱਚ = 1;
		bsm_audit_session_ਤਿਆਰੀ();
		snprintf(textbuf, ਆਕਾਰ(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_ਰਿਕਾਰਡ(0, textbuf, AUE_openssh);
		ਰੋਕੋ;

	ਹਾਲਤ SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		ਜੇ (logged_ਵਿੱਚ) {
			snprintf(textbuf, ਆਕਾਰ(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_ਰਿਕਾਰਡ(0, textbuf, AUE_logout);
		} ਨਹੀਂਤਾਂ {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		ਰੋਕੋ;

	ਹਾਲਤ SSH_NOLOGIN:
		bsm_audit_ਰਿਕਾਰਡ(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		ਰੋਕੋ;

	ਹਾਲਤ SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, ਆਕਾਰ(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_ਰਿਕਾਰਡ(1, textbuf, AUE_openssh);
		ਰੋਕੋ;

	ਹਾਲਤ SSH_LOGIN_ਜੜ੍ਹ_DENIED:
		bsm_audit_ਰਿਕਾਰਡ(2, gettext("not_console"), AUE_openssh);
		ਰੋਕੋ;

	ਹਾਲਤ SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		ਰੋਕੋ;

	ਹਾਲਤ SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		ਰੋਕੋ;

	ਮੂਲ:
		debug_f("unhandled event %d", event);
	}
}
#ਜੇ_ਅੰਤ /* BSM */
