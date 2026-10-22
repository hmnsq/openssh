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

#अन्तर्भाव "includes.h"
#यदि defined(USE_BSM_AUDIT)

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#यदि_परिभाषितम् BROKEN_BSM_API
#अन्तर्भाव <libscf.h>
#यदि_अन्तः

#अन्तर्भाव "ssh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "xmalloc.h"

#यदि_अपरिभाषितम् AUE_openssh
# define AUE_openssh     32800
#यदि_अन्तः
#अन्तर्भाव <bsm/audit.h>
#अन्तर्भाव <bsm/libbsm.h>
#अन्तर्भाव <bsm/audit_uevents.h>
#अन्तर्भाव <bsm/audit_record.h>
#अन्तर्भाव <locale.h>

#यदि defined(HAVE_GETAUDIT_ADDR)
#परिभाषय	AuditInfoStruct		auditinfo_addr
#परिभाषय Audit_Info_पदांशः_ID		au_tid_addr_t
#परिभाषय समुच्चयः_Audit_Func(a,b)	setaudit_addr((a),(b))
#परिभाषय समुच्चयः_Audit_Func_Text	"setaudit_addr"
#परिभाषय AUToSubjectFunc		au_गन्तव्यम्_subject_ex
#परिभाषय AUToReturnFunc(a,b)	au_गन्तव्यम्_return32((a), (int32_t)(b))
#अन्यथा
#परिभाषय	AuditInfoStruct		auditinfo
#परिभाषय Audit_Info_पदांशः_ID		au_tid_t
#परिभाषय समुच्चयः_Audit_Func(a,b)	setaudit(a)
#परिभाषय समुच्चयः_Audit_Func_Text	"setaudit"
#परिभाषय AUToSubjectFunc		au_गन्तव्यम्_subject
#परिभाषय AUToReturnFunc(a,b)	au_गन्तव्यम्_return((a), (u_int)(b))
#यदि_अन्तः

#यदि_अपरिभाषितम् cannot_audit
बाह्य पूर्णाङ्क	cannot_audit(पूर्णाङ्क);
#यदि_अन्तः
बाह्य शून्य	aug_init(शून्य);
बाह्य शून्य	aug_save_auid(au_id_t);
बाह्य शून्य	aug_save_uid(uid_t);
बाह्य शून्य	aug_save_euid(uid_t);
बाह्य शून्य	aug_save_gid(gid_t);
बाह्य शून्य	aug_save_egid(gid_t);
बाह्य शून्य	aug_save_pid(pid_t);
बाह्य शून्य	aug_save_asid(au_asid_t);
बाह्य शून्य	aug_save_tid(dev_t, अचिह्नित पूर्णाङ्क);
बाह्य शून्य	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
बाह्य पूर्णाङ्क	aug_save_me(शून्य);
बाह्य पूर्णाङ्क	aug_save_namask(शून्य);
बाह्य शून्य	aug_save_event(au_event_t);
बाह्य शून्य	aug_save_sorf(पूर्णाङ्क);
बाह्य शून्य	aug_save_text(वर्ण *);
बाह्य शून्य	aug_save_text1(वर्ण *);
बाह्य शून्य	aug_save_text2(वर्ण *);
बाह्य शून्य	aug_save_na(पूर्णाङ्क);
बाह्य शून्य	aug_save_user(वर्ण *);
बाह्य शून्य	aug_save_मार्गः(वर्ण *);
बाह्य पूर्णाङ्क	aug_save_policy(शून्य);
बाह्य शून्य	aug_save_afunc(पूर्णाङ्क (*)(पूर्णाङ्क));
बाह्य पूर्णाङ्क	aug_audit(शून्य);
बाह्य पूर्णाङ्क	aug_na_selected(शून्य);
बाह्य पूर्णाङ्क	aug_selected(शून्य);
बाह्य पूर्णाङ्क	aug_daemon_session(शून्य);

#यदि_अपरिभाषितम् HAVE_GETTEXT
# define gettext(a)	(a)
#यदि_अन्तः

बाह्य Authctxt *the_authctxt;
स्थिर Audit_Info_पदांशः_ID ssh_bsm_tid;

#यदि_परिभाषितम् BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#परिभाषय BSM_TEXTBUFSZ 256
#यदि_अन्तः

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#यदि defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
बाह्य पूर्णाङ्क aug_get_machine(वर्ण *, uint32_t *, uint32_t *);
#अन्यथा
स्थिर पूर्णाङ्क
aug_get_machine(वर्ण *host, uint32_t *addr, uint32_t *type)
{
	संरचना addrinfo *ai; 
	संरचना sockaddr_in *in4;
	संरचना sockaddr_in6 *in6;
	पूर्णाङ्क ret = 0, r;

	यदि ((r = getaddrinfo(host, रिक्त, रिक्त, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		प्रत्यागम -1;
	}
	
	विकल्प (ai->ai_family) {
	पक्ष AF_INET:
		in4 = (संरचना sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		स्मृतिं_प्रतिलिख(addr, &in4->sin_addr, परिमाण(संरचना in_addr));
		भङ्ग;
#यदि_परिभाषितम् AU_IPv6
	पक्ष AF_INET6: 
		in6 = (संरचना sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		स्मृतिं_प्रतिलिख(addr, &in6->sin6_addr, परिमाण(संरचना in6_addr));
		भङ्ग;
#यदि_अन्तः
	स्वभाव:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	प्रत्यागम ret;
}
#यदि_अन्तः

#यदि_परिभाषितम् BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
पूर्णाङ्क
getacna(वर्ण *auditstring, पूर्णाङ्क len)
{
	scf_handle_t *handle = रिक्त;
	scf_property_t *property = रिक्त;
	scf_मानम्_t *मानम् = रिक्त;
	पूर्णाङ्क ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_संस्करणम्);
	यदि (handle == रिक्त) 
		प्रत्यागम -2;

	ret = scf_handle_bind(handle);
	यदि (ret == -1) 
		प्रत्यागम -2;

	property = scf_property_create(handle);
	यदि (property == रिक्त) 
		प्रत्यागम -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    रिक्त, रिक्त, रिक्त, रिक्त, property, 0);
	यदि (ret == -1) 
		प्रत्यागम -2;

	मानम् = scf_मानम्_create(handle);
	यदि (मानम् == रिक्त) 
		प्रत्यागम -2;

	ret = scf_property_get_मानम्(property, मानम्);
	यदि (ret == -1) 
		प्रत्यागम -2;

	ret = scf_मानम्_get_astring(मानम्, auditstring, len);
	यदि (ret == -1) 
		प्रत्यागम -2;

	scf_मानम्_destroy(मानम्);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	प्रत्यागम 0;
}
#यदि_अन्तः

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
स्थिर पूर्णाङ्क
selected(वर्ण *username, uid_t uid, au_event_t event, पूर्णाङ्क sf)
{
	पूर्णाङ्क rc, sorf;
	वर्ण naflags[512];
	संरचना au_आवरणम् आवरणम्;

	आवरणम्.am_success = आवरणम्.am_failure = 0;
	यदि (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, परिमाण(naflags));
		यदि (rc == 0)
			(शून्य) getauditflagsbin(naflags, &आवरणम्);
	} अन्यथा
		rc = au_user_आवरणम्(username, &आवरणम्);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	प्रत्यागम(au_preselect(event, &आवरणम्, sorf, AU_PRS_REREAD));
}

स्थिर शून्य
bsm_audit_लेखः(पूर्णाङ्क typ, वर्ण *string, au_event_t event_no)
{
	पूर्णाङ्क		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	Audit_Info_पदांशः_ID	tid = ssh_bsm_tid;

	यदि (the_authctxt != रिक्त && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	यदि (!sel)
		प्रत्यागम;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(शून्य) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(शून्य) au_write(ad, au_गन्तव्यम्_text(string));
	(शून्य) au_write(ad, AUToReturnFunc(typ, rc));

#यदि_परिभाषितम् BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_गन्तव्यम्_WRITE, event_no, 0);
#अन्यथा
	rc = au_close(ad, AU_गन्तव्यम्_WRITE, event_no);
#यदि_अन्तः

	यदि (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

स्थिर शून्य
bsm_audit_session_सज्जता(शून्य)
{
	पूर्णाङ्क rc;
	संरचना AuditInfoStruct info;
	au_आवरणम्_t आवरणम्;

	यदि (the_authctxt == रिक्त) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		प्रत्यागम;
	}

	यदि (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	अन्यथा
		info.ai_auid = -1;
	info.ai_asid = getpid();
	आवरणम्.am_success = 0;
	आवरणम्.am_failure = 0;

	(शून्य) au_user_आवरणम्(the_authctxt->user, &आवरणम्);

	info.ai_आवरणम्.am_success  = आवरणम्.am_success;
	info.ai_आवरणम्.am_failure  = आवरणम्.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = समुच्चयः_Audit_Func(&info, परिमाण(info));
	यदि (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    समुच्चयः_Audit_Func_Text, strerror(errno));
}

स्थिर शून्य
bsm_audit_bad_login(ध्रुव वर्ण *what)
{
	वर्ण textbuf[BSM_TEXTBUFSZ];

	यदि (the_authctxt->valid) {
		(शून्य) snprintf(textbuf, परिमाण (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_लेखः(4, textbuf, AUE_openssh);
	} अन्यथा {
		(शून्य) snprintf(textbuf, परिमाण (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_लेखः(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

शून्य
audit_connection_from(ध्रुव वर्ण *host, पूर्णाङ्क पत्तनम्)
{
	Audit_Info_पदांशः_ID *tid = &ssh_bsm_tid;
	वर्ण buf[1024];

	यदि (cannot_audit(0))
		प्रत्यागम;
	debug3("BSM audit: connection from %.100s port %d", host, पत्तनम्);

	/* populate our terminal id structure */
#यदि defined(HAVE_GETAUDIT_ADDR)
	tid->at_पत्तनम् = (dev_t)पत्तनम्;
	aug_get_machine((वर्ण *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, परिमाण(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (पूर्णाङ्क)tid->at_type, buf);
#अन्यथा
	/* this is used on IPv4-only machines */
	tid->पत्तनम् = (dev_t)पत्तनम्;
	tid->machine = inet_addr(host);
	snprintf(buf, परिमाण(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#यदि_अन्तः
}

शून्य
audit_सततम्_command(ध्रुव वर्ण *command)
{
	/* not implemented */
}

शून्य
audit_session_open(संरचना logininfo *li)
{
	/* not implemented */
}

शून्य
audit_session_close(संरचना logininfo *li)
{
	/* not implemented */
}

शून्य
audit_event(संरचना ssh *ssh, ssh_audit_event_t event)
{
	वर्ण    textbuf[BSM_TEXTBUFSZ];
	स्थिर पूर्णाङ्क logged_अन्तर् = 0;
	ध्रुव वर्ण *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	यदि (cannot_audit(0))
		प्रत्यागम;

	विकल्प(event) {
	पक्ष SSH_AUTH_SUCCESS:
		logged_अन्तर् = 1;
		bsm_audit_session_सज्जता();
		snprintf(textbuf, परिमाण(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_लेखः(0, textbuf, AUE_openssh);
		भङ्ग;

	पक्ष SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		यदि (logged_अन्तर्) {
			snprintf(textbuf, परिमाण(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_लेखः(0, textbuf, AUE_logout);
		} अन्यथा {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		भङ्ग;

	पक्ष SSH_NOLOGIN:
		bsm_audit_लेखः(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		भङ्ग;

	पक्ष SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, परिमाण(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_लेखः(1, textbuf, AUE_openssh);
		भङ्ग;

	पक्ष SSH_LOGIN_मूलम्_DENIED:
		bsm_audit_लेखः(2, gettext("not_console"), AUE_openssh);
		भङ्ग;

	पक्ष SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		भङ्ग;

	पक्ष SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		भङ्ग;

	स्वभाव:
		debug_f("unhandled event %d", event);
	}
}
#यदि_अन्तः /* BSM */
