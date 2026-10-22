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
#जर defined(USE_BSM_AUDIT)

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#ifdef BROKEN_BSM_API
#अन्तर्भाव <libscf.h>
#endif

#अन्तर्भाव "ssh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#अन्तर्भाव <bsm/audit.h>
#अन्तर्भाव <bsm/libbsm.h>
#अन्तर्भाव <bsm/audit_uevents.h>
#अन्तर्भाव <bsm/audit_record.h>
#अन्तर्भाव <locale.h>

#जर defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#अन्यथा
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
बाह्य पूर्णांक	cannot_audit(पूर्णांक);
#endif
बाह्य शून्य	aug_init(शून्य);
बाह्य शून्य	aug_save_auid(au_id_t);
बाह्य शून्य	aug_save_uid(uid_t);
बाह्य शून्य	aug_save_euid(uid_t);
बाह्य शून्य	aug_save_gid(gid_t);
बाह्य शून्य	aug_save_egid(gid_t);
बाह्य शून्य	aug_save_pid(pid_t);
बाह्य शून्य	aug_save_asid(au_asid_t);
बाह्य शून्य	aug_save_tid(dev_t, अचिन्हित पूर्णांक);
बाह्य शून्य	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
बाह्य पूर्णांक	aug_save_me(शून्य);
बाह्य पूर्णांक	aug_save_namask(शून्य);
बाह्य शून्य	aug_save_event(au_event_t);
बाह्य शून्य	aug_save_sorf(पूर्णांक);
बाह्य शून्य	aug_save_text(अक्षर *);
बाह्य शून्य	aug_save_text1(अक्षर *);
बाह्य शून्य	aug_save_text2(अक्षर *);
बाह्य शून्य	aug_save_na(पूर्णांक);
बाह्य शून्य	aug_save_user(अक्षर *);
बाह्य शून्य	aug_save_path(अक्षर *);
बाह्य पूर्णांक	aug_save_policy(शून्य);
बाह्य शून्य	aug_save_afunc(पूर्णांक (*)(पूर्णांक));
बाह्य पूर्णांक	aug_audit(शून्य);
बाह्य पूर्णांक	aug_na_selected(शून्य);
बाह्य पूर्णांक	aug_selected(शून्य);
बाह्य पूर्णांक	aug_daemon_session(शून्य);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

बाह्य Authctxt *the_authctxt;
स्थिर AuditInfoTermID ssh_bsm_tid;

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
#जर defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
बाह्य पूर्णांक aug_get_machine(अक्षर *, uint32_t *, uint32_t *);
#अन्यथा
स्थिर पूर्णांक
aug_get_machine(अक्षर *host, uint32_t *addr, uint32_t *type)
{
	संरचना addrinfo *ai; 
	संरचना sockaddr_in *in4;
	संरचना sockaddr_in6 *in6;
	पूर्णांक ret = 0, r;

	जर ((r = getaddrinfo(host, रिक्त, रिक्त, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? म_त्रुटि(त्रुटि_सं) : gai_strerror(r));
		परत -1;
	}
	
	निवड (ai->ai_family) {
	स्थिती AF_INET:
		in4 = (संरचना sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		स_नकल(addr, &in4->sin_addr, आकार(संरचना in_addr));
		थांबा;
#ifdef AU_IPv6
	स्थिती AF_INET6: 
		in6 = (संरचना sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		स_नकल(addr, &in6->sin6_addr, आकार(संरचना in6_addr));
		थांबा;
#endif
	पूर्वनिर्धारित:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	परत ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
पूर्णांक
getacna(अक्षर *auditstring, पूर्णांक len)
{
	scf_handle_t *handle = रिक्त;
	scf_property_t *property = रिक्त;
	scf_मूल्य_t *मूल्य = रिक्त;
	पूर्णांक ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	जर (handle == रिक्त) 
		परत -2;

	ret = scf_handle_bind(handle);
	जर (ret == -1) 
		परत -2;

	property = scf_property_create(handle);
	जर (property == रिक्त) 
		परत -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    रिक्त, रिक्त, रिक्त, रिक्त, property, 0);
	जर (ret == -1) 
		परत -2;

	मूल्य = scf_मूल्य_create(handle);
	जर (मूल्य == रिक्त) 
		परत -2;

	ret = scf_property_get_मूल्य(property, मूल्य);
	जर (ret == -1) 
		परत -2;

	ret = scf_मूल्य_get_astring(मूल्य, auditstring, len);
	जर (ret == -1) 
		परत -2;

	scf_मूल्य_destroy(मूल्य);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	परत 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
स्थिर पूर्णांक
selected(अक्षर *username, uid_t uid, au_event_t event, पूर्णांक sf)
{
	पूर्णांक rc, sorf;
	अक्षर naflags[512];
	संरचना au_mask mask;

	mask.am_success = mask.am_failure = 0;
	जर (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, आकार(naflags));
		जर (rc == 0)
			(शून्य) getauditflagsbin(naflags, &mask);
	} अन्यथा
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	परत(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

स्थिर शून्य
bsm_audit_record(पूर्णांक typ, अक्षर *string, au_event_t event_no)
{
	पूर्णांक		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	जर (the_authctxt != रिक्त && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	जर (!sel)
		परत;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(शून्य) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(शून्य) au_write(ad, au_to_text(string));
	(शून्य) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#अन्यथा
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	जर (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, म_त्रुटि(त्रुटि_सं));
}

स्थिर शून्य
bsm_audit_session_setup(शून्य)
{
	पूर्णांक rc;
	संरचना AuditInfoStruct info;
	au_mask_t mask;

	जर (the_authctxt == रिक्त) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		परत;
	}

	जर (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	अन्यथा
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(शून्य) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, आकार(info));
	जर (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, म_त्रुटि(त्रुटि_सं));
}

स्थिर शून्य
bsm_audit_bad_login(स्थिरांक अक्षर *what)
{
	अक्षर textbuf[BSM_TEXTBUFSZ];

	जर (the_authctxt->valid) {
		(शून्य) snprintf(textbuf, आकार (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} अन्यथा {
		(शून्य) snprintf(textbuf, आकार (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

शून्य
audit_connection_from(स्थिरांक अक्षर *host, पूर्णांक port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	अक्षर buf[1024];

	जर (cannot_audit(0))
		परत;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#जर defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((अक्षर *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, आकार(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (पूर्णांक)tid->at_type, buf);
#अन्यथा
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, आकार(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

शून्य
audit_run_command(स्थिरांक अक्षर *command)
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
	अक्षर    textbuf[BSM_TEXTBUFSZ];
	स्थिर पूर्णांक logged_in = 0;
	स्थिरांक अक्षर *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	जर (cannot_audit(0))
		परत;

	निवड(event) {
	स्थिती SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, आकार(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		थांबा;

	स्थिती SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		जर (logged_in) {
			snprintf(textbuf, आकार(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} अन्यथा {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		थांबा;

	स्थिती SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		थांबा;

	स्थिती SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, आकार(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		थांबा;

	स्थिती SSH_LOGIN_मूळ_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		थांबा;

	स्थिती SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		थांबा;

	स्थिती SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		थांबा;

	पूर्वनिर्धारित:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
