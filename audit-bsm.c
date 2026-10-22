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

#समावेश "includes.h"
#अगर defined(USE_BSM_AUDIT)

#समावेश <sys/types.h>

#समावेश <errno.h>
#समावेश <netdb.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित BROKEN_BSM_API
#समावेश <libscf.h>
#पूर्ण_अगर

#समावेश "ssh.h"
#समावेश "log.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "xmalloc.h"

#अगर_अघोषित AUE_openssh
# define AUE_openssh     32800
#पूर्ण_अगर
#समावेश <bsm/audit.h>
#समावेश <bsm/libbsm.h>
#समावेश <bsm/audit_uevents.h>
#समावेश <bsm/audit_record.h>
#समावेश <locale.h>

#अगर defined(HAVE_GETAUDIT_ADDR)
#घोषणा	AuditInfoStruct		auditinfo_addr
#घोषणा AuditInfoTermID		au_tid_addr_t
#घोषणा SetAuditFunc(a,b)	setaudit_addr((a),(b))
#घोषणा SetAuditFuncText	"setaudit_addr"
#घोषणा AUToSubjectFunc		au_to_subject_ex
#घोषणा AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#अन्यथा
#घोषणा	AuditInfoStruct		auditinfo
#घोषणा AuditInfoTermID		au_tid_t
#घोषणा SetAuditFunc(a,b)	setaudit(a)
#घोषणा SetAuditFuncText	"setaudit"
#घोषणा AUToSubjectFunc		au_to_subject
#घोषणा AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#पूर्ण_अगर

#अगर_अघोषित cannot_audit
बाह्य पूर्णांक	cannot_audit(पूर्णांक);
#पूर्ण_अगर
बाह्य व्योम	aug_init(व्योम);
बाह्य व्योम	aug_save_auid(au_id_t);
बाह्य व्योम	aug_save_uid(uid_t);
बाह्य व्योम	aug_save_euid(uid_t);
बाह्य व्योम	aug_save_gid(gid_t);
बाह्य व्योम	aug_save_egid(gid_t);
बाह्य व्योम	aug_save_pid(pid_t);
बाह्य व्योम	aug_save_asid(au_asid_t);
बाह्य व्योम	aug_save_tid(dev_t, अचिन्हित पूर्णांक);
बाह्य व्योम	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
बाह्य पूर्णांक	aug_save_me(व्योम);
बाह्य पूर्णांक	aug_save_namask(व्योम);
बाह्य व्योम	aug_save_event(au_event_t);
बाह्य व्योम	aug_save_sorf(पूर्णांक);
बाह्य व्योम	aug_save_text(अक्षर *);
बाह्य व्योम	aug_save_text1(अक्षर *);
बाह्य व्योम	aug_save_text2(अक्षर *);
बाह्य व्योम	aug_save_na(पूर्णांक);
बाह्य व्योम	aug_save_user(अक्षर *);
बाह्य व्योम	aug_save_path(अक्षर *);
बाह्य पूर्णांक	aug_save_policy(व्योम);
बाह्य व्योम	aug_save_afunc(पूर्णांक (*)(पूर्णांक));
बाह्य पूर्णांक	aug_audit(व्योम);
बाह्य पूर्णांक	aug_na_selected(व्योम);
बाह्य पूर्णांक	aug_selected(व्योम);
बाह्य पूर्णांक	aug_daemon_session(व्योम);

#अगर_अघोषित HAVE_GETTEXT
# define gettext(a)	(a)
#पूर्ण_अगर

बाह्य Authctxt *the_authctxt;
अटल AuditInfoTermID ssh_bsm_tid;

#अगर_घोषित BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#घोषणा BSM_TEXTBUFSZ 256
#पूर्ण_अगर

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#अगर defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
बाह्य पूर्णांक aug_get_machine(अक्षर *, uint32_t *, uint32_t *);
#अन्यथा
अटल पूर्णांक
aug_get_machine(अक्षर *host, uint32_t *addr, uint32_t *type)
{
	काष्ठा addrinfo *ai; 
	काष्ठा sockaddr_in *in4;
	काष्ठा sockaddr_in6 *in6;
	पूर्णांक ret = 0, r;

	अगर ((r = getaddrinfo(host, शून्य, शून्य, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? म_त्रुटि(त्रुटि_सं) : gai_strerror(r));
		वापस -1;
	}
	
	चयन (ai->ai_family) {
	हाल AF_INET:
		in4 = (काष्ठा sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		स_नकल(addr, &in4->sin_addr, माप(काष्ठा in_addr));
		अवरोध;
#अगर_घोषित AU_IPv6
	हाल AF_INET6: 
		in6 = (काष्ठा sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		स_नकल(addr, &in6->sin6_addr, माप(काष्ठा in6_addr));
		अवरोध;
#पूर्ण_अगर
	शेष:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	वापस ret;
}
#पूर्ण_अगर

#अगर_घोषित BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
पूर्णांक
getacna(अक्षर *auditstring, पूर्णांक len)
{
	scf_handle_t *handle = शून्य;
	scf_property_t *property = शून्य;
	scf_मूल्य_t *मूल्य = शून्य;
	पूर्णांक ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	अगर (handle == शून्य) 
		वापस -2;

	ret = scf_handle_bind(handle);
	अगर (ret == -1) 
		वापस -2;

	property = scf_property_create(handle);
	अगर (property == शून्य) 
		वापस -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    शून्य, शून्य, शून्य, शून्य, property, 0);
	अगर (ret == -1) 
		वापस -2;

	मूल्य = scf_मूल्य_create(handle);
	अगर (मूल्य == शून्य) 
		वापस -2;

	ret = scf_property_get_मूल्य(property, मूल्य);
	अगर (ret == -1) 
		वापस -2;

	ret = scf_मूल्य_get_astring(मूल्य, auditstring, len);
	अगर (ret == -1) 
		वापस -2;

	scf_मूल्य_destroy(मूल्य);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	वापस 0;
}
#पूर्ण_अगर

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
अटल पूर्णांक
selected(अक्षर *username, uid_t uid, au_event_t event, पूर्णांक sf)
{
	पूर्णांक rc, sorf;
	अक्षर naflags[512];
	काष्ठा au_mask mask;

	mask.am_success = mask.am_failure = 0;
	अगर (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, माप(naflags));
		अगर (rc == 0)
			(व्योम) getauditflagsbin(naflags, &mask);
	} अन्यथा
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	वापस(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

अटल व्योम
bsm_audit_record(पूर्णांक typ, अक्षर *string, au_event_t event_no)
{
	पूर्णांक		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	अगर (the_authctxt != शून्य && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	अगर (!sel)
		वापस;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(व्योम) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(व्योम) au_write(ad, au_to_text(string));
	(व्योम) au_write(ad, AUToReturnFunc(typ, rc));

#अगर_घोषित BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#अन्यथा
	rc = au_close(ad, AU_TO_WRITE, event_no);
#पूर्ण_अगर

	अगर (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, म_त्रुटि(त्रुटि_सं));
}

अटल व्योम
bsm_audit_session_setup(व्योम)
{
	पूर्णांक rc;
	काष्ठा AuditInfoStruct info;
	au_mask_t mask;

	अगर (the_authctxt == शून्य) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		वापस;
	}

	अगर (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	अन्यथा
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(व्योम) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, माप(info));
	अगर (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, म_त्रुटि(त्रुटि_सं));
}

अटल व्योम
bsm_audit_bad_login(स्थिर अक्षर *what)
{
	अक्षर textbuf[BSM_TEXTBUFSZ];

	अगर (the_authctxt->valid) {
		(व्योम) snprintf(textbuf, माप (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} अन्यथा {
		(व्योम) snprintf(textbuf, माप (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

व्योम
audit_connection_from(स्थिर अक्षर *host, पूर्णांक port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	अक्षर buf[1024];

	अगर (cannot_audit(0))
		वापस;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#अगर defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((अक्षर *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, माप(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (पूर्णांक)tid->at_type, buf);
#अन्यथा
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, माप(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#पूर्ण_अगर
}

व्योम
audit_run_command(स्थिर अक्षर *command)
{
	/* not implemented */
}

व्योम
audit_session_open(काष्ठा logininfo *li)
{
	/* not implemented */
}

व्योम
audit_session_close(काष्ठा logininfo *li)
{
	/* not implemented */
}

व्योम
audit_event(काष्ठा ssh *ssh, ssh_audit_event_t event)
{
	अक्षर    textbuf[BSM_TEXTBUFSZ];
	अटल पूर्णांक logged_in = 0;
	स्थिर अक्षर *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	अगर (cannot_audit(0))
		वापस;

	चयन(event) {
	हाल SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, माप(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		अवरोध;

	हाल SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		अगर (logged_in) {
			snprintf(textbuf, माप(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} अन्यथा {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		अवरोध;

	हाल SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		अवरोध;

	हाल SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, माप(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		अवरोध;

	हाल SSH_LOGIN_मूल_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		अवरोध;

	हाल SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		अवरोध;

	हाल SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		अवरोध;

	शेष:
		debug_f("unhandled event %d", event);
	}
}
#पूर्ण_अगर /* BSM */
