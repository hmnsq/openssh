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

#অন্তর্ভাব "includes.h"
#যদি defined(USE_BSM_AUDIT)

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef BROKEN_BSM_API
#অন্তর্ভাব <libscf.h>
#endif

#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#অন্তর্ভাব <bsm/audit.h>
#অন্তর্ভাব <bsm/libbsm.h>
#অন্তর্ভাব <bsm/audit_uevents.h>
#অন্তর্ভাব <bsm/audit_record.h>
#অন্তর্ভাব <locale.h>

#যদি defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#অন্যথা
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
বাহ্যিক পূর্ণসংখ্যা	cannot_audit(পূর্ণসংখ্যা);
#endif
বাহ্যিক শূন্য	aug_init(শূন্য);
বাহ্যিক শূন্য	aug_save_auid(au_id_t);
বাহ্যিক শূন্য	aug_save_uid(uid_t);
বাহ্যিক শূন্য	aug_save_euid(uid_t);
বাহ্যিক শূন্য	aug_save_gid(gid_t);
বাহ্যিক শূন্য	aug_save_egid(gid_t);
বাহ্যিক শূন্য	aug_save_pid(pid_t);
বাহ্যিক শূন্য	aug_save_asid(au_asid_t);
বাহ্যিক শূন্য	aug_save_tid(dev_t, unsigned পূর্ণসংখ্যা);
বাহ্যিক শূন্য	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
বাহ্যিক পূর্ণসংখ্যা	aug_save_me(শূন্য);
বাহ্যিক পূর্ণসংখ্যা	aug_save_namask(শূন্য);
বাহ্যিক শূন্য	aug_save_event(au_event_t);
বাহ্যিক শূন্য	aug_save_sorf(পূর্ণসংখ্যা);
বাহ্যিক শূন্য	aug_save_text(অক্ষর *);
বাহ্যিক শূন্য	aug_save_text1(অক্ষর *);
বাহ্যিক শূন্য	aug_save_text2(অক্ষর *);
বাহ্যিক শূন্য	aug_save_na(পূর্ণসংখ্যা);
বাহ্যিক শূন্য	aug_save_user(অক্ষর *);
বাহ্যিক শূন্য	aug_save_path(অক্ষর *);
বাহ্যিক পূর্ণসংখ্যা	aug_save_policy(শূন্য);
বাহ্যিক শূন্য	aug_save_afunc(পূর্ণসংখ্যা (*)(পূর্ণসংখ্যা));
বাহ্যিক পূর্ণসংখ্যা	aug_audit(শূন্য);
বাহ্যিক পূর্ণসংখ্যা	aug_na_selected(শূন্য);
বাহ্যিক পূর্ণসংখ্যা	aug_selected(শূন্য);
বাহ্যিক পূর্ণসংখ্যা	aug_daemon_session(শূন্য);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

বাহ্যিক Authctxt *the_authctxt;
স্থির AuditInfoTermID ssh_bsm_tid;

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
#যদি defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
বাহ্যিক পূর্ণসংখ্যা aug_get_machine(অক্ষর *, uint32_t *, uint32_t *);
#অন্যথা
স্থির পূর্ণসংখ্যা
aug_get_machine(অক্ষর *host, uint32_t *addr, uint32_t *type)
{
	কাঠামো addrinfo *ai; 
	কাঠামো sockaddr_in *in4;
	কাঠামো sockaddr_in6 *in6;
	পূর্ণসংখ্যা ret = 0, r;

	যদি ((r = getaddrinfo(host, ফাঁকা, ফাঁকা, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		ফেরত -1;
	}
	
	নির্বাচন (ai->ai_family) {
	ক্ষেত্র AF_INET:
		in4 = (কাঠামো sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, আকার(কাঠামো in_addr));
		বিরতি;
#ifdef AU_IPv6
	ক্ষেত্র AF_INET6: 
		in6 = (কাঠামো sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, আকার(কাঠামো in6_addr));
		বিরতি;
#endif
	পূর্বনির্ধারিত:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	ফেরত ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
পূর্ণসংখ্যা
getacna(অক্ষর *auditstring, পূর্ণসংখ্যা len)
{
	scf_handle_t *handle = ফাঁকা;
	scf_property_t *property = ফাঁকা;
	scf_মান_t *মান = ফাঁকা;
	পূর্ণসংখ্যা ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	যদি (handle == ফাঁকা) 
		ফেরত -2;

	ret = scf_handle_bind(handle);
	যদি (ret == -1) 
		ফেরত -2;

	property = scf_property_create(handle);
	যদি (property == ফাঁকা) 
		ফেরত -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ফাঁকা, ফাঁকা, ফাঁকা, ফাঁকা, property, 0);
	যদি (ret == -1) 
		ফেরত -2;

	মান = scf_মান_create(handle);
	যদি (মান == ফাঁকা) 
		ফেরত -2;

	ret = scf_property_get_মান(property, মান);
	যদি (ret == -1) 
		ফেরত -2;

	ret = scf_মান_get_astring(মান, auditstring, len);
	যদি (ret == -1) 
		ফেরত -2;

	scf_মান_destroy(মান);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	ফেরত 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
স্থির পূর্ণসংখ্যা
selected(অক্ষর *username, uid_t uid, au_event_t event, পূর্ণসংখ্যা sf)
{
	পূর্ণসংখ্যা rc, sorf;
	অক্ষর naflags[512];
	কাঠামো au_mask mask;

	mask.am_success = mask.am_failure = 0;
	যদি (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, আকার(naflags));
		যদি (rc == 0)
			(শূন্য) getauditflagsbin(naflags, &mask);
	} অন্যথা
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	ফেরত(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

স্থির শূন্য
bsm_audit_record(পূর্ণসংখ্যা typ, অক্ষর *string, au_event_t event_no)
{
	পূর্ণসংখ্যা		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	যদি (the_authctxt != ফাঁকা && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	যদি (!sel)
		ফেরত;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(শূন্য) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(শূন্য) au_write(ad, au_to_text(string));
	(শূন্য) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#অন্যথা
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	যদি (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

স্থির শূন্য
bsm_audit_session_setup(শূন্য)
{
	পূর্ণসংখ্যা rc;
	কাঠামো AuditInfoStruct info;
	au_mask_t mask;

	যদি (the_authctxt == ফাঁকা) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		ফেরত;
	}

	যদি (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	অন্যথা
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(শূন্য) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, আকার(info));
	যদি (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

স্থির শূন্য
bsm_audit_bad_login(ধ্রুবক অক্ষর *what)
{
	অক্ষর textbuf[BSM_TEXTBUFSZ];

	যদি (the_authctxt->valid) {
		(শূন্য) snprintf(textbuf, আকার (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} অন্যথা {
		(শূন্য) snprintf(textbuf, আকার (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

শূন্য
audit_connection_from(ধ্রুবক অক্ষর *host, পূর্ণসংখ্যা port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	অক্ষর buf[1024];

	যদি (cannot_audit(0))
		ফেরত;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#যদি defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((অক্ষর *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, আকার(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (পূর্ণসংখ্যা)tid->at_type, buf);
#অন্যথা
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, আকার(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

শূন্য
audit_run_command(ধ্রুবক অক্ষর *command)
{
	/* not implemented */
}

শূন্য
audit_session_open(কাঠামো logininfo *li)
{
	/* not implemented */
}

শূন্য
audit_session_close(কাঠামো logininfo *li)
{
	/* not implemented */
}

শূন্য
audit_event(কাঠামো ssh *ssh, ssh_audit_event_t event)
{
	অক্ষর    textbuf[BSM_TEXTBUFSZ];
	স্থির পূর্ণসংখ্যা logged_in = 0;
	ধ্রুবক অক্ষর *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	যদি (cannot_audit(0))
		ফেরত;

	নির্বাচন(event) {
	ক্ষেত্র SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, আকার(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		বিরতি;

	ক্ষেত্র SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		যদি (logged_in) {
			snprintf(textbuf, আকার(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} অন্যথা {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		বিরতি;

	ক্ষেত্র SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		বিরতি;

	ক্ষেত্র SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, আকার(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		বিরতি;

	ক্ষেত্র SSH_LOGIN_মূল_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		বিরতি;

	ক্ষেত্র SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		বিরতি;

	ক্ষেত্র SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		বিরতি;

	পূর্বনির্ধারিত:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
