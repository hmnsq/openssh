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

#شامل "includes.h"
#اگر defined(USE_BSM_AUDIT)

#شامل <sys/types.h>

#شامل <errno.h>
#شامل <netdb.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>

#ifdef BROKEN_BSM_API
#شامل <libscf.h>
#endif

#شامل "ssh.h"
#شامل "log.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#شامل <bsm/audit.h>
#شامل <bsm/libbsm.h>
#شامل <bsm/audit_uevents.h>
#شامل <bsm/audit_record.h>
#شامل <locale.h>

#اگر defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#وگرنه
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
بیرونی صحیح	cannot_audit(صحیح);
#endif
بیرونی تهی	aug_init(تهی);
بیرونی تهی	aug_save_auid(au_id_t);
بیرونی تهی	aug_save_uid(uid_t);
بیرونی تهی	aug_save_euid(uid_t);
بیرونی تهی	aug_save_gid(gid_t);
بیرونی تهی	aug_save_egid(gid_t);
بیرونی تهی	aug_save_pid(pid_t);
بیرونی تهی	aug_save_asid(au_asid_t);
بیرونی تهی	aug_save_tid(dev_t, unsigned صحیح);
بیرونی تهی	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
بیرونی صحیح	aug_save_me(تهی);
بیرونی صحیح	aug_save_namask(تهی);
بیرونی تهی	aug_save_event(au_event_t);
بیرونی تهی	aug_save_sorf(صحیح);
بیرونی تهی	aug_save_text(نویسه *);
بیرونی تهی	aug_save_text1(نویسه *);
بیرونی تهی	aug_save_text2(نویسه *);
بیرونی تهی	aug_save_na(صحیح);
بیرونی تهی	aug_save_user(نویسه *);
بیرونی تهی	aug_save_path(نویسه *);
بیرونی صحیح	aug_save_policy(تهی);
بیرونی تهی	aug_save_afunc(صحیح (*)(صحیح));
بیرونی صحیح	aug_audit(تهی);
بیرونی صحیح	aug_na_selected(تهی);
بیرونی صحیح	aug_selected(تهی);
بیرونی صحیح	aug_daemon_session(تهی);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

بیرونی Authctxt *the_authctxt;
ایستا AuditInfoTermID ssh_bsm_tid;

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
#اگر defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
بیرونی صحیح aug_get_machine(نویسه *, uint32_t *, uint32_t *);
#وگرنه
ایستا صحیح
aug_get_machine(نویسه *host, uint32_t *addr, uint32_t *type)
{
	ساختار addrinfo *ai; 
	ساختار sockaddr_in *in4;
	ساختار sockaddr_in6 *in6;
	صحیح ret = 0, r;

	اگر ((r = getaddrinfo(host, پوچ, پوچ, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		بازگشت -1;
	}
	
	انتخاب (ai->ai_family) {
	حالت AF_INET:
		in4 = (ساختار sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, اندازه(ساختار in_addr));
		بشکن;
#ifdef AU_IPv6
	حالت AF_INET6: 
		in6 = (ساختار sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, اندازه(ساختار in6_addr));
		بشکن;
#endif
	پیشفرض:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	بازگشت ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
صحیح
getacna(نویسه *auditstring, صحیح len)
{
	scf_handle_t *handle = پوچ;
	scf_property_t *property = پوچ;
	scf_مقدار_t *مقدار = پوچ;
	صحیح ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	اگر (handle == پوچ) 
		بازگشت -2;

	ret = scf_handle_bind(handle);
	اگر (ret == -1) 
		بازگشت -2;

	property = scf_property_create(handle);
	اگر (property == پوچ) 
		بازگشت -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    پوچ, پوچ, پوچ, پوچ, property, 0);
	اگر (ret == -1) 
		بازگشت -2;

	مقدار = scf_مقدار_create(handle);
	اگر (مقدار == پوچ) 
		بازگشت -2;

	ret = scf_property_get_مقدار(property, مقدار);
	اگر (ret == -1) 
		بازگشت -2;

	ret = scf_مقدار_get_astring(مقدار, auditstring, len);
	اگر (ret == -1) 
		بازگشت -2;

	scf_مقدار_destroy(مقدار);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	بازگشت 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ایستا صحیح
selected(نویسه *username, uid_t uid, au_event_t event, صحیح sf)
{
	صحیح rc, sorf;
	نویسه naflags[512];
	ساختار au_mask mask;

	mask.am_success = mask.am_failure = 0;
	اگر (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, اندازه(naflags));
		اگر (rc == 0)
			(تهی) getauditflagsbin(naflags, &mask);
	} وگرنه
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	بازگشت(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

ایستا تهی
bsm_audit_record(صحیح typ, نویسه *string, au_event_t event_no)
{
	صحیح		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	اگر (the_authctxt != پوچ && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	اگر (!sel)
		بازگشت;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(تهی) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(تهی) au_write(ad, au_to_text(string));
	(تهی) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#وگرنه
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	اگر (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ایستا تهی
bsm_audit_session_setup(تهی)
{
	صحیح rc;
	ساختار AuditInfoStruct info;
	au_mask_t mask;

	اگر (the_authctxt == پوچ) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		بازگشت;
	}

	اگر (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	وگرنه
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(تهی) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, اندازه(info));
	اگر (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

ایستا تهی
bsm_audit_bad_login(ثابت نویسه *what)
{
	نویسه textbuf[BSM_TEXTBUFSZ];

	اگر (the_authctxt->valid) {
		(تهی) snprintf(textbuf, اندازه (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} وگرنه {
		(تهی) snprintf(textbuf, اندازه (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

تهی
audit_connection_from(ثابت نویسه *host, صحیح port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	نویسه buf[1024];

	اگر (cannot_audit(0))
		بازگشت;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#اگر defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((نویسه *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, اندازه(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (صحیح)tid->at_type, buf);
#وگرنه
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, اندازه(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

تهی
audit_run_command(ثابت نویسه *command)
{
	/* not implemented */
}

تهی
audit_session_open(ساختار logininfo *li)
{
	/* not implemented */
}

تهی
audit_session_close(ساختار logininfo *li)
{
	/* not implemented */
}

تهی
audit_event(ساختار ssh *ssh, ssh_audit_event_t event)
{
	نویسه    textbuf[BSM_TEXTBUFSZ];
	ایستا صحیح logged_in = 0;
	ثابت نویسه *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	اگر (cannot_audit(0))
		بازگشت;

	انتخاب(event) {
	حالت SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, اندازه(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		بشکن;

	حالت SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		اگر (logged_in) {
			snprintf(textbuf, اندازه(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} وگرنه {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		بشکن;

	حالت SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		بشکن;

	حالت SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, اندازه(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		بشکن;

	حالت SSH_LOGIN_ریشه_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		بشکن;

	حالت SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		بشکن;

	حالت SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		بشکن;

	پیشفرض:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
