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

#ضمن "includes.h"
#إذا defined(USE_BSM_AUDIT)

#ضمن <sys/types.h>

#ضمن <errno.h>
#ضمن <netdb.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ifdef BROKEN_BSM_API
#ضمن <libscf.h>
#endif

#ضمن "ssh.h"
#ضمن "log.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#ضمن <bsm/audit.h>
#ضمن <bsm/libbsm.h>
#ضمن <bsm/audit_uevents.h>
#ضمن <bsm/audit_record.h>
#ضمن <locale.h>

#إذا defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#وإلا
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
خارجي صحيح	cannot_audit(صحيح);
#endif
خارجي فراغ	aug_init(فراغ);
خارجي فراغ	aug_save_auid(au_id_t);
خارجي فراغ	aug_save_uid(uid_t);
خارجي فراغ	aug_save_euid(uid_t);
خارجي فراغ	aug_save_gid(gid_t);
خارجي فراغ	aug_save_egid(gid_t);
خارجي فراغ	aug_save_pid(pid_t);
خارجي فراغ	aug_save_asid(au_asid_t);
خارجي فراغ	aug_save_tid(dev_t, unsigned صحيح);
خارجي فراغ	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
خارجي صحيح	aug_save_me(فراغ);
خارجي صحيح	aug_save_namask(فراغ);
خارجي فراغ	aug_save_event(au_event_t);
خارجي فراغ	aug_save_sorf(صحيح);
خارجي فراغ	aug_save_text(حرف *);
خارجي فراغ	aug_save_text1(حرف *);
خارجي فراغ	aug_save_text2(حرف *);
خارجي فراغ	aug_save_na(صحيح);
خارجي فراغ	aug_save_user(حرف *);
خارجي فراغ	aug_save_path(حرف *);
خارجي صحيح	aug_save_policy(فراغ);
خارجي فراغ	aug_save_afunc(صحيح (*)(صحيح));
خارجي صحيح	aug_audit(فراغ);
خارجي صحيح	aug_na_selected(فراغ);
خارجي صحيح	aug_selected(فراغ);
خارجي صحيح	aug_daemon_session(فراغ);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

خارجي Authctxt *the_authctxt;
ساكن AuditInfoTermID ssh_bsm_tid;

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
#إذا defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
خارجي صحيح aug_get_machine(حرف *, uint32_t *, uint32_t *);
#وإلا
ساكن صحيح
aug_get_machine(حرف *host, uint32_t *addr, uint32_t *type)
{
	بنية addrinfo *ai; 
	بنية sockaddr_in *in4;
	بنية sockaddr_in6 *in6;
	صحيح ret = 0, r;

	إذا ((r = getaddrinfo(host, عدم, عدم, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		أرجع -1;
	}
	
	بدل (ai->ai_family) {
	حالة AF_INET:
		in4 = (بنية sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, حجم(بنية in_addr));
		اكسر;
#ifdef AU_IPv6
	حالة AF_INET6: 
		in6 = (بنية sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, حجم(بنية in6_addr));
		اكسر;
#endif
	افتراضي:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	أرجع ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
صحيح
getacna(حرف *auditstring, صحيح len)
{
	scf_handle_t *handle = عدم;
	scf_property_t *property = عدم;
	scf_قدر_t *قدر = عدم;
	صحيح ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	إذا (handle == عدم) 
		أرجع -2;

	ret = scf_handle_bind(handle);
	إذا (ret == -1) 
		أرجع -2;

	property = scf_property_create(handle);
	إذا (property == عدم) 
		أرجع -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    عدم, عدم, عدم, عدم, property, 0);
	إذا (ret == -1) 
		أرجع -2;

	قدر = scf_قدر_create(handle);
	إذا (قدر == عدم) 
		أرجع -2;

	ret = scf_property_get_قدر(property, قدر);
	إذا (ret == -1) 
		أرجع -2;

	ret = scf_قدر_get_astring(قدر, auditstring, len);
	إذا (ret == -1) 
		أرجع -2;

	scf_قدر_destroy(قدر);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	أرجع 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ساكن صحيح
selected(حرف *username, uid_t uid, au_event_t event, صحيح sf)
{
	صحيح rc, sorf;
	حرف naflags[512];
	بنية au_mask mask;

	mask.am_success = mask.am_failure = 0;
	إذا (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, حجم(naflags));
		إذا (rc == 0)
			(فراغ) getauditflagsbin(naflags, &mask);
	} وإلا
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	أرجع(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

ساكن فراغ
bsm_audit_record(صحيح typ, حرف *string, au_event_t event_no)
{
	صحيح		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	إذا (the_authctxt != عدم && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	إذا (!sel)
		أرجع;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(فراغ) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(فراغ) au_write(ad, au_to_text(string));
	(فراغ) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#وإلا
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	إذا (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ساكن فراغ
bsm_audit_session_setup(فراغ)
{
	صحيح rc;
	بنية AuditInfoStruct info;
	au_mask_t mask;

	إذا (the_authctxt == عدم) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		أرجع;
	}

	إذا (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	وإلا
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(فراغ) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, حجم(info));
	إذا (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

ساكن فراغ
bsm_audit_bad_login(ثابت حرف *what)
{
	حرف textbuf[BSM_TEXTBUFSZ];

	إذا (the_authctxt->valid) {
		(فراغ) snprintf(textbuf, حجم (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} وإلا {
		(فراغ) snprintf(textbuf, حجم (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

فراغ
audit_connection_from(ثابت حرف *host, صحيح port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	حرف buf[1024];

	إذا (cannot_audit(0))
		أرجع;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#إذا defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((حرف *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, حجم(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (صحيح)tid->at_type, buf);
#وإلا
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, حجم(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

فراغ
audit_run_command(ثابت حرف *command)
{
	/* not implemented */
}

فراغ
audit_session_open(بنية logininfo *li)
{
	/* not implemented */
}

فراغ
audit_session_close(بنية logininfo *li)
{
	/* not implemented */
}

فراغ
audit_event(بنية ssh *ssh, ssh_audit_event_t event)
{
	حرف    textbuf[BSM_TEXTBUFSZ];
	ساكن صحيح logged_in = 0;
	ثابت حرف *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	إذا (cannot_audit(0))
		أرجع;

	بدل(event) {
	حالة SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, حجم(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		اكسر;

	حالة SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		إذا (logged_in) {
			snprintf(textbuf, حجم(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} وإلا {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		اكسر;

	حالة SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		اكسر;

	حالة SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, حجم(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		اكسر;

	حالة SSH_LOGIN_جڑ_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		اكسر;

	حالة SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		اكسر;

	حالة SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		اكسر;

	افتراضي:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
