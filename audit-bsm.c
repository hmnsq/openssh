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

#که_تعریف_شوی BROKEN_BSM_API
#ضمن <libscf.h>
#د_که_پای

#ضمن "ssh.h"
#ضمن "log.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "xmalloc.h"

#که_نه_تعریف_شوی AUE_openssh
# define AUE_openssh     32800
#د_که_پای
#ضمن <bsm/audit.h>
#ضمن <bsm/libbsm.h>
#ضمن <bsm/audit_uevents.h>
#ضمن <bsm/audit_record.h>
#ضمن <locale.h>

#إذا defined(HAVE_GETAUDIT_ADDR)
#تعریف_کړه	AuditInfoStruct		auditinfo_addr
#تعریف_کړه Audit_Info_غړی_ID		au_tid_addr_t
#تعریف_کړه سېټ_Audit_Func(a,b)	setaudit_addr((a),(b))
#تعریف_کړه سېټ_Audit_Func_متن	"setaudit_addr"
#تعریف_کړه AUToSubjectFunc		au_منزل_subject_ex
#تعریف_کړه AUToReturnFunc(a,b)	au_منزل_return32((a), (int32_t)(b))
#وإلا
#تعریف_کړه	AuditInfoStruct		auditinfo
#تعریف_کړه Audit_Info_غړی_ID		au_tid_t
#تعریف_کړه سېټ_Audit_Func(a,b)	setaudit(a)
#تعریف_کړه سېټ_Audit_Func_متن	"setaudit"
#تعریف_کړه AUToSubjectFunc		au_منزل_subject
#تعریف_کړه AUToReturnFunc(a,b)	au_منزل_return((a), (u_int)(b))
#د_که_پای

#که_نه_تعریف_شوی cannot_audit
خارجي صحيح	cannot_audit(صحيح);
#د_که_پای
خارجي فراغ	aug_init(فراغ);
خارجي فراغ	aug_save_auid(au_id_t);
خارجي فراغ	aug_save_uid(uid_t);
خارجي فراغ	aug_save_euid(uid_t);
خارجي فراغ	aug_save_gid(gid_t);
خارجي فراغ	aug_save_egid(gid_t);
خارجي فراغ	aug_save_pid(pid_t);
خارجي فراغ	aug_save_asid(au_asid_t);
خارجي فراغ	aug_save_tid(dev_t, بینښه صحيح);
خارجي فراغ	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
خارجي صحيح	aug_save_me(فراغ);
خارجي صحيح	aug_save_namask(فراغ);
خارجي فراغ	aug_save_event(au_event_t);
خارجي فراغ	aug_save_sorf(صحيح);
خارجي فراغ	aug_save_متن(حرف *);
خارجي فراغ	aug_save_text1(حرف *);
خارجي فراغ	aug_save_text2(حرف *);
خارجي فراغ	aug_save_na(صحيح);
خارجي فراغ	aug_save_user(حرف *);
خارجي فراغ	aug_save_لار(حرف *);
خارجي صحيح	aug_save_policy(فراغ);
خارجي فراغ	aug_save_afunc(صحيح (*)(صحيح));
خارجي صحيح	aug_audit(فراغ);
خارجي صحيح	aug_na_selected(فراغ);
خارجي صحيح	aug_selected(فراغ);
خارجي صحيح	aug_daemon_session(فراغ);

#که_نه_تعریف_شوی HAVE_GETTEXT
# define gettext(a)	(a)
#د_که_پای

خارجي Authctxt *the_authctxt;
ساكن Audit_Info_غړی_ID ssh_bsm_tid;

#که_تعریف_شوی BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#تعریف_کړه BSM_TEXTBUFSZ 256
#د_که_پای

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
		حافظه_نقل(addr, &in4->sin_addr, حجم(بنية in_addr));
		اكسر;
#که_تعریف_شوی AU_IPv6
	حالة AF_INET6: 
		in6 = (بنية sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		حافظه_نقل(addr, &in6->sin6_addr, حجم(بنية in6_addr));
		اكسر;
#د_که_پای
	افتراضي:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	أرجع ret;
}
#د_که_پای

#که_تعریف_شوی BROKEN_BSM_API
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
	scf_ارزښت_t *ارزښت = عدم;
	صحيح ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_نسخه);
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

	ارزښت = scf_ارزښت_create(handle);
	إذا (ارزښت == عدم) 
		أرجع -2;

	ret = scf_property_get_ارزښت(property, ارزښت);
	إذا (ret == -1) 
		أرجع -2;

	ret = scf_ارزښت_get_astring(ارزښت, auditstring, len);
	إذا (ret == -1) 
		أرجع -2;

	scf_ارزښت_destroy(ارزښت);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	أرجع 0;
}
#د_که_پای

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ساكن صحيح
selected(حرف *username, uid_t uid, au_event_t event, صحيح sf)
{
	صحيح rc, sorf;
	حرف naflags[512];
	بنية au_ماسک ماسک;

	ماسک.am_success = ماسک.am_failure = 0;
	إذا (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, حجم(naflags));
		إذا (rc == 0)
			(فراغ) getauditflagsbin(naflags, &ماسک);
	} وإلا
		rc = au_user_ماسک(username, &ماسک);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	أرجع(au_preselect(event, &ماسک, sorf, AU_PRS_REREAD));
}

ساكن فراغ
bsm_audit_ریکارډ(صحيح typ, حرف *string, au_event_t event_no)
{
	صحيح		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	Audit_Info_غړی_ID	tid = ssh_bsm_tid;

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
	(فراغ) au_write(ad, au_منزل_متن(string));
	(فراغ) au_write(ad, AUToReturnFunc(typ, rc));

#که_تعریف_شوی BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_منزل_WRITE, event_no, 0);
#وإلا
	rc = au_close(ad, AU_منزل_WRITE, event_no);
#د_که_پای

	إذا (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ساكن فراغ
bsm_audit_session_تیاری(فراغ)
{
	صحيح rc;
	بنية AuditInfoStruct info;
	au_ماسک_t ماسک;

	إذا (the_authctxt == عدم) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		أرجع;
	}

	إذا (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	وإلا
		info.ai_auid = -1;
	info.ai_asid = getpid();
	ماسک.am_success = 0;
	ماسک.am_failure = 0;

	(فراغ) au_user_ماسک(the_authctxt->user, &ماسک);

	info.ai_ماسک.am_success  = ماسک.am_success;
	info.ai_ماسک.am_failure  = ماسک.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = سېټ_Audit_Func(&info, حجم(info));
	إذا (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    سېټ_Audit_Func_متن, strerror(errno));
}

ساكن فراغ
bsm_audit_bad_login(ثابت حرف *what)
{
	حرف textbuf[BSM_TEXTBUFSZ];

	إذا (the_authctxt->valid) {
		(فراغ) snprintf(textbuf, حجم (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_ریکارډ(4, textbuf, AUE_openssh);
	} وإلا {
		(فراغ) snprintf(textbuf, حجم (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_ریکارډ(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

فراغ
audit_connection_from(ثابت حرف *host, صحيح پورټ)
{
	Audit_Info_غړی_ID *tid = &ssh_bsm_tid;
	حرف buf[1024];

	إذا (cannot_audit(0))
		أرجع;
	debug3("BSM audit: connection from %.100s port %d", host, پورټ);

	/* populate our terminal id structure */
#إذا defined(HAVE_GETAUDIT_ADDR)
	tid->at_پورټ = (dev_t)پورټ;
	aug_get_machine((حرف *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, حجم(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (صحيح)tid->at_type, buf);
#وإلا
	/* this is used on IPv4-only machines */
	tid->پورټ = (dev_t)پورټ;
	tid->machine = inet_addr(host);
	snprintf(buf, حجم(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#د_که_پای
}

فراغ
audit_پرلپسې_command(ثابت حرف *command)
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
	ساكن صحيح logged_دننه = 0;
	ثابت حرف *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	إذا (cannot_audit(0))
		أرجع;

	بدل(event) {
	حالة SSH_AUTH_SUCCESS:
		logged_دننه = 1;
		bsm_audit_session_تیاری();
		snprintf(textbuf, حجم(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_ریکارډ(0, textbuf, AUE_openssh);
		اكسر;

	حالة SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		إذا (logged_دننه) {
			snprintf(textbuf, حجم(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_ریکارډ(0, textbuf, AUE_logout);
		} وإلا {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		اكسر;

	حالة SSH_NOLOGIN:
		bsm_audit_ریکارډ(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		اكسر;

	حالة SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, حجم(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_ریکارډ(1, textbuf, AUE_openssh);
		اكسر;

	حالة SSH_LOGIN_ریښه_DENIED:
		bsm_audit_ریکارډ(2, gettext("not_console"), AUE_openssh);
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
#د_که_پای /* BSM */
