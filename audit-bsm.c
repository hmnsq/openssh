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

#اگر_تعریف_شدہ BROKEN_BSM_API
#شامل <libscf.h>
#اگر_ختم

#شامل "ssh.h"
#شامل "log.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "xmalloc.h"

#اگر_غیر_تعریف_شدہ AUE_openssh
# define AUE_openssh     32800
#اگر_ختم
#شامل <bsm/audit.h>
#شامل <bsm/libbsm.h>
#شامل <bsm/audit_uevents.h>
#شامل <bsm/audit_record.h>
#شامل <locale.h>

#اگر defined(HAVE_GETAUDIT_ADDR)
#تعریف_کرو	AuditInfoStruct		auditinfo_addr
#تعریف_کرو Audit_Info_رکن_ID		au_tid_addr_t
#تعریف_کرو سیٹ_Audit_Func(a,b)	setaudit_addr((a),(b))
#تعریف_کرو سیٹ_Audit_Func_متن	"setaudit_addr"
#تعریف_کرو AUToSubjectFunc		au_مقصد_subject_ex
#تعریف_کرو AUToReturnFunc(a,b)	au_مقصد_return32((a), (int32_t)(b))
#ورنہ
#تعریف_کرو	AuditInfoStruct		auditinfo
#تعریف_کرو Audit_Info_رکن_ID		au_tid_t
#تعریف_کرو سیٹ_Audit_Func(a,b)	setaudit(a)
#تعریف_کرو سیٹ_Audit_Func_متن	"setaudit"
#تعریف_کرو AUToSubjectFunc		au_مقصد_subject
#تعریف_کرو AUToReturnFunc(a,b)	au_مقصد_return((a), (u_int)(b))
#اگر_ختم

#اگر_غیر_تعریف_شدہ cannot_audit
خارجی صحیح	cannot_audit(صحیح);
#اگر_ختم
خارجی خالی	aug_init(خالی);
خارجی خالی	aug_save_auid(au_id_t);
خارجی خالی	aug_save_uid(uid_t);
خارجی خالی	aug_save_euid(uid_t);
خارجی خالی	aug_save_gid(gid_t);
خارجی خالی	aug_save_egid(gid_t);
خارجی خالی	aug_save_pid(pid_t);
خارجی خالی	aug_save_asid(au_asid_t);
خارجی خالی	aug_save_tid(dev_t, غیرعلامتی صحیح);
خارجی خالی	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
خارجی صحیح	aug_save_me(خالی);
خارجی صحیح	aug_save_namask(خالی);
خارجی خالی	aug_save_event(au_event_t);
خارجی خالی	aug_save_sorf(صحیح);
خارجی خالی	aug_save_متن(حرف *);
خارجی خالی	aug_save_text1(حرف *);
خارجی خالی	aug_save_text2(حرف *);
خارجی خالی	aug_save_na(صحیح);
خارجی خالی	aug_save_user(حرف *);
خارجی خالی	aug_save_راستہ(حرف *);
خارجی صحیح	aug_save_policy(خالی);
خارجی خالی	aug_save_afunc(صحیح (*)(صحیح));
خارجی صحیح	aug_audit(خالی);
خارجی صحیح	aug_na_selected(خالی);
خارجی صحیح	aug_selected(خالی);
خارجی صحیح	aug_daemon_session(خالی);

#اگر_غیر_تعریف_شدہ HAVE_GETTEXT
# define gettext(a)	(a)
#اگر_ختم

خارجی Authctxt *the_authctxt;
ساکن Audit_Info_رکن_ID ssh_bsm_tid;

#اگر_تعریف_شدہ BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#تعریف_کرو BSM_TEXTBUFSZ 256
#اگر_ختم

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#اگر defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
خارجی صحیح aug_get_machine(حرف *, uint32_t *, uint32_t *);
#ورنہ
ساکن صحیح
aug_get_machine(حرف *host, uint32_t *addr, uint32_t *type)
{
	ساخت addrinfo *ai; 
	ساخت sockaddr_in *in4;
	ساخت sockaddr_in6 *in6;
	صحیح ret = 0, r;

	اگر ((r = getaddrinfo(host, تہی, تہی, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		واپس -1;
	}
	
	انتخاب (ai->ai_family) {
	حالت AF_INET:
		in4 = (ساخت sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		حافظہ_نقل(addr, &in4->sin_addr, حجم(ساخت in_addr));
		توڑو;
#اگر_تعریف_شدہ AU_IPv6
	حالت AF_INET6: 
		in6 = (ساخت sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		حافظہ_نقل(addr, &in6->sin6_addr, حجم(ساخت in6_addr));
		توڑو;
#اگر_ختم
	طےشدہ:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	واپس ret;
}
#اگر_ختم

#اگر_تعریف_شدہ BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
صحیح
getacna(حرف *auditstring, صحیح len)
{
	scf_handle_t *handle = تہی;
	scf_property_t *property = تہی;
	scf_قدر_t *قدر = تہی;
	صحیح ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_نسخہ);
	اگر (handle == تہی) 
		واپس -2;

	ret = scf_handle_bind(handle);
	اگر (ret == -1) 
		واپس -2;

	property = scf_property_create(handle);
	اگر (property == تہی) 
		واپس -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    تہی, تہی, تہی, تہی, property, 0);
	اگر (ret == -1) 
		واپس -2;

	قدر = scf_قدر_create(handle);
	اگر (قدر == تہی) 
		واپس -2;

	ret = scf_property_get_قدر(property, قدر);
	اگر (ret == -1) 
		واپس -2;

	ret = scf_قدر_get_astring(قدر, auditstring, len);
	اگر (ret == -1) 
		واپس -2;

	scf_قدر_destroy(قدر);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	واپس 0;
}
#اگر_ختم

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ساکن صحیح
selected(حرف *username, uid_t uid, au_event_t event, صحیح sf)
{
	صحیح rc, sorf;
	حرف naflags[512];
	ساخت au_نقاب نقاب;

	نقاب.am_success = نقاب.am_failure = 0;
	اگر (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, حجم(naflags));
		اگر (rc == 0)
			(خالی) getauditflagsbin(naflags, &نقاب);
	} ورنہ
		rc = au_user_نقاب(username, &نقاب);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	واپس(au_preselect(event, &نقاب, sorf, AU_PRS_REREAD));
}

ساکن خالی
bsm_audit_ریکارڈ(صحیح typ, حرف *string, au_event_t event_no)
{
	صحیح		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	Audit_Info_رکن_ID	tid = ssh_bsm_tid;

	اگر (the_authctxt != تہی && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	اگر (!sel)
		واپس;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(خالی) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(خالی) au_write(ad, au_مقصد_متن(string));
	(خالی) au_write(ad, AUToReturnFunc(typ, rc));

#اگر_تعریف_شدہ BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_مقصد_WRITE, event_no, 0);
#ورنہ
	rc = au_close(ad, AU_مقصد_WRITE, event_no);
#اگر_ختم

	اگر (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ساکن خالی
bsm_audit_session_تیاری(خالی)
{
	صحیح rc;
	ساخت AuditInfoStruct info;
	au_نقاب_t نقاب;

	اگر (the_authctxt == تہی) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		واپس;
	}

	اگر (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	ورنہ
		info.ai_auid = -1;
	info.ai_asid = getpid();
	نقاب.am_success = 0;
	نقاب.am_failure = 0;

	(خالی) au_user_نقاب(the_authctxt->user, &نقاب);

	info.ai_نقاب.am_success  = نقاب.am_success;
	info.ai_نقاب.am_failure  = نقاب.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = سیٹ_Audit_Func(&info, حجم(info));
	اگر (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    سیٹ_Audit_Func_متن, strerror(errno));
}

ساکن خالی
bsm_audit_bad_login(ثابت حرف *what)
{
	حرف textbuf[BSM_TEXTBUFSZ];

	اگر (the_authctxt->valid) {
		(خالی) snprintf(textbuf, حجم (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_ریکارڈ(4, textbuf, AUE_openssh);
	} ورنہ {
		(خالی) snprintf(textbuf, حجم (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_ریکارڈ(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

خالی
audit_connection_from(ثابت حرف *host, صحیح پورٹ)
{
	Audit_Info_رکن_ID *tid = &ssh_bsm_tid;
	حرف buf[1024];

	اگر (cannot_audit(0))
		واپس;
	debug3("BSM audit: connection from %.100s port %d", host, پورٹ);

	/* populate our terminal id structure */
#اگر defined(HAVE_GETAUDIT_ADDR)
	tid->at_پورٹ = (dev_t)پورٹ;
	aug_get_machine((حرف *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, حجم(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (صحیح)tid->at_type, buf);
#ورنہ
	/* this is used on IPv4-only machines */
	tid->پورٹ = (dev_t)پورٹ;
	tid->machine = inet_addr(host);
	snprintf(buf, حجم(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#اگر_ختم
}

خالی
audit_تسلسل_command(ثابت حرف *command)
{
	/* not implemented */
}

خالی
audit_session_open(ساخت logininfo *li)
{
	/* not implemented */
}

خالی
audit_session_close(ساخت logininfo *li)
{
	/* not implemented */
}

خالی
audit_event(ساخت ssh *ssh, ssh_audit_event_t event)
{
	حرف    textbuf[BSM_TEXTBUFSZ];
	ساکن صحیح logged_اندر = 0;
	ثابت حرف *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	اگر (cannot_audit(0))
		واپس;

	انتخاب(event) {
	حالت SSH_AUTH_SUCCESS:
		logged_اندر = 1;
		bsm_audit_session_تیاری();
		snprintf(textbuf, حجم(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_ریکارڈ(0, textbuf, AUE_openssh);
		توڑو;

	حالت SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		اگر (logged_اندر) {
			snprintf(textbuf, حجم(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_ریکارڈ(0, textbuf, AUE_logout);
		} ورنہ {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		توڑو;

	حالت SSH_NOLOGIN:
		bsm_audit_ریکارڈ(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		توڑو;

	حالت SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, حجم(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_ریکارڈ(1, textbuf, AUE_openssh);
		توڑو;

	حالت SSH_LOGIN_جڑ_DENIED:
		bsm_audit_ریکارڈ(2, gettext("not_console"), AUE_openssh);
		توڑو;

	حالت SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		توڑو;

	حالت SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		توڑو;

	طےشدہ:
		debug_f("unhandled event %d", event);
	}
}
#اگر_ختم /* BSM */
