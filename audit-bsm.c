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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଯଦି defined(USE_BSM_AUDIT)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef BROKEN_BSM_API
#ଅନ୍ତର୍ଭାଵ <libscf.h>
#endif

#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#ଅନ୍ତର୍ଭାଵ <bsm/audit.h>
#ଅନ୍ତର୍ଭାଵ <bsm/libbsm.h>
#ଅନ୍ତର୍ଭାଵ <bsm/audit_uevents.h>
#ଅନ୍ତର୍ଭାଵ <bsm/audit_record.h>
#ଅନ୍ତର୍ଭାଵ <locale.h>

#ଯଦି defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#ଅନ୍ୟଥା
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	cannot_audit(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif
ବାହ୍ୟ ଶୂନ୍ୟ	aug_init(ଶୂନ୍ୟ);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_auid(au_id_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_uid(uid_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_euid(uid_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_gid(gid_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_egid(gid_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_pid(pid_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_asid(au_asid_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_tid(dev_t, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	aug_save_me(ଶୂନ୍ୟ);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	aug_save_namask(ଶୂନ୍ୟ);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_event(au_event_t);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_sorf(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_text(ଅକ୍ଷର *);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_text1(ଅକ୍ଷର *);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_text2(ଅକ୍ଷର *);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_na(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_user(ଅକ୍ଷର *);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_path(ଅକ୍ଷର *);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	aug_save_policy(ଶୂନ୍ୟ);
ବାହ୍ୟ ଶୂନ୍ୟ	aug_save_afunc(ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା));
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	aug_audit(ଶୂନ୍ୟ);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	aug_na_selected(ଶୂନ୍ୟ);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	aug_selected(ଶୂନ୍ୟ);
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା	aug_daemon_session(ଶୂନ୍ୟ);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

ବାହ୍ୟ Authctxt *the_authctxt;
ସ୍ଥିର AuditInfoTermID ssh_bsm_tid;

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
#ଯଦି defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା aug_get_machine(ଅକ୍ଷର *, uint32_t *, uint32_t *);
#ଅନ୍ୟଥା
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
aug_get_machine(ଅକ୍ଷର *host, uint32_t *addr, uint32_t *type)
{
	ସଂରଚନା addrinfo *ai; 
	ସଂରଚନା sockaddr_in *in4;
	ସଂରଚନା sockaddr_in6 *in6;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0, r;

	ଯଦି ((r = getaddrinfo(host, ଖାଲି, ଖାଲି, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		ଫେରନ୍ତୁ -1;
	}
	
	ବାଛ (ai->ai_family) {
	ସ୍ଥିତି AF_INET:
		in4 = (ସଂରଚନା sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, ଆକାର(ସଂରଚନା in_addr));
		ଭାଙ୍ଗ;
#ifdef AU_IPv6
	ସ୍ଥିତି AF_INET6: 
		in6 = (ସଂରଚନା sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, ଆକାର(ସଂରଚନା in6_addr));
		ଭାଙ୍ଗ;
#endif
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	ଫେରନ୍ତୁ ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getacna(ଅକ୍ଷର *auditstring, ପୂର୍ଣ୍ଣସଂଖ୍ୟା len)
{
	scf_handle_t *handle = ଖାଲି;
	scf_property_t *property = ଖାଲି;
	scf_ମୂଲ୍ୟ_t *ମୂଲ୍ୟ = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	ଯଦି (handle == ଖାଲି) 
		ଫେରନ୍ତୁ -2;

	ret = scf_handle_bind(handle);
	ଯଦି (ret == -1) 
		ଫେରନ୍ତୁ -2;

	property = scf_property_create(handle);
	ଯଦି (property == ଖାଲି) 
		ଫେରନ୍ତୁ -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ଖାଲି, ଖାଲି, ଖାଲି, ଖାଲି, property, 0);
	ଯଦି (ret == -1) 
		ଫେରନ୍ତୁ -2;

	ମୂଲ୍ୟ = scf_ମୂଲ୍ୟ_create(handle);
	ଯଦି (ମୂଲ୍ୟ == ଖାଲି) 
		ଫେରନ୍ତୁ -2;

	ret = scf_property_get_ମୂଲ୍ୟ(property, ମୂଲ୍ୟ);
	ଯଦି (ret == -1) 
		ଫେରନ୍ତୁ -2;

	ret = scf_ମୂଲ୍ୟ_get_astring(ମୂଲ୍ୟ, auditstring, len);
	ଯଦି (ret == -1) 
		ଫେରନ୍ତୁ -2;

	scf_ମୂଲ୍ୟ_destroy(ମୂଲ୍ୟ);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	ଫେରନ୍ତୁ 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
selected(ଅକ୍ଷର *username, uid_t uid, au_event_t event, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rc, sorf;
	ଅକ୍ଷର naflags[512];
	ସଂରଚନା au_mask mask;

	mask.am_success = mask.am_failure = 0;
	ଯଦି (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, ଆକାର(naflags));
		ଯଦି (rc == 0)
			(ଶୂନ୍ୟ) getauditflagsbin(naflags, &mask);
	} ଅନ୍ୟଥା
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	ଫେରନ୍ତୁ(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

ସ୍ଥିର ଶୂନ୍ୟ
bsm_audit_record(ପୂର୍ଣ୍ଣସଂଖ୍ୟା typ, ଅକ୍ଷର *string, au_event_t event_no)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	ଯଦି (the_authctxt != ଖାଲି && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	ଯଦି (!sel)
		ଫେରନ୍ତୁ;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(ଶୂନ୍ୟ) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(ଶୂନ୍ୟ) au_write(ad, au_to_text(string));
	(ଶୂନ୍ୟ) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#ଅନ୍ୟଥା
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	ଯଦି (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

ସ୍ଥିର ଶୂନ୍ୟ
bsm_audit_session_setup(ଶୂନ୍ୟ)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rc;
	ସଂରଚନା AuditInfoStruct info;
	au_mask_t mask;

	ଯଦି (the_authctxt == ଖାଲି) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		ଫେରନ୍ତୁ;
	}

	ଯଦି (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	ଅନ୍ୟଥା
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(ଶୂନ୍ୟ) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, ଆକାର(info));
	ଯଦି (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

ସ୍ଥିର ଶୂନ୍ୟ
bsm_audit_bad_login(ଅଚଳ ଅକ୍ଷର *what)
{
	ଅକ୍ଷର textbuf[BSM_TEXTBUFSZ];

	ଯଦି (the_authctxt->valid) {
		(ଶୂନ୍ୟ) snprintf(textbuf, ଆକାର (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} ଅନ୍ୟଥା {
		(ଶୂନ୍ୟ) snprintf(textbuf, ଆକାର (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

ଶୂନ୍ୟ
audit_connection_from(ଅଚଳ ଅକ୍ଷର *host, ପୂର୍ଣ୍ଣସଂଖ୍ୟା port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	ଅକ୍ଷର buf[1024];

	ଯଦି (cannot_audit(0))
		ଫେରନ୍ତୁ;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#ଯଦି defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((ଅକ୍ଷର *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, ଆକାର(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)tid->at_type, buf);
#ଅନ୍ୟଥା
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, ଆକାର(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

ଶୂନ୍ୟ
audit_run_command(ଅଚଳ ଅକ୍ଷର *command)
{
	/* not implemented */
}

ଶୂନ୍ୟ
audit_session_open(ସଂରଚନା logininfo *li)
{
	/* not implemented */
}

ଶୂନ୍ୟ
audit_session_close(ସଂରଚନା logininfo *li)
{
	/* not implemented */
}

ଶୂନ୍ୟ
audit_event(ସଂରଚନା ssh *ssh, ssh_audit_event_t event)
{
	ଅକ୍ଷର    textbuf[BSM_TEXTBUFSZ];
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା logged_in = 0;
	ଅଚଳ ଅକ୍ଷର *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	ଯଦି (cannot_audit(0))
		ଫେରନ୍ତୁ;

	ବାଛ(event) {
	ସ୍ଥିତି SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, ଆକାର(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		ଯଦି (logged_in) {
			snprintf(textbuf, ଆକାର(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} ଅନ୍ୟଥା {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, ଆକାର(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି SSH_LOGIN_ମୂଳ_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		ଭାଙ୍ଗ;

	ସ୍ଥିତି SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		ଭାଙ୍ଗ;

	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
