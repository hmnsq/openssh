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

#అన్తర్భావ "includes.h"
#ఒకవేళ defined(USE_BSM_AUDIT)

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే BROKEN_BSM_API
#అన్తర్భావ <libscf.h>
#అయితే_ముగింపు

#అన్తర్భావ "ssh.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "xmalloc.h"

#నిర్వచితం_కాకపోతే AUE_openssh
# define AUE_openssh     32800
#అయితే_ముగింపు
#అన్తర్భావ <bsm/audit.h>
#అన్తర్భావ <bsm/libbsm.h>
#అన్తర్భావ <bsm/audit_uevents.h>
#అన్తర్భావ <bsm/audit_record.h>
#అన్తర్భావ <locale.h>

#ఒకవేళ defined(HAVE_GETAUDIT_ADDR)
#నిర్వచించు	AuditInfoStruct		auditinfo_addr
#నిర్వచించు Audit_Info_పదం_ID		au_tid_addr_t
#నిర్వచించు సమితి_Audit_Func(a,b)	setaudit_addr((a),(b))
#నిర్వచించు సమితి_Audit_Func_పాఠ్యం	"setaudit_addr"
#నిర్వచించు AUToSubjectFunc		au_గమ్యం_subject_ex
#నిర్వచించు AUToReturnFunc(a,b)	au_గమ్యం_return32((a), (int32_t)(b))
#లేకపోతే
#నిర్వచించు	AuditInfoStruct		auditinfo
#నిర్వచించు Audit_Info_పదం_ID		au_tid_t
#నిర్వచించు సమితి_Audit_Func(a,b)	setaudit(a)
#నిర్వచించు సమితి_Audit_Func_పాఠ్యం	"setaudit"
#నిర్వచించు AUToSubjectFunc		au_గమ్యం_subject
#నిర్వచించు AUToReturnFunc(a,b)	au_గమ్యం_return((a), (u_int)(b))
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే cannot_audit
బాహ్య పూర్ణాంకం	cannot_audit(పూర్ణాంకం);
#అయితే_ముగింపు
బాహ్య శూన్య	aug_init(శూన్య);
బాహ్య శూన్య	aug_save_auid(au_id_t);
బాహ్య శూన్య	aug_save_uid(uid_t);
బాహ్య శూన్య	aug_save_euid(uid_t);
బాహ్య శూన్య	aug_save_gid(gid_t);
బాహ్య శూన్య	aug_save_egid(gid_t);
బాహ్య శూన్య	aug_save_pid(pid_t);
బాహ్య శూన్య	aug_save_asid(au_asid_t);
బాహ్య శూన్య	aug_save_tid(dev_t, గుర్తులేని పూర్ణాంకం);
బాహ్య శూన్య	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
బాహ్య పూర్ణాంకం	aug_save_me(శూన్య);
బాహ్య పూర్ణాంకం	aug_save_namask(శూన్య);
బాహ్య శూన్య	aug_save_event(au_event_t);
బాహ్య శూన్య	aug_save_sorf(పూర్ణాంకం);
బాహ్య శూన్య	aug_save_పాఠ్యం(అక్షరం *);
బాహ్య శూన్య	aug_save_text1(అక్షరం *);
బాహ్య శూన్య	aug_save_text2(అక్షరం *);
బాహ్య శూన్య	aug_save_na(పూర్ణాంకం);
బాహ్య శూన్య	aug_save_user(అక్షరం *);
బాహ్య శూన్య	aug_save_మార్గం(అక్షరం *);
బాహ్య పూర్ణాంకం	aug_save_policy(శూన్య);
బాహ్య శూన్య	aug_save_afunc(పూర్ణాంకం (*)(పూర్ణాంకం));
బాహ్య పూర్ణాంకం	aug_audit(శూన్య);
బాహ్య పూర్ణాంకం	aug_na_selected(శూన్య);
బాహ్య పూర్ణాంకం	aug_selected(శూన్య);
బాహ్య పూర్ణాంకం	aug_daemon_session(శూన్య);

#నిర్వచితం_కాకపోతే HAVE_GETTEXT
# define gettext(a)	(a)
#అయితే_ముగింపు

బాహ్య Authctxt *the_authctxt;
స్థిర Audit_Info_పదం_ID ssh_bsm_tid;

#నిర్వచితమైతే BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#నిర్వచించు BSM_TEXTBUFSZ 256
#అయితే_ముగింపు

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#ఒకవేళ defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
బాహ్య పూర్ణాంకం aug_get_machine(అక్షరం *, uint32_t *, uint32_t *);
#లేకపోతే
స్థిర పూర్ణాంకం
aug_get_machine(అక్షరం *host, uint32_t *addr, uint32_t *type)
{
	నిర్మాణం addrinfo *ai; 
	నిర్మాణం sockaddr_in *in4;
	నిర్మాణం sockaddr_in6 *in6;
	పూర్ణాంకం ret = 0, r;

	ఒకవేళ ((r = getaddrinfo(host, ఖాళీ, ఖాళీ, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		తిరిగి -1;
	}
	
	ఎంపిక (ai->ai_family) {
	స్థితి AF_INET:
		in4 = (నిర్మాణం sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		జ్ఞాపకం_నకలు(addr, &in4->sin_addr, పరిమాణం(నిర్మాణం in_addr));
		ఆపు;
#నిర్వచితమైతే AU_IPv6
	స్థితి AF_INET6: 
		in6 = (నిర్మాణం sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		జ్ఞాపకం_నకలు(addr, &in6->sin6_addr, పరిమాణం(నిర్మాణం in6_addr));
		ఆపు;
#అయితే_ముగింపు
	అప్రమేయ:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	తిరిగి ret;
}
#అయితే_ముగింపు

#నిర్వచితమైతే BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
పూర్ణాంకం
getacna(అక్షరం *auditstring, పూర్ణాంకం len)
{
	scf_handle_t *handle = ఖాళీ;
	scf_property_t *property = ఖాళీ;
	scf_విలువ_t *విలువ = ఖాళీ;
	పూర్ణాంకం ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_సంస్కరణ);
	ఒకవేళ (handle == ఖాళీ) 
		తిరిగి -2;

	ret = scf_handle_bind(handle);
	ఒకవేళ (ret == -1) 
		తిరిగి -2;

	property = scf_property_create(handle);
	ఒకవేళ (property == ఖాళీ) 
		తిరిగి -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    ఖాళీ, ఖాళీ, ఖాళీ, ఖాళీ, property, 0);
	ఒకవేళ (ret == -1) 
		తిరిగి -2;

	విలువ = scf_విలువ_create(handle);
	ఒకవేళ (విలువ == ఖాళీ) 
		తిరిగి -2;

	ret = scf_property_get_విలువ(property, విలువ);
	ఒకవేళ (ret == -1) 
		తిరిగి -2;

	ret = scf_విలువ_get_astring(విలువ, auditstring, len);
	ఒకవేళ (ret == -1) 
		తిరిగి -2;

	scf_విలువ_destroy(విలువ);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	తిరిగి 0;
}
#అయితే_ముగింపు

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
స్థిర పూర్ణాంకం
selected(అక్షరం *username, uid_t uid, au_event_t event, పూర్ణాంకం sf)
{
	పూర్ణాంకం rc, sorf;
	అక్షరం naflags[512];
	నిర్మాణం au_ముసుగు ముసుగు;

	ముసుగు.am_success = ముసుగు.am_failure = 0;
	ఒకవేళ (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, పరిమాణం(naflags));
		ఒకవేళ (rc == 0)
			(శూన్య) getauditflagsbin(naflags, &ముసుగు);
	} లేకపోతే
		rc = au_user_ముసుగు(username, &ముసుగు);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	తిరిగి(au_preselect(event, &ముసుగు, sorf, AU_PRS_REREAD));
}

స్థిర శూన్య
bsm_audit_రికార్డు(పూర్ణాంకం typ, అక్షరం *string, au_event_t event_no)
{
	పూర్ణాంకం		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	Audit_Info_పదం_ID	tid = ssh_bsm_tid;

	ఒకవేళ (the_authctxt != ఖాళీ && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	ఒకవేళ (!sel)
		తిరిగి;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(శూన్య) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(శూన్య) au_write(ad, au_గమ్యం_పాఠ్యం(string));
	(శూన్య) au_write(ad, AUToReturnFunc(typ, rc));

#నిర్వచితమైతే BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_గమ్యం_WRITE, event_no, 0);
#లేకపోతే
	rc = au_close(ad, AU_గమ్యం_WRITE, event_no);
#అయితే_ముగింపు

	ఒకవేళ (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

స్థిర శూన్య
bsm_audit_session_అమరిక(శూన్య)
{
	పూర్ణాంకం rc;
	నిర్మాణం AuditInfoStruct info;
	au_ముసుగు_t ముసుగు;

	ఒకవేళ (the_authctxt == ఖాళీ) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		తిరిగి;
	}

	ఒకవేళ (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	లేకపోతే
		info.ai_auid = -1;
	info.ai_asid = getpid();
	ముసుగు.am_success = 0;
	ముసుగు.am_failure = 0;

	(శూన్య) au_user_ముసుగు(the_authctxt->user, &ముసుగు);

	info.ai_ముసుగు.am_success  = ముసుగు.am_success;
	info.ai_ముసుగు.am_failure  = ముసుగు.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = సమితి_Audit_Func(&info, పరిమాణం(info));
	ఒకవేళ (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    సమితి_Audit_Func_పాఠ్యం, strerror(errno));
}

స్థిర శూన్య
bsm_audit_bad_login(స్థిరరాశి అక్షరం *what)
{
	అక్షరం textbuf[BSM_TEXTBUFSZ];

	ఒకవేళ (the_authctxt->valid) {
		(శూన్య) snprintf(textbuf, పరిమాణం (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_రికార్డు(4, textbuf, AUE_openssh);
	} లేకపోతే {
		(శూన్య) snprintf(textbuf, పరిమాణం (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_రికార్డు(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

శూన్య
audit_connection_from(స్థిరరాశి అక్షరం *host, పూర్ణాంకం పోర్టు)
{
	Audit_Info_పదం_ID *tid = &ssh_bsm_tid;
	అక్షరం buf[1024];

	ఒకవేళ (cannot_audit(0))
		తిరిగి;
	debug3("BSM audit: connection from %.100s port %d", host, పోర్టు);

	/* populate our terminal id structure */
#ఒకవేళ defined(HAVE_GETAUDIT_ADDR)
	tid->at_పోర్టు = (dev_t)పోర్టు;
	aug_get_machine((అక్షరం *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, పరిమాణం(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (పూర్ణాంకం)tid->at_type, buf);
#లేకపోతే
	/* this is used on IPv4-only machines */
	tid->పోర్టు = (dev_t)పోర్టు;
	tid->machine = inet_addr(host);
	snprintf(buf, పరిమాణం(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#అయితే_ముగింపు
}

శూన్య
audit_నిరంతరం_command(స్థిరరాశి అక్షరం *command)
{
	/* not implemented */
}

శూన్య
audit_session_open(నిర్మాణం logininfo *li)
{
	/* not implemented */
}

శూన్య
audit_session_close(నిర్మాణం logininfo *li)
{
	/* not implemented */
}

శూన్య
audit_event(నిర్మాణం ssh *ssh, ssh_audit_event_t event)
{
	అక్షరం    textbuf[BSM_TEXTBUFSZ];
	స్థిర పూర్ణాంకం logged_లోపల = 0;
	స్థిరరాశి అక్షరం *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	ఒకవేళ (cannot_audit(0))
		తిరిగి;

	ఎంపిక(event) {
	స్థితి SSH_AUTH_SUCCESS:
		logged_లోపల = 1;
		bsm_audit_session_అమరిక();
		snprintf(textbuf, పరిమాణం(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_రికార్డు(0, textbuf, AUE_openssh);
		ఆపు;

	స్థితి SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		ఒకవేళ (logged_లోపల) {
			snprintf(textbuf, పరిమాణం(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_రికార్డు(0, textbuf, AUE_logout);
		} లేకపోతే {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		ఆపు;

	స్థితి SSH_NOLOGIN:
		bsm_audit_రికార్డు(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		ఆపు;

	స్థితి SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, పరిమాణం(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_రికార్డు(1, textbuf, AUE_openssh);
		ఆపు;

	స్థితి SSH_LOGIN_మూలం_DENIED:
		bsm_audit_రికార్డు(2, gettext("not_console"), AUE_openssh);
		ఆపు;

	స్థితి SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		ఆపు;

	స్థితి SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		ఆపు;

	అప్రమేయ:
		debug_f("unhandled event %d", event);
	}
}
#అయితే_ముగింపు /* BSM */
