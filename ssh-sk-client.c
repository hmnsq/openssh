/* $OpenBSD: ssh-sk-client.c,v 1.18 2026/03/11 09:10:59 dtucker Exp $ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/wait.h>

#अन्तर्भाव <limits.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <fcntl.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "msg.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "ssh-sk.h"
#अन्तर्भाव "misc.h"

/* #define DEBUG_SK 1 */

स्थिर पूर्णाङ्क
start_helper(पूर्णाङ्क *fdp, pid_t *pidp, शून्य (**osigchldp)(पूर्णाङ्क))
{
	शून्य (*osigchld)(पूर्णाङ्क);
	पूर्णाङ्क oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	वर्ण execbuf[100], *helper, *verbosity = रिक्त;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	यदि (helper == रिक्त || वाक्यदैर्घ्यम्(helper) == 0)
		helper = मार्गः_SSH_SK_HELPER;
#यदि_परिभाषितम् DEBUG_SK
	verbosity = "-vvv";
#यदि_अन्तः

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	यदि (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	यदि ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	यदि (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		यदि ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, परिमाण execbuf,
			    "dup2: %s", strerror(errno));
			लिख(execpipe[1], execbuf, वाक्यदैर्घ्यम्(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == रिक्त ? "" : verbosity);
		execlp(helper, helper, verbosity, (वर्ण *)रिक्त);
		snprintf(execbuf, परिमाण execbuf,
		    "execlp: %s", strerror(errno));
		लिख(execpipe[1], execbuf, वाक्यदैर्घ्यम्(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = पठ(execpipe[0], execbuf, परिमाण execbuf);
	close(execpipe[0]);
	यदि (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		प्रत्यागम SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (दीर्घ)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
reap_helper(pid_t pid)
{
	पूर्णाङ्क स्थितिः, oerrno;

	debug3_f("pid=%ld", (दीर्घ)pid);

	errno = 0;
	यावत् (waitpid(pid, &स्थितिः, 0) == -1) {
		यदि (errno == EINTR) {
			errno = 0;
			अनुवर्त;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	यदि (!WIFEXITED(स्थितिः)) {
		error_f("helper exited abnormally");
		प्रत्यागम SSH_ERR_AGENT_FAILURE;
	} अन्यथा यदि (WEXITSTATUS(स्थितिः) != 0) {
		error_f("helper exited with non-zero exit status");
		प्रत्यागम SSH_ERR_AGENT_FAILURE;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
client_converse(संरचना sshbuf *सन्देशः, संरचना sshbuf **respp, u_int type)
{
	पूर्णाङ्क oerrno, fd, r2, ll, r = SSH_ERR_आन्तरिकम्_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char संस्करणम्;
	शून्य (*osigchld)(पूर्णाङ्क);
	संरचना sshbuf *req = रिक्त, *resp = रिक्त;
	*respp = रिक्त;

	यदि ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		प्रत्यागम r;

	यदि ((req = sshbuf_new()) == रिक्त || (resp = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	यदि ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, सन्देशः)) != 0) {
		error_fr(r, "compose");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = ssh_सन्देशः_send(fd, SSH_SK_HELPER_संस्करणम्, req)) != 0) {
		error_fr(r, "send");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = ssh_सन्देशः_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_u8(resp, &संस्करणम्)) != 0) {
		error_fr(r, "parse version");
		गच्छ बहिर्गमनम्;
	}
	यदि (संस्करणम् != SSH_SK_HELPER_संस्करणम्) {
		error_f("unsupported version: got %u, expected %u",
		    संस्करणम्, SSH_SK_HELPER_संस्करणम्);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		गच्छ बहिर्गमनम्;
	}
	यदि (rtype == SSH_SK_HELPER_ERROR) {
		यदि ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			गच्छ बहिर्गमनम्;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		यदि (rerr == 0 || rerr >= अधिकतम_पूर्णाङ्कः)
			r = SSH_ERR_आन्तरिकम्_ERROR;
		अन्यथा
			r = -(पूर्णाङ्क)rerr;
		गच्छ बहिर्गमनम्;
	} अन्यथा यदि (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	oerrno = errno;
	close(fd);
	यदि ((r2 = reap_helper(pid)) != 0) {
		यदि (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	यदि (r == 0) {
		*respp = resp;
		resp = रिक्त;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	प्रत्यागम r;

}

पूर्णाङ्क
sshsk_sign(ध्रुव वर्ण *provider, संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp, ध्रुव u_char *दत्त, आकार_t datalen,
    u_int compat, ध्रुव वर्ण *pin)
{
	पूर्णाङ्क oerrno, r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *kbuf = रिक्त, *req = रिक्त, *resp = रिक्त;

	*sigp = रिक्त;
	*lenp = 0;

#यदि_अपरिभाषितम् ENABLE_SK
	प्रत्यागम SSH_ERR_कुञ्चिका_TYPE_UNKNOWN;
#यदि_अन्तः

	यदि ((kbuf = sshbuf_new()) == रिक्त ||
	    (req = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshkey_वैयक्तिकम्_serialize(कुञ्चिका, kbuf)) != 0) {
		error_fr(r, "encode key");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, दत्त, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, रिक्त)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		गच्छ बहिर्गमनम्;

	यदि ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	oerrno = errno;
	यदि (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = रिक्त;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	प्रत्यागम r;
}

पूर्णाङ्क
sshsk_enroll(पूर्णाङ्क type, ध्रुव वर्ण *provider_मार्गः, ध्रुव वर्ण *device,
    ध्रुव वर्ण *application, ध्रुव वर्ण *userid, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	पूर्णाङ्क oerrno, r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *kbuf = रिक्त, *abuf = रिक्त, *req = रिक्त, *resp = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;

	*keyp = रिक्त;
	यदि (attest != रिक्त)
		sshbuf_reset(attest);

#यदि_अपरिभाषितम् ENABLE_SK
	प्रत्यागम SSH_ERR_कुञ्चिका_TYPE_UNKNOWN;
#यदि_अन्तः

	यदि (type < 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	यदि ((abuf = sshbuf_new()) == रिक्त ||
	    (kbuf = sshbuf_new()) == रिक्त ||
	    (req = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_मार्गः)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		गच्छ बहिर्गमनम्;

	यदि ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshkey_वैयक्तिकम्_deserialize(kbuf, &कुञ्चिका)) != 0) {
		error_fr(r, "encode");
		गच्छ बहिर्गमनम्;
	}
	यदि (attest != रिक्त && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		गच्छ बहिर्गमनम्;
	}

	/* success */
	r = 0;
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त;
 बहिर्गमनम्:
	oerrno = errno;
	sshkey_free(कुञ्चिका);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	प्रत्यागम r;
}

स्थिर शून्य
sshsk_free_resident_कुञ्चिका(संरचना sshsk_resident_कुञ्चिका *srk)
{
	यदि (srk == रिक्त)
		प्रत्यागम;
	sshkey_free(srk->कुञ्चिका);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


शून्य
sshsk_free_resident_कुञ्चिकाः(संरचना sshsk_resident_कुञ्चिका **srks, आकार_t nsrks)
{
	आकार_t i;

	यदि (srks == रिक्त || nsrks == 0)
		प्रत्यागम;

	प्रति (i = 0; i < nsrks; i++)
		sshsk_free_resident_कुञ्चिका(srks[i]);
	मुक्त(srks);
}

पूर्णाङ्क
sshsk_आरोपय_resident(ध्रुव वर्ण *provider_मार्गः, ध्रुव वर्ण *device,
    ध्रुव वर्ण *pin, u_int flags, संरचना sshsk_resident_कुञ्चिका ***srksp,
    आकार_t *nsrksp)
{
	पूर्णाङ्क oerrno, r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *kbuf = रिक्त, *req = रिक्त, *resp = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshsk_resident_कुञ्चिका *srk = रिक्त, **srks = रिक्त, **tmp;
	u_char *userid = रिक्त;
	आकार_t userid_len = 0, nsrks = 0;

	*srksp = रिक्त;
	*nsrksp = 0;

	यदि ((kbuf = sshbuf_new()) == रिक्त ||
	    (req = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshbuf_put_cstring(req, provider_मार्गः)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = client_converse(req, &resp, SSH_SK_HELPER_आरोपय_RESIDENT)) != 0)
		गच्छ बहिर्गमनम्;

	यावत् (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		यदि ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, रिक्त, रिक्त)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		यदि ((r = sshkey_वैयक्तिकम्_deserialize(kbuf, &कुञ्चिका)) != 0) {
			error_fr(r, "decode key");
			गच्छ बहिर्गमनम्;
		}
		यदि ((srk = शून्यस्मृतिं_देहि(1, परिमाण(*srk))) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		srk->कुञ्चिका = कुञ्चिका;
		कुञ्चिका = रिक्त;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = रिक्त;
		userid_len = 0;
		यदि ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    परिमाण(*srks))) == रिक्त) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->कुञ्चिका), srk->कुञ्चिका->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = रिक्त;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = रिक्त;
	nsrks = 0;
 बहिर्गमनम्:
	oerrno = errno;
	sshsk_free_resident_कुञ्चिका(srk);
	sshsk_free_resident_कुञ्चिकाः(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(कुञ्चिका);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	प्रत्यागम r;
}
