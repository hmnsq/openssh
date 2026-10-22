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
	*osigchldp = संक_पूर्व;

	helper = दो_पर्या("SSH_SK_HELPER");
	यदि (helper == रिक्त || म_माप(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	यदि (pipe(execpipe) == -1) {
		error("pipe:  %s", म_त्रुटि(त्रुटि_सं));
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	यदि (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", म_त्रुटि(त्रुटि_सं));
		बंद(execpipe[0]);
		बंद(execpipe[1]);
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	यदि ((pid = विभाजन()) == -1) {
		oerrno = त्रुटि_सं;
		error("fork: %s", म_त्रुटि(त्रुटि_सं));
		बंद(pair[0]);
		बंद(pair[1]);
		बंद(execpipe[0]);
		बंद(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		त्रुटि_सं = oerrno;
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	}
	यदि (pid == 0) {
		बंद(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		यदि ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, परिमाण execbuf,
			    "dup2: %s", म_त्रुटि(त्रुटि_सं));
			लिख(execpipe[1], execbuf, म_माप(execbuf)+1);
			_exit(1);
		}
		बंद(pair[0]);
		बंद(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == रिक्त ? "" : verbosity);
		execlp(helper, helper, verbosity, (वर्ण *)रिक्त);
		snprintf(execbuf, परिमाण execbuf,
		    "execlp: %s", म_त्रुटि(त्रुटि_सं));
		लिख(execpipe[1], execbuf, म_माप(execbuf)+1);
		_exit(1);
	}
	बंद(pair[1]);

	बंद(execpipe[1]);
	n = पठ(execpipe[0], execbuf, परिमाण execbuf);
	बंद(execpipe[0]);
	यदि (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		फर्काऊ SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (दीर्घ)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
reap_helper(pid_t pid)
{
	पूर्णाङ्क status, oerrno;

	debug3_f("pid=%ld", (दीर्घ)pid);

	त्रुटि_सं = 0;
	जबसम्म (waitpid(pid, &status, 0) == -1) {
		यदि (त्रुटि_सं == EINTR) {
			त्रुटि_सं = 0;
			जारी;
		}
		oerrno = त्रुटि_सं;
		error_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	}
	यदि (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		फर्काऊ SSH_ERR_AGENT_FAILURE;
	} अन्यथा यदि (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		फर्काऊ SSH_ERR_AGENT_FAILURE;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
client_converse(संरचना sshbuf *सन्देश, संरचना sshbuf **respp, u_int type)
{
	पूर्णाङ्क oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	शून्य (*osigchld)(पूर्णाङ्क);
	संरचना sshbuf *req = रिक्त, *resp = रिक्त;
	*respp = रिक्त;

	यदि ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		फर्काऊ r;

	यदि ((req = sshbuf_new()) == रिक्त || (resp = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	यदि ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, सन्देश)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}
	यदि ((r = ssh_सन्देश_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		गच्छ out;
	}
	यदि ((r = ssh_सन्देश_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		गच्छ out;
	}
	यदि ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		गच्छ out;
	}
	यदि (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		गच्छ out;
	}
	यदि (rtype == SSH_SK_HELPER_ERROR) {
		यदि ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			गच्छ out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		यदि (rerr == 0 || rerr >= पूर्णांक_उच्च)
			r = SSH_ERR_INTERNAL_ERROR;
		अन्यथा
			r = -(पूर्णाङ्क)rerr;
		गच्छ out;
	} अन्यथा यदि (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	बंद(fd);
	यदि ((r2 = reap_helper(pid)) != 0) {
		यदि (r == 0) {
			r = r2;
			oerrno = त्रुटि_सं;
		}
	}
	यदि (r == 0) {
		*respp = resp;
		resp = रिक्त;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	त्रुटि_सं = oerrno;
	फर्काऊ r;

}

पूर्णाङ्क
sshsk_sign(अचर वर्ण *provider, संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp, अचर u_char *data, माप_प्रकार datalen,
    u_int compat, अचर वर्ण *pin)
{
	पूर्णाङ्क oerrno, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *kbuf = रिक्त, *req = रिक्त, *resp = रिक्त;

	*sigp = रिक्त;
	*lenp = 0;

#ifndef ENABLE_SK
	फर्काऊ SSH_ERR_साँचो_TYPE_UNKNOWN;
#endif

	यदि ((kbuf = sshbuf_new()) == रिक्त ||
	    (req = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	यदि ((r = sshkey_private_serialize(साँचो, kbuf)) != 0) {
		error_fr(r, "encode key");
		गच्छ out;
	}
	यदि ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, रिक्त)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}

	यदि ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		गच्छ out;

	यदि ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	यदि (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = रिक्त;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	त्रुटि_सं = oerrno;
	फर्काऊ r;
}

पूर्णाङ्क
sshsk_enroll(पूर्णाङ्क type, अचर वर्ण *provider_path, अचर वर्ण *device,
    अचर वर्ण *application, अचर वर्ण *userid, uint8_t flags,
    अचर वर्ण *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	पूर्णाङ्क oerrno, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *kbuf = रिक्त, *abuf = रिक्त, *req = रिक्त, *resp = रिक्त;
	संरचना sshkey *साँचो = रिक्त;

	*keyp = रिक्त;
	यदि (attest != रिक्त)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	फर्काऊ SSH_ERR_साँचो_TYPE_UNKNOWN;
#endif

	यदि (type < 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	यदि ((abuf = sshbuf_new()) == रिक्त ||
	    (kbuf = sshbuf_new()) == रिक्त ||
	    (req = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	यदि ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}

	यदि ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		गच्छ out;

	यदि ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((r = sshkey_private_deserialize(kbuf, &साँचो)) != 0) {
		error_fr(r, "encode");
		गच्छ out;
	}
	यदि (attest != रिक्त && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		गच्छ out;
	}

	/* success */
	r = 0;
	*keyp = साँचो;
	साँचो = रिक्त;
 out:
	oerrno = त्रुटि_सं;
	sshkey_free(साँचो);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	त्रुटि_सं = oerrno;
	फर्काऊ r;
}

स्थिर शून्य
sshsk_free_resident_साँचो(संरचना sshsk_resident_साँचो *srk)
{
	यदि (srk == रिक्त)
		फर्काऊ;
	sshkey_free(srk->साँचो);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


शून्य
sshsk_free_resident_साँचोहरू(संरचना sshsk_resident_साँचो **srks, माप_प्रकार nsrks)
{
	माप_प्रकार i;

	यदि (srks == रिक्त || nsrks == 0)
		फर्काऊ;

	लागि (i = 0; i < nsrks; i++)
		sshsk_free_resident_साँचो(srks[i]);
	मुक्त(srks);
}

पूर्णाङ्क
sshsk_load_resident(अचर वर्ण *provider_path, अचर वर्ण *device,
    अचर वर्ण *pin, u_int flags, संरचना sshsk_resident_साँचो ***srksp,
    माप_प्रकार *nsrksp)
{
	पूर्णाङ्क oerrno, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *kbuf = रिक्त, *req = रिक्त, *resp = रिक्त;
	संरचना sshkey *साँचो = रिक्त;
	संरचना sshsk_resident_साँचो *srk = रिक्त, **srks = रिक्त, **tmp;
	u_char *userid = रिक्त;
	माप_प्रकार userid_len = 0, nsrks = 0;

	*srksp = रिक्त;
	*nsrksp = 0;

	यदि ((kbuf = sshbuf_new()) == रिक्त ||
	    (req = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	यदि ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}

	यदि ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		गच्छ out;

	जबसम्म (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		यदि ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, रिक्त, रिक्त)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		यदि ((r = sshkey_private_deserialize(kbuf, &साँचो)) != 0) {
			error_fr(r, "decode key");
			गच्छ out;
		}
		यदि ((srk = सुस्मृति(1, परिमाण(*srk))) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		srk->साँचो = साँचो;
		साँचो = रिक्त;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = रिक्त;
		userid_len = 0;
		यदि ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    परिमाण(*srks))) == रिक्त) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->साँचो), srk->साँचो->sk_application,
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
 out:
	oerrno = त्रुटि_सं;
	sshsk_free_resident_साँचो(srk);
	sshsk_free_resident_साँचोहरू(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(साँचो);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	त्रुटि_सं = oerrno;
	फर्काऊ r;
}
