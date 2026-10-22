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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/wait.h>

#समावेश <limits.h>
#समावेश <errno.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <fcntl.h>

#समावेश "log.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "msg.h"
#समावेश "pathnames.h"
#समावेश "ssh-sk.h"
#समावेश "misc.h"

/* #define DEBUG_SK 1 */

अटल पूर्णांक
start_helper(पूर्णांक *fdp, pid_t *pidp, व्योम (**osigchldp)(पूर्णांक))
{
	व्योम (*osigchld)(पूर्णांक);
	पूर्णांक oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	अक्षर execbuf[100], *helper, *verbosity = शून्य;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = संक_पूर्व;

	helper = दो_पर्या("SSH_SK_HELPER");
	अगर (helper == शून्य || म_माप(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#अगर_घोषित DEBUG_SK
	verbosity = "-vvv";
#पूर्ण_अगर

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	अगर (pipe(execpipe) == -1) {
		error("pipe:  %s", म_त्रुटि(त्रुटि_सं));
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", म_त्रुटि(त्रुटि_सं));
		बंद(execpipe[0]);
		बंद(execpipe[1]);
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	अगर ((pid = विभाजन()) == -1) {
		oerrno = त्रुटि_सं;
		error("fork: %s", म_त्रुटि(त्रुटि_सं));
		बंद(pair[0]);
		बंद(pair[1]);
		बंद(execpipe[0]);
		बंद(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	अगर (pid == 0) {
		बंद(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		अगर ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, माप execbuf,
			    "dup2: %s", म_त्रुटि(त्रुटि_सं));
			ग_लिखो(execpipe[1], execbuf, म_माप(execbuf)+1);
			_निकास(1);
		}
		बंद(pair[0]);
		बंद(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == शून्य ? "" : verbosity);
		execlp(helper, helper, verbosity, (अक्षर *)शून्य);
		snprintf(execbuf, माप execbuf,
		    "execlp: %s", म_त्रुटि(त्रुटि_सं));
		ग_लिखो(execpipe[1], execbuf, म_माप(execbuf)+1);
		_निकास(1);
	}
	बंद(pair[1]);

	बंद(execpipe[1]);
	n = पढ़ो(execpipe[0], execbuf, माप execbuf);
	बंद(execpipe[0]);
	अगर (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		वापस SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (दीर्घ)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	वापस 0;
}

अटल पूर्णांक
reap_helper(pid_t pid)
{
	पूर्णांक status, oerrno;

	debug3_f("pid=%ld", (दीर्घ)pid);

	त्रुटि_सं = 0;
	जबतक (waitpid(pid, &status, 0) == -1) {
		अगर (त्रुटि_सं == EINTR) {
			त्रुटि_सं = 0;
			जारी;
		}
		oerrno = त्रुटि_सं;
		error_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	अगर (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		वापस SSH_ERR_AGENT_FAILURE;
	} अन्यथा अगर (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		वापस SSH_ERR_AGENT_FAILURE;
	}
	वापस 0;
}

अटल पूर्णांक
client_converse(काष्ठा sshbuf *संदेश, काष्ठा sshbuf **respp, u_int type)
{
	पूर्णांक oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	व्योम (*osigchld)(पूर्णांक);
	काष्ठा sshbuf *req = शून्य, *resp = शून्य;
	*respp = शून्य;

	अगर ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		वापस r;

	अगर ((req = sshbuf_new()) == शून्य || (resp = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	अगर ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, संदेश)) != 0) {
		error_fr(r, "compose");
		जाओ out;
	}
	अगर ((r = ssh_संदेश_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		जाओ out;
	}
	अगर ((r = ssh_संदेश_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		जाओ out;
	}
	अगर ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		जाओ out;
	}
	अगर (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		जाओ out;
	}
	अगर (rtype == SSH_SK_HELPER_ERROR) {
		अगर ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			जाओ out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		अगर (rerr == 0 || rerr >= पूर्णांक_उच्च)
			r = SSH_ERR_INTERNAL_ERROR;
		अन्यथा
			r = -(पूर्णांक)rerr;
		जाओ out;
	} अन्यथा अगर (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	बंद(fd);
	अगर ((r2 = reap_helper(pid)) != 0) {
		अगर (r == 0) {
			r = r2;
			oerrno = त्रुटि_सं;
		}
	}
	अगर (r == 0) {
		*respp = resp;
		resp = शून्य;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	त्रुटि_सं = oerrno;
	वापस r;

}

पूर्णांक
sshsk_sign(स्थिर अक्षर *provider, काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp, स्थिर u_char *तथ्य, माप_प्रकार datalen,
    u_int compat, स्थिर अक्षर *pin)
{
	पूर्णांक oerrno, r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *kbuf = शून्य, *req = शून्य, *resp = शून्य;

	*sigp = शून्य;
	*lenp = 0;

#अगर_अघोषित ENABLE_SK
	वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
#पूर्ण_अगर

	अगर ((kbuf = sshbuf_new()) == शून्य ||
	    (req = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	अगर ((r = sshkey_private_serialize(कुंजी, kbuf)) != 0) {
		error_fr(r, "encode key");
		जाओ out;
	}
	अगर ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, तथ्य, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, शून्य)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		जाओ out;
	}

	अगर ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		जाओ out;

	अगर ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	अगर (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = शून्य;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	त्रुटि_सं = oerrno;
	वापस r;
}

पूर्णांक
sshsk_enroll(पूर्णांक type, स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *application, स्थिर अक्षर *userid, uint8_t flags,
    स्थिर अक्षर *pin, काष्ठा sshbuf *challenge_buf,
    काष्ठा sshkey **keyp, काष्ठा sshbuf *attest)
{
	पूर्णांक oerrno, r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *kbuf = शून्य, *abuf = शून्य, *req = शून्य, *resp = शून्य;
	काष्ठा sshkey *कुंजी = शून्य;

	*keyp = शून्य;
	अगर (attest != शून्य)
		sshbuf_reset(attest);

#अगर_अघोषित ENABLE_SK
	वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
#पूर्ण_अगर

	अगर (type < 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((abuf = sshbuf_new()) == शून्य ||
	    (kbuf = sshbuf_new()) == शून्य ||
	    (req = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	अगर ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		जाओ out;
	}

	अगर ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		जाओ out;

	अगर ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((r = sshkey_private_deserialize(kbuf, &कुंजी)) != 0) {
		error_fr(r, "encode");
		जाओ out;
	}
	अगर (attest != शून्य && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		जाओ out;
	}

	/* success */
	r = 0;
	*keyp = कुंजी;
	कुंजी = शून्य;
 out:
	oerrno = त्रुटि_सं;
	sshkey_free(कुंजी);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	त्रुटि_सं = oerrno;
	वापस r;
}

अटल व्योम
sshsk_free_resident_कुंजी(काष्ठा sshsk_resident_कुंजी *srk)
{
	अगर (srk == शून्य)
		वापस;
	sshkey_free(srk->कुंजी);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


व्योम
sshsk_free_resident_कुंजियाँ(काष्ठा sshsk_resident_कुंजी **srks, माप_प्रकार nsrks)
{
	माप_प्रकार i;

	अगर (srks == शून्य || nsrks == 0)
		वापस;

	क्रम (i = 0; i < nsrks; i++)
		sshsk_free_resident_कुंजी(srks[i]);
	मुक्त(srks);
}

पूर्णांक
sshsk_load_resident(स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *pin, u_int flags, काष्ठा sshsk_resident_कुंजी ***srksp,
    माप_प्रकार *nsrksp)
{
	पूर्णांक oerrno, r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *kbuf = शून्य, *req = शून्य, *resp = शून्य;
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshsk_resident_कुंजी *srk = शून्य, **srks = शून्य, **tmp;
	u_char *userid = शून्य;
	माप_प्रकार userid_len = 0, nsrks = 0;

	*srksp = शून्य;
	*nsrksp = 0;

	अगर ((kbuf = sshbuf_new()) == शून्य ||
	    (req = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	अगर ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		जाओ out;
	}

	अगर ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		जाओ out;

	जबतक (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		अगर ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, शून्य, शून्य)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर ((r = sshkey_private_deserialize(kbuf, &कुंजी)) != 0) {
			error_fr(r, "decode key");
			जाओ out;
		}
		अगर ((srk = सुस्मृति(1, माप(*srk))) == शून्य) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		srk->कुंजी = कुंजी;
		कुंजी = शून्य;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = शून्य;
		userid_len = 0;
		अगर ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    माप(*srks))) == शून्य) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->कुंजी), srk->कुंजी->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = शून्य;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = शून्य;
	nsrks = 0;
 out:
	oerrno = त्रुटि_सं;
	sshsk_free_resident_कुंजी(srk);
	sshsk_free_resident_कुंजियाँ(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(कुंजी);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	त्रुटि_सं = oerrno;
	वापस r;
}
