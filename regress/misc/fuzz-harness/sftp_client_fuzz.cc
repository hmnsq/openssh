/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for OpenSSH SFTP client response parser (sftp-client.c)
 *
 * Target: sftp-client.c
 *
 * Drives every public sftp-client API on a socketpair using the
 * fuzzer input as the reply payload. A helper opens a fresh
 * socketpair, pre-fills a valid FXP_VERSION reply so sftp_init
 * succeeds, then writes the fuzzer body which the API call consumes
 * as its own response. Each iteration runs all 12 APIs on the same
 * input so no API is starved by a selector byte.
 *
 * Primary functions exercised:
 * - sftp_init, sftp_stat, sftp_lstat, sftp_realpath, sftp_expand_path
 * - sftp_readdir, sftp_statvfs, sftp_get_limits
 * - sftp_rm, sftp_mkdir, sftp_rmdir, sftp_rename, sftp_symlink
 * - decode_attrib via every reply path (sftp-common.c)
 *
 * Threat model: a malicious SFTP server returning crafted attribute
 * lists, name lists, status responses, and statvfs payloads to a
 * connected client (sshfs, sftp, scp to a hostile host).
 *
 * Failure handling: sftp-client.c calls fatal() liberally on
 * protocol violations. A custom cleanup_exit() longjmp()s back to
 * the helper. fuzz_arena (linker --wrap'd malloc family) frees
 * every still-live allocation on both the success and longjmp paths
 * so LSan sees zero per-iteration leaks.
 */

#समावेश <setjmp.h>
#समावेश <signal.h>
#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <sys/socket.h>
#समावेश <sys/types.h>

बाह्य "C" {
#समावेश "includes.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "log.h"
#समावेश "sftp.h"
#समावेश "sftp-common.h"
#समावेश "sftp-client.h"

व्योम fuzz_arena_begin(व्योम);
व्योम fuzz_arena_cleanup(व्योम);
}

बाह्य "C" अस्थिर संक_पूर्ण_प्रकार interrupted = 0;
बाह्य "C" पूर्णांक showprogress = 0;
बाह्य "C" व्योम start_progress_meter(स्थिर अक्षर *file, off_t filesize,
    off_t *ctr) { (व्योम)file; (व्योम)filesize; (व्योम)ctr; }
बाह्य "C" व्योम refresh_progress_meter(पूर्णांक force_update) { (व्योम)force_update; }
बाह्य "C" व्योम stop_progress_meter(व्योम) { }

अटल लाँघ_बफ fuzz_env;
अटल अस्थिर पूर्णांक in_fuzz = 0;

बाह्य "C" व्योम
cleanup_exit(पूर्णांक code)
{
	अगर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_निकास(code);
}

अटल स्थिर uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

क्रमागत {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_PATH,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_गिनती,
};

अटल व्योम
run_one(पूर्णांक api, स्थिर uint8_t *body, माप_प्रकार bsize)
{
	पूर्णांक sv[2] = { -1, -1 };
	अगर (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		वापस;

	ssize_t w = ग_लिखो(sv[0], k_version_reply, माप(k_version_reply));
	(व्योम)w;
	अगर (bsize > 0)
		w = ग_लिखो(sv[0], body, bsize);
	(व्योम)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	अगर (बनाओ_लाँघ(fuzz_env) == 0) {
		काष्ठा sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		अगर (conn != शून्य) {
			Attrib attr;
			attrib_clear(&attr);

			चयन (api) {
			हाल API_STAT: {
				Attrib a;
				(व्योम)sftp_stat(conn, "/fuzz", 1, &a);
				अवरोध;
			}
			हाल API_LSTAT: {
				Attrib a;
				(व्योम)sftp_lstat(conn, "/fuzz", 1, &a);
				अवरोध;
			}
			हाल API_REALPATH: {
				अक्षर *p = sftp_realpath(conn, "/fuzz");
				मुक्त(p);
				अवरोध;
			}
			हाल API_EXPAND_PATH: {
				अक्षर *p = sftp_expand_path(conn, "~");
				मुक्त(p);
				अवरोध;
			}
			हाल API_READDIR: {
				SFTP_DIRENT **dir = शून्य;
				(व्योम)sftp_readdir(conn, "/fuzz", &dir);
				अगर (dir != शून्य)
					sftp_free_dirents(dir);
				अवरोध;
			}
			हाल API_STATVFS: {
				काष्ठा sftp_statvfs vfs;
				(व्योम)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				अवरोध;
			}
			हाल API_GET_LIMITS: {
				काष्ठा sftp_limits lim;
				(व्योम)sftp_get_limits(conn, &lim);
				अवरोध;
			}
			हाल API_RM:
				(व्योम)sftp_rm(conn, "/fuzz");
				अवरोध;
			हाल API_MKDIR:
				(व्योम)sftp_mkdir(conn, "/fuzz", &attr, 0);
				अवरोध;
			हाल API_RMDIR:
				(व्योम)sftp_rmdir(conn, "/fuzz");
				अवरोध;
			हाल API_RENAME:
				(व्योम)sftp_rename(conn, "/a", "/b", 0);
				अवरोध;
			हाल API_SYMLINK:
				(व्योम)sftp_symlink(conn, "/a", "/b");
				अवरोध;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	बंद(sv[0]);
	बंद(sv[1]);
}

बाह्य "C" पूर्णांक
LLVMFuzzer_Test_One_निवेश(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अटल पूर्णांक initialized = 0;
	अगर (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	अगर (आकार > 65536)
		वापस 0;

	क्रम (पूर्णांक api = 0; api < API_गिनती; api++)
		run_one(api, तथ्य, आकार);

	वापस 0;
}
