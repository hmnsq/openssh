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

#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/types.h>

बाह्य "C" {
#अन्तर्भाव "includes.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sftp.h"
#अन्तर्भाव "sftp-common.h"
#अन्तर्भाव "sftp-client.h"

शून्य fuzz_arena_begin(शून्य);
शून्य fuzz_arena_cleanup(शून्य);
}

बाह्य "C" अस्थिर संक_पूर्ण_प्रकार interrupted = 0;
बाह्य "C" पूर्णांक showprogress = 0;
बाह्य "C" शून्य start_progress_meter(स्थिरांक अक्षर *file, off_t filesize,
    off_t *ctr) { (शून्य)file; (शून्य)filesize; (शून्य)ctr; }
बाह्य "C" शून्य refresh_progress_meter(पूर्णांक force_update) { (शून्य)force_update; }
बाह्य "C" शून्य stop_progress_meter(शून्य) { }

स्थिर लाँघ_बफ fuzz_env;
स्थिर अस्थिर पूर्णांक in_fuzz = 0;

बाह्य "C" शून्य
cleanup_exit(पूर्णांक code)
{
	जर (in_fuzz)
		दीर्घ_लाँघ(fuzz_env, code ? code : 1);
	_exit(code);
}

स्थिर स्थिरांक uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

गणना {
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
	API_मोजणी,
};

स्थिर शून्य
run_one(पूर्णांक api, स्थिरांक uint8_t *body, माप_प्रकार bsize)
{
	पूर्णांक sv[2] = { -1, -1 };
	जर (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		परत;

	ssize_t w = लिख(sv[0], k_version_reply, आकार(k_version_reply));
	(शून्य)w;
	जर (bsize > 0)
		w = लिख(sv[0], body, bsize);
	(शून्य)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	जर (बनाओ_लाँघ(fuzz_env) == 0) {
		संरचना sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		जर (conn != रिक्त) {
			Attrib attr;
			attrib_clear(&attr);

			निवड (api) {
			स्थिती API_STAT: {
				Attrib a;
				(शून्य)sftp_stat(conn, "/fuzz", 1, &a);
				थांबा;
			}
			स्थिती API_LSTAT: {
				Attrib a;
				(शून्य)sftp_lstat(conn, "/fuzz", 1, &a);
				थांबा;
			}
			स्थिती API_REALPATH: {
				अक्षर *p = sftp_realpath(conn, "/fuzz");
				मुक्त(p);
				थांबा;
			}
			स्थिती API_EXPAND_PATH: {
				अक्षर *p = sftp_expand_path(conn, "~");
				मुक्त(p);
				थांबा;
			}
			स्थिती API_READDIR: {
				SFTP_DIRENT **dir = रिक्त;
				(शून्य)sftp_readdir(conn, "/fuzz", &dir);
				जर (dir != रिक्त)
					sftp_free_dirents(dir);
				थांबा;
			}
			स्थिती API_STATVFS: {
				संरचना sftp_statvfs vfs;
				(शून्य)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				थांबा;
			}
			स्थिती API_GET_LIMITS: {
				संरचना sftp_limits lim;
				(शून्य)sftp_get_limits(conn, &lim);
				थांबा;
			}
			स्थिती API_RM:
				(शून्य)sftp_rm(conn, "/fuzz");
				थांबा;
			स्थिती API_MKDIR:
				(शून्य)sftp_mkdir(conn, "/fuzz", &attr, 0);
				थांबा;
			स्थिती API_RMDIR:
				(शून्य)sftp_rmdir(conn, "/fuzz");
				थांबा;
			स्थिती API_RENAME:
				(शून्य)sftp_rename(conn, "/a", "/b", 0);
				थांबा;
			स्थिती API_SYMLINK:
				(शून्य)sftp_symlink(conn, "/a", "/b");
				थांबा;
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
LLVMFuzzer_Test_One_आदान(स्थिरांक uint8_t *data, माप_प्रकार size)
{
	स्थिर पूर्णांक initialized = 0;
	जर (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	जर (size > 65536)
		परत 0;

	साठी (पूर्णांक api = 0; api < API_मोजणी; api++)
		run_one(api, data, size);

	परत 0;
}
