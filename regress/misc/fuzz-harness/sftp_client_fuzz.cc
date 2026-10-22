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

#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/types.h>

బాహ్య "C" {
#అన్తర్భావ "includes.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sftp.h"
#అన్తర్భావ "sftp-common.h"
#అన్తర్భావ "sftp-client.h"

శూన్య fuzz_arena_begin(శూన్య);
శూన్య fuzz_arena_cleanup(శూన్య);
}

బాహ్య "C" అస్థిర sig_atomic_t interrupted = 0;
బాహ్య "C" పూర్ణాంకం showprogress = 0;
బాహ్య "C" శూన్య ప్రారంభం_పురోగతి_meter(స్థిరరాశి అక్షరం *file, off_t filesize,
    off_t *ctr) { (శూన్య)file; (శూన్య)filesize; (శూన్య)ctr; }
బాహ్య "C" శూన్య refresh_పురోగతి_meter(పూర్ణాంకం force_update) { (శూన్య)force_update; }
బాహ్య "C" శూన్య stop_పురోగతి_meter(శూన్య) { }

స్థిర jmp_buf fuzz_env;
స్థిర అస్థిర పూర్ణాంకం లోపల_fuzz = 0;

బాహ్య "C" శూన్య
cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz)
		longjmp(fuzz_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

స్థిర స్థిరరాశి uint8_t k_సంస్కరణ_జవాబు[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

గణన {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_మార్గం,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_లెక్క,
};

స్థిర శూన్య
నిరంతరం_one(పూర్ణాంకం api, స్థిరరాశి uint8_t *body, కొలత_t bsize)
{
	పూర్ణాంకం sv[2] = { -1, -1 };
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		తిరిగి;

	ssize_t w = లిఖ(sv[0], k_సంస్కరణ_జవాబు, పరిమాణం(k_సంస్కరణ_జవాబు));
	(శూన్య)w;
	ఒకవేళ (bsize > 0)
		w = లిఖ(sv[0], body, bsize);
	(శూన్య)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	లోపల_fuzz = 1;
	ఒకవేళ (setjmp(fuzz_env) == 0) {
		నిర్మాణం sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		ఒకవేళ (conn != ఖాళీ) {
			Attrib attr;
			attrib_clear(&attr);

			ఎంపిక (api) {
			స్థితి API_STAT: {
				Attrib a;
				(శూన్య)sftp_stat(conn, "/fuzz", 1, &a);
				ఆపు;
			}
			స్థితి API_LSTAT: {
				Attrib a;
				(శూన్య)sftp_lstat(conn, "/fuzz", 1, &a);
				ఆపు;
			}
			స్థితి API_REALPATH: {
				అక్షరం *p = sftp_realpath(conn, "/fuzz");
				విడుదల(p);
				ఆపు;
			}
			స్థితి API_EXPAND_మార్గం: {
				అక్షరం *p = sftp_expand_మార్గం(conn, "~");
				విడుదల(p);
				ఆపు;
			}
			స్థితి API_READDIR: {
				SFTP_DIRENT **dir = ఖాళీ;
				(శూన్య)sftp_readdir(conn, "/fuzz", &dir);
				ఒకవేళ (dir != ఖాళీ)
					sftp_free_dirents(dir);
				ఆపు;
			}
			స్థితి API_STATVFS: {
				నిర్మాణం sftp_statvfs vfs;
				(శూన్య)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				ఆపు;
			}
			స్థితి API_GET_LIMITS: {
				నిర్మాణం sftp_limits lim;
				(శూన్య)sftp_get_limits(conn, &lim);
				ఆపు;
			}
			స్థితి API_RM:
				(శూన్య)sftp_rm(conn, "/fuzz");
				ఆపు;
			స్థితి API_MKDIR:
				(శూన్య)sftp_mkdir(conn, "/fuzz", &attr, 0);
				ఆపు;
			స్థితి API_RMDIR:
				(శూన్య)sftp_rmdir(conn, "/fuzz");
				ఆపు;
			స్థితి API_RENAME:
				(శూన్య)sftp_rename(conn, "/a", "/b", 0);
				ఆపు;
			స్థితి API_SYMLINK:
				(శూన్య)sftp_symlink(conn, "/a", "/b");
				ఆపు;
			}

			sftp_free(conn);
		}
	}
	లోపల_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

బాహ్య "C" పూర్ణాంకం
LLVMFuzzer_Test_One_ఆదానం(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	స్థిర పూర్ణాంకం initialized = 0;
	ఒకవేళ (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	ఒకవేళ (కొలత > 65536)
		తిరిగి 0;

	కొరకు (పూర్ణాంకం api = 0; api < API_లెక్క; api++)
		నిరంతరం_one(api, దత్తాంశం, కొలత);

	తిరిగి 0;
}
