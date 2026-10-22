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
 * Fuzzer for OpenSSH SFTP server message dispatch (sftp-server.c)
 *
 * Target: sftp-server.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sftp-server.c so
 * process() and the static process_* handlers, plus the file-scope
 * globals (iqueue, oqueue, pw, init_done, handles), are reachable from
 * this translation unit. Each iteration bootstraps an FXP_INIT then
 * feeds the fuzzer input as a single framed SFTP message.
 *
 * Primary functions exercised:
 * - process() and the 17 base process_* handlers (open / close / read /
 *   write / stat / lstat / fstat / setstat / fsetstat / opendir /
 *   readdir / remove / mkdir / rmdir / realpath / rename / readlink /
 *   symlink)
 * - process_extended_* (11 variants including posix-rename, statvfs,
 *   hardlink, fsync, lsetstat, limits, expand-path, copy-data,
 *   home-directory, users-groups-by-id)
 * - decode_attrib / encode_attrib (sftp-common.c)
 *
 * Failure handling: fatal() -> cleanup_exit() and
 * sftp_server_cleanup_exit() are intercepted with overriding
 * definitions that longjmp() back to the entry point. fuzz_arena
 * (linker --wrap'd malloc family) frees every still-live allocation on
 * recovery so LSan sees zero per-iteration leaks.
 */

#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <sys/types.h>

#అన్తర్భావ "log.h"

బాహ్య శూన్య fuzz_arena_begin(శూన్య);
బాహ్య శూన్య fuzz_arena_release(శూన్య);
బాహ్య శూన్య fuzz_arena_cleanup(శూన్య);

స్థిర jmp_buf fuzz_server_env;
స్థిర అస్థిర పూర్ణాంకం లోపల_fuzz_server = 0;

శూన్య
cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz_server)
		longjmp(fuzz_server_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

#నిర్వచించు sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#అన్తర్భావ "../../../sftp-server.c"
#నిర్వచనం_రద్దు sftp_server_cleanup_exit

శూన్య
sftp_server_cleanup_exit(పూర్ణాంకం సంకేతం_2)
{
	ఒకవేళ (లోపల_fuzz_server)
		longjmp(fuzz_server_env, సంకేతం_2 ? సంకేతం_2 : 1);
	_exit(సంకేతం_2);
}

స్థిర శూన్య (* స్థిరరాశి __force_use_renamed)(పూర్ణాంకం) =
    __orig_sftp_server_cleanup_exit;

స్థిర నిర్మాణం passwd fuzz_pw;
స్థిర పూర్ణాంకం log_initialized = 0;

స్థిర శూన్య
cleanup_handles(శూన్య)
{
	u_int i;
	ఒకవేళ (handles == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < అంకె_handles; i++) {
		ఒకవేళ (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		లేకపోతే ఒకవేళ (handles[i].use == HANDLE_DIR && handles[i].dirp != ఖాళీ)
			closedir(handles[i].dirp);
		విడుదల(handles[i].name);
	}
	విడుదల(handles);
	handles = ఖాళీ;
	అంకె_handles = 0;
	మొదటి_వాడని_handle = -1;
}

స్థిర శూన్య
reset_module_globals(శూన్య)
{
	pw = &fuzz_pw;
	client_addr = ఖాళీ;
	సంస్కరణ = 0;
	init_పూర్తి = 0;
	readonly = 0;
	request_allowlist = ఖాళీ;
	request_denylist = ఖాళీ;
	handles = ఖాళీ;
	అంకె_handles = 0;
	మొదటి_వాడని_handle = -1;
	iqueue = ఖాళీ;
	oqueue = ఖాళీ;
}

శూన్య
fuzz_server_one(స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t కొలత)
{
	ఒకవేళ (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		అక్షరం tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		ఒకవేళ (mkdtemp(tmpdir) != ఖాళీ && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, పరిమాణం(fuzz_pw));
		fuzz_pw.pw_name = (అక్షరం *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (అక్షరం *)"/tmp";
		fuzz_pw.pw_shell = (అక్షరం *)"/bin/sh";
	}

	ఒకవేళ (కొలత == 0 || కొలత > 65000)
		తిరిగి;

	reset_module_globals();

	fuzz_arena_begin();
	లోపల_fuzz_server = 1;
	ఒకవేళ (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		ఒకవేళ (iqueue == ఖాళీ || oqueue == ఖాళీ)
			వెళ్ళు బహిర్గతం;

		స్థిరరాశి uint8_t init_సందేశం[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		ఒకవేళ (sshbuf_put(iqueue, init_సందేశం, పరిమాణం(init_సందేశం)) != 0)
			వెళ్ళు బహిర్గతం;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((కొలత >> 24) & 0xff),
		    (uint8_t)((కొలత >> 16) & 0xff),
		    (uint8_t)((కొలత >> 8) & 0xff),
		    (uint8_t)(కొలత & 0xff),
		};
		ఒకవేళ (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, దత్తాంశం, కొలత) != 0)
			వెళ్ళు బహిర్గతం;
		process();
	బహిర్గతం:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		విడుదల(client_addr);
		iqueue = oqueue = ఖాళీ;
		client_addr = ఖాళీ;
		లోపల_fuzz_server = 0;
		fuzz_arena_release();
		తిరిగి;
	}
	cleanup_handles();
	లోపల_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = ఖాళీ;
	client_addr = ఖాళీ;
}
