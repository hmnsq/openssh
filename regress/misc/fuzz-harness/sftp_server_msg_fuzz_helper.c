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

#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ "log.h"

ಬಾಹ್ಯ ಶೂನ್ಯ fuzz_arena_begin(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ fuzz_arena_release(ಶೂನ್ಯ);
ಬಾಹ್ಯ ಶೂನ್ಯ fuzz_arena_cleanup(ಶೂನ್ಯ);

ಸ್ಥಿರ jmp_buf fuzz_server_env;
ಸ್ಥಿರ ಚಞ್ಚಲ ಪೂರ್ಣಾಙ್ಕ in_fuzz_server = 0;

ಶೂನ್ಯ
cleanup_exit(ಪೂರ್ಣಾಙ್ಕ code)
{
	ಯದಿ (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#ಅನ್ತರ್ಭಾವ "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

ಶೂನ್ಯ
sftp_server_cleanup_exit(ಪೂರ್ಣಾಙ್ಕ code)
{
	ಯದಿ (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

ಸ್ಥಿರ ಶೂನ್ಯ (* ಧ್ರುವ __force_use_renamed)(ಪೂರ್ಣಾಙ್ಕ) =
    __orig_sftp_server_cleanup_exit;

ಸ್ಥಿರ ಸಂರಚನಾ passwd fuzz_pw;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ log_initialized = 0;

ಸ್ಥಿರ ಶೂನ್ಯ
cleanup_handles(ಶೂನ್ಯ)
{
	u_int i;
	ಯದಿ (handles == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_handles; i++) {
		ಯದಿ (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		ಅನ್ಯಥಾ ಯದಿ (handles[i].use == HANDLE_DIR && handles[i].dirp != ರಿಕ್ತ)
			closedir(handles[i].dirp);
		ಮುಕ್ತ(handles[i].name);
	}
	ಮುಕ್ತ(handles);
	handles = ರಿಕ್ತ;
	ಅಂಕೆ_handles = 0;
	first_unused_handle = -1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
reset_module_globals(ಶೂನ್ಯ)
{
	pw = &fuzz_pw;
	client_addr = ರಿಕ್ತ;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = ರಿಕ್ತ;
	request_denylist = ರಿಕ್ತ;
	handles = ರಿಕ್ತ;
	ಅಂಕೆ_handles = 0;
	first_unused_handle = -1;
	iqueue = ರಿಕ್ತ;
	oqueue = ರಿಕ್ತ;
}

ಶೂನ್ಯ
fuzz_server_one(ಧ್ರುವ uint8_t *data, size_t size)
{
	ಯದಿ (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		ವರ್ಣ tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		ಯದಿ (mkdtemp(tmpdir) != ರಿಕ್ತ && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, ಪರಿಮಾಣ(fuzz_pw));
		fuzz_pw.pw_name = (ವರ್ಣ *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (ವರ್ಣ *)"/tmp";
		fuzz_pw.pw_shell = (ವರ್ಣ *)"/bin/sh";
	}

	ಯದಿ (size == 0 || size > 65000)
		ಪ್ರತ್ಯಾಗಮ;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	ಯದಿ (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		ಯದಿ (iqueue == ರಿಕ್ತ || oqueue == ರಿಕ್ತ)
			ಗಚ್ಛ out;

		ಧ್ರುವ uint8_t init_ಸಂದೇಶ[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		ಯದಿ (sshbuf_put(iqueue, init_ಸಂದೇಶ, ಪರಿಮಾಣ(init_ಸಂದೇಶ)) != 0)
			ಗಚ್ಛ out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		ಯದಿ (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			ಗಚ್ಛ out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		ಮುಕ್ತ(client_addr);
		iqueue = oqueue = ರಿಕ್ತ;
		client_addr = ರಿಕ್ತ;
		in_fuzz_server = 0;
		fuzz_arena_release();
		ಪ್ರತ್ಯಾಗಮ;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = ರಿಕ್ತ;
	client_addr = ರಿಕ್ತ;
}
