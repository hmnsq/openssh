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

#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਬਾਹਰੀ ਖਾਲੀ fuzz_arena_begin(ਖਾਲੀ);
ਬਾਹਰੀ ਖਾਲੀ fuzz_arena_release(ਖਾਲੀ);
ਬਾਹਰੀ ਖਾਲੀ fuzz_arena_cleanup(ਖਾਲੀ);

ਸਥਿਰ jmp_buf fuzz_server_env;
ਸਥਿਰ ਅਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_fuzz_server = 0;

ਖਾਲੀ
cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz_server)
		longjmp(fuzz_server_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#ਅਨ੍ਤਰ੍ਭਾਵ "../../../sftp-server.c"
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ sftp_server_cleanup_exit

ਖਾਲੀ
sftp_server_cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz_server)
		longjmp(fuzz_server_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

ਸਥਿਰ ਖਾਲੀ (* ਅਚਲ __force_use_renamed)(ਪੂਰਨ) =
    __orig_sftp_server_cleanup_exit;

ਸਥਿਰ ਬਣਤਰ passwd fuzz_pw;
ਸਥਿਰ ਪੂਰਨ log_initialized = 0;

ਸਥਿਰ ਖਾਲੀ
cleanup_handles(ਖਾਲੀ)
{
	u_int i;
	ਜੇ (handles == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < ਅੰਕ_handles; i++) {
		ਜੇ (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		ਨਹੀਂਤਾਂ ਜੇ (handles[i].use == HANDLE_DIR && handles[i].dirp != ਨਿਰਾ)
			closedir(handles[i].dirp);
		ਮੁਕਤ(handles[i].name);
	}
	ਮੁਕਤ(handles);
	handles = ਨਿਰਾ;
	ਅੰਕ_handles = 0;
	ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle = -1;
}

ਸਥਿਰ ਖਾਲੀ
reset_module_globals(ਖਾਲੀ)
{
	pw = &fuzz_pw;
	client_addr = ਨਿਰਾ;
	ਸੰਸਕਰਣ = 0;
	init_ਪੂਰਾ = 0;
	readonly = 0;
	request_allowlist = ਨਿਰਾ;
	request_denylist = ਨਿਰਾ;
	handles = ਨਿਰਾ;
	ਅੰਕ_handles = 0;
	ਪਹਿਲਾ_ਅਣਵਰਤਿਆ_handle = -1;
	iqueue = ਨਿਰਾ;
	oqueue = ਨਿਰਾ;
}

ਖਾਲੀ
fuzz_server_one(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਜੇ (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		ਅੱਖਰ tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		ਜੇ (mkdtemp(tmpdir) != ਨਿਰਾ && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, ਆਕਾਰ(fuzz_pw));
		fuzz_pw.pw_name = (ਅੱਖਰ *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (ਅੱਖਰ *)"/tmp";
		fuzz_pw.pw_shell = (ਅੱਖਰ *)"/bin/sh";
	}

	ਜੇ (ਮਾਪ == 0 || ਮਾਪ > 65000)
		ਵਾਪਸ;

	reset_module_globals();

	fuzz_arena_begin();
	ਵਿੱਚ_fuzz_server = 1;
	ਜੇ (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		ਜੇ (iqueue == ਨਿਰਾ || oqueue == ਨਿਰਾ)
			ਜਾਓ ਬਾਹਰਲਾ;

		ਅਚਲ uint8_t init_ਸੁਨੇਹਾ[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		ਜੇ (sshbuf_put(iqueue, init_ਸੁਨੇਹਾ, ਆਕਾਰ(init_ਸੁਨੇਹਾ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((ਮਾਪ >> 24) & 0xff),
		    (uint8_t)((ਮਾਪ >> 16) & 0xff),
		    (uint8_t)((ਮਾਪ >> 8) & 0xff),
		    (uint8_t)(ਮਾਪ & 0xff),
		};
		ਜੇ (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, ਅੰਕੜੇ, ਮਾਪ) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		process();
	ਬਾਹਰਲਾ:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		ਮੁਕਤ(client_addr);
		iqueue = oqueue = ਨਿਰਾ;
		client_addr = ਨਿਰਾ;
		ਵਿੱਚ_fuzz_server = 0;
		fuzz_arena_release();
		ਵਾਪਸ;
	}
	cleanup_handles();
	ਵਿੱਚ_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = ਨਿਰਾ;
	client_addr = ਨਿਰਾ;
}
