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

#समावेश <setjmp.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <pwd.h>
#समावेश <sys/types.h>

#समावेश "log.h"

बाह्य व्योम fuzz_arena_begin(व्योम);
बाह्य व्योम fuzz_arena_release(व्योम);
बाह्य व्योम fuzz_arena_cleanup(व्योम);

अटल लाँघ_बफ fuzz_server_env;
अटल अस्थिर पूर्णांक in_fuzz_server = 0;

व्योम
cleanup_exit(पूर्णांक code)
{
	अगर (in_fuzz_server)
		दीर्घ_लाँघ(fuzz_server_env, code ? code : 1);
	_निकास(code);
}

#घोषणा sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#समावेश "../../../sftp-server.c"
#अघोषित sftp_server_cleanup_exit

व्योम
sftp_server_cleanup_exit(पूर्णांक code)
{
	अगर (in_fuzz_server)
		दीर्घ_लाँघ(fuzz_server_env, code ? code : 1);
	_निकास(code);
}

अटल व्योम (* स्थिर __force_use_renamed)(पूर्णांक) =
    __orig_sftp_server_cleanup_exit;

अटल काष्ठा passwd fuzz_pw;
अटल पूर्णांक log_initialized = 0;

अटल व्योम
cleanup_handles(व्योम)
{
	u_int i;
	अगर (handles == शून्य)
		वापस;
	क्रम (i = 0; i < अंक_handles; i++) {
		अगर (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			बंद(handles[i].fd);
		अन्यथा अगर (handles[i].use == HANDLE_DIR && handles[i].dirp != शून्य)
			बंद_सूची(handles[i].dirp);
		मुक्त(handles[i].name);
	}
	मुक्त(handles);
	handles = शून्य;
	अंक_handles = 0;
	first_unused_handle = -1;
}

अटल व्योम
reset_module_globals(व्योम)
{
	pw = &fuzz_pw;
	client_addr = शून्य;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = शून्य;
	request_denylist = शून्य;
	handles = शून्य;
	अंक_handles = 0;
	first_unused_handle = -1;
	iqueue = शून्य;
	oqueue = शून्य;
}

व्योम
fuzz_server_one(स्थिर uint8_t *तथ्य, माप_प्रकार आकार)
{
	अगर (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		अक्षर tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		अगर (mkdtemp(tmpdir) != शून्य && स_बदलो(tmpdir) != 0)
			_निकास(1);

		स_रखो(&fuzz_pw, 0, माप(fuzz_pw));
		fuzz_pw.pw_name = (अक्षर *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (अक्षर *)"/tmp";
		fuzz_pw.pw_shell = (अक्षर *)"/bin/sh";
	}

	अगर (आकार == 0 || आकार > 65000)
		वापस;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	अगर (बनाओ_लाँघ(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		अगर (iqueue == शून्य || oqueue == शून्य)
			जाओ out;

		स्थिर uint8_t init_संदेश[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		अगर (sshbuf_put(iqueue, init_संदेश, माप(init_संदेश)) != 0)
			जाओ out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((आकार >> 24) & 0xff),
		    (uint8_t)((आकार >> 16) & 0xff),
		    (uint8_t)((आकार >> 8) & 0xff),
		    (uint8_t)(आकार & 0xff),
		};
		अगर (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, तथ्य, आकार) != 0)
			जाओ out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		मुक्त(client_addr);
		iqueue = oqueue = शून्य;
		client_addr = शून्य;
		in_fuzz_server = 0;
		fuzz_arena_release();
		वापस;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = शून्य;
	client_addr = शून्य;
}
