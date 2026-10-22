// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <unistd.h>

வெளி "C" {

#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "xmalloc.h"

// Stub out log output to reduce noise
வெறுமை sshsig_free(கட்டமைப்பு sshsig_ctx *ctx) {}

}  // extern "C"

நிலையான கட்டமைப்பு passwd fuzz_pw;
நிலையான எழுத்து fuzz_username[] = "fuzzer";
நிலையான எழுத்து fuzz_home[] = "/tmp";
நிலையான எழுத்து fuzz_shell[] = "/bin/sh";

நிலையான வெறுமை init_pw(வெறுமை) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

வெளி "C" முழு LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size) {
    நிலையான முழு initialized = 0;
    எனில் (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    எழுத்து tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    முழு fd = mkstemp(tmpfile);
    எனில் (fd < 0)
        திரும்பு 0;

    எனில் (லிக(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        திரும்பு 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     வெற்று, &options, 0, வெற்று);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    திரும்பு 0;
}
