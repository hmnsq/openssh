// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <unistd.h>

বাহ্যিক "C" {

#অন্তর্ভাব "includes.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "readconf.h"
#অন্তর্ভাব "xmalloc.h"

// Stub out log output to reduce noise
শূন্য sshsig_free(কাঠামো sshsig_ctx *ctx) {}

}  // extern "C"

স্থির কাঠামো passwd fuzz_pw;
স্থির অক্ষর fuzz_username[] = "fuzzer";
স্থির অক্ষর fuzz_home[] = "/tmp";
স্থির অক্ষর fuzz_shell[] = "/bin/sh";

স্থির শূন্য init_pw(শূন্য) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

বাহ্যিক "C" পূর্ণসংখ্যা LLVMFuzzer_Test_One_প্রবেশ(ধ্রুবক uint8_t *তথ্য, আকার_t আকার_2) {
    স্থির পূর্ণসংখ্যা initialized = 0;
    যদি (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    অক্ষর tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    পূর্ণসংখ্যা fd = mkstemp(tmpfile);
    যদি (fd < 0)
        ফেরত 0;

    যদি (লিখ(fd, তথ্য, আকার_2) != (ssize_t)আকার_2) {
        close(fd);
        unlink(tmpfile);
        ফেরত 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     ফাঁকা, &options, 0, ফাঁকা);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    ফেরত 0;
}
