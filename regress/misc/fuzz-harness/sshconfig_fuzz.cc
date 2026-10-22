// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <unistd.h>

बाह्य "C" {

#अन्तर्भाव "includes.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "xmalloc.h"

// Stub out log output to reduce noise
शून्य sshsig_free(संरचना sshsig_ctx *ctx) {}

}  // extern "C"

स्थिर संरचना passwd fuzz_pw;
स्थिर वर्ण fuzz_username[] = "fuzzer";
स्थिर वर्ण fuzz_home[] = "/tmp";
स्थिर वर्ण fuzz_shell[] = "/bin/sh";

स्थिर शून्य init_pw(शून्य) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

बाह्य "C" पूर्णाङ्क LLVMFuzzer_Test_One_आगत(अचर uint8_t *data, माप_प्रकार size) {
    स्थिर पूर्णाङ्क initialized = 0;
    यदि (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    वर्ण क्षणिक_ख[] = "/tmp/sshconfig_fuzz_XXXXXX";
    पूर्णाङ्क fd = mkstemp(क्षणिक_ख);
    यदि (fd < 0)
        फर्काऊ 0;

    यदि (लिख(fd, data, size) != (ssize_t)size) {
        बंद(fd);
        unlink(क्षणिक_ख);
        फर्काऊ 0;
    }
    बंद(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(क्षणिक_ख, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     रिक्त, &options, 0, रिक्त);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(क्षणिक_ख);
    फर्काऊ 0;
}
