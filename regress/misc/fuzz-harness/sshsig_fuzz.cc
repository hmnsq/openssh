// cc_fuzz_target test for sshsig verification.

#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

ബാഹ്യ "C" {

#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshsig.h"
#അന്തര്ഭാവ "log.h"

പൂർണ്ണസംഖ്യ LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t* sig, size_t slen)
{
  സ്ഥിതം സ്ഥിരം അക്ഷരം *data = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ഘടന sshbuf *signature = sshbuf_from(sig, slen);
  ഘടന sshbuf *message = sshbuf_from(data, strlen(data));
  ഘടന sshkey *k = ശൂന്യ;
  ഘടന sshkey_sig_details *details = ശൂന്യ;
  ബാഹ്യ അക്ഷരം *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, message, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(message);
  തിരികെ 0;
}

} // extern
