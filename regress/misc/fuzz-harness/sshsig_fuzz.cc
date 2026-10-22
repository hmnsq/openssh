// cc_fuzz_target test for sshsig verification.

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshsig.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t* sig, ਮਾਪ_t slen)
{
  ਸਥਿਰ ਅਚਲ ਅੱਖਰ *ਅੰਕੜੇ = "If everyone started announcing his nose had "
      "run away, I don’t know how it would all end";
  ਬਣਤਰ sshbuf *signature = sshbuf_from(sig, slen);
  ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ_2 = sshbuf_from(ਅੰਕੜੇ, ਲੜੀ_ਲੰਬਾਈ(ਅੰਕੜੇ));
  ਬਣਤਰ sshkey *k = ਨਿਰਾ;
  ਬਣਤਰ sshkey_sig_details *details = ਨਿਰਾ;
  ਬਾਹਰੀ ਅੱਖਰ *__progname;

  log_init(__progname, SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
  sshsig_verifyb(signature, ਸੁਨੇਹਾ_2, "castle", &k, &details);
  sshkey_sig_details_free(details);
  sshkey_free(k);
  sshbuf_free(signature);
  sshbuf_free(ਸੁਨੇਹਾ_2);
  ਵਾਪਸ 0;
}

} // extern
