/* $OpenBSD: pkcs11.h,v 1.4 2025/07/25 13:06:07 djm Exp $ */
/* pkcs11.h
   Copyright 2006, 2007 g10 Code GmbH
   Copyright 2006 Andreas Jellinghaus

   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even
   the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
   PURPOSE.  */

/* Please submit changes back to the Scute project at
   http://www.scute.org/ (or send them to marcus@g10code.com), so that
   they can be picked up by other projects from there as well.  */

/* This file is a modified implementation of the PKCS #11 standard by
   RSA Security Inc.  It is mostly a drop-in replacement, with the
   following change:

   This header file does not require any macro definitions by the user
   (like CK_DEFINE_FUNCTION etc).  In fact, it defines those macros
   for you (if useful, some are missing, let me know if you need
   more).

   There is an additional API available that does comply better to the
   GNU coding standard.  It can be switched on by defining
   CRYPTOKI_GNU before including this header file.  For this, the
   following changes are made to the specification:

   All structure types are changed to a "struct ck_foo" where CK_FOO
   is the type name in PKCS #11.

   All non-structure types are changed to ck_foo_t where CK_FOO is the
   lowercase version of the type name in PKCS #11.  The basic types
   (CK_ULONG et al.) are removed without substitute.

   All members of structures are modified in the following way: Type
   indication prefixes are removed, and underscore characters are
   inserted before words.  Then the result is lowercased.

   Note that function names are still in the original case, as they
   need for ABI compatibility.

   CK_FALSE, CK_TRUE and NULL_PTR are removed without substitute.  Use
   <stdbool.h>.

   If CRYPTOKI_COMPAT is defined before including this header file,
   then none of the API changes above take place, and the API is the
   one defined by the PKCS #11 standard.  */

#که_نه_تعریف_شوی PKCS11_H
#تعریف_کړه PKCS11_H 1

#إذا defined(__cplusplus)
خارجي "C" {
#د_که_پای


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#تعریف_کړه CRYPTOKI_نسخه_MAJOR		3
#تعریف_کړه CRYPTOKI_نسخه_MINOR		0
#تعریف_کړه CRYPTOKI_نسخه_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#که_نه_تعریف_شوی CRYPTOKI_GNU
#که_نه_تعریف_شوی CRYPTOKI_COMPAT
#تعریف_کړه CRYPTOKI_COMPAT 1
#د_که_پای
#د_که_پای

/* System dependencies.  */

#إذا defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#لارښوونه pack(ټېل, cryptoki, 1)

#که_تعریف_شوی CRYPTOKI_EXPORTS
#تعریف_کړه CK_SPEC __declspec(dllexport)
#وإلا
#تعریف_کړه CK_SPEC __declspec(dllimport)
#د_که_پای

#وإلا

#تعریف_کړه CK_SPEC

#د_که_پای

#که_تعریف_شوی CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#تعریف_کړه ck_flags_t CK_FLAGS
#تعریف_کړه ck_نسخه CK_نسخه

#تعریف_کړه ck_info _CK_INFO
#تعریف_کړه cryptoki_نسخه cryptoki_نسخه_2
#تعریف_کړه manufacturer_id manufacturerID
#تعریف_کړه library_description libraryDescription
#تعریف_کړه library_نسخه library_نسخه_2

#تعریف_کړه ck_notification_t CK_NOTIFICATION
#تعریف_کړه ck_خونه_id_t CK_خونه_ID

#تعریف_کړه ck_خونه_info CK_خونه_INFO
#تعریف_کړه خونه_description خونه_Description
#تعریف_کړه hardware_نسخه hardware_نسخه_2
#تعریف_کړه firmware_نسخه firmware_نسخه_2

#تعریف_کړه ck_token_info _CK_TOKEN_INFO
#تعریف_کړه serial_شمېره serial_شمېره_2
#تعریف_کړه max_session_شمېر ul_Max_Session_شمېر
#تعریف_کړه session_شمېر ul_Session_شمېر
#تعریف_کړه max_rw_session_شمېر ul_Max_Rw_Session_شمېر
#تعریف_کړه rw_session_شمېر ul_Rw_Session_شمېر
#تعریف_کړه max_pin_len ulMaxPinLen
#تعریف_کړه min_pin_len ulMinPinLen
#تعریف_کړه ټول_عامه_حافظه ul_ټول_عامه_حافظه
#تعریف_کړه free_عامه_حافظه ul_Free_عامه_حافظه
#تعریف_کړه ټول_شخصي_حافظه ul_ټول_شخصي_حافظه
#تعریف_کړه free_شخصي_حافظه ul_Free_شخصي_حافظه
#تعریف_کړه utc_وخت utc_وخت_2

#تعریف_کړه ck_session_handle_t CK_SESSION_HANDLE
#تعریف_کړه ck_user_type_t CK_USER_TYPE
#تعریف_کړه ck_state_t CK_STATE

#تعریف_کړه ck_session_info _CK_SESSION_INFO
#تعریف_کړه خونه_id خونه_ID
#تعریف_کړه device_error ulDeviceError

#تعریف_کړه ck_object_handle_t CK_OBJECT_HANDLE
#تعریف_کړه ck_object_class_t CK_OBJECT_CLASS
#تعریف_کړه ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#تعریف_کړه ck_کلی_type_t CK_کلی_TYPE
#تعریف_کړه ck_certificate_type_t CK_CERTIFICATE_TYPE
#تعریف_کړه ck_attribute_type_t CK_ATTRIBUTE_TYPE

#تعریف_کړه ck_attribute _CK_ATTRIBUTE
#تعریف_کړه ارزښت p_ارزښت
#تعریف_کړه ارزښت_len ul_ارزښت_Len

#تعریف_کړه ck_date _CK_DATE

#تعریف_کړه ck_mechanism_type_t CK_MECHANISM_TYPE

#تعریف_کړه ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#تعریف_کړه ck_mechanism _CK_MECHANISM
#تعریف_کړه parameter pParameter
#تعریف_کړه parameter_len ulParameterLen

#تعریف_کړه ck_mechanism_info _CK_MECHANISM_INFO
#تعریف_کړه min_کلی_اندازه ul_Min_کلی_اندازه
#تعریف_کړه max_کلی_اندازه ul_Max_کلی_اندازه

#تعریف_کړه ck_rv_t CK_RV
#تعریف_کړه ck_notify_t CK_NOTIFY

#تعریف_کړه ck_interface CK_INTERFACE

#تعریف_کړه ck_function_list _CK_FUNCTION_LIST
#تعریف_کړه ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#تعریف_کړه ck_createmutex_t CK_CREATEMUTEX
#تعریف_کړه ck_destroymutex_t CK_DESTROYMUTEX
#تعریف_کړه ck_lockmutex_t CK_LOCKMUTEX
#تعریف_کړه ck_unlockmutex_t CK_UNLOCKMUTEX

#تعریف_کړه ck_c_initialize_دلیلونه CK_C_INITIALIZE_دلیلونه
#تعریف_کړه create_mutex CreateMutex
#تعریف_کړه destroy_mutex DestroyMutex
#تعریف_کړه قلف_mutex قلف_Mutex
#تعریف_کړه unlock_mutex UnlockMutex
#تعریف_کړه reserved pReserved

#د_که_پای	/* CRYPTOKI_COMPAT */


تعريفنوع بینښه اوږد ck_flags_t;

بنية ck_نسخه
{
  بینښه حرف major;
  بینښه حرف minor;
};


بنية ck_info
{
  بنية ck_نسخه cryptoki_نسخه;
  بینښه حرف manufacturer_id[32];
  ck_flags_t flags;
  بینښه حرف library_description[32];
  بنية ck_نسخه library_نسخه;
};


تعريفنوع بینښه اوږد ck_notification_t;

#تعریف_کړه CKN_SURRENDER	(0UL)


تعريفنوع بینښه اوږد ck_خونه_id_t;


بنية ck_خونه_info
{
  بینښه حرف خونه_description[64];
  بینښه حرف manufacturer_id[32];
  ck_flags_t flags;
  بنية ck_نسخه hardware_نسخه;
  بنية ck_نسخه firmware_نسخه;
};


#تعریف_کړه CKF_TOKEN_PRESENT	(1UL << 0)
#تعریف_کړه CKF_REMOVABLE_DEVICE	(1UL << 1)
#تعریف_کړه CKF_HW_خونه		(1UL << 2)
#تعریف_کړه CKF_ARRAY_ATTRIBUTE	(1UL << 30)


بنية ck_token_info
{
  بینښه حرف label[32];
  بینښه حرف manufacturer_id[32];
  بینښه حرف model[16];
  بینښه حرف serial_شمېره[16];
  ck_flags_t flags;
  بینښه اوږد max_session_شمېر;
  بینښه اوږد session_شمېر;
  بینښه اوږد max_rw_session_شمېر;
  بینښه اوږد rw_session_شمېر;
  بینښه اوږد max_pin_len;
  بینښه اوږد min_pin_len;
  بینښه اوږد ټول_عامه_حافظه;
  بینښه اوږد free_عامه_حافظه;
  بینښه اوږد ټول_شخصي_حافظه;
  بینښه اوږد free_شخصي_حافظه;
  بنية ck_نسخه hardware_نسخه;
  بنية ck_نسخه firmware_نسخه;
  بینښه حرف utc_وخت[16];
};


#تعریف_کړه CKF_RNG					(1UL << 0)
#تعریف_کړه CKF_WRITE_PROTECTED			(1UL << 1)
#تعریف_کړه CKF_LOGIN_REQUIRED			(1UL << 2)
#تعریف_کړه CKF_USER_PIN_INITIALIZED		(1UL << 3)
#تعریف_کړه CKF_RESTORE_کلی_NOT_NEEDED		(1UL << 5)
#تعریف_کړه CKF_CLOCK_ON_TOKEN			(1UL << 6)
#تعریف_کړه CKF_PROTECTED_AUTHENTICATION_لار	(1UL << 8)
#تعریف_کړه CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#تعریف_کړه CKF_TOKEN_INITIALIZED			(1UL << 10)
#تعریف_کړه CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#تعریف_کړه CKF_USER_PIN_شمېر_ټیټ			(1UL << 16)
#تعریف_کړه CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#تعریف_کړه CKF_USER_PIN_LOCKED			(1UL << 18)
#تعریف_کړه CKF_USER_PIN_منزل_BE_بدل_شوی		(1UL << 19)
#تعریف_کړه CKF_SO_PIN_شمېر_ټیټ			(1UL << 20)
#تعریف_کړه CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#تعریف_کړه CKF_SO_PIN_LOCKED			(1UL << 22)
#تعریف_کړه CKF_SO_PIN_منزل_BE_بدل_شوی		(1UL << 23)

#تعریف_کړه CK_UNAVAILABLE_INFORMATION	((بینښه اوږد) -1)
#تعریف_کړه CK_EFFECTIVELY_INFINITE		(0UL)


تعريفنوع بینښه اوږد ck_session_handle_t;

#تعریف_کړه CK_INVALID_HANDLE	(0UL)


تعريفنوع بینښه اوږد ck_user_type_t;

#تعریف_کړه CKU_SO			(0UL)
#تعریف_کړه CKU_USER		(1UL)
#تعریف_کړه CKU_CONTEXT_SPECIFIC	(2UL)


تعريفنوع بینښه اوږد ck_state_t;

#تعریف_کړه CKS_RO_عامه_SESSION	(0UL)
#تعریف_کړه CKS_RO_USER_FUNCTIONS	(1UL)
#تعریف_کړه CKS_RW_عامه_SESSION	(2UL)
#تعریف_کړه CKS_RW_USER_FUNCTIONS	(3UL)
#تعریف_کړه CKS_RW_SO_FUNCTIONS	(4UL)


بنية ck_session_info
{
  ck_خونه_id_t خونه_id;
  ck_state_t state;
  ck_flags_t flags;
  بینښه اوږد device_error;
};

#تعریف_کړه CKF_RW_SESSION		(1UL << 1)
#تعریف_کړه CKF_SERIAL_SESSION	(1UL << 2)


تعريفنوع بینښه اوږد ck_object_handle_t;


تعريفنوع بینښه اوږد ck_object_class_t;

#تعریف_کړه CKO_معلومات		(0UL)
#تعریف_کړه CKO_CERTIFICATE		(1UL)
#تعریف_کړه CKO_عامه_کلی		(2UL)
#تعریف_کړه CKO_شخصي_کلی		(3UL)
#تعریف_کړه CKO_SECRET_کلی		(4UL)
#تعریف_کړه CKO_HW_FEATURE		(5UL)
#تعریف_کړه CKO_DOMAIN_PARAMETERS	(6UL)
#تعریف_کړه CKO_MECHANISM		(7UL)
#تعریف_کړه CKO_OTP_کلی		(8UL)
#تعریف_کړه CKO_PROFILE		(9UL)
#تعریف_کړه CKO_VENDOR_DEFINED	(1UL << 31)

#تعریف_کړه CKP_INVALID_ID                (0UL)
#تعریف_کړه CKP_BASELINE_PROVIDER         (1UL)
#تعریف_کړه CKP_EXTENDED_PROVIDER         (2UL)
#تعریف_کړه CKP_AUTHENTICATION_TOKEN      (3UL)
#تعریف_کړه CKP_عامه_CERTIFICATES_TOKEN (4UL)
#تعریف_کړه CKP_VENDOR_DEFINED            (1UL << 31)

تعريفنوع بینښه اوږد ck_hw_feature_type_t;

#تعریف_کړه CKH_MONOTONIC_COUNTER	(1UL)
#تعریف_کړه CKH_CLOCK		(2UL)
#تعریف_کړه CKH_USER_INTERFACE	(3UL)
#تعریف_کړه CKH_VENDOR_DEFINED	(1UL << 31)


تعريفنوع بینښه اوږد ck_کلی_type_t;

#تعریف_کړه CKK_RSA			(0UL)
#تعریف_کړه CKK_DSA			(1UL)
#تعریف_کړه CKK_DH			(2UL)
#تعریف_کړه CKK_ECDSA		(3UL)
#تعریف_کړه CKK_EC			(3UL)
#تعریف_کړه CKK_X9_42_DH		(4UL)
#تعریف_کړه CKK_KEA			(5UL)
#تعریف_کړه CKK_GENERIC_SECRET	(0x10UL)
#تعریف_کړه CKK_RC2			(0x11UL)
#تعریف_کړه CKK_RC4			(0x12UL)
#تعریف_کړه CKK_DES			(0x13UL)
#تعریف_کړه CKK_DES2		(0x14UL)
#تعریف_کړه CKK_DES3		(0x15UL)
#تعریف_کړه CKK_CAST		(0x16UL)
#تعریف_کړه CKK_CAST3		(0x17UL)
#تعریف_کړه CKK_CAST128		(0x18UL)
#تعریف_کړه CKK_RC5			(0x19UL)
#تعریف_کړه CKK_IDEA		(0x1aUL)
#تعریف_کړه CKK_SKIPJACK		(0x1bUL)
#تعریف_کړه CKK_BATON		(0x1cUL)
#تعریف_کړه CKK_JUNIPER		(0x1dUL)
#تعریف_کړه CKK_CDMF		(0x1eUL)
#تعریف_کړه CKK_AES			(0x1fUL)
#تعریف_کړه CKK_BLOWFISH		(0x20UL)
#تعریف_کړه CKK_TWOFISH		(0x21UL)
#تعریف_کړه CKK_GOSTR3410		(0x30UL)
#تعریف_کړه CKK_GOSTR3411		(0x31UL)
#تعریف_کړه CKK_GOST28147		(0x32UL)
#تعریف_کړه CKK_EC_EDWARDS		(0x40UL)
#تعریف_کړه CKK_EC_MONTGOMERY	(0x41UL)
#تعریف_کړه CKK_HKDF		(0x42UL)
#تعریف_کړه CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#تعریف_کړه NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#تعریف_کړه CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#تعریف_کړه CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

تعريفنوع بینښه اوږد ck_certificate_type_t;

#تعریف_کړه CKC_X_509		(0UL)
#تعریف_کړه CKC_X_509_ATTR_CERT	(1UL)
#تعریف_کړه CKC_WTLS		(2UL)
#تعریف_کړه CKC_VENDOR_DEFINED	(1UL << 31)


تعريفنوع بینښه اوږد ck_attribute_type_t;

#تعریف_کړه CKA_CLASS			(0UL)
#تعریف_کړه CKA_TOKEN			(1UL)
#تعریف_کړه CKA_شخصي			(2UL)
#تعریف_کړه CKA_LABEL			(3UL)
#تعریف_کړه CKA_UNIQUE_ID		(4UL)
#تعریف_کړه CKA_APPLICATION			(0x10UL)
#تعریف_کړه CKA_ارزښت			(0x11UL)
#تعریف_کړه CKA_OBJECT_ID			(0x12UL)
#تعریف_کړه CKA_CERTIFICATE_TYPE		(0x80UL)
#تعریف_کړه CKA_ISSUER			(0x81UL)
#تعریف_کړه CKA_SERIAL_شمېره		(0x82UL)
#تعریف_کړه CKA_AC_ISSUER			(0x83UL)
#تعریف_کړه CKA_OWNER			(0x84UL)
#تعریف_کړه CKA_ATTR_TYPES			(0x85UL)
#تعریف_کړه CKA_TRUSTED			(0x86UL)
#تعریف_کړه CKA_CERTIFICATE_CATEGORY	(0x87UL)
#تعریف_کړه CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#تعریف_کړه CKA_URL				(0x89UL)
#تعریف_کړه CKA_HASH_د_SUBJECT_عامه_کلی	(0x8aUL)
#تعریف_کړه CKA_HASH_د_ISSUER_عامه_کلی	(0x8bUL)
#تعریف_کړه CKA_CHECK_ارزښت			(0x90UL)
#تعریف_کړه CKA_کلی_TYPE			(0x100UL)
#تعریف_کړه CKA_SUBJECT			(0x101UL)
#تعریف_کړه CKA_ID				(0x102UL)
#تعریف_کړه CKA_SENSITIVE			(0x103UL)
#تعریف_کړه CKA_ENCRYPT			(0x104UL)
#تعریف_کړه CKA_DECRYPT			(0x105UL)
#تعریف_کړه CKA_WRAP			(0x106UL)
#تعریف_کړه CKA_UNWRAP			(0x107UL)
#تعریف_کړه CKA_SIGN			(0x108UL)
#تعریف_کړه CKA_SIGN_RECOVER		(0x109UL)
#تعریف_کړه CKA_VERIFY			(0x10aUL)
#تعریف_کړه CKA_VERIFY_RECOVER		(0x10bUL)
#تعریف_کړه CKA_DERIVE			(0x10cUL)
#تعریف_کړه CKA_پیل_DATE			(0x110UL)
#تعریف_کړه CKA_پای_ټکی_DATE			(0x111UL)
#تعریف_کړه CKA_MODULUS			(0x120UL)
#تعریف_کړه CKA_MODULUS_بټونه		(0x121UL)
#تعریف_کړه CKA_عامه_EXPONENT		(0x122UL)
#تعریف_کړه CKA_شخصي_EXPONENT		(0x123UL)
#تعریف_کړه CKA_اولي_1			(0x124UL)
#تعریف_کړه CKA_اولي_2			(0x125UL)
#تعریف_کړه CKA_EXPONENT_1			(0x126UL)
#تعریف_کړه CKA_EXPONENT_2			(0x127UL)
#تعریف_کړه CKA_COEFFICIENT			(0x128UL)
#تعریف_کړه CKA_عامه_کلی_INFO		(0x129UL)
#تعریف_کړه CKA_اولي			(0x130UL)
#تعریف_کړه CKA_SUBPRIME			(0x131UL)
#تعریف_کړه CKA_بنسټ			(0x132UL)
#تعریف_کړه CKA_اولي_بټونه			(0x133UL)
#تعریف_کړه CKA_SUB_اولي_بټونه		(0x134UL)
#تعریف_کړه CKA_ارزښت_بټونه			(0x160UL)
#تعریف_کړه CKA_ارزښت_LEN			(0x161UL)
#تعریف_کړه CKA_EXTRACTABLE			(0x162UL)
#تعریف_کړه CKA_LOCAL			(0x163UL)
#تعریف_کړه CKA_NEVER_EXTRACTABLE		(0x164UL)
#تعریف_کړه CKA_ALWAYS_SENSITIVE		(0x165UL)
#تعریف_کړه CKA_کلی_GEN_MECHANISM		(0x166UL)
#تعریف_کړه CKA_MODIFIABLE			(0x170UL)
#تعریف_کړه CKA_COPYABLE			(0x171UL)
#تعریف_کړه CKA_DESTROYABLE			(0x172UL)
#تعریف_کړه CKA_ECDSA_PARAMS		(0x180UL)
#تعریف_کړه CKA_EC_PARAMS			(0x180UL)
#تعریف_کړه CKA_EC_ټکی			(0x181UL)
#تعریف_کړه CKA_SECONDARY_AUTH		(0x200UL)
#تعریف_کړه CKA_AUTH_PIN_FLAGS		(0x201UL)
#تعریف_کړه CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#تعریف_کړه CKA_WRAP_WITH_TRUSTED		(0x210UL)
#تعریف_کړه CKA_GOSTR3410_PARAMS		(0x250UL)
#تعریف_کړه CKA_GOSTR3411_PARAMS		(0x251UL)
#تعریف_کړه CKA_GOST28147_PARAMS		(0x252UL)
#تعریف_کړه CKA_HW_FEATURE_TYPE		(0x300UL)
#تعریف_کړه CKA_RESET_ON_INIT		(0x301UL)
#تعریف_کړه CKA_HAS_RESET			(0x302UL)
#تعریف_کړه CKA_PIXEL_X			(0x400UL)
#تعریف_کړه CKA_PIXEL_Y			(0x401UL)
#تعریف_کړه CKA_RESOLUTION			(0x402UL)
#تعریف_کړه CKA_CHAR_لیکې			(0x403UL)
#تعریف_کړه CKA_CHAR_COLUMNS		(0x404UL)
#تعریف_کړه CKA_COLOR			(0x405UL)
#تعریف_کړه CKA_بټونه_فی_PIXEL		(0x406UL)
#تعریف_کړه CKA_CHAR_SETS			(0x480UL)
#تعریف_کړه CKA_ENCODING_METHODS		(0x481UL)
#تعریف_کړه CKA_MIME_TYPES			(0x482UL)
#تعریف_کړه CKA_MECHANISM_TYPE		(0x500UL)
#تعریف_کړه CKA_REQUIRED_CMS_ځانګړتیاوې	(0x501UL)
#تعریف_کړه CKA_DEFAULT_CMS_ځانګړتیاوې	(0x502UL)
#تعریف_کړه CKA_SUPPORTED_CMS_ځانګړتیاوې	(0x503UL)
#تعریف_کړه CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#تعریف_کړه CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#تعریف_کړه CKA_OTP_FORMAT			(0x220UL)
#تعریف_کړه CKA_OTP_اوږدتیا			(0x221UL)
#تعریف_کړه CKA_OTP_وخت_INTERVAL		(0x222UL)
#تعریف_کړه CKA_OTP_USER_FRIENDLY_ډېرپېښ	(0x223UL)
#تعریف_کړه CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#تعریف_کړه CKA_OTP_وخت_REQUIREMENT	(0x225UL)
#تعریف_کړه CKA_OTP_COUNTER_REQUIREMENT	(0x226UL)
#تعریف_کړه CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#تعریف_کړه CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#تعریف_کړه CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#تعریف_کړه CKA_OTP_SERVICE_LOGO		(0x22CUL)
#تعریف_کړه CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#تعریف_کړه CKA_OTP_COUNTER			(0x22EUL)
#تعریف_کړه CKA_OTP_وخت			(0x22FUL)
#تعریف_کړه CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#تعریف_کړه CKA_PROFILE_ID			(0x601UL)
#تعریف_کړه CKA_VENDOR_DEFINED		(1UL << 31)


بنية ck_attribute
{
  ck_attribute_type_t type;
  فراغ *ارزښت;
  بینښه اوږد ارزښت_len;
};


بنية ck_date
{
  بینښه حرف year[4];
  بینښه حرف month[2];
  بینښه حرف day[2];
};


تعريفنوع بینښه اوږد ck_mechanism_type_t;

#تعریف_کړه CKM_RSA_PKCS_کلی_PAIR_GEN	(0UL)
#تعریف_کړه CKM_RSA_PKCS			(1UL)
#تعریف_کړه CKM_RSA_9796			(2UL)
#تعریف_کړه CKM_RSA_X_509			(3UL)
#تعریف_کړه CKM_MD2_RSA_PKCS		(4UL)
#تعریف_کړه CKM_MD5_RSA_PKCS		(5UL)
#تعریف_کړه CKM_SHA1_RSA_PKCS		(6UL)
#تعریف_کړه CKM_RIPEMD128_RSA_PKCS		(7UL)
#تعریف_کړه CKM_RIPEMD160_RSA_PKCS		(8UL)
#تعریف_کړه CKM_RSA_PKCS_OAEP		(9UL)
#تعریف_کړه CKM_RSA_X9_31_کلی_PAIR_GEN	(0xaUL)
#تعریف_کړه CKM_RSA_X9_31			(0xbUL)
#تعریف_کړه CKM_SHA1_RSA_X9_31		(0xcUL)
#تعریف_کړه CKM_RSA_PKCS_PSS		(0xdUL)
#تعریف_کړه CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#تعریف_کړه CKM_DSA_کلی_PAIR_GEN		(0x10UL)
#تعریف_کړه	CKM_DSA				(0x11UL)
#تعریف_کړه CKM_DSA_SHA1			(0x12UL)
#تعریف_کړه CKM_DSA_SHA224			(0x13UL)
#تعریف_کړه CKM_DSA_SHA256			(0x14UL)
#تعریف_کړه CKM_DSA_SHA384			(0x15UL)
#تعریف_کړه CKM_DSA_SHA512			(0x16UL)
#تعریف_کړه CKM_DH_PKCS_کلی_PAIR_GEN	(0x20UL)
#تعریف_کړه CKM_DH_PKCS_DERIVE		(0x21UL)
#تعریف_کړه	CKM_X9_42_DH_کلی_PAIR_GEN	(0x30UL)
#تعریف_کړه CKM_X9_42_DH_DERIVE		(0x31UL)
#تعریف_کړه CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#تعریف_کړه CKM_X9_42_MQV_DERIVE		(0x33UL)
#تعریف_کړه CKM_SHA256_RSA_PKCS		(0x40UL)
#تعریف_کړه CKM_SHA384_RSA_PKCS		(0x41UL)
#تعریف_کړه CKM_SHA512_RSA_PKCS		(0x42UL)
#تعریف_کړه CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#تعریف_کړه CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#تعریف_کړه CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#تعریف_کړه CKM_SHA224_RSA_PKCS		(0x46UL)
#تعریف_کړه CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#تعریف_کړه CKM_SHA3_256_RSA_PKCS		(0x60UL)
#تعریف_کړه CKM_SHA3_384_RSA_PKCS		(0x61UL)
#تعریف_کړه CKM_SHA3_512_RSA_PKCS		(0x62UL)
#تعریف_کړه CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#تعریف_کړه CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#تعریف_کړه CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#تعریف_کړه CKM_SHA3_224_RSA_PKCS		(0x66UL)
#تعریف_کړه CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#تعریف_کړه CKM_RC2_کلی_GEN			(0x100UL)
#تعریف_کړه CKM_RC2_ECB			(0x101UL)
#تعریف_کړه	CKM_RC2_CBC			(0x102UL)
#تعریف_کړه	CKM_RC2_MAC			(0x103UL)
#تعریف_کړه CKM_RC2_MAC_GENERAL		(0x104UL)
#تعریف_کړه CKM_RC2_CBC_PAD			(0x105UL)
#تعریف_کړه CKM_RC4_کلی_GEN			(0x110UL)
#تعریف_کړه CKM_RC4				(0x111UL)
#تعریف_کړه CKM_DES_کلی_GEN			(0x120UL)
#تعریف_کړه CKM_DES_ECB			(0x121UL)
#تعریف_کړه CKM_DES_CBC			(0x122UL)
#تعریف_کړه CKM_DES_MAC			(0x123UL)
#تعریف_کړه CKM_DES_MAC_GENERAL		(0x124UL)
#تعریف_کړه CKM_DES_CBC_PAD			(0x125UL)
#تعریف_کړه CKM_DES2_کلی_GEN		(0x130UL)
#تعریف_کړه CKM_DES3_کلی_GEN		(0x131UL)
#تعریف_کړه CKM_DES3_ECB			(0x132UL)
#تعریف_کړه CKM_DES3_CBC			(0x133UL)
#تعریف_کړه CKM_DES3_MAC			(0x134UL)
#تعریف_کړه CKM_DES3_MAC_GENERAL		(0x135UL)
#تعریف_کړه CKM_DES3_CBC_PAD		(0x136UL)
#تعریف_کړه CKM_DES3_CMAC_GENERAL		(0x137UL)
#تعریف_کړه CKM_DES3_CMAC			(0x138UL)
#تعریف_کړه CKM_CDMF_کلی_GEN		(0x140UL)
#تعریف_کړه CKM_CDMF_ECB			(0x141UL)
#تعریف_کړه CKM_CDMF_CBC			(0x142UL)
#تعریف_کړه CKM_CDMF_MAC			(0x143UL)
#تعریف_کړه CKM_CDMF_MAC_GENERAL		(0x144UL)
#تعریف_کړه CKM_CDMF_CBC_PAD		(0x145UL)
#تعریف_کړه CKM_MD2				(0x200UL)
#تعریف_کړه CKM_MD2_HMAC			(0x201UL)
#تعریف_کړه CKM_MD2_HMAC_GENERAL		(0x202UL)
#تعریف_کړه CKM_MD5				(0x210UL)
#تعریف_کړه CKM_MD5_HMAC			(0x211UL)
#تعریف_کړه CKM_MD5_HMAC_GENERAL		(0x212UL)
#تعریف_کړه CKM_SHA_1			(0x220UL)
#تعریف_کړه CKM_SHA_1_HMAC			(0x221UL)
#تعریف_کړه CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#تعریف_کړه CKM_RIPEMD128			(0x230UL)
#تعریف_کړه CKM_RIPEMD128_HMAC		(0x231UL)
#تعریف_کړه CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#تعریف_کړه CKM_RIPEMD160			(0x240UL)
#تعریف_کړه CKM_RIPEMD160_HMAC		(0x241UL)
#تعریف_کړه CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#تعریف_کړه CKM_SHA256			(0x250UL)
#تعریف_کړه CKM_SHA256_HMAC			(0x251UL)
#تعریف_کړه CKM_SHA256_HMAC_GENERAL		(0x252UL)
#تعریف_کړه CKM_SHA224			(0x255UL)
#تعریف_کړه CKM_SHA224_HMAC			(0x256UL)
#تعریف_کړه CKM_SHA224_HMAC_GENERAL		(0x257UL)
#تعریف_کړه CKM_SHA384			(0x260UL)
#تعریف_کړه CKM_SHA384_HMAC			(0x261UL)
#تعریف_کړه CKM_SHA384_HMAC_GENERAL		(0x262UL)
#تعریف_کړه CKM_SHA512			(0x270UL)
#تعریف_کړه CKM_SHA512_HMAC			(0x271UL)
#تعریف_کړه CKM_SHA512_HMAC_GENERAL		(0x272UL)
#تعریف_کړه CKM_SHA3_256			(0x2B0UL)
#تعریف_کړه CKM_SHA3_256_HMAC		(0x2B1UL)
#تعریف_کړه CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#تعریف_کړه CKM_SHA3_256_کلی_GEN		(0x2B3UL)
#تعریف_کړه CKM_SHA3_224			(0x2B5UL)
#تعریف_کړه CKM_SHA3_224_HMAC		(0x2B6UL)
#تعریف_کړه CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#تعریف_کړه CKM_SHA3_224_کلی_GEN		(0x2B8UL)
#تعریف_کړه CKM_SHA3_384			(0x2C0UL)
#تعریف_کړه CKM_SHA3_384_HMAC		(0x2C1UL)
#تعریف_کړه CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#تعریف_کړه CKM_SHA3_384_کلی_GEN		(0x2C3UL)
#تعریف_کړه CKM_SHA3_512			(0x2D0UL)
#تعریف_کړه CKM_SHA3_512_HMAC		(0x2D1UL)
#تعریف_کړه CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#تعریف_کړه CKM_SHA3_512_کلی_GEN		(0x2D3UL)
#تعریف_کړه CKM_CAST_کلی_GEN		(0x300UL)
#تعریف_کړه CKM_CAST_ECB			(0x301UL)
#تعریف_کړه CKM_CAST_CBC			(0x302UL)
#تعریف_کړه CKM_CAST_MAC			(0x303UL)
#تعریف_کړه CKM_CAST_MAC_GENERAL		(0x304UL)
#تعریف_کړه CKM_CAST_CBC_PAD		(0x305UL)
#تعریف_کړه CKM_CAST3_کلی_GEN		(0x310UL)
#تعریف_کړه CKM_CAST3_ECB			(0x311UL)
#تعریف_کړه CKM_CAST3_CBC			(0x312UL)
#تعریف_کړه CKM_CAST3_MAC			(0x313UL)
#تعریف_کړه CKM_CAST3_MAC_GENERAL		(0x314UL)
#تعریف_کړه CKM_CAST3_CBC_PAD		(0x315UL)
#تعریف_کړه CKM_CAST5_کلی_GEN		(0x320UL)
#تعریف_کړه CKM_CAST128_کلی_GEN		(0x320UL)
#تعریف_کړه CKM_CAST5_ECB			(0x321UL)
#تعریف_کړه CKM_CAST128_ECB			(0x321UL)
#تعریف_کړه CKM_CAST5_CBC			(0x322UL)
#تعریف_کړه CKM_CAST128_CBC			(0x322UL)
#تعریف_کړه CKM_CAST5_MAC			(0x323UL)
#تعریف_کړه	CKM_CAST128_MAC			(0x323UL)
#تعریف_کړه CKM_CAST5_MAC_GENERAL		(0x324UL)
#تعریف_کړه CKM_CAST128_MAC_GENERAL		(0x324UL)
#تعریف_کړه CKM_CAST5_CBC_PAD		(0x325UL)
#تعریف_کړه CKM_CAST128_CBC_PAD		(0x325UL)
#تعریف_کړه CKM_RC5_کلی_GEN			(0x330UL)
#تعریف_کړه CKM_RC5_ECB			(0x331UL)
#تعریف_کړه CKM_RC5_CBC			(0x332UL)
#تعریف_کړه CKM_RC5_MAC			(0x333UL)
#تعریف_کړه CKM_RC5_MAC_GENERAL		(0x334UL)
#تعریف_کړه CKM_RC5_CBC_PAD			(0x335UL)
#تعریف_کړه CKM_IDEA_کلی_GEN		(0x340UL)
#تعریف_کړه CKM_IDEA_ECB			(0x341UL)
#تعریف_کړه	CKM_IDEA_CBC			(0x342UL)
#تعریف_کړه CKM_IDEA_MAC			(0x343UL)
#تعریف_کړه CKM_IDEA_MAC_GENERAL		(0x344UL)
#تعریف_کړه CKM_IDEA_CBC_PAD		(0x345UL)
#تعریف_کړه CKM_GENERIC_SECRET_کلی_GEN	(0x350UL)
#تعریف_کړه CKM_CONCATENATE_بنسټ_AND_کلی	(0x360UL)
#تعریف_کړه CKM_CONCATENATE_بنسټ_AND_معلومات	(0x362UL)
#تعریف_کړه CKM_CONCATENATE_معلومات_AND_بنسټ	(0x363UL)
#تعریف_کړه CKM_XOR_بنسټ_AND_معلومات		(0x364UL)
#تعریف_کړه CKM_ایستل_کلی_FROM_کلی	(0x365UL)
#تعریف_کړه CKM_SSL3_PRE_MASTER_کلی_GEN	(0x370UL)
#تعریف_کړه CKM_SSL3_MASTER_کلی_DERIVE	(0x371UL)
#تعریف_کړه CKM_SSL3_کلی_AND_MAC_DERIVE	(0x372UL)
#تعریف_کړه CKM_SSL3_MASTER_کلی_DERIVE_DH	(0x373UL)
#تعریف_کړه CKM_TLS_PRE_MASTER_کلی_GEN	(0x374UL)
#تعریف_کړه CKM_TLS_MASTER_کلی_DERIVE	(0x375UL)
#تعریف_کړه CKM_TLS_کلی_AND_MAC_DERIVE	(0x376UL)
#تعریف_کړه CKM_TLS_MASTER_کلی_DERIVE_DH	(0x377UL)
#تعریف_کړه CKM_SSL3_MD5_MAC		(0x380UL)
#تعریف_کړه CKM_SSL3_SHA1_MAC		(0x381UL)
#تعریف_کړه CKM_MD5_کلی_DERIVATION		(0x390UL)
#تعریف_کړه CKM_MD2_کلی_DERIVATION		(0x391UL)
#تعریف_کړه CKM_SHA1_کلی_DERIVATION		(0x392UL)
#تعریف_کړه CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#تعریف_کړه CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#تعریف_کړه CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#تعریف_کړه CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#تعریف_کړه CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#تعریف_کړه CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#تعریف_کړه CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#تعریف_کړه CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#تعریف_کړه CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#تعریف_کړه CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#تعریف_کړه CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#تعریف_کړه CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#تعریف_کړه CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#تعریف_کړه CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#تعریف_کړه CKM_PKCS5_PBKD2			(0x3b0UL)
#تعریف_کړه CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#تعریف_کړه CKM_کلی_WRAP_LYNKS		(0x400UL)
#تعریف_کړه CKM_کلی_WRAP_سېټ_OAEP		(0x401UL)
#تعریف_کړه CKM_SKIPJACK_کلی_GEN		(0x1000UL)
#تعریف_کړه CKM_SKIPJACK_ECB64		(0x1001UL)
#تعریف_کړه CKM_SKIPJACK_CBC64		(0x1002UL)
#تعریف_کړه CKM_SKIPJACK_OFB64		(0x1003UL)
#تعریف_کړه CKM_SKIPJACK_CFB64		(0x1004UL)
#تعریف_کړه CKM_SKIPJACK_CFB32		(0x1005UL)
#تعریف_کړه CKM_SKIPJACK_CFB16		(0x1006UL)
#تعریف_کړه CKM_SKIPJACK_CFB8		(0x1007UL)
#تعریف_کړه CKM_SKIPJACK_WRAP		(0x1008UL)
#تعریف_کړه CKM_SKIPJACK_شخصي_WRAP	(0x1009UL)
#تعریف_کړه CKM_SKIPJACK_RELAYX		(0x100aUL)
#تعریف_کړه CKM_KEA_کلی_PAIR_GEN		(0x1010UL)
#تعریف_کړه CKM_KEA_کلی_DERIVE		(0x1011UL)
#تعریف_کړه CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#تعریف_کړه CKM_BATON_کلی_GEN		(0x1030UL)
#تعریف_کړه CKM_BATON_ECB128		(0x1031UL)
#تعریف_کړه CKM_BATON_ECB96			(0x1032UL)
#تعریف_کړه CKM_BATON_CBC128		(0x1033UL)
#تعریف_کړه CKM_BATON_COUNTER		(0x1034UL)
#تعریف_کړه CKM_BATON_SHUFFLE		(0x1035UL)
#تعریف_کړه CKM_BATON_WRAP			(0x1036UL)
#تعریف_کړه CKM_ECDSA_کلی_PAIR_GEN		(0x1040UL)
#تعریف_کړه CKM_EC_کلی_PAIR_GEN		(0x1040UL)
#تعریف_کړه CKM_ECDSA			(0x1041UL)
#تعریف_کړه CKM_ECDSA_SHA1			(0x1042UL)
#تعریف_کړه CKM_ECDSA_SHA224		(0x1043UL)
#تعریف_کړه CKM_ECDSA_SHA256		(0x1044UL)
#تعریف_کړه CKM_ECDSA_SHA384		(0x1045UL)
#تعریف_کړه CKM_ECDSA_SHA512		(0x1046UL)
#تعریف_کړه CKM_ECDSA_SHA3_224		(0x1047UL)
#تعریف_کړه CKM_ECDSA_SHA3_256		(0x1048UL)
#تعریف_کړه CKM_ECDSA_SHA3_384		(0x1049UL)
#تعریف_کړه CKM_ECDSA_SHA3_512		(0x104AUL)
#تعریف_کړه CKM_ECDH1_DERIVE		(0x1050UL)
#تعریف_کړه CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#تعریف_کړه CKM_ECMQV_DERIVE		(0x1052UL)
#تعریف_کړه CKM_EC_EDWARDS_کلی_PAIR_GEN     (0x1055UL)
#تعریف_کړه CKM_EC_MONTGOMERY_کلی_PAIR_GEN  (0x1056UL)
#تعریف_کړه CKM_EDDSA			(0x1057UL)
#تعریف_کړه CKM_JUNIPER_کلی_GEN		(0x1060UL)
#تعریف_کړه CKM_JUNIPER_ECB128		(0x1061UL)
#تعریف_کړه CKM_JUNIPER_CBC128		(0x1062UL)
#تعریف_کړه CKM_JUNIPER_COUNTER		(0x1063UL)
#تعریف_کړه CKM_JUNIPER_SHUFFLE		(0x1064UL)
#تعریف_کړه CKM_JUNIPER_WRAP		(0x1065UL)
#تعریف_کړه CKM_FASTHASH			(0x1070UL)
#تعریف_کړه CKM_AES_کلی_GEN			(0x1080UL)
#تعریف_کړه CKM_AES_ECB			(0x1081UL)
#تعریف_کړه CKM_AES_CBC			(0x1082UL)
#تعریف_کړه CKM_AES_MAC			(0x1083UL)
#تعریف_کړه CKM_AES_MAC_GENERAL		(0x1084UL)
#تعریف_کړه CKM_AES_CBC_PAD			(0x1085UL)
#تعریف_کړه CKM_AES_CTR				(0x1086UL)
#تعریف_کړه CKM_AES_GCM				(0x1087UL)
#تعریف_کړه CKM_AES_CCM				(0x1088UL)
#تعریف_کړه CKM_AES_CTS				(0x1089UL)
#تعریف_کړه CKM_AES_CMAC			(0x108AUL)
#تعریف_کړه CKM_AES_CMAC_GENERAL		(0x108BUL)
#تعریف_کړه CKM_AES_XCBC_MAC		(0x108CUL)
#تعریف_کړه CKM_AES_XCBC_MAC_96		(0x108DUL)
#تعریف_کړه CKM_AES_GMAC			(0x108EUL)
#تعریف_کړه CKM_BLOWFISH_کلی_GEN    (0x1090UL)
#تعریف_کړه CKM_BLOWFISH_CBC        (0x1091UL)
#تعریف_کړه CKM_TWOFISH_کلی_GEN     (0x1092UL)
#تعریف_کړه CKM_TWOFISH_CBC         (0x1093UL)
#تعریف_کړه CKM_DES_ECB_ENCRYPT_معلومات	(0x1100UL)
#تعریف_کړه CKM_DES_CBC_ENCRYPT_معلومات	(0x1101UL)
#تعریف_کړه CKM_DES3_ECB_ENCRYPT_معلومات	(0x1102UL)
#تعریف_کړه CKM_DES3_CBC_ENCRYPT_معلومات	(0x1103UL)
#تعریف_کړه CKM_AES_ECB_ENCRYPT_معلومات	(0x1104UL)
#تعریف_کړه CKM_AES_CBC_ENCRYPT_معلومات	(0x1105UL)
#تعریف_کړه CKM_GOSTR3410_کلی_PAIR_GEN	(0x1200UL)
#تعریف_کړه CKM_GOSTR3410			(0x1201UL)
#تعریف_کړه CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#تعریف_کړه CKM_GOSTR3410_کلی_WRAP  (0x1203UL)
#تعریف_کړه CKM_GOSTR3410_DERIVE    (0x1204UL)
#تعریف_کړه CKM_GOSTR3410_512_کلی_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#تعریف_کړه CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#تعریف_کړه CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#تعریف_کړه CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#تعریف_کړه CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#تعریف_کړه CKM_GOSTR3411			(0x1210UL)
#تعریف_کړه CKM_GOSTR3411_HMAC      (0x1211UL)
#تعریف_کړه CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#تعریف_کړه CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#تعریف_کړه CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#تعریف_کړه CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#تعریف_کړه CKM_GOST28147_کلی_GEN   (0x1220UL)
#تعریف_کړه CKM_GOST28147_ECB       (0x1221UL)
#تعریف_کړه CKM_GOST28147           (0x1222UL)
#تعریف_کړه CKM_GOST28147_MAC       (0x1223UL)
#تعریف_کړه CKM_GOST28147_کلی_WRAP  (0x1224UL)

#تعریف_کړه CKM_DSA_PARAMETER_GEN		(0x2000UL)
#تعریف_کړه CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#تعریف_کړه CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#تعریف_کړه CKM_AES_OFB			(0x2104UL)
#تعریف_کړه CKM_AES_CFB64			(0x2105UL)
#تعریف_کړه CKM_AES_CFB8			(0x2106UL)
#تعریف_کړه CKM_AES_CFB128			(0x2107UL)
#تعریف_کړه CKM_AES_CFB1			(0x2108UL)
#تعریف_کړه CKM_AES_کلی_WRAP		(0x2109UL)
#تعریف_کړه CKM_AES_کلی_WRAP_PAD		(0x210AUL)
#تعریف_کړه CKM_XEDDSA			(0x4029UL)
#تعریف_کړه CKM_HKDF_DERIVE			(0x402AUL)
#تعریف_کړه CKM_HKDF_معلومات			(0x402BUL)
#تعریف_کړه CKM_HKDF_کلی_GEN		(0x402CUL)

#تعریف_کړه CKM_VENDOR_DEFINED		(1UL << 31)

بنية ck_mechanism
{
  ck_mechanism_type_t mechanism;
  فراغ *parameter;
  بینښه اوږد parameter_len;
};


بنية ck_mechanism_info
{
  بینښه اوږد min_کلی_اندازه;
  بینښه اوږد max_کلی_اندازه;
  ck_flags_t flags;
};

#تعریف_کړه CKF_HW			(1UL << 0)

#تعریف_کړه CKF_پیغام_ENCRYPT	(1UL << 1)
#تعریف_کړه CKF_پیغام_DECRYPT	(1UL << 2)
#تعریف_کړه CKF_پیغام_SIGN	(1UL << 3)
#تعریف_کړه CKF_پیغام_VERIFY	(1UL << 4)
#تعریف_کړه CKF_MULTI_پیغام	(1UL << 5)
#تعریف_کړه CKF_پیدا_کړه_OBJECTS	(1UL << 6)

#تعریف_کړه CKF_ENCRYPT		(1UL << 8)
#تعریف_کړه CKF_DECRYPT		(1UL << 9)
#تعریف_کړه CKF_DIGEST		(1UL << 10)
#تعریف_کړه CKF_SIGN		(1UL << 11)
#تعریف_کړه CKF_SIGN_RECOVER	(1UL << 12)
#تعریف_کړه CKF_VERIFY		(1UL << 13)
#تعریف_کړه CKF_VERIFY_RECOVER	(1UL << 14)
#تعریف_کړه CKF_GENERATE		(1UL << 15)
#تعریف_کړه CKF_GENERATE_کلی_PAIR	(1UL << 16)
#تعریف_کړه CKF_WRAP		(1UL << 17)
#تعریف_کړه CKF_UNWRAP		(1UL << 18)
#تعریف_کړه CKF_DERIVE		(1UL << 19)
#تعریف_کړه CKF_EXTENSION		(1UL << 31)

#تعریف_کړه CKF_EC_F_P			(1UL << 20)
#تعریف_کړه CKF_EC_F_2M			(1UL << 21)
#تعریف_کړه CKF_EC_ECPARAMETERS	(1UL << 22)
#تعریف_کړه CKF_EC_OID		(1UL << 23)
#تعریف_کړه CKF_EC_NAMEDCURVE	CKF_EC_OID
#تعریف_کړه CKF_EC_UNCOMPRESS	(1UL << 24)
#تعریف_کړه CKF_EC_COMPRESS		(1UL << 25)
#تعریف_کړه CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#تعریف_کړه CKF_DONT_بلاک				(1UL)

/* Flags for Key derivation */
#تعریف_کړه CKD_NULL			(0x1UL)
#تعریف_کړه CKD_SHA1_KDF			(0x2UL)
#تعریف_کړه CKD_SHA224_KDF			(0x5UL)
#تعریف_کړه CKD_SHA256_KDF			(0x6UL)
#تعریف_کړه CKD_SHA384_KDF			(0x7UL)
#تعریف_کړه CKD_SHA512_KDF			(0x8UL)

تعريفنوع بنية CK_ECDH1_DERIVE_PARAMS {
	بینښه اوږد  kdf;
	بینښه اوږد  ul_Shared_معلومات_Len;
	بینښه حرف *  p_Shared_معلومات;
	بینښه اوږد  ul_عامه_معلومات_Len;
	بینښه حرف *  p_عامه_معلومات;
} CK_ECDH1_DERIVE_PARAMS;

تعريفنوع بنية CK_ECMQV_DERIVE_PARAMS {
	بینښه اوږد kdf;
	بینښه اوږد ul_Shared_معلومات_Len;
	بینښه حرف * p_Shared_معلومات;
	بینښه اوږد ul_عامه_معلومات_Len;
	بینښه حرف * p_عامه_معلومات;
	بینښه اوږد ul_شخصي_معلومات_Len;
	CK_OBJECT_HANDLE h_شخصي_معلومات;
	بینښه اوږد ul_عامه_معلومات_Len2;
	بینښه حرف * p_عامه_Data2;
	CK_OBJECT_HANDLE عامه_کلی_2;
} CK_ECMQV_DERIVE_PARAMS;

تعريفنوع بینښه اوږد ck_rsa_pkcs_mgf_type_t;
تعريفنوع بینښه اوږد CK_RSA_PKCS_OAEP_سرچینه_TYPE;

تعريفنوع بنية CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_سرچینه_TYPE سرچینه;
	فراغ *p_سرچینه_معلومات;
	بینښه اوږد ul_سرچینه_معلومات_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

تعريفنوع بنية CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	بینښه اوږد sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#تعریف_کړه CKG_MGF1_SHA1			(0x00000001UL)
#تعریف_کړه CKG_MGF1_SHA224		(0x00000005UL)
#تعریف_کړه CKG_MGF1_SHA256		(0x00000002UL)
#تعریف_کړه CKG_MGF1_SHA384		(0x00000003UL)
#تعریف_کړه CKG_MGF1_SHA512		(0x00000004UL)
#تعریف_کړه CKG_MGF1_SHA3_224	(0x00000006UL)
#تعریف_کړه CKG_MGF1_SHA3_256	(0x00000007UL)
#تعریف_کړه CKG_MGF1_SHA3_384	(0x00000008UL)
#تعریف_کړه CKG_MGF1_SHA3_512	(0x00000009UL)

#تعریف_کړه CKZ_معلومات_SPECIFIED	(0x00000001UL)

تعريفنوع بنية CK_GCM_PARAMS {
	فراغ * pIv;
	بینښه اوږد ulIvLen;
	بینښه اوږد ul_Iv_بټونه;
	فراغ * pAAD;
	بینښه اوږد ulAADLen;
	بینښه اوږد ul_نښان_بټونه;
} CK_GCM_PARAMS;

تعريفنوع بنية CK_CCM_PARAMS {
	بینښه اوږد ul_معلومات_Len;
	بینښه حرف *pNonce;
	بینښه اوږد ulNonceLen;
	بینښه حرف *pAAD;
	بینښه اوږد ulAADLen;
	بینښه اوږد ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
تعريفنوع بنية CK_EDDSA_PARAMS {
	بینښه حرف phFlag;
	بینښه اوږد ul_Context_معلومات_Len;
	بینښه حرف *p_Context_معلومات;
} CK_EDDSA_PARAMS;

تعريفنوع CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
تعريفنوع بنية CK_XEDDSA_PARAMS {
	بینښه اوږد hash;
} CK_XEDDSA_PARAMS;

تعريفنوع CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

تعريفنوع بنية CK_AES_CTR_PARAMS {
    بینښه اوږد ul_Counter_بټونه;
    بینښه حرف cb[16];
} CK_AES_CTR_PARAMS;

تعريفنوع CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

تعريفنوع بینښه اوږد CK_MAC_GENERAL_PARAMS;

تعريفنوع CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

تعريفنوع بینښه اوږد ck_rv_t;


تعريفنوع ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, فراغ *application);

بنية ck_interface {
  حرف * pInterfaceName;
  فراغ * pFunctionList;
  ck_flags_t flags;
};

#تعریف_کړه CKF_INTERFACE_FORK_خوندي	(0x00000001UL)

/* Forward reference.  */
بنية ck_function_list;
بنية ck_function_list_3_0;

#تعریف_کړه _CK_DECLARE_FUNCTION(name, دلیلونه)	\
تعريفنوع ck_rv_t (*CK_ ## name) دلیلونه;		\
ck_rv_t CK_SPEC name دلیلونه

_CK_DECLARE_FUNCTION (C_Initialize, (فراغ *init_دلیلونه));
_CK_DECLARE_FUNCTION (C_Finalize, (فراغ *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (بنية ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (بنية ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_Get_خونه_List,
		      (بینښه حرف token_present, ck_خونه_id_t *خونه_list,
		       بینښه اوږد *شمېر));
_CK_DECLARE_FUNCTION (C_Get_خونه_Info,
		      (ck_خونه_id_t خونه_id, بنية ck_خونه_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_خونه_id_t خونه_id, بنية ck_token_info *info));
_CK_DECLARE_FUNCTION (C_Wait_For_خونه_Event,
		      (ck_flags_t flags, ck_خونه_id_t *خونه, فراغ *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_خونه_id_t خونه_id,
		       ck_mechanism_type_t *mechanism_list,
		       بینښه اوږد *شمېر));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_خونه_id_t خونه_id, ck_mechanism_type_t type,
		       بنية ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_خونه_id_t خونه_id, بینښه حرف *pin,
		       بینښه اوږد pin_len, بینښه حرف *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, بینښه حرف *pin,
		       بینښه اوږد pin_len));
_CK_DECLARE_FUNCTION (C_سېټ_PIN,
		      (ck_session_handle_t session, بینښه حرف *old_pin,
		       بینښه اوږد old_len, بینښه حرف *new_pin,
		       بینښه اوږد new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_خونه_id_t خونه_id, ck_flags_t flags,
		       فراغ *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_خونه_id_t خونه_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       بنية ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       بینښه حرف *operation_state,
		       بینښه اوږد *operation_state_len));
_CK_DECLARE_FUNCTION (C_سېټ_Operation_State,
		      (ck_session_handle_t session,
		       بینښه حرف *operation_state,
		       بینښه اوږد operation_state_len,
		       ck_object_handle_t encryption_کلی,
		       ck_object_handle_t authentication_کلی));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       بینښه حرف *pin, بینښه اوږد pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       بنية ck_attribute *templ,
		       بینښه اوږد شمېر, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       بنية ck_attribute *templ, بینښه اوږد شمېر,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_اندازه,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بینښه اوږد *اندازه));
_CK_DECLARE_FUNCTION (C_Get_Attribute_ارزښت,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بنية ck_attribute *templ,
		       بینښه اوږد شمېر));
_CK_DECLARE_FUNCTION (C_سېټ_Attribute_ارزښت,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بنية ck_attribute *templ,
		       بینښه اوږد شمېر));
_CK_DECLARE_FUNCTION (C_پیدا_کړه_Objects_Init,
		      (ck_session_handle_t session,
		       بنية ck_attribute *templ,
		       بینښه اوږد شمېر));
_CK_DECLARE_FUNCTION (C_پیدا_کړه_Objects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       بینښه اوږد max_object_شمېر,
		       بینښه اوږد *object_شمېر));
_CK_DECLARE_FUNCTION (C_پیدا_کړه_Objects_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       بینښه حرف *معلومات, بینښه اوږد معلومات_len,
		       بینښه حرف *encrypted_معلومات,
		       بینښه اوږد *encrypted_معلومات_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *part, بینښه اوږد part_len,
		       بینښه حرف *encrypted_part,
		       بینښه اوږد *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       بینښه حرف *وروستی_encrypted_part,
		       بینښه اوږد *وروستی_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       بینښه حرف *encrypted_معلومات,
		       بینښه اوږد encrypted_معلومات_len,
		       بینښه حرف *معلومات, بینښه اوږد *معلومات_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *encrypted_part,
		       بینښه اوږد encrypted_part_len,
		       بینښه حرف *part, بینښه اوږد *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       بینښه حرف *وروستی_part,
		       بینښه اوږد *وروستی_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       بینښه حرف *معلومات, بینښه اوږد معلومات_len,
		       بینښه حرف *digest,
		       بینښه اوږد *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *part, بینښه اوږد part_len));
_CK_DECLARE_FUNCTION (C_Digest_کلی,
		      (ck_session_handle_t session, ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       بینښه حرف *digest,
		       بینښه اوږد *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       بینښه حرف *معلومات, بینښه اوږد معلومات_len,
		       بینښه حرف *signature,
		       بینښه اوږد *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *part, بینښه اوږد part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       بینښه حرف *signature,
		       بینښه اوږد *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       بینښه حرف *معلومات, بینښه اوږد معلومات_len,
		       بینښه حرف *signature,
		       بینښه اوږد *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       بینښه حرف *معلومات, بینښه اوږد معلومات_len,
		       بینښه حرف *signature,
		       بینښه اوږد signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *part, بینښه اوږد part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       بینښه حرف *signature,
		       بینښه اوږد signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       بینښه حرف *signature,
		       بینښه اوږد signature_len,
		       بینښه حرف *معلومات,
		       بینښه اوږد *معلومات_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *part, بینښه اوږد part_len,
		       بینښه حرف *encrypted_part,
		       بینښه اوږد *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *encrypted_part,
		       بینښه اوږد encrypted_part_len,
		       بینښه حرف *part,
		       بینښه اوږد *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *part, بینښه اوږد part_len,
		       بینښه حرف *encrypted_part,
		       بینښه اوږد *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       بینښه حرف *encrypted_part,
		       بینښه اوږد encrypted_part_len,
		       بینښه حرف *part,
		       بینښه اوږد *part_len));

_CK_DECLARE_FUNCTION (C_Generate_کلی,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       بنية ck_attribute *templ,
		       بینښه اوږد شمېر,
		       ck_object_handle_t *کلی));
_CK_DECLARE_FUNCTION (C_Generate_کلی_Pair,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       بنية ck_attribute *عامه_کلی_template,
		       بینښه اوږد عامه_کلی_attribute_شمېر,
		       بنية ck_attribute *شخصي_کلی_template,
		       بینښه اوږد شخصي_کلی_attribute_شمېر,
		       ck_object_handle_t *عامه_کلی,
		       ck_object_handle_t *شخصي_کلی));
_CK_DECLARE_FUNCTION (C_Wrap_کلی,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_کلی,
		       ck_object_handle_t کلی,
		       بینښه حرف *wrapped_کلی,
		       بینښه اوږد *wrapped_کلی_len));
_CK_DECLARE_FUNCTION (C_Unwrap_کلی,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_کلی,
		       بینښه حرف *wrapped_کلی,
		       بینښه اوږد wrapped_کلی_len,
		       بنية ck_attribute *templ,
		       بینښه اوږد attribute_شمېر,
		       ck_object_handle_t *کلی));
_CK_DECLARE_FUNCTION (C_Derive_کلی,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t بنسټ_کلی,
		       بنية ck_attribute *templ,
		       بینښه اوږد attribute_شمېر,
		       ck_object_handle_t *کلی));

_CK_DECLARE_FUNCTION (C_تخم_Random,
		      (ck_session_handle_t session, بینښه حرف *تخم,
		       بینښه اوږد تخم_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       بینښه حرف *random_data,
		       بینښه اوږد random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_حالت, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (بنية ck_interface *interfaces_list,
		       بینښه اوږد *شمېر));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (بینښه حرف *interface_name,
		       بنية ck_نسخه *نسخه,
		       بنية ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       بینښه حرف *pin,
		       بینښه اوږد pin_len,
		       بینښه حرف *username,
		       بینښه اوږد username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_پیغام_Encrypt_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Encrypt_پیغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *associated_معلومات,
		       بینښه اوږد associated_معلومات_len,
		       بینښه حرف *plaintext,
		       بینښه اوږد plaintext_len,
		       بینښه حرف *ciphertext,
		       بینښه اوږد *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پیغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *associated_معلومات,
		       بینښه اوږد associated_معلومات_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پیغام_بل,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *plaintext_part,
		       بینښه اوږد plaintext_part_len,
		       بینښه حرف *ciphertext_part,
		       بینښه اوږد *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پیغام_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیغام_Decrypt_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Decrypt_پیغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *associated_معلومات,
		       بینښه اوږد associated_معلومات_len,
		       بینښه حرف *ciphertext,
		       بینښه اوږد ciphertext_len,
		       بینښه حرف *plaintext,
		       بینښه اوږد *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پیغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *associated_معلومات,
		       بینښه اوږد associated_معلومات_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پیغام_بل,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *ciphertext_part,
		       بینښه اوږد ciphertext_part_len,
		       بینښه حرف *plaintext_part,
		       بینښه اوږد *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پیغام_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیغام_Sign_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Sign_پیغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *معلومات,
		       بینښه اوږد معلومات_len,
		       بینښه حرف *signature,
		       بینښه اوږد *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_پیغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_پیغام_بل,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *معلومات,
		       بینښه اوږد معلومات_len,
		       بینښه حرف *signature,
		       بینښه اوږد *signature_len));
_CK_DECLARE_FUNCTION (C_پیغام_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پیغام_Verify_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t کلی));
_CK_DECLARE_FUNCTION (C_Verify_پیغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *معلومات,
		       بینښه اوږد معلومات_len,
		       بینښه حرف *signature,
		       بینښه اوږد signature_len));
_CK_DECLARE_FUNCTION (C_Verify_پیغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_پیغام_بل,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بینښه اوږد parameter_len,
		       بینښه حرف *معلومات,
		       بینښه اوږد معلومات_len,
		       بینښه حرف *signature,
		       بینښه اوږد signature_len));
_CK_DECLARE_FUNCTION (C_پیغام_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#تعریف_کړه CKF_پای_ټکی_د_پیغام	(0x00000001UL)

بنية ck_function_list
{
  بنية ck_نسخه نسخه;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_خونه_List C_Get_خونه_List;
  CK_C_Get_خونه_Info C_Get_خونه_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_سېټ_PIN C_سېټ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_سېټ_Operation_State C_سېټ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_اندازه C_Get_Object_اندازه;
  CK_C_Get_Attribute_ارزښت C_Get_Attribute_ارزښت;
  CK_C_سېټ_Attribute_ارزښت C_سېټ_Attribute_ارزښت;
  CK_C_پیدا_کړه_Objects_Init C_پیدا_کړه_Objects_Init;
  CK_C_پیدا_کړه_Objects C_پیدا_کړه_Objects;
  CK_C_پیدا_کړه_Objects_Final C_پیدا_کړه_Objects_Final;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_Digest_کلی C_Digest_کلی;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_Generate_کلی C_Generate_کلی;
  CK_C_Generate_کلی_Pair C_Generate_کلی_Pair;
  CK_C_Wrap_کلی C_Wrap_کلی;
  CK_C_Unwrap_کلی C_Unwrap_کلی;
  CK_C_Derive_کلی C_Derive_کلی;
  CK_C_تخم_Random C_تخم_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_حالت C_Get_Function_حالت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_خونه_Event C_Wait_For_خونه_Event;
};

بنية ck_function_list_3_0
{
  بنية ck_نسخه نسخه;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_خونه_List C_Get_خونه_List;
  CK_C_Get_خونه_Info C_Get_خونه_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_سېټ_PIN C_سېټ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_سېټ_Operation_State C_سېټ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_اندازه C_Get_Object_اندازه;
  CK_C_Get_Attribute_ارزښت C_Get_Attribute_ارزښت;
  CK_C_سېټ_Attribute_ارزښت C_سېټ_Attribute_ارزښت;
  CK_C_پیدا_کړه_Objects_Init C_پیدا_کړه_Objects_Init;
  CK_C_پیدا_کړه_Objects C_پیدا_کړه_Objects;
  CK_C_پیدا_کړه_Objects_Final C_پیدا_کړه_Objects_Final;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_Digest_کلی C_Digest_کلی;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_Generate_کلی C_Generate_کلی;
  CK_C_Generate_کلی_Pair C_Generate_کلی_Pair;
  CK_C_Wrap_کلی C_Wrap_کلی;
  CK_C_Unwrap_کلی C_Unwrap_کلی;
  CK_C_Derive_کلی C_Derive_کلی;
  CK_C_تخم_Random C_تخم_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_حالت C_Get_Function_حالت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_خونه_Event C_Wait_For_خونه_Event;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_پیغام_Encrypt_Init C_پیغام_Encrypt_Init;
  CK_C_Encrypt_پیغام C_Encrypt_پیغام;
  CK_C_Encrypt_پیغام_Begin C_Encrypt_پیغام_Begin;
  CK_C_Encrypt_پیغام_بل C_Encrypt_پیغام_بل;
  CK_C_پیغام_Encrypt_Final C_پیغام_Encrypt_Final;
  CK_C_پیغام_Decrypt_Init C_پیغام_Decrypt_Init;
  CK_C_Decrypt_پیغام C_Decrypt_پیغام;
  CK_C_Decrypt_پیغام_Begin C_Decrypt_پیغام_Begin;
  CK_C_Decrypt_پیغام_بل C_Decrypt_پیغام_بل;
  CK_C_پیغام_Decrypt_Final C_پیغام_Decrypt_Final;
  CK_C_پیغام_Sign_Init C_پیغام_Sign_Init;
  CK_C_Sign_پیغام C_Sign_پیغام;
  CK_C_Sign_پیغام_Begin C_Sign_پیغام_Begin;
  CK_C_Sign_پیغام_بل C_Sign_پیغام_بل;
  CK_C_پیغام_Sign_Final C_پیغام_Sign_Final;
  CK_C_پیغام_Verify_Init C_پیغام_Verify_Init;
  CK_C_Verify_پیغام C_Verify_پیغام;
  CK_C_Verify_پیغام_Begin C_Verify_پیغام_Begin;
  CK_C_Verify_پیغام_بل C_Verify_پیغام_بل;
  CK_C_پیغام_Verify_Final C_پیغام_Verify_Final;
};



تعريفنوع ck_rv_t (*ck_createmutex_t) (فراغ **mutex);
تعريفنوع ck_rv_t (*ck_destroymutex_t) (فراغ *mutex);
تعريفنوع ck_rv_t (*ck_lockmutex_t) (فراغ *mutex);
تعريفنوع ck_rv_t (*ck_unlockmutex_t) (فراغ *mutex);


بنية ck_c_initialize_دلیلونه
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t قلف_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  فراغ *reserved;
};


#تعریف_کړه CKF_LIBRARY_CANT_CREATE_OS_تارونه	(1UL << 0)
#تعریف_کړه CKF_OS_LOCKING_OK			(1UL << 1)

#تعریف_کړه CKR_OK					(0UL)
#تعریف_کړه CKR_CANCEL				(1UL)
#تعریف_کړه CKR_HOST_حافظه				(2UL)
#تعریف_کړه CKR_خونه_ID_INVALID			(3UL)
#تعریف_کړه CKR_GENERAL_ERROR			(5UL)
#تعریف_کړه CKR_FUNCTION_FAILED			(6UL)
#تعریف_کړه CKR_ARGUMENTS_BAD			(7UL)
#تعریف_کړه CKR_NO_EVENT				(8UL)
#تعریف_کړه CKR_NEED_منزل_CREATE_تارونه		(9UL)
#تعریف_کړه CKR_CANT_قلف				(0xaUL)
#تعریف_کړه CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#تعریف_کړه CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#تعریف_کړه CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#تعریف_کړه CKR_ATTRIBUTE_ارزښت_INVALID		(0x13UL)
#تعریف_کړه CKR_ACTION_PROHIBITED			(0x1BUL)
#تعریف_کړه CKR_معلومات_INVALID			(0x20UL)
#تعریف_کړه CKR_معلومات_LEN_RANGE			(0x21UL)
#تعریف_کړه CKR_DEVICE_ERROR			(0x30UL)
#تعریف_کړه CKR_DEVICE_حافظه			(0x31UL)
#تعریف_کړه CKR_DEVICE_REMOVED			(0x32UL)
#تعریف_کړه CKR_ENCRYPTED_معلومات_INVALID		(0x40UL)
#تعریف_کړه CKR_ENCRYPTED_معلومات_LEN_RANGE		(0x41UL)
#تعریف_کړه CKR_FUNCTION_CANCELED			(0x50UL)
#تعریف_کړه CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#تعریف_کړه CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#تعریف_کړه CKR_کلی_HANDLE_INVALID			(0x60UL)
#تعریف_کړه CKR_کلی_اندازه_RANGE			(0x62UL)
#تعریف_کړه CKR_کلی_TYPE_INCONSISTENT		(0x63UL)
#تعریف_کړه CKR_کلی_NOT_NEEDED			(0x64UL)
#تعریف_کړه CKR_کلی_بدل_شوی				(0x65UL)
#تعریف_کړه CKR_کلی_NEEDED				(0x66UL)
#تعریف_کړه CKR_کلی_INDIGESTIBLE			(0x67UL)
#تعریف_کړه CKR_کلی_FUNCTION_NOT_PERMITTED		(0x68UL)
#تعریف_کړه CKR_کلی_NOT_WRAPPABLE			(0x69UL)
#تعریف_کړه CKR_کلی_UNEXTRACTABLE			(0x6aUL)
#تعریف_کړه CKR_MECHANISM_INVALID			(0x70UL)
#تعریف_کړه CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#تعریف_کړه CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#تعریف_کړه CKR_OPERATION_فعال			(0x90UL)
#تعریف_کړه CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#تعریف_کړه CKR_PIN_INCORRECT			(0xa0UL)
#تعریف_کړه CKR_PIN_INVALID				(0xa1UL)
#تعریف_کړه CKR_PIN_LEN_RANGE			(0xa2UL)
#تعریف_کړه CKR_PIN_EXPIRED				(0xa3UL)
#تعریف_کړه CKR_PIN_LOCKED				(0xa4UL)
#تعریف_کړه CKR_SESSION_CLOSED			(0xb0UL)
#تعریف_کړه CKR_SESSION_شمېر			(0xb1UL)
#تعریف_کړه CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#تعریف_کړه CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#تعریف_کړه CKR_SESSION_READ_ONLY			(0xb5UL)
#تعریف_کړه CKR_SESSION_EXISTS			(0xb6UL)
#تعریف_کړه CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#تعریف_کړه CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#تعریف_کړه CKR_SIGNATURE_INVALID			(0xc0UL)
#تعریف_کړه CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#تعریف_کړه CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#تعریف_کړه CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#تعریف_کړه CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#تعریف_کړه CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#تعریف_کړه CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#تعریف_کړه	CKR_UNWRAPPING_کلی_HANDLE_INVALID	(0xf0UL)
#تعریف_کړه CKR_UNWRAPPING_کلی_اندازه_RANGE		(0xf1UL)
#تعریف_کړه CKR_UNWRAPPING_کلی_TYPE_INCONSISTENT	(0xf2UL)
#تعریف_کړه CKR_USER_ALREADY_LOGGED_دننه		(0x100UL)
#تعریف_کړه CKR_USER_NOT_LOGGED_دننه			(0x101UL)
#تعریف_کړه CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#تعریف_کړه CKR_USER_TYPE_INVALID			(0x103UL)
#تعریف_کړه CKR_USER_ANOTHER_ALREADY_LOGGED_دننه	(0x104UL)
#تعریف_کړه CKR_USER_TOO_MANY_TYPES			(0x105UL)
#تعریف_کړه CKR_WRAPPED_کلی_INVALID			(0x110UL)
#تعریف_کړه CKR_WRAPPED_کلی_LEN_RANGE		(0x112UL)
#تعریف_کړه CKR_WRAPPING_کلی_HANDLE_INVALID		(0x113UL)
#تعریف_کړه CKR_WRAPPING_کلی_اندازه_RANGE		(0x114UL)
#تعریف_کړه CKR_WRAPPING_کلی_TYPE_INCONSISTENT	(0x115UL)
#تعریف_کړه CKR_RANDOM_تخم_NOT_SUPPORTED		(0x120UL)
#تعریف_کړه CKR_RANDOM_NO_RNG			(0x121UL)
#تعریف_کړه CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#تعریف_کړه CKR_منحني_NOT_SUPPORTED			(0x140UL)
#تعریف_کړه CKR_بفر_TOO_SMALL			(0x150UL)
#تعریف_کړه CKR_SAVED_STATE_INVALID			(0x160UL)
#تعریف_کړه CKR_INFORMATION_SENSITIVE		(0x170UL)
#تعریف_کړه CKR_STATE_UNSAVEABLE			(0x180UL)
#تعریف_کړه CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#تعریف_کړه CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#تعریف_کړه CKR_MUTEX_BAD				(0x1a0UL)
#تعریف_کړه CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#تعریف_کړه CKR_FUNCTION_REJECTED			(0x200UL)
#تعریف_کړه CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#که_تعریف_شوی CRYPTOKI_COMPAT

#تعریف_لغوه CK_DEFINE_FUNCTION
#تعریف_کړه CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#ضمن <stddef.h>

تعريفنوع بینښه حرف CK_BYTE;
تعريفنوع بینښه حرف CK_CHAR;
تعريفنوع بینښه حرف CK_UTF8CHAR;
تعريفنوع بینښه حرف CK_BBOOL;
تعريفنوع بینښه اوږد صحيح CK_ULONG;
تعريفنوع اوږد صحيح CK_LONG;
تعريفنوع CK_BYTE *CK_BYTE_PTR;
تعريفنوع CK_CHAR *CK_CHAR_PTR;
تعريفنوع CK_UTF8CHAR *CK_UTF8CHAR_PTR;
تعريفنوع CK_ULONG *CK_ULONG_PTR;
تعريفنوع فراغ *CK_VOID_PTR;
تعريفنوع فراغ **CK_VOID_PTR_PTR;
#تعریف_کړه CK_FALSE 0
#تعریف_کړه CK_TRUE 1
#که_نه_تعریف_شوی CK_DISABLE_TRUE_FALSE
#که_نه_تعریف_شوی FALSE
#تعریف_کړه FALSE 0
#د_که_پای
#که_نه_تعریف_شوی TRUE
#تعریف_کړه TRUE 1
#د_که_پای
#د_که_پای

تعريفنوع بنية CK_HKDF_PARAMS {
	CK_BBOOL b_ایستل;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_کلی;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#تعریف_کړه CKF_HKDF_SALT_NULL 0x00000001UL
#تعریف_کړه CKF_HKDF_SALT_معلومات 0x00000002UL
#تعریف_کړه CKF_HKDF_SALT_کلی  0x00000004UL

تعريفنوع بنية ck_نسخه CK_نسخه_2;
تعريفنوع بنية ck_نسخه *CK_نسخه_PTR;

تعريفنوع بنية ck_info CK_INFO;
تعريفنوع بنية ck_info *CK_INFO_PTR;

تعريفنوع ck_خونه_id_t *CK_خونه_ID_PTR;

تعريفنوع بنية ck_خونه_info CK_خونه_INFO_2;
تعريفنوع بنية ck_خونه_info *CK_خونه_INFO_PTR;

تعريفنوع بنية ck_token_info CK_TOKEN_INFO;
تعريفنوع بنية ck_token_info *CK_TOKEN_INFO_PTR;

تعريفنوع ck_session_handle_t *CK_SESSION_HANDLE_PTR;

تعريفنوع بنية ck_session_info CK_SESSION_INFO;
تعريفنوع بنية ck_session_info *CK_SESSION_INFO_PTR;

تعريفنوع ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

تعريفنوع ck_object_class_t *CK_OBJECT_CLASS_PTR;

تعريفنوع بنية ck_attribute CK_ATTRIBUTE;
تعريفنوع بنية ck_attribute *CK_ATTRIBUTE_PTR;

تعريفنوع بنية ck_date CK_DATE;
تعريفنوع بنية ck_date *CK_DATE_PTR;

تعريفنوع ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

تعريفنوع ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

تعريفنوع بنية ck_mechanism CK_MECHANISM;
تعريفنوع بنية ck_mechanism *CK_MECHANISM_PTR;

تعريفنوع بنية ck_mechanism_info CK_MECHANISM_INFO;
تعريفنوع بنية ck_mechanism_info *CK_MECHANISM_INFO_PTR;

تعريفنوع بنية ck_interface CK_INTERFACE;
تعريفنوع بنية ck_interface *CK_INTERFACE_PTR;
تعريفنوع بنية ck_interface **CK_INTERFACE_PTR_PTR;

تعريفنوع بنية ck_function_list CK_FUNCTION_LIST;
تعريفنوع بنية ck_function_list *CK_FUNCTION_LIST_PTR;
تعريفنوع بنية ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

تعريفنوع بنية ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
تعريفنوع بنية ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
تعريفنوع بنية ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

تعريفنوع بنية ck_c_initialize_دلیلونه CK_C_INITIALIZE_دلیلونه_2;
تعريفنوع بنية ck_c_initialize_دلیلونه *CK_C_INITIALIZE_دلیلونه_PTR;

#تعریف_کړه NULL_PTR عدم

/* Delete the helper macros defined at the top of the file.  */
#تعریف_لغوه ck_flags_t
#تعریف_لغوه ck_نسخه

#تعریف_لغوه ck_info
#تعریف_لغوه cryptoki_نسخه
#تعریف_لغوه manufacturer_id
#تعریف_لغوه library_description
#تعریف_لغوه library_نسخه

#تعریف_لغوه ck_notification_t
#تعریف_لغوه ck_خونه_id_t

#تعریف_لغوه ck_خونه_info
#تعریف_لغوه خونه_description
#تعریف_لغوه hardware_نسخه
#تعریف_لغوه firmware_نسخه

#تعریف_لغوه ck_token_info
#تعریف_لغوه serial_شمېره
#تعریف_لغوه max_session_شمېر
#تعریف_لغوه session_شمېر
#تعریف_لغوه max_rw_session_شمېر
#تعریف_لغوه rw_session_شمېر
#تعریف_لغوه max_pin_len
#تعریف_لغوه min_pin_len
#تعریف_لغوه ټول_عامه_حافظه
#تعریف_لغوه free_عامه_حافظه
#تعریف_لغوه ټول_شخصي_حافظه
#تعریف_لغوه free_شخصي_حافظه
#تعریف_لغوه utc_وخت

#تعریف_لغوه ck_session_handle_t
#تعریف_لغوه ck_user_type_t
#تعریف_لغوه ck_state_t

#تعریف_لغوه ck_session_info
#تعریف_لغوه خونه_id
#تعریف_لغوه device_error

#تعریف_لغوه ck_object_handle_t
#تعریف_لغوه ck_object_class_t
#تعریف_لغوه ck_hw_feature_type_t
#تعریف_لغوه ck_کلی_type_t
#تعریف_لغوه ck_certificate_type_t
#تعریف_لغوه ck_attribute_type_t

#تعریف_لغوه ck_attribute
#تعریف_لغوه ارزښت
#تعریف_لغوه ارزښت_len

#تعریف_لغوه ck_date

#تعریف_لغوه ck_mechanism_type_t

#تعریف_لغوه ck_rsa_pkcs_mgf_type_t

#تعریف_لغوه ck_mechanism
#تعریف_لغوه parameter
#تعریف_لغوه parameter_len

#تعریف_لغوه ck_mechanism_info
#تعریف_لغوه min_کلی_اندازه
#تعریف_لغوه max_کلی_اندازه

#تعریف_لغوه ck_rv_t
#تعریف_لغوه ck_notify_t

#تعریف_لغوه ck_interface

#تعریف_لغوه ck_function_list
#تعریف_لغوه ck_function_list_3_0

#تعریف_لغوه ck_createmutex_t
#تعریف_لغوه ck_destroymutex_t
#تعریف_لغوه ck_lockmutex_t
#تعریف_لغوه ck_unlockmutex_t

#تعریف_لغوه ck_c_initialize_دلیلونه
#تعریف_لغوه create_mutex
#تعریف_لغوه destroy_mutex
#تعریف_لغوه قلف_mutex
#تعریف_لغوه unlock_mutex
#تعریف_لغوه reserved

#د_که_پای	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#إذا defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#لارښوونه pack(راوباسه, cryptoki)
#د_که_پای

#إذا defined(__cplusplus)
}
#د_که_پای

#د_که_پای	/* PKCS11_H */
