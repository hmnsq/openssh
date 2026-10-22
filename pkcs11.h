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

#جيڪڏهن_وصف_نه_ٿيل PKCS11_H
#وصف_ڪريو PKCS11_H 1

#إذا defined(__cplusplus)
خارجي "C" {
#جيڪڏهن_پورو


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#وصف_ڪريو CRYPTOKI_نسخو_MAJOR		3
#وصف_ڪريو CRYPTOKI_نسخو_MINOR		0
#وصف_ڪريو CRYPTOKI_نسخو_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#جيڪڏهن_وصف_نه_ٿيل CRYPTOKI_GNU
#جيڪڏهن_وصف_نه_ٿيل CRYPTOKI_COMPAT
#وصف_ڪريو CRYPTOKI_COMPAT 1
#جيڪڏهن_پورو
#جيڪڏهن_پورو

/* System dependencies.  */

#إذا defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#هدايت pack(ڌڪو, cryptoki, 1)

#جيڪڏهن_وصف_ٿيل CRYPTOKI_EXPORTS
#وصف_ڪريو CK_SPEC __declspec(dllexport)
#وإلا
#وصف_ڪريو CK_SPEC __declspec(dllimport)
#جيڪڏهن_پورو

#وإلا

#وصف_ڪريو CK_SPEC

#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#وصف_ڪريو ck_flags_t CK_FLAGS
#وصف_ڪريو ck_نسخو CK_نسخو

#وصف_ڪريو ck_info _CK_INFO
#وصف_ڪريو cryptoki_نسخو cryptoki_نسخو_2
#وصف_ڪريو manufacturer_id manufacturerID
#وصف_ڪريو library_description libraryDescription
#وصف_ڪريو library_نسخو library_نسخو_2

#وصف_ڪريو ck_notification_t CK_NOTIFICATION
#وصف_ڪريو ck_جڳهه_id_t CK_جڳهه_ID

#وصف_ڪريو ck_جڳهه_info CK_جڳهه_INFO
#وصف_ڪريو جڳهه_description جڳهه_Description
#وصف_ڪريو hardware_نسخو hardware_نسخو_2
#وصف_ڪريو firmware_نسخو firmware_نسخو_2

#وصف_ڪريو ck_token_info _CK_TOKEN_INFO
#وصف_ڪريو serial_عدد serial_عدد_2
#وصف_ڪريو max_session_ڳڻپ ul_Max_Session_ڳڻپ
#وصف_ڪريو session_ڳڻپ ul_Session_ڳڻپ
#وصف_ڪريو max_rw_session_ڳڻپ ul_Max_Rw_Session_ڳڻپ
#وصف_ڪريو rw_session_ڳڻپ ul_Rw_Session_ڳڻپ
#وصف_ڪريو max_pin_len ulMaxPinLen
#وصف_ڪريو min_pin_len ulMinPinLen
#وصف_ڪريو ڪل_عوامي_يادگيري ul_ڪل_عوامي_يادگيري
#وصف_ڪريو free_عوامي_يادگيري ul_Free_عوامي_يادگيري
#وصف_ڪريو ڪل_ذاتي_يادگيري ul_ڪل_ذاتي_يادگيري
#وصف_ڪريو free_ذاتي_يادگيري ul_Free_ذاتي_يادگيري
#وصف_ڪريو utc_وقت utc_وقت_2

#وصف_ڪريو ck_session_handle_t CK_SESSION_HANDLE
#وصف_ڪريو ck_user_type_t CK_USER_TYPE
#وصف_ڪريو ck_state_t CK_STATE

#وصف_ڪريو ck_session_info _CK_SESSION_INFO
#وصف_ڪريو جڳهه_id جڳهه_ID
#وصف_ڪريو device_error ulDeviceError

#وصف_ڪريو ck_object_handle_t CK_OBJECT_HANDLE
#وصف_ڪريو ck_object_class_t CK_OBJECT_CLASS
#وصف_ڪريو ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#وصف_ڪريو ck_ڪنجي_type_t CK_ڪنجي_TYPE
#وصف_ڪريو ck_certificate_type_t CK_CERTIFICATE_TYPE
#وصف_ڪريو ck_attribute_type_t CK_ATTRIBUTE_TYPE

#وصف_ڪريو ck_attribute _CK_ATTRIBUTE
#وصف_ڪريو قدر p_قدر
#وصف_ڪريو قدر_len ul_قدر_Len

#وصف_ڪريو ck_date _CK_DATE

#وصف_ڪريو ck_mechanism_type_t CK_MECHANISM_TYPE

#وصف_ڪريو ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#وصف_ڪريو ck_mechanism _CK_MECHANISM
#وصف_ڪريو parameter pParameter
#وصف_ڪريو parameter_len ulParameterLen

#وصف_ڪريو ck_mechanism_info _CK_MECHANISM_INFO
#وصف_ڪريو min_ڪنجي_سائيز ul_Min_ڪنجي_سائيز
#وصف_ڪريو max_ڪنجي_سائيز ul_Max_ڪنجي_سائيز

#وصف_ڪريو ck_rv_t CK_RV
#وصف_ڪريو ck_notify_t CK_NOTIFY

#وصف_ڪريو ck_interface CK_INTERFACE

#وصف_ڪريو ck_function_list _CK_FUNCTION_LIST
#وصف_ڪريو ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#وصف_ڪريو ck_createmutex_t CK_CREATEMUTEX
#وصف_ڪريو ck_destroymutex_t CK_DESTROYMUTEX
#وصف_ڪريو ck_lockmutex_t CK_LOCKMUTEX
#وصف_ڪريو ck_unlockmutex_t CK_UNLOCKMUTEX

#وصف_ڪريو ck_c_initialize_دليلون CK_C_INITIALIZE_دليلون
#وصف_ڪريو create_mutex CreateMutex
#وصف_ڪريو destroy_mutex DestroyMutex
#وصف_ڪريو تالو_mutex تالو_Mutex
#وصف_ڪريو unlock_mutex UnlockMutex
#وصف_ڪريو reserved pReserved

#جيڪڏهن_پورو	/* CRYPTOKI_COMPAT */


تعريفنوع بنانشان ڊگهو ck_flags_t;

بنية ck_نسخو
{
  بنانشان حرف major;
  بنانشان حرف minor;
};


بنية ck_info
{
  بنية ck_نسخو cryptoki_نسخو;
  بنانشان حرف manufacturer_id[32];
  ck_flags_t flags;
  بنانشان حرف library_description[32];
  بنية ck_نسخو library_نسخو;
};


تعريفنوع بنانشان ڊگهو ck_notification_t;

#وصف_ڪريو CKN_SURRENDER	(0UL)


تعريفنوع بنانشان ڊگهو ck_جڳهه_id_t;


بنية ck_جڳهه_info
{
  بنانشان حرف جڳهه_description[64];
  بنانشان حرف manufacturer_id[32];
  ck_flags_t flags;
  بنية ck_نسخو hardware_نسخو;
  بنية ck_نسخو firmware_نسخو;
};


#وصف_ڪريو CKF_TOKEN_PRESENT	(1UL << 0)
#وصف_ڪريو CKF_REMOVABLE_DEVICE	(1UL << 1)
#وصف_ڪريو CKF_HW_جڳهه		(1UL << 2)
#وصف_ڪريو CKF_ARRAY_ATTRIBUTE	(1UL << 30)


بنية ck_token_info
{
  بنانشان حرف label[32];
  بنانشان حرف manufacturer_id[32];
  بنانشان حرف model[16];
  بنانشان حرف serial_عدد[16];
  ck_flags_t flags;
  بنانشان ڊگهو max_session_ڳڻپ;
  بنانشان ڊگهو session_ڳڻپ;
  بنانشان ڊگهو max_rw_session_ڳڻپ;
  بنانشان ڊگهو rw_session_ڳڻپ;
  بنانشان ڊگهو max_pin_len;
  بنانشان ڊگهو min_pin_len;
  بنانشان ڊگهو ڪل_عوامي_يادگيري;
  بنانشان ڊگهو free_عوامي_يادگيري;
  بنانشان ڊگهو ڪل_ذاتي_يادگيري;
  بنانشان ڊگهو free_ذاتي_يادگيري;
  بنية ck_نسخو hardware_نسخو;
  بنية ck_نسخو firmware_نسخو;
  بنانشان حرف utc_وقت[16];
};


#وصف_ڪريو CKF_RNG					(1UL << 0)
#وصف_ڪريو CKF_WRITE_PROTECTED			(1UL << 1)
#وصف_ڪريو CKF_LOGIN_REQUIRED			(1UL << 2)
#وصف_ڪريو CKF_USER_PIN_INITIALIZED		(1UL << 3)
#وصف_ڪريو CKF_RESTORE_ڪنجي_NOT_NEEDED		(1UL << 5)
#وصف_ڪريو CKF_CLOCK_ON_TOKEN			(1UL << 6)
#وصف_ڪريو CKF_PROTECTED_AUTHENTICATION_رستو	(1UL << 8)
#وصف_ڪريو CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#وصف_ڪريو CKF_TOKEN_INITIALIZED			(1UL << 10)
#وصف_ڪريو CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#وصف_ڪريو CKF_USER_PIN_ڳڻپ_هيٺيون			(1UL << 16)
#وصف_ڪريو CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#وصف_ڪريو CKF_USER_PIN_LOCKED			(1UL << 18)
#وصف_ڪريو CKF_USER_PIN_منزل_BE_بدليو		(1UL << 19)
#وصف_ڪريو CKF_SO_PIN_ڳڻپ_هيٺيون			(1UL << 20)
#وصف_ڪريو CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#وصف_ڪريو CKF_SO_PIN_LOCKED			(1UL << 22)
#وصف_ڪريو CKF_SO_PIN_منزل_BE_بدليو		(1UL << 23)

#وصف_ڪريو CK_UNAVAILABLE_INFORMATION	((بنانشان ڊگهو) -1)
#وصف_ڪريو CK_EFFECTIVELY_INFINITE		(0UL)


تعريفنوع بنانشان ڊگهو ck_session_handle_t;

#وصف_ڪريو CK_INVALID_HANDLE	(0UL)


تعريفنوع بنانشان ڊگهو ck_user_type_t;

#وصف_ڪريو CKU_SO			(0UL)
#وصف_ڪريو CKU_USER		(1UL)
#وصف_ڪريو CKU_CONTEXT_SPECIFIC	(2UL)


تعريفنوع بنانشان ڊگهو ck_state_t;

#وصف_ڪريو CKS_RO_عوامي_SESSION	(0UL)
#وصف_ڪريو CKS_RO_USER_FUNCTIONS	(1UL)
#وصف_ڪريو CKS_RW_عوامي_SESSION	(2UL)
#وصف_ڪريو CKS_RW_USER_FUNCTIONS	(3UL)
#وصف_ڪريو CKS_RW_SO_FUNCTIONS	(4UL)


بنية ck_session_info
{
  ck_جڳهه_id_t جڳهه_id;
  ck_state_t state;
  ck_flags_t flags;
  بنانشان ڊگهو device_error;
};

#وصف_ڪريو CKF_RW_SESSION		(1UL << 1)
#وصف_ڪريو CKF_SERIAL_SESSION	(1UL << 2)


تعريفنوع بنانشان ڊگهو ck_object_handle_t;


تعريفنوع بنانشان ڊگهو ck_object_class_t;

#وصف_ڪريو CKO_معلومات		(0UL)
#وصف_ڪريو CKO_CERTIFICATE		(1UL)
#وصف_ڪريو CKO_عوامي_ڪنجي		(2UL)
#وصف_ڪريو CKO_ذاتي_ڪنجي		(3UL)
#وصف_ڪريو CKO_SECRET_ڪنجي		(4UL)
#وصف_ڪريو CKO_HW_FEATURE		(5UL)
#وصف_ڪريو CKO_DOMAIN_PARAMETERS	(6UL)
#وصف_ڪريو CKO_MECHANISM		(7UL)
#وصف_ڪريو CKO_OTP_ڪنجي		(8UL)
#وصف_ڪريو CKO_PROFILE		(9UL)
#وصف_ڪريو CKO_VENDOR_DEFINED	(1UL << 31)

#وصف_ڪريو CKP_INVALID_ID                (0UL)
#وصف_ڪريو CKP_BASELINE_PROVIDER         (1UL)
#وصف_ڪريو CKP_EXTENDED_PROVIDER         (2UL)
#وصف_ڪريو CKP_AUTHENTICATION_TOKEN      (3UL)
#وصف_ڪريو CKP_عوامي_CERTIFICATES_TOKEN (4UL)
#وصف_ڪريو CKP_VENDOR_DEFINED            (1UL << 31)

تعريفنوع بنانشان ڊگهو ck_hw_feature_type_t;

#وصف_ڪريو CKH_MONOTONIC_COUNTER	(1UL)
#وصف_ڪريو CKH_CLOCK		(2UL)
#وصف_ڪريو CKH_USER_INTERFACE	(3UL)
#وصف_ڪريو CKH_VENDOR_DEFINED	(1UL << 31)


تعريفنوع بنانشان ڊگهو ck_ڪنجي_type_t;

#وصف_ڪريو CKK_RSA			(0UL)
#وصف_ڪريو CKK_DSA			(1UL)
#وصف_ڪريو CKK_DH			(2UL)
#وصف_ڪريو CKK_ECDSA		(3UL)
#وصف_ڪريو CKK_EC			(3UL)
#وصف_ڪريو CKK_X9_42_DH		(4UL)
#وصف_ڪريو CKK_KEA			(5UL)
#وصف_ڪريو CKK_GENERIC_SECRET	(0x10UL)
#وصف_ڪريو CKK_RC2			(0x11UL)
#وصف_ڪريو CKK_RC4			(0x12UL)
#وصف_ڪريو CKK_DES			(0x13UL)
#وصف_ڪريو CKK_DES2		(0x14UL)
#وصف_ڪريو CKK_DES3		(0x15UL)
#وصف_ڪريو CKK_CAST		(0x16UL)
#وصف_ڪريو CKK_CAST3		(0x17UL)
#وصف_ڪريو CKK_CAST128		(0x18UL)
#وصف_ڪريو CKK_RC5			(0x19UL)
#وصف_ڪريو CKK_IDEA		(0x1aUL)
#وصف_ڪريو CKK_SKIPJACK		(0x1bUL)
#وصف_ڪريو CKK_BATON		(0x1cUL)
#وصف_ڪريو CKK_JUNIPER		(0x1dUL)
#وصف_ڪريو CKK_CDMF		(0x1eUL)
#وصف_ڪريو CKK_AES			(0x1fUL)
#وصف_ڪريو CKK_BLOWFISH		(0x20UL)
#وصف_ڪريو CKK_TWOFISH		(0x21UL)
#وصف_ڪريو CKK_GOSTR3410		(0x30UL)
#وصف_ڪريو CKK_GOSTR3411		(0x31UL)
#وصف_ڪريو CKK_GOST28147		(0x32UL)
#وصف_ڪريو CKK_EC_EDWARDS		(0x40UL)
#وصف_ڪريو CKK_EC_MONTGOMERY	(0x41UL)
#وصف_ڪريو CKK_HKDF		(0x42UL)
#وصف_ڪريو CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#وصف_ڪريو NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#وصف_ڪريو CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#وصف_ڪريو CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

تعريفنوع بنانشان ڊگهو ck_certificate_type_t;

#وصف_ڪريو CKC_X_509		(0UL)
#وصف_ڪريو CKC_X_509_ATTR_CERT	(1UL)
#وصف_ڪريو CKC_WTLS		(2UL)
#وصف_ڪريو CKC_VENDOR_DEFINED	(1UL << 31)


تعريفنوع بنانشان ڊگهو ck_attribute_type_t;

#وصف_ڪريو CKA_CLASS			(0UL)
#وصف_ڪريو CKA_TOKEN			(1UL)
#وصف_ڪريو CKA_ذاتي			(2UL)
#وصف_ڪريو CKA_LABEL			(3UL)
#وصف_ڪريو CKA_UNIQUE_ID		(4UL)
#وصف_ڪريو CKA_APPLICATION			(0x10UL)
#وصف_ڪريو CKA_قدر			(0x11UL)
#وصف_ڪريو CKA_OBJECT_ID			(0x12UL)
#وصف_ڪريو CKA_CERTIFICATE_TYPE		(0x80UL)
#وصف_ڪريو CKA_ISSUER			(0x81UL)
#وصف_ڪريو CKA_SERIAL_عدد		(0x82UL)
#وصف_ڪريو CKA_AC_ISSUER			(0x83UL)
#وصف_ڪريو CKA_OWNER			(0x84UL)
#وصف_ڪريو CKA_ATTR_TYPES			(0x85UL)
#وصف_ڪريو CKA_TRUSTED			(0x86UL)
#وصف_ڪريو CKA_CERTIFICATE_CATEGORY	(0x87UL)
#وصف_ڪريو CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#وصف_ڪريو CKA_URL				(0x89UL)
#وصف_ڪريو CKA_HASH_جو_SUBJECT_عوامي_ڪنجي	(0x8aUL)
#وصف_ڪريو CKA_HASH_جو_ISSUER_عوامي_ڪنجي	(0x8bUL)
#وصف_ڪريو CKA_CHECK_قدر			(0x90UL)
#وصف_ڪريو CKA_ڪنجي_TYPE			(0x100UL)
#وصف_ڪريو CKA_SUBJECT			(0x101UL)
#وصف_ڪريو CKA_ID				(0x102UL)
#وصف_ڪريو CKA_SENSITIVE			(0x103UL)
#وصف_ڪريو CKA_ENCRYPT			(0x104UL)
#وصف_ڪريو CKA_DECRYPT			(0x105UL)
#وصف_ڪريو CKA_WRAP			(0x106UL)
#وصف_ڪريو CKA_UNWRAP			(0x107UL)
#وصف_ڪريو CKA_SIGN			(0x108UL)
#وصف_ڪريو CKA_SIGN_RECOVER		(0x109UL)
#وصف_ڪريو CKA_VERIFY			(0x10aUL)
#وصف_ڪريو CKA_VERIFY_RECOVER		(0x10bUL)
#وصف_ڪريو CKA_DERIVE			(0x10cUL)
#وصف_ڪريو CKA_شروعات_DATE			(0x110UL)
#وصف_ڪريو CKA_پڇاڙي_DATE			(0x111UL)
#وصف_ڪريو CKA_MODULUS			(0x120UL)
#وصف_ڪريو CKA_MODULUS_بٽ		(0x121UL)
#وصف_ڪريو CKA_عوامي_EXPONENT		(0x122UL)
#وصف_ڪريو CKA_ذاتي_EXPONENT		(0x123UL)
#وصف_ڪريو CKA_مفرد_1			(0x124UL)
#وصف_ڪريو CKA_مفرد_2			(0x125UL)
#وصف_ڪريو CKA_EXPONENT_1			(0x126UL)
#وصف_ڪريو CKA_EXPONENT_2			(0x127UL)
#وصف_ڪريو CKA_COEFFICIENT			(0x128UL)
#وصف_ڪريو CKA_عوامي_ڪنجي_INFO		(0x129UL)
#وصف_ڪريو CKA_مفرد			(0x130UL)
#وصف_ڪريو CKA_SUBPRIME			(0x131UL)
#وصف_ڪريو CKA_بنياد			(0x132UL)
#وصف_ڪريو CKA_مفرد_بٽ			(0x133UL)
#وصف_ڪريو CKA_SUB_مفرد_بٽ		(0x134UL)
#وصف_ڪريو CKA_قدر_بٽ			(0x160UL)
#وصف_ڪريو CKA_قدر_LEN			(0x161UL)
#وصف_ڪريو CKA_EXTRACTABLE			(0x162UL)
#وصف_ڪريو CKA_LOCAL			(0x163UL)
#وصف_ڪريو CKA_NEVER_EXTRACTABLE		(0x164UL)
#وصف_ڪريو CKA_ALWAYS_SENSITIVE		(0x165UL)
#وصف_ڪريو CKA_ڪنجي_GEN_MECHANISM		(0x166UL)
#وصف_ڪريو CKA_MODIFIABLE			(0x170UL)
#وصف_ڪريو CKA_COPYABLE			(0x171UL)
#وصف_ڪريو CKA_DESTROYABLE			(0x172UL)
#وصف_ڪريو CKA_ECDSA_PARAMS		(0x180UL)
#وصف_ڪريو CKA_EC_PARAMS			(0x180UL)
#وصف_ڪريو CKA_EC_نقطو			(0x181UL)
#وصف_ڪريو CKA_SECONDARY_AUTH		(0x200UL)
#وصف_ڪريو CKA_AUTH_PIN_FLAGS		(0x201UL)
#وصف_ڪريو CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#وصف_ڪريو CKA_WRAP_WITH_TRUSTED		(0x210UL)
#وصف_ڪريو CKA_GOSTR3410_PARAMS		(0x250UL)
#وصف_ڪريو CKA_GOSTR3411_PARAMS		(0x251UL)
#وصف_ڪريو CKA_GOST28147_PARAMS		(0x252UL)
#وصف_ڪريو CKA_HW_FEATURE_TYPE		(0x300UL)
#وصف_ڪريو CKA_RESET_ON_INIT		(0x301UL)
#وصف_ڪريو CKA_HAS_RESET			(0x302UL)
#وصف_ڪريو CKA_PIXEL_X			(0x400UL)
#وصف_ڪريو CKA_PIXEL_Y			(0x401UL)
#وصف_ڪريو CKA_RESOLUTION			(0x402UL)
#وصف_ڪريو CKA_CHAR_صفون			(0x403UL)
#وصف_ڪريو CKA_CHAR_COLUMNS		(0x404UL)
#وصف_ڪريو CKA_COLOR			(0x405UL)
#وصف_ڪريو CKA_بٽ_في_PIXEL		(0x406UL)
#وصف_ڪريو CKA_CHAR_SETS			(0x480UL)
#وصف_ڪريو CKA_ENCODING_METHODS		(0x481UL)
#وصف_ڪريو CKA_MIME_TYPES			(0x482UL)
#وصف_ڪريو CKA_MECHANISM_TYPE		(0x500UL)
#وصف_ڪريو CKA_REQUIRED_CMS_خاصيتون	(0x501UL)
#وصف_ڪريو CKA_DEFAULT_CMS_خاصيتون	(0x502UL)
#وصف_ڪريو CKA_SUPPORTED_CMS_خاصيتون	(0x503UL)
#وصف_ڪريو CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#وصف_ڪريو CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#وصف_ڪريو CKA_OTP_FORMAT			(0x220UL)
#وصف_ڪريو CKA_OTP_ڊيگهائي			(0x221UL)
#وصف_ڪريو CKA_OTP_وقت_INTERVAL		(0x222UL)
#وصف_ڪريو CKA_OTP_USER_FRIENDLY_گهڻائي	(0x223UL)
#وصف_ڪريو CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#وصف_ڪريو CKA_OTP_وقت_REQUIREMENT	(0x225UL)
#وصف_ڪريو CKA_OTP_COUNTER_REQUIREMENT	(0x226UL)
#وصف_ڪريو CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#وصف_ڪريو CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#وصف_ڪريو CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#وصف_ڪريو CKA_OTP_SERVICE_LOGO		(0x22CUL)
#وصف_ڪريو CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#وصف_ڪريو CKA_OTP_COUNTER			(0x22EUL)
#وصف_ڪريو CKA_OTP_وقت			(0x22FUL)
#وصف_ڪريو CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#وصف_ڪريو CKA_PROFILE_ID			(0x601UL)
#وصف_ڪريو CKA_VENDOR_DEFINED		(1UL << 31)


بنية ck_attribute
{
  ck_attribute_type_t type;
  فراغ *قدر;
  بنانشان ڊگهو قدر_len;
};


بنية ck_date
{
  بنانشان حرف year[4];
  بنانشان حرف month[2];
  بنانشان حرف day[2];
};


تعريفنوع بنانشان ڊگهو ck_mechanism_type_t;

#وصف_ڪريو CKM_RSA_PKCS_ڪنجي_PAIR_GEN	(0UL)
#وصف_ڪريو CKM_RSA_PKCS			(1UL)
#وصف_ڪريو CKM_RSA_9796			(2UL)
#وصف_ڪريو CKM_RSA_X_509			(3UL)
#وصف_ڪريو CKM_MD2_RSA_PKCS		(4UL)
#وصف_ڪريو CKM_MD5_RSA_PKCS		(5UL)
#وصف_ڪريو CKM_SHA1_RSA_PKCS		(6UL)
#وصف_ڪريو CKM_RIPEMD128_RSA_PKCS		(7UL)
#وصف_ڪريو CKM_RIPEMD160_RSA_PKCS		(8UL)
#وصف_ڪريو CKM_RSA_PKCS_OAEP		(9UL)
#وصف_ڪريو CKM_RSA_X9_31_ڪنجي_PAIR_GEN	(0xaUL)
#وصف_ڪريو CKM_RSA_X9_31			(0xbUL)
#وصف_ڪريو CKM_SHA1_RSA_X9_31		(0xcUL)
#وصف_ڪريو CKM_RSA_PKCS_PSS		(0xdUL)
#وصف_ڪريو CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#وصف_ڪريو CKM_DSA_ڪنجي_PAIR_GEN		(0x10UL)
#وصف_ڪريو	CKM_DSA				(0x11UL)
#وصف_ڪريو CKM_DSA_SHA1			(0x12UL)
#وصف_ڪريو CKM_DSA_SHA224			(0x13UL)
#وصف_ڪريو CKM_DSA_SHA256			(0x14UL)
#وصف_ڪريو CKM_DSA_SHA384			(0x15UL)
#وصف_ڪريو CKM_DSA_SHA512			(0x16UL)
#وصف_ڪريو CKM_DH_PKCS_ڪنجي_PAIR_GEN	(0x20UL)
#وصف_ڪريو CKM_DH_PKCS_DERIVE		(0x21UL)
#وصف_ڪريو	CKM_X9_42_DH_ڪنجي_PAIR_GEN	(0x30UL)
#وصف_ڪريو CKM_X9_42_DH_DERIVE		(0x31UL)
#وصف_ڪريو CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#وصف_ڪريو CKM_X9_42_MQV_DERIVE		(0x33UL)
#وصف_ڪريو CKM_SHA256_RSA_PKCS		(0x40UL)
#وصف_ڪريو CKM_SHA384_RSA_PKCS		(0x41UL)
#وصف_ڪريو CKM_SHA512_RSA_PKCS		(0x42UL)
#وصف_ڪريو CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#وصف_ڪريو CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#وصف_ڪريو CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#وصف_ڪريو CKM_SHA224_RSA_PKCS		(0x46UL)
#وصف_ڪريو CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#وصف_ڪريو CKM_SHA3_256_RSA_PKCS		(0x60UL)
#وصف_ڪريو CKM_SHA3_384_RSA_PKCS		(0x61UL)
#وصف_ڪريو CKM_SHA3_512_RSA_PKCS		(0x62UL)
#وصف_ڪريو CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#وصف_ڪريو CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#وصف_ڪريو CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#وصف_ڪريو CKM_SHA3_224_RSA_PKCS		(0x66UL)
#وصف_ڪريو CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#وصف_ڪريو CKM_RC2_ڪنجي_GEN			(0x100UL)
#وصف_ڪريو CKM_RC2_ECB			(0x101UL)
#وصف_ڪريو	CKM_RC2_CBC			(0x102UL)
#وصف_ڪريو	CKM_RC2_MAC			(0x103UL)
#وصف_ڪريو CKM_RC2_MAC_GENERAL		(0x104UL)
#وصف_ڪريو CKM_RC2_CBC_PAD			(0x105UL)
#وصف_ڪريو CKM_RC4_ڪنجي_GEN			(0x110UL)
#وصف_ڪريو CKM_RC4				(0x111UL)
#وصف_ڪريو CKM_DES_ڪنجي_GEN			(0x120UL)
#وصف_ڪريو CKM_DES_ECB			(0x121UL)
#وصف_ڪريو CKM_DES_CBC			(0x122UL)
#وصف_ڪريو CKM_DES_MAC			(0x123UL)
#وصف_ڪريو CKM_DES_MAC_GENERAL		(0x124UL)
#وصف_ڪريو CKM_DES_CBC_PAD			(0x125UL)
#وصف_ڪريو CKM_DES2_ڪنجي_GEN		(0x130UL)
#وصف_ڪريو CKM_DES3_ڪنجي_GEN		(0x131UL)
#وصف_ڪريو CKM_DES3_ECB			(0x132UL)
#وصف_ڪريو CKM_DES3_CBC			(0x133UL)
#وصف_ڪريو CKM_DES3_MAC			(0x134UL)
#وصف_ڪريو CKM_DES3_MAC_GENERAL		(0x135UL)
#وصف_ڪريو CKM_DES3_CBC_PAD		(0x136UL)
#وصف_ڪريو CKM_DES3_CMAC_GENERAL		(0x137UL)
#وصف_ڪريو CKM_DES3_CMAC			(0x138UL)
#وصف_ڪريو CKM_CDMF_ڪنجي_GEN		(0x140UL)
#وصف_ڪريو CKM_CDMF_ECB			(0x141UL)
#وصف_ڪريو CKM_CDMF_CBC			(0x142UL)
#وصف_ڪريو CKM_CDMF_MAC			(0x143UL)
#وصف_ڪريو CKM_CDMF_MAC_GENERAL		(0x144UL)
#وصف_ڪريو CKM_CDMF_CBC_PAD		(0x145UL)
#وصف_ڪريو CKM_MD2				(0x200UL)
#وصف_ڪريو CKM_MD2_HMAC			(0x201UL)
#وصف_ڪريو CKM_MD2_HMAC_GENERAL		(0x202UL)
#وصف_ڪريو CKM_MD5				(0x210UL)
#وصف_ڪريو CKM_MD5_HMAC			(0x211UL)
#وصف_ڪريو CKM_MD5_HMAC_GENERAL		(0x212UL)
#وصف_ڪريو CKM_SHA_1			(0x220UL)
#وصف_ڪريو CKM_SHA_1_HMAC			(0x221UL)
#وصف_ڪريو CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#وصف_ڪريو CKM_RIPEMD128			(0x230UL)
#وصف_ڪريو CKM_RIPEMD128_HMAC		(0x231UL)
#وصف_ڪريو CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#وصف_ڪريو CKM_RIPEMD160			(0x240UL)
#وصف_ڪريو CKM_RIPEMD160_HMAC		(0x241UL)
#وصف_ڪريو CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#وصف_ڪريو CKM_SHA256			(0x250UL)
#وصف_ڪريو CKM_SHA256_HMAC			(0x251UL)
#وصف_ڪريو CKM_SHA256_HMAC_GENERAL		(0x252UL)
#وصف_ڪريو CKM_SHA224			(0x255UL)
#وصف_ڪريو CKM_SHA224_HMAC			(0x256UL)
#وصف_ڪريو CKM_SHA224_HMAC_GENERAL		(0x257UL)
#وصف_ڪريو CKM_SHA384			(0x260UL)
#وصف_ڪريو CKM_SHA384_HMAC			(0x261UL)
#وصف_ڪريو CKM_SHA384_HMAC_GENERAL		(0x262UL)
#وصف_ڪريو CKM_SHA512			(0x270UL)
#وصف_ڪريو CKM_SHA512_HMAC			(0x271UL)
#وصف_ڪريو CKM_SHA512_HMAC_GENERAL		(0x272UL)
#وصف_ڪريو CKM_SHA3_256			(0x2B0UL)
#وصف_ڪريو CKM_SHA3_256_HMAC		(0x2B1UL)
#وصف_ڪريو CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#وصف_ڪريو CKM_SHA3_256_ڪنجي_GEN		(0x2B3UL)
#وصف_ڪريو CKM_SHA3_224			(0x2B5UL)
#وصف_ڪريو CKM_SHA3_224_HMAC		(0x2B6UL)
#وصف_ڪريو CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#وصف_ڪريو CKM_SHA3_224_ڪنجي_GEN		(0x2B8UL)
#وصف_ڪريو CKM_SHA3_384			(0x2C0UL)
#وصف_ڪريو CKM_SHA3_384_HMAC		(0x2C1UL)
#وصف_ڪريو CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#وصف_ڪريو CKM_SHA3_384_ڪنجي_GEN		(0x2C3UL)
#وصف_ڪريو CKM_SHA3_512			(0x2D0UL)
#وصف_ڪريو CKM_SHA3_512_HMAC		(0x2D1UL)
#وصف_ڪريو CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#وصف_ڪريو CKM_SHA3_512_ڪنجي_GEN		(0x2D3UL)
#وصف_ڪريو CKM_CAST_ڪنجي_GEN		(0x300UL)
#وصف_ڪريو CKM_CAST_ECB			(0x301UL)
#وصف_ڪريو CKM_CAST_CBC			(0x302UL)
#وصف_ڪريو CKM_CAST_MAC			(0x303UL)
#وصف_ڪريو CKM_CAST_MAC_GENERAL		(0x304UL)
#وصف_ڪريو CKM_CAST_CBC_PAD		(0x305UL)
#وصف_ڪريو CKM_CAST3_ڪنجي_GEN		(0x310UL)
#وصف_ڪريو CKM_CAST3_ECB			(0x311UL)
#وصف_ڪريو CKM_CAST3_CBC			(0x312UL)
#وصف_ڪريو CKM_CAST3_MAC			(0x313UL)
#وصف_ڪريو CKM_CAST3_MAC_GENERAL		(0x314UL)
#وصف_ڪريو CKM_CAST3_CBC_PAD		(0x315UL)
#وصف_ڪريو CKM_CAST5_ڪنجي_GEN		(0x320UL)
#وصف_ڪريو CKM_CAST128_ڪنجي_GEN		(0x320UL)
#وصف_ڪريو CKM_CAST5_ECB			(0x321UL)
#وصف_ڪريو CKM_CAST128_ECB			(0x321UL)
#وصف_ڪريو CKM_CAST5_CBC			(0x322UL)
#وصف_ڪريو CKM_CAST128_CBC			(0x322UL)
#وصف_ڪريو CKM_CAST5_MAC			(0x323UL)
#وصف_ڪريو	CKM_CAST128_MAC			(0x323UL)
#وصف_ڪريو CKM_CAST5_MAC_GENERAL		(0x324UL)
#وصف_ڪريو CKM_CAST128_MAC_GENERAL		(0x324UL)
#وصف_ڪريو CKM_CAST5_CBC_PAD		(0x325UL)
#وصف_ڪريو CKM_CAST128_CBC_PAD		(0x325UL)
#وصف_ڪريو CKM_RC5_ڪنجي_GEN			(0x330UL)
#وصف_ڪريو CKM_RC5_ECB			(0x331UL)
#وصف_ڪريو CKM_RC5_CBC			(0x332UL)
#وصف_ڪريو CKM_RC5_MAC			(0x333UL)
#وصف_ڪريو CKM_RC5_MAC_GENERAL		(0x334UL)
#وصف_ڪريو CKM_RC5_CBC_PAD			(0x335UL)
#وصف_ڪريو CKM_IDEA_ڪنجي_GEN		(0x340UL)
#وصف_ڪريو CKM_IDEA_ECB			(0x341UL)
#وصف_ڪريو	CKM_IDEA_CBC			(0x342UL)
#وصف_ڪريو CKM_IDEA_MAC			(0x343UL)
#وصف_ڪريو CKM_IDEA_MAC_GENERAL		(0x344UL)
#وصف_ڪريو CKM_IDEA_CBC_PAD		(0x345UL)
#وصف_ڪريو CKM_GENERIC_SECRET_ڪنجي_GEN	(0x350UL)
#وصف_ڪريو CKM_CONCATENATE_بنياد_AND_ڪنجي	(0x360UL)
#وصف_ڪريو CKM_CONCATENATE_بنياد_AND_معلومات	(0x362UL)
#وصف_ڪريو CKM_CONCATENATE_معلومات_AND_بنياد	(0x363UL)
#وصف_ڪريو CKM_XOR_بنياد_AND_معلومات		(0x364UL)
#وصف_ڪريو CKM_ڪڍو_ڪنجي_FROM_ڪنجي	(0x365UL)
#وصف_ڪريو CKM_SSL3_PRE_MASTER_ڪنجي_GEN	(0x370UL)
#وصف_ڪريو CKM_SSL3_MASTER_ڪنجي_DERIVE	(0x371UL)
#وصف_ڪريو CKM_SSL3_ڪنجي_AND_MAC_DERIVE	(0x372UL)
#وصف_ڪريو CKM_SSL3_MASTER_ڪنجي_DERIVE_DH	(0x373UL)
#وصف_ڪريو CKM_TLS_PRE_MASTER_ڪنجي_GEN	(0x374UL)
#وصف_ڪريو CKM_TLS_MASTER_ڪنجي_DERIVE	(0x375UL)
#وصف_ڪريو CKM_TLS_ڪنجي_AND_MAC_DERIVE	(0x376UL)
#وصف_ڪريو CKM_TLS_MASTER_ڪنجي_DERIVE_DH	(0x377UL)
#وصف_ڪريو CKM_SSL3_MD5_MAC		(0x380UL)
#وصف_ڪريو CKM_SSL3_SHA1_MAC		(0x381UL)
#وصف_ڪريو CKM_MD5_ڪنجي_DERIVATION		(0x390UL)
#وصف_ڪريو CKM_MD2_ڪنجي_DERIVATION		(0x391UL)
#وصف_ڪريو CKM_SHA1_ڪنجي_DERIVATION		(0x392UL)
#وصف_ڪريو CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#وصف_ڪريو CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#وصف_ڪريو CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#وصف_ڪريو CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#وصف_ڪريو CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#وصف_ڪريو CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#وصف_ڪريو CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#وصف_ڪريو CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#وصف_ڪريو CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#وصف_ڪريو CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#وصف_ڪريو CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#وصف_ڪريو CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#وصف_ڪريو CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#وصف_ڪريو CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#وصف_ڪريو CKM_PKCS5_PBKD2			(0x3b0UL)
#وصف_ڪريو CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#وصف_ڪريو CKM_ڪنجي_WRAP_LYNKS		(0x400UL)
#وصف_ڪريو CKM_ڪنجي_WRAP_سيٽ_OAEP		(0x401UL)
#وصف_ڪريو CKM_SKIPJACK_ڪنجي_GEN		(0x1000UL)
#وصف_ڪريو CKM_SKIPJACK_ECB64		(0x1001UL)
#وصف_ڪريو CKM_SKIPJACK_CBC64		(0x1002UL)
#وصف_ڪريو CKM_SKIPJACK_OFB64		(0x1003UL)
#وصف_ڪريو CKM_SKIPJACK_CFB64		(0x1004UL)
#وصف_ڪريو CKM_SKIPJACK_CFB32		(0x1005UL)
#وصف_ڪريو CKM_SKIPJACK_CFB16		(0x1006UL)
#وصف_ڪريو CKM_SKIPJACK_CFB8		(0x1007UL)
#وصف_ڪريو CKM_SKIPJACK_WRAP		(0x1008UL)
#وصف_ڪريو CKM_SKIPJACK_ذاتي_WRAP	(0x1009UL)
#وصف_ڪريو CKM_SKIPJACK_RELAYX		(0x100aUL)
#وصف_ڪريو CKM_KEA_ڪنجي_PAIR_GEN		(0x1010UL)
#وصف_ڪريو CKM_KEA_ڪنجي_DERIVE		(0x1011UL)
#وصف_ڪريو CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#وصف_ڪريو CKM_BATON_ڪنجي_GEN		(0x1030UL)
#وصف_ڪريو CKM_BATON_ECB128		(0x1031UL)
#وصف_ڪريو CKM_BATON_ECB96			(0x1032UL)
#وصف_ڪريو CKM_BATON_CBC128		(0x1033UL)
#وصف_ڪريو CKM_BATON_COUNTER		(0x1034UL)
#وصف_ڪريو CKM_BATON_SHUFFLE		(0x1035UL)
#وصف_ڪريو CKM_BATON_WRAP			(0x1036UL)
#وصف_ڪريو CKM_ECDSA_ڪنجي_PAIR_GEN		(0x1040UL)
#وصف_ڪريو CKM_EC_ڪنجي_PAIR_GEN		(0x1040UL)
#وصف_ڪريو CKM_ECDSA			(0x1041UL)
#وصف_ڪريو CKM_ECDSA_SHA1			(0x1042UL)
#وصف_ڪريو CKM_ECDSA_SHA224		(0x1043UL)
#وصف_ڪريو CKM_ECDSA_SHA256		(0x1044UL)
#وصف_ڪريو CKM_ECDSA_SHA384		(0x1045UL)
#وصف_ڪريو CKM_ECDSA_SHA512		(0x1046UL)
#وصف_ڪريو CKM_ECDSA_SHA3_224		(0x1047UL)
#وصف_ڪريو CKM_ECDSA_SHA3_256		(0x1048UL)
#وصف_ڪريو CKM_ECDSA_SHA3_384		(0x1049UL)
#وصف_ڪريو CKM_ECDSA_SHA3_512		(0x104AUL)
#وصف_ڪريو CKM_ECDH1_DERIVE		(0x1050UL)
#وصف_ڪريو CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#وصف_ڪريو CKM_ECMQV_DERIVE		(0x1052UL)
#وصف_ڪريو CKM_EC_EDWARDS_ڪنجي_PAIR_GEN     (0x1055UL)
#وصف_ڪريو CKM_EC_MONTGOMERY_ڪنجي_PAIR_GEN  (0x1056UL)
#وصف_ڪريو CKM_EDDSA			(0x1057UL)
#وصف_ڪريو CKM_JUNIPER_ڪنجي_GEN		(0x1060UL)
#وصف_ڪريو CKM_JUNIPER_ECB128		(0x1061UL)
#وصف_ڪريو CKM_JUNIPER_CBC128		(0x1062UL)
#وصف_ڪريو CKM_JUNIPER_COUNTER		(0x1063UL)
#وصف_ڪريو CKM_JUNIPER_SHUFFLE		(0x1064UL)
#وصف_ڪريو CKM_JUNIPER_WRAP		(0x1065UL)
#وصف_ڪريو CKM_FASTHASH			(0x1070UL)
#وصف_ڪريو CKM_AES_ڪنجي_GEN			(0x1080UL)
#وصف_ڪريو CKM_AES_ECB			(0x1081UL)
#وصف_ڪريو CKM_AES_CBC			(0x1082UL)
#وصف_ڪريو CKM_AES_MAC			(0x1083UL)
#وصف_ڪريو CKM_AES_MAC_GENERAL		(0x1084UL)
#وصف_ڪريو CKM_AES_CBC_PAD			(0x1085UL)
#وصف_ڪريو CKM_AES_CTR				(0x1086UL)
#وصف_ڪريو CKM_AES_GCM				(0x1087UL)
#وصف_ڪريو CKM_AES_CCM				(0x1088UL)
#وصف_ڪريو CKM_AES_CTS				(0x1089UL)
#وصف_ڪريو CKM_AES_CMAC			(0x108AUL)
#وصف_ڪريو CKM_AES_CMAC_GENERAL		(0x108BUL)
#وصف_ڪريو CKM_AES_XCBC_MAC		(0x108CUL)
#وصف_ڪريو CKM_AES_XCBC_MAC_96		(0x108DUL)
#وصف_ڪريو CKM_AES_GMAC			(0x108EUL)
#وصف_ڪريو CKM_BLOWFISH_ڪنجي_GEN    (0x1090UL)
#وصف_ڪريو CKM_BLOWFISH_CBC        (0x1091UL)
#وصف_ڪريو CKM_TWOFISH_ڪنجي_GEN     (0x1092UL)
#وصف_ڪريو CKM_TWOFISH_CBC         (0x1093UL)
#وصف_ڪريو CKM_DES_ECB_ENCRYPT_معلومات	(0x1100UL)
#وصف_ڪريو CKM_DES_CBC_ENCRYPT_معلومات	(0x1101UL)
#وصف_ڪريو CKM_DES3_ECB_ENCRYPT_معلومات	(0x1102UL)
#وصف_ڪريو CKM_DES3_CBC_ENCRYPT_معلومات	(0x1103UL)
#وصف_ڪريو CKM_AES_ECB_ENCRYPT_معلومات	(0x1104UL)
#وصف_ڪريو CKM_AES_CBC_ENCRYPT_معلومات	(0x1105UL)
#وصف_ڪريو CKM_GOSTR3410_ڪنجي_PAIR_GEN	(0x1200UL)
#وصف_ڪريو CKM_GOSTR3410			(0x1201UL)
#وصف_ڪريو CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#وصف_ڪريو CKM_GOSTR3410_ڪنجي_WRAP  (0x1203UL)
#وصف_ڪريو CKM_GOSTR3410_DERIVE    (0x1204UL)
#وصف_ڪريو CKM_GOSTR3410_512_ڪنجي_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#وصف_ڪريو CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#وصف_ڪريو CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#وصف_ڪريو CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#وصف_ڪريو CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#وصف_ڪريو CKM_GOSTR3411			(0x1210UL)
#وصف_ڪريو CKM_GOSTR3411_HMAC      (0x1211UL)
#وصف_ڪريو CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#وصف_ڪريو CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#وصف_ڪريو CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#وصف_ڪريو CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#وصف_ڪريو CKM_GOST28147_ڪنجي_GEN   (0x1220UL)
#وصف_ڪريو CKM_GOST28147_ECB       (0x1221UL)
#وصف_ڪريو CKM_GOST28147           (0x1222UL)
#وصف_ڪريو CKM_GOST28147_MAC       (0x1223UL)
#وصف_ڪريو CKM_GOST28147_ڪنجي_WRAP  (0x1224UL)

#وصف_ڪريو CKM_DSA_PARAMETER_GEN		(0x2000UL)
#وصف_ڪريو CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#وصف_ڪريو CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#وصف_ڪريو CKM_AES_OFB			(0x2104UL)
#وصف_ڪريو CKM_AES_CFB64			(0x2105UL)
#وصف_ڪريو CKM_AES_CFB8			(0x2106UL)
#وصف_ڪريو CKM_AES_CFB128			(0x2107UL)
#وصف_ڪريو CKM_AES_CFB1			(0x2108UL)
#وصف_ڪريو CKM_AES_ڪنجي_WRAP		(0x2109UL)
#وصف_ڪريو CKM_AES_ڪنجي_WRAP_PAD		(0x210AUL)
#وصف_ڪريو CKM_XEDDSA			(0x4029UL)
#وصف_ڪريو CKM_HKDF_DERIVE			(0x402AUL)
#وصف_ڪريو CKM_HKDF_معلومات			(0x402BUL)
#وصف_ڪريو CKM_HKDF_ڪنجي_GEN		(0x402CUL)

#وصف_ڪريو CKM_VENDOR_DEFINED		(1UL << 31)

بنية ck_mechanism
{
  ck_mechanism_type_t mechanism;
  فراغ *parameter;
  بنانشان ڊگهو parameter_len;
};


بنية ck_mechanism_info
{
  بنانشان ڊگهو min_ڪنجي_سائيز;
  بنانشان ڊگهو max_ڪنجي_سائيز;
  ck_flags_t flags;
};

#وصف_ڪريو CKF_HW			(1UL << 0)

#وصف_ڪريو CKF_پيغام_ENCRYPT	(1UL << 1)
#وصف_ڪريو CKF_پيغام_DECRYPT	(1UL << 2)
#وصف_ڪريو CKF_پيغام_SIGN	(1UL << 3)
#وصف_ڪريو CKF_پيغام_VERIFY	(1UL << 4)
#وصف_ڪريو CKF_MULTI_پيغام	(1UL << 5)
#وصف_ڪريو CKF_ڳوليو_OBJECTS	(1UL << 6)

#وصف_ڪريو CKF_ENCRYPT		(1UL << 8)
#وصف_ڪريو CKF_DECRYPT		(1UL << 9)
#وصف_ڪريو CKF_DIGEST		(1UL << 10)
#وصف_ڪريو CKF_SIGN		(1UL << 11)
#وصف_ڪريو CKF_SIGN_RECOVER	(1UL << 12)
#وصف_ڪريو CKF_VERIFY		(1UL << 13)
#وصف_ڪريو CKF_VERIFY_RECOVER	(1UL << 14)
#وصف_ڪريو CKF_GENERATE		(1UL << 15)
#وصف_ڪريو CKF_GENERATE_ڪنجي_PAIR	(1UL << 16)
#وصف_ڪريو CKF_WRAP		(1UL << 17)
#وصف_ڪريو CKF_UNWRAP		(1UL << 18)
#وصف_ڪريو CKF_DERIVE		(1UL << 19)
#وصف_ڪريو CKF_EXTENSION		(1UL << 31)

#وصف_ڪريو CKF_EC_F_P			(1UL << 20)
#وصف_ڪريو CKF_EC_F_2M			(1UL << 21)
#وصف_ڪريو CKF_EC_ECPARAMETERS	(1UL << 22)
#وصف_ڪريو CKF_EC_OID		(1UL << 23)
#وصف_ڪريو CKF_EC_NAMEDCURVE	CKF_EC_OID
#وصف_ڪريو CKF_EC_UNCOMPRESS	(1UL << 24)
#وصف_ڪريو CKF_EC_COMPRESS		(1UL << 25)
#وصف_ڪريو CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#وصف_ڪريو CKF_DONT_بلاڪ				(1UL)

/* Flags for Key derivation */
#وصف_ڪريو CKD_NULL			(0x1UL)
#وصف_ڪريو CKD_SHA1_KDF			(0x2UL)
#وصف_ڪريو CKD_SHA224_KDF			(0x5UL)
#وصف_ڪريو CKD_SHA256_KDF			(0x6UL)
#وصف_ڪريو CKD_SHA384_KDF			(0x7UL)
#وصف_ڪريو CKD_SHA512_KDF			(0x8UL)

تعريفنوع بنية CK_ECDH1_DERIVE_PARAMS {
	بنانشان ڊگهو  kdf;
	بنانشان ڊگهو  ul_Shared_معلومات_Len;
	بنانشان حرف *  p_Shared_معلومات;
	بنانشان ڊگهو  ul_عوامي_معلومات_Len;
	بنانشان حرف *  p_عوامي_معلومات;
} CK_ECDH1_DERIVE_PARAMS;

تعريفنوع بنية CK_ECMQV_DERIVE_PARAMS {
	بنانشان ڊگهو kdf;
	بنانشان ڊگهو ul_Shared_معلومات_Len;
	بنانشان حرف * p_Shared_معلومات;
	بنانشان ڊگهو ul_عوامي_معلومات_Len;
	بنانشان حرف * p_عوامي_معلومات;
	بنانشان ڊگهو ul_ذاتي_معلومات_Len;
	CK_OBJECT_HANDLE h_ذاتي_معلومات;
	بنانشان ڊگهو ul_عوامي_معلومات_Len2;
	بنانشان حرف * p_عوامي_Data2;
	CK_OBJECT_HANDLE عوامي_ڪنجي_2;
} CK_ECMQV_DERIVE_PARAMS;

تعريفنوع بنانشان ڊگهو ck_rsa_pkcs_mgf_type_t;
تعريفنوع بنانشان ڊگهو CK_RSA_PKCS_OAEP_ذريعو_TYPE;

تعريفنوع بنية CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_ذريعو_TYPE ذريعو;
	فراغ *p_ذريعو_معلومات;
	بنانشان ڊگهو ul_ذريعو_معلومات_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

تعريفنوع بنية CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	بنانشان ڊگهو sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#وصف_ڪريو CKG_MGF1_SHA1			(0x00000001UL)
#وصف_ڪريو CKG_MGF1_SHA224		(0x00000005UL)
#وصف_ڪريو CKG_MGF1_SHA256		(0x00000002UL)
#وصف_ڪريو CKG_MGF1_SHA384		(0x00000003UL)
#وصف_ڪريو CKG_MGF1_SHA512		(0x00000004UL)
#وصف_ڪريو CKG_MGF1_SHA3_224	(0x00000006UL)
#وصف_ڪريو CKG_MGF1_SHA3_256	(0x00000007UL)
#وصف_ڪريو CKG_MGF1_SHA3_384	(0x00000008UL)
#وصف_ڪريو CKG_MGF1_SHA3_512	(0x00000009UL)

#وصف_ڪريو CKZ_معلومات_SPECIFIED	(0x00000001UL)

تعريفنوع بنية CK_GCM_PARAMS {
	فراغ * pIv;
	بنانشان ڊگهو ulIvLen;
	بنانشان ڊگهو ul_Iv_بٽ;
	فراغ * pAAD;
	بنانشان ڊگهو ulAADLen;
	بنانشان ڊگهو ul_ٽيگ_بٽ;
} CK_GCM_PARAMS;

تعريفنوع بنية CK_CCM_PARAMS {
	بنانشان ڊگهو ul_معلومات_Len;
	بنانشان حرف *pNonce;
	بنانشان ڊگهو ulNonceLen;
	بنانشان حرف *pAAD;
	بنانشان ڊگهو ulAADLen;
	بنانشان ڊگهو ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
تعريفنوع بنية CK_EDDSA_PARAMS {
	بنانشان حرف phFlag;
	بنانشان ڊگهو ul_Context_معلومات_Len;
	بنانشان حرف *p_Context_معلومات;
} CK_EDDSA_PARAMS;

تعريفنوع CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
تعريفنوع بنية CK_XEDDSA_PARAMS {
	بنانشان ڊگهو hash;
} CK_XEDDSA_PARAMS;

تعريفنوع CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

تعريفنوع بنية CK_AES_CTR_PARAMS {
    بنانشان ڊگهو ul_Counter_بٽ;
    بنانشان حرف cb[16];
} CK_AES_CTR_PARAMS;

تعريفنوع CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

تعريفنوع بنانشان ڊگهو CK_MAC_GENERAL_PARAMS;

تعريفنوع CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

تعريفنوع بنانشان ڊگهو ck_rv_t;


تعريفنوع ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, فراغ *application);

بنية ck_interface {
  حرف * pInterfaceName;
  فراغ * pFunctionList;
  ck_flags_t flags;
};

#وصف_ڪريو CKF_INTERFACE_FORK_محفوظ	(0x00000001UL)

/* Forward reference.  */
بنية ck_function_list;
بنية ck_function_list_3_0;

#وصف_ڪريو _CK_DECLARE_FUNCTION(name, دليلون)	\
تعريفنوع ck_rv_t (*CK_ ## name) دليلون;		\
ck_rv_t CK_SPEC name دليلون

_CK_DECLARE_FUNCTION (C_Initialize, (فراغ *init_دليلون));
_CK_DECLARE_FUNCTION (C_Finalize, (فراغ *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (بنية ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (بنية ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_Get_جڳهه_List,
		      (بنانشان حرف token_present, ck_جڳهه_id_t *جڳهه_list,
		       بنانشان ڊگهو *ڳڻپ));
_CK_DECLARE_FUNCTION (C_Get_جڳهه_Info,
		      (ck_جڳهه_id_t جڳهه_id, بنية ck_جڳهه_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_جڳهه_id_t جڳهه_id, بنية ck_token_info *info));
_CK_DECLARE_FUNCTION (C_Wait_For_جڳهه_Event,
		      (ck_flags_t flags, ck_جڳهه_id_t *جڳهه, فراغ *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_جڳهه_id_t جڳهه_id,
		       ck_mechanism_type_t *mechanism_list,
		       بنانشان ڊگهو *ڳڻپ));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_جڳهه_id_t جڳهه_id, ck_mechanism_type_t type,
		       بنية ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_جڳهه_id_t جڳهه_id, بنانشان حرف *pin,
		       بنانشان ڊگهو pin_len, بنانشان حرف *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, بنانشان حرف *pin,
		       بنانشان ڊگهو pin_len));
_CK_DECLARE_FUNCTION (C_سيٽ_PIN,
		      (ck_session_handle_t session, بنانشان حرف *old_pin,
		       بنانشان ڊگهو old_len, بنانشان حرف *new_pin,
		       بنانشان ڊگهو new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_جڳهه_id_t جڳهه_id, ck_flags_t flags,
		       فراغ *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_جڳهه_id_t جڳهه_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       بنية ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       بنانشان حرف *operation_state,
		       بنانشان ڊگهو *operation_state_len));
_CK_DECLARE_FUNCTION (C_سيٽ_Operation_State,
		      (ck_session_handle_t session,
		       بنانشان حرف *operation_state,
		       بنانشان ڊگهو operation_state_len,
		       ck_object_handle_t encryption_ڪنجي,
		       ck_object_handle_t authentication_ڪنجي));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       بنانشان حرف *pin, بنانشان ڊگهو pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       بنية ck_attribute *templ,
		       بنانشان ڊگهو ڳڻپ, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       بنية ck_attribute *templ, بنانشان ڊگهو ڳڻپ,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_سائيز,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بنانشان ڊگهو *سائيز));
_CK_DECLARE_FUNCTION (C_Get_Attribute_قدر,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بنية ck_attribute *templ,
		       بنانشان ڊگهو ڳڻپ));
_CK_DECLARE_FUNCTION (C_سيٽ_Attribute_قدر,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       بنية ck_attribute *templ,
		       بنانشان ڊگهو ڳڻپ));
_CK_DECLARE_FUNCTION (C_ڳوليو_Objects_Init,
		      (ck_session_handle_t session,
		       بنية ck_attribute *templ,
		       بنانشان ڊگهو ڳڻپ));
_CK_DECLARE_FUNCTION (C_ڳوليو_Objects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       بنانشان ڊگهو max_object_ڳڻپ,
		       بنانشان ڊگهو *object_ڳڻپ));
_CK_DECLARE_FUNCTION (C_ڳوليو_Objects_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       بنانشان حرف *معلومات, بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *encrypted_معلومات,
		       بنانشان ڊگهو *encrypted_معلومات_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *part, بنانشان ڊگهو part_len,
		       بنانشان حرف *encrypted_part,
		       بنانشان ڊگهو *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       بنانشان حرف *آخري_encrypted_part,
		       بنانشان ڊگهو *آخري_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       بنانشان حرف *encrypted_معلومات,
		       بنانشان ڊگهو encrypted_معلومات_len,
		       بنانشان حرف *معلومات, بنانشان ڊگهو *معلومات_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *encrypted_part,
		       بنانشان ڊگهو encrypted_part_len,
		       بنانشان حرف *part, بنانشان ڊگهو *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       بنانشان حرف *آخري_part,
		       بنانشان ڊگهو *آخري_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       بنانشان حرف *معلومات, بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *digest,
		       بنانشان ڊگهو *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *part, بنانشان ڊگهو part_len));
_CK_DECLARE_FUNCTION (C_Digest_ڪنجي,
		      (ck_session_handle_t session, ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       بنانشان حرف *digest,
		       بنانشان ڊگهو *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       بنانشان حرف *معلومات, بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *part, بنانشان ڊگهو part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       بنانشان حرف *معلومات, بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       بنانشان حرف *معلومات, بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *part, بنانشان ڊگهو part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو signature_len,
		       بنانشان حرف *معلومات,
		       بنانشان ڊگهو *معلومات_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *part, بنانشان ڊگهو part_len,
		       بنانشان حرف *encrypted_part,
		       بنانشان ڊگهو *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *encrypted_part,
		       بنانشان ڊگهو encrypted_part_len,
		       بنانشان حرف *part,
		       بنانشان ڊگهو *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *part, بنانشان ڊگهو part_len,
		       بنانشان حرف *encrypted_part,
		       بنانشان ڊگهو *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       بنانشان حرف *encrypted_part,
		       بنانشان ڊگهو encrypted_part_len,
		       بنانشان حرف *part,
		       بنانشان ڊگهو *part_len));

_CK_DECLARE_FUNCTION (C_Generate_ڪنجي,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       بنية ck_attribute *templ,
		       بنانشان ڊگهو ڳڻپ,
		       ck_object_handle_t *ڪنجي));
_CK_DECLARE_FUNCTION (C_Generate_ڪنجي_Pair,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       بنية ck_attribute *عوامي_ڪنجي_template,
		       بنانشان ڊگهو عوامي_ڪنجي_attribute_ڳڻپ,
		       بنية ck_attribute *ذاتي_ڪنجي_template,
		       بنانشان ڊگهو ذاتي_ڪنجي_attribute_ڳڻپ,
		       ck_object_handle_t *عوامي_ڪنجي,
		       ck_object_handle_t *ذاتي_ڪنجي));
_CK_DECLARE_FUNCTION (C_Wrap_ڪنجي,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_ڪنجي,
		       ck_object_handle_t ڪنجي,
		       بنانشان حرف *wrapped_ڪنجي,
		       بنانشان ڊگهو *wrapped_ڪنجي_len));
_CK_DECLARE_FUNCTION (C_Unwrap_ڪنجي,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_ڪنجي,
		       بنانشان حرف *wrapped_ڪنجي,
		       بنانشان ڊگهو wrapped_ڪنجي_len,
		       بنية ck_attribute *templ,
		       بنانشان ڊگهو attribute_ڳڻپ,
		       ck_object_handle_t *ڪنجي));
_CK_DECLARE_FUNCTION (C_Derive_ڪنجي,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t بنياد_ڪنجي,
		       بنية ck_attribute *templ,
		       بنانشان ڊگهو attribute_ڳڻپ,
		       ck_object_handle_t *ڪنجي));

_CK_DECLARE_FUNCTION (C_ٻج_Random,
		      (ck_session_handle_t session, بنانشان حرف *ٻج,
		       بنانشان ڊگهو ٻج_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       بنانشان حرف *random_data,
		       بنانشان ڊگهو random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_حالت, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (بنية ck_interface *interfaces_list,
		       بنانشان ڊگهو *ڳڻپ));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (بنانشان حرف *interface_name,
		       بنية ck_نسخو *نسخو,
		       بنية ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       بنانشان حرف *pin,
		       بنانشان ڊگهو pin_len,
		       بنانشان حرف *username,
		       بنانشان ڊگهو username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_پيغام_Encrypt_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Encrypt_پيغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *associated_معلومات,
		       بنانشان ڊگهو associated_معلومات_len,
		       بنانشان حرف *plaintext,
		       بنانشان ڊگهو plaintext_len,
		       بنانشان حرف *ciphertext,
		       بنانشان ڊگهو *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پيغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *associated_معلومات,
		       بنانشان ڊگهو associated_معلومات_len));
_CK_DECLARE_FUNCTION (C_Encrypt_پيغام_ايندڙ,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *plaintext_part,
		       بنانشان ڊگهو plaintext_part_len,
		       بنانشان حرف *ciphertext_part,
		       بنانشان ڊگهو *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پيغام_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پيغام_Decrypt_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Decrypt_پيغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *associated_معلومات,
		       بنانشان ڊگهو associated_معلومات_len,
		       بنانشان حرف *ciphertext,
		       بنانشان ڊگهو ciphertext_len,
		       بنانشان حرف *plaintext,
		       بنانشان ڊگهو *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پيغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *associated_معلومات,
		       بنانشان ڊگهو associated_معلومات_len));
_CK_DECLARE_FUNCTION (C_Decrypt_پيغام_ايندڙ,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *ciphertext_part,
		       بنانشان ڊگهو ciphertext_part_len,
		       بنانشان حرف *plaintext_part,
		       بنانشان ڊگهو *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_پيغام_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پيغام_Sign_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Sign_پيغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *معلومات,
		       بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_پيغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_پيغام_ايندڙ,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *معلومات,
		       بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو *signature_len));
_CK_DECLARE_FUNCTION (C_پيغام_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_پيغام_Verify_Init,
		      (ck_session_handle_t session,
		       بنية ck_mechanism *mechanism,
		       ck_object_handle_t ڪنجي));
_CK_DECLARE_FUNCTION (C_Verify_پيغام,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *معلومات,
		       بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو signature_len));
_CK_DECLARE_FUNCTION (C_Verify_پيغام_Begin,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_پيغام_ايندڙ,
		      (ck_session_handle_t session,
		       فراغ *parameter,
		       بنانشان ڊگهو parameter_len,
		       بنانشان حرف *معلومات,
		       بنانشان ڊگهو معلومات_len,
		       بنانشان حرف *signature,
		       بنانشان ڊگهو signature_len));
_CK_DECLARE_FUNCTION (C_پيغام_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#وصف_ڪريو CKF_پڇاڙي_جو_پيغام	(0x00000001UL)

بنية ck_function_list
{
  بنية ck_نسخو نسخو;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_جڳهه_List C_Get_جڳهه_List;
  CK_C_Get_جڳهه_Info C_Get_جڳهه_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_سيٽ_PIN C_سيٽ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_سيٽ_Operation_State C_سيٽ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_سائيز C_Get_Object_سائيز;
  CK_C_Get_Attribute_قدر C_Get_Attribute_قدر;
  CK_C_سيٽ_Attribute_قدر C_سيٽ_Attribute_قدر;
  CK_C_ڳوليو_Objects_Init C_ڳوليو_Objects_Init;
  CK_C_ڳوليو_Objects C_ڳوليو_Objects;
  CK_C_ڳوليو_Objects_Final C_ڳوليو_Objects_Final;
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
  CK_C_Digest_ڪنجي C_Digest_ڪنجي;
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
  CK_C_Generate_ڪنجي C_Generate_ڪنجي;
  CK_C_Generate_ڪنجي_Pair C_Generate_ڪنجي_Pair;
  CK_C_Wrap_ڪنجي C_Wrap_ڪنجي;
  CK_C_Unwrap_ڪنجي C_Unwrap_ڪنجي;
  CK_C_Derive_ڪنجي C_Derive_ڪنجي;
  CK_C_ٻج_Random C_ٻج_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_حالت C_Get_Function_حالت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_جڳهه_Event C_Wait_For_جڳهه_Event;
};

بنية ck_function_list_3_0
{
  بنية ck_نسخو نسخو;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_جڳهه_List C_Get_جڳهه_List;
  CK_C_Get_جڳهه_Info C_Get_جڳهه_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_سيٽ_PIN C_سيٽ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_سيٽ_Operation_State C_سيٽ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_سائيز C_Get_Object_سائيز;
  CK_C_Get_Attribute_قدر C_Get_Attribute_قدر;
  CK_C_سيٽ_Attribute_قدر C_سيٽ_Attribute_قدر;
  CK_C_ڳوليو_Objects_Init C_ڳوليو_Objects_Init;
  CK_C_ڳوليو_Objects C_ڳوليو_Objects;
  CK_C_ڳوليو_Objects_Final C_ڳوليو_Objects_Final;
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
  CK_C_Digest_ڪنجي C_Digest_ڪنجي;
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
  CK_C_Generate_ڪنجي C_Generate_ڪنجي;
  CK_C_Generate_ڪنجي_Pair C_Generate_ڪنجي_Pair;
  CK_C_Wrap_ڪنجي C_Wrap_ڪنجي;
  CK_C_Unwrap_ڪنجي C_Unwrap_ڪنجي;
  CK_C_Derive_ڪنجي C_Derive_ڪنجي;
  CK_C_ٻج_Random C_ٻج_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_حالت C_Get_Function_حالت;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_جڳهه_Event C_Wait_For_جڳهه_Event;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_پيغام_Encrypt_Init C_پيغام_Encrypt_Init;
  CK_C_Encrypt_پيغام C_Encrypt_پيغام;
  CK_C_Encrypt_پيغام_Begin C_Encrypt_پيغام_Begin;
  CK_C_Encrypt_پيغام_ايندڙ C_Encrypt_پيغام_ايندڙ;
  CK_C_پيغام_Encrypt_Final C_پيغام_Encrypt_Final;
  CK_C_پيغام_Decrypt_Init C_پيغام_Decrypt_Init;
  CK_C_Decrypt_پيغام C_Decrypt_پيغام;
  CK_C_Decrypt_پيغام_Begin C_Decrypt_پيغام_Begin;
  CK_C_Decrypt_پيغام_ايندڙ C_Decrypt_پيغام_ايندڙ;
  CK_C_پيغام_Decrypt_Final C_پيغام_Decrypt_Final;
  CK_C_پيغام_Sign_Init C_پيغام_Sign_Init;
  CK_C_Sign_پيغام C_Sign_پيغام;
  CK_C_Sign_پيغام_Begin C_Sign_پيغام_Begin;
  CK_C_Sign_پيغام_ايندڙ C_Sign_پيغام_ايندڙ;
  CK_C_پيغام_Sign_Final C_پيغام_Sign_Final;
  CK_C_پيغام_Verify_Init C_پيغام_Verify_Init;
  CK_C_Verify_پيغام C_Verify_پيغام;
  CK_C_Verify_پيغام_Begin C_Verify_پيغام_Begin;
  CK_C_Verify_پيغام_ايندڙ C_Verify_پيغام_ايندڙ;
  CK_C_پيغام_Verify_Final C_پيغام_Verify_Final;
};



تعريفنوع ck_rv_t (*ck_createmutex_t) (فراغ **mutex);
تعريفنوع ck_rv_t (*ck_destroymutex_t) (فراغ *mutex);
تعريفنوع ck_rv_t (*ck_lockmutex_t) (فراغ *mutex);
تعريفنوع ck_rv_t (*ck_unlockmutex_t) (فراغ *mutex);


بنية ck_c_initialize_دليلون
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t تالو_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  فراغ *reserved;
};


#وصف_ڪريو CKF_LIBRARY_CANT_CREATE_OS_ڌاڳا	(1UL << 0)
#وصف_ڪريو CKF_OS_LOCKING_OK			(1UL << 1)

#وصف_ڪريو CKR_OK					(0UL)
#وصف_ڪريو CKR_CANCEL				(1UL)
#وصف_ڪريو CKR_HOST_يادگيري				(2UL)
#وصف_ڪريو CKR_جڳهه_ID_INVALID			(3UL)
#وصف_ڪريو CKR_GENERAL_ERROR			(5UL)
#وصف_ڪريو CKR_FUNCTION_FAILED			(6UL)
#وصف_ڪريو CKR_ARGUMENTS_BAD			(7UL)
#وصف_ڪريو CKR_NO_EVENT				(8UL)
#وصف_ڪريو CKR_NEED_منزل_CREATE_ڌاڳا		(9UL)
#وصف_ڪريو CKR_CANT_تالو				(0xaUL)
#وصف_ڪريو CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#وصف_ڪريو CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#وصف_ڪريو CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#وصف_ڪريو CKR_ATTRIBUTE_قدر_INVALID		(0x13UL)
#وصف_ڪريو CKR_ACTION_PROHIBITED			(0x1BUL)
#وصف_ڪريو CKR_معلومات_INVALID			(0x20UL)
#وصف_ڪريو CKR_معلومات_LEN_RANGE			(0x21UL)
#وصف_ڪريو CKR_DEVICE_ERROR			(0x30UL)
#وصف_ڪريو CKR_DEVICE_يادگيري			(0x31UL)
#وصف_ڪريو CKR_DEVICE_REMOVED			(0x32UL)
#وصف_ڪريو CKR_ENCRYPTED_معلومات_INVALID		(0x40UL)
#وصف_ڪريو CKR_ENCRYPTED_معلومات_LEN_RANGE		(0x41UL)
#وصف_ڪريو CKR_FUNCTION_CANCELED			(0x50UL)
#وصف_ڪريو CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#وصف_ڪريو CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#وصف_ڪريو CKR_ڪنجي_HANDLE_INVALID			(0x60UL)
#وصف_ڪريو CKR_ڪنجي_سائيز_RANGE			(0x62UL)
#وصف_ڪريو CKR_ڪنجي_TYPE_INCONSISTENT		(0x63UL)
#وصف_ڪريو CKR_ڪنجي_NOT_NEEDED			(0x64UL)
#وصف_ڪريو CKR_ڪنجي_بدليو				(0x65UL)
#وصف_ڪريو CKR_ڪنجي_NEEDED				(0x66UL)
#وصف_ڪريو CKR_ڪنجي_INDIGESTIBLE			(0x67UL)
#وصف_ڪريو CKR_ڪنجي_FUNCTION_NOT_PERMITTED		(0x68UL)
#وصف_ڪريو CKR_ڪنجي_NOT_WRAPPABLE			(0x69UL)
#وصف_ڪريو CKR_ڪنجي_UNEXTRACTABLE			(0x6aUL)
#وصف_ڪريو CKR_MECHANISM_INVALID			(0x70UL)
#وصف_ڪريو CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#وصف_ڪريو CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#وصف_ڪريو CKR_OPERATION_سرگرم			(0x90UL)
#وصف_ڪريو CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#وصف_ڪريو CKR_PIN_INCORRECT			(0xa0UL)
#وصف_ڪريو CKR_PIN_INVALID				(0xa1UL)
#وصف_ڪريو CKR_PIN_LEN_RANGE			(0xa2UL)
#وصف_ڪريو CKR_PIN_EXPIRED				(0xa3UL)
#وصف_ڪريو CKR_PIN_LOCKED				(0xa4UL)
#وصف_ڪريو CKR_SESSION_CLOSED			(0xb0UL)
#وصف_ڪريو CKR_SESSION_ڳڻپ			(0xb1UL)
#وصف_ڪريو CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#وصف_ڪريو CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#وصف_ڪريو CKR_SESSION_READ_ONLY			(0xb5UL)
#وصف_ڪريو CKR_SESSION_EXISTS			(0xb6UL)
#وصف_ڪريو CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#وصف_ڪريو CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#وصف_ڪريو CKR_SIGNATURE_INVALID			(0xc0UL)
#وصف_ڪريو CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#وصف_ڪريو CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#وصف_ڪريو CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#وصف_ڪريو CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#وصف_ڪريو CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#وصف_ڪريو CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#وصف_ڪريو	CKR_UNWRAPPING_ڪنجي_HANDLE_INVALID	(0xf0UL)
#وصف_ڪريو CKR_UNWRAPPING_ڪنجي_سائيز_RANGE		(0xf1UL)
#وصف_ڪريو CKR_UNWRAPPING_ڪنجي_TYPE_INCONSISTENT	(0xf2UL)
#وصف_ڪريو CKR_USER_ALREADY_LOGGED_اندريون		(0x100UL)
#وصف_ڪريو CKR_USER_NOT_LOGGED_اندريون			(0x101UL)
#وصف_ڪريو CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#وصف_ڪريو CKR_USER_TYPE_INVALID			(0x103UL)
#وصف_ڪريو CKR_USER_ANOTHER_ALREADY_LOGGED_اندريون	(0x104UL)
#وصف_ڪريو CKR_USER_TOO_MANY_TYPES			(0x105UL)
#وصف_ڪريو CKR_WRAPPED_ڪنجي_INVALID			(0x110UL)
#وصف_ڪريو CKR_WRAPPED_ڪنجي_LEN_RANGE		(0x112UL)
#وصف_ڪريو CKR_WRAPPING_ڪنجي_HANDLE_INVALID		(0x113UL)
#وصف_ڪريو CKR_WRAPPING_ڪنجي_سائيز_RANGE		(0x114UL)
#وصف_ڪريو CKR_WRAPPING_ڪنجي_TYPE_INCONSISTENT	(0x115UL)
#وصف_ڪريو CKR_RANDOM_ٻج_NOT_SUPPORTED		(0x120UL)
#وصف_ڪريو CKR_RANDOM_NO_RNG			(0x121UL)
#وصف_ڪريو CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#وصف_ڪريو CKR_وڪر_NOT_SUPPORTED			(0x140UL)
#وصف_ڪريو CKR_بفر_TOO_SMALL			(0x150UL)
#وصف_ڪريو CKR_SAVED_STATE_INVALID			(0x160UL)
#وصف_ڪريو CKR_INFORMATION_SENSITIVE		(0x170UL)
#وصف_ڪريو CKR_STATE_UNSAVEABLE			(0x180UL)
#وصف_ڪريو CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#وصف_ڪريو CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#وصف_ڪريو CKR_MUTEX_BAD				(0x1a0UL)
#وصف_ڪريو CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#وصف_ڪريو CKR_FUNCTION_REJECTED			(0x200UL)
#وصف_ڪريو CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#جيڪڏهن_وصف_ٿيل CRYPTOKI_COMPAT

#وصف_رد CK_DEFINE_FUNCTION
#وصف_ڪريو CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#ضمن <stddef.h>

تعريفنوع بنانشان حرف CK_BYTE;
تعريفنوع بنانشان حرف CK_CHAR;
تعريفنوع بنانشان حرف CK_UTF8CHAR;
تعريفنوع بنانشان حرف CK_BBOOL;
تعريفنوع بنانشان ڊگهو صحيح CK_ULONG;
تعريفنوع ڊگهو صحيح CK_LONG;
تعريفنوع CK_BYTE *CK_BYTE_PTR;
تعريفنوع CK_CHAR *CK_CHAR_PTR;
تعريفنوع CK_UTF8CHAR *CK_UTF8CHAR_PTR;
تعريفنوع CK_ULONG *CK_ULONG_PTR;
تعريفنوع فراغ *CK_VOID_PTR;
تعريفنوع فراغ **CK_VOID_PTR_PTR;
#وصف_ڪريو CK_FALSE 0
#وصف_ڪريو CK_TRUE 1
#جيڪڏهن_وصف_نه_ٿيل CK_DISABLE_TRUE_FALSE
#جيڪڏهن_وصف_نه_ٿيل FALSE
#وصف_ڪريو FALSE 0
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل TRUE
#وصف_ڪريو TRUE 1
#جيڪڏهن_پورو
#جيڪڏهن_پورو

تعريفنوع بنية CK_HKDF_PARAMS {
	CK_BBOOL b_ڪڍو;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_ڪنجي;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#وصف_ڪريو CKF_HKDF_SALT_NULL 0x00000001UL
#وصف_ڪريو CKF_HKDF_SALT_معلومات 0x00000002UL
#وصف_ڪريو CKF_HKDF_SALT_ڪنجي  0x00000004UL

تعريفنوع بنية ck_نسخو CK_نسخو_2;
تعريفنوع بنية ck_نسخو *CK_نسخو_PTR;

تعريفنوع بنية ck_info CK_INFO;
تعريفنوع بنية ck_info *CK_INFO_PTR;

تعريفنوع ck_جڳهه_id_t *CK_جڳهه_ID_PTR;

تعريفنوع بنية ck_جڳهه_info CK_جڳهه_INFO_2;
تعريفنوع بنية ck_جڳهه_info *CK_جڳهه_INFO_PTR;

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

تعريفنوع بنية ck_c_initialize_دليلون CK_C_INITIALIZE_دليلون_2;
تعريفنوع بنية ck_c_initialize_دليلون *CK_C_INITIALIZE_دليلون_PTR;

#وصف_ڪريو NULL_PTR عدم

/* Delete the helper macros defined at the top of the file.  */
#وصف_رد ck_flags_t
#وصف_رد ck_نسخو

#وصف_رد ck_info
#وصف_رد cryptoki_نسخو
#وصف_رد manufacturer_id
#وصف_رد library_description
#وصف_رد library_نسخو

#وصف_رد ck_notification_t
#وصف_رد ck_جڳهه_id_t

#وصف_رد ck_جڳهه_info
#وصف_رد جڳهه_description
#وصف_رد hardware_نسخو
#وصف_رد firmware_نسخو

#وصف_رد ck_token_info
#وصف_رد serial_عدد
#وصف_رد max_session_ڳڻپ
#وصف_رد session_ڳڻپ
#وصف_رد max_rw_session_ڳڻپ
#وصف_رد rw_session_ڳڻپ
#وصف_رد max_pin_len
#وصف_رد min_pin_len
#وصف_رد ڪل_عوامي_يادگيري
#وصف_رد free_عوامي_يادگيري
#وصف_رد ڪل_ذاتي_يادگيري
#وصف_رد free_ذاتي_يادگيري
#وصف_رد utc_وقت

#وصف_رد ck_session_handle_t
#وصف_رد ck_user_type_t
#وصف_رد ck_state_t

#وصف_رد ck_session_info
#وصف_رد جڳهه_id
#وصف_رد device_error

#وصف_رد ck_object_handle_t
#وصف_رد ck_object_class_t
#وصف_رد ck_hw_feature_type_t
#وصف_رد ck_ڪنجي_type_t
#وصف_رد ck_certificate_type_t
#وصف_رد ck_attribute_type_t

#وصف_رد ck_attribute
#وصف_رد قدر
#وصف_رد قدر_len

#وصف_رد ck_date

#وصف_رد ck_mechanism_type_t

#وصف_رد ck_rsa_pkcs_mgf_type_t

#وصف_رد ck_mechanism
#وصف_رد parameter
#وصف_رد parameter_len

#وصف_رد ck_mechanism_info
#وصف_رد min_ڪنجي_سائيز
#وصف_رد max_ڪنجي_سائيز

#وصف_رد ck_rv_t
#وصف_رد ck_notify_t

#وصف_رد ck_interface

#وصف_رد ck_function_list
#وصف_رد ck_function_list_3_0

#وصف_رد ck_createmutex_t
#وصف_رد ck_destroymutex_t
#وصف_رد ck_lockmutex_t
#وصف_رد ck_unlockmutex_t

#وصف_رد ck_c_initialize_دليلون
#وصف_رد create_mutex
#وصف_رد destroy_mutex
#وصف_رد تالو_mutex
#وصف_رد unlock_mutex
#وصف_رد reserved

#جيڪڏهن_پورو	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#إذا defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#هدايت pack(ڪڍو, cryptoki)
#جيڪڏهن_پورو

#إذا defined(__cplusplus)
}
#جيڪڏهن_پورو

#جيڪڏهن_پورو	/* PKCS11_H */
