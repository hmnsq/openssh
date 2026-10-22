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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ PKCS11_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PKCS11_H 1

#ਜੇ defined(__cplusplus)
ਬਾਹਰੀ "C" {
#ਜੇ_ਅੰਤ


/* The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CRYPTOKI_ਸੰਸਕਰਣ_MAJOR		3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CRYPTOKI_ਸੰਸਕਰਣ_MINOR		0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CRYPTOKI_ਸੰਸਕਰਣ_REVISION	0


/* Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CRYPTOKI_GNU
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CRYPTOKI_COMPAT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CRYPTOKI_COMPAT 1
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ

/* System dependencies.  */

#ਜੇ defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

/* There is a matching pop below.  */
#ਹਦਾਇਤ pack(ਧੱਕੋ, cryptoki, 1)

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CRYPTOKI_EXPORTS
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_SPEC __declspec(dllexport)
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_SPEC __declspec(dllimport)
#ਜੇ_ਅੰਤ

#ਨਹੀਂਤਾਂ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_SPEC

#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CRYPTOKI_COMPAT
  /* If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_flags_t CK_FLAGS
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_ਸੰਸਕਰਣ CK_ਸੰਸਕਰਣ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_info _CK_INFO
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ cryptoki_ਸੰਸਕਰਣ cryptoki_ਸੰਸਕਰਣ_2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ manufacturer_id manufacturerID
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ library_description libraryDescription
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ library_ਸੰਸਕਰਣ library_ਸੰਸਕਰਣ_2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_notification_t CK_NOTIFICATION
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_ਥਾਂ_id_t CK_ਥਾਂ_ID

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_ਥਾਂ_info CK_ਥਾਂ_INFO
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਥਾਂ_description ਥਾਂ_Description
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ hardware_ਸੰਸਕਰਣ hardware_ਸੰਸਕਰਣ_2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ firmware_ਸੰਸਕਰਣ firmware_ਸੰਸਕਰਣ_2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_token_info _CK_TOKEN_INFO
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ serial_ਸੰਖਿਆ serial_ਸੰਖਿਆ_2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ max_session_ਗਿਣਤੀ ul_Max_Session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ session_ਗਿਣਤੀ ul_Session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ max_rw_session_ਗਿਣਤੀ ul_Max_Rw_Session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ rw_session_ਗਿਣਤੀ ul_Rw_Session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ max_pin_len ulMaxPinLen
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ min_pin_len ulMinPinLen
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਕੁੱਲ_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ ul_ਕੁੱਲ_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ ul_Free_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਕੁੱਲ_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ ul_ਕੁੱਲ_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ free_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ ul_Free_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ utc_ਸਮਾਂ utc_ਸਮਾਂ_2

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_session_handle_t CK_SESSION_HANDLE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_user_type_t CK_USER_TYPE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_state_t CK_STATE

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_session_info _CK_SESSION_INFO
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਥਾਂ_id ਥਾਂ_ID
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ device_error ulDeviceError

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_object_handle_t CK_OBJECT_HANDLE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_object_class_t CK_OBJECT_CLASS
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_hw_feature_type_t CK_HW_FEATURE_TYPE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_ਕੁੰਜੀ_type_t CK_ਕੁੰਜੀ_TYPE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_certificate_type_t CK_CERTIFICATE_TYPE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_attribute_type_t CK_ATTRIBUTE_TYPE

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_attribute _CK_ATTRIBUTE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੁੱਲ p_ਮੁੱਲ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਮੁੱਲ_len ul_ਮੁੱਲ_Len

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_date _CK_DATE

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_mechanism_type_t CK_MECHANISM_TYPE

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_rsa_pkcs_mgf_type_t CK_RSA_PKCS_MGF_TYPE

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_mechanism _CK_MECHANISM
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ parameter pParameter
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ parameter_len ulParameterLen

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_mechanism_info _CK_MECHANISM_INFO
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ min_ਕੁੰਜੀ_ਮਾਪ ul_Min_ਕੁੰਜੀ_ਮਾਪ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ max_ਕੁੰਜੀ_ਮਾਪ ul_Max_ਕੁੰਜੀ_ਮਾਪ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_rv_t CK_RV
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_notify_t CK_NOTIFY

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_interface CK_INTERFACE

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_function_list _CK_FUNCTION_LIST
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_function_list_3_0 _CK_FUNCTION_LIST_3_0

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_createmutex_t CK_CREATEMUTEX
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_destroymutex_t CK_DESTROYMUTEX
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_lockmutex_t CK_LOCKMUTEX
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_unlockmutex_t CK_UNLOCKMUTEX

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ck_c_initialize_ਦਲੀਲਾਂ CK_C_INITIALIZE_ਦਲੀਲਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ create_mutex CreateMutex
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ destroy_mutex DestroyMutex
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਤਾਲਾ_mutex ਤਾਲਾ_Mutex
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ unlock_mutex UnlockMutex
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ reserved pReserved

#ਜੇ_ਅੰਤ	/* CRYPTOKI_COMPAT */


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_flags_t;

ਬਣਤਰ ck_ਸੰਸਕਰਣ
{
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ major;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ minor;
};


ਬਣਤਰ ck_info
{
  ਬਣਤਰ ck_ਸੰਸਕਰਣ cryptoki_ਸੰਸਕਰਣ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ manufacturer_id[32];
  ck_flags_t flags;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ library_description[32];
  ਬਣਤਰ ck_ਸੰਸਕਰਣ library_ਸੰਸਕਰਣ;
};


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_notification_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKN_SURRENDER	(0UL)


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_ਥਾਂ_id_t;


ਬਣਤਰ ck_ਥਾਂ_info
{
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ ਥਾਂ_description[64];
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ manufacturer_id[32];
  ck_flags_t flags;
  ਬਣਤਰ ck_ਸੰਸਕਰਣ hardware_ਸੰਸਕਰਣ;
  ਬਣਤਰ ck_ਸੰਸਕਰਣ firmware_ਸੰਸਕਰਣ;
};


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_TOKEN_PRESENT	(1UL << 0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_REMOVABLE_DEVICE	(1UL << 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_HW_ਥਾਂ		(1UL << 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ARRAY_ATTRIBUTE	(1UL << 30)


ਬਣਤਰ ck_token_info
{
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ label[32];
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ manufacturer_id[32];
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ model[16];
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ serial_ਸੰਖਿਆ[16];
  ck_flags_t flags;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ max_session_ਗਿਣਤੀ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ session_ਗਿਣਤੀ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ max_rw_session_ਗਿਣਤੀ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ rw_session_ਗਿਣਤੀ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ max_pin_len;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ min_pin_len;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਕੁੱਲ_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ free_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਕੁੱਲ_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ free_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ;
  ਬਣਤਰ ck_ਸੰਸਕਰਣ hardware_ਸੰਸਕਰਣ;
  ਬਣਤਰ ck_ਸੰਸਕਰਣ firmware_ਸੰਸਕਰਣ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ utc_ਸਮਾਂ[16];
};


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_RNG					(1UL << 0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_WRITE_PROTECTED			(1UL << 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_LOGIN_REQUIRED			(1UL << 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_USER_PIN_INITIALIZED		(1UL << 3)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_RESTORE_ਕੁੰਜੀ_NOT_NEEDED		(1UL << 5)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_CLOCK_ON_TOKEN			(1UL << 6)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_PROTECTED_AUTHENTICATION_ਰਸਤਾ	(1UL << 8)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_DUAL_CRYPTO_OPERATIONS		(1UL << 9)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_TOKEN_INITIALIZED			(1UL << 10)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SECONDARY_AUTHENTICATION		(1UL << 11)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_USER_PIN_ਗਿਣਤੀ_ਨੀਵਾਂ			(1UL << 16)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_USER_PIN_FINAL_TRY			(1UL << 17)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_USER_PIN_LOCKED			(1UL << 18)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_USER_PIN_ਮੰਜ਼ਿਲ_BE_ਬਦਲਿਆ		(1UL << 19)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SO_PIN_ਗਿਣਤੀ_ਨੀਵਾਂ			(1UL << 20)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SO_PIN_FINAL_TRY			(1UL << 21)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SO_PIN_LOCKED			(1UL << 22)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SO_PIN_ਮੰਜ਼ਿਲ_BE_ਬਦਲਿਆ		(1UL << 23)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_UNAVAILABLE_INFORMATION	((ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ) -1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_EFFECTIVELY_INFINITE		(0UL)


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_session_handle_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_INVALID_HANDLE	(0UL)


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_user_type_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKU_SO			(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKU_USER		(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKU_CONTEXT_SPECIFIC	(2UL)


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_state_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKS_RO_ਜਨਤਕ_SESSION	(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKS_RO_USER_FUNCTIONS	(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKS_RW_ਜਨਤਕ_SESSION	(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKS_RW_USER_FUNCTIONS	(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKS_RW_SO_FUNCTIONS	(4UL)


ਬਣਤਰ ck_session_info
{
  ck_ਥਾਂ_id_t ਥਾਂ_id;
  ck_state_t state;
  ck_flags_t flags;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ device_error;
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_RW_SESSION		(1UL << 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SERIAL_SESSION	(1UL << 2)


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_object_handle_t;


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_object_class_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_ਅੰਕੜੇ		(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_CERTIFICATE		(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_ਜਨਤਕ_ਕੁੰਜੀ		(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_ਨਿੱਜੀ_ਕੁੰਜੀ		(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_SECRET_ਕੁੰਜੀ		(4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_HW_FEATURE		(5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_DOMAIN_PARAMETERS	(6UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_MECHANISM		(7UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_OTP_ਕੁੰਜੀ		(8UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_PROFILE		(9UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKO_VENDOR_DEFINED	(1UL << 31)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKP_INVALID_ID                (0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKP_BASELINE_PROVIDER         (1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKP_EXTENDED_PROVIDER         (2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKP_AUTHENTICATION_TOKEN      (3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKP_ਜਨਤਕ_CERTIFICATES_TOKEN (4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKP_VENDOR_DEFINED            (1UL << 31)

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_hw_feature_type_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKH_MONOTONIC_COUNTER	(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKH_CLOCK		(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKH_USER_INTERFACE	(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKH_VENDOR_DEFINED	(1UL << 31)


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_ਕੁੰਜੀ_type_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_RSA			(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_DSA			(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_DH			(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_ECDSA		(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_EC			(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_X9_42_DH		(4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_KEA			(5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_GENERIC_SECRET	(0x10UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_RC2			(0x11UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_RC4			(0x12UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_DES			(0x13UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_DES2		(0x14UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_DES3		(0x15UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_CAST		(0x16UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_CAST3		(0x17UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_CAST128		(0x18UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_RC5			(0x19UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_IDEA		(0x1aUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_SKIPJACK		(0x1bUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_BATON		(0x1cUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_JUNIPER		(0x1dUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_CDMF		(0x1eUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_AES			(0x1fUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_BLOWFISH		(0x20UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_TWOFISH		(0x21UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_GOSTR3410		(0x30UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_GOSTR3411		(0x31UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_GOST28147		(0x32UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_EC_EDWARDS		(0x40UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_EC_MONTGOMERY	(0x41UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_HKDF		(0x42UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_VENDOR_DEFINED	(1UL << 31)

/*
 * A mask for new GOST algorithms.
 * For details visit https://tc26.ru/standarts/perevody/guidelines-the-pkcs-11-extensions-for-implementing-the-gost-r-34-10-2012-and-gost-r-34-11-2012-russian-standards-.html
 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NSSCK_VENDOR_PKCS11_RU_TEAM     (CKK_VENDOR_DEFINED | 0x54321000)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_VENDOR_PKCS11_RU_TEAM_TK26   NSSCK_VENDOR_PKCS11_RU_TEAM

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKK_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003)

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_certificate_type_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKC_X_509		(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKC_X_509_ATTR_CERT	(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKC_WTLS		(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKC_VENDOR_DEFINED	(1UL << 31)


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_attribute_type_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_CLASS			(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_TOKEN			(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਨਿੱਜੀ			(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_LABEL			(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_UNIQUE_ID		(4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_APPLICATION			(0x10UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਮੁੱਲ			(0x11UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OBJECT_ID			(0x12UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_CERTIFICATE_TYPE		(0x80UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ISSUER			(0x81UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SERIAL_ਸੰਖਿਆ		(0x82UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_AC_ISSUER			(0x83UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OWNER			(0x84UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ATTR_TYPES			(0x85UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_TRUSTED			(0x86UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_CERTIFICATE_CATEGORY	(0x87UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_JAVA_MIDP_SECURITY_DOMAIN	(0x88UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_URL				(0x89UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_HASH_ਦਾ_SUBJECT_ਜਨਤਕ_ਕੁੰਜੀ	(0x8aUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_HASH_ਦਾ_ISSUER_ਜਨਤਕ_ਕੁੰਜੀ	(0x8bUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_CHECK_ਮੁੱਲ			(0x90UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਕੁੰਜੀ_TYPE			(0x100UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SUBJECT			(0x101UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ID				(0x102UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SENSITIVE			(0x103UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ENCRYPT			(0x104UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_DECRYPT			(0x105UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_WRAP			(0x106UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_UNWRAP			(0x107UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SIGN			(0x108UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SIGN_RECOVER		(0x109UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_VERIFY			(0x10aUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_VERIFY_RECOVER		(0x10bUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_DERIVE			(0x10cUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਸ਼ੁਰੂ_DATE			(0x110UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਸਿਰਾ_DATE			(0x111UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_MODULUS			(0x120UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_MODULUS_ਬਿੱਟ		(0x121UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਜਨਤਕ_EXPONENT		(0x122UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਨਿੱਜੀ_EXPONENT		(0x123UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਅਭਾਜ_1			(0x124UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਅਭਾਜ_2			(0x125UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_EXPONENT_1			(0x126UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_EXPONENT_2			(0x127UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_COEFFICIENT			(0x128UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਜਨਤਕ_ਕੁੰਜੀ_INFO		(0x129UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਅਭਾਜ			(0x130UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SUBPRIME			(0x131UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਅਧਾਰ			(0x132UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਅਭਾਜ_ਬਿੱਟ			(0x133UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SUB_ਅਭਾਜ_ਬਿੱਟ		(0x134UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਮੁੱਲ_ਬਿੱਟ			(0x160UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਮੁੱਲ_LEN			(0x161UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_EXTRACTABLE			(0x162UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_LOCAL			(0x163UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_NEVER_EXTRACTABLE		(0x164UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ALWAYS_SENSITIVE		(0x165UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਕੁੰਜੀ_GEN_MECHANISM		(0x166UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_MODIFIABLE			(0x170UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_COPYABLE			(0x171UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_DESTROYABLE			(0x172UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ECDSA_PARAMS		(0x180UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_EC_PARAMS			(0x180UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_EC_ਬਿੰਦੂ			(0x181UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SECONDARY_AUTH		(0x200UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_AUTH_PIN_FLAGS		(0x201UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ALWAYS_AUTHENTICATE		(0x202UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_WRAP_WITH_TRUSTED		(0x210UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_GOSTR3410_PARAMS		(0x250UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_GOSTR3411_PARAMS		(0x251UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_GOST28147_PARAMS		(0x252UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_HW_FEATURE_TYPE		(0x300UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_RESET_ON_INIT		(0x301UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_HAS_RESET			(0x302UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_PIXEL_X			(0x400UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_PIXEL_Y			(0x401UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_RESOLUTION			(0x402UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_CHAR_ਪੰਕਤੀਆਂ			(0x403UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_CHAR_COLUMNS		(0x404UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_COLOR			(0x405UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ਬਿੱਟ_ਪ੍ਰਤੀ_PIXEL		(0x406UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_CHAR_SETS			(0x480UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ENCODING_METHODS		(0x481UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_MIME_TYPES			(0x482UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_MECHANISM_TYPE		(0x500UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_REQUIRED_CMS_ਗੁਣ	(0x501UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_DEFAULT_CMS_ਗੁਣ	(0x502UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_SUPPORTED_CMS_ਗੁਣ	(0x503UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_WRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x211UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_UNWRAP_TEMPLATE		(CKF_ARRAY_ATTRIBUTE | 0x212UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_FORMAT			(0x220UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_ਲੰਮਾਈ			(0x221UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_ਸਮਾਂ_INTERVAL		(0x222UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_USER_FRIENDLY_ਬਹੁਲਕ	(0x223UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_CHALLENGE_REQUIREMENT	(0x224UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_ਸਮਾਂ_REQUIREMENT	(0x225UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_COUNTER_REQUIREMENT	(0x226UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_PIN_REQUIREMENT		(0x227UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_USER_IDENTIFIER		(0x22AUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_SERVICE_IDENTIFIER	(0x22BUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_SERVICE_LOGO		(0x22CUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_SERVICE_LOGO_TYPE	(0x22DUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_COUNTER			(0x22EUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_OTP_ਸਮਾਂ			(0x22FUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_ALLOWED_MECHANISMS		(CKF_ARRAY_ATTRIBUTE | 0x600UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_PROFILE_ID			(0x601UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKA_VENDOR_DEFINED		(1UL << 31)


ਬਣਤਰ ck_attribute
{
  ck_attribute_type_t type;
  ਖਾਲੀ *ਮੁੱਲ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਮੁੱਲ_len;
};


ਬਣਤਰ ck_date
{
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ year[4];
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ month[2];
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ day[2];
};


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_mechanism_type_t;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_PKCS_ਕੁੰਜੀ_PAIR_GEN	(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_PKCS			(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_9796			(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_X_509			(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD2_RSA_PKCS		(4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD5_RSA_PKCS		(5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA1_RSA_PKCS		(6UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD128_RSA_PKCS		(7UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD160_RSA_PKCS		(8UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_PKCS_OAEP		(9UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_X9_31_ਕੁੰਜੀ_PAIR_GEN	(0xaUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_X9_31			(0xbUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA1_RSA_X9_31		(0xcUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RSA_PKCS_PSS		(0xdUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA1_RSA_PKCS_PSS		(0xeUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DSA_ਕੁੰਜੀ_PAIR_GEN		(0x10UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CKM_DSA				(0x11UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DSA_SHA1			(0x12UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DSA_SHA224			(0x13UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DSA_SHA256			(0x14UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DSA_SHA384			(0x15UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DSA_SHA512			(0x16UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DH_PKCS_ਕੁੰਜੀ_PAIR_GEN	(0x20UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DH_PKCS_DERIVE		(0x21UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CKM_X9_42_DH_ਕੁੰਜੀ_PAIR_GEN	(0x30UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_X9_42_DH_DERIVE		(0x31UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_X9_42_DH_HYBRID_DERIVE	(0x32UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_X9_42_MQV_DERIVE		(0x33UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA256_RSA_PKCS		(0x40UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA384_RSA_PKCS		(0x41UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA512_RSA_PKCS		(0x42UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA256_RSA_PKCS_PSS		(0x43UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA384_RSA_PKCS_PSS		(0x44UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA512_RSA_PKCS_PSS		(0x45UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA224_RSA_PKCS		(0x46UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA224_RSA_PKCS_PSS		(0x47UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_256_RSA_PKCS		(0x60UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_384_RSA_PKCS		(0x61UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_512_RSA_PKCS		(0x62UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_256_RSA_PKCS_PSS	(0x63UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_384_RSA_PKCS_PSS	(0x64UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_512_RSA_PKCS_PSS	(0x65UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_224_RSA_PKCS		(0x66UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_224_RSA_PKCS_PSS	(0x67UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC2_ਕੁੰਜੀ_GEN			(0x100UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC2_ECB			(0x101UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CKM_RC2_CBC			(0x102UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CKM_RC2_MAC			(0x103UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC2_MAC_GENERAL		(0x104UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC2_CBC_PAD			(0x105UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC4_ਕੁੰਜੀ_GEN			(0x110UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC4				(0x111UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_ਕੁੰਜੀ_GEN			(0x120UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_ECB			(0x121UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_CBC			(0x122UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_MAC			(0x123UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_MAC_GENERAL		(0x124UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_CBC_PAD			(0x125UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES2_ਕੁੰਜੀ_GEN		(0x130UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_ਕੁੰਜੀ_GEN		(0x131UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_ECB			(0x132UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_CBC			(0x133UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_MAC			(0x134UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_MAC_GENERAL		(0x135UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_CBC_PAD		(0x136UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_CMAC_GENERAL		(0x137UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_CMAC			(0x138UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CDMF_ਕੁੰਜੀ_GEN		(0x140UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CDMF_ECB			(0x141UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CDMF_CBC			(0x142UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CDMF_MAC			(0x143UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CDMF_MAC_GENERAL		(0x144UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CDMF_CBC_PAD		(0x145UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD2				(0x200UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD2_HMAC			(0x201UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD2_HMAC_GENERAL		(0x202UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD5				(0x210UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD5_HMAC			(0x211UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD5_HMAC_GENERAL		(0x212UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA_1			(0x220UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA_1_HMAC			(0x221UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA_1_HMAC_GENERAL		(0x222UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD128			(0x230UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD128_HMAC		(0x231UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD128_HMAC_GENERAL	(0x232UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD160			(0x240UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD160_HMAC		(0x241UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RIPEMD160_HMAC_GENERAL	(0x242UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA256			(0x250UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA256_HMAC			(0x251UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA256_HMAC_GENERAL		(0x252UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA224			(0x255UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA224_HMAC			(0x256UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA224_HMAC_GENERAL		(0x257UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA384			(0x260UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA384_HMAC			(0x261UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA384_HMAC_GENERAL		(0x262UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA512			(0x270UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA512_HMAC			(0x271UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA512_HMAC_GENERAL		(0x272UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_256			(0x2B0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_256_HMAC		(0x2B1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_256_HMAC_GENERAL	(0x2B2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_256_ਕੁੰਜੀ_GEN		(0x2B3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_224			(0x2B5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_224_HMAC		(0x2B6UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_224_HMAC_GENERAL	(0x2B7UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_224_ਕੁੰਜੀ_GEN		(0x2B8UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_384			(0x2C0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_384_HMAC		(0x2C1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_384_HMAC_GENERAL	(0x2C2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_384_ਕੁੰਜੀ_GEN		(0x2C3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_512			(0x2D0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_512_HMAC		(0x2D1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_512_HMAC_GENERAL	(0x2D2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA3_512_ਕੁੰਜੀ_GEN		(0x2D3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST_ਕੁੰਜੀ_GEN		(0x300UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST_ECB			(0x301UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST_CBC			(0x302UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST_MAC			(0x303UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST_MAC_GENERAL		(0x304UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST_CBC_PAD		(0x305UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST3_ਕੁੰਜੀ_GEN		(0x310UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST3_ECB			(0x311UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST3_CBC			(0x312UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST3_MAC			(0x313UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST3_MAC_GENERAL		(0x314UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST3_CBC_PAD		(0x315UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST5_ਕੁੰਜੀ_GEN		(0x320UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST128_ਕੁੰਜੀ_GEN		(0x320UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST5_ECB			(0x321UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST128_ECB			(0x321UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST5_CBC			(0x322UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST128_CBC			(0x322UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST5_MAC			(0x323UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CKM_CAST128_MAC			(0x323UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST5_MAC_GENERAL		(0x324UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST128_MAC_GENERAL		(0x324UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST5_CBC_PAD		(0x325UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CAST128_CBC_PAD		(0x325UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC5_ਕੁੰਜੀ_GEN			(0x330UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC5_ECB			(0x331UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC5_CBC			(0x332UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC5_MAC			(0x333UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC5_MAC_GENERAL		(0x334UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_RC5_CBC_PAD			(0x335UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_IDEA_ਕੁੰਜੀ_GEN		(0x340UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_IDEA_ECB			(0x341UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CKM_IDEA_CBC			(0x342UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_IDEA_MAC			(0x343UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_IDEA_MAC_GENERAL		(0x344UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_IDEA_CBC_PAD		(0x345UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GENERIC_SECRET_ਕੁੰਜੀ_GEN	(0x350UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CONCATENATE_ਅਧਾਰ_AND_ਕੁੰਜੀ	(0x360UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CONCATENATE_ਅਧਾਰ_AND_ਅੰਕੜੇ	(0x362UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_CONCATENATE_ਅੰਕੜੇ_AND_ਅਧਾਰ	(0x363UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_XOR_ਅਧਾਰ_AND_ਅੰਕੜੇ		(0x364UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ਕੱਢੋ_ਕੁੰਜੀ_FROM_ਕੁੰਜੀ	(0x365UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SSL3_PRE_MASTER_ਕੁੰਜੀ_GEN	(0x370UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SSL3_MASTER_ਕੁੰਜੀ_DERIVE	(0x371UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SSL3_ਕੁੰਜੀ_AND_MAC_DERIVE	(0x372UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SSL3_MASTER_ਕੁੰਜੀ_DERIVE_DH	(0x373UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_TLS_PRE_MASTER_ਕੁੰਜੀ_GEN	(0x374UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_TLS_MASTER_ਕੁੰਜੀ_DERIVE	(0x375UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_TLS_ਕੁੰਜੀ_AND_MAC_DERIVE	(0x376UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_TLS_MASTER_ਕੁੰਜੀ_DERIVE_DH	(0x377UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SSL3_MD5_MAC		(0x380UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SSL3_SHA1_MAC		(0x381UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD5_ਕੁੰਜੀ_DERIVATION		(0x390UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_MD2_ਕੁੰਜੀ_DERIVATION		(0x391UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SHA1_ਕੁੰਜੀ_DERIVATION		(0x392UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_MD2_DES_CBC		(0x3a0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_MD5_DES_CBC		(0x3a1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_MD5_CAST_CBC		(0x3a2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_MD5_CAST3_CBC		(0x3a3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_MD5_CAST5_CBC		(0x3a4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_MD5_CAST128_CBC		(0x3a4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_CAST5_CBC		(0x3a5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_CAST128_CBC	(0x3a5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_RC4_128		(0x3a6UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_RC4_40		(0x3a7UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_DES3_EDE_CBC	(0x3a8UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_DES2_EDE_CBC	(0x3a9UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_RC2_128_CBC	(0x3aaUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBE_SHA1_RC2_40_CBC		(0x3abUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PKCS5_PBKD2			(0x3b0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_PBA_SHA1_WITH_SHA1_HMAC	(0x3c0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ਕੁੰਜੀ_WRAP_LYNKS		(0x400UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ਕੁੰਜੀ_WRAP_ਸੈੱਟ_OAEP		(0x401UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_ਕੁੰਜੀ_GEN		(0x1000UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_ECB64		(0x1001UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_CBC64		(0x1002UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_OFB64		(0x1003UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_CFB64		(0x1004UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_CFB32		(0x1005UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_CFB16		(0x1006UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_CFB8		(0x1007UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_WRAP		(0x1008UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_ਨਿੱਜੀ_WRAP	(0x1009UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_SKIPJACK_RELAYX		(0x100aUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_KEA_ਕੁੰਜੀ_PAIR_GEN		(0x1010UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_KEA_ਕੁੰਜੀ_DERIVE		(0x1011UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_FORTEZZA_TIMESTAMP		(0x1020UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BATON_ਕੁੰਜੀ_GEN		(0x1030UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BATON_ECB128		(0x1031UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BATON_ECB96			(0x1032UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BATON_CBC128		(0x1033UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BATON_COUNTER		(0x1034UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BATON_SHUFFLE		(0x1035UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BATON_WRAP			(0x1036UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_ਕੁੰਜੀ_PAIR_GEN		(0x1040UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_EC_ਕੁੰਜੀ_PAIR_GEN		(0x1040UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA			(0x1041UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA1			(0x1042UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA224		(0x1043UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA256		(0x1044UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA384		(0x1045UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA512		(0x1046UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA3_224		(0x1047UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA3_256		(0x1048UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA3_384		(0x1049UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDSA_SHA3_512		(0x104AUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDH1_DERIVE		(0x1050UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECDH1_COFACTOR_DERIVE	(0x1051UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_ECMQV_DERIVE		(0x1052UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_EC_EDWARDS_ਕੁੰਜੀ_PAIR_GEN     (0x1055UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_EC_MONTGOMERY_ਕੁੰਜੀ_PAIR_GEN  (0x1056UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_EDDSA			(0x1057UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_JUNIPER_ਕੁੰਜੀ_GEN		(0x1060UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_JUNIPER_ECB128		(0x1061UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_JUNIPER_CBC128		(0x1062UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_JUNIPER_COUNTER		(0x1063UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_JUNIPER_SHUFFLE		(0x1064UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_JUNIPER_WRAP		(0x1065UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_FASTHASH			(0x1070UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_ਕੁੰਜੀ_GEN			(0x1080UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_ECB			(0x1081UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CBC			(0x1082UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_MAC			(0x1083UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_MAC_GENERAL		(0x1084UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CBC_PAD			(0x1085UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CTR				(0x1086UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_GCM				(0x1087UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CCM				(0x1088UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CTS				(0x1089UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CMAC			(0x108AUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CMAC_GENERAL		(0x108BUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_XCBC_MAC		(0x108CUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_XCBC_MAC_96		(0x108DUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_GMAC			(0x108EUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BLOWFISH_ਕੁੰਜੀ_GEN    (0x1090UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_BLOWFISH_CBC        (0x1091UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_TWOFISH_ਕੁੰਜੀ_GEN     (0x1092UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_TWOFISH_CBC         (0x1093UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_ECB_ENCRYPT_ਅੰਕੜੇ	(0x1100UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES_CBC_ENCRYPT_ਅੰਕੜੇ	(0x1101UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_ECB_ENCRYPT_ਅੰਕੜੇ	(0x1102UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DES3_CBC_ENCRYPT_ਅੰਕੜੇ	(0x1103UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_ECB_ENCRYPT_ਅੰਕੜੇ	(0x1104UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CBC_ENCRYPT_ਅੰਕੜੇ	(0x1105UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_ਕੁੰਜੀ_PAIR_GEN	(0x1200UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410			(0x1201UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_WITH_GOSTR3411	(0x1202UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_ਕੁੰਜੀ_WRAP  (0x1203UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_DERIVE    (0x1204UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_512_ਕੁੰਜੀ_PAIR_GEN	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x005)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x006)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_12_DERIVE	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x007)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_WITH_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x008)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3410_WITH_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x009)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3411			(0x1210UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3411_HMAC      (0x1211UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3411_12_256	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x012)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3411_12_512	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x013)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3411_12_256_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x014)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOSTR3411_12_512_HMAC	(CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x015)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOST28147_ਕੁੰਜੀ_GEN   (0x1220UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOST28147_ECB       (0x1221UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOST28147           (0x1222UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOST28147_MAC       (0x1223UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_GOST28147_ਕੁੰਜੀ_WRAP  (0x1224UL)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DSA_PARAMETER_GEN		(0x2000UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_DH_PKCS_PARAMETER_GEN	(0x2001UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_X9_42_DH_PARAMETER_GEN	(0x2002UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_OFB			(0x2104UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CFB64			(0x2105UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CFB8			(0x2106UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CFB128			(0x2107UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_CFB1			(0x2108UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_ਕੁੰਜੀ_WRAP		(0x2109UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_AES_ਕੁੰਜੀ_WRAP_PAD		(0x210AUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_XEDDSA			(0x4029UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_HKDF_DERIVE			(0x402AUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_HKDF_ਅੰਕੜੇ			(0x402BUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_HKDF_ਕੁੰਜੀ_GEN		(0x402CUL)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKM_VENDOR_DEFINED		(1UL << 31)

ਬਣਤਰ ck_mechanism
{
  ck_mechanism_type_t mechanism;
  ਖਾਲੀ *parameter;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len;
};


ਬਣਤਰ ck_mechanism_info
{
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ min_ਕੁੰਜੀ_ਮਾਪ;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ max_ਕੁੰਜੀ_ਮਾਪ;
  ck_flags_t flags;
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_HW			(1UL << 0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ਸੁਨੇਹਾ_ENCRYPT	(1UL << 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ਸੁਨੇਹਾ_DECRYPT	(1UL << 2)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ਸੁਨੇਹਾ_SIGN	(1UL << 3)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ਸੁਨੇਹਾ_VERIFY	(1UL << 4)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_MULTI_ਸੁਨੇਹਾ	(1UL << 5)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ਲੱਭੋ_OBJECTS	(1UL << 6)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ENCRYPT		(1UL << 8)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_DECRYPT		(1UL << 9)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_DIGEST		(1UL << 10)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SIGN		(1UL << 11)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_SIGN_RECOVER	(1UL << 12)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_VERIFY		(1UL << 13)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_VERIFY_RECOVER	(1UL << 14)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_GENERATE		(1UL << 15)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_GENERATE_ਕੁੰਜੀ_PAIR	(1UL << 16)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_WRAP		(1UL << 17)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_UNWRAP		(1UL << 18)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_DERIVE		(1UL << 19)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EXTENSION		(1UL << 31)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_F_P			(1UL << 20)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_F_2M			(1UL << 21)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_ECPARAMETERS	(1UL << 22)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_OID		(1UL << 23)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_NAMEDCURVE	CKF_EC_OID
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_UNCOMPRESS	(1UL << 24)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_COMPRESS		(1UL << 25)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_EC_CURVENAME	(1UL << 26)

/* Flags for C_WaitForSlotEvent.  */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_DONT_ਖੰਡ				(1UL)

/* Flags for Key derivation */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKD_NULL			(0x1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKD_SHA1_KDF			(0x2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKD_SHA224_KDF			(0x5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKD_SHA256_KDF			(0x6UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKD_SHA384_KDF			(0x7UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKD_SHA512_KDF			(0x8UL)

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_ECDH1_DERIVE_PARAMS {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ  kdf;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ  ul_Shared_ਅੰਕੜੇ_Len;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *  p_Shared_ਅੰਕੜੇ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ  ul_ਜਨਤਕ_ਅੰਕੜੇ_Len;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *  p_ਜਨਤਕ_ਅੰਕੜੇ;
} CK_ECDH1_DERIVE_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_ECMQV_DERIVE_PARAMS {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ kdf;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_Shared_ਅੰਕੜੇ_Len;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ * p_Shared_ਅੰਕੜੇ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_ਜਨਤਕ_ਅੰਕੜੇ_Len;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ * p_ਜਨਤਕ_ਅੰਕੜੇ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_ਨਿੱਜੀ_ਅੰਕੜੇ_Len;
	CK_OBJECT_HANDLE h_ਨਿੱਜੀ_ਅੰਕੜੇ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_ਜਨਤਕ_ਅੰਕੜੇ_Len2;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ * p_ਜਨਤਕ_Data2;
	CK_OBJECT_HANDLE ਜਨਤਕ_ਕੁੰਜੀ_2;
} CK_ECMQV_DERIVE_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_rsa_pkcs_mgf_type_t;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ CK_RSA_PKCS_OAEP_ਸਰੋਤ_TYPE;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_ਸਰੋਤ_TYPE ਸਰੋਤ;
	ਖਾਲੀ *p_ਸਰੋਤ_ਅੰਕੜੇ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_ਸਰੋਤ_ਅੰਕੜੇ_Len;
} CK_RSA_PKCS_OAEP_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_RSA_PKCS_PSS_PARAMS {
	ck_mechanism_type_t hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ sLen;
} CK_RSA_PKCS_PSS_PARAMS;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA1			(0x00000001UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA224		(0x00000005UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA256		(0x00000002UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA384		(0x00000003UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA512		(0x00000004UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA3_224	(0x00000006UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA3_256	(0x00000007UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA3_384	(0x00000008UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKG_MGF1_SHA3_512	(0x00000009UL)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKZ_ਅੰਕੜੇ_SPECIFIED	(0x00000001UL)

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_GCM_PARAMS {
	ਖਾਲੀ * pIv;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ulIvLen;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_Iv_ਬਿੱਟ;
	ਖਾਲੀ * pAAD;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ulAADLen;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_ਟੈਗ_ਬਿੱਟ;
} CK_GCM_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_CCM_PARAMS {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_ਅੰਕੜੇ_Len;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pNonce;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ulNonceLen;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pAAD;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ulAADLen;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ulMACLen;
} CK_CCM_PARAMS;

/* EDDSA */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_EDDSA_PARAMS {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ phFlag;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_Context_ਅੰਕੜੇ_Len;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *p_Context_ਅੰਕੜੇ;
} CK_EDDSA_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

/* XEDDSA */
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_XEDDSA_PARAMS {
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ hash;
} CK_XEDDSA_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_XEDDSA_PARAMS *CK_XEDDSA_PARAMS_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_AES_CTR_PARAMS {
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ul_Counter_ਬਿੱਟ;
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ cb[16];
} CK_AES_CTR_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_AES_CTR_PARAMS *CK_AES_CTR_PARAMS_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ CK_MAC_GENERAL_PARAMS;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_MAC_GENERAL_PARAMS *CK_MAC_GENERAL_PARAMS_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ck_rv_t;


ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, ਖਾਲੀ *application);

ਬਣਤਰ ck_interface {
  ਅੱਖਰ * pInterfaceName;
  ਖਾਲੀ * pFunctionList;
  ck_flags_t flags;
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_INTERFACE_FORK_ਸੁਰੱਖਿਅਤ	(0x00000001UL)

/* Forward reference.  */
ਬਣਤਰ ck_function_list;
ਬਣਤਰ ck_function_list_3_0;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _CK_DECLARE_FUNCTION(name, ਦਲੀਲਾਂ)	\
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_rv_t (*CK_ ## name) ਦਲੀਲਾਂ;		\
ck_rv_t CK_SPEC name ਦਲੀਲਾਂ

_CK_DECLARE_FUNCTION (C_Initialize, (ਖਾਲੀ *init_ਦਲੀਲਾਂ));
_CK_DECLARE_FUNCTION (C_Finalize, (ਖਾਲੀ *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (ਬਣਤਰ ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (ਬਣਤਰ ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_Get_ਥਾਂ_List,
		      (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ token_present, ck_ਥਾਂ_id_t *ਥਾਂ_list,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਗਿਣਤੀ_2));
_CK_DECLARE_FUNCTION (C_Get_ਥਾਂ_Info,
		      (ck_ਥਾਂ_id_t ਥਾਂ_id, ਬਣਤਰ ck_ਥਾਂ_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_ਥਾਂ_id_t ਥਾਂ_id, ਬਣਤਰ ck_token_info *info));
_CK_DECLARE_FUNCTION (C_Wait_For_ਥਾਂ_Event,
		      (ck_flags_t flags, ck_ਥਾਂ_id_t *ਥਾਂ, ਖਾਲੀ *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_ਥਾਂ_id_t ਥਾਂ_id,
		       ck_mechanism_type_t *mechanism_list,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਗਿਣਤੀ_2));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_ਥਾਂ_id_t ਥਾਂ_id, ck_mechanism_type_t type,
		       ਬਣਤਰ ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_ਥਾਂ_id_t ਥਾਂ_id, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pin,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ pin_len, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pin,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ pin_len));
_CK_DECLARE_FUNCTION (C_ਸੈੱਟ_PIN,
		      (ck_session_handle_t session, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *old_pin,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ old_len, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *new_pin,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_ਥਾਂ_id_t ਥਾਂ_id, ck_flags_t flags,
		       ਖਾਲੀ *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_ਥਾਂ_id_t ਥਾਂ_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *operation_state,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *operation_state_len));
_CK_DECLARE_FUNCTION (C_ਸੈੱਟ_Operation_State,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *operation_state,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ operation_state_len,
		       ck_object_handle_t encryption_ਕੁੰਜੀ,
		       ck_object_handle_t authentication_ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pin, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_attribute *templ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਗਿਣਤੀ_2, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       ਬਣਤਰ ck_attribute *templ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਗਿਣਤੀ_2,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_Get_Object_ਮਾਪ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਮਾਪ));
_CK_DECLARE_FUNCTION (C_Get_Attribute_ਮੁੱਲ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ਬਣਤਰ ck_attribute *templ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਗਿਣਤੀ_2));
_CK_DECLARE_FUNCTION (C_ਸੈੱਟ_Attribute_ਮੁੱਲ,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       ਬਣਤਰ ck_attribute *templ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਗਿਣਤੀ_2));
_CK_DECLARE_FUNCTION (C_ਲੱਭੋ_Objects_Init,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_attribute *templ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਗਿਣਤੀ_2));
_CK_DECLARE_FUNCTION (C_ਲੱਭੋ_Objects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ max_object_ਗਿਣਤੀ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *object_ਗਿਣਤੀ));
_CK_DECLARE_FUNCTION (C_ਲੱਭੋ_Objects_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *encrypted_ਅੰਕੜੇ_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਆਖਰੀ_encrypted_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਆਖਰੀ_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ encrypted_ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਅੰਕੜੇ_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ encrypted_part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਆਖਰੀ_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਆਖਰੀ_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *digest,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ part_len));
_CK_DECLARE_FUNCTION (C_Digest_ਕੁੰਜੀ,
		      (ck_session_handle_t session, ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *digest,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ signature_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਅੰਕੜੇ_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ encrypted_part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *encrypted_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ encrypted_part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *part_len));

_CK_DECLARE_FUNCTION (C_Generate_ਕੁੰਜੀ,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ਬਣਤਰ ck_attribute *templ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਗਿਣਤੀ_2,
		       ck_object_handle_t *ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Generate_ਕੁੰਜੀ_Pair,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ਬਣਤਰ ck_attribute *ਜਨਤਕ_ਕੁੰਜੀ_template,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਜਨਤਕ_ਕੁੰਜੀ_attribute_ਗਿਣਤੀ,
		       ਬਣਤਰ ck_attribute *ਨਿੱਜੀ_ਕੁੰਜੀ_template,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਨਿੱਜੀ_ਕੁੰਜੀ_attribute_ਗਿਣਤੀ,
		       ck_object_handle_t *ਜਨਤਕ_ਕੁੰਜੀ,
		       ck_object_handle_t *ਨਿੱਜੀ_ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Wrap_ਕੁੰਜੀ,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_ਕੁੰਜੀ,
		       ck_object_handle_t ਕੁੰਜੀ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *wrapped_ਕੁੰਜੀ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *wrapped_ਕੁੰਜੀ_len));
_CK_DECLARE_FUNCTION (C_Unwrap_ਕੁੰਜੀ,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_ਕੁੰਜੀ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *wrapped_ਕੁੰਜੀ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ wrapped_ਕੁੰਜੀ_len,
		       ਬਣਤਰ ck_attribute *templ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ attribute_ਗਿਣਤੀ,
		       ck_object_handle_t *ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Derive_ਕੁੰਜੀ,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਅਧਾਰ_ਕੁੰਜੀ,
		       ਬਣਤਰ ck_attribute *templ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ attribute_ਗਿਣਤੀ,
		       ck_object_handle_t *ਕੁੰਜੀ));

_CK_DECLARE_FUNCTION (C_ਬੀਜ_Random,
		      (ck_session_handle_t session, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬੀਜ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਬੀਜ_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *random_data,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ random_len));

_CK_DECLARE_FUNCTION (C_Get_Function_ਸਥਿਤੀ, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_GetInterfaceList,
		      (ਬਣਤਰ ck_interface *interfaces_list,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ਗਿਣਤੀ_2));
_CK_DECLARE_FUNCTION (C_GetInterface,
		      (ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *interface_name,
		       ਬਣਤਰ ck_ਸੰਸਕਰਣ *ਸੰਸਕਰਣ,
		       ਬਣਤਰ ck_interface **interface_ptr,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_LoginUser,
		      (ck_session_handle_t session,
		       ck_user_type_t user_type,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pin,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ pin_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *username,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ username_len));

_CK_DECLARE_FUNCTION (C_SessionCancel,
		      (ck_session_handle_t session,
		       ck_flags_t flags));

_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Encrypt_Init,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Encrypt_ਸੁਨੇਹਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *associated_ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ associated_ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *plaintext,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ plaintext_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ciphertext,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ciphertext_len));
_CK_DECLARE_FUNCTION (C_Encrypt_ਸੁਨੇਹਾ_Begin,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *associated_ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ associated_ਅੰਕੜੇ_len));
_CK_DECLARE_FUNCTION (C_Encrypt_ਸੁਨੇਹਾ_ਅਗਲਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *plaintext_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ plaintext_part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ciphertext_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *ciphertext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Encrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Decrypt_Init,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Decrypt_ਸੁਨੇਹਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *associated_ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ associated_ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ciphertext,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ciphertext_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *plaintext,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *plaintext_len));
_CK_DECLARE_FUNCTION (C_Decrypt_ਸੁਨੇਹਾ_Begin,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *associated_ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ associated_ਅੰਕੜੇ_len));
_CK_DECLARE_FUNCTION (C_Decrypt_ਸੁਨੇਹਾ_ਅਗਲਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ciphertext_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ciphertext_part_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *plaintext_part,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *plaintext_part_len,
		       ck_flags_t flags));
_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Decrypt_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Sign_Init,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Sign_ਸੁਨੇਹਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *signature_len));
_CK_DECLARE_FUNCTION (C_Sign_ਸੁਨੇਹਾ_Begin,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len));
_CK_DECLARE_FUNCTION (C_Sign_ਸੁਨੇਹਾ_ਅਗਲਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ *signature_len));
_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Sign_Final,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Verify_Init,
		      (ck_session_handle_t session,
		       ਬਣਤਰ ck_mechanism *mechanism,
		       ck_object_handle_t ਕੁੰਜੀ));
_CK_DECLARE_FUNCTION (C_Verify_ਸੁਨੇਹਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ signature_len));
_CK_DECLARE_FUNCTION (C_Verify_ਸੁਨੇਹਾ_Begin,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len));
_CK_DECLARE_FUNCTION (C_Verify_ਸੁਨੇਹਾ_ਅਗਲਾ,
		      (ck_session_handle_t session,
		       ਖਾਲੀ *parameter,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ parameter_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਅੰਕੜੇ,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਅੰਕੜੇ_len,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *signature,
		       ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ signature_len));
_CK_DECLARE_FUNCTION (C_ਸੁਨੇਹਾ_Verify_Final,
		      (ck_session_handle_t session));

/* Flags in Message-based encryption/decryption API */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_ਸਿਰਾ_ਦਾ_ਸੁਨੇਹਾ	(0x00000001UL)

ਬਣਤਰ ck_function_list
{
  ਬਣਤਰ ck_ਸੰਸਕਰਣ ਸੰਸਕਰਣ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_ਥਾਂ_List C_Get_ਥਾਂ_List;
  CK_C_Get_ਥਾਂ_Info C_Get_ਥਾਂ_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_ਸੈੱਟ_PIN C_ਸੈੱਟ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_ਸੈੱਟ_Operation_State C_ਸੈੱਟ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_ਮਾਪ C_Get_Object_ਮਾਪ;
  CK_C_Get_Attribute_ਮੁੱਲ C_Get_Attribute_ਮੁੱਲ;
  CK_C_ਸੈੱਟ_Attribute_ਮੁੱਲ C_ਸੈੱਟ_Attribute_ਮੁੱਲ;
  CK_C_ਲੱਭੋ_Objects_Init C_ਲੱਭੋ_Objects_Init;
  CK_C_ਲੱਭੋ_Objects C_ਲੱਭੋ_Objects;
  CK_C_ਲੱਭੋ_Objects_Final C_ਲੱਭੋ_Objects_Final;
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
  CK_C_Digest_ਕੁੰਜੀ C_Digest_ਕੁੰਜੀ;
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
  CK_C_Generate_ਕੁੰਜੀ C_Generate_ਕੁੰਜੀ;
  CK_C_Generate_ਕੁੰਜੀ_Pair C_Generate_ਕੁੰਜੀ_Pair;
  CK_C_Wrap_ਕੁੰਜੀ C_Wrap_ਕੁੰਜੀ;
  CK_C_Unwrap_ਕੁੰਜੀ C_Unwrap_ਕੁੰਜੀ;
  CK_C_Derive_ਕੁੰਜੀ C_Derive_ਕੁੰਜੀ;
  CK_C_ਬੀਜ_Random C_ਬੀਜ_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_ਸਥਿਤੀ C_Get_Function_ਸਥਿਤੀ;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_ਥਾਂ_Event C_Wait_For_ਥਾਂ_Event;
};

ਬਣਤਰ ck_function_list_3_0
{
  ਬਣਤਰ ck_ਸੰਸਕਰਣ ਸੰਸਕਰਣ;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_Get_ਥਾਂ_List C_Get_ਥਾਂ_List;
  CK_C_Get_ਥਾਂ_Info C_Get_ਥਾਂ_Info;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_ਸੈੱਟ_PIN C_ਸੈੱਟ_PIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_ਸੈੱਟ_Operation_State C_ਸੈੱਟ_Operation_State;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_Get_Object_ਮਾਪ C_Get_Object_ਮਾਪ;
  CK_C_Get_Attribute_ਮੁੱਲ C_Get_Attribute_ਮੁੱਲ;
  CK_C_ਸੈੱਟ_Attribute_ਮੁੱਲ C_ਸੈੱਟ_Attribute_ਮੁੱਲ;
  CK_C_ਲੱਭੋ_Objects_Init C_ਲੱਭੋ_Objects_Init;
  CK_C_ਲੱਭੋ_Objects C_ਲੱਭੋ_Objects;
  CK_C_ਲੱਭੋ_Objects_Final C_ਲੱਭੋ_Objects_Final;
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
  CK_C_Digest_ਕੁੰਜੀ C_Digest_ਕੁੰਜੀ;
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
  CK_C_Generate_ਕੁੰਜੀ C_Generate_ਕੁੰਜੀ;
  CK_C_Generate_ਕੁੰਜੀ_Pair C_Generate_ਕੁੰਜੀ_Pair;
  CK_C_Wrap_ਕੁੰਜੀ C_Wrap_ਕੁੰਜੀ;
  CK_C_Unwrap_ਕੁੰਜੀ C_Unwrap_ਕੁੰਜੀ;
  CK_C_Derive_ਕੁੰਜੀ C_Derive_ਕੁੰਜੀ;
  CK_C_ਬੀਜ_Random C_ਬੀਜ_Random;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_Get_Function_ਸਥਿਤੀ C_Get_Function_ਸਥਿਤੀ;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_Wait_For_ਥਾਂ_Event C_Wait_For_ਥਾਂ_Event;
  /* PKCS #11 3.0 functions */
  CK_C_GetInterfaceList C_GetInterfaceList;
  CK_C_GetInterface C_GetInterface;
  CK_C_LoginUser C_LoginUser;
  CK_C_SessionCancel C_SessionCancel;
  CK_C_ਸੁਨੇਹਾ_Encrypt_Init C_ਸੁਨੇਹਾ_Encrypt_Init;
  CK_C_Encrypt_ਸੁਨੇਹਾ C_Encrypt_ਸੁਨੇਹਾ;
  CK_C_Encrypt_ਸੁਨੇਹਾ_Begin C_Encrypt_ਸੁਨੇਹਾ_Begin;
  CK_C_Encrypt_ਸੁਨੇਹਾ_ਅਗਲਾ C_Encrypt_ਸੁਨੇਹਾ_ਅਗਲਾ;
  CK_C_ਸੁਨੇਹਾ_Encrypt_Final C_ਸੁਨੇਹਾ_Encrypt_Final;
  CK_C_ਸੁਨੇਹਾ_Decrypt_Init C_ਸੁਨੇਹਾ_Decrypt_Init;
  CK_C_Decrypt_ਸੁਨੇਹਾ C_Decrypt_ਸੁਨੇਹਾ;
  CK_C_Decrypt_ਸੁਨੇਹਾ_Begin C_Decrypt_ਸੁਨੇਹਾ_Begin;
  CK_C_Decrypt_ਸੁਨੇਹਾ_ਅਗਲਾ C_Decrypt_ਸੁਨੇਹਾ_ਅਗਲਾ;
  CK_C_ਸੁਨੇਹਾ_Decrypt_Final C_ਸੁਨੇਹਾ_Decrypt_Final;
  CK_C_ਸੁਨੇਹਾ_Sign_Init C_ਸੁਨੇਹਾ_Sign_Init;
  CK_C_Sign_ਸੁਨੇਹਾ C_Sign_ਸੁਨੇਹਾ;
  CK_C_Sign_ਸੁਨੇਹਾ_Begin C_Sign_ਸੁਨੇਹਾ_Begin;
  CK_C_Sign_ਸੁਨੇਹਾ_ਅਗਲਾ C_Sign_ਸੁਨੇਹਾ_ਅਗਲਾ;
  CK_C_ਸੁਨੇਹਾ_Sign_Final C_ਸੁਨੇਹਾ_Sign_Final;
  CK_C_ਸੁਨੇਹਾ_Verify_Init C_ਸੁਨੇਹਾ_Verify_Init;
  CK_C_Verify_ਸੁਨੇਹਾ C_Verify_ਸੁਨੇਹਾ;
  CK_C_Verify_ਸੁਨੇਹਾ_Begin C_Verify_ਸੁਨੇਹਾ_Begin;
  CK_C_Verify_ਸੁਨੇਹਾ_ਅਗਲਾ C_Verify_ਸੁਨੇਹਾ_ਅਗਲਾ;
  CK_C_ਸੁਨੇਹਾ_Verify_Final C_ਸੁਨੇਹਾ_Verify_Final;
};



ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_rv_t (*ck_createmutex_t) (ਖਾਲੀ **mutex);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_rv_t (*ck_destroymutex_t) (ਖਾਲੀ *mutex);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_rv_t (*ck_lockmutex_t) (ਖਾਲੀ *mutex);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_rv_t (*ck_unlockmutex_t) (ਖਾਲੀ *mutex);


ਬਣਤਰ ck_c_initialize_ਦਲੀਲਾਂ
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t ਤਾਲਾ_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  ਖਾਲੀ *reserved;
};


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_LIBRARY_CANT_CREATE_OS_ਧਾਗੇ	(1UL << 0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_OS_LOCKING_OK			(1UL << 1)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_OK					(0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_CANCEL				(1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_HOST_ਸਮ੍ਰਿਤੀ				(2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਥਾਂ_ID_INVALID			(3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_GENERAL_ERROR			(5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_FUNCTION_FAILED			(6UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ARGUMENTS_BAD			(7UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_NO_EVENT				(8UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_NEED_ਮੰਜ਼ਿਲ_CREATE_ਧਾਗੇ		(9UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_CANT_ਤਾਲਾ				(0xaUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ATTRIBUTE_READ_ONLY			(0x10UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ATTRIBUTE_SENSITIVE			(0x11UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ATTRIBUTE_TYPE_INVALID		(0x12UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ATTRIBUTE_ਮੁੱਲ_INVALID		(0x13UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ACTION_PROHIBITED			(0x1BUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਅੰਕੜੇ_INVALID			(0x20UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਅੰਕੜੇ_LEN_RANGE			(0x21UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_DEVICE_ERROR			(0x30UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_DEVICE_ਸਮ੍ਰਿਤੀ			(0x31UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_DEVICE_REMOVED			(0x32UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ENCRYPTED_ਅੰਕੜੇ_INVALID		(0x40UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ENCRYPTED_ਅੰਕੜੇ_LEN_RANGE		(0x41UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_FUNCTION_CANCELED			(0x50UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_FUNCTION_NOT_PARALLEL		(0x51UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_FUNCTION_NOT_SUPPORTED		(0x54UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_HANDLE_INVALID			(0x60UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_ਮਾਪ_RANGE			(0x62UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_TYPE_INCONSISTENT		(0x63UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_NOT_NEEDED			(0x64UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_ਬਦਲਿਆ				(0x65UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_NEEDED				(0x66UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_INDIGESTIBLE			(0x67UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_FUNCTION_NOT_PERMITTED		(0x68UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_NOT_WRAPPABLE			(0x69UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਕੁੰਜੀ_UNEXTRACTABLE			(0x6aUL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_MECHANISM_INVALID			(0x70UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_MECHANISM_PARAM_INVALID		(0x71UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_OBJECT_HANDLE_INVALID		(0x82UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_OPERATION_ਸਰਗਰਮ			(0x90UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_OPERATION_NOT_INITIALIZED		(0x91UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_PIN_INCORRECT			(0xa0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_PIN_INVALID				(0xa1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_PIN_LEN_RANGE			(0xa2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_PIN_EXPIRED				(0xa3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_PIN_LOCKED				(0xa4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_CLOSED			(0xb0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_ਗਿਣਤੀ			(0xb1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_HANDLE_INVALID		(0xb3UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_PARALLEL_NOT_SUPPORTED	(0xb4UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_READ_ONLY			(0xb5UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_EXISTS			(0xb6UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_READ_ONLY_EXISTS		(0xb7UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SESSION_READ_WRITE_SO_EXISTS	(0xb8UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SIGNATURE_INVALID			(0xc0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SIGNATURE_LEN_RANGE			(0xc1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_TEMPLATE_INCOMPLETE			(0xd0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_TEMPLATE_INCONSISTENT		(0xd1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_TOKEN_NOT_PRESENT			(0xe0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_TOKEN_NOT_RECOGNIZED		(0xe1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_TOKEN_WRITE_PROTECTED		(0xe2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	CKR_UNWRAPPING_ਕੁੰਜੀ_HANDLE_INVALID	(0xf0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_UNWRAPPING_ਕੁੰਜੀ_ਮਾਪ_RANGE		(0xf1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_UNWRAPPING_ਕੁੰਜੀ_TYPE_INCONSISTENT	(0xf2UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_USER_ALREADY_LOGGED_ਵਿੱਚ		(0x100UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_USER_NOT_LOGGED_ਵਿੱਚ			(0x101UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_USER_PIN_NOT_INITIALIZED		(0x102UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_USER_TYPE_INVALID			(0x103UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_USER_ANOTHER_ALREADY_LOGGED_ਵਿੱਚ	(0x104UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_USER_TOO_MANY_TYPES			(0x105UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_WRAPPED_ਕੁੰਜੀ_INVALID			(0x110UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_WRAPPED_ਕੁੰਜੀ_LEN_RANGE		(0x112UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_WRAPPING_ਕੁੰਜੀ_HANDLE_INVALID		(0x113UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_WRAPPING_ਕੁੰਜੀ_ਮਾਪ_RANGE		(0x114UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_WRAPPING_ਕੁੰਜੀ_TYPE_INCONSISTENT	(0x115UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_RANDOM_ਬੀਜ_NOT_SUPPORTED		(0x120UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_RANDOM_NO_RNG			(0x121UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_DOMAIN_PARAMS_INVALID		(0x130UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਵਕਰ_NOT_SUPPORTED			(0x140UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_ਬਫਰ_TOO_SMALL			(0x150UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_SAVED_STATE_INVALID			(0x160UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_INFORMATION_SENSITIVE		(0x170UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_STATE_UNSAVEABLE			(0x180UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_CRYPTOKI_NOT_INITIALIZED		(0x190UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_CRYPTOKI_ALREADY_INITIALIZED	(0x191UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_MUTEX_BAD				(0x1a0UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_MUTEX_NOT_LOCKED			(0x1a1UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_FUNCTION_REJECTED			(0x200UL)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKR_VENDOR_DEFINED			(1UL << 31)


/* Compatibility layer.  */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ CRYPTOKI_COMPAT

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CK_DEFINE_FUNCTION
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_DEFINE_FUNCTION(retval, name) retval CK_SPEC name

/* For NULL.  */
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ CK_BYTE;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ CK_CHAR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ CK_UTF8CHAR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ CK_BBOOL;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਪੂਰਨ CK_ULONG;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਲੰਮਾ ਪੂਰਨ CK_LONG;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_BYTE *CK_BYTE_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_CHAR *CK_CHAR_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_UTF8CHAR *CK_UTF8CHAR_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ CK_ULONG *CK_ULONG_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ *CK_VOID_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ **CK_VOID_PTR_PTR;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_FALSE 0
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CK_TRUE 1
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CK_DISABLE_TRUE_FALSE
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ FALSE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FALSE 0
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ TRUE
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TRUE 1
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ CK_HKDF_PARAMS {
	CK_BBOOL b_ਕੱਢੋ;
	CK_BBOOL bExpand;
	CK_MECHANISM_TYPE prfHashMechanism;
	CK_ULONG ulSaltType;
	CK_BYTE_PTR pSalt;
	CK_ULONG ulSaltLen;
	CK_OBJECT_HANDLE h_Salt_ਕੁੰਜੀ;
	CK_BYTE_PTR pInfo;
	CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_HKDF_SALT_NULL 0x00000001UL
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_HKDF_SALT_ਅੰਕੜੇ 0x00000002UL
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CKF_HKDF_SALT_ਕੁੰਜੀ  0x00000004UL

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_ਸੰਸਕਰਣ CK_ਸੰਸਕਰਣ_2;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_ਸੰਸਕਰਣ *CK_ਸੰਸਕਰਣ_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_info CK_INFO;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_info *CK_INFO_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_ਥਾਂ_id_t *CK_ਥਾਂ_ID_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_ਥਾਂ_info CK_ਥਾਂ_INFO_2;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_ਥਾਂ_info *CK_ਥਾਂ_INFO_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_token_info CK_TOKEN_INFO;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_token_info *CK_TOKEN_INFO_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_session_handle_t *CK_SESSION_HANDLE_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_session_info CK_SESSION_INFO;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_session_info *CK_SESSION_INFO_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_object_handle_t *CK_OBJECT_HANDLE_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_object_class_t *CK_OBJECT_CLASS_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_attribute CK_ATTRIBUTE;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_attribute *CK_ATTRIBUTE_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_date CK_DATE;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_date *CK_DATE_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ck_rsa_pkcs_mgf_type_t *CK_RSA_PKCS_MGF_TYPE_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_mechanism CK_MECHANISM;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_mechanism *CK_MECHANISM_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_mechanism_info CK_MECHANISM_INFO;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_mechanism_info *CK_MECHANISM_INFO_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_interface CK_INTERFACE;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_interface *CK_INTERFACE_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_interface **CK_INTERFACE_PTR_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_function_list CK_FUNCTION_LIST;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_function_list *CK_FUNCTION_LIST_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_function_list **CK_FUNCTION_LIST_PTR_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_function_list_3_0 CK_FUNCTION_LIST_3_0;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_function_list_3_0 *CK_FUNCTION_LIST_3_0_PTR;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_function_list_3_0 **CK_FUNCTION_LIST_3_0_PTR_PTR;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_c_initialize_ਦਲੀਲਾਂ CK_C_INITIALIZE_ਦਲੀਲਾਂ_2;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ ck_c_initialize_ਦਲੀਲਾਂ *CK_C_INITIALIZE_ਦਲੀਲਾਂ_PTR;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NULL_PTR ਨਿਰਾ

/* Delete the helper macros defined at the top of the file.  */
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_flags_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_ਸੰਸਕਰਣ

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_info
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ cryptoki_ਸੰਸਕਰਣ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ manufacturer_id
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ library_description
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ library_ਸੰਸਕਰਣ

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_notification_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_ਥਾਂ_id_t

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_ਥਾਂ_info
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਥਾਂ_description
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ hardware_ਸੰਸਕਰਣ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ firmware_ਸੰਸਕਰਣ

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_token_info
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ serial_ਸੰਖਿਆ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ max_session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ max_rw_session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ rw_session_ਗਿਣਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ max_pin_len
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ min_pin_len
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਕੁੱਲ_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_ਜਨਤਕ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਕੁੱਲ_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ free_ਨਿੱਜੀ_ਸਮ੍ਰਿਤੀ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ utc_ਸਮਾਂ

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_session_handle_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_user_type_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_state_t

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_session_info
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਥਾਂ_id
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ device_error

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_object_handle_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_object_class_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_hw_feature_type_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_ਕੁੰਜੀ_type_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_certificate_type_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_attribute_type_t

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_attribute
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਮੁੱਲ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਮੁੱਲ_len

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_date

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_mechanism_type_t

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_rsa_pkcs_mgf_type_t

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_mechanism
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ parameter
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ parameter_len

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_mechanism_info
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ min_ਕੁੰਜੀ_ਮਾਪ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ max_ਕੁੰਜੀ_ਮਾਪ

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_rv_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_notify_t

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_interface

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_function_list
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_function_list_3_0

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_createmutex_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_destroymutex_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_lockmutex_t
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_unlockmutex_t

#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ck_c_initialize_ਦਲੀਲਾਂ
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ create_mutex
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ destroy_mutex
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ਤਾਲਾ_mutex
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ unlock_mutex
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ reserved

#ਜੇ_ਅੰਤ	/* CRYPTOKI_COMPAT */

/* System dependencies.  */
#ਜੇ defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#ਹਦਾਇਤ pack(ਕੱਢੋ, cryptoki)
#ਜੇ_ਅੰਤ

#ਜੇ defined(__cplusplus)
}
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ	/* PKCS11_H */
