#include "php.h"

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#include "zend_exceptions.h"
#include "ext/spl/spl_exceptions.h"
#include "php_gmkit.h"

#include <gmssl/sm2.h>
#include <gmssl/sm4.h>
#include <gmssl/sm3.h>

#if defined(ZTS) && defined(COMPILE_DL_GMKIT)
  /* if the extension was built for a thread-safe build and compiled as shared object */
  ZEND_TSRMLS_CACHE_EXTERN()
#endif

static zend_class_entry* exception;

PHP_MINIT_FUNCTION(gmkit) {

  zend_class_entry ce;

  INIT_CLASS_ENTRY(ce, "GMKitException", NULL);

  exception = zend_register_internal_class_ex(&ce, zend_ce_exception);

  zend_declare_class_constant_long(exception, "CODE_SM2_SIGNATURE_ERROR", 24, GMKIT_SM2_SIGNATURE_ERROR);
  zend_declare_class_constant_long(exception, "CODE_SM2_DECRYPTION_OR_ENCRYPTION_ERROR", 39, GMKIT_SM2_DECRYPTION_OR_ENCRYPTION_ERROR);
  zend_declare_class_constant_long(exception, "CODE_SM2_ERROR", 14, GMKIT_SM2_ERROR);

  return SUCCESS;
}

PHP_RINIT_FUNCTION(gmkit) {

  #if defined(ZTS) && defined(COMPILE_DL_TEST)
    /* if the extension was built for a thread-safe build and compiled as shared object */
    ZEND_TSRMLS_CACHE_UPDATE()
  #endif

  return SUCCESS;
}

PHP_FUNCTION(gmkit_xor) {

  size_t a, b;

  char *X;
  char *Y;

  ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(X, a)
    Z_PARAM_STRING(Y, b)
  ZEND_PARSE_PARAMETERS_END();

  if (a != b) {
    zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid value for bitwize XOR operation", 0);
    RETURN_THROWS();
  }

  for (size_t i = 0; i < a; i++) {
    X[i] ^= Y[i];
  }

  RETVAL_STRING(X);
}

PHP_FUNCTION(gmkit_sm2_verify) {

  char *M, *signer = NULL;
  zend_array *P, *_signature;
  size_t x, y;

  ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 3, 4)
    Z_PARAM_ARRAY_HT(P)
    Z_PARAM_ARRAY_HT(_signature)
    Z_PARAM_STRING(M, x)
    Z_PARAM_OPTIONAL
    Z_PARAM_STRING(signer, y)
  ZEND_PARSE_PARAMETERS_END();

  SM3_CTX sm3;
  SM2_SIGNATURE signature; 
  SM2_KEY dP;

  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_str_find(_signature, "R", 1), signature.r, "Invalid R property of signature");
  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_str_find(_signature, "S", 1), signature.s, "Invalid S property of signature");

  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(P, 0), dP.public_key.x, "Invalid x-coordinate of P.");
  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(P, 1), dP.public_key.y, "Invalid y-coordinate of P.");

  uint8_t z[SM3_DIGEST_SIZE];
  uint8_t e[SM3_DIGEST_SIZE];

  if ((signer ? sm2_compute_z(z, &dP.public_key, signer, y) : sm2_compute_z(z, &dP.public_key, SM2_DEFAULT_ID, 0 /*No Effect*/)) == -1) {
    zend_throw_exception(exception, "Failed to compute Z value by signer", GMKIT_SM2_SIGNATURE_ERROR);
    goto CLEAN;
  }

  sm3_init(&sm3);

  sm3_update(&sm3, z, sizeof(z));
  sm3_update(&sm3, M, x);
  sm3_finish(&sm3, e);

  if (sm2_do_verify(&dP, e, &signature) == -1) {
    RETVAL_BOOL(0);
  } else {
    RETVAL_BOOL(1);
  }

  CLEAN: {
    WRITE_0(sm3)
    WRITE_0(signature)
    WRITE_0(dP)
  }
}

PHP_FUNCTION(gmkit_sm2_sign) {

  char *M, *signer = NULL;
  zend_array *_dP;
  size_t x, y;

  ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 3) 
    Z_PARAM_ARRAY_HT(_dP)
    Z_PARAM_STRING(M, x) 
    Z_PARAM_OPTIONAL 
    Z_PARAM_STRING(signer, y)
  ZEND_PARSE_PARAMETERS_END();

  SM3_CTX sm3;
  SM2_SIGNATURE signature; 
  SM2_KEY dP;

  zval* d = zend_hash_str_find(_dP, "d", 1);
  zval* P = zend_hash_str_find(_dP, "P", 1);

  HANDLE_BIG_NUMBER_PROBABLY(d, dP.private_key, "Invalid d property");

  if (P == NULL || Z_TYPE_P(P) != IS_ARRAY) {
    zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid P property, it must be 2-tuple of bytes (such as: [\"x\",\"y\"]).", 0);
    goto CLEAN;
  }

  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(Z_ARR_P(P), 0), dP.public_key.x, "Invalid x-coordinate of P.");
  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(Z_ARR_P(P), 1), dP.public_key.y, "Invalid y-coordinate of P.");

  uint8_t z[SM3_DIGEST_SIZE];
  uint8_t e[SM3_DIGEST_SIZE];

  if ((signer ? sm2_compute_z(z, &dP.public_key, signer, y) : sm2_compute_z(z, &dP.public_key, SM2_DEFAULT_ID, 0 /*No Effect*/)) == -1) {
    zend_throw_exception(exception, "Failed to compute Z value by signer", GMKIT_SM2_SIGNATURE_ERROR);
    goto CLEAN;
  }

  sm3_init(&sm3);

  sm3_update(&sm3, z, sizeof(z));
  sm3_update(&sm3, M, x);
  sm3_finish(&sm3, e);

  if (sm2_do_sign(&dP, e, &signature) == -1) {
    zend_throw_exception(exception, "Failed to sign message", GMKIT_SM2_SIGNATURE_ERROR);
    goto CLEAN;
  }

  array_init(return_value);

  add_assoc_stringl_ex(return_value, "R", 1, (char *)signature.r, 32);
  add_assoc_stringl_ex(return_value, "S", 1, (char *)signature.s, 32);

  CLEAN: {
    WRITE_0(sm3)
    WRITE_0(signature)
    WRITE_0(dP)
  }
}

PHP_FUNCTION(gmkit_sm2_encrypt) {

  size_t s;
  zend_array *P;
  char *M;

  ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_ARRAY_HT(P)
    Z_PARAM_STRING(M, s)
  ZEND_PARSE_PARAMETERS_END();

  SM2_KEY dP;
  SM2_CIPHERTEXT cipher;
  zval C1;

  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(P, 0), dP.public_key.x, "Invalid x-coordinate of P.");
  HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(P, 1), dP.public_key.y, "Invalid y-coordinate of P.");

  if (sm2_do_encrypt(&dP, (uint8_t *)M, s, &cipher) == -1) {
    zend_throw_exception(exception, "Failed to encrypt", GMKIT_SM2_DECRYPTION_OR_ENCRYPTION_ERROR);
    goto CLEAN;
  }

  array_init(&C1);

  add_next_index_stringl(&C1, cipher.point.x, 32);
  add_next_index_stringl(&C1, cipher.point.y, 32);

  array_init(return_value);

  add_assoc_stringl(return_value, "C2", cipher.ciphertext, cipher.ciphertext_size);
  add_assoc_zval(return_value, "C1", &C1);
  add_assoc_stringl(return_value, "C3", cipher.hash, 32);

  CLEAN: {
    WRITE_0(cipher)
    WRITE_0(dP)
  }
}

PHP_FUNCTION(gmkit_sm2_decrypt) {

  size_t s;
  zend_array *_chiper;
  char* d;

  ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2) 
    Z_PARAM_STRING(d, s)
    Z_PARAM_ARRAY_HT(_chiper)
  ZEND_PARSE_PARAMETERS_END();

  if (s != 32) {
    zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid d value", 0);
    RETURN_THROWS();
  }

  SM2_CIPHERTEXT cipher;
  SM2_KEY dP;

  /* Graceful copy N bytes form given d to private key (d) */
  memcpy(dP.private_key, d, s);

  zval* C1 = zend_hash_str_find(_chiper, "C1", 2);
  zval* C2 = zend_hash_str_find(_chiper, "C2", 2);
  zval* C3 = zend_hash_str_find(_chiper, "C3", 2);

  if (!C2 || Z_TYPE_P(C2) != IS_STRING || ZSTR_LEN(Z_STR_P(C2)) == 0 || ZSTR_LEN(Z_STR_P(C2)) > SM2_MAX_PLAINTEXT_SIZE) {
    zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid C2 value", 0);
    goto CLEAN;
  }

  HANDLE_BIG_NUMBER_PROBABLY(C3, cipher.hash, "Invalid C3 value");

  if (C1 && Z_TYPE_P(C1) == IS_ARRAY) {
    HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(Z_ARR_P(C1), 0), cipher.point.x, "Invalid x-coordinate of C1.");
    HANDLE_BIG_NUMBER_PROBABLY(zend_hash_index_find(Z_ARR_P(C1), 1), cipher.point.y, "Invalid y-coordinate of C1.");
  } else {
    zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid C1 value", 0);
    goto CLEAN;
  }

  memcpy(cipher.ciphertext, ZSTR_VAL(Z_STR_P(C2)), cipher.ciphertext_size = ZSTR_LEN(Z_STR_P(C2)));

  uint8_t M[SM2_MAX_PLAINTEXT_SIZE];

  if (sm2_do_decrypt(&dP, &cipher, M, &s) == -1) {
    zend_throw_exception(exception, "Failed to decrypt given SM2 cipher", GMKIT_SM2_DECRYPTION_OR_ENCRYPTION_ERROR);
    goto CLEAN;
  }

  RETVAL_STRINGL(M, s);

  CLEAN: {
    WRITE_0(dP)
    WRITE_0(cipher)
    WRITE_0(M)
  }
}

PHP_FUNCTION(gmkit_sm2_key) {

  SM2_KEY d;

  if (-1 == sm2_key_generate(&d)) {
    zend_throw_exception(exception, "Failed to generate SM2 private key", GMKIT_SM2_ERROR);
    RETURN_THROWS();
  }

  SM2_POINT P = d.public_key;
  zval _P;

  array_init(return_value);
  array_init(&_P);

  add_next_index_stringl(&_P, (char *)P.x, 32);
  add_next_index_stringl(&_P, (char *)P.y, 32);

  add_assoc_stringl(return_value, "d", d.private_key, 32);
  add_assoc_zval(return_value, "P", &_P);

  WRITE_0(P)
  WRITE_0(d)
}

PHP_FUNCTION(gmkit_sm4) {

  size_t x, y;

  char *K;
  char *M;

  ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)
    Z_PARAM_STRING(K, x)
    Z_PARAM_STRING(M, y)
  ZEND_PARSE_PARAMETERS_END();

  if (x != SM4_KEY_SIZE) {
    zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid SM4 cryptography key (encipher/decipher)", 0);
    RETURN_THROWS();
  }

  if (x != y) {
    zend_throw_exception(spl_ce_InvalidArgumentException, "Invalid SM4 block", 0);
    RETURN_THROWS();
  }

  SM4_KEY key;

  sm4_set_encrypt_key(&key, K);

  ZVAL_STR(return_value, zend_string_alloc(SM4_BLOCK_SIZE, 0));

  sm4_encrypt(&key, M, Z_STRVAL_P(return_value));

  WRITE_0(key)
}

ZEND_BEGIN_ARG_INFO(_gmkit_xor, {})
  ZEND_ARG_INFO(0, X)
  ZEND_ARG_INFO(0, Y)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(_gmkit_sm2_key, {})
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(_gmkit_sm2_verify, {}, ZEND_RETURN_VALUE, 3)
  ZEND_ARG_INFO(0, P)
  ZEND_ARG_INFO(0, signature)
  ZEND_ARG_INFO(0, message)
  ZEND_ARG_INFO(0, signer)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO_EX(_gmkit_sm2_sign, {}, ZEND_RETURN_VALUE, 2)
  ZEND_ARG_INFO(0, dP)
  ZEND_ARG_INFO(0, message)
  ZEND_ARG_INFO(0, signer)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(_gmkit_sm2_encrypt, {})
  ZEND_ARG_INFO(0, P)
  ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(_gmkit_sm2_decrypt, {})
  ZEND_ARG_INFO(0, d)
  ZEND_ARG_INFO(0, cipher)
ZEND_END_ARG_INFO();

ZEND_BEGIN_ARG_INFO(_gmkit_sm4, {})
  ZEND_ARG_INFO(0, key)
  ZEND_ARG_INFO(0, block)
ZEND_END_ARG_INFO();

static const zend_function_entry exports[] = {
  PHP_FE(gmkit_xor, _gmkit_xor)
  PHP_FE(gmkit_sm2_encrypt, _gmkit_sm2_encrypt)
  PHP_FE(gmkit_sm2_decrypt, _gmkit_sm2_decrypt)
  PHP_FE(gmkit_sm2_sign, _gmkit_sm2_sign)
  PHP_FE(gmkit_sm2_verify, _gmkit_sm2_verify)
  PHP_FE(gmkit_sm2_key, _gmkit_sm2_key)
  PHP_FE(gmkit_sm4, _gmkit_sm4)
  PHP_FE_END
};

zend_module_entry gmkit_module_entry = { STANDARD_MODULE_HEADER, "gmkit", exports, PHP_MINIT(gmkit), NULL, PHP_RINIT(gmkit), NULL, NULL, PHP_GMKIT_VERSION, STANDARD_MODULE_PROPERTIES };

#define phpext_gmkit_ptr &gmkit_module_entry

#ifdef COMPILE_DL_GMKIT
  #ifdef ZTS
    /* if the extension was built for a thread-safe build and compiled as shared object */
    ZEND_TSRMLS_CACHE_DEFINE()
  #endif
  ZEND_GET_MODULE(gmkit)
#endif
