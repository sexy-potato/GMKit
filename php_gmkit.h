#ifndef PHP_GMKIT_H

  #define GMKIT_SM2_SIGNATURE_ERROR 1002
  #define GMKIT_SM2_DECRYPTION_OR_ENCRYPTION_ERROR 1001
  #define GMKIT_SM2_ERROR 1000

  /*
   * Error code:
   * 1001 Invalid big number for SM2 cryptography
   * 1002 Invalid point for argument ?, it MUST be 2-tuple of string (such as: ["x","y"])
   * 1003 Inner cryptography exception
   * 1000 General SM2 exception
   */
  #define HANDLE_BIG_NUMBER_PROBABLY(zval, raw, message) \
    if (zval != NULL && Z_TYPE_P(zval) == IS_STRING) { HANDLE_BIG_NUMBER(Z_STR_P(zval), raw, message); } else { \
      zend_throw_exception(spl_ce_InvalidArgumentException, message, 0); \
      RETURN_THROWS(); \
    }

  #define HANDLE_BIG_NUMBER(zstr, raw, message) \
    if (ZSTR_LEN(zstr) == 32) { \
      memcpy(raw, ZSTR_VAL(zstr), 32); \
    } else { \
      zend_throw_exception(spl_ce_InvalidArgumentException, message, 0); \
      RETURN_THROWS(); \
    }

  #define WRITE_0(v) memset(&v, 0, sizeof(v));

  #define PHP_GMKIT_VERSION "0.1.0"
  #define PHP_GMKIT_H

#endif