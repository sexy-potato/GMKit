PHP_ARG_ENABLE(gmkit, for gmssl support, AS_HELP_STRING(--enable-gmkit, Enable gmssl support), no)

if test "$PHP_GMKIT" = yes; then
  PHP_CHECK_LIBRARY(gmssl, gmssl_version_str, PHP_ADD_LIBRARY(gmssl, 1, GMKIT_SHARED_LIBADD), AC_MSG_ERROR(libgmssl is required for extension))
   PHP_ADD_EXTENSION_DEP(gmkit, spl)
  PHP_NEW_EXTENSION(gmkit, gmkit.c, $ext_shared)
  PHP_SUBST(GMKIT_SHARED_LIBADD)
fi