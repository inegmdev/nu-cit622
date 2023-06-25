/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

#ifndef SUDO_CONFIG_H
#define SUDO_CONFIG_H

/* Define to 1 if you want the insults from the "classic" version sudo. */
/* #undef CLASSIC_INSULTS */

/* Define to 1 if you want insults culled from the twisted minds of CSOps. */
/* #undef CSOPS_INSULTS */

/* Define to 1 if you want sudo to display "command not allowed" instead of
   "command not found" when a command cannot be found. */
/* #undef DONT_LEAK_PATH_INFO */

/* A colon-separated list of pathnames to be used as the editor for visudo. */
#define EDITOR _PATH_VI

/* Define to 1 to enable sudo's plugin interface. */
#define ENABLE_SUDO_PLUGIN_API 1

/* Define to 1 to enable environment function debugging. */
/* #undef ENV_DEBUG */

/* Define to 1 if you want visudo to honor the EDITOR and VISUAL env
   variables. */
#define ENV_EDITOR 1

/* Define to 1 to enable environment resetting by default. */
#define ENV_RESET 1

/* If defined, users in this group need not enter a passwd (ie "sudo"). */
/* #undef EXEMPTGROUP */

/* Define to 1 if you want to require fully qualified hosts in sudoers. */
/* #undef FQDN */

/* Define to the type of elements in the array set by 'getgroups'. Usually
   this is either 'int' or 'gid_t'. */
#define GETGROUPS_T gid_t

/* Define to 1 if you want insults from the "Goon Show". */
/* #undef GOONS_INSULTS */

/* Define to 1 if you want 2001-like insults. */
/* #undef HAL_INSULTS */

/* Define to 1 if you use AFS. */
/* #undef HAVE_AFS */

/* Define to 1 if you use AIX general authentication. */
/* #undef HAVE_AIXAUTH */

/* Define to 1 to enable AppArmor support. */
/* #undef HAVE_APPARMOR */

/* Define to 1 if you have the 'arc4random' function. */
/* #undef HAVE_ARC4RANDOM */

/* Define to 1 if you have the 'arc4random_buf' function. */
/* #undef HAVE_ARC4RANDOM_BUF */

/* Define to 1 if you have the 'arc4random_uniform' function. */
/* #undef HAVE_ARC4RANDOM_UNIFORM */

/* Define to 1 if you have the 'ASN1_STRING_get0_data' function. */
/* #undef HAVE_ASN1_STRING_GET0_DATA */

/* Define to 1 if you have the 'asprintf' function. */
#define HAVE_ASPRINTF 1

/* Define to 1 if the system has the type 'authdb_t'. */
/* #undef HAVE_AUTHDB_T */

/* Define to 1 if you have the 'authenticate' function. */
/* #undef HAVE_AUTHENTICATE */

/* Define to 1 if you have the 'auth_challenge' function. */
/* #undef HAVE_AUTH_CHALLENGE */

/* Define to 1 if the 'au_close' functions takes 4 arguments like Solaris 11.
   */
/* #undef HAVE_AU_CLOSE_SOLARIS11 */

/* Define to 1 if you have the 'bigcrypt' function. */
/* #undef HAVE_BIGCRYPT */

/* Define to 1 if you use BSD authentication. */
/* #undef HAVE_BSD_AUTH_H */

/* Define to 1 to enable BSM audit support. */
/* #undef HAVE_BSM_AUDIT */

/* Define to 1 if you have the 'bzero' function. */
/* #undef HAVE_BZERO */

/* Define to 1 if you have the 'cfmakeraw' function. */
#define HAVE_CFMAKERAW 1

/* Define to 1 if you have the 'clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the 'closefrom' function. */
/* #undef HAVE_CLOSEFROM */

/* Define to 1 if you have the 'close_range' function. */
/* #undef HAVE_CLOSE_RANGE */

/* Define to 1 if you have the 'crypt' function. */
#define HAVE_CRYPT 1

/* Define to 1 if you use OSF DCE. */
/* #undef HAVE_DCE */

/* Define to 1 if your 'DIR' contains dd_fd. */
/* #undef HAVE_DD_FD */

/* Define to 1 if you have the declaration of 'errno', and to 0 if you don't.
   */
#define HAVE_DECL_ERRNO 1

/* Define to 1 if you have the declaration of 'getdelim', and to 0 if you
   don't. */
#define HAVE_DECL_GETDELIM 1

/* Define to 1 if you have the declaration of 'getdomainname', and to 0 if you
   don't. */
#define HAVE_DECL_GETDOMAINNAME 1

/* Define to 1 if you have the declaration of 'getgrouplist_2', and to 0 if
   you don't. */
/* #undef HAVE_DECL_GETGROUPLIST_2 */

/* Define to 1 if you have the declaration of 'getresuid', and to 0 if you
   don't. */
#define HAVE_DECL_GETRESUID 1

/* Define to 1 if you have the declaration of 'getusershell', and to 0 if you
   don't. */
#define HAVE_DECL_GETUSERSHELL 1

/* Define to 1 if you have the declaration of 'h_errno', and to 0 if you
   don't. */
#define HAVE_DECL_H_ERRNO 1

/* Define to 1 if you have the declaration of 'innetgr', and to 0 if you
   don't. */
#define HAVE_DECL_INNETGR 1

/* Define to 1 if you have the declaration of 'LLONG_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_LLONG_MAX 1

/* Define to 1 if you have the declaration of 'LLONG_MIN', and to 0 if you
   don't. */
#define HAVE_DECL_LLONG_MIN 1

/* Define to 1 if you have the declaration of 'NSIG', and to 0 if you don't.
   */
#define HAVE_DECL_NSIG 1

/* Define to 1 if you have the declaration of 'PATH_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_PATH_MAX 1

/* Define to 1 if you have the declaration of 'pread64', and to 0 if you
   don't. */
/* #undef HAVE_DECL_PREAD64 */

/* Define to 1 if you have the declaration of 'pwrite64', and to 0 if you
   don't. */
/* #undef HAVE_DECL_PWRITE64 */

/* Define to 1 if you have the declaration of 'QUAD_MAX', and to 0 if you
   don't. */
/* #undef HAVE_DECL_QUAD_MAX */

/* Define to 1 if you have the declaration of 'QUAD_MIN', and to 0 if you
   don't. */
/* #undef HAVE_DECL_QUAD_MIN */

/* Define to 1 if you have the declaration of 'SECCOMP_MODE_FILTER', and to 0
   if you don't. */
#define HAVE_DECL_SECCOMP_MODE_FILTER 1

/* Define to 1 if you have the declaration of 'setauthdb', and to 0 if you
   don't. */
/* #undef HAVE_DECL_SETAUTHDB */

/* Define to 1 if you have the declaration of 'setresuid', and to 0 if you
   don't. */
#define HAVE_DECL_SETRESUID 1

/* Define to 1 if you have the declaration of 'SIG2STR_MAX', and to 0 if you
   don't. */
/* #undef HAVE_DECL_SIG2STR_MAX */

/* Define to 1 if you have the declaration of 'SIZE_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_SIZE_MAX 1

/* Define to 1 if you have the declaration of 'SIZE_T_MAX', and to 0 if you
   don't. */
/* #undef HAVE_DECL_SIZE_T_MAX */

/* Define to 1 if you have the declaration of 'SSIZE_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_SSIZE_MAX 1

/* Define to 1 if you have the declaration of 'sys_sigabbrev', and to 0 if you
   don't. */
#define HAVE_DECL_SYS_SIGABBREV 0

/* Define to 1 if you have the declaration of 'sys_siglist', and to 0 if you
   don't. */
/* #undef HAVE_DECL_SYS_SIGLIST */

/* Define to 1 if you have the declaration of 'sys_signame', and to 0 if you
   don't. */
#define HAVE_DECL_SYS_SIGNAME 0

/* Define to 1 if you have the declaration of 'ULLONG_MAX', and to 0 if you
   don't. */
#define HAVE_DECL_ULLONG_MAX 1

/* Define to 1 if you have the declaration of 'UQUAD_MAX', and to 0 if you
   don't. */
/* #undef HAVE_DECL_UQUAD_MAX */

/* Define to 1 if you have the declaration of 'usrinfo', and to 0 if you
   don't. */
/* #undef HAVE_DECL_USRINFO */

/* Define to 1 if you have the declaration of '_innetgr', and to 0 if you
   don't. */
/* #undef HAVE_DECL__INNETGR */

/* Define to 1 if you have the declaration of '_NSIG', and to 0 if you don't.
   */
/* #undef HAVE_DECL__NSIG */

/* Define to 1 if you have the declaration of '_POSIX_PATH_MAX', and to 0 if
   you don't. */
/* #undef HAVE_DECL__POSIX_PATH_MAX */

/* Define to 1 if you have the declaration of '_sys_siglist', and to 0 if you
   don't. */
/* #undef HAVE_DECL__SYS_SIGLIST */

/* Define to 1 if you have the declaration of '_sys_signame', and to 0 if you
   don't. */
#define HAVE_DECL__SYS_SIGNAME 0

/* Define to 1 if you have the declaration of '__NSIG', and to 0 if you don't.
   */
/* #undef HAVE_DECL___NSIG */

/* Define to 1 if you have the 'devname' function. */
/* #undef HAVE_DEVNAME */

/* Define to 1 if you have the <dirent.h> header file, and it defines 'DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the 'dirfd' function or macro. */
#define HAVE_DIRFD 1

/* Define to 1 if you have the 'dispcrypt' function. */
/* #undef HAVE_DISPCRYPT */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the 'dlopen' function. */
#define HAVE_DLOPEN 1

/* Define to 1 if you have the 'dl_iterate_phdr' function. */
#define HAVE_DL_ITERATE_PHDR 1

/* Define to 1 if the compiler supports the __visibility__ attribute. */
#define HAVE_DSO_VISIBILITY 1

/* Define to 1 if you have the 'dup3' function. */
#define HAVE_DUP3 1

/* Define to 1 if you have the <endian.h> header file. */
#define HAVE_ENDIAN_H 1

/* Define to 1 if you have the 'exect' function. */
/* #undef HAVE_EXECT */

/* Define to 1 if you have the 'execvP' function. */
/* #undef HAVE_EXECVP */

/* Define to 1 if you have the 'execvpe' function. */
#define HAVE_EXECVPE 1

/* Define to 1 if you have the 'explicit_bzero' function. */
#define HAVE_EXPLICIT_BZERO 1

/* Define to 1 if you have the 'explicit_memset' function. */
/* #undef HAVE_EXPLICIT_MEMSET */

/* Define to 1 if you have the 'faccessat' function. */
#define HAVE_FACCESSAT 1

/* Define to 1 if the compiler supports the fallthrough attribute. */
#define HAVE_FALLTHROUGH_ATTRIBUTE 1

/* Define to 1 if you have the 'fchmodat' function. */
#define HAVE_FCHMODAT 1

/* Define to 1 if you have the 'fchownat' function. */
#define HAVE_FCHOWNAT 1

/* Define to 1 if your system has the F_CLOSEM fcntl. */
/* #undef HAVE_FCNTL_CLOSEM */

/* Define to 1 if you have the 'fexecve' function. */
#define HAVE_FEXECVE 1

/* Define to 1 if you have the 'fmemopen' function. */
#define HAVE_FMEMOPEN 1

/* Define to 1 if you have the 'fnmatch' function. */
#define HAVE_FNMATCH 1

/* Define to 1 if you have the 'freeifaddrs' function. */
#define HAVE_FREEIFADDRS 1

/* Define to 1 if you have the 'freezero' function. */
/* #undef HAVE_FREEZERO */

/* Define to 1 if fseeko (and ftello) are declared in stdio.h. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the 'fstatat' function. */
#define HAVE_FSTATAT 1

/* Define to 1 if you have the 'futime' function. */
/* #undef HAVE_FUTIME */

/* Define to 1 if you have the 'futimens' function. */
#define HAVE_FUTIMENS 1

/* Define to 1 if you have the 'futimes' function. */
/* #undef HAVE_FUTIMES */

/* Define to 1 if you have the 'futimesat' function. */
/* #undef HAVE_FUTIMESAT */

/* Define to 1 if you use the FWTK authsrv daemon. */
/* #undef HAVE_FWTK */

/* Define to 1 if you are using gcrypt's sha2 functions. */
/* #undef HAVE_GCRYPT */

/* Define to 1 if you have the 'getaddrinfo' function. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the 'getauxval' function. */
#define HAVE_GETAUXVAL 1

/* Define to 1 if you have the 'getdelim' function. */
#define HAVE_GETDELIM 1

/* Define to 1 if you have the 'getdomainname' function. */
#define HAVE_GETDOMAINNAME 1

/* Define to 1 if you have the 'getentropy' function. */
/* #undef HAVE_GETENTROPY */

/* Define to 1 if you have the 'getgrouplist' function. */
#define HAVE_GETGROUPLIST 1

/* Define to 1 if you have the 'getgrouplist_2' function. */
/* #undef HAVE_GETGROUPLIST_2 */

/* Define to 1 if your system has a working 'getgroups' function. */
#define HAVE_GETGROUPS 1

/* Define to 1 if you have the 'getgrset' function. */
/* #undef HAVE_GETGRSET */

/* Define to 1 if you have the 'gethrtime' function. */
/* #undef HAVE_GETHRTIME */

/* Define to 1 if you have the 'getifaddrs' function. */
#define HAVE_GETIFADDRS 1

/* Define to 1 if you have the 'getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* Define to 1 if you have the 'getprogname' function. */
/* #undef HAVE_GETPROGNAME */

/* Define to 1 if you have the 'getprpwnam' function. (SecureWare-style shadow
   passwords). */
/* #undef HAVE_GETPRPWNAM */

/* Define to 1 if you have the 'getpwnam_shadow' function. */
/* #undef HAVE_GETPWNAM_SHADOW */

/* Define to 1 if you have the 'getresuid' function. */
#define HAVE_GETRESUID 1

/* Define to 1 if you have the 'getspnam' function (SVR4-style shadow
   passwords). */
#define HAVE_GETSPNAM 1

/* Define to 1 if you have the 'getttyent' function. */
/* #undef HAVE_GETTTYENT */

/* Define to 1 if you have the 'getuserattr' function. */
/* #undef HAVE_GETUSERATTR */

/* Define to 1 if you have the 'getusershell' function. */
#define HAVE_GETUSERSHELL 1

/* Define to 1 if you have the 'getutid' function. */
/* #undef HAVE_GETUTID */

/* Define to 1 if you have the 'getutsid' function. */
/* #undef HAVE_GETUTSID */

/* Define to 1 if you have the 'getutxid' function. */
#define HAVE_GETUTXID 1

/* Define to 1 if you have the 'glob' function. */
#define HAVE_GLOB 1

/* Define to 1 if you have the 'gmtime_r' function. */
#define HAVE_GMTIME_R 1

/* Define to 1 if you have the 'grantpt' function. */
/* #undef HAVE_GRANTPT */

/* Define to 1 if you have the <gssapi/gssapi.h> header file. */
/* #undef HAVE_GSSAPI_GSSAPI_H */

/* Define to 1 if you have the <gssapi/gssapi_krb5.h> header file. */
/* #undef HAVE_GSSAPI_GSSAPI_KRB5_H */

/* Define to 1 if you have the <gssapi.h> header file. */
/* #undef HAVE_GSSAPI_H */

/* Define to 1 if you have the 'gss_krb5_ccache_name' function. */
/* #undef HAVE_GSS_KRB5_CCACHE_NAME */

/* Define to 1 if your Kerberos is Heimdal. */
/* #undef HAVE_HEIMDAL */

/* Define to 1 if you have the 'inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the 'inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the 'initprivs' function. */
/* #undef HAVE_INITPRIVS */

/* Define to 1 if you have the 'innetgr' function. */
#define HAVE_INNETGR 1

/* Define to 1 if the system has the type 'int16_t'. */
/* #undef HAVE_INT16_T */

/* Define to 1 if the system has the type 'int32_t'. */
/* #undef HAVE_INT32_T */

/* Define to 1 if the system has the type 'int64_t'. */
/* #undef HAVE_INT64_T */

/* Define to 1 if the system has the type 'int8_t'. */
/* #undef HAVE_INT8_T */

/* Define to 1 if the system has the type 'intmax_t'. */
/* #undef HAVE_INTMAX_T */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if you have isblank(3). */
#define HAVE_ISBLANK 1

/* Define to 1 if you have the 'iscomsec' function. (HP-UX >= 10.x check for
   shadow enabled). */
/* #undef HAVE_ISCOMSEC */

/* Define to 1 if you use Kerberos V. */
/* #undef HAVE_KERB5 */

/* Define to 1 if you have the 'killpg' function. */
#define HAVE_KILLPG 1

/* Define to 1 if your system has a NetBSD-style kinfo_proc2 struct. */
/* #undef HAVE_KINFO_PROC2_NETBSD */

/* Define to 1 if your system has a 4.4BSD-style kinfo_proc struct. */
/* #undef HAVE_KINFO_PROC_44BSD */

/* Define to 1 if your system has a Dragonfly-style kinfo_proc struct. */
/* #undef HAVE_KINFO_PROC_DFLY */

/* Define to 1 if your system has a FreeBSD-style kinfo_proc struct. */
/* #undef HAVE_KINFO_PROC_FREEBSD */

/* Define to 1 if your system has an OpenBSD-style kinfo_proc struct. */
/* #undef HAVE_KINFO_PROC_OPENBSD */

/* Define to 1 if you have the 'krb5_get_init_creds_opt_alloc' function. */
/* #undef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC */

/* Define to 1 if your 'krb5_get_init_creds_opt_free' function takes two
   arguments. */
/* #undef HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_TWO_ARGS */

/* Define to 1 if you have the 'krb5_init_secure_context' function. */
/* #undef HAVE_KRB5_INIT_SECURE_CONTEXT */

/* Define to 1 if you have the 'krb5_verify_user' function. */
/* #undef HAVE_KRB5_VERIFY_USER */

/* Define to 1 if your LDAP needs <lber.h>. (OpenLDAP does not). */
/* #undef HAVE_LBER_H */

/* Define to 1 if you use LDAP for sudoers. */
/* #undef HAVE_LDAP */

/* Define to 1 if you have the <ldapssl.h> header file. */
/* #undef HAVE_LDAPSSL_H */

/* Define to 1 if you have the 'ldapssl_init' function. */
/* #undef HAVE_LDAPSSL_INIT */

/* Define to 1 if you have the 'ldapssl_set_strength' function. */
/* #undef HAVE_LDAPSSL_SET_STRENGTH */

/* Define to 1 if you have the 'ldap_create' function. */
/* #undef HAVE_LDAP_CREATE */

/* Define to 1 if you have the 'ldap_initialize' function. */
/* #undef HAVE_LDAP_INITIALIZE */

/* Define to 1 if you have the 'ldap_sasl_bind_s' function. */
/* #undef HAVE_LDAP_SASL_BIND_S */

/* Define to 1 if you have the 'ldap_sasl_interactive_bind_s' function. */
/* #undef HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

/* Define to 1 if you have the 'ldap_search_ext_s' function. */
/* #undef HAVE_LDAP_SEARCH_EXT_S */

/* Define to 1 if you have the 'ldap_search_st' function. */
/* #undef HAVE_LDAP_SEARCH_ST */

/* Define to 1 if you have the 'ldap_ssl_client_init' function. */
/* #undef HAVE_LDAP_SSL_CLIENT_INIT */

/* Define to 1 if you have the <ldap_ssl.h> header file. */
/* #undef HAVE_LDAP_SSL_H */

/* Define to 1 if you have the 'ldap_ssl_init' function. */
/* #undef HAVE_LDAP_SSL_INIT */

/* Define to 1 if you have the 'ldap_start_tls_s' function. */
/* #undef HAVE_LDAP_START_TLS_S */

/* Define to 1 if you have the 'ldap_start_tls_s_np' function. */
/* #undef HAVE_LDAP_START_TLS_S_NP */

/* Define to 1 if you have the 'ldap_str2dn' function. */
/* #undef HAVE_LDAP_STR2DN */

/* Define to 1 if you have the 'ldap_unbind_ext_s' function. */
/* #undef HAVE_LDAP_UNBIND_EXT_S */

/* Define to 1 if you have the <libintl.h> header file. */
#define HAVE_LIBINTL_H 1

/* Define to 1 if you have the <libproc.h> header file. */
/* #undef HAVE_LIBPROC_H */

/* Define to 1 if you have the <libutil.h> header file. */
/* #undef HAVE_LIBUTIL_H */

/* Define to 1 to enable Linux audit support. */
/* #undef HAVE_LINUX_AUDIT */

/* Define to 1 if you have the <linux/close_range.h> header file. */
/* #undef HAVE_LINUX_CLOSE_RANGE_H */

/* Define to 1 if you have the <linux/random.h> header file. */
#define HAVE_LINUX_RANDOM_H 1

/* Define to 1 if you have the 'localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define to 1 if you have the 'lockf' function. */
#define HAVE_LOCKF 1

/* Define to 1 if you have the <login_cap.h> header file. */
/* #undef HAVE_LOGIN_CAP_H */

/* Define to 1 if you have the <machine/endian.h> header file. */
/* #undef HAVE_MACHINE_ENDIAN_H */

/* Define to 1 if you have the 'mach_continuous_time' function. */
/* #undef HAVE_MACH_CONTINUOUS_TIME */

/* Define to 1 if you have the <maillock.h> header file. */
/* #undef HAVE_MAILLOCK_H */

/* Define to 1 if you have the 'memrchr' function. */
#define HAVE_MEMRCHR 1

/* Define to 1 if you have the 'memset_explicit' function. */
/* #undef HAVE_MEMSET_EXPLICIT */

/* Define to 1 if you have the 'memset_s' function. */
/* #undef HAVE_MEMSET_S */

/* Define to 1 if you have the <minix/config.h> header file. */
/* #undef HAVE_MINIX_CONFIG_H */

/* Define to 1 if you have the 'mkdirat' function. */
#define HAVE_MKDIRAT 1

/* Define to 1 if you have the 'mkdtempat' function. */
/* #undef HAVE_MKDTEMPAT */

/* Define to 1 if you have the 'mkdtempat_np' function. */
/* #undef HAVE_MKDTEMPAT_NP */

/* Define to 1 if you have the 'mkostempsat' function. */
/* #undef HAVE_MKOSTEMPSAT */

/* Define to 1 if you have the 'mkostempsat_np' function. */
/* #undef HAVE_MKOSTEMPSAT_NP */

/* Define to 1 if you have the <mps/ldap_ssl.h> header file. */
/* #undef HAVE_MPS_LDAP_SSL_H */

/* Define to 1 if you have the 'nanosleep' function. */
#define HAVE_NANOSLEEP 1

/* Define to 1 if you have the <ndir.h> header file, and it defines 'DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netgroup.h> header file. */
/* #undef HAVE_NETGROUP_H */

/* Define to 1 if you have the 'ngettext' function. */
#define HAVE_NGETTEXT 1

/* Define to 1 if you have the 'nl_langinfo' function. */
#define HAVE_NL_LANGINFO 1

/* Define to 1 if you have the <nss_dbdefs.h> header file. */
/* #undef HAVE_NSS_DBDEFS_H */

/* Define to 1 if you have the 'nss_search' function. */
/* #undef HAVE_NSS_SEARCH */

/* Define to 1 if you have the 'openat' function. */
#define HAVE_OPENAT 1

/* Define to 1 if you have the 'openpty' function. */
#define HAVE_OPENPTY 1

/* Define to 1 if you are using OpenSSL's TLS and sha2 functions. */
/* #undef HAVE_OPENSSL */

/* Define to 1 if you use NRL OPIE. */
/* #undef HAVE_OPIE */

/* Define to 1 if you have the 'optreset' symbol. */
/* #undef HAVE_OPTRESET */

/* Define to 1 if you use PAM authentication. */
/* #undef HAVE_PAM */

/* Define to 1 if you have the 'pam_getenvlist' function. */
/* #undef HAVE_PAM_GETENVLIST */

/* Define to 1 if you use a specific PAM session for sudo -i. */
/* #undef HAVE_PAM_LOGIN */

/* Define to 1 if you have the <pam/pam_appl.h> header file. */
/* #undef HAVE_PAM_PAM_APPL_H */

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define to 1 if you have the 'pipe2' function. */
#define HAVE_PIPE2 1

/* Define to 1 if you have the 'poll' function. */
/* #undef HAVE_POLL */

/* Define to 1 if you have the 'posix_openpt' function. */
/* #undef HAVE_POSIX_OPENPT */

/* Define to 1 if you have the 'posix_spawn' function. */
#define HAVE_POSIX_SPAWN 1

/* Define to 1 if you have the 'posix_spawnp' function. */
#define HAVE_POSIX_SPAWNP 1

/* Define to 1 if you have the 'ppoll' function. */
#define HAVE_PPOLL 1

/* Define to 1 if you have the 'pread' function. */
#define HAVE_PREAD 1

/* Define to 1 if you have the 'pread64' function. */
/* #undef HAVE_PREAD64 */

/* Define to 1 if you have the 'priv_set' function. */
/* #undef HAVE_PRIV_SET */

/* Define to 1 if you have the 'process_vm_readv' function. */
#define HAVE_PROCESS_VM_READV 1

/* Define to 1 if you have the <procfs.h> header file. */
/* #undef HAVE_PROCFS_H */

/* Define to 1 if you have the 'proc_pidinfo' function. */
/* #undef HAVE_PROC_PIDINFO */

/* Define to 1 if you have the <project.h> header file. */
/* #undef HAVE_PROJECT_H */

/* Define to 1 if you have the 'pselect' function. */
/* #undef HAVE_PSELECT */

/* Define to 1 if you have the 'pstat_getproc' function. */
/* #undef HAVE_PSTAT_GETPROC */

/* Define to 1 if you have the 'pthread_atfork' function. */
#define HAVE_PTHREAD_ATFORK 1

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the <pty.h> header file. */
#define HAVE_PTY_H 1

/* Define to 1 if you have the 'pwrite' function. */
#define HAVE_PWRITE 1

/* Define to 1 if you have the 'pwrite64' function. */
/* #undef HAVE_PWRITE64 */

/* Define to 1 if you have the 'pw_dup' function. */
/* #undef HAVE_PW_DUP */

/* Define to 1 if you have the 'reallocarray' function. */
#define HAVE_REALLOCARRAY 1

/* Define to 1 if you have the 'revoke' function. */
/* #undef HAVE_REVOKE */

/* Define to 1 if the skeychallenge() function is RFC1938-compliant and takes
   4 arguments. */
/* #undef HAVE_RFC1938_SKEYCHALLENGE */

/* Define to 1 if you have the <sasl.h> header file. */
/* #undef HAVE_SASL_H */

/* Define to 1 if you have the <sasl/sasl.h> header file. */
/* #undef HAVE_SASL_SASL_H */

/* Define to 1 if you use SecurID for authentication. */
/* #undef HAVE_SECURID */

/* Define to 1 if you have the <security/pam_appl.h> header file. */
/* #undef HAVE_SECURITY_PAM_APPL_H */

/* Define to 1 to enable SELinux RBAC support. */
/* #undef HAVE_SELINUX */

/* Define to 1 if you have the 'setauthdb' function. */
/* #undef HAVE_SETAUTHDB */

/* Define to 1 if you have the 'seteuid' function. */
#define HAVE_SETEUID 1

/* Define to 1 if you have the 'setgroupent' function. */
/* #undef HAVE_SETGROUPENT */

/* Define to 1 if you have the 'setkeycreatecon' function. */
/* #undef HAVE_SETKEYCREATECON */

/* Define to 1 if you have the 'setpassent' function. */
/* #undef HAVE_SETPASSENT */

/* Define to 1 if you have the 'setprogname' function. */
/* #undef HAVE_SETPROGNAME */

/* Define to 1 if you have the 'setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if you have the 'setreuid' function. */
#define HAVE_SETREUID 1

/* Define to 1 if you have the 'setrlimit64' function. */
/* #undef HAVE_SETRLIMIT64 */

/* Define to 1 if you have the 'set_auth_parameters' function. */
/* #undef HAVE_SET_AUTH_PARAMETERS */

/* Define to 1 if you have the 'SHA224Update' function. */
/* #undef HAVE_SHA224UPDATE */

/* Define to 1 if you have the 'shl_load' function. */
/* #undef HAVE_SHL_LOAD */

/* Define to 1 if you have the 'sia_ses_init' function. */
/* #undef HAVE_SIA_SES_INIT */

/* Define to 1 if you have the 'sig2str' function. */
/* #undef HAVE_SIG2STR */

/* Define to 1 if you have the 'sigabbrev_np' function. */
/* #undef HAVE_SIGABBREV_NP */

/* Define to 1 if the system has the type 'sig_atomic_t'. */
#define HAVE_SIG_ATOMIC_T 1

/* Define to 1 if you use S/Key. */
/* #undef HAVE_SKEY */

/* Define to 1 if your S/Key library has skeyaccess(). */
/* #undef HAVE_SKEYACCESS */

/* Define to 1 if you have the 'snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if the system has the type 'socklen_t'. */
#define HAVE_SOCKLEN_T 1

/* Define to 1 to enable Solaris audit support. */
/* #undef HAVE_SOLARIS_AUDIT */

/* Define to 1 if you have the <spawn.h> header file. */
#define HAVE_SPAWN_H 1

/* Define to 1 if you have the 'SSL_CTX_get0_certificate' function. */
/* #undef HAVE_SSL_CTX_GET0_CERTIFICATE */

/* Define to 1 if you have the 'SSL_CTX_set0_tmp_dh_pkey' function. */
/* #undef HAVE_SSL_CTX_SET0_TMP_DH_PKEY */

/* Define to 1 if you have the 'SSL_CTX_set_ciphersuites' function or macro.
   */
/* #undef HAVE_SSL_CTX_SET_CIPHERSUITES */

/* Define to 1 if you have the 'SSL_CTX_set_min_proto_version' function or
   macro. */
/* #undef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION */

/* Define to 1 to enable SSSD support. */
/* #undef HAVE_SSSD */

/* Define to 1 if stdbool.h conforms to C99. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the 'str2sig' function. */
/* #undef HAVE_STR2SIG */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the 'strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the 'strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the 'strndup' function. */
#define HAVE_STRNDUP 1

/* Define to 1 if you have the 'strnlen' function. */
#define HAVE_STRNLEN 1

/* Define to 1 if you have the 'strsignal' function. */
#define HAVE_STRSIGNAL 1

/* Define to 1 if you have the 'strtoull' function. */
#define HAVE_STRTOULL 1

/* Define to 1 if 'd_namlen' is a member of 'struct dirent'. */
/* #undef HAVE_STRUCT_DIRENT_D_NAMLEN */

/* Define to 1 if 'd_type' is a member of 'struct dirent'. */
#define HAVE_STRUCT_DIRENT_D_TYPE 1

/* Define to 1 if the system has the type 'struct in6_addr'. */
#define HAVE_STRUCT_IN6_ADDR 1

/* Define to 1 if 'pr_ttydev' is a member of 'struct psinfo'. */
/* #undef HAVE_STRUCT_PSINFO_PR_TTYDEV */

/* Define if your struct sockaddr_in has a sin_len field. */
/* #undef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

/* Define if your struct sockaddr has an sa_len field. */
/* #undef HAVE_STRUCT_SOCKADDR_SA_LEN */

/* Define to 1 if 'tm_gmtoff' is a member of 'struct tm'. */
/* #undef HAVE_STRUCT_TM_TM_GMTOFF */

/* Define to 1 if 'ut_exit' is a member of 'struct utmp'. */
#define HAVE_STRUCT_UTMP_UT_EXIT 1

/* Define to 1 if 'ut_exit.e_termination' is a member of 'struct utmp'. */
#define HAVE_STRUCT_UTMP_UT_EXIT_E_TERMINATION 1

/* Define to 1 if 'ut_exit.__e_termination' is a member of 'struct utmp'. */
/* #undef HAVE_STRUCT_UTMP_UT_EXIT___E_TERMINATION */

/* Define to 1 if 'ut_id' is a member of 'struct utmp'. */
#define HAVE_STRUCT_UTMP_UT_ID 1

/* Define to 1 if 'ut_pid' is a member of 'struct utmp'. */
#define HAVE_STRUCT_UTMP_UT_PID 1

/* Define to 1 if 'ut_tv' is a member of 'struct utmp'. */
#define HAVE_STRUCT_UTMP_UT_TV 1

/* Define to 1 if 'ut_type' is a member of 'struct utmp'. */
#define HAVE_STRUCT_UTMP_UT_TYPE 1

/* Define to 1 if 'ut_user' is a member of 'struct utmp'. */
/* #undef HAVE_STRUCT_UTMP_UT_USER */

/* Define to 1 if your struct stat has an st_mtim member. */
#define HAVE_ST_MTIM 1

/* Define to 1 if your struct stat has an st_mtimespec member. */
/* #undef HAVE_ST_MTIMESPEC */

/* Define to 1 if your struct stat has an st_nmtime member. */
/* #undef HAVE_ST_NMTIME */

/* Define to 1 if your struct stat uses an st__tim union. */
/* #undef HAVE_ST__TIM */

/* Define to 1 if you have the 'sysctl' function. */
#define HAVE_SYSCTL 1

/* Define to 1 if you have the 'sysinfo' function. */
/* #undef HAVE_SYSINFO */

/* Define to 1 if you have the <sys/bsdtypes.h> header file. */
/* #undef HAVE_SYS_BSDTYPES_H */

/* Define to 1 if you have the <sys/dir.h> header file, and it defines 'DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/endian.h> header file. */
/* #undef HAVE_SYS_ENDIAN_H */

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines 'DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/procfs.h> header file. */
#define HAVE_SYS_PROCFS_H 1

/* Define to 1 if you have the <sys/random.h> header file. */
/* #undef HAVE_SYS_RANDOM_H */

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if your libc has the 'sys_sigabbrev' symbol. */
#define HAVE_SYS_SIGABBREV 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/statvfs.h> header file. */
#define HAVE_SYS_STATVFS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/stropts.h> header file. */
/* #undef HAVE_SYS_STROPTS_H */

/* Define to 1 if you have the <sys/syscall.h> header file. */
#define HAVE_SYS_SYSCALL_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
/* #undef HAVE_SYS_SYSCTL_H */

/* Define to 1 if you have the <sys/sysmacros.h> header file. */
#define HAVE_SYS_SYSMACROS_H 1

/* Define to 1 if you have the <sys/systeminfo.h> header file. */
/* #undef HAVE_SYS_SYSTEMINFO_H */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the 'timegm' function. */
#define HAVE_TIMEGM 1

/* Define to 1 if you have the 'TLS_method' function. */
/* #undef HAVE_TLS_METHOD */

/* Define to 1 if you have the 'ttyslot' function. */
/* #undef HAVE_TTYSLOT */

/* Define to 1 if the system has the type 'uint16_t'. */
/* #undef HAVE_UINT16_T */

/* Define to 1 if the system has the type 'uint32_t'. */
/* #undef HAVE_UINT32_T */

/* Define to 1 if the system has the type 'uint64_t'. */
/* #undef HAVE_UINT64_T */

/* Define to 1 if the system has the type 'uint8_t'. */
/* #undef HAVE_UINT8_T */

/* Define to 1 if the system has the type 'uintmax_t'. */
/* #undef HAVE_UINTMAX_T */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the 'unlinkat' function. */
#define HAVE_UNLINKAT 1

/* Define to 1 if you have the 'unsetenv' function. */
#define HAVE_UNSETENV 1

/* Define to 1 if you have the <util.h> header file. */
/* #undef HAVE_UTIL_H */

/* Define to 1 if you have the 'utimensat' function. */
#define HAVE_UTIMENSAT 1

/* Define to 1 if you have the 'utimes' function. */
/* #undef HAVE_UTIMES */

/* Define to 1 if you have the <utmps.h> header file. */
/* #undef HAVE_UTMPS_H */

/* Define to 1 if you have the <utmpx.h> header file. */
#define HAVE_UTMPX_H 1

/* Define to 1 if you have the 'vasprintf' function. */
#define HAVE_VASPRINTF 1

/* Define to 1 if you have the 'va_copy' function. */
#define HAVE_VA_COPY 1

/* Define to 1 if you have the 'vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if you are using wolfSSL's TLS and sha2 functions. */
/* #undef HAVE_WOLFSSL */

/* Define to 1 if you have the 'wordexp' function. */
#define HAVE_WORDEXP 1

/* Define to 1 if you have the <wordexp.h> header file. */
#define HAVE_WORDEXP_H 1

/* Define to 1 if you have the 'X509_STORE_CTX_get0_cert' function. */
/* #undef HAVE_X509_STORE_CTX_GET0_CERT */

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to 1 if the system has the type '_Bool'. */
#define HAVE__BOOL 1

/* Define to 1 if you have the '_getpty' function. */
/* #undef HAVE__GETPTY */

/* Define to 1 if you have the '_innetgr' function. */
/* #undef HAVE__INNETGR */

/* Define to 1 if you have the '_nss_initf_group' function. */
/* #undef HAVE__NSS_INITF_GROUP */

/* Define to 1 if you have the '_nss_XbyY_buf_alloc' function. */
/* #undef HAVE__NSS_XBYY_BUF_ALLOC */

/* Define to 1 if you have the '_ttyname_dev' function. */
/* #undef HAVE__TTYNAME_DEV */

/* Define to 1 if the compiler supports the C99 __func__ variable. */
#define HAVE___FUNC__ 1

/* Define to 1 if you have dyld with __interpose attribute support. */
/* #undef HAVE___INTERPOSE */

/* Define to 1 if you have the '__nss_initf_group' function. */
/* #undef HAVE___NSS_INITF_GROUP */

/* Define to 1 if you have the '__nss_XbyY_buf_alloc' function. */
/* #undef HAVE___NSS_XBYY_BUF_ALLOC */

/* Define to 1 if your crt0.o defines the __progname symbol for you. */
#define HAVE___PROGNAME 1

/* Define to 1 if you have the '__va_copy' function. */
/* #undef HAVE___VA_COPY */

/* Define to 1 if you want the hostname to be entered into the log file. */
/* #undef HOST_IN_LOG */

/* Define to 1 if you want to ignore '.' and empty PATH elements. */
/* #undef IGNORE_DOT_PATH */

/* The message given when a bad password is entered. */
#define INCORRECT_PASSWORD "Sorry, try again."

/* The syslog facility sudo will use. */
#define LOGFAC "authpriv"

/* Define to SLOG_SYSLOG, SLOG_FILE, or SLOG_BOTH. */
#define LOGGING SLOG_SYSLOG

/* Define to 1 if you want a two line OTP (S/Key or OPIE) prompt. */
/* #undef LONG_OTP_PROMPT */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* The subject of the mail sent by sudo to the MAILTO user/address. */
#define MAILSUBJECT "*** SECURITY information for %h ***"

/* The user or email address that sudo mail is sent to. */
#define MAILTO "root"

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in <mkdev.h>.
   */
/* #undef MAJOR_IN_MKDEV */

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in
   <sysmacros.h>. */
#define MAJOR_IN_SYSMACROS 1

/* The max number of chars per log file line (for line wrapping). */
#define MAXLOGFILELEN 80

/* Define to the max length of a uid_t in string context (excluding the NUL).
   */
#define MAX_UID_T_LEN 10

/* Define to 1 if resolv.h must be included to get the 'inet_ntop' or
   'inet_pton' function prototypes. */
/* #undef NEED_RESOLV_H */

/* Define to 1 if you don't want sudo to prompt for a password by default. */
/* #undef NO_AUTHENTICATION */

/* Define to 1 if you want sudo to free up memory before exiting. */
/* #undef NO_LEAKS */

/* Define to 1 if you don't want users to get the lecture the first time they
   use sudo. */
/* #undef NO_LECTURE */

/* Define to 1 if you don't want to use sudo's PAM session support. */
/* #undef NO_PAM_SESSION */

/* Define to avoid running the mailer as root. */
/* #undef NO_ROOT_MAILER */

/* Define to 1 if root should not be allowed to use sudo. */
/* #undef NO_ROOT_SUDO */

/* Define if your C preprocessor does not support variadic macros. */
/* #undef NO_VARIADIC_MACROS */

/* Define to 1 to include offensive insults from the classic version of sudo.
   */
/* #undef OFFENSIVE_INSULTS */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://bugzilla.sudo.ws/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "sudo"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "sudo 1.9.13p3"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "sudo"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.9.13p3"

/* Define to 1 if your system uses a Solaris-derived PAM and not Linux-PAM or
   OpenPAM. */
/* #undef PAM_SUN_CODEBASE */

/* The default password prompt. */
#define PASSPROMPT "Password: "

/* The passwd prompt timeout (in minutes). */
#define PASSWORD_TIMEOUT 5

/* Define to 1 to enable replacement getcwd if system getcwd is broken. */
/* #undef PREFER_PORTABLE_GETCWD */

/* Enable replacement (v)snprintf if system (v)snprintf is broken. */
/* #undef PREFER_PORTABLE_SNPRINTF */

/* The syslog priority sudo will use for unsuccessful attempts/errors. */
#define PRI_FAILURE "alert"

/* The syslog priority sudo will use for successful attempts. */
#define PRI_SUCCESS "notice"

/* Define to const if the 'putenv' takes a const argument. */
#define PUTENV_CONST /**/

/* Define to 1 if you want insults from "Monty Python's Flying Circus". */
/* #undef PYTHON_INSULTS */

/* The default value of preloaded objects (if any). */
/* #undef RTLD_PRELOAD_DEFAULT */

/* The delimiter to use when defining multiple preloaded objects. */
#define RTLD_PRELOAD_DELIM ':'

/* An extra environment variable that is required to enable preloading (if
   any). */
/* #undef RTLD_PRELOAD_ENABLE_VAR */

/* The environment variable that controls preloading of dynamic objects. */
#define RTLD_PRELOAD_VAR "LD_PRELOAD"

/* The user sudo should run commands as by default. */
#define RUNAS_DEFAULT "root"

/* A colon-separated list of directories to override the user's PATH with. */
/* #undef SECURE_PATH */

/* Define to 1 to send mail when the user is not allowed to run a command. */
/* #undef SEND_MAIL_WHEN_NOT_OK */

/* Define to 1 to send mail when the user is not allowed to run sudo on this
   host. */
/* #undef SEND_MAIL_WHEN_NO_HOST */

/* Define to 1 to send mail when the user is not in the sudoers file. */
#define SEND_MAIL_WHEN_NO_USER 1

/* Define to 1 if the sha2 functions use 'const void *' instead of 'const
   unsigned char'. */
/* #undef SHA2_VOID_PTR */

/* Define to 1 if you want sudo to start a shell if given no arguments. */
/* #undef SHELL_IF_NO_ARGS */

/* Define to 1 if you want sudo to set $HOME in shell mode. */
/* #undef SHELL_SETS_HOME */

/* The size of 'id_t', as computed by sizeof. */
#define SIZEOF_ID_T 4

/* The size of 'long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of 'time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

/* Define to 1 to compile the sudoers plugin statically into the sudo binary.
   */
/* #undef STATIC_SUDOERS_PLUGIN */

/* Define to 1 if all of the C89 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to 1 if the code in interfaces.c does not compile for you. */
/* #undef STUB_LOAD_INTERFACES */

/* Define to 1 to compile support for sudo_logsrvd in the sudoers plugin. */
#define SUDOERS_LOG_CLIENT 1

/* An instance string to append to the username (separated by a slash) for
   Kerberos V authentication. */
/* #undef SUDO_KRB5_INSTANCE */

/* The umask that the sudo-run prog should use. */
#define SUDO_UMASK 0022

/* The number of minutes before sudo asks for a password again. */
#define TIMEOUT 5

/* Define to global, ppid or tty to set the default timestamp record type. */
#define TIMESTAMP_TYPE tty

/* The number of tries a user gets to enter their password. */
#define TRIES_FOR_PASSWORD 3

/* Define to 1 to use the umask specified in sudoers even when it is less
   restrictive than the invoking user's. */
/* #undef UMASK_OVERRIDE */

/* Define to 1 if the 'unsetenv' function returns void instead of 'int'. */
/* #undef UNSETENV_VOID */

/* Define to 1 if you want to insult the user for entering an incorrect
   password. */
/* #undef USE_INSULTS */

/* Define to 1 if you use GNU stow packaging. */
/* #undef USE_STOW */

/* Enable extensions on AIX, Interix, z/OS.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable general extensions on macOS.  */
#ifndef _DARWIN_C_SOURCE
# define _DARWIN_C_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable X/Open compliant socket functions that do not require linking
   with -lxnet on HP-UX 11.11.  */
#ifndef _HPUX_ALT_XOPEN_SOCKET_API
# define _HPUX_ALT_XOPEN_SOCKET_API 1
#endif
/* Identify the host operating system as Minix.
   This macro does not affect the system headers' behavior.
   A future release of Autoconf may stop defining this macro.  */
#ifndef _MINIX
/* # undef _MINIX */
#endif
/* Enable general extensions on NetBSD.
   Enable NetBSD compatibility extensions on Minix.  */
#ifndef _NETBSD_SOURCE
# define _NETBSD_SOURCE 1
#endif
/* Enable OpenBSD compatibility extensions on NetBSD.
   Oddly enough, this does nothing on OpenBSD.  */
#ifndef _OPENBSD_SOURCE
# define _OPENBSD_SOURCE 1
#endif
/* Define to 1 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_SOURCE
/* # undef _POSIX_SOURCE */
#endif
/* Define to 2 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_1_SOURCE
/* # undef _POSIX_1_SOURCE */
#endif
/* Enable POSIX-compatible threading on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
# define __STDC_WANT_IEC_60559_ATTRIBS_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
# define __STDC_WANT_IEC_60559_BFP_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
# define __STDC_WANT_IEC_60559_DFP_EXT__ 1
#endif
/* Enable extensions specified by C23 Annex F.  */
#ifndef __STDC_WANT_IEC_60559_EXT__
# define __STDC_WANT_IEC_60559_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
# define __STDC_WANT_IEC_60559_FUNCS_EXT__ 1
#endif
/* Enable extensions specified by C23 Annex H and ISO/IEC TS 18661-3:2015.  */
#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
# define __STDC_WANT_IEC_60559_TYPES_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
#ifndef __STDC_WANT_LIB_EXT2__
# define __STDC_WANT_LIB_EXT2__ 1
#endif
/* Enable extensions specified by ISO/IEC 24747:2009.  */
#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
# define __STDC_WANT_MATH_SPEC_FUNCS__ 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable X/Open extensions.  Define to 500 only if necessary
   to make mbstate_t available.  */
#ifndef _XOPEN_SOURCE
/* # undef _XOPEN_SOURCE */
#endif


/* Define to avoid using the passwd/shadow file for authentication. */
/* #undef WITHOUT_PASSWD */

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 if necessary to make fseeko visible. */
/* #undef _LARGEFILE_SOURCE */

/* Define to 1 on platforms where this makes off_t a 64-bit type. */
/* #undef _LARGE_FILES */

/* Number of bits in time_t, on hosts where this is settable. */
/* #undef _TIME_BITS */

/* Define to 1 on platforms where this makes time_t a 64-bit type. */
/* #undef __MINGW_USE_VC2005_COMPAT */

/* Define to __FUNCTION__ if your compiler supports __FUNCTION__ but not
   __func__ */
/* #undef __func__ */

/* Define to empty if 'const' does not conform to ANSI C. */
/* #undef const */

/* Define to 'int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to '__inline__' or '__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to an OS-specific initialization function or 'os_init_common'. */
#define os_init os_init_common

/* Define to 'unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to 'int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define to empty if the keyword 'volatile' does not work. Warning: valid
   code using 'volatile' can become incorrect without. Disable with care. */
/* #undef volatile */

/* Define C99 types if stdint.h and inttypes.h are missing. */
#if !defined(HAVE_STDINT_H) && !defined(HAVE_INTTYPES_H)
# ifndef HAVE_INT8_T
typedef char			int8_t;
# endif
# ifndef HAVE_UINT8_T
typedef	unsigned char		uint8_t;
# endif
# ifndef HAVE_INT16_T
typedef short			int16_t;
# endif
# ifndef HAVE_UINT16_T
typedef unsigned short		uint16_t;
# endif
# ifndef HAVE_INT32_T
typedef int			int32_t;
# endif
# ifndef HAVE_UINT32_T
typedef unsigned int		uint32_t;
# endif
# ifndef HAVE_INT64_T
typedef long long		int64_t;
# endif
# ifndef HAVE_UINT64_T
typedef unsigned long long	uint64_t;
# endif
# ifndef HAVE_INTMAX_T
typedef long long		intmax_t;
# endif
# ifndef HAVE_UINTMAX_T
typedef unsigned long long	uintmax_t;
# endif
#endif /* !HAVE_STDINT_H && !HAVE_INTTYPES_H */

#ifndef HAVE_SIG_ATOMIC_T
typedef int			sig_atomic_t;
#endif

#ifndef HAVE_SOCKLEN_T
typedef unsigned int		socklen_t;
#endif

#ifndef __GNUC_PREREQ__
# ifdef __GNUC__
#  define __GNUC_PREREQ__(ma, mi) \
	((__GNUC__ > (ma)) || (__GNUC__ == (ma) && __GNUC_MINOR__ >= (mi)))
# else
#  define __GNUC_PREREQ__(ma, mi)	0
# endif
#endif

/* Define away __attribute__ for non-gcc or old gcc. */
#if !defined(__attribute__) && !__GNUC_PREREQ__(2, 5)
# define __attribute__(x)
#endif

/* For functions that call exit() directly. */
#ifdef __has_c_attribute
# if __has_c_attribute(__noreturn__)
#  define sudo_noreturn		[[__noreturn__]]
# endif
#endif
#ifndef sudo_noreturn
# if __GNUC_PREREQ__(2, 5)
#  define sudo_noreturn		__attribute__((__noreturn__))
# else
#  define sudo_noreturn
# endif
#endif

/* For malloc-like functions that return uninitialized or zeroed memory. */
#if __GNUC_PREREQ__(2, 96)
# define sudo_malloclike	__attribute__((__malloc__))
#else
# define sudo_malloclike
#endif

/* Compile-time checking for function arguments that must not be NULL. */
#if __GNUC_PREREQ__(3, 3)
# define sudo_attr_nonnull(_a)	__attribute__((__nonnull__ (_a)))
#else
# define sudo_attr_nonnull(_a)
#endif

/* For catching format string mismatches. */
#if __GNUC_PREREQ__(2, 7)
# define sudo_printflike(_f, _v)	__attribute__((__format__ (__printf__, _f, _v))) sudo_attr_nonnull(_f)
# define sudo_printf0like(_f, _v)	__attribute__((__format__ (__printf__, _f, _v)))
# define sudo_attr_fmt_arg(_f)		__attribute__((__format_arg__ (_f)))
#else
# define sudo_printflike(_f, _v)
# define sudo_printf0like(_f, _v)
# define sudo_attr_fmt_arg(_f)
#endif

/* C23 defines a fallthrough attribute, gcc 7.0 and clang 10 have their own. */
#ifdef __has_c_attribute
# if __has_c_attribute(__fallthrough__)
# define FALLTHROUGH		[[__fallthrough__]]
# endif
#endif
#ifndef FALLTHROUGH
# if defined(HAVE_FALLTHROUGH_ATTRIBUTE)
#  define FALLTHROUGH		__attribute__((__fallthrough__))
# else
#  define FALLTHROUGH		do { } while (0)
# endif
#endif

/* Symbol visibility controls. */
#ifdef HAVE_DSO_VISIBILITY
# if defined(__GNUC__)
#  define sudo_dso_public __attribute__((__visibility__("default")))
# elif defined(__SUNPRO_C)
#  define sudo_dso_public __global
# else
#  define sudo_dso_public __declspec(dllexport)
# endif
#else
# define sudo_dso_public
#endif

/* BSD compatibility on some SVR4 systems. */
#ifdef __svr4__
# define BSD_COMP
#endif

/* Enable BSD extensions on systems that have them.  */
#ifndef _BSD_SOURCE
/* # undef _BSD_SOURCE */
#endif

/* Enable OpenBSD extensions on NetBSD.  */
#ifndef _OPENBSD_SOURCE
# define _OPENBSD_SOURCE 1
#endif

/* Enable BSD types on IRIX.  */
#ifndef _BSD_TYPES
/* # undef _BSD_TYPES */
#endif

/* Enable Linux-compatible extensions on AIX.  */
#ifndef _LINUX_SOURCE_COMPAT
/* # undef _LINUX_SOURCE_COMPAT */
#endif

/* Enable unlimited getgroups(2) support on macOS. */
#ifndef _DARWIN_UNLIMITED_GETGROUPS
/* # undef _DARWIN_UNLIMITED_GETGROUPS */
#endif

/* Enable prototypes in GCC fixed includes on older systems.  */
#ifndef __USE_FIXED_PROTOTYPES__
/* # undef __USE_FIXED_PROTOTYPES__ */
#endif

/* Enable XPG4v2 extensions to POSIX, needed for MSG_WAITALL on older HP-UX.  */
#ifndef _XOPEN_SOURCE_EXTENDED
/* # undef _XOPEN_SOURCE_EXTENDED */
#endif

/* Enable reentrant versions of the standard C API (obsolete).  */
#ifndef _REENTRANT
/* # undef _REENTRANT */
#endif

/* Enable "safer" versions of the standard C API (ISO C11).  */
#ifndef __STDC_WANT_LIB_EXT1__
/* # undef __STDC_WANT_LIB_EXT1__ */
#endif

/* Prevent static analyzers from genering bogus memory leak warnings. */
#if defined(__COVERITY__) && !defined(NO_LEAKS)
# define NO_LEAKS
#endif

#endif /* SUDO_CONFIG_H */
