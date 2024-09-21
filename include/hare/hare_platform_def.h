
#ifndef __KRC_PLATFORM_DEF_H__
#define __KRC_PLATFORM_DEF_H__

// -------------------------------------------------------------------------- //
// Platform(OS) Detection
// -------------------------------------------------------------------------- //
#if defined(_WIN32) || defined(WIN32) || defined(__CYGWIN__)
#	define KG_OS_WIN32
#	define KG_OS_WINDOWS
#elif defined(_WIN64)
#   define KG_OS_WIN64
#	define KG_OS_WINDOWS
#elif defined(__WINDOWS__) // IBM VisualAge special handling
#	define KG_OS_WINDOWS
#	if defined(__32BIT__)
#		define KG_OS_WIN32
#	else
#		define KG_OS_WIN16
#		error "Unknown Support OS Planform - Win16!"
#	endif
#elif defined(__linux__) || defined(__LINUX__) || defined(LINUX) || defined(_LINUX)
#	define KG_OS_LINUX
#	define KG_OS_UNIX
#	if defined(__ANDROID__)
#		define KG_OS_ANDROID
#	endif
#elif defined(_AIX)
#	define KG_OS_AIX
#	define KG_OS_UNIX
#	if defined(_AIXVERSION_430)
#		define KG_OS_AIX43  // for use of POSIX compliant pthread functions
#	endif
#elif defined(_SEQUENT_)
#	define KG_OS_PTX
#	define KG_OS_UNIX
#elif defined(_HP_UX) || defined(__hpux) || defined(_HPUX_SOURCE)
#	define KG_OS_HPUX
#	define KG_OS_UNIX
#elif defined(SOLARIS) || defined(__SVR4)
#	define KG_OS_SOLARIS
#	define KG_OS_UNIX
#elif defined(_SCO_DS)
#	define KG_OS_OPENSERVER
#	define KG_OS_UNIX
#elif defined(__UNIXWARE__) || defined(__USLC__)
#	define KG_OS_UNIXWARE
#	define KG_OS_UNIX
#elif defined(__FreeBSD__)
#	define KG_OS_FREEBSD
#	define KG_OS_UNIX
#elif defined(IRIX) || defined(__sgi)
#	define KG_OS_IRIX
#	define KG_OS_UNIX
#elif defined(__MVS__) || defined(EXM_OS390)
#	define KG_OS_OS390
#	define KG_OS_UNIX
#elif defined(__OS400__)
#	define KG_OS_AS400
#	define KG_OS_UNIX
#elif defined(__OS2__)
#	define KG_OS_OS2
#elif defined(__TANDEM)
#	define KG_OS_TANDEM
#	define KG_OS_UNIX
#	define KG_OS_CSET
#elif defined(__MSDX_OS__)
#	define KG_OS_DOS
#elif defined(__APPLE__) && defined(__MACH__)
#	define KG_OS_MACOS
#	define KG_OS_UNIX
#	include <TargetConditionals.h>
#	if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#		define KG_OS_IOS
#	elif defined(TARGET_OS_MAC) && TARGET_OS_MAC
#		define KG_OS_MACOSX
#	endif
#elif defined(__alpha) && defined(__osf__)
#	define KG_OS_TRU64
#else
#	error "Unknown OS Planform!!!"
#endif

#ifdef __LP64__
#	define KG_BIT_64
#else
#	define KG_BIT_32
#endif

#ifdef KG_BIT_64
#define _MTHREAD64
#endif


 // -------------------------------------------------------------------------- //
 // Platform(Compiler) Detection
 // -------------------------------------------------------------------------- //
#if defined(__BORLANDC__)
#	define KG_CC_BC
#	define KG_CC_BCB
#	if defined(SYSMAC_H)
#		define KG_BCB_USECLX
#	endif
#elif defined(_MSC_VER)
#	define KG_CC_VC
#elif defined(__GNUG__) || defined(__GNUC__)
#	define KG_CC_GCC
#	if defined(__clang__)
#		define KG_CC_CLANG
#	endif
#elif defined(__xlC__)
#	define KG_CC_CSET
#elif defined(KG_OS_SOLARIS)
#	if defined(__SUNPRO_CC) && (__SUNPRO_CC >=0x500)
#		define KG_CC_SUNCC5
#	elif defined(__SUNPRO_CC) && (__SUNPRO_CC <0x500)
#		define KG_CC_SUNCC
#	elif defined(_EDG_RUNTIME_USES_NAMESPACES)
#		define KG_CC_SOLARIS_KAICC
#	elif defined(__GNUG__)
#		define KG_CC_GCC
#	else
#		error "Unknown C/C++ Compiler!!!"
#	endif
#elif defined(KG_OS_HPUX)
#	if defined(EXM_HPUX)
#		define KG_CC_HPUX_KAICC
#	elif (__cplusplus == 1)
#		define KG_CC_HPUX_CC
#	elif (__cplusplus == 199707 || __cplusplus == 199711)
#		define KG_CC_HPUX_ACC
#	endif
#elif defined(KG_OS_IRIX)
#	define KG_CC_MIPSPRO_CC
#elif defined(KG_OS_PTX)
#	define KG_CC_PTX_CC
#elif defined(KG_OS_TANDEM)
#	define KG_CC_TANDEMCC
#elif defined(KG_OS_OS390) && defined(__cplusplus)
#	define KG_CC_MVSCPP
#elif defined(__IBMC__) || defined(__IBMCPP__)
#	if defined(KG_OS_WIN32)
#		define KG_CC_IBMVAW32
#	elif defined(KG_CC_OS2)
#		define KG_CC_IBMVAOS2
#		if (__IBMC__ >= 400 || __IBMCPP__ >= 400)
#			define KG_CC_IBMVA4_OS2
#		endif
#	endif
#elif defined(KG_OS_TRU64) && defined(__DECCXX)
#	define KG_CC_DECCXX
#elif defined(__MWERKS__)
#	define KG_CC_METROWERKS
#elif defined(__clang__)
#	define KG_CC_GCC
#	define KG_CC_CLANG
#else
#	error "Unknown C/C++ Compiler!!!"
#endif

#if defined(__MT__) && !defined(_MT)
#   define _MT
#endif

 // -------------------------------------------------------------------------- //
 // CPU Detection
 // -------------------------------------------------------------------------- //
#if defined(__SPARC__) || defined(SPARC) || defined(_SPARC)
#	define KG_CPU_SPARC
#	undef  BYTESWAP
#	define BYTESWAP
#elif defined(_M_IX86) || defined(__i386__)
#	define KG_CPU_X86
#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_X64) || defined(_M_IA64) || defined(_M_AMD64)
#	define KG_CPU_X86_64
#elif defined(__mips__) || defined(mips) || defined (_mips) || (__mips)
#	define KG_CPU_MIPS
#elif defined(__arm__) || defined(_ARM_) || defined(__aarch__)
#	define KG_CPU_ARM
#elif defined(__arm64__) || defined(__aarch64__) || defined(__loongarch64)
#	define KG_CPU_ARM_64
#elif defined(__sw_64__)
#	define KG_CPU_SW_64
#else
#	error "Unknown CPU Arch!!!"
#endif

#if defined(BYTESWAP)
#	undef  __BYTESWAP__
#	define __BYTESWAP__
#endif

 // -------------------------------------------------------------------------- //
 // Unicode-Character Encoding Detection
 // -------------------------------------------------------------------------- //
#if defined(KG_OS_WINDOWS)
#	define KG_ENCODE_UCS2
#elif defined(KG_OS_LINUX)
#	if defined(KG_CC_BC)
#		define KG_ENCODE_UCS4
#	elif defined(KG_CC_GCC)
#		define KG_ENCODE_UCS4
#	else
#		error "Unknown Unicode-Character Encoding!!!"
#	endif
#elif defined(KG_OS_FREEBSD)
#	define KG_ENCODE_UCS4
#elif defined(KG_OS_MACOS)
#	define KG_ENCODE_UCS4
#else
#	error "Unknown Unicode-Character Encoding!!!"
#endif

 // -------------------------------------------------------------------------- //
 // Module-Type Detection
 // -------------------------------------------------------------------------- //
#if defined(_LIB) || defined(__LIB__)
#	define KG_APPTYPE_LIB
#elif defined(_USRDLL) || defined(__DLL__)
#	define KG_APPTYPE_DLL
#elif defined(_CONSOLE) || defined(__CONSOLE__)
#	define KG_APPTYPE_CONSOLE
#elif defined(_WINDOWS)
#	define KG_APPTYPE_WINDOWS
#else
#	define KG_APPTYPE_UNKNOWN
#endif


#endif //__KRC_PLATFORM_DEF_H__
