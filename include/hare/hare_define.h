
#ifndef __HARE_DEFINE_H__
#define __HARE_DEFINE_H__


#include <ctype.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARE_API
#if defined(_WIN32)
	#include <Windows.h>

	#pragma warning(disable:4290)
	#pragma warning(disable:4244)

  #if defined(_WIN32)
		#ifdef HARE_DLL_EXPORT
			#define HARE_API __declspec(dllexport)
		#else
//			#define HARE_API __declspec(dllimport)
			#define HARE_API
		#endif

		#define HARE_DFAPI __stdcall
	#else
		#define HARE_DFAPI __fastcall
		#define HARE_API
	#endif

#else
	#if defined (__GNUC__)
		#define HARE_API __attribute__((visibility("default")))
		#define HARE_DFAPI
	#else
		#define HARE_API
		#define HARE_DFAPI
	#endif
#endif //_WINDOWS
#endif

#define HARE_FUNCTION HARE_API


#if defined(_WIN32)
#include <windows.h>
#define HARE_MAX_PATH MAX_PATH
#else
#if defined(__linux__) || defined(__LINUX__) || defined(LINUX) || defined(_LINUX)
#include <linux/limits.h>
#define HARE_MAX_PATH PATH_MAX
#else
#include <limits.h>
#define HARE_MAX_PATH PATH_MAX
#endif
#endif


#endif //__HARE_DEFINE_H__
