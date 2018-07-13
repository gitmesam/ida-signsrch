
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0601 // _WIN32_WINNT_WIN7
#define _WIN32_WINNT 0x0601
#define _WIN32_WINDOWS 0x0601
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#include <math.h>
#include <float.h>
#include <crtdbg.h>
#include <mmsystem.h>
#include <Psapi.h>
#include <intrin.h>

#include <new>
#include <vector>
#include <algorithm>

#pragma intrinsic(memset, memcmp, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos, _rotl)

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#define NO_OBSOLETE_FUNCS
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#pragma warning(pop)

#include "Utility.h"

// Helper in replacing the old custom allocators
template <typename _Ty> _Ty *TAlloc(size_t Elements) { return((_Ty *) malloc(Elements * sizeof(_Ty))); }
template <typename _Ty> _Ty *TRealloc(_Ty *lpMem, size_t Elements) { return((_Ty *) realloc((PVOID) lpMem, Elements * sizeof(_Ty))); }

#define XML_STATIC 1
#include <expat.h>

#define MY_VERSION MAKEWORD(6, 1) // Low, high, convention: 0 to 99

