// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <tchar.h>
#include <math.h>
#include <crtdbg.h>
#include <intrin.h>

#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos)


// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#pragma warning(push)
#pragma warning(disable:4267) // "conversion from 'size_t' to 'xxx', possible loss of data"
#include <typeinf.hpp>
#pragma warning(pop)
#include <struct.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#include <hexrays.hpp>

#include <unordered_set>
#include <unordered_map>

#include "wrap.h"
#include "Utility.h"
#include "undname.h"
#include "Vftable.h"
#include "RTTI.h"

#pragma comment(lib, "ida.lib")
#pragma comment(lib, "pro.lib")

typedef qlist<ea_t> eaList;
typedef std::unordered_set<ea_t> eaSet;
typedef std::unordered_map<ea_t, UINT> eaRefMap;
struct earef
{
	ea_t ea;
	UINT refs;
};
typedef qlist<earef> eaRefList;

// Get IDA 32 bit value with verification
template <class T> BOOL getVerify32_t(ea_t eaPtr, T &rValue)
{
	// Location valid?
	if (isLoaded(eaPtr))
	{
		// Get 32bit value
		rValue = (T)get_32bit(eaPtr);
		return(TRUE);
	}

	return(FALSE);
}

// Get address/pointer value
inline ea_t getEa(ea_t ea)
{
#ifndef __EA64__
	return((ea_t)get_32bit(ea));
#else
	return((ea_t)get_64bit(ea));
#endif
}


// Returns TRUE if ea_t sized value flags
inline BOOL isEa(flags_t f)
{
#ifndef __EA64__
	return(isDwrd(f));
#else
	return(isQwrd(f));
#endif
}


#define STYLE_PATH ":/classinf/"
#define MY_VERSION MAKEWORD(2, 2) // Low, high, convention: 0 to 99