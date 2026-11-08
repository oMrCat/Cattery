// Compatibility shim for linking the prebuilt x64 Intel XED lib.
//
// xed2/lib/libxed_x64.lib was compiled against the VS2013 static CRT and
// references __iob_func(), which no longer exists in the UCRT. The only
// call site in the library obtains stderr as __iob_func() + 0x60 (the old
// FILE array layout is 3 entries of 0x30 bytes). Returning stderr-0x60
// makes that address the real UCRT stderr stream.
//
// This file is empty for Win32 builds, which keep using the original
// XEDParse.lib import library and do not pull in libxed objects.

#include <stdio.h>

#ifdef _WIN64

extern "C" FILE* __iob_func(void)
{
    return (FILE*)((char*)__acrt_iob_func(2) - 0x60);
}

#endif
