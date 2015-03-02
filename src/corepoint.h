#ifndef _COREPOINT_H
#define _COREPOINT_H

#include "elfcore.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * __x86_64__: The implementation is clearly x64 specific (trap instruction and sizes are
 * hardcoded), however porting to other arch should be straightforward.
 * __linux__: Obviously, as ptrace is used.
 */
#if defined(__x86_64__) && defined(__linux)

#define COREPOINT_SUPPORTED

#endif

int Coredumper_PutCorePointAt(void* iAddress, const char* iFileName, const struct CoreDumpParameters* iParameters);
int Coredumper_DeleteCorePointAt(void* iAddress);
int Coredumper_IsCorePointSet(void* iAddress);
size_t Coredumper_GetListOfCorePoints(size_t iAddressListLength, void** iAddressList);
size_t Coredumper_GetCorePointsCount();

#ifdef __cplusplus
}

#endif
#endif
