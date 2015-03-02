#include "google/coredumper.h"
#include "corepoint.h"
#include "linux_syscall_support.h"
#include "linuxthreads.h"
#include "thread_lister.h"
#include <errno.h>
#include <stdlib.h>
#include <ucontext.h>

#ifdef COREPOINT_SUPPORTED

static const uint8_t kTrapInstruction = 0xCCU;
/* Fixed core point array, since we cannot call malloc from a signal handler,
 * 1024 should be far enough. */
#define kMaxCorePointCount ((size_t)1024UL)

struct CorePointDescription_t
{
    void* address; /* The real (non-aligned) address of the core point. */
    const char* fileName;
    const struct CoreDumpParameters* coreDumpParameters;
    uint8_t originalInstruction;
};

static struct CorePointDescription_t _corePoints[kMaxCorePointCount];
static size_t _corePointCount = 0;

static struct kernel_sigaction _defaultTrapSignalHandler;

/* Returns _corePointCount if the core point is not found. */
static size_t getCorePointIndex(void* iAddress)
{
    size_t i;

    for (i = 0; i < _corePointCount; ++i)
    {
        if (iAddress == _corePoints[i].address)
        {
            return i;
        }
    }

    return _corePointCount;
}

static void insertCorePoint(void* iAddress, const char* iFileName, const struct CoreDumpParameters* iCoreDumpParameters, uint8_t iOriginalInstruction)
{
    _corePoints[_corePointCount].address = iAddress;
    _corePoints[_corePointCount].fileName = iFileName;
    _corePoints[_corePointCount].coreDumpParameters = iCoreDumpParameters;
    _corePoints[_corePointCount].originalInstruction = iOriginalInstruction;
    ++_corePointCount;
}

static void removeCorePointAtIndex(size_t iIndex)
{
    /* We don't want a sparse array, and we don't
     * really care about the index order since all operations
     * are globally mutexed and atomic.
     */
    if (iIndex != _corePointCount - 1)
    {
        _corePoints[iIndex] = _corePoints[_corePointCount - 1];
    }

    --_corePointCount;
}

static uintptr_t align64BitsAddress(uintptr_t iAddress)
{
    return iAddress & (~(uintptr_t)(sizeof(void*) - 1));
}

/*
 * Read a quad word at iAlignedAddress and put it in oOutputData. Then
 * clobbers the process memory at iAlignedAddress with the content of
 * iInputData. Only the bits of iDataMask are get/set, the other bits
 * are set to 0 in oOutputData, and left unchanged in the process memory.
 * Return 0 if it fails, 1 otherwise.
 */
static int swapDataAtAlignedAddress(pid_t iPid, uintptr_t iAlignedAddress, uint64_t iInputData, uint64_t* oOutputData, uint64_t iDataMask)
{
    uint64_t aReadData;

    if (sys_ptrace(PTRACE_PEEKTEXT, iPid, (void*)iAlignedAddress, (void*)&aReadData))
    {
        return 0;
    }

    uint64_t aWriteData = (aReadData & (~iDataMask)) | (iInputData & iDataMask);

    if (sys_ptrace(PTRACE_POKETEXT, iPid, (void*)iAlignedAddress, (void*)aWriteData))
    {
        return 0;
    }

    *oOutputData = aReadData & iDataMask;

    return 1;
}

/*
 * Address don't need to be aligned here.
 * Return 0 if it fails, 1 otherwise.
 */
int swapByteAtAddress(pid_t iPid, uintptr_t iAddress, uint8_t iData, uint8_t* oData)
{
    uintptr_t aAlignedAddress = align64BitsAddress(iAddress);
    uint64_t aAddressOffsetInBits = (iAddress - aAlignedAddress) * 8;
    uint64_t aDataMask = ((uint64_t)0xFFUL) << aAddressOffsetInBits;
    uint64_t aInputData = ((uint64_t)iData) << aAddressOffsetInBits;
    uint64_t aOutputData;

    if (swapDataAtAlignedAddress(iPid, aAlignedAddress, aInputData, &aOutputData, aDataMask))
    {
        *oData = (uint8_t)(aOutputData >> aAddressOffsetInBits);

        return 1;
    }
    else
    {
        return 0;
    }
}

/*
 * While this is not guaranteed, we try hard to make this code work in a signal handler.
 *
 * This function is guaranteed *NOT* to be run concurrently.
 */
static int internalPutCorePointAt(void* iUnused __attribute__((unused)), int iThreadCount __attribute__((unused)), pid_t* iPids, va_list iVariableArguments)
{
    void* aCoreDumpAddress = va_arg(iVariableArguments, void*);
    const char* aFileName = va_arg(iVariableArguments, const char*);
    const struct CoreDumpParameters* aCoreDumpParameters = va_arg(iVariableArguments, const struct CoreDumpParameters*);

    uint8_t aOriginalInstruction;

    int aCorePointSet = swapByteAtAddress(iPids[0], (uintptr_t)aCoreDumpAddress, kTrapInstruction, &aOriginalInstruction);

    if (aCorePointSet)
    {
        /* The core point has been successfully added, put it in the array *BEFORE* resuming the threads. */
        insertCorePoint(aCoreDumpAddress, aFileName, aCoreDumpParameters, aOriginalInstruction);
    }

    return aCorePointSet ? 1 : -1;
}

static int internalDeleteCorePointAt(void* iUnused __attribute__((unused)), int iThreadCount __attribute__((unused)), pid_t* iPids, va_list iVariableArguments)
{
    size_t aCorePointIndex = va_arg(iVariableArguments, size_t);
    uint8_t aReadTrapInstruction;

    int aCorePointUnset = swapByteAtAddress(iPids[0], (uintptr_t)_corePoints[aCorePointIndex].address, _corePoints[aCorePointIndex].originalInstruction, &aReadTrapInstruction);

    if (aCorePointUnset)
    {
        /* Do this *BEFORE* resuming the threads. */
        removeCorePointAtIndex(aCorePointIndex);
    }

    return aCorePointUnset ? 1 : -1;
}

static int InternalGetCoreDumpProxy(void* iFrame, int iThreadCount, pid_t* iPids, ...)
{
    va_list aGetCoreDumpArguments;
    va_start(aGetCoreDumpArguments, iPids);

    int aReturnValue = InternalGetCoreDump(iFrame, iThreadCount, iPids, aGetCoreDumpArguments);

    va_end(aGetCoreDumpArguments);

    return aReturnValue;
}

static int writeCoreDumpAndDeleteCorePoint(void* iFrame, int iThreadCount, pid_t* iPids, va_list iVariableArguments)
{
    va_list aVariableArgumentsCopy;
    va_copy(aVariableArgumentsCopy, iVariableArguments);
    size_t aCorePointIndex = va_arg(aVariableArgumentsCopy, size_t);

    /* Save the core point data before removing it. */
    const char* aFileName = _corePoints[aCorePointIndex].fileName;
    const struct CoreDumpParameters* aCoreDumpParameters = _corePoints[aCorePointIndex].coreDumpParameters;

    /* Put back the correct instruction before dumping, so that we get correct data in gdb. */
    internalDeleteCorePointAt(NULL, iThreadCount, iPids, iVariableArguments);

    return InternalGetCoreDumpProxy(iFrame, iThreadCount, iPids, aCoreDumpParameters, aFileName, getenv("PATH"));
}

static int ListAllProcessThreadsLockedProxy(void* iFrame, ListAllProcessThreadsCallBack iCallback, ...)
{
    va_list aGetCoreDumpArguments;
    va_start(aGetCoreDumpArguments, iCallback);

    int aReturnValue = ListAllProcessThreadsLocked(iFrame, iCallback, aGetCoreDumpArguments);

    va_end(aGetCoreDumpArguments);

    return aReturnValue;
}

static void unregisterTrapSignalHandler();

/*
 * Handle traps. It looks for a registered core point at the faulty instruction address. If
 * one is found a core is dumped and the core point is removed so that the execution can start
 * again the normal execution path. In case of race conditions where 2 threads reaches the same
 * core point at the same time, only one will dump a core. However both will safely execute the
 * original instruction without issues. In the current implementation is not possible to put back
 * the corepoint after it was reached by one thread. That logic to put back the core point is far
 * more complicated to implement without race conditions with other threads, and is more the job
 * for a real debugger like gdb. Anyway, the goal of corepoints is to punctually dump a core in
 * order to investigate offline one exceptionnal program state, so ephemeral traps should be
 * enough.
 */
static void trapSignalHandler(int iSignal, siginfo_t* iSignalInfo __attribute__((unused)), void* ioVoidContext)
{
    FRAME_FROM_SIGNAL_HANDLER_SAVED_CONTEXT(aFrame, ioVoidContext);

    /* errno *MUST* be saved for the underlying code where the trap happened.
    we know it will be clobbered. */
    int aSavedErrno = errno;

    /* Prevent gcc from optimizing out the context pointer with "volatile", so that we can
     * easily access it in the generated core dump for analyzing the real context (ie registers)
     * at the moment the core point was reached. */
    volatile struct ucontext* aContext = (struct ucontext*)ioVoidContext;
    volatile struct kernel_sigcontext* aReturnRegisters = (struct kernel_sigcontext*)&aContext->uc_mcontext;

    if (iSignal == SIGTRAP)
    {
        /* $rip is set to the following instruction, so we have to move back from
         * from sizeof(trap instruction) = 1 byte. */
        void* aTrapInstructionAddress = (void*)(aReturnRegisters->rip - 1L);

        /* Move back $rip to the original instruction start. */
        aReturnRegisters->rip = (int64_t)aTrapInstructionAddress;

        if (FRAME_FROM_SIGNAL_HANDLER_SAVED_CONTEXT_IS_EXACT)
        {
            /* Also update the frame rip we will write in the core. */
            aFrame.uregs.rip = (int64_t)aTrapInstructionAddress;
        }

        LockGlobalMutex();

        /* Look for a registered core point. */
        size_t aCorePointIndex = getCorePointIndex(aTrapInstructionAddress);

        /* A registered core point has been found. */
        if (aCorePointIndex != _corePointCount)
        {
            ListAllProcessThreadsLockedProxy(&aFrame, &writeCoreDumpAndDeleteCorePoint, aCorePointIndex);

            if (_corePointCount == 0)
            {
                /* Better do this in this process, I don't know how it behaves if you make it from the local cloned thread. */
                unregisterTrapSignalHandler();
            }
        }
        /*
         * If no core point was found it likely means two threads reached
         * the same corepoint at the same time. The other thread dumped a core
         * so we just do nothing. When the signal handler returns, the original
         * instruction will already have been written back by the other thread,
         * so we will continue our flow normally.
         */

        UnlockGlobalMutex();
    }

    errno = aSavedErrno;
}

/* Return 0 if it fails, 1 otherwise. */
static int registerTrapSignalHandler()
{
    /* Here we can call the glibc signal related functions and note the one
     * redefined in linux_syscall_support.h because we are sure we launch that
     * in the original process and the ptracer thread is dead. */
    struct kernel_sigaction aTrapSignalConfiguration;
    memset(&aTrapSignalConfiguration, 0, sizeof(aTrapSignalConfiguration));
    aTrapSignalConfiguration.sa_sigaction_ = &trapSignalHandler;
    sys_sigfillset(&aTrapSignalConfiguration.sa_mask);
    aTrapSignalConfiguration.sa_flags = SA_SIGINFO;

    return sys_sigaction(SIGTRAP, &aTrapSignalConfiguration, &_defaultTrapSignalHandler) ? 0 : 1;
}

static void unregisterTrapSignalHandler()
{
    sys_sigaction(SIGTRAP, &_defaultTrapSignalHandler, NULL);
}

int Coredumper_PutCorePointAt(void* iAddress, const char* iFileName, const struct CoreDumpParameters* iParameters)
{
    struct CoreDumpParameters params;
    ClearCoreDumpParameters(&params);
    int aReturnValue = 0;

    LockGlobalMutex();

    size_t aCorePointIndex = getCorePointIndex(iAddress);

    /* Core point is not already set. */
    if (aCorePointIndex == _corePointCount)
    {
        if (_corePointCount != kMaxCorePointCount)
        {
            if (_corePointCount == 0)
            {
                /* Better do this in this process, I don't know how it behaves if you make it from the local cloned thread.
                 * Do this *BEFORE* we actually put the first trap. */
                if (!registerTrapSignalHandler())
                {
                    aReturnValue = -1;
                }
            }

            if (aReturnValue == 0)
            {
                aReturnValue = ListAllProcessThreadsLockedProxy(NULL, &internalPutCorePointAt, iAddress, iFileName, iParameters);

                if (_corePointCount == 0)
                {
                    /* Looks like we failed to add the first core point. */
                    unregisterTrapSignalHandler();
                }
            }
        }
        else
        {
            /* We don't have any room for more corepoints. */
            errno = ENOMEM;
            aReturnValue = -1;
        }
    }

    UnlockGlobalMutex();

    return aReturnValue;
}

int Coredumper_DeleteCorePointAt(void* iAddress)
{
    int aReturnValue = 0;

    LockGlobalMutex();

    size_t aCorePointIndex = getCorePointIndex(iAddress);

    /* Core point is already set. */
    if (aCorePointIndex != _corePointCount)
    {
        aReturnValue = ListAllProcessThreadsLockedProxy(NULL, &internalDeleteCorePointAt, aCorePointIndex);

        if (_corePointCount == 0)
        {
            /* Better do this in this process, I don't know how it behaves if you make it from the local cloned thread. */
            unregisterTrapSignalHandler();
        }
    }

    UnlockGlobalMutex();

    return aReturnValue;
}

int Coredumper_IsCorePointSet(void* iAddress)
{
    LockGlobalMutex();

    int aReturnValue = getCorePointIndex(iAddress) == _corePointCount ? 0 : 1;

    UnlockGlobalMutex();

    return aReturnValue;
}

size_t Coredumper_GetListOfCorePoints(size_t iAddressListLength, void** iAddressList)
{
    LockGlobalMutex();

    size_t aReturnValue = _corePointCount;
    size_t aMaxI = iAddressListLength < _corePointCount ? iAddressListLength : _corePointCount;
    size_t i;

    for (i = 0; i < aMaxI; ++i)
    {
        iAddressList[i] = _corePoints[i].address;
    }

    UnlockGlobalMutex();

    return aReturnValue;
}

size_t Coredumper_GetCorePointsCount()
{
    LockGlobalMutex();

    size_t aReturnValue = _corePointCount;

    UnlockGlobalMutex();

    return aReturnValue;
}

#else /* Core points are not supported. */

int Coredumper_PutCorePointAt(void* iAddress)
{
  errno = EINVAL;
  return -1;
}

int Coredumper_DeleteCorePointAt(void* iAddress)
{
  errno = EINVAL;
  return -1;
}

int Coredumper_IsCorePointSet(void* iAddress __attribute__((unused)))
{
    return 0;
}

size_t Coredumper_GetListOfCorePoints(size_t iAddressListLength __attribute__((unused)), void** iAddressList __attribute__((unused)))
{
    return 0;
}

size_t Coredumper_GetCorePointsCount()
{
    return 0;
}

#endif
