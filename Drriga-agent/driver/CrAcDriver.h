#pragma once
#include <ntddk.h>
#include <wdf.h>

//
// IOCTL kodları — src/driver_comm.rs içindeki değerlerle BİREBİR aynı olmalı.
//
#define IOCTL_PROTECT_PROCESS \
    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUERY_INTEGRITY \
    CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DEVICE_NAME      L"\\Device\\CrAcDriver"
#define SYMLINK_NAME     L"\\DosDevices\\CrAcDriver"   // user-mode: \\.\CrAcDriver

#pragma pack(push, 1)
typedef struct _PROTECT_PROCESS_REQUEST {
    ULONG Pid;
    UCHAR Nonce[16];
    UCHAR Hmac[32];
} PROTECT_PROCESS_REQUEST, *PPROTECT_PROCESS_REQUEST;
#pragma pack(pop)

//
// Global durum
//
typedef struct _DRIVER_CONTEXT {
    UCHAR HmacKey[32];              // provisioning sırasında set edilir
    BOOLEAN IntegrityOk;            // periyodik self-check sonucu
    PVOID RegistrationHandle;       // ObRegisterCallbacks handle'ı
    LIST_ENTRY ProtectedProcesses;  // korunan PID listesi
    KSPIN_LOCK ProtectedListLock;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

extern DRIVER_CONTEXT g_DriverContext;

typedef struct _PROTECTED_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE Pid;
} PROTECTED_PROCESS_ENTRY, *PPROTECTED_PROCESS_ENTRY;

//
// Fonksiyon prototipleri
//
DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH CrAcCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH CrAcDeviceControl;

DRIVER_UNLOAD CrAcUnload;

NTSTATUS CrAcVerifyHmac(
    _In_ PPROTECT_PROCESS_REQUEST Request
);

OB_PREOP_CALLBACK_STATUS CrAcPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

VOID CrAcIntegrityCheckTimer(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

BOOLEAN CrAcCheckSelfIntegrity(VOID);
