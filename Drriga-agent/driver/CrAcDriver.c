//
// CrAcDriver.c
//
// Bu dosya bir WDK (Windows Driver Kit) projesi içinde, gerçek bir
// Windows makinesinde Visual Studio + WDK ile derlenmelidir. Bu ortamda
// (Linux konteyner, ağ erişimi yok) derlenip test edilmesi mümkün değildir.
// Aşağıdaki kod gerçek DDI (Driver Development Interface) imzalarına
// göre yazılmıştır ancak WDK test ortamında doğrulanmadan production'a
// (özellikle test-signing/attestation-signing gerektiren bir sürücü
// olarak) ALINMAMALIDIR.
//
// Gerekli:
//   - Windows Driver Kit (WDK) + Visual Studio
//   - Test-signing modu (geliştirme) veya EV sertifikalı attestation
//     signing (production; Microsoft'un WHQL/HLK sürecinden geçmeli)
//   - HMAC doğrulaması için bcrypt.lib (BCrypt CNG API'leri)
//

#include "CrAcDriver.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

DRIVER_CONTEXT g_DriverContext = { 0 };

//
// DriverEntry: sürücü yüklendiğinde çağrılır.
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING deviceName, symLinkName;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = CrAcCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = CrAcCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CrAcDeviceControl;
    DriverObject->DriverUnload                          = CrAcUnload;

    InitializeListHead(&g_DriverContext.ProtectedProcesses);
    KeInitializeSpinLock(&g_DriverContext.ProtectedListLock);

    // ⚠️ HmacKey burada SIFIR olarak bırakıldı — gerçek dağıtımda bu
    // anahtar imzalı bir provisioning paketinden veya TPM-sealed bir
    // storage'dan yüklenmeli. Sıfır anahtarla HMAC doğrulaması GÜVENSİZDİR.
    RtlZeroMemory(g_DriverContext.HmacKey, sizeof(g_DriverContext.HmacKey));
    g_DriverContext.IntegrityOk = TRUE;

    // Process handle açma isteklerini filtrelemek için ObRegisterCallbacks.
    // Bu, korunan process'lere PROCESS_TERMINATE / PROCESS_VM_WRITE gibi
    // hakların diğer (whitelist dışı) process'ler tarafından alınmasını
    // engellemek için kullanılır.
    OB_OPERATION_REGISTRATION operations[1] = { 0 };
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = CrAcPreOperationCallback;
    operations[0].PostOperation = NULL;

    OB_CALLBACK_REGISTRATION registration = { 0 };
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&registration.Altitude, L"420000"); // dokümante edilmiş bir aralıktan seçilmeli
    registration.RegistrationContext = NULL;
    registration.OperationRegistration = operations;

    status = ObRegisterCallbacks(&registration, &g_DriverContext.RegistrationHandle);
    if (!NT_SUCCESS(status)) {
        // ObRegisterCallbacks başarısız olsa bile IOCTL kanalı çalışmaya
        // devam edebilir; ama process protection devre dışı kalır.
        // Bunu telemetry ile üst katmana bildiriyoruz (IOCTL_QUERY_INTEGRITY
        // üzerinden okunabilir hale getirilebilir).
        g_DriverContext.IntegrityOk = FALSE;
    }

    return STATUS_SUCCESS;
}

VOID
CrAcUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLinkName);

    if (g_DriverContext.RegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_DriverContext.RegistrationHandle);
    }

    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS
CrAcCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

//
// HMAC-SHA256 doğrulaması (BCrypt CNG API'leri ile).
// user-mode tarafındaki src/driver_comm.rs::protect_process ile
// aynı algoritma: HMAC(key, pid_le_bytes || nonce).
//
NTSTATUS
CrAcVerifyHmac(
    _In_ PPROTECT_PROCESS_REQUEST Request
)
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR computedHmac[32] = { 0 };
    ULONG resultLength = 0;

    status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptCreateHash(
        hAlg, &hHash,
        NULL, 0,
        g_DriverContext.HmacKey, sizeof(g_DriverContext.HmacKey),
        0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return status;
    }

    BCryptHashData(hHash, (PUCHAR)&Request->Pid, sizeof(Request->Pid), 0);
    BCryptHashData(hHash, (PUCHAR)Request->Nonce, sizeof(Request->Nonce), 0);
    BCryptFinishHash(hHash, computedHmac, sizeof(computedHmac), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Sabit zamanlı karşılaştırma — timing side-channel'ı önlemek için
    // erken çıkışlı memcmp yerine RtlEqualMemory KULLANMA (o da erken
    // çıkabilir); elle sabit-zaman XOR-accumulate kullanıyoruz.
    UCHAR diff = 0;
    for (ULONG i = 0; i < sizeof(computedHmac); i++) {
        diff |= computedHmac[i] ^ Request->Hmac[i];
    }

    return (diff == 0) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

NTSTATUS
CrAcDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_PROTECT_PROCESS: {
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(PROTECT_PROCESS_REQUEST) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PPROTECT_PROCESS_REQUEST request =
            (PPROTECT_PROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        NTSTATUS hmacStatus = CrAcVerifyHmac(request);
        PULONG response = (PULONG)Irp->AssociatedIrp.SystemBuffer;

        if (!NT_SUCCESS(hmacStatus)) {
            *response = 0;
            information = sizeof(ULONG);
            status = STATUS_SUCCESS; // IOCTL'in kendisi başarılı, auth reddedildi
            break;
        }

        // PID'yi doğrula (var mı, çağıran process'in kendisi mi vs. —
        // gerçek uygulamada PsLookupProcessByProcessId ile kontrol edilmeli)
        PPROTECTED_PROCESS_ENTRY entry =
            (PPROTECTED_PROCESS_ENTRY)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(PROTECTED_PROCESS_ENTRY), 'ACrC');

        if (entry == NULL) {
            *response = 0;
            information = sizeof(ULONG);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        entry->Pid = (HANDLE)(ULONG_PTR)request->Pid;

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DriverContext.ProtectedListLock, &oldIrql);
        InsertTailList(&g_DriverContext.ProtectedProcesses, &entry->ListEntry);
        KeReleaseSpinLock(&g_DriverContext.ProtectedListLock, oldIrql);

        *response = 1;
        information = sizeof(ULONG);
        break;
    }

    case IOCTL_QUERY_INTEGRITY: {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PULONG response = (PULONG)Irp->AssociatedIrp.SystemBuffer;
        *response = CrAcCheckSelfIntegrity() ? 1 : 0;
        information = sizeof(ULONG);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

//
// Kendi .text section'ının hash'ini önceden hesaplanmış bir referansla
// karşılaştırır. İhlal durumunda BUGCHECK YAPILMAZ — sadece flag set edilir.
//
BOOLEAN
CrAcCheckSelfIntegrity(VOID)
{
    // TODO: gerçek implementasyon:
    //   1) Driver'ın PE header'ından .text section RVA + boyutunu al
    //   2) Bu bölgenin SHA256'sını hesapla
    //   3) Derleme zamanında gömülen referans hash ile karşılaştır
    // Basitleştirme: mevcut bayrağı döndürüyoruz (ObRegisterCallbacks
    // başarısız olduysa DriverEntry içinde FALSE set edilmişti).
    return g_DriverContext.IntegrityOk;
}

//
// Korunan bir process'e diğer process'lerden PROCESS_TERMINATE /
// PROCESS_VM_WRITE / PROCESS_VM_OPERATION gibi tehlikeli haklarla handle
// açılmasını engeller. Kendi süreci (self) ve sistem süreçleri (PID 4)
// için istisna tanınmalı.
//
OB_PREOP_CALLBACK_STATUS
CrAcPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);

    BOOLEAN isProtected = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectedListLock, &oldIrql);
    for (PLIST_ENTRY entry = g_DriverContext.ProtectedProcesses.Flink;
         entry != &g_DriverContext.ProtectedProcesses;
         entry = entry->Flink) {
        PPROTECTED_PROCESS_ENTRY p = CONTAINING_RECORD(entry, PROTECTED_PROCESS_ENTRY, ListEntry);
        if (p->Pid == targetPid) {
            isProtected = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_DriverContext.ProtectedListLock, oldIrql);

    if (!isProtected) {
        return OB_PREOP_SUCCESS;
    }

    // Çağıranın kendisi (self-open) her zaman izinli olmalı.
    if (PsGetCurrentProcessId() == targetPid) {
        return OB_PREOP_SUCCESS;
    }

    const ACCESS_MASK DANGEROUS_RIGHTS =
        PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
            ~DANGEROUS_RIGHTS;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
            ~DANGEROUS_RIGHTS;
    }

    return OB_PREOP_SUCCESS;
}
