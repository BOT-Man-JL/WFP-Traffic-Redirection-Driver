/*++

  Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Inspect\Parameters
    - LocalRealAddress
    - LocalFakeAddress
    - RemoteRealAddress
    - RemoteFakeAddress
    - LocalRealPort
    - LocalFakePort
    - RemoteRealPort
    - RemoteFakePort
    - LocalEthernetAddress
    - RemoteEthernetAddress
    * Setting `0.0.0.0` or `0` to disable modification

--*/

#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#include "inspect.h"

#define INITGUID
#include <guiddef.h>


// 
// Configurable parameters
//

IN_ADDR localAddrReal;
IN_ADDR localAddrFake;
IN_ADDR remoteAddrReal;
IN_ADDR remoteAddrFake;
UINT16 localPortReal;
UINT16 localPortFake;
UINT16 remotePortReal;
UINT16 remotePortFake;
BYTE localEthernetAddress[6];
BYTE remoteEthernetAddress[6];

// 
// Callout and sublayer GUIDs
//

// bb6e405b-19f4-4ff3-b501-1a3dc01aae01
DEFINE_GUID(
    TL_INSPECT_OUTBOUND_NETWORK_CALLOUT_V4,
    0xbb6e405b,
    0x19f4,
    0x4ff3,
    0xb5, 0x01, 0x1a, 0x3d, 0xc0, 0x1a, 0xae, 0x01
);
// 07248379-248b-4e49-bf07-24d99d52f8d0
DEFINE_GUID(
    TL_INSPECT_INBOUND_NETWORK_CALLOUT_V4,
    0x07248379,
    0x248b,
    0x4e49,
    0xbf, 0x07, 0x24, 0xd9, 0x9d, 0x52, 0xf8, 0xd0
);
// cabf7559-7c60-46c8-9d3b-2155ad5cf83f
DEFINE_GUID(
    TL_INSPECT_OUTBOUND_ETHERNET_CALLOUT,
    0xcabf7559,
    0x7c60,
    0x46c8,
    0x9d, 0x3b, 0x21, 0x55, 0xad, 0x5c, 0xf8, 0x3f
);
// 6d126434-ed67-4285-925c-cb29282e0e06
DEFINE_GUID(
    TL_INSPECT_INBOUND_ETHERNET_CALLOUT,
    0x6d126434,
    0xed67,
    0x4285,
    0x92, 0x5c, 0xcb, 0x29, 0x28, 0x2e, 0x0e, 0x06
);

// 76b743d4-1249-4614-a632-6f9c4d08d25a
DEFINE_GUID(
    TL_INSPECT_TEMP_CALLOUT_1,
    0x76b743d4,
    0x1249,
    0x4614,
    0xa6, 0x32, 0x6f, 0x9c, 0x4d, 0x08, 0xd2, 0x5a
);

// ac80683a-5b84-43c3-8ae9-eddb5c0d23c2
DEFINE_GUID(
    TL_INSPECT_TEMP_CALLOUT_2,
    0xac80683a,
    0x5b84,
    0x43c3,
    0x8a, 0xe9, 0xed, 0xdb, 0x5c, 0x0d, 0x23, 0xc2
);

// 2e207682-d95f-4525-b966-969f26587f03
DEFINE_GUID(
    TL_INSPECT_SUBLAYER,
    0x2e207682,
    0xd95f,
    0x4525,
    0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);

// 
// Callout driver global variables
//

DEVICE_OBJECT* gWdmDevice;
WDFKEY gParametersKey;

HANDLE gEngineHandle;

UINT32 gOutboundNetworkCalloutId;
UINT32 gInboundNetworkCalloutId;
UINT32 gOutboundEthernetCalloutId;
UINT32 gInboundEthernetCalloutId;
UINT32 gTempCalloutId1;
UINT32 gTempCalloutId2;

HANDLE gInjectionHandleNetwork;
HANDLE gInjectionHandleEthernet;

PNDIS_GENERIC_OBJECT gNdisHandle;
NDIS_HANDLE gNblPoolHandle;
NDIS_HANDLE gNbPoolHandle;

LIST_ENTRY gPacketQueue;
LIST_ENTRY gFrameQueue;
KSPIN_LOCK gQueueLock;

KEVENT gWorkerEvent;

BOOLEAN gDriverUnloading = FALSE;
void* gThreadObj;

// 
// Callout driver implementation
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD TLInspectEvtDriverUnload;

NTSTATUS
TLInspectReadEthernetAddressFromKey(
    _In_ const WDFKEY key,
    _In_ PCUNICODE_STRING valueName,
    _Out_ BYTE *addrStorage
)
{
    NTSTATUS status;
    PWSTR terminator;

    DECLARE_UNICODE_STRING_SIZE(value, INET6_ADDRSTRLEN);

    status = WdfRegistryQueryUnicodeString(key, valueName, NULL, &value);
    if (!NT_SUCCESS(status))
        return status;

    value.Length = min(value.Length, value.MaximumLength - sizeof(WCHAR));
    value.Buffer[value.Length / sizeof(WCHAR)] = UNICODE_NULL;

    DbgPrint("  %S: %S\n", valueName->Buffer, value.Buffer);

    status = RtlEthernetStringToAddressW(
        value.Buffer,
        &terminator,
        (DL_EUI48 *)addrStorage
    );

    return status;
}

NTSTATUS
TLInspectReadAddressFromKey(
    _In_ const WDFKEY key,
    _In_ PCUNICODE_STRING valueName,
    _Out_ IN_ADDR *addrStorage
)
{
    NTSTATUS status;
    PWSTR terminator;

    DECLARE_UNICODE_STRING_SIZE(value, INET6_ADDRSTRLEN);

    status = WdfRegistryQueryUnicodeString(key, valueName, NULL, &value);
    if (!NT_SUCCESS(status))
        return status;

    value.Length = min(value.Length, value.MaximumLength - sizeof(WCHAR));
    value.Buffer[value.Length / sizeof(WCHAR)] = UNICODE_NULL;

    DbgPrint("  %S: %S\n", valueName->Buffer, value.Buffer);

    status = RtlIpv4StringToAddressW(
        value.Buffer,
        TRUE,
        &terminator,
        addrStorage
    );

    return status;
}

NTSTATUS
TLInspectReadPortFromKey(
    _In_ const WDFKEY key,
    _In_ PCUNICODE_STRING valueName,
    _Out_ UINT16 *port
)
{
    NTSTATUS status;
    ULONG ulongValue;

    status = WdfRegistryQueryULong(key, valueName, &ulongValue);
    if (!NT_SUCCESS(status))
        return status;

    DbgPrint("  %S: %u\n", valueName->Buffer, ulongValue);

    *port = (UINT16)ulongValue;
    *port = RtlUshortByteSwap(*port);

    return status;
}

NTSTATUS
TLInspectLoadConfig(
    _In_ const WDFKEY key
)
{
    NTSTATUS status;

    DECLARE_CONST_UNICODE_STRING(strLocalRealAddress, L"LocalRealAddress");
    DECLARE_CONST_UNICODE_STRING(strLocalFakeAddress, L"LocalFakeAddress");
    DECLARE_CONST_UNICODE_STRING(strRemoteRealAddress, L"RemoteRealAddress");
    DECLARE_CONST_UNICODE_STRING(strRemoteFakeAddress, L"RemoteFakeAddress");
    DECLARE_CONST_UNICODE_STRING(strLocalRealPort, L"LocalRealPort");
    DECLARE_CONST_UNICODE_STRING(strLocalFakePort, L"LocalFakePort");
    DECLARE_CONST_UNICODE_STRING(strRemoteRealPort, L"RemoteRealPort");
    DECLARE_CONST_UNICODE_STRING(strRemoteFakePort, L"RemoteFakePort");
    DECLARE_CONST_UNICODE_STRING(strLocalEthernetAddress, L"LocalEthernetAddress");
    DECLARE_CONST_UNICODE_STRING(strRemoteEthernetAddress, L"RemoteEthernetAddress");

    // Address

    status = TLInspectReadAddressFromKey(
        key,
        &strLocalRealAddress,
        &localAddrReal
    );
    if (!NT_SUCCESS(status))
        return status;

    status = TLInspectReadAddressFromKey(
        key,
        &strLocalFakeAddress,
        &localAddrFake
    );
    if (!NT_SUCCESS(status))
        return status;

    status = TLInspectReadAddressFromKey(
        key,
        &strRemoteRealAddress,
        &remoteAddrReal
    );
    if (!NT_SUCCESS(status))
        return status;

    status = TLInspectReadAddressFromKey(
        key,
        &strRemoteFakeAddress,
        &remoteAddrFake
    );
    if (!NT_SUCCESS(status))
        return status;

    // Port

    status = TLInspectReadPortFromKey(
        key,
        &strLocalRealPort,
        &localPortReal
    );
    if (!NT_SUCCESS(status))
        return status;

    status = TLInspectReadPortFromKey(
        key,
        &strLocalFakePort,
        &localPortFake
    );
    if (!NT_SUCCESS(status))
        return status;

    status = TLInspectReadPortFromKey(
        key,
        &strRemoteRealPort,
        &remotePortReal
    );
    if (!NT_SUCCESS(status))
        return status;

    status = TLInspectReadPortFromKey(
        key,
        &strRemoteFakePort,
        &remotePortFake
    );
    if (!NT_SUCCESS(status))
        return status;

    // Ethernet Address

    status = TLInspectReadEthernetAddressFromKey(
        key,
        &strLocalEthernetAddress,
        localEthernetAddress
    );
    if (!NT_SUCCESS(status))
        return status;

    status = TLInspectReadEthernetAddressFromKey(
        key,
        &strRemoteEthernetAddress,
        remoteEthernetAddress
    );
    if (!NT_SUCCESS(status))
        return status;

    return status;
}

NTSTATUS
TLInspectAddFilter(
    _In_ wchar_t* filterName,
    _In_ FWPM_FILTER_CONDITION *filterConditions,
    _In_ UINT numFilterConditions,
    _In_ UINT64 context,
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_FILTER filter = { 0 };

    filter.layerKey = *layerKey;
    filter.subLayerKey = TL_INSPECT_SUBLAYER;  // global

    filter.displayData.name = filterName;
    filter.displayData.description = filterName;

    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *calloutKey;
    filter.weight.type = FWP_EMPTY; // auto-weight.
    filter.rawContext = context;

    filter.filterCondition = filterConditions;
    filter.numFilterConditions = numFilterConditions;

    status = FwpmFilterAdd(
        gEngineHandle,
        &filter,
        NULL,
        NULL);

    return status;
}

NTSTATUS
TLInspectAddSCallout(
    _In_ const GUID* calloutKey,
    _Inout_ void* deviceObject,
    _Out_ UINT32* calloutId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPS_CALLOUT sCallout = { 0 };

    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = TLInspectClassify;
    sCallout.notifyFn = TLInspectNotify;

    status = FwpsCalloutRegister(
        deviceObject,
        &sCallout,
        calloutId
    );

    return status;
}

NTSTATUS
TLInspectAddMCallout(
    _In_ wchar_t* calloutName,
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_CALLOUT mCallout = { 0 };

    mCallout.calloutKey = *calloutKey;
    mCallout.displayData.name = calloutName;
    mCallout.displayData.description = calloutName;
    mCallout.applicableLayer = *layerKey;

    status = FwpmCalloutAdd(
        gEngineHandle,
        &mCallout,
        NULL,
        NULL
    );

    return status;
}

NTSTATUS
TLInspectRegisterCalloutAndFilter(
    _In_ wchar_t* calloutName,
    _In_ const GUID* layerKey,
    _In_ const GUID* calloutKey,
    _In_ FWPM_FILTER_CONDITION *filterConditions,
    _In_ UINT numFilterConditions,
    _Inout_ void* deviceObject,
    _Out_ UINT32* calloutId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN calloutRegistered = FALSE;

    status = TLInspectAddSCallout(
        calloutKey,
        deviceObject,
        calloutId
    );

    if (!NT_SUCCESS(status))
        goto Exit;
    calloutRegistered = TRUE;

    status = TLInspectAddMCallout(
        calloutName,
        layerKey,
        calloutKey
    );

    if (!NT_SUCCESS(status))
        goto Exit;

    status = TLInspectAddFilter(
        calloutName,
        filterConditions,
        numFilterConditions,
        0,
        layerKey,
        calloutKey
    );

Exit:

    if (!NT_SUCCESS(status))
    {
        if (calloutRegistered)
        {
            FwpsCalloutUnregisterById(*calloutId);
            *calloutId = 0;
        }
    }

    return status;
}

NTSTATUS
TLInspectRegisterCallouts(
    _Inout_ void* deviceObject
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SUBLAYER TLInspectSubLayer = { 0 };

    BOOLEAN engineOpened = FALSE;
    BOOLEAN inTransaction = FALSE;

    DbgPrint("TLInspectRegisterCallouts\n");

    FWPM_SESSION session = { 0 };

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &gEngineHandle
    );

    if (!NT_SUCCESS(status))
        goto Exit;
    engineOpened = TRUE;

    status = FwpmTransactionBegin(gEngineHandle, 0);

    if (!NT_SUCCESS(status))
        goto Exit;
    inTransaction = TRUE;

    TLInspectSubLayer.subLayerKey = TL_INSPECT_SUBLAYER;
    TLInspectSubLayer.displayData.name = L"Inspect Sub-Layer";
    TLInspectSubLayer.displayData.description = L"Inspect Sub-Layer by BOT Man";
    TLInspectSubLayer.flags = 0;
    TLInspectSubLayer.weight = 0; // must be less than the weight of 
                                  // FWPM_SUBLAYER_UNIVERSAL to be
                                  // compatible with Vista's IpSec
                                  // implementation.

    status = FwpmSubLayerAdd(gEngineHandle, &TLInspectSubLayer, NULL);

    if (!NT_SUCCESS(status))
        goto Exit;

    FWPM_FILTER_CONDITION filterCondition = { 0 };
    filterCondition.matchType = FWP_MATCH_EQUAL;

    // Register Network Callout

    filterCondition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    filterCondition.conditionValue.type = FWP_UINT32;
    filterCondition.conditionValue.uint32 = RtlUlongByteSwap(remoteAddrReal.S_un.S_addr);

    status = TLInspectRegisterCalloutAndFilter(
        L"Network Outbound",
        &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        &TL_INSPECT_OUTBOUND_NETWORK_CALLOUT_V4,
        &filterCondition,
        1,
        deviceObject,
        &gOutboundNetworkCalloutId
    );
    if (!NT_SUCCESS(status))
        goto Exit;

    filterCondition.conditionValue.uint32 = RtlUlongByteSwap(remoteAddrFake.S_un.S_addr);

    status = TLInspectRegisterCalloutAndFilter(
        L"Network Inbound",
        &FWPM_LAYER_INBOUND_IPPACKET_V4,
        &TL_INSPECT_INBOUND_NETWORK_CALLOUT_V4,
        &filterCondition,
        1,
        deviceObject,
        &gInboundNetworkCalloutId
    );
    if (!NT_SUCCESS(status))
        goto Exit;

    // Register Temp Callout

    status = TLInspectRegisterCalloutAndFilter(
        L"Transport Inbound Discard",
        &FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD,
        &TL_INSPECT_TEMP_CALLOUT_1,
        &filterCondition,
        1,
        deviceObject,
        &gTempCalloutId1
    );
    if (!NT_SUCCESS(status))
        goto Exit;

    status = TLInspectRegisterCalloutAndFilter(
        L"Transport Inbound",
        &FWPM_LAYER_INBOUND_TRANSPORT_V4,
        &TL_INSPECT_TEMP_CALLOUT_2,
        &filterCondition,
        1,
        deviceObject,
        &gTempCalloutId2
    );
    if (!NT_SUCCESS(status))
        goto Exit;

    // Register Ethernet Callout

    filterCondition.fieldKey = FWPM_CONDITION_ETHER_TYPE;
    filterCondition.conditionValue.type = FWP_UINT16;
    filterCondition.conditionValue.uint16 = NDIS_ETH_TYPE_IPV4;

    status = TLInspectRegisterCalloutAndFilter(
        L"Ethernet Outbound",
        &FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET,
        &TL_INSPECT_OUTBOUND_ETHERNET_CALLOUT,
        &filterCondition,
        1,
        deviceObject,
        &gOutboundEthernetCalloutId
    );
    if (!NT_SUCCESS(status))
        goto Exit;

    status = TLInspectRegisterCalloutAndFilter(
        L"Ethernet Inbound",
        &FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
        &TL_INSPECT_INBOUND_ETHERNET_CALLOUT,
        &filterCondition,
        1,
        deviceObject,
        &gInboundEthernetCalloutId
    );
    if (!NT_SUCCESS(status))
        goto Exit;

    status = FwpmTransactionCommit(gEngineHandle);

    if (!NT_SUCCESS(status))
        goto Exit;
    inTransaction = FALSE;

Exit:

    if (!NT_SUCCESS(status))
    {
        if (inTransaction)
        {
            FwpmTransactionAbort(gEngineHandle);
            _Analysis_assume_lock_not_held_(gEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
        }

        if (engineOpened)
        {
            FwpmEngineClose(gEngineHandle);
            gEngineHandle = NULL;
        }
    }

    return status;
}

void
TLInspectUnregisterCallouts(void)
{
    DbgPrint("TLInspectUnregisterCallouts\n");

    FwpmEngineClose(gEngineHandle);
    gEngineHandle = NULL;

    FwpsCalloutUnregisterById(gOutboundNetworkCalloutId);
    FwpsCalloutUnregisterById(gInboundNetworkCalloutId);
    FwpsCalloutUnregisterById(gOutboundEthernetCalloutId);
    FwpsCalloutUnregisterById(gInboundEthernetCalloutId);
    FwpsCalloutUnregisterById(gTempCalloutId1);
    FwpsCalloutUnregisterById(gTempCalloutId2);
}

void
TLInspectNDISPoolDataPurge()
{
    if (gNdisHandle)
    {
        if (gNbPoolHandle)
        {
            NdisFreeNetBufferPool(gNbPoolHandle);
            gNbPoolHandle = NULL;
        }

        if (gNblPoolHandle)
        {
            NdisFreeNetBufferListPool(gNblPoolHandle);
            gNblPoolHandle = NULL;
        }

        NdisFreeGenericObject(gNdisHandle);
        gNdisHandle = NULL;
    }
}

NTSTATUS
TLInspectNDISPoolDataPopulate()
{
    NTSTATUS                        status = STATUS_SUCCESS;
    NET_BUFFER_LIST_POOL_PARAMETERS nblPoolParameters = { 0 };
    NET_BUFFER_POOL_PARAMETERS      nbPoolParameters = { 0 };

    gNdisHandle = NdisAllocateGenericObject(0,
        TL_INSPECT_NDIS_POOL_TAG,
        0);
    if (gNdisHandle == NULL)
    {
        status = STATUS_INVALID_HANDLE;
        goto Exit;
    }

    nblPoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nblPoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblPoolParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblPoolParameters.fAllocateNetBuffer = TRUE;
    nblPoolParameters.DataSize = 0;
    nblPoolParameters.PoolTag = TL_INSPECT_NDIS_POOL_TAG;

    gNblPoolHandle = NdisAllocateNetBufferListPool(gNdisHandle,
        &nblPoolParameters);
    if (gNblPoolHandle == NULL)
    {
        status = STATUS_INVALID_HANDLE;
        goto Exit;
    }

    nbPoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbPoolParameters.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPoolParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPoolParameters.PoolTag = TL_INSPECT_NDIS_POOL_TAG;
    nbPoolParameters.DataSize = 0;

    gNbPoolHandle = NdisAllocateNetBufferPool(gNdisHandle,
        &nbPoolParameters);
    if (gNbPoolHandle == NULL)
    {
        status = STATUS_INVALID_HANDLE;
        goto Exit;
    }

Exit:
    if (status != STATUS_SUCCESS)
        TLInspectNDISPoolDataPurge();

    return status;
}

_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
TLInspectEvtDriverUnload(
    _In_ WDFDRIVER driverObject
)
{
    UNREFERENCED_PARAMETER(driverObject);

    DbgPrint("TLInspectEvtDriverUnload\n");

    BOOLEAN isQueueEmpty = FALSE;
    KLOCK_QUEUE_HANDLE queueLockHandle;

    KeAcquireInStackQueuedSpinLock(
        &gQueueLock,
        &queueLockHandle
    );

    gDriverUnloading = TRUE;
    isQueueEmpty =
        IsListEmpty(&gPacketQueue) &&
        IsListEmpty(&gFrameQueue);

    KeReleaseInStackQueuedSpinLock(&queueLockHandle);

    if (isQueueEmpty)
    {
        KeSetEvent(
            &gWorkerEvent,
            IO_NO_INCREMENT,
            FALSE
        );
    }

    NT_ASSERT(gThreadObj != NULL);

    KeWaitForSingleObject(
        gThreadObj,
        Executive,
        KernelMode,
        FALSE,
        NULL
    );

    ObDereferenceObject(gThreadObj);

    TLInspectUnregisterCallouts();

    FwpsInjectionHandleDestroy(gInjectionHandleNetwork);
    FwpsInjectionHandleDestroy(gInjectionHandleEthernet);

    TLInspectNDISPoolDataPurge();
}

NTSTATUS
TLInspectInitDriverObjects(
    _Inout_ DRIVER_OBJECT* driverObject,
    _In_ const UNICODE_STRING* registryPath,
    _Out_ WDFDRIVER* pDriver,
    _Out_ WDFDEVICE* pDevice
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    PWDFDEVICE_INIT pInit = NULL;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = TLInspectEvtDriverUnload;

    status = WdfDriverCreate(
        driverObject,
        registryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        pDriver
    );

    if (!NT_SUCCESS(status))
        goto Exit;

    pInit = WdfControlDeviceInitAllocate(*pDriver, &SDDL_DEVOBJ_KERNEL_ONLY);

    if (!pInit)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    WdfDeviceInitSetDeviceType(pInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(pInit, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetCharacteristics(pInit, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

    status = WdfDeviceCreate(&pInit, WDF_NO_OBJECT_ATTRIBUTES, pDevice);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(pInit);
        goto Exit;
    }

    WdfControlFinishInitializing(*pDevice);

Exit:
    return status;
}

NTSTATUS
DriverEntry(
    DRIVER_OBJECT* driverObject,
    UNICODE_STRING* registryPath
)
{
    NTSTATUS status;
    WDFDRIVER driver;
    WDFDEVICE device;
    HANDLE threadHandle;

    DbgPrint("DriverEntry\n");

    // Request NX Non-Paged Pool when available
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    status = TLInspectInitDriverObjects(
        driverObject,
        registryPath,
        &driver,
        &device
    );

    if (!NT_SUCCESS(status))
        goto Exit;

    status = WdfDriverOpenParametersRegistryKey(
        driver,
        KEY_READ,
        WDF_NO_OBJECT_ATTRIBUTES,
        &gParametersKey
    );

    if (!NT_SUCCESS(status))
        goto Exit;

    status = TLInspectLoadConfig(gParametersKey);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("Config Error: 0x%08X\n", status);

        status = STATUS_DEVICE_CONFIGURATION_ERROR;
        goto Exit;
    }

    status = TLInspectNDISPoolDataPopulate();

    if (!NT_SUCCESS(status))
        goto Exit;

    status = FwpsInjectionHandleCreate(
        AF_INET,
        FWPS_INJECTION_TYPE_NETWORK,
        &gInjectionHandleNetwork
    );

    if (!NT_SUCCESS(status))
        goto Exit;

    status = FwpsInjectionHandleCreate(
        AF_UNSPEC,
        FWPS_INJECTION_TYPE_L2,
        &gInjectionHandleEthernet
    );

    if (!NT_SUCCESS(status))
        goto Exit;

    InitializeListHead(&gPacketQueue);
    InitializeListHead(&gFrameQueue);
    KeInitializeSpinLock(&gQueueLock);

    KeInitializeEvent(
        &gWorkerEvent,
        NotificationEvent,
        FALSE
    );

    gWdmDevice = WdfDeviceWdmGetDeviceObject(device);

    status = TLInspectRegisterCallouts(gWdmDevice);

    if (!NT_SUCCESS(status))
        goto Exit;

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        TLInspectWorker,
        NULL
    );

    if (!NT_SUCCESS(status))
        goto Exit;

    status = ObReferenceObjectByHandle(
        threadHandle,
        0,
        NULL,
        KernelMode,
        &gThreadObj,
        NULL
    );
    NT_ASSERT(NT_SUCCESS(status));

    ZwClose(threadHandle);

Exit:

    if (!NT_SUCCESS(status))
    {
        if (gEngineHandle != NULL)
        {
            TLInspectUnregisterCallouts();
        }
        if (gInjectionHandleNetwork != NULL)
        {
            FwpsInjectionHandleDestroy(gInjectionHandleNetwork);
        }
        if (gInjectionHandleEthernet != NULL)
        {
            FwpsInjectionHandleDestroy(gInjectionHandleEthernet);
        }
    }

    return status;
};

