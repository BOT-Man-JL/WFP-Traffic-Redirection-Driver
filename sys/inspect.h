/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   This header files declares common data types and function prototypes used
   throughout the Network Inspect sample.

Environment:

    Kernel mode

--*/

#ifndef _TL_INSPECT_H_
#define _TL_INSPECT_H_

//
// IP Packet
//

typedef struct TL_INSPECT_PENDED_PACKET_
{
    LIST_ENTRY listEntry;
    FWP_DIRECTION direction;
    NET_BUFFER_LIST* netBufferList;

    UINT32 ipHeaderSize;
    COMPARTMENT_ID compartmentId;
    IF_INDEX interfaceIndex;
    IF_INDEX subInterfaceIndex;

} TL_INSPECT_PENDED_PACKET;

//
// Ethernet Frame
//

typedef struct TL_INSPECT_PENDED_FRAME_
{
    LIST_ENTRY listEntry;
    FWP_DIRECTION direction;
    NET_BUFFER_LIST* netBufferList;

    UINT32 ethernetMacHeaderSize;
    IF_INDEX interfaceIndex;
    NDIS_PORT_NUMBER ndisPortNumber;

} TL_INSPECT_PENDED_FRAME;

//
// Pooltags used by this callout driver.
//

#define TL_INSPECT_PENDED_PACKET_POOL_TAG 'kppD'
#define TL_INSPECT_PENDED_FRAME_POOL_TAG 'dcdD'
#define TL_INSPECT_NDIS_POOL_TAG 'PNSW'

//
// Shared global data.
//

extern IN_ADDR localAddrReal;
extern IN_ADDR localAddrFake;
extern IN_ADDR remoteAddrReal;
extern IN_ADDR remoteAddrFake;
extern UINT16 localPortReal;
extern UINT16 localPortFake;
extern UINT16 remotePortReal;
extern UINT16 remotePortFake;
extern BYTE localEthernetAddress[6];
extern BYTE remoteEthernetAddress[6];

extern HANDLE gInjectionHandleNetwork;
extern HANDLE gInjectionHandleEthernet;

extern PNDIS_GENERIC_OBJECT gNdisHandle;
extern NDIS_HANDLE gNblPoolHandle;
extern NDIS_HANDLE gNbPoolHandle;

extern LIST_ENTRY gPacketQueue;
extern LIST_ENTRY gFrameQueue;
extern KSPIN_LOCK gQueueLock;

extern KEVENT gWorkerEvent;

extern BOOLEAN gDriverUnloading;

//
// Shared function prototypes
//

void
TLInspectClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

NTSTATUS
TLInspectNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const FWPS_FILTER* filter
);

KSTART_ROUTINE TLInspectWorker;

#endif // _TL_INSPECT_H_
