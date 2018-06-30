/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   This file implements the classifyFn callout functions for the network callouts.
   In addition the system worker thread
   that performs the actual packet inspection is also implemented here along
   with the eventing mechanisms shared between the classify function and the
   worker thread.

   Packet inspection is done out-of-band by a system worker thread
   using the reference-drop-clone-reinject
   Therefore the sample can serve as a base in scenarios where
   filtering decision cannot be made within the classifyFn() callout and
   instead must be made, for example, by an user-mode application.

Environment:

    Kernel mode

--*/


#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <mstcpip.h>

#include "protocol-headers.h"
#include "inspect.h"
#include "utils.h"

//
// Callback
//

__inline
BOOL HasWriteRight(
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    return (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE);
}

__inline
BOOL HasInspected(
    _In_ const NET_BUFFER_LIST* layerData,
    _In_ HANDLE injectionHandle
)
{
    FWPS_PACKET_INJECTION_STATE packetState;
    packetState = FwpsQueryPacketInjectionState(
        injectionHandle,
        layerData,
        NULL
    );

    return
        (packetState == FWPS_PACKET_INJECTED_BY_SELF) ||
        (packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF);
}

void
PermitClassify(
    _In_ const FWPS_FILTER* filter,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

void
BlockClassify(
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

void
AbsorbClassify(
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    BlockClassify(classifyOut);
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}

BOOL
IsFrameInterested(
    _In_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOL isOutbound
)
{
    // TODO: only care about IPv4 Frame

    BOOL result = FALSE;
    if (isOutbound)
        AdvancePacketBuffer(netBufferList, sizeof(ETHERNET_HEADER));

    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    IP_HEADER_V4* pIPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(IP_HEADER_V4), NULL, 1, 0);

    if (pIPHeader)
    {
        if (isOutbound)
        {
            result =
                RtlEqualMemory(
                    pIPHeader->pSourceAddress,
                    &localAddrReal,
                    sizeof(pIPHeader->pSourceAddress)
                ) && RtlEqualMemory(
                    pIPHeader->pDestinationAddress,
                    &remoteAddrFake,
                    sizeof(pIPHeader->pDestinationAddress)
                );
        }
        else
        {
            result =
                RtlEqualMemory(
                    pIPHeader->pSourceAddress,
                    &remoteAddrFake,
                    sizeof(pIPHeader->pSourceAddress)
                ) && RtlEqualMemory(
                    pIPHeader->pDestinationAddress,
                    &localAddrFake,
                    sizeof(pIPHeader->pDestinationAddress)
                );
        }
    }
    else
    {
        DbgPrint("IsFrameInterested failed to get IP header");
        result = FALSE;
    }

    if (isOutbound)
        RetreatPacketBuffer(netBufferList, sizeof(ETHERNET_HEADER));
    return result;
}

NTSTATUS
TLInspectCloneReinjectOutboundFrame(
    _Inout_ TL_INSPECT_PENDED_FRAME* frame
);
NTSTATUS
TLInspectCloneReinjectInboundFrame(
    _Inout_ TL_INSPECT_PENDED_FRAME* frame
);
NTSTATUS
TLInspectCloneReinjectOutboundPacket(
    _Inout_ TL_INSPECT_PENDED_PACKET* packet
);
NTSTATUS
TLInspectCloneReinjectInboundPacket(
    _Inout_ TL_INSPECT_PENDED_PACKET* packet
);

void
TLInspectClassify(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT* classifyOut
)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);

    if (!HasWriteRight(classifyOut))
    {
        DbgPrint("TLInspectClassify no write right\n");
        return;
    }

    if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4_DISCARD ||
        inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD ||
        inFixedValues->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD ||
        inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD)
    {
        if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_DISCARD_REASON))
        {
            DbgPrint("! Discard at layer %u (module: %u, reason: %u)\n",
                inFixedValues->layerId,
                inMetaValues->discardMetadata.discardModule,
                inMetaValues->discardMetadata.discardReason);
            // see IP_DISCARD_REASON, INET_DISCARD_REASON, FWPS_GENERAL_DISCARD_REASON
        }
        else
        {
            DbgPrint("! Discard at layer %u (unknown module/reason)\n",
                inFixedValues->layerId);
        }

        PermitClassify(filter, classifyOut);
        return;
    }

    BOOL outboundNotInterested = (
        inFixedValues->layerId == FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET &&
        !IsFrameInterested(layerData, TRUE)
        );
    BOOL inboundNotInterested = (
        inFixedValues->layerId == FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET &&
        !IsFrameInterested(layerData, FALSE)
        );

    if (outboundNotInterested || inboundNotInterested)
    {
        PermitClassify(filter, classifyOut);
        return;
    }

    BOOL hasInspected = FALSE;

    switch (inFixedValues->layerId)
    {
    case FWPS_LAYER_INBOUND_IPPACKET_V4:
    case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
        hasInspected = HasInspected(layerData, gInjectionHandleNetwork);
        break;

    case FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET:
    case FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET:
        hasInspected = HasInspected(layerData, gInjectionHandleEthernet);
        break;

    default:
        NT_ASSERT(0);
    }

    if (hasInspected)
    {
        DbgPrint("TLInspectClassify already inspected (layerId: %u)\n", inFixedValues->layerId);
        PermitClassify(filter, classifyOut);
        return;
    }

    TL_INSPECT_PENDED_PACKET* pendedPacket = NULL;
    TL_INSPECT_PENDED_FRAME* pendedFrame = NULL;

    switch (inFixedValues->layerId)
    {
    case FWPS_LAYER_INBOUND_IPPACKET_V4:
    case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
        pendedPacket = AllocateAndInitializePendedPacket(
            inFixedValues,
            inMetaValues,
            layerData
        );
        break;

    case FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET:
    case FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET:
        pendedFrame = AllocateAndInitializePendedFrame(
            inFixedValues,
            layerData
        );
        break;

    default:
        NT_ASSERT(0);
    }

    if (pendedPacket == NULL && pendedFrame == NULL)
    {
        DbgPrint("TLInspectClassify failed to construct packet/frame\n");
        BlockClassify(classifyOut);
        return;
    }

    if (pendedPacket)
        PrintPacket(pendedPacket);
    if (pendedFrame)
        PrintFrame(pendedFrame);

    BOOLEAN isQueueEmpty = FALSE;
    KLOCK_QUEUE_HANDLE queueLockHandle;

    KeAcquireInStackQueuedSpinLock(
        &gQueueLock,
        &queueLockHandle
    );

    if (!gDriverUnloading)
    {
        //isQueueEmpty =
        //    IsListEmpty(&gPacketQueue) &&
        //    IsListEmpty(&gFrameQueue);

        //switch (inFixedValues->layerId)
        //{
        //case FWPS_LAYER_INBOUND_IPPACKET_V4:
        //case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
        //    InsertTailList(&gPacketQueue, &pendedPacket->listEntry);
        //    pendedPacket = NULL; // ownership transferred

        //    AbsorbClassify(classifyOut);
        //    break;

        //case FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET:
        //case FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET:
        //    InsertTailList(&gFrameQueue, &pendedFrame->listEntry);
        //    pendedFrame = NULL; // ownership transferred

        //    AbsorbClassify(classifyOut);
        //    break;

        //default:
        //    NT_ASSERT(0);
        //}
    }
    else
    {
        DbgPrint("TLInspectClassify driver is unloading\n");
        PermitClassify(filter, classifyOut);
    }

    KeReleaseInStackQueuedSpinLock(&queueLockHandle);

    if (pendedPacket != NULL)
    {
        switch (inFixedValues->layerId)
        {
        case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
            TLInspectCloneReinjectOutboundPacket(pendedPacket);
            break;
        case FWPS_LAYER_INBOUND_IPPACKET_V4:
            TLInspectCloneReinjectInboundPacket(pendedPacket);
            break;
        default:
            NT_ASSERT(0);
        }

        pendedPacket = NULL; // ownership transferred
        AbsorbClassify(classifyOut);
    }

    if (pendedFrame != NULL)
    {
        switch (inFixedValues->layerId)
        {
        case FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET:
            TLInspectCloneReinjectOutboundFrame(pendedFrame);
            break;
        case FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET:
            TLInspectCloneReinjectInboundFrame(pendedFrame);
            break;
        default:
            NT_ASSERT(0);
        }

        pendedFrame = NULL; // ownership transferred
        AbsorbClassify(classifyOut);
    }

    if (isQueueEmpty)
    {
        NT_ASSERT(0);

        KeSetEvent(
            &gWorkerEvent,
            IO_NO_INCREMENT,
            FALSE
        );
    }

    //Exit:
    if (pendedPacket != NULL)
        FreePendedPacket(pendedPacket);

    if (pendedFrame != NULL)
        FreePendedFrame(pendedFrame);
}

NTSTATUS
TLInspectNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const FWPS_FILTER* filter
)
{
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(filterKey);

    DbgPrint("* TLInspectNotify (notifyType: %d)\n", notifyType);

    return STATUS_SUCCESS;
}

//
// Reinjection
//

/*
    1R -> 2R
Network Outbound
    1R -> 2F
Ethernet Outbound
    1F -> 2F
 Physics Layer
    1F -> 2F
Ethernet Inbound
    1F -> 2R
Network Inbound
    1R -> 2R
*/

NTSTATUS
AllocateCloneNetBufferList(
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ UINT32 bytesRetreated,
    _Outptr_ NET_BUFFER_LIST** clonedNetBufferList
)
{
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Note that the clone will inherit the original net buffer list's offset.
    //

    if (bytesRetreated)
        RetreatPacketBuffer(netBufferList, bytesRetreated);

    status = FwpsAllocateCloneNetBufferList(
        netBufferList,
        gNblPoolHandle,
        gNbPoolHandle,
        0,
        clonedNetBufferList
    );

    if (bytesRetreated)
        AdvancePacketBuffer(netBufferList, bytesRetreated);

    return status;
}

void
ModifyOutboundPacketClonedBuffer(
    _Inout_ NET_BUFFER_LIST* clonedNetBufferList
)
{
    BOOL enableModifyAddr = remoteAddrReal.S_un.S_addr && remoteAddrFake.S_un.S_addr;
    if (!enableModifyAddr)
        return;

    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(clonedNetBufferList);
    IP_HEADER_V4* pIPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(IP_HEADER_V4), NULL, 1, 0);
    if (pIPHeader)
    {
        RtlCopyMemory(pIPHeader->pDestinationAddress, &remoteAddrFake, sizeof(pIPHeader->pDestinationAddress));

        BOOL enableModifyLocalPort = localPortReal && localPortFake;
        BOOL enableModifyRemotePort = remotePortReal && remotePortFake;
        UINT32 ipLength = pIPHeader->headerLength * 4;

        AdvancePacketBuffer(clonedNetBufferList, ipLength);
        switch (pIPHeader->protocol)
        {
        case IPPROTO_TCP:
        {
            TCP_HEADER* pTCPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(TCP_HEADER), NULL, 1, 0);
            if (pTCPHeader)
            {
                if (enableModifyLocalPort &&
                    pTCPHeader->sourcePort == localPortReal)
                    pTCPHeader->sourcePort = localPortFake;

                if (enableModifyRemotePort &&
                    pTCPHeader->destinationPort == remotePortReal)
                    pTCPHeader->destinationPort = remotePortFake;
            }
            break;
        }
        case IPPROTO_UDP:
        {
            UDP_HEADER* pUDPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(UDP_HEADER), NULL, 1, 0);
            if (pUDPHeader)
            {
                if (enableModifyLocalPort &&
                    pUDPHeader->sourcePort == localPortReal)
                    pUDPHeader->sourcePort = localPortFake;

                if (enableModifyRemotePort &&
                    pUDPHeader->destinationPort == remotePortReal)
                    pUDPHeader->destinationPort = remotePortFake;
            }
            break;
        }
        }
        RetreatPacketBuffer(clonedNetBufferList, ipLength);
    }
}

void
ModifyInboundPacketClonedBuffer(
    _Inout_ NET_BUFFER_LIST* clonedNetBufferList
)
{
    BOOL enableModifyAddr = remoteAddrReal.S_un.S_addr && remoteAddrFake.S_un.S_addr;
    if (!enableModifyAddr)
        return;

    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(clonedNetBufferList);
    IP_HEADER_V4* pIPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(IP_HEADER_V4), NULL, 1, 0);
    if (pIPHeader)
    {
        RtlCopyMemory(pIPHeader->pSourceAddress, &remoteAddrReal, sizeof(pIPHeader->pSourceAddress));

        BOOL enableModifyLocalPort = localPortReal && localPortFake;
        BOOL enableModifyRemotePort = remotePortReal && remotePortFake;
        UINT32 ipLength = pIPHeader->headerLength * 4;

        AdvancePacketBuffer(clonedNetBufferList, ipLength);
        switch (pIPHeader->protocol)
        {
        case IPPROTO_TCP:
        {
            TCP_HEADER* pTCPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(TCP_HEADER), NULL, 1, 0);
            if (pTCPHeader)
            {
                if (enableModifyLocalPort &&
                    pTCPHeader->destinationPort == localPortFake)
                    pTCPHeader->destinationPort = localPortReal;

                if (enableModifyRemotePort &&
                    pTCPHeader->sourcePort == remotePortFake)
                    pTCPHeader->sourcePort = remotePortReal;
            }
            break;
        }
        case IPPROTO_UDP:
        {
            UDP_HEADER* pUDPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(UDP_HEADER), NULL, 1, 0);
            if (pUDPHeader)
            {
                if (enableModifyLocalPort &&
                    pUDPHeader->destinationPort == localPortFake)
                    pUDPHeader->destinationPort = localPortReal;

                if (enableModifyRemotePort &&
                    pUDPHeader->sourcePort == remotePortFake)
                    pUDPHeader->sourcePort = remotePortReal;
            }
            break;
        }
        }
        RetreatPacketBuffer(clonedNetBufferList, ipLength);
    }
}

void
ModifyOutboundFrameClonedBuffer(
    _Inout_ NET_BUFFER_LIST* clonedNetBufferList
)
{
    BOOL enableModifyAddr = localAddrReal.S_un.S_addr && localAddrFake.S_un.S_addr;
    if (!enableModifyAddr)
        return;

    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(clonedNetBufferList);
    ETHERNET_HEADER* pEthernetHeader = NdisGetDataBuffer(pNetBuffer, sizeof(ETHERNET_HEADER), NULL, 1, 0);
    if (pEthernetHeader)
    {
        UINT16 typeCode = RtlUshortByteSwap(pEthernetHeader->type);
        NT_ASSERT(typeCode == NDIS_ETH_TYPE_IPV4);

        RtlCopyMemory(
            pEthernetHeader->pSourceAddress,
            localEthernetAddress,
            sizeof(pEthernetHeader->pSourceAddress)
        );

        RtlCopyMemory(
            pEthernetHeader->pDestinationAddress,
            remoteEthernetAddress,
            sizeof(pEthernetHeader->pDestinationAddress)
        );

        AdvancePacketBuffer(clonedNetBufferList, sizeof(ETHERNET_HEADER));

        IP_HEADER_V4* pIPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(IP_HEADER_V4), NULL, 1, 0);
        if (pIPHeader)
        {
            RtlCopyMemory(pIPHeader->pSourceAddress, &localAddrFake, sizeof(pIPHeader->pSourceAddress));
        }

        RetreatPacketBuffer(clonedNetBufferList, sizeof(ETHERNET_HEADER));
    }
}

void
ModifyInboundFrameClonedBuffer(
    _Inout_ NET_BUFFER_LIST* clonedNetBufferList
)
{
    BOOL enableModifyAddr = localAddrReal.S_un.S_addr && localAddrFake.S_un.S_addr;
    if (!enableModifyAddr)
        return;

    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(clonedNetBufferList);
    ETHERNET_HEADER* pEthernetHeader = NdisGetDataBuffer(pNetBuffer, sizeof(ETHERNET_HEADER), NULL, 1, 0);
    if (pEthernetHeader)
    {
        UINT16 typeCode = RtlUshortByteSwap(pEthernetHeader->type);
        NT_ASSERT(typeCode == NDIS_ETH_TYPE_IPV4);

        AdvancePacketBuffer(clonedNetBufferList, sizeof(ETHERNET_HEADER));

        IP_HEADER_V4* pIPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(IP_HEADER_V4), NULL, 1, 0);
        if (pIPHeader)
        {
            RtlCopyMemory(pIPHeader->pDestinationAddress, &localAddrReal, sizeof(pIPHeader->pDestinationAddress));
        }

        RetreatPacketBuffer(clonedNetBufferList, sizeof(ETHERNET_HEADER));
    }
}

void TLInspectInjectPacketComplete(
    _Inout_ void* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
)
{
    UNREFERENCED_PARAMETER(dispatchLevel);

    if (!NT_SUCCESS(netBufferList->Status))
    {
        DbgPrint("! Packet injection failed: 0x%08X\n", netBufferList->Status);
        PrintPacket((TL_INSPECT_PENDED_PACKET*)context);
    }

    FwpsFreeCloneNetBufferList(netBufferList, 0);
    FreePendedPacket((TL_INSPECT_PENDED_PACKET*)context);
}

void TLInspectInjectFrameComplete(
    _Inout_ void* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
)
{
    UNREFERENCED_PARAMETER(dispatchLevel);

    if (!NT_SUCCESS(netBufferList->Status))
    {
        DbgPrint("! Frame injection failed: 0x%08X\n", netBufferList->Status);
        PrintFrame((TL_INSPECT_PENDED_FRAME*)context);
    }

    FwpsFreeCloneNetBufferList(netBufferList, 0);
    FreePendedFrame((TL_INSPECT_PENDED_FRAME*)context);
}

NTSTATUS
TLInspectCloneReinjectOutboundPacket(
    _Inout_ TL_INSPECT_PENDED_PACKET* packet
)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST* clonedNetBufferList = NULL;

    status = AllocateCloneNetBufferList(
        packet->netBufferList,
        packet->ipHeaderSize,
        &clonedNetBufferList
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("TLInspectCloneReinjectOutboundPacket clone buffer failed\n");
        goto Exit;
    }

    ModifyOutboundPacketClonedBuffer(clonedNetBufferList);

    status = FwpsInjectNetworkSendAsync(
        gInjectionHandleNetwork,
        NULL,
        0,
        packet->compartmentId,
        clonedNetBufferList,
        TLInspectInjectPacketComplete,
        packet
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("FwpsInjectNetworkSendAsync failed\n");
        goto Exit;
    }

    clonedNetBufferList = NULL; // ownership transferred to completionFn

Exit:
    if (clonedNetBufferList != NULL)
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);

    return status;
}

NTSTATUS
TLInspectCloneReinjectInboundPacket(
    _Inout_ TL_INSPECT_PENDED_PACKET* packet
)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST* clonedNetBufferList = NULL;

    status = AllocateCloneNetBufferList(
        packet->netBufferList,
        packet->ipHeaderSize,
        &clonedNetBufferList
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("TLInspectCloneReinjectInboundPacket clone buffer failed\n");
        goto Exit;
    }

    ModifyInboundPacketClonedBuffer(clonedNetBufferList);

    status = FwpsInjectNetworkReceiveAsync(
        gInjectionHandleNetwork,
        NULL,
        0,
        packet->compartmentId,
        packet->interfaceIndex,
        packet->subInterfaceIndex,
        clonedNetBufferList,
        TLInspectInjectPacketComplete,
        packet
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("FwpsInjectNetworkReceiveAsync failed\n");
        goto Exit;
    }

    clonedNetBufferList = NULL; // ownership transferred to completionFn

Exit:
    if (clonedNetBufferList != NULL)
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);

    return status;
}

NTSTATUS
TLInspectCloneReinjectOutboundFrame(
    _Inout_ TL_INSPECT_PENDED_FRAME* frame
)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST* clonedNetBufferList = NULL;

    status = AllocateCloneNetBufferList(
        frame->netBufferList,
        frame->ethernetMacHeaderSize,
        &clonedNetBufferList
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("TLInspectCloneReinjectOutboundFrame clone buffer failed\n");
        goto Exit;
    }

    ModifyOutboundFrameClonedBuffer(clonedNetBufferList);

    status = FwpsInjectMacSendAsync(
        gInjectionHandleEthernet,
        NULL,
        0,
        FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET,
        frame->interfaceIndex,
        frame->ndisPortNumber,
        clonedNetBufferList,
        TLInspectInjectFrameComplete,
        frame
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("FwpsInjectMacSendAsync failed\n");
        goto Exit;
    }

    clonedNetBufferList = NULL; // ownership transferred to completionFn

Exit:
    if (clonedNetBufferList != NULL)
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);

    return status;
}

NTSTATUS
TLInspectCloneReinjectInboundFrame(
    _Inout_ TL_INSPECT_PENDED_FRAME* frame
)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST* clonedNetBufferList = NULL;

    status = AllocateCloneNetBufferList(
        frame->netBufferList,
        frame->ethernetMacHeaderSize,
        &clonedNetBufferList
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("TLInspectCloneReinjectInboundFrame clone buffer failed\n");
        goto Exit;
    }

    ModifyInboundFrameClonedBuffer(clonedNetBufferList);

    status = FwpsInjectMacReceiveAsync(
        gInjectionHandleEthernet,
        NULL,
        0,
        FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET,
        frame->interfaceIndex,
        frame->ndisPortNumber,
        clonedNetBufferList,
        TLInspectInjectFrameComplete,
        frame
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("FwpsInjectMacReceiveAsync failed\n");
        goto Exit;
    }

    clonedNetBufferList = NULL; // ownership transferred to completionFn

Exit:
    if (clonedNetBufferList != NULL)
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);

    return status;
}

//
// TLInspectWorker
//

TL_INSPECT_PENDED_PACKET*
ExtractPacketFromQueue()
{
    LIST_ENTRY* listEntry = RemoveHeadList(&gPacketQueue);

    TL_INSPECT_PENDED_PACKET* packet = CONTAINING_RECORD(
        listEntry,
        TL_INSPECT_PENDED_PACKET,
        listEntry
    );

    return packet;
}

TL_INSPECT_PENDED_FRAME*
ExtractFrameFromQueue()
{
    LIST_ENTRY* listEntry = RemoveHeadList(&gFrameQueue);

    TL_INSPECT_PENDED_FRAME* frame = CONTAINING_RECORD(
        listEntry,
        TL_INSPECT_PENDED_FRAME,
        listEntry
    );

    return frame;
}

void
TLInspectWorker(
    _In_ void* StartContext
)
{
    NTSTATUS status;
    KLOCK_QUEUE_HANDLE queueLockHandle;
    UNREFERENCED_PARAMETER(StartContext);

    for (;;)
    {
        KeWaitForSingleObject(
            &gWorkerEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );

        if (gDriverUnloading)
            break;

        NT_ASSERT(0);

        TL_INSPECT_PENDED_PACKET* packet = NULL;
        TL_INSPECT_PENDED_FRAME* frame = NULL;

        KeAcquireInStackQueuedSpinLock(
            &gQueueLock,
            &queueLockHandle
        );

        if (!IsListEmpty(&gPacketQueue))
            packet = ExtractPacketFromQueue();
        else if (!IsListEmpty(&gFrameQueue))
            frame = ExtractFrameFromQueue();
        else
            NT_ASSERT(0);  // at least one queue not empty

        KeReleaseInStackQueuedSpinLock(&queueLockHandle);

        if (packet != NULL)
        {
            if (packet->direction == FWP_DIRECTION_OUTBOUND)
                status = TLInspectCloneReinjectOutboundPacket(packet);
            else
                status = TLInspectCloneReinjectInboundPacket(packet);

            if (!NT_SUCCESS(status))
            {
                DbgPrint("TLInspectWorker free failed packet\n");
                FreePendedPacket(packet);
            }
        }

        if (frame != NULL)
        {
            if (frame->direction == FWP_DIRECTION_OUTBOUND)
                status = TLInspectCloneReinjectOutboundFrame(frame);
            else
                status = TLInspectCloneReinjectInboundFrame(frame);

            if (!NT_SUCCESS(status))
            {
                DbgPrint("TLInspectWorker free failed frame\n");
                FreePendedFrame(frame);
            }
        }

        KeAcquireInStackQueuedSpinLock(
            &gQueueLock,
            &queueLockHandle
        );

        BOOLEAN isQueueEmpty =
            IsListEmpty(&gPacketQueue) &&
            IsListEmpty(&gFrameQueue);

        if (isQueueEmpty && !gDriverUnloading)
        {
            KeClearEvent(&gWorkerEvent);
        }
        // else:
        // continue to process the next one or quit

        KeReleaseInStackQueuedSpinLock(&queueLockHandle);
    }

    DbgPrint("TLInspectWorker unloading\n");

    NT_ASSERT(gDriverUnloading);

    //
    // Discard all the pended packets/frames if driver is being unloaded.
    //

    while (!IsListEmpty(&gPacketQueue))
    {
        DbgPrint("TLInspectWorker discard pended packet\n");
        TL_INSPECT_PENDED_PACKET* packet = NULL;

        KeAcquireInStackQueuedSpinLock(
            &gQueueLock,
            &queueLockHandle
        );

        if (!IsListEmpty(&gPacketQueue))
            packet = ExtractPacketFromQueue();

        KeReleaseInStackQueuedSpinLock(&queueLockHandle);

        if (packet != NULL)
            FreePendedPacket(packet);
    }

    while (!IsListEmpty(&gFrameQueue))
    {
        DbgPrint("TLInspectWorker discard pended packet\n");
        TL_INSPECT_PENDED_FRAME* frame = NULL;

        KeAcquireInStackQueuedSpinLock(
            &gQueueLock,
            &queueLockHandle
        );

        if (!IsListEmpty(&gFrameQueue))
            frame = ExtractFrameFromQueue();

        KeReleaseInStackQueuedSpinLock(&queueLockHandle);

        if (frame != NULL)
            FreePendedFrame(frame);
    }

    DbgPrint("TLInspectWorker terminating\n");

    PsTerminateSystemThread(STATUS_SUCCESS);
}
