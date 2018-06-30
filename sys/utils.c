/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   This file implements the utility/helper functions for use by the classify
   functions and worker thread of the Network Inspect sample.

Environment:

    Kernel mode

--*/


#include <ntddk.h>
#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <mstcpip.h>

#include "protocol-headers.h"
#include "inspect.h"
#include "utils.h"

__drv_allocatesMem(Mem)
TL_INSPECT_PENDED_PACKET*
AllocateAndInitializePendedPacket(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData
)
{
    TL_INSPECT_PENDED_PACKET* pendedPacket = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(TL_INSPECT_PENDED_PACKET),
        TL_INSPECT_PENDED_PACKET_POOL_TAG
    );

    if (pendedPacket == NULL)
        return NULL;

    RtlZeroMemory(pendedPacket, sizeof(TL_INSPECT_PENDED_PACKET));

    pendedPacket->direction = GetDirectionForLayer(inFixedValues->layerId);
    if (layerData != NULL)
    {
        pendedPacket->netBufferList = layerData;
        //FwpsReferenceNetBufferList(pendedPacket->netBufferList, TRUE);
    }

    NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
        FWPS_METADATA_FIELD_COMPARTMENT_ID));
    pendedPacket->compartmentId = inMetaValues->compartmentId;

    if (pendedPacket->direction == FWP_DIRECTION_OUTBOUND)
    {
    }
    else
    {
        pendedPacket->interfaceIndex =
            inFixedValues->incomingValue[
                FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
        pendedPacket->subInterfaceIndex =
            inFixedValues->incomingValue[
                FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;

        NT_ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
            FWPS_METADATA_FIELD_IP_HEADER_SIZE));
        pendedPacket->ipHeaderSize = inMetaValues->ipHeaderSize;
    }

    return pendedPacket;
}

__drv_allocatesMem(Mem)
TL_INSPECT_PENDED_FRAME*
AllocateAndInitializePendedFrame(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _Inout_opt_ void* layerData
)
{
    TL_INSPECT_PENDED_FRAME* pendedFrame = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(TL_INSPECT_PENDED_FRAME),
        TL_INSPECT_PENDED_FRAME_POOL_TAG
    );

    if (pendedFrame == NULL)
        return NULL;

    RtlZeroMemory(pendedFrame, sizeof(TL_INSPECT_PENDED_FRAME));

    pendedFrame->direction = GetDirectionForLayer(inFixedValues->layerId);
    if (layerData != NULL)
    {
        pendedFrame->netBufferList = layerData;
        //FwpsReferenceNetBufferList(pendedFrame->netBufferList, TRUE);
    }

    if (pendedFrame->direction == FWP_DIRECTION_OUTBOUND)
    {
        pendedFrame->interfaceIndex =
            inFixedValues->incomingValue[
                FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_INTERFACE_INDEX].value.uint32;
        pendedFrame->ndisPortNumber =
            inFixedValues->incomingValue[
                FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_NDIS_PORT].value.uint32;
    }
    else
    {
        pendedFrame->interfaceIndex =
            inFixedValues->incomingValue[
                FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_INTERFACE_INDEX].value.uint32;
        pendedFrame->ndisPortNumber =
            inFixedValues->incomingValue[
                FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_NDIS_PORT].value.uint32;

        pendedFrame->ethernetMacHeaderSize = sizeof(ETHERNET_HEADER);
    }

    return pendedFrame;
}

void
FreePendedPacket(
    _Inout_ __drv_freesMem(Mem) TL_INSPECT_PENDED_PACKET* packet
)
{
    //if (packet->netBufferList != NULL)
    //    FwpsDereferenceNetBufferList(packet->netBufferList, FALSE);

    ExFreePoolWithTag(packet, TL_INSPECT_PENDED_PACKET_POOL_TAG);
}

void
FreePendedFrame(
    _Inout_ __drv_freesMem(Mem) TL_INSPECT_PENDED_FRAME* frame
)
{
    //if (frame->netBufferList != NULL)
    //    FwpsDereferenceNetBufferList(frame->netBufferList, FALSE);

    ExFreePoolWithTag(frame, TL_INSPECT_PENDED_FRAME_POOL_TAG);
}

void
PrintChecksumStatus(
    NET_BUFFER_LIST* netBufferList,
    FWP_DIRECTION direction
)
{
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO ChecksumInfo;
    ChecksumInfo.Value = (ULONG)(ULONG_PTR)NET_BUFFER_LIST_INFO(netBufferList,
        TcpIpChecksumNetBufferListInfo);

    if (direction == FWP_DIRECTION_OUTBOUND)
    {
        DbgPrint("   (Checksum: %u %u %u)\n",
            ChecksumInfo.Transmit.NdisPacketIpChecksum,
            ChecksumInfo.Transmit.NdisPacketTcpChecksum,
            ChecksumInfo.Transmit.NdisPacketUdpChecksum
        );
    }
    else
    {
        DbgPrint("   (Checksum: succeeded %u %u %u, failed %u %u %u)\n",
            ChecksumInfo.Receive.NdisPacketIpChecksumSucceeded,
            ChecksumInfo.Receive.NdisPacketTcpChecksumSucceeded,
            ChecksumInfo.Receive.NdisPacketUdpChecksumSucceeded,
            ChecksumInfo.Receive.NdisPacketIpChecksumFailed,
            ChecksumInfo.Receive.NdisPacketTcpChecksumFailed,
            ChecksumInfo.Receive.NdisPacketUdpChecksumFailed
        );
    }
}

void
PrintPacket(
    _In_ TL_INSPECT_PENDED_PACKET * packet
)
{
    DbgPrint(" * %s Packet:\n",
        packet->direction == FWP_DIRECTION_OUTBOUND ? "Outbound" : "Inbound");

    PrintChecksumStatus(packet->netBufferList, packet->direction);

    if (packet->ipHeaderSize)  // FWP_DIRECTION_INBOUND
    {
        // trans header -> IP header
        RetreatPacketBuffer(packet->netBufferList, packet->ipHeaderSize);
    }
    // -> IP header

    PrintIPHeader(packet->netBufferList);

    if (packet->ipHeaderSize)  // FWP_DIRECTION_INBOUND
    {
        // IP header -> trans header
        AdvancePacketBuffer(packet->netBufferList, packet->ipHeaderSize);
    }
}

void
PrintFrame(
    _In_ TL_INSPECT_PENDED_FRAME* frame
)
{
    DbgPrint(" * %s Frame:\n",
        frame->direction == FWP_DIRECTION_OUTBOUND ? "Outbound" : "Inbound");

    PrintChecksumStatus(frame->netBufferList, frame->direction);

    if (frame->ethernetMacHeaderSize)  // FWP_DIRECTION_INBOUND
    {
        // IP header -> MAC header
        RetreatPacketBuffer(frame->netBufferList, frame->ethernetMacHeaderSize);
    }
    // -> MAC header

    PrintEthernetHeader(frame->netBufferList);

    if (frame->ethernetMacHeaderSize)  // FWP_DIRECTION_INBOUND
    {
        // MAC header -> IP header
        AdvancePacketBuffer(frame->netBufferList, frame->ethernetMacHeaderSize);
    }
}

void
PrintEthernetHeader(
    _In_ NET_BUFFER_LIST* netBufferList
)
{
    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    ETHERNET_HEADER* pEthernetHeader = NdisGetDataBuffer(pNetBuffer, sizeof(ETHERNET_HEADER), NULL, 1, 0);
    if (!pEthernetHeader)
        return;

    UINT16 typeCode = RtlUshortByteSwap(pEthernetHeader->type);
    CHAR macAddr1[20], macAddr2[20];
    RtlEthernetAddressToStringA((const DL_EUI48 *)pEthernetHeader->pSourceAddress, macAddr1);
    RtlEthernetAddressToStringA((const DL_EUI48 *)pEthernetHeader->pDestinationAddress, macAddr2);

    DbgPrint("  * Ethernet Header (%s -> %s, type 0x%04X)\n",
        macAddr1, macAddr2, typeCode);

    // Print Next Protocol Headers
    switch (typeCode)
    {
    case NDIS_ETH_TYPE_IPV4:
        AdvancePacketBuffer(netBufferList, sizeof(ETHERNET_HEADER));
        PrintIPHeader(netBufferList);
        RetreatPacketBuffer(netBufferList, sizeof(ETHERNET_HEADER));
        break;
    case NDIS_ETH_TYPE_ARP:
        AdvancePacketBuffer(netBufferList, sizeof(ETHERNET_HEADER));
        PrintARPHeader(netBufferList);
        RetreatPacketBuffer(netBufferList, sizeof(ETHERNET_HEADER));
        break;
    }
}

void
PrintARPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
)
{
    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    ARP_IP_V4_HEADER* pArpHeader = NdisGetDataBuffer(pNetBuffer, sizeof(ARP_IP_V4_HEADER), NULL, 1, 0);
    if (!pArpHeader)
        return;

    UINT16 hardwareType = RtlUshortByteSwap(pArpHeader->hardwareType);
    UINT16 protocolType = RtlUshortByteSwap(pArpHeader->protocolType);
    UINT16 opCode = RtlUshortByteSwap(pArpHeader->operation);

    if (hardwareType != 0x0001 || protocolType != NDIS_ETH_TYPE_IPV4 ||
        pArpHeader->hardwareAddressLength != 0x06 || pArpHeader->protocolAddressLength != 0x04)
    {
        DbgPrint("  * ARP Header (hardware 0x%04X / len %u, protocol 0x%04X / len %u, op %u)\n",
            hardwareType, pArpHeader->hardwareAddressLength,
            protocolType, pArpHeader->protocolAddressLength,
            opCode);
        return;
    }

    CHAR macAddr1[20], macAddr2[20];
    RtlEthernetAddressToStringA((const DL_EUI48 *)pArpHeader->pSenderHardwareAddress, macAddr1);
    RtlEthernetAddressToStringA((const DL_EUI48 *)pArpHeader->pTargetHardwareAddress, macAddr2);

    CHAR ipAddr1[20], ipAddr2[20];
    RtlIpv4AddressToStringA((const IN_ADDR *)pArpHeader->pSenderProtocolAddress, ipAddr1);
    RtlIpv4AddressToStringA((const IN_ADDR *)pArpHeader->pTargetProtocolAddress, ipAddr2);

    DbgPrint("  * ARP Header (hardware 0x%04X, protocol 0x%04X, op %u, %s/%s -> %s/%s)\n",
        hardwareType, protocolType, opCode,
        macAddr1, ipAddr1, macAddr2, ipAddr2);
}

void
PrintIPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
)
{
    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    IP_HEADER_V4* pIPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(IP_HEADER_V4), NULL, 1, 0);
    if (!pIPHeader)
        return;

    UINT32 ipLength = pIPHeader->headerLength * 4;
    CHAR ipAddr1[20], ipAddr2[20];
    RtlIpv4AddressToStringA((const IN_ADDR *)pIPHeader->pSourceAddress, ipAddr1);
    RtlIpv4AddressToStringA((const IN_ADDR *)pIPHeader->pDestinationAddress, ipAddr2);
    DbgPrint("  * IP Header (%s -> %s, length %u/%u, protocol %u, checksum 0x%04X)\n",
        ipAddr1, ipAddr2, pIPHeader->totalLength, ipLength,
        pIPHeader->protocol, pIPHeader->checksum);

    // Print Next Protocol Headers
    switch (pIPHeader->protocol)
    {
    case IPPROTO_ICMP:
        AdvancePacketBuffer(netBufferList, ipLength);
        PrintICMPHeader(netBufferList);
        RetreatPacketBuffer(netBufferList, ipLength);
        break;
    case IPPROTO_TCP:
        AdvancePacketBuffer(netBufferList, ipLength);
        PrintTCPHeader(netBufferList);
        RetreatPacketBuffer(netBufferList, ipLength);
        break;
    case IPPROTO_UDP:
        AdvancePacketBuffer(netBufferList, ipLength);
        PrintUDPHeader(netBufferList);
        RetreatPacketBuffer(netBufferList, ipLength);
        break;
    }
}

void
PrintICMPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
)
{
    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    ICMP_HEADER_V4* pICMPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(ICMP_HEADER_V4), NULL, 1, 0);
    if (!pICMPHeader)
        return;

    DbgPrint("  * ICMP Header (type %u, code %u, checksum 0x%04X)\n",
        pICMPHeader->type, pICMPHeader->code, RtlUshortByteSwap(pICMPHeader->checksum));
}

void
PrintTCPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
)
{
    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    TCP_HEADER* pTCPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(TCP_HEADER), NULL, 1, 0);
    if (!pTCPHeader)
        return;

    DbgPrint("  * TCP Header (%u -> %u, seq %u, ack %u, SYN %u, ACK %u, FIN %u, RST %u, checksum 0x%04X)\n",
        RtlUshortByteSwap(pTCPHeader->sourcePort), RtlUshortByteSwap(pTCPHeader->destinationPort),
        pTCPHeader->sequenceNumber, pTCPHeader->acknowledgementNumber,
        pTCPHeader->SYN, pTCPHeader->ACK, pTCPHeader->FIN, pTCPHeader->RST, pTCPHeader->checksum);
}

void
PrintUDPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
)
{
    NET_BUFFER* pNetBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    UDP_HEADER* pUDPHeader = NdisGetDataBuffer(pNetBuffer, sizeof(UDP_HEADER), NULL, 1, 0);
    if (!pUDPHeader)
        return;

    DbgPrint("  * UDP Header (%u -> %u, length %u, checksum 0x%04X)\n",
        RtlUshortByteSwap(pUDPHeader->sourcePort), RtlUshortByteSwap(pUDPHeader->destinationPort),
        pUDPHeader->length, pUDPHeader->checksum);
}

void
RetreatPacketBuffer(
    _In_ NET_BUFFER_LIST* netBufferList,
    _In_ ULONG offsetDelta
)
{
    NDIS_STATUS ndisStatus;
    NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);

    ndisStatus = NdisRetreatNetBufferDataStart(netBuffer, offsetDelta, 0, NULL);
    _Analysis_assume_(ndisStatus == NDIS_STATUS_SUCCESS);
}

void
AdvancePacketBuffer(
    _In_ NET_BUFFER_LIST* netBufferList,
    _In_ ULONG offsetDelta
)
{
    NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    NdisAdvanceNetBufferDataStart(netBuffer, offsetDelta, FALSE, NULL);
}
