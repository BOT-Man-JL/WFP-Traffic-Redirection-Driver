/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   This file declares the utility/helper functions for use by the classify
   functions and worker thread of the Network Inspect sample.

Environment:

    Kernel mode

--*/

#ifndef _TL_INSPECT_UTILS_H_
#define _TL_INSPECT_UTILS_H_

__inline
FWP_DIRECTION GetDirectionForLayer(
    _In_ UINT16 layerId
)
{
    FWP_DIRECTION direction;

    switch (layerId)
    {
    case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
    case FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET:
        direction = FWP_DIRECTION_OUTBOUND;
        break;
    case FWPS_LAYER_INBOUND_IPPACKET_V4:
    case FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET:
        direction = FWP_DIRECTION_INBOUND;
        break;
    default:
        direction = FWP_DIRECTION_MAX;
        NT_ASSERT(0);
    }

    return direction;
}

// Packet / Frame

__drv_allocatesMem(Mem)
TL_INSPECT_PENDED_PACKET*
AllocateAndInitializePendedPacket(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    _Inout_opt_ void* layerData
);

__drv_allocatesMem(Mem)
TL_INSPECT_PENDED_FRAME*
AllocateAndInitializePendedFrame(
    _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    _Inout_opt_ void* layerData
);

void
FreePendedPacket(
    _Inout_ __drv_freesMem(Mem) TL_INSPECT_PENDED_PACKET* packet
);

void
FreePendedFrame(
    _Inout_ __drv_freesMem(Mem) TL_INSPECT_PENDED_FRAME* frame
);

void
PrintPacket(
    _In_ TL_INSPECT_PENDED_PACKET* packet
);

void
PrintFrame(
    _In_ TL_INSPECT_PENDED_FRAME* frame
);

// Print Header

void
PrintEthernetHeader(
    _In_ NET_BUFFER_LIST* netBufferList
);

void
PrintARPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
);

void
PrintIPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
);

void
PrintICMPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
);

void
PrintTCPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
);

void
PrintUDPHeader(
    _In_ NET_BUFFER_LIST* netBufferList
);

// Helpers

void
RetreatPacketBuffer(
    _In_ NET_BUFFER_LIST* netBufferList,
    _In_ ULONG offsetDelta
);

void
AdvancePacketBuffer(
    _In_ NET_BUFFER_LIST* netBufferList,
    _In_ ULONG offsetDelta
);

#endif // _TL_INSPECT_UTILS_H_
