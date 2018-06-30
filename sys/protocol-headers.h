
//
// Protocol Headers
//

#ifndef _TL_PROTOCOL_HEADERS_H_
#define _TL_PROTOCOL_HEADERS_H_

#pragma warning(push)

#pragma warning(disable: 4201)
#pragma warning(disable: 4214)

/*
    RFC 894 - A Standard for the Transmission of     <br>
              IP Datagrams over Ethernet Networks    <br>
                                                     <br>
    0                   1                   2        <br>
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3  <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                                               | <br>
   +            Destination MAC Address            + <br>
   |                                               | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                                               | <br>
   +               Source MAC Address              + <br>
   |                                               | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |              Type             |    Data...    | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
                                                     <br>
   RFC_REF: http://www.faqs.org/rfcs/rfc894.html     <br>
*/

typedef struct _ETHERNET_HEADER_
{
   BYTE   pDestinationAddress[6];
   BYTE   pSourceAddress[6];
   UINT16 type;
}ETHERNET_HEADER;

/*
   RFC 826 - An Ethernet Address Resolution Protocol <br>
                                                     <br>
   RFC_REF: http://www.faqs.org/rfcs/rfc826.html     <br>
*/

typedef struct _ARP_IP_V4_HEADER_
{
    UINT16 hardwareType;
    UINT16 protocolType;
    UINT8  hardwareAddressLength;
    UINT8  protocolAddressLength;
    UINT16 operation;
    BYTE   pSenderHardwareAddress[6];
    BYTE   pSenderProtocolAddress[sizeof(UINT32)];
    BYTE   pTargetHardwareAddress[6];
    BYTE   pTargetProtocolAddress[sizeof(UINT32)];
}ARP_IP_V4_HEADER;

/*
                     RFC 791 - Internet Protocol                     <br>
                                                                     <br>
    0                   1                   2                   3    <br>
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |Version|  IHL  |Type of Service|         Total Length          | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |        Identification         |Flags|     Fragment Offset     | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |  Time to Live |     Protocol  |        Header Checksum        | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                        Source Address                         | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                      Destination Address                      | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                    Options                    |    Padding    | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
                                                                     <br>
   RFC_REF: http://www.faqs.org/rfcs/rfc791.html                     <br>
*/

typedef struct _IP_HEADER_V4_
{
    union
    {
        UINT8 versionAndHeaderLength;
        struct
        {
            UINT8 headerLength : 4;
            UINT8 version : 4;
        };
    };
    union
    {
        UINT8  typeOfService;
        UINT8  differentiatedServicesCodePoint;
        struct
        {
            UINT8 explicitCongestionNotification : 2;
            UINT8 typeOfService6bit : 6;
        };
    };
    UINT16 totalLength;
    UINT16 identification;
    union
    {
        UINT16 flagsAndFragmentOffset;
        struct
        {
            UINT16 fragmentOffset : 13;
            UINT16 flags : 3;
        };
    };
    UINT8  timeToLive;
    UINT8  protocol;
    UINT16 checksum;
    BYTE   pSourceAddress[sizeof(UINT32)];
    BYTE   pDestinationAddress[sizeof(UINT32)];
}IP_HEADER_V4, *PIP_HEADER_V4;

/*
             RFC 792 - Internet Control Message Protocol             <br>
                                                                     <br>
    0                   1                   2                   3    <br>
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |     Type      |     Code      |           Checksum            | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |              Variable (Dependent on Type / Code)              | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
                                                                     <br>
   RFC_REF: http://www.faqs.org/rfcs/rfc792.html                     <br>
*/

typedef struct _ICMP_HEADER_V4_
{
   UINT8  type;
   UINT8  code;
   UINT16 checksum;
/*
   union
   {
      ECHO_MESSAGE                    echo;
      DESTINATION_UNREACHABLE_MESSAGE destinationUnreachable;
      SOURCE_QUENCH_MESSAGE           sourceQuench;
      REDIRECT_MESSAGE                redirect;
      TIME_EXCEEDED_MESSAGE           timeExceeded;
      PARAMETER_PROBLEM_MESSAGE       parameterProblem;
      TIMESTAMP_MESSAGE               timestamp;
      INFORMATION_MESSAGE             information;
   };
*/
}ICMP_HEADER_V4, *PICMP_HEADER_V4;

/*
               RFC 793 - Transmission Control Protocol               <br>
                                                                     <br>
    0                   1                   2                   3    <br>
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |          Source Port          |       Destination Port        | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                        Sequence Number                        | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                     Acknowledgment Number                     | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |Offset |Rsvd |N|C|E|U|A|P|R|S|F|            Window             | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |           Checksum            |        Urgent Pointer         | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |                    Options                    |    Padding    | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
                                                                     <br>
   RFC_REF: http://www.faqs.org/rfcs/rfc793.html                     <br>
*/

typedef struct _TCP_HEADER_
{
    UINT16 sourcePort;
    UINT16 destinationPort;
    UINT32 sequenceNumber;
    UINT32 acknowledgementNumber;
    union
    {
        UINT8 dataOffsetReservedAndNS;
        struct
        {
            UINT8 nonceSum : 1;
            UINT8 reserved : 3;
            UINT8 dataOffset : 4;
        }dORNS;
    };
    union
    {
        UINT8 controlBits;
        struct
        {
            UINT8 FIN : 1;
            UINT8 SYN : 1;
            UINT8 RST : 1;
            UINT8 PSH : 1;
            UINT8 ACK : 1;
            UINT8 URG : 1;
            UINT8 ECE : 1;
            UINT8 CWR : 1;
        };
    };
    UINT16 window;
    UINT16 checksum;
    UINT16 urgentPointer;
}TCP_HEADER, *PTCP_HEADER;

/*
                    RFC 768 - User Datagram Protocol                 <br>
                                                                     <br>
    0                   1                   2                   3    <br>
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |          Source Port          |       Destination Port        | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   |            Length             |           Checksum            | <br>
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
                                                                     <br>
   RFC_REF: http://www.faqs.org/rfcs/rfc768.html                     <br>
*/

typedef struct _UDP_HEADER_
{
    UINT16 sourcePort;
    UINT16 destinationPort;
    UINT16 length;
    UINT16 checksum;
}UDP_HEADER, *PUDP_HEADER;

#pragma warning(pop)

#endif // _TL_PROTOCOL_HEADERS_H_
