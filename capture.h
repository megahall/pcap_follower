#ifndef _CAPTURE_H_
#define _CAPTURE_H_

/*
 * Defines structures needed to write correct libpcap files.
 * Read pcap-int.h from the libpcap source code if you are curious.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>

#define CAPTURE_VERSION_MAJOR 2 // do not change
#define CAPTURE_VERSION_MINOR 4 // do not change

#define CAPTURE_MAGIC        0xA1B2C3D4 // do not change
#define CAPTURE_MAGIC_BAD    0xD4C3B2A1 // do not change
#define CAPTURE_SNAPLEN      0xFFFF     // do not change
#define CAPTURE_MAXLEN       9238
#define CAPTURE_MAC_ETHERNET 1          // do not change

#define CAPTURE_ALIGNMENT    64
#define CAPTURE_MAX_BULK     32
#define CAPTURE_PATH_MAX     (PATH_MAX * 2)

/*
 * This is the same as 'pcap_file_header' which is used in libpcap files.
 *
 * Do not change the format of this structure in any way.
 */
typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
     int32_t thiszone;      /* gmt to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length saved portion of each pkt */
    uint32_t linktype;      /* data link type (LINKTYPE_*) */
} capture_file_header_t;

/*
 * This is a timeval as stored in a libpcap file. Libpcap always uses
 * 32-bit sec and usec values. This is signed because time_t really is signed
 * (to allow math).
 *
 * Do not change the format of this structure in any way.
 */
typedef struct {
    union {
        struct {
            int32_t sec;  /* seconds */
            int32_t usec; /* microseconds */
        };
        int64_t sec_usec;
    };
} capture_timeval_t;

/*
 * This is the same as 'pcap_pkthdr' which is used in libpcap files.
 *
 * Do not change the format of this structure in any way.
 */
typedef struct {
    capture_timeval_t time;    /* time stamp */
    uint32_t          wlength; /* writing length */
    uint32_t          clength; /* capture length */
} capture_packet_header_t;

/*
 * Special structure which includes a packet header and a data pointer.
 * 
 * Do not change the format of this structure in any way.
 */
typedef struct {
    capture_packet_header_t header;
    uint8_t*                data;
} capture_packet_t;

#endif /* _CAPTURE_H_ */
