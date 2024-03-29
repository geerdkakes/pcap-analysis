// configuration file read by 'index.js'
//
// please note this file is in javascript format

var config ={};

// ------------------------------------------------------------------------
// filenames
//
// pcap file name (input)

config.inputfileA = "systemA.pcap";
config.inputfileB = "systemB.pcap";

// csv output file name (output)
config.resultFilename = "matches.csv";

// Note: if you capture packets using tcpdump. Consider using the following flags:
//   tcpdum -i eth0 -n -B 4096 -w dump.pcap
//     -B <buffer size>, eg: -B 4096 for a buffer of 4MByte
//     -n to not reverse lookup domain names
//     -w <filename> to write all data to a file
//     -i <interface>
//  
//   If the command reports that packets were dropped by the kernel you might want to increase 
//   buffersize or give some more time to establish a buffer.



// ----------------------------------------------------------------------
// Timing variables:
// maximum delay in which packets are still matched.
// be warned. The larger the delay (in useconds), the longer the algorith will run
config.max_delay = 500000; // 0,5 seconds

// maximum error allowed to match packets. The larger this value the longer the search
config.max_error = 500000; // 0,5 seconds

// offset to use if source and destination are not in sync
config.offset = 0;

// -----------------------------------------------------------------------
// Variables for a slices output. This converts a pcap input file into multiple csv output files.
// In the filename the date, starttime, endtime and basename is specified
//
// window length in seconds, used in combination with command line flag -i to specify single input pcap file
config.window_length = 300;  // write out a new file every 5 minutes

// write in parts, only when command line flag -i is used to specify single input pcap file
config.sliced_output = true;

// basename, used to specify part of the filename that is used with a sliced output.
config.basename = "testbasename"

// decoding combination
config.decoders = [
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5005, operator: "eq"}
            ],
            protocol: "rtp"
        },
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5006, operator: "eq"}
            ],
            protocol: "rtp"
        },
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5007, operator: "eq"}
            ],
            protocol: "rtp"
        },
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5008, operator: "eq"}
            ],
            protocol: "rtp"
        }
    ]

// ------------------------------------------------------------------------
// match array
//
// defines the headers which need to be matched from two packets
//
// currently only type match is supported. 
// This array is used by the function match_array in 'compare_pcap.js'
config.match_array = [
    { type: "match", id: "protocol" },
    { type: "match", id: "udpHeader.dest_port" },
    { type: "match", id:  "dataChksum" }
];


// -----------------------------------------------------------------------
// header fields
// 
// defines the header fiels used to store the compared packets in a csv file format
// 
// used by 'compare_pcap.js'
config.header_fields = [
    {"id": "source_packetNr", "title": "source_packetNr"}, 
    {"id": "destination_packetNr", "title": "destination_packetNr"},
    {"id": "source_pcapPacketHeader.ts_sec", "title": "source_pcapPacketHeader.ts_sec"},
    {"id": "source_pcapPacketHeader.ts_usec", "title": "source_pcapPacketHeader.ts_usec"},
    {"id": "destination_pcapPacketHeader.ts_sec", "title": "destination_pcapPacketHeader.ts_sec"},
    {"id": "destination_pcapPacketHeader.ts_usec", "title": "destination_pcapPacketHeader.ts_usec"},
    {"id": "delay_usec", "title": "delay_usec"},
    {"id": "pcapPacketHeader.orig_len", "title": "pcapPacketHeader.orig_len"},
    {"id": "udpHeader.dest_port", "title": "udpHeader.dest_port"},
    {"id": "udpHeader.src_port", "title": "udpHeader.src_port"},
    {"id": "protocol", "title": "protocol"},
    {"id": "rtpHeader.sequence_number", "title": "rtpHeader.sequence_number"},
    {"id": "rtpHeader.timestamp", "title": "rtpHeader.timestamp"},
    {"id": "rtpHeader.marker", "title": "rtpHeader.marker"},
    {"id": "lost", "title": "lost"}
];

// -----------------------------------------------------------------------
// destination filter set
// 
// Defines the filters to filter the packets at the destination.
// Extra objects can be added with field and value defined.
// All objects together in the level two array define one packet 
// to be matched and form an AND relation. 
// 
// The operator can be one of the following values:
// eq: equal
// ne: not equal
// gt: greater than
// lt: less than
// ge: greater or equal
// le: less or equal
// contains: contains a value
//
// used by 'filter_packet' function defined in 'index.js'

remote_station = [
    [
        // identifies control packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 22, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 0, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 2, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5001, operator: "eq"},
        {type: "direction", value: "up" }
    ],
    [
        // identifies time reference packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 22, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 0, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 2, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5002, operator: "eq"},
        {type: "match", type: "direction", value: "up" }
    ],
    [
        // identifies video packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 22, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 0, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 2, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5005, operator: "eq"},
        {type: "direction", value: "up" }
    ],
    [
        // identifies packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 22, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 0, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 2, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5006, operator: "eq"},
        {type: "direction", value: "up" }
    ],        
    [
        // identifies packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 22, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 0, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 2, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5007, operator: "eq"},
        {type: "direction", value: "up" }
    ],
    [
        // identifies packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 22, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 0, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 2, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5008, operator: "eq"},
        {type: "direction", value: "up" }
    ]
];

// -----------------------------------------------------------------------
// source filter set
// 
// Defines the filters to filter the packets at the source.
// Extra objects can be added with field and value defined.
// All objects together in the level two array define one packet 
// to be matched and form a AND relation. 
// 
// used by 'filter_packet' function defined in 'index.js'
filterset_remote_car = [
    [
        // identifies video packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5005, operator: "eq"},
        {type: "direction", value: "up" }
    ],
    [
        // identifies video packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5006, operator: "eq"},
        {type: "direction", value: "up" }
    ],        
    [
        // identifies video packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {field: "udpHeader.dest_port", value: 5007, operator: "eq"},
        {type: "direction", value: "up" }
    ],
    [
        // identifies video packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5008, operator: "eq"},
        {type: "direction", value: "up" }
    ],
    [
        // identifies time reference packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5002, operator: "eq"},
        {type: "direction", value: "up" }
    ],
    [
        // identifies control packets arriving at remote station
        {type: "match", field: "protocol", value: "udp", operator: "eq"},
        {type: "match", field: "ipHeader.src.0", value: 192, operator: "eq"},
        {type: "match", field: "ipHeader.src.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.src.2", value: 1, operator: "eq"},
        {type: "match", field: "ipHeader.src.3", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.0", value: 10, operator: "eq"},
        {type: "match", field: "ipHeader.dst.1", value: 168, operator: "eq"},
        {type: "match", field: "ipHeader.dst.2", value: 207, operator: "eq"},
        {type: "match", field: "ipHeader.dst.3", value: 3, operator: "eq"},
        {type: "match", field: "udpHeader.dest_port", value: 5001, operator: "eq"},
        {type: "direction", value: "up" }
    ]
];

// testrun with source from vehicle and destination for gNodeB

config.filter_setA = filterset_remote_car;
config.filter_setB = remote_station;

// export the config object
module.exports = config;
