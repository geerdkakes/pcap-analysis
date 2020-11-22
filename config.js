// configuration file read by 'index.js'
//
// please note this file is in javascript format

var config ={};

// ------------------------------------------------------------------------
// filenames
//
// pcap file name (input)
config.sourcePcapName = "/Users/geerd/data/cases/helmond/drive test/20-11-2020 remote driving test/2020-11-20_12.52.33_remotecar_eth0.pcap";
config.destinationPcapName = "/Users/geerd/data/cases/helmond/drive test/20-11-2020 remote driving test/gNodeB-test1-12.55.pcap";
// 
// csv file names (output)
config.sourceCsvName = "/Users/geerd/data/cases/helmond/drive test/20-11-2020 remote driving test/2020-11-20_12.52.33_remotecar_eth0.csv"
config.destinationCsvName = "/Users/geerd/data/cases/helmond/drive test/20-11-2020 remote driving test/gNodeB-test1-12.55.csv";
config.resultFilename = "/Users/geerd/data/cases/helmond/drive test/20-11-2020 remote driving test/test_3.csv";



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
    {"id": "frameCnt", "title": "frameCnt"},
    {"id": "source_pcapPacketHeader.ts_sec", "title": "source_pcapPacketHeader.ts_sec"},
    {"id": "source_pcapPacketHeader.ts_usec", "title": "source_pcapPacketHeader.ts_usec"},
    {"id": "destination_pcapPacketHeader.ts_sec", "title": "destination_pcapPacketHeader.ts_sec"},
    {"id": "destination_pcapPacketHeader.ts_usec", "title": "destination_pcapPacketHeader.ts_usec"},
    {"id": "pcapPacketHeader.orig_len", "title": "pcapPacketHeader.orig_len"},
    {"id": "udpHeader.dest_port", "title": "udpHeader.dest_port"},
    {"id": "udpHeader.src_port", "title": "udpHeader.src_port"},
    {"id": "protocol", "title": "protocol"},
    {"id": "lost", "title": "lost"}
];

// -----------------------------------------------------------------------
// destination filter set
// 
// Defines the filters to filter the packets at the destination.
// Extra objects can be added with field and value defined.
// All objects together in the level two array define one packet 
// to be matched and form a AND relation. 
// 
// used by 'filter_packet' function defined in 'index.js'
remote_station = [
    [
        // identifies control packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 10},
        {field: "ipHeader.src.1", value: 38},
        {field: "ipHeader.src.2", value: 253},
        {field: "ipHeader.src.3", value: 128},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 39},
        {field: "ipHeader.dst.2", value: 200},
        {field: "ipHeader.dst.3", value: 121},
        {field: "udpHeader.dest_port", value: 5001}
    ],
    [
        // identifies time reference packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 10},
        {field: "ipHeader.src.1", value: 38},
        {field: "ipHeader.src.2", value: 253},
        {field: "ipHeader.src.3", value: 128},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 39},
        {field: "ipHeader.dst.2", value: 200},
        {field: "ipHeader.dst.3", value: 121},
        {field: "udpHeader.dest_port", value: 5002}
    ],
    [
        // identifies video packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 10},
        {field: "ipHeader.src.1", value: 38},
        {field: "ipHeader.src.2", value: 253},
        {field: "ipHeader.src.3", value: 128},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 39},
        {field: "ipHeader.dst.2", value: 200},
        {field: "ipHeader.dst.3", value: 121},
        {field: "udpHeader.dest_port", value: 5005}
    ],
    [
        // identifies packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 10},
        {field: "ipHeader.src.1", value: 38},
        {field: "ipHeader.src.2", value: 253},
        {field: "ipHeader.src.3", value: 128},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 39},
        {field: "ipHeader.dst.2", value: 200},
        {field: "ipHeader.dst.3", value: 121},
        {field: "udpHeader.dest_port", value: 5006}
    ],        
    [
        // identifies packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 10},
        {field: "ipHeader.src.1", value: 38},
        {field: "ipHeader.src.2", value: 253},
        {field: "ipHeader.src.3", value: 128},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 39},
        {field: "ipHeader.dst.2", value: 200},
        {field: "ipHeader.dst.3", value: 121},
        {field: "udpHeader.dest_port", value: 5007}
    ],
    [
        // identifies packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 10},
        {field: "ipHeader.src.1", value: 38},
        {field: "ipHeader.src.2", value: 253},
        {field: "ipHeader.src.3", value: 128},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 39},
        {field: "ipHeader.dst.2", value: 200},
        {field: "ipHeader.dst.3", value: 121},
        {field: "udpHeader.dest_port", value: 5008}
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
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 22},
        {field: "ipHeader.src.1", value: 1},
        {field: "ipHeader.src.2", value: 0},
        {field: "ipHeader.src.3", value: 3},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 38},
        {field: "ipHeader.dst.2", value: 253},
        {field: "ipHeader.dst.3", value: 2},
        {field: "udpHeader.dest_port", value: 5005}
    ],
    [
        // identifies video packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 22},
        {field: "ipHeader.src.1", value: 1},
        {field: "ipHeader.src.2", value: 0},
        {field: "ipHeader.src.3", value: 3},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 38},
        {field: "ipHeader.dst.2", value: 253},
        {field: "ipHeader.dst.3", value: 2},
        {field: "udpHeader.dest_port", value: 5006}
    ],        
    [
        // identifies video packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 22},
        {field: "ipHeader.src.1", value: 1},
        {field: "ipHeader.src.2", value: 0},
        {field: "ipHeader.src.3", value: 3},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 38},
        {field: "ipHeader.dst.2", value: 253},
        {field: "ipHeader.dst.3", value: 2},
        {field: "udpHeader.dest_port", value: 5007}
    ],
    [
        // identifies video packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 22},
        {field: "ipHeader.src.1", value: 1},
        {field: "ipHeader.src.2", value: 0},
        {field: "ipHeader.src.3", value: 3},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 38},
        {field: "ipHeader.dst.2", value: 253},
        {field: "ipHeader.dst.3", value: 2},
        {field: "udpHeader.dest_port", value: 5008}
    ],
    [
        // identifies time reference packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 22},
        {field: "ipHeader.src.1", value: 1},
        {field: "ipHeader.src.2", value: 0},
        {field: "ipHeader.src.3", value: 3},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 38},
        {field: "ipHeader.dst.2", value: 253},
        {field: "ipHeader.dst.3", value: 2},
        {field: "udpHeader.dest_port", value: 5002}
    ],
    [
        // identifies control packets arriving at remote station
        {field: "protocol", value: "udp"},
        {field: "ipHeader.src.0", value: 22},
        {field: "ipHeader.src.1", value: 1},
        {field: "ipHeader.src.2", value: 0},
        {field: "ipHeader.src.3", value: 3},
        {field: "ipHeader.dst.0", value: 10},
        {field: "ipHeader.dst.1", value: 38},
        {field: "ipHeader.dst.2", value: 253},
        {field: "ipHeader.dst.3", value: 2},
        {field: "udpHeader.dest_port", value: 5001}
    ]
];

// testrun with source from vehicle and destination for gNodeB

config.sourceFilterset = filterset_remote_car;
config.destFilterSet = filterset_remote_car;

// export the config object
module.exports = config;