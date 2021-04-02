// read_pcap.js
// main function is read_pcap which returns a promise.
// read_pcap walks through the whole pcapfile and reads each packet
// using the pcapfile object.
// this function will also store the results to a csv file
// all main data is stored in the pcapfile object defined in 'pcapfile.js'
// read_pcap is called from 'index.js'

// get main pcapfile object
var PcapFile = require('./pcapfile');

// get header fields defining which fields are stored in a csv file
var header_fields = require('./header_fields');

// get createCsvWriter used to store data in a csv file
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

// Determine if we want to keep all data in memory. Needed when we want to
// compare the results. 
var keep_buffer = false;

// determine how manu packets are cached before writing to file
const write_to_csv = 1000;


// function to read packet header and ethernet header
// based on ethernet type an other read_header_function is called
// this function returns a promise
function readPacket(pcapdata){
    if (pcapdata.fileNotCompleted()) {
        return pcapdata.readPacketHeader(pcapdata)
            .then(function(result){
                switch (result._ethernet) {
                    case 1:
                        return result.readEthernetHeader(result)
                            .then(function(result){
                                switch(result._currentPacket.ethernetHeader.ethernet_type) {
                                    case 0x800:
                                        return readIPPacket(result);
                                    case 0x806:
                                        return readARPPacket(result);
                                    case 0x86dd:
                                        return readIPv6Packet(result);
                                    default:
                                        result._logger.info("Unknown ethernet protocol at packet " + 
                                                    result._packetCnt + 
                                                    " with ethernet type/length 0x" + 
                                                    result._currentPacket.ethernetHeader.ethernet_type.toString(16)
                                                    );
                                        return readGenericEthernetPacket(result);
                                }
                        });
                    case 101:
                        return result.readPacketIPVersion(result)
                            .then(function(result){
                                switch (result._currentPacket.ipVersion.version) {
                                    case 4:
                                        return readIPPacket(result);
                                    case 6:
                                        return readIPv6Packet(result);
                                    default:
                                        result._logger.info("Unknown ip protocol at packet " + 
                                                            result._packetCnt + 
                                                            " with ip type: " + 
                                                            result._currentPacket.ipVersion.version.toString(16)
                                                            );
                                }
                    });
                    default:
                        result._logger.error("Unknown LINK-LAYER HEADER TYPE: " + result._ethernet);
                        return;
                }
            })
        } else {
            return pcapdata;
        }
}
function readIPv6Packet(pcapdata){
    return pcapdata.readPacketIPv6Header(pcapdata).then( function(result){
        switch(result._currentPacket.ipV6Header.nextHeader) {
            case 17: // udp packet
                return readUDPPacket(result);
            case 6: // tcp packet
                return readTCPPacket(result);
            case 1: // icmp
                result._currentPacket.protocol = "icmp";
                return readGenericIPPacket(result);
            case 0: // IPv6 Hop-by-Hop Option
                return readNexIPv6Header(result);
            case 43: // Routing Header for IPv6
                return readNexIPv6Header(result);
            case 44: // Fragment Header for IPv6
                return readNexIPv6Header(result);
            case 50: // Encapsulating Security Payload
                return readNexIPv6Header(result);
            case 51: // Authentication Header
                return readNexIPv6Header(result);
            case 60: // Destination Options for IPv6
                return readNexIPv6Header(result);
            case 135: // Mobility Header
                return readNexIPv6Header(result);
            case 139: // Host Identity Protocol
                return readNexIPv6Header(result);
            case 140: // Shim6 Protocol
                return readNexIPv6Header(result);
            case 253: // Use for experimentation and testing
                return readNexIPv6Header(result);
            case 254: // Use for experimentation and testing
                return readNexIPv6Header(result);
            default:
                result._logger.info("Unknown IP protocol at IPv6 packet " + 
                            result._packetCnt + 
                            " with type " + 
                            result._currentPacket.ethernetHeader.ethernet_type.toString(10)
                            );
                return readGenericIPv6Packet(result);
          }
    });
}
function readNexIPv6Header(pcapdata) {
    return pcapdata.readNexIPv6Header(pcapdata).then(function(result) {

        switch(result._currentPacket.ipV6OptionHeader[result._currentPacket.ipV6Header.optionHeaderCnt-1].nextHeader) {
            case 17: // udp packet
                return readUDPPacket(result);
            case 6: // tcp packet
                return readTCPPacket(result);
            case 1: // icmp
                result._currentPacket.protocol = "icmp";
                return readGenericIPPacket(result);
            case 0: // IPv6 Hop-by-Hop Option
                return readNexIPv6Header(result);
            case 43: // Routing Header for IPv6
                return readNexIPv6Header(result);
            case 44: // Fragment Header for IPv6
                return readNexIPv6Header(result);
            case 50: // Encapsulating Security Payload
                return readNexIPv6Header(result);
            case 51: // Authentication Header
                return readNexIPv6Header(result);
            case 60: // Destination Options for IPv6
                return readNexIPv6Header(result);
            case 135: // Mobility Header
                return readNexIPv6Header(result);
            case 139: // Host Identity Protocol
                return readNexIPv6Header(result);
            case 140: // Shim6 Protocol
                return readNexIPv6Header(result);
            case 253: // Use for experimentation and testing
                return readNexIPv6Header(result);
            case 254: // Use for experimentation and testing
                return readNexIPv6Header(result);
            default:
                result._logger.info("Unknown IP protocol at IPv6 packet " + 
                            result._packetCnt + 
                            " with type " + 
                            result._currentPacket.ethernetHeader.ethernet_type.toString(10)
                            );
                return readGenericIPv6Packet(result);
        }
    });
}
function readIPPacket(pcapdata){
    return pcapdata.readPacketIPHeader(pcapdata)
        .then(function(result){

            switch(result._currentPacket.ipHeader.protocol) {
                case 17: // udp packet
                    return readUDPPacket(result);
                case 6: // tcp packet
                    return readTCPPacket(result);
                case 1: // icmp
                    result._currentPacket.protocol = "icmp";
                    return readGenericIPPacket(result);
                default:
                    result._logger.info("Unknown IP protocol at IP packet " + 
                                result._packetCnt + 
                                " with type " + 
                                result._currentPacket.ipHeader.protocol.toString(10)
                                );
                    return readGenericIPPacket(result);
            }
        });
}
function readGenericEthernetPacket(pcapdata){
    return pcapdata.readgenericEthernetPacket(pcapdata);
}
function readGenericIPPacket(pcapdata){
    return pcapdata.readgenericIPPacket(pcapdata);
}
function readGenericIPv6Packet(pcapdata){
    return pcapdata.readgenericIPv6Packet(pcapdata);
}
function readUDPPacket(pcapdata) {
    return pcapdata.readPacketUDPHeader(pcapdata)
            .then(function(result){
                if (result._currentPacket.udpHeader.src_port == "2152" && result._currentPacket.udpHeader.dest_port == "2152") {
                    // port 2152 indicates gprs tunnel. first interpret this tunnel header
                    return readGprsTunnelHeader(result);
                } else {
                    return result.readDataPacket(result);
                }
            });

}
function readTCPPacket(pcapdata) {
    return pcapdata.readPacketTCPHeader(pcapdata)
            .then(function(result){
                return result.readDataPacket(result);
            });

}
function readARPPacket(pcapdata) {
    return pcapdata.readArpPacket(pcapdata);
}
function readGprsTunnelHeader(pcapdata) {
    return pcapdata.readGprsTunnelHeader(pcapdata)
             .then(function(result){
                 return readIPPacket(result);
             });
}

// function to itterate of all packets in the file
// from this function the readPacket is called which 
// will call the other read header functions
// this function will return a promise
function itteratePackets(pcapdata) {
    return readPacket(pcapdata)
            .then(function(result){
                return result.storePacket();
            })
            .then(function(result){
                return track_frames(result);
            })
            .then(function(result){
        if (result.fileNotCompleted(result)) {
            // write every 1000 packets to file
            if (result._packets.length % 5000 && result._progressBar) {
                result._progressBar.update(Math.floor(result._bytes_read/1048576));
            }
            // write every 1000 packets to file
            if ( result._packets.length % write_to_csv == 0) {
                return result._csvWriter.writeRecords(result._packets.slice((keep_buffer)?result._packetsWritenToCSV:0))
                            .then(() => {
                                return new Promise(function(resolve, reject) {
                                    result._packetsWritenToCSV += write_to_csv;
                                    // check if we need to keep the buffer and reset if not
                                    if (!keep_buffer) {
                                        result._packets.length = 0;
                                    }
                                    resolve(result);
                                });
                            })
                            .then(() => {return itteratePackets(result)});
            } else return itteratePackets(result);
        } else {
            result._logger.info("last packet read");
            return result;
        }
    });
}
// function track_frames
//
// this function tracks which packets belong to the same information frame, e.g. video frame.
function track_frames(pcdata) {
    return new Promise(function(resolve, reject){
        packet = pcdata._packets[pcdata._packets.length - 1];
        if (!packet) {
            // not defined yet exit gracefully. Might be that we are still at the beginning
            return resolve(pcdata);
        }
        if (packet.frameCnt !== undefined) {
            // already analysed
            return resolve(pcdata);
        }
        track_data = get_track_data(packet);
        if (!track_data) {
            // nothing found, exit
            return resolve(pcdata);
        }
        for (let ell of pcdata._frameTracker) {
            if (match_object(ell,track_data)) {
                // same track found
                let timeDifference = time_diff(ell['pcapPacketHeader.ts_sec'], ell['pcapPacketHeader.ts_usec'],
                                               packet['pcapPacketHeader.ts_sec'],packet['pcapPacketHeader.ts_usec']);
                // if larger than 1msec (1000usec) than we have a new frame
                if (timeDifference > 1000) {
                    // new frame found, increase frame counter
                    ell.frameCnt++;
                    ell['pcapPacketHeader.ts_sec'] = packet['pcapPacketHeader.ts_sec'];
                    ell['pcapPacketHeader.ts_usec'] = packet['pcapPacketHeader.ts_usec'];
                    packet.frameCnt = ell.frameCnt;
                    return resolve(pcdata);
                } else {
                    // same frame, store latest time
                    ell['pcapPacketHeader.ts_sec'] = packet['pcapPacketHeader.ts_sec'];
                    ell['pcapPacketHeader.ts_usec'] = packet['pcapPacketHeader.ts_usec'];
                    packet.frameCnt = ell.frameCnt;
                    return resolve(pcdata);
                }
            }
        }
        // no match found. Store track with zero counter
        track_data['pcapPacketHeader.ts_sec'] = packet['pcapPacketHeader.ts_sec'];
        track_data['pcapPacketHeader.ts_usec'] = packet['pcapPacketHeader.ts_usec'];
        track_data.frameCnt = 0;
        pcdata._frameTracker.push(track_data);
        packet.frameCnt = 0;
        return resolve(pcdata);
    });
}
// function get_ports
// 
// helper function to get object with source and destination port
// for udp and tcp
function get_track_data(packet) {
    if (!packet) {
        // no packet data return
        return;
    } 
    switch (packet.protocol) {
        case 'udp':
            return {
                protocol: 'udp', 
                srcPort: packet['udpHeader.src_port'], 
                dstPort: packet['udpHeader.dest_port'],
                dstIP0: packet['ipHeader.dst.0'],
                dstIP1: packet['ipHeader.dst.2'],
                dstIP2: packet['ipHeader.dst.3'],
                dstIP3: packet['ipHeader.dst.4'],
                srcIP0: packet['ipHeader.src.0'],
                srcIP1: packet['ipHeader.src.2'],
                srcIP2: packet['ipHeader.src.3'],
                srcIP3: packet['ipHeader.src.4']
            };
        case 'tcp':
            return {
                protocol: 'tcp', 
                srcPort: packet['tcpHeader.src_port'], 
                dstPort: packet['tcpHeader.dest_port'],
                dstIP0: packet['ipHeader.dst.0'],
                dstIP1: packet['ipHeader.dst.2'],
                dstIP2: packet['ipHeader.dst.3'],
                dstIP3: packet['ipHeader.dst.4'],
                srcIP0: packet['ipHeader.src.0'],
                srcIP1: packet['ipHeader.src.2'],
                srcIP2: packet['ipHeader.src.3'],
                srcIP3: packet['ipHeader.src.4']
            };
    }
    // if we reach this point the protocol was neither udp or tcp
    return;
}
// function match_object
//
// helper function to match object data
// object must be one level deep
// there may be more fields in search_object than your search_fields contains
function match_object(search_object, search_fields) {
    for (let ell in search_fields) {
        if (search_object[ell]) {
            // element exists in search_object
            if (search_object[ell] === search_fields[ell]) {
                continue;
            } else {
                // elements not the same, stop search
                return false;
            }
        }
    }
    return true;
}
// function time_diff
//
// helper function to get time difference based on four fields:
//  - time1 with seconds and microseconds
//  - time2 with seconds and microseconds
function time_diff(t1_sec, t1_msec, t2_sec, t2_msec) {
    return (t2_sec - t1_sec)*1000000 + (t2_msec - t1_msec);
}
// main function 'read_pcap' used to read a pcapfile
//
// this function takes:
//   inputfile:      string with pcap filename
//
//   csvfile:        string with export csv filename
//
//   logger:         logger object to log information. logger.debug, logger.info
//                   and logger.error are called
//
//   filter:         to determine which packets to keep. filter(packet) is called. 
//                   when true is returned the packet is stored
//
//   keep_in_memory: determine if all data should be kept in memory (used to compare after reading)
//
//   multibar:       parse a multibar object if a progressbar should be shown in a terminal
//
// this function is called from 'index.js' to read different pcapfiles and than to compare the result.
// this function returns a promise
function read_pcap(inputfile, csvfile, logger, filter, keep_in_memory, multibar, decoders) {
    return new Promise(function(resolve_readpcap, reject_readpcap) {
        (function(inputfile, csvfile, logger, filter, keep_in_memory, multibar, decoders){
            var pcap1 = new PcapFile(inputfile, logger, filter, decoders);

            if (keep_in_memory) {
                keep_buffer = true;
            }

            pcap1._csvWriter = createCsvWriter({
                path: csvfile,
                header: header_fields
            });
            pcap1.initFile()
            .then(function(result){
                if (multibar) {
                    result._progressBar = multibar.create(Math.floor(result._fileSize/1048576), 0);
                    if (result._progressBar) {
                        result._progressBar.update(0, {filename: result._fileName});
                    }
                }
                return result.readHeader(result);
            })
            .then(function(result){
                return itteratePackets(result);
            })
            .then(function(result){
                return result._csvWriter.writeRecords(result._packets)       // returns a promise
            })
            .then(() => {
                pcap1._packetsWritenToCSV += pcap1._packets.length % write_to_csv
                logger.info('...Done');
                resolve_readpcap(pcap1);
            })
            .catch(function(result){
                reject_readpcap(result);
                return logger.error("err at packet: " + result._packetCnt + " with message: " + result);
            });
        })(inputfile, csvfile, logger, filter, keep_in_memory, multibar, decoders)
    });
}

module.exports = read_pcap;