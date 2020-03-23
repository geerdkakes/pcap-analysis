
var PcapFile = require('./pcapfile');
var header_fields = require('./header_fields');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const cliProgress = require('cli-progress');
const max_packet_buffer = 10000;

// progress bar
const multibar = new cliProgress.MultiBar({
    clearOnComplete: false,
    hideCursor: true
 
}, cliProgress.Presets.shades_grey);

var logger;



function flattenObject(ob) {
    var toReturn = {};

    for (var i in ob) {
        if (!ob.hasOwnProperty(i)) continue;

        if ((typeof ob[i]) == 'object' && ob[i] !== null) {
            var flatObject = flattenObject(ob[i]);
            for (var x in flatObject) {
                if (!flatObject.hasOwnProperty(x)) continue;

                toReturn[i + '.' + x] = flatObject[x];
            }
        } else {
            toReturn[i] = ob[i];
        }
    }
    return toReturn;
}

function readPacket(pcapdata){
    if (pcapdata.fileNotCompleted()) {
        return pcapdata.readPacketHeader(pcapdata)
            .then(function(result){
                return result.readEthernetHeader(result);
            })
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
                                result._currentPacket.ethernetHeader.ethernet_type.toString(10)
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
                return result.readDataPacket(result);
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

function itteratePackets(pcapdata) {
    return readPacket(pcapdata).then(function(result){
        if (result.fileNotCompleted(result)) {
            result._logger.debug("packets read: " + 
                          result._packetCnt + 
                          JSON.stringify(flattenObject(result._currentPacket))
                         );
            result._packets.push(flattenObject(result._currentPacket));
            // write every 1000 packets to file
            if (result._packets.length % 10000 || result._packets.length == max_packet_buffer) {
                result._progressBar.update(Math.floor(result._bytes_read/1048576));
            }
            // write every 1000 packets to file
            if (result._packets.length == max_packet_buffer) {
                
                return result._csvWriter.writeRecords(result._packets)
                            .then(() => {
                                return new Promise(function(resolve, reject) {
                                    // reset array
                                    result._packets.length = 0;
                                    resolve(result);
                                });
                            })
                            .then(() => {return itteratePackets(result)});
            }
            return itteratePackets(result);
        } else {
            // console.log("last packet read " + result._packetCnt,flattenObject(result._currentPacket));
            result._logger.info("last packet read");
            result._packets.push(flattenObject(result._currentPacket));
            return result;
        }
    });
}

function read_pcap(inputfile, csvfile, logger) {
    var pcap1 = new PcapFile(inputfile, logger);

    pcap1._csvWriter = createCsvWriter({
        path: csvfile,
        header: header_fields
    });

    pcap1.initFile()
    .then(function(result){
        result._progressBar = multibar.create(Math.floor(result._fileSize/1048576), 0);
        result._progressBar.update(0, {filename: result._fileName});
        return result.readHeader(result);
    })
    .then(function(result){
        return itteratePackets(result);
    })
    .then(function(result){
        return csvWriter.writeRecords(result._packets)       // returns a promise

    })
    .then(() => {
        // stop all bars
        multibar.stop();
        result._logger.info('...Done');
        console.log("packets read: " + pcap1._packetCnt);
    })
    .catch(function(result){
        return logger.error("err at packet: " + result._packetCnt + " with message: " + result);
    });
}

module.exports = read_pcap;