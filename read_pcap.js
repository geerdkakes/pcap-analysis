var fs = require('fs');

const args = require('minimist')(process.argv.slice(2));
var PcapFile = require('./pcapfile');
var header_fields = require('./header_fields');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const cliProgress = require('cli-progress');

// progress bar
const multibar = new cliProgress.MultiBar({
    clearOnComplete: false,
    hideCursor: true
 
}, cliProgress.Presets.shades_grey);
var b1;

// read commandline flags
const inputfile = (typeof args.i === 'undefined' || args.i === null) ? "./inputfile.pcap" : args.i;
const csvfile = (typeof args.c === 'undefined' || args.c === null) ? "./output.csv" : args.c;
const debuglevel = (typeof args.d === 'undefined' || args.d === null) ? "error" : args.d;
const csvWriter = createCsvWriter({
    path: csvfile,
    header: header_fields
});
var logger = require('./logger')(debuglevel);
var pcap1 = new PcapFile(inputfile);


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
        return pcap1.readPacketHeader(pcapdata)
            .then(function(result){
                return pcap1.readEthernetHeader(result);
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
                        logger.info("Unknown ethernet protocol at packet " + 
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
    return pcap1.readPacketIPv6Header(pcapdata).then( function(result){
        switch(result._currentPacket.ipV6Header.nextHeader) {
            case 17: // udp packet
                return readUDPPacket(pcapdata);
            case 6: // tcp packet
                return readTCPPacket(pcapdata);
            case 1: // icmp
                result._currentPacket.protocol = "icmp";
                return readGenericIPPacket(pcapdata);
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
                logger.info("Unknown IP protocol at IPv6 packet " + 
                            result._packetCnt + 
                            " with type " + 
                            result._currentPacket.ethernetHeader.ethernet_type.toString(10)
                            );
                return readGenericIPv6Packet(result);
          }
    });
}
function readNexIPv6Header(pcapdata) {
    return pcap1.readNexIPv6Header(pcapdata).then(function(result) {

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
                logger.info("Unknown IP protocol at IPv6 packet " + 
                            result._packetCnt + 
                            " with type " + 
                            result._currentPacket.ethernetHeader.ethernet_type.toString(10)
                            );
                return readGenericIPv6Packet(result);
        }
    });
}
function readIPPacket(pcapdata){
    return pcap1.readPacketIPHeader(pcapdata)
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
                    logger.info("Unknown IP protocol at IP packet " + 
                                result._packetCnt + 
                                " with type " + 
                                result._currentPacket.ethernetHeader.ethernet_type.toString(10)
                                );
                    return readGenericIPPacket(result);
            }
        });
}
function readGenericEthernetPacket(pcapdata){
    return pcap1.readgenericEthernetPacket(pcapdata);
}
function readGenericIPPacket(pcapdata){
    return pcap1.readgenericIPPacket(pcapdata);
}
function readGenericIPv6Packet(pcapdata){
    return pcapdata.readgenericIPv6Packet(pcapdata);
}
function readUDPPacket(pcapdata) {
    return pcap1.readPacketUDPHeader(pcapdata)
            .then(function(result){
                return pcap1.readDataPacket(result);
            });

}

function readTCPPacket(pcapdata) {
    return pcap1.readPacketTCPHeader(pcapdata)
            .then(function(result){
                return pcap1.readDataPacket(result);
            });

}

function readARPPacket(pcapdata) {
    return pcap1.readArpPacket(pcapdata);
}

function itteratePackets(pcapdata) {
    return readPacket(pcapdata).then(function(result){
        if (result.fileNotCompleted(result)) {
            logger.debug("packets read: " + 
                          result._packetCnt + 
                          JSON.stringify(flattenObject(result._currentPacket))
                         );
            result._packets.push(flattenObject(result._currentPacket));
            // write every 1000 packets to file
            if (result._packets.length == 1000) {
                b1.update(Math.floor(result._bytes_read/1048576));
                // logger.info("packets read " + 
                //              result._packetCnt +
                //              " complete: " +
                //              Math.floor(result._bytes_read / result._fileSize * 100) +
                //              "%"
                //             );
                return csvWriter.writeRecords(result._packets)
                            .then(() => {
                                return new Promise(function(resolve, reject) {
                                    // reset array
                                    pcapdata._packets.length = 0;
                                    resolve(pcapdata);
                                });
                            })
                            .then(() => {return itteratePackets(pcapdata)});
            }
            return itteratePackets(pcapdata);
        } else {
            // console.log("last packet read " + result._packetCnt,flattenObject(result._currentPacket));
            logger.info("last packet read");
            result._packets.push(flattenObject(result._currentPacket));
            return result;
        }
    });
}

// main program
pcap1.initFile()
.then(function(result){
    b1 = multibar.create(Math.floor(result._fileSize/1048576), 0);
    b1.update(0, {filename: result._fileName});
    return pcap1.readHeader(result);
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
    logger.info('...Done');
})
.catch(function(result){
    return logger.error("err at packet: " + pcap1._packetCnt + " with message: " + result);
});
 
