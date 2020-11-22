var Parser = require("binary-parser").Parser;

var packetDefinitions = {
    pcapPacketHeader: new Parser()
                .endianess("little")
                .uint32("ts_sec")
                .uint32("ts_usec")
                .uint32("incl_len")
                .uint32("orig_len"),
    ethernetHeader: new Parser()
                .endianess("big")
                .array("dest_mac", {
                    type: "uint8",
                    length: 6
                })
                .array("src_mac", {
                    type: "uint8",
                    length: 6
                })
                .uint16("ethernet_type"),
    ieee802_1q: new Parser()
            .endianess("big")
            .bit3("pcp")
            .bit1("dei")
            .uint12("vid")
            .uint16("ethernet_type"),
    ipHeader: new Parser()
                .endianess("big")
                .bit4("version")
                .bit4("headerLength")
                .uint8("tos")
                .uint16("packetLength")
                .uint16("id")
                .bit3("flags")
                .bit13("fragOffset")
                .uint8("ttl")
                .uint8("protocol")
                .uint16("checksum")
                .array("src", {
                type: "uint8",
                length: 4
                })
                .array("dst", {
                type: "uint8",
                length: 4
                }),
    ipV6Header: new Parser()
                .endianess("big")
//                .bit4("version")
//                .uint8("trafficClass")
//                .bit20("flowLabel")
// changed to overig.. bug in library??
                .bit32('overig')
                .uint16("packetLength")
                .uint8("nextHeader")
                .uint8("hopLimit")
                .array("src", {
                    type: "uint8",
                    length: 16
                })
                .array("dst", {
                    type: "uint8",
                    length: 16
                }),
    ipV6OptionHeader: new Parser()
                .endianess("big")
                .uint8("nextHeader")
                .uint8("headerLength"),
    arpPacket: new Parser()
                .endianess("big")
                .uint16("hw_type")
                .uint16("prot_type")
                .uint8("hplen")
                .uint8("plen")
                .uint16("operation")
                .array("src_mac", {
                    type: "uint8",
                    length: 6
                })
                .array("src_ip", {
                    type: "uint8",
                    length: 4
                })
                .array("dst_mac", {
                    type: "uint8",
                    length: 6
                })
                .array("dst_ip", {
                    type: "uint8",
                    length: 4
                }),
    udpHeader: new Parser()
                .endianess("big")
                .uint16("src_port")
                .uint16("dest_port")
                .uint16("length")
                .uint16("chksum"),
    tcpHeader: new Parser()
                .endianess("big")
                .uint16("src_port")
                .uint16("dest_port")
                .uint32("sequence_nr")
                .uint32("ack_nr")
                .bit4("header_offset")
                .bit3("reserved")
                .bit9("control_flags")
                .uint16("length")
                .uint16("chksum")
                .uint16("urgent_ptr"),
    gprsHeader: new Parser()
                .endianess("big")
                .bit3("version")
                .bit1("pt")
                .bit1("reserved")
                .bit1("e")
                .bit1("s")
                .bit1("n_pdu")
                .uint8("message_type")
                .uint16("length")
                .uint32("teid"),
    gprsHeaderExtension: new Parser()
                .endianess("big")
                .uint8("length")
                .bit4("pdu_type")
                .bit6("spare")
                .bit6("qfi")
                .uint8("next_header")
}

module.exports = packetDefinitions;

