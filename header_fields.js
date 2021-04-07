header_fields = [
    {"id": "packetNr", "title": "packetNr"},
    {"id": "protocol", "title": "protocol"},
    {"id": "direction", "title": "direction"},
    {"id": "pcapPacketHeader.ts_sec", "title": "pcapPacketHeader.ts_sec"},
    {"id": "pcapPacketHeader.ts_usec", "title": "pcapPacketHeader.ts_usec"},
    {"id": "pcapPacketHeader.incl_len", "title": "pcapPacketHeader.incl_len"},
    {"id": "pcapPacketHeader.orig_len", "title": "pcapPacketHeader.orig_len"},
    {"id": "ethernetHeader.dest_mac.0", "title": "ethernetHeader.dest_mac.0"},
    {"id": "ethernetHeader.dest_mac.1", "title": "ethernetHeader.dest_mac.1"},
    {"id": "ethernetHeader.dest_mac.2", "title": "ethernetHeader.dest_mac.2"},
    {"id": "ethernetHeader.dest_mac.3", "title": "ethernetHeader.dest_mac.3"},
    {"id": "ethernetHeader.dest_mac.4", "title": "ethernetHeader.dest_mac.4"},
    {"id": "ethernetHeader.dest_mac.5", "title": "ethernetHeader.dest_mac.5"},
    {"id": "ethernetHeader.src_mac.0", "title": "ethernetHeader.src_mac.0"},
    {"id": "ethernetHeader.src_mac.1", "title": "ethernetHeader.src_mac.1"},
    {"id": "ethernetHeader.src_mac.2", "title": "ethernetHeader.src_mac.2"},
    {"id": "ethernetHeader.src_mac.3", "title": "ethernetHeader.src_mac.3"},
    {"id": "ethernetHeader.src_mac.4", "title": "ethernetHeader.src_mac.4"},
    {"id": "ethernetHeader.src_mac.5", "title": "ethernetHeader.src_mac.5"},
    {"id": "ethernetHeader.ethernet_type", "title": "ethernetHeader.ethernet_type"},
    {"id": "ipHeader.version", "title": "ipHeader.version"},
    {"id": "ipHeader.headerLength", "title": "ipHeader.headerLength"},
    {"id": "ipHeader.tos", "title": "ipHeader.tos"},
    {"id": "ipHeader.packetLength", "title": "ipHeader.packetLength"},
    {"id": "ipHeader.id", "title": "ipHeader.id"},
    {"id": "ipHeader.flags", "title": "ipHeader.flags"},
    {"id": "ipHeader.fragOffset", "title": "ipHeader.fragOffset"},
    {"id": "ipHeader.ttl", "title": "ipHeader.ttl"},
    {"id": "ipHeader.protocol", "title": "ipHeader.protocol"},
    {"id": "ipHeader.checksum", "title": "ipHeader.checksum"},
    {"id": "ipHeader.src.0", "title": "ipHeader.src.0"},
    {"id": "ipHeader.src.1", "title": "ipHeader.src.1"},
    {"id": "ipHeader.src.2", "title": "ipHeader.src.2"},
    {"id": "ipHeader.src.3", "title": "ipHeader.src.3"},
    {"id": "ipHeader.dst.0", "title": "ipHeader.dst.0"},
    {"id": "ipHeader.dst.1", "title": "ipHeader.dst.1"},
    {"id": "ipHeader.dst.2", "title": "ipHeader.dst.2"},
    {"id": "ipHeader.dst.3", "title": "ipHeader.dst.3"},    
    {"id": "udpHeader.src_port", "title": "udpHeader.src_port"},
    {"id": "udpHeader.dest_port", "title": "udpHeader.dest_port"},
    {"id": "udpHeader.length", "title": "udpHeader.length"},
    {"id": "udpHeader.chksum", "title": "udpHeader.chksum"},
    {"id": "tcpHeader.src_port", "title": "tcpHeader.src_port"},
    {"id": "tcpHeader.dest_port", "title": "tcpHeader.dest_port"},
    {"id": "tcpHeader.sequence_nr", "title": "tcpHeader.sequence_nr"},
    {"id": "tcpHeader.ack_nr", "title": "tcpHeader.ack_nr"},
    {"id": "tcpHeader.header_offset", "title": "tcpHeader.header_offset"},
    {"id": "tcpHeader.reserved", "title": "tcpHeader.reserved"},
    {"id": "tcpHeader.control_flags", "title": "tcpHeader.control_flags"},
    {"id": "tcpHeader.length", "title": "tcpHeader.length"},
    {"id": "tcpHeader.chksum", "title": "tcpHeader.chksum"},
    {"id": "tcpHeader.urgent_ptr", "title": "tcpHeader.urgent_ptr"},
    {"id": "tcpHeader.optional.0", "title": "tcpHeader.optional.0"},
    {"id": "tcpHeader.optional.1", "title": "tcpHeader.optional.1"},
    {"id": "tcpHeader.optional.2", "title": "tcpHeader.optional.2"},
    {"id": "tcpHeader.optional.3", "title": "tcpHeader.optional.3"},
    {"id": "tcpHeader.optional.4", "title": "tcpHeader.optional.4"},
    {"id": "tcpHeader.optional.5", "title": "tcpHeader.optional.5"},
    {"id": "tcpHeader.optional.6", "title": "tcpHeader.optional.6"},
    {"id": "tcpHeader.optional.7", "title": "tcpHeader.optional.7"},
    {"id": "tcpHeader.optional.8", "title": "tcpHeader.optional.8"},
    {"id": "tcpHeader.optional.9", "title": "tcpHeader.optional.9"},
    {"id": "arpPacket.hw_type", "title": "arpPacket.hw_type"},
    {"id": "arpPacket.prot_type", "title": "arpPacket.prot_type"},
    {"id": "arpPacket.hplen", "title": "arpPacket.hplen"},
    {"id": "arpPacket.plen", "title": "arpPacket.plen"},
    {"id": "arpPacket.operation", "title": "arpPacket.operation"},
    {"id": "arpPacket.src_mac.0", "title": "arpPacket.src_mac.0"},
    {"id": "arpPacket.src_mac.1", "title": "arpPacket.src_mac.1"},
    {"id": "arpPacket.src_mac.2", "title": "arpPacket.src_mac.2"},
    {"id": "arpPacket.src_mac.3", "title": "arpPacket.src_mac.3"},
    {"id": "arpPacket.src_mac.4", "title": "arpPacket.src_mac.4"},
    {"id": "arpPacket.src_mac.5", "title": "arpPacket.src_mac.5"},
    {"id": "arpPacket.src_ip.0", "title": "arpPacket.src_ip.0"},
    {"id": "arpPacket.src_ip.1", "title": "arpPacket.src_ip.1"},
    {"id": "arpPacket.src_ip.2", "title": "arpPacket.src_ip.2"},
    {"id": "arpPacket.src_ip.3", "title": "arpPacket.src_ip.3"},
    {"id": "arpPacket.dst_mac.0", "title": "arpPacket.dst_mac.0"},
    {"id": "arpPacket.dst_mac.1", "title": "arpPacket.dst_mac.1"},
    {"id": "arpPacket.dst_mac.2", "title": "arpPacket.dst_mac.2"},
    {"id": "arpPacket.dst_mac.3", "title": "arpPacket.dst_mac.3"},
    {"id": "arpPacket.dst_mac.4", "title": "arpPacket.dst_mac.4"},
    {"id": "arpPacket.dst_mac.5", "title": "arpPacket.dst_mac.5"},
    {"id": "arpPacket.dst_ip.0", "title": "arpPacket.dst_ip.0"},
    {"id": "arpPacket.dst_ip.1", "title": "arpPacket.dst_ip.1"},
    {"id": "arpPacket.dst_ip.2", "title": "arpPacket.dst_ip.2"},
    {"id": "arpPacket.dst_ip.3", "title": "arpPacket.dst_ip.3"},
    {"id": "rtpHeader.sequence_number", "title": "rtpHeader.sequence_number"},
    {"id": "rtpHeader.timestamp", "title": "rtpHeader.timestamp"},
    {"id": "rtpHeader.marker", "title": "rtpHeader.marker"},
    {"id": "dataChksum", "title": "dataChksum"}
]

module.exports = header_fields;