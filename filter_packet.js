// filter function, used by read_pcap function to store only the relevant packets.
function filter_packet(filterSet) {

    // this function is returned to read_pcap. it expects a packet in the format defined by function Packet() in 'pcapfile.js'
    return function(packet) {
        
        for (items of filterSet) {
            var result = true;
            for (item of items) {
                if (item.type && item.type == "direction") {
                    // direction is set. Add direction field to packet
                    packet.direction = item.value;
                }
                if (!item.type || item.type == "match") {
                    switch (item.operator) {
                        case "eq": 
                            result = (packet[item.field] == item.value);
                            break;
                        case "ne":
                            result = (packet[item.field] != item.value);
                            break;
                        case "gt":
                            result = (packet[item.field] > item.value);
                            break;
                        case "lt":
                            result = (packet[item.field] < item.value);
                            break;
                        case "ge":
                            result = (packet[item.field] >= item.value);
                            break;
                        case "le":
                            result = (packet[item.field] <= item.value);
                            break;
                        case "contains":
                            result = (packet[item.field].includes(item.value));
                            break;
                        default:
                            // unknown operator
                            result = false;
                    }
                }
                if (!result) break;
            }
            if (result) {
                return true;
            }
        }
        return false;
    }
}

// export the filter function
module.exports = filter_packet;