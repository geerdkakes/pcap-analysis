var fs = require('fs');
var Logger = require('./logger');
var Parser = require("binary-parser").Parser;
var packetDefinitions = require('packet_definitions');
var crypto = require('crypto');
var maxPacketLength = 20000;

function checksum(str, algorithm, encoding) {
  return crypto
    .createHash(algorithm || 'md5')
    .update(str, 'utf8')
    .digest(encoding || 'hex')
}

function Packet() {
    this.protocol="";
    this.pcapPacketHeader= {
        ts_sec: 0,
        ts_usec: 0,
        incl_len: 0,
        orig_len: 0
    };
    this.ethernetHeader= {
        dest_mac: [0, 0, 0, 0, 0, 0],
        src_mac: [0, 0, 0, 0, 0, 0],
        ethernet_type: 0
    };
    this.ipHeader= {
        version: 0,
        headerLength: 0,
        tos: 0,
        packetLength: 0,
        id: 0,
        flags: 0,
        fragOffset: 0,
        ttl: 0,
        protocol: 0,
        checksum: 0,
        src: [0, 0, 0, 0],
        dst: []
    };
    this.udpHeader= {
        src_port: 0,
        dest_port: 0,
        length: 0,
        chksum: 0
    };
    this.tcpHeader= {
        src_port: 0,
        dest_port: 0,
        sequence_nr: 0,
        ack_nr: 0,
        header_offset: 0,
        reserved: 0,
        control_flags: 0,
        length: 0,
        chksum: 0,
        urgent_ptr: 0,
        optional: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    };
    this.arpPacket = {
        hw_type: 0,
        prot_type:0,
        hplen: 0,
        plen: 0,
        operation: 0,
        src_mac: [0, 0, 0, 0, 0, 0],
        src_ip: [0, 0, 0, 0],
        dst_mac: [0, 0, 0, 0, 0, 0],
        dst_ip: [0, 0, 0, 0]
    };
    this.genericIPPacket = {
        checksum: 0
    };
    this.genericEthernetPacket = {
        checksum:0 
    };
    this.dataChksum= '';
}


function PcapFile(fileName, debugLevel) {
      this._buffer = Buffer.alloc(maxPacketLength);
      this._fileName = fileName;
      this._fd = null;
      this._bytes_read=0;
      this._currentPacket = {};
      this._packets = [];
      this._fileSize;
      this._fileNotCompleted = true;
      this._packetCnt = 0;
      this._logger = Logger(debugLevel);
      this._ptrBufferCurrentPacket = 0;
      this._lenBufferCurrentPacket = 0;
    }

PcapFile.prototype.fileNotCompleted = function(self) {
    if (!self) {
        self = this;
    }
    return self._fileNotCompleted;
}    

PcapFile.prototype.updateBytesRead = function(self,dataRead) {
    self._bytes_read += dataRead;
    if (self._fileSize <= self._bytes_read ) {
        self._fileNotCompleted = false;
        self._logger.info("end of file reached");
    }
}
PcapFile.prototype.readBuf = function(dataToRead) {
    var self = this;
    var start = self._ptrBufferCurrentPacket;
    var end = self._ptrBufferCurrentPacket + dataToRead;
    self._ptrBufferCurrentPacket += dataToRead;
    return self._buffer.slice(start, end);
}
PcapFile.prototype.initFile = function(){
        var self = this;
        return new Promise(function(resolve, reject) {
            if (self._fd) {
                const err = new Error('file already initialized');
                reject(err);
            }
            fs.open(self._fileName, 'r', function(err, fd) {
                if (err) {
                    logger.error(err.message);
                    reject(err);
                }
                self._fd = fd;
                fs.fstat(fd, function (err,stats){
                    self._fileSize = stats["size"];
                    self._logger.info("filesize " + self._fileSize + " bytes");
                    resolve(self);
                });
            });

        });
    }


    PcapFile.prototype.readHeader = function(self) {

        return new Promise(function(resolve, reject) {
            fs.read(self._fd, self._buffer, 0, 24, null, function(err, num) {
                if (err) {
                    self._logger.error("readHeader: error reading file", err);
                    reject(err);
                }
                self._logger.info("read",num,"bytes");
                self.updateBytesRead(self,num);

                if ( self._buffer.toString('hex', 0, 4) === 'd4c3b2a1' ) {
                    self._endian = 'litle';
                    Buffer.prototype.readUInt = Buffer.prototype.readUIntLE;
                    Buffer.prototype.readInt = Buffer.prototype.readIntLE;
                    self._logger.debug('litle endian file format');
                } else {
                    self._endian = 'big';
                    Buffer.prototype.readUInt = Buffer.prototype.readUIntBE;
                    Buffer.prototype.readInt = Buffer.prototype.readIntBE;
                    self._logger.debug('big endian file format');
                }

                self._majorVersion = self._buffer.readUInt(4,2);
                self._minorVersion = self._buffer.readUInt(6,2);
                self._thisZone = self._buffer.readInt(8,4);
                self._sigFigs = self._buffer.readUInt(12,4);
                self._snapLen = self._buffer.readUInt(16,4);
                self._ethernet = self._buffer.readUInt(20, 4);

                self._logger.info('pcap file with version: ' + self._majorVersion + '.' + self._minorVersion);
                resolve(self);
            });
        });
    }

    PcapFile.prototype.readPacketHeader = function (self){
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            // read packet header first
            fs.read(self._fd, self._buffer, 0, 16, null, function(err, num, buf) {
                if (err) {
                    self._logger.error("error reading packet header: " + err.message);
                    reject(err);
                }

                self.updateBytesRead(self,num);
                self._currentPacket = new Packet();
                self._currentPacket.pcapPacketHeader = packetDefinitions.pcapPacketHeader.parse(buf);
                self._ptrBufferCurrentPacket = 0;
                
                // determine remaining bytes to read
                self._currentPacket._ptrCurrentPacket=0;
                var remaining_data_to_read = self._currentPacket.pcapPacketHeader.incl_len;
                self._packetCnt++;

                if (remaining_data_to_read > maxPacketLength) {
                    self._logger.error("More than " + maxPacketLength + 
                                         " bytes to read, please check file structure at packet " +
                                         self._currentPacket._packetCnt
                                       );
                                return reject(new Error('data to read (' + 
                                                remaining_data_to_read +
                                                 'bytes) exceeds buffer. At packet: ' + 
                                                 self._packetCnt++));
                }

                // read remaining packet data into buffer
                fs.read(self._fd, self._buffer, 0, remaining_data_to_read, null, function(err, num, buf) {
                    if (err) {
                        self._logger.error(err.message);
                    }
                    self.updateBytesRead(self,num);
                    self._lenBufferCurrentPacket = num;
                    resolve(self);
                });    
                
            });
        });
    }
    PcapFile.prototype.readEthernetHeader = function(self){
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            let buf = self.readBuf(14);
            self._currentPacket.ethernetHeader = packetDefinitions.ethernetHeader.parse(buf);
            resolve(self);

        });
    }
    PcapFile.prototype.readPacketIPHeader = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {
            let buf = self.readBuf(20);
            self._currentPacket.ipHeader = packetDefinitions.ipHeader.parse(buf);
            resolve(self);

        });
    }
    PcapFile.prototype.readPacketIPv6Header = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            // read 40 bytes packet header
            let buf = self.readBuf(40);
            self._currentPacket.ipV6Header = packetDefinitions.ipV6Header.parse(buf);

            self._currentPacket.ipV6Header.optionHeaderCnt = 0;
            self._currentPacket.ipV6OptionHeader = [];

            // set data_read to zero (to monitor what has been read)
            self._currentPacket.ipV6Header.dataRead = 0;
            resolve(self);

        });
    }
    PcapFile.prototype.readNexIPv6Header = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            // read first two bytes to determine length of option packet
            let length_first_fields = 2
            let buf = self.readBuf(length_first_fields);
            self._currentPacket.ipV6Header.dataRead +=length_first_fields;
            self._currentPacket.ipV6OptionHeader[self._currentPacket.ipV6Header.optionHeaderCnt] = 
                                                        packetDefinitions.ipV6OptionHeader.parse(buf);
            var bytesOptionHeaderLeft = self._currentPacket.ipV6OptionHeader[self._currentPacket.ipV6Header.optionHeaderCnt].headerLength;

            // read and discard rest of optionheader
            let disrecardedBuf = self.readBuf(bytesOptionHeaderLeft);
            self._currentPacket.ipV6Header.optionHeaderCnt++;
            self._currentPacket.ipV6Header.dataRead +=bytesOptionHeaderLeft;
            resolve(self);
            
        });

    }
    PcapFile.prototype.readgenericEthernetPacket = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            data_to_read = self._currentPacket.pcapPacketHeader.incl_len - 14;

            let buf = self.readBuf(data_to_read);
            self._currentPacket.genericEthernetPacket.checksum = checksum(buf);
            resolve(self);

        });
    }
    PcapFile.prototype.readgenericIPPacket = function(self) {
        if (!self) {
             self = this;
        }
        return new Promise(function(resolve, reject) {

            data_to_read = self._currentPacket.pcapPacketHeader.incl_len - 14 -20;

            let buf = self.readBuf(data_to_read);
            self._currentPacket.genericIPPacket.checksum = checksum(buf);
            resolve(self);

        });
    }
    PcapFile.prototype.readgenericIPv6Packet = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            data_to_read = self._currentPacket.ipV6Header.packetLength - self._currentPacket.ipV6Header.dataRead;

            // read data left
            let buf = self.readBuf(data_to_read);
            self._currentPacket.genericIPPacket.checksum = checksum(buf);
            resolve(self);

        });
    }
    PcapFile.prototype.readArpPacket = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

                let buf = self.readBuf(28);
                self._currentPacket.protocol = "arp";
                self._currentPacket.arpPacket = packetDefinitions.arpPacket.parse(buf);
                // read ethernet packet 14
                // read arp packet 28
                var remainingBytes = self._currentPacket.pcapPacketHeader.incl_len - 28 - 14;
                if (remainingBytes) {
                    // read 18 padding bytes and discard
                    let disrecardedBuf = self.readBuf(18);
                    resolve(self);
                } else {
                    resolve(self);
                }
        });
    }
    PcapFile.prototype.readPacketUDPHeader = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            let buf = self.readBuf(8);
            self._currentPacket.protocol = "udp";
            self._currentPacket.udpHeader=packetDefinitions.udpHeader.parse(buf);
            self._currentPacket.dataSize = self._currentPacket.udpHeader.length - 8;
            resolve(self);

         });
    }
    PcapFile.prototype.readPacketTCPHeader = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {


                let buf = self.readBuf(20);
                self._currentPacket.protocol = "tcp";
                self._currentPacket.tcpHeader = packetDefinitions.tcpHeader.parse(buf);
                self._currentPacket.dataSize = self._currentPacket.ipHeader.packetLength - 20 - self._currentPacket.tcpHeader.header_offset*4;
                if (self._currentPacket.tcpHeader.header_offset > 5) {
                    var bytes_to_read = (self._currentPacket.tcpHeader.header_offset - 5)*4;
                    var i=0;
                    self._currentPacket.tcpHeader.optional = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

                    let buf = self.readBuf(bytes_to_read);
                    for(i; i< bytes_to_read/4; i++) {
                        self._currentPacket.tcpHeader.optional[i] = buf.readUIntBE(i*4,4);
                    }
                    resolve(self);

                } else {
                    resolve(self);
                }

         });
    }
    PcapFile.prototype.readDataPacket = function(self){
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {

            var length = self._currentPacket.dataSize;


            if (length > 0 ) {

                let buf = self.readBuf(length);
                var chksum = checksum(buf);
                self._currentPacket.dataChksum = chksum;
                resolve(self);

            } else {
                self._currentPacket.dataChksum =  "";
                resolve(self);
            }
        });
    }
  
  module.exports = PcapFile;