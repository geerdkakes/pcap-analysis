// pcapfile.js
//
// defines the pcapfile object and all functions needed to read the file.
// this file is called from 'read_pcap.js'

// main libraries used
var fs = require('fs');
var crypto = require('crypto');

// Packet_definitions contains all header fields currrently recognised by 'pcapfile'
var packetDefinitions = require('./packet_definitions');


// Buffer to read a new packet to memmory is currently set to 20k Bytes
var maxPacketLength = 20000;

// checksum function, used to create a checksum of the payload
function checksum(buf, algorithm, encoding) {
  return crypto
    .createHash(algorithm || 'md5')
    .update(buf)
    .digest(encoding || 'hex')
}

// helper function flattenObject, used to flatten the packet-object before storing in a csv-file
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

// this function defines the packet object
// for each new packet this object is used to
// create a new packet. Used by 'readPacketHeader'
function Packet() {
    this.protocol="";
    this.packetNr;
    this.pcapPacketHeader= {};
    this.ethernetHeader= {};
    this.ipHeader= {};
    this.udpHeader= {};
    this.tcpHeader= {};
    this.arpPacket = {};
    this.genericIPPacket = {};
    this.genericEthernetPacket = {};
    this.dataChksum= '';
}

// main object PcapFile
// used to create a new pcapfile object
// called from function 'read_pcap.js'
function PcapFile(fileName, logger, filter) {
      this._buffer = Buffer.alloc(maxPacketLength);
      this._fileName = fileName;
      this._filter = filter;
      this._fd = null;
      this._bytes_read=0;
      this._currentPacket = {};
      this._packets = [];
      this._fileSize;
      this._fileNotCompleted = true;
      this._packetCnt = 0;
      this._logger = logger;
      this._ptrBufferCurrentPacket = 0;
      this._lenBufferCurrentPacket = 0;
      this._csvWriter;
      this._progressBar;
      this._packetsWritenToCSV = 0;
      this._frameTracker = [];
    }

// helper function to determine if we reached end of file
PcapFile.prototype.fileNotCompleted = function(self) {
    if (!self) {
        self = this;
    }
    return self._fileNotCompleted;
}    

// helper function to keep track of the number of bytes read
PcapFile.prototype.updateBytesRead = function(self,dataRead) {
    self._bytes_read += dataRead;
    if (self._fileSize <= self._bytes_read ) {
        self._fileNotCompleted = false;
        self._logger.info("end of file reached");
    }
}

// helper function to create a sub-buffer from the same address range to
// which a packet has been stored.
PcapFile.prototype.readBuf = function(dataToRead) {
    var self = this;
    var start = self._ptrBufferCurrentPacket;
    var end = self._ptrBufferCurrentPacket + dataToRead;
    self._ptrBufferCurrentPacket += dataToRead;
    return self._buffer.slice(start, end);
}

// initialise, open file and determine file size
PcapFile.prototype.initFile = function(){
        var self = this;
        return new Promise(function(resolve, reject) {
            if (self._fd) {
                const err = new Error('file already initialized');
                reject(err);
            }
            fs.open(self._fileName, 'r', function(err, fd) {
                if (err) {
                    self.logger.error(err.message);
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

    // store found packet in memory. Filter function is called that has been parsed when creating
    // object to determine if we want to keep this packet.
    PcapFile.prototype.storePacket = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject){
            let currentPacket = flattenObject(self._currentPacket);
            if (self._filter(currentPacket)) {
                self._packets.push(currentPacket);
            }
            resolve(self);
        }); 
    }

    // Read pcap header (main header)
    PcapFile.prototype.readHeader = function(self) {
        if (!self) {
            self = this;
        }
        return new Promise(function(resolve, reject) {
            fs.read(self._fd, self._buffer, 0, 24, null, function(err, num) {
                if (err) {
                    self._logger.error("readHeader: error reading file", err);
                    reject(err);
                }
                self._logger.info("read",num,"bytes");
                self.updateBytesRead(self,num);

                // determine big indian or litle indian by reading magic string
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

    // read packet header, containing time stamp and packet length
    // after packet length has been determined, the remaining packet
    // is also read
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
                self._currentPacket.packetNr = self._packetCnt;
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