// 'compare_pcap.js'
//
// function to compare two arrays with packets.
// a new array is created with the resulting matches
// with writerecords function the results can be writen to a csv file
//
// create a new object using: new ComparePcap(...)
// call comparePcapArrays to match two packet array's.

// libraries to use
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

// --------------------------------------------------------------------------------------
// 'ComparePcap'
//
// main object. Initialize with:
//   - match_array:     array with fields to match packets
//
//   - logger:          logger object. logger.debug, logger.info or logger.error is called
//                      to log information
//
//   - result_filename: file name to which the results are stored in csv format
//
//   - header_fields:   array of fields whih are stored to the csv file
//
//   - multibar:        if you want progressbar, pass a multibar object
//
// first create an object used to store the results of the compare action using:
// var comparePcap = new ComparePcap(....)
function ComparePcap(match_array, logger, result_filename, header_fields, multibar, max_delay, max_error, offset) {

    this._match_array = match_array;
    this._logger = logger;
    this._result_filename = result_filename;
    this._header_fields = header_fields;
    this._resultArray =[];
    this._csvWriter = createCsvWriter({
        path: this._result_filename,
        header: this._header_fields
    });
    this._progressBarTotal;
    this._progressBarMatches;
    this._multibar = multibar;
    this._max_delay = max_delay;
    this._max_error = max_error;
    this._offset = offset;

}
// --------------------------------------------------------------------------------------
// 'match_packet'
//
// helper function to match packets
// returns true or false
ComparePcap.prototype.match_packet = function(sourcePacket, destinationPacket, matchArray){
    var self = this;
    if (!matchArray) {
        matchArray = self._match_array;
    }
    let result = false;
    for (matchItem of matchArray) {
        switch (matchItem.type) {
            case "match":
                result = (sourcePacket[matchItem.id] == destinationPacket[matchItem.id])
        }
        if (!result) break;
    }
    return result;
}
// --------------------------------------------------------------------------------------
// 'findStartIndex'
//
// helper function to find start index of both arrays. The functions uses the time stamps
// to find a matching index.
// returns an object with sourceIndex and destIndex or null when no match is found.
ComparePcap.prototype.findStartIndex = function(sourceArray, destArray){
    if (sourceArray === null || sourceArray[0] === 'undefined' || sourceArray[0] === null) {
        return null;
    }
    if (destArray === null || destArray[0] === 'undefined' || destArray[0] === null) {
        return null;
    }
    firstSourceTimestamp = sourceArray[0]["pcapPacketHeader.ts_sec"];
    firstDestTimestamp = destArray[0]["pcapPacketHeader.ts_sec"];
    var laggingArray, laterTime, index, sequence;
    if (firstSourceTimestamp <= firstDestTimestamp) {

        laggingArray = sourceArray;
        laterTime = firstDestTimestamp;
        sequence = "srcLagging";
    } else {
        laggingArray = destArray;
        laterTime = firstSourceTimestamp;
        sequence = "destLagging";
    }
    for (let i=0; i<laggingArray.length; i++) {
        if (laggingArray[i]["pcapPacketHeader.ts_sec"]>= laterTime) {
            index = (i>0)? i-1:0;
            break;
        }
    }
    if (index == undefined) {
        return null;
    }
    if (sequence == "destLagging") {
        return { sourceIndex: 0, destIndex: index};
    } else {
        return { sourceIndex: index, destIndex: 0};
    }
}
// --------------------------------------------------------------------------------------
// 'writeRecords'
//
// write records to a csv file
ComparePcap.prototype.writeRecords = function(resultArray) {
    var self = this;
    if (!resultArray) {
        resultArray = self._resultArray;
    }
    return self._csvWriter.writeRecords(resultArray);
}
// --------------------------------------------------------------------------------------
// 'comparePcapArrays'
//
// main function to compare two arrays. the function takes a source and destination array
// this function returns a promise
ComparePcap.prototype.comparePcapArrays = function(sourceArray, destinationArray) {
    var self = this;
    return new Promise(function(resolve, reject) {
        var i;
        var lastFoundAt = 0;
        // find start index
        var startIndex = self.findStartIndex(sourceArray, destinationArray);
        if (!startIndex) {
            self._logger.error("comparePcapArrays: no timestamps found that match");
            reject(new Error("comparePcapArray->findStartIndex: no timestamps found that match"));
        }
        var nrOfMatches = 0;
        var nrOfLosts = 0;
        var lastMatchAtResultArray = 0;
        if (self._multibar) {
            self._progressBarTotal = self._multibar.create(Math.floor((sourceArray.length-startIndex.sourceIndex)/1000), 0);
            self._progressBarMatches = self._multibar.create(Math.floor((sourceArray.length-startIndex.sourceIndex)/1000), 0);
            if (self._progressBarTotal) {
                self._progressBarTotal.update(0,{name: "compare source and destination"});
            }
            if (self._progressBarMatches) {
                self._progressBarMatches.update(0,{name: "compare source and destination"});
            }
        }
        for (let p = startIndex.sourceIndex; p< sourceArray.length; p++) {
            if (p % 1000 == 0 && self._progressBarTotal) {
                self._progressBarTotal.update(Math.floor(p/1000));
            }
            sourcePacket = sourceArray[p];
            i = startIndex.destIndex
            for (; i<destinationArray.length; i++) {
                destinationPacket = destinationArray[i];
                if (destinationArray[startIndex.destIndex]["pcapPacketHeader.ts_sec"]*1000000 + destinationArray[startIndex.destIndex]["pcapPacketHeader.ts_usec"] 
                                           + self._max_error + self._offset
                                           <  sourcePacket["pcapPacketHeader.ts_sec"]*1000000 + sourcePacket["pcapPacketHeader.ts_usec"]  ) {
                    // start at least with searching at the same second
                    startIndex.destIndex = i;
                } else {
                    if (destinationPacket["pcapPacketHeader.ts_sec"]*1000000 + destinationPacket["pcapPacketHeader.ts_usec"] + self._offset
                           > sourcePacket["pcapPacketHeader.ts_sec"]*1000000 + sourcePacket["pcapPacketHeader.ts_usec"] + self._max_delay) {
                        // more than max_delay usecond difference, give up
                        break;
                    }
                }
                if (!sourcePacket.found && self.match_packet(sourcePacket, destinationPacket, self._match_array)) {
                    self._resultArray.push({
                        "source_packetNr": sourcePacket["packetNr"],
                        "destination_packetNr": destinationPacket["packetNr"],
                        "frameCnt": sourcePacket["frameCnt"],
                        "source_pcapPacketHeader.ts_sec": sourcePacket["pcapPacketHeader.ts_sec"],
                        "source_pcapPacketHeader.ts_usec": sourcePacket["pcapPacketHeader.ts_usec"],
                        "destination_pcapPacketHeader.ts_sec": destinationPacket["pcapPacketHeader.ts_sec"],
                        "destination_pcapPacketHeader.ts_usec": destinationPacket["pcapPacketHeader.ts_usec"],
                        "pcapPacketHeader.incl_len": sourcePacket["pcapPacketHeader.incl_len"],
                        "pcapPacketHeader.orig_len": sourcePacket["pcapPacketHeader.orig_len"],
                        "udpHeader.dest_port": sourcePacket["udpHeader.dest_port"],
                        "udpHeader.src_port": sourcePacket["udpHeader.src_port"],
                        "protocol": sourcePacket["protocol"],
                        "lost": false
                    })
                    lastFoundAt = i;
                    lastMatchAtResultArray = self._resultArray.length;
                    nrOfMatches++;
                    if (nrOfMatches%1000 == 0 && self._progressBarMatches) {
                        self._progressBarMatches.update(Math.floor(nrOfMatches/1000));
                    }
                    sourcePacket.found = true;
                    break;
                }
            }
            if (!sourcePacket.found && nrOfMatches>0) {
                    // we lost this packet
                    nrOfLosts++;
                    self._resultArray.push({
                        "source_packetNr": sourcePacket["packetNr"],
                        "frameCnt": sourcePacket["frameCnt"],
                        "source_pcapPacketHeader.ts_sec": sourcePacket["pcapPacketHeader.ts_sec"],
                        "source_pcapPacketHeader.ts_usec": sourcePacket["pcapPacketHeader.ts_usec"],
                        "pcapPacketHeader.incl_len": sourcePacket["pcapPacketHeader.incl_len"],
                        "pcapPacketHeader.orig_len": sourcePacket["pcapPacketHeader.orig_len"],
                        "udpHeader.dest_port": sourcePacket["udpHeader.dest_port"],
                        "udpHeader.src_port": sourcePacket["udpHeader.src_port"],
                        "protocol": sourcePacket["protocol"],
                        "lost": true
                    })
            }
        }
        self._logger.info("found: " + nrOfMatches + " and lost: " + 
                          (lastMatchAtResultArray - nrOfMatches) + 
                          " (Matched: " + Math.floor(100*(nrOfMatches/(lastMatchAtResultArray - nrOfMatches))) +
                          "%)");

        resolve(self._resultArray.slice(0, lastMatchAtResultArray));
    });
}

module.exports = ComparePcap;