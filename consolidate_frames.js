// simple program to consolidate csv found with dest and source compared and to group by frame
// input: csv created by index.js
// output: consolidated csv
//
// usage: node --max-old-space-size=8192 consolidate_frames.js -i analysed_input.csv -o consolidated_output.csv


// libraries
const args = require('minimist')(process.argv.slice(2));
const csv = require('csv-parser')
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const fs = require('fs')

// read command line flags
const filename_in = (typeof args.i === "undefined" || args.i === null) ? "/Users/geerd/data/cases/helmond/drive test/20-11-2020 remote driving test/test_1_car-gNodeB.csv" : args.i;
const filename_out = (typeof args.o === "undefined" || args.o === null) ? "/Users/geerd/data/cases/helmond/drive test/20-11-2020 remote driving test/test_1_car-gNodeB_consolidated.csv" : args.o;

// array to which input csv is parsed
const read_array = [];

// array which will contain consolidated data
const cons_array =[];

// header fields which will be writen to the output csv
const header_fields = [
  {"id": "rtpTimestamp", "title": "rtpTimestamp"},
  {"id": "sendCnt", "title": "sendCnt"},
  {"id": "rcvCnt", "title": "rcvCnt"},
  {"id": "start_ts_sec", "title": "start_ts_sec"},
  {"id": "start_ts_usec", "title": "start_ts_usec"},
  {"id": "min_diff", "title": "min_diff"},
  {"id": "max_diff", "title": "max_diff"},
  {"id": "overall_diff", "title": "frame_latency"},
  {"id": "total_frame_len", "title": "total_frame_len"},
  {"id": "first_src_pckt_nr", "title": "first_src_pckt_nr"},
  {"id": "udpHeader.dest_port", "title": "udpHeader.dest_port"},
  {"id": "udpHeader.src_port", "title": "udpHeader.src_port"},
  {"id": "protocol", "title": "protocol"},
  {"id": "markerbit_set", "title": "markerbit_set"},
  {"id": "rcv_seq_wrong", "title": "rcv_seq_wrong"}
];

// prepare output csv
const csvWriter = createCsvWriter({
  path: filename_out,
  header: header_fields
});

// read input csv and start function search_array when finished
fs.createReadStream(filename_in)
  .pipe(csv())
  .on('data', (data) =>  read_array.push(data))
  .on('end', () => {
    search_array(read_array);
  });


// main function to find matching packets
function search_array(src_array) {

  let start_match_index = 0;

  // loop through input data
  for (ell of src_array) {
    // check if rtp timestamp is present
    if (!ell["rtpHeader.timestamp"] || ell["rtpHeader.timestamp"] == "" ) {
      continue;
    }
    let match_found = false;
    let match_set = {
      "rtpTimestamp": ell["rtpHeader.timestamp"],
      "udpHeader.dest_port": ell["udpHeader.dest_port"],
      "udpHeader.src_port": ell["udpHeader.src_port"],
      "protocol": ell["protocol"]
    };
    // for each entry in input data look if we already have a matching frame found
    for (let p = start_match_index;p<cons_array.length; p++) {
      match_ell = cons_array[p];
      if ( match_ell.start_ts_sec  < ell["source_pcapPacketHeader.ts_sec"]) {
        // start index at latest possible moment to shorten search
        start_match_index = p;
      }
      if (match_object(match_ell,match_set)) {
        match_found = true;
        if (ell["lost"] == "false") {
          // destintion packet present
          let timeDif = time_diff(ell["source_pcapPacketHeader.ts_sec"],
                                  ell["source_pcapPacketHeader.ts_usec"],
                                  ell["destination_pcapPacketHeader.ts_sec"],
                                  ell["destination_pcapPacketHeader.ts_usec"]);
          if (match_ell.min_diff > timeDif) {
            match_ell.min_diff = timeDif;
          } else if (match_ell.max_diff < timeDif) {
            match_ell.max_diff = timeDif;
          }
          let rcv_dif_usec = time_diff(match_ell.start_ts_sec,
                                       match_ell.start_ts_usec,
                                       ell["destination_pcapPacketHeader.ts_sec"],
                                       ell["destination_pcapPacketHeader.ts_usec"]);
          if (rcv_dif_usec < match_ell.latest_rcv_dif_usec) {
            // receive sequence wrong
            match_ell.rcv_seq_wrong = true;
          }
          match_ell.latest_rcv_dif_usec = rcv_dif_usec;
          match_ell.end_ts_sec = ell["destination_pcapPacketHeader.ts_sec"];
          match_ell.end_ts_usec = ell["destination_pcapPacketHeader.ts_usec"];
          match_ell.overall_diff = Math.max(rcv_dif_usec,match_ell.latest_rcv_dif_usec);
          match_ell.rcvCnt++;
        }
        if (ell["rtpHeader.marker"] == 1) {
          match_ell.markerbit_set = true;
        }
        match_ell.sendCnt++;
        match_ell.total_frame_len += Number(ell["pcapPacketHeader.orig_len"]);

        break;
      }
    }
    if (!match_found) {
      // first entry of this frame
      match_set.sendCnt = 1;
      if (ell["lost"] == "false") {
        let timeDif = time_diff(ell["source_pcapPacketHeader.ts_sec"],
                                ell["source_pcapPacketHeader.ts_usec"],
                                ell["destination_pcapPacketHeader.ts_sec"],
                                ell["destination_pcapPacketHeader.ts_usec"]);
        match_set.min_diff = timeDif;
        match_set.max_diff = timeDif;
        match_set.overall_diff = timeDif;
        match_set.latest_rcv_dif_usec = time_diff(ell["source_pcapPacketHeader.ts_sec"],
                                                  ell["source_pcapPacketHeader.ts_usec"],
                                                  ell["destination_pcapPacketHeader.ts_sec"],
                                                  ell["destination_pcapPacketHeader.ts_usec"]);
        match_set.rcvCnt = 1;
        match_set.end_ts_sec = ell["destination_pcapPacketHeader.ts_sec"];
        match_set.end_ts_usec = ell["destination_pcapPacketHeader.ts_usec"];
      } else {
        // if no destination packet match set diff to zero.
        match_set.latest_rcv_dif_usec = 0;
        match_set.rcvCnt = 0;
      }
      match_set.first_src_pckt_nr = ell["source_packetNr"];
      match_set.total_frame_len = Number(ell["pcapPacketHeader.orig_len"]);
      match_set.start_ts_sec = ell["source_pcapPacketHeader.ts_sec"];
      match_set.start_ts_usec = ell["source_pcapPacketHeader.ts_usec"];
      match_set.latest_sequence_num = ell["rtpHeader.sequence_number"];
      if (ell["rtpHeader.marker"] == 1) {
        match_set.markerbit_set = true;
      } else {
        match_set.markerbit_set = false;
      }
      match_set.rcv_seq_wrong = false;
      cons_array.push(match_set);
    }

  }
  csvWriter.writeRecords(cons_array);

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

