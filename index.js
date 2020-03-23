const args = require('minimist')(process.argv.slice(2));


var read_pcap = require('./read_pcap');

// read commandline flags
const inputfile = (typeof args.i === 'undefined' || args.i === null) ? "./inputfile.pcap" : args.i;
const csvfile = (typeof args.c === 'undefined' || args.c === null) ? "./output.csv" : args.c;
const debuglevel = (typeof args.d === 'undefined' || args.d === null) ? "error" : args.d;
var logger = require('./logger')(debuglevel);

read_pcap(inputfile, csvfile, logger);