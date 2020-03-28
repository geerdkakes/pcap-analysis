// 'index.js'
//
// function to read two pcap files (source and destination)
// both pcapfiles are compared and a csv is created with:
//       - packet number source
//       - packet number destination (when match found)
//       - time stamps source
//       - time stamp destination (when match found)
//       - source port
//       - destination port
//       - protocol
// 
// to read pcapfiles and create packet array the function in 'read_pcap.js' is used
// to compare two packet array's the function in 'compare_pcap.js' is used
//
//
// When running make sure extra memory is allowed to store all info in memory
// e.g.: node  --max-old-space-size=8192   index.js
//


// main libraries to use
const args = require('minimist')(process.argv.slice(2));
const cliProgress = require('cli-progress');

// load function to read pcap files
var read_pcap = require('./read_pcap');

// load object-template to compare pcap files
var ComparePcap = require('./compare_pcap');

// read commandline flags
const configFilename = (typeof args.c === 'undefined' || args.c === null) ? "./config" : args.c;
const debuglevel = (typeof args.d === 'undefined' || args.d === null) ? "error" : args.d;

// set debugger with debuglevel from commandline, default is error
var logger = require('./logger')(debuglevel);

// read config from configfile (javascript format)
const config = require(configFilename);

// declare variables destination and source Array. Will be defined using read_pcap function.
var destinationArray;
var sourceArray;

// progress bar - only working when using command line
const multibar = new cliProgress.MultiBar({
    clearOnComplete: false,
    hideCursor: true
 
}, cliProgress.Presets.shades_grey);

// new comparePcap object using template-object
var comparePcap = new ComparePcap(config.match_array, logger, config.resultFilename, config.header_fields, multibar);

// define our own filter function, used by read_pcap function to store only the relevant packets.
function filter_packet(filterSet) {

    // this function is returned to read_pcap. it expects a packet in the format defined by function Packet() in 'pcapfile.js'
    return function(packet) {
        
        for (items of filterSet) {
            var result = true;
            for (item of items) {
                result = (packet[item.field] == item.value);
                if (!result) break;
            }
            if (result) {
                return true;
            }
        }
        return false;
    }
}


// start reading source pcapfile
read_pcap(config.sourcePcapName, config.sourceCsvName, logger, filter_packet(config.sourceFilterset), true, multibar)
.then(function(result){
    sourceArray = result._packets;
    return read_pcap(config.destinationPcapName, config.destinationCsvName, logger, filter_packet(config.destFilterSet), true, multibar)
})
.then(function(result){
    destinationArray = result._packets;
    return comparePcap.comparePcapArrays(sourceArray, destinationArray);
})
.then(function(result){
    return comparePcap.writeRecords(result);
})
.then(function(){
    // stop all bars
    if (multibar) {
        multibar.stop();
    }
    logger.info("ready");
})
.catch(function(result){
    console.log("error caught: ", result);
    process.exit(1);
});



