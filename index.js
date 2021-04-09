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


//  libraries to use
const args = require('minimist')(process.argv.slice(2));
const cliProgress = require('cli-progress');

// load function to read pcap files
var read_pcap = require('./read_pcap');

// load function to read csv files
var read_csv = require('./read_csv');


// load object-template to compare pcap files
var ComparePcap = require('./compare_pcap');



// set debugger with debuglevel from commandline, default is error
const debuglevel = (typeof args.d === 'undefined' || args.d === null) ? "error" : args.d;
var logger = require('./logger')(debuglevel);



// load helper functions
var Load_config =  require('./load_config')
const configFilename = (typeof args.c === 'undefined' || args.c === null) ? "./config" : args.c;
var configuration = new Load_config(configFilename, logger, args);



// get filter function used to filter out the packets we need to analyse and indicate which are up and down link packets
filter_packet = require('./filter_packet');

// declare variables destination and source Array. Will be defined using read_pcap function.
var pcapDataArrayA;
var pcapDataArrayB;
var upMatches;
var downMatches;
var comparePcap

// progress bar - only working when using command line
const multibar = new cliProgress.MultiBar({
    clearOnComplete: false,
    hideCursor: true
 
}, cliProgress.Presets.shades_grey);


// if input file given on commandline we only process this file:
if (configuration._singleInput) {
    var input = {};


    return new Promise(function(resolve, reject) {
        if (configuration.parse_filename(configuration._singleFileInput, input)) {
            let msg = "Error using input file: " + inputfile;
            logger.error(msg);
            reject(new Error(msg));
        }
        if (configuration.load_filterset(input)) {
            let msg = "Error retrieving default filterset 'config.filter_set' from configuration: " + configFilename
            logger.error(msg);
            reject(new Error(msg));
        }
        resolve(configuration)
    })
    .then(function(result) {
        fileObject = {}
        if (configuration._slicedOutput) {
            fileObject.basename = configuration._baseName;
            fileObject.basepath = input.csvName.match(/^(.+)\/([^\/]+)$/i)[1].concat('/');
            fileObject.windowlength = configuration._windowlength
        } else {
            fileObject.staticPctBufLen = configuration._staticPctBufLen;
            fileObject.staticfilename = input.csvName;
        }
        input.fileObject = fileObject;
        return parse_data_file(input, configuration)
                .then(function(result) {
                    process.exit(0);
                })
    })
} else {
    // start by checking filenames in main config
    configuration.init()
    .then(function(result){
        return itterate_input_files(configuration);
    })
    .then(function(result){
        pcapDataArrayA = result.pop_pcap_packet_array();
        pcapDataArrayB = result.pop_pcap_packet_array();
        // new comparePcap object using template-object
        comparePcap = new ComparePcap(result._matchArray, logger, result._resultFileName, result._headerFields, multibar, result._maxDelay, result._maxError, result._offset);

        return comparePcap.comparePcapArrays(pcapDataArrayA, pcapDataArrayB, "up");
    })
    .then(function(result){
        logger.debug("Found " + result.length + " matches in up direction");
        upMatches = result;
        return comparePcap.comparePcapArrays(pcapDataArrayA, pcapDataArrayB, "down");
    })
    .then(function(result){
        logger.debug("Found " + result.length + " matches in down direction");
        downMatches = result;
        return comparePcap.writeRecords(upMatches.concat(downMatches));
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
}


function itterate_input_files(config) {
    var input_file = config.pop_inputfile(config);
    if (input_file) {
        fileObject ={}
        fileObject.staticPctBufLen = configuration._staticPctBufLen;
        fileObject.staticfilename = input_file.csvName;
        input_file.fileObject = fileObject;
        // currently only static file names allowed. For future work also enable slicing of files in small parts.
        return parse_data_file(input_file, config)
                .then(function(result){
                    config._logger.debug("read pcap data file: ");
                    config._logger.debug(JSON.stringify(input_file));
                    config.push_pcap_packet_array(result);
                    return itterate_input_files(config);
                 });
    } else {
        // all files loaded return
        return config;
    }
}

function parse_data_file(input_file, config) {
    switch(input_file.inputType) {
        case "pcap":
            // add code to populate fileobject (to replace csvName)
            return read_pcap(input_file.pcapName, input_file.fileObject, logger, filter_packet(input_file.filterSet), true, multibar,config._decoders)
            .then(function(result) {
                return result._packets
            })
        case "csv":
            return read_csv(input_file.csvName);
    }
}