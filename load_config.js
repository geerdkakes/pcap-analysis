function get_basename(filename) {
    return filename.replace(/\.[^/.]+$/, "");
}

function get_extension(filename) {
    return filename.match(/[^.][0-9a-z]+$/i)[0].toLowerCase();
}

function Load_config(configFilename, logger, args) {

    this._logger = logger;
    this._configFilename = configFilename;
    this._input = [];
    this._maxDelay = 500000;
    this._maxError = 500000;
    this._offset = 0;
    this._pcapDataArrays = [];
    this._decoders = [];
    this._matchArray = [];
    this._resultFileName = "";
    this._headerFields = [];
    this._singleInputFile = null;
    this._baseName = "";
    this._args = args;
    this._singleInput = (typeof args.i === "undefined" || args.i === null)? false: true;
    this._windowlength = 0;
    this._staticPctBufLen = 1000;
    this._singleFileInput = null;

    // read config from configfile (javascript format)
    this._configData = require(configFilename);

    this.check_parameters();
}

Load_config.prototype.init = function(self) {
    if (typeof self === "undefined" || self === null) {
        self = this;
    }
    return self.check_filenames(self)
}

Load_config.prototype.check_filenames = function(self) {
    if (typeof self === "undefined" || self === null) {
        self = this;
    }
    return new Promise(function(resolve, reject) {

        if (typeof self._configData.input !== "undefined" && self._configData.input !== null) {
            // config already present
            self._logger.info("Found input object in configuration with " + self._configDaga.input.length + " elements. Using found object")
            self._input = self._configDaga.input;
            return resolve(self);
        }
        var i =0;
        // iterate over capital letters A to Z:
        for (let n = 0; n < 26; n++) {

            var chr = String.fromCharCode(65 + n);
            let inputFilename = self._configData["inputfile" + chr];
            // check input filename
            if (inputFilename && inputFilename != "") {
                // found filename config
                var input = {};
                let result = self.parse_filename(inputFilename, input, self._configData["pcapName" + chr], self._configData["csvName" + chr]);
                if (result) {
                    // unknown extension
                    self._logger.error("unknown extension \"" + get_extension(inputFilename) + "\"" + " for inputfile: " + self._configData["inputfile" + chr]);
                    return reject(new Error("Unknown file extension: " + get_extension(inputFilename)));
                } 
                input["indexLetter"] = chr;

                // load filterSet
                result = self.load_filterset(input, self._configData["filter_set" + chr]);
                if (result) {
                    self._logger.error("No filterset \"" + "filter_set" + chr + "\" present for \"" + inputFilename + "\"");
                    return reject(new Error("Missing filterset for input file: " + inputFilename));
                }
                self._input[i] = input;
                i++;
            } else {
                // no filename found for this letter
                continue;
            }
        }
        resolve(self);
    });
}

Load_config.prototype.parse_filename = function(inputFilename, input, pcapName, csvName) {

    var self = this;

    // check extension
    let fileExtension = get_extension(inputFilename);
    if (!input) {
        input = {};
    }
    switch (fileExtension) {
        case "pcap":
            // found extension pcap. Check if pcapName was specified, if not set it
            if (!pcapName)  {
                input.pcapName = inputFilename;
            } else {
                input.pcapName = pcapName;
            }
            // Check if csvpName was specified, if not set it
            if (!csvName) {
                input.csvName = get_basename(inputFilename) + ".csv";
            } else {
                input.csvName = csvName;
            }
            // set input type to pcap
                input.inputType = "pcap";
            break;
        case "csv":
            // check if csvName was specified, if not set it:
            if (!csvName) {
                input.csvName = inputFilename;
            } else {
                input.csvName = csvName;
            }
            // set input type to csv
                input.inputType = "csv";
            break;
        default:
            return 1;

    }
    return 0;
}

Load_config.prototype.load_filterset = function(input, currentFilterset){
    var self = this;
    if (typeof currentFilterset !== "undefined" && currentFilterset !== null) {
        input.filterSet = currentFilterset
        return 0;
    } else {
        // check if default / generic filterset is defined
        if (typeof self._configData["filter_set"] !== "undefined" && self._configData["filter_set"] !== null) {
            input.filterSet = self._configData["filter_set"]
            return 0;
        } else {
            return 1;
        }
    }
}

Load_config.prototype.check_parameters = function(self){
    if (!self) {
        self = this;
    }

    // check available parameters
    if (typeof self._args.i !== 'undefined' && self._args.i !== null) {
        self._singleFileInput = self._args.i;
    }
    if (typeof self._configData.max_delay !== 'undefined' && self._configData.max_delay !== null) {
        self._maxDelay = self._configData.max_delay;
    }
    if (typeof self._configData.max_error !== 'undefined' && self._configData.max_error !== null) {
        self._maxError = self._configData.max_error;
    }
    if (typeof self._configData.offset !== 'undefined' && self._configData.offset !== null) {
        self._offset = self._configData.offset;
    }
    if (typeof self._configData.decoders !== 'undefined' && self._configData.decoders !== null) {
        self._decoders = self._configData.decoders;
    }
    if (typeof self._configData.match_array !== 'undefined' && self._configData.match_array !== null) {
        self._matchArray = self._configData.match_array;
    } else {
        self._logger.info("Missing match array");
    }
    if (typeof self._args.r !== 'undefined' && self._args.r !== null) {
        self._resultFileName = self._args.r;
    } else {
        if (typeof self._configData.resultFilename !== 'undefined' && self._configData.resultFilename !== null) {
            self._resultFileName = self._configData.resultFilename;
        } else {
            self._logger.info("Missing result file name");
        }
    }
    if (typeof self._configData.header_fields !== 'undefined' && self._configData.header_fields !== null) {
        self._headerFields = self._configData.header_fields;
    } else {
        self._logger.info("Missing header fields to export results");
    }
    if (typeof self._args.b !== 'undefined' && self._args.b !== null) {
        self._baseName = self._args.b
    } else {
        if (typeof self._configData.basename !== 'undefined' && self._configData.basename !== null) {
            self._baseName = self._configData.basename;
        } else {
            self._baseName = "";
        }
    }
    if (typeof self._args.s !== 'undefined' && self._args.s !== null) {
        if (self._args.s === 'true' || self._args.s === 'True' || self._args.s === 'TRUE') {
           self._slicedOutput = true
        }
    } else {
        if (typeof self._configData.sliced_output !== 'undefined' && self._configData.sliced_output !== null) {
            self._slicedOutput = self._configData.sliced_output;
        } else {
            self._slicedOutput = false;
        }
    }

    if (typeof self._configData.window_length !== 'undefined' && self._configData.window_length !== null) {
        self._windowlength = self._configData.window_length;
    } else {
        self._windowlength = 300; // 5 minnutes
    }
    if (typeof self._configData.static_pct_buf_len !== 'undefined' && self._configData.static_pct_buf_len !== null) {
        self._staticPctBufLen = self._configData.static_pct_buf_len;
    } else {
        self._staticPctBufLen = 1000;
    }

    if (typeof self._args.compare !== 'undefined' && self._args.compare !== null) {
        var filesToCompare = self._args.compare.split(",");
        
        for (let i = 0; i < filesToCompare.length; i++) {
            // itterate of letters starting with A
            var chr = String.fromCharCode(65 + i);
            self._configData["inputfile" + chr] = filesToCompare[i];
        }
    }
    
    // singleInputFile only parsed from commandline. treated as base name when slicedOutput is defined else as full file name (static)
    if (!self._slicedOutput) {
        if (self._singleFileInput) {
            self._singleInputFile = self._singleFileInput;
        }
    } 
}


Load_config.prototype.pop_inputfile = function(self) {
    if (typeof self === "undefined" || self === null) {
        self = this;
    }
    if (self._input.length > 0) {
        var input_file = self._input[0];
        self._input.shift();
        return input_file;
    } else {
        return null;
    }
}

Load_config.prototype.push_pcap_packet_array = function(pcapData){
    self = this;

    self._pcapDataArrays.push(pcapData);
}

Load_config.prototype.pop_pcap_packet_array = function(){
    self = this;
    var tmp_array = [];
    if (self._pcapDataArrays.length > 0) {
        tmp_array = self._pcapDataArrays[0];
        self._pcapDataArrays.shift();
        return tmp_array;
    } else {
        return null;
    }
}




// export the Load_config class
module.exports = Load_config;