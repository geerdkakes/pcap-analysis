function get_basename(filename) {
    return filename.replace(/\.[^/.]+$/, "");
}

function get_extension(filename) {
    return filename.match(/[^.][0-9a-z]+$/i)[0].toLowerCase();
}

function Load_config(configFilename, logger) {

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

    // read config from configfile (javascript format)
    this._configData = require(configFilename);


}

Load_config.prototype.init = function(self) {
    if (!self) {
        self = this;
    }
    return self.check_filenames(self)
           .then(function(result){
               return result.check_parameters(result);ß
            });
}

Load_config.prototype.check_filenames = function(self) {
    if (!self) {
        self = this;
    }
    return new Promise(function(resolve, reject) {

        if (typeof self._configData.input !== "undefined" && self._configDaga.input !== null) {
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
                self._input[i] = {};
                self._input[i]["indexLetter"] = chr;
                // check extension
                let fileExtension = get_extension(inputFilename);
                switch (fileExtension) {
                    case "pcap":
                        // found extension pcap. Check if pcapName was specified, if not set it
                        if (!self._configData["pcapName" + chr])  {
                            self._input[i].pcapName = inputFilename;
                        } else {
                            self._input[i].pcapName = self._configData["pcapName" + chr];
                        }
                        // Check if csvpName was specified, if not set it
                        if (!self._configData["csvName" + chr]) {
                            self._input[i].csvName = get_basename(inputFilename) + ".csv";
                        } else {
                            self._input[i].csvName = self._configData["csvName" + chr];
                        }
                        // set input type to pcap
                        self._input[i].inputType = "pcap";
                        break;
                    case "csv":
                        // check if csvName was specified, if not set it:
                        if (!self._configData["csvName" + chr]) {
                            self._input[i].csvName = inputFilename;
                        } else {
                            self._input[i].csvName = self._configData["csvName" + chr];
                        }
                        // set input type to csv
                        self._input[i].inputType = "csv";
                        break;
                    default:
                        // unknown extension
                        self._logger.error("unknown extension \"" + fileExtension + "\"" + " for inputfile: " + self._configData["inputfile" + chr]);
                        return reject(new Error("Unknown file extension: " + fileExtension));
                }
                // load filterSet
                let currentFilterset = self._configData["filter_set" + chr];
                if (typeof currentFilterset !== "undefined" && currentFilterset !== null) {
                    self._input[i].filterSet = currentFilterset
                } else {
                    self._logger.error("No filterset + \"" + "filter_set" + chr + "\" present for \"" + inputFilename + "\"");
                    return reject(new Error("Missing filterset for input file: " + inputFilename));
                }
                i++;
            } else {
                // no filename found for this letter
                continue;
            }
        }
        resolve(self);
    });
}

Load_config.prototype.check_parameters = function(self){
    if (!self) {
        self = this;
    }
    return new Promise(function(resolve, reject) {
        // check available parameters
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
        if (typeof self._configData.resultFilename !== 'undefined' && self._configData.resultFilename !== null) {
            self._resultFileName = self._configData.resultFilename;
        } else {
            self._logger.info("Missing result file name");
        }
        if (typeof self._configData.header_fields !== 'undefined' && self._configData.header_fields !== null) {
            self._headerFields = self._configData.header_fields;
        } else {
            self._logger.info("Missing header fields to export results");
        }
        resolve(self);
    });
}


Load_config.prototype.pop_inputfile = function(self) {
    if (!self) {
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