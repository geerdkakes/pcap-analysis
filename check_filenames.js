

function get_basename(filename) {
    return filename.replace(/\.[^/.]+$/, "");
}

function get_extension(filename) {
    return filename.match(/[^.][0-9a-z]+$/i)[0].toLowerCase();
}



function check_filenames(config, logger) {

    // iterate over capital letters A to Z:
    for (let n = 0; n < 26; n++) {

        var chr = String.fromCharCode(65 + n);
        let inputFilename = config["inputfile" + chr];
        // check input filename
        if (inputFilename && inputFilename != "") {
            // check extension
            let fileExtension = get_extension(config.inputfileA);
             switch (fileExtension) {
                case "pcap":
                    // found extension pcap. Check if pcapName was specified, if not set it
                    if (!config["pcapName" + chr])  {
                        config["pcapName" + chr] = inputFilename;
                    }
                    // Check if csvpName was specified, if not set it
                    if (!config["csvName" + chr]) {
                        config["csvName" + chr] = get_basename(inputFilename) + ".csv";
                    }
                    // set input type to pcap
                    config["inputType" + chr] = "pcap";
                    break;
                case "csv":
                    // check if csvName was specified, if not set it:
                    if (!config["csvName" + chr]) {
                        config["csvName" + chr] = inputFilename;
                    }
                    // set input type to csv
                    config["inputType" + chr] = "csv";
                    break;
                default:
                    // unknown extension
                    logger.error("unknown extension \"" + fileExtension + "\"" + " for inputfile: " + config["inputfile" + chr]);
             }
        }
    }

}


// export the check_filenames function
module.exports = check_filenames;