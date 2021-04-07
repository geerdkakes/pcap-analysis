const parse = require('csv-parse')

var fs = require('fs');






function read_csv(filename) {
    return new Promise(function(resolve, reject) {
        const read_array = [];
        // Create the parser
        const parser = parse({
            delimiter: ',',
            cast: true,
            columns: true
        });  
        parser.on('readable', function(){
            let record
            while (record = parser.read()) {
                read_array.push(record)
            }
        });

        // Catch any error
        parser.on('error', function(err){
            reject(err);
        });

        parser.on('end', function(){
            resolve(read_array);
        });

        fs.createReadStream(filename).pipe(parser);
    });

}

// export the read_csv function
module.exports = read_csv;