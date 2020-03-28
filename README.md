# pcap-analysis

Pcap-analysis contains a set of functions to analyse pcap files. Currently the main function is 
to compare two pcap files and match the packets. This way the packet loss and packet delay can be
determined. The function creates several csv-files to which all information is stored.

 ----------                          -----------
|          |                        |           |
|  source  | ---------------------> |destination|
|   pcap   |                        |   pcap    |
 ----------                          -----------

## usage

All configurations are stored in `config.js`. Here you can define the source and destination pcap file names,
the field names that need to be matched, the filters that need to be applied and the field names that need to
be stored in the resulting csv-file (storing the matching result).

After changing the 'config.js' run the program using:
```
node  --max-old-space-size=8192   index.js
```

## other uses

You can also use `read_pcap.js` to convert a pcap file to a csv format. For now you need to write your own code to do this.
Use `index.js` as an example.


## Contribute

Please fork this code and create a pull request to contribute.

## License

This code may be freely used under the MIT license

## Author

This code has been created by Geerd Kakes. 