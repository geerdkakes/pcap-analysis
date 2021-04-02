# pcap-analysis

Pcap-analysis contains a set of functions to analyse pcap files. Currently the main function is 
to compare two pcap files and match the packets. This way the packet loss and packet delay can be
determined. The function creates several csv-files to which all information is stored.

     ----------                          -----------
    |          |                        |           |
    |  source  | ---------------------> |destination|
    |   pcap   |                        |   pcap    |
     ----------                          -----------

## recording pcap's

Packets can be captured easily using tcpdump. Consider using the following flags:
   tcpdum -i eth0 -n -B 4096 -w dump.pcap
     -B <buffer size>, eg: -B 4096 for a buffer of 4MByte
     -n to not reverse lookup domain names
     -w <filename> to write all data to a file
     -i <interface>
  
   If the command reports that packets were dropped by the kernel you might want to increase 
   buffersize or give some more time to establish a buffer.

Also packets can be captured using wireshark. You should save using the older pcap format.

## usage

All configurations are stored in `config.js`. Here you can define the source and destination pcap file names,
the field names that need to be matched, the filters that need to be applied and the field names that need to
be stored in the resulting csv-file (storing the matching result).

After changing the 'config.js' run the program using:
```
node  --max-old-space-size=8192   index.js
```

## consolidate frames

Using the output from the earlier run you can also create a csv file with all frames consolidated. During the first search frames are assumed for all source frames with matching source and destination addresses + ports and of which the packets are less than 1msec apart. To view the results per frame, consolidate these frames using:

```
node --max-old-space-size=8192 consolidate_frames.js -i analysed_input.csv -o consolidated_output.csv
```

## other uses

You can also use `read_pcap.js` to convert a pcap file to a csv format. For now you need to write your own code to do this.
Use `index.js` as an example.

## changes

5-2-2021: added operator field to filter, allowing for different types of matching (e.g. greater than, less than, contains, etc). Please see example `config.js` for the different options.

## Contribute

Please fork this code and create a pull request to contribute.

## License

This code may be freely used under the MIT license. Please see `LICENSE.md`.

## Author

This code has been created by Geerd Kakes. 