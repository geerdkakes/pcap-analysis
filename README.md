# pcap-analysis

Pcap-analysis contains a set of functions to analyse pcap files. Currently the main function is 
to compare two pcap files and match the packets. This way the packet loss and packet delay can be
determined. The function creates several csv-files to which all information is stored.

     ----------                          -----------
    |          |     ----> up           |           |
    |   pcap   | ---------------------> |    pcap   |
    |     A    |     <---- down         |      B    |
     ----------                          -----------

## recording pcap's

Packets can be captured easily using tcpdump. Consider using the following flags:
```
   tcpdump -i eth0 -n -B 4096 -w dump.pcap
     -B <buffer size>, eg: -B 4096 for a buffer of 4MByte
     -n to not reverse lookup domain names
     -w <filename> to write all data to a file
     -i <interface>
```
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

optional command line flags:
-  -c \<config filename>
-  -d \<error|info|debug>
-  -i <filename to convert to csv>
-  -r <result filename>
- --compare=<filename1>,<fielaname2>

Using the `-i` flag a pcap file is only converted to a csv format. During the conversion, header fieds are decoded (like tcp, ip, udp, rtp, etc.) and the payload is converted to a checksum for future comparison. With the `--compare` flag multiple files can be specified for comparison. This to be able to script the conversion and comparison of the different pcap files.

Filenames specified via the command line take precedence over the files specified in the configuration file.

## consolidate frames

Using the output from the earlier run you can also create a csv file with all frames consolidated. Packets are consolidated into frames using rtp timestamp. All packets that have the same timestamp are considered to be part of one frame. Make sure that you specify which stream is an rtp stream when running the previous pcap analysis program. You can specify which stream is an rtp stream in the configuration file using:
```
config.decoders = [
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5005, operator: "eq"}
            ],
            protocol: "rtp"
        },
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5006, operator: "eq"}
            ],
            protocol: "rtp"
        },
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5007, operator: "eq"}
            ],
            protocol: "rtp"
        },
        {
            matchfields: [
                {field: "protocol", value: "udp", operator: "eq"},
                {field: "udpHeader.dest_port", value: 5008, operator: "eq"}
            ],
            protocol: "rtp"
        }
    ]
```
In this example 4 streams are identified to be rtp streams using the destination port number and the protocal field. The protocol can either be tcp or udp. 

After the pcap analysis program has run you can consolidate the output per frame using:

```
node --max-old-space-size=8192 consolidate_frames.js -i analysed_input.csv -o consolidated_output.csv
```

## sliced output

Using command line flags you can instruct to only write out csv files. There is an option to write out to multiple csv files, splitting up the pcap file in different files with the same duration in time. To instruct to only convert to a csv file use the `-i` flag:
- -i <filename> where filename is the input pcap filename
- -s <false|true> to specify a sliced output
- -b <basename> the basename contained in the output csv (together with a date and time stamp)

In the configuration file you can also specify the duration in time that should be contained in an output csv file.

## changes

- 5-2-2021: added operator field to filter, allowing for different types of matching (e.g. greater than, less than, contains, etc). Please see example `config.js` for the different options.
- 5-3-2021: added extra offset parameters to help the search when both pcaps are no aligned correctly in time.
- 4-4-2021: added decoder for rtp packets. Now the rtp timestamp is used to recognise which packets belong to a frame.
- 5-4-2021: added `direction` to packets. From source to destination is `up` and the other way around `down`
- 10-4-2021: possibility to only covert to csv files using a commandline flag. Also the input variables to specify the input filename in the configuration file is changed (see config for an example)

## To do
- improve the progress bar (e.g. display eta, work while reading csv and enable in between updates while comparing packets)
- enable comparison of more than two probes. Currently only two probes are allowed
- correct time using chrony output. For each source optionally a "statistics.log" file can be specified + the reference to be used (e.g. PPS). The time is than corrected using the `Est offset` field. This field is in seconds, a positive value means the time in the PCAP is estimated to be fast.

## Contribute

Please fork this code and create a pull request to contribute.

## License

This code may be freely used under the MIT license. Please see `LICENSE.md`.

## Author

This code has been created by Geerd Kakes. 
