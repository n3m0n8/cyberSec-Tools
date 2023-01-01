# this packet sniffer was written by Bucky @thenewboston's online video guide. Website: https://thenewboston.com
# DISCLAIMER : THIS PROGRAMME IS WRITTEN AND SHOWN SOLELY FOR EDUCATIONAL PURPOSES ONLY. DO NOT USE THIS FOR ANYTHING OTHER THAN LEARNING PURPOSES. NO LIABILITY CAN BE CLAIMED FOR ANY OTHER UNINTENDED USE AND/OR DEVELOPMENT OF THIS PROGRAMME.
# NOTE the following begins with the programme along with explanatory notes. In the appendix at the bottom, you will find the raw programme without notes.
# /////////BASIC BACKGROUND NOTES FOR NETWORKING CONTEXT\\\\
'''
ASSUMING ETHERNET 802.3x type protocol because other protocols will have different Maximum Transmission Units and other quirks:

layer 4 transport  - either  (1)TCP or (2)UDP
data is incoming at the application layer levels 7,6,5 from whicher programmes are running. for instance a web browser's programme/execution communicated TCP information necessary for network activity. NOTE that TCP/UDP is only in use in an inter-network .... we can communicate with UDP or other packaging on a local area network. And in fact if we communicate purely on a local host 127 address or with direct link between only two devices, or for instance bluetooth or apple's tech, then we can use other packaging frameworks, for example between two devices we have FTP.
# Assuming processor sends relevant network instructions and packages the tcp/udp packaging, this is encapsulated within a broader IP packet (conforming to the relevant internet protocol assigned in the IP packet header- in this case 802.3x) and this is then further encapsulated within an even broader 802.3 ethernet frame covering the physical signals being sent to the devices network interface card to via data layer through an internetwork.
vice versa on the recieving end etc..
1. TCP  doesn't have a max-size because it is not based on self-contained communication of packets but rather segments that are logical packed and sequenced within the IP-Payload/Ethernet-Frames. The key to TCP is instead to get a TCP handshake via the TCP header information allowing a persistent stream of data.
BUT  payload size IS limited by two packet related factors since this TCP-packaged data is still (1)logically(IP packet payload/level3) and (2)physically(ethernetframe payload(level4)) encapsulated into a IPpacket-ethernet frame. these are all the same physical  binary-based electric signals, just being represented at different organisation and logical levels.
This counts payload ONLY, not the combined TCP/IP header section which preceded the max-64kb payload.
This combined TCP/IP header section can contain a maximum of 60 bytes, usually 20 reserved for IP header, 20 for TCP header and 20 for filling/optional ip info.

the tCP header contains PORT information since TCP is the packaging of networked data for applications to successful navigate the shared network resources managed by a a device's processor, memory and network cards- ports being simply logical gateways to asssign processor/memory and network resources fgor particular programmes on a device. so TCP header starts with: source Port (6 bits), destination port(6 bits) followed by varied further relevant packagin info as well as a checksum to verify integrity of this seciton of the ethernetframe/ippacket upon arrival at destination.


2. UDP is an older packagign mechanism and is more straightforward since it deals with segmented communication of a maximum 65,507(on ipv4) or 65,527(on ipv6) payload BUT the logical (ip packet payload) and physical (ethernet frame payload) limits -dealt with below- still apply. On the other hand UDP has slightly more space that TCP on each transmission because it is loud and crude, it doesn't have a header of up to 60bytes, the UDP header is always 8 bytes and only has fundamental logical(ip/port)/physical(mac) addressing information... no packet loss or handshaking.

layer 3 network    - IP PACKET - logical addressing
-the ip packet header has 20bytes starting with version(usuall ipv4(4 bits), header length info (4bits), TOS (8bits) total lenght of ip packet , further info relating to the order of the data as it is to be recived, time to live (for dropping packets and making sure they are resent), protocol, then the logical address part - source ip, destination ip. and then followed by the tcp header
- the ip payload has a max size of 64kb ie. 65,535 bits BUT, just like UDP and TCP, this is actually LIMITED by the data-layer transmission packaging which ,despite all these newer formats/protocols is still (in the ethernet case) the funamental ethernet frame from the early 1960s:

layer 2 data       - Ethernet frame (MAC or physical addressing to find specific devices on each IP network)

- maximum size of each payload is 1.5kb. (MTU)
-max header for eth frame is 18 bytes with MAC addressing data and usual checksum
THUS regardles of use of TCP or UDP bundling of the app/programme's network-related data via a logical (ip packet) addressing format/protocol, all of this data at a level 1 physical layer (i.e. the 1 and 0 electric signals) are fragmented from the max size (theoretically infinite with TCP, 65kb with UDP) and bundled into each ethernet frame at 1500 bytes apiec (or smaller/larger in other networking protocoles liek 802.11 etc.)
# the internet protocol packet is the overall          data carrier. it contains a header with
    #       logical (ip) address for large network linking
    #       and thus sits at level 3 of the OSI model
    #       (network level). Within that packet we find
    #       information relevant to data level 4(
    #       transport) in the form of a TCP segment or a
    #       UDP datagram. Also encapsulated in the ip
    #       packet is the level 2(data) MAC-address based
    #       ethernet/wifi frame.
'''
# /////////IMPORTS\\\\\\\\\\\\
# import socket functions package for opening network socket
import socket
# struct is a c-inherited class of inbuilt python functions for writing data to and from byte format and interpreting it. Commonly used in network frame transactions because the data needs to be packed into byte format and unpacked from byte format.
import struct
# textwrap conditionally formats text according to the args passed to it as a function
import textwrap

# /////////Compile\\\\\\\\\\\\
#Constants declared related to formatting of the output of metadata and contentpayloads at the various OSI layer -related packages of data(ethernetFrame,IPPacket,TCP/UDP/other final packaging -explained further down).
metaHeadTab1 = '\t - '
metaHeadTab2 = '\t\t - '
metaHeadTab3 = '\t\t\t - '
metaHeadTab4 = '\t\t\t\t - '
payloadTab1 = '\t '
payloadTab2 = '\t\t '
payloadTab3 = '\t\t\t '
payloadTab4 = '\t\t\t\t '

# /////////MAIN FUNCTION FIRST-ORDER COMPILATION TO PAVE THE WAY TO RUNTIME EXECUTION\\\\
def sniff():
    # create an instance of the socket.socket class object:
    #   a. Pass arg1 as the frame family (AF_PACKET - in        this case ethernet).
    #   b. pass arg2 as the choice of data type (SOCKRAW)
    #       - in this case raw
    #       bytestrings.
    #   c.  socket.nthos meth converts the network-side
    #       bigEndian bytestring format to operating
    #       system littleEndian bytestring form. the
    #       decimal 3 passed into arg1 , which can be
    #       written as a byte string of 0x0003 is simply a
    #       directive telling the thread execution to
    #       capture all incoming bigEndian bytestrings.

    # NOTE, the ethernet frame is the larger RAW data
    # AF_ adddress family packet sock.raw = raw bytestrings socket inflow
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.nthos(3))
    # while we have data incoming...
    while True:
        # create  Link layer data var (remember that the ethernet frame is dealing with OSI layer 2- the data-link level) - we handle the incoming raw bytestream data and assign it to the 64kb data packet value (64kb is actually 65,535bytes) because this is the max size of any ip packet (64kb).
        # address var to --not clear why we need an address var to also slurp up the incoming bytestream link-level data... it seems very ineficient to duplicate the data flowing in into two separate variables..???
        # Also note that we are assigning this incoming value into BOTH rawdata and address variables...
        linkDataIn, address = connection.recvfrom(65535)
        # now we seaprate this linkdata stream into four variables BUT NOTE that each variable is NOT SIMPLY being assigned the incoming data value... the unpack ethernet_frame function is being called on the linkDataIn container variable... this means that we are formatting the data as it enters (with the ethernet frame header being the first bits of the  overall bytestream since the frame header is what encapsulates both the IP packet and the TCP segment as explained above).
        # Once the relevant ethernet_frame-related bytestream values have been successfully isolated and assigned to the first three vars, then notice that the fourth and last variable absorbs the remaining bytestream of the raw incoming data, which is now relevant to the encapsulated two remaining data packages(the ip packet and the tcp segment in this case). that variable has been nicknamed the logicalData since these packages deal with logical data.
        # note that we assign these ethernet-frame layer2(data link level) related metadata and contentPayload vars by calling the second-order compilation method unpack_ethernet_frame which has been defined below in the source code.
        destination_MAC, source_MAC, ethernet_protocol, logicalDataIn = unpack_ethernet_frame(linkDataIn)
        print('\nEthernet Frame: ')
        print(metaHeadTab1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_MAC, source_MAC, ethernet_protocol))
        # ETHERNET FRAME PROCESSINGbasic check to ensure that the ethernet_protocol signal in the ethernet frame header is indeed an 8, which is the signal for 802.3x ethernet protocol comms, in order to successfully run the unpacking of this programme
        if ethernet_protocol == 8:
        # IP PACKET PROCESSING - here we assign to the relevant IP PACKET metadata and logicaldata vars the unpacked (using the unpack_ipV4_packet second-order compilation method defined below) ethernetFrame data that has been unpacked just above.
            (version, header_length, timeToLive, IPprotocol, IPsource, IPtarget) = unpack_ethernet_frame(logicalDataIn)
        # now we deploy the relevant IPPacket-level metadata to the terminalconsol output to inform user of IPPacket-related metadat info at the first-level of encapsulation:
            print(metaHeadTab1+'IPv4Packet Metadata: ')
            print(metaHeadTab2+'Version: {}, Header Length: {}, TimeToLive: {}'.format(version, header_length, timeToLive))
            print(metaHeadTab2+'IP Protocol: {}, IP Source: {}, IP Destination: {}'.format(IPprotocol, IPsource, IPtarget))
        # FINAL SECOND-DEPTH ENCAPSULATION PROCESSING - based on a choice of which type of second-depth packaging is detected when reading the IPPacket header's IPprotocol variable, we now stream out the second-depth encapsulated metadata and the actual content payload to the terminal console for the user to read. The output will be formated by the bytestrings formatting second-order compilation function (at the bottom of this source code) so it will be put out to the console in a regular column format. But the content will still be in bytestrings, so perhaps a good project is to find a way to output those bytestrings as plaintext for readability?
        # Decision point for choosing which IPpacket header Protocol signal is incoming and thereby allocating the correct second-order compilation function for unpacking the final second-depth encapsulated header/payload content.
            if IPprotocol == 1:
        # ICMP OPTION
                icmp_flag, packagingCode, chkSum, logicalDataIn = unpackICMP(logicalDataIn)
                print(metaHeadTab1 + 'ICMP Package Metadata: ')
                print(metaHeadTab2 + 'Icmp Flag: {}, packaging Code: {}, Check Sum: {}'.format(icmp_flag, packagingCode, chkSum ))
                print(metaHeadTab2 + 'ICMP Package Data: ')
                print(format_bytestrings(payloadTab3, logicalDataIn))
        # TCP OPTION
            elif IPprotocol == 6:
                source_port, destination_port, sequenceNum, acknowledgeNum, offset_reserved_nFlags,flag_urgent, flag_ack, flag_push, flag_reset, flag_sync, flag_finish, logicalDataIn= unpackTCP(logicalDataIn)
                print(metaHeadTab1 + 'TCP Segment Metadata: ')
                print(metaHeadTab2 + 'Source Port: {}, Destination Port: {}'.format(source_port, destination_port))
                print((metaHeadTab2 + 'Sequence Number: {}, Acknowledge Number: {}').format(sequenceNum,acknowledgeNum))
                print(metaHeadTab2 + 'Flags: ')
                print(metaHeadTab3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urgent, flag_ack, flag_push, flag_reset, flag_sync, flag_finish))
                print(format_bytestrings(payloadTab4, logicalDataIn))
        # UDP OPTION
            elif IPprotocol == 17:
                source_port, destination_port, size, logicalDataIn = unpackUDP(logicalDataIn)
                print(metaHeadTab1 + 'UDP Datagram Metadata')
                print(metaHeadTab2 + 'Source Port: {}, Destination Port: {}, Size: {}'.format(source_port, destination_port, size))
                print(format_bytestrings(payloadTab3, logicalDataIn))
        # ANY OTHER OPTION
            else:
                print(metaHeadTab1 + 'Data: ')
                print(format_bytestrings(payloadTab2, logicalDataIn))

# SECOND ORDER COMPILATION
# /////////LAYER 2 DATA-LINK LEVEL RELATED FIRST-ORDER COMPILATION\\\\
# Here is the aforementioned ethernetExtractor method which takes in the link-level data as arg1
def unpack_ethernet_frame(linkDataIn):
    # we assign these three vars whatever data is being unpacked from the ethernet frames that are being vacuumed up.
    # note that arg1 of the unpack(meth) has ! which tells the compiler to absorb the bigEndian bytestrings that are flowing into our network interface card (since networking bytestring formats use the bigEndian storage system) into the littleEndian storage system, more appropriate for PCs.
    # arg1 will need the number and type of data inputs that the compiler is to expect. in this case, the destination mac will take up 6 bytes(6s), same for source MAC and H refers to a small unsigned(positive num only) int
    # arg2 takes in the network data inflow to be picked up from the frame BUT it passes data with an array that takes only the first 14 bytes from the frame. The first 8 bytes of the frame consist of binary packed information. The following 14 bytes consist of 6bytes for destination MAC address, 6 for source Mac and 2 for header protocol (http/s, tls etc)
    # So by adding an array that specifies we want the first 14 bytes from the raw data (discounting the raw binary which is skipped over by the unpacker) we are basically extracting from the data frame the packet/frame header METADATA
    destination_MAC, source_MAC, ethernet_protocol = struct.unpack('! 6s 6s H', linkDataIn[:14])
    # these custom functions prefacing the returned vars are defined below and their purpose is to convert the raw bytestring data into standardised versions, like a normal hex MAC address for example.
    # socket.htons is an inbuilt meth that makes the bigEndian bytestring human readable.
    # NOTE that final return statement, returning the remaining payload of the frame after the 14th byte [:14]... since we don't know the exact size of the contained data so we cannot specifically unpack it. We can only grab it wholesale.
    return format_MAC(destination_MAC), format_MAC(source_MAC), socket.htons(ethernet_protocol), linkDataIn[14:]
# note that these correctly formatted vars are now returned to main memory, ready for use in the main sniff() function defd'd above here but runtim'd below.
# now we define the format_MAC funct which is called by the above unpack_ethernet_frame function in order to note only extract the MAC source and destination addresses but also to output them in a standard MAC format
def format_MAC(bytes_format_in):
    # use the map() which iterates through a set of iterables passed in arg3 and undertakes whatever the arg1 callback function tells it to do. So use the format() function in arg1 prefaced with the regexp of the typical mac address formatting in order to take the raw bytestrings and turn it into MAC style but still unjoined and not in uppercases for the alphabetic chars.
    bytes_string = map('{:02x}'.format(), bytes_format_in)
    # this next variable now holds the fully formated MAC address. This is achieved by joining all of the mapped out bytes_string using the join() meth on each of the incoming (now hexadecimmally formatted) bytestring but also  concatanating the toUpper method (upper in py) and attaching a : for every MAC address element (which has been determined previously as being each of the first two hexadecimal units being cut up in the first operation of this function).
    mac_formatted = ':'.join(bytes_string).upper()
    return mac_formatted

    # /////////LAYER 3 NETWORK LEVEL RELATED FIRST-ORDER COMPILATION\\\\
# function to unpack the ip address from the ip packet header
# NOTE that this function is instead dealing with the level3 IP PACKET, not just the MAC-related level2 ethernetframe which is physically (binary-wise) encapsulated in the IP packet anyway.

# format ipV4 addressing:
    def format_ipv4(ipV4address):
        return '.'.join(map(str, ipV4address))

    def unpack_ipv4_packet(logicalDataIn):
    # get info about version & header length sections of the IP packet.
    # The IP packet has different sections and one of those sections is the header.
    # the IP header has several sections and can actually vary in length.
    # the first section of the ip header part of the IP Packet is the version ... usually IpV4- this is communicated by having a decimal value of 4 in this section to denote IP version 4 (100 in bits)
    # the next section is the ip header length denotation, telling us the length of this ip header seciton of the ip packet. The length is flagged by a decimal number (passed as binary of course) which acts as a placeholder flag for the multiples of (the numer of) 32 bit spaces that are contained in the header (the header's size is calculated by this convention in multiples of 32 bit spaces). So a decimal 5(101) will represent 5*32 bits of space... which is 160 which is 20 bytes(160/8 =20).
    # the minimum length of an ip header is actuall that: 20bytes (8bits is a byte so, in the header lenght section this is denoted as a decimal 5 (101). The maximum lenght of the header is 15 in decimal(1111)  which calculates to 60bytes or 480/8 or 32bytes*15.
    # there are many other sections, relating to checksum and ip etc. but for the packet sniffer here is what matters in this function, extracting the ip addressing (logical addressing) from the header.
    # The version_header_length variable is initialised and is defined as being the first bit(0) of the data stream of the packet header coming in.
    # remember that these are coming in as 1s and 0s  into the ingress point (the network interface card , presumably after the router has successfully determined the MAC-related information held within the pack in the etherenet frame's data in order to send to the relevant client/host on the designated ip network?)
        version_header_length = logicalDataIn[0]
    # Now by using a simple bitwise arithmetic operation, we can shift the bits coming in by 4 bits to the right, meaning that the initial 1s and 0s relating to the first four bits that relate to the first section of the header (dealing with the ip version which is not important to our purposes) can be 'extracted off the table' so to speak.
    # NOTE that bitwise arithmetic is NOT like decimal arithmetic. Neither addition/substraction nor shifting makes the same difference to the sum/product of the operation. Instead, it has a more 'presentaitonal' impact. For instance bitwise addition actually doesn't sum the total of the two or more added bit sequences, but rather 'cancels out' all of the 'uncertain' bit states and produces an outcome of 'certain' bits i.e. only bit states that have a 1. Example:
    # a 110101011 +
    # b 010101010  in bit = would be:
    # c 010101010  NOTE only the 1s existing in both a and b make it into c... the decimal values of these bit sequences would add up to a totally different number than that of the decimal value of c - its more about logical order than functional product....
    # likewise with a bit shift to the right:
    # a = 0101 0011
    # b = a >> 4  (bitshifted 4 to the right means:
    # b = 0011    .... 0101 has been "wiped off" the bitstream 'production line'
    # so the trick here is that we bit shift the container var of the entire ip-packet header by  4 to exract the first 4 ingressing bit values which are representing the first section of the ip version flag which we assign to a variable
        version = version_header_length >> 4
    # now, assuming although we have isolated the version element of the ip packet header, the adjoined element of header lenght is still not isolated.
    # To do this he uses another trick. He takes the full section (version as well as header length) as it has been ingressed from the zero-base (initial bit) incoming via the packet. BUT, he uses a bitwise AND operation. Remember that this doesn't produce the same arithmetic function, but rather 'overlays' the bits of each bit sequence and only 'returns' those 'hits' where both sequences have a 1.
    # so for example, the full version and header length section is two bytes of
    #              1010  1101  <---bitstream incoming
    #first bit here^     ^^^
                       #versn length
    # 15 in bits of the same bit entities length is:
    # 0000 1111
    # adding them:  10101101 &
                #   00001111  = 00001101 = 14 in decimal
    # remember that convention stores the length of a ip packet header in 32 bit units. 8 bits is one byte. 8*4 = 32 bytes. So by multiplying the 14 decimal value by 4 we are getting the total number of bits that are assigned as the header length, because the 14 value represents the decimal number of bits  being deployed as a marker/flag of multiples of 32bit units that the header's true size is. By multiplying that flag/placeholder by 4 we are saying: give me how many of the 32 bit units are being placeheld/represented by the binary flag in this header-length space(in our example that's 1101(14).
        header_length = (version_header_length & 15) * 4
    # in our exmaple the header lenght will be 14*4 = 64bits of header length (aside from the 4 bits for the verison which was already extracted).
    # Now that we have all the header worked out, we can start unpacking all of the header data that is relevant for our purposes. in particular the time to live, protocol, source and target. To isolate these, we use a struct.unpack again with bit-relevant notations)
        timeToLive, IPprotocol, IPsource, IPtarget = struct.unpack('! 8x B B 2x 4s 4s', logicalDataIn[:20]) # note arg2 is data to be unpacked into these vars, in this case, all data ingressing from the first bit for the next 20 bytes (20bytes being the full lenght of the non-optional ip packet header- and any variable part of the header lenght being due to optional/padding).
    # NOTE that the point of calculating the header lenght is that these can vary, meaning we are not sure of where the header stops and the ip packet payload(content) begins. So we need a grasp of the header length before then extracting the payload (content) - our juicy target.
        return version, header_length, timeToLive, IPprotocol, IPsource, IPtarget, format_ipv4(IPsource), format_ipv4(IPtarget), logicalDataIn[header_length:]

    # MULTIPLE UNPACKS ON THE IPPAYLOAD SECTIONS DEPENDING OF THE SECOND-ORDER ENCAPSULATIONS (i.e. TCP SEGMENT, ICMP MESSAGE, UDP DATAGRAM) Note that arg1 of these is nicknamed logical payload in order to distinguish it from the ethernet_frame unpacker's link-level data (this is just to distinguish it clearly for our use... the data is all the same physical electric signals communicated in binary- although one difference is that now, we have extracted the first parts of that physical raw binary data into the ethernet frame header as well as isolating and extracting the ipPacket header in the past two functions... so now we deal with whatever is further encapsulated at a second-depth encapsulation.
    # The way we let the programme know which of the following second-order compilation functions to run so as to correctly unpack at a second-depth of encapsulation the final set of headers and actual content data we want to capure is by using the IP Packet header's IPProtocol variable - which we isolated and extract(returned to main memory) in the previous function relating to unpacking the IPPacket. The IP Protocol variable which will hold the data relevant to the protocol field of the IP Packet header, has a binary written code which, in decimals correlates to the relevant type of second-depth encapsulation format.
    # For ICMP (internet control message protocol), the code is 1.
    #for  UDP it's 17. For TCP  it's 6 etc... the relvant code being passed in the first-order main compilation function at the top of this source code will determing which of these second-order compilation functions will be chosen by the programme. And the programme will know which number to pass to that first order main compilation function because the physical data coming in and extracted as the IPProtocal var via the preceding IPPacket unpacking function will tell it what type of protocol the raw data is being sent under. Reading that IPProtocol var's value will allow the right choice as to which of the following second-order compilation functions to run relating to the second-depth encapsulation unpacking that we finally need to do to get to the final header and separate that from the actual content data being sniffed (and thus having separated all of the metadate from that content data of the raw binary data that has been sent through the network card).

    # OPTION 1 ICMP type payloads (internet control messaging protocol - used for diagnosis).
    # only a 4 byte header so relatively simple to set the header-related container vars with bitwise-notation assigning them then followed by the content payload, signalled by a 4byte starting array position marker.
def unpackICMP(logicalDataIn):
    icmp_flag, packagingCode, chkSum = struct.unpack('! B B H', logicalDataIn[4:])
    # OPTION 2 TCP type payloads
    # in this case we take the level3 logicalpayload aspect of the level2 raw etherenet frame bitstream and we separate it from the TCP segment header. Most the lines in this function deal with sub-segmenting that TCP segment header into its various container vars for each sub-segment and the final line assigns the remaining bits beyond the calculated TCP segment header length to be the logicalPayload (i.e. after two orders of encapsulation, we have the actual content data being sent - aside from ethFrame, IpPackt and TCPSgmnt metadata)
    # regarding the TCP header subssegment we see that this includes the source and destination ports for the OS application to undertake whatever networking activity it is asking the device to do and several TCP-specific header fields all of which are allocated into the container vars. the TCP header is always 14 bytes long, so we see that on first assignment, we set the bitwise notation and the content-related IP Packet (post IPpacket Header extraction) logicalPayload data incoming upond call of the unpackTCP method.
def unpackTCP(logicalDataIn):
    (source_port, destination_port, sequenceNum, acknowledgeNum, offset_reserved_nFlags) = struct.unpack('! H H L L H', logicalDataIn[:14])
        # the purpose of this bitwise offset is similar to that used previously with the ethernetFrameHeader. This separate action is necessaryu because the offset_reserved and Flags sub-segments within the TCP header are actually sent as one 16 bit sub-segment. So unlike the other header sub-segment, we will need to have a further separation process of this offset/reserved/flags sub-segment group. So here we are doing the old trick: we know the first of the sub-segments in this group, the offset sub-segment, is 4 bits long. So we bitshift the 16-bit group of data as it is being read into main memory by >>12 bits thus isolating and extracting the first 4 bits that arrived - which we assign to the offsetSubSeg variable. NOTE that this variable now is not only isolated but also contains a bit-equivalent value for the decimal value of the length of the TCP header. So by isolating it, we now have a value for the TCP header's entire length, which we will use at the end of this function to demarcate where the header ends, and the content data TCP payload is to begin (to be isolated and extracted)
    offsetSubSeg = (offset_reserved_nFlags >> 12) * 4
        # the flags relate to notation used for first comms of the TCP headers with recieving server/host and for routers. Thes flags, like the famous SYN-ACK-SYN TCP handshake are all contained in the header.
        # it seems here that he is using bitwise arithmetic (bitwise addition) to create a 'bit mask' that overlays whatever the value of the flags (if they have a value) and then do the bitshift trick on each of them as was just done on the offset in order to isolate and extract.
        # the reason we need the bitmask here is because these flags may have no value or a value in order to signal them but they are incoming as raw bit data in a particular order. So as per the binary order of ^2s for every binary unit, we are masking the relevant bits over the relevant bit unit position (it seems).
        # eg:
        #              bit ^2 unit position (bitmask basis)
        #                32 16 8 4 2 1
        # offst|| rsrvd||flagsSubSeg
        #  0101||001000|| 0  1 0 1 0 1 <------bits incomin
    flag_urgent = (offset_reserved_nFlags & 32) >> 5
    flag_ack = (offset_reserved_nFlags & 16) >> 4
    flag_push = (offset_reserved_nFlags & 8) >> 3
    flag_reset = (offset_reserved_nFlags & 4) >> 2
    flag_sync = (offset_reserved_nFlags & 2) >> 1
    flag_finish = offset_reserved_nFlags & 1
        # note that there are several further TCP header sub-segments like the checksum... but we don't care about them for our purposes, we have already isolated and extract the header lenght(data offset subsegment var) so as to demarcate the conteent payload
    return source_port, destination_port, sequenceNum, acknowledgeNum, flag_finish, flag_sync, flag_reset,flag_push, flag_urgent, flag_ack, logicalDataIn[offsetSubSeg:]
    # note as mentioned previously that the offsetSubSegment allows us to demarcate start of TCP content payload.

    # OPTION 3  UDP type payloads
    # unpack the UDP datagram header and separate from payload. This is relatively easy because UDP datagrams always have an 8 byte header followed by the up to 64kb payload (65535bits). So we use struct.unpack and assigning the bit-relevant notations we first fill the header as being the first 8 bytes of the logicalPayload being shipped in via the layer2-link-data ethernet frame bytestreams. then, whatever comes after byte number 8 is our payload
def unpackUDP(logicalDataIn):
    source_port, destination_port, size = struct.unpack('! H H 2x H', logicalDataIn[:8])
    return source_port, destination_port, size, logicalDataIn[8:]

# format incoming bytestream into regular newlines for readability on the terminal console:
def format_bytestrings(prefix, bytestring, size=80):
        # in the call we have two unset vars, one for the prefix of the
    size = len(prefix)
        # if the bystestrings variable filled in within the context of the main (first order compilation) function at the top of source code is made up of bytes then...
    if isinstance(bytestring, bytes):
            # join the bytes under the give bitwise ntation formatting for every byte encountered in the bystring stream contained in the relevant var that is being passed into this format_bytestrings function
        bytestring = ''.join(r'\x{:02x}'.format(byte) for byte in bytestring)
    if size % 2:
        size = 1
        # put together the prefix with the bystring but with a newline character setting them apart for clarity and also wrap the content var bytsring stream that was formatted above into a wrap() method subjected set of rows of text, with the size variable determining the character width number at which the softwrap forces the text into a new line.
    return '\n'.join([prefix + line for line in textwrap.wrap(bytestring, size)])
# /////////RUNTIME CALL\\\\\\\\\\\\
sniff()




# ++++++++++++++++++++++ANNEX : PROGRAMME IN FULL++++++++++++++++
# IMPORTS
import socket
import struct
import textwrap

                        #////// COMPILATION\\\\\\\
# Tabs for bytestrings/metadata presentation on output of programme to terminal console (readability)
metaHeadTab1 = '\t - '
metaHeadTab2 = '\t\t - '
metaHeadTab3 = '\t\t\t - '
metaHeadTab4 = '\t\t\t\t - '
payloadTab1 = '\t '
payloadTab2 = '\t\t '
payloadTab3 = '\t\t\t '
payloadTab4 = '\t\t\t\t '

# FIRST ORDER MAIN FUNCTION COMPILATION
def sniff():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.nthos(3))
    while True:
        linkDataIn, address = connection.recvfrom(65535)
        destination_MAC, source_MAC, ethernet_protocol, logicalDataIn = unpack_ethernet_frame(linkDataIn)
        print('\nEthernet Frame: ')
        print(metaHeadTab1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_MAC, source_MAC, ethernet_protocol))
        if ethernet_protocol == 8:
            (version, header_length, timeToLive, IPprotocol, IPsource, IPtarget) = unpack_ethernet_frame(logicalDataIn)
            print(metaHeadTab1 + 'IPv4Packet Metadata: ')
            print(metaHeadTab2 + 'Version: {}, Header Length: {}, TimeToLive: {}'.format(version, header_length, timeToLive))
            print(metaHeadTab2 + 'IP Protocol: {}, IP Source: {}, IP Destination: {}'.format(IPprotocol, IPsource, IPtarget))
            if IPprotocol == 1:
                icmp_flag, packagingCode, chkSum, logicalDataIn = unpackICMP(logicalDataIn)
                print(metaHeadTab1 + 'ICMP Package Metadata: ')
                print(metaHeadTab2 + 'Icmp Flag: {}, packaging Code: {}, Check Sum: {}'.format(icmp_flag, packagingCode, chkSum))
                print(metaHeadTab2 + 'ICMP Package Data: ')
                print(format_bytestrings(payloadTab3, logicalDataIn))
            elif IPprotocol == 6:
                source_port, destination_port, sequenceNum, acknowledgeNum, offset_reserved_nFlags, flag_urgent, flag_ack, flag_push, flag_reset, flag_sync, flag_finish, logicalDataIn= unpackTCP(logicalDataIn)
                print(metaHeadTab1 + 'TCP Segment Metadata: ')
                print(metaHeadTab2 + 'Source Port: {}, Destination Port: {}'.format(source_port, destination_port))
                print((metaHeadTab2 + 'Sequence Number: {}, Acknowledge Number: {}').format(sequenceNum,acknowledgeNum))
                print(metaHeadTab2 + 'Flags: ')
                print(metaHeadTab3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urgent, flag_ack, flag_push, flag_reset, flag_sync, flag_finish))
                print(format_bytestrings(payloadTab4, logicalDataIn))
            elif IPprotocol == 17:
                source_port, destination_port, size, logicalDataIn = unpackUDP(logicalDataIn)
                print(metaHeadTab1 + 'UDP Datagram Metadata')
                print(metaHeadTab2 + 'Source Port: {}, Destination Port: {}, Size: {}'.format(source_port, destination_port, size))
                print(format_bytestrings(payloadTab3, logicalDataIn))
            else:
                print(metaHeadTab1 + 'Data: ')
                print(format_bytestrings(payloadTab2, logicalDataIn))

# SECOND ORDER SECNDARY FUNCTS COMPILATION
    #LAYER2 ETHERNET FRAME UNPACK
def unpack_ethernet_frame(linkDataIn):
    destination_MAC, source_MAC, ethernet_protocol = struct.unpack('! 6s 6s H', linkDataIn[:14])
    return format_MAC(destination_MAC), format_MAC(source_MAC), socket.htons(ethernet_protocol), linkDataIn[14:]
    #FORMAT THE MAC ADDRESS
def format_MAC(bytes_format_in):
    bytes_string = map('{:02x}'.format(), bytes_format_in)
    mac_formatted = ':'.join(bytes_string).upper()
    return mac_formatted
    # FORMAT IPv4 ADDRESS
def format_ipv4(ipV4address):
    return '.'.join(map(str, ipV4address))
    #LAYER3 IP PACKET UNPACK
def unpack_ipv4_packet(logicalDataIn):
    version_header_length = logicalDataIn[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    timeToLive, IPprotocol, IPsource, IPtarget = struct.unpack('! 8x B B 2x 4s 4s', logicalDataIn[:20])
    return version, header_length, timeToLive, IPprotocol, IPsource, IPtarget, format_ipv4(IPsource), format_ipv4(IPtarget), logicalDataIn[header_length:]
    # SECOND-DEPTH ENCAPSULATION OPTIONS
        #OPTION 1 : ICMP MESSAGE
def unpackICMP(logicalDataIn):
    icmp_flag, packagingCode, chkSum = struct.unpack('! B B H', logicalDataIn[4:])
        #OPTION 2: TCP SEGMENT
def unpackTCP(logicalDataIn):
    (source_port, destination_port, sequenceNum, acknowledgeNum, offset_reserved_nFlags) = struct.unpack('! H H L L H', logicalDataIn[:14])
    offsetSubSeg = (offset_reserved_nFlags >> 12) * 4
    flag_urgent = (offset_reserved_nFlags & 32) >> 5
    flag_ack = (offset_reserved_nFlags & 16) >> 4
    flag_push = (offset_reserved_nFlags & 8) >> 3
    flag_reset = (offset_reserved_nFlags & 4) >> 2
    flag_sync = (offset_reserved_nFlags & 2) >> 1
    flag_finish = offset_reserved_nFlags & 1
    return source_port, destination_port, sequenceNum, acknowledgeNum, flag_finish, flag_sync, flag_reset,flag_push, flag_urgent, flag_ack, logicalDataIn[offsetSubSeg:]
        #OPTION 3: UDP DATAGRAM
def unpackUDP(logicalDataIn):
    source_port, destination_port, size = struct.unpack('! H H 2x H', logicalDataIn[:8])
    return source_port, destination_port, size, logicalDataIn[8:]
    # FORMAT BYTSTRINGS PAYLOAD CONTENT DATA INTO MANAGEABLE COLUMNS
def format_bytestrings(prefix, bytestring, size=80):
    size = len(prefix)
    if isinstance(bytestring, bytes):
        bytestring = ''.join(r'\x{:02x}'.format(byte) for byte in bytestring)
    if size % 2:
        size = 1
    return '\n'.join([prefix + line for line in textwrap.wrap(bytestring, size)])
                    # ////////// RUNTIME \\\\\\\\
# RUNTIME EXECUTION CALL
sniff()
