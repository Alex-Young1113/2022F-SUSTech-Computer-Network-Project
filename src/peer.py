import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle
import random
import time

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512*1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024

config = None
ex_output_file = None
ex_received_chunk = dict()
ex_downloading_chunkhash = ""
ex_sending_chunkhash = ""

received_chunk_list = dict() # used for sorting chunks in select retransmit

# ex_max_send = 0 # used for DENIED packet, deprecated
redundant_ack = 0 # redundant number of ack, if it == 3, fast retransmit
last_ack = -1 # last Ack in header
connections = dict() # indicate that corresponding chunk is in transfer, in chunkhash: from_addr
pkt_time_stamp = dict() # used for calculating RTT, in chunkhash: start_time

# used for time out
estimated_rtt = 0.95
dev_rtt = 0.05
timeout_interval = 1.0

# used for congestion control, need to modify
cwnd = 0
rwnd = 0
ssthresh = 0

# ------------ notes ------------
# Ack & Seq in the header are better not to change. They are different from what we learnt in course
# Better not to modify the header. If modified, please notify here.
#
#
# -------------------------------

def process_download(sock, chunkfile, outputfile):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global config
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash
    
    global connections

    ex_output_file = outputfile
    connections[ex_output_file] = tuple()
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        index, datahash_str = cf.readline().strip().split(" ")
        ex_received_chunk[datahash_str] = bytes()
        ex_downloading_chunkhash = datahash_str

        # hex_str to bytes
        datahash = bytes.fromhex(datahash_str)
        download_hash = download_hash + datahash

    # Step2: make WHOHAS pkt
    # header:
    # |2byte magic|1byte team |1byte type|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  | 
    whohas_header = struct.pack("!HBBHHII", 52305, 68, 0, HEADER_LEN, HEADER_LEN+len(download_hash), 0, 0)
    whohas_pkt = whohas_header + download_hash

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list: # p[0], p[1], p[2]: nodeid, hostname, port
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))

def process_inbound_udp(sock):
    # Receive pkt    
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("!HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    
    if Type in (1, 3):
        process_receiver(sock, from_addr, Type, data, plen, Seq)
    elif Type in (0, 2, 4):
        process_sender(sock, from_addr, Type, data, plen, Ack)

def process_receiver(sock, from_addr, Type, data, plen, Seq):
    global config
    global ex_received_chunk
    
    global ex_output_file
    
    global connections
    
    global last_ack
    
    global received_chunk_list
    
    if Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]

        # send back GET pkt
        get_header = bytes()
        if connections[ex_output_file] == tuple() or connections[ex_output_file] == from_addr:
            # if it has not built connection, then Ack = 0
            connections[ex_output_file] = from_addr
            get_header = struct.pack("!HBBHHII", 52305, 68, 2, HEADER_LEN, HEADER_LEN+len(get_chunk_hash), 0, 0)
        else:
            # if it has built connection, then Ack = -1
            get_header = struct.pack("!HBBHHII", 52305, 68, 2, HEADER_LEN, HEADER_LEN+len(get_chunk_hash), 0, -1)
        
        get_pkt = get_header + get_chunk_hash
        sock.sendto(get_pkt, from_addr)
    elif Type == 3:
        # received a DATA pkt
        # guarantee that the chunk is sorted
        if Seq >= 2:
            if last_seq in received_chunk_list:
                received_chunk_list[Seq] = data
        ex_received_chunk[ex_downloading_chunkhash] += data

        # send back ACK
        ack_num = Seq
        ack_pkt = struct.pack("!HBBHHII", 52305, 68, 4, HEADER_LEN, HEADER_LEN, 0, ack_num)
        sock.sendto(ack_pkt, from_addr)
        
        # see if finished
        if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)

            # add to this peer's haschunk:
            config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")

            # The following things are just for illustration, you do not need to print out in your design.
            sha1 = hashlib.sha1()
            sha1.update(ex_received_chunk[ex_downloading_chunkhash])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {ex_downloading_chunkhash}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = ex_downloading_chunkhash==received_chunkhash_str
            print(f"Successful received: {success}")
            if success:
                print("Congrats! You have completed the example!")
            else:
                print("Example fails. Please check the example files carefully.")

def process_sender(sock, from_addr, Type, data, plen, Ack):
    global config
    global ex_sending_chunkhash
    
    global ex_output_file
    
    global connections
    global pkt_time_stamp
    
    global last_ack
    global redundant_ack
    
    global estimated_rtt
    global dev_rtt
    global timeout_interval
    
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        whohas_chunk_hash = data[:20]
        # bytes to hex_str
        chunkhash_str = bytes.hex(whohas_chunk_hash)
        ex_sending_chunkhash = chunkhash_str

        # followings are used for DENIED pkt, deprecated
        # -----------------------------------------
        # if ex_max_send >= config.max_conn:
        #     # send back DENIED pkt
        #     denied_pkt = struct.pack("HBBHHII", socket.htons(52305), 68, 5, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN), socket.htonl(0), socket.htonl(0))
        #     sock.sendto(denied_pkt, from_addr)
        # else:
        #     ex_max_send += 1
        #     print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        #     if chunkhash_str in config.haschunks:
        #         # send back IHAVE pkt
        #         ihave_header = struct.pack("HBBHHII", socket.htons(52305), 68, 1, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN+len(whohas_chunk_hash)), socket.htonl(0), socket.htonl(0))
        #         ihave_pkt = ihave_header + whohas_chunk_hash
        #         sock.sendto(ihave_pkt, from_addr)
        # -----------------------------------------
        
        print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        if chunkhash_str in config.haschunks:
            # send back IHAVE pkt            
            ihave_header = struct.pack("!HBBHHII", 52305, 68, 1, HEADER_LEN, HEADER_LEN+len(whohas_chunk_hash), 0, 0)
            ihave_pkt = ihave_header + whohas_chunk_hash
            sock.sendto(ihave_pkt, from_addr)
    elif Type == 2:
        # received a GET pkt
        chunk_data = config.haschunks[ex_sending_chunkhash][:MAX_PAYLOAD]

        # send back DATA 
        # only valid when Ack == 0
        if Ack == 0:
            # start timer in sender
            pkt_time_stamp[ex_output_file] = time.time()
            # with Seq = 1 in header
            data_header = struct.pack("!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), 1, 0)
            data_pkt = data_header+chunk_data
            sock.sendto(data_pkt, from_addr)
    elif Type == 4:
        # received an ACK pkt
        ack_num = Ack
        if last_ack == ack_num:
            redundant_ack += 1
            if redundant_ack == 3:
                redundant_ack = 0
                left = (ack_num) * MAX_PAYLOAD
                right = min((ack_num+1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
                data_header = struct.pack("!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), ack_num+1, 0)
                data_pkt = data_header+chunk_data
                sock.sendto(data_pkt, from_addr)
        else:
            last_ack = ack_num
            # calculate RTT and time_interval
            start_time = pkt_time_stamp.get(ex_sending_chunkhash, -1)
            if start_time != -1:
                end_time = time.time()
                sample_rtt = end_time - start_time
                
                estimated_rtt = 0.875 * estimated_rtt + 0.125 * sample_rtt
                dev_rtt = 0.75 * dev_rtt + 0.25 * abs(estimated_rtt - sample_rtt)
                timeout_interval = estimated_rtt + 4 * dev_rtt
            
            if (ack_num)*MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                print(f"finished sending {ex_sending_chunkhash}")
                pass
            else:
                # continue sending DATA 
                left = (ack_num) * MAX_PAYLOAD
                right = min((ack_num+1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data = config.haschunks[ex_sending_chunkhash][left: right]
                # start timer
                pkt_time_stamp[ex_sending_chunkhash] = time.time()
                # send next data
                data_header = struct.pack("!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(next_data), ack_num+1, 0)
                data_pkt = data_header+next_data
                sock.sendto(data_pkt, from_addr)

def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock ,chunkf, outf)
    else:
        pass

def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin],[],[], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
