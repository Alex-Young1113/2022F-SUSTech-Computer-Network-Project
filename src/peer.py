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
import time
import math

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512*1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024

config: bt_utils.BtConfig = None
# ------
# to handle concurrency, all of below must be dict (or dict of dict). Keys are all Tuple(sender_addr, receiver_addr)
# ------

ex_output_file_dict = dict()
ex_received_chunk_dict = dict()
ex_downloading_chunkhash_dict = dict() # Tuple(sender_addr, receiver_addr): str
ex_sending_chunkhash_dict = dict() # Tuple(sender_addr, receiver_addr): chunkhash_str: str

# ------
# !! ONLY modified in receiver when receives IHAVE pkt. ONLY viewed in receiver when receives DATA pkt to see if there is next get_chunkhash.
# the chunkhash list get from ihave pkt. 
#   B: 1，2，3; C: 4，5
#   A->B,C: WHOHAS 1,2,4?
#   B->A: IHAVE 1,2
#   C->A: IHAVE 4
# at this time, in A, get_chunkhash_list_dict[(B, A)] = [1, 2]; get_chunkhash_list_dict[(C, A)] = [4]
#   A->B: GET 1
#   A->C: GET 4
#   concurrently download 1,
# at this time, in A, get_chunkhash_list_dict[(B, A)] = [2]; get_chunkhash_list_dict[(C, A)] = []
#   A->B: GET 2
#   download 2 from B
# ------
get_chunkhash_list_dict = dict() # Tuple(sender_addr, receiver_addr): list(chunkhash: bytes)

received_chunk_list_dict = dict() # used for sorting chunks in select retransmit

pkt_time_stamp_dict = dict() # used for calculating RTT, in chunkhash: start_time

redundant_ack_dict = dict() # redundant number of ack, if it == 3, fast retransmit
connections = dict() # indicate that corresponding chunk is in transfer, in chunkhash: Tuple(sender_addr, receiver_addr)

# only used in sender
smallest_ack_dict = dict() # the smallest Ack in header
biggest_ack_dict = dict() # the biggest Ack received in header. Not always equal to smallest_ack
# only used in receiver
smallest_seq_dict = dict() # the smallest Seq in header
biggest_seq_dict = dict() # the biggest Seq received in header. Not always equal to smallest_seq
if_seq_in_order_dict = dict() # the flag for ordering Seq

# used for time out
estimated_rtt_dict = dict()
dev_rtt_dict = dict()
timeout_interval_dict = dict()

# used for congestion control, need to modify
cwnd = dict()
ssthresh = dict() 
status = dict()

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
    global ex_output_file_dict
    global ex_received_chunk_dict
    global estimated_rtt_dict
    global dev_rtt_dict
    global timeout_interval_dict

    ex_output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    ex_received_chunk = dict()
    ex_downloading_chunkhash = list()
    with open(chunkfile, 'r') as cf:
        while line := cf.readline():
            index, datahash_str = line.strip().split(" ")
            ex_received_chunk[datahash_str] = bytes()
            ex_downloading_chunkhash.append(datahash_str) 

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
    receiver_addr = (config.ip, config.port)
    for p in peer_list: # p[0], p[1], p[2]: nodeid, hostname, port
        if int(p[0]) != config.identity:
            sender_addr = (p[1], int(p[2]))
            key = (sender_addr, receiver_addr)
            ex_output_file_dict[key] = ex_output_file
            ex_received_chunk_dict[key] = ex_received_chunk
            estimated_rtt_dict[key], dev_rtt_dict[key], timeout_interval_dict[key] = 0.95, 0.05, 1.0
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

def process_receiver(sock: simsocket.SimSocket, from_addr, Type, data, plen, Seq):
    global ex_output_file_dict
    global ex_received_chunk_dict
    global ex_downloading_chunkhash_dict
    
    global get_chunkhash_list_dict
    
    global connections
    
    global smallest_seq_dict
    global biggest_seq_dict
    global if_seq_in_order_dict
    
    global received_chunk_list_dict
    
    receiver_addr = (config.ip, config.port)
    key = (from_addr, receiver_addr)
    
    if Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        blen = plen - HEADER_LEN # the body length
        num_of_chunkhash = blen // 20 # number of chunk hashes
        get_chunkhash_list = list()
        for i in range(num_of_chunkhash):
            chunkhash = data[i*20 : i*20+20]
            get_chunkhash_list.append(chunkhash)
        
        get_chunkhash = get_chunkhash_list.pop(0)
        get_chunkhash_list_dict[key] = get_chunkhash_list
        # send back GET pkt
        if get_chunkhash not in connections or connections[get_chunkhash] == key:
            # if it has not built connection, then send back GET pkt
            connections[get_chunkhash] = key
            ex_downloading_chunkhash_dict[key] = bytes.hex(get_chunkhash)
            smallest_seq_dict[key], biggest_seq_dict[key] = 0, 0
            if_seq_in_order_dict[key] = True
            get_header = struct.pack("!HBBHHII", 52305, 68, 2, HEADER_LEN, HEADER_LEN+len(get_chunkhash), 0, 0)
            get_pkt = get_header + get_chunkhash
            sock.sendto(get_pkt, from_addr)
        else:
            # if it has built connection, then send back DENIED pkt
            # ex_output_file_dict.pop(key)
            # ex_received_chunk_dict.pop(key)
            # ex_downloading_chunkhash_dict.pop(key)
            denied_pkt = struct.pack("!HBBHHII", 52305, 68, 5, HEADER_LEN, HEADER_LEN, 0, 0)
            sock.sendto(denied_pkt, from_addr)
    elif Type == 3:
        # received a DATA pkt
        # guarantee that the chunk is sorted      
        ex_downloading_chunkhash = ex_downloading_chunkhash_dict[key]  
        smallest_seq, biggest_seq = smallest_seq_dict[key], biggest_seq_dict[key]
        if_seq_in_order = if_seq_in_order_dict[key]
        received_chunk_list = received_chunk_list_dict.get(key, dict())
        
        if smallest_seq == biggest_seq and Seq == smallest_seq+1: # in order
            ex_received_chunk_dict[key][ex_downloading_chunkhash] += data
        else: # disorder
            received_chunk_list[Seq] = data

        # send back ACK
        biggest_seq = max(Seq, biggest_seq)
        ack_num = biggest_seq
        # ------ note ------
        # the first 2 branches are used to handle discontinuous pkts
        #   - if there is a discontinuous pkt arrival, then step into the 1st branch, 
        #       which will send a pkt with Ack = the smallest Seq we have received to ask for retransmit.
        #   - once the retransmission complete (may be many retransmissions), it will step into the 2nd branch,
        #       which will add the data in order to ex_received_chunk[ex_downloading_chunkhash].
        #   !! the order of the 2 branches is immutable. 
        #       If changed, then it could not handle the situation that received: 1,3,5 and ask for: 2,4.
        # the last branch is used for normal situation.
        # ------------------
        if if_seq_in_order and Seq != smallest_seq+1: # not continuous pkt received at first time
            ack_num = smallest_seq
            if_seq_in_order = False
        elif not if_seq_in_order: # handle completing
            flag = True # flag for changing if_seq_in_order
            for idx in range(smallest_seq+1, biggest_seq+1):
                if received_chunk_list.get(idx) is None:
                    ack_num = idx-1
                    smallest_seq = Seq
                    flag = False
                    break
            if flag: # all in order
                # add into ex_received_chunk
                for idx in range(smallest_seq+1, biggest_seq+1):
                    ex_received_chunk_dict[key][ex_downloading_chunkhash] += received_chunk_list[idx]
                # reset
                if_seq_in_order = True
                ack_num = biggest_seq
                smallest_seq = biggest_seq
        else: # normal
            ack_num = biggest_seq
            smallest_seq = Seq # can also be biggest_seq
            
        smallest_seq_dict[key], biggest_seq_dict[key] = smallest_seq, biggest_seq
        if_seq_in_order_dict[key] = if_seq_in_order
        received_chunk_list_dict[key] = received_chunk_list
        
        ack_pkt = struct.pack("!HBBHHII", 52305, 68, 4, HEADER_LEN, HEADER_LEN, 0, ack_num)
        sock.sendto(ack_pkt, from_addr)
        
        # see if finished
        ex_received_chunk = ex_received_chunk_dict[key]
        ex_output_file = ex_output_file_dict[key]
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
                
            # See if there exists next get_chunkhash
            if len(get_chunkhash_list_dict[key]) > 0:
                # if there is, then send back GET
                get_chunkhash = get_chunkhash_list.pop(0)
                connections[get_chunkhash] = key
                smallest_seq_dict[key], biggest_seq_dict[key] = 0, 0
                if_seq_in_order_dict[key] = True
                get_header = struct.pack("!HBBHHII", 52305, 68, 2, HEADER_LEN, HEADER_LEN+len(get_chunkhash), 0, 0)
                get_pkt = get_header + get_chunkhash
                sock.sendto(get_pkt, from_addr)

def process_sender(sock: simsocket.SimSocket, from_addr, Type, data, plen, Ack):
    global config
    global ex_sending_chunkhash_dict
    
    global pkt_time_stamp_dict
    global connections
    
    global smallest_ack_dict
    global biggest_ack_dict
    global redundant_ack_dict
    
    global estimated_rtt_dict
    global dev_rtt_dict
    global timeout_interval_dict
    
    global cwnd
    global ssthresh
    global status
    
    sender_addr = (config.ip, config.port)
    key = (sender_addr, from_addr)
    
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        ihave_chunkhash_list = list() # list of bytes
        chunkhash_str_list = list() # list of str
        blen = plen - HEADER_LEN # the body length
        num_of_chunkhash = blen // 20 # number of chunk hashes
        for i in range(num_of_chunkhash):
            chunkhash = data[i*20 : i*20+20]
            # bytes to hex_str
            chunkhash_str = bytes.hex(chunkhash)
            if chunkhash_str in config.haschunks:
                ihave_chunkhash_list.append(chunkhash)
                chunkhash_str_list.append(chunkhash_str)
        
        # print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        if len(ihave_chunkhash_list) > 0:
            # send back IHAVE pkt
            ihave_chunkhash = b''.join(ihave_chunkhash_list)
            ihave_header = struct.pack("!HBBHHII", 52305, 68, 1, HEADER_LEN, HEADER_LEN+len(ihave_chunkhash), 0, 0)
            ihave_pkt = ihave_header + ihave_chunkhash
            sock.sendto(ihave_pkt, from_addr)
    elif Type == 2:
        # received a GET pkt
        get_chunkhash = data[:20]
        # add into connections
        connections[get_chunkhash] = key
        ex_sending_chunkhash_dict[key] = bytes.hex(get_chunkhash)
        # send back DATA 
        # send 5 pkt at one time
        cwnd[key], ssthresh[key], status[key] = 1, 64, 1
        flag = False # if the file is smaller than 5 chunk, break
        smallest_ack_dict[key], redundant_ack_dict[key] = 0, 0 
        estimated_rtt_dict[key], dev_rtt_dict[key], timeout_interval_dict[key] = 0.95, 0.05, 1.0
        ex_sending_chunkhash = ex_sending_chunkhash_dict[key]
        for seq_num in range(1, math.floor(cwnd[key] + 1)): # seq_num = [1, 2, 3, 4, 5]
            biggest_ack_dict[key] = seq_num
            left = (seq_num-1) * MAX_PAYLOAD
            right = min((seq_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
            flag = (seq_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE
            chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
            # start timer in sender
            pkt_time_stamp_dict[key] = dict()
            pkt_time_stamp_dict[key][(ex_sending_chunkhash, seq_num)] = time.time()
            # with Seq = 1 in header
            data_header = struct.pack("!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), seq_num, 0)
            data_pkt = data_header+chunk_data
            sock.sendto(data_pkt, from_addr)
            if flag:
                break
    elif Type == 4:
        # received an ACK pkt
        # adjust congestion window
        if(status[key] == 1): # slow start
            cwnd[key] += 1
            if cwnd[key] >= ssthresh[key]:
                status[key] = 2
        elif(status[key] == 2): # congestion avoidance
            cwnd[key] += (1 / cwnd[key])
            pass
        
        ack_num = Ack
        # must process all retransmit then normally send DATA
        smallest_ack, biggest_ack, redundant_ack = smallest_ack_dict[key], biggest_ack_dict[key], redundant_ack_dict[key]
        ex_sending_chunkhash = ex_sending_chunkhash_dict[key]
        if smallest_ack == ack_num:
            redundant_ack += 1
            # fast retransmit
            if redundant_ack == 3:
                ssthresh[key] = max(math.floor(cwnd[key] / 2), 2)
                cwnd[key] = 1
                if status[key] == 2:
                    status[key] = 1
                # no need to calculate RTT and time_interval for retransmit pkt
                redundant_ack = 0 # clear redundant_ack
                left = (ack_num) * MAX_PAYLOAD
                right = min((ack_num+1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
                data_header = struct.pack("!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), ack_num+1, 0)
                data_pkt = data_header+chunk_data
                sock.sendto(data_pkt, from_addr)
        else:
            smallest_ack = ack_num
            redundant_ack = 0 # clear redundant_ack
            # calculate RTT and time_interval
            start_time = pkt_time_stamp_dict[key].get((ex_sending_chunkhash, ack_num), -1)
            estimated_rtt, dev_rtt, timeout_interval = estimated_rtt_dict[key], dev_rtt_dict[key], timeout_interval_dict[key]
            if start_time != -1:
                pkt_time_stamp_dict[key].pop((ex_sending_chunkhash, ack_num))
                end_time = time.time()
                sample_rtt = end_time - start_time
                
                estimated_rtt = 0.875 * estimated_rtt + 0.125 * sample_rtt
                dev_rtt = 0.75 * dev_rtt + 0.25 * abs(estimated_rtt - sample_rtt)
                timeout_interval = estimated_rtt + 4 * dev_rtt
                
                estimated_rtt_dict[key], dev_rtt_dict[key], timeout_interval_dict[key] = estimated_rtt, dev_rtt, timeout_interval
            
            if (ack_num)*MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                status[key] = 0
                # finished
                print(f"finished sending {ex_sending_chunkhash}")
                pass
            else:
                # continue sending DATA 
                flag = False # if the file is smaller than 5 chunk, break
                for seq_num in range(ack_num+1, ack_num+math.floor(cwnd[key])+1): # seq_num = [+1, +2, +3, +4, +5]
                    biggest_ack = seq_num
                    left = (seq_num-1) * MAX_PAYLOAD
                    right = min((seq_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    flag = (seq_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE
                    chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
                    # start timer in sender
                    pkt_time_stamp_dict[key] = dict()
                    pkt_time_stamp_dict[key][(ex_sending_chunkhash, seq_num)] = time.time()
                    # send next data
                    data_header = struct.pack("!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), seq_num, 0)
                    data_pkt = data_header+chunk_data
                    sock.sendto(data_pkt, from_addr)
                    if flag:
                        break
        smallest_ack_dict[key], biggest_ack_dict[key], redundant_ack_dict[key] = smallest_ack, biggest_ack, redundant_ack

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
