# bibibibi
import time
import math
import pickle
import argparse
import hashlib
import util.bt_utils as bt_utils
import socket
import struct
import util.simsocket as simsocket
import select
import sys
import os
import traceback
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024

config: bt_utils.BtConfig = None
# ------
# to handle concurrency, all of below must be dict (or dict of dict). Keys are all Tuple(sender_addr, receiver_addr)
# ------

ex_output_file_dict = dict()  # Tuple(sender_addr, receiver_addr): str
# Tuple(sender_addr, receiver_addr): Dict(str, bytes)
ex_received_chunk_dict = dict()
# Tuple(sender_addr, receiver_addr): str
ex_downloading_chunkhash_dict = dict()
# Tuple(sender_addr, receiver_addr): chunkhash_str: str
ex_sending_chunkhash_dict = dict()

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
# Tuple(sender_addr, receiver_addr): list(chunkhash: bytes)
get_chunkhash_list_dict = dict()
# indicate that corresponding chunk is in transfer, in chunkhash: Tuple(sender_addr, receiver_addr)
connections = dict()
# different from pkt_time_stamp_dict, it is ued for crash
last_recv_time_dict = dict()

# only used in sender
smallest_ack_dict = dict()  # the smallest Ack in header
# the biggest Ack received in header. Not always equal to smallest_ack
biggest_ack_dict = dict()
# record of having sent pkts, i.e., pkts of waiting for ACK. dict of set
pipe_list_dict = dict()
# used for calculating RTT, in Tuple(sender_addr, receiver_addr):{(chunkhash, seq_num): start_time}
pkt_time_stamp_dict = dict()
redundant_ack_dict = dict()  # redundant number of ack, if it == 3, fast retransmit

# only used in receiver
smallest_seq_dict = dict()  # the smallest Seq in header
# the biggest Seq received in header. Not always equal to smallest_seq
biggest_seq_dict = dict()
if_seq_in_order_dict = dict()  # the flag for ordering Seq
received_chunk_list_dict = dict()  # used for sorting chunks in select retransmit
# the received chunks of one file, in output_file:{chunkhash: bytes}
finished_chunk_list_dict = dict()

# used for time out
estimated_rtt_dict = dict()
dev_rtt_dict = dict()
timeout_interval_dict = dict()

# used for congestion control
cwnd = dict()
ssthresh = dict()
status = dict()  # show what status it is now. 1 for slow start, 2 for congestion avoidance, 3 for fast recovery

# store the start time for connection
download_start_time = dict()

already_acked = dict()
# ------------ notes ------------
# Ack & Seq in the header are better not to change. They are different from what we learnt in course
# Better not to modify the header. If modified, please notify here.
#
# header:
# |2byte magic|1byte team |1byte type|
# |2byte  header len  |2byte pkt len |
# |      4byte  seq                  |
# |      4byte  ack                  |
#
# -------------------------------

chunkfile: str
outputfile: str


def process_download(sock: simsocket.SimSocket, chunkfile: str, outputfile: str):
    '''
    if DOWNLOAD is used, the peer will keep getting files until it is done
    '''
    global config
    global ex_output_file_dict
    global ex_received_chunk_dict
    global ex_downloading_chunkhash_dict
    global finished_chunk_list_dict

    global estimated_rtt_dict
    global dev_rtt_dict
    global timeout_interval_dict

    ex_output_file = outputfile
    finished_chunk_list_dict[ex_output_file] = dict()
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    ex_received_chunk = dict()
    with open(chunkfile, 'r') as cf:
        lines = cf.readlines()
        for line in lines:
            index, datahash_str = line.strip().split(" ")
            ex_received_chunk[datahash_str] = bytes()

            # hex_str to bytes
            datahash = bytes.fromhex(datahash_str)
            download_hash = download_hash + datahash

    # Step2: make WHOHAS pkt
    # header:
    # |2byte magic|1byte team |1byte type|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    whohas_header = struct.pack(
        "!HBBHHII", 52305, 68, 0, HEADER_LEN, HEADER_LEN+len(download_hash), 0, 0)
    whohas_pkt = whohas_header + download_hash

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    receiver_addr = (config.ip, config.port)
    for p in peer_list:  # p[0], p[1], p[2]: nodeid, hostname, port
        if int(p[0]) != config.identity:
            sender_addr = (p[1], int(p[2]))
            key = (sender_addr, receiver_addr)
            if key not in ex_downloading_chunkhash_dict:
                # if there is no connection built previously, send whohas
                # ------
                # initialization
                ex_output_file_dict[key] = ex_output_file
                ex_received_chunk_dict[key] = ex_received_chunk
                if key not in timeout_interval_dict:
                    # no need to re-calculate the time out interval
                    estimated_rtt_dict[key], dev_rtt_dict[key], timeout_interval_dict[key] = 0.95, 0.05, 1.0
                # ------
                sock.sendto(whohas_pkt, (p[1], int(p[2])))


def reSendWhohas():
    pass


def process_inbound_udp(sock: simsocket.SimSocket):
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack(
        "!HBBHHII", pkt[:HEADER_LEN])
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

    global last_recv_time_dict
    global connections

    global smallest_seq_dict
    global biggest_seq_dict
    global if_seq_in_order_dict

    global received_chunk_list_dict
    global finished_chunk_list_dict

    receiver_addr = (config.ip, config.port)
    key = (from_addr, receiver_addr)

    if Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        blen = plen - HEADER_LEN  # the body length
        num_of_chunkhash = blen // 20  # number of chunk hashes
        get_chunkhash_list = list()  # list of bytes
        for i in range(num_of_chunkhash):
            chunkhash = data[i*20: i*20+20]
            get_chunkhash_list.append(chunkhash)
        if len(get_chunkhash_list) == 0:
            # a branch that never stepped in
            return

        get_chunkhash: bytes = get_chunkhash_list.pop(0)
        if get_chunkhash is None:
            return
        chunkhash_str = bytes.hex(get_chunkhash)
        # for continuing sending next chunk
        get_chunkhash_list_dict[key] = get_chunkhash_list
        # send back GET pkt
        if chunkhash_str not in connections and key not in ex_downloading_chunkhash_dict:
            # if it has not built connection on this chunk and the channel is empty, then send back GET pkt
            # ------
            # initialization
            connections[chunkhash_str] = key  # build connection
            # denote the chunk in downloading
            ex_downloading_chunkhash_dict[key] = chunkhash_str
            smallest_seq_dict[key], biggest_seq_dict[key] = 0, 0
            if_seq_in_order_dict[key] = True
            
            # ------
            get_header = struct.pack(
                "!HBBHHII", 52305, 68, 2, HEADER_LEN, HEADER_LEN+len(get_chunkhash), 0, 0)
            get_pkt = get_header + get_chunkhash
            sock.sendto(get_pkt, from_addr)
        else:
            # if it has built connection, then send back DENIED pkt
            # ------
            # remove records
            ex_output_file_dict.pop(key, None)
            ex_received_chunk_dict.pop(key, None)
            # ------
            denied_pkt = struct.pack(
                "!HBBHHII", 52305, 68, 5, HEADER_LEN, HEADER_LEN, 0, 0)
            sock.sendto(denied_pkt, from_addr)
    elif Type == 3:
        # received a DATA pkt
        # guarantee that the chunk is sorted
        if key not in ex_downloading_chunkhash_dict:
            return
        last_recv_time_dict[key] = time.time()

        ex_downloading_chunkhash: str = ex_downloading_chunkhash_dict[key]
        smallest_seq, biggest_seq = smallest_seq_dict[key], biggest_seq_dict[key]
        if_seq_in_order: bool = if_seq_in_order_dict[key]
        # if it has not been used, then there will not be a k-v pair. So return an empty dict
        received_chunk_list = received_chunk_list_dict.get(key, dict())

        if smallest_seq == biggest_seq and Seq == smallest_seq+1:  # in order
            ex_received_chunk_dict[key][ex_downloading_chunkhash] += data
        else:  # disorder
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
        lost_pkt_seq = list()
        if if_seq_in_order and Seq != smallest_seq + 1:  # not continuous pkt received at first time
            ack_num = smallest_seq
            if_seq_in_order = False
        elif not if_seq_in_order:  # handle completing
            flag = True  # flag for changing if_seq_in_order
            first = True
            for idx in range(smallest_seq + 1, biggest_seq + 1):
                if received_chunk_list.get(idx) is None:
                    if first:
                        ack_num = idx - 1
                        first = False
                    else:
                        lost_pkt_seq.append(idx-1)
                    flag = False
            if flag:  # all in order
                # add into ex_received_chunk
                for idx in range(smallest_seq+1, biggest_seq+1):
                    ex_received_chunk_dict[key][ex_downloading_chunkhash] += received_chunk_list[idx]
                    received_chunk_list.pop(idx, None)
                # reset
                if_seq_in_order = True
                ack_num = biggest_seq
                smallest_seq = biggest_seq
        else:  # normal
            ack_num = biggest_seq
            smallest_seq = biggest_seq

        # write back to the dict value
        smallest_seq_dict[key], biggest_seq_dict[key] = smallest_seq, biggest_seq
        if_seq_in_order_dict[key] = if_seq_in_order
        received_chunk_list_dict[key] = received_chunk_list

        # SACK machanism
        top_len = min(MAX_PAYLOAD // 4, len(lost_pkt_seq))
        fmt_str = "!" + "I" * top_len
        ack_body = struct.pack(fmt_str, *lost_pkt_seq[:top_len])
        ack_header = struct.pack(
            "!HBBHHII", 52305, 68, 4, HEADER_LEN, HEADER_LEN+len(ack_body), 0, ack_num)
        ack_pkt = ack_header + ack_body
        sock.sendto(ack_pkt, from_addr)
        # ------
        # initialization
        last_recv_time_dict[key] = time.time()
        pkt_time_stamp_dict[key] = time.time()
        # ------

        ex_received_chunk = ex_received_chunk_dict[key]
        ex_output_file = ex_output_file_dict[key]
        # if finished downloading this chunk
        if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
            # add to this peer's haschunk:
            finished_chunk_list_dict[ex_output_file][ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]
            config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]
            # The following things are just for illustration, you do not need to print out in your design.
            sha1 = hashlib.sha1()
            sha1.update(ex_received_chunk[ex_downloading_chunkhash])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {ex_downloading_chunkhash}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = ex_downloading_chunkhash == received_chunkhash_str
            print(f"Successful received: {success}")
            if success:
                print("Congrats! You have completed downloading the chunk!")
            else:
                print("Download fails. Please check the example files carefully.")

            # See if there exists next get_chunkhash
            if len(get_chunkhash_list_dict[key]) > 0:
                # if there is, then send back GET, continuing the connection
                get_chunkhash = get_chunkhash_list_dict[key].pop(0)
                chunkhash_str = bytes.hex(get_chunkhash)
                # ------
                # initialization
                connections[chunkhash_str] = key
                ex_downloading_chunkhash_dict[key] = chunkhash_str
                smallest_seq_dict[key], biggest_seq_dict[key] = 0, 0
                if_seq_in_order_dict[key] = True
                # ------
                get_header = struct.pack(
                    "!HBBHHII", 52305, 68, 2, HEADER_LEN, HEADER_LEN+len(get_chunkhash), 0, 0)
                get_pkt = get_header + get_chunkhash
                sock.sendto(get_pkt, from_addr)
            else:  # disconnect
                connections.pop(ex_downloading_chunkhash, None)
                ex_downloading_chunkhash_dict.pop(key, None)
                pkt_time_stamp_dict.pop(key, None)
                last_recv_time_dict.pop(key, None)

        # if finished downloading all chunkdata
        is_all_finished = False
        for idx in finished_chunk_list_dict[ex_output_file]:
            if len(finished_chunk_list_dict[ex_output_file][idx]) == CHUNK_DATA_SIZE:
                is_all_finished = True
        if is_all_finished:
            # finished downloading all chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(finished_chunk_list_dict[ex_output_file], wf)

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")


def process_sender(sock: simsocket.SimSocket, from_addr, Type, data, plen, Ack):
    global config
    global ex_sending_chunkhash_dict

    global pkt_time_stamp_dict
    global last_recv_time_dict
    global connections

    global smallest_ack_dict
    global biggest_ack_dict
    global redundant_ack_dict

    global pipe_list_dict

    global estimated_rtt_dict
    global dev_rtt_dict
    global timeout_interval_dict

    global cwnd
    global ssthresh
    global status

    global download_start_time
    sender_addr = (config.ip, config.port)
    key = (sender_addr, from_addr)

    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        # there may be many chunks that receiver needs and sender has
        ihave_chunkhash_list = list()  # list of bytes
        whohas_chunk_list = list()  # list of str
        blen: int = plen - HEADER_LEN  # the body length
        num_of_chunkhash = blen // 20  # number of chunk hashes
        for i in range(num_of_chunkhash):
            chunkhash: bytes = data[i*20: i*20+20]
            # bytes to hex_str
            chunkhash_str = bytes.hex(chunkhash)
            whohas_chunk_list.append(chunkhash_str)
            if chunkhash_str in config.haschunks:
                ihave_chunkhash_list.append(chunkhash)

        print(
            f"whohas: {whohas_chunk_list}, has: {list(config.haschunks.keys())}")
        if len(ihave_chunkhash_list) > 0:
            # send back IHAVE pkt
            ihave_chunkhash = b''.join(ihave_chunkhash_list)
            ihave_header = struct.pack(
                "!HBBHHII", 52305, 68, 1, HEADER_LEN, HEADER_LEN+len(ihave_chunkhash), 0, 0)
            ihave_pkt = ihave_header + ihave_chunkhash
            sock.sendto(ihave_pkt, from_addr)
    elif Type == 2:
        # received a GET pkt
        # check if reached max connection
        if len(ex_sending_chunkhash_dict) < config.max_conn:
            get_chunkhash: bytes = data[:20]
            ex_sending_chunkhash: str = bytes.hex(get_chunkhash)
            # add into connections
            connections[ex_sending_chunkhash] = key
            ex_sending_chunkhash_dict[key] = ex_sending_chunkhash
            # send back DATA
            # ------
            # initialization
            if key not in cwnd:  # if it did not connect before, initialize; else, keep the old one.
                cwnd[key], ssthresh[key], status[key] = 1, 64, 1
                estimated_rtt_dict[key], dev_rtt_dict[key], timeout_interval_dict[key] = 0.95, 0.05, 1.0
            # ------

            # ------
            # initialization
            smallest_ack_dict[key], redundant_ack_dict[key] = 0, 0
            pkt_time_stamp_dict[key] = dict()
            pipe_list_dict[key] = set()
            download_start_time[key] = time.time()
            sock.add_log('cwnd ' + str(time.time() -
                         download_start_time[key]) + ' ' + str(cwnd[key]))
            already_acked[key] = []
            # ------
            upper_bound = math.floor(cwnd[key]+1)
            # seq_num = [1, ..., math.floor(cwnd[key]+1)]
            for seq_num in range(1, upper_bound):
                biggest_ack_dict[key] = seq_num
                left = (seq_num-1) * MAX_PAYLOAD
                right = min((seq_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
                # start timer in sender
                pkt_time_stamp_dict[key][(
                    ex_sending_chunkhash, seq_num)] = time.time()
                # with Seq = 1 in header
                data_header = struct.pack(
                    "!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), seq_num, 0)
                data_pkt = data_header + chunk_data
                sock.sendto(data_pkt, from_addr)
                pipe_list_dict[key].add(seq_num)
                if (seq_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:  # already complete sending
                    # if the chunk is smaller than #math.floor(cwnd[key]+1) pkts, break
                    break
        else:
            denied_pkt = struct.pack(
                "!HBBHHII", 52305, 68, 5, HEADER_LEN, HEADER_LEN, 0, 0)
            sock.sendto(denied_pkt, from_addr)
    elif Type == 4:
        # received an ACK pkt
        if key not in ex_sending_chunkhash_dict:
            return
        already_acked[key].append(Ack)
        last_recv_time_dict[key] = time.time()
        smallest_ack, biggest_ack, redundant_ack = smallest_ack_dict[
            key], biggest_ack_dict[key], redundant_ack_dict[key]
        timeout_interval = timeout_interval_dict[key] if config.timeout == 0 else config.timeout

        if Ack in pipe_list_dict[key]:
            # remove the pkt of waiting for Ack from pipe_list
            pipe_list_dict[key].remove(Ack)

        # must process all retransmit then normally send DATA
        ex_sending_chunkhash: str = ex_sending_chunkhash_dict[key]
        if smallest_ack == Ack:  # reduplicate Ack
            redundant_ack += 1
            pkt_time_stamp_dict.pop((ex_sending_chunkhash, Ack), None)

            if status[key] == 3:
                cwnd[key] += 1
                sock.add_log('cwnd ' + str(time.time() -
                             download_start_time[key]) + ' ' + str(cwnd[key]))
            # fast retransmit
            if redundant_ack == 3:
                # with 3 redundant Ack, get into fast recovery
                if status[key] == 1 or status[key] == 2:
                    ssthresh[key] = max(math.floor(cwnd[key] / 2), 2.0)
                    cwnd[key] = ssthresh[key] + 3
                    sock.add_log('cwnd ' + str(time.time() -
                                 download_start_time[key]) + ' ' + str(cwnd[key]))
                    status[key] = 3

                # no need to calculate RTT and time_interval for retransmit pkt
                redundant_ack = 0  # clear redundant_ack

                left = (Ack) * MAX_PAYLOAD
                right = min((Ack + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
                data_header = struct.pack(
                    "!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), Ack+1, 0)
                data_pkt = data_header + chunk_data
                sock.sendto(data_pkt, from_addr)

                # if there are more pkt to retransmit
                if plen > HEADER_LEN:
                    blen = plen - HEADER_LEN
                    num_of_seq_num = blen // 4
                    fmt_str = "!" + "I" * num_of_seq_num
                    data_unpack = struct.unpack(fmt_str, data)
                    for i in range(num_of_seq_num):
                        seq_num = data_unpack[i]
                        left = (seq_num) * MAX_PAYLOAD
                        right = min((seq_num + 1) * MAX_PAYLOAD,
                                    CHUNK_DATA_SIZE)
                        chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
                        data_header = struct.pack(
                            "!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), seq_num+1, 0)
                        data_pkt = data_header + chunk_data
                        sock.sendto(data_pkt, from_addr)
        else:
            smallest_ack = Ack
            redundant_ack = 0  # clear redundant_ack

            # adjust congestion window
            if status[key] == 1:  # slow start
                cwnd[key] += 1.0
                sock.add_log('cwnd ' + str(time.time() -
                             download_start_time[key]) + ' ' + str(cwnd[key]))
                if cwnd[key] >= ssthresh[key]:
                    status[key] = 2
            elif status[key] == 2:  # congestion avoidance
                cwnd[key] += (1 / cwnd[key])
            elif status[key] == 3:  # fast recovery
                cwnd[key] = ssthresh[key]
                sock.add_log('cwnd ' + str(time.time() -
                             download_start_time[key]) + ' ' + str(cwnd[key]))
                status[key] = 2

            # calculate RTT and time_interval
            start_time = pkt_time_stamp_dict[key].get(
                (ex_sending_chunkhash, Ack), -1)
            estimated_rtt, dev_rtt = estimated_rtt_dict[key], dev_rtt_dict[key]
            # no need to caculate time interval when config.timeout is set
            if config.timeout == 0 and start_time != -1:
                pkt_time_stamp_dict[key].pop((ex_sending_chunkhash, Ack), None)
                end_time = time.time()
                sample_rtt = end_time - start_time

                estimated_rtt = 0.875 * estimated_rtt + 0.125 * sample_rtt
                dev_rtt = 0.75 * dev_rtt + 0.25 * \
                    abs(estimated_rtt - sample_rtt)
                timeout_interval = estimated_rtt + 4 * dev_rtt
                estimated_rtt_dict[key], dev_rtt_dict[key], timeout_interval_dict[key] = estimated_rtt, dev_rtt, timeout_interval
            else:
                pkt_time_stamp_dict[key].pop((ex_sending_chunkhash, Ack), None)

            if (Ack)*MAX_PAYLOAD >= CHUNK_DATA_SIZE and len(pipe_list_dict[key]) == 0:
                # already complete sending
                status[key] = 0
                connections.pop(ex_sending_chunkhash, None)
                ex_sending_chunkhash_dict.pop(key, None)
                last_recv_time_dict.pop(key, None)
                pkt_time_stamp_dict.pop(key, None)
                # finished
                print(f"finished sending {ex_sending_chunkhash}")
            elif plen > HEADER_LEN:
                # if there are more pkt to retransmit
                blen = plen - HEADER_LEN
                num_of_seq_num = blen // 4
                fmt_str = "!" + "I" * num_of_seq_num
                data_unpack = struct.unpack(fmt_str, data)
                for i in range(num_of_seq_num):
                    seq_num = data_unpack[i]
                    left = (seq_num) * MAX_PAYLOAD
                    right = min((seq_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    chunk_data = config.haschunks[ex_sending_chunkhash][left: right]
                    data_header = struct.pack(
                        "!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), seq_num+1, 0)
                    data_pkt = data_header + chunk_data
                    sock.sendto(data_pkt, from_addr)
            else:
                # continue sending DATA
                pkt_time_stamp_dict[key] = dict()
                seq_st = biggest_ack
                smallest_ack = 0
                if(len(pipe_list_dict[key]) != 0):
                    smallest_unack = min(pipe_list_dict[key])
                # if there is free window size, then continue sending DATA pkt

                # free_window_size = cwnd[key] - len(pipe_list_dict[key])
                # if free_window_size > 0:
                #     upper_bound = seq_st + min(10, free_window_size) + 1
                #     for seq_num in range(seq_st+1, upper_bound): # seq_num = [+1,..., +free_window_size+1]
                #         biggest_ack_dict[key] = seq_num
                #         left = (seq_num - 1) * MAX_PAYLOAD
                #         right = min((seq_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                #         chunk_data: bytes = config.haschunks[ex_sending_chunkhash][left: right]
                #         # start timer in sender
                #         if config.timeout == 0:
                #             pkt_time_stamp_dict[key][(ex_sending_chunkhash, seq_num)] = time.time()
                #         # send next data
                #         data_header = struct.pack("!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN + len(chunk_data), seq_num, 0)
                #         data_pkt = data_header + chunk_data
                #         sock.sendto(data_pkt, from_addr)
                #         pipe_list_dict[key].add(seq_num)
                #         if (seq_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE: # already complete sending
                #             break

                upper_bound = seq_st+math.floor(cwnd[key]) + 1
                # seq_num = [+1,..., +free_window_size+1]
                for seq_num in range(smallest_unack, smallest_unack + cwnd[key]):
                    if seq_num in pipe_list_dict[key] or seq_num in already_acked[key]:
                        continue
                    biggest_ack = seq_num
                    left = (seq_num - 1) * MAX_PAYLOAD
                    right = min((seq_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    chunk_data: bytes = config.haschunks[ex_sending_chunkhash][left: right]
                    # start timer in sender
                    pkt_time_stamp_dict[key][(
                        ex_sending_chunkhash, seq_num)] = time.time()
                    # send next data
                    data_header = struct.pack(
                        "!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN + len(chunk_data), seq_num, 0)
                    data_pkt = data_header + chunk_data
                    sock.sendto(data_pkt, from_addr)
                    pipe_list_dict[key].add(seq_num)
                    if (seq_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:  # already complete sending
                        break

        smallest_ack_dict[key], biggest_ack_dict[key], redundant_ack_dict[key] = smallest_ack, biggest_ack, redundant_ack


def time_out_retransmission(sock: simsocket.SimSocket, from_addr):

    global ex_sending_chunkhash_dict
    global ex_downloading_chunkhash_dict
    global config
    global ex_output_file_dict
    global ex_received_chunk_dict

    global pkt_time_stamp_dict
    global connections
    global timeout_interval_dict

    global cwnd
    global ssthresh
    global status

    global last_recv_time_dict

    cur_time = time.time()
    self_addr = (config.ip, config.port)
    # [as sender, as receiver]
    keys = [(self_addr, from_addr), (from_addr, self_addr)]

    for idx, key in enumerate(keys):
        # Tuple(sender_addr, receiver_addr):{(chunkhash, seq_num): start_time} as sender,
        # Tuple(sender_addr, receiver_addr): start_time as receiver

        pkt_time_stamp = pkt_time_stamp_dict.get(key, -1)

        if pkt_time_stamp == -1:
            continue

        timeout_interval = timeout_interval_dict[key] if config.timeout == 0 else config.timeout

        crash_time_interval = 4 * timeout_interval

        # 无论是sender还是receiver， 收到包后last_recv_time_dict就会更新，且直到连接中断前不会pop
        # 因此，若last_recv_time_dict[key]为空，说明目前两个地址之间没有连接，可以直接结束函数以加快速度
        last_recv_time = last_recv_time_dict.get(key, -1)
        if last_recv_time == -1:
            continue

        # as sender
        if idx == 0:
            # 离最近一次受到包间隔超过一定时间，对方peer已crash
            # 由于该case考虑peer为sender的情况，暂时认为仅中断链接即可（不确定）
            # TODO：crash的情况下是否还需要进行其他操作？
            if cur_time - last_recv_time_dict[key] > crash_time_interval:
                ex_sending_chunkhash: str = ex_sending_chunkhash_dict.get(
                    key[0], None)
                if ex_sending_chunkhash is None:
                    continue
                connections.pop(ex_sending_chunkhash, None)
                ex_downloading_chunkhash_dict.pop(key, None)
                pkt_time_stamp_dict.pop(key, None)
                last_recv_time_dict.pop(key, None)

            # check the time stamps
            # pkt_time_stamp = {(chunkhash, seq_num): start_time}
            # 遍历所有尚未收到ack的包，检查是否有包超时，如果超时则重传一份
            for pkt_time_stamp_key in list(pkt_time_stamp.keys()):
                start_time = pkt_time_stamp[pkt_time_stamp_key]
                if cur_time - start_time > timeout_interval:  # normal time out
                    # timeout retransmit
                    pkt_time_stamp_dict[key].pop(pkt_time_stamp_key, None)
                    (chunkhash_str, seq_num) = pkt_time_stamp_key

                    left = (seq_num - 1) * MAX_PAYLOAD
                    right = min((seq_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    chunk_data = config.haschunks[chunkhash_str][left: right]
                    data_header = struct.pack(
                        "!HBBHHII", 52305, 68, 3, HEADER_LEN, HEADER_LEN+len(chunk_data), seq_num, 0)
                    data_pkt = data_header + chunk_data
                    sock.sendto(data_pkt, from_addr)

                    if status[key] == 1:  # slow start
                        ssthresh[key] = max(math.floor(cwnd[key] / 2), 2.0)
                        cwnd[key] = 1
                        sock.add_log('cwnd ' + str(time.time() -
                                                   download_start_time[key]) + ' ' + str(cwnd[key]))
                        redundant_ack_dict[key] = 0
                    elif status[key] == 2:  # congestion avoidance
                        ssthresh[key] = max(math.floor(cwnd[key] / 2), 2.0)
                        cwnd[key] = 1
                        sock.add_log('cwnd ' + str(time.time() -
                                                   download_start_time[key]) + ' ' + str(cwnd[key]))
                        redundant_ack_dict[key] = 0
                        status[key] = 1
                    elif status[key] == 3:  # fast recovery
                        ssthresh[key] = max(math.floor(cwnd[key] / 2), 2.0)
                        cwnd[key] = 1
                        sock.add_log('cwnd ' + str(time.time() -
                                     download_start_time[key]) + ' ' + str(cwnd[key]))
                        redundant_ack_dict[key] = 0
                        status[key] = 1
        else:  # as receiver
            # pkt_time_stamp = start_time
            # 当发送方超过crash_time_interval未发送数据时，判定为crash
            if cur_time - last_recv_time > crash_time_interval:  # peer is crash
                # 当receiver检测到sender已crash时，需要重新发送whohas
                # 获取当前正在传输的chunk
                ex_downloading_chunkhash: str = ex_downloading_chunkhash_dict.get(
                    key, None)

                # TODO：ex_sending_chunkhash在连接中是否一定存在？
                # 由于上面已经通过last_recv_time检查过是否处于连接中，此处认为ex_sending_chunkhash在连接中必定存在
                # if ex_sending_chunkhash is None:
                #     pass

                # 清空上一次传输的内容
                connections.pop(ex_downloading_chunkhash, None)
                last_recv_time_dict.pop(key, None)
                pkt_time_stamp_dict.pop(key, None)

                # TODO:发送WHOHAS
                global chunkfile
                global outputfile
                process_download(sock, chunkfile, outputfile)


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        global chunkfile
        global outputfile
        chunkfile = chunkf
        outputfile = outf
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:

            for chunk_hash in list(connections.keys()):
                (sender_addr, receiver_addr) = connections.get(chunk_hash)
                # every time when receive pkt, check if time out
                from_addr = sender_addr if receiver_addr == addr else receiver_addr
                time_out_retransmission(sock, from_addr)

            ready = select.select([sock, sys.stdin], [], [], 0.1)
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
        sock.add_log('quit')

    except Exception as ex:
        sock.add_log(str(ex))
        sock.add_log(str(traceback.format_exc()))
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
    parser.add_argument(
        '-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument(
        '-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument(
        '-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument(
        '-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)