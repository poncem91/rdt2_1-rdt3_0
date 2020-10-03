import threading

import Network
import argparse
import hashlib
from time import sleep


def print_lock(statement):
    with threading.Lock():
        print(statement)


class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    # length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        # extract the fields
        seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        return self(seq_num, msg_S)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    def isACK(self):
        return self.msg_S == "1"

    def isNAK(self):
        return self.msg_S == "0"

    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[
                     Packet.length_S_length + Packet.seq_num_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length]
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]

        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    # latest sequence number used in a packet for each thread (send and receive)
    seq_num_snd = 1
    seq_num_rcv = 1
    # buffer of bytes read from network
    byte_buffer = ''
    receive_thread = None

    def __init__(self, role_S, server_S, port):
        # use the passed in port and port+1 to set up unidirectional links between
        # RDT send and receive functions
        # cross the ports on the client and server to match net_snd to net_rcv
        if role_S == 'server':
            self.net_snd = Network.NetworkLayer(role_S, server_S, port)
            self.net_rcv = Network.NetworkLayer(role_S, server_S, port + 1)
        else:
            self.net_rcv = Network.NetworkLayer(role_S, server_S, port)
            self.net_snd = Network.NetworkLayer(role_S, server_S, port + 1)
        self.receive_thread = threading.Thread(target=self.receive_helper)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def disconnect(self):
        self.net_snd.disconnect()
        self.net_rcv.disconnect()
        if self.receive_thread:
            self.receive_thread.join()

    def rdt_2_1_send(self, msg_S):
        p = Packet(self.seq_num_snd, msg_S)

        while True:
            self.net_snd.udt_send(p.get_byte_S())
            ack_or_nak = self.net_snd.udt_receive()

            # wait for an ACK/NAK response
            while not ack_or_nak:
                ack_or_nak = self.net_snd.udt_receive()

            # extract length of packet
            length = int(ack_or_nak[:Packet.length_S_length])

            # check if ACK/NAK is corrupt
            ack_or_nak_bytes = ack_or_nak[0:length]
            corrupt = Packet.corrupt(ack_or_nak_bytes)

            if corrupt:
                print_lock("SENDER: ACK/NAK corrupt... Re-sending packet")
                continue

            if not corrupt:
                response = Packet.from_byte_S(ack_or_nak_bytes)

                if self.seq_num_snd != response.seq_num:
                    sndpkt = Packet(response.seq_num, "1")
                    self.net_snd.udt_send(sndpkt.get_byte_S())
                    print_lock("SENDER: Unexpected numbered packet... Resending ACK")
                    continue

                if response.isACK():
                    self.seq_num_snd = (self.seq_num_snd + 1) % 2
                    print_lock("SENDER: ACK received... Updating sequence number")
                    break

                elif response.isNAK():
                    pass
                    print_lock("SENDER: NAK received... Re-sending packet")

    def receive_helper(self):
        while True:
            byte_S = self.net_rcv.udt_receive()

            # check if we have received enough bytes
            if len(byte_S) < Packet.length_S_length:
                continue  # not enough bytes to read packet length
            # extract length of packet
            length = int(byte_S[:Packet.length_S_length])

            if len(byte_S) < length:
                continue  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string

            corrupt = Packet.corrupt(byte_S)

            if corrupt:
                sndpkt = Packet(self.seq_num_rcv, "0")
                self.net_rcv.udt_send(sndpkt.get_byte_S())
                print_lock("RECEIVER: Packet corrupt, sending NAK")

            elif not corrupt:
                p = Packet.from_byte_S(byte_S[0:length])

                if p.isACK() or p.isNAK():
                    continue

                if self.seq_num_rcv == p.seq_num:
                    self.byte_buffer += byte_S
                    sndpkt = Packet(p.seq_num, "1")
                    self.net_rcv.udt_send(sndpkt.get_byte_S())
                    self.seq_num_rcv = (self.seq_num_rcv + 1) % 2
                    print_lock("RECEIVER: Packet received successfully, sending ACK and updating seq num")

                else:
                    sndpkt = Packet(p.seq_num, "1")
                    self.net_rcv.udt_send(sndpkt.get_byte_S())
                    print_lock("RECEIVER: Unexpected numbered packet, resending ACK")

    def rdt_2_1_receive(self):
        ret_S = None
        if self.byte_buffer:
            length = int(self.byte_buffer[:Packet.length_S_length])
            ret_S = Packet.from_byte_S(self.byte_buffer[0:length]).msg_S
            self.byte_buffer = ""
        return ret_S


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_2_1_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_2_1_receive())
        rdt.disconnect()

    else:
        sleep(1)
        print(rdt.rdt_2_1_receive())
        rdt.rdt_2_1_send('MSG_FROM_SERVER')
        rdt.disconnect()
