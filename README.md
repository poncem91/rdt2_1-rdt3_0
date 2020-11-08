# RDT 2.1 & RDT 3.0

An implementation of the Reliable Data Transmission protocols RDT 2.1 and RDT 3.0 constructed by extending an RDT 1.0 implementation.

### RDT 2.1

`rdt.py` has been extended to tolerate packet corruption by modifying the Packet class and RDT's send and receive functions to make use of ACKs and NAKs that handle corrupted packets.

### RDT 3.0

`rdt.py` has been extended to tolerate packet loss by modifying the Packet class and RDT's send and receive functions to retransmit lost packets after a timeout or after a lost ACK, and ignores duplicate packets after premature timeouts or lost ACKs.

### Program Invocation

Run in separate terminal windows:

```
python server.py 5000
```

and

```
python client.py localhost 5000
```

Starting the servers first, to allow it to start listening on a socket used by `network.py`, and start the client soon after, before the server times out.

### Co-Authors
Starter code with RDT 1.0 implementation provided by Prof. Mike Wittie from Montana State University.
