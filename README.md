# go-back-n
**Abbreviated Go-back-n protocol implemented in C, similar to TCP/IP**

Cornell Tech | Networked and Distributed Systems<br>Jon Cutler (jlc553), Zen Yui (jzy6)


### Overview
The accompanying code implements a Go­back­n protocol (GBN) similar to that of real­world TCP/IP transmission. The goal of this protocol implementation was to provide a reliable transport protocol. We extended the provided methods and created several additional functions to ensure both a sender and receiver can reliably communicate data to each other through a socket api without worrying about packet loss or corruption.

The GBN protocol allows a sender to transmit up to a window of N packets consecutively before waiting for acknowledgements (ACKs). Per the assignment specification, our server supports two modes: slow mode and fast mode, which allow a window of 1 and 2 packets respectively. While the server optimistically begins operation in fast mode, it temporarily reverts to slow mode when congestion is encountered. GBN is often called the “sliding window” protocol as it increments the window of N packets as prior packets are successfully acknowledged.

Our implementation of GBN provides global structures for both the sender and receiver to track packet sequence numbers independently of one another. Although GBN is not the most performant protocol, our implementation is robust against corruption and packet loss, as both the sender and receiver participate in a simple and effective communication of ACKs, including cumulative ACKs that “fast­forward” the sender when prior ACKs are lost, and repeated ACKs when the sender sends duplicate data. The global state has one obvious downside ­ this implementation cannot support multiple clients simultaneously, we simply reject future connections with an RST packet, per the assignment specification.

### Methods Implemented
- `gbn socket()`<br>Used by both the sender and receiver to setup a socket. To do this we leverage the system call provided by UDP our application.

- `gbn connect()`<br>Used by the sender to initiate a connection with the receiver. At the start of the request we use this opportunity to initialize state the sender’s state. After this we build and send the SYN packet and wait to receive a SYNACK packet. If receiving a response from the receiver fails due to timeout, packet corruption or unexpected packet bad sequence number we attempt to resend the SYN packet to the receiver. Once we successfully receive a valid packet from the receiver we check to make sure that it is of type SYNACK before returning the socket file descriptor to the caller. If we receive a RST packet connect logs and returns ­1 to the caller.

- `gbn send()`<br>Used to send packet data using the GBN protocol. Our implementation supports both fast (GB2) and slow (GB1) modes. At the start of the request the sender will provide a buffer of data and its length. Because this buffer may be larger than what can fit in a single DATA packet it must be split up into multiple send requests. When in fast mode the implementation will send two packets at a time and then attempt to receive two DATAACK packets from the receiver. When in slow mode the implementation will send a single packet at a time and then attempt to receive a single DATAACK packet from the receiver. If receiving a response from the receiver fails due to timeout, packet corruption or unexpected packet bad sequence number we adjust our sending mode to slow and attempt to resend the window packets to the receiver. Once successful transmission of the window is complete with no losses the implementation can switch back to fast mode.

- `gbn recv()`<br>Used to receive packet data using the GBN protocol. At the start of the request the receiver waits to receive a packet from the sender. Once a packet is received and parsed into the gbnhdr struct we validate the packet’s checksum to ensure that it is not corrupt. If the checksum is invalid we simply drop the packet and do not acknowledge receiving it. We do this because without knowing the type of packet we cannot confidently send the correct type of acknowledgement packet. If we determine that the packet is not corrupt, but the sequence number is unexpected the receiver simply acknowledges the expected sequence number to the sender. If the packet is expected and is of packet type DATA we copy the data portion of the packet into the receiver’s buffer, send a DATAACK and continue receiving. If the packet is expected and is of packet type FIN we send a FINACK and return zero bytes received to the caller.

- `gbn close()`<br>Used to end a connection and close the socket. In the case of the sender this means sending the FIN packet and waiting to receive a FINACK packet. If receiving a response from the receiver fails due to timeout, packet corruption or unexpected packet bad sequence number we attempt to resend the FIN packet to the receiver. If after FIN_MAX attempts, the receivers acknowledgment has not yet been received the sender will proceed to close the socket. To do this we leverage the system call provided by UDP our application.

- `gbn bind()`<br>Used by the receiver to bind a socket to an application.

- `gbn listen()`<br>Used by the receiver to change the state to listening on the socket. To do this we
leverage the system call provided by UDP our application.

- `gbn accept()`<br>Used by the receiver to accept an incoming connection. At the start of the request we use this opportunity to initialize state the receiver’s state. After this we attempt to receive a packet. If receiving from the sender fails due to packet corruption we simply drop the incoming packet and wait to receive again. Once a valid packet of type SYN is obtained, the receiver can maintain state about the client’s address as well as set state about the new active connection. If however, the receiver currently has an active connection the incoming SYN request is responded to with a packet of type RST instead of a SYNACK.


### Challenges:
The following section outlines the challenges we encountered during this implementation and our solutions:

- Duplicate data sent when ACK packets dropped
We initially struggled to accommodate the “fast mode” of our GBN implementation with lossy transmission ­ when ACKs were lost, the sender would retransmit the same data, and the receiver had to know to ignore these packets. In response, we designed the receiving functions such that the receiver retransmits the ACK packet for the last good data packet received, so the sender is responsible for “fast forwarding” when ACKs were lost, and retransmitting when data packets were lost. Since the real risk was duplicate or missing data on the recipient’s end, this appeared to be the most appropriate solution.

- Inconsistent errors from “maybe_sendto”
As the loss and corruption errors were configured to randomly occur 1% and 0.1% of the time, respectively, it was very difficult to identify areas that our protocol was losing or duplicating data. To address this, we temporarily increased the rate of failure to 25% of packets for both, and tested on shorter files, which allowed us to reproduce both errors predictably and often.

- Rotating sequence numbers made it difficult to know if packets were “early” or “late”. As sequence numbers have to rotate, it became tricky to analyze if packets were “early” or “late” with only the integers 0 to 4 to use. We implemented functions to retrieve the next, last, and “nth” sequence numbers from the current number, which allowed our program to analyze sequence numbers relative to the current, expected sequence and thereby either re­-ack or drop packets appropriately.
