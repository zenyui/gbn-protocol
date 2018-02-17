#include "gbn.h"

state_t s;

void signal_handler(){
	// do nothing
}

uint8_t get_last_seq_num(uint8_t seqnum)
{
	if (seqnum == 0) {
		return SEQNUM - 1;
	}
	return --seqnum;
}

uint8_t get_next_seq_num(uint8_t seq_num)
{
	if (seq_num == (SEQNUM - 1)){
		return 0;
	}

	return ++seq_num;
}

uint8_t get_nth_seq_num(uint8_t seqnum, int n){
	// return the nth sequence number ahead
	int i;
	uint8_t tmp_seqnum = seqnum;

	for (i=0; i<n; i++){
		tmp_seqnum = get_next_seq_num(tmp_seqnum);
	}

	return tmp_seqnum;
}

void increment_seq_num()
{
	printf("increment_seq_num:\n");
	s.seqnum = get_next_seq_num(s.seqnum);
}

void gbnhdr_clear(gbnhdr *packet)
{
	memset(packet, 0, sizeof(*packet));
}

size_t gbnhdr_build(gbnhdr *packet, uint8_t type, uint8_t seqnum, const void *buf, size_t len)
{
	if (len > DATALEN){
		return -1;
	}

	gbnhdr_clear(packet);

	packet->type = type;
	packet->seqnum = seqnum;
	packet->checksum = 0;

	// copy data into the packet data buffer
	if (buf != NULL && len > 0){
		memcpy(packet->data, buf, len);
	}

	// calculate and store the checksum in the packet
	packet->checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

	printf("gbnhdr_build: calculated checksum %d\n", packet->checksum);

	return sizeof(packet->type) + sizeof(packet->seqnum) + sizeof(packet->checksum) + (sizeof(uint8_t) * len);
}

uint8_t validate_packet(gbnhdr *packet)
{
	uint16_t received_checksum = packet->checksum;
	packet->checksum = 0;
	uint16_t calculated_checksum = checksum((uint16_t *)packet, sizeof(*packet) / sizeof(uint16_t));

	if (received_checksum == calculated_checksum){
		printf("validate_packet: success, checksum %d\n", received_checksum);
		return TRUE;
	}
	printf("*********************************************************\n");
	printf("validate_packet: mismatch, received: %d, calculated: %d\n", received_checksum, calculated_checksum);
	printf("*********************************************************\n");
	return FALSE;
}

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t recv_ack(int sockfd, gbnhdr *packet, int flags){
	printf("recv_ack:\n");

	gbnhdr_clear(packet);

	// set the signal alarm
	alarm(TIMEOUT);

	ssize_t result = recvfrom(sockfd, packet, sizeof(gbnhdr), flags, (struct sockaddr *)&s.sockaddr, &s.socklen);

	// reset the signal alarm to a large value
	alarm(INT_MAX);

	if (result == 0){
		return 0;
	}

	if (result == -1){
		// the packet recv timeout occured wait again for a packet
		if (errno == EINTR){
			printf("recv_ack: ACK TIMEOUT\n");
			return ACKSTATUS_TIMEOUT;
		}

		return -1;
	}

	uint8_t packet_valid = validate_packet(packet);

	// the packet is corrupt
	if (packet_valid == FALSE){
		printf("recv_ack: ACK CORRUPT\n");
		return ACKSTATUS_CORRUPT;
	}

	printf("recv_ack: sequence number: %d\n", packet->seqnum);

	// the receiver is expecting a different packet
	if (packet->seqnum != get_nth_seq_num(s.seqnum, 1) &&
		  packet->seqnum != get_nth_seq_num(s.seqnum, 2)){

		printf("recv_ack: ACK BAD SEQ NUM\n");
		return ACKSTATUS_BADSEQ;
	}

	// increment sequence number
	increment_seq_num();

	return result;
}

ssize_t maybe_send_packet(int sockfd, uint8_t seqnum, int flags){
	printf("maybe_send_packet: seqnum=%d\n", seqnum);

	return maybe_sendto(sockfd, &s.packet_buf[seqnum], s.packet_size[seqnum], flags, (struct sockaddr *)&s.sockaddr, s.socklen);
}

ssize_t maybe_send(int sockfd, uint8_t type, uint8_t seqnum, const void *buf, size_t len, int flags){
	printf("maybe_send:\n");

	gbnhdr packet;
	size_t packet_size = gbnhdr_build(&packet, type, seqnum, buf, len);

	return maybe_sendto(sockfd, &packet, packet_size, flags, (struct sockaddr *)&s.sockaddr, s.socklen);
}

void store_packet(uint8_t type, uint8_t seqnum, const void *buf, size_t len){
	printf("store_packet: seqnum=%d\n", seqnum);

	gbnhdr packet;
	size_t packet_size = gbnhdr_build(&packet, type, seqnum, buf, len);

	memcpy(&s.packet_buf[seqnum], &packet, sizeof(gbnhdr));
	s.packet_size[seqnum] = packet_size;
}

void set_window_slow(){
	printf("set_window_slow: window=%d\n", WINDOW_SLOWMODE);
	s.windowsize = WINDOW_SLOWMODE;
}

void set_window_fast(){
	printf("set_window_fast: window=%d\n", WINDOW_FASTMODE);
	s.windowsize = WINDOW_FASTMODE;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	printf("gbn_send:\n");

	gbnhdr packet;
	size_t current_offset = 0;
	size_t ack_status = 0;
	size_t tmp_current_offset = 0;

	int packetcount = 0;
	int sentpackets = 0;
	int ackedpackets = 0;
	uint8_t error_detected = FALSE;

	uint8_t tmp_seqnum;
	size_t data_size;

	// init window size
	set_window_fast();
	// set_window_slow();

	while (current_offset < len){
		printf("--------------------------------------\n");
		printf("gbn_send: current_offset: (%d / %d)\n", current_offset, len);
		printf("gbn_send: windowsize=%d\n", s.windowsize);

		// copy current offset
		tmp_current_offset = current_offset;

		// create all necessary packets per current window size
		for (packetcount = 0; packetcount < s.windowsize; packetcount++){
			// get the nth seqnum away from s.seqnum
			tmp_seqnum = get_nth_seq_num(s.seqnum, packetcount);

			// set data size, create packet, store in packet_buf
			data_size = MIN(DATALEN, len - tmp_current_offset);

			// if nothing to send, stop building packets
			if (data_size <= 0) break;

			store_packet(DATA, tmp_seqnum, buf+tmp_current_offset, data_size);

			tmp_current_offset += data_size;
		}

		printf("gbn_send: created %d packet(s)\n", packetcount);


		// you have created "packtcount" number of packets in memory
		while (TRUE){

			printf("-------------------\n");

			// for each created packet, send packet and recv ack
			for (sentpackets = 0; sentpackets < packetcount; sentpackets++){

				// get the nth seqnum away from s.seqnum
				tmp_seqnum = get_nth_seq_num(s.seqnum, sentpackets);

				printf("gbn_send: sending DATA packet, seqnum=%d\n", tmp_seqnum);
				if (maybe_send_packet(sockfd, tmp_seqnum, flags) < 0){
					return -1;
				}
			}

			printf("-------------------\n");

			// receive each packet
			for (ackedpackets = 0; ackedpackets < packetcount; ackedpackets++){

				printf("gbn_send: expecting DATAACK for packet %d\n", s.seqnum);

				// on successful recv, s.seqnum is incremented
				ack_status = recv_ack(sockfd, &packet, flags);
				if (ack_status == ACKSTATUS_TIMEOUT){
					error_detected = TRUE;
				}
				else if (ack_status == ACKSTATUS_CORRUPT){
					error_detected = TRUE;
				}
				else if (ack_status == ACKSTATUS_BADSEQ){
					error_detected = TRUE;
				}
				else if (ack_status <= 0){
					return -1;
				}
				else {
					printf("gbn_send: received ACK, updating current_offset\n");
					current_offset += MIN(DATALEN, len - current_offset);
					error_detected = FALSE;
				}
			}

			// if no more packets, go to top and build new ones
			if (error_detected){
				set_window_slow();
			}
			else {
				set_window_fast();
			}

			break;
		}
	}

	return 0;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	printf("gbn_recv:\n");

	gbnhdr packet;
	size_t packet_len_bytes;

	while (TRUE){
		printf("--------------------------------------\n");
		printf("gbn_recv: receiving DATA\n");

		gbnhdr_clear(&packet);
		packet_len_bytes = recvfrom(sockfd, &packet, sizeof(gbnhdr), flags, (struct sockaddr *)&s.sockaddr, &s.socklen);
		if (packet_len_bytes <= 0){
			return packet_len_bytes;
		}

		uint8_t packet_valid = validate_packet(&packet);

		// the packet is corrupt, drop it (ack the expected sequence number?)
		if (packet_valid == FALSE){
			continue;
		}

		printf("gbn_recv: sequence number: %d\n", packet.seqnum);

		// the packet is not expected, drop it (ack the expected sequence number?)
		if (packet.seqnum != s.seqnum){
			if (packet.type == DATA){
				printf("gbn_recv: sending DATAACK\n");
				if (maybe_send(sockfd, DATAACK, s.seqnum, NULL, 0, flags) < 0){
					return -1;
				}
			}
			else if (packet.type == SYN){
				printf("gbn_recv: sending SYNACK\n");
				if (maybe_send(sockfd, SYNACK, s.seqnum, NULL, 0, flags) < 0){
					return -1;
				}
			}
			else{
				return -1;
			}

			continue;
		}

		break;
	}

	// increment sequence number
	increment_seq_num();

	if (packet.type == DATA){
		printf("gbn_recv: received DATA packet\n");

		size_t data_len_bytes = packet_len_bytes - (sizeof(packet.type) + sizeof(packet.seqnum) + sizeof(packet.checksum));
		memcpy(buf, packet.data, data_len_bytes);

		// print received data to the console for debugging
		// printf("%.*s\n", (int)data_len_bytes, buf);

		printf("gbn_recv: sending DATAACK\n");
		if (maybe_send(sockfd, DATAACK, s.seqnum, NULL, 0, flags) < 0){
			return -1;
		}

		return data_len_bytes;
	}
	else if (packet.type == FIN){
		printf("gbn_recv: received FIN packet\n");

		printf("gbn_recv: sending FINACK\n");
		if (maybe_send(sockfd, FINACK, s.seqnum, NULL, 0, flags) < 0){
			return -1;
		}

		return 0;
	}

	printf("gbn_recv: expecting DATA or FIN packet\n");
	return -1;
}

int gbn_close(int sockfd){
	printf("gbn_close:\n");

	int flags = 0;
	int ack_status = 0;
	int fin_count = 0;
	gbnhdr ack_packet;

	if (s.is_sender == TRUE){

		while (fin_count < FIN_MAX) {
			printf("gbn_close: sending FIN\n");
			if (maybe_send(sockfd, FIN, s.seqnum, NULL, 0, flags) < 0){
				return -1;
			}

			fin_count ++;

			printf("gbn_close: receiving FINACK\n");
			ack_status = recv_ack(sockfd, &ack_packet, flags);
			if (ack_status == ACKSTATUS_TIMEOUT){
				continue;
			}
			else if (ack_status == ACKSTATUS_CORRUPT){
				continue;
			}
			// if seqnum too high, resend packet
			else if (ack_status == ACKSTATUS_BADSEQ){
				continue;
			}
			else if (ack_status <= 0){
				return -1;
			}
			else if (ack_packet.type != FINACK){
				printf("gbn_close: expecting FINACK packet\n");
				return -1;
			}
			else {
				break;
			}
		}

	}

	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
	printf("gbn_connect:\n");

	int flags = 0;
	int ack_status = 0;
	gbnhdr ack_packet;

	gbn_init();

	memcpy(&s.sockaddr, server, socklen);
	memcpy(&s.socklen, &socklen, sizeof(socklen_t));

	while (TRUE) {
		printf("gbn_connect: sending SYN\n");
		if(maybe_send(sockfd, SYN, s.seqnum, NULL, 0, flags) < 0){
			return -1;
		}

		printf("gbn_connect: receiving SYNACK\n");

		ack_status = recv_ack(sockfd, &ack_packet, flags);
		if (ack_status == ACKSTATUS_TIMEOUT){
			continue;
		}
		else if (ack_status == ACKSTATUS_CORRUPT){
			continue;
		}
		// if seqnum too high, resend packet
		else if (ack_status == ACKSTATUS_BADSEQ){
			continue;
		}
		else if (ack_status <= 0){
			return -1;
		}
		else {
			break;
		}
	}

	if (ack_packet.type != SYNACK){
		printf("gbn_connect: expecting SYNACK packet\n");
		return -1;
	}

	if (ack_packet.type == RST){
		printf("gbn_connect: rejected with RST packet\n");
		return -1;
	}

	if (ack_packet.seqnum != s.seqnum){
		printf("gbn_connect: bad sequence number\n");
		return -1;
	}

	s.active_connection = TRUE;
	s.is_sender = TRUE;

	return sockfd;
}

int gbn_listen(int sockfd, int backlog){
	printf("gbn_listen:\n");

	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	printf("gbn_bind:\n");

	return bind(sockfd, server, socklen);
}

int gbn_socket(int domain, int type, int protocol){
	printf("gbn_socket:\n");

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	return socket(domain, type, protocol);
}

void gbn_init(){
	printf("gbn_init:\n");

	// register the signal handler for timeout
	struct sigaction sact = {
		.sa_handler = signal_handler,
		.sa_flags = 0,
	};

	sigaction(SIGALRM, &sact, NULL);

	s.seqnum = 0;
	s.active_connection = FALSE;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
	printf("gbn_accept:\n");

	int flags = 0;
	gbnhdr packet;

	gbn_init();

	while (TRUE){
		printf("gbn_accept: receiving SYN\n");
		gbnhdr_clear(&packet);
		if (recvfrom(sockfd, &packet, sizeof(gbnhdr), flags, client, socklen) < 0){
			printf("gbn_accept: failed receiving SYN packet\n");
			return -1;
		}

		uint8_t packet_valid = validate_packet(&packet);

		// the packet is corrupt, drop it (ack the expected sequence number?)
		if (packet_valid == FALSE){
			continue;
		}

		break;
	}

	printf("gbn_accept: sequence number: %d\n", packet.seqnum);

	if (packet.type != SYN) {
		printf("gbn_accept: expecting SYN packet\n");
		return -1;
	}

	if (packet.seqnum != s.seqnum){
		printf("gbn_accept: bad sequence number\n");
		return -1;
	}

	memcpy(&s.sockaddr, client, *socklen);
	memcpy(&s.socklen, socklen, sizeof(socklen_t));

	// return RST packet if socket has current connection
	if (s.active_connection == TRUE){
		printf("gbn_accept: sending RST\n");
		if (maybe_send(sockfd, RST, s.seqnum, NULL, 0, 0) < 0){
			return -1;
		}

		// TODO: should we send back the sockfd even though the connection is rejected?
		return sockfd;
	}

	// increment sequence number
	increment_seq_num();

	printf("gbn_accept: sending SYNACK\n");
	if(maybe_send(sockfd, SYNACK, s.seqnum, NULL, 0, 0) < 0){
		return -1;
	}

	s.active_connection = TRUE;
	s.is_sender = FALSE;

	return sockfd;
}

ssize_t maybe_sendto(int s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);


	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){

			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
