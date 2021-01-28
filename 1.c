#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>

#define AVDTP_DISCOVER			0x01
#define AVDTP_GET_CAPABILITIES		0x02
#define AVDTP_SET_CONFIGURATION		0x03
#define AVDTP_GET_CONFIGURATION		0x04
#define AVDTP_RECONFIGURE		0x05
#define AVDTP_OPEN			0x06
#define AVDTP_START			0x07
#define AVDTP_CLOSE			0x08
#define AVDTP_SUSPEND			0x09
#define AVDTP_ABORT			0x0A

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avdtp_header {
	uint8_t message_type:2;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint8_t signal_id:6;
	uint8_t rfa0:2;
} __attribute__ ((packed));

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avdtp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t message_type:2;
	uint8_t rfa0:2;
	uint8_t signal_id:6;
} __attribute__ ((packed));

struct avctp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t cr:1;
	uint8_t ipid:1;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

#else
#error "Unknown byte order"
#endif

#define AVCTP_COMMAND		0
#define AVCTP_RESPONSE		1

#define AVCTP_PACKET_SINGLE	0

static int media_sock = -1;


static int set_send_buffer_size(int sk, int size)
{
	socklen_t optlen = sizeof(size);

	if (setsockopt(sk, SOL_SOCKET, SO_SNDBUF, &size, optlen) < 0) {
		int err = -errno;
		perror("setsockopt(SO_SNDBUF) failed");
		return err;
	}

	return 0;
}

static int set_max_mtu(int sk)
{
	struct l2cap_options l2o;
	socklen_t optlen;

	memset(&l2o, 0, sizeof(l2o));
	optlen = sizeof(l2o);

	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &optlen) < 0) {
		perror("getsockopt");
		return -1;
	}

	printf("\nomtu:[%d]. imtu:[%d]. flush_to:[%d]. mode:[%d]\n", l2o.omtu, l2o.imtu, l2o.flush_to, l2o.mode);

	l2o.imtu = 65534;
	l2o.omtu = 65534;

	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, sizeof(l2o)) < 0) {
		perror("setsockopt");
		return -1;
	}

	set_send_buffer_size(sk, 65534);
	printf("\nomtu:[%d]. imtu:[%d]. flush_to:[%d]. mode:[%d]\n", l2o.omtu, l2o.imtu, l2o.flush_to, l2o.mode);

	return 0;
}

static int do_connect(const bdaddr_t *src, const bdaddr_t *dst, int avctp,
								int fragment)
{
	struct sockaddr_l2 addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		return -1;
	}
	
	set_max_mtu(sk);

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(23);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		perror("Unable to connect");
		goto error;
	}

	return sk;

error:
	close(sk);
	return -1;
}

void simple_avrcp_mangle(unsigned char* pBuf, unsigned int nSize)
{
	char opcodes[] = {0x30,0x31,0x00,0x7c};
   	for(unsigned int i = 0; i < nSize; i++)
	{
		if(i == 2)
		{
			int nIdx = rand() % 4;
			pBuf[i] = opcodes[nIdx];
			
		}
		else
			pBuf[i] = rand() % 256;
	}
}

void util_sleepForMSec(uint64_t msec) {
    if (msec == 0) {
        return;
    }
    struct timespec ts = {
        .tv_sec  = msec / 1000U,
        .tv_nsec = (msec % 1000U) * 1000000U,
    };
    (nanosleep(&ts, &ts));
}

static void do_avctp_send(int sk, int invalid)
{
	unsigned char buf[2000];
	struct avctp_header *hdr = (void *) buf;
	unsigned char play_pressed[] = { 0x00, 0x48, 0x7c, 0x44, 0x00 };
	ssize_t len;

	memset(buf, 0, sizeof(buf));

	hdr->packet_type = AVCTP_PACKET_SINGLE;
	hdr->cr = AVCTP_COMMAND;
	if (invalid)
		hdr->pid = 0xffff;
	else
		hdr->pid = htons(AV_REMOTE_SVCLASS_ID);

	// mod
	srand((int)time(NULL)); 
	int nCount = 1;

	play_pressed[2] = 0x00;
	len = write(sk, buf, AVCTP_HEADER_LENGTH + 300);	

	for(unsigned int i = 0; i < 0xFFFFFFFF; i++) 
	{
		simple_avrcp_mangle(play_pressed, sizeof(play_pressed));

		memcpy(&buf[AVCTP_HEADER_LENGTH], play_pressed, sizeof(play_pressed));

		unsigned int writelen = (rand() % 500);
		len = write(sk, buf, AVCTP_HEADER_LENGTH + writelen);
		printf("[%d]write len: %ld, wish writelen: %d", nCount++, len, writelen);
		printf("\n");

		util_sleepForMSec(1);

		if(len == -1)
		{
			printf("send error!\n");
			break;
		}	
	}
	
}

enum {
	MODE_NONE, MODE_REJECT, MODE_SEND,
};

int main(int argc, char *argv[])
{
	unsigned char cmd = 0x00;
	bdaddr_t src, dst;
	int opt, mode = MODE_NONE, sk, invalid = 0, preconf = 0, fragment = 0;
	int avctp = 0, wait_before_exit = 0;

	bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);

	avctp = MODE_SEND;
	mode = MODE_SEND;
	cmd = AVDTP_OPEN;		

	if (argv[optind])
		str2ba(argv[optind], &dst);

	sk = do_connect(&src, &dst, avctp, fragment);
	if (sk < 0)
		exit(1);
	do_avctp_send(sk, invalid);

	return 0;
}
