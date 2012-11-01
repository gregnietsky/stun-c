struct stun_header {
	unsigned short msgtype;
	unsigned short msglen;
	unsigned int id[4];
	unsigned char ies[0];
} __attribute__((packed));

struct stun_attr {
	unsigned short attr;
	unsigned short len;
	unsigned char value[0];
} __attribute__((packed));

struct stun_addr {
	unsigned char unused;
	unsigned char family;
	unsigned short port;
	unsigned int addr;
} __attribute__((packed));

struct stun_state {
	char *username;
	char *password;
	struct sockaddr_in caddr,maddr;
	int result,pcnt;
	struct timeval laststun;
	struct sockaddr_in bindaddr; //bindaddr ast_rtp->us
	int sock; //ast_rtp->s
};

#define STUN_IGNORE     (0)
#define STUN_ACCEPT     (1)

#define STUN_BINDREQ 0x0001
#define STUN_BINDRESP   0x0101
#define STUN_BINDERR 0x0111
#define STUN_SECREQ  0x0002
#define STUN_SECRESP 0x0102
#define STUN_SECERR  0x0112
#define STUN_MAPPED_ADDRESS   0x0001
#define STUN_RESPONSE_ADDRESS 0x0002
#define STUN_CHANGE_REQUEST   0x0003
#define STUN_SOURCE_ADDRESS   0x0004
#define STUN_CHANGED_ADDRESS  0x0005
#define STUN_USERNAME      0x0006
#define STUN_PASSWORD      0x0007
#define STUN_MESSAGE_INTEGRITY   0x0008
#define STUN_ERROR_CODE    0x0009
#define STUN_UNKNOWN_ATTRIBUTES  0x000a
#define STUN_REFLECTED_FROM   0x000b
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#define STUN_SERVERNAME    0x0022
