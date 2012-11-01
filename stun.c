#define _GNU_SOURCE
#define MAX_BUFFER_SIZE 1024

#define STUN_NAT_SYMN   0x1
#define STUN_NAT_SYMF   0x2
#define STUN_NAT_OPEN   0x4
#define STUN_NAT_FULL   0x8
#define STUN_NAT_PORT   0x10
#define STUN_NAT_RES    0x20
#define STUN_NAT_BLOCK  0x0

#define STUN_CHANGE_NONE 0x0000000
#define STUN_CHANGE_PORT 0x00000002
#define STUN_CHANGE_IP 0x00000004
#define STUN_CHANGE_BOTH 0x00000006
       
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/signal.h>
#include <sys/poll.h>
#include <sys/time.h>
#include "stun.h"
#include <pthread.h>

void stun_handle_packet(struct stun_state *st, struct sockaddr_in *src,void *buf, int len);
static void stun_send(unsigned short msgtype,struct stun_state *st, void* data, int len,int testid);

struct sockaddr_in stunserver={AF_INET,};

static const char *stun_msg2str(int msg) {
	switch(msg) {
		case STUN_BINDREQ:
			return "Binding Request";
		case STUN_BINDRESP:
			return "Binding Response";
		case STUN_BINDERR:
			return "Binding Error Response";
		case STUN_SECREQ:
			return "Shared Secret Request";
		case STUN_SECRESP:
			return "Shared Secret Response";
		case STUN_SECERR:
			return "Shared Secret Error Response";
		}
	return "Non-RFC3489 Message";
}

static const char* stun_attr2str(int msg) {
	switch(msg) {
		case STUN_MAPPED_ADDRESS:
			return "Mapped Address";
		case STUN_RESPONSE_ADDRESS:
			return "Response Address";
		case STUN_CHANGE_REQUEST:
			return "Change Request";
		case STUN_SOURCE_ADDRESS:
			return "Source Address";
		case STUN_CHANGED_ADDRESS:
			return "Changed Address";
		case STUN_USERNAME:
			return "Username";
		case STUN_PASSWORD:
			return "Password";
		case STUN_MESSAGE_INTEGRITY:
			return "Message Integrity";
		case STUN_ERROR_CODE:
			return "Error Code";
		case STUN_UNKNOWN_ATTRIBUTES:
			return "Unknown Attributes";
		case STUN_REFLECTED_FROM:
			return "Reflected From";
	}
	return "Non-RFC3489 Attribute";
}

struct stun_attr* stun_message() {
	struct stun_attr *stunmsg;
	stunmsg=malloc(MAX_BUFFER_SIZE-sizeof(struct stun_header));
	bzero(stunmsg,sizeof(stunmsg));
	return stunmsg;
}

static int stun_attr_change(long changeflag,void *data, int offset) {
	unsigned short attrlen=sizeof(changeflag);
	long val;
	struct stun_attr *attr;
	
	attr=(struct stun_attr*)(data+offset);

	attr->attr=htons(STUN_CHANGE_REQUEST);
	attr->len=htons(attrlen);
	val=htonl(changeflag);
	memcpy(&attr->value,(long*)&val,sizeof(val));

	return attrlen+sizeof(struct stun_attr);
}

static int stun_attr_string(char *s, short int msgtype, void *data, int offset) {
	short int attrlen;	
	struct stun_attr *attr;
	
	attr=(struct stun_attr*)(data+offset);

	attr->attr=htons(msgtype);
	attrlen=strlen(s);
	memcpy(&attr->value,s,attrlen);

	while (attrlen % 4) {
		printf("Str Len: %i\n",attrlen);
		attrlen++;
	}
	printf("Str Len: %i\n",attrlen);
	attr->len=htons(attrlen);

	return attrlen+sizeof(struct stun_attr);
}

static int stun_attr_addr(struct sockaddr_in *sin, short int msgtype, void *data, int offset) {
	short int attrlen=sizeof(struct stun_addr);	
	struct stun_attr *attr;
	struct stun_addr *addr;

	attr=(struct stun_attr*)(data+offset);
	attr->attr=htons(msgtype);
	attr->len=htons(attrlen);

	addr=(struct stun_addr*)attr->value;
	addr->unused = 0;
	addr->family = 0x01;
	addr->port = sin->sin_port;
	addr->addr = sin->sin_addr.s_addr;

	return attrlen+sizeof(struct stun_attr);
}

struct sockaddr_in stun_addr_message(struct stun_addr *attrval) {
	struct sockaddr_in attraddr={AF_INET,};
	attraddr.sin_port=attrval->port;
	attraddr.sin_addr.s_addr=attrval->addr;
	return attraddr;
}


void ast_rtp_stun_request_peer(struct stun_state *st) {
	struct stun_attr *stunmsg=stun_message();
	int msglen=stun_attr_change(STUN_CHANGE_NONE,stunmsg,0);
	if (st->username) {
		msglen+=stun_attr_string(st->username, STUN_USERNAME, stunmsg, msglen);
	}
	stun_send(STUN_BINDREQ,st,stunmsg,msglen,0);
}


static void stun_send(unsigned short msgtype,struct stun_state *st, void* data, int len,int testid) {
	void *buf;
	struct stun_header *req;
	int x;
	struct sockaddr_in *dst;


	if (testid > 1) {
		dst=&st->caddr;
	} else {
		dst=&stunserver;
	}

	buf=malloc(MAX_BUFFER_SIZE);

	req=(struct stun_header*)buf;

	for (x = 0; x < 4; x++)
		req->id[x] = random();

	req->id[3] = (req->id[3] & 0xFFFFFF00) | testid;

	req->msgtype = htons(msgtype);

	if (data) {
		if (len) {
			memcpy(buf+sizeof(struct stun_header),data,len);
			req->msglen = htons(len);
		} else
			req->msglen = htons(0);
		free(data);
	} else {
		struct stun_attr *stunmsg=stun_message();
		len=stun_attr_change(STUN_CHANGE_NONE,stunmsg,0);
		memcpy(buf+sizeof(struct stun_header),stunmsg,len);
		req->msglen = htons(len);
		free(stunmsg);
	}

	sendto(st->sock, buf, len + sizeof(struct stun_header), 0,(struct sockaddr *)dst, sizeof(*dst));
	free(buf);
}

void *data_thread(void *data) {
	int rv,len;
	struct stun_state *st=data;
	struct pollfd psock[1];
	unsigned char *buf;
	socklen_t sinlen=sizeof(struct sockaddr_in);
	struct sockaddr_in sin;	

	buf=malloc(MAX_BUFFER_SIZE);
	bzero(buf,sizeof(buf));

	psock[0].fd=st->sock;
	psock[0].events=POLLIN;

	st->result=0;
	st->pcnt=0;
	gettimeofday(&st->laststun,0);

	while(1) {
		rv = poll(psock, 1, -1);
		if ((psock[0].revents & POLLIN) && (rv > 0)){
			gettimeofday(&st->laststun,0);
			len=recvfrom(st->sock,buf,MAX_BUFFER_SIZE,MSG_WAITALL,&sin,&sinlen);
			if (len > 0) {
				stun_handle_packet(st,&sin,buf,len);
			}
		}
	}
	free(buf);
	pthread_exit((void *) 0);
}

void stun_handle_packet(struct stun_state *st,struct sockaddr_in *src, void *buf, int len) {
	struct stun_header *hdr;
	unsigned char *data;
	int pcnt,msglen, option_debug=1,stundebug=1,msgtype;
	struct stun_attr *stunmsg;
	struct stun_attr *attr;
	struct sockaddr_in maddr,caddr;

	hdr=(struct stun_header *)buf;
	msgtype=ntohs(hdr->msgtype);

	if ((msgtype != STUN_BINDREQ) && (msgtype != STUN_BINDRESP)) {
		if (option_debug)
			printf("Dunno what to do with STUN message %04x (%s)\n", msgtype, stun_msg2str(msgtype));
		return;
	}

	if (len < sizeof(struct stun_header)) {
		if (option_debug)
			printf("Runt STUN packet (only %zd, wanting at least %zd)\n", len, sizeof(struct stun_header));
		return;
	}

	if (stundebug)
		printf("STUN Packet, msg %s (%04x), length: %d\n", stun_msg2str(ntohs(hdr->msgtype)), ntohs(hdr->msgtype), ntohs(hdr->msglen));

	if (ntohs(hdr->msglen) > len - sizeof(struct stun_header)) {
		printf("Scrambled STUN packet length (got %d, expecting %d)\n", ntohs(hdr->msglen), (int)(len - sizeof(struct stun_header)));
		return;
	} else {
		len = ntohs(hdr->msglen);
	}

	maddr=st->bindaddr;
	pcnt=hdr->id[3] & 0x000000FF;

	data = buf+sizeof(struct stun_header);


	if (len > 0) {
		while(len) {
			if (len < sizeof(struct stun_attr)) {
				if (option_debug)
					printf("Runt Attribute (got %zd, expecting %zd)\n", len, sizeof(struct stun_attr));
				break;
			}
			attr = (struct stun_attr*)data;
			if (ntohs(attr->len) > len) {
				if (option_debug)
					printf("Inconsistent Attribute (length %d exceeds remaining msg len %zd)\n", ntohs(attr->len), len);
				break;
			}
			switch (ntohs(attr->attr)) {
				case STUN_USERNAME:
					st->username=(char*)attr->value;
					break;
				case STUN_PASSWORD:
					st->password=(char*)attr->value;
					break;
				case STUN_MAPPED_ADDRESS:
					maddr=stun_addr_message((struct stun_addr*)attr->value);
					break;
				case STUN_CHANGED_ADDRESS:
					caddr=stun_addr_message((struct stun_addr*)attr->value);
					break;
				case STUN_CHANGE_REQUEST:
					printf("Change Request Sent Value %d\n",ntohl(*(long*)attr->value));
					break;
				default:
					if (stundebug)
						printf("Ignoring STUN attribute %s (%04x), length %d\n", stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr), ntohs(attr->len));
					if (option_debug)
						printf("Failed to handle attribute %s (%04x)\n", stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr));
					break;
			}
			data += ntohs(attr->len) + sizeof(struct stun_attr);
			len -= ntohs(attr->len) + sizeof(struct stun_attr);
		}
	} else {
		return;
	}
		

	switch (ntohs(hdr->msgtype)) {
		case STUN_BINDREQ:
			stunmsg=stun_message();
			msglen=0;
			if (st->username) {
				msglen=stun_attr_string(st->username, STUN_USERNAME, stunmsg, msglen);
			}
			msglen+=stun_attr_addr(src,STUN_MAPPED_ADDRESS, stunmsg, msglen);
			stun_send(STUN_BINDRESP,st,stunmsg,msglen,0);
			break;
		case STUN_BINDRESP:
			switch (pcnt) {
				case 0:
					st->maddr=maddr;
					st->caddr=caddr;
					st->result |= STUN_NAT_SYMN;
					if ((st->bindaddr.sin_addr.s_addr == maddr.sin_addr.s_addr) && (st->bindaddr.sin_port == maddr.sin_port))
						st->result |= STUN_NAT_SYMF;
					stunmsg=stun_message();
					msglen=stun_attr_change(STUN_CHANGE_PORT | STUN_CHANGE_IP,stunmsg,0);
					stun_send(STUN_BINDREQ,st,stunmsg,msglen,1);
					break;
				case 1:
					if (st->result & STUN_NAT_SYMF) {
						st->result |= STUN_NAT_OPEN;
					} else {
						st->result |= STUN_NAT_FULL;
					}
					break;
				case 2:
					if ((maddr.sin_addr.s_addr == st->maddr.sin_addr.s_addr) && (maddr.sin_port == st->maddr.sin_port))
						st->result |= STUN_NAT_PORT;
					stunmsg=stun_message();
					msglen=stun_attr_change(STUN_CHANGE_PORT,stunmsg,0);
					stun_send(STUN_BINDREQ,st,stunmsg,msglen,3);
					break;
				case 3:
					st->result |= STUN_NAT_RES;
					break;
			}
			st->pcnt++;
			break;
	}
	return;
}

int main(int argc, char *argv[]) {
	struct hostent *hp;
	int flags;
	struct timeval tv;
	struct stun_state st;
        pthread_attr_t attr;
        pthread_t thread;

	gettimeofday(&tv, 0);
	srandom(tv.tv_sec + tv.tv_usec);

	hp=gethostbyname(argv[1]);
	memcpy(&stunserver.sin_addr, hp->h_addr, sizeof(stunserver.sin_addr));
	stunserver.sin_port = htons(3478);

	st.sock=socket(PF_INET,SOCK_DGRAM,0);
	flags = fcntl(st.sock, F_GETFL);
	fcntl(st.sock, F_SETFL, flags | O_NONBLOCK);

	st.bindaddr.sin_family=AF_INET;
	st.bindaddr.sin_addr.s_addr=inet_addr(argv[2]);
	st.bindaddr.sin_port=htons((random() % (65535-1023))+1023);
	bind(st.sock,(struct sockaddr *)&st.bindaddr,sizeof(struct sockaddr_in));

	pthread_attr_init(&attr);
	pthread_attr_setschedpolicy(&attr, SCHED_RR);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED);
	pthread_create(&thread, &attr, data_thread, &st);

	stun_send(STUN_BINDREQ,&st,NULL,0,0);

	while(1) {
		usleep(20000);
		gettimeofday(&tv,0);
		if ((tv.tv_sec*1000000+tv.tv_usec)-(st.laststun.tv_sec*1000000+st.laststun.tv_usec) > atoi(argv[3])*1000) {
			if ((st.result & STUN_NAT_SYMN) && (st.pcnt == 1)) {
				stun_send(STUN_BINDREQ,&st,NULL,0,2);
			} else {
				if (st.result < STUN_NAT_OPEN)
					printf("NEW IP:%s:%i Result: %i\n",inet_ntoa(st.bindaddr.sin_addr),ntohs(st.bindaddr.sin_port),st.result);
				else
					printf("NEW IP:%s:%i Result: %i\n",inet_ntoa(st.maddr.sin_addr),ntohs(st.maddr.sin_port),st.result);
				break;
			}
		}
	}
	pthread_attr_destroy(&attr);
	shutdown(st.sock,SHUT_RDWR);

	exit(0);
}
