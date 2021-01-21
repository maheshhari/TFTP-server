#pragma once
#include<Windows.h>

enum opcode {
	RRQ = 1,
	WRQ,
	DATA,
	ACK,
	ERR
};

enum errcode {
	undefined,
	fnf,
	accessviolation,
	illegaltftpop,
	unknowntransferid,
};

typedef struct{

	USHORT opcode;
	union {
		struct {
			char filename[MAX_PATH];
			UINT16 blocksz;
		} req;

		struct {
			USHORT blocknr;
			char data[0x200];
		} data;

		struct {
			USHORT blocknr;
		} ack;

		struct {
			USHORT errCode;
			char errMsg[0x50];
		} err;
	};
} tftpPacket;


typedef struct {
	USHORT opcode;
	char* filename;
	HANDLE hFile;
	SOCKET sock;

	struct sockaddr_in clientAddr;
	USHORT clientPort;
	UINT32 blocknr;
	UINT16 blocksz;
	char* blkdata;

	int timestamp;
} tftpSession;

