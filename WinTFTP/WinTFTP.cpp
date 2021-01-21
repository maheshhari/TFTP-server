#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNING
#define WIN32_LEAN_AND_MEAN

#undef UNICODE

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "WinTFTP.h"

#pragma comment (lib, "Ws2_32.lib")

#define PORT 13337
#define MAX_SESSIONS 5
#define INVALID -1

HANDLE hHeap;
tftpSession* sessions[5];

tftpSession* allocateSession() {

	DWORD i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		if (sessions[i] == NULL)
			break;
	}
	if (i == MAX_SESSIONS) {
		printf("Sessions are full\n");
		return NULL;
	}

	tftpSession* session = (tftpSession*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(tftpSession));
	session->filename = (CHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);
	session->blkdata = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 512);
	sessions[i] = session;
	return session;
}


tftpSession* findSession(sockaddr_in* addr) {

	DWORD i = 0;
	for (i = 0; i < MAX_SESSIONS; i++) {
		if (sessions[i] != NULL && (ULONG64)sessions[i] != -1) {
			if (sessions[i]->clientAddr.sin_addr.s_addr == addr->sin_addr.s_addr) {
				if (sessions[i]->clientAddr.sin_port == addr->sin_port) {
					printf("session already exists\n");
					return sessions[i];
				}
			}

		}
	}
	printf("Allocating new session\n");
	tftpSession* session = allocateSession();
	memcpy((VOID*)&session->clientAddr, addr, sizeof(sockaddr_in));
	session->blocksz = 512;
	return session;
}


INT terminateSession(tftpSession* session, BOOL FLAG) {
	CloseHandle(session->hFile);
	HeapFree(hHeap, NULL, session->filename);
	HeapFree(hHeap, NULL, session->blkdata);
	HeapFree(hHeap, NULL, session);

	DWORD i = 0;
	for (i = 0; i < MAX_SESSIONS; i++) {
		if (sessions[i] != NULL) {
			if (sessions[i]->clientAddr.sin_addr.s_addr == session->clientAddr.sin_addr.s_addr) {
				if (sessions[i]->clientAddr.sin_port == session->clientAddr.sin_port) {
					sessions[i] = NULL;
					if (FLAG == true)
						sessions[i] = (tftpSession*)INVALID;
				}
			}
		}
	}
	return NULL;
}


INT sendError(INT code, tftpSession* session) {

	tftpPacket* sPacket = (tftpPacket*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(tftpPacket));
	sPacket->opcode = ERR;
	sPacket->err.errCode = code;
	memcpy(sPacket->err.errMsg, session->filename, sizeof(sPacket->err.errMsg));
	printf("Error: %d\n", code);

	INT result = sendto(session->sock, (CHAR*)sPacket, sizeof(tftpPacket), 0,
		(SOCKADDR*)&session->clientAddr, sizeof(session->clientAddr));
	if (result == SOCKET_ERROR) {
		printf("sendto failed with error: %d\n", WSAGetLastError());
		closesocket(session->sock);
		WSACleanup();
		return 1;
	}

	return 0;
}

INT sendData(tftpSession* session) {
	if (session->opcode != RRQ)
		return -1;

	BOOL eof = false;

	// ReadFile
	OVERLAPPED overlapped = { 0 };
	overlapped.Offset = session->blocknr * 512;
	DWORD nIn = 0;
	if (!ReadFile(session->hFile, session->blkdata, session->blocksz, &nIn, &overlapped)) {
		printf("ReadFile failed with error %d\n", GetLastError());
		if (GetLastError() == 38) {
			eof = TRUE;
			printf("Reached EOF\n");
		}
	}

	// Initialize Packet
	tftpPacket* sPacket = (tftpPacket*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(tftpPacket));
	sPacket->opcode = DATA;
	sPacket->data.blocknr = session->blocknr;
	memcpy(sPacket->data.data, session->blkdata, 512);

	// Sending data
	INT result = sendto(session->sock, (CHAR*)sPacket, sizeof(tftpPacket), 0,
		(SOCKADDR*)&session->clientAddr, sizeof(session->clientAddr));
	if (result == SOCKET_ERROR) {
		printf("sendto failed with error: %d\n", WSAGetLastError());
		closesocket(session->sock);
		WSACleanup();
		return 1;
	}

	HeapFree(hHeap, 0, sPacket);

	if (eof) {
		printf("Terminating session\n");
		terminateSession(session, FALSE);
	}

	return 0;
}


INT handleReq(tftpPacket* packet, tftpSession* session, DWORD size) {

	// Check filename
	CHAR* reqFname = (CHAR*)&packet->req.filename;
	if (strstr(reqFname, "..\\") ||
		reqFname[strlen(reqFname) - 1] == '\\' ||
		strstr(reqFname, "../") ||
		reqFname[strlen(reqFname) - 1] == '/') {
		sendError(accessviolation, session);
		terminateSession(session, TRUE);
		return -1;
	}

	packet->req.filename[MAX_PATH - 1] = (char)0;
	if (size > MAX_PATH)
		size = MAX_PATH;
	memcpy(session->filename, packet->req.filename, size); 

	session->blocksz = packet->req.blocksz;
	session->blocknr = 0;

	switch (session->opcode) {
	case RRQ: session->hFile = CreateFileA(session->filename, GENERIC_READ,
		FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_READONLY,
		NULL);
		if (session->hFile == INVALID_HANDLE_VALUE) {
			printf("CreateFileA failed with error %d\n", GetLastError());
			sendError(undefined, session);
			terminateSession(session, TRUE);
			return 0;
		}
		sendData(session);
		break;

	case WRQ: session->hFile = CreateFileA(session->filename, GENERIC_READ | GENERIC_WRITE,
		NULL, NULL,
		CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
		NULL);
		if (session->hFile == INVALID_HANDLE_VALUE) {
			printf("CreateFileA failed with error %d\n", GetLastError());
			sendError(fnf, session);
			return 0;
		}
		break;
	}

	return 0;
}

INT sendAck(tftpSession* session) {
	// Initialize Packet
	tftpPacket* sPacket = (tftpPacket*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(tftpPacket));
	sPacket->opcode = ACK;
	sPacket->ack.blocknr = session->blocknr;

	// Sending ack
	INT result = sendto(session->sock, (CHAR*)sPacket, sizeof(tftpPacket), 0,
		(SOCKADDR*)&session->clientAddr, sizeof(session->clientAddr));
	if (result == SOCKET_ERROR) {
		printf("sendto failed with error: %d\n", WSAGetLastError());
		closesocket(session->sock);
		WSACleanup();
		return 1;
	}

	return 0;
}


INT handleData(tftpPacket* packet, tftpSession* session, DWORD size) {
	if (session->opcode != WRQ)
		return -1;

	BOOL eof = FALSE;
	if (size >= 0 && size < 512) {
		printf("last packet\n");
		eof = TRUE;
	}
	session->blocknr = packet->data.blocknr;
	OVERLAPPED overlapped = { 0 };
	overlapped.Offset = session->blocknr * 512;
	DWORD nIn = 0;
	printf("blocknr = %d\n\n", session->blocknr);
	if (!WriteFile(session->hFile, packet->data.data, size, &nIn, &overlapped)) {
		printf("WriteFile failed with error %d\n", GetLastError());
		}

	sendAck(session);
	if (eof == TRUE)
		terminateSession(session, FALSE);
	return 0;
}


INT handleAck(tftpPacket* packet, tftpSession* session) {

	if (packet->data.blocknr == session->blocknr && session->opcode == RRQ) {
		printf("ack no: %d\n", session->blocknr);
		session->blocknr++;
		sendData(session);
	}

	return 0;
}



INT main(void) {


	INT result;
	WSADATA wsaData;
	SOCKET ServerSocket;
	sockaddr_in ServerAddr;
	sockaddr_in ClientAddr;
	INT clientAddrSize = sizeof(sockaddr_in);

	hHeap = HeapCreate(0, 0, 0);

	// Setup
	result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0) {
		printf("WSAStartup failed with error: %d\n", result);
		ExitProcess(EXIT_FAILURE);
	}

	// Create socket
	ServerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ServerSocket == INVALID_SOCKET) {
		printf("socket failed with error %d\n", WSAGetLastError());
		ExitProcess(EXIT_FAILURE);
	}

	// Initialize structure
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(PORT);
	inet_pton(AF_INET, "127.0.0.1", &(ServerAddr.sin_addr));

	// Bind socket to port
	result = bind(ServerSocket, (sockaddr*)&ServerAddr, sizeof(sockaddr_in));
	if (result != 0) {
		printf("bind failed with error %d\n", WSAGetLastError());
	}

	// Allocate memory to store incoming packet
	tftpPacket* rPacket = (tftpPacket*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(tftpPacket));

	// Revc packet 
	DWORD nIn=0;
	while (1) {
		RtlZeroMemory(rPacket, sizeof(tftpPacket));
		nIn = recvfrom(ServerSocket, (CHAR*)rPacket, sizeof(tftpPacket), 0, (sockaddr*)&ClientAddr, &clientAddrSize);
		if (nIn == SOCKET_ERROR && WSAGetLastError() != WSAECONNRESET) {
			printf("recvfrom failed with error %d\n", WSAGetLastError());
			closesocket(ServerSocket);
			WSACleanup();
			ExitProcess(EXIT_FAILURE);
		}

		CHAR ipv4[INET_ADDRSTRLEN];
		tftpSession* session = findSession(&ClientAddr);
		inet_ntop(AF_INET, &(session->clientAddr.sin_addr), ipv4, INET_ADDRSTRLEN);
		printf("Details of Client :\n");
		printf("ip : %s\n", ipv4);
		printf("port : %d\n", session->clientAddr.sin_port);
		printf("opcode = %d\n", rPacket->opcode);
		session->sock = ServerSocket;
		printf("Packet size = %d\n", nIn);
		// Handle Packet
		switch (rPacket->opcode) {
		case RRQ:;
		case WRQ: session->opcode = rPacket->opcode;
			handleReq(rPacket, session, nIn - 4);
			break;
		case DATA: handleData(rPacket, session, nIn - 4);
			break; 
		case ACK: handleAck(rPacket, session);
			break;
		case ERR: 
			break;
		}

	HeapFree(hHeap, NULL, rPacket);
	}

	result = closesocket(ServerSocket);
	if (result == SOCKET_ERROR) {
		printf("closesocket failed with error %d\n", WSAGetLastError());
		ExitProcess(EXIT_FAILURE);
	}

	WSACleanup();
	return 0;
}
