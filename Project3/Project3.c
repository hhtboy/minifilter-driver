#include <windows.h>
#include <stdio.h>

// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_HELLO\
 CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

void printBuffer(const char* buffer, DWORD size) {
    printf("Buffer contents: ");
    for (DWORD i = 0; i < size; i++) {
        printf("%02X ", (unsigned char)buffer[i]);
    }
    printf("\n");
}

void decodeBuffer(char* buffer, DWORD size) {
    const UCHAR xorKey = 0x5A;  // 드라이버와 동일한 XOR 키
    for (DWORD i = 0; i < size; i++) {
        buffer[i] ^= xorKey;
    }
}

int main(int argc, char* argv[])
{
	HANDLE hDevice;
	DWORD dwBytesRead = 0;
	char ReadBuffer[50] = { 0 };

	// 디바이스 열기
	hDevice = CreateFile(L"\\\\.\\MyDevice", 
		GENERIC_WRITE | GENERIC_READ, 
		0, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);
	
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Failed to open device. Error: %d\n", GetLastError());
		return 1;
	}

	printf("Handle: %p\n", hDevice);

	// IOCTL 호출하여 인코딩된 메시지 받기
	if (!DeviceIoControl(hDevice, 
		IOCTL_HELLO, 
		NULL, 
		0, 
		ReadBuffer, 
		sizeof(ReadBuffer), 
		&dwBytesRead, 
		NULL))
	{
		printf("DeviceIoControl failed. Error: %d\n", GetLastError());
		CloseHandle(hDevice);
		return 1;
	}

	// 인코딩된 버퍼 출력
	printf("Received encoded message (%d bytes):\n", dwBytesRead);
	printBuffer(ReadBuffer, dwBytesRead);

	// 버퍼 디코딩
	decodeBuffer(ReadBuffer, dwBytesRead);
	
	// 디코딩된 메시지 출력
	printf("Decoded message: %s\n", ReadBuffer);

	CloseHandle(hDevice);
	return 0;
}