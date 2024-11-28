#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma warning(disable:4127)

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define BUFFER_SIZE 1024
const UCHAR XOR_KEY = 0x5A;  // 암호화 키

#define DEBUG_TRACE_ERROR   1
#define DEBUG_TRACE_NORMAL  2
#define DEBUG_TRACE_VERBOSE 3

#define DEBUG_TRACE_LEVEL DEBUG_TRACE_VERBOSE

#if DBG && (DEBUG_TRACE_LEVEL > 0)
    #define DbgPrintEx(Level, Message, ...) \
        if (Level <= DEBUG_TRACE_LEVEL) { \
            DbgPrint("[MyDriver1] " Message, __VA_ARGS__); \
        }
#else
    #define DbgPrintEx(Level, Message, ...)
#endif

/*
 * 프로토타입 선언
 */
DRIVER_INITIALIZE DriverEntry;
NTSTATUS UnloadDriver(FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS PreReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// 파일이 .txt인지 확인하는 함수
BOOLEAN IsTextFile(PUNICODE_STRING FileName) {
    if (FileName->Length < 8) return FALSE;  // ".txt"의 최소 길이

    PWCHAR ptr = &FileName->Buffer[FileName->Length/sizeof(WCHAR) - 4];
    return (_wcsnicmp(ptr, L".txt", 4) == 0);
}

// 버퍼 암호화/복호화 함수
VOID EncryptDecryptBuffer(PVOID Buffer, ULONG Length) {
    PUCHAR byteBuffer = (PUCHAR)Buffer;
    for (ULONG i = 0; i < Length; i++) {
        byteBuffer[i] ^= XOR_KEY;
    }
}

// 콜백 작업 등록
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_READ,
        0,
        PreReadOperation,
        PostReadOperation
    },
    {
        IRP_MJ_OPERATION_END
    }
};

// 필터 등록 데이터
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    UnloadDriver,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// Pre-Read 콜백 함수
FLT_PREOP_CALLBACK_STATUS PreReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo;
    NTSTATUS status;
    
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    DbgPrint("PreReadOperation: File read attempt detected\n");

    // 파일 이름 정보 가져오기
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (NT_SUCCESS(status)) {
        // 파일 이름 파싱
        status = FltParseFileNameInformation(nameInfo);
        
        if (NT_SUCCESS(status)) {
            // 모든 파일 접근에 대해 로그 출력
            DbgPrint("File Access: %wZ\n", &nameInfo->Name);
            
            // .txt 파일인 경우에만 처리
            if (IsTextFile(&nameInfo->Name)) {
                DbgPrint("=== TXT File Read Detected ===\n");
                DbgPrint("File Path: %wZ\n", &nameInfo->Name);
                DbgPrint("File Size: %lld bytes\n", Data->Iopb->Parameters.Read.Length);
                DbgPrint("Read Offset: %lld\n", Data->Iopb->Parameters.Read.ByteOffset.QuadPart);
                *CompletionContext = (PVOID)TRUE;  // Post-operation에서 처리하도록 표시
            }
        }
        FltReleaseFileNameInformation(nameInfo);
    } else {
        DbgPrint("Failed to get file information. Status: 0x%X\n", status);
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Post-Read 콜백 함수
FLT_POSTOP_CALLBACK_STATUS PostReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    // .txt 파일이고 읽기 작업이 성공한 경우에만 처리
    if (CompletionContext && NT_SUCCESS(Data->IoStatus.Status)) {
        PVOID buffer;
        ULONG length;

        // 버퍼와 길이 가져오기
        length = (ULONG)Data->Iopb->Parameters.Read.Length;
        buffer = Data->Iopb->Parameters.Read.ReadBuffer;

        if (buffer && length > 0) {
            DbgPrint("=== Starting Buffer Decryption ===\n");
            DbgPrint("Buffer Size: %d bytes\n", length);
            
            // 버퍼 복호화
            EncryptDecryptBuffer(buffer, length);
            
            DbgPrint("Buffer Decryption Complete\n");
            DbgPrint("============================\n");
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// 드라이버 언로드 함수
NTSTATUS UnloadDriver(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
    }
    
    DbgPrint("Driver Unloaded\n");
    return STATUS_SUCCESS;
}

// 드라이버 엔트리 포인트
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    // 드라이버 로드 시 디버그 메시지 출력
    DbgPrint("==============================================\n");
    DbgPrint("MyDriver1: 드라이버가 로드되었습니다!\n");
    DbgPrint("==============================================\n");

    // 필터 등록
    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &gFilterHandle);

    if (NT_SUCCESS(status)) {
        // 필터링 시작
        status = FltStartFiltering(gFilterHandle);
        
        if (!NT_SUCCESS(status)) {
            DbgPrint("MyDriver1: 필터링 시작 실패. Status: 0x%X\n", status);
            FltUnregisterFilter(gFilterHandle);
        }
        else {
            DbgPrint("MyDriver1: 필터링이 성공적으로 시작되었습니다.\n");
        }
    }
    else {
        DbgPrint("MyDriver1: 필터 등록 실패. Status: 0x%X\n", status);
    }

    return status;
}