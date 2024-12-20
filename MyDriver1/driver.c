#include <fltKernel.h>

PFLT_FILTER gFilterHandle = NULL;

// XOR Key for encoding
#define XOR_KEY 0xAA

// Define a stream context structure
typedef struct _MY_STREAM_CONTEXT {
    BOOLEAN IsTargetFile;
} MY_STREAM_CONTEXT, *PMY_STREAM_CONTEXT;

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);
FLT_PREOP_CALLBACK_STATUS
PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
);
FLT_POSTOP_CALLBACK_STATUS
PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);
FLT_PREOP_CALLBACK_STATUS
PreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
);
FLT_POSTOP_CALLBACK_STATUS
PostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Define the callback functions
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        PreCreate,
        PostCreate
    },
    {
        IRP_MJ_READ,
        0,
        PreRead,
        PostRead
    },
    { IRP_MJ_OPERATION_END }
};

// Define the context registration
const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    {
        FLT_STREAM_CONTEXT,
        0,
        NULL, // Optional cleanup callback
        sizeof(MY_STREAM_CONTEXT),
        'txet' // Unique context tag
    },
    { FLT_CONTEXT_END }
};

// Update the filter registration structure
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration, // Register the context
    Callbacks,
    DriverUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

FLT_PREOP_CALLBACK_STATUS
PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PMY_STREAM_CONTEXT context = NULL;
    NTSTATUS status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&context);
    if (NT_SUCCESS(status)) {
        // Context already exists
        FltReleaseContext(context);
        return FLT_POSTOP_FINISHED_PROCESSING;
    } else if (status != STATUS_NOT_FOUND) {
        DbgPrint("[MyDriver1] Failed to get stream context. Status: 0x%X\n", status);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo;
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyDriver1] Failed to get file name information. Status: 0x%X\n", status);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyDriver1] Failed to parse file name information. Status: 0x%X\n", status);
        FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    UNICODE_STRING targetFileName;
    RtlInitUnicodeString(&targetFileName, L"test.txt");

    BOOLEAN isTargetFile = RtlEqualUnicodeString(&nameInfo->FinalComponent, &targetFileName, TRUE);
    if (isTargetFile) {
        DbgPrint("[MyDriver1] Target file (test.txt) opened: %wZ\n", &nameInfo->Name);
    }

    FltReleaseFileNameInformation(nameInfo);

    if (!isTargetFile) {
        // Not the target file; no need to set context
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Allocate a new context
    status = FltAllocateContext(FltObjects->Filter,
                                FLT_STREAM_CONTEXT,
                                sizeof(MY_STREAM_CONTEXT),
                                NonPagedPool,
                                (PFLT_CONTEXT*)&context);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[MyDriver1] Failed to allocate stream context. Status: 0x%X\n", status);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Initialize context
    RtlZeroMemory(context, sizeof(MY_STREAM_CONTEXT));
    context->IsTargetFile = TRUE;

    // Set the context
    PFLT_CONTEXT oldContext = NULL;
    status = FltSetStreamContext(FltObjects->Instance,
                                 FltObjects->FileObject,
                                 FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                 context,
                                 &oldContext);

    if (NT_SUCCESS(status)) {
        // Successfully set context
        DbgPrint("[MyDriver1] Stream context set for test.txt\n");
        FltReleaseContext(context);
    } else if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        DbgPrint("[MyDriver1] Stream context already exists for test.txt\n");
        // Another context already exists, release contexts
        FltReleaseContext(context);
        FltReleaseContext(oldContext);
    } else {
        DbgPrint("[MyDriver1] Failed to set stream context for test.txt. Status: 0x%X\n", status);
        FltReleaseContext(context);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);

    PMY_STREAM_CONTEXT context = NULL;
    NTSTATUS status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&context);
    if (NT_SUCCESS(status)) {
        if (context->IsTargetFile) {
            *CompletionContext = (PVOID)(ULONG_PTR)XOR_KEY;
            DbgPrint("[MyDriver1] PreRead processing test.txt\n");
            FltReleaseContext(context);
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        FltReleaseContext(context);
    } else {
        DbgPrint("[MyDriver1] Failed to get stream context in PreRead. Status: 0x%X\n", status);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (CompletionContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    UCHAR xorKey = (UCHAR)(ULONG_PTR)CompletionContext;

    if (NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Information > 0) {
        SIZE_T bytesRead = Data->IoStatus.Information;
        DbgPrint("[MyDriver1] Processing %zu bytes of test.txt\n", bytesRead);

        if (Data->Iopb->Parameters.Read.MdlAddress != NULL) {
            PVOID buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority);
            if (buffer != NULL) {
                PUCHAR byteBuffer = (PUCHAR)buffer;
                for (SIZE_T i = 0; i < bytesRead; i++) {
                    byteBuffer[i] ^= xorKey;
                }
            }
        } else if (Data->Iopb->Parameters.Read.ReadBuffer != NULL) {
            PUCHAR buffer = (PUCHAR)Data->Iopb->Parameters.Read.ReadBuffer;
            for (SIZE_T i = 0; i < bytesRead; i++) {
                buffer[i] ^= xorKey;
            }
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
DriverUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("[MyDriver1] Driver unloading...\n");
    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(gFilterHandle);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[MyDriver1] Failed to start filtering. Status: 0x%X\n", status);
            FltUnregisterFilter(gFilterHandle);
        }
    } else {
        DbgPrint("[MyDriver1] Failed to register filter. Status: 0x%X\n", status);
    }
    return status;
}
