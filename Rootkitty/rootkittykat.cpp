#include <ntifs.h>


// An IOCTL code is just an 32bit interger that packs different parameters together
// we calling it IOCTL_INVINCIBLE_PROCESS
// Custom IOCTL Code:
#define IOCTL_INVINCIBLE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
/*
	Parameters in order:
	FILE_DEVICE_UNKOWN			is just the devicetype
	0x803						is the function code,	|	unique id number set exclusively for this code. Must be in the range of 0x800-0xFFF because 0x000-0x7FF is reserved by microsoft for windows System commands
	METHOD_BUFFERED				is the transfer method	|	safest option. Tells windows to take whatever data our usermode program sends, allocate a safe buffer for it in kernel memory, and copy this data into this allocated buffer
	FILE_ANY_ACCESS				requires acces			| 

*/ 

UNICODE_STRING DeviceName;
UNICODE_STRING SymLinkName;

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

NTSTATUS DeviceControlHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {

}


NTSTATUS CreateCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

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