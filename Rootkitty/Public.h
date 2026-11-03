/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_Rootkitty,
    0xcd4a8337,0x29e3,0x4fa4,0xa5,0x04,0x74,0x8e,0x40,0x12,0x94,0x8d);
// {cd4a8337-29e3-4fa4-a504-748e4012948d}
