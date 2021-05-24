// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpncmgr.c
// VPN Client connection manager program

#ifdef _WINDOWS

#include <windows.h>
#include "n2n.h"
#ifdef WIN32
#include <sys/stat.h>
#endif


// WinMain function
// Initialize the Client Connection Manager

void InitCM(bool set_app_id)
{

	MsSetShutdownParameters(0x4ff, SHUTDOWN_NORETRY);
	InitWinUi(_UU("CM_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

}

// Stop the Client Connection Manager
void FreeCM()
{
	if (cm == NULL)
	{
		return;
	}

	CmFreeEnumHub();
	ReleaseCedar(cm->Cedar);

	FreeWinUi();

	// Release the memory
	if (cm->server_name != NULL)
	{
		Free(cm->server_name);
	}
	Free(cm);
	cm = NULL;
}


int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	InitProcessCallOnce();

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	CMExec();
	FreeMayaqua();
	return 0;
}
#endif

