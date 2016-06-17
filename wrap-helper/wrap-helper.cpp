// wrap-helper.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


static HWND WINAPI getIdaHwnd() { return((HWND)callui(ui_get_hwnd).vptr); }

static HMODULE myModuleHandle = NULL;

int idaapi IDAP_init();
void idaapi IDAP_term();
void idaapi IDAP_run(int arg);
extern void StartPlugin(int iArg);
// === Data ===
static char IDAP_comment[] = "";
static char IDAP_help[] = "";
static char IDAP_name[] = "Wrap VFTable";

// Plug-in description block
extern "C" ALIGN(16) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	PLUGIN_PROC,            // Plug-in flags
	IDAP_init,	            // Initialization function
	IDAP_term,	            // Clean-up function
	IDAP_run,	            // Main plug-in body
	IDAP_comment,	        // Comment
	IDAP_help,	            // Help
	IDAP_name,	            // Plug-in name shown in Edit->Plugins menu
	NULL	                // Hot key to run the plug-in
};

int idaapi IDAP_init()
{
	if (strcmp(inf.procName, "metapc") == 0) // (ph.id == PLFM_386)
	{
		if (!init_hexrays_plugin())
			return PLUGIN_SKIP; // no decompiler

		GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR)&IDAP_init, &myModuleHandle);
		return(PLUGIN_KEEP);
	}
	return(PLUGIN_SKIP);
}


void idaapi IDAP_term()
{
	term_hexrays_plugin();
}

void idaapi IDAP_run(int arg)
{
	StartPlugin(arg);
}
