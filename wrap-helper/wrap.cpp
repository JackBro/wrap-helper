#include "stdafx.h"

#include "Vftable.h"
#include "RTTI.h"
#include <map>
typedef std::map<ea_t, std::string> STRMAP;

// Hex-Rays API pointer
hexdsp_t *hexdsp = NULL;

// Netnode constants
const static char NETNODE_NAME[] = { "$WRAPhelper_node" };
const char NN_DATA_TAG = 'A';
const char NN_TABLE_TAG = 'S';

// Our netnode value indexes
enum NETINDX
{
	NIDX_VERSION,   // ClassInformer version
	NIDX_COUNT      // Table entry count
};

// VFTable entry container (fits in a netnode MAXSPECSIZE size)
#pragma pack(push, 1)
struct TBLENTRY
{
	ea_t vft;
	WORD methods;
	WORD flags;
	WORD strSize;
	char str[MAXSPECSIZE - (sizeof(ea_t) + (sizeof(WORD) * 3))]; // IDA MAXSTR = 1024
};
#pragma pack(pop)

// Line background color for non parent/top level hierarchy lines
// TOOD: Assumes text background is white. A way to make these user theme/style color aware?
#define GRAY(v) RGB(v,v,v)
static const bgcolor_t NOT_PARENT_COLOR = GRAY(235);

// === Function Prototypes ===
static BOOL processStaticTables();
static BOOL getRttiData();

// === Data ===
static TIMESTAMP s_startTime = 0;
static HMODULE myModuleHandle = NULL;
static UINT staticCCtorCnt = 0, staticCppCtorCnt = 0, staticCDtorCnt = 0;
static UINT startingFuncCount = 0, staticCtorDtorCnt = 0;
static BOOL uiHookInstalled = FALSE;
static int  chooserIcon = 0;
static netnode *netNode = NULL;
static eaList colList;

// Options
BOOL optionPlaceStructs = TRUE;
BOOL optionProcessStatic = TRUE;
BOOL optionOverwriteComments = FALSE;

static WORD getStoreVersion() { return((WORD)netNode->altval_idx8(NIDX_VERSION, NN_DATA_TAG)); }
static UINT getTableCount() { return(netNode->altval_idx8(NIDX_COUNT, NN_DATA_TAG)); }
static BOOL setTableCount(UINT count) { return(netNode->altset_idx8(NIDX_COUNT, count, NN_DATA_TAG)); }
static BOOL getTableEntry(TBLENTRY &entry, UINT index) { return(netNode->supval(index, &entry, sizeof(TBLENTRY), NN_TABLE_TAG) > 0); }
static BOOL setTableEntry(TBLENTRY &entry, UINT index) { return(netNode->supset(index, &entry, (offsetof(TBLENTRY, str) + entry.strSize), NN_TABLE_TAG)); }

struct vftable_info_t
{
	TForm *form;
	TCustomControl *cv;
	TCustomControl *codeview;
	strvec_t sv;
	vftable_info_t(TForm *f) : form(f), cv(NULL) {}
};

static int current_line_pos = 0;

static qstring get_vtbl_hint(int line_num)
{
	current_line_pos = line_num;
	qstring tag_lines;

	TBLENTRY e;
	getTableEntry(e, line_num);

	if (isEnabled(e.vft))
	{
		int flags = calc_default_idaplace_flags();
		linearray_t ln(&flags);

		idaplace_t here;
		here.ea = e.vft;
		here.lnnum = 0;
		ln.set_place(&here);

		int used = 0;
		int n = ln.get_linecnt();
		for (int i = 0; i < n; i++)
		{
			char hint_str[MAXSTR];
			char* line = ln.down();
			tag_remove(line, hint_str, sizeof(hint_str));
			tag_lines.cat_sprnt((COLSTR(SCOLOR_INV"%s\n", SCOLOR_DREF)), hint_str);
			used++;
			int n = qmin(ln.get_linecnt(), 20);
			used += n;
			for (int j = 0; j < n; ++j)
				tag_lines.cat_sprnt("%s\n", ln.down());
		}

	}
	return qstrdup(tag_lines.c_str());
}


int idaapi ui_vftable_callback(void *ud, int code, va_list va)
{
	vftable_info_t *si = (vftable_info_t *)ud;
	switch (code)
	{
	case ui_get_custom_viewer_hint:
	{
		TCustomControl *viewer = va_arg(va, TCustomControl *);
		place_t *place = va_arg(va, place_t *);
		int *important_lines = va_arg(va, int *);
		qstring &hint = *va_arg(va, qstring *);

		if (si->cv == viewer)
		{
			if (place == NULL)
				return 0;

			simpleline_place_t *spl = (simpleline_place_t *)place;
			hint = get_vtbl_hint(spl->n);
			*important_lines = 20;
			return 1;
		}
		break;
	}
	case ui_tform_invisible:
	{
		TForm *f = va_arg(va, TForm *);
		if (f == si->form)
		{
			delete si;
			unhook_from_notification_point(HT_UI, ui_vftable_callback, NULL);
		}
	}
	break;
	}
	return 0;
}

int create_open_file(const char* file_name) {
	int file_id = qopen(file_name, O_BINARY | O_TRUNC | O_CREAT);
	if (file_id == BADADDR)
		file_id = qcreate(file_name, 511);

	return file_id;
}

char header_filename[30];
static bool idaapi make_code_cpp(void *ud)
{
	TBLENTRY e;
	getTableEntry(e, current_line_pos);
	sprintf(header_filename, EAFORMAT "_h.cpp", e.vft);
	int file_id = create_open_file(header_filename);
	if (file_id != -1)
	{
		ea_t ea = e.vft;
		ea_t vtbl_addr_end = e.vft + (sizeof(ea_t) * e.methods);
		int vf_idx = 0;

		qstring header = "//!vftable wrap function generator V.0.000001 By Acaz\r\n";
		header.cat_sprnt("//!RTTI name %s \r\n", e.str);
		header.cat_sprnt("//!Totals function %d \r\n", e.methods);
		header += "//!Have a nice day.\r\n\r\n";

		qwrite(file_id, header.c_str(), header.length());

		while (ea < vtbl_addr_end) 
		{
			qstring method_name;
			qstring dump_line = "inline ";
			ea_t method_ea = getEa(ea);

			if (method_ea == 0) break;
			if (!isEnabled(method_ea)) break;

			flags_t method_flags = getFlags(method_ea);
			if (isFunc(method_flags)) {
				method_name = get_short_name(method_ea);
				if (method_name.length() != 0)
				{
					func_t *f = get_func(method_ea);
					if (f == NULL)
						break;

					hexrays_failure_t hf;
					cfuncptr_t cfunc = decompile(f, &hf);
					if (cfunc != NULL)
					{
						tinfo_t type;
						cfunc->get_func_type(&type);
		
						//!--ret type
						qstring rettype_str = "";
						tinfo_t ret_type =  type.get_rettype();
						ret_type.print(&rettype_str, NULL, PRTYPE_DEF | PRTYPE_1LINE | PRTYPE_CPP);

						//!--calling conversion
						bool is_thiscall = false;
						qstring cc_str = "";
						cm_t cc_type = type.get_cc();
						switch (cc_type)
						{
							case CM_CC_CDECL:
							{
								cc_str = "__cdecl";
								break;
							}
							case CM_CC_STDCALL:
							{
								cc_str = "__stdcall";
								break;
							}
							case CM_CC_FASTCALL:
							{
								cc_str = "__fastcall";
								break;
							}
							case CM_CC_THISCALL:
							{
								cc_str = "__thiscall";
								is_thiscall = true;
								break;
							}
						}
						
						method_name.replace("::", "_");
						method_name.replace("`vector deleting destructor'", "vec_del");
						size_t pos_ag = method_name.find("(");
						if (pos_ag > 0)
						{
							method_name.remove(pos_ag, method_name.size() - pos_ag);
						}

						dump_line.cat_sprnt("//!--IDX %d\r\n", vf_idx);

						if (rettype_str.size() > 0)
						{
							dump_line += rettype_str;
						}
						if (cc_str.size() > 0)
						{
							dump_line += " ";
							dump_line += cc_str;
						}
						if (method_name.size() > 0)
						{
							dump_line += " ";
							dump_line += method_name;
						}
						
						qstring args_str;
						qstring args_type_str;
						qstring args_val_str;
						if (type.get_nargs() > 0)
						{
							int vidx = 0;
							args_str += "(";
							args_type_str += "(";
							args_val_str += "(";
							if (is_thiscall == true)
							{
								if (vidx + 1 < type.get_nargs())
								{
									args_type_str += "void *,";
									args_val_str += "(void*)this,";
								}
								else
								{
									args_type_str += "void *";
									args_val_str += "(void*)this";
								}

								vidx = 1;
							}
							for (; vidx < type.get_nargs(); ++vidx)
							{
								qstring v_str = "";
								qstring vname_str = "";
								tinfo_t v_type = type.get_nth_arg(vidx);
								vname_str.sprnt("_param_%d", vidx);
								v_type.print(&v_str, NULL, PRTYPE_DEF | PRTYPE_1LINE | PRTYPE_CPP);
								if (v_str.size() > 0)
								{
									args_str += " ";
									args_str += v_str;
									args_type_str += v_str;
									if (vname_str.size() > 0)
									{
										args_str += " ";
										args_str += vname_str;
										args_val_str += vname_str;
										if (vidx + 1 < type.get_nargs())
										{
											args_str += ",";
											args_type_str += ",";
											args_val_str += ",";
										}
									}
								}
							}
							args_str += ")";
							args_type_str += ")";
							args_val_str += ")";
						}
						else
						{
							args_str += "();";
							args_type_str += "()";
							args_val_str += "()";
						}
						dump_line += args_str;
						dump_line += "\r\n{\r\n";
						dump_line += "\t\t((";
						dump_line += rettype_str;
						dump_line += "(";
						dump_line += cc_str;
						dump_line += "*)";
						dump_line += args_type_str;
						dump_line += ")";
						dump_line += "((DWORD)";
						dump_line.cat_sprnt("0x" EAFORMAT, method_ea);
						dump_line += "))";
						dump_line += args_val_str;
						dump_line += "";
						dump_line += ";\r\n}\r\n";
					}
				}
			}

			dump_line += "\n";
			qwrite(file_id, dump_line.c_str(), dump_line.length());

			ea = ea + sizeof(ea_t);
			flags_t ea_flags = getFlags(ea);

			vf_idx++;
			if (has_any_name(ea_flags)) break;
		}

		qclose(file_id);
	}
	return true;
}


static void idaapi ct_vftable_popup(TCustomControl *v, void *ud)
{
	set_custom_viewer_popup_menu(v, NULL);
	add_custom_viewer_popup_item(v, "Generate Code", "", make_code_cpp, ud);
}

static bool idaapi ct_vftable_dblclick(TCustomControl *v, int shift, void *ud)
{
	int x, y;
	place_t *place = get_custom_viewer_place(v, true, &x, &y);
	simpleline_place_t *spl = (simpleline_place_t *)place;
	int line_num = spl->n;

	TBLENTRY e;
	getTableEntry(e, line_num);

	ea_t cur_vt_ea = e.vft;
	jumpto(cur_vt_ea);

	return true;
}

char simplebuffer_addr[16];
char simplebuffer_name[1024];
char simplebuffer_all[2048];
void vftable_form_init()
{
	if (getTableCount()>0)
	{
		HWND hwnd = NULL;
		TForm *form = create_tform("VFTable list", &hwnd);
		if (hwnd == NULL)
		{
			form = find_tform("VFTable list");
			if (form != NULL)
				switchto_tform(form, true);
			return;
		}

		vftable_info_t *si = new vftable_info_t(form);

		qstring simple_line;

		for (UINT n = 0; n < getTableCount(); ++n)
		{
			TBLENTRY e;
			getTableEntry(e, n);
			// vft address
			sprintf(simplebuffer_addr, EAFORMAT, e.vft);

			// Type
			LPCSTR tag = strchr(e.str, '@');
			if (tag)
			{
				size_t pos = (tag - e.str);
				memcpy(simplebuffer_name, e.str, pos);
				simplebuffer_name[pos] = 0;
				++tag;
			}
			sprintf(simplebuffer_all, "[%s] - %s (%u)", simplebuffer_addr, simplebuffer_name , e.methods);
			simple_line = simplebuffer_all;
			si->sv.push_back(simple_line);
		}

		
		simpleline_place_t s1;
		simpleline_place_t s2(si->sv.size() - 1);
		si->cv = create_custom_viewer("", NULL, &s1, &s2, &s1, 0, &si->sv);
		si->codeview = create_code_viewer(form, si->cv, CDVF_STATUSBAR);

		set_custom_viewer_handlers(si->cv, NULL, ct_vftable_popup, NULL, ct_vftable_dblclick, NULL, NULL, si);

		hook_to_notification_point(HT_UI, ui_vftable_callback, si);
		open_tform(form, FORM_TAB | FORM_MENU | FORM_RESTORE);
	}
}

static bool idaapi display_vtbl_objects()
{
	vftable_form_init();
	return false;
}


static void freeWorkingData()
{
	try
	{
		if (uiHookInstalled)
		{
			uiHookInstalled = FALSE;
		}

		if (chooserIcon)
		{
			free_custom_icon(chooserIcon);
			chooserIcon = 0;
		}

		RTTI::freeWorkingData();
		colList.clear();

		if (netNode)
		{
			delete netNode;
			netNode = NULL;
		}
	}
	CATCH()
}

// Init new netnode storage
static void newNetnodeStore()
{
	// Kill any existing store data first
	netNode->supdel_all(NN_DATA_TAG);
	netNode->supdel_all(NN_TABLE_TAG);

	// Init defaults
	netNode->altset_idx8(NIDX_VERSION, MY_VERSION, NN_DATA_TAG);
	netNode->altset_idx8(NIDX_COUNT, 0, NN_DATA_TAG);
}


// Add an entry to the vftable list
void addTableEntry(UINT flags, ea_t vft, int methodCount, LPCTSTR format, ...)
{
	TBLENTRY e;
	e.vft = vft;
	e.methods = methodCount;
	e.flags = flags;
	e.str[SIZESTR(e.str)] = 0;

	va_list vl;
	va_start(vl, format);
	_vsntprintf(e.str, SIZESTR(e.str), format, vl);
	va_end(vl);
	e.strSize = (WORD)(strlen(e.str) + 1);

	UINT count = getTableCount();
	setTableEntry(e, count);
	setTableCount(++count);
}


static HWND WINAPI getIdaHwnd() { return((HWND)callui(ui_get_hwnd).vptr); }

void StartPlugin(int arg)
{
	try
	{
		char version[16];
		sprintf(version, "%u.%u", HIBYTE(MY_VERSION), LOBYTE(MY_VERSION));
		if (!autoIsOk())
		{
			msg("** Class Informer: Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
			return;
		}

		freeWorkingData();
		optionProcessStatic = TRUE;
		optionOverwriteComments = FALSE;
		optionPlaceStructs = TRUE;
		startingFuncCount = get_func_qty();
		colList.clear();
		staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;

		// Create storage netnode
		if (!(netNode = new netnode(NETNODE_NAME, SIZESTR(NETNODE_NAME), TRUE)))
		{
			QASSERT(66, FALSE);
			return;
		}

		UINT tableCount = getTableCount();
		BOOL aborted = FALSE;
		if (1 == 1)
		{
			newNetnodeStore();

			// Only MS Visual C++ targets are supported
			comp_t cmp = get_comp(default_compiler());
			if (cmp != COMP_MS)
			{
				msg("** IDA reports target compiler: \"%s\"\n", get_compiler_name(cmp));
				int iResult = askbuttons_c(NULL, NULL, NULL, 0, "HIDECANCEL\nIDA reports this IDB's compiler as: \"%s\" \n\nThis plug-in only understands MS Visual C++ targets.\nRunning it on other targets (like Borland© compiled, etc.) will have unpredicted results.   \n\nDo you want to continue anyhow?", get_compiler_name(cmp));
				if (iResult != 1)
				{
					msg("- Aborted -\n\n");
					return;
				}
			}


			msg("Working..\n");


			// Add structure definitions to IDA once per session
			static BOOL createStructsOnce = FALSE;
			if (optionPlaceStructs && !createStructsOnce)
			{
				createStructsOnce = TRUE;
				RTTI::addDefinitionsToIda();
			}

			if (optionProcessStatic)
			{
				// Process global and static ctor sections
				msg("\nProcessing C/C++ ctor & dtor tables.\n");
				if (!(aborted = processStaticTables()))
					msg("Processing time: %s.\n", timeString(getTimeStamp() - s_startTime));
			}

			if (!aborted)
			{
				// Get RTTI data
				if (!(aborted = getRttiData()))
				{
					msg("Done.\n\n");
					display_vtbl_objects();
				}
			}

			refresh_idaview_anyway();
			if (aborted)
			{
				msg("- Aborted -\n\n");
				return;
			}
		}

		// Show list result window
		if (!aborted && (getTableCount() > 0))
		{
			
		}
	}
	CATCH()
}


// ================================================================================================

// Fix/create label and comment C/C++ initializer tables
static void setIntializerTable(ea_t start, ea_t end, BOOL isCpp)
{
	try
	{
		if (UINT count = ((end - start) / sizeof(ea_t)))
		{
			// Set table elements as pointers
			ea_t ea = start;
			while (ea <= end)
			{
				fixEa(ea);

				// Might fix missing/messed stubs
				if (ea_t func = get_32bit(ea))
					fixFunction(func);

				ea += sizeof(ea_t);
			};

			// Start label
			if (!hasUniqueName(start))
			{
				char name[MAXSTR]; name[SIZESTR(name)] = 0;
				if (isCpp)
					_snprintf(name, SIZESTR(name), "__xc_a_%d", staticCppCtorCnt);
				else
					_snprintf(name, SIZESTR(name), "__xi_a_%d", staticCCtorCnt);
				set_name(start, name, (SN_NON_AUTO | SN_NOWARN));
			}

			// End label
			if (!hasUniqueName(end))
			{
				char name[MAXSTR]; name[SIZESTR(name)] = 0;
				if (isCpp)
					_snprintf(name, SIZESTR(name), "__xc_z_%d", staticCppCtorCnt);
				else
					_snprintf(name, SIZESTR(name), "__xi_z_%d", staticCCtorCnt);
				set_name(end, name, (SN_NON_AUTO | SN_NOWARN));
			}

			// Comment
			// Never overwrite, it might be the segment comment
			if (!hasAnteriorComment(start))
			{
				if (isCpp)
					add_long_cmt(start, TRUE, "%d C++ static ctors (#classinformer)", count);
				else
					add_long_cmt(start, TRUE, "%d C initializers (#classinformer)", count);
			}
			else
				// Place comment @ address instead
				if (!has_cmt(get_flags_novalue(start)))
				{
					char comment[MAXSTR]; comment[SIZESTR(comment)] = 0;
					if (isCpp)
					{
						_snprintf(comment, SIZESTR(comment), "%d C++ static ctors (#classinformer)", count);
						set_cmt(start, comment, TRUE);
					}
					else
					{
						_snprintf(comment, SIZESTR(comment), "%d C initializers (#classinformer)", count);
						set_cmt(start, comment, TRUE);
					}
				}

			if (isCpp)
				staticCppCtorCnt++;
			else
				staticCCtorCnt++;
		}
	}
	CATCH()
}

// Fix/create label and comment C/C++ terminator tables
static void setTerminatorTable(ea_t start, ea_t end)
{
	try
	{
		if (UINT count = ((end - start) / sizeof(ea_t)))
		{
			// Set table elements as pointers
			ea_t ea = start;
			while (ea <= end)
			{
				fixEa(ea);

				// Fix function
				if (ea_t func = getEa(ea))
					fixFunction(func);

				ea += sizeof(ea_t);
			};

			// Start label
			if (!hasUniqueName(start))
			{
				char name[MAXSTR]; name[SIZESTR(name)] = 0;
				_snprintf(name, SIZESTR(name), "__xt_a_%d", staticCDtorCnt);
				set_name(start, name, (SN_NON_AUTO | SN_NOWARN));
			}

			// End label
			if (!hasUniqueName(end))
			{
				char name[MAXSTR]; name[SIZESTR(name)] = 0;
				_snprintf(name, SIZESTR(name), "__xt_z_%d", staticCDtorCnt);
				set_name(end, name, (SN_NON_AUTO | SN_NOWARN));
			}

			// Comment
			// Never overwrite, it might be the segment comment
			if (!hasAnteriorComment(start))
				add_long_cmt(start, TRUE, "%d C terminators (#classinformer)", count);
			else
				// Place comment @ address instead
				if (!has_cmt(get_flags_novalue(start)))
				{
					char comment[MAXSTR]; comment[SIZESTR(comment)] = 0;
					_snprintf(comment, SIZESTR(comment), "%d C terminators (#classinformer)", count);
					set_cmt(start, comment, TRUE);
				}

			staticCDtorCnt++;
		}
	}
	CATCH()
}

// "" for when we are uncertain of ctor or dtor type table
static void setCtorDtorTable(ea_t start, ea_t end)
{
	try
	{
		if (UINT count = ((end - start) / sizeof(ea_t)))
		{
			// Set table elements as pointers
			ea_t ea = start;
			while (ea <= end)
			{
				fixEa(ea);

				// Fix function
				if (ea_t func = getEa(ea))
					fixFunction(func);

				ea += sizeof(ea_t);
			};

			// Start label
			if (!hasUniqueName(start))
			{
				char name[MAXSTR]; name[SIZESTR(name)] = 0;
				_snprintf(name, SIZESTR(name), "__x?_a_%d", staticCtorDtorCnt);
				set_name(start, name, (SN_NON_AUTO | SN_NOWARN));
			}

			// End label
			if (!hasUniqueName(end))
			{
				char name[MAXSTR]; name[SIZESTR(name)] = 0;
				_snprintf(name, SIZESTR(name), "__x?_z_%d", staticCtorDtorCnt);
				set_name(end, name, (SN_NON_AUTO | SN_NOWARN));
			}

			// Comment
			// Never overwrite, it might be the segment comment
			if (!hasAnteriorComment(start))
				add_long_cmt(start, TRUE, "%d C initializers/terminators (#classinformer)", count);
			else
				// Place comment @ address instead
				if (!has_cmt(get_flags_novalue(start)))
				{
					char comment[MAXSTR]; comment[SIZESTR(comment)] = 0;
					_snprintf(comment, SIZESTR(comment), "%d C initializers/terminators (#classinformer)", count);
					set_cmt(start, comment, TRUE);
				}

			staticCtorDtorCnt++;
		}
	}
	CATCH()
}


// Process redister based _initterm() 
static void processRegisterInitterm(ea_t start, ea_t end, ea_t call)
{
	if ((end != BADADDR) && (start != BADADDR))
	{
		// Should be in the same segment
		if (getseg(start) == getseg(end))
		{
			if (start > end)
				swap_t(start, end);

			msg("    " EAFORMAT " to " EAFORMAT " CTOR table.\n", start, end);
			setIntializerTable(start, end, TRUE);
			set_cmt(call, "_initterm", TRUE);
		}
		else
			msg("  ** Bad address range of " EAFORMAT ", " EAFORMAT " for \"_initterm\" type ** <click address>.\n", start, end);
	}
}

static UINT doInittermTable(func_t *func, ea_t start, ea_t end, LPCTSTR name)
{
	UINT found = FALSE;

	if ((start != BADADDR) && (end != BADADDR))
	{
		// Should be in the same segment
		if (getseg(start) == getseg(end))
		{
			if (start > end)
				swap_t(start, end);

			// Try to determine if we are in dtor or ctor section
			if (func)
			{
				qstring qstr;
				if (get_long_name(&qstr, func->startEA) > 0)
				{
					char funcName[MAXSTR]; funcName[SIZESTR(funcName)] = 0;
					strncpy(funcName, qstr.c_str(), (MAXSTR - 1));
					_strlwr(funcName);

					// Start/ctor?
					if (strstr(funcName, "cinit") || strstr(funcName, "tmaincrtstartup") || strstr(funcName, "start"))
					{
						msg("    " EAFORMAT " to " EAFORMAT " CTOR table.\n", start, end);
						setIntializerTable(start, end, TRUE);
						found = TRUE;
					}
					else
						// Exit/dtor function?
						if (strstr(funcName, "exit"))
						{
							msg("    " EAFORMAT " to " EAFORMAT " DTOR table.\n", start, end);
							setTerminatorTable(start, end);
							found = TRUE;
						}
				}
			}

			if (!found)
			{
				// Fall back to generic assumption
				msg("    " EAFORMAT " to " EAFORMAT " CTOR/DTOR table.\n", start, end);
				setCtorDtorTable(start, end);
				found = TRUE;
			}
		}
		else
			msg("    ** Miss matched segment table addresses " EAFORMAT ", " EAFORMAT " for \"%s\" type **\n", start, end, name);
	}
	else
		msg("    ** Bad input address range of " EAFORMAT ", " EAFORMAT " for \"%s\" type **\n", start, end, name);

	return(found);
}

// Process _initterm function
// Returns TRUE if at least one found
static BOOL processInitterm(ea_t address, LPCTSTR name)
{
	msg(EAFORMAT" processInitterm: \"%s\" \n", address, name);
	UINT count = 0;

	// Walk xrefs
	ea_t xref = get_first_fcref_to(address);
	while (xref && (xref != BADADDR))
	{
		msg("  " EAFORMAT " \"%s\" xref.\n", xref, name);

		// Should be code
		if (isCode(get_flags_novalue(xref)))
		{
			do
			{
				// The most common are two instruction arguments
				// Back up two instructions
				ea_t instruction1 = prev_head(xref, 0);
				if (instruction1 == BADADDR)
					break;
				ea_t instruction2 = prev_head(instruction1, 0);
				if (instruction2 == BADADDR)
					break;

				// Bail instructions are past the function start now
				func_t *func = get_func(xref);
				if (func && (instruction2 < func->startEA))
				{
					//msg("   " EAFORMAT " arg2 outside of contained function **\n", func->startEA);
					break;
				}

				struct ARG2PAT
				{
					LPCSTR pattern;
					UINT start, end, padding;
				} static const ALIGN(16) arg2pat[] =
				{
#ifndef __EA64__
					{ "68 ?? ?? ?? ?? 68 ?? ?? ?? ??", 6, 1 },          // push offset s, push offset e
					{ "B8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ??", 8, 1 },    // mov [esp+4+var_4], offset s, mov eax, offset e   Maestia
					{ "68 ?? ?? ?? ?? B8 ?? ?? ?? ??", 6, 1 },          // mov eax, offset s, push offset e
#else
					{ "48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??", 3, 3 },  // lea rdx,s, lea rcx,e
#endif
				};
				BOOL matched = FALSE;
				for (UINT i = 0; (i < qnumber(arg2pat)) && !matched; i++)
				{
					ea_t match = find_binary(instruction2, xref, arg2pat[i].pattern, 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
					if (match != BADADDR)
					{
#ifndef __EA64__
						ea_t start = getEa(match + arg2pat[i].start);
						ea_t end = getEa(match + arg2pat[i].end);
#else
						UINT startOffset = get_32bit(instruction1 + arg2pat[i].start);
						UINT endOffset = get_32bit(instruction2 + arg2pat[i].end);
						ea_t start = (instruction1 + 7 + *((PINT)&startOffset)); // TODO: 7 is hard coded instruction length, put this in arg2pat table?
						ea_t end = (instruction2 + 7 + *((PINT)&endOffset));
#endif
						msg("  " EAFORMAT " Two instruction pattern match #%d\n", match, i);
						count += doInittermTable(func, start, end, name);
						matched = TRUE;
						break;
					}
				}

				// 3 instruction
				/*
				searchStart = prev_head(searchStart, BADADDR);
				if (searchStart == BADADDR)
				break;
				if (func && (searchStart < func->startEA))
				break;

				if (func && (searchStart < func->startEA))
				{
				msg("  " EAFORMAT " arg3 outside of contained function **\n", func->startEA);
				break;
				}

				.text:10008F78                 push    offset unk_1000B1B8
				.text:10008F7D                 push    offset unk_1000B1B0
				.text:10008F82                 mov     dword_1000F83C, 1
				"68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ??"
				*/

				if (!matched)
					msg("  ** arguments not located!\n");

			} while (FALSE);
		}
		else
			msg("  " EAFORMAT " ** \"%s\" xref is not code! **\n", xref, name);

		xref = get_next_fcref_to(address, xref);
	};

	msg(" \n");
	return(count > 0);
}


// Process global/static ctor & dtor tables.
// Returns TRUE if user aborted
static BOOL processStaticTables()
{
	staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;

	// x64 __tmainCRTStartup, _CRT_INIT

	try
	{
		// Locate _initterm() and _initterm_e() functions        
		STRMAP inittermMap;
		func_t  *cinitFunc = NULL;
		UINT funcCount = get_func_qty();
		for (UINT i = 0; i < funcCount; i++)
		{
			if (func_t *func = getn_func(i))
			{
				qstring qstr;
				if (get_long_name(&qstr, func->startEA) > 0)
				{
					char name[MAXSTR]; name[SIZESTR(name)] = 0;
					strncpy(name, qstr.c_str(), (MAXSTR - 1));

					int len = strlen(name);
					if (len >= SIZESTR("_cinit"))
					{
						if (strcmp((name + (len - SIZESTR("_cinit"))), "_cinit") == 0)
						{
							// Skip stub functions
							if (func->size() > 16)
							{
								msg(EAFORMAT" C: \"%s\", %d bytes.\n", func->startEA, name, func->size());
								_ASSERT(cinitFunc == NULL);
								cinitFunc = func;
							}
						}
						else
							if ((len >= SIZESTR("_initterm")) && (strcmp((name + (len - SIZESTR("_initterm"))), "_initterm") == 0))
							{
								msg(EAFORMAT" I: \"%s\", %d bytes.\n", func->startEA, name, func->size());
								inittermMap[func->startEA] = name;
							}
							else
								if ((len >= SIZESTR("_initterm_e")) && (strcmp((name + (len - SIZESTR("_initterm_e"))), "_initterm_e") == 0))
								{
									msg(EAFORMAT" E: \"%s\", %d bytes.\n", func->startEA, name, func->size());
									inittermMap[func->startEA] = name;
								}
					}
				}
			}
		}

		// Look for import versions
		{
			static LPCSTR imports[] =
			{
				"__imp__initterm", "__imp__initterm_e"
			};
			for (UINT i = 0; i < qnumber(imports); i++)
			{
				ea_t adress = get_name_ea(BADADDR, imports[i]);
				if (adress != BADADDR)
				{
					if (inittermMap.find(adress) == inittermMap.end())
					{
						msg(EAFORMAT" import: \"%s\".\n", adress, imports[i]);
						inittermMap[adress] = imports[i];
					}
				}
			}
		}

		// Process register based _initterm() calls inside _cint()
		if (cinitFunc)
		{
			struct CREPAT
			{
				LPCSTR pattern;
				UINT start, end, call;
			} static const ALIGN(16) pat[] =
			{
				{ "B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 59 8B F8 3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE 72 F1", 1, 6, 0x17 },
				{ "BE ?? ?? ?? ?? 8B C6 BF ?? ?? ?? ?? 3B C7 59 73 0F 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 F1", 1, 8, 0x17 },
			};

			for (UINT i = 0; i < qnumber(pat); i++)
			{
				ea_t match = find_binary(cinitFunc->startEA, cinitFunc->endEA, pat[i].pattern, 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
				while (match != BADADDR)
				{
					msg("  " EAFORMAT " Register _initterm(), pattern #%d.\n", match, i);
					ea_t start = getEa(match + pat[i].start);
					ea_t end = getEa(match + pat[i].end);
					processRegisterInitterm(start, end, (match + pat[i].call));
					match = find_binary(match + 30, cinitFunc->endEA, pat[i].pattern, 16, (SEARCH_NEXT | SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));
				};
			}
		}
		msg(" \n");

		// Process _initterm references
		for (STRMAP::iterator it = inittermMap.begin(); it != inittermMap.end(); ++it)
		{
			if (processInitterm(it->first, it->second.c_str()))
			{

			}
		}
	}
	CATCH()

		return(FALSE);
}

// ================================================================================================


// Return TRUE if address as a anterior comment
inline BOOL hasAnteriorComment(ea_t ea)
{
	return(get_first_free_extra_cmtidx(ea, E_PREV) != E_PREV);
}

// Delete any anterior comment(s) at address if there is some
inline void killAnteriorComments(ea_t ea)
{
	delete_extra_cmts(ea, E_PREV);
}

// Force a memory location to be DWORD size
void fixDword(ea_t ea)
{
	if (!isDwrd(get_flags_novalue(ea)))
	{
		setUnknown(ea, sizeof(DWORD));
		doDwrd(ea, sizeof(DWORD));
	}
}

// Force memory location to be ea_t size
void fixEa(ea_t ea)
{
#ifndef __EA64__
	if (!isDwrd(get_flags_novalue(ea)))
#else
	if (!isQwrd(get_flags_novalue(ea)))
#endif
	{
		setUnknown(ea, sizeof(ea_t));
#ifndef __EA64__
		doDwrd(ea, sizeof(ea_t));
#else
		doQwrd(ea, sizeof(ea_t));
#endif
	}
}

// Make address a function
void fixFunction(ea_t ea)
{
	flags_t flags = get_flags_novalue(ea);
	if (!isCode(flags))
	{
		create_insn(ea);
		add_func(ea, BADADDR);
	}
	else
		if (!isFunc(flags))
			add_func(ea, BADADDR);
}

// Get IDA EA bit value with verification
BOOL getVerifyEa(ea_t ea, ea_t &rValue)
{
	// Location valid?   
	if (isLoaded(ea))
	{
		// Get ea_t value
		rValue = getEa(ea);
		return(TRUE);
	}

	return(FALSE);
}


// Undecorate to minimal class name
// typeid(T).name()
// http://en.wikipedia.org/wiki/Name_mangling
// http://en.wikipedia.org/wiki/Visual_C%2B%2B_name_mangling
// http://www.agner.org/optimize/calling_conventions.pdf

BOOL getPlainTypeName(__in LPCSTR mangled, __out_bcount(MAXSTR) LPSTR outStr)
{
	outStr[0] = outStr[MAXSTR - 1] = 0;

	// Use CRT function for type names
	if (mangled[0] == '.')
	{
		__unDName(outStr, mangled + 1, MAXSTR, malloc, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU));
		if ((outStr[0] == 0) || (strcmp((mangled + 1), outStr) == 0))
		{
			msg("** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n", mangled);
			return(FALSE);
		}
	}
	else
		// IDA demangler for everything else
	{
		qstring qstr;
		int result = demangle_name2(&qstr, mangled, (MT_MSCOMP | MNG_NODEFINIT));
		if (result < 0)
		{
			//msg("** getPlainClassName:demangle_name2() failed to unmangle! result: %d, input: \"%s\"\n", result, mangled);
			return(FALSE);
		}

		// No inhibit flags will drop this
		strncpy(outStr, qstr.c_str(), (MAXSTR - 1));
		if (LPSTR ending = strstr(outStr, "::`vftable'"))
			*ending = 0;
	}

	return(TRUE);
}

// Wrapper for 'add_struc_member()' with error messages
// See to make more sense of types: http://idapython.googlecode.com/svn-history/r116/trunk/python/idc.py
int addStrucMember(struc_t *sptr, char *name, ea_t offset, flags_t flag, opinfo_t *type, asize_t nbytes)
{
	int r = add_struc_member(sptr, name, offset, flag, type, nbytes);
	switch (r)
	{
	case STRUC_ERROR_MEMBER_NAME:
		msg("AddStrucMember(): error: already has member with this name (bad name)\n");
		break;

	case STRUC_ERROR_MEMBER_OFFSET:
		msg("AddStrucMember(): error: already has member at this offset\n");
		break;

	case STRUC_ERROR_MEMBER_SIZE:
		msg("AddStrucMember(): error: bad number of bytes or bad sizeof(type)\n");
		break;

	case STRUC_ERROR_MEMBER_TINFO:
		msg("AddStrucMember(): error: bad typeid parameter\n");
		break;

	case STRUC_ERROR_MEMBER_STRUCT:
		msg("AddStrucMember(): error: bad struct id (the 1st argument)\n");
		break;

	case STRUC_ERROR_MEMBER_UNIVAR:
		msg("AddStrucMember(): error: unions can't have variable sized members\n");
		break;

	case STRUC_ERROR_MEMBER_VARLAST:
		msg("AddStrucMember(): error: variable sized member should be the last member in the structure\n");
		break;

	case STRUC_ERROR_MEMBER_NESTED:
		msg("AddStrucMember(): error: recursive structure nesting is forbidden\n");
		break;
	};

	return(r);
}


void setUnknown(ea_t ea, int size)
{
	// TODO: Does the overrun problem still exist?
	//do_unknown_range(ea, (size_t)size, DOUNK_SIMPLE);    
	while (size > 0)
	{
		int isize = get_item_size(ea);
		if (isize > size)
			break;
		else
		{
			do_unknown(ea, DOUNK_SIMPLE);
			ea += (ea_t)isize, size -= isize;
		}
	};
}


// Scan segment for COLs
static BOOL scanSeg4Cols(segment_t *seg)
{
	char name[64];
	if (get_true_segm_name(seg, name, SIZESTR(name)) <= 0)
		strcpy(name, "???");
	msg(" N: \"%s\", A: " EAFORMAT " - " EAFORMAT ", S: %s.\n", name, seg->startEA, seg->endEA, byteSizeString(seg->size()));

	UINT found = 0;
	if (seg->size() >= sizeof(RTTI::_RTTICompleteObjectLocator))
	{
		ea_t startEA = ((seg->startEA + sizeof(UINT)) & ~((ea_t)(sizeof(UINT) - 1)));
		ea_t endEA = (seg->endEA - sizeof(RTTI::_RTTICompleteObjectLocator));

		for (ea_t ptr = startEA; ptr < endEA;)
		{
#ifdef __EA64__
			// Check for possible COL here
			// Signature will be one
			// TODO: Is this always 1 or can it be zero like 32bit?
			if (get_32bit(ptr + offsetof(RTTI::_RTTICompleteObjectLocator, signature)) == 1)
			{
				if (RTTI::_RTTICompleteObjectLocator::isValid(ptr))
				{
					// yes
					colList.push_front(ptr);
					RTTI::_RTTICompleteObjectLocator::doStruct(ptr);
					ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
					continue;
				}
			}
			else
			{
				// TODO: Should we check stray BCDs?
				// Each value would have to be tested for a valid type_def and
				// the pattern is pretty ambiguous.
			}
#else
			// TypeDescriptor address here?
			ea_t ea = getEa(ptr);
			if (ea >= 0x10000)
			{
				if (RTTI::type_info::isValid(ea))
				{
					// yes, a COL here?
					ea_t col = (ptr - offsetof(RTTI::_RTTICompleteObjectLocator, typeDescriptor));
					if (RTTI::_RTTICompleteObjectLocator::isValid2(col))
					{
						// yes
						colList.push_front(col);
						RTTI::_RTTICompleteObjectLocator::doStruct(col);
						ptr += sizeof(RTTI::_RTTICompleteObjectLocator);
						continue;
					}
				}
			}
#endif


			ptr += sizeof(UINT);
		}
	}

	if (found)
	{
		char numBuffer[32];
		msg(" Count: %s\n", prettyNumberString(found, numBuffer));
	}
	return(FALSE);
}
//
// Locate COL by descriptor list
static BOOL findCols()
{
	try
	{
#ifdef _DEVMODE
		TIMESTAMP startTime = getTimeStamp();
#endif

		// Usually in ".rdata" seg, try it first
		std::unordered_set<segment_t *> segSet;
		if (segment_t *seg = get_segm_by_name(".rdata"))
		{
			segSet.insert(seg);
			if (scanSeg4Cols(seg))
				return(FALSE);
		}

		// And ones named ".data"
		int segCount = get_segm_qty();
		//if (colList.empty())
		{
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (segSet.find(seg) == segSet.end())
						{
							char name[8];
							if (get_true_segm_name(seg, name, SIZESTR(name)) == SIZESTR(".data"))
							{
								if (strcmp(name, ".data") == 0)
								{
									segSet.insert(seg);
									if (scanSeg4Cols(seg))
										return(FALSE);
								}
							}
						}
					}
				}
			}
		}

		// If still none found, try any remaining data type segments
		if (colList.empty())
		{
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (segSet.find(seg) == segSet.end())
						{
							segSet.insert(seg);
							if (scanSeg4Cols(seg))
								return(FALSE);
						}
					}
				}
			}
		}

		char numBuffer[32];
		msg("     Total COL: %s\n", prettyNumberString(colList.size(), numBuffer));
#ifdef _DEVMODE
		msg("COL scan time: %.3f\n", (getTimeStamp() - startTime));
#endif

	}
	CATCH()
		return(FALSE);
}


// Locate vftables
static BOOL scanSeg4Vftables(segment_t *seg, eaRefMap &colMap)
{
	char name[64];
	if (get_true_segm_name(seg, name, SIZESTR(name)) <= 0)
		strcpy(name, "???");
	msg(" N: \"%s\", A: " EAFORMAT "-" EAFORMAT ", S: %s.\n", name, seg->startEA, seg->endEA, byteSizeString(seg->size()));

	UINT found = 0;
	if (seg->size() >= sizeof(ea_t))
	{
		ea_t startEA = ((seg->startEA + sizeof(ea_t)) & ~((ea_t)(sizeof(ea_t) - 1)));
		ea_t endEA = (seg->endEA - sizeof(ea_t));
		eaRefMap::iterator colEnd = colMap.end();

		for (ea_t ptr = startEA; ptr < endEA; ptr += sizeof(UINT))  //sizeof(ea_t)
		{
			// COL here?
			ea_t ea = getEa(ptr);
			eaRefMap::iterator it = colMap.find(ea);
			if (it != colEnd)
			{
				// yes, look for vftable one ea_t below
				ea_t vfptr = (ptr + sizeof(ea_t));
				ea_t method = getEa(vfptr);
				// Points to code?
				if (segment_t *s = getseg(method))
				{
					// yes,
					if (s->type == SEG_CODE)
					{
						RTTI::processVftable(vfptr, it->first);
						it->second++, found++;
					}
				}
			}

		}
	}

	if (found)
	{
		char numBuffer[32];
		msg(" Count: %s\n", prettyNumberString(found, numBuffer));
	}
	return(FALSE);
}
//
static BOOL findVftables()
{
	try
	{
#ifdef _DEVMODE
		TIMESTAMP startTime = getTimeStamp();
#endif

		// COLs in a hash map for speed, plus match counts
		eaRefMap colMap;
		for (eaList::const_iterator it = colList.begin(), end = colList.end(); it != end; ++it)
			colMap[*it] = 0;

		// Usually in ".rdata", try first.
		std::unordered_set<segment_t *> segSet;
		if (segment_t *seg = get_segm_by_name(".rdata"))
		{
			segSet.insert(seg);
			if (scanSeg4Vftables(seg, colMap))
				return(TRUE);
		}

		// And ones named ".data"
		int segCount = get_segm_qty();
		//if (colList.empty())
		{
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (segSet.find(seg) == segSet.end())
						{
							char name[8];
							if (get_true_segm_name(seg, name, SIZESTR(name)) == SIZESTR(".data"))
							{
								if (strcmp(name, ".data") == 0)
								{
									segSet.insert(seg);
									if (scanSeg4Vftables(seg, colMap))
										return(TRUE);
								}
							}
						}
					}
				}
			}
		}

		// If still none found, try any remaining data type segments
		if (colList.empty())
		{
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (segSet.find(seg) == segSet.end())
						{
							segSet.insert(seg);
							if (scanSeg4Vftables(seg, colMap))
								return(TRUE);
						}
					}
				}
			}
		}

		// Rebuild 'colList' with any that were not located
		if (!colList.empty())
		{
			colList.clear();
			for (eaRefMap::const_iterator it = colMap.begin(), end = colMap.end(); it != end; ++it)
			{
				if (it->second == 0)
					colList.push_front(it->first);
			}
		}

#ifdef _DEVMODE
		msg("vftable scan time: %.3f\n", (getTimeStamp() - startTime));
#endif
	}
	CATCH()
		return(FALSE);
}


// ================================================================================================

// Gather RTTI data
static BOOL getRttiData()
{
	// Free RTTI working data on return
	struct OnReturn { ~OnReturn() { RTTI::freeWorkingData(); }; } onReturn;

	try
	{
		// ==== Locate __type_info_root_node
		BOOL aborted = FALSE;

		// ==== Find and process COLs
		msg("\nScanning for for RTTI Complete Object Locators.\n");
		if (findCols())
			return(TRUE);
		// typeDescList = TDs left that don't have a COL reference
		// colList = Located COLs          

		// ==== Find and process vftables
		msg("\nScanning for vftables.\n");
		if (findVftables())
			return(TRUE);
		// colList = COLs left that don't have a vft reference

		// Could use the unlocated ref lists typeDescList & colList around for possible separate listing, etc.
		// They get cleaned up on return of this function anyhow.       
	}
	CATCH()

		return(FALSE);
}
