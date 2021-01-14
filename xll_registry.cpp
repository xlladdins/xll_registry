// xll_registry.cpp - Windows registry wrapper
#include "xll/xll/xll.h"
#include "xll/xll/registry.h"

#define CATEGORY "Registry"

using namespace xll;
using namespace Reg;

#define HKEY_LONG(k) ((LONG)(((ULONG_PTR)(k)) & 0xFFFFFFFF))
#define LONG_HKEY(l) ((HKEY)((ULONG_PTR)(l)))

#define KEY_TOPIC "https://docs.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
#define KEY_CONST(a, b, c) XLL_CONST(LONG, HKEY_##a, HKEY_LONG(HKEY_##b), c, CATEGORY, KEY_TOPIC)
REG_KEY(KEY_CONST)
#undef KEY_CONST
#undef KEY_TOPIC

//HKEY_CURRENT_CONFIG

#define SAM_TOPIC "https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights"
#define SAM_CONST(a, b) XLL_CONST(LONG, KEY_##a, KEY_##a, b, CATEGORY, SAM_TOPIC)
REG_SAM(SAM_CONST)
#undef SAM_CONST
#undef SAM_TOPIC

using xcstr = traits<XLOPERX>::xcstr;

AddIn xai_reg_key(
	Function(XLL_HANDLE, "xll_reg_key", "REG_KEY")
	.Args({
		Arg(XLL_LONG, "hive", "is the registry hive from =HKEY_xxx().", "=HKEY_HKCU()"),
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "Volatile Environment"),
		Arg(XLL_LONG, "sam", "is the access rights mask from =KEY_xxx() values.", "=KEY_READ()"),
	})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw")
);
HANDLEX WINAPI xll_reg_key(LONG hkey, xcstr subkey, LONG sam)
{
#pragma XLLEXPORT
	HANDLEX h = INVALID_HANDLEX;

	try {
		if (sam == 0) {
			sam = KEY_READ | KEY_WOW64_64KEY;
		}
		handle<Reg::Key> h_(new Reg::Key(LONG_HKEY(hkey), subkey, sam));
		ensure(h_);
		h = h_.get();
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return h;
}

AddIn xai_reg_key_info(
	Function(XLL_LPOPER, "xll_reg_key_info", "REG.KEY.INFO")
	.Args({
		Arg(XLL_HANDLE, "hkey", "is a handle to a key returned by =REG_KEY().", "=HKEY_HKCU()"),
		})
		.FunctionHelp("Return a two column array of informationa aout the registry key.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw")
);
LPOPER WINAPI xll_reg_key_info(HANDLEX hkey)
{
#pragma XLLEXPORT
	static OPER info;

	info = ErrNA;
	try {
		handle<Reg::Key> h_(hkey);
		ensure(h_);

		DWORD   subKeys;
		DWORD   maxSubKeyLen;
		DWORD   values;
		DWORD   maxValueNameLen;
		DWORD   maxValueLen;
		FILETIME ftLastWriteTime;

		LSTATUS status = RegQueryInfoKey(*h_.ptr(), NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, &ftLastWriteTime);
		if (ERROR_SUCCESS != status) {
			throw std::runtime_error(Reg::GetFormatMessage(status));
		}

		SYSTEMTIME st;
		ensure(FileTimeToSystemTime(&ftLastWriteTime, &st));
		OPER oDate = Excel(xlfDate, OPER(st.wYear), OPER(st.wMonth), OPER(st.wDay));
		OPER oTime = Excel(xlfTime, OPER(st.wHour), OPER(st.wMinute), OPER(st.wSecond + st.wMilliseconds / 1000.));

		info = OPER({
			OPER("subKeys"), OPER(subKeys),
			OPER("maxSubKeyLen"), OPER(maxSubKeyLen),
			OPER("values"), OPER(values),
			OPER("maxValueNameLen"), OPER(maxValueNameLen),
			OPER("maxValueLen"), OPER(maxValueLen),
			OPER("lastWriteTime"), OPER(oDate.val.num + oTime.val.num)
		});
		info.resize(info.size() / 2, 2);
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return &info;
}

AddIn xai_reg_keys(
	Function(XLL_LPOPER, "xll_reg_keys", "REG.KEYS")
	.Args({
		Arg(XLL_HANDLE, "hkey", "is a handle to a key returned by =REG_KEY().", "=HKEY_HKCU()"),
	})
	.FunctionHelp("Return a one column array of subkey names.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw")
);
LPOPER WINAPI xll_reg_keys(HANDLEX hkey)
{
#pragma XLLEXPORT
	static OPER keys;

	keys = ErrNA;
	try {
		handle<Reg::Key> h_(hkey);
		ensure(h_);
		keys = OPER{};
		for (auto k : *h_.ptr()) {
			keys.append_bottom(OPER(k));
		}
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return &keys;
}

AddIn xai_reg_values(
	Function(XLL_LPOPER, "xll_reg_values", "REG.VALUES")
	.Args({
		Arg(XLL_HANDLE, "hkey", "is a handle to a key returned by =REG_KEY().", "=HKEY_HKCU()"),
	})
	.FunctionHelp("Return a one column array of value names.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew")
);
LPOPER WINAPI xll_reg_values(HANDLEX hkey)
{
#pragma XLLEXPORT
	static OPER values;

	values = ErrNA;
	try {
		handle<Reg::Key> h_(hkey);
		ensure(h_);
		values = OPER{};
		Reg::Key::ValueIterator vi(*h_.ptr());
		while (vi) {
			values.append_bottom(OPER(*vi));
			++vi;
		}
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return &values;
}
