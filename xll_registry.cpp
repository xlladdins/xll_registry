// xll_registry.cpp - Windows registry wrapper
#include "xll/xll/xll.h"
#include "xll/xll/registry.h"

#define CATEGORY "Registry"

using namespace xll;
using namespace Reg;

#ifdef _DEBUG
Auto<OpenAfter> xaoa_registry_documentation([]() {
	return xll::Documentation("xll_registry", "Registry functions.");
});
#endif // _DEBUG

using xcstr = traits<XLOPERX>::xcstr;
using xchar = traits<XLOPERX>::xchar;

#define HKEY_LONG(k) ((LONG)(((ULONG_PTR)(k)) & 0xFFFFFFFF))
#define LONG_HKEY(l) ((HKEY)((ULONG_PTR)(l)))
/*
#define HKEY_TOPIC "https://docs.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
#define HKEY_CONST(a, b, c) XLL_CONST(LONG, HIVE_##a, HKEY_LONG(HKEY_##b), c, CATEGORY, HKEY_TOPIC)
REG_HKEY(HKEY_CONST)
#undef HKEY_CONST
#undef HKEY_TOPIC
*/
//HKEY_CURRENT_CONFIG

#define KEY_TOPIC "https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights"
#define KEY_CONST(a, b) XLL_CONST(LONG, KEY_##a, KEY_##a, b, CATEGORY, KEY_TOPIC)
REG_KEY(KEY_CONST)
#undef KEY_CONST
#undef KEY_TOPIC

#define TYPES_TOPIC "https ://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types"
#define TYPES_CONST(a, b, c) XLL_CONST(LONG, REG_##a, REG_##a, c, CATEGORY, TYPES_TOPIC)
REG_TYPES(TYPES_CONST)
#undef TYPES_CONST
#undef TYPES_TOPIC

inline OPER GetValue(const Reg::Value& value)
{
	OPER o = ErrNA;

	switch (value.type) {
	case REG_DWORD:
		o = (DWORD)value;

		break;
	case REG_SZ:
		o = (xcstr)value;

		break;
	case REG_MULTI_SZ:
		{
			o = OPER{};
			PCTSTR b = (PCTSTR)value, e = _tcschr(b, TEXT('\0'));
			while (b and b != e) {
				o.push_back(OPER(b, static_cast<xchar>(e - b)));
				b = e + 1;
				e = _tcschr(b, TEXT('\0'));
			}
			o.resize(1, o.size());

		}
		break;
	}

	return o;
}

inline Reg::Value SetValue(PCTSTR name, const OPER& o)
{
	Reg::Value v;

	switch (type(o)) {
	case xltypeNum:
		v = Reg::Value(name, (DWORD)o.val.num);

		break;
	case xltypeInt:
		v.type = REG_DWORD;
		v = (DWORD)o.val.w;
		
		break;
	case xltypeBool:
		v.type = REG_DWORD;
		v = (DWORD)o.val.xbool;
		
		break;
	case xltypeStr:
		v = Reg::Value(name, o.val.str + 1, o.val.str[0]);
		
		break;
	// case xltypeMulti: // must be an array of strings
	}

	return v;
}

HANDLEX WINAPI xll_reg_key_hive(HKEY hkey, xcstr subkey, LONG sam, BOOL open)
{
	HANDLEX h = INVALID_HANDLEX;

	try {
		if (sam == 0) {
			sam = KEY_READ | KEY_WOW64_64KEY;
		}
		handle<Reg::Key> h_(new Reg::Key(hkey, subkey, sam, open));
		ensure(h_);
		h = h_.get();
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return h;
}

// Known registry keys
AddIn xai_reg_key_hkcr(
	Function(XLL_HANDLE, "xll_reg_key_hkcr", "\\REG.KEY.HKCR")
	.Arguments({
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "\"Applications\""),
		Arg(XLL_LONG, "sam", "is the security access mask from =KEY_xxx() values.", "KEY_READ()"),
		Arg(XLL_BOOL, "_open", "is an optional boolean argument indicating an existing key should be opened, not created. The default is FALSE.", "TRUE")
		})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle in the HKEY_CLASSES_ROOT hive.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw")
	.Documentation(R"xyzyx(
Open an existing key or creates a new subkey in a 
the <code>HKEY_CLASSES_ROOT</code> hive.
If <code>_open<code> is <code>TRUE</code> this function will only open an existing subkey.
If the subkey does not exist an invalid handle is returned.
)xyzyx")
);
HANDLEX WINAPI xll_reg_key_hkcr(xcstr subkey, LONG sam, BOOL open)
{
#pragma XLLEXPORT
	static HANDLEX h = xll_reg_key_hive(HKEY_CLASSES_ROOT, subkey, sam, open);
	return h;
}

AddIn xai_reg_key_hkcc(
	Function(XLL_HANDLE, "xll_reg_key_hkcc", "\\REG.KEY.HKCC")
	.Arguments({
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "\"Software\\Fonts\""),
		Arg(XLL_LONG, "sam", "is the security access mask from =KEY_xxx() values.", "KEY_READ()"),
		Arg(XLL_BOOL, "_open", "is an optional boolean argument indicating an existing key should be opened, not created. The default is FALSE.", "TRUE")
	})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle in the HKEY_CURRENT_CONFIG hive.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw")
	.Documentation(R"xyzyx(
Open an existing key or creates a new subkey in a 
the <code>HKEY_CURRENT_CONFIG</code> hive.
If <code>_open<code> is <code>TRUE</code> this function will only open an existing subkey.
If the subkey does not exist an invalid handle is returned.
)xyzyx")
);
HANDLEX WINAPI xll_reg_key_hkcc(xcstr subkey, LONG sam, BOOL open)
{
#pragma XLLEXPORT
	static HANDLEX h = xll_reg_key_hive(HKEY_CURRENT_CONFIG, subkey, sam, open);
	return h;
}

AddIn xai_reg_key_hkcu(
	Function(XLL_HANDLE, "xll_reg_key_hkcu", "\\REG.KEY.HKCU")
	.Arguments({
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "\"Console\""),
		Arg(XLL_LONG, "sam", "is the security access mask from =KEY_xxx() values.", "KEY_READ()"),
		Arg(XLL_BOOL, "_open", "is an optional boolean argument indicating an existing key should be opened, not created. The default is FALSE.", "TRUE")
		})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle in the HKEY_CURRENT_USER hive.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw")
	.Documentation(R"xyzyx(
Open an existing key or creates a new subkey in a 
the <code>HKEY_CURRENT_USER</code> hive.
If <code>_open<code> is <code>TRUE</code> this function will only open an existing subkey.
If the subkey does not exist an invalid handle is returned.
)xyzyx")
);
HANDLEX WINAPI xll_reg_key_hkcu(xcstr subkey, LONG sam, BOOL open)
{
#pragma XLLEXPORT
	static HANDLEX h = xll_reg_key_hive(HKEY_CURRENT_USER, subkey, sam, open);
	return h;
}

AddIn xai_reg_key_hklm(
	Function(XLL_HANDLE, "xll_reg_key_hklm", "\\REG.KEY.HKLM")
	.Arguments({
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "\"SOFTWARE\\DefaultUserEnvironment\""),
		Arg(XLL_LONG, "sam", "is the security access mask from =KEY_xxx() values.", "KEY_READ()"),
		Arg(XLL_BOOL, "_open", "is an optional boolean argument indicating an existing key should be opened, not created. The default is FALSE.", "TRUE")
		})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle in the HKEY_LOCAL_MACHINE hive.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw")
	.Documentation(R"xyzyx(
Open an existing key or creates a new subkey in a 
the <code>HKEY_LOCAL_MACHINE</code> hive.
If <code>_open<code> is <code>TRUE</code> this function will only open an existing subkey.
If the subkey does not exist an invalid handle is returned.
)xyzyx")
);
HANDLEX WINAPI xll_reg_key_hklm(xcstr subkey, LONG sam, BOOL open)
{
#pragma XLLEXPORT
	static HANDLEX h = xll_reg_key_hive(HKEY_LOCAL_MACHINE, subkey, sam, open);
	return h;
}

AddIn xai_reg_key(
	Function(XLL_HANDLE, "xll_reg_key", "\\REG.KEY")
	.Arguments({
		Arg(XLL_HANDLEX, "key", "is a handle to a registry key.", "=\\REG.KEY.HKCU()"),
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "\"Console\""),
		Arg(XLL_LONG, "sam", "is the security access mask from =KEY_xxx() values.", "=KEY_READ()"),
		Arg(XLL_BOOL, "_open", "is an optional boolean argument indicating an existing key should be opened, not created. The default is FALSE.", "TRUE")
	})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw")
	.Documentation(R"xyzyx(
Open an existing key or create a new subkey.
Use <code>_open = TRUE</code> or <a href="REG.KEY.OPEN.html"><code>\REG.KEY.OPEN</code></a> 
if you do not want to create a new key.
)xyzyx")
);
HANDLEX WINAPI xll_reg_key(HANDLEX hkey, xcstr subkey, LONG sam, BOOL open)
{
#pragma XLLEXPORT
	HANDLEX h = INVALID_HANDLEX;

	try {
		if (sam == 0) {
			sam = KEY_READ | KEY_WOW64_64KEY;
		}
		handle<Reg::Key> hkey_(hkey);
		ensure(hkey_);
		handle<Reg::Key> h_(new Reg::Key(*hkey_, subkey, sam, open));
		h = h_.get();
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return h;
}

AddIn xai_reg_key_open(
	Function(XLL_HANDLEX, "xll_reg_key_open", "\\REG.KEY.OPEN")
	.Arguments({
		Arg(XLL_HANDLEX, "key", "is a handle to a registry key.", "=\\REG.KEY.HKCU()"),
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "\"Console\""),
		Arg(XLL_LONG, "sam", "is the access rights mask from =KEY_xxx() values.", "=KEY_READ()"),
	})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle to an existing entry.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw")
	.Documentation(R"xyzyx(
The function <code>\REG.KEY.OPEN</code> opens an existing key in a hive.
The call <a href="REG.KEY.html"><code>\REG.KEY(hive, subkey, sam, TRUE)</code></a> 
produces an identical result.
)xyzyx")
);
HANDLEX WINAPI xll_reg_key_open(HANDLEX hkey, xcstr subkey, LONG sam)
{
#pragma XLLEXPORT
	HANDLEX h = INVALID_HANDLEX;

	try {
		if (sam == 0) {
			sam = KEY_READ | KEY_WOW64_64KEY;
		}
		handle<Reg::Key> hkey_(hkey);
		ensure(hkey_);
		handle<Reg::Key> h_(new Reg::Key(*hkey_, subkey, sam, true));
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
	.Arguments({
		Arg(XLL_HANDLE, "key", "is a handle to a registry key.", "=\\REG.KEY.HKCU()"),
	})
	.FunctionHelp("Return a information about the registry key.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw")
	.Documentation(R"xyzyx(
Return a one row range of key information: the number of subkeys, 
the maximum subkey name length,the number of values, the maximum value name length, 
the maximum value length, and the last time the key was modified as UTC system time. 
If key is <code>0</code> return descriptive names of the information.
)xyzyx")
);
LPOPER WINAPI xll_reg_key_info(HANDLEX hkey)
{
#pragma XLLEXPORT
	static OPER info;

	info = ErrNA;
	try {
		if (hkey) {
			info = OPER({
				OPER("subKeys"),
				OPER("maxSubKeyLen"),
				OPER("values"),
				OPER("maxValueNameLen"),
				OPER("maxValueLen"),
				OPER("lastWriteTime")
			});
		}
		else {
			handle<Reg::Key> h_(hkey);
			ensure(h_);

			DWORD   subKeys;
			DWORD   maxSubKeyLen;
			DWORD   values;
			DWORD   maxValueNameLen;
			DWORD   maxValueLen;
			FILETIME ftLastWriteTime;

			LSTATUS status = RegQueryInfoKey(*h_.ptr(), NULL, NULL, NULL, 
				&subKeys, &maxSubKeyLen, NULL, &values, &maxValueNameLen, &maxValueLen, NULL, &ftLastWriteTime);
			if (ERROR_SUCCESS != status) {
				throw std::runtime_error(Reg::GetFormatMessage(status));
			}

			SYSTEMTIME st;
			ensure(FileTimeToSystemTime(&ftLastWriteTime, &st));
			OPER oDate = Excel(xlfDate, OPER(st.wYear), OPER(st.wMonth), OPER(st.wDay));
			OPER oTime = Excel(xlfTime, OPER(st.wHour), OPER(st.wMinute), OPER(st.wSecond + st.wMilliseconds / 1000.));

			info = OPER({
				OPER(subKeys),
				OPER(maxSubKeyLen),
				OPER(values),
				OPER(maxValueNameLen),
				OPER(maxValueLen),
				OPER(oDate.val.num + oTime.val.num)
			});
		}
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return &info;
}

AddIn xai_reg_keys(
	Function(XLL_LPOPER, "xll_reg_keys", "REG.KEYS")
	.Arguments({
		Arg(XLL_HANDLE, "hkey", "is a handle to a registry key.", "=\\REG.KEY.HKCU()"),
	})
	.FunctionHelp("Return subkey names.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw")
	.Documentation(R"(Return key names as a one row range.)")
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
		for (const auto& k : h_.ptr()->Keys()) {
			keys.push_back(OPER(k));
		}
		keys.resize(1, keys.size());
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return &keys;
}

AddIn xai_reg_values(
	Function(XLL_LPOPER, "xll_reg_values", "REG.VALUES")
	.Arguments({
		Arg(XLL_HANDLE, "hkey", "is a handle to a registry key.", "=\\REG.KEY.HKCU()"),
	})
	.FunctionHelp("Return a two column range of value names and their values.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew")
	.Documentation(R"(Enumerate all value names and values of a registry key.)")
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
		for (const Reg::Value& value : h_->Values()) {
			OPER name(value.name.c_str());
			OPER val(GetValue(value));
			values.push_back(OPER({ name, val }));
		}
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return &values;
}

AddIn xai_reg_value_query(
	Function(XLL_LPOPER, "xll_reg_value_query", "REG.VALUE.QUERY")
	.Arguments({
		Arg(XLL_HANDLE, "hkey", "is a handle to a registy key.", "=\\REG.KEY.HKCU(\"Console\")"),
		Arg(XLL_CSTRING, "name", "is the name of the value to set.", "\"FaceName\""),
	})
	.FunctionHelp("Return value of registry key given its name.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvaluew")
	.Documentation(R"(
Return the value associated with a registry key name. 
)")
);
LPOPER WINAPI xll_reg_value_query(HANDLEX hkey, xcstr name)
{
#pragma XLLEXPORT
	static OPER value;

	try {
		handle<Reg::Key> key(hkey);
		ensure(key);
		Reg::Value val(name);
		val.Query(*key);
		value = GetValue(val);
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());

		value = ErrNA;
	}

	return &value;
}

AddIn xai_reg_value_set(
	Function(XLL_HANDLEX, "xll_reg_value_set", "REG.VALUE.SET")
	.Arguments({
		Arg(XLL_HANDLEX, "key", "is a handle to a registy key."),
		Arg(XLL_CSTRING, "name", "is the name of the value to set."),
		Arg(XLL_LPOPER, "value", "is the value to set.")
	})
	.FunctionHelp("Return the handle to the registry key.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvaluew")
	.Documentation(R"(
Set the the subkey with <code>name</code> to <code>value</code>.
If <code>value</code> is a number or boolean then the key type is <code>REG_DWORD</code>
If <code>value</code> is a string then the key type is <code>REG_SZ</code>.
)")
);
HANDLEX WINAPI xll_reg_value_set(HANDLEX hkey, xcstr name, LPOPER pvalue)
{
#pragma XLLEXPORT
	try {
		handle<Reg::Key> key(hkey);
		ensure(key);
		Reg::Value value = SetValue(name, *pvalue);
		ensure(value || !"unrecognized registry value type");
		value.Set(*key);
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());

		hkey = INVALID_HANDLEX;
	}

	return hkey;
}
