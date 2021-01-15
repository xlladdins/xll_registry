// xll_registry.cpp - Windows registry wrapper
#include "xll/xll/xll.h"
#include "xll/xll/registry.h"

#define CATEGORY "Registry"

using namespace xll;
using namespace Reg;

using xcstr = traits<XLOPERX>::xcstr;
using xchar = traits<XLOPERX>::xchar;

#define HKEY_LONG(k) ((LONG)(((ULONG_PTR)(k)) & 0xFFFFFFFF))
#define LONG_HKEY(l) ((HKEY)((ULONG_PTR)(l)))

#define KEY_TOPIC "https://docs.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys"
#define KEY_CONST(a, b, c) XLL_CONST(LONG, HIVE_##a, HKEY_LONG(HKEY_##b), c, CATEGORY, KEY_TOPIC)
REG_KEY(KEY_CONST)
#undef KEY_CONST
#undef KEY_TOPIC

//HKEY_CURRENT_CONFIG

#define SAM_TOPIC "https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights"
#define SAM_CONST(a, b) XLL_CONST(LONG, KEY_##a, KEY_##a, b, CATEGORY, SAM_TOPIC)
REG_SAM(SAM_CONST)
#undef SAM_CONST
#undef SAM_TOPIC

#define TYPE_TOPIC "https ://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types"
#define TYPE_CONST(a, b, c) XLL_CONST(LONG, REG_##a, REG_##a, c, CATEGORY, TYPE_TOPIC)
REG_TYPE(TYPE_CONST)
#undef TYPE_CONST
#undef TYPE_TOPIC

inline OPER GetValue(HKEY hkey, PCTSTR subkey, PCTSTR name)
{
	OPER o = ErrNA;
	DWORD type = 0;
	DWORD size = 0;
	
	LSTATUS status = RegGetValue(hkey, subkey, name, RRF_RT_ANY, &type, NULL, &size);
	if (ERROR_SUCCESS == status) {
		switch (type) {
		case REG_DWORD:
			o.xltype = xltypeNum;
			o.val.num = GetValue<DWORD>(hkey, subkey, name);

			break;
		case REG_SZ:
			ensure(size / sizeof(xchar) <= traits<XLOPERX>::charmax);
			o.xltype = xltypeStr;
			o.val.str = (xchar*)malloc(sizeof(xchar) + size);
			ensure(o.val.str != nullptr);
			status = RegGetValue(hkey, subkey, name, RRF_RT_REG_SZ, &type, o.val.str + 1, &size);
			if (ERROR_SUCCESS != status) {
				free(o.val.str);

				o = ErrNA;;
			}
			o.val.str[0] = static_cast<xchar>(size / sizeof(xchar));  // -1 ???

			break;
		case REG_MULTI_SZ:
		{
			using tstring = std::basic_string<xchar>;
			using size_type = tstring::size_type;
			tstring buf;
			buf.resize(1 + size / sizeof(xchar));
			status = RegGetValue(hkey, subkey, name, RRF_RT_REG_SZ, &type, buf.data(), &size);
			size_type b = 0, e = buf.find(TEXT('\0'), b);
			while (b != e) {
				o.append_bottom(OPER(&buf[b], static_cast<int>(e - b)));
				b = e + 1;
				e = buf.find(TEXT('\0'), b);
			}
			o.resize(1, o.size());
			break;
		}
		default:
			o = ErrNA;
		}
	}

	return o;
}

inline OPER EnumValue(Reg::Key::ValueIterator& vi)
{
	OPER o = ErrNA;
	auto [name, index, type, size] = *vi;

	switch (type) {
	case REG_DWORD:
		o.xltype = xltypeNum;
		DWORD dw;
		ensure (ERROR_SUCCESS == vi.Value((PBYTE)&dw));
		o.val.num = dw;

		break;
	case REG_SZ: case REG_MULTI_SZ:
		ensure(size / sizeof(xchar) <= traits<XLOPERX>::charmax);
		o.xltype = xltypeStr;
		o.val.str = (xchar*)malloc(1 + sizeof(xchar) + size);
		ensure(o.val.str != nullptr);
		ensure(ERROR_SUCCESS == vi.Value((PBYTE)(o.val.str + 1)));
		o.val.str[0] = static_cast<xchar>(size / sizeof(xchar));  // -1 ???

		break;
	default:
		o = ErrNA;
	}

	return o;
}

AddIn xai_reg_key(
	Function(XLL_HANDLE, "xll_reg_key", "\\REG.KEY")
	.Args({
		Arg(XLL_LONG, "hive", "is the registry hive from =HIVE_xxx().", "=HIVE_HKCU()"),
		Arg(XLL_CSTRING, "subkey", "is the registry subkey to open or create.", "Volatile Environment"),
		Arg(XLL_LONG, "sam", "is the access rights mask from =KEY_xxx() values.", "=KEY_READ()"),
	})
	.Uncalced()
	.FunctionHelp("Return a HKEY registry handle.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw")
	.Documentation(R"xyzyx(
The function <code>REG.KEY</code> opens an existing key or creates a new subkey in a hive.
)xyzyx")
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

// \REG.KEY.OPEN - will not create new key

AddIn xai_reg_key_info(
	Function(XLL_LPOPER, "xll_reg_key_info", "REG.KEY.INFO")
	.Args({
		Arg(XLL_HANDLE, "hkey", "is a handle to a key returned by =REG_KEY().", "=HIVE_HKCU()"),
	})
	.FunctionHelp("Return a two column array of information about the registry key.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw")
	.Documentation(R"xyzyx(
Return a two column array of key information. The first column describes the data returned.
)xyzyx")
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
		Arg(XLL_HANDLE, "hkey", "is a handle to a key returned by =REG_KEY().", "=HIVE_HKCU()"),
	})
	.FunctionHelp("Return a one column array of subkey names.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw")
	.Documentation(R"(Enumerate the key names.)")
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
		for (auto k : h_.ptr()->Keys()) {
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
		Arg(XLL_HANDLE, "hkey", "is a handle to a key returned by =REG_KEY().", "=HIVE_HKCU()"),
		Arg(XLL_BOOL, "_values", "is a boolean indicating if values are to be returned in the second column. Default is FALSE.")
	})
	.FunctionHelp("Return an range of value names and optionally their values.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew")
	.Documentation(R"(Enumerate the value names.)")
);
LPOPER WINAPI xll_reg_values(HANDLEX hkey, BOOL b)
{
#pragma XLLEXPORT
	static OPER values;

	values = ErrNA;
	try {
		handle<Reg::Key> h_(hkey);
		ensure(h_);
		values = OPER{};
		auto val = h_.ptr()->Values();
		while (val) {
			auto [name, index, type, len] = *val;
			if (b) {
				values.append_bottom(OPER({ OPER(name), EnumValue(val) }));
			}
			else {
				values.append_bottom(OPER(name));
			}
			++val;
		}
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());
	}

	return &values;
}

AddIn xai_reg_value_get(
	Function(XLL_LPOPER, "xll_reg_value_get", "REG.VALUE.GET")
	.Args({
		Arg(XLL_HANDLE, "hkey", "is a handle to a key returned by =REG_KEY().", "=REG_KEY(HIVE_HKCU(), \"Environment\")"),
		Arg(XLL_CSTRING, "subkey", "is the name of the subkey to get.", ""),
		Arg(XLL_CSTRING, "name", "is the name of the value to get.", "Path"),
	})
	.FunctionHelp("Return key value given its name.")
	.Category(CATEGORY)
	.HelpTopic("https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew")
);
LPOPER WINAPI xll_reg_value_get(HANDLEX hkey, xcstr subkey, xcstr name)
{
#pragma XLLEXPORT
	static OPER value;

	try {
		handle<Reg::Key> key(hkey);
		ensure(key);
		value = GetValue(*key.ptr(), subkey, name);
	}
	catch (const std::exception& ex) {
		XLL_ERROR(ex.what());

		value = ErrNA;
	}

	return &value;
}
