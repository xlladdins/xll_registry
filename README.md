# xll_registry

Excel add-in for accessing the Windows registry.

## Registry

Every Windows computer has a _registry_. The registry groups related information into _hives_.
The most common hives are `HKEY_CLASSES_ROOT` for document types and their properties,
`HKEY_CURRENT_USER` for preferences related to the current user, and `HKEY_LOCAL_MACHINE` for
the physical state of the machine.

Hives have a heirarchical structure similar to a file system. The top level hive has _keys_
that are analogous to directories. 
Keys have a case insensitve string name and associated security
attributes for reading (`r`) and writing (`w`) _values_ the key contains, and searching into _subkeys_ (`x`).
Keys also keep track of the last time they were modified and _volatile_ keys are deleted when the process that created the key terminates.
The type `HKEY` represents the 'directory' containing its subkeys and values. 

Keys contain _values_ that are like files with restricted content type. 
Values have case insensitive strings names and their associated content type.
The most common content types are `REG_DWORD` for 32-bit unsigned integers, 
`REG_SZ` for null terminated strings, and `REG_BINARY` that can be any array of 8-bit bytes.

## `Reg::Key`

Existing keys can be _opened_ and new keys can be _created_. The function
[`RegCreateKey`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)
can do double duty. The class `Reg::Key` calls this to either open or create keys.
The member function `Reg::Key::disposition()` returns
`REG_OPENED_EXISTING_KEY` if an existing key was opened or `REG_CREATED_NEW_KEY` 
if a new key was created.

Keys cannot be copied or assigned to, only moved or move assigned. They have semantics
similar to `std::unique_ptr`.

This class defines `operator HKEY()` to return the underlying key so it is possible to
use it in native Windows registry functions. For example, there is no `DeleteKey`
method. One simply calls the Windows API function `RegDeleteKey(key, "subKey")`.
To get key information call the function 
[`RegQueryInfoKey`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw)

Key values can be queried and set using `Reg::Key::QueryValue` and `Reg::Key::SetValue`
that call `RegQueryValueEx` and `RegSetValueEx` respectively. It is more convenient
to use `Reg::Key::operator[]` which returns a proxy class. The proxy has overloads for `operator T()`
where `T` is any value type to get values. Registry values can be set using the proxy overload
for `operator=(const T&)`. Keys can be used as built-in C++ types. 
The assignment `key["valueName"] = value` results in setting 
the regitsry value having name `"valueName"` with the contents of `value`.

### `Reg::Key::KeyIterator

The function [`RegEnumKeyEx`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw)
enumerates the names of the subkeys of a key. The class `Reg::Key` has a `begin()` and and `end()` method
for use with the STL. For example, the range based for loop
`for (PCTSTR& name : key) { cout << name << endl; }` prints
the names of all subkeys of `key`.

The corresponding add-in function [`REG.KEYS`](???) returns a one column array of subkey names.

### `Reg::Key::ValueIterator`

The function [`RegEnumValue`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew)
enumerates the names and types of the values contained in a key.
The corresponding add-in function [`REG.VALUES`](???) returns a one column array of value names.
