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
The type `HKEY` represents the 'directory'.

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

### `Reg::Key::Info`

The function [`RegQueryInfoKey`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw)
retrieves information about the key: how many subkeys it has, the maximum length of the subkey names,
how many values the key has, the maximum length of the value names, the maximum size of the
all values, and the last time the key was modified.
The corresponding add-in function is [`REG.KEY.INFO`](???).

### `Reg::Key::Keys

The function [`RegEnumKeyEx`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw)
enumerates the names of the subkeys of a key.
The corresponding add-in function [`REG.KEYS`](???) returns a one column array of subkey names.

### `Reg::Key::Values`

The function [`RegEnumValue`](https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew)
enumerates the names and types of the values contained in a key.
The corresponding add-in function [`REG.VALUES`](???) returns a one column array of value names.
