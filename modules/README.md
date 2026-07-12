# Drop-in modules

This folder is for **example / shipped** community modules. Your *personal*
drop-in folder (the one the app scans at runtime) lives at:

```
%LOCALAPPDATA%\Angerona\modules\
```

Open the app → **Settings** to see the exact path. Drop any `.py` file that
defines a `BaseModule` subclass there and it appears in the **Modules** page on
next launch. See [`../docs/writing-modules.md`](../docs/writing-modules.md).
