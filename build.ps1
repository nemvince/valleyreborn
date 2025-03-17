$env:NUITKA_CACHE_DIR = 'C:\cache'; py -m nuitka --standalone --onefile --windows-console-mode=disable --plugin-enable=pyqt6 --mingw64 --clang --output-dir=dist main.py
