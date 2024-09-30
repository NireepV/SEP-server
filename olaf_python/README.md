## How to configure environment

To maintain dependencies and ensure this code can run "anywhere", a virtual environment is used to develop/run the code.

From the root directory, run:
```bash
python3 -m venv olaf_python
```

Then, run the following (different commands for macOS/Linux & Windows):
```bash
source olaf_python/bin/activate  **(macOS/Linux)**
```
```powershell
olaf_python/Scripts/Activate.ps1  **(Windows)**
```

Finally, to install the dependencies, run:
```bash
pip install -r requirements.txt
```