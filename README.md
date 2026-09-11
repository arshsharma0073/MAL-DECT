# MAL-DECT

A beginner-friendly Windows malware-risk detector by Visionary Coders, created for a hackathon.

It performs **static analysis**: it only reads a small portion of selected files and never executes them. It flags potentially risky files using extensions, recent changes, and suspicious commands within common script files. A flagged item is a lead to investigate, not proof of malware.

## Run it on Windows

1. Install Python 3 from [python.org](https://www.python.org/downloads/). During installation, check **Add Python to PATH**.
2. Open the `windows-malware-risk-detector` folder.
3. Right-click in empty space, choose **Open in Terminal**.
4. Run:

```powershell
python app.py
```

5. Choose a safe test folder such as Downloads, then click **Scan folder**.

No extra packages are needed.

## Three things to say in the presentation

1. “MAL-DECT gives people a first-pass device safety check without executing suspicious files.”
2. “We combine file type, file age, and suspicious script behavior into an explainable score from 0 to 100.”
3. “In a production version, we would add cloud reputation checks, signed-file verification, and continuously updated threat intelligence.”

## Safe demo idea

Create a text file called `demo.ps1` in a test folder containing this harmless line:

```powershell
# Demo only: powershell -EncodedCommand base64
```

The app should flag it based on its script type and keywords. Do not download, run, or use real malware for a demo.
