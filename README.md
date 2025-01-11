# Start-WindowsPayload

# Legal Notice
    The author of this script is not responsible for any damage, loss, or legal consequences that may arise from the use or misuse of this script. By using this script, you agree to take full responsibility for your actions and obtain proper authorization before conducting any penetration testing activities.

# Disclaimer

### Intended Use
    This script is designed solely for educational purposes and for use in authorized security lab testing environments. This means it should be used as a learning tool to understand security practices, vulnerabilities, and defenses within a controlled setting.

### Restrictions
    Using this script outside of these specified purposes, especially in real-world environments without explicit permission, is strictly prohibited.

### Unauthorized Access
    Accessing or modifying any computer system, network, or data without explicit permission from the owner is both illegal and unethical. Unauthorized actions can lead to severe legal consequences, including fines and imprisonment.

### Compliance
    Always comply with all applicable laws and regulations when using this script. This includes local, national, and international laws related to computer security, privacy, and data protection.

### Responsible Usage
    Ethical Conduct: Use this script responsibly and ethically. This involves respecting the privacy and property of others, obtaining necessary permissions, and avoiding actions that could harm systems, data, or individuals.

### Educational Focus
    Focus on the educational aspect of using this script. Use it to enhance your knowledge and skills in cybersecurity within a safe and legal framework.

# Use Cases
    1. Authorized Testing -  Ensure you have written permission from the system or network owner.
    2. Educational Purposes - Use this script to learn and practice ethical hacking techniques in a controlled and legal environment.

# Safety Tips
    1. Always use a secure and isolated environment for testing.
    2. Do not share or distribute this script without proper context and warnings.
    3. Report any vulnerabilities discovered during testing to the appropriate parties responsibly.

# What this script does

This PowerShell script performs a series of actions primarily focused on data collection, logging, and system configuration. Here's a breakdown of its functionality:

    - Directory Setup:

    Creates directories for logging and storing collected data ($loggingDir, $lootDir).

    - Logging and Loot Directories:

    Ensures the necessary directories exist and logs the creation process.

    - Loot Subdirectories:

    Creates subdirectories within the loot directory for various types of data (e.g., Antivirus, Certificates, Cookies).

    - Distraction:

    Opens a website (Microsoft) to distract the user while the script runs.

    - Functions:

    1. Disable-PowerShellLogging: Disables PowerShell event logging and clears logs.
    2. Get-WifiData: Retrieves Wi-Fi profiles and passwords, saving them to the loot directory.
    3. Get-Data: Collects various system information (environment variables, user info, network info, etc.) and saves it to the loot directory.
    4. Get-WebCookieFile: Stops Microsoft Edge, copies the cookies file to the loot directory, and restarts Edge.
    5. Get-PowerShellHistory: Retrieves PowerShell command history and saves it to the loot directory.
    6. Write-ToErrorLog: Logs error messages to a specified error log file.
    7. New-PowerShellSetup: Configures PowerShell settings and installs necessary package providers.
    8. Add-WindowsPersistence: Adds persistence by modifying the startup registry key and downloading/executing a payload.
    9. New-CollectionArchive: Zips up all collected data
    10. Submit-DataCollection: Uploads to dropbox
    11. Start-WindowsCleanup: Cleans up PowerShell history and session data.
    12. Enable-PowerShellLogging: Enables PowerShell event logging.

    - Execution of Functions:

    Iterates through a list of functions, executing each one and logging the execution.
    Handles errors by logging them.

    - Cleanup and Logging:

    After executing the main functions, it performs cleanup and re-enables PowerShell logging.

    Overall, the script is designed to collect a wide range of system data, log its actions, and ensure persistence by modifying system settings.

# Stay safe and ethical in your security testing endeavors!
