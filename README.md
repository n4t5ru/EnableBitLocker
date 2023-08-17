# EnableBitLocker

## Notes

- Script automating the process of Enabling BitLocker
- The script uses computer name to generate PIN / PASSWORD
- PIN / PASSWORD will be shown after the script completes. Make note of the this as this will not be stored anywhere.

## How it works

- Open powershell as an administrator.
- Run the Script via powershell.
- If BitLocker is already enabled, Script will disable the encryption and will keep running until the drive is decrypted.
- Once decrypted, script will generate a code / password and encrypt the drive.
- Script will also generate a '''Recovery Key''' and store it in a remote location specified.
- Also, the script will enable Remote Access to the device. (This feature is a function. if not required Comment out the function calls).
