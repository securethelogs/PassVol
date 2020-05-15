# PassVol

![Passvol](https://ctrla1tdel.files.wordpress.com/2020/05/passvol.gif)

## About
PassVoL helps identify passwords stored in GPO XML files. Once discovered it decrypts the passwords and displays.  

## Run

You can either download locally or run remotely: 

powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/securethelogs/PassVol/master/PassVol.ps1')"

## Credit

To be able to crack the cpasswords, I modfied the awesome script Get-DecryptedCpassword:
https://github.com/obscuresec/PowerShell/blob/master/Get-DecryptedCpassword
