<#
    Author:         n4t5ru
    Email:          hello@nasru.me
    Version:        2.0
    Created:        12/09/2022
    ScriptName:     Enable BitLocker
    Description:    Enables bitlocker with a code generated using hostname
    How To:         Run the script as Administrator:
                    - In case of Domain environment update the required GPO from domain server
                    - If not a domain environment, copy the regkey edits into the main function and run the file
#> 
<#
    # REG Edits. These values can be updated in case of "Error Code: 0x80310031" or the above mentioned 
    # Or you can update Local GPO That corresponds with the following Reg Keys
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "(Default)" -Value "1"
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value "1" -PropertyType "DWORD"
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "EnableWithNonTPM" -Value "0" -PropertyType "DWORD"
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "UseTPMKey" -Value "1" -PropertyType "DWORD"
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "UsePIN" -Value "1" -PropertyType "DWORD"
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "UseTPMKeyPIN" -Value "1" -PropertyType "DWORD"
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FVE" -Name "UseTPM" -Value "1" -PropertyType "DWORD"
    # Updates the GPO after the changes. Just incase.
    GPUPDATE /Force
#>

# This function creates required code for hosts with TPM
function createCode {

    # Retrieves the hostname
    $initialName = $env:COMPUTERNAME | Select-Object;

    # Removes any symbols in the hostnames and replaces with no char
    $convertedName = $initialName.Replace("-","").Replace("_","").Replace(".","").Replace(" ", "")
    
    $pcName_Array = $convertedName.ToCharArray()

    foreach ($echName in $pcName_Array){
        $HEX_CODE = $HEX_CODE + [System.String]::Format("{0:x2}", [System.Convert]::ToUInt32($echName))
    }

    $code = $HEX_CODE.Substring($HEX_CODE.Length - 5)

    return $code
}

# This function creates required passcode for hosts without TPM
function createPassCode {

    # Retrieves the hostname
    $initialName = $env:COMPUTERNAME | Select-Object;

    # Removes any symbols in the hostnames and replaces with no char
    $convertedName = $initialName.Replace("-","").Replace("_","").Replace(".","").Replace(" ", "")
    
    $pcName_Array = $convertedName.ToCharArray()

    foreach ($echName in $pcName_Array){
        $HEX_CODE = $HEX_CODE + [System.String]::Format("{0:x2}", [System.Convert]::ToUInt32($echName))
    }

    # Add desired string to either end or the beginning of the code.
    $code = $HEX_CODE.Substring($HEX_CODE.Length - 5) + '' 

    return $code
}

# This function is used to convert multiple device names (if exported) to hex codes
function generateHexandPassCodes {

    # Retrieves the hostname
    $pcName = Get-Content -Path # Path to file

    foreach ($name in $pcName){

        # Retrieves the hostname
        $orignalDeviceName = $name -split ','

        # Removes any symbols in the hostnames and replaces with no char
        $deviceName = $orignalDeviceName.Replace("-","").Replace("_","").Replace(".","").Replace(" ", "")

        $pcName_Array = $deviceName.ToCharArray()

        foreach ($echName in $pcName_Array){
            $HEX_CODE = $HEX_CODE + [System.String]::Format("{0:x2}", [System.Convert]::ToUInt32($echName))
        }

        $code = $HEX_CODE.Substring($HEX_CODE.Length - 5)
        
        # Add desired string to either end or the beginning of the code.
        # String in the createPassCode function and this should be the same for less/no confusion
        $Password = $HEX_CODE.Substring($HEX_CODE.Length - 5) + '' 

        $string = 'PC Name: ' + $orignalDeviceName + ', Code: ' + $code + ', Password: ' + $Password

        foreach-object{
            Add-Content -Path [PATH TO FILE] -Value $string 
        }

        Start-Sleep 5
    }

}

function main(){

    # If the GPOs have been update via server keep this uncommented.
    GPUpdate /Force

    # Checks status of bitlocker and stores in varriable
    $manageBDE = Manage-Bde -Status C:

    # If the protection is off, runs the default commands
    if($manageBDE[13] -eq '    Identification Field: None'){

        $tpmCheck = Get-Tpm | Out-String
        $tpmArray = @($tpmCheck.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries))

        if($tpmArray[0] = 'TpmPresent                : True'){

            # Variable to store the returned HEX Code from createCode Function
            $returnedVaule = createCode

            # Convert the variable to a secure string
            $Pin = ConvertTo-SecureString $returnedVaule -AsPlainText -Force

            Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -Pin $Pin -TPMandPinProtector

        }
        else{
            # Variable to store the returned HEX and String from createPassCode Function
            $returnedVaule = createPassCode

            # Convert the variable to a secure string
            $Password = ConvertTo-SecureString $returnedVaule -AsPlainText -Force

            Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -PasswordProtector -Password $Password
        }

    }

    # If Bitlocker is on by default
    else {

        Manage-BDE -Off C:

        Write-Host "Your Drive is being Decrypted. Please Keep the Script Running..." -ForegroundColor Red

        $status = Manage-BDE -Status C:
            
        if($status[9] -ne '    Percentage Encrypted: 0.0%'){
            [bool] $statusCheck = $true

            while($statusCheck -eq $true){

                $whileStatus = Manage-BDE -Status C:

                Write-Host $whileStatus[9]
                Start-Sleep 10
                
                if ($whileStatus[9] -eq '    Percentage Encrypted: 0.0%') {
                    Write-Host "Decryption Completed!" -ForegroundColor Green
                    $statusCheck = $false

                    $tpmCheck2 = Get-Tpm | Out-String
                    $tpmArray2 = @($tpmCheck2.Split([System.Environment]::NewLine,[System.StringSplitOptions]::RemoveEmptyEntries))

                    if($tpmArray2[0] -eq 'TpmPresent                : True') {
                
                        # Variable to store the returned HEX Code from createCode Function
                        $returnedVaule = createCode
        
                        # Convert the variable to a secure string
                        $Pin = ConvertTo-SecureString $returnedVaule -AsPlainText -Force
        
                        Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -Pin $Pin -TPMandPinProtector
        
                    }
                    else {
        
                        # Variable to store the returned HEX and String from createPassCode Function
                        $returnedVaule = createPassCode
        
                        # Convert the variable to a secure string
                        $Password = ConvertTo-SecureString $returnedVaule -AsPlainText -Force
        
                        Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -PasswordProtector -Password $Password
                    }
                }
                
            }
        }
    }

    Write-Host "Your Device will restart in 10 Seconds."

    Start-sleep 10

    Remove-Item $PSCommandPath -Force

    Restart-Computer -Force

}

# Uncomment and Comment-out as per your requirement. 
# generateHexandPassCodes
main