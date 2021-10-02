# PowerSpray

In an Active Directory environment, Kerberos authentication is initiated for a given user by requesting a TGT with preauthentication data encrypted with the user's password-based key (KRB_AS_REQ message).
The domain controller's Kerberos service (Key Distribution Center) receives the authentication request, validates the data, and replies with a TGT encrypted and signed by the KDC service account (KRB_AS_REP message).
The TGT provided to the user is then presented to the KDC as proof of identity every time a resource ticket is requested to access a specific resource (Service Principal Name).

PowerSpray leverages Kerberos preauthentication in order to:
  - Identify valid usernames from an unauthenticated perspective (enumeration)
  - Retrieve encrypted material for users that do not have preauthentication required (AS-REP roasting)
  - Validate plain-text passwords against domain users (spraying)
  - Validate NTLM password hashes dumped from a compromised domain against another target domain in order to identify credential reuse (stuffing)


## Enumeration

When a AS-REQ is sent without preauthentication data, the server responds with a Kerberos error code that reveals the validity of a username:

| Kerberos error              | User status            |
| --------------------------- | ---------------------- |
| KDC_ERR_C_PRINCIPAL_UNKNOWN | Does not exist         |
| KDC_ERR_PREAUTH_REQUIRED    | Present and enabled    |
| KDC_ERR_CLIENT_REVOKED      | Disabled or locked out |

To discover valid usernames from an unauthenticated perspective, the following command launches a bruteforce-style attack based on a list of likely usernames:

```
PS C:\> Invoke-PowerSpray -UserFile .\users.lst -Server 192.168.1.10 -Threads 5
```


## AS-REP roasting

If preauthentication is not enabled for a given user, the server returns an AS-REP response including encrypted material that can be cracked offline to reveal the target user's password.
The encryption type may be downgraded to ARCFOUR-HMAC-MD5 (ETYPE 23) which is significantly quicker to crack than the default AES256-CTS-HMAC-SHA1-96 (ETYPE 18) encryption.
From an authenticated perspective, users vulnerable to this attack known as "AS-REP roasting" can be retrieved via LDAP based on their attribute "userAccountControl":

```
PS C:\> Invoke-PowerSpray -Ldap -Server DC.ADATUM.CORP -EncType RC4
```

By default, the LDAP connection is established within the current user authenticated context but alternative credentials can be specified using `-LdapCredential` parameters.


## Spraying

Kerberos preauthentication is a stealthy way to credential guessing since a failing attempt does not trigger traditional logon failure event.
When an AS-REQ is sent with preauthentication data, the server returns a TGT in a AS-REP response or a Kerberos error code such as "KDC_ERR_PREAUTH_FAILED" and "KDC_ERR_KEY_EXPIRED".
The latter is useful here as well, since it reveals that the provided password is valid but expired.

A password spraying attack attempts to login across all of the enabled domain users using one strategically chosen password:

```
PS C:\> Invoke-PowerSpray -Ldap -Server DC.ADATUM.CORP -Password 'Welcome2020'
```

As an alternative, the `-UserAsPassword` switch can be used to specify the username as password for each authentication attempt.

To prevent account lockout, the attribute "badPwdCount" is retrieved via LDAP for each domain account and compared to the threshold defined in domain's default password policy. A custom threshold can also be specified with the `-LockoutThreshold` parameter.
This LDAP attribute can also be useful to check after an unsuccessful authentication because an unchanged value means that the provided password is a previous one of the given user, revealing a potential password pattern.
This feature can be enabled using the `-CheckOldPwd` switch but it implies an increased number of LDAP queries.

Privilege escalation capabilities from guessed credentials to high value targets are identified against a prepopulated BloodHound instance using the `-BloodHound` switch.
The Neo4j credentials are pass through the `-Neo4jCredential` parameter and the Neo4j server address and port can be specified using `-Neo4jHost` and `-Neo4jPort`.


## Stuffing

To authenticate the subject making the AS-REQ, a timestamp included in the preauthentication data is encrypted with the secret key derived from the user's password and based on DES, AES128, AES256 or RC4 algorithm.
The RC4 encryption algorithm allows us to perform Kerberos preauthentication using an NTLM password hash:

```
PS C:\> Invoke-PowerSpray -UserName testuser -Server DC.ADATUM.CORP -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 
```

Such pass-the-key attack can be leveraged to identify credential reuse between a compromised domain and another target domain.
A password stuffing attack attempts to login to the target domain using the secretsdump output resulting from a DCSync attack against the compromised domain:

```
PS C:\> Invoke-PowerSpray -DumpFile .\CONTOSO.ntds -Server ADATUM.CORP -Delay 1 -Jitter 0.5
```

Credential reuse between domains may provide a way to domain compromising when no trust relationship could be exploited.


## Credits

* https://www.harmj0y.net/blog/activedirectory/roasting-as-reps
* https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus
* https://blog.fox-it.com/2017/11/28/further-abusing-the-badpwdcount-attribute
