# getlapsbof

Beacon Object File (BOF) to retrieve and decrypt LAPSv2 passwords.

# Usage:
Syntax: `getlapsbof <TARGET_DC> <BASE_DN> <TARGET_COMPUTER_DN>`

Example: `getlapsbof sandstone.camp DC=sandstone,DC=camp CN=edworkbox1,OU=LAPSManaged,DC=sandstone,DC=camp`


## Requirements:
- LDAP Connectivity.
- Account with adequate privileges to read the password.

## Caveats:
- LAPSv1 (aka Legacy LAPS) not currently supported. LAPSv1 password is already NOT encrypted. 

## Screenshots
![Image01](scrn/image01.jpg)

## Credits
- jborean93 (DPAPI-NG)
- xpn (Adam Chester)
- DSInternals (Michael Grafnetter)
- Impacket (Fortra/HelpSystems)
- MSDN
