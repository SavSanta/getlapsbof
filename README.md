# getlapsbof

Beacon Object File (BOF) to retrieve and decrypt LAPSv2 passwords.

# Usage:
Syntax: `getlapsbof <TARGET_DC> <BASE_DN> <TARGET_COMPUTER_DN>`

Example: `getlapsbof sandstone.camp DC=sandstone,DC=camp CN=edworkbox1,OU=LAPSManaged,DC=sandstone,DC=camp`


<picture will go here>

## Requirements:
- LDAP Connectivity.
- Account with adequate privileges to read the password.

## Caveats:
- LAPSv1 (aka Legacy LAPS) not supported. LAPSv1 password is already NOT encrypted.
- Expiration date is not currently retrievable using the publicized methods. The account Password Last Set Date is retrievable.
The operator must manually calculate the actual expiration date by adding the LAPS Policy for change to the Password Last Set Date.

## Credits
- xpn (Adam Chester)
- DSInternals (Micheal Grafnetter)
- Impacket (Fortra/HelpSystems)
- MSDN 
