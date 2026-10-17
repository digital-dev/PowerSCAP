using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using PowerScap.Engine.Native;

namespace PowerScap.Engine.Oval
{
    /// <summary>What a shell command printed, as the interpreter's shell would have shown it.</summary>
    public class CommandOutput
    {
        public CommandOutput()
        {
            Stdout = new List<string>();
            Stderr = new List<string>();
        }

        /// <summary>False when PowerSCAP has no native implementation; nothing was run.</summary>
        public bool Handled { get; set; }

        /// <summary>Exit code of the native program that ran (unsigned), or null when none ran ($LASTEXITCODE unset).</summary>
        public string ExitStatus { get; set; }

        public List<string> Stdout { get; private set; }
        public List<string> Stderr { get; private set; }

        public static CommandOutput Unhandled(string reason)
        {
            var o = new CommandOutput();
            o.Stderr.Add(reason);
            return o;
        }
    }

    public delegate CommandOutput CommandRunner(string shell, string command);

    /// <summary>
    /// Produces the output of shellcommand_object commands without starting a shell or script interpreter.
    /// Scans never run PowerShell or cmd: PowerShell snippets found in SCAP content are reimplemented here
    /// in C#, and plain program invocations start that program directly. A command with no native
    /// implementation is not run at all (Handled = false), and the content inventory test lists it.
    /// </summary>
    public static class NativeShell
    {
        public const int TimeoutMs = 300000;

        delegate Func<CommandOutput> Handler(string command);

        public static CommandOutput Run(string shell, string command)
        {
            var run = Resolve(shell, command);
            if (run == null)
                return CommandOutput.Unhandled("PowerSCAP has no native implementation of this " + shell + " command and does not run shell scripts: " + command);
            var output = run();
            output.Handled = true;
            return output;
        }

        /// <summary>True when Run would handle the command natively. Executes nothing.</summary>
        public static bool IsSupported(string shell, string command)
        {
            return Resolve(shell, command) != null;
        }

        static Func<CommandOutput> Resolve(string shell, string command)
        {
            if (command == null) return null;
            string normalized = Regex.Replace(command.Trim(), @"\s+", " ");
            Handler[] handlers;
            if (IsPowerShell(shell)) handlers = PowerShellHandlers;
            else if (shell == null || shell.Equals("cmd", StringComparison.OrdinalIgnoreCase)) handlers = CmdHandlers;
            else return null;
            foreach (var h in handlers)
            {
                var run = h(normalized);
                if (run != null) return run;
            }
            return null;
        }

        static bool IsPowerShell(string shell)
        {
            return shell != null && (shell.Equals("powershell", StringComparison.OrdinalIgnoreCase) || shell.Equals("pwsh", StringComparison.OrdinalIgnoreCase));
        }

        static readonly Handler[] PowerShellHandlers =
        {
            RegistryAclDump, PnpDeviceClass, ConfirmSecureBoot, AppxPackageByName, GetServiceByName, GetWinEvent,
            IcaclsEnv, IcaclsRegistryValue, PowerShellProgram
        };

        static readonly Handler[] CmdHandlers = { CmdProgram };

        static Match Exact(string pattern, string command)
        {
            var m = Regex.Match(command, "^" + pattern + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return m.Success ? m : null;
        }

        // ---- PowerShell snippets ------------------------------------------------------------------

        const string AclDumpTemplate = "([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(\"{KEY}\", [System.Security.AccessControl.RegistryRights]::ReadPermissions)).GetAccessControl().Access | Where-Object { $_.RegistryRights -notmatch '\\d+' } | ForEach-Object { \"Identity:$($_.IdentityReference), Rights: $($_.RegistryRights), Access: $($_.AccessControlType), IsInherited: $($_.IsInherited), InheritanceFlags: $($_.InheritanceFlags), PropagationFlags: $($_.PropagationFlags)\" }";

        /// <summary>Access rules of an HKLM key, one formatted line per rule whose rights have a name.</summary>
        static Func<CommandOutput> RegistryAclDump(string command)
        {
            var m = Exact(@"\(\[Microsoft\.Win32\.Registry\]::LocalMachine\.OpenSubKey\(""([^""]+)"".*", command);
            if (m == null) return null;
            string key = m.Groups[1].Value;
            if (!string.Equals(AclDumpTemplate.Replace("{KEY}", key), command, StringComparison.OrdinalIgnoreCase)) return null;
            return () =>
            {
                var o = new CommandOutput();
                try
                {
                    using (var lm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default))
                    using (var k = lm.OpenSubKey(key, RegistryKeyPermissionCheck.Default, RegistryRights.ReadPermissions))
                    {
                        if (k == null) { o.Stderr.Add("You cannot call a method on a null-valued expression."); return o; }
                        foreach (RegistryAccessRule rule in k.GetAccessControl().GetAccessRules(true, true, typeof(NTAccount)))
                        {
                            string rights = rule.RegistryRights.ToString();
                            if (Regex.IsMatch(rights, @"\d+")) continue;
                            o.Stdout.Add("Identity:" + rule.IdentityReference + ", Rights: " + rights + ", Access: " + rule.AccessControlType +
                                ", IsInherited: " + (rule.IsInherited ? "True" : "False") + ", InheritanceFlags: " + rule.InheritanceFlags +
                                ", PropagationFlags: " + rule.PropagationFlags);
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (!(ex is System.Security.SecurityException || ex is UnauthorizedAccessException || ex is IOException)) throw;
                    o.Stderr.Add(ex.Message);
                }
                return o;
            };
        }

        /// <summary>(Get-PnpDevice -class X -status OK).class: the class name once per working device of that class.</summary>
        static Func<CommandOutput> PnpDeviceClass(string command)
        {
            var m = Exact(@"\(Get-PnpDevice -class (\w+) -status OK\)\.class", command);
            if (m == null) return null;
            string cls = m.Groups[1].Value;
            return () =>
            {
                var o = new CommandOutput();
                string wql = "SELECT PNPClass FROM Win32_PnPEntity WHERE PNPClass = '" + cls + "' AND Status = 'OK'";
                using (var s = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"), new ObjectQuery(wql)))
                    foreach (ManagementBaseObject mo in s.Get())
                        o.Stdout.Add(Convert.ToString(mo["PNPClass"], CultureInfo.InvariantCulture));
                if (o.Stdout.Count == 0)
                    o.Stderr.Add("Get-PnpDevice : No matching Win32_PnPEntity objects found by CIM query for instances of the ROOT/cimv2/Win32_PnPEntity class on the  CIM server: SELECT * FROM Win32_PnPEntity  WHERE ((PNPClass LIKE '" + cls + "')) AND ((Status LIKE 'OK')). Verify query parameters and retry.");
                return o;
            };
        }

        /// <summary>Confirm-SecureBootUEFI: the UEFI SecureBoot variable, True when it is 1.</summary>
        static Func<CommandOutput> ConfirmSecureBoot(string command)
        {
            if (Exact("Confirm-SecureBootUEFI", command) == null) return null;
            return () =>
            {
                var o = new CommandOutput();
                if (Firmware.Type() != "Uefi") { o.Stderr.Add("Confirm-SecureBootUEFI : Cmdlet not supported on this platform: 0xC0000002"); return o; }
                bool? enabled = Firmware.SecureBootEnabled();
                if (enabled == null) o.Stderr.Add("Confirm-SecureBootUEFI : Access was denied.");
                else o.Stdout.Add(enabled.Value ? "True" : "False");
                return o;
            };
        }

        /// <summary>
        /// Get-AppxPackage -AllUsers filtered by name. Packages come from the machine package repository, which
        /// covers every user. Output lines follow the cmdlet's list layout; content only tests whether any exist.
        /// </summary>
        static Func<CommandOutput> AppxPackageByName(string command)
        {
            var m = Exact(@"Get-AppxPackage -AllUsers \| Where-Object \{ \$_\.Name -like '([^']*)' \}", command);
            if (m == null) return null;
            var like = LikePattern(m.Groups[1].Value);
            return () =>
            {
                var o = new CommandOutput();
                const string repo = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages";
                using (var lm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default))
                using (var packages = lm.OpenSubKey(repo))
                {
                    if (packages == null) return o;
                    foreach (var fullName in packages.GetSubKeyNames())
                    {
                        // PackageFullName = Name_Version_Architecture_ResourceId_PublisherId; "~" marks a bundle.
                        var parts = fullName.Split('_');
                        if (parts.Length != 5 || parts[3] == "~" || !like.IsMatch(parts[0])) continue;
                        string location;
                        using (var k = packages.OpenSubKey(fullName)) location = k == null ? null : k.GetValue("Path") as string;
                        var fields = new List<KeyValuePair<string, string>>
                        {
                            new KeyValuePair<string, string>("Name", parts[0]),
                            new KeyValuePair<string, string>("Architecture", Architecture(parts[2])),
                            new KeyValuePair<string, string>("ResourceId", parts[3]),
                            new KeyValuePair<string, string>("Version", parts[1]),
                            new KeyValuePair<string, string>("PackageFullName", fullName),
                            new KeyValuePair<string, string>("InstallLocation", location ?? ""),
                            new KeyValuePair<string, string>("PackageFamilyName", parts[0] + "_" + parts[4]),
                            new KeyValuePair<string, string>("PublisherId", parts[4])
                        };
                        o.Stdout.AddRange(ListLayout(fields));
                    }
                }
                return o;
            };
        }

        /// <summary>PowerShell -like wildcard (* ? [set], backtick escapes), case-insensitive.</summary>
        static Regex LikePattern(string pattern)
        {
            var sb = new StringBuilder("^");
            for (int i = 0; i < pattern.Length; i++)
            {
                char c = pattern[i];
                if (c == '`' && i + 1 < pattern.Length) { sb.Append(Regex.Escape(pattern[++i].ToString())); continue; }
                if (c == '*') sb.Append(".*");
                else if (c == '?') sb.Append('.');
                else if (c == '[' && pattern.IndexOf(']', i + 1) > i)
                {
                    int close = pattern.IndexOf(']', i + 1);
                    sb.Append('[').Append(pattern.Substring(i + 1, close - i - 1).Replace("\\", "\\\\")).Append(']');
                    i = close;
                }
                else sb.Append(Regex.Escape(c.ToString()));
            }
            return new Regex(sb.Append('$').ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        static string Architecture(string arch)
        {
            switch (arch.ToLowerInvariant())
            {
                case "x64": return "X64";
                case "x86": return "X86";
                case "arm": return "Arm";
                case "arm64": return "Arm64";
                default: return "Neutral";
            }
        }

        /// <summary>Format-List layout for one object: blank lines around "Label : value" rows.</summary>
        static IEnumerable<string> ListLayout(IList<KeyValuePair<string, string>> fields)
        {
            int width = fields.Max(f => f.Key.Length);
            yield return "";
            yield return "";
            foreach (var f in fields) yield return f.Key.PadRight(width) + " : " + f.Value;
        }

        /// <summary>Get-Service -name X in the default 5.1 table view (Status 8, Name 18, DisplayName 38; fixed widths truncate with "...").</summary>
        static Func<CommandOutput> GetServiceByName(string command)
        {
            var m = Exact(@"Get-Service -name ([\w.-]+)", command);
            if (m == null) return null;
            string name = m.Groups[1].Value;
            return () =>
            {
                var o = new CommandOutput();
                var svc = ServiceController.GetServices().Concat(ServiceController.GetDevices())
                    .FirstOrDefault(s => s.ServiceName.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (svc == null) { o.Stderr.Add("Get-Service : Cannot find any service with service name '" + name + "'."); return o; }
                using (svc)
                {
                    var widths = new[] { 8, 18, 38 };
                    o.Stdout.Add("");
                    o.Stdout.Add(Row(widths, "Status", "Name", "DisplayName"));
                    o.Stdout.Add(Row(widths, "------", "----", "-----------"));
                    o.Stdout.Add(Row(widths, svc.Status.ToString(), svc.ServiceName, svc.DisplayName));
                    o.Stdout.Add("");
                    o.Stdout.Add("");
                }
                return o;
            };
        }

        /// <summary>One table row with fixed-width, left-aligned columns separated by a space.</summary>
        static string Row(int[] widths, params string[] cells)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < cells.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(Fit(cells[i] ?? "", widths[i]));
            }
            return sb.ToString();
        }

        static string Fit(string value, int width)
        {
            if (value.Length > width) return value.Substring(0, width - 3) + "...";
            return value.PadRight(width);
        }

        /// <summary>get-winevent -logname L -MaxEvents N in the default table view, newest first, grouped by provider.</summary>
        static Func<CommandOutput> GetWinEvent(string command)
        {
            var m = Exact(@"(get-winevent) -logname (\S+) -MaxEvents (\d+)", command);
            if (m == null) return null;
            string typed = m.Groups[1].Value, log = m.Groups[2].Value;
            int max = int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);
            return () =>
            {
                var o = new CommandOutput();
                if (!EventLogSession.GlobalSession.GetLogNames().Contains(log, StringComparer.OrdinalIgnoreCase))
                {
                    o.Stderr.Add(typed + " : There is not an event log on the localhost computer that matches \"" + log + "\".");
                    return o;
                }
                var events = new List<EventRecord>();
                try
                {
                    using (var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName) { ReverseDirection = true }))
                    {
                        EventRecord e;
                        while (events.Count < max && (e = reader.ReadEvent()) != null) events.Add(e);
                    }
                    if (events.Count == 0) { o.Stderr.Add(typed + " : No events were found that match the specified selection criteria."); return o; }
                    string provider = null;
                    foreach (var e in events)
                    {
                        if (e.ProviderName != provider)
                        {
                            if (provider != null) { o.Stdout.Add(""); o.Stdout.Add(""); }
                            provider = e.ProviderName;
                            o.Stdout.Add("");
                            o.Stdout.Add("");
                            o.Stdout.Add("   ProviderName: " + provider);
                            o.Stdout.Add("");
                            o.Stdout.Add("TimeCreated                      Id LevelDisplayName Message");
                            o.Stdout.Add("-----------                      -- ---------------- -------");
                        }
                        string time = e.TimeCreated.HasValue ? e.TimeCreated.Value.ToString(CultureInfo.CurrentCulture) : "";
                        string level = "";
                        try { level = e.LevelDisplayName ?? ""; } catch (EventLogException) { }
                        string message = null;
                        try { message = e.FormatDescription(); } catch (EventLogException) { }
                        message = (message ?? "").Replace("\r\n", "\n");
                        int nl = message.IndexOf('\n');
                        if (nl >= 0) message = message.Substring(0, nl) + "...";
                        o.Stdout.Add(Fit(time, 25) + " " + e.Id.ToString(CultureInfo.InvariantCulture).PadLeft(9) + " " + Fit(level, 16) + " " + message);
                    }
                    o.Stdout.Add("");
                    o.Stdout.Add("");
                }
                finally
                {
                    foreach (var e in events) e.Dispose();
                }
                return o;
            };
        }

        /// <summary>icacls($env:NAME) and icacls($env:NAME + '\').</summary>
        static Func<CommandOutput> IcaclsEnv(string command)
        {
            var m = Exact(@"icacls ?\(\$env:(\w+)( \+ '\\')?\)", command);
            if (m == null) return null;
            string name = m.Groups[1].Value;
            bool slash = m.Groups[2].Success;
            return () =>
            {
                string value = Environment.GetEnvironmentVariable(name) ?? "";
                return RunProgram(SystemProgram("icacls"), PowerShellArgument(value + (slash ? "\\" : "")));
            };
        }

        /// <summary>icacls (Get-ItemProperty -Path "HKLM:\..." -Name N).N, with N bare or single-quoted.</summary>
        static Func<CommandOutput> IcaclsRegistryValue(string command)
        {
            var m = Exact(@"icacls \(Get-ItemProperty -Path ""HKLM:\\([^""]+)"" -Name (?:'([^']+)'|(\w+))\)\.(?:'([^']+)'|(\w+))", command);
            if (m == null) return null;
            string key = m.Groups[1].Value;
            string name = m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
            string member = m.Groups[4].Success ? m.Groups[4].Value : m.Groups[5].Value;
            if (!name.Equals(member, StringComparison.OrdinalIgnoreCase)) return null;
            return () =>
            {
                object value;
                using (var lm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default))
                using (var k = lm.OpenSubKey(key))
                    value = k == null ? null : k.GetValue(name);
                if (value == null)
                {
                    var o = new CommandOutput();
                    o.Stderr.Add("Get-ItemProperty : Property " + name + " does not exist at path HKEY_LOCAL_MACHINE\\" + key + ".");
                    return o;
                }
                return RunProgram(SystemProgram("icacls"), PowerShellArgument(Convert.ToString(value, CultureInfo.InvariantCulture)));
            };
        }

        /// <summary>Default PowerShell 5.1 aliases that would shadow a System32 program of the same name.</summary>
        static readonly HashSet<string> PowerShellAliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "sc", "where", "sort", "fc", "curl", "wget", "echo", "type", "dir", "copy", "del", "move", "ren", "md", "rd",
            "cls", "set", "start", "kill", "ls", "cat", "cp", "mv", "rm", "ps", "man", "mount", "measure", "select", "tee", "write", "compare", "diff"
        };

        /// <summary>A System32 program with plain arguments (e.g. "bcdedit /enum"), started directly.</summary>
        static Func<CommandOutput> PowerShellProgram(string command)
        {
            var m = Exact(@"([A-Za-z][\w.]*)((?: [^\s$()|;{}`""'@&<>,]+)*)", command);
            if (m == null || PowerShellAliases.Contains(m.Groups[1].Value)) return null;
            string program = SystemProgram(m.Groups[1].Value);
            if (program == null) return null;
            string args = m.Groups[2].Value.Trim();
            return () => RunProgram(program, args);
        }

        /// <summary>cmd.exe internal commands, which take precedence over any program of the same name.</summary>
        static readonly HashSet<string> CmdBuiltins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "assoc", "break", "call", "cd", "chdir", "cls", "color", "copy", "date", "del", "dir", "dpath", "echo", "endlocal", "erase",
            "exit", "for", "ftype", "goto", "if", "keys", "md", "mkdir", "mklink", "move", "path", "pause", "popd", "prompt", "pushd",
            "rd", "rem", "ren", "rename", "rmdir", "set", "setlocal", "shift", "start", "time", "title", "type", "ver", "verify", "vol"
        };

        /// <summary>cmd: "program args" with no cmd operators; %VAR% expands as cmd would. Builtins and batch files are not run.</summary>
        static Func<CommandOutput> CmdProgram(string command)
        {
            if (command.IndexOfAny(new[] { '&', '|', '<', '>', '^' }) >= 0) return null;
            string expanded = Environment.ExpandEnvironmentVariables(command);
            string file, args;
            if (expanded.StartsWith("\""))
            {
                int close = expanded.IndexOf('"', 1);
                if (close < 0) return null;
                file = expanded.Substring(1, close - 1);
                args = expanded.Substring(close + 1).Trim();
            }
            else
            {
                int space = expanded.IndexOf(' ');
                file = space < 0 ? expanded : expanded.Substring(0, space);
                args = space < 0 ? "" : expanded.Substring(space + 1).Trim();
            }
            if (CmdBuiltins.Contains(file)) return null;
            string program = FindProgram(file);
            if (program == null) return null;
            return () => RunProgram(program, args);
        }

        static string SystemProgram(string name)
        {
            if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return null;
            foreach (var candidate in new[] { name, name + ".exe", name + ".com" })
            {
                if (!candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !candidate.EndsWith(".com", StringComparison.OrdinalIgnoreCase)) continue;
                string path = Path.Combine(Environment.SystemDirectory, candidate);
                if (File.Exists(path)) return path;
            }
            return null;
        }

        /// <summary>An .exe/.com by full path, or by name on PATH.</summary>
        static string FindProgram(string file)
        {
            if (file.Length == 0 || file.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return null;
            var names = Path.HasExtension(file) ? new[] { file } : new[] { file + ".exe", file + ".com" };
            names = names.Where(n => n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".com", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (Path.IsPathRooted(file)) return names.FirstOrDefault(File.Exists);
            if (file.IndexOfAny(new[] { '\\', '/' }) >= 0) return null;
            var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';').Where(d => d.Trim().Length > 0);
            foreach (var dir in dirs)
                foreach (var n in names)
                {
                    string path;
                    try { path = Path.Combine(Environment.ExpandEnvironmentVariables(dir.Trim().Trim('"')), n); }
                    catch (ArgumentException) { continue; }
                    if (File.Exists(path)) return path;
                }
            return null;
        }

        /// <summary>How PowerShell 5.1 passes one string argument to a program: quoted only when it contains whitespace.</summary>
        static string PowerShellArgument(string value)
        {
            return Regex.IsMatch(value, @"\s") ? "\"" + value + "\"" : value;
        }

        /// <summary>Starts the program itself (no shell) and captures its output lines and exit code.</summary>
        public static CommandOutput RunProgram(string program, string arguments)
        {
            var o = new CommandOutput();
            var encoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
            var psi = new ProcessStartInfo(program, arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = encoding,
                StandardErrorEncoding = encoding,
                WorkingDirectory = Environment.SystemDirectory
            };
            using (var p = Process.Start(psi))
            {
                var err = p.StandardError.ReadToEndAsync();
                string stdout = p.StandardOutput.ReadToEnd();
                if (!p.WaitForExit(TimeoutMs))
                {
                    try { p.Kill(); } catch (Exception) { }
                    throw new System.TimeoutException("Program timed out: " + program + " " + arguments);
                }
                o.Stdout.AddRange(Lines(stdout));
                o.Stderr.AddRange(Lines(err.Result).Where(l => l.Length > 0));
                o.ExitStatus = unchecked((uint)p.ExitCode).ToString(CultureInfo.InvariantCulture);
            }
            return o;
        }

        /// <summary>Lines as a line reader sees them: the final newline does not start another (empty) line.</summary>
        public static IList<string> Lines(string text)
        {
            if (string.IsNullOrEmpty(text)) return new string[0];
            return text.Replace("\r\n", "\n").TrimEnd('\n').Split('\n');
        }
    }

    /// <summary>UEFI firmware facts (kernel32).</summary>
    public static class Firmware
    {
        [DllImport("kernel32.dll")]
        static extern bool GetFirmwareType(out int type);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int GetFirmwareEnvironmentVariableEx(string name, string guid, byte[] buffer, int size, out int attributes);

        const string GlobalVariableGuid = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";

        /// <summary>FIRMWARE_TYPE name as PowerShell shows it: Unknown, Bios, Uefi or Max.</summary>
        public static string Type()
        {
            int t;
            if (!GetFirmwareType(out t)) return "Unknown";
            switch (t)
            {
                case 1: return "Bios";
                case 2: return "Uefi";
                case 3: return "Max";
                default: return "Unknown";
            }
        }

        /// <summary>The SecureBoot UEFI variable; null when it cannot be read (needs SeSystemEnvironmentPrivilege).</summary>
        public static bool? SecureBootEnabled()
        {
            Hive.EnablePrivilege("SeSystemEnvironmentPrivilege");
            var buffer = new byte[1];
            int attributes;
            int size = GetFirmwareEnvironmentVariableEx("SecureBoot", GlobalVariableGuid, buffer, buffer.Length, out attributes);
            if (size > 0) return buffer[0] == 1;
            int error = Marshal.GetLastWin32Error();
            if (error == 203) return false; // ERROR_ENVVAR_NOT_FOUND: firmware without Secure Boot
            return null;
        }
    }
}
