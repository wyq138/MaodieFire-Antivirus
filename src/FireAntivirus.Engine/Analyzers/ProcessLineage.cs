// 进程血缘图 + kill chain 链级阻断 + LOLBins 无文件执行链路：
//   节点 = PID/PPID/镜像/命令行/深度/恶意标记；边 = 父子关系（保留 30 分钟，上限 5000 节点）。
//   规则命中"父/祖先 → 子 + 命令行标记"链路（Office/浏览器→shell、shell→certutil/regsvr32/mshta…、
//   powershell -enc/-hidden/iex、wmic process call create、mshta javascript: 等）。
//   链级阻断：对确认恶意或高危链路执行 Process.Kill(entireProcessTree:true)，系统/安全进程白名单拒绝。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace FireAntivirus.Engine.Analyzers
{
    public sealed class ProcessNode
    {
        public int Pid { get; set; }
        public int ParentPid { get; set; }
        public int Depth { get; set; }
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public DateTime StartUtc { get; set; } = DateTime.UtcNow;
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
        public bool Malicious { get; set; }
        public string MaliciousReason { get; set; } = "";
    }

    public sealed class ChainHit
    {
        public bool Hit { get; set; }
        public string Name { get; set; } = "";
        public string Technique { get; set; } = "";
        public int Score { get; set; }
        public string Chain { get; set; } = "";
        public bool AutoBlock { get; set; }
    }

    public sealed class ChainBlockResult
    {
        public bool Success { get; set; }
        public int Killed { get; set; }
        public List<string> Failed { get; set; } = new List<string>();
        public string Message { get; set; } = "";
    }

    public static class ProcessLineageGraph
    {
        public static bool Enabled { get; set; } = true;
        public static bool AutoBlockEnabled { get; set; } = true;
        public static int MaxNodes { get; set; } = 5000;
        public static TimeSpan Retention { get; set; } = TimeSpan.FromMinutes(30);

        private sealed class ChainRule
        {
            public string Name { get; set; }
            public string Technique { get; set; }
            public int Score { get; set; }
            public string[] Parents { get; set; }
            public string[] Children { get; set; }
            public string[] CmdMarkers { get; set; } = Array.Empty<string>();
            public bool RequireCmd { get; set; }
        }

        private static readonly string[] Shells = { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32" };

        private static readonly List<ChainRule> Rules = new List<ChainRule>
        {
            new ChainRule { Name = "Office 宏启动解释器", Technique = "T1566/T1204", Score = 70,
                Parents = new[] { "winword", "excel", "powerpnt", "outlook", "wps", "et", "wpp" },
                Children = Shells, RequireCmd = false },
            new ChainRule { Name = "浏览器拉起解释器", Technique = "T1189", Score = 65,
                Parents = new[] { "chrome", "msedge", "firefox", "iexplore", "brave", "opera" },
                Children = Shells, RequireCmd = false },
            new ChainRule { Name = "解释器调用 LOLBin 远程执行", Technique = "T1218/T1105", Score = 85,
                Parents = Shells,
                Children = new[] { "certutil", "bitsadmin", "regsvr32", "rundll32", "mshta", "installutil", "msbuild", "regasm", "regsvcs" },
                CmdMarkers = new[] { "http://", "https://", "urlcache", "-decode", "/i:http", "scrobj", "javascript:", "vbscript:", "ftp://" },
                RequireCmd = true },
            new ChainRule { Name = "PowerShell 编码/隐藏执行", Technique = "T1059.001/T1027", Score = 85,
                Parents = new[] { "*" },
                Children = new[] { "powershell", "pwsh" },
                CmdMarkers = new[] { "-enc ", "-encodedcommand", "-windowstyle hidden", "-w hidden", "iex ", "invoke-expression", "downloadstring", "frombase64string" },
                RequireCmd = true },
            new ChainRule { Name = "WMI 远程进程创建", Technique = "T1047", Score = 78,
                Parents = new[] { "*" }, Children = new[] { "wmic" },
                CmdMarkers = new[] { "process call create", "/node:" }, RequireCmd = true },
            new ChainRule { Name = "mshta 无文件脚本", Technique = "T1218.005", Score = 82,
                Parents = new[] { "*" }, Children = new[] { "mshta" },
                CmdMarkers = new[] { "http://", "https://", "javascript:", "vbscript:" }, RequireCmd = true },
            new ChainRule { Name = "regsvr32 Squiblydoo", Technique = "T1218.010", Score = 88,
                Parents = new[] { "*" }, Children = new[] { "regsvr32" },
                CmdMarkers = new[] { "scrobj.dll", "/i:http", "/i:https" }, RequireCmd = true },
            new ChainRule { Name = "rundll32 JavaScript 执行", Technique = "T1218.011", Score = 82,
                Parents = new[] { "*" }, Children = new[] { "rundll32" },
                CmdMarkers = new[] { "javascript:", "url.dll,fileprotocolhandler" }, RequireCmd = true },
            new ChainRule { Name = "服务宿主异常拉起解释器", Technique = "T1543", Score = 62,
                Parents = new[] { "services", "svchost", "wininit" }, Children = Shells, RequireCmd = false },
            new ChainRule { Name = "临时目录未签名父进程拉起子进程", Technique = "T1059", Score = 60,
                Parents = new[] { "*temp*", "*appdata*", "*programdata*" }, Children = Shells, RequireCmd = false },
            new ChainRule { Name = "安装器滥用执行载荷", Technique = "T1218.004", Score = 72,
                Parents = new[] { "*" }, Children = new[] { "installutil", "msbuild", "regasm", "regsvcs" },
                CmdMarkers = new[] { "http://", "https://", ".dll", "/u " }, RequireCmd = true }
        };

        private static readonly HashSet<string> ProtectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass", "winlogon", "lsaiso", "dwm", "explorer",
            "MsMpEng", "MpDefenderCoreService", "NisSrv", "SecurityHealthService", "SgrmBroker",
            "FireAntivirus", "FireAntivirus.Host.WinUI", "FireAntivirus.ServiceHost"
        };

        private static readonly Dictionary<int, ProcessNode> _nodes = new Dictionary<int, ProcessNode>();
        private static readonly object _lock = new object();

        public static void Register(int pid, int parentPid, string name, string path, string commandLine)
        {
            if (!Enabled || pid <= 0) return;
            lock (_lock)
            {
                int depth = 1;
                if (_nodes.TryGetValue(parentPid, out var parent))
                {
                    depth = parent.Depth + 1;
                    parent.LastSeenUtc = DateTime.UtcNow;
                }
                else if (parentPid > 0)
                {
                    try
                    {
                        using var p = Process.GetProcessById(parentPid);
                        depth = 2;
                        _nodes[parentPid] = new ProcessNode
                        {
                            Pid = parentPid,
                            ParentPid = 0,
                            Depth = 1,
                            Name = Clean(p.ProcessName),
                            StartUtc = DateTime.UtcNow,
                            LastSeenUtc = DateTime.UtcNow
                        };
                    }
                    catch (Exception ex) { System.Diagnostics.Trace.WriteLine("FA-suppressed: " + ex.Message); }
                }

                _nodes[pid] = new ProcessNode
                {
                    Pid = pid,
                    ParentPid = parentPid,
                    Depth = Math.Min(depth, 64),
                    Name = Clean(name),
                    Path = path ?? "",
                    CommandLine = commandLine ?? "",
                    StartUtc = DateTime.UtcNow,
                    LastSeenUtc = DateTime.UtcNow
                };

                if (_nodes.Count > MaxNodes) PruneInternal();
            }
        }

        public static ProcessNode Get(int pid)
        {
            lock (_lock)
            {
                return _nodes.TryGetValue(pid, out var node) ? node : null;
            }
        }

        public static void MarkMalicious(int pid, string reason)
        {
            lock (_lock)
            {
                if (!_nodes.TryGetValue(pid, out var node)) return;
                node.Malicious = true;
                node.MaliciousReason = reason ?? "";
            }
        }

        public static List<ProcessNode> Ancestors(int pid, int maxDepth = 8)
        {
            var list = new List<ProcessNode>();
            lock (_lock)
            {
                int current = pid;
                for (int i = 0; i < maxDepth; i++)
                {
                    if (!_nodes.TryGetValue(current, out var node) || node.ParentPid <= 0) break;
                    if (!_nodes.TryGetValue(node.ParentPid, out var parent)) break;
                    list.Add(parent);
                    current = parent.Pid;
                }
            }
            return list;
        }

        public static List<ProcessNode> Descendants(int pid)
        {
            var result = new List<ProcessNode>();
            lock (_lock)
            {
                var queue = new Queue<int>();
                queue.Enqueue(pid);
                int guard = 0;
                while (queue.Count > 0 && guard++ < MaxNodes)
                {
                    int current = queue.Dequeue();
                    foreach (var child in _nodes.Values.Where(n => n.ParentPid == current))
                    {
                        if (result.Any(n => n.Pid == child.Pid)) continue;
                        result.Add(child);
                        queue.Enqueue(child.Pid);
                    }
                }
            }
            return result;
        }

        public static string DescribeChain(int pid)
        {
            var parts = new List<string>();
            lock (_lock)
            {
                int current = pid;
                for (int i = 0; i < 12; i++)
                {
                    if (!_nodes.TryGetValue(current, out var node)) break;
                    parts.Add($"{node.Name}({node.Pid})");
                    if (node.ParentPid <= 0 || !_nodes.ContainsKey(node.ParentPid)) break;
                    current = node.ParentPid;
                }
            }
            parts.Reverse();
            return string.Join(" → ", parts);
        }

        public static ChainHit Evaluate(int pid)
        {
            var hit = new ChainHit();
            if (!Enabled) return hit;

            ProcessNode node;
            lock (_lock)
            {
                if (!_nodes.TryGetValue(pid, out node)) return hit;
            }

            var ancestors = Ancestors(pid);
            string commandLine = (node.CommandLine ?? "").ToLowerInvariant();

            foreach (var rule in Rules)
            {
                if (!rule.Children.Any(c => NameMatches(node.Name, c))) continue;

                bool parentOk = rule.Parents.Length == 0 || rule.Parents.Any(pattern =>
                    ancestors.Any(a => NameMatches(a.Name, pattern) || PathMatches(a.Path, pattern)));

                if (!parentOk) continue;
                if (rule.RequireCmd && !rule.CmdMarkers.Any(m => commandLine.Contains(m))) continue;

                hit.Hit = true;
                hit.Name = rule.Name;
                hit.Technique = rule.Technique;
                hit.Score = rule.Score;
                hit.Chain = DescribeChain(pid);
                hit.AutoBlock = rule.Score >= 80 && rule.RequireCmd;
                return hit;
            }
            return hit;
        }

        public static ChainBlockResult BlockChain(int pid, bool includeSelf = true)
        {
            var result = new ChainBlockResult();
            if (!Enabled || pid <= 0)
            {
                result.Message = "血缘图未启用或 PID 无效";
                return result;
            }

            ProcessNode node;
            lock (_lock)
            {
                _nodes.TryGetValue(pid, out node);
            }

            if (node == null)
            {
                result.Message = $"PID {pid} 不在血缘图中";
                return result;
            }

            if (ProtectedNames.Contains(node.Name))
            {
                result.Message = $"拒绝终止系统/安全进程: {node.Name} (PID {pid})";
                return result;
            }

            int descendants = Descendants(pid).Count;
            try
            {
                using var process = Process.GetProcessById(pid);
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
                result.Success = true;
                result.Killed = includeSelf ? descendants + 1 : descendants;
                result.Message = $"已链级终止 {result.Killed} 个进程（根: {node.Name} PID {pid}，链: {DescribeChain(pid)}）";
                FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning, result.Message);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = $"链级终止失败（可能进程已退出或权限不足）: {ex.Message}";
                result.Failed.Add(node.Name + ":" + ex.Message);
            }
            return result;
        }

        public static IReadOnlyList<ProcessNode> Snapshot()
        {
            lock (_lock)
            {
                return _nodes.Values.OrderByDescending(n => n.StartUtc).Take(500).ToList();
            }
        }

        public static void Prune()
        {
            lock (_lock) { PruneInternal(); }
        }

        private static void PruneInternal()
        {
            var cutoff = DateTime.UtcNow - Retention;
            foreach (var key in _nodes.Where(kv => kv.Value.LastSeenUtc < cutoff && !IsAlive(kv.Key))
                                      .Select(kv => kv.Key).ToList())
                _nodes.Remove(key);

            if (_nodes.Count <= MaxNodes) return;
            foreach (var key in _nodes.OrderBy(kv => kv.Value.LastSeenUtc)
                                      .Take(_nodes.Count - MaxNodes)
                                      .Select(kv => kv.Key).ToList())
                _nodes.Remove(key);
        }

        private static bool IsAlive(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return !p.HasExited;
            }
            catch { return false; }
        }

        private static string Clean(string name)
        {
            if (string.IsNullOrEmpty(name)) return "";
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
        }

        private static bool NameMatches(string name, string pattern)
        {
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(pattern)) return false;
            var baseName = System.IO.Path.GetFileNameWithoutExtension(name);
            if (pattern == "*") return true;
            if (pattern.Contains('*'))
                return WildcardMatch(name, pattern) || WildcardMatch(baseName, pattern);
            var patternBase = System.IO.Path.GetFileNameWithoutExtension(pattern);
            return string.Equals(baseName, patternBase, StringComparison.OrdinalIgnoreCase);
        }

        private static bool PathMatches(string path, string pattern)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(pattern) || !pattern.Contains('*')) return false;
            return WildcardMatch(path, pattern);
        }

        private static bool WildcardMatch(string text, string pattern)
        {
            int i = 0, j = 0, star = -1, match = 0;
            while (i < text.Length)
            {
                if (j < pattern.Length && (pattern[j] == '*' || char.ToLowerInvariant(pattern[j]) == char.ToLowerInvariant(text[i])))
                {
                    if (j < pattern.Length && pattern[j] == '*') { star = j; match = i; j++; }
                    else { i++; j++; }
                }
                else if (star >= 0) { j = star + 1; match++; i = match; }
                else return false;
            }
            while (j < pattern.Length && pattern[j] == '*') j++;
            return j == pattern.Length;
        }
    }
}