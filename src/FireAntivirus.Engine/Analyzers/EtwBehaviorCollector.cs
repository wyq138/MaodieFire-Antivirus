// ETW-TI 内核行为遥测（Microsoft.Diagnostics.Tracing.TraceEvent，非原生 P/Invoke）：
//   内核 provider: Process / FileIO / FileIOInit / NetworkTCPIP / Registry；
//   事件 → EtwBehaviorEvent（进程启动含父 PID、文件读写、TCP 连接、注册表写入），
//   供血缘图、熵变时序、污点追踪、WFP 阻断与 EDR 时间线消费。
//   需要管理员权限；失败如实返回错误码并在日志标注，不影响其余防护链。
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace FireAntivirus.Engine.Analyzers
{
    public enum EtwBehaviorKind { ProcessStart, ProcessStop, FileWrite, FileRead, FileDelete, TcpConnect, RegistrySet }

    public sealed class EtwBehaviorEvent
    {
        public EtwBehaviorKind Kind { get; set; }
        public DateTime TimeUtc { get; set; } = DateTime.UtcNow;
        public int Pid { get; set; }
        public int ParentPid { get; set; }
        public string ProcessName { get; set; } = "";
        public string ImagePath { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string RegistryKey { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    public static class EtwBehaviorCollector
    {
        public static bool Enabled { get; set; } = true;
        public static bool IsRunning { get; private set; }
        public static string LastError { get; private set; } = "";
        public static long TotalEvents { get; private set; }

        public static event Action<EtwBehaviorEvent> Behavior;

        private static readonly object _lock = new object();
        private static TraceEventSession _session;
        private static Thread _thread;

        public static bool Start()
        {
            lock (_lock)
            {
                if (IsRunning) return true;
                if (!Enabled) return false;
                try
                {
                    _session = new TraceEventSession("FireAntivirus-ETW", TraceEventSessionOptions.Create)
                    {
                        StopOnDispose = true
                    };

                    _session.EnableKernelProvider(
                        KernelTraceEventParser.Keywords.Process |
                        KernelTraceEventParser.Keywords.FileIO |
                        KernelTraceEventParser.Keywords.FileIOInit |
                        KernelTraceEventParser.Keywords.NetworkTCPIP |
                        KernelTraceEventParser.Keywords.Registry);

                    var kernel = _session.Source.Kernel;

                    kernel.ProcessStart += data => Emit(new EtwBehaviorEvent
                    {
                        Kind = EtwBehaviorKind.ProcessStart,
                        TimeUtc = data.TimeStamp.ToUniversalTime(),
                        Pid = data.ProcessID,
                        ParentPid = data.ParentID,
                        ProcessName = data.ImageFileName ?? "",
                        ImagePath = data.ImageFileName ?? "",
                        Detail = data.CommandLine ?? ""
                    });

                    kernel.ProcessStop += data => Emit(new EtwBehaviorEvent
                    {
                        Kind = EtwBehaviorKind.ProcessStop,
                        TimeUtc = data.TimeStamp.ToUniversalTime(),
                        Pid = data.ProcessID,
                        ProcessName = data.ImageFileName ?? ""
                    });

                    kernel.FileIOWrite += data => EmitFile(EtwBehaviorKind.FileWrite, data);
                    kernel.FileIORead += data => EmitFile(EtwBehaviorKind.FileRead, data);
                    kernel.FileIODelete += data => Emit(new EtwBehaviorEvent
                    {
                        Kind = EtwBehaviorKind.FileDelete,
                        TimeUtc = data.TimeStamp.ToUniversalTime(),
                        Pid = data.ProcessID,
                        ProcessName = data.ProcessName ?? "",
                        FilePath = data.FileName ?? "",
                        Detail = data.FileName ?? ""
                    });

                    kernel.TcpIpConnect += data => Emit(new EtwBehaviorEvent
                    {
                        Kind = EtwBehaviorKind.TcpConnect,
                        TimeUtc = data.TimeStamp.ToUniversalTime(),
                        Pid = data.ProcessID,
                        ProcessName = data.ProcessName ?? "",
                        RemoteAddress = data.daddr?.ToString() ?? "",
                        RemotePort = data.dport,
                        Detail = $"{data.saddr}:{data.sport} → {data.daddr}:{data.dport}"
                    });

                    kernel.RegistrySetValue += data => Emit(new EtwBehaviorEvent
                    {
                        Kind = EtwBehaviorKind.RegistrySet,
                        TimeUtc = data.TimeStamp.ToUniversalTime(),
                        Pid = data.ProcessID,
                        ProcessName = data.ProcessName ?? "",
                        RegistryKey = data.KeyName ?? "",
                        Detail = $"{data.KeyName}\\{data.ValueName}"
                    });

                    _thread = new Thread(() =>
                    {
                        try { _session.Source.Process(); }
                        catch (Exception ex)
                        {
                            LastError = ex.Message;
                            FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                                "ETW 会话结束: " + ex.Message);
                        }
                    })
                    { IsBackground = true, Name = "FAV-ETW" };
                    _thread.Start();

                    IsRunning = true;
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Info,
                        "ETW-TI 行为采集已启动（Process/FileIO/Network/Registry）");
                    return true;
                }
                catch (Exception ex)
                {
                    LastError = ex.Message;
                    IsRunning = false;
                    FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Warning,
                        "ETW 启动失败（需要管理员权限）: " + ex.Message);
                    try { _session?.Dispose(); } catch { }
                    _session = null;
                    return false;
                }
            }
        }

        public static void Stop()
        {
            lock (_lock)
            {
                try { _session?.Dispose(); } catch { }
                _session = null;
                IsRunning = false;
            }
        }

        private static void EmitFile(EtwBehaviorKind kind, FileIOReadWriteTraceData data)
        {
            Emit(new EtwBehaviorEvent
            {
                Kind = kind,
                TimeUtc = data.TimeStamp.ToUniversalTime(),
                Pid = data.ProcessID,
                ProcessName = data.ProcessName ?? "",
                FilePath = data.FileName ?? "",
                Detail = $"{data.FileName} ({data.IoSize} bytes)"
            });
        }

        private static void Emit(EtwBehaviorEvent evt)
        {
            if (!Enabled || evt == null) return;
            TotalEvents++;
            try
            {
                if (evt.Kind == EtwBehaviorKind.ProcessStart && evt.Pid > 0)
                    ProcessLineageGraph.Register(evt.Pid, evt.ParentPid, evt.ProcessName, evt.ImagePath, evt.Detail);

                if ((evt.Kind == EtwBehaviorKind.FileWrite || evt.Kind == EtwBehaviorKind.FileDelete) &&
                    !string.IsNullOrEmpty(evt.FilePath))
                    EntropyTimelineAnalyzer.Observe(evt.FilePath, evt.Pid);

                if (evt.Kind == EtwBehaviorKind.TcpConnect && !string.IsNullOrEmpty(evt.RemoteAddress))
                {
                    DetectionTimeline.Record("ETW", "网络连接", "Info", "T1071", evt.Pid,
                        evt.ProcessName, evt.RemoteAddress, evt.Detail);

                    // 已确认恶意进程的外连 → WFP 数据包级阻断（实时）
                    var node = ProcessLineageGraph.Get(evt.Pid);
                    if (node != null && node.Malicious && WfpBlocker.Enabled)
                        WfpBlocker.Block(evt.RemoteAddress, "恶意进程外连: " + node.Name, 10);
                }

                Behavior?.Invoke(evt);
            }
            catch { }
        }
    }
}