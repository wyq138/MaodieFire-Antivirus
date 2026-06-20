using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FireAntivirus.Common;
using FireAntivirus.Data;

namespace FireAntivirus.Sandbox
{
    public class SandboxManager
    {
        private DataManager _dataManager;
        private string _sandboxRoot;
        private List<SandboxSession> _activeSessions;

        public SandboxManager(DataManager dataManager)
        {
            _dataManager = dataManager;
            _sandboxRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FireAntivirus", "Sandbox");
            _activeSessions = new List<SandboxSession>();
            InitializeSandboxEnvironment();
        }

        private void InitializeSandboxEnvironment()
        {
            Directory.CreateDirectory(_sandboxRoot);
        }

        public SandboxSession CreateSandboxSession()
        {
            string sessionId = Guid.NewGuid().ToString();
            string sessionPath = Path.Combine(_sandboxRoot, sessionId);
            Directory.CreateDirectory(sessionPath);

            var session = new SandboxSession
            {
                SessionId = sessionId,
                SessionPath = sessionPath,
                CreatedTime = DateTime.Now,
                Status = SandboxStatus.Ready
            };

            _activeSessions.Add(session);
            _dataManager.AddLog(new LogEntry
            {
                Id = Guid.NewGuid().ToString(),
                Time = DateTime.Now,
                Type = "SandboxSessionCreated",
                Message = "沙箱会话已创建",
                Details = $"会话ID: {sessionId}"
            });

            return session;
        }

        public bool RunInSandbox(string filePath, SandboxSession session)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    return false;
                }

                session.Status = SandboxStatus.Running;

                // 模拟在沙箱中运行程序
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = filePath,
                    WorkingDirectory = session.SessionPath,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (Process process = Process.Start(startInfo))
                {
                    process.WaitForExit();
                    session.ExitCode = process.ExitCode;
                }

                session.Status = SandboxStatus.Completed;
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxProgramExecuted",
                    Message = "程序已在沙箱中执行",
                    Details = $"文件: {filePath}, 会话ID: {session.SessionId}"
                });

                return true;
            }
            catch (Exception ex)
            {
                session.Status = SandboxStatus.Failed;
                session.ErrorMessage = ex.Message;
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxExecutionError",
                    Message = "沙箱执行错误",
                    Details = $"文件: {filePath}, 错误: {ex.Message}"
                });
                return false;
            }
        }

        public void CloseSandboxSession(SandboxSession session)
        {
            try
            {
                // 清理沙箱目录
                if (Directory.Exists(session.SessionPath))
                {
                    Directory.Delete(session.SessionPath, true);
                }

                _activeSessions.Remove(session);
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxSessionClosed",
                    Message = "沙箱会话已关闭",
                    Details = $"会话ID: {session.SessionId}"
                });
            }
            catch (Exception ex)
            {
                _dataManager.AddLog(new LogEntry
                {
                    Id = Guid.NewGuid().ToString(),
                    Time = DateTime.Now,
                    Type = "SandboxCleanupError",
                    Message = "沙箱清理错误",
                    Details = $"会话ID: {session.SessionId}, 错误: {ex.Message}"
                });
            }
        }

        public List<SandboxSession> GetActiveSessions()
        {
            return _activeSessions;
        }
    }
}