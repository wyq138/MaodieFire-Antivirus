using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;

namespace FireAntivirus.Host
{
    public static class ModuleInitializer
    {
        [ModuleInitializer]
        public static void Initialize()
        {
            try
            {
                var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                var libsDir = Path.Combine(baseDir ?? ".", "libs");
                
                // 注册Resolving事件
                AssemblyLoadContext.Default.Resolving += (context, assemblyName) =>
                {
                    try
                    {
                        var dllPath = Path.Combine(libsDir, assemblyName.Name + ".dll");
                        if (File.Exists(dllPath))
                        {
                            return AssemblyLoadContext.Default.LoadFromAssemblyPath(dllPath);
                        }
                    }
                    catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ModuleInitializer.cs 捕获异常", ex.Message); }
                    return null;
                };
                
                // 预加载
                if (Directory.Exists(libsDir))
                {
                    foreach (var dll in Directory.GetFiles(libsDir, "*.dll"))
                    {
                        try { AssemblyLoadContext.Default.LoadFromAssemblyPath(dll); } catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ModuleInitializer.cs 捕获异常", ex.Message); }
                    }
                }
            }
            catch (System.Exception ex) { FireAntivirus.Common.LogHelper.Log(FireAntivirus.Common.LogHelper.LogLevel.Error, "ModuleInitializer.cs 捕获异常", ex.Message); }
        }
    }
}