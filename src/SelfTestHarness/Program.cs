using System;
using System.Threading.Tasks;
using FireAntivirus.Data;
using FireAntivirus.Engine;
using FireAntivirus.RealTimeProtectionPlus;

internal static class Program
{
    private static async Task<int> Main()
    {
        Console.WriteLine("=== FireAntivirus 功能自检 ===");
        try
        {
            var dm = new DataManager();
            var engine = new AntivirusEngine(dm);

            // 特征库概况
            Console.WriteLine($"[特征库] 播种后 哈希={engine.GetSignatureDatabaseStatus().HashCount}, URL={engine.GetSignatureDatabaseStatus().UrlCount}, IP={engine.GetSignatureDatabaseStatus().IpCount}, 最后更新={engine.GetSignatureDatabaseStatus().LastUpdate:HH:mm:ss}");

            // 真实拉取一次更新（联网），捕获统计/错误
            Console.WriteLine("[更新] 开始联网拉取最新特征(abuse.ch)...");
            try
            {
                var up = await engine.UpdateSignatureDatabaseAsync();
                Console.WriteLine($"[更新] 成功={up.Succeeded} 新增哈希={up.HashesAdded} 新增URL={up.UrlsAdded} 新增IP={up.IpsAdded} 总计={up.Total}");
                if (!string.IsNullOrWhiteSpace(up.Error)) Console.WriteLine($"[更新] 错误: {up.Error}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[更新] 异常(不影响离线查杀): {ex.Message}");
            }

            Console.WriteLine($"[调试] EnableCloudScan={engine.EnableCloudScan} Timeout={engine.CloudScanTimeoutSeconds}");
            var rtp = new RealTimeProtectionPlusManager(dm, engine);
            var results = await FeatureSelfTest.RunAllAsync(dm, engine, rtp);

            int pass = 0, fail = 0;
            foreach (var r in results)
            {
                Console.WriteLine($"[{(r.Passed ? "PASS" : "FAIL")}] {r.Category} | {r.Name} | {r.Detail}");
                if (r.Passed) pass++; else fail++;
            }
            Console.WriteLine($"=== 汇总: 通过 {pass} / 失败 {fail} / 共 {results.Count} ===");
            return fail == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FATAL] {ex}");
            return 2;
        }
    }
}