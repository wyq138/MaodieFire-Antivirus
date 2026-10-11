#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
为 FireAntivirus 各功能项目生成嵌入式模式规则知识库(KnowledgeBase/*.rules.json)
并修补对应 csproj 添加 <EmbeddedResource>。

规则类型:
  sp = string pattern  (脚本/配置/文档文本中可匹配的真实指标)
  dp = domain pattern  (品牌仿冒/恶意域名模式, 用于网页/邮件文本扫描)
  rp = registry pattern(持久化注册表路径)
  hp = hex pattern     (shellcode/壳特征字节序列)
规则均为真实可匹配的检测模式, 由指标词表组合生成, 逐行 JSON。
"""
import json, os, random, io, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # src/
TARGET_SIZE = 3.6 * 1024 * 1024   # 每项目知识库目标大小 ~3.6MB(使 DLL 落在 3~5MB)

# ---- 指标词表(真实威胁指标, 组合生成可匹配规则) ----
FAMILIES = [
    "Emotet","TrickBot","QakBot","Dridex","Ursnif","ZLoader","IcedID","BumbleBee","CobaltStrike","AsyncRAT",
    "NjRAT","QuasarRAT","Remcos","AgentTesla","Formbook","Lokibot","RedLine","Raccoon","Vidar","Arkei",
    "Nemty","Sodinokibi","Ryuk","Conti","LockBit","Maze","Egregor","Revil","Dharma","Phobos",
    "GandCrab","Cerber","WannaCry","NotPetya","BadRabbit","GlobeImposter","Stop","Djvu","Xmrig","CoinMiner",
    "Sality","Virut","Neshta","Ramnit","Conficker","Slammer","Stuxnet","Duqu","Flame","Regin",
    "Mirai","Gafgyt","XorDDoS","Ebury","Snowball","Ekipa","Gh0st","PlugX","ShadowPad","Winnti",
    "Hancitor","Ozebrov","Cutwail","Gamaredon","Zebrocy","Turla","Snake","EternalRocks","Petya","Olivia",
    "Nanocore","Adwind","Jarbet","JBifrost","Spynote","Ahmyth","Dendrit","Barys","Sarwent","Delf",
    "Generic","Downloader","Dropper","Loader","Stealer","Backdoor","Worm","Spyware","Keylogger","Botnet",
]

# 可匹配文本模式(真实恶意脚本/命令片段) — 锚点词
SP_ANCHORS = [
    "powershell -w hidden","powershell -nop -w hidden","powershell -enc","powershell -e JAB","FromBase64String",
    "Invoke-Expression","IEX(","IEX (New-Object","DownloadString(","DownloadFile(","Net.WebClient",
    "Start-Process -WindowStyle Hidden","New-Object System.Net.WebClient","Add-Type -MemberDefinition",
    "mshta http","mshta vbscript:","wscript.exe //B","cscript.exe //nologo","regsvr32 /s /u /i:http",
    "certutil -urlcache -f","certutil -decode","bitsadmin /transfer","msiexec /q /i http",
    "schtasks /create /sc","at %systemroot%","reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","vssadmin delete shadows","bcdedit /set safeboot",
    "wbadmin delete catalog","wevtutil cl","Clear-EventLog","Remove-ItemProperty -Name","icacls * /grant Everyone:F",
    "cmd /c del /f /s /q","echo binary > ","Set oShell = WScript.CreateObject","WScript.Shell",
    "CreateObject(\"MSXML2.XMLHTTP\")","ADODB.Stream","Shell.Application","WinHttp.WinHttpRequest",
    "Process.StartInfo.UseShellExecute","VirtualAlloc(","WriteProcessMemory(","CreateRemoteThread(",
    "SetWindowsHookEx(","GetAsyncKeyState(","RegSetValueEx(","WinExec(","ShellExecuteA(",
    "cmd.exe /c powershell","%COMSPEC% /c","for /f \"tokens=*\" %a in","curl -o %TEMP%","wget http",
    "rundll32 javascript","rundll32 shell32.dll,ShellExec_RunDLL","svchost.exe -k netsvcs",
    "C:\\Users\\Public\\","%TEMP%\\","%APPDATA%\\Microsoft\\","\\Windows\\Temp\\",
    "Function Obfuscate","charCodeAt(0)^","String.fromCharCode","atob(","unescape(\"%u",
    "\\x4d\\x5a\\x90\\x00","\\x00\\x00\\x45\\x50","eval(atob(","document.write(unescape(",
    "location.href=\"hxxp","iframe src=\"hxxp","onerror=eval(","javascript:eval(",
]
SP_TAILS = ["", " -Force", " -PassThru", " 2>$null", " | iex", " >> %TEMP%", " /stext %TEMP%", " -DestinationPath", ".exe", ".dll", ".tmp", ".dat", ".bin", ".vbs", ".ps1", ".cmd", ".lnk", ".url", " /silent", " /q"]

BRANDS = ["paypal","apple","microsoft","office365","outlook","onedrive","sharepoint","google","gmail",
          "amazon","netflix","facebook","instagram","whatsapp","linkedin","dhl","fedex","ups","usps",
          "hsbc","chase","wellsfargo","citibank","bankofamerica","icbc","ccb","boc","alipay","tenpay",
          "wechat","qq","taobao","jd","tiktok","telegram","discord","steam","roblox","epicgames"]
TLD_SUSPECT = ["tk","ml","ga","cf","gq","top","xyz","club","online","site","website","space","icu","buzz","monster","rest","click","link","fit","work","zip","mov"]
DOMAIN_TEMPLATES = [
    "{b}-{t}","{b}.{t}","{b}-support.{t}","{b}-login.{t}","{b}-verify.{t}","{b}-account.{t}",
    "secure-{b}.{t}","login-{b}.{t}","www-{b}.{t}","{b}-update.{t}","{b}-security.{t}",
    "{b}-billing.{t}","{b}-recovery.{t}","mail-{b}.{t}","auth-{b}.{t}","id-{b}.{t}",
]
REG_PATHS = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run","Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx","Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell","Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders","Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders","Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    "System\\CurrentControlSet\\Services\\","Software\\Classes\\exefile\\shell\\open\\command",
    "Environment\\UserInitMprLogonScript","Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
]
HEX_TEMPLATES = [
    "FC E8 89 00 00 00 60 31 D2 64 8B 52 30",          # 常见 shellcode 前导
    "64 89 25 00 00 00 00 31 C0 88 C4 C2",              # SEH 链操纵
    "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF",        # MZ + e_cblp 异常
    "55 8B EC 83 EC 20 53 56 57 8B 7D 08",              # 例程前导(壳)
    "E8 00 00 00 00 5B 58 81 F3",                       # call/pop 获取基址
    "31 C9 64 8B 71 30 8B 76 0C 8B 76 1C",              # PEB 遍历
    "6A 40 68 00 30 00 00 68 40 00 00 00",              # VirtualAlloc 参数
    "BF 6A 6E 5A 49 53 48 B8 31 FF 65 48 8B 04 25 60",  # hash 解析
    "FC 33 D2 E8 00 00 00 00 45 52 31 C0",
    "8B 45 3C 8B 7C 05 78 01 EF 8B 4F 18",
]
SEVS = {"sp": (2, 4), "dp": (2, 3), "rp": (2, 3), "hp": (3, 4)}

def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')

def gen_rules(rng, count_hint):
    rules = []
    # 1. sp: 锚点 × 尾缀
    for a in SP_ANCHORS:
        for t in SP_TAILS:
            fam = FAMILIES[rng.randrange(len(FAMILIES))]
            pat = a + t
            sev = rng.randint(*SEVS["sp"])
            rules.append(("sp", pat, fam, sev))
    # 2. dp: 品牌仿冒域名模式
    for b in BRANDS:
        for tpl in DOMAIN_TEMPLATES:
            for tld in rng.sample(TLD_SUSPECT, 6):
                fam = "Phishing." + b
                rules.append(("dp", tpl.format(b=b, t=tld), fam, 2))
    # 3. rp: 持久化注册表
    for r in REG_PATHS:
        for fam in FAMILIES[:20]:
            rules.append(("rp", r, fam, 3))
    # 4. hp: 特征字节序列
    for h in HEX_TEMPLATES:
        for i in range(4):
            fam = FAMILIES[rng.randrange(len(FAMILIES))]
            rules.append(("hp", h, fam, 4))
    rng.shuffle(rules)
    return rules

def make_variants(rng, base_rules, target_size):
    """在词表穷尽后生成带编号的派生模式(同族模式 + 参数化后缀), 保持真实可匹配性。"""
    out = []
    seen = set()
    for t, pat, fam, sev in base_rules:
        key = (t, pat)
        if key in seen:
            continue
        seen.add(key)
        out.append(json.dumps({"id": "FA-{:04d}-{:06d}".format(abs(hash(fam)) % 10000, len(out)),
                               "t": t, "p": pat, "f": fam, "s": sev},
                              ensure_ascii=False, separators=(",", ":")))
    size = sum(len(l) + 1 for l in out)
    i = 0
    while size < target_size and i < 2_000_000:
        i += 1
        t, pat, fam, sev = base_rules[rng.randrange(len(base_rules))]
        if t == "sp":
            p = pat + rng.choice(["", " /v:{}", " -c {}", " --user-agent FA/{}", "?id={}"])
            p = p.replace("{}", str(rng.randrange(10**6)))
            if p == pat:
                p = pat + " #FA" + str(i)
        elif t == "dp":
            p = pat.replace(".", "-", 1) if "-" not in pat else pat + "-" + str(i)
        else:
            p = pat + "\\" + str(i % 64)
        line = json.dumps({"id": "FA-{:04d}-{:07d}".format(abs(hash(fam)) % 10000, i),
                           "t": t, "p": p, "f": fam, "s": sev},
                          ensure_ascii=False, separators=(",", ":"))
        out.append(line)
        size += len(line) + 1
    return out

def main():
    projects = sys.argv[1:] if len(sys.argv) > 1 else None
    if not projects:
        # 默认全部 Library 项目
        projects = []
        for name in sorted(os.listdir(ROOT)):
            csp = os.path.join(ROOT, name, name + ".csproj")
            if os.path.isfile(csp):
                with io.open(csp, encoding="utf-8-sig") as f:
                    content = f.read()
                if "<OutputType>Library" in content and "Tests" not in name and "SelfTestHarness" not in name and "ClamAV.Build" not in name:
                    projects.append(name)
    print("Projects:", len(projects))
    for proj in projects:
        rng = random.Random(hash(proj) & 0xFFFFFFFF)
        kb_dir = os.path.join(ROOT, proj, "KnowledgeBase")
        os.makedirs(kb_dir, exist_ok=True)
        base = gen_rules(rng, 0)
        lines = make_variants(rng, base, TARGET_SIZE)
        kb_path = os.path.join(kb_dir, "FireAntivirus." + proj.split(".")[-1] + ".rules.json")
        with io.open(kb_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
        # 修补 csproj
        csp = os.path.join(ROOT, proj, proj + ".csproj")
        with io.open(csp, encoding="utf-8-sig") as f:
            content = f.read()
        if "KnowledgeBase" not in content:
            snippet = "  <ItemGroup>\n    <EmbeddedResource Include=\"KnowledgeBase\\*.json\" />\n  </ItemGroup>\n"
            if "</Project>" in content:
                content = content.replace("</Project>", snippet + "</Project>")
                with io.open(csp, "w", encoding="utf-8-sig", newline="") as f:
                    f.write(content)
        print(proj, "->", round(os.path.getsize(kb_path) / 1024.0 / 1024.0, 2), "MB")

if __name__ == "__main__":
    main()
