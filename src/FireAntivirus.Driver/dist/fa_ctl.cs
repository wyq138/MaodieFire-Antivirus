using System;
using System.Runtime.InteropServices;

class FaCtl {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, uint inLen, byte[] outBuf, uint outLen, out uint ret, IntPtr ov);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern uint GetLastError();

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
    const uint IOCTL_GET_EVENTS = 0x222014;

    static void Main() {
        IntPtr h = CreateFile(@"\\.\FireAntivirusKernel", GENERIC_READ|GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h == (IntPtr)(-1)) {
            uint e = GetLastError();
            Console.WriteLine("OPEN FAILED err=" + e + (e==5 ? " (ACCESS_DENIED - needs admin)" : (e==2 ? " (NOT FOUND - device/symlink missing)" : "")));
            return;
        }
        Console.WriteLine("OPEN OK");
        byte[] outBuf = new byte[4 + 64*520];
        uint ret;
        if (!DeviceIoControl(h, IOCTL_GET_EVENTS, null, 0, outBuf, (uint)outBuf.Length, out ret, IntPtr.Zero)) {
            Console.WriteLine("IOCTL FAILED err=" + GetLastError());
        } else {
            uint count = BitConverter.ToUInt32(outBuf, 0);
            Console.WriteLine("IOCTL OK, events=" + count);
            for (int i = 0; i < count && i < 64; i++) {
                int off = 4 + i*520;
                uint type = BitConverter.ToUInt32(outBuf, off);
                uint pid = BitConverter.ToUInt32(outBuf, off+4);
                string src = System.Text.Encoding.Unicode.GetString(outBuf, off+8, 256).TrimEnd('\0');
                string det = System.Text.Encoding.Unicode.GetString(outBuf, off+264, 256).TrimEnd('\0');
                Console.WriteLine("  [type=" + type + "] pid=" + pid + " src=" + src + " detail=" + det);
            }
        }
        CloseHandle(h);
    }
}