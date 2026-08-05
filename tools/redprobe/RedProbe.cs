using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Ignotus.RedMode
{
    public sealed class ProbeResult
    {
        public string Module { get; set; }
        public string Export { get; set; }
        public string Path { get; set; }
        public string LoadedBytes { get; set; }
        public string CleanBytes { get; set; }
        public bool BytesMatch { get; set; }
        public string MemoryProtection { get; set; }
        public bool WritableExecutable { get; set; }
        public bool SuspiciousPrologue { get; set; }
        public string Status { get; set; }
        public string Error { get; set; }
    }

    public static class NativeProbe
    {
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint PAGE_READONLY = 0x02;
        private const uint SEC_IMAGE = 0x01000000;
        private const uint FILE_MAP_READ = 0x0004;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string fileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleFileName(IntPtr module, StringBuilder fileName, int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UIntPtr VirtualQuery(IntPtr address, out MEMORY_BASIC_INFORMATION info, UIntPtr length);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileMapping(
            IntPtr file, IntPtr attributes, uint protect, uint maximumSizeHigh,
            uint maximumSizeLow, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr MapViewOfFile(
            IntPtr mapping, uint desiredAccess, uint fileOffsetHigh,
            uint fileOffsetLow, UIntPtr bytesToMap);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UnmapViewOfFile(IntPtr address);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static ProbeResult[] Inspect()
        {
            var results = new List<ProbeResult>();
            InspectModule(results, "amsi.dll", new[] { "AmsiScanBuffer", "AmsiScanString" });
            InspectModule(results, "ntdll.dll", new[] { "EtwEventWrite", "NtTraceEvent" });
            return results.ToArray();
        }

        private static void InspectModule(List<ProbeResult> results, string moduleName, string[] exports)
        {
            IntPtr module = LoadLibrary(moduleName);
            if (module == IntPtr.Zero)
            {
                foreach (string export in exports)
                    results.Add(Failure(moduleName, export, "LoadLibrary failed: " + Marshal.GetLastWin32Error()));
                return;
            }

            var pathBuffer = new StringBuilder(32768);
            GetModuleFileName(module, pathBuffer, pathBuffer.Capacity);
            string path = pathBuffer.ToString();

            IntPtr file = CreateFile(
                path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (file == new IntPtr(-1))
            {
                foreach (string export in exports)
                    results.Add(Failure(moduleName, export, "CreateFile failed: " + Marshal.GetLastWin32Error()));
                return;
            }

            IntPtr mapping = IntPtr.Zero;
            IntPtr cleanBase = IntPtr.Zero;
            try
            {
                mapping = CreateFileMapping(file, IntPtr.Zero, PAGE_READONLY | SEC_IMAGE, 0, 0, null);
                if (mapping == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileMapping failed");
                cleanBase = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, UIntPtr.Zero);
                if (cleanBase == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "MapViewOfFile failed");

                foreach (string export in exports)
                    results.Add(InspectExport(moduleName, export, path, module, cleanBase));
            }
            catch (Exception error)
            {
                foreach (string export in exports)
                    results.Add(Failure(moduleName, export, error.Message));
            }
            finally
            {
                if (cleanBase != IntPtr.Zero) UnmapViewOfFile(cleanBase);
                if (mapping != IntPtr.Zero) CloseHandle(mapping);
                CloseHandle(file);
            }
        }

        private static ProbeResult InspectExport(
            string moduleName, string export, string path, IntPtr loadedBase, IntPtr cleanBase)
        {
            IntPtr loadedAddress = GetProcAddress(loadedBase, export);
            IntPtr cleanAddress = FindExport(cleanBase, export);
            if (loadedAddress == IntPtr.Zero || cleanAddress == IntPtr.Zero)
                return Failure(moduleName, export, "Export not found in loaded or clean image");

            byte[] loaded = ReadBytes(loadedAddress, 16);
            byte[] clean = ReadBytes(cleanAddress, 16);
            bool match = ConstantTimeEquals(loaded, clean);
            bool suspicious = IsSuspiciousPrologue(loaded);

            MEMORY_BASIC_INFORMATION memory;
            VirtualQuery(loadedAddress, out memory, new UIntPtr((uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))));
            uint baseProtection = memory.Protect & 0xFF;
            bool writableExecutable = baseProtection == 0x40 || baseProtection == 0x80;

            return new ProbeResult
            {
                Module = moduleName,
                Export = export,
                Path = path,
                LoadedBytes = Hex(loaded),
                CleanBytes = Hex(clean),
                BytesMatch = match,
                MemoryProtection = "0x" + memory.Protect.ToString("X"),
                WritableExecutable = writableExecutable,
                SuspiciousPrologue = suspicious,
                Status = match && !suspicious && !writableExecutable ? "PASS" : "WARN",
                Error = null
            };
        }

        private static IntPtr FindExport(IntPtr imageBase, string target)
        {
            int peOffset = Marshal.ReadInt32(IntPtr.Add(imageBase, 0x3C));
            IntPtr optional = IntPtr.Add(imageBase, peOffset + 24);
            short magic = Marshal.ReadInt16(optional);
            int dataDirectoryOffset = magic == 0x20B ? 112 : 96;
            int exportRva = Marshal.ReadInt32(IntPtr.Add(optional, dataDirectoryOffset));
            if (exportRva == 0) return IntPtr.Zero;

            IntPtr directory = IntPtr.Add(imageBase, exportRva);
            int numberOfNames = Marshal.ReadInt32(IntPtr.Add(directory, 24));
            int functionsRva = Marshal.ReadInt32(IntPtr.Add(directory, 28));
            int namesRva = Marshal.ReadInt32(IntPtr.Add(directory, 32));
            int ordinalsRva = Marshal.ReadInt32(IntPtr.Add(directory, 36));

            for (int index = 0; index < numberOfNames; index++)
            {
                int nameRva = Marshal.ReadInt32(IntPtr.Add(imageBase, namesRva + index * 4));
                string name = Marshal.PtrToStringAnsi(IntPtr.Add(imageBase, nameRva));
                if (!String.Equals(name, target, StringComparison.Ordinal)) continue;
                short ordinal = Marshal.ReadInt16(IntPtr.Add(imageBase, ordinalsRva + index * 2));
                int functionRva = Marshal.ReadInt32(IntPtr.Add(imageBase, functionsRva + ordinal * 4));
                return IntPtr.Add(imageBase, functionRva);
            }
            return IntPtr.Zero;
        }

        private static byte[] ReadBytes(IntPtr address, int count)
        {
            var bytes = new byte[count];
            Marshal.Copy(address, bytes, 0, count);
            return bytes;
        }

        private static bool ConstantTimeEquals(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }

        private static bool IsSuspiciousPrologue(byte[] bytes)
        {
            if (bytes.Length == 0) return true;
            if (bytes[0] == 0xC3 || bytes[0] == 0xCC || bytes[0] == 0xE9) return true;
            if (bytes.Length >= 3 && bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3) return true;
            if (bytes.Length >= 6 && bytes[0] == 0xB8 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0xC3) return true;
            if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0x25) return true;
            return false;
        }

        private static string Hex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        private static ProbeResult Failure(string moduleName, string export, string error)
        {
            return new ProbeResult
            {
                Module = moduleName,
                Export = export,
                Status = "ERROR",
                Error = error
            };
        }
    }
}
