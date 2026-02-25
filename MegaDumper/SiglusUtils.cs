using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using ProcessUtils;
using System.Diagnostics;

namespace Mega_Dumper
{
    public static class SiglusUtils
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PACK_HDR
        {
            public int header_size;
            public int inc_prop_list_ofs;
            public int inc_prop_cnt;
            public int inc_prop_name_index_list_ofs;
            public int inc_prop_name_index_cnt;
            public int inc_prop_name_list_ofs;
            public int inc_prop_name_cnt;
            public int inc_cmd_list_ofs;
            public int inc_cmd_cnt;
            public int inc_cmd_name_index_list_ofs;
            public int inc_cmd_name_index_cnt;
            public int inc_cmd_name_list_ofs;
            public int inc_cmd_name_cnt;
            public int scn_name_index_list_ofs;
            public int scn_name_index_cnt;
            public int scn_name_list_ofs;
            public int scn_name_cnt;
            public int scn_data_index_list_ofs;
            public int scn_data_index_cnt;
            public int scn_data_list_ofs;
            public int scn_data_cnt;
            public int scn_data_exe_angou_mod;
            public int original_source_header_size;
        }

        private static bool IsValidHeader(PACK_HDR hdr, long regionSize)
        {
            // header_size must be >= 92 (size of struct)
            // It is usually 92.
            if (hdr.header_size < 92) return false;

            // Check bounds for some offsets
            if (hdr.inc_prop_list_ofs < 0 || hdr.inc_prop_list_ofs >= regionSize) return false;
            if (hdr.scn_data_list_ofs < 0 || hdr.scn_data_list_ofs >= regionSize) return false;

            // Heuristic: Counts shouldn't be negative
            if (hdr.inc_prop_cnt < 0) return false;
            if (hdr.scn_data_cnt < 0) return false;

            // Additional check: Index list bounds
            try
            {
                long indexListSize = (long)hdr.scn_data_index_cnt * 8;
                if (indexListSize < 0) return false;
                if ((long)hdr.scn_data_index_list_ofs + indexListSize > regionSize) return false;
            }
            catch { return false; }

            return true;
        }

        public static string DumpScenePck(uint processId, string outputDir)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(0x0010 | 0x0020 | 0x0008 | 0x0400, false, processId); // VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION

                if (hProcess == IntPtr.Zero) return "Failed to open process.";

                MainForm.SYSTEM_INFO sysInfo = new MainForm.SYSTEM_INFO();
                MainForm.GetSystemInfo(ref sysInfo);

                ulong minAddress = (ulong)sysInfo.lpMinimumApplicationAddress.ToInt64();
                ulong maxAddress = (ulong)sysInfo.lpMaximumApplicationAddress.ToInt64();

                MainForm.MEMORY_BASIC_INFORMATION mbi;
                ulong currentAddress = minAddress;

                while (currentAddress < maxAddress)
                {
                    if (MainForm.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MainForm.MEMORY_BASIC_INFORMATION))) == 0)
                        break;

                    bool isCommitted = (mbi.State == MainForm.MEM_COMMIT);
                    bool isReadable = (mbi.Protect & MainForm.PAGE_NOACCESS) == 0 && (mbi.Protect & MainForm.PAGE_GUARD) == 0;

                    if (isCommitted && isReadable)
                    {
                        ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                        // Read first page (header size is small)
                        byte[] buffer = new byte[Math.Min((long)regionSize, 4096)];
                        uint bytesRead = 0;
                        if (MainForm.ReadProcessMemory(hProcess, currentAddress, buffer, (uint)buffer.Length, ref bytesRead) && bytesRead >= 92)
                        {
                            PACK_HDR hdr = ByteArrayToStructure<PACK_HDR>(buffer);
                            if (IsValidHeader(hdr, (long)regionSize))
                            {
                                // Assume Scene.pck takes the whole mapped region
                                long estimatedSize = (long)regionSize;

                                string fileName = Path.Combine(outputDir, "Scene.pck");
                                if (File.Exists(fileName))
                                    fileName = Path.Combine(outputDir, $"Scene_{DateTime.Now.Ticks}.pck");

                                DumpMemoryToFile(hProcess, currentAddress, (ulong)estimatedSize, fileName);
                                CloseHandle(hProcess);
                                return $"Successfully dumped Scene.pck to {fileName} (Size: {estimatedSize} bytes)";
                            }
                        }
                    }

                    currentAddress = (ulong)mbi.BaseAddress.ToInt64() + (ulong)mbi.RegionSize.ToInt64();
                }
            }
            catch (Exception ex)
            {
                return "Error: " + ex.Message;
            }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }

            return "Scene.pck header not found in memory.";
        }

        private static void DumpMemoryToFile(IntPtr hProcess, ulong address, ulong size, string fileName)
        {
            using (FileStream fs = new FileStream(fileName, FileMode.Create))
            {
                byte[] buffer = new byte[64 * 1024]; // 64KB chunks
                ulong remaining = size;
                ulong current = address;

                while (remaining > 0)
                {
                    uint toRead = (uint)Math.Min(remaining, (ulong)buffer.Length);
                    uint bytesRead = 0;
                    if (MainForm.ReadProcessMemory(hProcess, current, buffer, toRead, ref bytesRead))
                    {
                        fs.Write(buffer, 0, (int)bytesRead);
                        current += bytesRead;
                        remaining -= bytesRead;
                        if (bytesRead < toRead) break;
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        private static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            finally
            {
                handle.Free();
            }
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
