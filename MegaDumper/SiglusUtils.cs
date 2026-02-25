using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using ProcessUtils;
using System.Diagnostics;
using System.Text;

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

        private static string _logFile;

        private static void Log(string message)
        {
            try
            {
                if (!string.IsNullOrEmpty(_logFile))
                {
                    File.AppendAllText(_logFile, $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                }
            }
            catch { }
        }

        private static bool IsValidHeader(PACK_HDR hdr)
        {
            // Strict check: header_size must be exactly 92
            if (hdr.header_size != 92) return false;

            // Strict check: scn_data_exe_angou_mod must be 0 or 1
            if (hdr.scn_data_exe_angou_mod != 0 && hdr.scn_data_exe_angou_mod != 1) return false;

            // Basic checks for negative counts
            if (hdr.inc_prop_cnt < 0) return false;
            if (hdr.inc_prop_name_index_cnt < 0) return false;
            if (hdr.inc_prop_name_cnt < 0) return false;
            if (hdr.inc_cmd_cnt < 0) return false;
            if (hdr.inc_cmd_name_index_cnt < 0) return false;
            if (hdr.inc_cmd_name_cnt < 0) return false;
            if (hdr.scn_name_index_cnt < 0) return false;
            if (hdr.scn_name_cnt < 0) return false;
            if (hdr.scn_data_index_cnt < 0) return false;
            if (hdr.scn_data_cnt < 0) return false;

            // Basic checks for offsets (must be at least after the header)
            if (hdr.inc_prop_list_ofs < 92 && hdr.inc_prop_cnt > 0) return false;
            if (hdr.scn_data_list_ofs < 92 && hdr.scn_data_cnt > 0) return false;

            // If scn_data_index_cnt is huge (e.g. > 1 million), it's suspicious but possible.
            // Let's set a sanity limit for offsets to avoid reading random garbage as valid.
            // Assuming the PCK file is less than 2GB (int32 limit for offsets usually implies this).
            if (hdr.scn_data_list_ofs > 2000000000) return false;

            return true;
        }

        public static string DumpScenePck(uint processId, string outputDir)
        {
            IntPtr hProcess = IntPtr.Zero;
            _logFile = Path.Combine(outputDir, "dump_log.txt");

            try
            {
                if (File.Exists(_logFile)) File.Delete(_logFile);
                Log($"Starting dump for PID: {processId}");

                hProcess = OpenProcess(0x0010 | 0x0020 | 0x0008 | 0x0400, false, processId); // VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION

                if (hProcess == IntPtr.Zero)
                {
                    Log("Failed to open process.");
                    return "Failed to open process.";
                }

                MainForm.SYSTEM_INFO sysInfo = new MainForm.SYSTEM_INFO();
                MainForm.GetSystemInfo(ref sysInfo);

                ulong minAddress = (ulong)sysInfo.lpMinimumApplicationAddress.ToInt64();
                ulong maxAddress = (ulong)sysInfo.lpMaximumApplicationAddress.ToInt64();

                Log($"Scanning memory from {minAddress:X} to {maxAddress:X}");

                MainForm.MEMORY_BASIC_INFORMATION mbi;
                ulong currentAddress = minAddress;

                // Buffer for reading memory chunks (e.g., 1MB)
                int bufferSize = 1024 * 1024;
                byte[] buffer = new byte[bufferSize];

                while (currentAddress < maxAddress)
                {
                    if (MainForm.VirtualQueryEx(hProcess, (IntPtr)currentAddress, out mbi, (uint)Marshal.SizeOf(typeof(MainForm.MEMORY_BASIC_INFORMATION))) == 0)
                        break;

                    bool isCommitted = (mbi.State == MainForm.MEM_COMMIT);
                    bool isReadable = (mbi.Protect & MainForm.PAGE_NOACCESS) == 0 && (mbi.Protect & MainForm.PAGE_GUARD) == 0;

                    ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                    ulong regionBase = (ulong)mbi.BaseAddress.ToInt64();

                    if (isCommitted && isReadable)
                    {
                        // Log($"Scanning region: Base={regionBase:X}, Size={regionSize:X}");

                        // Read the region in chunks
                        ulong regionOffset = 0;
                        while (regionOffset < regionSize)
                        {
                            ulong readAddr = regionBase + regionOffset;
                            ulong remaining = regionSize - regionOffset;
                            uint toRead = (uint)Math.Min((ulong)bufferSize, remaining);
                            uint bytesRead = 0;

                            if (MainForm.ReadProcessMemory(hProcess, readAddr, buffer, toRead, ref bytesRead) && bytesRead > 92)
                            {
                                // Scan buffer for header
                                // We scan with 4-byte alignment because struct members are ints
                                for (int i = 0; i <= (int)bytesRead - 92; i += 4)
                                {
                                    // Quick check for header_size (first int) == 92
                                    if (BitConverter.ToInt32(buffer, i) == 92)
                                    {
                                        // Potential candidate
                                        PACK_HDR hdr = ByteArrayToStructure<PACK_HDR>(buffer, i);
                                        if (IsValidHeader(hdr))
                                        {
                                            ulong foundAddress = readAddr + (ulong)i;
                                            Log($"Header found at {foundAddress:X} (Offset in region: {regionOffset + (ulong)i:X})");
                                            Log($"Header details: scn_data_cnt={hdr.scn_data_cnt}, scn_data_list_ofs={hdr.scn_data_list_ofs}, angou_mod={hdr.scn_data_exe_angou_mod}");

                                            long estimatedSize = CalculatePckSize(hProcess, foundAddress, hdr);
                                            Log($"Calculated size: {estimatedSize} bytes");

                                            // Fallback if size calculation fails or is unreasonably small (just header)
                                            if (estimatedSize <= 92)
                                            {
                                                Log("Warning: Calculated size is too small. Dumping up to end of region or 1GB.");
                                                // Estimate size as remaining region size, capped at reasonable max
                                                long remainingInRegion = (long)(regionSize - (regionOffset + (ulong)i));
                                                estimatedSize = Math.Min(remainingInRegion, 1024 * 1024 * 1024); // Cap at 1GB
                                            }

                                            string fileName = Path.Combine(outputDir, "Scene.pck");
                                            if (File.Exists(fileName))
                                                fileName = Path.Combine(outputDir, $"Scene_{DateTime.Now.Ticks}.pck");

                                            DumpMemoryToFile(hProcess, foundAddress, (ulong)estimatedSize, fileName);
                                            CloseHandle(hProcess);

                                            string successMsg = $"Successfully dumped Scene.pck to {fileName} (Size: {estimatedSize} bytes)";
                                            Log(successMsg);
                                            return successMsg;
                                        }
                                    }
                                }
                            }

                            regionOffset += bytesRead;
                            if (bytesRead == 0) break; // Should not happen if query says committed, but safe break
                        }
                    }

                    // Move to next region
                    ulong nextAddress = regionBase + regionSize;
                    if (nextAddress <= currentAddress) break; // Overflow protection
                    currentAddress = nextAddress;
                }
            }
            catch (Exception ex)
            {
                Log($"Error: {ex.Message}\n{ex.StackTrace}");
                return "Error: " + ex.Message;
            }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }

            Log("Scan complete. Header not found.");
            return "Scene.pck header not found in memory.";
        }

        private static long CalculatePckSize(IntPtr hProcess, ulong baseAddress, PACK_HDR hdr)
        {
            // Start with a reasonable minimum (header + some data)
            long maxEnd = hdr.scn_data_list_ofs;

            // We need to read the index list to find the extent of the data.
            // scn_data_index_list_ofs points to an array of (offset, size) pairs.
            // struct { int offset; int size; }

            int count = hdr.scn_data_index_cnt;
            if (count > 0 && count < 2000000) // Sanity check count
            {
                long listOffset = hdr.scn_data_index_list_ofs;
                int itemSize = 8; // 2 ints
                long totalListSize = (long)count * itemSize;

                Log($"Reading index list: Offset={listOffset}, Count={count}, TotalSize={totalListSize}");

                // We read the index list in chunks to avoid large allocations
                byte[] chunkBuffer = new byte[64 * 1024]; // 64KB chunks
                int itemsPerChunk = chunkBuffer.Length / itemSize;

                int itemsRead = 0;
                while (itemsRead < count)
                {
                    int itemsToRead = Math.Min(itemsPerChunk, count - itemsRead);
                    int bytesToRead = itemsToRead * itemSize;

                    uint bytesRead = 0;
                    ulong currentListAddr = baseAddress + (ulong)listOffset + (ulong)(itemsRead * itemSize);

                    if (MainForm.ReadProcessMemory(hProcess, currentListAddr, chunkBuffer, (uint)bytesToRead, ref bytesRead) && bytesRead > 0)
                    {
                        for (int i = 0; i < bytesRead / itemSize; i++)
                        {
                            int offset = BitConverter.ToInt32(chunkBuffer, i * itemSize);
                            int size = BitConverter.ToInt32(chunkBuffer, i * itemSize + 4);

                            if (offset >= 0 && size > 0)
                            {
                                long end = (long)hdr.scn_data_list_ofs + offset + size;
                                if (end > maxEnd) maxEnd = end;
                            }
                        }
                        itemsRead += (int)(bytesRead / itemSize);
                    }
                    else
                    {
                        Log("Failed to read part of the index list.");
                        break;
                    }
                }
            }

            // If original_source_header_size is present, add it.
            // Note: The structure of the file usually ends after the last scene data block + original source header + original source data?
            // If we don't know the size of original source data, we might be missing the tail.
            // However, typically Scene.pck contains just the scene data.
            if (hdr.original_source_header_size > 0)
            {
                maxEnd += hdr.original_source_header_size;
            }

            return maxEnd;
        }

        private static void DumpMemoryToFile(IntPtr hProcess, ulong address, ulong size, string fileName)
        {
            Log($"Dumping {size} bytes to {fileName}...");
            using (FileStream fs = new FileStream(fileName, FileMode.Create))
            {
                byte[] buffer = new byte[64 * 1024]; // 64KB chunks
                ulong remaining = size;
                ulong current = address;

                while (remaining > 0)
                {
                    uint toRead = (uint)Math.Min(remaining, (ulong)buffer.Length);
                    uint bytesRead = 0;
                    if (MainForm.ReadProcessMemory(hProcess, current, buffer, toRead, ref bytesRead) && bytesRead > 0)
                    {
                        fs.Write(buffer, 0, (int)bytesRead);
                        current += bytesRead;
                        remaining -= bytesRead;
                    }
                    else
                    {
                        Log($"Read failed at offset {current - address}. Stopping dump.");
                        break;
                    }
                }
            }
            Log("Dump finished.");
        }

        private static T ByteArrayToStructure<T>(byte[] bytes, int offset) where T : struct
        {
            // Pinned handle is tricky with offsets, so we copy the slice.
            // Ideally we'd use unsafe pointers but let's stick to safe code if possible or just copy.
            // Since T is small (92 bytes), copying is cheap.
            int size = Marshal.SizeOf(typeof(T));
            if (offset + size > bytes.Length) throw new ArgumentOutOfRangeException("offset");

            byte[] slice = new byte[size];
            Array.Copy(bytes, offset, slice, 0, size);

            GCHandle handle = GCHandle.Alloc(slice, GCHandleType.Pinned);
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
