using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace OpnSenseACME2Exchange.ServiceHost;

/// <summary>
/// Dienst-Installation per Win32-API (statt sc.exe, damit das Passwort des Dienstkontos nie auf einer Kommandozeile steht).
/// </summary>
internal static class NativeServiceApi
{
    private const uint ScManagerAllAccess = 0xF003F;
    private const uint ServiceAllAccess = 0xF01FF;
    private const uint ServiceWin32OwnProcess = 0x10;
    private const uint ServiceAutoStart = 2;
    private const uint ServiceErrorNormal = 1;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const uint ConfigDescription = 1;
    private const uint ConfigFailureActions = 2;
    private const uint ConfigDelayedAutoStart = 3;
    private const uint ConfigFailureActionsFlag = 4;
    private const int ErrorServiceExists = 1073;
    private const int ErrorServiceDoesNotExist = 1060;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access, uint type, uint start,
        uint error, string binaryPath, string? loadOrderGroup, IntPtr tagId, string? dependencies, string? account, string? password);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ChangeServiceConfigW(IntPtr service, uint type, uint start, uint error, string? binaryPath,
        string? loadOrderGroup, IntPtr tagId, string? dependencies, string? account, string? password, string? display);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ChangeServiceConfig2W(IntPtr service, uint infoLevel, IntPtr info);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr service);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ScAction { public int Type; public uint Delay; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceFailureActions
    {
        public uint ResetPeriod;
        public IntPtr RebootMsg;
        public IntPtr Command;
        public uint ActionCount;
        public IntPtr Actions;
    }

    /// <summary>Legt den Dienst an oder aktualisiert ihn (Pfad, Konto, Starttyp).</summary>
    public static bool CreateOrUpdate(string name, string display, string description, string binaryPath, string? account, string? password)
    {
        var scm = OpenSCManagerW(null, null, ScManagerAllAccess);
        if (scm == IntPtr.Zero) throw new Win32Exception();
        try
        {
            bool created = true;
            var svc = CreateServiceW(scm, name, display, ServiceAllAccess, ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal,
                binaryPath, null, IntPtr.Zero, null, account, password);
            if (svc == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                if (err != ErrorServiceExists) throw new Win32Exception(err);
                created = false;
                svc = OpenServiceW(scm, name, ServiceAllAccess);
                if (svc == IntPtr.Zero) throw new Win32Exception();
                if (!ChangeServiceConfigW(svc, ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal, binaryPath,
                        null, IntPtr.Zero, null, account ?? "LocalSystem", password, display))
                    throw new Win32Exception();
            }
            try
            {
                SetDescription(svc, description);
                SetDelayedAutoStart(svc);
                SetRecovery(svc);
            }
            finally { CloseServiceHandle(svc); }
            return created;
        }
        finally { CloseServiceHandle(scm); }
    }

    public static bool Delete(string name)
    {
        var scm = OpenSCManagerW(null, null, ScManagerAllAccess);
        if (scm == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var svc = OpenServiceW(scm, name, ServiceAllAccess);
            if (svc == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                if (err == ErrorServiceDoesNotExist) return false;
                throw new Win32Exception(err);
            }
            try { if (!DeleteService(svc)) throw new Win32Exception(); }
            finally { CloseServiceHandle(svc); }
            return true;
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void SetDescription(IntPtr svc, string description)
    {
        var text = Marshal.StringToHGlobalUni(description);
        var info = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            Marshal.WriteIntPtr(info, text);
            if (!ChangeServiceConfig2W(svc, ConfigDescription, info)) throw new Win32Exception();
        }
        finally { Marshal.FreeHGlobal(info); Marshal.FreeHGlobal(text); }
    }

    private static void SetDelayedAutoStart(IntPtr svc)
    {
        var info = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            Marshal.WriteInt32(info, 1);
            if (!ChangeServiceConfig2W(svc, ConfigDelayedAutoStart, info)) throw new Win32Exception();
        }
        finally { Marshal.FreeHGlobal(info); }
    }

    /// <summary>Selbstheilung auf Dienstebene: Neustart nach 1 min, 1 min, 5 min; Zähler nach 1 Tag zurücksetzen.</summary>
    private static void SetRecovery(IntPtr svc)
    {
        var actions = new[]
        {
            new ScAction { Type = 1, Delay = 60_000 },
            new ScAction { Type = 1, Delay = 60_000 },
            new ScAction { Type = 1, Delay = 300_000 }
        };
        int size = Marshal.SizeOf<ScAction>();
        var actionsPtr = Marshal.AllocHGlobal(size * actions.Length);
        var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceFailureActions>());
        var flagPtr = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            for (int i = 0; i < actions.Length; i++) Marshal.StructureToPtr(actions[i], actionsPtr + i * size, false);
            Marshal.StructureToPtr(new ServiceFailureActions
            {
                ResetPeriod = 86_400,
                ActionCount = (uint)actions.Length,
                Actions = actionsPtr
            }, infoPtr, false);
            if (!ChangeServiceConfig2W(svc, ConfigFailureActions, infoPtr)) throw new Win32Exception();

            Marshal.WriteInt32(flagPtr, 1); // auch bei Beenden mit Fehlercode, nicht nur bei Absturz
            ChangeServiceConfig2W(svc, ConfigFailureActionsFlag, flagPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(actionsPtr);
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(flagPtr);
        }
    }

    // ───────────────────────── "Als Dienst anmelden" ─────────────────────────

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LsaUnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, uint access, out IntPtr policy);

    [DllImport("advapi32.dll")]
    private static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LsaUnicodeString[] rights, uint count);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policy);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(uint status);

    public static void GrantServiceLogonRight(SecurityIdentifier sid)
    {
        const uint policyCreateAccount = 0x10, policyLookupNames = 0x800;
        var attrs = new LsaObjectAttributes { Length = Marshal.SizeOf<LsaObjectAttributes>() };
        var status = LsaOpenPolicy(IntPtr.Zero, ref attrs, policyCreateAccount | policyLookupNames, out var policy);
        if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
        const string right = "SeServiceLogonRight";
        var buffer = Marshal.StringToHGlobalUni(right);
        try
        {
            var rights = new[]
            {
                new LsaUnicodeString { Buffer = buffer, Length = (ushort)(right.Length * 2), MaximumLength = (ushort)((right.Length + 1) * 2) }
            };
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            status = LsaAddAccountRights(policy, bytes, rights, 1);
            if (status != 0) throw new Win32Exception(LsaNtStatusToWinError(status));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            LsaClose(policy);
        }
    }
}
