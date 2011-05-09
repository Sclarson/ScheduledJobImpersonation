using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using EPiServer.BaseLibrary.Scheduling;

namespace BlendInteractive.CustomUserJob
{
    public class ImpersonationJob : JobBase
    {

        /// <summary>
        /// Username of the user you wish to impersonate
        /// </summary>
        public virtual string Username { get { return "username";  } }

        /// <summary>
        /// Password of the user you wish to impersonate
        /// </summary>
        public virtual string Password { get { return "password"; } }

        /// <summary>
        /// Domain of the user you wish to impersonate
        /// </summary>
        public virtual string Domain { get { return "domain"; } }


        public override string Execute()
        {
            
            if (ImpersonateValidUser(Username, Domain, Password)) // amazing its the same combination as my luggage!
            {
                string message = ExecuteSuccessfulImpersonation();
                UndoImpersonation();
                return message;
            }

            return ExecuteFailedImpersonation();
        }

        /// <summary>
        /// Function which is called if Impersonation succeeds.  Override and fill with logic you want to execute as the impersonating user.
        /// </summary>
        /// <returns></returns>
        protected virtual string ExecuteSuccessfulImpersonation()
        {
            var windowsIdentity = WindowsIdentity.GetCurrent();
            if (windowsIdentity != null)
            {
                return "Successfully impersonated" + windowsIdentity.Name;
            }

            return "ImpersonateValidUser was true but WindowsIdentity.GetCurrent() returned null";
        }

        /// <summary>
        /// Fucntionwhich is called if Impersonation fails.  Override and fill with logic you want to execute if impersonation fails.
        /// </summary>
        /// <returns></returns>
        protected virtual string ExecuteFailedImpersonation()
        {
            return "Failed Impersonation";
        }

        protected virtual void UndoImpersonation()
        {
            impersonationContext.Undo();
        }

        protected virtual LogonType UserLogonType { get { return LogonType.Logon32LogonNetwork; } }

        protected virtual LogonProvider UserLogonProvider { get { return LogonProvider.Logon32ProviderDefault; } }

        private WindowsImpersonationContext impersonationContext;
        [DllImport("advapi32.dll")]
        public static extern int LogonUserA(String lpszUserName,
            String lpszDomain,
            String lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DuplicateToken(IntPtr hToken,
            int impersonationLevel,
            ref IntPtr hNewToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        protected virtual bool ImpersonateValidUser(String userName, String domain, String password)
        {
            var token = IntPtr.Zero;
            var tokenDuplicate = IntPtr.Zero;

            if (RevertToSelf())
            {
                if (LogonUserA(userName, domain, password, (int) UserLogonType,
                    (int) UserLogonProvider, ref token) != 0)
                {
                    if (DuplicateToken(token, 2, ref tokenDuplicate) != 0)
                    {
                        var tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
                        impersonationContext = tempWindowsIdentity.Impersonate();
                        if (impersonationContext != null)
                        {
                            CloseHandle(token);
                            CloseHandle(tokenDuplicate);
                            return true;
                        }
                    }
                }
            }
            if (token != IntPtr.Zero)
                CloseHandle(token);
            if (tokenDuplicate != IntPtr.Zero)
                CloseHandle(tokenDuplicate);
            return false;
        }

        public enum LogonType : int
        {
            Logon32LogonInteractive = 2,
            Logon32LogonNetwork = 3,
            Logon32LogonBatch = 4,
            Logon32LogonService = 5,
            Logon32LogonUnlock = 7,
            Logon32LogonNetworkCleartext = 8,
            Logon32LogonNewCredentials = 9
        };

        public enum LogonProvider : int
        {
            Logon32ProviderDefault = 0,
            Logon32ProviderWinnt35 = 1,
            Logon32ProviderWinnt40 = 2,
            Logon32ProviderWinnt50 = 3
        };
    }
}
