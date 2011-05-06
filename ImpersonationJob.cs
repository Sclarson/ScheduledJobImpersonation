using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using EPiServer.BaseLibrary.Scheduling;
using EPiServer.PlugIn;

namespace BlendInteractive.CustomUserJob
{
    [ScheduledPlugIn(DisplayName = "Impersonating Scheduled Job", Description = "A plugin to demonstrate changing the current user while a process runs", SortIndex = 1)]
    public class ImpersonationJob : JobBase
    {
        public ImpersonationJob()
        {
            //Oh noes virtuals in a constructor remove this later
            Username = "WorkerMonkey";
            Password = "12345";
            Domain = "";
        }

        public virtual string Username { get; set; }
        public virtual string Password { get; set; }
        public virtual string Domain { get; set; }

        public override string Execute()
        {
            string starterName = WindowsIdentity.GetCurrent().Name;
            string endingName, midpointName;
            this.OnStatusChanged(starterName);


            if (ImpersonateValidUser(Username, Domain, Password)) // amazing its the same combination as my luggage!
            {
                //Stuff you want to do as the impersonated user goes here
                midpointName = WindowsIdentity.GetCurrent().Name;
                this.OnStatusChanged(midpointName);

                
                //Undo your impersonation.  We don't need that power anymore
                UndoImpersonation();
                endingName = WindowsIdentity.GetCurrent().Name;
                this.OnStatusChanged(endingName);
                
                
                return "Starting Name: " + starterName + " Midpoint Name: " + midpointName + " Ending Name:" +
                       endingName;
            }
            
            // Some sort of failsafe code here to alert is things went wack
            return "F-F-F-F-Failure";
        }

        protected virtual void UndoImpersonation()
        {
            impersonationContext.Undo();
        }

        // Nasty starts here
        public const int LOGON32_LOGON_INTERACTIVE = 2;
        public const int LOGON32_PROVIDER_DEFAULT = 0;

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
                if (LogonUserA(userName, domain, password, LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT, ref token) != 0)
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
    }
}
