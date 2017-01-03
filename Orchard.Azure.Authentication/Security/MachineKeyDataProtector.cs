using System;
using System.Diagnostics;
using System.Web.Security;
using Microsoft.Owin.Security.DataProtection;
using Orchard.Logging;

namespace Orchard.Azure.Authentication.Security {
    public class MachineKeyProtectionProvider : IDataProtectionProvider {
        public IDataProtector Create(params string[] purposes) {
            return new MachineKeyDataProtector(purposes);
        }
    }

    public class MachineKeyDataProtector : IDataProtector {
        private readonly string[] _purposes;


        public MachineKeyDataProtector(string[] purposes) {
            _purposes = purposes;
            Logger = NullLogger.Instance;
        }

        public ILogger Logger { get; set; }

        public byte[] Protect(byte[] userData) {
            byte[] outBytes = null;
            if (userData == null) return null;
            try {
                outBytes = MachineKey.Protect(userData, _purposes);
            }
            catch (Exception ex) {
                Logger.Log(LogLevel.Debug, ex, "An error occured while unprotecting data: {0}");
                Debug.WriteLine("Protect: " + ex.Message);
            }

            return outBytes;
        }

        public byte[] Unprotect(byte[] protectedData) {
            byte[] outBytes = null;
            if (protectedData == null) return null;
            try {
                outBytes = MachineKey.Unprotect(protectedData, _purposes);
            }
            catch (Exception ex) {
                Logger.Log(LogLevel.Debug, ex, "An error occured while unprotecting data: {0}");
                Debug.WriteLine("Unprotect" + ex.Message);
            }
            return outBytes;
        }
    }
}