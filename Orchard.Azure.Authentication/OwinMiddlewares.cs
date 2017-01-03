using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Web.Helpers;
using System.Web.WebPages;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.OpenIdConnect;
using Orchard.Azure.Authentication.Constants;
using Orchard.Azure.Authentication.Models;
using Orchard.Azure.Authentication.Security;
using Orchard.Azure.Authentication.Services;
using Orchard.ContentManagement;
using Orchard.Logging;
using Orchard.Owin;
using Orchard.Settings;
using Owin;
using LogLevel = Orchard.Logging.LogLevel;

namespace Orchard.Azure.Authentication {
    public class OwinMiddlewares : IOwinMiddlewareProvider {
        private string _azureAdInstance = DefaultAzureSettings.ADInstance;

        private string _azureClientId = DefaultAzureSettings.ClientId;

        private string _azureGraphiApiUri = DefaultAzureSettings.GraphiApiUri;
        private string _azureTenant = DefaultAzureSettings.Tenant;
        private bool _azureWebSiteProtectionEnabled = DefaultAzureSettings.AzureWebSiteProtectionEnabled;

        private string _clientSecret = DefaultAzureSettings.ClientSecret;
        private string _logoutRedirectUri = DefaultAzureSettings.LogoutRedirectUri;
        private bool _useAzureGraphApi = DefaultAzureSettings.UseAzureGraphApi;


        public OwinMiddlewares(ISiteService siteService) {
            Logger = NullLogger.Instance;
            GetSettings(siteService);
        }

        public ILogger Logger { get; set; }

        public IEnumerable<OwinMiddlewareRegistration> GetOwinMiddlewares() {
            var middlewares = new List<OwinMiddlewareRegistration>();
            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;
            var openIdOptions = new OpenIdConnectAuthenticationOptions {
                ClientId = _azureClientId,
                ClientSecret = _clientSecret,
                Authority = string.Format(CultureInfo.InvariantCulture, _azureAdInstance, _azureTenant), // e.g. "https://login.windows.net/azurefridays.onmicrosoft.com/"
                PostLogoutRedirectUri = _logoutRedirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications()
            };

            var cookieOptions = new CookieAuthenticationOptions();

            if (_azureWebSiteProtectionEnabled)
                middlewares.Add(new OwinMiddlewareRegistration {
                    Priority = "9",
                    Configure = app => { app.SetDataProtectionProvider(new MachineKeyProtectionProvider()); }
                });

            middlewares.Add(new OwinMiddlewareRegistration {
                Priority = "10",
                Configure = app => {
                    app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
                    app.UseCookieAuthentication(cookieOptions);
                    app.UseOpenIdConnectAuthentication(openIdOptions);
                }
            });

            if (_useAzureGraphApi)
                middlewares.Add(new OwinMiddlewareRegistration {
                    Priority = "11",
                    Configure = app => app.Use(async (context, next) => {
                        try {
                            if ((AzureActiveDirectoryService.token == null) && AzureActiveDirectoryService.token.IsEmpty()) {
                                RegenerateAzureGraphApiToken();
                            }
                            else {
                                if (DateTimeOffset.Compare(DateTimeOffset.UtcNow, AzureActiveDirectoryService.tokenExpiresOn) > 0) RegenerateAzureGraphApiToken();
                            }
                        }
                        catch (Exception ex) {
                            Logger.Log(LogLevel.Error, ex, "An error occured generating azure api credential {0}", ex.Message);
                            Debug.WriteLine("UseGraphApi: " + ex.Message);
                        }

                        await next.Invoke();
                    })
                });

            return middlewares;
        }

        private void GetSettings(ISiteService siteService) {
            try {
                var settings = siteService.GetSiteSettings().As<AzureSettingsPart>();

                if (settings == null) return;

                _azureClientId = string.IsNullOrEmpty(settings.ClientId) ? _azureClientId : settings.ClientId;
                _azureTenant = string.IsNullOrEmpty(settings.Tenant) ? _azureTenant : settings.Tenant;
                _azureAdInstance = string.IsNullOrEmpty(settings.ADInstance) ? _azureAdInstance : settings.ADInstance;
                _logoutRedirectUri = string.IsNullOrEmpty(settings.LogoutRedirectUri) ? _logoutRedirectUri : settings.LogoutRedirectUri;
                _azureWebSiteProtectionEnabled = settings.AzureWebSiteProtectionEnabled;
                _azureGraphiApiUri = string.IsNullOrEmpty(settings.GraphApiUrl) ? _azureGraphiApiUri : settings.GraphApiUrl;
                _clientSecret = string.IsNullOrEmpty(settings.ClientSecret) ? _clientSecret : settings.ClientSecret;
                _useAzureGraphApi = settings.ClientSecret == null ? _useAzureGraphApi : settings.UseAzureGraphApi;
            }
            catch (Exception ex) {
                Logger.Log(LogLevel.Debug, ex, "An error occured while accessing azure settings: {0}");
                Debug.WriteLine("GetSettings: " + ex.Message);
            }
        }

        private void RegenerateAzureGraphApiToken() {
            try {
                var TokenResult = GetAuthContext().AcquireTokenAsync(_azureGraphiApiUri, GetClientCredential()).Result;

                AzureActiveDirectoryService.tokenExpiresOn = TokenResult.ExpiresOn;
                AzureActiveDirectoryService.token = TokenResult.AccessToken;
                AzureActiveDirectoryService.azureGraphApiUri = _azureGraphiApiUri;
                AzureActiveDirectoryService.azureTenant = _azureTenant;
            }
            catch (AdalException ex) {
                Logger.Log(LogLevel.Error, ex, "An error occured generating azure api credential {0}", ex.Message);
                Debug.WriteLine("GraphApi: " + ex.Message);
            }
        }

        private ClientCredential GetClientCredential() {
            return new ClientCredential(_azureClientId, _clientSecret);
        }

        private AuthenticationContext GetAuthContext() {
            var authority = string.Format(CultureInfo.InvariantCulture, _azureAdInstance, _azureTenant);

            return new AuthenticationContext(authority, false);
        }
    }
}