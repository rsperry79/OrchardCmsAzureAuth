using System;
using System.Diagnostics;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Orchard.Azure.Authentication.Services;
using Orchard.ContentManagement;
using Orchard.Environment.Extensions;
using Orchard.Localization;
using Orchard.Logging;
using Orchard.Mvc;
using Orchard.Security;
using Orchard.Themes;
using Orchard.Users.Events;
using Orchard.Users.Models;
using Orchard.Users.Services;

namespace Orchard.Azure.Authentication.Controllers {
    [HandleError]
    [Themed]
    [OrchardSuppressDependency("Orchard.Users.Controllers.AccountController")]
    public class AccountController : Controller {
        private readonly IAuthenticationService _azureAuthentication;
        private readonly IAzureRolesPersistence _azureRolesPersistence;
        private readonly IAzureGraphiApiService _graphiApiService;

        private readonly IMembershipService _membershipService;
        private readonly IOrchardServices _orchardServices;
        private readonly IUserEventHandler _userEventHandler;
        private readonly IUserService _userService;

        public AccountController(AzureAuthenticationService azureAuthentication,
            IAzureGraphiApiService graphiApiService,
            IAzureRolesPersistence azureRolesPersistence,
            IMembershipService membershipService,
            IUserService userService,
            IOrchardServices orchardServices,
            IUserEventHandler userEventHandler) {

                Logger = NullLogger.Instance;
                _graphiApiService = graphiApiService;
                _azureRolesPersistence = azureRolesPersistence;
                _membershipService = membershipService;
                _userService = userService;
                _orchardServices = orchardServices;
                _userEventHandler = userEventHandler;
                Logger = NullLogger.Instance;
                T = NullLocalizer.Instance;
                _azureAuthentication = azureAuthentication;
        }

        public ILogger Logger { get; set; }
        public Localizer T { get; set; }


        [AlwaysAccessible]
        public void LogOn()
        {
            if (Request.IsAuthenticated)
            {
                return; //TODO: redirect to home if we can?
            }

            var redirectUri = Url.Content("~/users/account/logoncallback");

            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = redirectUri },
                OpenIdConnectAuthenticationDefaults.AuthenticationType);
        }

        [AlwaysAccessible]
        public void LogOff() {
            HttpContext.GetOwinContext().Authentication.SignOut(
                OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType); //OpenID Connect sign-out request.
        }

        public ActionResult LogonCallback() {
            var userName = HttpContext.GetOwinContext().Authentication.User.Identity.Name.Trim();

            try {
                var groups = _graphiApiService.GetUserGroups(userName);
                _azureRolesPersistence.SyncAzureGroupsToOrchardRoles(userName, groups);
            }
            catch (Exception ex) {
                Logger.Error(ex.Message, ex);
            }

            return Redirect(Url.Content("~/"));
        }

        [AlwaysAccessible]
        public ActionResult AccessDenied() {
            var returnUrl = Request.QueryString["ReturnUrl"];
            var currentUser = _azureAuthentication.GetAuthenticatedUser();

            if (currentUser == null) {
                Logger.Information("Access denied to anonymous request on {0}", returnUrl);
                var shape = _orchardServices.New.LogOn().Title(T("Access Denied").Text);
                return new ShapeResult(this, shape);
            }

            //TODO: (erikpo) Add a setting for whether or not to log access denieds since these can fill up a database pretty fast from bots on a high traffic site
            //Suggestion: Could instead use the new AccessDenined IUserEventHandler method and let modules decide if they want to log this event?
            Logger.Information("Access denied to user #{0} '{1}' on {2}", currentUser.Id, currentUser.UserName, returnUrl);

            _userEventHandler.AccessDenied(currentUser);

            return View();
        }

        [Authorize]
        [AlwaysAccessible]
        public ActionResult ChangePassword() {
            return View();
        }


        [AlwaysAccessible]
        public ActionResult Register() {
            // ensure users can register
            var registrationSettings = _orchardServices.WorkContext.CurrentSite.As<RegistrationSettingsPart>();
            if (!registrationSettings.UsersCanRegister) return HttpNotFound();
            bool didRegister;
            IUser localUser = null;


            try {
                var userName = HttpContext.GetOwinContext().Authentication.User.Identity.Name.Trim();

                //Get the local user, if local user account doesn't exist, create it 
                localUser = _membershipService.GetUser(userName) ?? _membershipService.CreateUser(new CreateUserParams(
                                userName, Membership.GeneratePassword(16, 1), userName, string.Empty, string.Empty, true
                            ));
                didRegister = true;
            }
            catch (Exception){
                didRegister = false;
                Logger.Information("Access denied to user #{0} '{1}' on {2}", localUser.Id, localUser.UserName);

                throw;
            }
            var register = didRegister ? "successful" : "unsucessfull";
            ViewData["Register"] = register;
            return View();
        }
    }
}