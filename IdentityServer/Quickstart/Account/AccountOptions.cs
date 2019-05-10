using Microsoft.AspNetCore.Server.IISIntegration;
using System;

namespace IdentityServer4.Quickstart.UI
{
    public class AccountOptions
    {
        public static readonly string WindowsAuthenticationSchemeName = IISDefaults.AuthenticationScheme;

        public static bool AllowLocalLogin = true;

        public static bool AllowRememberLogin = true;

        public static bool AutomaticRedirectAfterSignOut = false;

        public static bool IncludeWindowsGroups = false;

        public static string InvalidCredentialsErrorMessage = "Invalid username or password";

        public static TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

        public static bool ShowLogoutPrompt = true;
    }
}
