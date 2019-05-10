namespace IdentityServer4.Quickstart.UI
{
    public class LoggedOutViewModel
    {
        public bool AutomaticRedirectAfterSignOut { get; set; } = false;

        public string ClientName { get; set; }

        public string ExternalAuthenticationScheme { get; set; }

        public string LogoutId { get; set; }

        public string PostLogoutRedirectUri { get; set; }

        public string SignOutIframeUrl { get; set; }

        public bool TriggerExternalSignout => ExternalAuthenticationScheme != null;
    }
}
