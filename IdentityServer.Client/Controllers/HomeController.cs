using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityServer.Client.Controllers
{
    public class HomeController : Controller
    {
        public HomeController(IOptions<AppSettings> appSettings)
        {
            AppSettings = appSettings.Value;
        }

        private AppSettings AppSettings { get; }

        public async Task<IActionResult> Api()
        {
            var tokenResponse = await RequestClientCredentialsTokenAsync().ConfigureAwait(false);

            var apiResponse = await GetApi(tokenResponse.AccessToken).ConfigureAwait(false);

            var model = new ViewModel
            {
                Token = tokenResponse.AccessToken,
                ApiResponse = apiResponse
            };

            return View(model);
        }

        [Authorize]
        public IActionResult Implicit()
        {
            return View();
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Logout()
        {
            return SignOutResult();
        }

        public async Task<IActionResult> ResourceOwnerPassword()
        {
            var tokenResponse = await RequestPasswordTokenAsync().ConfigureAwait(false);

            var apiResponse = await GetApi(tokenResponse.AccessToken).ConfigureAwait(false);

            var model = new ViewModel
            {
                Token = tokenResponse.AccessToken,
                ApiResponse = apiResponse
            };

            return View(model);
        }

        private static SignOutResult SignOutResult()
        {
            return new SignOutResult(new[]
            {
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectDefaults.AuthenticationScheme
            });
        }

        private Task<string> GetApi(string token)
        {
            var httpClient = new HttpClient();

            httpClient.SetBearerToken(token);

            return httpClient.GetStringAsync(AppSettings.ApiUrl);
        }

        private async Task<TokenResponse> RequestClientCredentialsTokenAsync()
        {
            var client = new HttpClient();

            var disco = await client.GetDiscoveryDocumentAsync(AppSettings.Authority);

            var clientCredentialsTokenRequest = new ClientCredentialsTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = AppSettings.ClientId,
                ClientSecret = AppSettings.ClientSecret,
                Scope = AppSettings.Scope
            };

            return await client.RequestClientCredentialsTokenAsync(clientCredentialsTokenRequest);
        }

        private async Task<TokenResponse> RequestPasswordTokenAsync()
        {
            var client = new HttpClient();

            var disco = await client.GetDiscoveryDocumentAsync(AppSettings.Authority);

            var passwordTokenRequest = new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = AppSettings.ClientId,
                ClientSecret = AppSettings.ClientSecret,
                Scope = AppSettings.Scope,
                UserName = AppSettings.UserUsername,
                Password = AppSettings.UserPassword
            };

            return await client.RequestPasswordTokenAsync(passwordTokenRequest);
        }
    }
}
