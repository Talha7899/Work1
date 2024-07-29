using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Crud_Operations_in_Asp.Net_Core.Controllers
{
    public class AdminController : Controller
    {
        [Authorize(Roles = "Admin")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(string email, string password)
        {
            bool isAuthenticated = false;
            bool isAdmin = false;
            ClaimsIdentity identity = null;

            if (email == "admin@gmail.com" && password == "admin123")
            {
                identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name,"Talha" ),
                    new Claim(ClaimTypes.Role, "Admin"),
                   
                }, CookieAuthenticationDefaults.AuthenticationScheme);

                isAdmin = true;
                isAuthenticated = true;
               

            }else if(email == "user@gmail.com" && password == "user123"){
                identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name,"User1" ),
                    new Claim(ClaimTypes.Role, "User")
                }, CookieAuthenticationDefaults.AuthenticationScheme);

                isAdmin = false;
                isAuthenticated = true;
            }
            if (isAuthenticated && isAdmin)
            {
                var principal = new ClaimsPrincipal(identity);

                var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                return RedirectToAction("Index", "Admin");

            }
            else if (isAuthenticated)
            {
                var principal = new ClaimsPrincipal(identity);

                var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                return RedirectToAction("Index", "Home");
            }
            else
            {
                ViewBag.msg = "Invalid credentials";
                return View();
            }
        }
        public IActionResult Logout()
        {
            var login = HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction("Login", "Admin");
        }
    }
}
