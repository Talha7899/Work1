using Crud_Operations_in_Asp.Net_Core.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Crud_Operations_in_Asp.Net_Core.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Products()
        {
            return View();
        }

		public IActionResult About()
		{
			return View();
		}

		public IActionResult Services()
		{
			return View();
		}

		public IActionResult Blog()
		{
			return View();
		}

		public IActionResult Contact()
		{
			return View();
		}

		public IActionResult Cart()
		{
			return View();
		}

		public IActionResult Checkout()
		{
			return View();
		}

        public IActionResult Thankyou()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
