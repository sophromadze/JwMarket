using JewelryMarket.Interfaces;
using System.Security.Claims;

namespace JewelryMarket.Repository
{
    public class UserRepository : IUserRepository
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserRepository(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public string GetName()
        {
            var user = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);

            return user;
        }
    }
}
