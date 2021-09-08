using APIJWTAuthentication.Dtos;
using System.Threading.Tasks;

namespace APIJWTAuthentication.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> LoginAsync(LoginModel model);

    }
}
