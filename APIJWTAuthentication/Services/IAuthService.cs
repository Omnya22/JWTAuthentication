using APIJWTAuthentication.Dtos;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace APIJWTAuthentication.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> LoginAsync(LoginModel model);
        Task<string> AddRoleAsync(RoleModel model);
        Task<IEnumerable<UserModel>> GetAllUsers();
    }
}
