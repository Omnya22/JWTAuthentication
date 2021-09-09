using System.ComponentModel.DataAnnotations;

namespace APIJWTAuthentication.Dtos
{
    public class RoleModel
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Role { get; set; }
    }
}
