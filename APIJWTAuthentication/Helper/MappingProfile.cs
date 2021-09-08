using APIJWTAuthentication.Dtos;
using APIJWTAuthentication.Models;
using AutoMapper;

namespace APIJWTAuthentication.Helper
{
    public class MappingProfile : Profile 
    {
        public MappingProfile()
        {
            CreateMap<ApplicationUser, RegisterModel>().ReverseMap();
        }
    }
}
