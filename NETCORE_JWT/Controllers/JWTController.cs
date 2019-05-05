using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace NETCORE_JWT.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class JWTController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public JWTController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        
        [ActionName("GetToken")]
        [HttpGet]
        public string GetToken(string email)
        {
            string key = _configuration["Jwt:JwtKey"].ToString();//Key is required more 16 character
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                //new Claim(ClaimTypes.Name,email),
                new Claim(ClaimTypes.Sid,Guid.NewGuid().ToString()),
                new Claim("Email",email),
                new Claim("Order ID","A0001"),
                new Claim("Price","100.99")
            };
            
            var token = new JwtSecurityToken(
                //issuer: _configuration["Jwt:JwtIssuer"],
                //audience: _configuration["Jwt:JwtAudience"],
                claims: claims,
                //expires: DateTime.Now.AddDays(Convert.ToDouble(_configuration["JwtExpireDays"])),
                signingCredentials: credentials
            );


            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [ActionName("DecryptJwt")]
        [HttpGet]
        public IActionResult DecryptJwt()
        {
            string tokenString = HttpContext.Request.Headers["Authorization"];
            var jwtEncodedString = tokenString.Substring(7); // trim 'Bearer ' from the start since its just a prefix for the token string

            if (ValidateToken(jwtEncodedString))
            {
                //Is Authen >> success
            }
            else
            {
                //Is Authen >> fail
            }

            var token = new JwtSecurityToken(jwtEncodedString: jwtEncodedString);

            //ระบุ Keys ตรง ๆ
            List<dynamic> list1 = new List<dynamic>();
            var Email = token.Payload["Email"];
            var OrderID = token.Payload["Order ID"];
            var Price = token.Payload["Price"];
            list1.Add(new
            {
                Email,
                OrderID,
                Price
            });

            //Get parameter and value
            List<dynamic> list2 = new List<dynamic>();
            if (token.Claims.Count() > 0)
            {
                foreach (var item in token.Claims)
                {
                    list2.Add(new
                    {
                        type = item.Type,
                        valie = item.Value
                    });
                }
            }

            List<dynamic> res = new List<dynamic>();
            res.Add(new
            {
                list1,
                list2
            });

            return Ok(res);
        }
        private static bool ValidateToken(string authToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GetValidationParameters();

            SecurityToken validatedToken;
            try
            {
                IPrincipal principal = tokenHandler.ValidateToken(authToken, validationParameters, out validatedToken);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
            
        }
        private static TokenValidationParameters GetValidationParameters()
        {
            string key = "DevelopBySaksitSuksamai";//Key is required more 16 character
            return new TokenValidationParameters()
            {
                ValidateLifetime = false, // Because there is no expiration in the generated token
                ValidateAudience = false, // Because there is no audiance in the generated token
                ValidateIssuer = false,   // Because there is no issuer in the generated token
                //ValidIssuer = "Saksit Suksamai",
                //ValidAudience = "Bond",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)) // The same key as the one that generate the token
            };

            
        }

        
    }
}