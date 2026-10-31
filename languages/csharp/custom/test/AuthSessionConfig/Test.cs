using System;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

public class SessionTests
{
    public void Bad()
    {
        HttpContext.Current.Session.Timeout = -1; // BAD: session never expires
    }

    public void BadLong()
    {
        var session = HttpContext.Current.Session;
        session.Timeout = 525600; // BAD: one year
    }

    public void Good()
    {
        HttpContext.Current.Session.Timeout = 20; // GOOD
    }
}

public class RedirectTests
{
    public void Bad(HttpResponse resp, bool loggedIn)
    {
        if (!loggedIn)
        {
            resp.Redirect("/login"); // BAD: execution continues
        }
        resp.Write("secret");
    }

    public void BadInBlock(HttpResponse resp)
    {
        resp.Redirect("/login", false); // BAD: explicitly does not end the response
        resp.Write("secret");
    }

    public void BadCore(Microsoft.AspNetCore.Http.HttpResponse resp, bool loggedIn)
    {
        if (!loggedIn)
            resp.Redirect("/login"); // BAD: ASP.NET Core never ends the request
        Console.WriteLine("privileged");
    }

    public void GoodReturn(HttpResponse resp, bool loggedIn)
    {
        if (!loggedIn)
        {
            resp.Redirect("/login"); // GOOD: followed by return
            return;
        }
        resp.Write("secret");
    }

    public void GoodEnd(HttpResponse resp)
    {
        resp.Redirect("/login", true); // GOOD: ends the response
        resp.Write("unreachable");
    }

    public void GoodLast(HttpResponse resp)
    {
        resp.Write("bye");
        resp.Redirect("/login"); // GOOD: nothing executes afterwards
    }

    public void GoodExplicitEnd(HttpResponse resp)
    {
        resp.Redirect("/login", false); // GOOD: response ended explicitly
        resp.End();
    }
}

public class IdentityTests
{
    public void ConfigureBad(IdentityOptions options)
    {
        options.Password.RequiredLength = 2; // BAD
        options.Password.RequireDigit = false;
        options.Lockout.AllowedForNewUsers = false; // BAD
    }

    public void ConfigureBadInit()
    {
        var p = new PasswordOptions { RequiredLength = 4 }; // BAD
    }

    public void ConfigureGood(IdentityOptions options)
    {
        options.Password.RequiredLength = 12; // GOOD
        options.Lockout.AllowedForNewUsers = true; // GOOD
    }
}

public class TokenTests
{
    public TokenValidationParameters Bad()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = false, // BAD
            ValidateAudience = false, // BAD
            ValidateIssuerSigningKey = true
        };
    }

    public void BadAssign(TokenValidationParameters p)
    {
        p.ValidateLifetime = false; // BAD
        p.RequireSignedTokens = false; // BAD
    }

    public TokenValidationParameters Good()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidIssuer = "https://issuer.example"
        };
    }
}
