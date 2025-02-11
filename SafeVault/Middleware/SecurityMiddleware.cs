using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Text;
using System.Threading.Tasks;

public class SecurityMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Header Validation
        if (!ValidateHeaders(context))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid Headers.");
            return;
        }

        // Protect against SQL Injection and XSS in Query Strings / Request Body (Basic Check)
        if (context.Request.QueryString.HasValue &&
            ContainsInjectionPatterns(context.Request.QueryString.Value))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Potential SQL Injection or XSS detected in Query String.");
            return;
        }

        if (context.Request.ContentLength > 0)
        {
            context.Request.EnableBuffering();
            var bodyContent = await ReadRequestBody(context.Request);

            if (ContainsInjectionPatterns(bodyContent))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Potential SQL Injection or XSS detected in Request Body.");
                return;
            }

            context.Request.Body.Position = 0;
        }

        await _next(context);
    }

    private bool ValidateHeaders(HttpContext context)
    {
        foreach (var header in context.Request.Headers)
        {
            var headerValue = header.Value.ToString();

            // Basic example: Reject suspicious characters in header values
            if (ContainsInjectionPatterns(headerValue))
            {
                return false;
            }
        }

        return true;
    }

    private static bool ContainsInjectionPatterns(string? content)
    {
        if (string.IsNullOrEmpty(content)) return false;

        // Simple Regex Patterns for Basic Injection Checks
        var sqlPattern = new Regex(
            @"(\b(SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|ALTER|EXEC|UNION|MERGE)\b)|(;--|--\s|\')",
            RegexOptions.IgnoreCase);
        var xssPattern = new Regex(@"(<\s*script[^>]*>|<[^>]+on[a-z]+\s*=|javascript:|<iframe|eval\s*\()",
            RegexOptions.IgnoreCase);

        return sqlPattern.IsMatch(content) || xssPattern.IsMatch(content);
    }

    private static async Task<string> ReadRequestBody(HttpRequest request)
    {
        using var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        return body;
    }
}