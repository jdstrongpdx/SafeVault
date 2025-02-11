using System;
using Xunit;
using SafeVault.Utilities;

namespace SafeVault.Tests
{
    public class TestInputValidation
    {
        [Fact]
        public void TestForSQLInjection()
        {
            // Placeholder for SQL Injection test
        }

        [Fact]
        public void TestForXSS()
        {
            string maliciousInput = "<script>alert('XSS');</script>";
            bool isValid = ValidationHelpers.IsValidXssInput(maliciousInput);
            Assert.False(isValid, "XSS Test Failed: Input should be invalid for XSS attacks.");
        }
    }
}