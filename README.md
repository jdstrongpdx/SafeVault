# SafeVault

SafeVault is a portfolio project developed for the Microsoft Backend Security and Authentication Class. This project showcases modern security and authentication principles for backend applications built using ASP.NET Core. SafeVault focuses on creating secure, modular, and tested APIs for authentication and authorization.

---

## Purpose

The primary goal of SafeVault is to demonstrate skills in implementing backend security features, including Role-Based Access Control (RBAC), JWT-based authentication, security middleware, and robust input validation.

This project is also a showcase of best practices for testing using **xUnit** and **Moq**, ensuring the application is highly reliable and maintainable.

---

## Features

### 1. **Secrets Management**
- Securely loads sensitive configuration and secrets (e.g., connection strings, API keys) directly from `appsettings.json`.

---

### 2. **Role-Based Access Control (RBAC)**
- Implements user roles with specific permissions for accessing routes and resources.
- Enforces authorization policies to limit access to protected resources based on roles.

---

### 3. **JWT Generation & Validation**
- Provides services for creating and validating JSON Web Tokens (JWTs).
- Supports stateless session management using tokens to enable secure authentication.

---

### 4. **Security Middleware**
- Custom middleware to prevent:
    - Invalid HTTP headers.
    - SQL injection patterns in incoming requests.
    - XSS (Cross-Site Scripting) attacks.
- Proactively hardens the application against common vulnerabilities.

---

### 5. **Input Validation with DataAnnotations**
- Models decorated with `[DataAnnotations]` for strict validation of inputs.
- Prevents invalid or malicious data from being processed by the application.

---

### 6. **Input Sanitization in Controller Routes**
- Ensures all inputs to API endpoints are validated and sanitized to mitigate security risks.
- Guards against injecting unsafe patterns into the system.

---

### 7. **Password Hashing & Salting**
- Utilizes **bcrypt** to securely hash and salt user passwords.
- Protects stored credentials from brute force and rainbow table attacks.

---

### 8. **Testing with xUnit and Moq**
- Comprehensive unit testing using xUnit.
- Tests cover:
    - **Authentication Endpoints:** Login, Register, Logout.
    - Mocked dependencies for services using Moq.
- Ensures robustness and reliability in authentication services.

---

## Getting Started

### Prerequisites
- .NET SDK (v8.0 or higher)
- Visual Studio or JetBrains Rider IDE
- SQL Server (or any database supported by your app configuration)

### Setup
1. Clone the repository:
```shell script
git clone https://github.com/your-repo/SafeVault.git
```
2. Navigate to the project directory:
```shell script
cd SafeVault
```
3. Install dependencies:
```shell script
dotnet restore
```
4. Add your secrets in `appsettings.json`:
```json
{
     "JwtSettings": {
       "Issuer": "SafeVaultIssuer",
       "Audience": "SafeVaultAudience",
       "SecretKey": "YourSuperSecretKey"
     }
   }
```
5. Run the application:
```shell script
dotnet run
```
6. Access the API on the localhost:port generated.

---

## Project Structure

The project is organized into the following layers:

- **Controllers**: Expose RESTful endpoints and handle input sanitization/validation.
- **Services**: Encapsulate the business logic, including JWT generation and role management.
- **Models**: Define the data structure with validated properties using DataAnnotations.
- **Middleware**: Custom middleware to inspect and protect incoming HTTP requests.

---

## Testing

To run tests, use the following command:

```shell script
dotnet test
```

This will execute all unit tests written in xUnit while mocking dependencies using Moq.

---

## Security Features Breakdown

| Feature                        | Purpose                                                   |
|--------------------------------|-----------------------------------------------------------|
| Secrets Management             | Protects sensitive configuration stored in appsettings.   |
| RBAC                           | Restricts access to resources based on user roles.        |
| JWT Authentication             | Stateless and secure user session management.             |
| Security Middleware            | Defense against SQL injection, XSS, and invalid headers.  |
| Input Validation & Sanitization | Ensures inputs are valid and safe for processing.         |
| Password Hashing (bcrypt)      | Secures stored passwords against common attack vectors.   |

---

## Contributing

Contributions are welcome! If you'd like to contribute to SafeVault:
1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request.

---

## License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

## Author

SafeVault was developed as part of the **Microsoft Backend Security and Authentication Class** by [Your Name or Organization].

For any questions or comments, feel free to reach out!

--- 

Happy coding! 🚀