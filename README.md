# Spring Boot Kotlin Authentication API

## Overview
This project demonstrates secure, token-based authentication built using Spring Boot, Kotlin, and JWT. The application is **running on a free-tier EC2 instance**, and it supports essential authentication operations such as user registration, login, password reset, and updating user information. Additionally, an Actuator server is available on port `8090` for monitoring and managing the application.

## Features
- **User Registration:** Register new users with email, password, and personal details.
- **Login:** Authenticate users via email and password, and generate JWT tokens for secure access.
- **Password Reset:** Send password reset tokens to user emails.
- **Update User Info:** Modify user details using the user ID.
- **JWT-based Security:** Protect API endpoints using JSON Web Tokens (JWT).
- **User Management:** List all users, read individual user details, and delete users by ID.
- **Actuator Support:** Monitor application health and performance using Spring Boot Actuator on port `8090`.

## API Endpoints

### Authentication
- **Register User**  
  `POST /auth/register`  
  Register a new user with the provided details.

- **Login User**  
  `POST /auth/login`  
  Authenticate a user using email and password.

- **Reset Password**  
  `POST /auth/reset`  
  Send a password reset token to the user’s email.

- **Change Password**  
  `POST /auth/change`  
  Change the password using the provided token.

### User Management
- **List Users**  
  `GET /auth/users`  
  Retrieve a list of all registered users.

- **Read User**  
  `GET /auth/users/{id}`  
  Retrieve a user's details using their ID.

- **Update User**  
  `PUT /auth/users/{id}update`  
  Update a user’s information by their ID.

- **Delete User**  
  `DELETE /auth/users/{id}/delete`  
  Delete a user from the system using their ID.

### Account Confirmation
- **Confirm Account**  
  `GET /auth/confirm?token={confirmationToken}`  
  Confirm a user's account using the token sent to their email.

## Installation

### Prerequisites
- Java 21 or later
- Kotlin
- Gradle

### Running the Project
1. Clone the repository:
   ```bash
   git clone https://github.com/Kenato254/spring-kotlin-authentication-demo
   ```
2. Navigate to the project directory:
   ```bash
   cd spring-kotlin-authentication-demo
   ```
3. Build the project with Gradle:
   ```bash
   ./gradlew build
   ```
4. Run the application:
   ```bash
   ./gradlew bootRun
   ```

The application will run locally at `http://localhost:8080/api`, and the Actuator endpoints will be accessible on `http://localhost:8090`.

## API Documentation
The API is documented using OpenAPI/Swagger. After running the application, access the API documentation at:
```
http://localhost:8080/api/swagger-ui.html
```

## License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Contact
For any issues or questions, reach out to:
- **Name:** Spring Kotlin Authentication Demo
- **Email:** [kendygitonga@gmail.com](mailto:kendygitonga@gmail.com)
- **GitHub:** [Kenato254](https://github.com/Kenato254/spring-kotlin-authentication-demo)

---

Happy coding! 😊
