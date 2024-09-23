package com.springKotlinAuthentication.demo.authentication.controller

import com.springKotlinAuthentication.demo.authentication.dto.request.*
import com.springKotlinAuthentication.demo.authentication.dto.response.Api
import com.springKotlinAuthentication.demo.authentication.dto.response.LoginResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.RegisterResponse
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.service.AuthenticationService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.FieldError
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.*
import java.util.*
import io.swagger.v3.oas.annotations.parameters.RequestBody as Body


@RestController
@CrossOrigin(origins = ["*"]) // Allow all origins for anyone to test
@RequestMapping("auth")
class AuthenticationController(
    private val authenticationService: AuthenticationService
) {

    @Operation(summary = "Register a user")
    @ApiResponse(responseCode = "201", description = "Registers a user")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "409", description = "Conflict")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @PostMapping("register")
    fun register(
        @Body(description = "Request body containing user registration details", required = true)
        @RequestBody @Validated request: RegisterRequest
    ): ResponseEntity<Api<RegisterResponse>> {
        val token = authenticationService.registerUser(request)
        val response = Api.ok(token, "Register successful")
        return ResponseEntity.status(HttpStatus.CREATED).body(response)
    }


    @Operation(summary = "Read a user", description = "Retrieves user by a provided id")
    @ApiResponse(responseCode = "200", description = "Read user successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    @ApiResponse(responseCode = "403", description = "Forbidden")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("users/{id}")
    fun readUser(
        @Parameter(description = "ID of the user to retrieve", required = true)
        @PathVariable id: UUID
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.readUserById(id)
        val response = Api.ok(userResponse, "Read user successful")
        return ResponseEntity.ok(response)
    }


    @Operation(summary = "Update a user", description = "Updates user by a provided id")
    @ApiResponse(responseCode = "200", description = "Update user successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    @ApiResponse(responseCode = "403", description = "Forbidden")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @SecurityRequirement(name = "Bearer Authentication")
    @PutMapping("users/{id}update")
    fun updateUser(
        @Parameter(description = "ID of the user to be updated", required = true)
        @PathVariable id: UUID,

        @Body(
            description = "Request body containing the user details to be updated",
            required = true,
        )
        @RequestBody request: UpdateUserRequest
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.updateUserById(id, request)
        val response = Api.ok(userResponse, "Update user successful")
        return ResponseEntity.ok(response)
    }


    @Operation(summary = "Delete a user", description = "Deletes user by a provided id")
    @ApiResponse(responseCode = "200", description = "Delete user successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    @ApiResponse(responseCode = "403", description = "Forbidden")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @SecurityRequirement(name = "Bearer Authentication")
    @DeleteMapping("users/{id}/delete")
    fun deleteUser(
        @Parameter(description = "ID of the user to delete", required = true)
        @PathVariable id: UUID
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.deleteUserById(id)
        val response = Api.ok(userResponse, "Delete user successful")
        return ResponseEntity.ok(response)
    }


    @Operation(summary = "Login a user")
    @ApiResponse(responseCode = "202", description = "Logins a user using email and password")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @PostMapping("login")
    fun login(
        @Body(
            description = "Login request containing username and password",
            required = true,
        )
        @RequestBody @Validated request: LoginRequest
    ): ResponseEntity<Api<LoginResponse>> {
        val userResponse = authenticationService.loginUser(request)
        val successResponse = Api.ok(userResponse, "Login successful")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(successResponse)
    }


    @Operation(summary = "Confirm user account")
    @ApiResponse(responseCode = "202", description = "Confirms the user's account using a provided token")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "404", description = "User or Token not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @GetMapping("confirm")
    fun confirm(
        @Parameter(description = "Confirmation token for user account", required = true)
        @RequestParam("token") token: String
    ): ResponseEntity<Api<Unit>> {
        val confirmed = authenticationService.confirmUser(token)
        val successResponse = Api.ok(confirmed, "Confirm account successful")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(successResponse)
    }


    @Operation(summary = "Reset password", description = "Sends a password reset token to the user's email")
    @ApiResponse(responseCode = "202", description = "Password reset successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "404", description = "User not found")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @PostMapping("reset")
    fun reset(
        @Body(description = "Request body containing user email for password reset", required = true)
        @RequestBody @Validated request: ResetPasswordRequest
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.resetPassword(request)
        val response = Api.ok(userResponse, "Reset token sent successfully")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response)
    }


    @Operation(summary = "Change password", description = "Changes the user's password using the provided token")
    @ApiResponse(responseCode = "202", description = "Password change successful")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "401", description = "Unauthorized")
    @ApiResponse(responseCode = "403", description = "Forbidden")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("change")
    fun change(
        @Body(description = "Request body containing new password details", required = true)
        @RequestBody @Validated request: ChangePasswordRequest
    ): ResponseEntity<Api<UserResponse>> {
        val userResponse = authenticationService.changePassword(request)
        val response = Api.ok(userResponse, "Password change successful")
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response)
    }


    @Operation(summary = "List all users")
    @ApiResponse(responseCode = "200", description = "Retrieves a list of all users")
    @ApiResponse(responseCode = "400", description = "Bad request")
    @ApiResponse(responseCode = "403", description = "Unauthorized")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("users")
    fun getAllUsers(): ResponseEntity<Api<List<UserResponse>>> {
        val userResponses = authenticationService.getAllUsers()
        val response = Api.ok(userResponses, "List of users")
        return ResponseEntity.ok(response)
    }


    @ExceptionHandler(MethodArgumentNotValidException::class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleValidationExceptions(
        ex: MethodArgumentNotValidException
    ): Map<String, String?> {
        val errors: MutableMap<String, String?> = HashMap()
        ex.bindingResult.allErrors.forEach { error ->
            val fieldName = (error as FieldError).field
            val errorMessage = error.defaultMessage
            errors[fieldName] = errorMessage
        }
        return errors
    }
}
