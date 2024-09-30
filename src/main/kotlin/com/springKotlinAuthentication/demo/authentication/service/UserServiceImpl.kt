package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.UserUtil
import com.springKotlinAuthentication.demo.authentication.constant.Constant
import com.springKotlinAuthentication.demo.authentication.dto.request.UpdateUserRequest
import com.springKotlinAuthentication.demo.authentication.dto.response.UserResponse
import com.springKotlinAuthentication.demo.authentication.repository.UserRepository
import org.springframework.data.domain.Sort
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDate
import java.util.*

class UserServiceImpl(
    private val userRepository: UserRepository
): UserService {

    @Transactional(readOnly = true)
    override fun readUserById(userId: UUID): UserResponse {
        val user = userRepository.findById(userId)
            .orElseThrow { UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, userId)) }

        return UserUtil.userToUserResponse(user)
    }

    @Transactional
    override fun updateUserById(userId: UUID, request: UpdateUserRequest): UserResponse {
        TODO("Not yet implemented")
    }

    @Transactional
    override fun deleteUserById(userId: UUID): UserResponse {
        val user = userRepository.findById(userId)
            .orElseThrow { UsernameNotFoundException(String.format(Constant.USER_NOT_FOUND, userId)) }

        userRepository.delete(user)
        return UserUtil.userToUserResponse(user)
    }

    @Transactional(readOnly = true)
    override fun retrieveAllUsers(): List<UserResponse> {
        val sort = Sort.by(Sort.Direction.DESC, "createdAt")
        return userRepository.findAll(sort)
            .map { user -> UserUtil.userToUserResponse(user) }
    }

    @Transactional(readOnly = true)
    override fun listUsersByDob(dob: LocalDate): List<UserResponse> {
        return userRepository.findByDob(dob)
            .map { user -> UserUtil.userToUserResponse(user) }
    }
}