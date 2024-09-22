package com.springKotlinAuthentication.demo.authentication.service

import com.springKotlinAuthentication.demo.authentication.repository.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class CustomUserDetailService(private val userRepository: UserRepository) : UserDetailsService {
    override fun loadUserByUsername(username: String?): UserDetails {
        val user = userRepository.findByEmail(username!!)
            ?: throw UsernameNotFoundException("User not found with email: $username")

        return org.springframework.security.core.userdetails.User(
            user.email,
            user.password,
            user.isEnabled,
            user.credentialExpired,
            user.expired,
            user.locked,
            user.authorities
        )
    }
}
