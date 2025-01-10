package com.krishna.authenticationservice.controller;

import com.krishna.authenticationservice.model.User;
import com.krishna.authenticationservice.service.JwtService;
import com.krishna.authenticationservice.service.UserService;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
// @RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    private UserService service;

    @Autowired
    private JwtService jwtService;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("register")
    public ResponseEntity<User> register(@RequestBody User user) {
        try {
            System.out.println(user.getUsername());
            User savedUser = service.saveUser(user);
            if (savedUser == null)
                return new ResponseEntity<>(HttpStatus.CONFLICT);

            System.out.println(savedUser.getPasswordHash());
            return new ResponseEntity<>(savedUser, HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }
    }

    @PostMapping("login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPasswordHash()));

            if (authentication.isAuthenticated()) {
                // Fetch the authenticated user from the database to get their role
                User authenticatedUser = service.findByUsername(user.getUsername());

                // Generate the token with role
                String token = jwtService.generateToken(authenticatedUser.getUsername(), authenticatedUser.getRole());

                // Add token to the response header
                return ResponseEntity.ok()
                        .header("Authorization", "Bearer " + token)
                        .body("Login successful");
            } else {
                return new ResponseEntity<>("Login Failed", HttpStatus.UNAUTHORIZED);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("api/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        System.out.println("Hello");
        response.setHeader("Authorization", ""); 
        return ResponseEntity.ok("Logged out successfully");
    }

    @Secured("ROLE_ADMIN")
    @PostMapping("/admin/endpoint")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Admin access granted");
    }

}