package com.example.rbac_auth.controller;

import java.util.Map;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.rbac_auth.dto.LoginRequest;
import com.example.rbac_auth.dto.RegisterRequest;
import com.example.rbac_auth.model.User;
import com.example.rbac_auth.repo.UserRepository;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepo;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public AuthController(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest req) {
        if (userRepo.existsByUsername(req.username)) {
            return Map.of("error", "Username already exists");
        }

        User user = new User(
                req.username,
                encoder.encode(req.password),
                req.role
        );

        userRepo.save(user);

        return Map.of(
                "message", "User registered",
                "username", user.getUsername(),
                "role", user.getRole()
        );
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest req) {
        var userOpt = userRepo.findByUsername(req.username);

        if (userOpt.isEmpty()) {
            return Map.of("error", "Invalid credentials");
        }

        User user = userOpt.get();

        if (!encoder.matches(req.password, user.getPassword())) {
            return Map.of("error", "Invalid credentials");
        }

        return Map.of(
                "message", "Login successful",
                "username", user.getUsername(),
                "role", user.getRole()
        );
    }
}


