package com.security2.demo.controllers;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.security2.demo.security.jwt.AuthEntryPointJwt;
import com.security2.demo.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security2.demo.models.ERole;
import com.security2.demo.models.Role;
import com.security2.demo.models.User;
import com.security2.demo.payload.request.LoginRequest;
import com.security2.demo.payload.request.SignupRequest;
import com.security2.demo.payload.response.JwtResponse;
import com.security2.demo.payload.response.MessageResponse;
import com.security2.demo.repository.RoleRepository;
import com.security2.demo.repository.UserRepository;
import com.security2.demo.security.jwt.JwtUtils;
import com.security2.demo.security.services.UserDetailsImp;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping(value = "/api/auth", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)

public class AuthController {
    //@Autowired
    AuthenticationManager authenticationManager;
    //@Autowired
    UserRepository userRepository;
    ///@Autowired
    RoleRepository roleRepository;
    PasswordEncoder encoder;

   // @Autowired
    JwtUtils jwtUtils;
    public AuthController(AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          RoleRepository roleRepository,
                          PasswordEncoder encoder,
                          JwtUtils jwtUtils
                          ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImp userDetailsImp = (UserDetailsImp) authentication.getPrincipal();
        List<String> roles = userDetailsImp.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());


        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetailsImp.getId(),
                userDetailsImp.getUsername(),
                userDetailsImp.getPassword(),
                roles));
    }
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse(("Error: Email is already in use!")));
        }
        User user = new User(signUpRequest.getUsername(),encoder.encode(signUpRequest.getPassword()),signUpRequest.getEmail() );
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null){
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("Error:Role is not found"));
            roles.add(userRole);
        }else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
