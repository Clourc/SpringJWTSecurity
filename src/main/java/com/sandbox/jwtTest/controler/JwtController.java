package com.sandbox.jwtTest.controler;

import com.sandbox.jwtTest.dto.UserDto;
import com.sandbox.jwtTest.jwt.Jwt;
import com.sandbox.jwtTest.service.UserService;
import com.sandbox.jwtTest.utility.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;

@Controller
public class JwtController {

    private final Jwt jwtUtil;
    private final UserService userService;

    public JwtController(Jwt jwtUtil, UserService userService) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    @PostMapping("/register")
    @ResponseBody
    public ResponseEntity<ApiResponse<Object>> register(@RequestBody UserDto newUser) {
        HashMap<String, Object> data = new HashMap<>();
        try {
            userService.register(newUser);
            String token = jwtUtil.generateToken(newUser);
            data.put("user", newUser);
            data.put("token", token);
            data.put("Request", "User registered");
            return new ResponseEntity<>(new ApiResponse<>(data), HttpStatus.OK);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return new ResponseEntity<>(new ApiResponse<>(e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login")
    @ResponseBody
    public ResponseEntity<ApiResponse<Object>> login(@RequestBody UserDto user) {
        HashMap<String, Object> data = new HashMap<>();
        try {
            userService.login(user);
            String token = jwtUtil.generateToken(user);
            data.put("user", user);
            data.put("token", token);
            data.put("Request", "User logged in");
            return new ResponseEntity<>(new ApiResponse<>(data), HttpStatus.OK);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return new ResponseEntity<>(new ApiResponse<>(e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/admin-only")
    @ResponseBody
    public ResponseEntity<ApiResponse<Object>> adminData(){
        HashMap<String, Object> data = new HashMap<>();
        try {
            data.put("message", "This is only accessible by admins");
            return new ResponseEntity<>(new ApiResponse<>(data), HttpStatus.OK);
        } catch (Exception e){
            System.out.println(e.getMessage());
            return new ResponseEntity<>(new ApiResponse<>(e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/all")
    @ResponseBody
    public ResponseEntity<ApiResponse<Object>> userAdminData(){
        HashMap<String, Object> data = new HashMap<>();
        try {
            data.put("message", "This is accessible by everyone");
            return new ResponseEntity<>(new ApiResponse<>(data), HttpStatus.OK);
        } catch (Exception e){
            System.out.println(e.getMessage());
            return new ResponseEntity<>(new ApiResponse<>(e.getMessage()), HttpStatus.BAD_REQUEST);
        }
    }
}
