package com.hoannt.security.controllers;

import com.hoannt.security.dto.UserDTO;
import com.hoannt.security.security.UserDetail.CurrentUser;
import com.hoannt.security.security.UserDetail.UserDetailImpl;
import com.hoannt.security.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    UserService userService;

    @GetMapping("/currentUser")
    @PreAuthorize("hasRole('USER')")
    public UserDTO getCurrentUser(@CurrentUser UserDetailImpl currentUser) {
        UserDTO userDTO = new UserDTO(currentUser.getId(), currentUser.getUsername(), currentUser.getName());
        return userDTO;
    }

}
