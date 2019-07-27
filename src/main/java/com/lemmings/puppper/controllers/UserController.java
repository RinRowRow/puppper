package com.lemmings.puppper.controllers;

import com.lemmings.puppper.model.Status;
import com.lemmings.puppper.model.User;
import com.lemmings.puppper.security.jwt.JwtTokenProvider;
import com.lemmings.puppper.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/{id}")
    public String getUser(@PathVariable("id") Long id, Model model) {
        model.addAttribute("user", userService.findById(id));
        return "account";
    }

    @GetMapping("/signup")
    public String registration(Model model) {
        model.addAttribute("user", new User());
        return "signup";
    }


    @PostMapping("/signup")
    public ModelAndView registration(@ModelAttribute("user") User user,
                                     HttpServletResponse response,
                                     Model model) throws IOException {

        User userFind = userService.findByEmail(user.getEmail());
        if (userFind != null) {
            model.addAttribute("error", "this user is already exists");
            return new ModelAndView("signup");
        }

        String token = jwtTokenProvider.createToken(user.getEmail());
        User registeredUser = userService.register(user);

        addCookie(response, registeredUser, token);

        response.sendRedirect("/home");
        return new ModelAndView();
    }



    @GetMapping("/login")
    public String authentication(Model model) {
        model.addAttribute("user", new User());
        return "login";
    }

    @PostMapping("/login")
    public ModelAndView authentication(@ModelAttribute("user") User user,
                                       HttpServletResponse response,
                                       Model model) throws IOException {
        try {
            String userEmail = user.getEmail();
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userEmail, user.getPassword()));
            User userFind = userService.findByEmail(userEmail);

            if (userFind == null) {
                throw new UsernameNotFoundException("User with email: " + userEmail + " not found");
            }

            if (userFind.getStatus() == Status.DELETED) {
                userService.restoreToStatus(userFind);
            }

            String token = jwtTokenProvider.createToken(userEmail);

            addCookie(response, userFind, token);

            response.sendRedirect("/home");
            return new ModelAndView();
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid email or password");
        }
    }

    @GetMapping("/update")
    public String update(Model model) {
        model.addAttribute("user", new User());
        return "update";
    }

    @PostMapping("/update")
    public ModelAndView update(@ModelAttribute("user") User user,
                           HttpServletResponse response) throws IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUserEmail = auth.getName();

        if (!user.getName().equals("")) {
            Cookie userNameCookie = new Cookie("user_name", user.getName());
            response.addCookie(userNameCookie);
            userService.setName(currentUserEmail, user.getName());
        }

        if (!user.getPassword().equals("")) {
            String token = jwtTokenProvider.createToken(user.getPassword());
            Cookie accessTokenCookie = new Cookie("access_token", token);
            response.addCookie(accessTokenCookie);
            userService.setPassword(currentUserEmail, user.getPassword());
        }

        response.sendRedirect("/home");
        return new ModelAndView();
    }

    @GetMapping("/delete")
    public String delete( ) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUserEmail = auth.getName();
        userService.deleteToStatus(currentUserEmail);
        SecurityContextHolder.clearContext();

        return "login";
    }

    @GetMapping("/settings")
    public String settings() {
        return "settings";
    }


    @GetMapping("/restore")
    public String restore(Model model) {
        model.addAttribute("user", new User());
        return "restore";
    }

    @PostMapping("/restore")
    public ModelAndView restore(@ModelAttribute("user") User user,
                                HttpServletResponse response) throws IOException {

        User userFind = userService.findByEmail(user.getEmail());

        if (userFind == null) {
            throw new UsernameNotFoundException(
                    "User with email: "
                    + user.getEmail() + " not found"
            );
        }

        if (userService.matchesPass(user.getPassword(), userFind.getPassword())) {
            userService.restoreToStatus(userFind);
        }

        response.sendRedirect("/home");
        return new ModelAndView();
    }


    private void addCookie(HttpServletResponse response, User user, String token) {

        Cookie accessTokenCookie = new Cookie("access_token", token);
        Cookie userNameCookie = new Cookie("user_name", user.getName());
        Cookie userIdCookie = new Cookie("user_id", user.getId().toString());
        Cookie roleNameCookie = new Cookie("role", user.getRole().getName());

        accessTokenCookie.setMaxAge(60 * 60);
        userNameCookie.setMaxAge(60 * 60);
        userIdCookie.setMaxAge(60 * 60);
        roleNameCookie.setMaxAge(60 * 60);

        response.addCookie(accessTokenCookie);
        response.addCookie(userNameCookie);
        response.addCookie(userIdCookie);
        response.addCookie(roleNameCookie);
    }
}
