package com.example.demo;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
public class LoginController {

    private Map<String, Integer> loginAttempts = new HashMap<>();

    @GetMapping("/login")
    public ModelAndView login(HttpServletRequest request, HttpSession session) {
        ModelAndView modelAndView = new ModelAndView();

        // Check for existing cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("user".equals(cookie.getName()) && "admin".equals(cookie.getValue())) {
                    session.setAttribute("username", "admin");

                    Integer count = (Integer) session.getAttribute("count");
                    session.setAttribute("count", (count == null ? 1 : count + 1));

                    session.setAttribute("lastVisit", LocalDateTime.now());

                    modelAndView.setViewName("redirect:/home");
                    return modelAndView;
                }
            }
        }

        modelAndView.setViewName("login");
        return modelAndView;
    }

    @PostMapping("/login")
    public ModelAndView login(@RequestParam String username, @RequestParam String password,
                              HttpSession session, HttpServletResponse response) {
        ModelAndView modelAndView = new ModelAndView();

        // Check login attempts
        int attempts = loginAttempts.getOrDefault(username, 0);
        if (attempts >= 3) {
            modelAndView.setViewName("login");
            modelAndView.addObject("error", "Too many failed attempts. Please try again later.");
            return modelAndView;
        }

        if ("admin".equals(username) && "admin".equals(password)) {
            session.setAttribute("username", username);

            Integer count = (Integer) session.getAttribute("count");
            session.setAttribute("count", (count == null ? 1 : count + 1));

            session.setAttribute("lastVisit", LocalDateTime.now());

            Cookie cookie = new Cookie("user", username);
            cookie.setMaxAge(60 * 60 * 24 * 28); // 4 weeks
            cookie.setPath("/");
            response.addCookie(cookie);

            loginAttempts.put(username, 0); // Reset attempts on successful login

            modelAndView.setViewName("redirect:/home");
        } else {
            loginAttempts.put(username, attempts + 1);
            modelAndView.setViewName("login");
            modelAndView.addObject("error", "Invalid username or password");
        }
        return modelAndView;
    }

    @GetMapping("/home")
    public ModelAndView home(HttpSession session) {
        if (session.getAttribute("username") == null) {
            return new ModelAndView("redirect:/login");
        }

        ModelAndView modelAndView = new ModelAndView("home");
        modelAndView.addObject("username", session.getAttribute("username"));
        modelAndView.addObject("count", session.getAttribute("count"));
        modelAndView.addObject("lastVisit", session.getAttribute("lastVisit"));
        return modelAndView;
    }
}