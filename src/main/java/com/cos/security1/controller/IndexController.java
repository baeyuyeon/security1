package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IndexController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping({"/", ""})
    public String index() {
        // 머스테치 기본폴더 src/main/resources/
        // 뷰리졸버 설정 : templates(prefix),.mustache(suffix)
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user() {
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    // 스프링 시큐리티 해당주소를 낚아채버림.
    // SecurityConfig 생성 후 안낚아챔.
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        System.out.println("user = " + user);
        user.setRole("ROLE_USER");

        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);

        user.setPassword(encPassword);

        // 회원가입 잘됨, 그렇지만 시큐리티로 로그인할 수 없음, 이유는 패스워드가 암호화가 안되어 있어서.
        // 위에서 bCryptPasswordEncoder처리를 해주어서 이제 시큐리티로 로그인됨.
        userRepository.save(user);
        return "redirect:/loginForm";
    }


}
