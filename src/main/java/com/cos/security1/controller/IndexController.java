package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
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
    
    @GetMapping("/test/login")
    public @ResponseBody String testLogin(Authentication authentication,
            @AuthenticationPrincipal PrincipalDetails userDetails){
        System.out.println("/test/login =======================");
        //1번방법
        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        System.out.println("authentication = " + principalDetails.getUser());
        
        //2번방법
        System.out.println("userDetails= " + userDetails.getUser());
        return "세션정보 리턴";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOauthLogin(Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth){
        System.out.println("/test/login =======================");
        //1번방법
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        System.out.println("oAuth2User = " + oAuth2User.getAttributes());

        //2번방법
        System.out.println("oauth = " + oauth.getAttributes());
        return "세션정보 리턴";
    }

    @GetMapping({"/", ""})
    public String index() {
        // 머스테치 기본폴더 src/main/resources/
        // 뷰리졸버 설정 : templates(prefix),.mustache(suffix)
        return "index";
    }

    //OAuth 로그인을 해도 PrincipalDetails를 받을 수 있고
    //일반 로그인을 해도 PrincipalDetails를 받을 수 있고
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
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

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    //이거 사용하면 data()라는 메서드가 실행하기 전에 실행됨.
    //여러개 걸고싶을 때 쓰면 좋을듯.
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터정보";
    }
}
