package com.cos.security1.config;

import com.cos.security1.config.auth.PrincipalDetailsService;
import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@AllArgsConstructor
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
//secured 어노테이션 활성화
//preAuthorize, postAuthorize 어노테이션 활성화
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    private final PrincipalOauth2UserService principalOauth2UserService;

    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    /*@Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }*/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해 준다.
                //즉 controller에 login을 안만들어도 됨.
                .loginProcessingUrl("/login")
                // 얘가 로그인페이지를 통해서 요청해주면 index.html 로 가지만
                // 만약 다른 페이지를 요청했었다면 로그인 후 해당 페이지로 이동시켜준다.
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                // 구글 로그인이 완료된 뒤의 후처리가 필요함. 1. 코드받기(인증), 2. 엑세스토큰(권한)
                // 3. 사용자 프로필 정보를 가져와서, 4-1). 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함.
                //4-2) (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (vip 등급, 일반등급)
                //추가 정보가 있다면 추가적인 회원가입을 진행하고 기본정보만 필요하다면 자동으로 회원가입됨.
                //구글 로그인 완료가 되면 코드 안받고, (엑세스 토큰+사용자 프로필 정보 한번에 받음)
                .userInfoEndpoint()
                .userService(principalOauth2UserService);

    }
}
