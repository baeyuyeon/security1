package com.cos.security1.respository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//CRUD 함수를 JPARepository 가 들고 있음
//@Repository 라는 어노테이션이 없어도 , IOC가 된다.
public interface UserRepository extends JpaRepository<User, Integer> {

    // findBy규칙 -> Username 문법
    // select * from user where username = 1?
    public User findByUsername(String username); //JPA Query Methods
}
