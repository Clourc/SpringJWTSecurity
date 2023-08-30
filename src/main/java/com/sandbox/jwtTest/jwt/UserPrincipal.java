package com.sandbox.jwtTest.jwt;

import org.springframework.security.core.GrantedAuthority;
import com.sandbox.jwtTest.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserPrincipal implements UserDetails {

    User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        List<GrantedAuthority> authorities = new ArrayList<>();
        //authorities.add(new SimpleGrantedAuthority(user.getRole().getType()));
        return authorities;
    }

    public UserPrincipal(User user){
        this.user = user;
    }

    @Override
    public String getPassword(){ return user.getPassword(); }

    @Override
    public String getUsername(){
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() { return false; }

    @Override
    public boolean isAccountNonLocked() { return false; }

    @Override
    public boolean isCredentialsNonExpired(){ return false; }

    @Override
    public boolean isEnabled(){ return true; }
}
