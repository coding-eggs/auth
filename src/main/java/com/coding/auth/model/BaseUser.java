package com.coding.auth.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * base_user
 * @author 
 */
@Data
public class BaseUser implements Serializable{
    private Integer id;

    private String username;

    private String password;

    private Boolean accountNonExpired;

    private Boolean accountNonLocked;

    private Boolean credentialsNonExpired;

    private Boolean enable;

    @Serial
    private static final long serialVersionUID = 1L;
}