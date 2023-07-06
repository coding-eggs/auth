package com.coding.auth.model;

import java.io.Serial;
import java.io.Serializable;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

/**
 * base_role
 * @author 
 */
@Data
public class BaseRole implements Serializable{
    private Integer id;

    private String roleName;

    @Serial
    private static final long serialVersionUID = 1L;

}