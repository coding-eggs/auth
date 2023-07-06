package com.coding.auth.model.security;

import com.coding.auth.model.BaseRole;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;


@EqualsAndHashCode(callSuper = true)
@Data
public class SecurityGrantedAuthority extends BaseRole implements GrantedAuthority {


    @Override
    public String getAuthority() {
        return super.getRoleName();
    }
}
