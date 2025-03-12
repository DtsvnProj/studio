package org.craftercms.studio.impl.v2.security.authentication.ldap;

import org.craftercms.studio.api.v2.dal.User;
import org.craftercms.studio.api.v2.service.security.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapName;
import java.util.List;

public class LdapAuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(LdapAuthService.class);
    private final LdapTemplate ldapTemplate;
    private final UserService userService;
    private String url;
    private String base;
    private String userDn;
    private String password;
    private String pooled;

    public LdapAuthService(LdapTemplate ldapTemplate, UserService userService) {
        this.ldapTemplate = ldapTemplate;
        this.userService = userService;
    }

    // Getter & Setter (cần thiết để Spring inject properties từ XML)
    public void setUrl(String url) {
        this.url = url;
    }

    public void setBase(String base) {
        this.base = base;
    }

    public void setUserDn(String userDn) {
        this.userDn = userDn;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setPooled(String pooled) {
        this.pooled = pooled;
    }

    public boolean authenticate(String username, String password) {

        LOGGER.info("Authenticating user query | url: {} ; base: {} ; userDn: {} ; password: {} ; pooled: {}", this.url, this.base, this.userDn, this.password, this.pooled);
        LOGGER.info("User login: {}/{}", username, password);
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("uid", username)); // Dùng cn thay vì uid

        try {
            return ldapTemplate.authenticate(LdapUtils.emptyLdapName(), filter.encode(), password);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public User loadUserFromDB(String username) {
        try {
            User user = userService.getUserByUsernameInternal(username);
            return user;
        } catch (Exception e) {
            e.printStackTrace();
            throw new UsernameNotFoundException("User not found in DB: " + username);
        }
    }
}
