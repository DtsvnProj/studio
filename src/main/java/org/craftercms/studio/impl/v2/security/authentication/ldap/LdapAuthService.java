package org.craftercms.studio.impl.v2.security.authentication.ldap;

import org.craftercms.studio.api.v2.dal.User;
import org.craftercms.studio.api.v2.service.security.UserService;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class LdapAuthService {

    private final LdapTemplate ldapTemplate;
    private final UserService userService;

    public LdapAuthService(LdapTemplate ldapTemplate, UserService userService) {
        this.ldapTemplate = ldapTemplate;
        this.userService = userService;
    }

    public boolean authenticate(String username, String password) {
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("cn", username)); // Dùng cn thay vì uid

        try {
            return ldapTemplate.authenticate("ou=people", filter.encode(), password);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public User loadUserFromDB(String username) {
        try {
            User user = userService.getUserByUsernameInternal(username);
            return user;
        }catch (Exception e) {
            e.printStackTrace();
            throw new UsernameNotFoundException("User not found in DB: " + username);
        }
    }
}
