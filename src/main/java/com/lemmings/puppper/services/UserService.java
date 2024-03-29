package com.lemmings.puppper.services;

import com.lemmings.puppper.dao.RoleDAO;
import com.lemmings.puppper.dao.UserDAO;
import com.lemmings.puppper.model.Role;
import com.lemmings.puppper.model.Status;
import com.lemmings.puppper.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    @Autowired
    private  UserDAO userDAO;
    @Autowired
    private  RoleDAO roleDAO;
    @Autowired
    private  PasswordEncoder passwordEncoder;

    @Value("${passwordServ}")
    private String passwordServ;

    public User register(User user) {
        Role roleUser = findRoleByName("user");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(roleUser);
        user.setStatus(Status.ACTIVE);

        User registeredUser = userDAO.save(user);

        return registeredUser;
    }

    public List<User> getAll() {
        List<User> result = userDAO.findAll();
        return  result;
    }

    public User findByEmail(String email) {
        User result = userDAO.findByEmail(email);
        return result;
    }

    public User setPassword(String email, String password) {
        User user = findByEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        userDAO.save(user);
        return user;
    }

    public User setName(String email, String name) {
        User user = findByEmail(email);
        user.setName(name);
        userDAO.save(user);
        return user;
    }

    public User deleteToStatus(String email) {
        User user = findByEmail(email);
        user.setStatus(Status.DELETED);
        userDAO.save(user);
        return user;
    }

    public User findById(Long id) {
        return userDAO.findById(id).get();
    }

    public Role findRoleByName(String name) {
        return roleDAO.findByName(name);
    }

    public User makeAdmin(String email, String password) {

        if (!password.equals(passwordServ)) {
            throw new IllegalArgumentException("not correct password");
        }

        User user = userDAO.findByEmail(email);
        Role role = findRoleByName("admin");
        user.setRole(role);
        userDAO.save(user);
        return user;

    }

    public User restoreToStatus(User user) {
        user.setStatus(Status.ACTIVE);
        userDAO.save(user);
        return user;
    }

    public void delete(Long id) {
        userDAO.deleteById(id);
    }


    public boolean matchesPass (String rawPass, String encodedPass) {
        return passwordEncoder.matches(rawPass, encodedPass);
    }
}
