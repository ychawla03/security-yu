package com.springjwt.security.services;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import com.springjwt.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

//The UserDetailsImpl class implements the UserDetails interface, which is part of Spring Security.
//This class represents the authenticated user and provides the essential details Spring Security
//needs to handle authentication and authorization, such as username, password, and roles
//(authorities). Here's a detailed breakdown of what this class does:

public class UserDetailsImpl implements UserDetails {
  private static final long serialVersionUID = 1L;

  private Long id;

  private String username;

  private String email;

  @JsonIgnore
  private String password;

  private Collection<? extends GrantedAuthority> authorities;


  //This constructor initializes the user's details, such as ID, username, email, password, and
  // authorities (roles/permissions).

  public UserDetailsImpl(Long id, String username, String email, String password,
      Collection<? extends GrantedAuthority> authorities) {
    this.id = id;
    this.username = username;
    this.email = email;
    this.password = password;
    this.authorities = authorities;
  }

  //Implements UserDetails: By implementing this interface, this class provides the information
  //needed by Spring Security for authentication and authorization.

  //Fields:
  //id: The user's unique identifier.
  //username: The user's username, typically used for login.
  //email: The user's email address.
  //password: The user's hashed password (annotated with @JsonIgnore to prevent it from being
  //serialized when converting the object to JSON).

  //authorities: A collection of granted authorities (roles/permissions) that the user has.
  public static UserDetailsImpl build(User user) {
    List<GrantedAuthority> authorities = user.getRoles().stream()
        .map(role -> new SimpleGrantedAuthority(role.getName().name()))
        .collect(Collectors.toList());

    return new UserDetailsImpl(
        user.getId(), 
        user.getUsername(), 
        user.getEmail(),
        user.getPassword(), 
        authorities);
  }

  //Static Factory Method: This method creates an instance of UserDetailsImpl from a User object.
  //Converts Roles to Authorities: It converts the user's roles into Spring Security's
  //GrantedAuthority objects. Each role is mapped to a SimpleGrantedAuthority object.

  //This method is useful when the UserDetailsImpl needs to be created from a domain object
  //(like a User entity in the database).

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public Long getId() {
    return id;
  }

  public String getEmail() {
    return email;
  }

  //getAuthorities(): Returns the user's authorities (roles/permissions), which are necessary for
  //role-based access control in Spring Security.

  //Other Getters: getId(), getEmail(), getPassword(), and getUsername() provide access to the
  //user's details (ID, email, password, and username).
  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  //These methods define the account status and are required by Spring Security to check whether
  //the user's account is valid. All of them return true here, which means:
  //
  //The account is not expired.
  //The account is not locked.
  //The credentials (password) are not expired.
  //The account is enabled (active).

  //These can be customized based on application-specific logic, such as disabling accounts or
  //locking them after too many failed login attempts.
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o)
      return true;
    if (o == null || getClass() != o.getClass())
      return false;
    UserDetailsImpl user = (UserDetailsImpl) o;
    return Objects.equals(id, user.id);
  }
}

//The equals() method is overridden to compare UserDetailsImpl objects based on their id. This is
//useful for checking if two instances of UserDetailsImpl represent the same user.

//Summary
//The UserDetailsImpl class represents a custom implementation of Spring Security’s UserDetails
//interface. It encapsulates user information (ID, username, email, password, and authorities)
//and is used by Spring Security for authentication and authorization. The class provides:

//
//Authorities (roles): For role-based access control.
//User account details: Like username, password, and email.
//Account status checks: To determine if the account is expired, locked, or disabled.
//This class is essential in integrating the application's User domain with Spring Security's
//user authentication system.