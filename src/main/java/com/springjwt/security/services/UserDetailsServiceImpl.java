package com.springjwt.security.services;

import com.springjwt.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.springjwt.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UserRepository userRepository;

  //The UserDetailsServiceImpl class implements Spring Security's UserDetailsService interface. It
  //provides a custom way to load user-specific data, which is required during the authentication
  //process. This class is responsible for retrieving a user from the database using a
  //UserRepository and converting the user entity into an instance of UserDetailsImpl, which
  //Spring Security uses to perform authentication and authorization. Here's a breakdown of
  //the class:

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }

  //@Service: Marks this class as a Spring service, meaning it will
  //be detected during component scanning and managed by Spring's dependency injection container.


  //UserRepository: This is an interface for interacting with the database. It's autowired into
  //this class to retrieve user data from the database. The UserRepository likely has a method to
  //find users by their username.

}


//Implements loadUserByUsername: This is the main method of the UserDetailsService interface. It's
//called by Spring Security when a user attempts to log in.

//Parameter:
//username: This is the username entered by the user during login.
//Find User by Username:
//The method tries to retrieve the User entity from the database using the userRepository.
//findByUsername(username).
//If the user is not found, it throws a UsernameNotFoundException with an appropriate error
//message.


//Convert to UserDetailsImpl:
//If the user is found, it is converted into an instance of UserDetailsImpl by calling
//UserDetailsImpl.build(user).
//UserDetailsImpl implements UserDetails and represents the authenticated user in Spring
//Security, holding necessary information like username, password, and authorities (roles).

//3. How It Works with Spring Security
//During the authentication process, Spring Security calls this loadUserByUsername() method with
// the username entered by the user.
//This method then looks up the user in the database via UserRepository and converts the retrieved
// User entity into a UserDetailsImpl object.
//Spring Security uses this UserDetailsImpl object to validate the credentials
// (such as the password) and grant appropriate authorities (roles/permissions) to the user.
//Summary
//The UserDetailsServiceImpl class plays a key role in Spring Security's authentication
// process. It:
//
//Loads User Data: Retrieves the user from the database using the provided username.
//Handles Missing Users: Throws an exception if the user is not found.
//Converts to UserDetailsImpl: Transforms the retrieved User entity into a UserDetailsImpl object,
// which Spring Security uses to manage authentication and authorization.
//This class is essential for bridging the application's user management system with Spring
// Security’s authentication mechanism.