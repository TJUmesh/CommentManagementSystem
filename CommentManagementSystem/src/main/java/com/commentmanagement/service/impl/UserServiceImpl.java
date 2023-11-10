package com.commentmanagement.service.impl;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.commentmanagement.exceptions.*;
import com.commentmanagement.model.User;
import com.commentmanagement.repository.UserRepository;

@Service
public class UserServiceImpl {

	@Autowired
	private UserRepository userRepository;

//	// create
//	public User createUser(User user) {
//		User savedUser = this.userRepository.save(user);
//		return savedUser;
//
//	}

// update
//	public User updateUser(User user, Integer userId) {
//		User users = this.userRepository.findById(userId)
//				.orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
//		users.setName(users.getName());
//		users.setEmail(users.getEmail());
//		users.setPassword(users.getPassword());
//		User updatedUser = this.userRepository.save(user);
//
//		return updatedUser;
//	}

// get By Id
	public User getUserById(Integer userId) {
		User user = this.userRepository.findById(userId)
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
		return user;
	}

//	public List<User> getAllUsers() {
//		List<User> users = this.userRepository.findAll();
//		return users;
//	}

	public void deleteUser(Integer userId) {
		User user = this.userRepository.findById(userId)
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

		this.userRepository.delete(user);
	}

}
