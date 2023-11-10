package com.commentmanagement.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.commentmanagement.model.User;
import com.commentmanagement.payloads.ApiResponse;
import com.commentmanagement.service.impl.UserServiceImpl;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

	@Autowired
	private UserServiceImpl userServiceImpl;

	// getuserBy Id
	@GetMapping("/{userId}")
	public ResponseEntity<User> getUserById(@PathVariable Integer userId) {
		return ResponseEntity.ok(this.userServiceImpl.getUserById(userId));

	}

	// delete user
	@DeleteMapping("/{userId}")
	public ResponseEntity<ApiResponse> deleteUser(@PathVariable Integer userId) {
		this.userServiceImpl.deleteUser(userId);
		return new ResponseEntity<ApiResponse>(new ApiResponse("User Deleted SuccessFully", true), HttpStatus.OK);

	}
}
