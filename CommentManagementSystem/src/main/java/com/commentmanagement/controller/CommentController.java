package com.commentmanagement.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.commentmanagement.model.Comment;
import com.commentmanagement.payloads.ApiResponse;
import com.commentmanagement.service.impl.CommentServiceimpl;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/comments")
public class CommentController {

	@Autowired
	private CommentServiceimpl commentServiceimpl;

	@PostMapping("/{postId}")
	public ResponseEntity<Comment> createComment(@Valid @RequestBody Comment comment, @PathVariable Integer postId) {

		Comment createComment = this.commentServiceimpl.createComment(comment, postId);

		return new ResponseEntity<Comment>(createComment, HttpStatus.CREATED);
	}

	@DeleteMapping("/{commentId}")
	public ResponseEntity<ApiResponse> deleteComment(@PathVariable Integer commentId) {
		this.commentServiceimpl.deleteComment(commentId);
		return new ResponseEntity<ApiResponse>(new ApiResponse("Deleted Successfully !! ", true), HttpStatus.OK);
	}

	@PutMapping("/{commentId}")
	public ResponseEntity<Comment> updateComment(@Valid @RequestBody Comment comment, @PathVariable Integer commentId) {

		Comment createComment = this.commentServiceimpl.updateComment(comment, commentId);

		return new ResponseEntity<Comment>(createComment, HttpStatus.OK);
	}

}
