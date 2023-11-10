package com.commentmanagement.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.commentmanagement.exceptions.ResourceNotFoundException;
import com.commentmanagement.model.Comment;
import com.commentmanagement.model.Post;
import com.commentmanagement.repository.CommentRepository;
import com.commentmanagement.repository.PostRepository;

@Service
public class CommentServiceimpl {

	@Autowired
	private CommentRepository commentRepository;
	@Autowired
	private PostRepository postRepository;

	public Comment createComment(Comment comment, Integer postId) {

		Post postById = this.postRepository.findById(postId)
				.orElseThrow(() -> new ResourceNotFoundException("Post", "post Id", postId));

		comment.setPost(postById);
		Comment savedComment = this.commentRepository.save(comment);
		return savedComment;

	}

	public void deleteComment(Integer commentId) {
		Comment com = this.commentRepository.findById(commentId)
				.orElseThrow(() -> new ResourceNotFoundException("Comment", "comment Id", commentId));
		this.commentRepository.delete(com);

	}

	public Comment updateComment(Comment comment, Integer commentId) {

		Post postById = this.postRepository.findById(commentId)
				.orElseThrow(() -> new ResourceNotFoundException("Post", "post Id", commentId));

		postById.setContent(comment.getContent());
		Comment savedComment = this.commentRepository.save(comment);
		return savedComment;

	}

}
