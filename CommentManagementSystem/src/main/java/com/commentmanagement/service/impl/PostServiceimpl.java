package com.commentmanagement.service.impl;

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.config.ConfigDataResourceNotFoundException;
import org.springframework.stereotype.Service;

import com.commentmanagement.exceptions.ResourceNotFoundException;
import com.commentmanagement.model.Post;
import com.commentmanagement.model.User;
import com.commentmanagement.repository.PostRepository;
import com.commentmanagement.repository.UserRepository;

@Service
public class PostServiceimpl {

	@Autowired
	private PostRepository postRepository;

	@Autowired
	private UserRepository userRepository;

	// Create Post
	public Post createPost(Post post, Integer userId) {
		User user = this.userRepository.findById(userId)
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));

	//	post.setAddDate(new Date());
		post.setImageName("default.png");
		post.setUser(user);
		Post p = this.postRepository.save(post);
		return p;
	}

	// get All Post By User
	public List<Post> getPostByUser(Integer userId) {
		User user = this.userRepository.findById(userId)
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", userId));
		List<Post> posts = this.postRepository.findByUser(user);
		return posts;
	}

	// Get All Posts
	public List<Post> getAllPost() {
		List<Post> allPosts = this.postRepository.findAll();

		return allPosts;
	}

	// get Posts By PostId
	public Post getPostById(Integer postId) {
		Post postById = this.postRepository.findById(postId)
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", postId));

		return postById;
	}

	// update Post
	public Post updatePost(Post post, Integer postId) {
		Post postById = this.postRepository.findById(postId)
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", postId));

		postById.setTitle(post.getTitle());
		postById.setContent(post.getContent());
		postById.setImageName(post.getImageName());
		Post updatedPost = this.postRepository.save(postById);
		return updatedPost;

	}

	// delete Post
	public void deletePost(Integer postId) {
		Post postById = this.postRepository.findById(postId)
				.orElseThrow(() -> new ResourceNotFoundException("User", "id", postId));
		this.postRepository.delete(postById);

	}
}
