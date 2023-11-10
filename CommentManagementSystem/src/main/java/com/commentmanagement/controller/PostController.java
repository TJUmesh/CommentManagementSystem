package com.commentmanagement.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.commentmanagement.model.Post;
import com.commentmanagement.payloads.ApiResponse;
import com.commentmanagement.service.impl.FileServiceimpl;
import com.commentmanagement.service.impl.PostServiceimpl;

@RestController
@RequestMapping("/api/posts")
public class PostController {

	@Autowired
	private PostServiceimpl postServiceimpl;

	@Autowired
	private FileServiceimpl fileServiceimpl;

	@Value("${project.image}")
	private String path;

	@PostMapping("{userId}/")
	public ResponseEntity<Post> createPost(@RequestBody Post post, @PathVariable Integer userId)

	{
		Post createdPost = this.postServiceimpl.createPost(post, userId);
		return new ResponseEntity<Post>(createdPost, HttpStatus.CREATED);

	}

	// Get By User
	@GetMapping("/user/{userId}/posts")
	public ResponseEntity<List<Post>> getPostsByUser(@PathVariable Integer userId) {

		List<Post> posts = this.postServiceimpl.getPostByUser(userId);
		return new ResponseEntity<List<Post>>(posts, HttpStatus.OK);

	}

//	// get All Post
//	@GetMapping("/")
//	public ResponseEntity<List<Post>> getAllPost() {
//		List<Post> allPost = this.postServiceimpl.getAllPost();
//		return new ResponseEntity<List<Post>>(allPost, HttpStatus.OK);
//	}

	// get Posts By PostId
	@GetMapping("/{postId}")
	public ResponseEntity<Post> getPostById(@PathVariable Integer postId) {
		Post postById = this.postServiceimpl.getPostById(postId);
		return new ResponseEntity<Post>(postById, HttpStatus.OK);
	}

	// update Posts
	@PutMapping("/{postId}")
	public ResponseEntity<Post> updatePosts(@RequestBody Post post, @PathVariable Integer postId) {
		Post updatePost = this.postServiceimpl.updatePost(post, postId);
		return new ResponseEntity<Post>(updatePost, HttpStatus.OK);

	}

	// delete Post
	@DeleteMapping("/{postId}")
	public ApiResponse deletePost(@PathVariable Integer postId) {
		this.postServiceimpl.deletePost(postId);
		return new ApiResponse("Post is Successfully deleted !!", true);
	}

	// Post Image upload

	@PostMapping("/image/upload/{postId}")
	public ResponseEntity<Post> uploadPostImage(@RequestParam("image") MultipartFile image,
			@PathVariable Integer postId) throws IOException {
		Post posts = this.postServiceimpl.getPostById(postId);
		String fileName = this.fileServiceimpl.uploadImage(path, image);
		posts.setImageName(fileName);
		Post updatePost = this.postServiceimpl.updatePost(posts, postId);
		return new ResponseEntity<Post>(updatePost, HttpStatus.OK);
	}

}
