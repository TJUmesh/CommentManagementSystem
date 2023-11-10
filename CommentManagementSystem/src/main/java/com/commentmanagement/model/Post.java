package com.commentmanagement.model;

import java.util.*;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import lombok.Data;

@Entity
@Data
public class Post {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Integer postId;
	@Column(name = "post_title", length = 100, nullable = false)
	private String title;
	private String content;
	private String imageName;
	//private Date addDate;
	@ManyToOne
	@JsonBackReference
	private User user;

	@OneToMany(mappedBy = "post", cascade = CascadeType.ALL,fetch = FetchType.LAZY)
	//@JsonManagedReference
	private Set<Comment> comments = new HashSet<>();

	
}
