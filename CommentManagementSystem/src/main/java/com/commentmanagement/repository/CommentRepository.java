package com.commentmanagement.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.commentmanagement.model.Comment;

public interface CommentRepository extends JpaRepository<Comment, Integer> {

}
