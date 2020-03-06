package com.lx.shiro.mapper;

import java.util.Set;

import com.lx.shiro.pojo.User;
import com.lx.shiro.util.MyMapper;

public interface UserMapper extends MyMapper<User> {
	Set<String> getRole (String userName);
}