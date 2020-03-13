package com.lx.shiro.util;

import lombok.Data;

@Data
public class LogVo {
	private String token;
	private String userName;
	private String passWord;
	private String role;
}
