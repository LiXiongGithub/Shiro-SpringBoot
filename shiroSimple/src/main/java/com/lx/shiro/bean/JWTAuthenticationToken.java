package com.lx.shiro.bean;

import org.apache.shiro.authc.AuthenticationToken;

import com.lx.shiro.util.LogVo;

/**
 * 自定义验证对象 用来存储用户名和jwt密文
 * 
 * @author Administrator
 *
 */
public class JWTAuthenticationToken implements AuthenticationToken {

	private static final long serialVersionUID = -1765686192037750369L;
	

	private LogVo logVo;
	

	public void setLogVo(LogVo logVo) {
		this.logVo = logVo;
	}

	@Override
	public Object getPrincipal() {
		return this.logVo;
	}

	@Override
	public Object getCredentials() {
		return this.logVo;
	}

}
