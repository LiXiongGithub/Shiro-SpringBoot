package com.lx.shiro.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lx.shiro.mapper.UserMapper;
import com.lx.shiro.pojo.User;

import java.util.HashSet;
import java.util.Set;

/**
 * Created with IntelliJ IDEA
 *
 * @Author yuanhaoyue swithaoy@gmail.com
 * @Description 自定义 Realm
 * @Date 2018-03-25
 * @Time 21:46
 */
@Component
public class CustomRealm extends AuthorizingRealm {
	
	@Autowired
	private UserMapper userMapper;

	/**
	 * 用户权限认证
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		System.out.println("————权限认证————");
		String username = (String) SecurityUtils.getSubject().getPrincipal();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 获得该用户角色
		Set<String> role = userMapper.getRole(username);
		// 设置该用户拥有的角色
		info.setRoles(role);
		// 设置该角色所拥有的的权限
		// Set<String> permissionSet = new HashSet<>();
		// permissionSet = userMapper.getPermission(username);
		// info.setStringPermissions(permissionSet);

		return info;
	}

	
	@Override
	/**
	 *用户身份认证
	 */
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
		System.out.println("————身份认证方法————");
		UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
		// 从数据库获取对应用户名密码的用户
		User user = new User();
		user.setName(token.getUsername());
		User result = userMapper.selectOne(user);
		String password = result.getPassword();
		if (null == password) {
			throw new AccountException("用户名不正确");
		} else if (!password.equals(new String((char[]) token.getCredentials()))) {
			throw new AccountException("密码不正确");
		}
		return new SimpleAuthenticationInfo(token.getPrincipal(), password, getName());
	}}
