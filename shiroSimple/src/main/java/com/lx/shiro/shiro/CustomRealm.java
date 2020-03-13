package com.lx.shiro.shiro;

import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSON;
import com.lx.shiro.bean.JWTAuthenticationToken;
import com.lx.shiro.mapper.UserMapper;
import com.lx.shiro.pojo.User;
import com.lx.shiro.util.JWTUtil;
import com.lx.shiro.util.LogVo;

import lombok.extern.slf4j.Slf4j;

/**
 * 自定义的身份和权限认证类
 * @author lx
 *
 */
@Component
@Slf4j
public class CustomRealm extends AuthorizingRealm {

	@Autowired
	private UserMapper userMapper;

	@Override
	/**
	 * 用户身份认证
	 */
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
			throws AuthenticationException {
		log.info("————身份认证方法————");
		log.info(JSON.toJSONString(authenticationToken));
		// 获取token，username，password进行校验
		JWTAuthenticationToken jwtBean = (JWTAuthenticationToken) authenticationToken;

		LogVo logVo = (LogVo) jwtBean.getCredentials();

		// 如果token为空，则表示未登录的身份校验
		if (StringUtils.isEmpty(logVo.getToken())) {
			User user = new User();
			user.setName(logVo.getUserName());
			user.setPassword(logVo.getPassWord());
			User resultUser = userMapper.selectOne(user);
			if (null == resultUser) {
				throw new AccountException("用户名或密码不正确");
			} else {
				// 登录成功
				return new SimpleAuthenticationInfo(logVo, logVo, getName());
			}
		} else {// 如果token不为空，则表示已登录，只需校验token和username是否一致
			boolean result = JWTUtil.verify(logVo.getToken(), logVo.getUserName());
			if (result) {
				// 校验成功,设置用户名
				String userName = JWTUtil.getUsername(logVo.getToken());
				logVo.setUserName(userName);
				return new SimpleAuthenticationInfo(logVo, logVo, getName());
			} else {
				throw new AccountException("请重新登录，授权码或用户名不正确");
			}
		}
	}

	/**
	 * 用户权限认证
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		log.info("————权限认证————");
		// 根据用户名查出用户所有角色和权限
		String userName = "";
		
		LogVo logVo = (LogVo) SecurityUtils.getSubject().getPrincipal();
		//如果token为空，首次验证
		if(StringUtils.isEmpty(logVo.getToken())) {
			userName = logVo.getUserName();
		}else {//否则从token解密出username
			userName = JWTUtil.getUsername(logVo.getToken());
		}
		
		Set<String> perMissionSet = userMapper.getPermission(userName);
		Set<String> roleSet = userMapper.getRole(userName);
		// 返回查询出的权限信息
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.setRoles(roleSet);
		info.setStringPermissions(perMissionSet);
		return info;
	}
	
	@Override
	public boolean supports(AuthenticationToken token) {
		return token instanceof JWTAuthenticationToken;
	}

}
