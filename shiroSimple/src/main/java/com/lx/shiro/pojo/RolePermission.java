package com.lx.shiro.pojo;

import javax.persistence.*;

@Table(name = "role_permission")
public class RolePermission {
    @Id
    @GeneratedValue(generator = "JDBC")
    private Long rid;

    @Id
    private Long pid;

    /**
     * @return rid
     */
    public Long getRid() {
        return rid;
    }

    /**
     * @param rid
     */
    public void setRid(Long rid) {
        this.rid = rid;
    }

    /**
     * @return pid
     */
    public Long getPid() {
        return pid;
    }

    /**
     * @param pid
     */
    public void setPid(Long pid) {
        this.pid = pid;
    }
}