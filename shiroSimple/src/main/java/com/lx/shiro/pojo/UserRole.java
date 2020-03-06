package com.lx.shiro.pojo;

import javax.persistence.*;

@Table(name = "user_role")
public class UserRole {
    @Id
    @GeneratedValue(generator = "JDBC")
    private Long uid;

    @Id
    private Long rid;

    /**
     * @return uid
     */
    public Long getUid() {
        return uid;
    }

    /**
     * @param uid
     */
    public void setUid(Long uid) {
        this.uid = uid;
    }

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
}