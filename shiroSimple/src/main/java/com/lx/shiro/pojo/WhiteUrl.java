package com.lx.shiro.pojo;

import javax.persistence.*;

@Table(name = "white_url")
public class WhiteUrl {
    @Id
    @GeneratedValue(generator = "JDBC")
    private Integer id;

    private String url;

    /**
     * @return id
     */
    public Integer getId() {
        return id;
    }

    /**
     * @param id
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * @return url
     */
    public String getUrl() {
        return url;
    }

    /**
     * @param url
     */
    public void setUrl(String url) {
        this.url = url;
    }
}