package com.coding.auth.mapper;

import com.coding.auth.model.BaseRole;

public interface BaseRoleMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(BaseRole record);

    int insertSelective(BaseRole record);

    BaseRole selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(BaseRole record);

    int updateByPrimaryKey(BaseRole record);
}