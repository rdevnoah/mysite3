package com.cafe24.mysite.vo;

import javax.validation.constraints.Pattern;

import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;

import com.cafe24.mysite.validator.constraints.ValidGender;

public class UserVo {
	private Long no;

	@NotEmpty
	@Length(min=2, max=8)
	private String name;

	@Email
	@NotEmpty
	private String email;
	
	@Pattern(regexp="(?=.*[A-Za-z])(?=.*\\d)(?=.*[$@$!%*#?&])[A-Za-z\\d$@$!%*#?&]{8,20}", message="비밀번호는 8자 이상 20자 이하의 알파벳, 숫자, 특수문자를 조합하여 작성해야 합니다.") 
	@Length(min=8, max=20, message="비밀번호는 8자 이상 20자 이하로 입력해야 합니다.")
	private String password;		// 비밀번호

	@ValidGender
	private String gender;

	private String role = "ROLE_USER";
	
	private String joinDate;
	
	public UserVo() {}
	
	public  UserVo(String email, String password) {
		this.email = email;
		this.password = password;
	}
	
	public Long getNo() {
		return no;
	}
	public void setNo(Long no) {
		this.no = no;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getGender() {
		return gender;
	}
	public void setGender(String gender) {
		this.gender = gender;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	public String getJoinDate() {
		return joinDate;
	}
	public void setJoinDate(String joinDate) {
		this.joinDate = joinDate;
	}
	@Override
	public String toString() {
		return "UserVo [no=" + no + ", name=" + name + ", email=" + email + ", password=" + password + ", gender="
				+ gender + ", joinDate=" + joinDate + "]";
	}
}
