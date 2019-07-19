package com.cafe24.mysite.controller.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.cafe24.config.web.TestWebConfig;
import com.cafe24.mysite.config.AppConfig;
import com.cafe24.mysite.vo.UserVo;
import com.google.gson.Gson;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes= {AppConfig.class, TestWebConfig.class})
@WebAppConfiguration
public class UserControllerTest {
	private MockMvc mockMvc;
	
	@Autowired
	private WebApplicationContext webApplicationContext;
	
	@Before	
	public void setUp() {
		mockMvc = MockMvcBuilders.
			webAppContextSetup(webApplicationContext).
			build();
	}

	@Test
	public void testUserJoin() throws Exception {
		UserVo userVo = new UserVo();
		
		//1. Normal User's Join Data
		userVo.setName("안대혁");
		userVo.setEmail("kickscar@gmail.com");
		userVo.setPassword( "kickscar#2019" );
		userVo.setGender( "NONE" );
		
		ResultActions resultActions =
		mockMvc
			.perform(post("/api/user/join")
					.contentType(MediaType.APPLICATION_JSON)
					.content(new Gson().toJson(userVo)));
	
		resultActions
		.andDo(print())
		.andExpect(status().isOk());
		
		//2. Invalidation in Name : length must be between 2 and 8
		userVo.setName("안");
		userVo.setEmail("kickscar@gmail.com");
		userVo.setPassword( "kickscar#2019" );
		userVo.setGender( "MALE" );
		
		resultActions =
		mockMvc
			.perform(post("/api/user/join")
					.contentType(MediaType.APPLICATION_JSON)
					.content(new Gson().toJson(userVo)));
	
		resultActions
		.andExpect(status().isBadRequest())
		.andDo(print())
		.andExpect(jsonPath("$.result", is("fail")));

		
		//2. Invalidation in password : 
		userVo.setName("안대혁");
		userVo.setEmail("kickscar@gmail.com");
		userVo.setPassword( "kickscar2019" );
		userVo.setGender( "MALE" );
		
		resultActions =
		mockMvc
			.perform(post("/api/user/join")
					.contentType(MediaType.APPLICATION_JSON)
					.content(new Gson().toJson(userVo)));
	
		resultActions
		.andExpect(status().isBadRequest())
		.andDo(print())
		.andExpect(jsonPath("$.result", is("fail")));

		//3. Invalidation in gender : 
		userVo.setName("안대혁");
		userVo.setEmail("kickscar@gmail.com");
		userVo.setPassword( "kickscar#2019" );
		userVo.setGender( "MAN" );
		
		resultActions =
		mockMvc
			.perform(post("/api/user/join")
					.contentType(MediaType.APPLICATION_JSON)
					.content(new Gson().toJson(userVo)));
	
		resultActions
		.andExpect(status().isBadRequest())
		.andDo(print())
		.andExpect(jsonPath("$.result", is("fail")));
	}
	
	@Test
	public void testUserLogin() throws Exception {
		UserVo userVo = new UserVo();
		
		//1. Normal User's Login Data
		userVo.setEmail("kickscar");
		userVo.setPassword( "kickscar#2019" );
		
		ResultActions resultActions =
		mockMvc
			.perform(post("/api/user/login")
					.contentType(MediaType.APPLICATION_JSON)
					.content(new Gson().toJson(userVo)));
	
		resultActions
		.andDo(print())
		.andExpect(status().isBadRequest())
		.andExpect(jsonPath("$.result", is("fail")));
	}
	
}
