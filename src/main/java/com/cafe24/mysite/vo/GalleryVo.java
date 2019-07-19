package com.cafe24.mysite.vo;

public class GalleryVo {
	private Long no;
	private String comment;
	private String imageURL;
	
	public Long getNo() {
		return no;
	}
	public void setNo(Long no) {
		this.no = no;
	}
	public String getComment() {
		return comment;
	}
	public void setComment(String comment) {
		this.comment = comment;
	}
	public String getImageURL() {
		return imageURL;
	}
	public void setImageURL(String imageURL) {
		this.imageURL = imageURL;
	}
	
	@Override
	public String toString() {
		return "GalleryVo [no=" + no + ", comment=" + comment + ", imageURL=" + imageURL + "]";
	}
}
