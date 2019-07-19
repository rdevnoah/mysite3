<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%> 
<%@ page contentType="text/html;charset=UTF-8" %>
<!DOCTYPE html>
<html>
<head>
<title>mysite</title>
<meta http-equiv="content-type" content="text/html; charset=utf-8">
<link rel="stylesheet" href="${pageContext.request.contextPath }/assets/css/guestbook-spa.css" rel="stylesheet" type="text/css">
<link rel="stylesheet" href="//code.jquery.com/ui/1.12.1/themes/base/jquery-ui.css">
<style type="text/css">
.ui-dialog .ui-dialog-buttonpane .ui-dialog-buttonset{
	float: none;
	text-align:center
}
.ui-dialog .ui-dialog-buttonpane button {
	margin-left:10px;
	margin-right:auto;
}

#dialog-message p {
	padding:20px 0;
	font-weight:bold;
	font-size:1.0em;
}

#dialog-delete-form p {
	padding:10px;
	font-weight:bold;
	font-size:1.0em; 
}

#dialog-delete-form p.error {
	color: #f00;
}

#dialog-delete-form input[type="password"] {
	padding:5px;
	border:1px solid #888;
	outline: none;
	width: 180px;
}

</style>
<script type="text/javascript" src="${pageContext.request.contextPath }/assets/js/jquery/jquery-1.9.0.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath }/assets/js/ejs/ejs.js"></script>
<script src="https://code.jquery.com/ui/1.12.1/jquery-ui.js"></script>
<script>
var emptyFunction = function(){};
// jQuery PlugIn
(function($){
	$.fn.flash = function(){
		$(this).click(function(){
			var isBlink = false;
			var $that = $(this);
			setInterval(function(){
				$that.css("backgroundColor", isBlink ? "#f00" : "#aaa");
				isBlink = !isBlink;
			}, 1000);
		})
	}
})(jQuery);

///////////////////////////////
var messageBox = function( title, message, callback ) {
	$("#dialog-message").attr('title', title);
	$("#dialog-message p").text(message)
	$("#dialog-message").dialog({
		modal: true,
		buttons: {
			"확인": function(){
				$(this).dialog('close');
			}
		},
		close: function(){
			//....
			//....
			//....
			(callback || emptyFunction)();
		}
	});
}

// import ejs template
var listItemTemplate = new EJS({
	url: '${pageContext.request.contextPath }/assets/js/ejs-templates/guestbook-list-item.ejs'
});
var listTemplate = new EJS({
	url: '${pageContext.request.contextPath }/assets/js/ejs-templates/guestbook-list.ejs'
});

var isEnd = false;
var fetchList = function(){
	if(isEnd){
		return;
	}
	
	var lastNo = $('#list-guestbook li').last().data('no') || 0;
	$.ajax({
		url: "${pageContext.request.contextPath }/api/guestbook/list/" + lastNo,
		type: "get",
		//contentType: "application/json" //post 방식으로  JSON Type으로 데이터를 보낼 때
		dataType: "json",
		data: "",
		success: function(response){
			if(response.result != "success"){
				console.error(reponse.message);
				return;
			}
			
			// detect end
			if(response.data.length == 0){
				isEnd = true;
				$("#btn-next").prop("disabled", true);
				return;
			}					
			
			// rendering
			var html = listTemplate.render(response);
			$("#list-guestbook").append(html);
		},
		error: function(jqXHR, status, e){
			console.error(status + ":" + e);
		}
	});
}

$(function(){
	
	var dialogDelete = $( "#dialog-delete-form" ).dialog({
		autoOpen: false,
        height: 170,
        width: 300,
        modal: true,
        buttons: {
			"삭제": function(){
				var vo = {
					no: $("#hidden-no").val(),
					password: $("#password-delete").val()
				}
				
				$.ajax({
					url: "${pageContext.request.contextPath }/api/guestbook",
					type: "delete",
					//contentType: "application/json", //post 방식으로  JSON Type으로 데이터를 보낼 때
					dataType: "json",
					data: "passwodord=" + $("#password-delete").val(),
					success: function(response){
						if(response.result != "success"){
							console.error(response.message);
							return;
						}
						
						//li 엘리멘트 삭제
						$("#list-guestbook li[data-no='" + response.data + "']").remove();
						dialogDelete.dialog('close');
					},
					error: function(jqXHR, status, e){
						console.error(status + ":" + e);
					}
				});
			},
			"취소": function() {
				dialogDelete.dialog("close");
			}
		},
		close: function() {
			$("#password-delete").val("");
			$("#hidden-no").val("");
        }
	});	
	
	$(window).scroll(function(){
		var $window = $(this);
		var scrollTop = $window.scrollTop();
		var windowHeight = $window.height();
		var documentHeight = $(document).height();
		if( scrollTop + windowHeight + 10 > documentHeight ){
			fetchList();
		}
	});
	
	$("#add-form").submit(function(event){
		// submit event 기본 동작을 막음
		// posting을 막음
		event.preventDefault();
		
		var vo = {};
		
		// validation (clinet side, UX, jQuery Validation Plug-in)
		vo.name = $("#input-name").val();
		if(vo.name == ''){
			messageBox('글남기기', '이름은 필수 입력 항목입니다.', function(){
				$('#input-name').focus();
			});
			return;
		}		
		vo.password = $("#input-password").val();
		if(vo.password == ''){
			messageBox('글남기기', '비밀번호는 필수 입력 항목입니다.', function(){
				$('#input-password').focus();
			});
			return;
		}		
		vo.contents = $("#tx-content").val();
		if(vo.contents == ''){
			messageBox('글남기기', '내용은 필수 입력 항목입니다.');
			return;
		}		
		
		//console.log( $.param(vo) );
		//console.log( JSON.stringify(vo) );
		
		$.ajax({
			url: "${pageContext.request.contextPath }/api/guestbook/add",
			type: "post",
			contentType: "application/json", //post 방식으로  JSON Type으로 데이터를 보낼 때
			dataType: "json",
			data: JSON.stringify(vo),
			success: function(response){
				if(response.result != "success"){
					console.error(reponse.message);
					return;
				}
				
				//rendering
				var html = listItemTemplate.render(response.data);
				$("#list-guestbook").prepend(html);
				
				// reset form
				$("#add-form")[0].reset();
			},
			error: function(jqXHR, status, e){
				console.error(status + ":" + e);
			}
		});
	})
	
	// Live Event => delegation(위임) 방식
	$(document).on('click', '#guestbook ul li a', function(event){
		event.preventDefault();

		$("#hidden-no").val($(this).data('no'));
		dialogDelete.dialog('open');
	});
	
	// 최초 리스트 가져오기
	fetchList();
	
	// jquery plugin test
	$("#btn-next").flash();
});
</script>
</head>
<body>
	<div id="container">
		<c:import url="/WEB-INF/views/includes/header.jsp" />
		<div id="content">
			<div id="guestbook">
				<h1>방명록</h1>
				<button id="btn-next">flash jquery plug-in</button>
				<br/>
				<form id="add-form" action="" method="post">
					<input type="text" id="input-name" placeholder="이름">
					<input type="password" id="input-password" placeholder="비밀번호">
					<textarea id="tx-content" placeholder="내용을 입력해 주세요."></textarea>
					<input type="submit" value="보내기" />
				</form>
				<ul id="list-guestbook"></ul>
			</div>
			<div id="dialog-delete-form" title="메세지 삭제" style="display:none">
  				<p class="validateTips normal">작성시 입력했던 비밀번호를 입력하세요.</p>
  				<p class="validateTips error" style="display:none">비밀번호가 틀립니다.</p>
  				<form>
 					<input type="password" id="password-delete" value="" class="text ui-widget-content ui-corner-all">
					<input type="hidden" id="hidden-no" value="">
					<input type="submit" tabindex="-1" style="position:absolute; top:-1000px">
  				</form>
			</div>
			<div id="dialog-message" title="" style="display:none">
  				<p></p>
			</div>						
		</div>
		<c:import url="/WEB-INF/views/includes/navigation.jsp">
			<c:param name="menu" value="guestbook-ajax"/>
		</c:import>
		<c:import url="/WEB-INF/views/includes/footer.jsp" />
	</div>
</body>
</html>