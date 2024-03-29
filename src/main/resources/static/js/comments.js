var userId = null; //ToDo реализовать получение id из сессии
var userName = null;
var commentsGraphs = new Map();
var replyParent = 0;
var editContent = "";
var editFooter = "";
var editing = false;
const showCommentsMap = new Map();

$(function () {
    init();

    function getCookie(name) {
        let match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
        if (match) {
            return match[2];
        } else {
            console.log('--something went wrong---');
        }
    }

    function init() {
        userId = getCookie("user_id");
        userName = getCookie("user_name");
    }

    function showCommentHead(postId) {
        document.getElementById('root_comments_' + postId).innerHTML += '<div class=\"form-group\"> ' +
            '<textarea name = \"post_content_' + postId + '\" id = \"post_content_' + postId + '\" class = \"form-control auto-size\" rows = \"5\" placeholder=\"Введите комментарий\"></textarea></div>' +
            '<div class=\"form-group\">' +
            '<input type=\"hidden\" id = \"main_reply_' + postId + '\" value=\"' + postId + '\"/>' +
            '<input type=\"submit\" name = \"submit\" id = \"' + postId + '\" class = \"btn btn-info submit\" value=\"Отправить\"/></div>';
    }

    $(document).on("click", ".showComments", function (event) {
        event.preventDefault();
        let postId = $(this).attr("id");
        if (showCommentsMap.get(postId) == null || showCommentsMap.get(postId) === false) {
            showCommentsMap.set(postId, true);
            showCommentHead(postId);
            ajaxWrapper("/comments/getComments", "GET", {post_id: postId}, function (data) {
                commentsGraphs.set(parseInt(postId), data);
                showComments(data[0], "", 'root_comments_' + postId);
                $('.auto-size').each(function () {
                    autoSize(this);
                }).on('input', function () {
                    autoSize(this);
                });
            });
        }
    });

    $(document).on("click", ".submit", function (event) {
        event.preventDefault();
        let postId = $(this).attr('id');
        let content = $("#post_content_" + postId).val();
        ajaxWrapper("/comments/addComment", "POST", {post_id: postId, content: content, parent_id: 0},
            function (data) {
                if (data.success) {
                    let commentId = data.message;
                    let mainBlock = '<div class = \"panel panel-default\" id = \"comment_' + commentId + '\">' +
                        '<div class = \"panel-heading\" id = \"user_' + commentId + '\" name = \"' + userName + '\">' + userName + '<button type=\"button\" class=\"btn btn-link edit\" id = \"' + commentId + '\">Редактировать</button><button type=\"button\" class=\"btn btn-link delete\" id = \"' + commentId + '\">Удалить</button></div>' +
                        '<div class = \"panel-body\" id = \"comment_content_' + commentId + '\">' + content + '</div>' +
                        '<div class = \"panel-footer\" align=\"right\" id = \"comment_footer_' + commentId + '\">' +
                        '<button type=\"button\" class = \"btn btn-default reply\" name = \"' + commentId + '\" id = \"' + commentId + '\">Ответить</button>' +
                        '</div><div id=\"replies_list_' + commentId + '\"></div><br/>' +
                        '<br/><form class=\"form-horizontal\"><div class=\"form-group\">' +
                        '<input type=\"hidden\" name=\"' + postId + '\" id=\"reply_' + commentId + '\" value=\"' + commentId + '\"/>' +
                        '<textarea class=\"col-xs-10 auto-size\" name =\"comment_content\" id = \"reply_text_area_' + commentId + '\" rows=\"2\" style=\"margin-left: 48px\"></textarea>' +
                        '<button type=\"button\" class=\"btn btn-default submit2\" id = \"' + commentId + '\">Отправить</button>' +
                        '</div></form><br/>';
                    commentsGraphs.set(commentId, {});
                    document.getElementById('root_comments_' + postId).innerHTML += mainBlock;
                } else {
                    alert(data.message);
                }
            });
    });

    $(document).on("click", ".reply", function () {
        let parentId = $(this).attr("id");
        let commentId = $(this).attr("name");
        let userName = $("#user_" + commentId).attr("name");
        $("#reply_text_area_" + parentId).val(userName + ", ");
        if (parentId === 0) {
            parentId = commentId;
        }
        $("#reply_" + parentId).val(commentId);
    });

    $(document).on("click", ".delete", function () {
        event.preventDefault();
        let commentId = $(this).attr("id");
        ajaxWrapper("/comments/deleteComment", "DELETE", {comment_id: commentId},
            function (data) {
                $("#comment_" + commentId).html("Комментарий удален :3");
            });
    });

    $(document).on("click", ".edit", function () {
        let commentId = $(this).attr("id");
        if (!editing) {
            editing = true;
            editContent = $("#comment_content_" + commentId).clone();
            editFooter = $("#comment_footer_" + commentId).clone();
            $("#comment_content_" + commentId + "").html("<textarea class=\"form-control\" id = \"editText\" rows=\"1\"></textarea>");
            let footEdit = '<button type=\"button\" class = \"btn btn-default saveEdit\" id = \"' + commentId + '\">Сохранить</button>' +
                '<button type=\"button\" class = \"btn btn-default cancel\" id = \"' + commentId + '\">Отменить</button>';
            $("#comment_footer_" + commentId).html(footEdit);
        }
    });

    $(document).on("click", ".saveEdit", function () {
        let commentId = $(this).attr("id");
        let newContent = $("#editText").val();
        if (editContent.text() === newContent || newContent === "") {
            $("#comment_content_" + commentId).replaceWith(editContent);
            $("#comment_footer_" + commentId).replaceWith(editFooter);
        } else {
            ajaxWrapper("/comments/editComment", "POST", {id: commentId, content: newContent}, function (data) {
                if (data.success) {
                    $("#comment_content_" + commentId).html(data.message);
                    $("#comment_footer_" + commentId).replaceWith(editFooter);
                } else {
                    alert(data.message);
                }
            });
        }
        editing = false;
    });

    $(document).on("click", ".cancel", function () {
        var commentId = $(this).attr("id");
        $("#comment_content_" + commentId).replaceWith(editContent);
        $("#comment_footer_" + commentId).replaceWith(editFooter);
        editing = false;
    });

    $(document).on("click", ".submit2", function () {
        event.preventDefault();
        let commentId = $(this).attr("id");
        let content = $("#reply_text_area_" + commentId).val();
        let parentId = $("#reply_" + commentId).val();
        let postId = parseInt($("#reply_" + commentId).attr('name'));
        ajaxWrapper("/comments/addComment", "POST", {post_id: postId, content: content, parent_id: parentId},
            function (data) {
                if (data.success) {
                    var comment = {
                        id: data.message,
                        userName: userName,
                        userId: userId,
                        parent: parentId,
                        content: content,
                        deleted: 0
                    };
                    let containerName = "replies_list_" + comment.parent;
                    replyParent = commentId;
                    displayComment(comment, "", containerName);
                    if (commentsGraphs.get(postId)[parentId] == null) {
                        document.getElementById("comment_" + parentId).innerHTML += '<button type=\"button\" class=\"btn btn-info\" data-toggle=\"collapse\" data-target=\"#replies_list_' + parentId + '\">Ответы</button>';
                        (commentsGraphs.get(postId))[parentId] = {};
                    }
                } else {
                    alert(data.message);
                }
            });
    });
});

function displayComment(comment, parentName, containerName) {
    let marginLeft = 0;
    let headingText = comment.userName;
    //let replyButton = comment.id;
    if (comment.parent != 0) {
        marginLeft = 48;
        headingText += " ответил " + parentName;
        //replyButton = $("."+comment.parent).attr("id");
        //document.getElementsByName(comment.parent);
    }
    let headRight = '';
    if (comment.userId == userId) {
        headRight = '<button type=\"button\" class=\"btn btn-link edit\" id = \"' + comment.id + '\">Редактировать</button>' +
            '<button type=\"button\" class=\"btn btn-link delete\" id = \"' + comment.id + '\">Удалить</button>';
    }
    document.getElementById(containerName).innerHTML += '<div class = \"panel border border-secondary-rounded' +
        ' panel-default\" id =' +
        ' \"comment_' + comment.id + '\" style=\"margin-left: ' + marginLeft + 'px\">' +
        '<div class = \"panel-heading\" id = \"user_' + comment.id + '\" name = \"' + comment.userName + '\">' + headingText + '' + headRight +
        '</div>' +
        '<div class = \"panel-body\" id = \"comment_content_' + comment.id + '\">' + comment.content + '</div>' +
        '<div class = \"panel-footer\" align=\"right\" id = \"comment_footer_' + comment.id + '\">' +
        '<button type=\"button\" class = \"btn btn-outline-dark reply\" name = \"' + comment.id + '\" id = \"' + replyParent + '\">Ответить</button>' +
        '</div><div id=\"replies_list_' + comment.id + '\" class = \"collapse\"></div></div>';
}

function displayDeletedComment(comment, container) {
    let marginLeft = 0;
    if (comment.parent !== 0) {
        marginLeft = 48;
    }
    let mainBlock = '<div class = \"panel border border-secondary rounded panel-default\" style=\"margin-left: ' + marginLeft + 'px\">' +
        '<div class = \"panel-body\" id = \"comment_content_' + comment.id + '\">Комментарий удален</div>' +
        '</div><div id=\"replies_list_' + comment.id + '\" class = \"collapse\"></div>';
    container.innerHTML += mainBlock;
}

function autoSize(element) {
    $element = $(element);
    element.style.overflowY = 'hidden';
    var paddingTopBottom = $element.innerHeight() - $element.height();
    element.style.height = 'auto';

    $element.height(element.scrollHeight - paddingTopBottom);
}

function showComments(data, parentName, containerName) {
    for (let i in data) {
        let container = document.getElementById(containerName);
        let comment = data[i];
        let postId = comment.postId;
        if (comment.parent == 0) {
            replyParent = comment.id;
        }
        if (comment.deleted == 0) {
            displayComment(comment, parentName, containerName);
        } else {
            if ((commentsGraphs.get(postId))[comment.id] != null) {
                displayDeletedComment(comment, container);
            }
        }
        if ((commentsGraphs.get(postId))[comment.id] != null) {
            container.innerHTML += '<button type=\"button\" class=\"btn btn-outline-dark\" data-toggle=\"collapse\"' +
                ' data-target=\"#replies_list_' + comment.id + '\">Ответы</button>';
            showComments(commentsGraphs.get(postId)[comment.id], comment.userName, "replies_list_" + comment.id);
        }

        if (comment.parent === 0) {
            container.innerHTML += '<br/><form class=\"form-horizontal mt-1\"><div class=\"form-group border' +
                ' border-secondary-rounded\">' +
                '<input type=\"hidden\" name=\"' + comment.postId + '\" id=\"reply_' + comment.id + '\" value=\"' + comment.id + '\"/>' +
                '<textarea class=\"col-xs-10 auto-size\" name =\"comment_content\" id = \"reply_text_area_' + comment.id + '\" rows=\"2\" style=\"margin-left: 48px\"></textarea>' +
                '<button type=\"button\" class=\"btn btn-outline-primary submit2\" id = \"' + comment.id + '\">Отправить</button>' +
                '</div></form><br/>';
        }
    }
}