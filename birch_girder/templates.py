from string import Template

ISSUE_TEMPLATE = Template('''<!--
$hidden_content_block
-->
| `$from_address` | 
| ----- | 

$body

$attachment_table
---

Note : To trigger sending an email comment back to `$reply_to` include
@$github_username in your comment.
<!--
$headers
-->''')
COMMENT_TEMPLATE = Template('''| `$from_address` | 
| ----- | 

$body

$comment_attachments
<!--
$headers
-->''')

SUBJECT_TEMPLATE = Template('$subject (#$issue_number)')
EMAIL_TEXT_TEMPLATE = Template('''##- Please type your reply above this line -##
$text_body

--------------------------------
This email is a service from $provider.









$issue_reference
''')
EMAIL_HTML_TEMPLATE = Template(
    '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html>
    <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
      <style type="text/css">
        table td {
          border-collapse: collapse;
        }
        body[dir=rtl] .directional_text_wrapper { direction: rtl; unicode-bidi: embed; }

      </style>
    </head>
    <body  style="width: 100%!important; margin: 0; padding: 0;">
      <div style="padding: 10px ; line-height: 18px; font-family: 'Lucida Grande',Verdana,Arial,sans-serif; font-size: 12px; color:#444444;">
        <div style="color: #b5b5b5;">##- Please type your reply above this line -##</div>
         $html_body
        <div style="color: #aaaaaa; margin: 10px 0 14px 0; padding-top: 10px; border-top: 1px solid #eeeeee;">
         This email is a service from $provider.
        </div>
      </div>
    <span style="color:#FFFFFF">$issue_reference</span></body>
    </html>''')