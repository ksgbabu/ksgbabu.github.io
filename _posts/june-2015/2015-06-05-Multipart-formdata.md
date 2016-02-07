---
layout: post
---

I had a chance to work on multipart-formdata with some params and files mixed.  Initially we thought it is not easy to pass the parameters and files together.  But finally I figured out there is a way.  

The content type "application/x-www-form-urlencoded" is inefficient for sending large quantities of binary data or text containing non ASCII characters.  The content-type "multipart/form-data" should be used for submitting forms that contain files, non-ascii data, and binary data.

A multipart/formdata message contains a series of parts, each representing a successful control.  Each part has an optional content-type header that defaults to text/plain.  Each part is expected to contain:
1. A "Content-Disposition" header whose values is "form-data"
2. a name attribute specifying the control name of the corresponding control.  

Thus for example, for a control named "mycontrol", the corresponding part would be specified:
Content-Disposition: form-data; name="mycontrol"

If the user enters "Larry" in the text input, and selects the text file "file1.txt", the user agent might send back the following data:

    Content-Type: multipart/form-data; boundary=AaB03x

    --AaB03x
    Content-Disposition: form-data; name="submit-name"

    Larry
    --AaB03x
    Content-Disposition: form-data; name="files"; filename="file1.txt"
    Content-Type: text/plain
 
    ... contents of file1.txt ...
    --AaB03x--
	
	