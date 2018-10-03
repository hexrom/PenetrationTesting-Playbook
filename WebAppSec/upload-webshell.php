<?php
if(isset($_POST["submit"])) {
$name = $_FILES['file_upload']['name']; // Check for errors
       if($_FILES['file_upload']['error'] > 0)  die('An error ocurred');
// Upload file if(!move_uploaded_file($_FILES['file_upload']['tmp_name'],$name))
die('Error uploading');
       die('File uploaded successfully.');
}?>
<form method='post' enctype='multipart/form-data'>
File: <input type='file' name='file_upload'>
<input type="submit" value="Upload Image" name="submit">
</form>
