rule andresriancho_cc_lambda {   
   	meta:   
   		description = "Conversion into Yara-X of search strings found in https://github.com/andresriancho/cc-lambda/blob/master/cc-lambda.py. Code license is not known."
   	strings:   
   		$s1 = "IdentityPoolId"
        $s2 = "AWS.CognitoIdentityCredentials("
        $s3 = "AWS.WebIdentityCredentials("
        $s4 = "assumeRoleWithWebIdentity"
        $s5 = "sdk.amazonaws.com/js/aws-sdk"
        $s6 = "AWS.config.update"
        $s7 = "from 'aws-amplify';"
        $s8 = "require('aws-sdk');"
        $s9 = "License at https://sdk.amazonaws.com/js/BUNDLE_LICENSE.txt"

   	condition:   
   		1 of them
    }

rule aws_keys {   
   	meta:   
   		description = "AWS keys"
   	strings:   
   		$s1 = "aws_access_key_id"
        $s2 = "AWS_ACCOUNT_ID="
        $s3 = "AWS_SECRET_ACCESS_KEY="

   	condition:   
   		1 of them
    }

rule tinyfilemanager {   
   	meta:   
   		description = "Detect https://github.com/prasathmani/tinyfilemanager"
   	strings:   
   		$s1 = ">CCP Programmers</a> &mdash;&mdash;"
        $s2 = "aria-label=\"H3K Tiny File Manager\">"
        $s3 = "content=\"Web based File Manager in PHP, Manage your files efficiently and easily with Tiny File Manager\">"
        $s4 = "<title>Tiny File Manager</title>"
        $html_1 = "#/select-all"
        $html_2 = "#/unselect-all"
        $html_3 = "#/invert-all"
        $html_4 = "a-delete"
        $html_5 = "a-zip"
        $html_6 = "a-tar"
        $html_7 = "a-copy"
   	condition:   
   		1 of ($s*) or all of ($html_*) 
    }

rule fake_404_login {   
   	meta:   
   		description = "Detect https://github.com/sagsooz/Webshell-bypass/blob/main/jquery.php"
   	strings:   
   		$s1 = "<title>404 Not Found</title>"
		$s2 = "<input type=\"password\" name=\"password\""
 	condition:   
   		all of them 
    }

rule adminer {   
   	meta:   
   		description = "Detect https://www.adminer.org/en/"
   	strings:   
   		$s1 = "<title>Select database - Adminer</title>"
        $html_1 = ">Create database<"
        $html_2 = ">Privileges<"
        $html_3 = ">Process list<"
        $html_4 = ">Variables<"
        $html_5 = ">Status<"
		$html_6 = ">SQL command<"
   	condition:   
   		1 of ($s*) or all of ($html_*) 
    }  
