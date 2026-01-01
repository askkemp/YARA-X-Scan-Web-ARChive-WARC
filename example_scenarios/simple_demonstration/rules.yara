rule example_askkemp_1 {   
   	meta:   
   		description = "Example - Find specific names on a page"
   	strings:   
   		$s1 = "Emily Parker"  
   		$s2 = "Michael Chen"
        $s3 = "David Rodriguez"
        $s4 = "James Wilson"
        $s5 = "Robert Kim"
        $s6 = "Lisa Thompson"
   	condition:   
   		all of them
   }

rule file_woff {
  meta:
    description = "Example - Detects WOFF File Format 2.0"
  strings:
    $magic = { 77 4F 46 32 }  // 'wOF2'
  condition:
    $magic at 0
}

rule file_avif_ftyp
{
  meta:
    description = "Example - Detects AVIF"

  strings:
    $ftyp = "ftyp"

  condition:
    $ftyp at 4
}

rule javascript_tailwindcss
{
  meta:
    description = "Example - Detects JavaScript code referencing TailwindCSS runtime/config"

  strings:
    $s1 = "tailwindcss" ascii nocase
    $s2 = "tailwind.config" ascii nocase
    $s3 = "theme" ascii
    $s4 = "variants" ascii
    $s5 = "apply" ascii
    $s6 = "plugin" ascii
    $s7 = "jit" ascii

  condition:
    $s1 and $s2 and 1 of ($s3,$s4,$s5,$s6,$s7)
}
