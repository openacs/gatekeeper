# /packages/gatekeeper/tcl/gatekeeper-procs.tcl
ad_library {
     Procs used by the gatekeeper module.
     @author jbank@arsdigita.com [jbank@arsdigita.com]
     @creation-date Wed Dec  6 11:19:49 2000
     @cvs-id
}

#TODO: 
#  -Fixup the replacement algorithm

##FILTERING CODE
ad_proc -public gatekeeper_register_filter { package_id filter } {
    Register a new filter for a particular instance of the gatekeeper package.
    Note that its probably easier to simply use ACS permissions to restrict
    access instead of registering a filter.
} {
    nsv_lappend gatekeeper_filters $package_id $filter
}

ad_proc -private gatekeeper_run_filters { user_id url } {
    Run any registered filters.  Returns 0 if access is denied.
} {
    set package_id [ad_conn package_id]
    if {[nsv_exists gatekeeper_filters $package_id]} {
        set filters [nsv_get gatekeeper_filters $package_id]
        foreach filter $filters {
            set res [eval [list $filter $package_id $user_id $url]]
            if { $res != "ok" } {
                return 0
            }
        }
    }
    return 1
}

ad_proc -private gatekeeper_server_root_prefix {} {
    Return dummy server root prefix
} {
    return "sr"
}

##GUARD INFO
ad_proc -private gatekeeper_guard_info {} {
    Return guard info as server, dir, file
} {
    set guard_url [ad_parameter -package_id [ad_conn package_id] "GuardUrl"]
    set server ""
    set dir ""
    set file ""
    regexp {^(http://[^/]*)(.*/)?([^/]*)?$} $guard_url match server dir file
    set guard_info(server) $server
    set guard_info(dir) $dir
    set guard_info(file) $file
    set guard_info(full_url) $guard_url
    set guard_info(server_dir) "$server$dir"
    return [array get guard_info]
} 

ad_proc -private gatekeeper_server_relative_url {} {
    Return server relative url.
} {
    array set guard_info [gatekeeper_guard_info]
    if { [empty_string_p $guard_info(dir)] } {
        return [ad_conn package_url]
    } else {
        return "[ad_conn package_url][gatekeeper_server_root_prefix]/"
    }
}

##REQUEST TO FOREIGN URL MAPPING
ad_proc -private gatekeeper_request_url_to_foreign_url { url } {
    Combine packages guarded url with passed in url
} {
    array set guard_info [gatekeeper_guard_info]
    
    if { [regexp "^/[gatekeeper_server_root_prefix](/.*)$" $url match rest] } {
        return "$guard_info(server)$rest"
    }
    if { $url == "/" } {
        return $guard_info(full_url)
    }
    return "$guard_info(server_dir)$url"
}

##PAGE REWRITING
ad_proc -private gatekeeper_guardurlregexp {} {
    Return the regexp to match for the guarded url.  This either uses the
    parameter GuardUrlRegexp or GuardUrl if it is defined.
} {
    array set guard_info [gatekeeper_guard_info]
    return "$guard_info(server_dir)"
}

ad_proc -private gatekeeper_subst_tag { page tag relative_url this_dir} {
    #Handle relative urls that start with ../ by translating them as if they were server rr 
    regsub -nocase -all "(<\[^>]*\[ \n\t\]+$tag\[ \n\t\]*=\[ \n\t\]*\"?)\.\./(\[^> \n\t\]*)(\[> \n\t\])" $page "\\1$this_dir../\\2\\3" page

    regsub -nocase -all "(<\[^>]*\[ \n\t\]+$tag\[ \n\t\]*=\[ \n\t\]*\"?)/(\[^> \n\t\]*)(\[> \n\t\])" $page "\\1$relative_url\\2\\3" page
    return $page
}

ad_proc -private gatekeeper_rewrite_page { page this_url } {
    Rewrite a retrieved page to use the gatekeeper url instead of the url being guarded.
} {
    set gatekeeper_relative_url "[gatekeeper_server_relative_url]"

    set this_server ""
    set this_dir ""
    set this_file ""
    regexp {^(http://[^/]*)(.*/)?([^/]*)?$} $this_url match this_server this_dir this_file



    
    
    ##THIS CAPTURES REDIRECTING SERVER RELATIVE urls like href=/foo 
    ##FOR RELATIVE HREF's like href=foo, there is no need to do this.
    set page [gatekeeper_subst_tag $page "href" $gatekeeper_relative_url $this_dir]
    set page [gatekeeper_subst_tag $page "src" $gatekeeper_relative_url $this_dir]
    set page [gatekeeper_subst_tag $page "action" $gatekeeper_relative_url $this_dir]
    set page [gatekeeper_subst_tag $page "codebase" $gatekeeper_relative_url $this_dir]

    ##THIS CAPTURES REDIRECTING SERVER ABSOLUTE href=http://.../ to point to here.
    set page [gatekeeper_absolute_substitution $page]
    return $page
}

ad_proc -private gatekeeper_absolute_substitution { url } {
    Do url substitution of the guarded url with the gatekeeper url.
} {
    array set guard_info [gatekeeper_guard_info]
    set gatekeeper_base_url "[ad_url][ad_conn package_url]"
    ##First substitute for all server_dir directories
    regsub -nocase -all "[gatekeeper_guardurlregexp]" $url $gatekeeper_base_url url
    regsub -nocase -all "$guard_info(server)" $url "$gatekeeper_base_url[gatekeeper_server_root_prefix]/" url
    return $url
}

##COOKIE HANDLING
ad_proc -private gatekeeper_cookie_prefix { } { Cookie wrapper prefix. } {
    return "[ad_conn package_id]__"
}
ad_proc -private gatekeeper_cookie_suffix { } { Cookie wrapper suffix. } {
    return "__[ad_conn package_id]"
}

ad_proc -private gatekeeper_munge_cookies {cookie} {
    Munge any gatekeeper cookies to strip off the cookie wrappers
    before sending it to the foreign server.
} {
    set cookies [split $cookie ";"]
    set return_cookies [list]
    foreach cookie $cookies {
        set cv [split $cookie "="]
        set key [lindex $cv 0]
        set val [lindex $cv 1]
        if {[regexp "[gatekeeper_cookie_prefix](.*)[gatekeeper_cookie_suffix]" $key match new_key ] } {
            lappend return_cookies "$new_key=$val"
        }
    }
    set extra_cookies [ad_parameter -package_id [ad_conn package_id] "ExtraCookie"]
    if { ![empty_string_p extra_cookies] } {
        lappend return_cookies $extra_cookies
    }
    #ns_log Notice "Sending cookies: $return_cookies"
    return [join $return_cookies "; "]
}

ad_proc -private gatekeeper_munge_output_cookies {headers} {
    Add cookie wrappers for any outgoing cookies
    that we are sending back to the user.
} {
    for { set i 0 } { $i < [ns_set size $headers] } { incr i } {
        if { ![string compare [string tolower [ns_set key $headers $i]] "set-cookie"] } {
            regsub "^(\[^=\]*)=" [ns_set value $headers $i] "[gatekeeper_cookie_prefix]\\1[gatekeeper_cookie_suffix]=" value
            ns_set put [ad_conn outputheaders] "Set-Cookie" $value
        }
    }
}

##QUERY AND RETURN RESULTS FROM FOREIGN SERVER
ad_proc -private gatekeeper_read_fully {fd timeout length} {
    Read the output of fd fully. 
} {
    set page ""
    set err [catch {
	while 1 {
	    set buf [_ns_http_read $timeout $fd $length]
	    append page $buf
	    if [string match "" $buf] {
		break
	    }
	    if {$length > 0} {
		incr length -[string length $buf]
		if {$length <= 0} {
		    break
		}
	    }
	}
    } errMsg]
    return $page
}

ad_proc -private gatekeeper_query_foreign {url {timeout 30}} {
    Query a foreign url.
} {
    ns_log "Notice" "Requesting foreign url: $url"
    set input_headers [ad_conn headers]

    set headers [ns_set copy $input_headers]
    #ns_log Notice "original headers: [NsSettoTclString $headers]"
    
    set pdata ""
    ns_set idelkey $headers host
    
    set cookies [ns_set iget $headers cookie]
    ns_set idelkey $headers cookie
    ns_set put $headers Cookie [gatekeeper_munge_cookies $cookies]


    if { [ns_conn method] == "POST" } {
        set rqset [ns_getform]
        set formvars [list]
        for {set i 0} {$i < [ns_set size $rqset]} {incr i} {
            lappend formvars "[ns_urlencode [ns_set key $rqset $i]]=[ns_urlencode [ns_set value $rqset $i]]"
        }
        set formvars [join $formvars "&"]
        ns_set idelkey $headers "Content-type"
        ns_set put $headers "Content-type" "application/x-www-form-urlencoded"
        ns_set idelkey $headers "Content-length"
        ns_set put $headers "Content-length" "[string length $formvars]"
        append pdata "$formvars\r"
        #ns_log Notice "Doing POST: [NsSettoTclString $headers]\n$formvars"
    }

    #ns_log Notice "ns_httpopen [ad_conn method] $url [NsSettoTclString $headers] $timeout $pdata"

    set http [ns_httpopen [ad_conn method] $url $headers $timeout $pdata]
    set rfd [lindex $http 0]
    set wfd [lindex $http 1]
    close $wfd
    set return_headers [lindex $http 2]
    #ns_log Notice "Got return headers [NsSettoTclString $return_headers]"
    set response [ns_set name $return_headers]
    set status [lindex $response 1]
    #Handle cookies
    gatekeeper_munge_output_cookies $return_headers
    #ns_log Notice "Using new return headers [NsSettoTclString [ad_conn outputheaders]]"

    if {$status == 302} {
	#
	# The response was a redirect, so free the return_headers and
	# recurse.
	#
	set location [ns_set iget $return_headers location]
	if {$location != ""} {
	    ns_set free $return_headers
	    close $rfd
	    if {[string first http:// $location] != 0} {
		set url2 [split $url /]
		set hp [split [lindex $url2 2] :]
		set host [lindex $hp 0]
		set port [lindex $hp 1]
		if [string match $port ""] {
                    set port 80
                }
		regexp "^(.*)://" $url match method
		
		set location "$method://$host:$port/$location"
	    }
            set new_url [gatekeeper_absolute_substitution $location]
            set old_url [gatekeeper_absolute_substitution $url]
            #ns_log Notice "Doing redirect to location: $location, $new_url, $old_url"
            if { [string compare $old_url $new_url] == 0 } {
                return [gatekeeper_query_foreign $location $timeout]
            }
            ad_returnredirect $new_url
	    return 
	}
    }
    
    set content_type [ns_set iget $return_headers content-type]
    set length [ns_set iget $return_headers content-length]
    if [string match "" $length] {
	set length -1
    }


    #TODO: Copy return_headers into connections output headers
    if { [regexp "text/html" $content_type match] } {
        #ns_log Notice "Calling gatekeeper_read_fully $rfd $timeout $length"
        set result [gatekeeper_read_fully $rfd $timeout $length]
        set page_body [gatekeeper_rewrite_page $result $url]
        ns_set free $return_headers
        close $rfd
        ns_return $status $content_type $page_body
    } else {
        set result ""
        ns_returnfp $status $content_type $rfd $length
        ns_set free $return_headers
        close $rfd
    }
}

##Main request handler
ad_proc -public gatekeeper_serve_request { } {
    The main entry point for the gatekeeper codes.
    Serve a foreign request with security access control and url remapping.
} {
    set user_id [ad_verify_and_get_user_id]
    set url "/[ad_conn extra_url]"
    if { ![empty_string_p [ad_conn query]] } {
        append url "?[ad_conn query]"
    }

    #Run filters on the url
    if {![gatekeeper_run_filters $user_id $url]} {
        #ns_log Notice "Gatekeeper denied access"
        ad_return_error "Access Denied" "Access Denied"
    }

    if { [catch { gatekeeper_query_foreign [gatekeeper_request_url_to_foreign_url $url]}] } {
	global errorInfo
	ns_log "Error" "Error fetching $url:\n$errorInfo"
	ad_return_error "Unable to retreive page." "Unable to retreive page."
    }
}
